/*
 * Smart Moto Security – DW3000 PDOA Test & Gateway Bridge
 * =========================================================
 * Purpose:
 *   1. Enable Phase Difference Of Arrival (PDOA) on DW3000 and log raw phase,
 *      angle-of-arrival (AoA), STS quality, and TWR distance via UART.
 *   2. Emit JSON frames on Serial2 so a BLE/Wi-Fi gateway app (e.g. ESP32-S3
 *      running esps3.ino) can forward them to Qorvo IP app or any third-party
 *      UWB app that reads JSON over UART/BLE/HTTP.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PDOA Primer (DW3000)
 * ─────────────────────────────────────────────────────────────────────────────
 *  PDOA = phase difference between two antenna phase-of-arrival values.
 *  Supported modes:
 *    DWT_PDOA_M0  – PDOA disabled (default in this repo)
 *    DWT_PDOA_M1  – Phase diff between Ipatov POA and STS POA  (requires STS)
 *    DWT_PDOA_M3  – Phase diff between two STS POAs (requires STS mode 3)
 *
 *  Key registers:
 *    CIA_TDOA_1_PDOA (0x0C001C) – bits [29:16] hold 14-bit signed PDOA value
 *    BUF0_PDOA       (0x180014) – same field in double-buffer 0
 *    BUF1_PDOA       (0x1800FC) – same field in double-buffer 1
 *
 *  Conversion from raw PDOA to angle (far-field, 2-antenna model):
 *    phi_rad = ((float)raw_pdoa / (1 << 11))          // Q1.11 fixed-point
 *    phi_deg = phi_rad * 180.0 / M_PI
 *    theta   = asin( phi_rad * lambda / (2*pi*d) )    // d = antenna spacing
 *    (wrap:  valid when |d| <= lambda/2)
 *
 *  DW3000 typical centre frequencies and lambda/2:
 *    Ch 5  ~ 6.49 GHz  ->  lambda ~ 46.2 mm  ->  lambda/2 ~ 23.1 mm
 *    Ch 9  ~ 7.99 GHz  ->  lambda ~ 37.5 mm  ->  lambda/2 ~ 18.7 mm
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Antenna Spacing Recommendations
 * ─────────────────────────────────────────────────────────────────────────────
 *  Spacing d = lambda/2 maximises unambiguous angle range (-90° … +90°) but
 *  gives only ±90° coverage with no phase unwrapping needed.
 *  Spacing d < lambda/2 reduces ambiguity at the cost of angular resolution.
 *  Spacing d > lambda/2 increases resolution but introduces phase ambiguity.
 *
 *  Practical guideline for DW3000 Channel 5 (6.49 GHz):
 *    Recommended: 20–23 mm (≈ lambda/2) – best balance
 *    Minimum:     10 mm (lambda/4)       – low resolution, no ambiguity
 *    Maximum:     46 mm (lambda)         – high resolution, ±90° ambiguity
 *
 *  For a 4-element ULA (Uniform Linear Array):
 *    Same per-element spacing as above; improves resolution ×2 vs 2-element.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Factors Affecting PDOA Accuracy
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. Multipath / reflections   – use STS (longer = better rejection)
 *  2. Low SNR                   – check stsCpQual; discard if < SNR_MIN_THRESHOLD
 *  3. Antenna phase-center mismatch – calibrate with PDOA_PHASE_OFFSET_RAD
 *  4. Near-field effects        – Fraunhofer distance: R > 2*D^2/lambda
 *  5. Clock drift               – dwt_readclockoffset() compensates TWR distance
 *  6. Temperature / ageing      – re-calibrate periodically
 *  7. STS length                – longer STS improves phase estimate quality
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Interoperability with Qorvo IP App / Third-Party UWB Apps
 * ─────────────────────────────────────────────────────────────────────────────
 *  Option A – Native FiRa/IEEE 802.15.4 compatibility:
 *    Implement MAC frame format + AES-CCM* nonce/MIC per FiRa spec.
 *    DW3000 supports 802.15.4 UWB; both anchor and tag must use the same
 *    profile, key management, and nonce derivation as the target app.
 *
 *  Option B – Gateway/Bridge (implemented below):
 *    This sketch outputs JSON via Serial2.  A gateway MCU (ESP32-S3) reads
 *    the JSON, bridges it over BLE or HTTP to the third-party app.
 *    The app never needs to speak UWB directly.
 *    JSON schema: {"dist_m":x.xx,"pdoa_raw":nnnn,"aoa_deg":x.x,"sts_qual":nn,"bat_pct":nn}
 *
 *  Option C – Proprietary frame matching:
 *    Requires Qorvo SDK / app developer docs.  Capture frames with a sniffer
 *    (DW3000 sniffer mode or Wireshark + plugin), analyse nonce/MIC format,
 *    then replicate in firmware.  Contact Qorvo for SDK access.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Hardware
 * ─────────────────────────────────────────────────────────────────────────────
 *  Target: STM32F103C8T6 (BluePill) or ESP32-C3 – any board with DW3000.
 *  Runs standalone as a PDOA receiver/anchor.
 *
 *  SPI (STM32 defaults):  CLK=PA5, MISO=PA6, MOSI=PA7, CS=PA4
 *  DW3000:                IRQ=PB0, RST=PA1
 *  UART debug:            Serial  (USB CDC or UART0)
 *  UART gateway bridge:   Serial2 (to ESP32-S3 or BLE module)
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 Smart-CBOX Project Contributors
 */

#include <math.h>
#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"

// ─── STM32duino FreeRTOS portability stubs ───────────────────────────────────
#if defined(ARDUINO_ARCH_STM32) || defined(ARDUINO_ARCH_STM32F1) || defined(__STM32F1__)
#ifndef portENTER_CRITICAL
#define portENTER_CRITICAL(m)  noInterrupts()
#endif
#ifndef portEXIT_CRITICAL
#define portEXIT_CRITICAL(m)   interrupts()
#endif
#ifndef portDISABLE_INTERRUPTS
#define portDISABLE_INTERRUPTS() noInterrupts()
#endif
#ifndef portENABLE_INTERRUPTS
#define portENABLE_INTERRUPTS()  interrupts()
#endif
#endif

// ─── CONFIGURATION ───────────────────────────────────────────────────────────
#define APP_NAME        "PDOA Test v1.0"

// Network addressing (match your anchor/tag pair)
#define ANCHOR_ADDR     0x1111
#define TAG_ADDR        0x2222
#define PAN_ID          0x3412

// PDOA calibration – measured per-board by rotating to a known angle.
// Adjust PDOA_PHASE_OFFSET_RAD until reported AoA matches ground truth at 0°.
#define PDOA_PHASE_OFFSET_RAD   (0.0f)     // radians – tune per hardware

// Antenna spacing in metres (distance between the two receiving antenna elements)
// Default: 23.1 mm ≈ lambda/2 at 6.49 GHz (Channel 5)
#define ANTENNA_SPACING_M       (0.0231f)

// Channel centre frequency (Hz) used to compute lambda
// Channel 5 = 6.4896 GHz, Channel 9 = 7.9872 GHz
#define UWB_CENTRE_FREQ_HZ      (6489.6e6f)
#define SPEED_OF_LIGHT_F        (299702547.0f)

// Minimum STS quality index to trust PDOA reading (0–100 scale, rough guide)
// Discard frames below this threshold (likely multipath or low SNR)
#define STS_QUAL_MIN_THRESHOLD  60

// Ranging constants (matching stm.ino / tagc3.ino)
#define TX_ANT_DLY              16385
#define RX_ANT_DLY              16385
#define POLL_TX_TO_RESP_RX_DLY_UUS 1720
#define RESP_RX_TIMEOUT_UUS     250
#define RX_BUF_LEN              127

// ─── PIN DEFINITIONS ─────────────────────────────────────────────────────────
// Adjust to match your board wiring
#ifdef ARDUINO_ARCH_STM32
const uint8_t PIN_DW_CS  = PA4;
const uint8_t PIN_DW_IRQ = PB0;
const uint8_t PIN_DW_RST = PA1;
#else
// ESP32-C3 defaults (same as tagc3.ino)
const uint8_t PIN_DW_CS  = 7;
const uint8_t PIN_DW_IRQ = 2;
const uint8_t PIN_DW_RST = 3;
#endif

// ─── DW3000 CONFIG – PDOA MODE 1 ─────────────────────────────────────────────
//  PDOA mode 1 requires STS to be enabled.  We use STS mode 1 (STS appended
//  after data payload) with STS length 128 for good phase estimate quality.
//  STS length 128 → STS_MNTH ≈ SQRT(16/8) * 0x10 = 0x16 (adjusted automatically
//  by dwt_configure via the sts_length_factors[] table in dw3000_device_api.cpp).
static dwt_config_t pdoa_config = {
    5,                  // Channel 5 (6.49 GHz)
    DWT_PLEN_128,       // Preamble length 128 symbols
    DWT_PAC8,           // PAC size 8
    9,                  // TX preamble code
    9,                  // RX preamble code
    1,                  // SFD type: DW 8-bit
    DWT_BR_6M8,         // Data rate 6.8 Mbps
    DWT_PHRMODE_STD,    // Standard PHR mode
    DWT_PHRRATE_STD,    // Standard PHR rate
    (129 + 8 - 8),      // SFD timeout
    DWT_STS_MODE_1,     // STS mode 1 – required for PDOA mode 1
    DWT_STS_LEN_128,    // STS length 128 – longer = better phase estimate
    DWT_PDOA_M1         // *** PDOA mode 1 enabled ***
};

extern dwt_txconfig_t txconfig_options;  // from dw3000_config_options.cpp

// ─── GLOBAL STATE ─────────────────────────────────────────────────────────────
static uint8_t  rx_buffer[RX_BUF_LEN];
static uint32_t frame_count    = 0;
static uint32_t pdoa_samples   = 0;
static double   last_distance  = -1.0;
static float    last_aoa_deg   = 0.0f;

// ─── FUNCTION PROTOTYPES ─────────────────────────────────────────────────────
static void     init_dw3000_pdoa(void);
static bool     wait_for_rx_frame(void);
static void     read_and_log_pdoa(uint32_t frame_len);
static float    pdoa_to_angle_deg(int16_t raw_pdoa);
static double   compute_twr_distance(void);
static void     emit_json_gateway(float aoa_deg, double dist_m, int16_t raw_pdoa, int16_t sts_qual);

// ─────────────────────────────────────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────────────────────────────────────
void setup() {
    // Debug UART (USB CDC on ESP32, UART0 on STM32)
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== " APP_NAME " ===");
    Serial.println("PDOA mode 1 | STS length 128 | Channel 5 (6.49 GHz)");
    Serial.println("CSV header: frame,dist_m,pdoa_raw,aoa_deg,sts_qual,valid");

    // Gateway UART (to ESP32-S3 / BLE module)
    // Uncomment for your platform:
    // Serial2.begin(115200);   // STM32: UART2  | ESP32: Serial2 on pins 16/17

    pinMode(PIN_DW_CS,  OUTPUT); digitalWrite(PIN_DW_CS,  HIGH);
    pinMode(PIN_DW_RST, OUTPUT); digitalWrite(PIN_DW_RST, HIGH);
    pinMode(PIN_DW_IRQ, INPUT);

    init_dw3000_pdoa();

    Serial.println("DW3000 ready – waiting for UWB frames...");
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN LOOP
// ─────────────────────────────────────────────────────────────────────────────
void loop() {
    // Enable receiver and block until a valid frame arrives (or error/timeout)
    dwt_rxenable(DWT_START_RX_IMMEDIATE);

    if (!wait_for_rx_frame()) {
        return;  // error or timeout – retry
    }

    uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
    dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

    if (frame_len < 2 || frame_len > RX_BUF_LEN) {
        return;
    }

    read_and_log_pdoa(frame_len);
    frame_count++;
}

// ─────────────────────────────────────────────────────────────────────────────
// INIT DW3000 WITH PDOA ENABLED
// ─────────────────────────────────────────────────────────────────────────────
static void init_dw3000_pdoa(void) {
    // Hardware reset
    digitalWrite(PIN_DW_RST, LOW);
    delay(2);
    digitalWrite(PIN_DW_RST, HIGH);
    delay(5);

    // Wait for IDLE
    int tries = 100;
    while (!dwt_checkidlerc() && --tries > 0) {
        delay(1);
    }
    if (tries == 0) {
        Serial.println("ERR: DW3000 IDLE timeout");
        while (1) { delay(500); }
    }

    // Initialise chip
    if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR) {
        Serial.println("ERR: dwt_initialise failed");
        while (1) { delay(500); }
    }

    // Verify that this DW3000 silicon supports PDOA.
    // PDOA variants: DWT_A0_PDOA_DEV_ID, DWT_B0_PDOA_DEV_ID, DWT_C0_PDOA_DEV_ID
    uint32_t dev_id = dwt_read32bitreg(DEV_ID_ID);
    bool pdoa_capable = (dev_id == DWT_A0_PDOA_DEV_ID) ||
                        (dev_id == DWT_B0_PDOA_DEV_ID) ||
                        (dev_id == DWT_C0_PDOA_DEV_ID);
    Serial.print("DEV_ID = 0x");
    Serial.print(dev_id, HEX);
    if (pdoa_capable) {
        Serial.println("  [PDOA capable ✓]");
    } else {
        Serial.println("  [WARNING: non-PDOA silicon – PDOA register values unreliable]");
    }

    // Apply PDOA-enabled config
    if (dwt_configure(&pdoa_config) != 0) {
        Serial.println("ERR: dwt_configure failed");
        while (1) { delay(500); }
    }

    dwt_configuretxrf(&txconfig_options);
    dwt_setrxantennadelay(RX_ANT_DLY);
    dwt_settxantennadelay(TX_ANT_DLY);
    dwt_setrxaftertxdelay(POLL_TX_TO_RESP_RX_DLY_UUS);
    dwt_setrxtimeout(RESP_RX_TIMEOUT_UUS);

    // Enable LEDs (blink on RX/TX) for visual confirmation
    dwt_setleds(DWT_LEDS_ENABLE | DWT_LEDS_INIT_BLINK);
    dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);

    // Enable CIA diagnostic logging so PDOA register is populated
    dwt_configciadiag(DW_CIA_DIAG_LOG_MIN);

    // Frame filter: accept data frames for our PAN/address
    dwt_configureframefilter(DWT_FF_DATA_EN, 0);
    dwt_setpanid(PAN_ID);
    dwt_setaddress16(ANCHOR_ADDR);

    Serial.println("DW3000 configured: PDOA_M1, STS_MODE_1, STS_LEN_128");
    Serial.print("Antenna spacing:   ");
    Serial.print(ANTENNA_SPACING_M * 1000.0f, 1);
    Serial.println(" mm");
    Serial.print("Lambda/2 at 6.49GHz: ");
    float lambda = SPEED_OF_LIGHT_F / UWB_CENTRE_FREQ_HZ;
    Serial.print(lambda / 2.0f * 1000.0f, 1);
    Serial.println(" mm");
}

// ─────────────────────────────────────────────────────────────────────────────
// WAIT FOR RX FRAME (polling, up to 2 s)
// Returns true if frame received OK, false on error / timeout.
// ─────────────────────────────────────────────────────────────────────────────
static bool wait_for_rx_frame(void) {
    uint32_t start = millis();

    while ((millis() - start) < 2000UL) {
        uint32_t status = dwt_read32bitreg(SYS_STATUS_ID);

        if (status & SYS_STATUS_RXFCG_BIT_MASK) {
            return true;
        }
        if (status & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
            dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
            return false;
        }
        delay(1);
    }

    // Timeout – force off receiver
    dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_TO | SYS_STATUS_ALL_RX_ERR);
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// READ PDOA + DIAGNOSTICS AND LOG TO UART
// ─────────────────────────────────────────────────────────────────────────────
static void read_and_log_pdoa(uint32_t frame_len) {
    // ── 1. Read raw PDOA value from DW3000 CIA register ──────────────────────
    //  dwt_readpdoa() reads CIA_TDOA_1_PDOA bits [29:16] (14-bit signed),
    //  sign-extends to 16-bit and returns the value in Q1.11 fixed-point.
    //  To convert to radians:  phi_rad = raw / 2048.0f
    //  To convert to degrees:  phi_deg = phi_rad * 180.0 / M_PI
    int16_t raw_pdoa = dwt_readpdoa();

    // ── 2. STS quality index ─────────────────────────────────────────────────
    //  stsCpQual: 0 = worst, higher = better.  Roughly >60% of STS length
    //  is considered good quality for 64 MHz PRF.
    int16_t sts_qual = 0;
    (void)dwt_readstsquality(&sts_qual);

    bool pdoa_valid = (sts_qual >= STS_QUAL_MIN_THRESHOLD);

    // ── 3. Convert PDOA → angle of arrival ───────────────────────────────────
    float aoa_deg = pdoa_to_angle_deg(raw_pdoa);

    // ── 4. Optionally compute TWR ranging distance ────────────────────────────
    //  Reads TX and RX timestamps available in SYS_STATUS after frame reception.
    //  Only meaningful when the received frame contains embedded TWR timestamps
    //  (as in tagc3.ino / stm.ino).  Falls back to -1 if frame is too short.
    double dist_m = -1.0;
    if (frame_len >= 19) {
        dwt_readrxdata(rx_buffer, frame_len - 2, 0);
        dist_m = compute_twr_distance();
        last_distance = dist_m;
    }

    last_aoa_deg = aoa_deg;
    pdoa_samples++;

    // ── 5. CSV log to debug Serial ────────────────────────────────────────────
    //  Format: frame,dist_m,pdoa_raw,aoa_deg,sts_qual,valid
    char line[96];
    int dist_int  = (dist_m >= 0.0) ? (int)dist_m            : -1;
    int dist_frac = (dist_m >= 0.0) ? (int)((dist_m - (int)dist_m) * 100.0) : 0;
    snprintf(line, sizeof(line),
             "%lu,%d.%02d,%d,%.2f,%d,%s",
             (unsigned long)frame_count,
             dist_int, dist_frac,
             (int)raw_pdoa,
             aoa_deg,
             (int)sts_qual,
             pdoa_valid ? "OK" : "WARN");
    Serial.println(line);

    // ── 6. Verbose register dump (every 10 frames) ────────────────────────────
    //  CIA_TDOA_1_PDOA (0x0C001C): bits [29:16] hold the 14-bit signed PDOA.
    //  BUF0_PDOA (0x180014) / BUF1_PDOA (0x1800FC) are only populated when
    //  double-buffer mode is active; we do not use double-buffering here.
    if (frame_count % 10 == 0) {
        uint32_t cia_reg = dwt_read32bitreg(CIA_TDOA_1_PDOA_ID);
        Serial.print("  [CIA_TDOA_1_PDOA 0x0C001C] 0x");
        Serial.print(cia_reg, HEX);
        Serial.print("  PDOA bits[29:16] = 0x");
        Serial.println((cia_reg >> 16) & 0x3FFFUL, HEX);
        Serial.print("  [Clock offset ppm] ");
        float clk_off = ((float)dwt_readclockoffset()) / (float)(1UL << 26);
        Serial.println(clk_off * 1e6f, 3);
    }

    // ── 7. JSON gateway output ────────────────────────────────────────────────
    //  Emitted on Serial2 so a downstream gateway (ESP32-S3 / BLE) can relay
    //  the data to Qorvo IP app or any HTTP/BLE consumer.
    emit_json_gateway(aoa_deg, dist_m, raw_pdoa, sts_qual);
}

// ─────────────────────────────────────────────────────────────────────────────
// PDOA RAW → ANGLE OF ARRIVAL (degrees)
// ─────────────────────────────────────────────────────────────────────────────
//  Formula (two-antenna, far-field, narrowband approximation):
//    phi  = raw_pdoa / 2048.0          (radians, Q1.11 fixed-point)
//    phi -= PDOA_PHASE_OFFSET_RAD      (remove calibration offset)
//    lambda = c / f                    (wavelength in metres)
//    arg  = phi * lambda / (2*pi*d)    (d = antenna spacing in metres)
//    theta = asin(clamp(arg, -1, 1))   (angle of arrival in radians)
//
//  Valid only in far-field region (R >> 2*D^2/lambda).
//  Phase ambiguity arises when d > lambda/2; use phase unwrapping algorithms
//  or reduce spacing to avoid it.
// ─────────────────────────────────────────────────────────────────────────────
static float pdoa_to_angle_deg(int16_t raw_pdoa) {
    // Convert Q1.11 fixed-point to radians
    float phi_rad = (float)raw_pdoa / 2048.0f;

    // Subtract calibration offset (measured empirically per board/antenna)
    phi_rad -= PDOA_PHASE_OFFSET_RAD;

    // Wavelength at configured centre frequency
    float lambda = SPEED_OF_LIGHT_F / UWB_CENTRE_FREQ_HZ;

    // Compute sin(theta)
    float sin_theta = phi_rad * lambda / (2.0f * (float)M_PI * ANTENNA_SPACING_M);

    // Clamp to valid asin() input range to guard against noise exceeding ±1
    if (sin_theta >  1.0f) sin_theta =  1.0f;
    if (sin_theta < -1.0f) sin_theta = -1.0f;

    float theta_rad = asinf(sin_theta);
    return theta_rad * 180.0f / (float)M_PI;
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPUTE TWR DISTANCE FROM EMBEDDED TIMESTAMPS
// Reads TX-side timestamps embedded in the received frame (bytes 9..16)
// as per the tagc3.ino / stm.ino frame layout.
// Returns distance in metres, or -1.0 on error.
// ─────────────────────────────────────────────────────────────────────────────
static double compute_twr_distance(void) {
    // Anchor timestamps (local to this receiver)
    uint32_t poll_tx_ts = dwt_readtxtimestamplo32();
    uint32_t resp_rx_ts = dwt_readrxtimestamplo32();

    // Tag timestamps embedded in frame header (bytes 9..16 per tagc3.ino layout)
    uint32_t poll_rx_ts = ((uint32_t)rx_buffer[9]  <<  0) |
                          ((uint32_t)rx_buffer[10]  <<  8) |
                          ((uint32_t)rx_buffer[11]  << 16) |
                          ((uint32_t)rx_buffer[12]  << 24);
    uint32_t resp_tx_ts = ((uint32_t)rx_buffer[13] <<  0) |
                          ((uint32_t)rx_buffer[14]  <<  8) |
                          ((uint32_t)rx_buffer[15]  << 16) |
                          ((uint32_t)rx_buffer[16]  << 24);

    int32_t rtd_init = (int32_t)(resp_rx_ts - poll_tx_ts);
    int32_t rtd_resp = (int32_t)(resp_tx_ts - poll_rx_ts);
    float   clk_off  = ((float)dwt_readclockoffset()) / (float)(1UL << 26);
    double  tof      = ((rtd_init - rtd_resp * (1.0 - clk_off)) / 2.0) * DWT_TIME_UNITS;
    double  dist     = tof * SPEED_OF_LIGHT;

    if (dist < 0.0 || dist > 100.0) return -1.0;
    return dist;
}

// ─────────────────────────────────────────────────────────────────────────────
// EMIT JSON GATEWAY FRAME ON Serial2
// ─────────────────────────────────────────────────────────────────────────────
//  Schema (compatible with esps3.ino /api/data endpoint extension):
//    {"frame":N,"dist_m":X.XX,"pdoa_raw":N,"aoa_deg":X.X,"sts_qual":N,"valid":true}
//
//  The downstream gateway (ESP32-S3 esps3.ino) can parse this JSON and either:
//    a) Publish it via ERa/MQTT for cloud dashboards.
//    b) Serve it on /api/data HTTP endpoint consumed by a web/mobile app.
//    c) Forward it over BLE to a mobile app (Qorvo IP app or custom app).
//
//  For BLE bridging:
//    Use a BLE NUS (Nordic UART Service) characteristic on the gateway MCU.
//    The Qorvo IP app can connect if it exposes a developer/debug API; otherwise
//    implement a custom BLE service with the same JSON payload.
// ─────────────────────────────────────────────────────────────────────────────
static void emit_json_gateway(float aoa_deg, double dist_m, int16_t raw_pdoa, int16_t sts_qual) {
    char json[128];

    int dist_int  = (dist_m >= 0.0) ? (int)dist_m                        : -1;
    int dist_frac = (dist_m >= 0.0) ? (int)((dist_m - (int)dist_m) * 100.0) : 0;
    int aoa_int   = (int)aoa_deg;
    int aoa_frac  = (int)fabsf((aoa_deg - (float)aoa_int) * 10.0f);

    snprintf(json, sizeof(json),
             "{\"frame\":%lu,\"dist_m\":%d.%02d,\"pdoa_raw\":%d,"
             "\"aoa_deg\":%d.%d,\"sts_qual\":%d,\"valid\":%s}\r\n",
             (unsigned long)frame_count,
             dist_int, dist_frac,
             (int)raw_pdoa,
             aoa_int, aoa_frac,
             (int)sts_qual,
             (sts_qual >= STS_QUAL_MIN_THRESHOLD) ? "true" : "false");

    // Uncomment when Serial2 (gateway UART) is available:
    // Serial2.print(json);

    // Mirror to debug Serial for development
    Serial.print("JSON> ");
    Serial.print(json);
}

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * CALIBRATION PROCEDURE
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Place the DW3000 anchor board at a known orientation (0° boresight).
 * 2. Place the tag at ≥ 1 m distance, directly in front (0°).
 * 3. Record average aoa_deg over 100 frames.
 * 4. Set PDOA_PHASE_OFFSET_RAD = (average_aoa_deg * M_PI / 180.0) to zero it.
 * 5. Verify with tag at +45° and −45° from boresight.
 *
 * PDOA ACCURACY TEST PROCEDURE
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Mount board on turntable.  Tag at fixed 2 m distance.
 * 2. Sweep from −80° to +80° in 5° steps; record 50 samples per step.
 * 3. Compute RMSE(measured AoA, true AoA) – target < 5° RMS in open space.
 * 4. Repeat in reflective environment to characterise multipath bias.
 * 5. If sts_qual frequently < STS_QUAL_MIN_THRESHOLD, increase STS_LEN or
 *    move to a less cluttered environment.
 *
 * ANTENNA SPACING REFERENCE TABLE
 * ─────────────────────────────────────────────────────────────────────────────
 *  Channel | Centre freq | Lambda   | Lambda/2 | Recommended spacing
 *  --------+-------------+----------+----------+---------------------
 *    5      | 6.49 GHz    | 46.2 mm  | 23.1 mm  | 20–23 mm
 *    9      | 7.99 GHz    | 37.5 mm  | 18.7 mm  | 17–19 mm
 *   (3.5)   | 3.99 GHz    | 75.1 mm  | 37.6 mm  | 33–38 mm  (Ch 1–4)
 *
 * INTEROPERABILITY CHECKLIST
 * ─────────────────────────────────────────────────────────────────────────────
 *  □ Confirm target app frame format: FiRa / Qorvo proprietary / custom.
 *  □ Capture frames with UWB sniffer; note: PAN ID, address, nonce fields.
 *  □ Check AES mode: CCM* (standard) vs AES-GCM / proprietary?  Key size?
 *  □ If FiRa: implement FiRa MAC/PHY profile; apply for FiRa certification.
 *  □ If proprietary: request SDK/docs from vendor (Qorvo developer portal).
 *  □ If gateway: extend esps3.ino /api/data to expose JSON above.
 *  □ If BLE: add BLE NUS service to gateway; advertise to target app.
 *
 * SNIFFER WORKFLOW (DW3000 promiscuous mode)
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. Remove frame filter:  dwt_configureframefilter(0, 0);
 *  2. Enable auto-RX re-arm in ISR after each reception.
 *  3. Dump raw rx_buffer[] via Serial for every received frame.
 *  4. Decode bytes manually or forward to Wireshark via custom pipe.
 *  5. Look for proprietary fields after standard 802.15.4 MAC header.
 */
