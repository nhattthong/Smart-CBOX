/*
 * Smart Moto Security – STM32F411CEU6 ANCHOR (SmartKey Controller v3.0)
 * =========================================================================
 * Migration: STM32F103C8T6 → STM32F411CEU6 (BlackPill)
 *
 * Why F411 over F103:
 *   - Cortex-M4F @ 100 MHz  vs  Cortex-M3 @ 72 MHz (faster ranging loop)
 *   - Hardware FPU  → all float/double KF math is native HW (no SW emulation)
 *   - 128 KB SRAM   vs  20 KB  (can store much larger noise-history window)
 *   - 512 KB Flash  vs  64 KB  (room for ML/filter + EEPROM emulation)
 *   - USB FS built-in (USB-C) for debug without needing a separate UART adapter
 *   - Same SPI1/UART1 pin mapping → drop-in replacement on the PCB
 *
 * Role: UWB TWR Responder (v3), AES-CCM* FINAL Verifier, Relay Control, UART to ESP32-S3
 *       + Adaptive Kalman Filter (AKF) that auto-learns ranging noise/environment
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Role change v2 → v3:
 * ─────────────────────────────────────────────────────────────────────────────
 *   v2: Anchor = TWR Initiator. Sent POLL every 100ms.  DW3000 cycling TX+RX.
 *   v3: Anchor = TWR Responder. Stays in continuous DW3000 RX.  When the tag's
 *       POLL arrives, sends a plain RESP with TWR timestamps, then waits for
 *       the tag's encrypted FINAL frame (3-frame DS-TWR protocol).
 *   The anchor runs on the motorcycle's battery so continuous DW3000 RX (~60mA)
 *   is acceptable.  The tag (fob) switches to timer wakeup every 3 s → 120×
 *   lower average current on its small coin/li-po cell.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Pinout (STM32F411CEU6 BlackPill – identical wiring to F103 BluePill)
 * ─────────────────────────────────────────────────────────────────────────────
 *   SPI1:   PA5=SCK, PA6=MISO, PA7=MOSI, PA4=CS
 *   DW3000: PB0=IRQ, PA1=RST
 *   Relay:  PB1 (HIGH=UNLOCK, LOW=LOCK) via NPN transistor + flyback diode
 *   UART1:  PA9=TX, PA10=RX → ESP32-S3 Serial2 (RX=17, TX=18)
 *   USB-C:  PA11/PA12 (CDC Serial for debug – no external adapter needed)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Adaptive Kalman Filter (AKF) – auto-learns noise from environment
 * ─────────────────────────────────────────────────────────────────────────────
 * State model (1-D, constant-position):
 *   x[k] = x[k-1] + w    process noise  w ~ N(0, Q)
 *   z[k] = x[k]   + v    measurement    v ~ N(0, R)
 *
 * Standard KF cycle:
 *   Predict:  x_pred = x_est
 *             P_pred = P_est + Q
 *   Update:   K      = P_pred / (P_pred + R)
 *             x_est  = x_pred + K*(z - x_pred)
 *             P_est  = (1-K) * P_pred
 *             innov  = z - x_pred             ← innovation (residual)
 *
 * Environment / noise adaptation (Innovation-based Adaptive Estimation):
 *   Track EMA of innovation squared  → ε² = EMA(innov²)
 *   Theoretical innovation variance  → S  = P_pred + R
 *   If ε² ≫ S → environment is noisier than the filter expects:
 *       increase R (be less trusting of individual measurements)
 *   If ε² ≪ S → environment is quieter:
 *       decrease R (trust measurements more → tighter, faster tracking)
 *   Process noise Q adapts similarly, allowing faster tracking when the
 *   physical distance is genuinely changing (tag is moving).
 *
 * Gate (outlier rejection):
 *   Reject any measurement where |innov| > GATE_SIGMA * sqrt(S)
 *   This removes UWB multipath spikes without disturbing the filter state.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Security (same as stm.ino / tagc3.ino)
 * ─────────────────────────────────────────────────────────────────────────────
 *   AES-128 CCM*, nonce anti-replay, MIC verification
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * UART Protocol to ESP32-S3 (unchanged from v2)
 * ─────────────────────────────────────────────────────────────────────────────
 *   "STATUS:KEY=ON|DIST=1.23|KF=1.21|Q=0.0010|R=0.0500|BAT=85\r\n"
 *   "STATUS:KEY=OFF|DIST=0.00|KF=0.00|Q=0.0010|R=0.0500|BAT=85\r\n"
 *   "ERR:DECRYPT\r\n"   – AES-CCM* MIC verification failed
 *   "ERR:REPLAY\r\n"    – Nonce replay detected
 *   "ERR:CMD\r\n"       – Unknown CMD in decrypted payload
 *   "ERR:GATE\r\n"      – KF outlier gate rejected measurement
 *   "ERR:XDIST\r\n"     – Distance cross-check failed (forgery attempt)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Arduino IDE Setup for STM32F411CEU6
 * ─────────────────────────────────────────────────────────────────────────────
 *   Board:       STM32F4xx > Generic F4 series  → STM32F411CE
 *   Upload via:  STM32CubeProgrammer (DFU) or ST-Link SWD
 *   Library:     STM32duino (https://github.com/stm32duino/Arduino_Core_STM32)
 *   Optimise:    Sketch > Optimize = "Faster (-O2)" to enable FPU scheduling
 */

// ─── STM32duino FreeRTOS portability stubs (F1 and F4) ──────────────────────
#if defined(ARDUINO_ARCH_STM32) || defined(ARDUINO_ARCH_STM32F1) || \
    defined(__STM32F1__) || defined(ARDUINO_ARCH_STM32F4) || defined(__STM32F4__)
#ifndef portENTER_CRITICAL
#define portENTER_CRITICAL(m)    noInterrupts()
#endif
#ifndef portEXIT_CRITICAL
#define portEXIT_CRITICAL(m)     interrupts()
#endif
#ifndef portDISABLE_INTERRUPTS
#define portDISABLE_INTERRUPTS() noInterrupts()
#endif
#ifndef portENABLE_INTERRUPTS
#define portENABLE_INTERRUPTS()  interrupts()
#endif
#endif

#include <math.h>
#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"
#include <IWatchdog.h>   // STM32duino IWDG – available on both F1 and F4

extern dwt_txconfig_t txconfig_options;

// ─── CONFIGURATION ───────────────────────────────────────────────────────────
#define APP_NAME            "SmartKey Anchor v3.0 (F411)"
#define TAG_ADDR            0x2222
#define ANCHOR_ADDR         0x1111
#define PAN_ID              0x3412

// Signal timeout: how long after the last valid FINAL before forcing relay off.
// Must be > POLL_INTERVAL_S * 3 to tolerate 3 missed poll cycles.
// Default: 10 s (tag polls every 3 s; allows missing ~3 consecutive cycles).
#define SIGNAL_TIMEOUT_MS   10000

// Relay hysteresis (on KF-filtered distance)
#define DIST_THRESHOLD_ON   1.5f    // metres – unlock when KF distance < this
#define DIST_THRESHOLD_OFF  3.0f    // metres – lock  when KF distance > this

// Distance cross-check tolerance: maximum allowed difference between the
// anchor-computed distance (from T1/T2/T3/T4) and the DIST field embedded in
// the tag's encrypted payload (tag's own computation).  Rejects forged headers.
#define DIST_XCHECK_TOL_M   0.50f   // metres

// AES / frame sizes
#define MIC_LEN             4
#define HEADER_LEN          21
#define PAYLOAD_MAX_LEN     36
#define NONCE_HISTORY_SIZE  32

// ─── UWB PROTOCOL TIMING (v3 – Anchor Responder) ─────────────────────────────
// Time from anchor receiving POLL to anchor transmitting RESP.
// Must be long enough for: read POLL, get timestamp, build RESP frame, call starttx.
// STM32F411 @ 100 MHz: all steps take < 200 µs → 2000 µs gives plenty of margin.
#define POLL_RX_TO_RESP_TX_DLY_UUS   2000

// Timeout anchor waits for tag's FINAL frame (after anchor sends RESP).
// Tag sends FINAL RESP_RX_TO_FINAL_TX_DLY_UUS (6000 µs in tagc3.ino) after
// its RESP RX.  Add 2× max ToF (50 µs at 15 m) and margin → 8000 µs.
#define FINAL_WAIT_TIMEOUT_UUS        8000

// Wall-clock timeout anchor waits for a POLL from the tag.
// Must be slightly > POLL_INTERVAL_S (3 s) to handle timer drift; 4.5 s leaves
// enough margin before the 8 s hardware watchdog triggers.
#define POLL_WAIT_TIMEOUT_MS          4500

// RESP frame length: [MAC 9B][T2:4B][T3:4B] = 17 data bytes
#define RESP_FRAME_LEN                17

// POLL frame: 9B MAC + 4B 'POLL' = 13 data bytes
#define POLL_FRAME_LEN                13

// RX buffer
#define RX_BUF_LEN                    127

// ─── AES-128 PRE-SHARED KEY ───────────────────────────────────────────────────
// *** CHANGE BEFORE DEPLOYMENT – must match tagc3.ino ***
// Generate: python3 -c "import os; d=os.urandom(16); \
//   print(','.join(hex(int.from_bytes(d[i:i+4],'big'))+'UL' for i in range(0,16,4)))"
static const dwt_aes_key_t aes_key = {
    0xAABBCCDDUL, 0xEEFF0011UL, 0x22334455UL, 0x66778899UL,
    0, 0, 0, 0
};

// ─── PIN DEFINITIONS (BlackPill F411) ────────────────────────────────────────
const uint8_t PIN_DW_CS  = PA4;
const uint8_t PIN_DW_IRQ = PB0;
const uint8_t PIN_DW_RST = PA1;
const uint8_t PIN_RELAY  = PB1;

// ─── DW3000 CONFIG ────────────────────────────────────────────────────────────
static dwt_config_t config = {
    5,                  // Channel 5 (6.49 GHz)
    DWT_PLEN_128,
    DWT_PAC8,
    9,                  // TX preamble code
    9,                  // RX preamble code
    1,                  // SFD type DW 8-bit
    DWT_BR_6M8,
    DWT_PHRMODE_STD,
    DWT_PHRRATE_STD,
    (129 + 8 - 8),
    DWT_STS_MODE_OFF,
    DWT_STS_LEN_64,
    DWT_PDOA_M0
};

#define TX_ANT_DLY               16385
#define RX_ANT_DLY               16385
// (RX_BUF_LEN defined above with the other protocol constants)

// ─── ADAPTIVE KALMAN FILTER ───────────────────────────────────────────────────
//  All arithmetic uses float; the Cortex-M4F FPU executes these as
//  single-cycle hardware instructions, matching double-precision performance
//  on a Cortex-M3 but at 100 MHz with no software overhead.
//
//  Tuning parameters (re-tuned for 3 s POLL interval, not 100 ms):
//    AKF_Q_INIT – initial process noise variance (m²).  At 3 s intervals a
//                 walking person can move ~4 m → 2 m 1-sigma → Q ≈ 4 m².
//                 However, this project targets parked bikes, so Q_INIT = 0.05
//                 (22 cm sigma) is a reasonable starting point.
//    AKF_ALPHA  – EMA coefficient.  At 3 s rate with α=0.15, the effective
//                 window is 1/0.15 ≈ 7 measurements = 21 s to converge.
//    AKF_GATE   – unchanged at 4σ; works well regardless of update rate.
#define AKF_Q_INIT   0.050f     // m² – 22 cm sigma per 3-second step
#define AKF_R_INIT   0.050f     // m² – DW3000 TWR typical ±22 cm @ 1-sigma
#define AKF_ALPHA    0.15f      // 15% weight for newest innovation (~7-sample window)
#define AKF_GATE     4.0f       // reject if innovation > 4-sigma
#define AKF_Q_MIN    0.0001f
#define AKF_Q_MAX    0.5f
#define AKF_R_MIN    0.001f
#define AKF_R_MAX    2.0f

typedef struct {
    float x;             // Current state estimate: filtered distance (m)
    float P;             // Error covariance (m²)
    float Q;             // Process noise variance – learned from environment
    float R;             // Measurement noise variance – learned from environment
    float ema_innov_sq;  // EMA of innovation²: tracks actual measurement scatter
    bool  initialized;   // First measurement seeds x directly (no prediction)
} akf_t;

static akf_t kf = {
    .x            = 0.0f,
    .P            = 1.0f,       // start with high uncertainty
    .Q            = AKF_Q_INIT,
    .R            = AKF_R_INIT,
    .ema_innov_sq = AKF_R_INIT, // seed EMA with initial R so gate works immediately
    .initialized  = false
};

/*
 * akf_update() – feed one raw TWR distance measurement into the adaptive KF.
 * Returns the filtered distance estimate, or -1.0f if the measurement was
 * rejected by the outlier gate.
 *
 * Side effects: updates kf.Q, kf.R, kf.x, kf.P, kf.ema_innov_sq
 */
static float akf_update(akf_t *kf, float z_meas) {
    // ── Seed on first measurement ─────────────────────────────────────────────
    if (!kf->initialized) {
        kf->x           = z_meas;
        kf->P           = kf->R;
        kf->initialized = true;
        return z_meas;
    }

    // ── Predict ───────────────────────────────────────────────────────────────
    // x_pred = x_est (constant-position model: state doesn't change on its own)
    float x_pred = kf->x;
    float P_pred = kf->P + kf->Q;

    // ── Innovation and gate ───────────────────────────────────────────────────
    float innov = z_meas - x_pred;
    float S     = P_pred + kf->R;              // innovation variance (m²)
    float gate  = AKF_GATE * sqrtf(S);         // gate threshold (m)

    if (fabsf(innov) > gate) {
        // Outlier detected – reject measurement, still adapt ema slightly
        // to allow the filter to recover if the environment genuinely shifted
        kf->ema_innov_sq = (1.0f - AKF_ALPHA) * kf->ema_innov_sq
                         + AKF_ALPHA * (innov * innov);
        return -1.0f;                          // signal: measurement rejected
    }

    // ── Update EMA of innovation² (tracks actual noise level) ─────────────────
    float innov_sq    = innov * innov;
    kf->ema_innov_sq  = (1.0f - AKF_ALPHA) * kf->ema_innov_sq
                      + AKF_ALPHA * innov_sq;

    // ── Kalman gain and state/covariance update ───────────────────────────────
    float K   = P_pred / S;
    kf->x     = x_pred + K * innov;
    kf->P     = (1.0f - K) * P_pred;

    // ── Adapt R: compare EMA(ε²) to expected S ────────────────────────────────
    // ε² > S → noisier than model → increase R (trust measurements less)
    // ε² < S → quieter than model → decrease R (trust measurements more)
    float ratio = kf->ema_innov_sq / S;
    if (ratio > 1.2f) {
        kf->R *= 1.05f;                        // 5 % increase per measurement
    } else if (ratio < 0.8f) {
        kf->R *= 0.97f;                        // 3 % decrease per measurement
    }
    if (kf->R < AKF_R_MIN) kf->R = AKF_R_MIN;
    if (kf->R > AKF_R_MAX) kf->R = AKF_R_MAX;

    // ── Adapt Q: if K is large (filter uncertain), measurements are driving
    //    the state fast; if K is small, Q may be over-estimated.
    //    Heuristic: Q ~ K * R (scale with current Kalman gain)
    float Q_target = K * kf->R;
    kf->Q = (1.0f - AKF_ALPHA) * kf->Q + AKF_ALPHA * Q_target;
    if (kf->Q < AKF_Q_MIN) kf->Q = AKF_Q_MIN;
    if (kf->Q > AKF_Q_MAX) kf->Q = AKF_Q_MAX;

    return kf->x;
}

// ─── GLOBAL STATE ─────────────────────────────────────────────────────────────
static uint8_t  rx_buffer[RX_BUF_LEN];

// Anchor's own TWR timestamps for the current ranging exchange
static uint64_t anchor_poll_rx_ts  = 0;   // T2 – anchor RX timestamp of tag's POLL
static uint64_t anchor_resp_tx_ts  = 0;   // T3 – anchor TX timestamp of RESP to tag

double   last_distance_raw = -1.0;  // raw TWR distance (m)
float    last_distance_kf  = -1.0f; // KF-filtered distance (m)
bool     relay_state       = false;
uint32_t last_signal_ms    = 0;
uint8_t  last_bat_pct      = 0;

#define AES_STS_ERROR_MASK  0x3E
static uint32_t nonce_history[NONCE_HISTORY_SIZE] = {0};
static uint8_t  nonce_history_idx = 0;

// ─── FUNCTION PROTOTYPES ──────────────────────────────────────────────────────
void    init_dw3000(void);
bool    wait_for_poll_and_respond(void);
bool    wait_for_final_and_process(void);
bool    decrypt_and_verify_payload(uint8_t *rx_buf, uint32_t frame_len,
                                   double measured_dist, uint8_t seq);
void    build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_bytes);
bool    is_nonce_replay(uint32_t nonce_word);
void    record_nonce(uint32_t nonce_word);
void    update_relay(void);
void    send_status(const char *key_str, double dist_raw, float dist_kf, uint8_t bat);
void    send_error(const char *err);
void    print_debug(const char *msg);

// ─────────────────────────────────────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────────────────────────────────────
void setup() {
    delay(1000);

    // USB CDC Serial (F411 built-in USB FS – connect USB-C for debug)
    Serial.begin(115200);
    print_debug("=== " APP_NAME " Starting ===");

    // UART1 to ESP32-S3 (PA9=TX, PA10=RX via Serial1 in STM32duino)
    Serial1.begin(115200);

    pinMode(PIN_DW_CS,  OUTPUT); digitalWrite(PIN_DW_CS,  HIGH);
    pinMode(PIN_DW_RST, OUTPUT); digitalWrite(PIN_DW_RST, HIGH);
    pinMode(PIN_RELAY,  OUTPUT); digitalWrite(PIN_RELAY,  LOW);
    pinMode(PIN_DW_IRQ, INPUT);

    // Hardware watchdog: 8 s
    IWatchdog.begin(8000000);

    init_dw3000();

    print_debug(APP_NAME " Ready – listening for tag POLL");
    last_signal_ms = millis();
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN LOOP (v3 Responder)
// ─────────────────────────────────────────────────────────────────────────────
void loop() {
    IWatchdog.reload();

    // Phase 1: Wait for POLL from tag, send RESP with T2/T3 timestamps
    bool got_poll = wait_for_poll_and_respond();

    if (got_poll) {
        // Phase 2: Wait for encrypted FINAL from tag
        // DW3000 is already in RX (auto-enabled by DWT_RESPONSE_EXPECTED in phase 1)
        wait_for_final_and_process();
    }

    // Update relay (handles signal timeout → lock)
    update_relay();

    // Re-enable continuous RX for next POLL (no timeout while waiting)
    dwt_setrxtimeout(0);
    dwt_rxenable(DWT_START_RX_IMMEDIATE);

    IWatchdog.reload();
}

// ─────────────────────────────────────────────────────────────────────────────
// BUILD 13-BYTE CCM* NONCE
// ─────────────────────────────────────────────────────────────────────────────
void build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_bytes) {
    nonce[0]  = (uint8_t)(TAG_ADDR    & 0xFF);
    nonce[1]  = (uint8_t)(TAG_ADDR    >> 8);
    nonce[2]  = (uint8_t)(ANCHOR_ADDR & 0xFF);
    nonce[3]  = (uint8_t)(ANCHOR_ADDR >> 8);
    nonce[4]  = seq;
    nonce[5]  = rand_bytes[0];
    nonce[6]  = rand_bytes[1];
    nonce[7]  = rand_bytes[2];
    nonce[8]  = rand_bytes[3];
    nonce[9]  = 0x00;
    nonce[10] = 0x00;
    nonce[11] = 0x00;
    nonce[12] = 0x00;
}

// ─────────────────────────────────────────────────────────────────────────────
// NONCE REPLAY PROTECTION
// ─────────────────────────────────────────────────────────────────────────────
bool is_nonce_replay(uint32_t nonce_word) {
    if (nonce_word == 0) return true;
    for (uint8_t i = 0; i < NONCE_HISTORY_SIZE; i++) {
        if (nonce_history[i] == nonce_word) return true;
    }
    return false;
}

void record_nonce(uint32_t nonce_word) {
    nonce_history[nonce_history_idx % NONCE_HISTORY_SIZE] = nonce_word;
    nonce_history_idx++;
}

// ─────────────────────────────────────────────────────────────────────────────
// INIT DW3000
// ─────────────────────────────────────────────────────────────────────────────
void init_dw3000(void) {
    digitalWrite(PIN_DW_RST, LOW);
    delay(2);
    digitalWrite(PIN_DW_RST, HIGH);
    delay(5);

    int max_tries = 100;
    while (!dwt_checkidlerc() && --max_tries > 0) {
        delay(1);
    }
    if (max_tries == 0) {
        print_debug("DW3000 IDLE check failed");
        while (1) { IWatchdog.reload(); delay(100); }
    }

    if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR) {
        print_debug("DW3000 Init failed");
        while (1) { IWatchdog.reload(); delay(100); }
    }

    dwt_setleds(DWT_LEDS_ENABLE | DWT_LEDS_INIT_BLINK);

    if (dwt_configure(&config)) {
        print_debug("DW3000 Config failed");
        while (1) { IWatchdog.reload(); delay(100); }
    }

    dwt_configuretxrf(&txconfig_options);
    dwt_setrxantennadelay(RX_ANT_DLY);
    dwt_settxantennadelay(TX_ANT_DLY);
    dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);

    // Frame filter: accept frames destined to ANCHOR_ADDR
    // (both POLL and FINAL come from TAG_ADDR to ANCHOR_ADDR)
    dwt_configureframefilter(DWT_FF_DATA_EN | DWT_FF_ACK_EN, 0);
    dwt_setpanid(PAN_ID);
    dwt_setaddress16(ANCHOR_ADDR);

    // Start continuous RX (no timeout while waiting for POLL)
    dwt_setrxtimeout(0);
    dwt_rxenable(DWT_START_RX_IMMEDIATE);

    print_debug("DW3000 Initialized OK – in continuous RX");
}

// ─────────────────────────────────────────────────────────────────────────────
// WAIT FOR POLL FROM TAG AND SEND PLAIN RESP
//
// Blocks until a POLL arrives (up to POLL_WAIT_TIMEOUT_MS ms) or returns false.
// On POLL received:
//   - Records T2 = anchor_poll_rx_ts (40-bit DW3000 RX timestamp)
//   - Builds 17-byte RESP frame embedding T2 and T3
//   - Sends RESP with delayed TX + DWT_RESPONSE_EXPECTED (DW3000 auto-enables
//     RX for the tag's subsequent FINAL frame, using FINAL_WAIT_TIMEOUT_UUS)
//   - Records T3 = anchor_resp_tx_ts
// ─────────────────────────────────────────────────────────────────────────────
bool wait_for_poll_and_respond(void) {
    uint32_t status_reg;
    uint32_t deadline = millis() + POLL_WAIT_TIMEOUT_MS;

    while (millis() < deadline) {
        IWatchdog.reload();
        status_reg = dwt_read32bitreg(SYS_STATUS_ID);

        if (status_reg & SYS_STATUS_RXFCG_BIT_MASK) {
            uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
            dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

            // POLL from tag: 13 data bytes + 2 FCS = 15 total from FINFO
            // Accept range [13..POLL_FRAME_LEN+2] to handle slight length variation
            if (frame_len < (uint32_t)(POLL_FRAME_LEN + 2) ||
                frame_len > (uint32_t)(POLL_FRAME_LEN + 4)) {
                // Not a POLL – might be noise or FINAL from a previous cycle
                dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
                dwt_rxenable(DWT_START_RX_IMMEDIATE);
                continue;
            }

            dwt_readrxdata(rx_buffer, frame_len - 2, 0);

            // Verify 'POLL' magic at bytes [9..12]
            if (rx_buffer[9]  != 'P' || rx_buffer[10] != 'O' ||
                rx_buffer[11] != 'L' || rx_buffer[12] != 'L') {
                dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
                dwt_rxenable(DWT_START_RX_IMMEDIATE);
                continue;
            }

            // T2 – anchor's timestamp of receiving POLL
            anchor_poll_rx_ts = get_rx_timestamp_u64();

            // Compute RESP TX time (delayed after POLL RX)
            uint32_t resp_tx_time = (uint32_t)(
                (anchor_poll_rx_ts +
                 ((uint64_t)POLL_RX_TO_RESP_TX_DLY_UUS * UUS_TO_DWT_TIME))
                >> 8);
            dwt_setdelayedtrxtime(resp_tx_time);

            // T3 – anchor's intended RESP TX timestamp (pre-computed)
            anchor_resp_tx_ts = (((uint64_t)(resp_tx_time & 0xFFFFFFFEUL)) << 8)
                                + TX_ANT_DLY;

            // Build plain RESP frame: [MAC 9B][T2:4B][T3:4B] = 17B
            uint8_t resp_frame[RESP_FRAME_LEN];
            uint8_t ri = 0;
            resp_frame[ri++] = 0x41;
            resp_frame[ri++] = 0x88;
            resp_frame[ri++] = rx_buffer[2] + 1;              // SEQ from POLL + 1
            resp_frame[ri++] = (uint8_t)(PAN_ID    & 0xFF);
            resp_frame[ri++] = (uint8_t)(PAN_ID    >> 8);
            resp_frame[ri++] = (uint8_t)(TAG_ADDR  & 0xFF);   // DST = tag
            resp_frame[ri++] = (uint8_t)(TAG_ADDR  >> 8);
            resp_frame[ri++] = (uint8_t)(ANCHOR_ADDR & 0xFF); // SRC = anchor
            resp_frame[ri++] = (uint8_t)(ANCHOR_ADDR >> 8);
            // T2 (anchor_poll_rx_ts) bytes [9..12]
            resp_frame[ri++] = (uint8_t)((anchor_poll_rx_ts >>  0) & 0xFF);
            resp_frame[ri++] = (uint8_t)((anchor_poll_rx_ts >>  8) & 0xFF);
            resp_frame[ri++] = (uint8_t)((anchor_poll_rx_ts >> 16) & 0xFF);
            resp_frame[ri++] = (uint8_t)((anchor_poll_rx_ts >> 24) & 0xFF);
            // T3 (anchor_resp_tx_ts) bytes [13..16]
            resp_frame[ri++] = (uint8_t)((anchor_resp_tx_ts >>  0) & 0xFF);
            resp_frame[ri++] = (uint8_t)((anchor_resp_tx_ts >>  8) & 0xFF);
            resp_frame[ri++] = (uint8_t)((anchor_resp_tx_ts >> 16) & 0xFF);
            resp_frame[ri++] = (uint8_t)((anchor_resp_tx_ts >> 24) & 0xFF);
            // ri == 17

            // Set FINAL RX timeout (applies to auto-RX after RESP TX)
            dwt_setrxtimeout(FINAL_WAIT_TIMEOUT_UUS);

            dwt_writetxdata(ri, resp_frame, 0);
            dwt_writetxfctrl(ri, 0, 1);  // ranging = 1

            // Send RESP (delayed) and auto-enable RX for FINAL
            int ret = dwt_starttx(DWT_START_TX_DELAYED | DWT_RESPONSE_EXPECTED);
            if (ret != DWT_SUCCESS) {
                // Delayed TX failed (timing too tight) – go back to RX
                dwt_rxenable(DWT_START_RX_IMMEDIATE);
                return false;
            }

            return true;
        }

        if (status_reg & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
            dwt_write32bitreg(SYS_STATUS_ID,
                              SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
            dwt_rxenable(DWT_START_RX_IMMEDIATE);
        }

        delay(1);
    }

    return false;   // Timeout: no POLL received within POLL_WAIT_TIMEOUT_MS
}

// ─────────────────────────────────────────────────────────────────────────────
// WAIT FOR FINAL FROM TAG AND PROCESS IT
//
// DW3000 is already in RX (auto-enabled by wait_for_poll_and_respond).
// Waits for FINAL frame with FINAL_WAIT_TIMEOUT_UUS timeout.
// On FINAL received:
//   - Extracts T1 (tag poll TX ts) and T4 (tag resp RX ts) from FINAL header
//   - Uses T2, T3 (stored by wait_for_poll_and_respond) to compute DS-TWR distance
//   - Runs AKF, decrypts and verifies AES-CCM* payload, cross-checks DIST
//   - Updates relay and sends UART status
// ─────────────────────────────────────────────────────────────────────────────
bool wait_for_final_and_process(void) {
    uint32_t status_reg;
    uint32_t t_start = millis();

    // Wall-clock guard: FINAL_WAIT_TIMEOUT_UUS + margin → 15ms
    while (millis() - t_start < 15) {
        status_reg = dwt_read32bitreg(SYS_STATUS_ID);

        if (status_reg & SYS_STATUS_RXFCG_BIT_MASK) {
            uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
            dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

            // FINAL must be at least: HEADER_LEN(21) + 1 payload + MIC(4) + FCS(2) = 28
            if (frame_len < (uint32_t)(HEADER_LEN + MIC_LEN + 3) ||
                frame_len > RX_BUF_LEN) {
                dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
                return false;
            }

            dwt_readrxdata(rx_buffer, frame_len - 2, 0);

            // Extract T1 (tag poll TX ts) from FINAL header bytes [9..12]
            uint64_t t1_tag = ((uint64_t)rx_buffer[9]  <<  0) |
                              ((uint64_t)rx_buffer[10] <<  8) |
                              ((uint64_t)rx_buffer[11] << 16) |
                              ((uint64_t)rx_buffer[12] << 24);

            // Extract T4 (tag resp RX ts) from FINAL header bytes [13..16]
            uint64_t t4_tag = ((uint64_t)rx_buffer[13] <<  0) |
                              ((uint64_t)rx_buffer[14] <<  8) |
                              ((uint64_t)rx_buffer[15] << 16) |
                              ((uint64_t)rx_buffer[16] << 24);

            // ── DS-TWR distance computation ───────────────────────────────────
            // rtd_tag  = T4 - T1  (tag's round-trip from TX POLL to RX RESP)
            // rtd_anch = T3 - T2  (anchor's reply time from RX POLL to TX RESP)
            // ToF = (rtd_tag - rtd_anch * (1 - clkOffset)) / 2
            int64_t rtd_tag  = (int64_t)(t4_tag             - t1_tag);
            int64_t rtd_anch = (int64_t)(anchor_resp_tx_ts  - anchor_poll_rx_ts);
            float   clk_off  = ((float)dwt_readclockoffset()) / (float)(1UL << 26);
            double  tof      = ((rtd_tag - rtd_anch * (1.0 - clk_off)) / 2.0)
                               * DWT_TIME_UNITS;
            double  dist_raw = tof * SPEED_OF_LIGHT;

            if (dist_raw < 0.0 || dist_raw > 100.0) {
                dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
                return false;
            }

            // ── Adaptive Kalman Filter ────────────────────────────────────────
            float dist_kf = akf_update(&kf, (float)dist_raw);
            if (dist_kf < 0.0f) {
                send_error("GATE");
                return false;
            }

            // ── AES-CCM* decrypt + nonce replay check + dist cross-check ─────
            uint8_t seq = rx_buffer[2];
            bool ok = decrypt_and_verify_payload(rx_buffer, frame_len - 2,
                                                 dist_raw, seq);
            if (ok) {
                last_distance_raw = dist_raw;
                last_distance_kf  = dist_kf;
                last_signal_ms    = millis();
            }
            return ok;
        }

        if (status_reg & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
            dwt_write32bitreg(SYS_STATUS_ID,
                              SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
            return false;
        }

        delay(1);
    }

    return false;   // Timeout: no FINAL received
}

// ─────────────────────────────────────────────────────────────────────────────
// DECRYPT AND VERIFY AES-CCM* FINAL PAYLOAD
//
// FINAL frame header layout (v3):
//   [MAC 9B][T1/poll_tx_ts:4B][T4/resp_rx_ts:4B][rand_nonce:4B] = 21B AAD
//   [AES-CCM*(CMD:OPEN|DIST:x.xx|BAT:nnn)][MIC:4B]
//
// measured_dist: anchor-computed distance from DS-TWR timestamps (metres).
// Security cross-check: compare measured_dist to DIST field in decrypted
// payload.  If they differ by more than DIST_XCHECK_TOL_M, reject the frame
// (an attacker who modifies T1/T4 in the unencrypted header cannot also forge
// the DIST in the AES-protected payload).
// ─────────────────────────────────────────────────────────────────────────────
bool decrypt_and_verify_payload(uint8_t *rx_data, uint32_t data_len,
                                double measured_dist, uint8_t seq) {
    if (data_len < (uint32_t)(HEADER_LEN + MIC_LEN + 1)) {
        return false;
    }

    // Random nonce is at bytes [17..20] of the FINAL header (unchanged from v2)
    uint8_t rand_nonce[4];
    rand_nonce[0] = rx_data[17];
    rand_nonce[1] = rx_data[18];
    rand_nonce[2] = rx_data[19];
    rand_nonce[3] = rx_data[20];

    uint32_t nonce_word = ((uint32_t)rand_nonce[0]      ) |
                          ((uint32_t)rand_nonce[1] <<  8 ) |
                          ((uint32_t)rand_nonce[2] << 16 ) |
                          ((uint32_t)rand_nonce[3] << 24 );

    if (is_nonce_replay(nonce_word)) {
        send_error("REPLAY");
        return false;
    }

    uint16_t payload_len = (uint16_t)(data_len - HEADER_LEN - MIC_LEN);

    uint8_t ccm_nonce[13];
    build_ccm_nonce(ccm_nonce, seq, rand_nonce);

    dwt_set_keyreg_128(&aes_key);

    dwt_aes_config_t aes_cfg;
    aes_cfg.aes_key_otp_type = AES_key_RAM;
    aes_cfg.aes_core_type    = AES_core_type_CCM;
    aes_cfg.mic              = MIC_4;
    aes_cfg.key_src          = AES_KEY_Src_Register;
    aes_cfg.key_load         = AES_KEY_No_Load;
    aes_cfg.key_addr         = 0;
    aes_cfg.key_size         = AES_KEY_128bit;
    aes_cfg.mode             = AES_Decrypt;
    dwt_configure_aes(&aes_cfg);

    uint8_t decrypted[PAYLOAD_MAX_LEN + 1];
    memset(decrypted, 0, sizeof(decrypted));

    dwt_aes_job_t aes_job;
    aes_job.nonce       = ccm_nonce;
    aes_job.header      = rx_data;
    aes_job.header_len  = HEADER_LEN;
    aes_job.payload     = decrypted;
    aes_job.payload_len = payload_len;
    aes_job.src_port    = AES_Src_Rx_buf_0;
    aes_job.dst_port    = AES_Dst_Scratch;
    aes_job.mode        = AES_Decrypt;
    aes_job.mic_size    = MIC_LEN;

    int8_t aes_ret = dwt_do_aes(&aes_job, AES_core_type_CCM);
    if (aes_ret < 0 || (aes_ret & AES_STS_ERROR_MASK) != 0) {
        send_error("DECRYPT");
        return false;
    }

    decrypted[payload_len] = '\0';

    bool cmd_open = (strstr((char *)decrypted, "CMD:OPEN") != NULL);
    if (!cmd_open) {
        send_error("CMD");
        return false;
    }

    // ── Distance cross-check ─────────────────────────────────────────────────
    // The tag computed its own DS-TWR distance and embedded it in the encrypted
    // payload as "DIST:x.xx".  Compare to the anchor's independent computation.
    // A forgery that manipulates T1/T4 in the unencrypted header will produce a
    // mismatch here because the DIST in the AES payload is unforgeable.
    char *dist_p = strstr((char *)decrypted, "DIST:");
    if (dist_p != NULL) {
        double payload_dist = atof(dist_p + 5);
        double diff = measured_dist - payload_dist;
        if (diff < 0.0) diff = -diff;
        if (diff > (double)DIST_XCHECK_TOL_M) {
            send_error("XDIST");
            return false;
        }
    }

    char *bat_p = strstr((char *)decrypted, "BAT:");
    if (bat_p != NULL) {
        last_bat_pct = (uint8_t)atoi(bat_p + 4);
    }

    record_nonce(nonce_word);

    // Use KF-filtered distance for unlock decision
    const char *key_str = (last_distance_kf >= 0.0f &&
                           last_distance_kf < DIST_THRESHOLD_ON) ? "ON" : "OFF";
    send_status(key_str, measured_dist, last_distance_kf, last_bat_pct);

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// UPDATE RELAY STATE (hysteresis on KF-filtered distance)
// ─────────────────────────────────────────────────────────────────────────────
void update_relay(void) {
    uint32_t now = millis();
    bool new_state = relay_state;

    if (now - last_signal_ms > SIGNAL_TIMEOUT_MS) {
        new_state = false;
    } else if (last_distance_kf >= 0.0f) {
        if (!relay_state && last_distance_kf < DIST_THRESHOLD_ON) {
            new_state = true;
        } else if (relay_state && last_distance_kf > DIST_THRESHOLD_OFF) {
            new_state = false;
        }
    }

    if (new_state != relay_state) {
        relay_state = new_state;
        digitalWrite(PIN_RELAY, relay_state ? HIGH : LOW);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEND EXTENDED STATUS TO ESP32-S3
// Format: "STATUS:KEY=ON|DIST=1.23|KF=1.21|Q=0.0010|R=0.0500|BAT=85\r\n"
// ─────────────────────────────────────────────────────────────────────────────
void send_status(const char *key_str, double dist_raw, float dist_kf, uint8_t bat) {
    char buf[96];
    int  raw_int  = (dist_raw >= 0.0) ? (int)dist_raw            : -1;
    int  raw_frac = (dist_raw >= 0.0) ? (int)((dist_raw - (int)dist_raw) * 100.0) : 0;
    if (raw_frac < 0) raw_frac = -raw_frac;
    int  kf_int   = (dist_kf >= 0.0f) ? (int)dist_kf             : -1;
    int  kf_frac  = (dist_kf >= 0.0f) ? (int)((dist_kf - (int)dist_kf) * 100.0f) : 0;

    snprintf(buf, sizeof(buf),
             "STATUS:KEY=%s|DIST=%d.%02d|KF=%d.%02d|Q=%.4f|R=%.4f|BAT=%u\r\n",
             key_str,
             raw_int, raw_frac,
             kf_int,  kf_frac,
             (double)kf.Q,
             (double)kf.R,
             (unsigned)bat);
    Serial1.print(buf);
    Serial1.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// SEND ERROR TO ESP32-S3
// ─────────────────────────────────────────────────────────────────────────────
void send_error(const char *err) {
    char buf[32];
    snprintf(buf, sizeof(buf), "ERR:%s\r\n", err);
    Serial1.print(buf);
    Serial1.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// DEBUG PRINT (USB CDC Serial on F411)
// ─────────────────────────────────────────────────────────────────────────────
void print_debug(const char *msg) {
    Serial.println(msg);
}

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * MIGRATION NOTES: F103 → F411
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Board package: Install "STM32 Cores" by STMicroelectronics in Arduino IDE
 *    Boards Manager.  Select: STM32F4xx → Generic F4 series → STM32F411CE.
 * 2. Upload: STM32CubeProgrammer via DFU (hold BOOT0, press RST, release BOOT0)
 *    or ST-Link SWD (PA13=SWDIO, PA14=SWCLK).
 * 3. FPU: STM32duino enables the Cortex-M4F FPU automatically.  All float
 *    operations in akf_update() execute as single HW instructions.
 * 4. UART: Serial1 = UART1 (PA9/PA10) – same as F103.  Serial = USB CDC.
 * 5. Watchdog: IWatchdog.begin(8000000) and IWatchdog.reload() unchanged.
 * 6. SPI: SPI1 pins PA4-PA7 unchanged.
 * 7. Flash / EEPROM: F411 has no data EEPROM.  For learned KF parameters to
 *    survive a power cycle, use the STM32duino EEPROM emulation library
 *    (stores Q/R in a dedicated Flash page).  By default, the filter re-learns
 *    from scratch on every boot (~7 measurements to converge at 3s interval).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ROLE SWAP (v2 → v3): ANCHOR NOW RESPONDS, TAG INITIATES
 * ─────────────────────────────────────────────────────────────────────────────
 * The main loop changed from "send POLL every 100ms" to "wait for tag POLL,
 * send RESP, wait for encrypted FINAL".  This means:
 *
 * 1. Update rate: 10 Hz → 0.33 Hz (POLL_INTERVAL_S=3 in tagc3.ino).
 *    AKF re-tuned: AKF_ALPHA=0.15 (was 0.05), AKF_Q_INIT=0.050 (was 0.001).
 *    Convergence: ~7 cycles × 3 s ≈ 21 s (was ~2 s).
 *
 * 2. Relay response latency: up to POLL_INTERVAL_S seconds.
 *    To halve latency, set POLL_INTERVAL_S=1 in tagc3.ino (tag uses ~1.4 mA).
 *
 * 3. SIGNAL_TIMEOUT_MS=10000 (10 s): relay stays ON through up to 3 missed
 *    poll cycles before forcing lock.
 *
 * 4. Anchor DW3000 continuous RX: ~60 mA constant.  Acceptable on motorcycle
 *    battery/alternator; do NOT use this firmware on a small coin cell anchor.
 *
 * 5. Distance cross-check (DIST_XCHECK_TOL_M=0.5 m): rejects frames where the
 *    anchor-computed DS-TWR distance and the tag's self-reported DIST differ by
 *    more than 0.5 m.  This catches header-manipulation attacks.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ADAPTIVE FILTER CONVERGENCE & BEHAVIOUR (at 3s update rate)
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Boot (uninitialised): first raw measurement seeds x directly.
 * 2. Convergence (~7 cycles @ 3 s = 21 s): Q and R stabilise around the
 *    actual noise level of your specific RF environment and PCB layout.
 * 3. Open space: R converges low (≈ DW3000 spec ±15 cm) → tight tracking.
 * 4. Reflective environment (garage, metal frame): R converges higher → smoother
 *    output, some lag, but far fewer false unlock/lock transitions.
 * 5. Tag moving (e.g. approaching the bike): K increases → Q increases →
 *    filter tracks faster even at 3 s intervals.
 * 6. Outlier gate (AKF_GATE=4): rejects multipath spikes > 4σ.
 *    Increase (e.g. 5) if valid fast movements are being gated.
 *    Decrease (e.g. 3) in very clean environments.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * UWB ON SMARTPHONE – CONNECTION OPTIONS
 * ─────────────────────────────────────────────────────────────────────────────
 * Option A – Gateway BLE bridge (recommended, works with any phone):
 *   ESP32-S3 runs a BLE GATT server (NUS / custom service).
 *   Phone app reads UWB distance JSON over BLE.
 *   No native UWB hardware required on the phone.
 *   → See esps3.ino comments for BLE NUS implementation.
 *
 * Option B – Native Android UWB API (Android 12+):
 *   Phones with UWB hardware (Samsung Galaxy S21 Ultra / S22+, Pixel 6 Pro+,
 *   Pixel 7 Pro+, some OnePlus / Xiaomi flagships).
 *   Android uses the FiRa Consortium FIRA_PHY / FIRA_MAC ranging stack.
 *   DW3000 supports FiRa; implement FiRa Controller (anchor) role here.
 *   → Requires Qorvo FiRa-certified SDK or open-source FiRa stack.
 *
 * Option C – Apple Nearby Interaction (iOS 14+, iPhone 11+):
 *   iPhone U1/H1 chip speaks UWB.  Accessories must be in Apple MFi program
 *   with Qorvo QM33120W / MDEK1001 and Apple-specific firmware.
 *   → Requires Apple MFi agreement + Qorvo SDK + certification.
 *
 * Option D – Smartphone as tag (replaces ESP32-C3 + DW3000 fob):
 *   Android 12+ android.uwb API: phone acts as initiator against this anchor.
 *   Implement FiRa Responder role on this anchor board.
 *   Practical: Option A (Gateway BLE) works in <1 day with any phone.
 */
