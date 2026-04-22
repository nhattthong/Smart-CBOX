/*
 * Smart Moto Security – ESP32-C3 REMOTE TAG (SmartKey Fob)
 * Version 3.0 – UWB TWR Initiator, Timer Deep-Sleep, AES-CCM* FINAL Frame
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Role change v2 → v3 (power-saving role swap):
 * ─────────────────────────────────────────────────────────────────────────────
 *   v2: Tag = TWR Responder. DW3000 left in continuous RX (~60 mA) while
 *       ESP32-C3 deep-sleeps. Woken by anchor POLL every 100 ms via GPIO IRQ.
 *       Average tag current ≈ 60 mA → ~17 h on 1000 mAh. VERY POOR.
 *
 *   v3: Tag = TWR Initiator. ESP32-C3 wakes by hardware timer every
 *       POLL_INTERVAL_S seconds. Runs one full 3-frame ranging cycle, then
 *       pulls DW3000 RST low (≈100 µA in reset) and sleeps again.
 *       Average tag current ≈ 0.5 mA → ~2000 h (83 days) on 1000 mAh.
 *
 *   The anchor (STM32F411) stays in continuous DW3000 RX – fine, it is
 *   permanently powered by the motorcycle's battery / charging system.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * 3-frame Double-Sided TWR protocol (tag initiates):
 * ─────────────────────────────────────────────────────────────────────────────
 *   Frame 1  TAG → ANCHOR : POLL  (short 13-byte beacon)
 *     T1 = tag poll TX timestamp (read from DW3000 after TX, stored in RTC RAM)
 *
 *   Frame 2  ANCHOR → TAG : RESP  (17-byte plain frame, no AES)
 *     T2 = anchor poll RX timestamp  (embedded in RESP body bytes [9..12])
 *     T3 = anchor resp TX timestamp  (embedded in RESP body bytes [13..16])
 *
 *   Frame 3  TAG → ANCHOR : FINAL (AES-CCM* encrypted, 21B AAD + payload + 4B MIC)
 *     T4 = tag resp RX timestamp     (embedded in FINAL header bytes [13..16])
 *     T1 = tag poll TX timestamp     (embedded in FINAL header bytes [ 9..12])
 *     CMD:OPEN|DIST:x.xx|BAT:nnn    (AES-encrypted payload)
 *
 *   Distance (computed on ANCHOR from T1, T2, T3, T4):
 *     ToF = ((T4-T1) - (T3-T2) * (1 - clkOffset)) / 2
 *     dist = ToF * DWT_TIME_UNITS * SPEED_OF_LIGHT
 *
 *   Security cross-check: anchor also compares computed dist to DIST field
 *   in the encrypted payload (tag's own calculation). If they differ by >0.5 m
 *   the frame is rejected (forgery attempt on unencrypted timestamps).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Hardware (unchanged from v2):
 * ─────────────────────────────────────────────────────────────────────────────
 *   - ESP32-C3 (single core, ultra-low power)
 *   - DW3000 UWB Module (SPI + IRQ + RST)
 *   - Battery voltage divider: VBAT → R1(100k) → GPIO0 → R2(100k) → GND
 *
 * Pinout:
 *   SPI: SCK=4, MISO=5, MOSI=6, CS=7
 *   DW3000: IRQ=2, RST=3
 *   Battery ADC: GPIO0 (ADC1_CH0, 1:2 divider)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Security:
 * ─────────────────────────────────────────────────────────────────────────────
 *   - Pre-shared AES-128 key (must match f411.ino)
 *   - 4-byte random nonce (esp_random) per FINAL frame
 *   - CCM* nonce: [TAG_ADDR(2)][ANC_ADDR(2)][SEQ(1)][RAND(4)][zeros(4)] = 13B
 *   - Replay protection on anchor side (nonce history ring buffer)
 *   - Distance cross-check: anchor independently verifies DIST field
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * FINAL Frame Layout (21B AAD header + encrypted + 4B MIC):
 * ─────────────────────────────────────────────────────────────────────────────
 *   [FC:2][SEQ:1][PAN:2][DST=ANCHOR:2][SRC=TAG:2] = 9B MAC header
 *   [poll_tx_ts/T1: 4B][resp_rx_ts/T4: 4B][rand_nonce: 4B]         = 12B
 *   Total AAD = 21B
 *   [AES-CCM*(CMD:OPEN|DIST:x.xx|BAT:nnn)][MIC: 4B]
 */

#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"
#include <math.h>
#include <esp32-hal.h>
#include <esp_random.h>
#include <driver/adc.h>

// ─── CONFIGURATION ───────────────────────────────────────────────────────────
#define APP_NAME          "SmartKey Tag v3.0"
#define ANCHOR_ADDR       0x1111
#define TAG_ADDR          0x2222
#define PAN_ID            0x3412
#define MIC_LEN           4
#define PAYLOAD_MAX_LEN   36

// Deep-sleep interval between TX cycles (seconds).
// Lower → faster relay response but more power.
//   1s ≈ 1.4 mA avg;  2s ≈ 0.75 mA avg;  3s ≈ 0.5 mA avg (default).
#define POLL_INTERVAL_S   3

// UWB timing ──────────────────────────────────────────────────────────────────
// How long the tag waits (after POLL TX) for the anchor's RESP frame.
// Must be > POLL_RX_TO_RESP_TX_DLY_UUS (set in f411.ino = 2000 µs) + 2×ToF.
#define RESP_WAIT_TIMEOUT_UUS       3500

// How long after RESP RX the tag waits before sending FINAL.
// Gives time for: read battery ADC + build payload + AES encrypt on DW3000 HW.
#define RESP_RX_TO_FINAL_TX_DLY_UUS 6000

#define TX_ANT_DLY    16385
#define RX_ANT_DLY    16385
#define RX_BUF_LEN    127

// RESP frame from anchor: 17 data bytes (no FCS)
// [MAC 9B][poll_rx_ts 4B][resp_tx_ts 4B] = 17B
#define RESP_FRAME_BODY_LEN  17

// ─── AES-128 PRE-SHARED KEY (must match f411.ino) ────────────────────────────
// *** CHANGE THIS KEY BEFORE DEPLOYMENT ***
// Generate: python3 -c "import os; d=os.urandom(16); \
//   print(','.join(hex(int.from_bytes(d[i:i+4],'big'))+'UL' for i in range(0,16,4)))"
static const dwt_aes_key_t aes_key = {
    0xAABBCCDDUL, 0xEEFF0011UL, 0x22334455UL, 0x66778899UL,
    0, 0, 0, 0
};

// Static assertion: calibration sanity check
static_assert(BAT_ADC_FULL != BAT_ADC_EMPTY, "BAT ADC calibration error: FULL == EMPTY");

// ─── PIN DEFINITIONS ─────────────────────────────────────────────────────────
const uint8_t PIN_DW_CS   = 7;
const uint8_t PIN_DW_IRQ  = 2;
const uint8_t PIN_DW_RST  = 3;
const uint8_t PIN_BAT_ADC = 0;   // GPIO0 = ADC1_CH0, 1:2 voltage divider

// ─── BATTERY ADC CALIBRATION ─────────────────────────────────────────────────
// Voltage divider 1:2, ADC 12-bit (4095 = 3.3V)
// 4.2V full → 2.1V → ~2607; 3.3V empty → 1.65V → ~2048
#define BAT_ADC_FULL  2607
#define BAT_ADC_EMPTY 2048

// ─── DW3000 CONFIG ────────────────────────────────────────────────────────────
static dwt_config_t config = {
    5,               // Channel 5 (6.49 GHz)
    DWT_PLEN_128,
    DWT_PAC8,
    9, 9,            // TX/RX preamble codes
    1,               // SFD type DW 8-bit
    DWT_BR_6M8,
    DWT_PHRMODE_STD,
    DWT_PHRRATE_STD,
    (129 + 8 - 8),
    DWT_STS_MODE_OFF,
    DWT_STS_LEN_64,
    DWT_PDOA_M0
};

// ─── GLOBAL STATE (persists across deep sleep in RTC SRAM) ───────────────────
RTC_DATA_ATTR static uint8_t  seq_num     = 0;     // Frame sequence number
RTC_DATA_ATTR static uint64_t poll_tx_ts  = 0;     // T1 – tag POLL TX timestamp
RTC_DATA_ATTR static uint64_t resp_rx_ts  = 0;     // T4 – tag RESP RX timestamp
RTC_DATA_ATTR static float    last_dist_m = 0.0f;  // Last computed distance (m)
RTC_DATA_ATTR static uint32_t frame_count = 0;     // Total successful FINAL TX count

static uint8_t rx_buffer[RX_BUF_LEN];

// ─── FUNCTION PROTOTYPES ──────────────────────────────────────────────────────
void    init_dw3000(void);
void    enter_timer_sleep(void);
bool    run_ranging_cycle(void);
uint8_t read_battery_percent(void);
void    build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_nonce);

// ─────────────────────────────────────────────────────────────────────────────
// SETUP  (runs on every wakeup from timer deep sleep)
// ─────────────────────────────────────────────────────────────────────────────
void setup() {
    pinMode(PIN_DW_CS,  OUTPUT); digitalWrite(PIN_DW_CS,  HIGH);
    pinMode(PIN_DW_RST, OUTPUT); digitalWrite(PIN_DW_RST, HIGH);
    pinMode(PIN_DW_IRQ, INPUT);

    adc1_config_width(ADC_WIDTH_BIT_12);
    adc1_config_channel_atten(ADC1_CHANNEL_0, ADC_ATTEN_DB_11);

    init_dw3000();
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN LOOP
// ─────────────────────────────────────────────────────────────────────────────
void loop() {
    run_ranging_cycle();   // TX POLL → RX RESP → compute dist → TX FINAL
    enter_timer_sleep();   // DW3000 off, ESP32-C3 sleeps for POLL_INTERVAL_S
}

// ─────────────────────────────────────────────────────────────────────────────
// READ BATTERY PERCENT
// ─────────────────────────────────────────────────────────────────────────────
uint8_t read_battery_percent(void) {
    if (BAT_ADC_FULL == BAT_ADC_EMPTY) return 50;
    int raw = adc1_get_raw(ADC1_CHANNEL_0);
    int pct = (int)(((long)(raw - BAT_ADC_EMPTY) * 100L) / (BAT_ADC_FULL - BAT_ADC_EMPTY));
    if (pct < 0)   pct = 0;
    if (pct > 100) pct = 100;
    return (uint8_t)pct;
}

// ─────────────────────────────────────────────────────────────────────────────
// BUILD 13-BYTE CCM* NONCE
// Layout: [TAG_ADDR LE:2][ANC_ADDR LE:2][seq:1][rand:4][zeros:4]
// ─────────────────────────────────────────────────────────────────────────────
void build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_nonce) {
    nonce[0]  = (uint8_t)(TAG_ADDR    & 0xFF);
    nonce[1]  = (uint8_t)(TAG_ADDR    >> 8);
    nonce[2]  = (uint8_t)(ANCHOR_ADDR & 0xFF);
    nonce[3]  = (uint8_t)(ANCHOR_ADDR >> 8);
    nonce[4]  = seq;
    nonce[5]  = rand_nonce[0];
    nonce[6]  = rand_nonce[1];
    nonce[7]  = rand_nonce[2];
    nonce[8]  = rand_nonce[3];
    nonce[9]  = 0x00;
    nonce[10] = 0x00;
    nonce[11] = 0x00;
    nonce[12] = 0x00;
}

// ─────────────────────────────────────────────────────────────────────────────
// INIT DW3000
// ─────────────────────────────────────────────────────────────────────────────
void init_dw3000(void) {
    // Hard-reset DW3000
    digitalWrite(PIN_DW_RST, LOW);  delay(2);
    digitalWrite(PIN_DW_RST, HIGH); delay(5);

    int tries = 100;
    while (!dwt_checkidlerc() && --tries > 0) delay(1);
    if (tries == 0) { enter_timer_sleep(); }

    if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR) { enter_timer_sleep(); }
    if (dwt_configure(&config))                    { enter_timer_sleep(); }

    dwt_setrxantennadelay(RX_ANT_DLY);
    dwt_settxantennadelay(TX_ANT_DLY);
    dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);

    // Frame filter: accept frames addressed to TAG_ADDR (filters RESP from anchor)
    dwt_configureframefilter(DWT_FF_DATA_EN | DWT_FF_ACK_EN, 0);
    dwt_setpanid(PAN_ID);
    dwt_setaddress16(TAG_ADDR);
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTER TIMER DEEP SLEEP
// Pulls DW3000 RST low (~100 µA in reset) before sleeping.
// On wakeup, setup() calls init_dw3000() which de-asserts RST.
// ─────────────────────────────────────────────────────────────────────────────
void enter_timer_sleep(void) {
    // DW3000 into reset → ~100 µA (vs ~60 mA in RX mode)
    digitalWrite(PIN_DW_RST, LOW);

    esp_sleep_enable_timer_wakeup((uint64_t)POLL_INTERVAL_S * 1000000ULL);
    esp_deep_sleep_start();
    // Never reached
}

// ─────────────────────────────────────────────────────────────────────────────
// FULL 3-FRAME RANGING CYCLE
//
//  Frame 1: TX POLL         → anchor
//  Frame 2: RX RESP (plain) ← anchor (contains T2, T3)
//  Frame 3: TX FINAL (AES)  → anchor (contains T1, T4, CMD, DIST, BAT)
//
// Returns true if FINAL was sent successfully.
// ─────────────────────────────────────────────────────────────────────────────
bool run_ranging_cycle(void) {
    // ── Frame 1: Build and send POLL ──────────────────────────────────────────
    uint8_t poll_frame[13];
    uint8_t pi = 0;
    poll_frame[pi++] = 0x41;                          // FC0: data, 16-bit addr
    poll_frame[pi++] = 0x88;                          // FC1
    poll_frame[pi++] = seq_num;
    poll_frame[pi++] = (uint8_t)(PAN_ID      & 0xFF);
    poll_frame[pi++] = (uint8_t)(PAN_ID      >> 8);
    poll_frame[pi++] = (uint8_t)(ANCHOR_ADDR & 0xFF); // DST = anchor
    poll_frame[pi++] = (uint8_t)(ANCHOR_ADDR >> 8);
    poll_frame[pi++] = (uint8_t)(TAG_ADDR    & 0xFF); // SRC = this tag
    poll_frame[pi++] = (uint8_t)(TAG_ADDR    >> 8);
    poll_frame[pi++] = 'P'; poll_frame[pi++] = 'O';
    poll_frame[pi++] = 'L'; poll_frame[pi++] = 'L';
    // pi == 13

    // Set RX timeout for RESP before TX (applies after TX completes)
    dwt_setrxtimeout(RESP_WAIT_TIMEOUT_UUS);

    dwt_writetxdata(pi, poll_frame, 0);
    dwt_writetxfctrl(pi, 0, 1);  // ranging = 1

    // TX immediately, auto-enable RX after TX for RESP
    if (dwt_starttx(DWT_START_TX_IMMEDIATE | DWT_RESPONSE_EXPECTED) != DWT_SUCCESS) {
        return false;
    }

    // Wait for TX done, then record T1 = poll TX timestamp
    uint32_t t_start = millis();
    while (!(dwt_read32bitreg(SYS_STATUS_ID) & SYS_STATUS_TXFRS_BIT_MASK)) {
        if (millis() - t_start > 10) return false;
        delayMicroseconds(100);
    }
    poll_tx_ts = get_tx_timestamp_u64();   // T1
    dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_TXFRS_BIT_MASK);

    // ── Frame 2: Wait for RESP from anchor ────────────────────────────────────
    // DW3000 is now in RX mode (auto-enabled by DWT_RESPONSE_EXPECTED)
    uint32_t status_reg;
    t_start = millis();
    while (millis() - t_start < 10) {    // 10ms wall-clock fallback timeout
        status_reg = dwt_read32bitreg(SYS_STATUS_ID);

        if (status_reg & SYS_STATUS_RXFCG_BIT_MASK) {
            uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
            dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

            // RESP = 17 data bytes + 2 FCS = 19 total from DW3000 FINFO
            if (frame_len < (uint32_t)(RESP_FRAME_BODY_LEN + 2) ||
                frame_len > RX_BUF_LEN) {
                dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
                return false;
            }

            dwt_readrxdata(rx_buffer, frame_len - 2, 0);
            resp_rx_ts = get_rx_timestamp_u64();   // T4

            // Extract T2 (anchor poll_rx_ts) and T3 (anchor resp_tx_ts) from RESP body
            uint64_t t2_anchor = ((uint64_t)rx_buffer[9]  <<  0) |
                                 ((uint64_t)rx_buffer[10] <<  8) |
                                 ((uint64_t)rx_buffer[11] << 16) |
                                 ((uint64_t)rx_buffer[12] << 24);
            uint64_t t3_anchor = ((uint64_t)rx_buffer[13] <<  0) |
                                 ((uint64_t)rx_buffer[14] <<  8) |
                                 ((uint64_t)rx_buffer[15] << 16) |
                                 ((uint64_t)rx_buffer[16] << 24);

            // ── Compute distance (DS-TWR) ──────────────────────────────────────
            // rtd_tag  = T4 - T1  (tag's total round-trip time)
            // rtd_anch = T3 - T2  (anchor's reply processing time)
            // ToF = (rtd_tag - rtd_anch * (1 - clkOffset)) / 2
            int64_t rtd_tag  = (int64_t)(resp_rx_ts - poll_tx_ts);
            int64_t rtd_anch = (int64_t)(t3_anchor  - t2_anchor);
            float   clk_off  = ((float)dwt_readclockoffset()) / (float)(1UL << 26);
            double  tof      = ((rtd_tag - rtd_anch * (1.0 - clk_off)) / 2.0)
                               * DWT_TIME_UNITS;
            double  dist_m   = tof * SPEED_OF_LIGHT;

            if (dist_m < 0.0 || dist_m > 100.0) {
                dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
                return false;
            }
            last_dist_m = (float)dist_m;

            // ── Frame 3: Build encrypted FINAL and send ────────────────────────
            // Random nonce (non-zero for replay protection on anchor side)
            uint32_t rand_word;
            do { rand_word = esp_random(); } while (rand_word == 0);
            uint8_t rand_nonce[4] = {
                (uint8_t)( rand_word        & 0xFF),
                (uint8_t)((rand_word >>  8) & 0xFF),
                (uint8_t)((rand_word >> 16) & 0xFF),
                (uint8_t)((rand_word >> 24) & 0xFF)
            };

            uint8_t seq_final = seq_num + 1;

            // FINAL AAD header (21 bytes):
            // [MAC Hdr 9B][T1/poll_tx_ts 4B][T4/resp_rx_ts 4B][nonce 4B]
            uint8_t header[21];
            uint8_t hi = 0;
            header[hi++] = 0x41;
            header[hi++] = 0x88;
            header[hi++] = seq_final;
            header[hi++] = (uint8_t)(PAN_ID      & 0xFF);
            header[hi++] = (uint8_t)(PAN_ID      >> 8);
            header[hi++] = (uint8_t)(ANCHOR_ADDR & 0xFF);  // DST = anchor
            header[hi++] = (uint8_t)(ANCHOR_ADDR >> 8);
            header[hi++] = (uint8_t)(TAG_ADDR    & 0xFF);  // SRC = tag
            header[hi++] = (uint8_t)(TAG_ADDR    >> 8);
            // T1 (poll_tx_ts) bytes [9..12]
            header[hi++] = (uint8_t)((poll_tx_ts >>  0) & 0xFF);
            header[hi++] = (uint8_t)((poll_tx_ts >>  8) & 0xFF);
            header[hi++] = (uint8_t)((poll_tx_ts >> 16) & 0xFF);
            header[hi++] = (uint8_t)((poll_tx_ts >> 24) & 0xFF);
            // T4 (resp_rx_ts) bytes [13..16]
            header[hi++] = (uint8_t)((resp_rx_ts >>  0) & 0xFF);
            header[hi++] = (uint8_t)((resp_rx_ts >>  8) & 0xFF);
            header[hi++] = (uint8_t)((resp_rx_ts >> 16) & 0xFF);
            header[hi++] = (uint8_t)((resp_rx_ts >> 24) & 0xFF);
            // Random nonce bytes [17..20]
            header[hi++] = rand_nonce[0];
            header[hi++] = rand_nonce[1];
            header[hi++] = rand_nonce[2];
            header[hi++] = rand_nonce[3];
            // hi == 21

            // Plaintext payload: "CMD:OPEN|DIST:x.xx|BAT:nnn"
            uint8_t bat_pct = read_battery_percent();
            char payload_str[PAYLOAD_MAX_LEN + 1];
            int d_int  = (int)last_dist_m;
            int d_frac = (int)((last_dist_m - (float)d_int) * 100.0f);
            snprintf(payload_str, sizeof(payload_str),
                     "CMD:OPEN|DIST:%d.%02d|BAT:%u",
                     d_int, d_frac, (unsigned)bat_pct);
            uint16_t payload_len = (uint16_t)strlen(payload_str);

            // CCM* nonce (13 bytes)
            uint8_t ccm_nonce[13];
            build_ccm_nonce(ccm_nonce, seq_final, rand_nonce);

            // Configure DW3000 AES engine (hardware encrypt)
            dwt_set_keyreg_128(&aes_key);
            dwt_aes_config_t aes_cfg;
            aes_cfg.aes_key_otp_type = AES_key_RAM;
            aes_cfg.aes_core_type    = AES_core_type_CCM;
            aes_cfg.mic              = MIC_4;
            aes_cfg.key_src          = AES_KEY_Src_Register;
            aes_cfg.key_load         = AES_KEY_No_Load;
            aes_cfg.key_addr         = 0;
            aes_cfg.key_size         = AES_KEY_128bit;
            aes_cfg.mode             = AES_Encrypt;
            dwt_configure_aes(&aes_cfg);

            // AES-CCM* encrypt → DW3000 TX buffer
            dwt_aes_job_t aes_job;
            aes_job.nonce       = ccm_nonce;
            aes_job.header      = header;
            aes_job.header_len  = hi;
            aes_job.payload     = (uint8_t *)payload_str;
            aes_job.payload_len = payload_len;
            aes_job.src_port    = AES_Src_Scratch;
            aes_job.dst_port    = AES_Dst_Tx_buf;
            aes_job.mode        = AES_Encrypt;
            aes_job.mic_size    = MIC_LEN;
            int8_t aes_ret = dwt_do_aes(&aes_job, AES_core_type_CCM);
            if (aes_ret < 0) return false;

            // Set TX frame length (header + encrypted payload + MIC)
            uint16_t final_frame_len = (uint16_t)(hi + payload_len + MIC_LEN);
            dwt_writetxfctrl(final_frame_len, 0, 1);

            // Delayed TX: RESP_RX_TO_FINAL_TX_DLY_UUS after tag's RESP RX timestamp
            uint32_t final_tx_time = (uint32_t)(
                (resp_rx_ts + ((uint64_t)RESP_RX_TO_FINAL_TX_DLY_UUS * UUS_TO_DWT_TIME))
                >> 8);
            dwt_setdelayedtrxtime(final_tx_time);

            // TX FINAL (no response expected – tag sleeps after this)
            int ret = dwt_starttx(DWT_START_TX_DELAYED);
            if (ret == DWT_SUCCESS) {
                int timeout_ms = 60;
                while (timeout_ms-- > 0) {
                    if (dwt_read32bitreg(SYS_STATUS_ID) & SYS_STATUS_TXFRS_BIT_MASK) {
                        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_TXFRS_BIT_MASK);
                        break;
                    }
                    delayMicroseconds(1000);
                }
            }

            // Advance sequence counter (POLL used seq_num, FINAL used seq_num+1)
            seq_num += 2;
            frame_count++;
            return true;
        }

        if (status_reg & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
            dwt_write32bitreg(SYS_STATUS_ID,
                              SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
            return false;
        }

        delayMicroseconds(500);
    }

    // Wall-clock timeout: no RESP received
    dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_TO | SYS_STATUS_ALL_RX_ERR);
    return false;
}

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * POWER BREAKDOWN (v3 – Tag Initiator, 3-frame DS-TWR)
 * ─────────────────────────────────────────────────────────────────────────────
 *   Deep sleep phase (POLL_INTERVAL_S − ~22ms ≈ ~2978ms):
 *     ESP32-C3: ~5 µA
 *     DW3000 in RST: ~100 µA
 *     Total standby: ~0.105 mA
 *
 *   Active phase (~22ms per cycle):
 *     DW3000 init (hard-reset + config): ~10ms @ 30 mA
 *     TX POLL (1ms) + RX RESP wait (3ms): ~4ms @ 70 mA avg
 *     AES encrypt + build payload: ~3ms @ 30 mA
 *     TX FINAL (1ms): 1ms @ 100 mA
 *     Other: 3ms @ 30 mA
 *     Active avg: ~50 mA × 22ms / 3000ms ≈ 0.37 mA
 *
 *   Total average: ≈ 0.48 mA
 *   Battery life (1000 mAh): ≈ 2083 h ≈ 87 days
 *
 *   vs v2 (DW3000 continuous RX): ~60 mA → ~17 h → 120× improvement
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * IMPACT OF ROLE SWAP ON SYSTEM BEHAVIOUR
 * ─────────────────────────────────────────────────────────────────────────────
 *   1. Update rate: 10 Hz → 0.33 Hz. The AKF in f411.ino is re-tuned:
 *      AKF_ALPHA = 0.15 (was 0.05), AKF_Q_INIT = 0.050 (was 0.001).
 *   2. Relay response latency: up to POLL_INTERVAL_S seconds (3s by default).
 *      Reduce POLL_INTERVAL_S to 1 for faster response (≈1.4 mA avg on tag).
 *   3. SIGNAL_TIMEOUT_MS on anchor extended to 10000ms (10s) so that missing
 *      3 consecutive polls does not immediately lock the relay.
 *   4. 3-frame protocol adds one extra UWB frame per cycle but the total active
 *      time increase is minimal (~2ms for FINAL TX).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * CALIBRATION NOTES
 * ─────────────────────────────────────────────────────────────────────────────
 *   BAT_ADC_FULL / BAT_ADC_EMPTY: tune to your specific battery and divider.
 *   AES key must be identical on Tag (this file) and Anchor (f411.ino).
 *   Provision keys via a secure out-of-band method before deployment.
 */
