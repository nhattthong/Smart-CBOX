/*
 * Smart Moto Security – ESP32-C3 TAG (Periodic TX / Beacon Mode)
 * Version: 1.0  —  companion to anchor_rx_beacon.ino
 *
 * Role: Periodic UWB Beacon Transmitter (one-way), Deep Sleep between TX.
 *       Replaces the continuous RX-listen design of tagc3.ino.
 *
 * Hardware:
 *   - ESP32-C3 (single core, ultra-low power)
 *   - DW3000 UWB Module (SPI + IRQ + RST)
 *   - Battery voltage divider: VBAT -> R1(100k) -> GPIO0 -> R2(100k) -> GND
 *
 * Pinout:
 *   SPI: SCK=4, MISO=5, MOSI=6, CS=7
 *   DW3000: IRQ=2, RST=3
 *   Battery ADC: GPIO0 (ADC1_CH0)
 *
 * Power Strategy:
 *   - Both ESP32-C3 AND DW3000 enter deep sleep between broadcasts.
 *   - Timer wakeup every TX_INTERVAL_S seconds (no IRQ needed).
 *   - On wake: init DW3000 → encrypt & send beacon → sleep.
 *
 * Security:
 *   - AES-128 CCM* encrypted payload (same pre-shared key as anchor_rx_beacon.ino)
 *   - 32-bit monotonic sequence counter (RTC memory, survives deep sleep)
 *   - 4-byte cryptographic random nonce (from esp_random, never zero)
 *   - Anchor rejects frames with seq_ctr <= last_accepted (replay prevention)
 *
 * Frame Layout (one-way, no TWR timestamps):
 *   AAD (17 B): [FC:2][SEQ_BYTE:1][PAN:2][DST:2][SRC:2][SEQ_CTR:4][RAND_NONCE:4]
 *   Encrypted:  "CMD:BEACON|BAT:nnn|SEQ:nnnnnnnn"
 *   MIC:        4 bytes (appended by DW3000 hardware)
 *
 * POWER BREAKDOWN (estimates — must be validated with a bench power meter):
 *   Deep sleep (ESP32-C3 RTC on, DW3000 powered down): ~5 µA
 *   Wake + SPI init + DW3000 init:          ~50 mA × 10 ms = 0.50 mAs
 *   AES encrypt + TX burst:                 ~100 mA × 3 ms = 0.30 mAs
 *   Total energy per TX_INTERVAL_S=5 s:
 *       Active:  0.80 mAs
 *       Sleep:   5 µA × 4987 ms ≈ 0.025 mAs
 *       Total:   ≈ 0.825 mAs → avg ≈ 0.165 mA
 *   Battery life (1000 mAh @ 0.165 mA avg):  ≈ 6060 h  ≈ 252 days
 *
 *   Compare — current RX-listen design (tagc3.ino):
 *   DW3000 in RX mode:  ~8–12 mA continuously
 *   Battery life (1000 mAh @ 10 mA avg):     ≈ 100 h   ≈ 4 days
 *
 *   Improvement:  ~60× longer battery life (all figures are estimates).
 *
 * NOTE: All numeric values are estimates and MUST be validated with
 *       measurements on the actual hardware board.
 */

#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"
#include <esp32-hal.h>
#include <esp_random.h>
#include <driver/adc.h>

// ===== CONFIGURATION =====
#define APP_NAME        "SmartKey Tag TX-Periodic v1.0"
#define ANCHOR_ADDR     0x1111    // Anchor short address (destination of beacon)
#define TAG_ADDR        0x2222    // This tag's 16-bit short address
#define PAN_ID          0x3412    // Network PAN ID (must match anchor)
#define MIC_LEN         4         // AES-CCM* MIC size in bytes
#define PAYLOAD_MAX_LEN 44        // Max plaintext payload length (bytes)

// Configurable TX interval. Change to tune duty cycle vs. latency.
// Smaller = lower latency, higher avg current; larger = longer battery life.
#define TX_INTERVAL_S   5         // Beacon every N seconds (default: 5)

// ===== PIN DEFINITIONS =====
const uint8_t PIN_DW_CS  = 7;
const uint8_t PIN_DW_IRQ = 2;
const uint8_t PIN_DW_RST = 3;

// ===== BATTERY ADC CALIBRATION =====
// Voltage divider 1:2, ADC ref 3.3 V (12-bit = 4095)
// 4.2 V full  → 2.1 V at GPIO0 → ADC ≈ 2607
// 3.3 V empty → 1.65 V          → ADC ≈ 2048
#define BAT_ADC_FULL  2607
#define BAT_ADC_EMPTY 2048
static_assert(BAT_ADC_FULL != BAT_ADC_EMPTY,
              "BAT ADC calibration error: FULL == EMPTY");

// ===== AES-128 PRE-SHARED KEY =====
// *** CHANGE THIS KEY BEFORE DEPLOYMENT ***
// Must be identical to the key in anchor_rx_beacon.ino.
// Generate with:
//   python3 -c "import os; d=os.urandom(16); \
//     print(','.join(hex(int.from_bytes(d[i:i+4],'big'))+'UL' for i in range(0,16,4)))"
static const dwt_aes_key_t aes_key = {
    0xAABBCCDDUL, 0xEEFF0011UL, 0x22334455UL, 0x66778899UL,
    0, 0, 0, 0   // Upper 128 bits unused for AES-128
};

// ===== DW3000 CONFIG =====
static dwt_config_t config = {
    5,                // Channel 5
    DWT_PLEN_128,     // Preamble length
    DWT_PAC8,         // PAC size
    9,                // TX preamble code
    9,                // RX preamble code
    1,                // SFD type (DW proprietary 8-bit)
    DWT_BR_6M8,       // Data rate 6.8 Mbps
    DWT_PHRMODE_STD,  // PHY header mode
    DWT_PHRRATE_STD,  // PHY header rate
    (129 + 8 - 8),    // SFD timeout
    DWT_STS_MODE_OFF, // No STS (faster, lower power)
    DWT_STS_LEN_64,   // STS length (unused)
    DWT_PDOA_M0       // No PDOA
};

#define TX_ANT_DLY   16385
#define RX_ANT_DLY   16385

// ===== GLOBAL STATE (preserved in RTC memory across deep sleep) =====
// seq_counter: 32-bit monotonic beacon counter used for anti-replay on anchor.
// frame_seq:   8-bit MAC frame sequence number (wraps at 255, not for security).
RTC_DATA_ATTR uint32_t seq_counter = 0;
RTC_DATA_ATTR uint8_t  frame_seq   = 0;

// ===== FUNCTION PROTOTYPES =====
void    init_dw3000(void);
void    enter_deep_sleep(void);
uint8_t read_battery_percent(void);
void    build_ccm_nonce(uint8_t *nonce, uint8_t mac_seq, const uint8_t *rand_nonce);
bool    send_beacon(void);

// ===== SETUP =====
void setup() {
    pinMode(PIN_DW_CS,  OUTPUT); digitalWrite(PIN_DW_CS,  HIGH);
    pinMode(PIN_DW_RST, OUTPUT); digitalWrite(PIN_DW_RST, HIGH);
    pinMode(PIN_DW_IRQ, INPUT);

    // Battery ADC
    adc1_config_width(ADC_WIDTH_BIT_12);
    adc1_config_channel_atten(ADC1_CHANNEL_0, ADC_ATTEN_DB_11);

    init_dw3000();
    send_beacon();
    enter_deep_sleep();
}

// loop() is never reached — setup() always ends with enter_deep_sleep().
void loop() { }

// ===== READ BATTERY PERCENT =====
uint8_t read_battery_percent(void) {
    int raw = adc1_get_raw(ADC1_CHANNEL_0);
    int pct = (int)(((long)(raw - BAT_ADC_EMPTY) * 100L)
                    / (BAT_ADC_FULL - BAT_ADC_EMPTY));
    if (pct < 0)   pct = 0;
    if (pct > 100) pct = 100;
    return (uint8_t)pct;
}

// ===== BUILD 13-BYTE CCM* NONCE =====
// Layout: [TAG_ADDR LE:2][ANC_ADDR LE:2][mac_seq:1][rand:4][zeros:4]
// Matches the nonce derivation expected by anchor_rx_beacon.ino.
void build_ccm_nonce(uint8_t *nonce, uint8_t mac_seq, const uint8_t *rand_nonce) {
    nonce[0]  = (uint8_t)(TAG_ADDR    & 0xFF);
    nonce[1]  = (uint8_t)(TAG_ADDR    >> 8);
    nonce[2]  = (uint8_t)(ANCHOR_ADDR & 0xFF);
    nonce[3]  = (uint8_t)(ANCHOR_ADDR >> 8);
    nonce[4]  = mac_seq;
    nonce[5]  = rand_nonce[0];
    nonce[6]  = rand_nonce[1];
    nonce[7]  = rand_nonce[2];
    nonce[8]  = rand_nonce[3];
    nonce[9]  = 0x00;
    nonce[10] = 0x00;
    nonce[11] = 0x00;
    nonce[12] = 0x00;
}

// ===== INIT DW3000 =====
void init_dw3000(void) {
    // Hard reset
    digitalWrite(PIN_DW_RST, LOW);
    delay(2);
    digitalWrite(PIN_DW_RST, HIGH);
    delay(5);

    int max_tries = 100;
    while (!dwt_checkidlerc() && --max_tries > 0) { delay(1); }
    if (max_tries == 0)                             { enter_deep_sleep(); }

    if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR)  { enter_deep_sleep(); }
    if (dwt_configure(&config))                     { enter_deep_sleep(); }

    dwt_configuretxrf(&txconfig_options);
    dwt_setrxantennadelay(RX_ANT_DLY);
    dwt_settxantennadelay(TX_ANT_DLY);
    dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);
}

// ===== ENTER DEEP SLEEP (timer-based) =====
// Unlike tagc3.ino (IRQ wake), both the ESP32-C3 and the DW3000 power rail
// are off during sleep. The DW3000 is re-initialised from scratch on every wake.
void enter_deep_sleep(void) {
    // If your hardware allows cutting DW3000 power via a load switch, do it here
    // before calling esp_deep_sleep_start() for the lowest possible sleep current.
    // Example: digitalWrite(PIN_DW_PWR_EN, LOW);

    esp_sleep_enable_timer_wakeup((uint64_t)TX_INTERVAL_S * 1000000ULL);
    esp_deep_sleep_start();
    // Never reached
}

// ===== SEND ENCRYPTED BEACON =====
// Builds an AES-CCM* encrypted one-way frame and transmits it immediately.
// Returns true if the DW3000 confirmed the TX (TXFRS bit set), false otherwise.
bool send_beacon(void) {
    uint8_t  mac_seq = frame_seq++;
    uint32_t ctr     = seq_counter++;

    // --- 4-byte cryptographic random nonce (never zero) ---
    uint32_t rand_word;
    do { rand_word = esp_random(); } while (rand_word == 0);
    uint8_t rand_nonce[4] = {
        (uint8_t)(rand_word         & 0xFF),
        (uint8_t)((rand_word >>  8) & 0xFF),
        (uint8_t)((rand_word >> 16) & 0xFF),
        (uint8_t)((rand_word >> 24) & 0xFF)
    };

    // --- Build AAD / MAC header (17 bytes) ---
    // This buffer is used as Additional Authenticated Data for AES-CCM*.
    // Layout: [FC:2][SEQ_BYTE:1][PAN:2][DST:2][SRC:2][SEQ_CTR:4][RAND_NONCE:4]
    uint8_t header[17];
    uint8_t hi = 0;
    header[hi++] = 0x41;                         // FC byte 0: data, 16-bit addr
    header[hi++] = 0x88;                         // FC byte 1
    header[hi++] = mac_seq;
    header[hi++] = (uint8_t)(PAN_ID      & 0xFF);
    header[hi++] = (uint8_t)(PAN_ID      >> 8);
    header[hi++] = (uint8_t)(ANCHOR_ADDR & 0xFF); // Destination = anchor
    header[hi++] = (uint8_t)(ANCHOR_ADDR >> 8);
    header[hi++] = (uint8_t)(TAG_ADDR    & 0xFF); // Source = this tag
    header[hi++] = (uint8_t)(TAG_ADDR    >> 8);
    // 32-bit monotonic counter (LE) — anchor uses this for replay detection
    header[hi++] = (uint8_t)(ctr         & 0xFF);
    header[hi++] = (uint8_t)((ctr >>  8) & 0xFF);
    header[hi++] = (uint8_t)((ctr >> 16) & 0xFF);
    header[hi++] = (uint8_t)((ctr >> 24) & 0xFF);
    // Random nonce
    header[hi++] = rand_nonce[0];
    header[hi++] = rand_nonce[1];
    header[hi++] = rand_nonce[2];
    header[hi++] = rand_nonce[3];
    // hi == 17

    // --- Build plaintext payload ---
    uint8_t bat_pct = read_battery_percent();
    char payload_str[PAYLOAD_MAX_LEN + 1];
    snprintf(payload_str, sizeof(payload_str),
             "CMD:BEACON|BAT:%u|SEQ:%lu",
             (unsigned)bat_pct, (unsigned long)ctr);
    uint16_t payload_len = (uint16_t)strlen(payload_str);

    // --- 13-byte CCM* nonce ---
    uint8_t ccm_nonce[13];
    build_ccm_nonce(ccm_nonce, mac_seq, rand_nonce);

    // --- Configure DW3000 AES engine ---
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

    // --- AES-CCM* encrypt: plaintext → TX buffer ---
    dwt_aes_job_t aes_job;
    aes_job.nonce       = ccm_nonce;
    aes_job.header      = header;
    aes_job.header_len  = hi;                  // 17 bytes AAD
    aes_job.payload     = (uint8_t *)payload_str;
    aes_job.payload_len = payload_len;
    aes_job.src_port    = AES_Src_Scratch;     // Plaintext via scratch
    aes_job.dst_port    = AES_Dst_Tx_buf;      // Ciphertext → TX buffer
    aes_job.mode        = AES_Encrypt;
    aes_job.mic_size    = MIC_LEN;

    int8_t aes_ret = dwt_do_aes(&aes_job, AES_core_type_CCM);
    if (aes_ret < 0) { return false; }

    // TX buffer now contains: [header 17B][cipher N B][MIC 4B]
    uint16_t tx_frame_len = (uint16_t)(hi + payload_len + MIC_LEN);

    // ranging bit = 0 (this is not a TWR ranging frame)
    dwt_writetxfctrl(tx_frame_len, 0, 0);

    if (dwt_starttx(DWT_START_TX_IMMEDIATE) != DWT_SUCCESS) { return false; }

    // Wait for TX done (max 50 ms)
    int timeout = 50;
    while (timeout-- > 0) {
        if (dwt_read32bitreg(SYS_STATUS_ID) & SYS_STATUS_TXFRS_BIT_MASK) {
            dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_TXFRS_BIT_MASK);
            return true;
        }
        delayMicroseconds(1000);
    }
    return false;
}

/*
 * CALIBRATION NOTES:
 *   BAT_ADC_FULL / BAT_ADC_EMPTY must be tuned to your voltage divider
 *   and battery chemistry using a calibrated reference voltage.
 *
 * AES KEY NOTES:
 *   The aes_key must be identical in tag_tx_periodic.ino and anchor_rx_beacon.ino.
 *   Store the key outside this file in a gitignored secret_key.h in production.
 *
 * TX_INTERVAL_S TUNING:
 *   5 s  →  avg ~0.165 mA  →  ~250 days on 1000 mAh  (latency ≤ 5 s)
 *   2 s  →  avg ~0.37 mA   →  ~110 days on 1000 mAh  (latency ≤ 2 s)
 *   10 s →  avg ~0.09 mA   →  ~460 days on 1000 mAh  (latency ≤ 10 s)
 *   All estimates; validate with measurements.
 *
 * SIGNAL_TIMEOUT on Anchor:
 *   Set SIGNAL_TIMEOUT_MS in anchor_rx_beacon.ino to at least
 *   2.5 × TX_INTERVAL_S × 1000 ms to avoid false lock-outs from
 *   occasional missed beacons.
 */
