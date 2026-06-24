/*
 * Smart Moto Security – STM32F103C8T6 ANCHOR (Beacon RX Mode)
 * Version: 1.0  —  companion to tag_tx_periodic.ino
 *
 * Role: UWB Beacon Receiver, AES-CCM* Verifier, Relay Control, UART to ESP32-S3.
 *       Replaces the TWR-initiator (POLL/RESP) role of stm.ino.
 *
 * Hardware: (identical pinout to stm.ino)
 *   - STM32F103C8T6 (BluePill)
 *   - DW3000 UWB Module (SPI1 + IRQ + RST)
 *   - Relay 5V (GPIO control, transistor + flyback diode)
 *   - UART1 TX=PA9, RX=PA10 → ESP32-S3 Serial2
 *
 * Pinout:
 *   SPI1: CLK=PA5, MISO=PA6, MOSI=PA7, CS=PA4
 *   DW3000: IRQ=PB0, RST=PA1
 *   Relay:  PB1  (HIGH = UNLOCK, LOW = LOCK)
 *   UART1:  TX=PA9, RX=PA10 → ESP32-S3
 *
 * Design differences from stm.ino (TWR initiator):
 *   - No POLL transmitted; anchor stays in RX mode permanently.
 *   - Tag beacons every TX_INTERVAL_S seconds (see tag_tx_periodic.ino).
 *   - Relay controlled by last-seen timeout only (no TWR distance available).
 *   - Anti-replay: monotonic 32-bit seq counter; reject if recv ≤ last.
 *   - UART reports presence (KEY=ON/OFF) and battery, but no distance.
 *
 * UART Protocol (backward-compatible subset of stm.ino):
 *   "STATUS:KEY=ON|BAT=85\r\n"
 *   "STATUS:KEY=OFF|BAT=85\r\n"
 *   "ERR:DECRYPT\r\n"
 *   "ERR:REPLAY\r\n"
 *   "ERR:CMD\r\n"
 *
 * NOTE: All numeric values are estimates and MUST be validated with
 *       measurements on the actual hardware board.
 */

// ----- STM32duino / FreeRTOS portability stubs (identical to stm.ino) -----
#if defined(ARDUINO_ARCH_STM32) || defined(ARDUINO_ARCH_STM32F1) || defined(__STM32F1__)
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

#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"
#include <IWatchdog.h>

extern dwt_txconfig_t txconfig_options;

// ===== CONFIGURATION =====
#define APP_NAME          "SmartKey Anchor Beacon v1.0"
#define TAG_ADDR          0x2222    // Remote tag short address
#define ANCHOR_ADDR       0x1111    // This anchor short address
#define PAN_ID            0x3412    // Network PAN ID (must match tag)

// Relay timeout: how long after the last valid beacon the relay stays ON.
// Recommended: ≥ 2.5 × TX_INTERVAL_S × 1000 to tolerate occasional missed beacons.
// Default TX_INTERVAL_S=5 → SIGNAL_TIMEOUT_MS=13000 (2.6 × 5000).
#define SIGNAL_TIMEOUT_MS 13000

// AES
#define MIC_LEN           4        // MIC size in bytes (must match tag)
// AAD size: FC(2)+SEQ_BYTE(1)+PAN(2)+DST(2)+SRC(2)+SEQ_CTR(4)+RAND_NONCE(4) = 17
#define HEADER_LEN        17
#define PAYLOAD_MAX_LEN   44       // Max decrypted payload length

// ===== AES-128 PRE-SHARED KEY (must match tag_tx_periodic.ino) =====
// *** CHANGE THIS KEY BEFORE DEPLOYMENT ***
static const dwt_aes_key_t aes_key = {
    0xAABBCCDDUL, 0xEEFF0011UL, 0x22334455UL, 0x66778899UL,
    0, 0, 0, 0
};

// ===== PIN DEFINITIONS =====
const uint8_t PIN_DW_CS  = PA4;
const uint8_t PIN_DW_IRQ = PB0;
const uint8_t PIN_DW_RST = PA1;
const uint8_t PIN_RELAY  = PB1;

// ===== DW3000 CONFIG (identical to stm.ino) =====
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
    DWT_STS_MODE_OFF, // No STS
    DWT_STS_LEN_64,
    DWT_PDOA_M0
};

#define TX_ANT_DLY   16385
#define RX_ANT_DLY   16385
#define RX_BUF_LEN   127

static uint8_t rx_buffer[RX_BUF_LEN];

// ===== GLOBAL STATE =====
bool     relay_state     = false;
uint32_t last_signal_ms  = 0;
uint8_t  last_bat_pct    = 0;
uint32_t last_seq_ctr    = 0xFFFFFFFFUL; // Initialized to max; first valid frame is always accepted
bool     seq_initialized = false;        // True after the first successfully decrypted frame

// AES_STS error bits [5:1]; bit[0] is AES_DONE
#define AES_STS_ERROR_MASK 0x3E

// ===== FUNCTION PROTOTYPES =====
void init_dw3000(void);
void enable_rx(void);
bool receive_and_process_beacon(void);
bool decrypt_and_verify_beacon(uint8_t *rx_data, uint32_t data_len);
void build_ccm_nonce(uint8_t *nonce, uint8_t mac_seq, const uint8_t *rand_nonce);
void update_relay(void);
void send_status(const char *key_str, uint8_t bat);
void send_error(const char *err);
void print_debug(const char *msg);

// ===== SETUP =====
void setup() {
    delay(1000);

    Serial1.begin(115200);   // To ESP32-S3
    print_debug("=== SmartKey Anchor Beacon v1.0 Starting ===");

    pinMode(PIN_DW_CS,  OUTPUT); digitalWrite(PIN_DW_CS,  HIGH);
    pinMode(PIN_DW_RST, OUTPUT); digitalWrite(PIN_DW_RST, HIGH);
    pinMode(PIN_RELAY,  OUTPUT); digitalWrite(PIN_RELAY,  LOW);
    pinMode(PIN_DW_IRQ, INPUT);

    IWatchdog.begin(8000000); // 8 s watchdog

    init_dw3000();
    enable_rx();

    last_signal_ms = millis();
    print_debug("SmartKey Anchor Beacon Ready — listening for tag beacons");
}

// ===== MAIN LOOP =====
void loop() {
    IWatchdog.reload();
    receive_and_process_beacon();
    update_relay();
    delay(5);
}

// ===== BUILD 13-BYTE CCM* NONCE =====
// Layout: [TAG_ADDR LE:2][ANC_ADDR LE:2][mac_seq:1][rand:4][zeros:4]
// Must be identical to the derivation in tag_tx_periodic.ino.
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
    digitalWrite(PIN_DW_RST, LOW);
    delay(2);
    digitalWrite(PIN_DW_RST, HIGH);
    delay(5);

    int max_tries = 100;
    while (!dwt_checkidlerc() && --max_tries > 0) { delay(1); }
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
    // No setrxaftertxdelay / setrxtimeout: anchor never transmits in beacon mode.
    dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);

    print_debug("DW3000 Initialized OK");
}

// ===== ENABLE RX (with address filtering) =====
// Address filter: only accept frames addressed to ANCHOR_ADDR on PAN_ID.
void enable_rx(void) {
    dwt_configureframefilter(DWT_FF_DATA_EN, 0);
    dwt_setpanid(PAN_ID);
    dwt_setaddress16(ANCHOR_ADDR);
    dwt_rxenable(DWT_START_RX_IMMEDIATE);
}

// ===== RECEIVE AND PROCESS BEACON (non-blocking) =====
// Called every loop() iteration. Checks the DW3000 status register once;
// if a good frame is present it is processed, otherwise returns immediately.
bool receive_and_process_beacon(void) {
    uint32_t status_reg = dwt_read32bitreg(SYS_STATUS_ID);

    if (status_reg & SYS_STATUS_RXFCG_BIT_MASK) {
        uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

        // Minimum: HEADER_LEN(17) + MIC(4) + FCS(2) = 23
        if (frame_len < (uint32_t)(HEADER_LEN + MIC_LEN + 2) ||
            frame_len > RX_BUF_LEN) {
            dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
            enable_rx();
            return false;
        }

        // Read frame without FCS bytes
        dwt_readrxdata(rx_buffer, frame_len - 2, 0);

        bool ok = decrypt_and_verify_beacon(rx_buffer, frame_len - 2);
        if (ok) {
            last_signal_ms = millis();
        }

        enable_rx();
        return ok;
    }

    if (status_reg & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
        enable_rx();
    }

    return false;
}

// ===== DECRYPT AND VERIFY BEACON =====
// rx_data: full received frame without FCS, length = frame_len - 2.
// Returns true if: AES-CCM* MIC passes, CMD=BEACON, and seq counter is monotonically increasing.
bool decrypt_and_verify_beacon(uint8_t *rx_data, uint32_t data_len) {
    if (data_len < (uint32_t)(HEADER_LEN + MIC_LEN + 1)) {
        return false;
    }

    // Expected AAD layout (bytes 0..16):
    //  [0..1]  FC
    //  [2]     MAC seq byte
    //  [3..4]  PAN ID
    //  [5..6]  DST = ANCHOR_ADDR
    //  [7..8]  SRC = TAG_ADDR
    //  [9..12] 32-bit monotonic seq counter (LE)
    //  [13..16] 4-byte random nonce

    // Extract monotonic counter
    uint32_t recv_ctr = ((uint32_t)rx_data[9]        ) |
                        ((uint32_t)rx_data[10] <<  8  ) |
                        ((uint32_t)rx_data[11] << 16  ) |
                        ((uint32_t)rx_data[12] << 24  );

    // Monotonic anti-replay check.
    // After initialisation seq_initialized=false, so first frame is always accepted.
    if (seq_initialized && recv_ctr <= last_seq_ctr) {
        send_error("REPLAY");
        return false;
    }

    uint8_t rand_nonce[4] = {
        rx_data[13], rx_data[14], rx_data[15], rx_data[16]
    };
    uint8_t mac_seq   = rx_data[2];
    uint16_t payload_len = (uint16_t)(data_len - HEADER_LEN - MIC_LEN);

    // Build CCM* nonce
    uint8_t ccm_nonce[13];
    build_ccm_nonce(ccm_nonce, mac_seq, rand_nonce);

    // Configure DW3000 AES engine for decryption
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
    aes_job.header      = rx_data;           // Full AAD pointer
    aes_job.header_len  = HEADER_LEN;        // 17 bytes
    aes_job.payload     = decrypted;         // Destination for decrypted bytes
    aes_job.payload_len = payload_len;
    aes_job.src_port    = AES_Src_Rx_buf_0;  // Ciphertext already in RX buffer
    aes_job.dst_port    = AES_Dst_Scratch;   // Write decrypted to SCRATCH
    aes_job.mode        = AES_Decrypt;
    aes_job.mic_size    = MIC_LEN;

    int8_t aes_ret = dwt_do_aes(&aes_job, AES_core_type_CCM);

    // Negative return: parameter/size error.  Error bits [5:1] set: MIC failure.
    if (aes_ret < 0 || (aes_ret & AES_STS_ERROR_MASK) != 0) {
        send_error("DECRYPT");
        return false;
    }

    decrypted[payload_len] = '\0';

    // Verify CMD field
    if (strstr((char *)decrypted, "CMD:BEACON") == NULL) {
        send_error("CMD");
        return false;
    }

    // Parse battery percentage
    char *bat_p = strstr((char *)decrypted, "BAT:");
    if (bat_p != NULL) {
        last_bat_pct = (uint8_t)atoi(bat_p + 4);
    }

    // Commit the new sequence counter (replay window advances)
    last_seq_ctr    = recv_ctr;
    seq_initialized = true;

    // Report current state
    send_status(relay_state ? "ON" : "OFF", last_bat_pct);

    return true;
}

// ===== UPDATE RELAY STATE (timeout-based) =====
// The relay is held ON as long as valid beacons arrive within SIGNAL_TIMEOUT_MS.
// When the tag moves out of range or is powered off, the relay locks after the timeout.
void update_relay(void) {
    uint32_t now = millis();
    bool new_state = relay_state;

    if ((now - last_signal_ms) > SIGNAL_TIMEOUT_MS) {
        // No beacon received within timeout window — lock
        new_state = false;
    } else if (seq_initialized) {
        // At least one valid beacon received and not yet timed out — unlock
        new_state = true;
    }

    if (new_state != relay_state) {
        relay_state = new_state;
        digitalWrite(PIN_RELAY, relay_state ? HIGH : LOW);
        send_status(relay_state ? "ON" : "OFF", last_bat_pct);
    }
}

// ===== SEND STATUS LINE TO ESP32-S3 =====
// Format: "STATUS:KEY=ON|BAT=85\r\n"
void send_status(const char *key_str, uint8_t bat) {
    char buf[48];
    snprintf(buf, sizeof(buf), "STATUS:KEY=%s|BAT=%u\r\n",
             key_str, (unsigned)bat);
    Serial1.print(buf);
    Serial1.flush();
}

// ===== SEND ERROR LINE TO ESP32-S3 =====
void send_error(const char *err) {
    char buf[32];
    snprintf(buf, sizeof(buf), "ERR:%s\r\n", err);
    Serial1.print(buf);
    Serial1.flush();
}

// ===== DEBUG PRINT =====
void print_debug(const char *msg) {
    (void)msg;
    // Uncomment for development on a debug UART:
    // Serial.println(msg);
}

/*
 * NOTES:
 *   1. AES key must be identical in tag_tx_periodic.ino and anchor_rx_beacon.ino.
 *   2. SIGNAL_TIMEOUT_MS must be > 2 × TX_INTERVAL_S × 1000 to tolerate
 *      occasional missed beacons (packet loss, multipath fades).
 *      Default: 13000 ms for TX_INTERVAL_S=5.
 *   3. Relay wiring: PB1 → NPN transistor base (1 kΩ) →
 *      transistor collector → relay coil → 5 V; flyback diode across coil.
 *   4. seq_initialized=false allows the first beacon after anchor reset to always
 *      succeed. If the tag resets (seq_counter goes back to 0) before the anchor,
 *      the anchor will reject beacons with lower counters until it too resets.
 *      To handle tag resets, implement a gap tolerance or a dedicated reset frame.
 *   5. No distance measurement is available in beacon mode. If proximity sensing
 *      is required, consider using received signal level (RXPACC/RSL from DW3000
 *      diagnostics) as a coarse proximity indicator, or switch back to TWR on
 *      demand (hybrid mode: tag beacons every 5 s; anchor initiates TWR only when
 *      presence is confirmed).
 *   6. IWatchdog.reload() in loop() prevents MCU hang during missed beacons.
 */
