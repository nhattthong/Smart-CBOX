/*
 * Smart Moto Security - STM32F103C8T6 ANCHOR (SmartKey Controller)
 * Version 2.0 - AES-128 CCM* Decrypt + Nonce Anti-Replay
 *
 * Role: UWB TWR Initiator, AES-CCM* Verifier, Relay Control, UART to ESP32-S3
 *
 * Hardware:
 *   - STM32F103C8T6 (BluePill)
 *   - DW3000 UWB Module (SPI1 + IRQ + RST)
 *   - Relay 5V (GPIO control, use transistor + flyback diode)
 *   - UART1 TX=PA9, RX=PA10 -> ESP32-S3 Serial2
 *
 * Pinout:
 *   SPI1: CLK=PA5, MISO=PA6, MOSI=PA7, CS=PA4
 *   DW3000: IRQ=PB0, RST=PA1
 *   Relay: PB1 (HIGH=UNLOCK, LOW=LOCK)
 *   UART1: TX=PA9, RX=PA10 -> ESP32-S3
 *
 * Security:
 *   - Same AES-128 pre-shared key as Tag
 *   - DW3000 hardware AES-CCM* decryption
 *   - 4-byte MIC verification (AES_STS_AES_DONE must be set)
 *   - Nonce replay protection: ring buffer of last NONCE_HISTORY_SIZE nonces
 *   - Cross-check: measured TWR distance vs CMD (both must pass)
 *
 * RESP Frame Expected Layout:
 *   [MAC Header: 9B][Poll RX TS: 4B][Resp TX TS: 4B][Nonce: 4B] = 21B AAD
 *   [Encrypted payload: N bytes][MIC: 4B]
 *   Total = 21 + N + 4 bytes (+ 2 FCS added by DW3000)
 *
 * UART Protocol to ESP32-S3:
 *   "STATUS:KEY=ON|DIST=1.23|BAT=85\r\n"
 *   "STATUS:KEY=OFF|DIST=0.00|BAT=85\r\n"
 *   "ERR:DECRYPT\r\n"    -- MIC verification failed
 *   "ERR:REPLAY\r\n"     -- Nonce replay detected
 *   "ERR:CMD\r\n"        -- Unknown CMD in decrypted payload
 */

// ----- STM32duino / FreeRTOS portability stubs -----
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

#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"
#include <IWatchdog.h>

extern dwt_txconfig_t txconfig_options;

// ===== CONFIGURATION =====
#define APP_NAME          "SmartKey Anchor v2.0"
#define TAG_ADDR          0x2222    // Remote tag address
#define ANCHOR_ADDR       0x1111    // This anchor address
#define PAN_ID            0x3412    // Network PAN ID
#define RANGING_INTERVAL_MS 100     // Ranging poll interval

// Relay hysteresis thresholds
#define DIST_THRESHOLD_ON  1.5f   // meters - unlock when closer
#define DIST_THRESHOLD_OFF 3.0f   // meters - lock when farther
#define SIGNAL_TIMEOUT_MS  5000   // 5s no signal -> force lock

// AES
#define MIC_LEN            4        // MIC size in bytes
#define HEADER_LEN         21       // AAD size: MAC(9)+TWR_TS(8)+NONCE(4)
#define PAYLOAD_MAX_LEN    36       // Max decrypted payload length

// Anti-replay nonce history
#define NONCE_HISTORY_SIZE 32       // Ring buffer size (× 4 bytes = 128 bytes)

// ===== AES-128 PRE-SHARED KEY (must match tagc3.ino) =====
// *** CHANGE THIS KEY BEFORE DEPLOYMENT ***
// Must be identical to the key in tagc3.ino.
static const dwt_aes_key_t aes_key = {
    0xAABBCCDDUL, 0xEEFF0011UL, 0x22334455UL, 0x66778899UL,
    0, 0, 0, 0
};

// ===== PIN DEFINITIONS =====
const uint8_t PIN_DW_CS  = PA4;
const uint8_t PIN_DW_IRQ = PB0;
const uint8_t PIN_DW_RST = PA1;
const uint8_t PIN_RELAY  = PB1;

// ===== DW3000 CONFIG =====
static dwt_config_t config = {
    5,               // Channel 5
    DWT_PLEN_128,    // Preamble length
    DWT_PAC8,        // PAC size
    9,               // TX preamble code
    9,               // RX preamble code
    1,               // SFD type (DW 8-bit)
    DWT_BR_6M8,      // Data rate 6.8 Mbps
    DWT_PHRMODE_STD, // PHY header mode
    DWT_PHRRATE_STD, // PHY header rate
    (129 + 8 - 8),   // SFD timeout
    DWT_STS_MODE_OFF,// No STS
    DWT_STS_LEN_64,
    DWT_PDOA_M0
};

#define TX_ANT_DLY              16385
#define RX_ANT_DLY              16385
#define POLL_TX_TO_RESP_RX_DLY_UUS 1720
#define RESP_RX_TIMEOUT_UUS     250
#define RX_BUF_LEN              127

static uint8_t tx_poll_msg[] = {'P','O','L','L'};
static uint8_t rx_buffer[RX_BUF_LEN];

// ===== GLOBAL STATE =====
double   last_distance   = -1.0;
uint32_t last_ranging_ms = 0;
bool     relay_state     = false;
uint32_t last_signal_ms  = 0;
uint8_t  last_bat_pct    = 0;

// AES_STS error bits [5:1]; bit[0] is AES_DONE
#define AES_STS_ERROR_MASK  0x3E
static uint32_t nonce_history[NONCE_HISTORY_SIZE] = {0};
static uint8_t  nonce_history_idx = 0;

// ===== FUNCTION PROTOTYPES =====
void    init_dw3000(void);
void    send_poll_frame(void);
bool    receive_and_process_response(void);
bool    decrypt_and_verify_payload(uint8_t *rx_buf, uint32_t frame_len, double measured_dist, uint8_t seq);
void    build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_nonce_bytes);
bool    is_nonce_replay(uint32_t nonce_word);
void    record_nonce(uint32_t nonce_word);
void    update_relay(void);
void    send_status(const char *key_str, double dist, uint8_t bat);
void    send_error(const char *err);
void    print_debug(const char *msg);

// ===== SETUP =====
void setup() {
  delay(1000);

  Serial1.begin(115200);    // To ESP32-S3
  print_debug("=== SmartKey Anchor v2.0 Starting ===");

  pinMode(PIN_DW_CS,  OUTPUT); digitalWrite(PIN_DW_CS, HIGH);
  pinMode(PIN_DW_RST, OUTPUT); digitalWrite(PIN_DW_RST, HIGH);
  pinMode(PIN_RELAY,  OUTPUT); digitalWrite(PIN_RELAY, LOW);
  pinMode(PIN_DW_IRQ, INPUT);

  IWatchdog.begin(8000000);  // 8s watchdog

  init_dw3000();

  print_debug("SmartKey Anchor Ready");
  last_ranging_ms = millis();
  last_signal_ms  = millis();
}

// ===== MAIN LOOP =====
void loop() {
  IWatchdog.reload();

  uint32_t now = millis();
  if (now - last_ranging_ms >= RANGING_INTERVAL_MS) {
    last_ranging_ms = now;

    send_poll_frame();
    delay(10);
    bool got_response = receive_and_process_response();
    (void)got_response;

    update_relay();
  }

  delay(5);
}

// ===== BUILD 13-BYTE CCM* NONCE =====
void build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_nonce_bytes) {
  nonce[0]  = (uint8_t)(TAG_ADDR    & 0xFF);
  nonce[1]  = (uint8_t)(TAG_ADDR    >> 8);
  nonce[2]  = (uint8_t)(ANCHOR_ADDR & 0xFF);
  nonce[3]  = (uint8_t)(ANCHOR_ADDR >> 8);
  nonce[4]  = seq;
  nonce[5]  = rand_nonce_bytes[0];
  nonce[6]  = rand_nonce_bytes[1];
  nonce[7]  = rand_nonce_bytes[2];
  nonce[8]  = rand_nonce_bytes[3];
  nonce[9]  = 0x00;
  nonce[10] = 0x00;
  nonce[11] = 0x00;
  nonce[12] = 0x00;
}

// ===== NONCE REPLAY CHECK =====
bool is_nonce_replay(uint32_t nonce_word) {
  if (nonce_word == 0) return true;  // Zero nonce never valid
  for (uint8_t i = 0; i < NONCE_HISTORY_SIZE; i++) {
    if (nonce_history[i] == nonce_word) return true;
  }
  return false;
}

void record_nonce(uint32_t nonce_word) {
  nonce_history[nonce_history_idx % NONCE_HISTORY_SIZE] = nonce_word;
  nonce_history_idx++;
}

// ===== INIT DW3000 =====
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
  dwt_setrxaftertxdelay(POLL_TX_TO_RESP_RX_DLY_UUS);
  dwt_setrxtimeout(RESP_RX_TIMEOUT_UUS);
  dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);

  print_debug("DW3000 Initialized OK");
}

// ===== SEND POLL FRAME =====
void send_poll_frame(void) {
  static uint8_t seq_num = 0;

  uint8_t poll_frame[16];
  uint8_t idx = 0;

  poll_frame[idx++] = 0x41;   // FC0 - data frame, 16-bit addr
  poll_frame[idx++] = 0x88;   // FC1
  poll_frame[idx++] = seq_num++;
  poll_frame[idx++] = (uint8_t)(PAN_ID    & 0xFF);
  poll_frame[idx++] = (uint8_t)(PAN_ID    >> 8);
  poll_frame[idx++] = (uint8_t)(TAG_ADDR    & 0xFF);
  poll_frame[idx++] = (uint8_t)(TAG_ADDR    >> 8);
  poll_frame[idx++] = (uint8_t)(ANCHOR_ADDR & 0xFF);
  poll_frame[idx++] = (uint8_t)(ANCHOR_ADDR >> 8);
  memcpy(&poll_frame[idx], tx_poll_msg, sizeof(tx_poll_msg));
  idx += sizeof(tx_poll_msg);

  dwt_writetxdata(idx, poll_frame, 0);
  dwt_writetxfctrl(idx, 0, 1);
  dwt_starttx(DWT_START_TX_IMMEDIATE | DWT_RESPONSE_EXPECTED);
}

// ===== RECEIVE & PROCESS RESPONSE =====
bool receive_and_process_response(void) {
  uint32_t status_reg;
  uint32_t start = millis();

  while ((millis() - start) < 500) {
    status_reg = dwt_read32bitreg(SYS_STATUS_ID);

    if (status_reg & SYS_STATUS_RXFCG_BIT_MASK) {
      uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
      dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

      // Minimum: HEADER_LEN(21) + MIC(4) + FCS(2) = 27
      if (frame_len < (uint32_t)(HEADER_LEN + MIC_LEN + 2) || frame_len > RX_BUF_LEN) {
        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
        return false;
      }

      // Read frame (without FCS bytes)
      dwt_readrxdata(rx_buffer, frame_len - 2, 0);

      // --- TWR timestamp calculation ---
      uint32_t poll_tx_ts = dwt_readtxtimestamplo32();
      uint32_t resp_rx_ts = dwt_readrxtimestamplo32();

      // Extract embedded timestamps from frame (bytes 9..16)
      uint32_t poll_rx_ts = ((uint32_t)rx_buffer[9]  <<  0) |
                            ((uint32_t)rx_buffer[10]  <<  8) |
                            ((uint32_t)rx_buffer[11]  << 16) |
                            ((uint32_t)rx_buffer[12]  << 24);
      uint32_t resp_tx_ts = ((uint32_t)rx_buffer[13] <<  0) |
                            ((uint32_t)rx_buffer[14] <<  8) |
                            ((uint32_t)rx_buffer[15] << 16) |
                            ((uint32_t)rx_buffer[16] << 24);

      int32_t rtd_init = (int32_t)(resp_rx_ts - poll_tx_ts);
      int32_t rtd_resp = (int32_t)(resp_tx_ts - poll_rx_ts);
      float   clk_off  = ((float)dwt_readclockoffset()) / (float)(1UL << 26);
      double  tof      = ((rtd_init - rtd_resp * (1.0 - clk_off)) / 2.0) * DWT_TIME_UNITS;
      double  dist_m   = tof * SPEED_OF_LIGHT;

      // Reject clearly erroneous distances (negative or > 100m)
      if (dist_m < 0.0 || dist_m > 100.0) {
        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR);
        return false;
      }

      // --- AES decrypt + replay check ---
      uint8_t seq = rx_buffer[2];  // sequence number from received frame
      bool    ok  = decrypt_and_verify_payload(rx_buffer, frame_len - 2, dist_m, seq);

      if (ok) {
        last_distance  = dist_m;
        last_signal_ms = millis();
      }
      return ok;
    }

    if (status_reg & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
      dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
      return false;
    }

    delay(1);
  }

  dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_TO | SYS_STATUS_ALL_RX_ERR);
  return false;
}

// ===== DECRYPT AND VERIFY PAYLOAD =====
// rx_data: full received frame (without FCS), len = frame_len - 2
// measured_dist: TWR-computed distance in metres
// seq: sequence number byte from MAC header
// Returns true if authentication passed, CMD=OPEN, and distance is valid
bool decrypt_and_verify_payload(uint8_t *rx_data, uint32_t data_len, double measured_dist, uint8_t seq) {
  // Expected layout:
  //  [0..8]   MAC header   (9B)
  //  [9..12]  poll_rx_ts   (4B)
  //  [13..16] resp_tx_ts   (4B)
  //  [17..20] rand_nonce   (4B)
  //  [21..data_len-MIC-1]  encrypted payload
  //  [data_len-MIC..data_len-1]  MIC (4B)

  if (data_len < (uint32_t)(HEADER_LEN + MIC_LEN + 1)) {
    return false;
  }

  // Extract 4-byte random nonce from frame bytes [17..20]
  uint8_t rand_nonce[4];
  rand_nonce[0] = rx_data[17];
  rand_nonce[1] = rx_data[18];
  rand_nonce[2] = rx_data[19];
  rand_nonce[3] = rx_data[20];

  // Build 32-bit nonce word for replay check (LE)
  uint32_t nonce_word = ((uint32_t)rand_nonce[0]       ) |
                        ((uint32_t)rand_nonce[1] <<  8  ) |
                        ((uint32_t)rand_nonce[2] << 16  ) |
                        ((uint32_t)rand_nonce[3] << 24  );

  // Anti-replay: reject if we've seen this nonce recently
  if (is_nonce_replay(nonce_word)) {
    send_error("REPLAY");
    return false;
  }

  // Payload length = data_len - HEADER_LEN - MIC_LEN
  uint16_t payload_len = (uint16_t)(data_len - HEADER_LEN - MIC_LEN);

  // Build 13-byte CCM* nonce (same derivation as Tag)
  uint8_t ccm_nonce[13];
  build_ccm_nonce(ccm_nonce, seq, rand_nonce);

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

  // Buffer for decrypted payload
  uint8_t decrypted[PAYLOAD_MAX_LEN + 1];
  memset(decrypted, 0, sizeof(decrypted));

  // AES job: RX buffer -> SCRATCH (decrypted output)
  dwt_aes_job_t aes_job;
  aes_job.nonce       = ccm_nonce;
  aes_job.header      = rx_data;          // Header pointer for AAD reference
  aes_job.header_len  = HEADER_LEN;       // 21 bytes
  aes_job.payload     = decrypted;        // Destination for decrypted bytes
  aes_job.payload_len = payload_len;
  aes_job.src_port    = AES_Src_Rx_buf_0; // Ciphertext already in RX buffer
  aes_job.dst_port    = AES_Dst_Scratch;  // Write decrypted to SCRATCH
  aes_job.mode        = AES_Decrypt;
  aes_job.mic_size    = MIC_LEN;

  int8_t aes_ret = dwt_do_aes(&aes_job, AES_core_type_CCM);

  // AES_STS_AES_DONE_BIT_MASK = 0x01; any error bit set means MIC failure
  // aes_ret is the raw AES_STS_ID register value on success, negative on param error
  if (aes_ret < 0) {
    send_error("DECRYPT");
    return false;
  }
  // Check that only DONE bit is set (no error bits)
  // Bits [5:1] are error flags; bit[0] is AES_DONE
  if ((aes_ret & AES_STS_ERROR_MASK) != 0) {
    send_error("DECRYPT");
    return false;
  }

  // decrypted[] now contains the plaintext payload
  decrypted[payload_len] = '\0';  // Null-terminate

  // Parse CMD, DIST, BAT from "CMD:OPEN|DIST:x.xx|BAT:nnn"
  bool cmd_open = (strstr((char *)decrypted, "CMD:OPEN") != NULL);
  if (!cmd_open) {
    send_error("CMD");
    return false;
  }

  // Parse BAT field
  char *bat_p = strstr((char *)decrypted, "BAT:");
  if (bat_p != NULL) {
    last_bat_pct = (uint8_t)atoi(bat_p + 4);
  }

  // Nonce is now verified; record it to prevent replay
  record_nonce(nonce_word);

  // Send status to ESP32-S3
  const char *key_str = (measured_dist < DIST_THRESHOLD_ON) ? "ON" : "OFF";
  send_status(key_str, measured_dist, last_bat_pct);

  return true;
}

// ===== UPDATE RELAY STATE (Hysteresis) =====
void update_relay(void) {
  uint32_t now = millis();
  bool new_relay_state = relay_state;

  if (now - last_signal_ms > SIGNAL_TIMEOUT_MS) {
    new_relay_state = false;
  } else if (last_distance >= 0.0) {
    if (!relay_state && last_distance < DIST_THRESHOLD_ON) {
      new_relay_state = true;
    } else if (relay_state && last_distance > DIST_THRESHOLD_OFF) {
      new_relay_state = false;
    }
  }

  if (new_relay_state != relay_state) {
    relay_state = new_relay_state;
    digitalWrite(PIN_RELAY, relay_state ? HIGH : LOW);
  }
}

// ===== SEND STATUS LINE TO ESP32-S3 =====
// Format: "STATUS:KEY=ON|DIST=1.23|BAT=85\r\n"
void send_status(const char *key_str, double dist, uint8_t bat) {
  char buf[64];
  int  dist_int  = (int)dist;
  int  dist_frac = (int)((dist - dist_int) * 100.0);
  if (dist_frac < 0) dist_frac = -dist_frac;
  snprintf(buf, sizeof(buf), "STATUS:KEY=%s|DIST=%d.%02d|BAT=%u\r\n",
           key_str, dist_int, dist_frac, (unsigned)bat);
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

// ===== DEBUG PRINT (stub – enable UART0 for dev builds) =====
void print_debug(const char *msg) {
  (void)msg;
  // Uncomment for development:
  // Serial.println(msg);
}

/*
 * NOTES:
 *   1. AES key must be identical in tagc3.ino and stm.ino.
 *   2. Relay wiring: PB1 -> NPN transistor base (1k resistor) ->
 *      transistor collector -> relay coil -> 5V; flyback diode across coil.
 *   3. NONCE_HISTORY_SIZE=32 protects against replays of up to 32 recent frames.
 *      Increase for higher security, decrease to save RAM (each entry = 4 bytes).
 *   4. dwt_do_aes() AES_STS register on success = 0x01 (DONE only).
 *      Bits [5:2] indicate: MIC error, RAM full, RAM empty, etc.
 *   5. IWatchdog.reload() in loop() prevents MCU hang. Extend timeout if needed.
 */
