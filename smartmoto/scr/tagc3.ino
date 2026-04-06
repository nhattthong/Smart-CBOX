/*
 * Smart Moto Security - ESP32-C3 REMOTE TAG (SmartKey Fob)
 * Version 2.0 - AES-128 CCM* Encrypted Payload + Battery Monitor
 *
 * Role: UWB TWR Responder, Deep Sleep with IRQ Wake, AES-CCM* Security
 *
 * Hardware:
 *   - ESP32-C3 (single core, ultra-low power)
 *   - DW3000 UWB Module (SPI + IRQ + RST)
 *   - Battery voltage divider: VBAT -> R1(100k) -> GPIO4 -> R2(100k) -> GND
 *
 * Pinout:
 *   SPI: SCK=4, MISO=5, MOSI=6, CS=7
 *   DW3000: IRQ=2 (RTC IO, wakes from deep sleep), RST=3
 *   Battery ADC: GPIO0 (ADC1_CH0, with 1:2 voltage divider)
 *
 * Security:
 *   - Pre-shared AES-128 key loaded into DW3000 hardware AES engine
 *   - 4-byte random nonce (via esp_random) embedded in each frame
 *   - Full CCM* nonce: [TAG_ADDR(2)][ANC_ADDR(2)][SEQ(1)][RAND(4)][PAD(4)] = 13B
 *   - Payload "CMD:OPEN|DIST:x.xx|BAT:nnn" encrypted with AES-CCM*
 *   - 4-byte MIC (Message Integrity Code) appended by DW3000 hardware
 *   - Replay protection on Anchor side (nonce history list)
 *
 * RESP Frame Layout:
 *   [MAC Header: 9B][Poll RX TS: 4B][Resp TX TS: 4B][Nonce: 4B] = 21B header (AAD)
 *   [Encrypted payload: ~30B][MIC: 4B]
 *
 * Power Strategy:
 *   - ESP32-C3 Deep Sleep; DW3000 RX listen with address filter
 *   - Wake on GPIO2 HIGH (DW3000 IRQ)
 *   - One ranging + respond cycle per wake (~5ms), then sleep
 *   - Average: ~1-2mA at 10 ranging/sec duty cycle
 */

#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include "dw3000_shared_functions.h"
#include <esp32-hal.h>
#include <esp_random.h>
#include <driver/adc.h>

// ===== CONFIGURATION =====
#define APP_NAME        "SmartKey Tag v2.0"
#define ANCHOR_ADDR     0x1111    // Anchor address
#define TAG_ADDR        0x2222    // This tag's address
#define PAN_ID          0x3412    // Network PAN ID
#define MIC_LEN         4         // MIC size in bytes (AES-CCM* tag)
#define PAYLOAD_MAX_LEN 36        // Max plaintext payload length

// ===== AES-128 PRE-SHARED KEY (must match Anchor stm.ino) =====
// *** CHANGE THIS KEY BEFORE DEPLOYMENT ***
// Replace all four words with cryptographically random values.
// Using a known placeholder here will NOT provide real security.
// Generate with: python3 -c "import os; d=os.urandom(16); print(','.join(hex(int.from_bytes(d[i:i+4],'big'))+'UL' for i in range(0,16,4)))"
static const dwt_aes_key_t aes_key = {
    0xAABBCCDDUL, 0xEEFF0011UL, 0x22334455UL, 0x66778899UL,
    0, 0, 0, 0   // upper 128 bits unused for AES-128
};
// Static assertion: ensure full/empty ADC calibration values differ
static_assert(BAT_ADC_FULL != BAT_ADC_EMPTY, "BAT ADC calibration error: FULL == EMPTY");

// ===== PIN DEFINITIONS =====
const uint8_t PIN_DW_CS  = 7;
const uint8_t PIN_DW_IRQ = 2;   // RTC IO - wakes from deep sleep
const uint8_t PIN_DW_RST = 3;
const uint8_t PIN_BAT_ADC = 0;  // GPIO0 = ADC1_CH0 (voltage divider)

// ===== BATTERY ADC CALIBRATION =====
// Voltage divider 1:2, ADC ref 3.3V (12-bit = 4095)
// 4.2V full -> 2.1V -> ADC ~2607; 3.3V empty -> 1.65V -> ADC ~2048
#define BAT_ADC_FULL  2607
#define BAT_ADC_EMPTY 2048

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
    DWT_STS_MODE_OFF,// No STS (faster, lower power)
    DWT_STS_LEN_64,  // STS length (unused)
    DWT_PDOA_M0      // No PDOA
};

#define TX_ANT_DLY              16385
#define RX_ANT_DLY              16385
#define POLL_RX_TO_RESP_TX_DLY_UUS 2000
#define RX_BUF_LEN              127

static uint8_t rx_buffer[RX_BUF_LEN];

// ===== GLOBAL STATE (preserved in RTC memory across deep sleep) =====
RTC_DATA_ATTR uint64_t poll_rx_ts  = 0;
RTC_DATA_ATTR uint64_t resp_tx_ts  = 0;
RTC_DATA_ATTR uint32_t frame_count = 0;
RTC_DATA_ATTR float    last_dist_m = 0.0f;  // Distance from last TWR cycle

// ===== ISR =====
volatile bool irq_fired = false;

// ===== FUNCTION PROTOTYPES =====
void IRAM_ATTR on_dw_irq(void);
void     init_dw3000(void);
void     enter_rx_and_sleep(void);
void     process_poll_and_respond(void);
void     configure_frame_filter(void);
uint8_t  read_battery_percent(void);
void     build_ccm_nonce(uint8_t *nonce, uint8_t seq, const uint8_t *rand_nonce);

// ===== SETUP =====
void setup() {
  pinMode(PIN_DW_CS, OUTPUT);
  digitalWrite(PIN_DW_CS, HIGH);
  pinMode(PIN_DW_RST, OUTPUT);
  digitalWrite(PIN_DW_RST, HIGH);
  pinMode(PIN_DW_IRQ, INPUT);

  // Configure battery ADC
  adc1_config_width(ADC_WIDTH_BIT_12);
  adc1_config_channel_atten(ADC1_CHANNEL_0, ADC_ATTEN_DB_11);

  init_dw3000();

  esp_sleep_enable_ext0_wakeup((gpio_num_t)PIN_DW_IRQ, 1);
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_ON);

  enter_rx_and_sleep();
}

// ===== MAIN LOOP (only reached after IRQ wakeup) =====
void loop() {
  process_poll_and_respond();
  enter_rx_and_sleep();
}

// ===== READ BATTERY PERCENT =====
uint8_t read_battery_percent(void) {
  // Guard against misconfigured calibration constants
  if (BAT_ADC_FULL == BAT_ADC_EMPTY) return 50;
  int raw = adc1_get_raw(ADC1_CHANNEL_0);
  int pct = (int)(((long)(raw - BAT_ADC_EMPTY) * 100L) / (BAT_ADC_FULL - BAT_ADC_EMPTY));
  if (pct < 0)   pct = 0;
  if (pct > 100) pct = 100;
  return (uint8_t)pct;
}

// ===== BUILD 13-BYTE CCM* NONCE =====
// Layout: [TAG_ADDR LE: 2B][ANC_ADDR LE: 2B][seq: 1B][rand: 4B][zeros: 4B]
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
    enter_rx_and_sleep();
  }

  if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR) {
    enter_rx_and_sleep();
  }

  if (dwt_configure(&config)) {
    enter_rx_and_sleep();
  }

  dwt_setrxantennadelay(RX_ANT_DLY);
  dwt_settxantennadelay(TX_ANT_DLY);
  dwt_setrxaftertxdelay(POLL_RX_TO_RESP_TX_DLY_UUS);

  configure_frame_filter();

  dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);
}

// ===== CONFIGURE FRAME FILTER =====
void configure_frame_filter(void) {
  dwt_configureframefilter(DWT_FF_DATA_EN | DWT_FF_ACK_EN, 0);
  dwt_setpanid(PAN_ID);
  dwt_setaddress16(TAG_ADDR);
}

// ===== ENTER RX + DEEP SLEEP =====
void enter_rx_and_sleep(void) {
  dwt_rxenable(DWT_START_RX_IMMEDIATE);
  delay(1);
  esp_deep_sleep_start();
  // Never reached until next wakeup
}

// ===== PROCESS POLL & SEND ENCRYPTED RESPONSE =====
void process_poll_and_respond(void) {
  uint32_t status_reg = dwt_read32bitreg(SYS_STATUS_ID);

  if (!(status_reg & SYS_STATUS_RXFCG_BIT_MASK)) {
    dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
    return;
  }

  dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);

  uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
  if (frame_len < 12 || frame_len > RX_BUF_LEN) {
    return;
  }

  dwt_readrxdata(rx_buffer, frame_len - 2, 0);

  // Verify POLL magic in payload (after 9-byte MAC header)
  // rx_buffer holds (frame_len - 2) bytes; last valid index = (frame_len - 3)
  int data_len = (int)(frame_len - 2);
  bool is_poll = false;
  for (int i = 9; i <= data_len - 4; i++) {
    if (rx_buffer[i]   == 'P' && rx_buffer[i+1] == 'O' &&
        rx_buffer[i+2] == 'L' && rx_buffer[i+3] == 'L') {
      is_poll = true;
      break;
    }
  }
  if (!is_poll) {
    return;
  }

  // --- TWR timestamp capture ---
  poll_rx_ts = get_rx_timestamp_u64();
  uint32_t resp_tx_time = (poll_rx_ts + ((uint64_t)POLL_RX_TO_RESP_TX_DLY_UUS * UUS_TO_DWT_TIME)) >> 8;
  dwt_setdelayedtrxtime(resp_tx_time);
  resp_tx_ts = (((uint64_t)(resp_tx_time & 0xFFFFFFFEUL)) << 8) + TX_ANT_DLY;

  uint8_t seq = rx_buffer[2] + 1;

  // --- Random 4-byte nonce (anti-replay) ---
  // Re-draw if zero to avoid anchor rejecting a legitimate frame (zero nonce = always rejected)
  uint32_t rand_word;
  do {
    rand_word = esp_random();
  } while (rand_word == 0);
  uint8_t  rand_nonce[4];
  rand_nonce[0] = (uint8_t)(rand_word & 0xFF);
  rand_nonce[1] = (uint8_t)((rand_word >> 8)  & 0xFF);
  rand_nonce[2] = (uint8_t)((rand_word >> 16) & 0xFF);
  rand_nonce[3] = (uint8_t)((rand_word >> 24) & 0xFF);

  // --- Build MAC header (9 bytes) ---
  // header[] is the AAD (authenticated but not encrypted)
  // Layout: [FC:2][SEQ:1][PAN:2][DST:2][SRC:2][TS_POLL_RX:4][TS_RESP_TX:4][NONCE:4] = 21B
  uint8_t header[21];
  uint8_t hi = 0;

  header[hi++] = 0x41;  // Frame Control byte 0 (data, 16-bit addr)
  header[hi++] = 0x88;  // Frame Control byte 1
  header[hi++] = seq;
  header[hi++] = (uint8_t)(PAN_ID    & 0xFF);
  header[hi++] = (uint8_t)(PAN_ID    >> 8);
  header[hi++] = (uint8_t)(ANCHOR_ADDR & 0xFF);
  header[hi++] = (uint8_t)(ANCHOR_ADDR >> 8);
  header[hi++] = (uint8_t)(TAG_ADDR    & 0xFF);
  header[hi++] = (uint8_t)(TAG_ADDR    >> 8);
  // TWR timestamps
  header[hi++] = (uint8_t)(poll_rx_ts & 0xFF);
  header[hi++] = (uint8_t)((poll_rx_ts >>  8) & 0xFF);
  header[hi++] = (uint8_t)((poll_rx_ts >> 16) & 0xFF);
  header[hi++] = (uint8_t)((poll_rx_ts >> 24) & 0xFF);
  header[hi++] = (uint8_t)(resp_tx_ts & 0xFF);
  header[hi++] = (uint8_t)((resp_tx_ts >>  8) & 0xFF);
  header[hi++] = (uint8_t)((resp_tx_ts >> 16) & 0xFF);
  header[hi++] = (uint8_t)((resp_tx_ts >> 24) & 0xFF);
  // Random nonce
  header[hi++] = rand_nonce[0];
  header[hi++] = rand_nonce[1];
  header[hi++] = rand_nonce[2];
  header[hi++] = rand_nonce[3];
  // hi == 21

  // --- Build plaintext payload ---
  uint8_t bat_pct = read_battery_percent();
  char payload_str[PAYLOAD_MAX_LEN + 1];
  char dist_buf[8];
  // Build "CMD:OPEN|DIST:x.xx|BAT:nnn"
  int dist_int  = (int)last_dist_m;
  int dist_frac = (int)((last_dist_m - dist_int) * 100.0f);
  snprintf(payload_str, sizeof(payload_str),
           "CMD:OPEN|DIST:%d.%02d|BAT:%u",
           dist_int, dist_frac, (unsigned)bat_pct);
  uint16_t payload_len = (uint16_t)strlen(payload_str);

  // --- Build 13-byte CCM* nonce ---
  uint8_t ccm_nonce[13];
  build_ccm_nonce(ccm_nonce, seq, rand_nonce);

  // --- Configure AES engine ---
  dwt_set_keyreg_128(&aes_key);

  dwt_aes_config_t aes_cfg;
  aes_cfg.aes_key_otp_type = AES_key_RAM;
  aes_cfg.aes_core_type    = AES_core_type_CCM;
  aes_cfg.mic              = MIC_4;                  // 4-byte MIC
  aes_cfg.key_src          = AES_KEY_Src_Register;   // Key from registers
  aes_cfg.key_load         = AES_KEY_No_Load;
  aes_cfg.key_addr         = 0;
  aes_cfg.key_size         = AES_KEY_128bit;
  aes_cfg.mode             = AES_Encrypt;
  dwt_configure_aes(&aes_cfg);

  // --- Perform AES-CCM* encryption ---
  // Plaintext (header + payload) written to SCRATCH; encrypted goes to TX buffer
  dwt_aes_job_t aes_job;
  aes_job.nonce       = ccm_nonce;
  aes_job.header      = header;
  aes_job.header_len  = hi;                  // 21 bytes AAD
  aes_job.payload     = (uint8_t *)payload_str;
  aes_job.payload_len = payload_len;
  aes_job.src_port    = AES_Src_Scratch;     // Plaintext in scratch
  aes_job.dst_port    = AES_Dst_Tx_buf;      // Ciphertext to TX buffer
  aes_job.mode        = AES_Encrypt;
  aes_job.mic_size    = MIC_LEN;             // 4 bytes

  int8_t aes_ret = dwt_do_aes(&aes_job, AES_core_type_CCM);
  if (aes_ret < 0) {
    // AES failed (size issue etc.) - abort
    return;
  }

  // TX buffer now contains: [header 21B][cipher ~30B][MIC 4B]
  uint16_t tx_frame_len = (uint16_t)(hi + payload_len + MIC_LEN);

  // Set TX frame control (ranging bit = 1)
  dwt_writetxfctrl(tx_frame_len, 0, 1);

  // Start delayed TX
  int ret = dwt_starttx(DWT_START_TX_DELAYED);
  if (ret == DWT_SUCCESS) {
    int timeout = 50;
    while (timeout-- > 0) {
      if (dwt_read32bitreg(SYS_STATUS_ID) & SYS_STATUS_TXFRS_BIT_MASK) {
        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_TXFRS_BIT_MASK);
        break;
      }
      delayMicroseconds(1000);
    }
  }

  frame_count++;
}

// ===== ISR (optional, for debug) =====
void IRAM_ATTR on_dw_irq(void) {
  irq_fired = true;
}

/*
 * CALIBRATION NOTES:
 *   BAT_ADC_FULL / BAT_ADC_EMPTY should be tuned to your specific battery
 *   and voltage divider values using a known reference voltage and multimeter.
 *
 * AES KEY NOTES:
 *   The aes_key must be identical on both Tag (this file) and Anchor (stm.ino).
 *   For production, provision the key via a secure out-of-band method.
 *
 * POWER BREAKDOWN:
 *   - ESP32-C3 Deep Sleep (RTC on):  ~5 µA
 *   - DW3000 RX (address filtered): ~8-12 mA pulsed
 *   - TX burst (~3 ms at 10 Hz):    ~100 mA peak, ~1.2 mA avg
 *   - Battery life (1000 mAh):      ~800 hours standby
 */
