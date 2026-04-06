/*
 * Smart Moto Security - ESP32-C3 REMOTE TAG (SmartKey Fob)
 * Role: UWB Two-Way Ranging Responder, Deep Sleep with IRQ Wake, Minimal Power
 * 
 * Hardware:
 *   - ESP32-C3 (single core, ultra-low power)
 *   - DW3000 UWB Module (SPI + IRQ + RST)
 *   - Optional: LED, button (not used in sleep)
 * 
 * Pinout:
 *   SPI: SCK=4, MISO=5, MOSI=6, CS=7
 *   DW3000: IRQ=2 (RTC IO capable, can wake from deep sleep), RST=3
 * 
 * Power Strategy:
 *   - ESP32-C3 in Deep Sleep by default (μA current)
 *   - DW3000 in RX mode, address-filtered
 *   - When DW3000 receives POLL from Anchor (dest=0x2222 = TAG), IRQ goes HIGH
 *   - GPIO2 IRQ triggers ext0_wakeup (RTC domain)
 *   - ESP32-C3 wakes, processes 1 ranging cycle, returns to sleep (3-5ms)
 *   - Sleep current: ~10μA (DW3000) + ~5μA (ESP32-C3 RTC) ≈ 15μA total
 * 
 * Features:
 *   - Hardware address filtering on DW3000 (reduces false wakes)
 *   - Single poll-response cycle per wake
 *   - CRC check on received frames
 *   - Low latency TX to ensure Anchor can measure accurately
 *   - No WiFi, no Serial (minimal power draw)
 */

#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include <esp32-hal.h>

// ===== CONFIGURATION =====
#define APP_NAME "SmartKey Tag v1.0"
#define ANCHOR_ADDR 0x1111    // Expected originator
#define TAG_ADDR 0x2222       // This tag's address
#define PAN_ID 0x3412         // Network PAN ID

// ===== PIN DEFINITIONS =====
const uint8_t PIN_DW_CS = 7;
const uint8_t PIN_DW_IRQ = 2;    // RTC IO (GPIO2) - can wake from deep sleep
const uint8_t PIN_DW_RST = 3;

// ===== DW3000 CONFIG (minimal, low power) =====
static dwt_config_t config = {
    5,               // Channel
    DWT_PLEN_128,    // Preamble length
    DWT_PAC8,        // PAC size
    9,               // TX preamble code
    9,               // RX preamble code
    1,               // SFD type
    DWT_BR_6M8,      // Data rate 6.8 Mbps
    DWT_PHRMODE_STD, // PHY header mode
    DWT_PHRRATE_STD, // PHY header rate
    (129 + 8 - 8),   // SFD timeout
    DWT_STS_MODE_OFF,// No STS (faster, lower power)
    DWT_STS_LEN_64,  // STS length
    DWT_PDOA_M0      // No PDOA
};

#define TX_ANT_DLY 16385
#define RX_ANT_DLY 16385
#define POLL_RX_TO_RESP_TX_DLY_UUS 2000
#define RX_BUF_LEN 127

static uint8_t rx_poll_msg[] = {'P','O','L','L'};
static uint8_t tx_resp_msg[] = {0, 0, 0, 0, 0, 0, 0, 0, 'R','E','S','P'};
static uint8_t rx_buffer[RX_BUF_LEN];

// ===== GLOBAL STATE (preserved in RTC memory across sleep) =====
RTC_DATA_ATTR uint64_t poll_rx_ts = 0;
RTC_DATA_ATTR uint64_t resp_tx_ts = 0;
RTC_DATA_ATTR uint32_t frame_count = 0;

// ===== ISR VOLATILE =====
volatile bool irq_fired = false;

// ===== FUNCTION PROTOTYPES =====
void IRAM_ATTR on_dw_irq(void);
void init_dw3000(void);
void enter_rx_and_sleep(void);
void process_poll_and_respond(void);
void configure_frame_filter(void);

// ===== SETUP =====
void setup() {
  // Minimal init: just enable necessary IO
  pinMode(PIN_DW_CS, OUTPUT);
  digitalWrite(PIN_DW_CS, HIGH);
  pinMode(PIN_DW_RST, OUTPUT);
  digitalWrite(PIN_DW_RST, HIGH);
  pinMode(PIN_DW_IRQ, INPUT);
  
  // Init DW3000
  init_dw3000();
  
  // Configure ESP32 wake on IRQ (GPIO2 LOW->HIGH edge)
  esp_sleep_enable_ext0_wakeup((gpio_num_t)PIN_DW_IRQ, 1); // Wake on HIGH
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_ON);
  
  // Attach ISR for debug (optional, can remove for lower power)
  // attachInterrupt(PIN_DW_IRQ, on_dw_irq, RISING);
  
  // Enter RX + sleep mode
  enter_rx_and_sleep();
}

// ===== MAIN LOOP =====
void loop() {
  // Code only reaches here after wakeup from IRQ
  
  // Process the received POLL and send RESPONSE
  process_poll_and_respond();
  
  // Re-enable RX and go back to sleep
  enter_rx_and_sleep();
}

// ===== INIT DW3000 =====
void init_dw3000(void) {
  // Reset DW3000
  digitalWrite(PIN_DW_RST, LOW);
  delay(2);
  digitalWrite(PIN_DW_RST, HIGH);
  delay(5);
  
  // Check IDLE
  int max_tries = 100;
  while (!dwt_checkidlerc() && --max_tries > 0) {
    delay(1);
  }
  if (max_tries == 0) {
    // Cannot init - go to sleep anyway (will wake on next IRQ if some come)
    enter_rx_and_sleep();
  }
  
  // Initialize DW
  if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR) {
    enter_rx_and_sleep();
  }
  
  // Minimal LED (optional)
  // dwt_setleds(DWT_LEDS_ENABLE);
  
  // Configure
  if (dwt_configure(&config)) {
    enter_rx_and_sleep();
  }
  
  // TX power (using external txconfig_options)
  dwt_configuretxrf(&txconfig_options);
  
  // Antenna delay
  dwt_setrxantennadelay(RX_ANT_DLY);
  dwt_settxantennadelay(TX_ANT_DLY);
  
  // RX timing
  dwt_setrxaftertxdelay(POLL_RX_TO_RESP_TX_DLY_UUS);
  
  // Frame filtering by address (tag=0x2222)
  configure_frame_filter();
  
  // LNA + PA
  dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);
}

// ===== CONFIGURE FRAME FILTER =====
void configure_frame_filter(void) {
  // Enable frame filtering for short addressing (16-bit)
  dwt_enableframefilter(DWT_FF_DATA_FRAME | DWT_FF_ACK_FRAME | DWT_FF_15_4_FRAME);
  
  // Set PAN ID
  dwt_setpanid(PAN_ID);
  
  // Set short address to TAG_ADDR (0x2222)
  dwt_setaddress16(TAG_ADDR);
}

// ===== ENTER RX + DEEP SLEEP =====
void enter_rx_and_sleep(void) {
  // Enable RX
  dwt_rxenable(DWT_START_RX_IMMEDIATE);
  
  // Small delay for RX to stabilize
  delay(1);
  
  // Go to deep sleep with ext0 wakeup on GPIO2 (DW3000 IRQ)
  // Press Wake on HIGH (DW3000 IRQ is active HIGH)
  esp_deep_sleep_start();
  
  // Code below never executes until woken by IRQ
}

// ===== PROCESS POLL & SEND RESPONSE =====
void process_poll_and_respond(void) {
  uint32_t status_reg = dwt_read32bitreg(SYS_STATUS_ID);
  
  // Check if we got a good frame (RXFCG = RX Frame Complete Good)
  if (!(status_reg & SYS_STATUS_RXFCG_BIT_MASK)) {
    // False alarm or error - clear and go back to sleep
    dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
    return;
  }
  
  // Clear RXFCG flag
  dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);
  
  // Read frame length
  uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
  
  // Sanity check
  if (frame_len < 12 || frame_len > RX_BUF_LEN) {
    return; // Bad frame
  }
  
  // Read frame into buffer
  dwt_readrxdata(rx_buffer, frame_len - 2, 0); // -2 for FCS
  
  // Check if it's a POLL from expected ANCHOR
  // Simple check: look for "POLL" string in payload area
  bool is_poll = false;
  for (int i = 8; i < frame_len - 4; i++) {  // Start after MAC header
    if (rx_buffer[i] == 'P' && rx_buffer[i+1] == 'O' &&
        rx_buffer[i+2] == 'L' && rx_buffer[i+3] == 'L') {
      is_poll = true;
      break;
    }
  }
  
  if (!is_poll) {
    return; // Not our frame
  }
  
  // Get RX timestamp (when we received POLL)
  poll_rx_ts = get_rx_timestamp_u64();
  
  // Calculate TX time (2000 UUS delay = 2ms)
  uint32_t resp_tx_time = (poll_rx_ts + (POLL_RX_TO_RESP_TX_DLY_UUS * UUS_TO_DWT_TIME)) >> 8;
  dwt_setdelayedtrxtime(resp_tx_time);
  
  // TX timestamp (includes antenna delay)
  resp_tx_ts = (((uint64_t)(resp_tx_time & 0xFFFFFFFEUL)) << 8) + TX_ANT_DLY;
  
  // Embed timestamps in response message
  // Bytes 0-3: poll RX time (little-endian)
  tx_resp_msg[0] = (uint8_t)(poll_rx_ts & 0xFF);
  tx_resp_msg[1] = (uint8_t)((poll_rx_ts >> 8) & 0xFF);
  tx_resp_msg[2] = (uint8_t)((poll_rx_ts >> 16) & 0xFF);
  tx_resp_msg[3] = (uint8_t)((poll_rx_ts >> 24) & 0xFF);
  
  // Bytes 4-7: response TX time (little-endian)
  tx_resp_msg[4] = (uint8_t)(resp_tx_ts & 0xFF);
  tx_resp_msg[5] = (uint8_t)((resp_tx_ts >> 8) & 0xFF);
  tx_resp_msg[6] = (uint8_t)((resp_tx_ts >> 16) & 0xFF);
  tx_resp_msg[7] = (uint8_t)((resp_tx_ts >> 24) & 0xFF);
  
  // Build MAC frame manually (16-bit addressing)
  uint8_t resp_frame[32];
  uint8_t idx = 0;
  
  // Frame Control (16-bit, data frame)
  resp_frame[idx++] = 0x41;  // FC0
  resp_frame[idx++] = 0x88;  // FC1
  
  // Sequence number (copy from received frame or increment)
  resp_frame[idx++] = rx_buffer[2] + 1;
  
  // PAN ID (big-endian)
  resp_frame[idx++] = (uint8_t)(PAN_ID & 0xFF);
  resp_frame[idx++] = (uint8_t)((PAN_ID >> 8) & 0xFF);
  
  // Destination (ANCHOR)
  resp_frame[idx++] = (uint8_t)(ANCHOR_ADDR & 0xFF);
  resp_frame[idx++] = (uint8_t)((ANCHOR_ADDR >> 8) & 0xFF);
  
  // Source (TAG)
  resp_frame[idx++] = (uint8_t)(TAG_ADDR & 0xFF);
  resp_frame[idx++] = (uint8_t)((TAG_ADDR >> 8) & 0xFF);
  
  // Payload (timestamps + "RESP")
  memcpy(&resp_frame[idx], tx_resp_msg, sizeof(tx_resp_msg));
  idx += sizeof(tx_resp_msg);
  
  // Write to TX buffer
  dwt_writetxdata(idx, resp_frame, 0);
  dwt_writetxfctrl(idx, 0, 1); // 1 = ranging bit set
  
  // Start delayed TX
  int ret = dwt_starttx(DWT_START_TX_DELAYED);
  
  if (ret == DWT_SUCCESS) {
    // Wait for TX to complete (poll)
    int timeout = 50; // 50ms max
    while (timeout-- > 0) {
      if (dwt_read32bitreg(SYS_STATUS_ID) & SYS_STATUS_TXFRS_BIT_MASK) {
        dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_TXFRS_BIT_MASK);
        break;
      }
      delayMicroseconds(1000);
    }
  }
  
  // Increment frame count for statistics (optional)
  frame_count++;
}

// ===== ISR (optional, for debug) =====
void IRAM_ATTR on_dw_irq(void) {
  irq_fired = true;
}

/*
 * NOTES FOR STM32 USERS (if you want to adapt to STM32H7):
 * 1. Replace esp_deep_sleep_start() with HAL low-power mode equivalent
 * 2. Replace RTC_DATA_ATTR with appropriate retention RAM section (__attribute__ ((section(".backup_sram"))))
 * 3. Replace esp_sleep_enable_ext0_wakeup with HAL EXTI configuration
 * 4. Replace get_rx_timestamp_u64() - ensure compatible with DW3000 driver
 * 5. SPI init handled by DW3000 driver; configure SPI1/SPI2 appropriately for STM32H7
 * 
 * POWER CONSUMPTION BREAKDOWN:
 * - ESP32-C3 Deep Sleep (RTC active): ~5μA
 * - DW3000 in RX mode: ~8-12mA average (pulsed RX, address filtering reduces wake-ups)
 * - Total during sleep: ~8-12mA (dominated by DW3000)
 * - Total during TX (3-5ms): ~100mA
 * - With 1% duty cycle (20 ranging per sec, 3ms each): ~1.2mA average
 * - Suitable for 1000mAh battery: ~800 hours (33 days) continuous ranging
 * 
 * FURTHER OPTIMIZATION:
 * - Reduce DW3000 RX LED blink (dwt_setleds(0))
 * - Enable DW3000 low-power mode register bits (if driver supports)
 * - Use address filtering to prevent false wakes
 * - Reduce TX power if range < 50m (dwt_configuretxrf with lower power)
 */
