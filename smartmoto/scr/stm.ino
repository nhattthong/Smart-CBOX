/*
 * Smart Moto Security - STM32F103C8T6 ANCHOR (SmartKey Controller)
 * Role: UWB Two-Way Ranging Initiator, Relay Control, UART to ESP32-S3 Monitor
 * 
 * Hardware:
 *   - STM32F103C8T6 (BluePill)
 *   - DW3000 UWB Module (SPI1 + IRQ + RST)
 *   - Relay 5V (GPIO control)
 *   - UART1 to ESP32-S3 for status updates
 * 
 * Pinout:
 *   SPI1: CLK=PA5, MISO=PA6, MOSI=PA7, CS=PA4
 *   DW3000: IRQ=PB0, RST=PA1
 *   Relay: PB1 (HIGH=ON, LOW=OFF)
 *   UART1: TX=PA9, RX=PA10 (to ESP32-S3)
 * 
 * Features:
 *   - Continuous polling for UWB tag (0x2222)
 *   - Distance calculation via Two-Way Ranging
 *   - Relay hysteresis: ON @ <1.5m, OFF @ >3.0m, timeout 5s
 *   - Serial output: "KEY:ON", "KEY:OFF", "DIST:1.2m"
 *   - Independent Watchdog (IWDG) anti-hang protection
 *   - Optimized for fast response (100ms ranging interval)
 */

#if defined(ARDUINO_ARCH_STM32) || defined(ARDUINO_ARCH_STM32F1) || defined(__STM32F1__)
// Provide compatibility macros for DW3000 library builds on STM32 (no library edits)
// Map FreeRTOS port critical macros to Arduino interrupt primitives for STM32duino
#ifndef portENTER_CRITICAL
#define portENTER_CRITICAL(mutex) noInterrupts()
#endif
#ifndef portEXIT_CRITICAL
#define portEXIT_CRITICAL(mutex) interrupts()
#endif
#ifndef portDISABLE_INTERRUPTS
#define portDISABLE_INTERRUPTS() noInterrupts()
#endif
#ifndef portENABLE_INTERRUPTS
#define portENABLE_INTERRUPTS() interrupts()
#endif
#endif
#include "dw3000.h"
#include "dw3000_mac_802_15_4.h"
#include <IWatchdog.h>

// Ensure txconfig_options defined in DW3000 port/example is visible here
extern dwt_txconfig_t txconfig_options;

// ===== CONFIGURATION =====
#define APP_NAME "SmartKey Anchor v1.0"
#define TAG_ADDR 0x2222      // Target remote tag address
#define ANCHOR_ADDR 0x1111   // This anchor address
#define RANGING_INTERVAL_MS 100

// Relay control hysteresis
#define DISTANCE_THRESHOLD_ON  1.5f   // meters - turn relay ON when closer
#define DISTANCE_THRESHOLD_OFF 3.0f   // meters - turn relay OFF when farther
#define SIGNAL_TIMEOUT_MS 5000        // 5 seconds no ranging = OFF

// ===== PIN DEFINITIONS =====
const uint8_t PIN_DW_CS = PA4;
const uint8_t PIN_DW_IRQ = PB0;
const uint8_t PIN_DW_RST = PA1;
const uint8_t PIN_RELAY = PB1;

// ===== DW3000 CONFIG =====
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
    DWT_STS_MODE_OFF,// No STS
    DWT_STS_LEN_64,  // STS length
    DWT_PDOA_M0      // No PDOA
};

#define TX_ANT_DLY 16385
#define RX_ANT_DLY 16385
#define POLL_TX_TO_RESP_RX_DLY_UUS 1720
#define RESP_RX_TIMEOUT_UUS 250
#define RX_BUF_LEN 127

static uint8_t tx_poll_msg[] = {'P','O','L','L'};
static uint8_t rx_resp_msg[] = {0, 0, 0, 0, 0, 0, 0, 0, 'R','E','S','P'};
static uint8_t rx_buffer[RX_BUF_LEN];

// ===== GLOBAL STATE =====
double last_distance = -1.0;
uint32_t last_ranging_time = 0;
bool relay_state = false;         // false=OFF, true=ON
bool relay_cmd_pending = false;
uint32_t last_signal_time = 0;

// Frame control for 16-bit addressing
#define MAC_FRAME_CTRL {0x41, 0x88}  // Data frame, 16-bit addressing, no security

// ===== FUNCTION PROTOTYPES =====
void init_dw3000(void);
void send_poll_frame(void);
void receive_and_process_response(void);
void update_relay(void);
void send_to_esp32(const char *msg);
void print_debug(const char *msg);

// ===== SETUP =====
void setup() {
  delay(1000); // Wait for serial stabilization
  
  // Serial1 to ESP32-S3 (PA9/PA10)
  Serial1.begin(115200);
  print_debug("=== SmartKey Anchor Starting ===");
  
  // GPIO setup
  pinMode(PIN_DW_CS, OUTPUT);
  digitalWrite(PIN_DW_CS, HIGH);
  pinMode(PIN_DW_RST, OUTPUT);
  digitalWrite(PIN_DW_RST, HIGH);
  pinMode(PIN_RELAY, OUTPUT);
  digitalWrite(PIN_RELAY, LOW);  // Relay OFF initially
  pinMode(PIN_DW_IRQ, INPUT);
  
  // Init Independent Watchdog (8s timeout)
  IWatchdog.begin(8000000); // 8 seconds
  
  // SPI1 init (handled by DW library)
  // Configure DW3000
  init_dw3000();
  
  print_debug("SmartKey Anchor Ready");
  last_ranging_time = millis();
  last_signal_time = millis();
}

// ===== MAIN LOOP =====
void loop() {
  IWatchdog.reload(); // Kick watchdog
  
  uint32_t now = millis();
  
  // Ranging interval control
  if (now - last_ranging_time >= RANGING_INTERVAL_MS) {
    last_ranging_time = now;
    
    send_poll_frame();
    delay(10); // Brief settle time
    receive_and_process_response();
    
    // Update relay state based on distance
    update_relay();
  }
  
  delay(5); // Small delay to prevent CPU hogging
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
    print_debug("DW3000 IDLE check failed");
    while(1);
  }
  
  // Initialize
  if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR) {
    print_debug("DW3000 Init failed");
    while(1);
  }
  
  // Enable LEDs (debug)
  dwt_setleds(DWT_LEDS_ENABLE | DWT_LEDS_INIT_BLINK);
  
  // Configure
  if (dwt_configure(&config)) {
    print_debug("DW3000 Config failed");
    while(1);
  }
  
  // TX power from txconfig_options (external)
  dwt_configuretxrf(&txconfig_options);
  
  // Antenna delay
  dwt_setrxantennadelay(RX_ANT_DLY);
  dwt_settxantennadelay(TX_ANT_DLY);
  
  // RX timing
  dwt_setrxaftertxdelay(POLL_TX_TO_RESP_RX_DLY_UUS);
  dwt_setrxtimeout(RESP_RX_TIMEOUT_UUS);
  
  // LNA + PA
  dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);
  
  print_debug("DW3000 Initialized OK");
}

// ===== SEND POLL FRAME =====
void send_poll_frame(void) {
  // Build simple MAC frame (16-bit addressing, no security for simplicity)
  uint8_t poll_frame[16];
  uint8_t idx = 0;
  
  // Frame Control (16-bit addr, data frame)
  poll_frame[idx++] = 0x41;  // FC0
  poll_frame[idx++] = 0x88;  // FC1
  
  // Sequence number
  static uint8_t seq_num = 0;
  poll_frame[idx++] = seq_num++;
  
  // PAN ID (big-endian for 802.15.4)
  poll_frame[idx++] = 0x34;
  poll_frame[idx++] = 0x12;
  
  // Dest addr (TAG)
  poll_frame[idx++] = (uint8_t)(TAG_ADDR & 0xFF);
  poll_frame[idx++] = (uint8_t)((TAG_ADDR >> 8) & 0xFF);
  
  // Source addr (ANCHOR)
  poll_frame[idx++] = (uint8_t)(ANCHOR_ADDR & 0xFF);
  poll_frame[idx++] = (uint8_t)((ANCHOR_ADDR >> 8) & 0xFF);
  
  // Payload: "POLL"
  memcpy(&poll_frame[idx], tx_poll_msg, sizeof(tx_poll_msg));
  idx += sizeof(tx_poll_msg);
  
  // Write to TX buffer
  dwt_writetxdata(idx, poll_frame, 0);
  dwt_writetxfctrl(idx, 0, 1); // 1 = ranging bit
  
  // Transmit expecting response
  dwt_starttx(DWT_START_TX_IMMEDIATE | DWT_RESPONSE_EXPECTED);
}

// ===== RECEIVE & PROCESS RESPONSE =====
void receive_and_process_response(void) {
  uint32_t status_reg;
  int timeout = 500; // 500ms timeout for response
  uint32_t start = millis();
  
  // Poll for RX completion or timeout
  while ((millis() - start) < timeout) {
    status_reg = dwt_read32bitreg(SYS_STATUS_ID);
    
    if (status_reg & SYS_STATUS_RXFCG_BIT_MASK) {
      // Got good frame
      uint32_t frame_len = dwt_read32bitreg(RX_FINFO_ID) & RXFLEN_MASK;
      
      // Clear flag
      dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_RXFCG_BIT_MASK);
      
      // Read frame
      dwt_readrxdata(rx_buffer, frame_len - 2, 0); // -2 for FCS
      
      // Simple frame check: look for "RESP" in payload
      bool is_resp = false;
      for (int i = 0; i < frame_len - 10; i++) {
        if (rx_buffer[i] == 'R' && rx_buffer[i+1] == 'E' &&
            rx_buffer[i+2] == 'S' && rx_buffer[i+3] == 'P') {
          is_resp = true;
          break;
        }
      }
      
      if (is_resp) {
        // Read timestamps for ToF calculation
        uint32_t poll_tx_ts = dwt_readtxtimestamplo32();
        uint32_t resp_rx_ts = dwt_readrxtimestamplo32();
        
        // Get embedded timestamps from response (first 8 bytes of payload)
        uint32_t poll_rx_ts = (rx_buffer[0] << 0) | (rx_buffer[1] << 8) | 
                              (rx_buffer[2] << 16) | (rx_buffer[3] << 24);
        uint32_t resp_tx_ts = (rx_buffer[4] << 0) | (rx_buffer[5] << 8) | 
                              (rx_buffer[6] << 16) | (rx_buffer[7] << 24);
        
        // Calculate ToF
        int32_t rtd_init = resp_rx_ts - poll_tx_ts;
        int32_t rtd_resp = resp_tx_ts - poll_rx_ts;
        float clockOffsetRatio = ((float)dwt_readclockoffset()) / (1UL << 26);
        
        double tof = ((rtd_init - rtd_resp * (1.0 - clockOffsetRatio)) / 2.0) * DWT_TIME_UNITS;
        last_distance = tof * SPEED_OF_LIGHT;
        last_signal_time = millis();
        
        // Debug output
        char dist_str[64];
        snprintf(dist_str, sizeof(dist_str), "DIST:%.2f", last_distance);
        send_to_esp32(dist_str);
      }
      
      return;
    }
    
    // Check for RX error
    if (status_reg & (SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO)) {
      dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_ERR | SYS_STATUS_ALL_RX_TO);
      return;
    }
    
    delay(1);
  }
  
  // RX timeout
  dwt_write32bitreg(SYS_STATUS_ID, SYS_STATUS_ALL_RX_TO | SYS_STATUS_ALL_RX_ERR);
}

// ===== UPDATE RELAY STATE (Hysteresis) =====
void update_relay(void) {
  uint32_t now = millis();
  bool new_relay_state = relay_state;
  
  // Check signal timeout
  if (now - last_signal_time > SIGNAL_TIMEOUT_MS) {
    // No signal for too long -> force OFF
    new_relay_state = false;
  } else if (last_distance >= 0) {
    // Valid distance measured
    if (relay_state == false && last_distance < DISTANCE_THRESHOLD_ON) {
      // Closed enough and relay is OFF -> turn ON
      new_relay_state = true;
    } else if (relay_state == true && last_distance > DISTANCE_THRESHOLD_OFF) {
      // Far enough and relay is ON -> turn OFF
      new_relay_state = false;
    }
  }
  
  // Apply relay change
  if (new_relay_state != relay_state) {
    relay_state = new_relay_state;
    digitalWrite(PIN_RELAY, relay_state ? HIGH : LOW);
    
    const char *msg = relay_state ? "KEY:ON" : "KEY:OFF";
    send_to_esp32(msg);
  }
}

// ===== SEND MESSAGE TO ESP32-S3 =====
void send_to_esp32(const char *msg) {
  Serial1.print(msg);
  Serial1.print("\r\n");
  Serial1.flush();
}

// ===== DEBUG PRINT =====
void print_debug(const char *msg) {
  // For debugging via SWD or UART0 if available
  // Can be removed to save memory
}

/*
 * NOTES:
 * 1. This code assumes:
 *    - DW3000 Makerfabs library ported to Arduino IDE with STM32duino
 *    - Board selected: "Generic STM32F1 series" -> "BluePill F103C8"
 *    - SPI1 pins: PA5=CLK, PA6=MISO, PA7=MOSI
 *    - txconfig_options is defined externally in the DW3000 driver
 * 2. Timestamp synchronization: This basic version uses local timestamps.
 *    For production, consider clock offset correction more carefully.
 * 3. Relay control: Set PIN_RELAY to HIGH to energize relay (activate 12V circuit).
 *    Connect GPIO to relay coil via transistor+diode for protection.
 * 4. Watchdog: IWatchdog is enabled at 8s timeout. Each loop() reloads it.
 *    If firmware hangs, STM32 will auto-reset.
 * 5. Serial1 UART: TX=PA9 goes to ESP32-S3 RX. Configure ESP32 Serial2(17,18)
 *    to match baud rate 115200.
 */
