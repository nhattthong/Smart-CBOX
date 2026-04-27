/*
 * JK BMS Bluetooth BLE Reader - ESP32-S3
 * Version 1.0
 *
 * Connects to a JK BMS via BLE and reads real-time battery parameters:
 *   - Pack voltage (V), current (A), power (W)
 *   - State of Charge (%)
 *   - MOSFET & battery temperatures (°C)
 *   - Individual cell voltages (V), cell min/max/delta
 *   - Balance current (mA), charge cycle count
 *
 * Target BLE device name : "KLARA THONG"  (JK BMS unit)
 * Board                  : ESP32-S3
 * Upload port            : COM32
 *
 * Protocol  : JK BMS 0x4E57 BLE UART
 *   BLE Service  : 0000FFE0-0000-1000-8000-00805F9B34FB
 *   Notify (RX)  : 0000FFE1-0000-1000-8000-00805F9B34FB
 *   Write  (TX)  : 0000FFE2-0000-1000-8000-00805F9B34FB
 *                  (falls back to FFE1 when FFE2 is absent)
 *
 * Web UI : http://<ip>/          — live dashboard (auto-refresh 2 s)
 *          http://<ip>/api/data  — JSON snapshot of all BMS fields
 * Serial : 115200 baud — human-readable status printed every 2 s
 *
 * WiFi   : Tries STA first (WIFI_SSID / WIFI_PASS).
 *          Falls back to AP "JKBMS_Monitor" / "12345678" on failure.
 *
 * Libraries required (install via Arduino Library Manager):
 *   ESP32 BLE Arduino  (built-in with ESP32 board package)
 *   WiFi               (built-in)
 *   WebServer          (built-in)
 */

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEClient.h>
#include <BLERemoteService.h>
#include <BLERemoteCharacteristic.h>
#include <WiFi.h>
#include <WebServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

// ===== USER CONFIGURATION =====
#define BMS_DEVICE_NAME   "KLARA THONG"   // JK BMS BLE advertised name
#define WIFI_SSID         "Moto_4G"       // WiFi network SSID
#define WIFI_PASS         "1234567890"    // WiFi network password
#define WEB_PORT          80
#define SERIAL_BAUD       115200

// ===== TIMING =====
#define BLE_SCAN_SEC      5               // seconds per BLE scan window
#define BLE_POLL_MS       3000            // ms between data requests
#define BLE_RETRY_MS      5000            // ms before reconnect attempt
#define SERIAL_PRINT_MS   2000            // ms between Serial prints

// ===== LIMITS =====
#define MAX_CELLS         24              // maximum cells supported
#define RX_BUF_SIZE       1024            // BLE reassembly buffer (bytes)
// Cell JSON buffer: each entry is at most "x.xxx," = 6 chars, plus '[', ']', '\0'
#define CELLS_JSON_SIZE   (MAX_CELLS * 6 + 3)

// ===== JK BMS BLE SERVICE / CHARACTERISTIC UUIDs =====
static BLEUUID SVC_UUID    ("0000ffe0-0000-1000-8000-00805f9b34fb");
static BLEUUID NOTIFY_UUID ("0000ffe1-0000-1000-8000-00805f9b34fb");
static BLEUUID WRITE_UUID  ("0000ffe2-0000-1000-8000-00805f9b34fb");

// ===== JK BMS REQUEST FRAME — "Get All Data" (0x06) =====
// Frame layout (21 bytes, big-endian):
//   [0-1]  4E 57        Start of frame
//   [2-3]  00 13        Length field = total_bytes - 2 header = 19
//   [4-7]  00 00 00 00  Terminal / device ID (broadcast = 0)
//   [8]    06           Command: read all data
//   [9]    03           Frame source: host (0x03)
//   [10]   00           Transport type
//   [11-14] 00 00 00 00 Record number (4 bytes)
//   [15]   00           Reserved
//   [16]   68           End-of-data marker
//   [17-20] 00 00 01 29 CRC = sum of bytes [0]..[16] = 0x129 = 297
static const uint8_t JK_REQUEST[] = {
  0x4E, 0x57,
  0x00, 0x13,
  0x00, 0x00, 0x00, 0x00,
  0x06,
  0x03,
  0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00,
  0x68,
  0x00, 0x00, 0x01, 0x29
};

// ===== JK BMS TLV TAG IDs (response) =====
// Response TLV layout per record: [tag 1B][length 1B][value nB big-endian]
#define TAG_CELL_VOLTAGES  0x83   // 2 bytes per cell, unit: 1 mV
#define TAG_MOSFET_TEMP    0x84   // int16, unit: 0.1 °C
#define TAG_BAT_TEMP1      0x85   // int16, unit: 0.1 °C
#define TAG_BAT_TEMP2      0x86   // int16, unit: 0.1 °C
#define TAG_BAT_VOLTAGE    0x87   // uint16, unit: 10 mV  → ×0.01 V
#define TAG_BALANCE_CURR   0x88   // uint16, unit: 1 mA
#define TAG_BAT_CURRENT    0x89   // int16,  unit: 10 mA  → ×0.01 A
#define TAG_SOC            0x8A   // uint16, unit: 1 %
#define TAG_CYCLE_COUNT    0x8B   // uint32
#define TAG_CYCLE_CAP      0x8C   // uint32, unit: 10 mAh → ×0.01 Ah

// ===== BMS DATA STRUCTURE =====
typedef struct {
  float    voltage;              // Pack voltage (V)
  float    current;              // Pack current (A) — positive=charge
  float    power;                // Power (W) = voltage × current
  float    soc;                  // State of charge (%)
  float    temp_mos;             // MOSFET temperature (°C)
  float    temp_bat1;            // Battery temperature sensor 1 (°C)
  float    temp_bat2;            // Battery temperature sensor 2 (°C)
  float    balance_ma;           // Active balance current (mA)
  uint16_t cell_count;           // Number of cells detected
  float    cell_volt[MAX_CELLS]; // Per-cell voltage (V)
  float    cell_min;             // Lowest cell voltage (V)
  float    cell_max;             // Highest cell voltage (V)
  float    cell_delta;           // cell_max − cell_min (V)
  uint32_t cycle_count;          // Total charge cycles
  float    cycle_cap_ah;         // Cumulative capacity (Ah)
  uint32_t timestamp_ms;         // millis() at last successful parse
  bool     valid;                // True when at least one frame was decoded
} jkbms_data_t;

// ===== GLOBALS =====
static jkbms_data_t      bms_data;
static SemaphoreHandle_t bms_mutex      = NULL;

static BLEAddress       *bms_addr       = nullptr;
static BLEClient        *ble_client     = nullptr;
static volatile bool     ble_connected  = false;
static volatile bool     ble_found      = false;
static volatile bool     do_reconnect   = false;

static uint8_t  rx_buf[RX_BUF_SIZE];
static uint16_t rx_len = 0;

static WebServer web_server(WEB_PORT);

// ===== FORWARD DECLARATIONS =====
static bool parse_jkbms_frame(const uint8_t *buf, uint16_t len);
static bool ble_connect(void);
static void web_handle_root(void);
static void web_handle_api(void);

// ─────────────────────────────────────────────
// BLE SCAN CALLBACK
// ─────────────────────────────────────────────
class ScanCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) override {
    if (dev.getName() == BMS_DEVICE_NAME) {
      Serial.printf("[BLE] Found '%s' → %s\n",
                    BMS_DEVICE_NAME,
                    dev.getAddress().toString().c_str());
      BLEDevice::getScan()->stop();
      bms_addr  = new BLEAddress(dev.getAddress());
      ble_found = true;
    }
  }
};

// ─────────────────────────────────────────────
// BLE CLIENT CALLBACKS
// ─────────────────────────────────────────────
class ClientCB : public BLEClientCallbacks {
  void onConnect(BLEClient *) override {
    Serial.println("[BLE] Connected");
    ble_connected = true;
  }
  void onDisconnect(BLEClient *) override {
    Serial.println("[BLE] Disconnected — will retry");
    ble_connected = false;
    do_reconnect  = true;
    rx_len        = 0;
  }
};

// Static instances — reused across every scan/connect cycle (no heap leak)
static ScanCB   scan_cb_instance;
static ClientCB client_cb_instance;

// ─────────────────────────────────────────────
// BLE NOTIFY CALLBACK — reassemble multi-packet frames
// ─────────────────────────────────────────────
static void ble_notify_cb(BLERemoteCharacteristic *,
                          uint8_t *data, size_t length, bool)
{
  // Guard against buffer overflow
  if (rx_len + length >= RX_BUF_SIZE) {
    Serial.println("[BLE] RX overflow — flushing buffer");
    rx_len = 0;
  }
  memcpy(rx_buf + rx_len, data, length);
  rx_len += (uint16_t)length;

  // Wait until we have at least 4 bytes to read the length field
  if (rx_len < 4) return;

  // Discard garbage until we see the 4E 57 header
  if (rx_buf[0] != 0x4E || rx_buf[1] != 0x57) {
    rx_len = 0;
    return;
  }

  uint16_t frame_data_len = ((uint16_t)rx_buf[2] << 8) | rx_buf[3];
  uint16_t total           = frame_data_len + 2; // +2 for 4E 57 header

  if (total > RX_BUF_SIZE) {
    Serial.printf("[BLE] Frame too large (%u bytes) — discarding\n", total);
    rx_len = 0;
    return;
  }

  // Not enough bytes yet — wait for more notifications
  if (rx_len < total) return;

  // Full frame received — attempt parse
  if (parse_jkbms_frame(rx_buf, total)) {
    // Frame OK — optionally echo raw hex for debugging
    // Serial.printf("[BLE] Raw %u bytes: ", total);
    // for (int i = 0; i < total; i++) Serial.printf("%02X ", rx_buf[i]);
    // Serial.println();
  } else {
    Serial.printf("[BLE] Parse failed — raw %u bytes:", total);
    for (int i = 0; i < (int)total && i < 32; i++)
      Serial.printf(" %02X", rx_buf[i]);
    Serial.println("...");
  }
  rx_len = 0;
}

// ─────────────────────────────────────────────
// JK BMS FRAME PARSER
// ─────────────────────────────────────────────
// Response frame layout:
//   [0-1]   4E 57         start marker
//   [2-3]   LEN           total_bytes − 2  (big-endian)
//   [4-7]   device_id     4 bytes (BMS serial)
//   [8]     record_type   0x03 = data frame
//   [9]     source        0x02 = BMS
//   [10]    transport     0x01 = response
//   [11]    seq_no        1 byte
//   [12..total-6]  TLV records
//   [total-5]      0x68   end-of-data marker
//   [total-4..total-1]    CRC (uint32 big-endian, sum bytes [0]..[total-5])
static bool parse_jkbms_frame(const uint8_t *buf, uint16_t len)
{
  if (len < 17) return false;
  if (buf[0] != 0x4E || buf[1] != 0x57) return false;

  // Validate length field
  uint16_t declared = ((uint16_t)buf[2] << 8) | buf[3];
  if ((uint16_t)(declared + 2) != len) return false;

  // Locate end marker (0x68) — must be 5 bytes before end
  int end_pos = (int)len - 5;
  if (end_pos < 12 || buf[end_pos] != 0x68) {
    // Some firmware places the end marker 4 bytes before end
    end_pos = (int)len - 4;
    if (end_pos < 12 || buf[end_pos] != 0x68) return false;
  }

  // Verify CRC: sum of bytes [0]..[end_pos] must equal bytes [end_pos+1]..[end_pos+4]
  uint32_t calc_crc = 0;
  for (int i = 0; i <= end_pos; i++) calc_crc += buf[i];
  uint32_t frame_crc = ((uint32_t)buf[end_pos + 1] << 24)
                     | ((uint32_t)buf[end_pos + 2] << 16)
                     | ((uint32_t)buf[end_pos + 3] <<  8)
                     |  (uint32_t)buf[end_pos + 4];
  if (calc_crc != frame_crc) {
    Serial.printf("[BMS] CRC mismatch: calc=0x%08X frame=0x%08X\n",
                  (unsigned)calc_crc, (unsigned)frame_crc);
    return false;
  }

  // TLV records start at byte 12 (after fixed 11-byte header + 1-byte seq)
  int tlv_start = 12;

  jkbms_data_t d;
  memset(&d, 0, sizeof(d));
  d.cell_min = 9999.0f;

  for (int pos = tlv_start; pos < end_pos; ) {
    if (pos + 2 > end_pos) break;
    uint8_t tag  = buf[pos++];
    uint8_t tlen = buf[pos++];
    if (pos + tlen > end_pos) break;

    const uint8_t *v = buf + pos;
    pos += tlen;

    switch (tag) {

      case TAG_CELL_VOLTAGES: {
        // 2 bytes per cell (big-endian), unit: 1 mV
        int nc = tlen / 2;
        if (nc > MAX_CELLS) nc = MAX_CELLS;
        d.cell_count = (uint16_t)nc;
        d.cell_min   = 9999.0f;
        d.cell_max   = 0.0f;
        for (int i = 0; i < nc; i++) {
          uint16_t mv = ((uint16_t)v[i * 2] << 8) | v[i * 2 + 1];
          d.cell_volt[i] = mv * 0.001f;
          if (d.cell_volt[i] < d.cell_min) d.cell_min = d.cell_volt[i];
          if (d.cell_volt[i] > d.cell_max) d.cell_max = d.cell_volt[i];
        }
        d.cell_delta = d.cell_max - d.cell_min;
        break;
      }

      case TAG_MOSFET_TEMP:
        if (tlen >= 2)
          d.temp_mos = (int16_t)(((uint16_t)v[0] << 8) | v[1]) * 0.1f;
        break;

      case TAG_BAT_TEMP1:
        if (tlen >= 2)
          d.temp_bat1 = (int16_t)(((uint16_t)v[0] << 8) | v[1]) * 0.1f;
        break;

      case TAG_BAT_TEMP2:
        if (tlen >= 2)
          d.temp_bat2 = (int16_t)(((uint16_t)v[0] << 8) | v[1]) * 0.1f;
        break;

      case TAG_BAT_VOLTAGE:
        // unit: 10 mV  →  × 0.01 V
        if (tlen >= 2)
          d.voltage = (((uint16_t)v[0] << 8) | v[1]) * 0.01f;
        break;

      case TAG_BALANCE_CURR:
        // unit: 1 mA
        if (tlen >= 2)
          d.balance_ma = (((uint16_t)v[0] << 8) | v[1]);
        break;

      case TAG_BAT_CURRENT:
        // unit: 10 mA  →  × 0.01 A   (signed)
        if (tlen >= 2)
          d.current = (int16_t)(((uint16_t)v[0] << 8) | v[1]) * 0.01f;
        break;

      case TAG_SOC:
        // unit: 1 %
        if (tlen >= 2)
          d.soc = (((uint16_t)v[0] << 8) | v[1]);
        break;

      case TAG_CYCLE_COUNT:
        if (tlen >= 4)
          d.cycle_count = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16)
                        | ((uint32_t)v[2] <<  8) |  (uint32_t)v[3];
        break;

      case TAG_CYCLE_CAP:
        // unit: 10 mAh  →  × 0.01 Ah
        if (tlen >= 4) {
          uint32_t raw = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16)
                       | ((uint32_t)v[2] <<  8) |  (uint32_t)v[3];
          d.cycle_cap_ah = raw * 0.01f;
        }
        break;

      default:
        // Unknown tag — skip silently
        break;
    }
  }

  // Basic sanity check
  if (d.voltage < 0.5f) return false;

  d.power        = d.voltage * d.current;
  d.timestamp_ms = millis();
  d.valid        = true;

  if (xSemaphoreTake(bms_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    bms_data = d;
    xSemaphoreGive(bms_mutex);
  }
  return true;
}

// ─────────────────────────────────────────────
// BLE CONNECT HELPER
// ─────────────────────────────────────────────
static bool ble_connect(void)
{
  if (!bms_addr) return false;

  // Clean up any previous client
  if (ble_client) {
    if (ble_client->isConnected()) ble_client->disconnect();
    delete ble_client;
    ble_client = nullptr;
  }

  ble_client = BLEDevice::createClient();
  ble_client->setClientCallbacks(&client_cb_instance);

  Serial.printf("[BLE] Connecting to %s ...\n",
                bms_addr->toString().c_str());

  if (!ble_client->connect(*bms_addr)) {
    Serial.println("[BLE] Connection failed");
    return false;
  }

  BLERemoteService *svc = ble_client->getService(SVC_UUID);
  if (!svc) {
    Serial.println("[BLE] Service FFE0 not found");
    ble_client->disconnect();
    return false;
  }

  // Notify characteristic FFE1
  BLERemoteCharacteristic *nc = svc->getCharacteristic(NOTIFY_UUID);
  if (!nc) {
    Serial.println("[BLE] Notify char FFE1 not found");
    ble_client->disconnect();
    return false;
  }
  if (nc->canNotify()) {
    nc->registerForNotify(ble_notify_cb);
    Serial.println("[BLE] Subscribed FFE1 notifications");
  } else if (nc->canIndicate()) {
    nc->registerForNotify(ble_notify_cb, true);
    Serial.println("[BLE] Subscribed FFE1 indications");
  } else {
    Serial.println("[BLE] FFE1: no notify/indicate support");
  }

  // Write characteristic: try FFE2 first, fall back to FFE1
  BLERemoteCharacteristic *wc = svc->getCharacteristic(WRITE_UUID);
  if (!wc) {
    Serial.println("[BLE] FFE2 not found — using FFE1 for write");
    wc = nc;
  }

  // Send initial data request
  delay(300);
  wc->writeValue((uint8_t *)JK_REQUEST, sizeof(JK_REQUEST), false);
  Serial.println("[BLE] Sent JK BMS data request");

  ble_connected = true;
  return true;
}

// ─────────────────────────────────────────────
// BLE TASK (Core 0)
// ─────────────────────────────────────────────
static void task_ble(void *p)
{
  BLEScan *scanner = BLEDevice::getScan();
  scanner->setAdvertisedDeviceCallbacks(&scan_cb_instance);
  scanner->setActiveScan(true);
  scanner->setInterval(100);
  scanner->setWindow(99);

  uint32_t last_poll = 0;

  for (;;) {
    // ── Need to (re)connect ──────────────────────
    if (!ble_connected || do_reconnect) {
      do_reconnect = false;
      ble_found    = false;
      if (bms_addr) { delete bms_addr; bms_addr = nullptr; }

      Serial.printf("[BLE] Scanning for '%s' ...\n", BMS_DEVICE_NAME);
      scanner->start(BLE_SCAN_SEC, false);
      scanner->clearResults();

      if (!ble_found) {
        Serial.println("[BLE] Device not found — retrying");
        vTaskDelay(pdMS_TO_TICKS(2000));
        continue;
      }

      if (!ble_connect()) {
        Serial.println("[BLE] Connect failed — retrying");
        vTaskDelay(pdMS_TO_TICKS(BLE_RETRY_MS));
        continue;
      }
      last_poll = millis();
    }

    // ── Periodic data poll ────────────────────────
    if (ble_connected && ble_client &&
        (millis() - last_poll >= BLE_POLL_MS)) {
      last_poll = millis();
      BLERemoteService *svc = ble_client->getService(SVC_UUID);
      if (svc) {
        BLERemoteCharacteristic *wc = svc->getCharacteristic(WRITE_UUID);
        if (!wc) wc = svc->getCharacteristic(NOTIFY_UUID);
        if (wc) {
          wc->writeValue((uint8_t *)JK_REQUEST, sizeof(JK_REQUEST), false);
        }
      }
    }

    vTaskDelay(pdMS_TO_TICKS(200));
  }
}

// ─────────────────────────────────────────────
// SERIAL PRINT TASK (Core 1)
// ─────────────────────────────────────────────
static void task_serial(void *p)
{
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(SERIAL_PRINT_MS));

    jkbms_data_t d;
    if (xSemaphoreTake(bms_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
      d = bms_data;
      xSemaphoreGive(bms_mutex);
    } else {
      continue;
    }

    Serial.printf("[BLE] %s\n",
                  ble_connected ? "CONNECTED" : "NOT CONNECTED");

    if (!d.valid) {
      Serial.println("[BMS] No valid data yet...");
      continue;
    }

    Serial.println("===== JK BMS (" BMS_DEVICE_NAME ") =====");
    Serial.printf("  Voltage    : %7.2f V\n",  d.voltage);
    Serial.printf("  Current    : %7.2f A  (%s)\n",
                  d.current,
                  d.current > 0.0f ? "CHARGING" :
                  d.current < 0.0f ? "DISCHARGING" : "IDLE");
    Serial.printf("  Power      : %7.1f W\n",  d.power);
    Serial.printf("  SOC        : %7.0f %%\n", d.soc);
    Serial.printf("  Temp MOS   : %7.1f C\n",  d.temp_mos);
    Serial.printf("  Temp Bat1  : %7.1f C\n",  d.temp_bat1);
    Serial.printf("  Temp Bat2  : %7.1f C\n",  d.temp_bat2);
    Serial.printf("  Balance    : %7.0f mA\n", d.balance_ma);
    Serial.printf("  Cycles     : %u\n",        d.cycle_count);
    Serial.printf("  Cycle cap  : %7.1f Ah\n", d.cycle_cap_ah);
    Serial.printf("  Cells      : %u\n",        d.cell_count);
    Serial.printf("  Cell min   : %.3f V\n",    d.cell_min);
    Serial.printf("  Cell max   : %.3f V\n",    d.cell_max);
    Serial.printf("  Cell delta : %.3f V\n",    d.cell_delta);
    for (int i = 0; i < (int)d.cell_count; i++) {
      Serial.printf("    C%02d      : %.3f V\n", i + 1, d.cell_volt[i]);
    }
    Serial.printf("  Age        : %u ms ago\n",
                  (unsigned)(millis() - d.timestamp_ms));
    Serial.println("==========================================");
  }
}

// ─────────────────────────────────────────────
// WEB DASHBOARD HTML (stored in flash)
// ─────────────────────────────────────────────
static const char HTML_DASH[] PROGMEM = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JK BMS Monitor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0a0a0a;color:#0f0;font-size:13px}
header{background:#111;padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #2a2a2a}
header h1{font-size:15px;flex:1}
#dot{width:10px;height:10px;border-radius:50%;background:#f00;display:inline-block}
#dot.ok{background:#0f0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;padding:8px}
.card{background:#111;border:1px solid #2a2a2a;border-radius:4px;padding:10px}
.card h2{font-size:10px;color:#666;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.big{font-size:26px;color:#0f0;font-weight:bold}
.unit{font-size:12px;color:#888;margin-left:4px}
.sub{font-size:11px;color:#666;margin-top:5px}
.cells{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.cell{padding:3px 7px;border-radius:3px;font-size:11px;border:1px solid #333}
.cell.lo{border-color:#f55;color:#f55}
.cell.hi{border-color:#0f0;color:#0f0}
.cell.mid{border-color:#fa0;color:#fa0}
.bar-bg{background:#1a1a1a;border-radius:2px;height:10px;margin-top:6px;border:1px solid #333;overflow:hidden}
.bar{height:10px;border-radius:2px;background:linear-gradient(90deg,#060,#0f0);transition:width .5s}
footer{text-align:center;color:#333;font-size:10px;padding:6px}
</style>
</head>
<body>
<header>
  <span id="dot"></span>
  <h1>&#9889; JK BMS Monitor &mdash; KLARA THONG</h1>
  <span id="ts" style="color:#555;font-size:11px">--</span>
</header>
<div class="grid">
  <div class="card">
    <h2>&#128267; Pack Voltage</h2>
    <span class="big" id="volt">--</span><span class="unit">V</span>
    <div class="sub">
      Min cell: <span id="cmin">--</span> V |
      Max: <span id="cmax">--</span> V |
      &Delta;: <span id="cdelta">--</span> V
    </div>
  </div>
  <div class="card">
    <h2>&#9889; Current</h2>
    <span class="big" id="curr">--</span><span class="unit">A</span>
    <div class="sub" id="curDir">--</div>
  </div>
  <div class="card">
    <h2>&#128161; Power</h2>
    <span class="big" id="pwr">--</span><span class="unit">W</span>
    <div class="sub">Balance: <span id="bal">--</span> mA</div>
  </div>
  <div class="card">
    <h2>&#128268; State of Charge</h2>
    <span class="big" id="soc">--</span><span class="unit">%</span>
    <div class="bar-bg"><div class="bar" id="socBar" style="width:0%"></div></div>
    <div class="sub">Cycles: <span id="cyc">--</span> | Cap: <span id="cap">--</span> Ah</div>
  </div>
  <div class="card">
    <h2>&#127777; Temperature</h2>
    MOS: <span class="big" id="tmos" style="font-size:20px">--</span><span class="unit">&#176;C</span><br>
    <div class="sub">Bat1: <span id="tb1">--</span>&#176;C | Bat2: <span id="tb2">--</span>&#176;C</div>
  </div>
  <div class="card" id="cellCard" style="grid-column:span 2">
    <h2>&#128300; Cell Voltages (<span id="ncells">0</span> cells)</h2>
    <div class="cells" id="cellsDiv">--</div>
  </div>
</div>
<footer>JK BMS BLE Monitor v1.0 &mdash; Auto-refresh 2 s</footer>
<script>
function fmt(v,d){return(typeof v==='number'&&isFinite(v))?v.toFixed(d):'--';}
function el(id){return document.getElementById(id);}
function fetchData(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    var ok=d.valid&&d.ble_connected;
    el('dot').className=ok?'ok':'';
    if(!d.valid){el('ts').textContent='Waiting for BMS data...';return;}
    el('ts').textContent='Updated: '+new Date().toLocaleTimeString();
    el('volt').textContent=fmt(d.voltage,2);
    el('curr').textContent=fmt(d.current,2);
    el('curDir').textContent=d.current>0.05?'\u2b06 Charging':d.current<-0.05?'\u2b07 Discharging':'Idle';
    el('pwr').textContent=fmt(d.power,1);
    el('soc').textContent=fmt(d.soc,0);
    el('socBar').style.width=Math.min(100,Math.max(0,d.soc||0))+'%';
    el('cmin').textContent=fmt(d.cell_min,3);
    el('cmax').textContent=fmt(d.cell_max,3);
    el('cdelta').textContent=fmt(d.cell_delta,3);
    el('tmos').textContent=fmt(d.temp_mos,1);
    el('tb1').textContent=fmt(d.temp_bat1,1);
    el('tb2').textContent=fmt(d.temp_bat2,1);
    el('bal').textContent=fmt(d.balance_ma,0);
    el('cyc').textContent=d.cycle_count;
    el('cap').textContent=fmt(d.cycle_cap_ah,1);
    el('ncells').textContent=d.cell_count||0;
    var cells=d.cell_voltages||[];
    var mn=d.cell_min,mx=d.cell_max;
    var html='';
    for(var i=0;i<cells.length;i++){
      var v=cells[i];
      var cls=(v<=mn+0.003)?'lo':(v>=mx-0.003)?'hi':'mid';
      html+='<div class="cell '+cls+'">C'+(i+1)+': '+v.toFixed(3)+'V</div>';
    }
    el('cellsDiv').innerHTML=html||'No cell data';
  }).catch(function(e){
    el('dot').className='';
    el('ts').textContent='Error: '+e.message;
  });
}
fetchData();
setInterval(fetchData,2000);
</script>
</body>
</html>)html";

// ─────────────────────────────────────────────
// WEB HANDLER — root dashboard
// ─────────────────────────────────────────────
static void web_handle_root(void)
{
  web_server.send_P(200, "text/html", HTML_DASH);
}

// ─────────────────────────────────────────────
// WEB HANDLER — /api/data  (JSON)
// ─────────────────────────────────────────────
static void web_handle_api(void)
{
  jkbms_data_t d;
  if (xSemaphoreTake(bms_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    d = bms_data;
    xSemaphoreGive(bms_mutex);
  }

  // Build cell voltage JSON array (track offset to avoid O(n²) strlen calls)
  char cells_json[CELLS_JSON_SIZE];
  int  cj_pos = 0;
  cells_json[cj_pos++] = '[';
  for (int i = 0; i < (int)d.cell_count && cj_pos < (int)sizeof(cells_json) - 8; i++) {
    cj_pos += snprintf(cells_json + cj_pos,
                       sizeof(cells_json) - (size_t)cj_pos,
                       "%.3f%s",
                       d.cell_volt[i],
                       (i < (int)d.cell_count - 1) ? "," : "");
  }
  if (cj_pos < (int)sizeof(cells_json) - 2) {
    cells_json[cj_pos++] = ']';
  }
  cells_json[cj_pos] = '\0';

  char json[1024];
  snprintf(json, sizeof(json),
    "{"
    "\"valid\":%s,"
    "\"ble_connected\":%s,"
    "\"voltage\":%.2f,"
    "\"current\":%.2f,"
    "\"power\":%.1f,"
    "\"soc\":%.0f,"
    "\"temp_mos\":%.1f,"
    "\"temp_bat1\":%.1f,"
    "\"temp_bat2\":%.1f,"
    "\"balance_ma\":%.0f,"
    "\"cycle_count\":%u,"
    "\"cycle_cap_ah\":%.1f,"
    "\"cell_count\":%u,"
    "\"cell_min\":%.3f,"
    "\"cell_max\":%.3f,"
    "\"cell_delta\":%.3f,"
    "\"cell_voltages\":%s,"
    "\"timestamp_ms\":%u"
    "}",
    d.valid        ? "true" : "false",
    ble_connected  ? "true" : "false",
    d.voltage, d.current, d.power, d.soc,
    d.temp_mos, d.temp_bat1, d.temp_bat2,
    d.balance_ma, d.cycle_count, d.cycle_cap_ah,
    d.cell_count, d.cell_min, d.cell_max, d.cell_delta,
    cells_json,
    d.timestamp_ms);

  web_server.sendHeader("Access-Control-Allow-Origin", "*");
  web_server.send(200, "application/json", json);
}

// ─────────────────────────────────────────────
// WiFi SETUP — STA with AP fallback
// ─────────────────────────────────────────────
static void setup_wifi(void)
{
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("[WiFi] Connecting to '%s'", WIFI_SSID);

  uint8_t tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WiFi] Connected — IP: %s\n",
                  WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\n[WiFi] STA failed — starting AP 'JKBMS_Monitor'");
    WiFi.mode(WIFI_AP);
    WiFi.softAP("JKBMS_Monitor", "12345678");
    Serial.printf("[WiFi] AP IP: %s\n",
                  WiFi.softAPIP().toString().c_str());
  }
}

// ─────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────
void setup(void)
{
  Serial.begin(SERIAL_BAUD);
  delay(500);
  Serial.println("\n===== JK BMS BLE Monitor v1.0 =====");
  Serial.printf("Target BLE device : %s\n", BMS_DEVICE_NAME);
  Serial.printf("Serial baud       : %d\n", SERIAL_BAUD);

  bms_mutex = xSemaphoreCreateMutex();
  memset(&bms_data, 0, sizeof(bms_data));

  setup_wifi();

  // Register web routes
  web_server.on("/",         HTTP_GET, web_handle_root);
  web_server.on("/api/data", HTTP_GET, web_handle_api);
  web_server.begin();
  Serial.printf("[Web] Server started on port %d\n", WEB_PORT);

  // Init BLE stack
  BLEDevice::init("ESP32-S3-JKBMS");

  // Launch FreeRTOS tasks
  //   BLE task on Core 0 (radio core) with elevated stack
  //   Serial task on Core 1 (app core)
  xTaskCreatePinnedToCore(task_ble,    "BLE",    8192, NULL, 2, NULL, 0);
  xTaskCreatePinnedToCore(task_serial, "Serial", 3072, NULL, 1, NULL, 1);

  Serial.println("[OK] All tasks started — loop() handles web server");
}

// ─────────────────────────────────────────────
// LOOP — web server only (tasks own BLE + serial)
// ─────────────────────────────────────────────
void loop(void)
{
  web_server.handleClient();
  delay(5);
}
