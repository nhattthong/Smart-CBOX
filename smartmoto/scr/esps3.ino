/*
 * Smart Moto Telemetry Monitor - ESP32-S3
 * Version 2.0 - Web Dashboard + Fail-Safe Sensors + New UART Protocol
 *
 * Dual Core FreeRTOS:
 *   Core 1: Sensor reading (BMI160, VL53L1X ×2, AHT10, DS18B20, UART parser)
 *   Core 0: FFT, OLED display, WiFi/ERa publishing, HTTP WebServer
 *
 * Hardware (same as v1.0):
 *   Primary I2C   (Wire):  SDA=21, SCL=22 – BMI160(0x68), VL53L1X(0x29/0x30), SSD1306(0x3C)
 *   Secondary I2C (Wire1): SDA=4,  SCL=2  – DS1307(0x68), AHT10(0x38)
 *   UART2: RX=17, TX=18 (from STM32F103 PA9)
 *   SD Card: CS=5
 *   OneWire: GPIO12 (DS18B20)
 *   Menu button: GPIO35
 *
 * New UART protocol from STM32 Anchor:
 *   "STATUS:KEY=ON|DIST=1.23|BAT=85\r\n"  — normal status
 *   "ERR:DECRYPT\r\n"                       — AES MIC failure
 *   "ERR:REPLAY\r\n"                        — nonce replay detected
 *   "ERR:CMD\r\n"                           — unknown command
 *
 * Web Dashboard:
 *   GET  /         → HTML5 dashboard (auto-refresh via JS)
 *   GET  /api/data → JSON with all sensor + security data
 *   GET  /api/log  → JSON array with last 50 log entries
 *
 * Libraries required:
 *   U8g2, DFRobot_BMI160, Adafruit_VL53L1X, Adafruit_AHTX0,
 *   OneWire, DallasTemperature, RTClib, arduinoFFT, ERa
 */

#include <Wire.h>
#include <U8g2lib.h>
#include <DFRobot_BMI160.h>
#include <Adafruit_VL53L1X.h>
#include <Adafruit_AHTX0.h>
#include <WiFi.h>
#include <WebServer.h>
#include <SD.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <RTClib.h>
#include <arduinoFFT.h>
#include <ERa.hpp>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

// ===== CONFIGURATION =====
#define WIFI_SSID          "Moto_4G"
#define WIFI_PASS          "1234567890"
#define ERA_AUTH_TOKEN     "your_era_auth_token_here"
#define UART_BAUD          115200
#define I2C_FREQ_PRIMARY   400000
#define I2C_FREQ_SECONDARY 400000
#define SENSOR_SAMPLE_MS   10     // 100 Hz sensor loop
#define FFT_SAMPLES        256
#define WIFI_POST_MS       5000
#define LOG_RING_SIZE      50     // Max log entries kept in RAM
#define WEB_SERVER_PORT    80

// ===== PIN DEFINITIONS =====
const int SDA_PRIMARY   = 21;
const int SCL_PRIMARY   = 22;
const int SDA_SECONDARY = 4;
const int SCL_SECONDARY = 2;
const int UART_RX       = 17;
const int UART_TX       = 18;
const int ONEWIRE_PIN   = 12;
const int SD_CS         = 5;
const int MENU_BTN      = 35;

// ===== SENSOR ADDRESSES =====
const uint8_t BMI160_ADDR = 0x68;
const uint8_t AHT10_ADDR  = 0x38;

// ===== DISPLAY =====
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, SCL_PRIMARY, SDA_PRIMARY, U8X8_PIN_NONE);

// ===== SENSOR OBJECTS =====
DFRobot_BMI160   bmi160;
Adafruit_VL53L1X vl53_front;
Adafruit_VL53L1X vl53_rear;
Adafruit_AHTX0   aht;
RTC_DS1307       rtc;
OneWire          oneWire(ONEWIRE_PIN);
DallasTemperature ds18b20(&oneWire);

// ===== FFT =====
double fft_input[FFT_SAMPLES];
double fft_imag[FFT_SAMPLES];
ArduinoFFT<double> fft_obj = ArduinoFFT<double>(fft_input, fft_imag, FFT_SAMPLES, 1000.0 / SENSOR_SAMPLE_MS, false);

// ===== WEB SERVER =====
WebServer web_server(WEB_SERVER_PORT);

// ===== FREERTOS PRIMITIVES =====
SemaphoreHandle_t i2c_mutex     = NULL;
SemaphoreHandle_t sd_mutex      = NULL;
SemaphoreHandle_t display_mutex = NULL;
SemaphoreHandle_t data_mutex    = NULL;   // Protects shared sensor/status data

// ===== SENSOR FLAGS (which sensors initialised successfully) =====
bool bmi160_ok   = false;
bool vl53f_ok    = false;
bool vl53r_ok    = false;
bool aht10_ok    = false;
bool rtc_ok      = false;
bool ds18b20_ok  = false;
bool sd_ok       = false;

// ===== DATA STRUCTURES =====
typedef struct {
  uint32_t timestamp_ms;
  // IMU
  float accel_x, accel_y, accel_z;
  float gyro_x, gyro_y, gyro_z;
  bool  imu_valid;
  // LiDAR
  uint16_t lidar_front_mm, lidar_rear_mm;
  bool     lidar_front_valid, lidar_rear_valid;
  // Temperature / humidity
  float temp_ds18b20;
  float temp_aht10, humidity_aht10;
  bool  temp_ds_valid, temp_aht_valid;
  // Smart key status (from STM32 UART)
  char  key_status[8];    // "ON" / "OFF"
  float key_dist_m;       // Measured distance from anchor
  uint8_t key_bat_pct;    // Tag battery %
  char  last_err[16];     // Last error string from anchor
} sensor_data_t;

typedef struct {
  double peak_accel_z;
  double peak_freq_hz;
  double quality_factor;
} fft_result_t;

// ===== RING BUFFER LOG =====
typedef struct {
  char   text[64];
  uint32_t ts_ms;
} log_entry_t;

static log_entry_t log_ring[LOG_RING_SIZE];
static int         log_head = 0;
static int         log_count = 0;
SemaphoreHandle_t  log_mutex = NULL;

// ===== GLOBAL STATE =====
sensor_data_t current_sensor = {0};
fft_result_t  current_fft    = {0};
bool          menu_active    = false;
uint32_t      last_wifi_post = 0;
char          csv_filepath[40] = "";

// ===== FUNCTION PROTOTYPES =====
void task_sensor_reader(void *p);
void task_display_manager(void *p);
void task_wifi_poster(void *p);
void init_sensors(void);
void read_sensors(sensor_data_t *d);
void parse_uart_status(const char *line);
void process_fft(double *buf, fft_result_t *r);
void update_display(void);
void display_suspension_menu(void);
void log_to_sd(const sensor_data_t *d);
void create_csv_file(void);
void add_log(const char *fmt, ...);
void handle_web_root(void);
void handle_api_data(void);
void handle_api_log(void);
void setup_webserver(void);

WiFiClient mbTcpClient;

// ===== HTML DASHBOARD (stored in flash) =====
static const char HTML_DASHBOARD[] PROGMEM = R"rawhtml(<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart Moto Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#111;color:#0f0;font-size:13px}
header{background:#1a1a1a;padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #333}
header h1{font-size:15px;flex:1}
#statusDot{width:10px;height:10px;border-radius:50%;background:#f00;display:inline-block}
#statusDot.on{background:#0f0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;padding:8px}
.card{background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px}
.card h2{font-size:11px;color:#888;margin-bottom:6px;text-transform:uppercase}
.val{font-size:16px;color:#0f0}
.chip{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;margin:2px}
.chip.ok{background:#0a2a0a;border:1px solid #0f0;color:#0f0}
.chip.err{background:#2a0a0a;border:1px solid #f00;color:#f00}
.chip.warn{background:#2a1a00;border:1px solid #fa0;color:#fa0}
#log{background:#0a0a0a;border:1px solid #333;padding:6px;height:140px;overflow-y:auto;font-size:11px;margin:0 8px 8px}
.log-ok{color:#0a0}
.log-err{color:#f44}
.log-btn{color:#4af}
footer{text-align:center;color:#444;font-size:10px;padding:4px}
</style>
</head>
<body>
<header>
  <span id="statusDot"></span>
  <h1>🏍 Smart Moto Dashboard</h1>
  <span id="uptimeEl" style="color:#888;font-size:11px">--</span>
</header>
<div class="grid">
  <div class="card">
    <h2>🔑 Smart Key</h2>
    <div id="keyStatus" class="val">--</div>
    <div style="margin-top:4px">
      Dist: <span id="keyDist">--</span> m &nbsp;|&nbsp;
      BAT:  <span id="keyBat">--</span>%
    </div>
    <div id="keyErr" class="chip warn" style="display:none"></div>
  </div>
  <div class="card">
    <h2>📐 Suspension LiDAR</h2>
    Front: <span id="lidarF" class="val">--</span> mm<br>
    Rear:  <span id="lidarR" class="val">--</span> mm
    <div style="margin-top:4px">
      <span id="chipF" class="chip">F</span>
      <span id="chipR" class="chip">R</span>
    </div>
  </div>
  <div class="card">
    <h2>🌀 IMU (BMI160)</h2>
    <span id="chipIMU" class="chip">IMU</span><br>
    Ax:<span id="ax">--</span> Ay:<span id="ay">--</span> Az:<span id="az">--</span><br>
    Gx:<span id="gx">--</span> Gy:<span id="gy">--</span> Gz:<span id="gz">--</span>
  </div>
  <div class="card">
    <h2>📊 FFT Analysis</h2>
    Peak: <span id="fftFreq" class="val">--</span> Hz<br>
    Amp:  <span id="fftAmp">--</span> g<br>
    Q:    <span id="fftQ">--</span>
  </div>
  <div class="card">
    <h2>🌡 Environment</h2>
    <span id="chipAHT" class="chip">AHT</span>
    <span id="chipDS" class="chip">DS18B20</span><br>
    Temp AHT: <span id="tAht">--</span>°C<br>
    Humid:    <span id="hAht">--</span>%<br>
    Temp DS:  <span id="tDs">--</span>°C
  </div>
  <div class="card">
    <h2>📡 Network</h2>
    WiFi: <span id="wifiSt">--</span><br>
    IP:   <span id="wifiIP">--</span><br>
    RSSI: <span id="wifiRSSI">--</span> dBm
  </div>
</div>
<div id="log"></div>
<footer>Smart Moto v2.0 | Auto-refresh 2s</footer>
<script>
window.onerror=function(m,s,l,c,e){
  appendLog('[JS-ERR] '+m+' '+s+':'+l,'err');
  return false;  // Allow normal browser error propagation
};
function safeGet(o,k,def){
  if(!o||o[k]===undefined||o[k]===null)return def;
  return o[k];
}
function setEl(id,v){
  var e=document.getElementById(id);
  if(e)e.textContent=v;
}
function setChip(id,ok){
  var e=document.getElementById(id);
  if(!e)return;
  e.className='chip '+(ok?'ok':'err');
}
function appendLog(msg,cls){
  var d=document.getElementById('log');
  if(!d)return;
  var sp=document.createElement('span');
  sp.className='log-'+(cls||'ok');
  sp.textContent=msg+'\n';
  d.appendChild(sp);
  while(d.childElementCount>80)d.removeChild(d.firstChild);
  d.scrollTop=d.scrollHeight;
}
function fmtUptime(ms){
  var s=Math.floor(ms/1000);
  var m=Math.floor(s/60);s=s%60;
  var h=Math.floor(m/60);m=m%60;
  return h+'h '+m+'m '+s+'s';
}
function refresh(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    if(!d)return;
    var dot=document.getElementById('statusDot');
    if(dot)dot.className=safeGet(d,'wifi_connected',false)?'on':'';
    setEl('uptimeEl',fmtUptime(safeGet(d,'uptime_ms',0)));
    // Key
    var ks=safeGet(d,'key_status','--');
    setEl('keyStatus',ks);
    var ke=document.getElementById('keyStatus');
    if(ke)ke.style.color=ks==='ON'?'#0f0':'#f44';
    setEl('keyDist',(safeGet(d,'key_dist_m',0)).toFixed(2));
    setEl('keyBat',safeGet(d,'key_bat_pct',0));
    var errEl=document.getElementById('keyErr');
    var errStr=safeGet(d,'last_err','');
    if(errEl){
      if(errStr){errEl.style.display='';errEl.textContent='ERR:'+errStr;}
      else errEl.style.display='none';
    }
    // LiDAR
    var fv=safeGet(d,'lidar_front_valid',false);
    var rv=safeGet(d,'lidar_rear_valid',false);
    setEl('lidarF',fv?safeGet(d,'lidar_front_mm',0):'--');
    setEl('lidarR',rv?safeGet(d,'lidar_rear_mm',0):'--');
    setChip('chipF',fv);setChip('chipR',rv);
    // IMU
    var iv=safeGet(d,'imu_valid',false);
    setChip('chipIMU',iv);
    setEl('ax',iv?safeGet(d,'accel_x',0).toFixed(2):'--');
    setEl('ay',iv?safeGet(d,'accel_y',0).toFixed(2):'--');
    setEl('az',iv?safeGet(d,'accel_z',0).toFixed(2):'--');
    setEl('gx',iv?safeGet(d,'gyro_x',0).toFixed(1):'--');
    setEl('gy',iv?safeGet(d,'gyro_y',0).toFixed(1):'--');
    setEl('gz',iv?safeGet(d,'gyro_z',0).toFixed(1):'--');
    // FFT
    setEl('fftFreq',safeGet(d,'fft_freq_hz',0).toFixed(1));
    setEl('fftAmp',safeGet(d,'fft_amp_g',0).toFixed(2));
    setEl('fftQ',safeGet(d,'fft_q',0).toFixed(2));
    // Env
    var av=safeGet(d,'temp_aht_valid',false);
    var dv=safeGet(d,'temp_ds_valid',false);
    setChip('chipAHT',av);setChip('chipDS',dv);
    setEl('tAht',av?safeGet(d,'temp_aht10',0).toFixed(1):'--');
    setEl('hAht',av?safeGet(d,'humidity_aht10',0).toFixed(1):'--');
    setEl('tDs',dv?safeGet(d,'temp_ds18b20',0).toFixed(1):'--');
    // Network
    setEl('wifiSt',safeGet(d,'wifi_connected',false)?'Connected':'Disconnected');
    setEl('wifiIP',safeGet(d,'wifi_ip','--'));
    setEl('wifiRSSI',safeGet(d,'wifi_rssi',0));
  }).catch(function(e){appendLog('[ERR] fetch: '+e,'err');});

  fetch('/api/log').then(function(r){return r.json();}).then(function(arr){
    if(!arr||!arr.length)return;
    arr.forEach(function(entry){
      if(!entry)return;
      var cls='ok';
      var t=entry.text||'';
      if(t.indexOf('[ERR]')>=0||t.indexOf('ERR:')>=0)cls='err';
      else if(t.indexOf('[BTN]')>=0)cls='btn';
      appendLog(t,cls);
    });
  }).catch(function(){});
}
setInterval(refresh,2000);
refresh();
</script>
</body>
</html>
)rawhtml";

// ===== SETUP =====
void setup() {
  delay(1000);

  Serial.begin(115200);
  Serial.println("\n\n=== Smart Moto Monitor v2.0 Booting ===");

  Serial2.begin(UART_BAUD, SERIAL_8N1, UART_RX, UART_TX);

  i2c_mutex     = xSemaphoreCreateMutex();
  sd_mutex      = xSemaphoreCreateMutex();
  display_mutex = xSemaphoreCreateMutex();
  data_mutex    = xSemaphoreCreateMutex();
  log_mutex     = xSemaphoreCreateMutex();

  init_sensors();

  if (!SD.begin(SD_CS, SPI, 1000000)) {
    Serial.println("[WARN] SD init FAILED");
  } else {
    Serial.println("[OK] SD init");
    sd_ok = true;
    create_csv_file();
  }

  ERa.setModbusClient(mbTcpClient);
  ERa.begin(WIFI_SSID, WIFI_PASS, ERA_AUTH_TOKEN);
  Serial.println("[OK] ERa connecting...");

  setup_webserver();

  pinMode(MENU_BTN, INPUT_PULLUP);
  u8g2.begin();
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(0, 10, "Smart Moto v2.0");
  u8g2.drawStr(0, 22, "Booting...");
  u8g2.sendBuffer();

  xTaskCreatePinnedToCore(task_sensor_reader,  "SensorTask",  4096, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(task_display_manager,"DisplayTask", 3072, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(task_wifi_poster,    "WiFiTask",    3072, NULL, 1, NULL, 0);

  Serial.println("[OK] All tasks created");
  add_log("[OK] System booted");
}

void loop() {
  ERa.run();
  web_server.handleClient();
  vTaskDelay(pdMS_TO_TICKS(10));
}

// ===== LOG HELPER =====
#include <stdarg.h>
void add_log(const char *fmt, ...) {
  if (!log_mutex) return;
  char buf[64];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (xSemaphoreTake(log_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    int idx = log_head % LOG_RING_SIZE;
    strncpy(log_ring[idx].text, buf, sizeof(log_ring[idx].text) - 1);
    log_ring[idx].text[sizeof(log_ring[idx].text) - 1] = '\0';
    log_ring[idx].ts_ms = millis();
    log_head++;
    if (log_count < LOG_RING_SIZE) log_count++;
    xSemaphoreGive(log_mutex);
  }
}

// ===== TASK: SENSOR READER (Core 1) =====
void task_sensor_reader(void *parameter) {
  TickType_t xLastWake = xTaskGetTickCount();
  int   fft_idx = 0;
  double accel_z_buf[FFT_SAMPLES] = {0};

  while (1) {
    sensor_data_t snap = {0};
    read_sensors(&snap);

    // Parse any pending UART data from STM32
    while (Serial2.available()) {
      static char uart_buf[64] = {0};
      static int  uart_idx     = 0;
      char c = Serial2.read();
      if (c == '\n' || c == '\r') {
        if (uart_idx > 0) {
          uart_buf[uart_idx] = '\0';
          parse_uart_status(uart_buf);
          uart_idx = 0;
        }
      } else if (uart_idx < (int)(sizeof(uart_buf) - 1)) {
        uart_buf[uart_idx++] = c;
      }
    }

    // Copy key fields from global state into snap (protected)
    if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
      strncpy(snap.key_status, current_sensor.key_status, sizeof(snap.key_status));
      snap.key_dist_m  = current_sensor.key_dist_m;
      snap.key_bat_pct = current_sensor.key_bat_pct;
      strncpy(snap.last_err, current_sensor.last_err, sizeof(snap.last_err));
      // Push sensor data back into shared state
      current_sensor = snap;
      xSemaphoreGive(data_mutex);
    }

    // Accumulate for FFT
    accel_z_buf[fft_idx % FFT_SAMPLES] = snap.accel_z;
    fft_idx++;
    if ((fft_idx % FFT_SAMPLES) == 0) {
      process_fft(accel_z_buf, &current_fft);
    }

    if (sd_ok) {
      log_to_sd(&snap);
    }

    vTaskDelayUntil(&xLastWake, pdMS_TO_TICKS(SENSOR_SAMPLE_MS));
  }
}

// ===== TASK: DISPLAY MANAGER (Core 0) =====
void task_display_manager(void *parameter) {
  uint32_t last_btn = 0;
  while (1) {
    uint32_t now = millis();
    if (now - last_btn > 200) {
      if (digitalRead(MENU_BTN) == LOW) {
        menu_active = !menu_active;
        last_btn = now;
        add_log("[BTN] Menu %s", menu_active ? "OPEN" : "CLOSE");
      }
    }
    if (xSemaphoreTake(display_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
      if (menu_active) display_suspension_menu();
      else             update_display();
      xSemaphoreGive(display_mutex);
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

// ===== TASK: WiFi POSTER (Core 0) =====
void task_wifi_poster(void *parameter) {
  while (1) {
    uint32_t now = millis();
    if (now - last_wifi_post > WIFI_POST_MS) {
      last_wifi_post = now;
      sensor_data_t snap;
      if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snap = current_sensor;
        xSemaphoreGive(data_mutex);
      }
      if (snap.imu_valid) {
        ERa.virtualWrite(0, snap.accel_x);
        ERa.virtualWrite(1, snap.accel_y);
        ERa.virtualWrite(2, snap.accel_z);
      }
      if (snap.lidar_front_valid) ERa.virtualWrite(3, snap.lidar_front_mm);
      if (snap.lidar_rear_valid)  ERa.virtualWrite(4, snap.lidar_rear_mm);
      ERa.virtualWrite(5, current_fft.peak_freq_hz);
      ERa.virtualWrite(6, current_fft.peak_accel_z);
      if (snap.temp_aht_valid) {
        ERa.virtualWrite(7, snap.temp_aht10);
        ERa.virtualWrite(8, snap.humidity_aht10);
      }
      ERa.virtualWrite(9,  snap.key_bat_pct);
      ERa.virtualWrite(10, snap.key_dist_m);
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// ===== INIT SENSORS (fail-safe: each sensor isolated) =====
void init_sensors(void) {
  Wire.begin(SDA_PRIMARY, SCL_PRIMARY);
  Wire.setClock(I2C_FREQ_PRIMARY);
  Wire1.begin(SDA_SECONDARY, SCL_SECONDARY);
  Wire1.setClock(I2C_FREQ_SECONDARY);

  // BMI160
  bmi160.softReset();
  delay(100);
  if (bmi160.I2cInit(BMI160_ADDR) == BMI160_OK) {
    bmi160_ok = true;
    Serial.println("[OK] BMI160");
  } else {
    Serial.println("[WARN] BMI160 init failed");
  }

  // VL53L1X Front (addr 0x29)
  if (vl53_front.begin(0x29, &Wire)) {
    vl53_front.setTimingBudget(50);
    vl53_front.startRanging();
    vl53f_ok = true;
    Serial.println("[OK] VL53L1X Front");
  } else {
    Serial.println("[WARN] VL53L1X Front init failed");
  }

  // VL53L1X Rear (addr 0x30 – requires XSHUT pin to change address)
  if (vl53_rear.begin(0x30, &Wire)) {
    vl53_rear.setTimingBudget(50);
    vl53_rear.startRanging();
    vl53r_ok = true;
    Serial.println("[OK] VL53L1X Rear");
  } else {
    Serial.println("[WARN] VL53L1X Rear init failed");
  }

  // AHT10
  if (aht.begin(&Wire1)) {
    aht10_ok = true;
    Serial.println("[OK] AHT10");
  } else {
    Serial.println("[WARN] AHT10 init failed");
  }

  // RTC DS1307
  if (rtc.begin(&Wire1)) {
    if (!rtc.isrunning()) {
      rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    }
    rtc_ok = true;
    Serial.println("[OK] DS1307 RTC");
  } else {
    Serial.println("[WARN] DS1307 init failed");
  }

  // DS18B20
  ds18b20.begin();
  if (ds18b20.getDeviceCount() > 0) {
    ds18b20_ok = true;
    Serial.println("[OK] DS18B20");
  } else {
    Serial.println("[WARN] DS18B20 not found");
  }

  delay(300);
}

// ===== READ ALL SENSORS (per-sensor fail-safe) =====
void read_sensors(sensor_data_t *d) {
  d->timestamp_ms = millis();

  // BMI160
  d->imu_valid = false;
  if (bmi160_ok) {
    int16_t imu[6] = {0};
    if (bmi160.getAccelGyroData(imu) == 0) {
      d->accel_x = imu[0] / 16384.0f;
      d->accel_y = imu[1] / 16384.0f;
      d->accel_z = imu[2] / 16384.0f;
      d->gyro_x  = imu[3] / 131.0f;
      d->gyro_y  = imu[4] / 131.0f;
      d->gyro_z  = imu[5] / 131.0f;
      d->imu_valid = true;
    }
  }

  // VL53L1X (both sensors, independent)
  d->lidar_front_valid = false;
  d->lidar_rear_valid  = false;
  if (vl53f_ok || vl53r_ok) {
    if (xSemaphoreTake(i2c_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
      if (vl53f_ok && vl53_front.dataReady()) {
        int16_t r = vl53_front.distance();
        if (r > 0) { d->lidar_front_mm = (uint16_t)r; d->lidar_front_valid = true; }
        vl53_front.clearInterrupt();
      }
      if (vl53r_ok && vl53_rear.dataReady()) {
        int16_t r = vl53_rear.distance();
        if (r > 0) { d->lidar_rear_mm = (uint16_t)r; d->lidar_rear_valid = true; }
        vl53_rear.clearInterrupt();
      }
      xSemaphoreGive(i2c_mutex);
    }
  }

  // AHT10
  d->temp_aht_valid = false;
  if (aht10_ok) {
    sensors_event_t hum, tmp;
    if (aht.getEvent(&hum, &tmp)) {
      d->temp_aht10      = tmp.temperature;
      d->humidity_aht10  = hum.relative_humidity;
      d->temp_aht_valid  = true;
    }
  }

  // DS18B20  (DEVICE_DISCONNECTED_C = -127.0 from DallasTemperature library, indicates no sensor)
  d->temp_ds_valid = false;
  if (ds18b20_ok) {
    ds18b20.requestTemperatures();
    float t = ds18b20.getTempCByIndex(0);
    if (t != DEVICE_DISCONNECTED_C) {  // -127.0°C means sensor disconnected
      d->temp_ds18b20 = t;
      d->temp_ds_valid = true;
    }
  }
}

// ===== PARSE UART STATUS FROM STM32 =====
// Expected formats:
//   "STATUS:KEY=ON|DIST=1.23|BAT=85"
//   "ERR:DECRYPT" / "ERR:REPLAY" / "ERR:CMD"
void parse_uart_status(const char *line) {
  if (!line || strlen(line) == 0) return;

  if (strncmp(line, "STATUS:", 7) == 0) {
    char key_val[8]   = "?";
    float dist_val    = 0.0f;
    uint8_t bat_val   = 0;

    // Parse KEY=
    const char *kp = strstr(line, "KEY=");
    if (kp) {
      kp += 4;
      if (strncmp(kp, "ON", 2) == 0)  strncpy(key_val, "ON",  sizeof(key_val));
      else                             strncpy(key_val, "OFF", sizeof(key_val));
    }

    // Parse DIST=
    const char *dp = strstr(line, "DIST=");
    if (dp) dist_val = atof(dp + 5);

    // Parse BAT=
    const char *bp = strstr(line, "BAT=");
    if (bp) bat_val = (uint8_t)atoi(bp + 4);

    if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
      strncpy(current_sensor.key_status, key_val, sizeof(current_sensor.key_status));
      current_sensor.key_dist_m  = dist_val;
      current_sensor.key_bat_pct = bat_val;
      current_sensor.last_err[0] = '\0';
      xSemaphoreGive(data_mutex);
    }

    add_log("[%s] DIST=%.2f BAT=%u%%",
            key_val, (double)dist_val, (unsigned)bat_val);

  } else if (strncmp(line, "ERR:", 4) == 0) {
    const char *err = line + 4;
    if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
      strncpy(current_sensor.last_err, err, sizeof(current_sensor.last_err) - 1);
      xSemaphoreGive(data_mutex);
    }
    add_log("[ERR] AES %s", err);
  }
}

// ===== PROCESS FFT =====
void process_fft(double *buf, fft_result_t *r) {
  for (int i = 0; i < FFT_SAMPLES; i++) {
    fft_input[i] = buf[i];
    fft_imag[i]  = 0.0;
  }
  fft_obj.windowing(fft_input, FFT_SAMPLES, FFT_WIN_TYP_HAMMING, FFT_FORWARD);
  fft_obj.compute(fft_input, fft_imag, FFT_SAMPLES, FFT_FORWARD);
  fft_obj.complexToMagnitude(fft_input, fft_imag, FFT_SAMPLES);

  r->peak_accel_z = 0;
  r->peak_freq_hz = 0;
  double rms = 0;
  double sample_rate = 1000.0 / SENSOR_SAMPLE_MS;

  for (int i = 1; i < FFT_SAMPLES / 2; i++) {
    if (fft_input[i] > r->peak_accel_z) {
      r->peak_accel_z = fft_input[i];
      r->peak_freq_hz = (i * sample_rate) / FFT_SAMPLES;
    }
    rms += fft_input[i] * fft_input[i];
  }
  r->quality_factor = sqrt(rms / (FFT_SAMPLES / 2));
}

// ===== UPDATE OLED DISPLAY =====
void update_display(void) {
  sensor_data_t snap;
  if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    snap = current_sensor;
    xSemaphoreGive(data_mutex);
  }

  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_5x8_tf);
  char buf[32];

  snprintf(buf, sizeof(buf), "KEY:%s D:%.1fm B:%u%%",
           snap.key_status[0] ? snap.key_status : "?",
           (double)snap.key_dist_m, (unsigned)snap.key_bat_pct);
  u8g2.drawStr(0, 8, buf);

  if (snap.lidar_front_valid && snap.lidar_rear_valid) {
    snprintf(buf, sizeof(buf), "F:%umm R:%umm", snap.lidar_front_mm, snap.lidar_rear_mm);
  } else if (snap.lidar_front_valid) {
    snprintf(buf, sizeof(buf), "F:%umm R:--", snap.lidar_front_mm);
  } else {
    snprintf(buf, sizeof(buf), "LiDAR: --");
  }
  u8g2.drawStr(0, 18, buf);

  snprintf(buf, sizeof(buf), "FFT:%.1fHz @%.2fg",
           current_fft.peak_freq_hz, current_fft.peak_accel_z);
  u8g2.drawStr(0, 28, buf);

  if (snap.imu_valid) {
    snprintf(buf, sizeof(buf), "Az:%.2fg", (double)snap.accel_z);
  } else {
    snprintf(buf, sizeof(buf), "IMU:--");
  }
  u8g2.drawStr(0, 38, buf);

  if (snap.temp_aht_valid) {
    snprintf(buf, sizeof(buf), "T:%.1fC H:%.0f%%",
             (double)snap.temp_aht10, (double)snap.humidity_aht10);
  } else {
    snprintf(buf, sizeof(buf), "Env:--");
  }
  u8g2.drawStr(0, 48, buf);

  snprintf(buf, sizeof(buf), "WiFi:%s",
           WiFi.isConnected() ? WiFi.localIP().toString().c_str() : "Offline");
  u8g2.drawStr(0, 58, buf);

  u8g2.sendBuffer();
}

// ===== DISPLAY SUSPENSION MENU =====
void display_suspension_menu(void) {
  sensor_data_t snap;
  if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    snap = current_sensor;
    xSemaphoreGive(data_mutex);
  }

  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_5x8_tf);
  char buf[32];

  u8g2.drawStr(0, 8, "== Suspension ==");

  snprintf(buf, sizeof(buf), "Front: %s mm",
           snap.lidar_front_valid ? String(snap.lidar_front_mm).c_str() : "--");
  u8g2.drawStr(0, 20, buf);

  snprintf(buf, sizeof(buf), "Rear:  %s",
           snap.lidar_rear_valid ? String(snap.lidar_rear_mm).c_str() : "--");
  u8g2.drawStr(0, 30, buf);

  snprintf(buf, sizeof(buf), "Vib: %.1fHz", current_fft.peak_freq_hz);
  u8g2.drawStr(0, 42, buf);

  snprintf(buf, sizeof(buf), "Amp: %.2fg", current_fft.peak_accel_z);
  u8g2.drawStr(0, 52, buf);

  u8g2.sendBuffer();
}

// ===== LOG TO SD CARD =====
void log_to_sd(const sensor_data_t *d) {
  if (!sd_ok || !SD.exists(csv_filepath)) return;

  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    File f = SD.open(csv_filepath, FILE_APPEND);
    if (f) {
      char line[160];
      snprintf(line, sizeof(line),
        "%lu,%.3f,%.3f,%.3f,%.2f,%.2f,%.2f,%s,%s,%.1f,%.1f,%.1f,%s,%.2f,%u\n",
        d->timestamp_ms,
        d->imu_valid    ? (double)d->accel_x : NAN,
        d->imu_valid    ? (double)d->accel_y : NAN,
        d->imu_valid    ? (double)d->accel_z : NAN,
        d->imu_valid    ? (double)d->gyro_x  : NAN,
        d->imu_valid    ? (double)d->gyro_y  : NAN,
        d->imu_valid    ? (double)d->gyro_z  : NAN,
        d->lidar_front_valid ? String(d->lidar_front_mm).c_str() : "",
        d->lidar_rear_valid  ? String(d->lidar_rear_mm).c_str()  : "",
        d->temp_ds_valid  ? (double)d->temp_ds18b20  : NAN,
        d->temp_aht_valid ? (double)d->temp_aht10    : NAN,
        d->temp_aht_valid ? (double)d->humidity_aht10: NAN,
        d->key_status,
        (double)d->key_dist_m,
        (unsigned)d->key_bat_pct
      );
      f.print(line);
      f.close();
    }
    xSemaphoreGive(sd_mutex);
  }
}

// ===== CREATE CSV FILE =====
void create_csv_file(void) {
  if (rtc_ok) {
    DateTime now = rtc.now();
    snprintf(csv_filepath, sizeof(csv_filepath),
      "/moto_%04d%02d%02d_%02d%02d%02d.csv",
      now.year(), now.month(), now.day(),
      now.hour(), now.minute(), now.second());
  } else {
    snprintf(csv_filepath, sizeof(csv_filepath), "/moto_data.csv");
  }

  File f = SD.open(csv_filepath, FILE_WRITE);
  if (f) {
    f.println("TS_ms,Ax_g,Ay_g,Az_g,Gx_dps,Gy_dps,Gz_dps,"
              "Susp_F_mm,Susp_R_mm,"
              "Temp_DS_C,Temp_AHT_C,Hum_AHT_Pct,"
              "Key,Dist_m,TagBat_Pct");
    f.close();
    Serial.print("[OK] CSV: ");
    Serial.println(csv_filepath);
  }
}

// ===== WEB SERVER SETUP =====
void setup_webserver(void) {
  web_server.on("/",        HTTP_GET, handle_web_root);
  web_server.on("/api/data",HTTP_GET, handle_api_data);
  web_server.on("/api/log", HTTP_GET, handle_api_log);
  web_server.begin();
  Serial.println("[OK] Web server started on port 80");
}

// ===== HANDLER: GET / =====
void handle_web_root(void) {
  web_server.send_P(200, "text/html", HTML_DASHBOARD);
}

// ===== HANDLER: GET /api/data =====
void handle_api_data(void) {
  sensor_data_t snap;
  fft_result_t  fft_snap;

  if (xSemaphoreTake(data_mutex, pdMS_TO_TICKS(30)) == pdTRUE) {
    snap = current_sensor;
    xSemaphoreGive(data_mutex);
  }
  fft_snap = current_fft;

  char json[768];
  int n = 0;

  n += snprintf(json + n, sizeof(json) - n, "{");

  // Uptime
  n += snprintf(json + n, sizeof(json) - n, "\"uptime_ms\":%lu,", millis());

  // WiFi
  bool wconn = WiFi.isConnected();
  n += snprintf(json + n, sizeof(json) - n,
    "\"wifi_connected\":%s,\"wifi_ip\":\"%s\",\"wifi_rssi\":%d,",
    wconn ? "true" : "false",
    wconn ? WiFi.localIP().toString().c_str() : "",
    wconn ? WiFi.RSSI() : 0);

  // Smart Key
  n += snprintf(json + n, sizeof(json) - n,
    "\"key_status\":\"%s\",\"key_dist_m\":%.2f,\"key_bat_pct\":%u,\"last_err\":\"%s\",",
    snap.key_status[0] ? snap.key_status : "?",
    (double)snap.key_dist_m,
    (unsigned)snap.key_bat_pct,
    snap.last_err);

  // IMU
  n += snprintf(json + n, sizeof(json) - n,
    "\"imu_valid\":%s,\"accel_x\":%.3f,\"accel_y\":%.3f,\"accel_z\":%.3f,"
    "\"gyro_x\":%.2f,\"gyro_y\":%.2f,\"gyro_z\":%.2f,",
    snap.imu_valid ? "true" : "false",
    (double)snap.accel_x, (double)snap.accel_y, (double)snap.accel_z,
    (double)snap.gyro_x,  (double)snap.gyro_y,  (double)snap.gyro_z);

  // LiDAR
  n += snprintf(json + n, sizeof(json) - n,
    "\"lidar_front_valid\":%s,\"lidar_front_mm\":%u,"
    "\"lidar_rear_valid\":%s,\"lidar_rear_mm\":%u,",
    snap.lidar_front_valid ? "true" : "false", (unsigned)snap.lidar_front_mm,
    snap.lidar_rear_valid  ? "true" : "false", (unsigned)snap.lidar_rear_mm);

  // Temperature / humidity
  n += snprintf(json + n, sizeof(json) - n,
    "\"temp_aht_valid\":%s,\"temp_aht10\":%.1f,\"humidity_aht10\":%.1f,"
    "\"temp_ds_valid\":%s,\"temp_ds18b20\":%.1f,",
    snap.temp_aht_valid ? "true" : "false",
    (double)snap.temp_aht10, (double)snap.humidity_aht10,
    snap.temp_ds_valid  ? "true" : "false",
    (double)snap.temp_ds18b20);

  // FFT
  n += snprintf(json + n, sizeof(json) - n,
    "\"fft_freq_hz\":%.2f,\"fft_amp_g\":%.3f,\"fft_q\":%.3f",
    fft_snap.peak_freq_hz, fft_snap.peak_accel_z, fft_snap.quality_factor);

  n += snprintf(json + n, sizeof(json) - n, "}");

  web_server.send(200, "application/json", json);
}

// ===== HANDLER: GET /api/log =====
void handle_api_log(void) {
  // Return the newest 20 log entries as JSON array
  // Use static buffer to avoid large stack allocation in embedded handler
  static char json[1200];
  int  n = 0;
  n += snprintf(json + n, sizeof(json) - n, "[");

  if (xSemaphoreTake(log_mutex, pdMS_TO_TICKS(30)) == pdTRUE) {
    int count = log_count < 20 ? log_count : 20;
    int start = (log_head - count + LOG_RING_SIZE * 2) % LOG_RING_SIZE;
    for (int i = 0; i < count; i++) {
      int idx = (start + i) % LOG_RING_SIZE;
      if (n < (int)sizeof(json) - 60) {
        n += snprintf(json + n, sizeof(json) - n,
          "%s{\"ts\":%lu,\"text\":\"%s\"}",
          i > 0 ? "," : "",
          log_ring[idx].ts_ms,
          log_ring[idx].text);
      }
    }
    xSemaphoreGive(log_mutex);
  }

  n += snprintf(json + n, sizeof(json) - n, "]");
  web_server.send(200, "application/json", json);
}

// ===== ERa CALLBACKS =====
ERA_CONNECTED() {
  Serial.println("[OK] ERa connected!");
  add_log("[OK] ERa connected");
}

ERA_DISCONNECTED() {
  Serial.println("[WARN] ERa disconnected");
  add_log("[WARN] ERa disconnected");
}
