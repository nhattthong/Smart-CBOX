/*
 * Smart Moto Telemetry Monitor - ESP32-S3
 * Dual Core FreeRTOS: Core 1 (Sensors/Logging), Core 0 (FFT/WiFi/Display)
 * 
 * Features:
 *   - Core 1: UART (STM32 status), IMU (BMI160), LiDAR (2x VL53L1X), SD logging
 *   - Core 0: FFT analysis (512 samples), OLED display (U8G2), WiFi posting
 *   - Mutex protection for I2C, SD, display shared resources
 *   - FreeRTOS task synchronization with queues
 * 
 * Hardware:
 *   - Primary I2C (Wire): SDA=21, SCL=22 - BMI160 (0x68), VL53L1X (0x29), SSD1306 (0x3C)
 *   - Secondary I2C (Wire1): SDA=4, SCL=2 - DS1307 RTC (0x68), AHT10 (0x38)
 *   - UART2: RX=17, TX=18 (from STM32F103 PA9)
 *   - SD Card: CS=5 (SPI standard pins)
 *   - OneWire: GPIO12 (DS18B20)
 */

#include <Wire.h>
#include <U8g2lib.h>
#include <DFRobot_BMI160.h>
#include <Adafruit_VL53L1X.h>
#include <Adafruit_AHTX0.h>
#include <WiFi.h>
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
#define WIFI_SSID "Moto_4G"
#define WIFI_PASS "1234567890"
#define ERA_AUTH_TOKEN "your_era_auth_token_here"
#define UART_BAUD 115200
#define I2C_FREQ_PRIMARY 400000
#define I2C_FREQ_SECONDARY 400000
#define SENSOR_SAMPLE_RATE 100
#define FFT_SAMPLES 256
#define CSV_BUFFER_SIZE 512
#define WIFI_POST_INTERVAL_MS 5000

// ===== PIN DEFINITIONS =====
const int SDA_PRIMARY = 21;
const int SCL_PRIMARY = 22;
const int SDA_SECONDARY = 4;
const int SCL_SECONDARY = 2;
const int UART_RX = 17;
const int UART_TX = 18;
const int ONEWIRE_PIN = 12;
const int SD_CS = 5;
const int MENU_BUTTON_PIN = 35;

// ===== DEVICE ADDRESSES =====
const uint8_t BMI160_ADDR = 0x68;
const uint8_t AHT10_ADDR = 0x38;

// ===== DISPLAY =====
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, 22, 21, U8X8_PIN_NONE);

// ===== SENSOR OBJECTS =====
DFRobot_BMI160 bmi160;
Adafruit_VL53L1X vl53_front;
Adafruit_VL53L1X vl53_rear;
Adafruit_AHTX0 aht;
RTC_DS1307 rtc;
OneWire oneWire(ONEWIRE_PIN);
DallasTemperature ds18b20(&oneWire);

// ===== FFT =====
double fftInput[FFT_SAMPLES];
double fftImag[FFT_SAMPLES];
ArduinoFFT<double> fft = ArduinoFFT<double>(fftInput, fftImag, FFT_SAMPLES, SENSOR_SAMPLE_RATE, false);

// ===== FREERTOS =====
SemaphoreHandle_t i2c_mutex = NULL;
SemaphoreHandle_t sd_mutex = NULL;
SemaphoreHandle_t display_mutex = NULL;
// QueueHandle_t sensor_queue = NULL;  // Removed - not needed

// ===== DATA STRUCTURES =====
typedef struct {
  uint32_t timestamp;
  float accel_x, accel_y, accel_z;
  float gyro_x, gyro_y, gyro_z;
  uint16_t lidar_front, lidar_rear;
  float temp_ds18b20;
  float temp_aht10, humidity_aht10;
  char key_status[16];
  uint8_t battery_percent;
} sensor_data_t;

typedef struct {
  double peak_accel_z;
  double peak_freq_hz;
  double quality_factor;
} fft_result_t;

// ===== GLOBAL STATE =====
sensor_data_t current_sensor = {0};
fft_result_t current_fft = {0};
bool menu_active = false;
uint32_t last_wifi_post = 0;
char csv_filepath[32] = "";
File csv_file;

// ===== FUNCTION PROTOTYPES =====
void task_sensor_reader(void *parameter);
// task_fft_processor removed
void task_display_manager(void *parameter);
void task_wifi_poster(void *parameter);
void init_sensors(void);
void read_sensors(sensor_data_t *data);
void process_fft(double *accel_z_buffer, fft_result_t *result);
void update_display(void);
void display_suspension_menu(void);
void read_uart_status(void);
void log_to_sd(const sensor_data_t *data);
void create_csv_file(void);
WiFiClient mbTcpClient;

// ===== SETUP =====
void setup() {
  delay(1000);
  
  Serial.begin(115200);
  Serial.println("\n\n=== Smart Moto Monitor Booting ===");
  
  Serial2.begin(UART_BAUD, SERIAL_8N1, UART_RX, UART_TX);
  
  i2c_mutex = xSemaphoreCreateMutex();
  sd_mutex = xSemaphoreCreateMutex();
  display_mutex = xSemaphoreCreateMutex();
  
  init_sensors();
  
  if (!SD.begin(SD_CS, SPI, 1000000)) {
    Serial.println("SD init FAILED");
  } else {
    Serial.println("SD init OK");
    create_csv_file();
  }
  
  /* Setup Client for ERa */
  ERa.setModbusClient(mbTcpClient);
  /* Initializing the ERa library */
  ERa.begin(WIFI_SSID, WIFI_PASS, ERA_AUTH_TOKEN);
  Serial.println("ERa connecting...");
  
  pinMode(MENU_BUTTON_PIN, INPUT_PULLUP);
  u8g2.begin();
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(0, 10, "Booting...");
  u8g2.sendBuffer();
  
  xTaskCreatePinnedToCore(task_sensor_reader, "SensorTask", 3072, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(task_display_manager, "DisplayTask", 3072, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(task_wifi_poster, "WiFiTask", 3072, NULL, 1, NULL, 0);
  
  Serial.println("All tasks created");
}

void loop() {
  ERa.run();
  vTaskDelay(pdMS_TO_TICKS(10));
}

// ===== TASK: SENSOR READER (Core 1) =====
void task_sensor_reader(void *parameter) {
  TickType_t xLastWakeTime = xTaskGetTickCount();
  int32_t accel_z_idx = 0;
  double accel_z_buffer[FFT_SAMPLES] = {0};
  
  while (1) {
    read_sensors(&current_sensor);
    read_uart_status();
    
    accel_z_buffer[accel_z_idx % FFT_SAMPLES] = current_sensor.accel_z;
    accel_z_idx++;
    
    log_to_sd(&current_sensor);
    
    if (accel_z_idx % FFT_SAMPLES == 0) {
      process_fft(accel_z_buffer, &current_fft);
    }
    
    vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(10));
  }
}

// FFT processor task removed - sensor_reader handles FFT directly

// ===== TASK: DISPLAY MANAGER (Core 0) =====
void task_display_manager(void *parameter) {
  uint32_t last_button_check = 0;
  
  while (1) {
    if (millis() - last_button_check > 200) {
      if (digitalRead(MENU_BUTTON_PIN) == LOW) {
        menu_active = !menu_active;
        last_button_check = millis();
      }
    }
    
    if (xSemaphoreTake(display_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
      if (menu_active) {
        display_suspension_menu();
      } else {
        update_display();
      }
      xSemaphoreGive(display_mutex);
    }
    
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

// ===== TASK: WiFi POSTER (Core 0) =====
void task_wifi_poster(void *parameter) {
  while (1) {
    uint32_t now = millis();
    if (now - last_wifi_post > WIFI_POST_INTERVAL_MS) {
      last_wifi_post = now;
      /* Publish sensor data to ERa virtual pins */
      ERa.virtualWrite(0, current_sensor.accel_x);
      ERa.virtualWrite(1, current_sensor.accel_y);
      ERa.virtualWrite(2, current_sensor.accel_z);
      ERa.virtualWrite(3, current_sensor.lidar_front);
      ERa.virtualWrite(4, current_sensor.lidar_rear);
      ERa.virtualWrite(5, current_fft.peak_freq_hz);
      ERa.virtualWrite(6, current_fft.peak_accel_z);
      ERa.virtualWrite(7, current_sensor.temp_aht10);
      ERa.virtualWrite(8, current_sensor.humidity_aht10);
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// ===== INITIALIZE SENSORS =====
void init_sensors(void) {
  Wire.begin(SDA_PRIMARY, SCL_PRIMARY);
  Wire.setClock(I2C_FREQ_PRIMARY);
  
  Wire1.begin(SDA_SECONDARY, SCL_SECONDARY);
  Wire1.setClock(I2C_FREQ_SECONDARY);
  
  bmi160.softReset();
  delay(100);
  bmi160.I2cInit(BMI160_ADDR);
  
  vl53_front.begin(0x29, &Wire);
  vl53_front.setTimingBudget(50);
  vl53_front.startRanging();
  
  vl53_rear.begin(0x30, &Wire);
  vl53_rear.setTimingBudget(50);
  vl53_rear.startRanging();
  
  aht.begin(&Wire1);
  
  if (!rtc.isrunning()) {
    rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
  }
  
  ds18b20.begin();
  
  delay(500);
}

// ===== READ ALL SENSORS =====
void read_sensors(sensor_data_t *data) {
  data->timestamp = millis();
  
  int16_t imuData[6] = {0};
  if (bmi160.getAccelGyroData(imuData) == 0) {
    data->accel_x = imuData[0] / 16384.0f;
    data->accel_y = imuData[1] / 16384.0f;
    data->accel_z = imuData[2] / 16384.0f;
    data->gyro_x = imuData[3] / 131.0f;
    data->gyro_y = imuData[4] / 131.0f;
    data->gyro_z = imuData[5] / 131.0f;
  }
  
  if (xSemaphoreTake(i2c_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
    if (vl53_front.dataReady()) {
      data->lidar_front = vl53_front.distance();
      vl53_front.clearInterrupt();
    }
    if (vl53_rear.dataReady()) {
      data->lidar_rear = vl53_rear.distance();
      vl53_rear.clearInterrupt();
    }
    xSemaphoreGive(i2c_mutex);
  }
  
  sensors_event_t humidity, temp;
  if (aht.getEvent(&humidity, &temp)) {
    data->temp_aht10 = temp.temperature;
    data->humidity_aht10 = humidity.relative_humidity;
  }
  
  ds18b20.requestTemperatures();
  data->temp_ds18b20 = ds18b20.getTempCByIndex(0);
}

// ===== READ UART STATUS =====
void read_uart_status(void) {
  while (Serial2.available()) {
    static char uart_buffer[32] = {0};
    static int uart_idx = 0;
    
    char c = Serial2.read();
    
    if (c == '\n' || c == '\r') {
      if (uart_idx > 0) {
        uart_buffer[uart_idx] = 0;
        if (strncmp(uart_buffer, "KEY:", 4) == 0 || 
            strncmp(uart_buffer, "DIST:", 5) == 0) {
          strncpy(current_sensor.key_status, uart_buffer, sizeof(current_sensor.key_status) - 1);
        }
        uart_idx = 0;
      }
    } else if (uart_idx < sizeof(uart_buffer) - 1) {
      uart_buffer[uart_idx++] = c;
    }
  }
}

// ===== PROCESS FFT =====
void process_fft(double *accel_z_buffer, fft_result_t *result) {
  for (int i = 0; i < FFT_SAMPLES; i++) {
    fftInput[i] = accel_z_buffer[i];
    fftImag[i] = 0.0;
  }
  
  fft.windowing(fftInput, FFT_SAMPLES, FFT_WIN_TYP_HAMMING, FFT_FORWARD);
  fft.compute(fftInput, fftImag, FFT_SAMPLES, FFT_FORWARD);
  fft.complexToMagnitude(fftInput, fftImag, FFT_SAMPLES);
  
  result->peak_accel_z = 0;
  result->peak_freq_hz = 0;
  double rms = 0;
  
  for (int i = 0; i < FFT_SAMPLES / 2; i++) {
    if (fftInput[i] > result->peak_accel_z) {
      result->peak_accel_z = fftInput[i];
      result->peak_freq_hz = (i * 100.0) / FFT_SAMPLES;
    }
    rms += fftInput[i] * fftInput[i];
  }
  
  result->quality_factor = sqrt(rms / (FFT_SAMPLES / 2));
}

// ===== UPDATE DISPLAY =====
void update_display(void) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tf);
  
  char buf[64];
  
  snprintf(buf, sizeof(buf), "Status: %s", current_sensor.key_status);
  u8g2.drawStr(0, 10, buf);
  
  snprintf(buf, sizeof(buf), "Front:%umm Rear:%umm", 
           current_sensor.lidar_front, current_sensor.lidar_rear);
  u8g2.drawStr(0, 20, buf);
  
  snprintf(buf, sizeof(buf), "Peak:%.1fHz @%.2fg", 
           current_fft.peak_freq_hz, current_fft.peak_accel_z);
  u8g2.drawStr(0, 30, buf);
  
  snprintf(buf, sizeof(buf), "Accel Z:%.2fg", current_sensor.accel_z);
  u8g2.drawStr(0, 40, buf);
  
  snprintf(buf, sizeof(buf), "T:%.1fC H:%.1f%%", 
           current_sensor.temp_aht10, current_sensor.humidity_aht10);
  u8g2.drawStr(0, 50, buf);
  
  u8g2.drawStr(0, 60, "ERa: Publishing...");
  
  u8g2.sendBuffer();
}

// ===== DISPLAY SUSPENSION MENU =====
void display_suspension_menu(void) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tf);
  
  char buf[64];
  
  u8g2.drawStr(0, 10, "=== Suspension Menu ===");
  
  snprintf(buf, sizeof(buf), "Front LiDAR: %umm", current_sensor.lidar_front);
  u8g2.drawStr(0, 25, buf);
  
  snprintf(buf, sizeof(buf), "Rear LiDAR:  %umm", current_sensor.lidar_rear);
  u8g2.drawStr(0, 35, buf);
  
  snprintf(buf, sizeof(buf), "Vibration: %.1fHz", current_fft.peak_freq_hz);
  u8g2.drawStr(0, 45, buf);
  
  snprintf(buf, sizeof(buf), "Amplitude: %.2fg", current_fft.peak_accel_z);
  u8g2.drawStr(0, 55, buf);
  
  u8g2.sendBuffer();
}

// ===== LOG TO SD =====
void log_to_sd(const sensor_data_t *data) {
  if (!SD.exists(csv_filepath)) {
    return;
  }
  
  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    csv_file = SD.open(csv_filepath, FILE_APPEND);
    
    if (csv_file) {
      char line[256];
      snprintf(line, sizeof(line),
        "%lu,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,%.1f,%.1f,%.1f,%s\n",
        data->timestamp,
        data->accel_x, data->accel_y, data->accel_z,
        data->gyro_x, data->gyro_y, data->gyro_z,
        data->lidar_front, data->lidar_rear,
        data->temp_ds18b20, data->temp_aht10, data->humidity_aht10,
        data->key_status
      );
      
      csv_file.print(line);
      csv_file.close();
    }
    
    xSemaphoreGive(sd_mutex);
  }
}

// ===== CREATE CSV FILE =====
void create_csv_file(void) {
  DateTime now = rtc.now();
  snprintf(csv_filepath, sizeof(csv_filepath),
    "/data_%04d%02d%02d_%02d%02d%02d.csv",
    now.year(), now.month(), now.day(),
    now.hour(), now.minute(), now.second()
  );
  
  csv_file = SD.open(csv_filepath, FILE_WRITE);
  if (csv_file) {
    csv_file.println("Timestamp_ms,Accel_X_g,Accel_Y_g,Accel_Z_g,"
                     "Gyro_X_dps,Gyro_Y_dps,Gyro_Z_dps,"
                     "Suspension_LiDAR_Front_mm,Suspension_LiDAR_Rear_mm,"
                     "Temp_DS18B20_C,Temp_AHT10_C,Humidity_AHT10_Pct,Status");
    csv_file.close();
    Serial.print("CSV file created: ");
    Serial.println(csv_filepath);
  }
}

/* ERa Connected callback */
ERA_CONNECTED() {
    Serial.println("ERa connected!");
}

/* ERa Disconnected callback */
ERA_DISCONNECTED() {
    Serial.println("ERa disconnected!");
}
