# Smart-CBOX
This project is Innova for individual purposes to control and manage data from my EV bike.
Inculce:
+ Multi sensors (measure rad cooling, motor, environment)
+ CAN control changer ( adjust voltage, current)
+ Smart key ( UWB measure distance condition, position 2D view )
+ Internet platform ( manage, control all data, changer) 
+ Gyro + Acceleration ( Next ver: Machine-learning for electric suspension adjust) 


Ver 1.0
Ver 2.0 
+ ESP 8266
+ Multi sensors (measure rad cooling, motor, environment)
+ Time, speed by GPS + RTC DS2331

Ver 3.0 
Currently innovation.
+ ESP32 s3
+ LCD menu UIs icon
+ CAN control
+ MOD change suitable
+ UWB

---

## JK BMS Bluetooth BLE Reader (`smartmoto/scr/jkbms_ble/`)

Reads real-time data from a **JK BMS** unit over Bluetooth Low Energy (BLE) on an
**ESP32-S3** board.

### Target BLE device
| Field | Value |
|-------|-------|
| BLE name | `KLARA THONG` |
| BLE service | `FFE0` |
| Notify char | `FFE1` (BMS → ESP32) |
| Write char | `FFE2` (ESP32 → BMS, falls back to FFE1) |

### Protocol — JK BMS `0x4E57` frame
Request frame (21 bytes) sent every 3 s to trigger a data push:
```
4E 57 00 13 00 00 00 00 06 03 00 00 00 00 00 00 68 00 00 01 29
```
Response TLV tags parsed (big-endian):

| Tag | Field | Unit |
|-----|-------|------|
| 0x83 | Cell voltages | 1 mV / cell |
| 0x84 | MOSFET temperature | 0.1 °C |
| 0x85 | Battery temperature 1 | 0.1 °C |
| 0x86 | Battery temperature 2 | 0.1 °C |
| 0x87 | Pack voltage | 10 mV → ×0.01 V |
| 0x88 | Balance current | 1 mA |
| 0x89 | Pack current (signed) | 10 mA → ×0.01 A |
| 0x8A | State of charge | 1 % |
| 0x8B | Charge cycle count | — |
| 0x8C | Cycle total capacity | 10 mAh → ×0.01 Ah |

Power (W) = Voltage × Current is calculated on-device.

### Web UI
- `http://<ip>/` — live dashboard with auto-refresh every 2 s  
- `http://<ip>/api/data` — JSON snapshot of all BMS fields

WiFi: connects to `Moto_4G` (STA). Falls back to AP `JKBMS_Monitor` / `12345678`
if STA fails.

### Serial output
115200 baud — full BMS status printed every 2 s including per-cell voltages,
current direction (CHARGING / DISCHARGING / IDLE), and BLE connection state.

### Libraries required
All are included in the ESP32 Arduino board package (no extra installs needed):
- `BLEDevice` / `BLEScan` / `BLEClient`
- `WiFi`
- `WebServer`
- `freertos/FreeRTOS.h`

### Board settings (Arduino IDE)
| Setting | Value |
|---------|-------|
| Board | ESP32S3 Dev Module |
| Upload Speed | 921600 |
| USB CDC On Boot | Enabled |
| Port | COM32 |

