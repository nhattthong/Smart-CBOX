# Smart-CBOX — EV Smart Motorcycle Control & Security System

> **Version 3.0** — STM32F411 anchor · Adaptive Kalman Filter · UWB Smart Key ·
> Full-stack IoT dashboard · Suspension telemetry

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SMART-CBOX SYSTEM                                   │
│                                                                             │
│   ┌──────────────┐  UWB TWR   ┌──────────────────────────────────────┐      │
│   │  ESP32-C3    │◄──────────►│  STM32F411CEU6  (BlackPill Anchor)   │      │
│   │  (Tag / Fob) │  802.15.4  │  - DW3000 UWB module                 │      │
│   │  DW3000      │  AES-CCM*  │  - Adaptive Kalman Filter (AKF)      │      │
│   │  Deep-sleep  │            │  - AES-128 CCM* decrypt + anti-replay │      │
│   └──────────────┘            │  - Relay control (unlock/lock)       │      │
│                                └──────────────┬───────────────────────┘      │
│                                               │ UART1 115200 bps             │
│                                               │ STATUS:KEY=ON|DIST=|KF=|... │
│                                               ▼                              │
│                                ┌──────────────────────────────────────────┐  │
│                                │          ESP32-S3  (Gateway Hub)         │  │
│                                │  Core 1: Sensor reader + UART parser     │  │
│                                │  Core 0: FFT + OLED + WiFi + WebServer   │  │
│                                │                                           │  │
│                                │  Sensors on I2C / OneWire / UART:        │  │
│                                │  - BMI160 IMU (vibration / acceleration) │  │
│                                │  - 2× VL53L1X LiDAR (suspension travel) │  │
│                                │  - AHT10 temp/humidity                   │  │
│                                │  - DS18B20 temperature                   │  │
│                                │  - DS1307 RTC                            │  │
│                                │  - SD card (CSV logging)                 │  │
│                                │  - SSD1306 OLED 128×64                   │  │
│                                │                                           │  │
│                                │  Output:                                  │  │
│                                │  - HTTP /api/data (JSON)                 │  │
│                                │  - HTTP /api/log  (JSON log ring)        │  │
│                                │  - ERa IoT platform (virtual pins)       │  │
│                                │  - BLE (future: UWB → phone gateway)     │  │
│                                └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Hardware Modules

### 1. STM32F411CEU6 — UWB Anchor (`f411.ino`)
| Parameter | Value |
|-----------|-------|
| MCU | STM32F411CEU6 BlackPill |
| Core | Cortex-M4F @ 100 MHz + HW FPU |
| RAM / Flash | 128 KB / 512 KB |
| UWB | DW3000 via SPI1 (PA4–PA7) |
| UART to ESP32-S3 | UART1 PA9/PA10 @ 115200 |
| Relay | PB1 (HIGH = unlock) |
| DW3000 IRQ/RST | PB0 / PA1 |
| Upload | DFU (USB-C) or ST-Link SWD |

**Replaces** the previous STM32F103C8T6 (BluePill). Same wiring, same relay/SPI pinout.
Key improvements over F103:
- Hardware FPU eliminates software float overhead in Adaptive KF
- 6× more RAM → larger nonce history, richer filter state
- USB-C CDC for direct debug without a USB–UART adapter

### 2. ESP32-S3 — Sensor Hub & Gateway (`esps3.ino`)
| Peripheral | Interface | Notes |
|------------|-----------|-------|
| BMI160 IMU | I2C1 SDA=21 SCL=22 | Vibration, accel, gyro |
| VL53L1X ×2 | I2C1 | Front/rear suspension travel |
| AHT10 | I2C2 SDA=4 SCL=2 | Temp/humidity |
| DS18B20 | OneWire GPIO12 | Engine/motor temp |
| DS1307 RTC | I2C2 | Timestamp for CSV |
| OLED SSD1306 | I2C1 | 128×64 status display |
| SD card | SPI CS=5 | CSV data logging |
| Anchor UART | Serial2 RX=17 TX=18 | From STM32F411 |

**Dual-core FreeRTOS:**
- Core 1: Sensor reading loop (100 Hz), UART parser
- Core 0: FFT, OLED update, WiFi/ERa publish, HTTP server

### 3. ESP32-C3 — Smart Key Fob / Tag (`tagc3.ino`)
| Parameter | Value |
|-----------|-------|
| Role | UWB TWR Responder |
| UWB | DW3000 SPI (SCK=4, MISO=5, MOSI=6, CS=7) |
| IRQ/RST | GPIO2 (RTC wake) / GPIO3 |
| Power | Deep sleep between ranging cycles (~1–2 mA average) |
| Security | AES-128 CCM* payload, random nonce, 4-byte MIC |
| Battery ADC | GPIO0 (1:2 divider, 12-bit) |

---

## Adaptive Kalman Filter (Machine Learning for Noise Reduction)

The STM32F411 runs an **Adaptive Kalman Filter (AKF)** that automatically learns the ranging noise characteristics of the specific motorcycle/garage environment, removing the need for manual filter tuning.

### Model
```
State x[k]       = distance (m)
Process noise w  ~ N(0, Q)   — models real movement of the tag
Measurement v    ~ N(0, R)   — models DW3000 TWR ranging error
```

### Standard KF Cycle
```
Predict:   x_pred = x_est           (constant-position model)
           P_pred = P_est + Q

Update:    innov  = z - x_pred      (innovation / residual)
           K      = P_pred / (P_pred + R)
           x_est  = x_pred + K * innov
           P_est  = (1 - K) * P_pred
```

### Adaptation (Innovation-based Adaptive Estimation)
```
EMA(ε²)    = α * innov² + (1-α) * EMA(ε²)    (tracks actual noise)
S_theory   = P_pred + R                        (expected innovation var)

If EMA(ε²) > 1.2 * S_theory  →  R *= 1.05   (noisier → trust measurements less)
If EMA(ε²) < 0.8 * S_theory  →  R *= 0.97   (quieter → trust measurements more)
Q adapts via K*R heuristic (fast movement → larger Q)
```

### Outlier Gate
Measurements where `|innov| > 4 * sqrt(S)` are **rejected** (multipath spikes, NLoS).
These are reported to ESP32-S3 as `ERR:GATE`.

### Convergence
| Phase | Duration | Behaviour |
|-------|----------|-----------|
| Boot (seed) | 1st measurement | x set directly, no prediction |
| Convergence | ~2 s (20 × 100 ms cycles) | Q, R stabilise to environment |
| Steady-state open | ongoing | R ≈ 0.01–0.03 m², tight tracking |
| Steady-state garage | ongoing | R ≈ 0.05–0.15 m², smooth output |
| Tag moving | immediate | Q increases → faster tracking |

---

## Communication Protocol

### UART: STM32F411 → ESP32-S3

```
STATUS:KEY=ON|DIST=1.23|KF=1.21|Q=0.0010|R=0.0500|BAT=85\r\n
ERR:DECRYPT\r\n    — AES MIC failed
ERR:REPLAY\r\n     — nonce replay detected
ERR:CMD\r\n        — unknown plaintext command
ERR:GATE\r\n       — KF outlier gate rejected measurement
```

Field meanings:
- `DIST` — raw Two-Way Ranging distance (m)
- `KF`   — Adaptive KF filtered distance (m) ← used for relay decision
- `Q`    — learned process noise variance
- `R`    — learned measurement noise variance

### HTTP REST: ESP32-S3 → Browser / App

| Endpoint | Method | Response |
|----------|--------|----------|
| `/` | GET | HTML5 dashboard (auto-refresh 2 s) |
| `/api/data` | GET | JSON all sensors + KF state |
| `/api/log` | GET | JSON array, last 20 log entries |

Sample `/api/data` response:
```json
{
  "key_status": "ON",
  "key_dist_m": 1.23,
  "key_kf_dist_m": 1.21,
  "key_kf_q": 0.0010,
  "key_kf_r": 0.0500,
  "key_bat_pct": 85,
  "fft_freq_hz": 12.5,
  "accel_z": 0.97,
  "lidar_front_mm": 95,
  "lidar_rear_mm": 82
}
```

### ERa IoT Virtual Pin Map

| V-Pin | Signal |
|-------|--------|
| V0 | Accel X (g) |
| V1 | Accel Y (g) |
| V2 | Accel Z (g) |
| V3 | LiDAR Front (mm) |
| V4 | LiDAR Rear (mm) |
| V5 | FFT Peak Freq (Hz) |
| V6 | FFT Peak Amplitude (g) |
| V7 | Temperature AHT10 (°C) |
| V8 | Humidity AHT10 (%) |
| V9 | Tag Battery (%) |
| V10 | UWB Raw Distance (m) |
| V11 | UWB KF Distance (m) |
| V12 | KF Process Noise Q |
| V13 | KF Measurement Noise R |

---

## UWB Smart Key — Security Design

```
Tag (ESP32-C3 + DW3000)                   Anchor (STM32F411 + DW3000)
────────────────────────                  ───────────────────────────────────
DW3000 receives POLL frame        ←────── Sends POLL frame every 100 ms
Records poll RX timestamp (T2)            Records poll TX timestamp (T1)
Sends RESP frame with:            ──────► Records resp RX timestamp (T4)
  [MAC header 9B]                         Extracts T2, T3 from frame
  [T2: poll RX  4B]                       Computes: ToF = ((T4-T1)-(T3-T2))/2
  [T3: resp TX  4B]                       Distance = ToF × c
  [rand_nonce 4B]                         AKF(distance) → filtered distance
  [AES-CCM*(CMD:OPEN|BAT:nn) ]            AES-CCM* decrypt + MIC verify
  [MIC 4B]                                Nonce anti-replay check
                                          Relay control based on KF distance
```

**Key material**: 128-bit pre-shared AES key (change `aes_key` in both `f411.ino`
and `tagc3.ino` before deployment).

---

## UWB on Smartphone — Connection Options

### Option A — Gateway BLE Bridge ✅ Recommended, any phone
ESP32-S3 exposes a **BLE GATT** service (Nordic UART Service or custom).
Phone app reads KF distance as BLE characteristic.
- Works with **any Android or iOS phone**
- No UWB hardware needed on phone
- Implementation: add `NimBLE` or `BLE` library to `esps3.ino`;
  notify characteristic `key_kf_dist_m` every 500 ms.

### Option B — Native Android UWB API (Android 12+)
Compatible phones: **Samsung Galaxy S21 Ultra / S22+ / S23+, Pixel 6 Pro+, Pixel 7+,
Pixel 8, OnePlus 12, Xiaomi 14** (verify with `UwbManager.isAvailable()`).

Requirements:
1. Replace the proprietary frame format in `f411.ino` with **FiRa MAC/PHY**
   (RANGING_ROUND_CONTROL frames, SESSION_INIT, SESSION_START BLE out-of-band).
2. Use Qorvo's open-source **FiRa stack** or the STM32 port of the FiRa reference.
3. Android app uses `androidx.core.uwb` (Jetpack UWB Ranging API).

### Option C — Apple Nearby Interaction (iPhone 11+, iOS 14+)
Requires:
- Apple **MFi program** membership
- Qorvo **QM33120W** module or MDEK1001 kit with Apple-specific certified firmware
- `NISession` / `NINearbyObject` APIs (SwiftUI/UIKit)
- Out-of-band session token exchange over BLE (GAP / GATT)

### Option D — Phone as Tag (replaces ESP32-C3 fob)
On Android 12+ UWB-capable phones, the phone can act as the **UWB initiator/tag**
directly, ranging against this anchor. The phone uses `UwbControllerSessionScope`
or `UwbControleeSessionScope` depending on the role.
Requires FiRa-compatible firmware on the anchor (see Option B).

> **Quick-start recommendation**: Implement Option A (BLE bridge in `esps3.ino`)
> first — works today with zero additional hardware. Add FiRa firmware later for
> native Options B/D.

---

## Source Files

| File | MCU | Role |
|------|-----|------|
| `smartmoto/scr/f411.ino` | STM32F411CEU6 | UWB anchor + AKF + AES security |
| `smartmoto/scr/esps3.ino` | ESP32-S3 | Sensor hub + dashboard + IoT |
| `smartmoto/scr/tagc3.ino` | ESP32-C3 | UWB tag/fob + deep-sleep |
| `smartmoto/scr/pdoa_test.ino` | STM32/ESP32 | PDOA AoA test + gateway JSON |
| `smartmoto/scr/stm.ino` | STM32F103 | Legacy anchor (superseded by f411.ino) |
| `smartmoto/libaries/` | — | DW3000 driver (Decawave/Qorvo) |

---

## Version History

| Version | Notes |
|---------|-------|
| 1.0 | ESP8266, basic multi-sensor |
| 2.0 | ESP32-S3, STM32F103, DW3000 UWB, AES-CCM* smart key |
| 3.0 | **STM32F411 anchor**, Adaptive Kalman Filter, PDOA test, extended dashboard |
