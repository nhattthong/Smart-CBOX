# Power Trade-off Report: Tag RX-Listen vs Periodic TX (UWB DW3000 / ESP32-C3)

> **Repository:** nhattthong/Smart-CBOX  
> **Date:** 2026-04-24  
> **Affected files:** `ESP32C3_SmartKey_Tag.ino`, `smartmoto/scr/tagc3.ino`, `smartmoto/scr/stm.ino`  
> **New files:** `smartmoto/scr/tag_tx_periodic.ino`, `smartmoto/scr/anchor_rx_beacon.ino`

> ⚠️ **All numeric values in this document are estimates based on published datasheet
> figures and reasonable engineering assumptions. They MUST be validated with bench
> measurements on the actual hardware before making production decisions.**

---

## 1. Current Design (RX-Listen / TWR Responder)

### 1.1 Architecture

```
Anchor (STM32F103)               Tag (ESP32-C3 + DW3000)
─────────────────────            ────────────────────────
Every 100 ms:                    Deep sleep (ESP32-C3)
  TX POLL ──────────────────────►  DW3000 in RX-listen
                                   DW3000 IRQ → GPIO2 HIGH
                                   ESP32-C3 wakes (ext0)
              RESP ◄──────────────  Process POLL, TX RESP
                                   Return to sleep
  Receive RESP
  Compute TWR distance
  AES-CCM* decrypt
  Relay control
```

### 1.2 Power Consumption Estimates

| Component | State | Current (estimate) |
|---|---|---|
| ESP32-C3 | Deep sleep, RTC on | ~5 µA |
| DW3000 | RX-listen, address-filtered | ~8–12 mA |
| **System total (sleep)** | | **~8–12 mA** |
| ESP32-C3 | Active (wake, process) | ~30–80 mA |
| DW3000 | TX burst (~3 ms) | ~100 mA |
| **System (TX burst)** | ~3 ms per cycle | **~100 mA peak** |

**Average current (10 ranging/s, 5 ms active per cycle):**

```
I_avg ≈ I_sleep × (1 − duty) + I_active × duty
      ≈ 10 mA × 0.95 + 80 mA × 0.05
      ≈ 9.5 mA + 4 mA ≈ 13.5 mA
```

**Battery life estimate (1000 mAh):** `1000 / 13.5 ≈ 74 hours ≈ 3 days`

> The DW3000 in RX mode is the dominant consumer, regardless of ESP32-C3 deep sleep.

---

## 2. Alternative Design (Periodic TX / Beacon Mode)

### 2.1 Architecture

```
Tag (ESP32-C3 + DW3000)          Anchor (STM32F103)
────────────────────────         ─────────────────────────
Deep sleep (both MCU + DW3000)   DW3000 in RX-listen
                                 (anchor is always powered)

Every TX_INTERVAL_S seconds:
  Timer wakeup
  Init DW3000
  AES-CCM* encrypt beacon
  TX beacon ──────────────────►  Receive beacon
  Return to deep sleep           AES-CCM* decrypt
                                 Seq counter check
                                 Relay control (timeout-based)
```

### 2.2 Power Consumption Estimates

**Tag power (TX_INTERVAL_S = 5 s):**

| Phase | Duration | Current | Energy |
|---|---|---|---|
| DW3000 off, ESP32-C3 RTC sleep | 4987 ms | ~5 µA | 0.025 mAs |
| Wake + DW3000 init (SPI, configure) | ~10 ms | ~50 mA | 0.50 mAs |
| AES encrypt + TX burst | ~3 ms | ~100 mA | 0.30 mAs |
| **Total per 5 s cycle** | 5000 ms | — | **0.825 mAs** |
| **Average current** | — | — | **≈ 0.165 mA** |

**Battery life estimate (1000 mAh):** `1000 / 0.165 ≈ 6060 hours ≈ 252 days`

**Effect of TX interval on average current and battery life (estimates):**

| TX_INTERVAL_S | Avg current | Battery life (1000 mAh) | Max latency |
|---|---|---|---|
| 1 s | ~0.82 mA | ~51 days | 1 s |
| 2 s | ~0.41 mA | ~102 days | 2 s |
| 5 s | ~0.165 mA | ~252 days | 5 s |
| 10 s | ~0.085 mA | ~490 days | 10 s |
| 30 s | ~0.030 mA | ~1400 days | 30 s |

---

## 3. Comparison: RX-Listen vs Periodic TX

| Criterion | RX-Listen (current) | Periodic TX (proposed) |
|---|---|---|
| **Tag avg current** | ~10–13 mA | ~0.17 mA (5 s interval) |
| **Battery life** | ~3–4 days (1000 mAh) | ~252 days (1000 mAh) |
| **Improvement** | baseline | **≈ 60×** |
| **Distance measurement** | Yes (TWR, ±10 cm typical) | No (one-way only) |
| **Presence detection** | Yes + distance | Yes (timeout-based) |
| **Max response latency** | <100 ms | ≤ TX_INTERVAL_S |
| **Multi-tag support** | Requires scheduling (anchor polls each tag in sequence) | Natural (each tag beacons independently, anchor filters by address) |
| **Anchor power** | Anchors stays active (powered, initiates) | Anchor stays in RX-listen (same as DW3000 RX power always on) |
| **AES-CCM* security** | Yes | Yes |
| **Anti-replay** | Nonce ring buffer (32 entries × 4B rand) | Monotonic 32-bit counter |
| **Collision risk** | None (anchor-scheduled) | Low at 1 tag; grows with N tags broadcasting simultaneously |
| **Robustness** | Single missed response → anchor retries next cycle | Single missed beacon → relay stays ON until timeout |

---

## 4. Advantages and Disadvantages

### 4.1 Periodic TX — Advantages
1. **Massive power saving on tag:** ~60× reduction in average current → months of battery life from a coin-cell or small LiPo.
2. **Simpler tag firmware:** no RX state machine, no TWR timing, no delayed-TX scheduling.
3. **Natural multi-tag scaling:** beacons are broadcast; one anchor handles many tags with only address filtering.
4. **DW3000 can be fully powered off** between beacons (load switch), further reducing sleep current.

### 4.2 Periodic TX — Disadvantages
1. **No ranging distance:** one-way link cannot do TWR. Proximity is detection-only (in-range / out-of-range based on RSSI or timeout).
2. **Higher latency:** access control latency equals TX_INTERVAL_S (up to 5 s). For a motorcycle smart key this may be acceptable.
3. **Collision risk in dense deployments:** if N tags beacon at the same rate and start synchronized (e.g., all powered on at the same time), probability of overlap increases. Mitigation: random jitter on TX interval (see §6).
4. **Anchor always in RX mode:** the anchor's DW3000 power budget does not decrease — only the tag saves power. If the anchor is mains-powered (motorcycle ECU), this is not an issue.
5. **Tag reset causes seq counter reset:** after battery replacement or power cycle, the monotonic counter restarts at 0. If the anchor has a higher last_seq stored, it will reject the first N beacons until the counter exceeds the anchor's last known value. Mitigation: anchor resets its stored counter on a configurable gap (e.g., if recv_ctr < last_seq by more than 0x7FFFFFFF, treat as reset).

---

## 5. Impact on Latency, Reliability, Multi-Tag, and Security

### 5.1 Latency
- **Current (RX-listen):** Anchor polls every 100 ms → tag responds within ~5 ms → latency < 100 ms.
- **Periodic TX:** Worst-case latency = TX_INTERVAL_S. Anchor detects absence only after SIGNAL_TIMEOUT_MS. Recommended: set SIGNAL_TIMEOUT_MS ≥ 2.5 × TX_INTERVAL_S × 1000 to handle occasional missed beacons.
- **Mitigation:** Reduce TX_INTERVAL_S to 1–2 s if sub-5-second latency is required (battery life still 50–100 days).

### 5.2 Reliability
- **Packet loss:** DW3000 at UWB CH5, 6.8 Mbps in typical indoor environment: PER < 1% at distances < 10 m. With TX every 5 s and 2.5× timeout, the relay tolerates ~1.5 consecutive missed beacons before locking.
- **Multipath:** unlikely to cause consistent frame loss at typical keyless-entry ranges (1–3 m).
- **Recommendation:** set SIGNAL_TIMEOUT_MS = 3 × TX_INTERVAL_S × 1000 for better tolerance.

### 5.3 Multi-Tag Handling
- **Current design:** anchor must poll each tag address separately (sequential polling), limiting scalability.
- **Periodic TX:** each tag broadcasts independently to the anchor address. The anchor's DW3000 address filter accepts frames to its own address regardless of source — it identifies the source from the MAC SRC field. Multiple tags can coexist with zero additional anchor code, at the cost of occasional collisions.
- **Collision probability (2 tags, T=5 s, frame duration ≈ 1 ms):** P_collision ≈ 1 ms / 5000 ms = 0.02% per interval (negligible). With 10 tags: P ≈ 0.2% per interval per pair. Random jitter eliminates synchronised bursts.

### 5.4 Security
- **AES-CCM* integrity:** unchanged — same DW3000 hardware engine, same MIC_LEN=4. The cryptographic strength is identical.
- **Replay protection:** replaced ring-buffer (32 × 4B random nonce) with monotonic 32-bit counter. The counter is stronger against systematic replay but weaker against tag-reset attacks (see §4.2). Combine with random nonce in AAD for additional protection.
- **MIC size:** 4-byte MIC provides 2^32 brute-force resistance per frame; adequate for a physical-layer access control tag, but increasing to 8 bytes (MIC_8) would improve security with negligible overhead.
- **Key management:** the pre-shared key is hard-coded in both sketches. For production, provision via a secure out-of-band channel and store in a gitignored `secret_key.h`.
- **Eavesdropping / replay from sniffer:** without the AES key an attacker cannot forge or replay a valid beacon (MIC check fails). The monotonic counter prevents recorded-and-replayed beacons.

---

## 6. Recommendations

### 6.1 Should you swap roles?
**Yes, for battery-powered tags where battery life > 1 week is required.**  
Keep the RX-listen design only if sub-100 ms latency AND ranging distance are both required simultaneously.

### 6.2 Suggested Parameters

| Parameter | Recommended value | Rationale |
|---|---|---|
| `TX_INTERVAL_S` | 5 s | Good balance: ~252 days battery, ≤5 s latency |
| `SIGNAL_TIMEOUT_MS` | 13000 ms (2.6 × 5000) | Tolerates 2 consecutive missed beacons |
| `MIC_LEN` | 4 (current), upgrade to 8 for production | 4B sufficient for prototype |
| Random jitter on TX interval | ±500 ms (uniform random) | Prevents synchronised collisions with multiple tags |
| DW3000 preamble length | `DWT_PLEN_64` for lower TX time | Reduce active window; validate PER |
| TX power | Reduce by 3–6 dB if operating range < 5 m | Lower interference + slightly lower TX current |

### 6.3 Hybrid Mode (optional)
For applications needing both low power AND ranging:
1. Tag beacons every 5 s (presence announcement, low power).
2. Anchor detects presence → initiates a single TWR exchange on demand.
3. Tag wakes via IRQ for the TWR cycle, then returns to deep sleep.
This provides ~95% of the power savings with full distance capability.

### 6.4 Collision Avoidance for Multiple Tags
Add a random jitter in `enter_deep_sleep()`:
```cpp
// In tag_tx_periodic.ino, replace:
esp_sleep_enable_timer_wakeup((uint64_t)TX_INTERVAL_S * 1000000ULL);
// With:
uint32_t jitter_us = (esp_random() % 1000000UL); // 0–1 s jitter
esp_sleep_enable_timer_wakeup(
    (uint64_t)TX_INTERVAL_S * 1000000ULL + jitter_us);
```

---

## 7. Implementation Plan

### 7.1 New Files
| File | Role |
|---|---|
| `smartmoto/scr/tag_tx_periodic.ino` | Tag firmware — periodic TX beacon |
| `smartmoto/scr/anchor_rx_beacon.ino` | Anchor firmware — beacon RX mode |

### 7.2 Modified Files (not changed in this PR — for reference)
| File | Required changes if adopting new design |
|---|---|
| `smartmoto/scr/tagc3.ino` | No changes needed; keep for TWR/ranging fallback |
| `smartmoto/scr/stm.ino` | No changes needed; keep for TWR/ranging fallback |

### 7.3 Step-by-Step Validation

**Step 1 — Flash and basic TX test:**
1. Flash `tag_tx_periodic.ino` to an ESP32-C3 board.
2. Connect a logic analyser or second DW3000 board in sniffer mode to confirm beacons are transmitted every 5 s.
3. Verify AES flag in DW3000 TX: `dwt_read32bitreg(SYS_STATUS_ID)` bit `SYS_STATUS_TXFRS_BIT_MASK` set after TX.

**Step 2 — Flash anchor and end-to-end test:**
1. Flash `anchor_rx_beacon.ino` to the STM32 BluePill board.
2. Monitor `Serial1` output (UART1 → USB-UART adapter): expect `STATUS:KEY=ON|BAT=xx` every 5 s.
3. Power off the tag: after `SIGNAL_TIMEOUT_MS` ms (13 s), expect `STATUS:KEY=OFF|BAT=0`.

**Step 3 — Anti-replay test:**
1. Capture a raw UWB beacon frame with a DW3000 sniffer.
2. Re-inject it using a replay device: anchor should output `ERR:REPLAY`.
3. Confirm: only frames with `recv_ctr > last_seq_ctr` are accepted.

**Step 4 — Power measurement:**
1. Insert a precision current meter (e.g., Nordic PPK2 or Otii Arc) in series with the tag battery.
2. Record current vs time for at least 3 full TX cycles.
3. Calculate average current and compare to estimates in §2.2.
4. Measure peak TX current and verify it does not exceed battery/regulator limits.

**Measurement setup diagram:**
```
[Battery+] ──► [Current meter] ──► [VCC pin of ESP32-C3]
[Battery−] ─────────────────────► [GND pin of ESP32-C3]
```

**Step 5 — Multi-tag test:**
1. Flash `tag_tx_periodic.ino` to two boards with different `TAG_ADDR` values.
2. Modify `anchor_rx_beacon.ino` to accept any source address (remove strict address filter on SRC field).
3. Monitor anchor UART for both tag addresses appearing in `STATUS:KEY=ON|BAT=xx` messages.

---

## 8. Security Checklist

- [ ] Replace placeholder AES key with a cryptographically random key before deployment.
- [ ] Store the key in a gitignored `secret_key.h`, not in the committed source file.
- [ ] Generate key: `python3 -c "import os; d=os.urandom(16); print(','.join(hex(int.from_bytes(d[i:i+4],'big'))+'UL' for i in range(0,16,4)))"`
- [ ] Consider increasing `MIC_LEN` from 4 to 8 for production builds.
- [ ] Implement anchor-side handling for tag seq counter reset (large downward jump = reset event).
- [ ] Validate nonce entropy: `esp_random()` on ESP32-C3 uses the hardware RNG seeded by RF noise; confirm RNG is seeded before first use (it is, by default in ESP-IDF).

---

## 9. References

- [DW3000 Datasheet — Qorvo](https://www.qorvo.com/products/p/DW3000)
- [DW3000 User Manual (UWB Chip) — Current consumption, RX mode, §6]
- [ESP32-C3 Datasheet — Deep sleep current, §4.5]
- [IEEE 802.15.4-2015 — MAC frame format, AES-CCM*]
- Existing tag firmware: `smartmoto/scr/tagc3.ino` (v2.0)
- Existing anchor firmware: `smartmoto/scr/stm.ino` (v2.0)
