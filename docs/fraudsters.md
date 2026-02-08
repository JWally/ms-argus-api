# Fraud Prevention & Anomaly Detection

## What does the anomaly detection system actually do?

Every fingerprint that comes in gets run through four independent detector modules. Each one looks for a different class of suspicious behavior. They run in sequence but are error-isolated -- if one detector throws, the others still run.

```
Fingerprint
    |
    ├── Fingerprint Signals    headless? proxy? VPN? consistency checks
    ├── Cross-Field Anomalies  navigator vs worker scope mismatches
    ├── Statistical V2         Shannon entropy -- is this fingerprint rare?
    └── IP History             ASN hopping, IP churn
    |
    v
AnomalyResult { signals[], aggregateScore, suggestedFlags[] }
```

Each detector returns zero or more **anomaly signals**, each with a severity from 0 to 1. These get converted into device flags, and the flags drive the risk score.

---

## How are headless browsers and bots detected?

Two layers: direct detection in the fingerprint signals detector, and heuristic bot detection in the flag computation.

### Direct headless detection

The client-side library probes for headless browser artifacts and sets `is_headless: true` if they're present. If that flag arrives, it's an immediate anomaly signal at severity **0.9**.

### Bot heuristics (flag computation)

These checks run independently of the anomaly detectors:

| Signal                                                     | What it catches                                             |
| ---------------------------------------------------------- | ----------------------------------------------------------- |
| GPU renderer contains "SwiftShader"                        | Chrome headless (SwiftShader is Chrome's software renderer) |
| Screen dimensions = 800x600                                | Default headless viewport                                   |
| User agent contains "bot", "crawler", "spider", "headless" | Self-identifying bots                                       |
| CPU cores = 1 AND memory < 1 GB                            | Minimal VM/container                                        |

Any of these adds a `BOT_DETECTED` flag. SwiftShader also adds `HEADLESS_BROWSER`.

---

## How do proxy and VPN detection work?

The TCP/TLS probe on the server side computes `proxy_score` and `vpn_score` (0 to 1) based on network-layer signals. On the anomaly detection side, either score above **0.7** triggers a signal:

- **proxy_score > 0.7**: Severity = the score itself (e.g., 0.85 proxy score -> 0.85 severity). Adds `LIKELY_PROXY` flag.
- **vpn_score > 0.7**: Severity = score \* 0.8 (VPN is treated more leniently than proxy since many legitimate users use VPNs). Adds `LIKELY_VPN` flag.

---

## What cross-field consistency checks are there?

These catch fingerprint spoofing by comparing values that _should_ agree but don't. Spoofing tools often override one API without patching the others.

### Within-payload checks (fingerprint-signals detector)

| Check                        | Severity | What it catches                                                                                                                                                                              |
| ---------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Screen/CSS mismatch**      | 0.9      | `screen.width/height` differs from `cssMedia.screenQuery.width/height`. A spoofed screen resolution that forgot to patch CSS media queries.                                                  |
| **Audio noise**              | 0.85     | `offlineAudioContext.noise > 0`. Anti-fingerprinting extensions (like Canvas Blocker) inject noise into the audio context. Noise = 0 is the only honest value.                               |
| **Timezone offset mismatch** | 0.9      | `timezone.offset` differs from `workerScope.timezoneOffset`. The main thread and worker should always agree on timezone. A mismatch means one was spoofed.                                   |
| **Touch mismatch**           | 0.7      | `maxTouchPoints > 0` but `screen.touch = false`, or touch points reported but CSS says `anyPointer: fine` + `anyHover: hover` (mouse-only). Desktop pretending to be mobile (or vice versa). |
| **WebGL renderer mismatch**  | 0.85     | `canvasWebgl.parameters.UNMASKED_RENDERER_WEBGL` differs from `workerScope.webglRenderer`. Same GPU should report the same renderer string everywhere.                                       |

### Cross-scope checks (worker-scope-consistency detector)

Compares navigator properties across execution contexts: main thread, dedicated worker, shared worker, and service worker. Fields checked:

| Field                 | Severity | Notes                              |
| --------------------- | -------- | ---------------------------------- |
| `userAgent`           | 0.8      | Most commonly spoofed              |
| `platform`            | 0.75     | Often overlooked by spoofing tools |
| `hardwareConcurrency` | 0.7      | Rarely changes legitimately        |

Every pair of scopes is compared. A browser extension that overrides `navigator.userAgent` in the main thread but forgets the dedicated worker scope will get caught here.

---

## What is the statistical anomaly detection?

This is the most sophisticated layer. It uses **Shannon self-information** (information theory) to detect fingerprints that are statistically rare for their browser group.

### The core idea

For each fingerprint signal (JA4, HTTP/2 fingerprint, math hash, fonts, etc.), we maintain a frequency baseline grouped by browser family. If you claim to be Chrome on Windows but your JA4 TLS fingerprint has never been seen before on Chrome, that's suspicious.

### How Shannon scoring works

```
surprise = -log2(count / total)
score    = min(1.0, surprise / maxSurpriseBits)
```

| Probability | Surprise        | What it means                                       |
| ----------- | --------------- | --------------------------------------------------- |
| 50%         | 1 bit           | Completely normal                                   |
| 10%         | 3.3 bits        | Slightly unusual                                    |
| 1%          | 6.6 bits        | Rare                                                |
| 0.1%        | 9.9 bits        | Very rare                                           |
| Never seen  | max score (1.0) | This has never been observed for this browser group |

Each fingerprint type has a `maxSurpriseBits` ceiling that controls how aggressively rarity maps to severity. High-cardinality signals (like JA4 with many valid values) use higher ceilings (12 bits) so that moderate rarity doesn't trigger too easily.

### What fingerprint types are tracked?

| Type                  | What it is                                  | Why it matters                                                                                                                                  |
| --------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **JA4**               | TLS client fingerprint                      | Hard to spoof without recompiling the browser                                                                                                   |
| **H2**                | HTTP/2 settings fingerprint                 | Baked into the HTTP stack                                                                                                                       |
| **Maths**             | Hash of `Math.sin`, `Math.tan`, etc.        | Deterministic per JS engine -- V8 always produces the same output. If you say you're Chrome but your math hash is SpiderMonkey's, you're lying. |
| **Fonts**             | Installed font hash                         | Platform/locale dependent                                                                                                                       |
| **Lies**              | Hash of detected API lies                   | Fingerprint of the spoofing tool itself                                                                                                         |
| **CSS**               | CSS computed style hash                     | Browser-specific rendering                                                                                                                      |
| **TCP MSS**           | TCP maximum segment size                    | Network stack fingerprint                                                                                                                       |
| **TLS ratio**         | TLS-to-TCP timing ratio                     | Proxy detection signal                                                                                                                          |
| **Language/Timezone** | Language for timezone, timezone for country | Geo-consistency                                                                                                                                 |
| **JS engine**         | Console error patterns                      | Engine identification                                                                                                                           |
| **CSS key count**     | Number of CSS computed style properties     | Browser version fingerprint                                                                                                                     |
| **Navigator vendor**  | `navigator.vendor` value                    | Should match browser family                                                                                                                     |
| **WebGL vendor**      | WebGL `VENDOR` parameter                    | Should match GPU/driver                                                                                                                         |

### Combined scoring

Individual signals are useful, but the real power comes from combining them. If your JA4 is slightly unusual (score 0.5) _and_ your HTTP/2 fingerprint is slightly unusual (score 0.5), neither alone is damning. But the combined score uses:

```
combined = 1 - (1 - 0.5) * (1 - 0.5) = 0.75
```

This is the "probability of at least one real anomaly" formula. Two independent 50% signals combine to 75%. The combined threshold is **0.65** -- so those two moderate signals together would trigger a `RARE_FINGERPRINT_COMBO` flag.

Requirements for combination: at least 2 signals, each with confidence >= 0.3 and score >= 0.15.

### Confidence and sample size

The system tracks how many observations it's seen per browser group. Early on, with few samples, the confidence is low and the system won't flag things aggressively. Confidence uses a square-root curve:

```
confidence = sqrt(sampleCount / saturationThreshold)
```

This means the first few hundred observations build confidence quickly, then it plateaus. A signal is only emitted when both the score _and_ the confidence exceed their thresholds.

### Baseline poisoning prevention

Tampered fingerprints would corrupt the statistical baseline if we recorded them. Before recording an observation, the system runs baseline rules to filter out:

- Excessive API tampering (lie_count > 50)
- Worker UA mismatches (indicates spoofing)
- Headless browsers with stealth plugins (headless + lies > 10)

Filtered fingerprints are still _scored_ against the existing baseline (we want to detect them), they just don't _contribute_ to it. The rules are config-driven via `baseline-rules.json`.

---

## How does IP history anomaly detection work?

For returning devices, we track IP and ASN history. Two checks:

| Signal                 | Threshold                     | Severity | What it means                                                                                          |
| ---------------------- | ----------------------------- | -------- | ------------------------------------------------------------------------------------------------------ |
| **New ASN for device** | ASN not in history            | 0.3      | Device appeared on a network it's never used before. Soft signal -- could be travel, new ISP, etc.     |
| **IP churn**           | >= 100 unique IPs in 24 hours | 0.5      | Device cycling through many IPs rapidly. Strong indicator of proxy rotation, botnet, or relay network. |

---

## How do flags and risk scores work?

### Flag generation

Flags come from three sources, combined and deduplicated:

1. **Bot signals** -- SwiftShader, 800x600, bot UA, low hardware
2. **Anomaly signals** -- Everything above (anomaly codes lowercased into flag names)
3. **Behavioral signals** -- Fingerprint drift from stored profile, rapid requests (> 50/hour)

Positive flags (`VERIFIED`, `RETURNING_USER`) are preserved from the existing profile.

### Risk score calculation

Risk starts at a base value and adds/subtracts weights per flag:

```
base = 0.5 (new device) or 0.3 (returning device)
risk = base + sum(flag weights)
```

| Flag                   | Weight    |             |
| ---------------------- | --------- | ----------- |
| `BOT_DETECTED`         | +0.25     |             |
| `WORKER_MISMATCH`      | +0.20     |             |
| `IP_CHURN`             | +0.20     |             |
| `HEADLESS_BROWSER`     | +0.15     |             |
| `FINGERPRINT_MISMATCH` | +0.15     |             |
| `NAVIGATOR_LIES`       | +0.15     |             |
| `RAPID_REQUESTS`       | +0.10     |             |
| `LIKELY_PROXY`         | +0.10     |             |
| `SCREEN_CSS_MISMATCH`  | +0.10     |             |
| `LIKELY_VPN`           | +0.05     |             |
| `NEW_ASN_FOR_DEVICE`   | +0.05     |             |
| `VERIFIED`             | **-0.20** | Trust bonus |
| `RETURNING_USER`       | **-0.10** | Trust bonus |

### Historical blending

For returning devices, the new risk score is blended with the historical one:

```
finalRisk = newRisk * 0.7 + historicalRisk * 0.3
```

This prevents a single anomalous request from spiking a device's risk score from 0.2 to 0.8. The 30% historical weight acts as inertia.

Final score is clamped to [0, 1].

### What do risk scores mean?

| Score    | Interpretation                                                       |
| -------- | -------------------------------------------------------------------- |
| 0.0--0.2 | Trusted device (verified, returning, no flags)                       |
| 0.2--0.4 | Normal returning device                                              |
| 0.4--0.6 | New device or mildly suspicious returning device                     |
| 0.6--0.8 | Multiple anomaly signals firing                                      |
| 0.8--1.0 | Strong bot/spoofing signals -- headless, worker mismatches, IP churn |

---

## What is drift detection?

When a returning device sends a new fingerprint, we check whether it's different enough from the stored profile to warrant an update.

**Primary check**: If `stable_hash` changed, there's drift. Full stop.

**Secondary check** (only if stable_hash matches): Count how many of these changed:

- `canvas_hash`
- `webgl_hash`
- `audio_hash`
- `gpu_renderer`
- `screen_dims`

If **2 or more** changed, there's drift. If the fingerprint drifted _and_ the device already existed, a `FINGERPRINT_MISMATCH` flag is added (risk weight +0.15).

Drift detection also controls write amplification: if nothing meaningful changed, we skip the profile write entirely (but still refresh hash indexes and anchor buckets).

---

## How does all of this fit into the request flow?

```
1. Fingerprint arrives at matching worker

2. Device matching runs (see matching.md)
   → Returns device_id + match tier

3. Profile update queued to SQS

4. Profile updater processes the update:
   a. Acquire mutation gate (skip if device was just updated)
   b. Load existing profile
   c. Run anomaly detection:
      - Fingerprint signals (headless, proxy, VPN, consistency)
      - Cross-field anomalies (worker scope)
      - Statistical V2 (Shannon scoring against Valkey baseline)
      - IP history (ASN hopping, IP churn)
   d. Compute flags from anomalies + bot signals + drift + rate
   e. Compute risk score from flags
   f. Write profile with updated flags and risk_score
   g. Write identity indexes, hash indexes, anchor buckets
   h. Queue vector upsert (if configured)
```

The anomaly detection runs **during profile update**, not during the initial match. This keeps the latency-sensitive matching path fast while still enriching the device profile with fraud signals that are available on subsequent lookups.
