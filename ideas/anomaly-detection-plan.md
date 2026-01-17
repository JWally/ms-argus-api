# Anomaly Detection Plan

## Overview

Add comprehensive inconsistency and anomaly detection to identify spoofed, manipulated, or suspicious device fingerprints. The system has rich signal data (79+ fingerprint fields, sigint, timing) but currently only uses a fraction for fraud detection.

## Current State

**Existing detection in `flag-computation.ts`:**

- SwiftShader GPU (headless)
- 800x600 viewport (bot)
- UA contains "bot/crawler/spider/headless"
- 1 CPU core + <1GB memory

**Unused data:**

- `lie_count` - extracted but never checked
- Cross-field consistency - not validated
- Sigint network data - stored but not cross-referenced
- Math engine fingerprints - not compared against claimed browser
- Worker scope data - not compared against main thread

---

## Architecture

### New Module Structure

```
src/services/profile/
├── profile-service.ts
├── flag-computation.ts
├── drift-detection.ts
└── anomaly/                      # NEW
    ├── index.ts                  # Re-exports + detectAllAnomalies()
    ├── types.ts                  # AnomalySignal, AnomalyResult
    ├── cross-field.ts            # Navigator ↔ Worker, Screen ↔ CSS
    ├── browser-engine.ts         # Math results ↔ UA, JA4 ↔ UA
    ├── network.ts                # IP ↔ Timezone, RTT validation
    ├── hardware.ts               # GPU ↔ Memory ↔ Cores plausibility
    └── identity.ts               # Evercookie ↔ FaviconCache ↔ CryptoId
```

### Data Flow

```
Ingestion Handler
       │
       ▼
   SQS Queue
       │
       ▼
Matching Worker ◄─── detectAllAnomalies(normalized, raw, sigint)
       │
       ▼
  computeFlags() ◄── anomaly signals converted to flags
       │
       ▼
Profile Updater ◄── flags + risk_score persisted
```

### Key Change

`normalizeFingerprint()` currently discards the raw payload structure. The matching worker needs access to both:

- `normalized: Fingerprint` (flat, for matching)
- `raw: WebFingerprintResult` (nested, for anomaly detection)

---

## Types

```typescript
// src/services/profile/anomaly/types.ts

export type AnomalyType =
  | "CROSS_FIELD" // Two fields contradict each other
  | "TEMPORAL" // Change pattern over time is suspicious
  | "NETWORK" // Network signals don't match claims
  | "HARDWARE" // Hardware config is implausible
  | "IDENTITY"; // Persistent ID behavior is suspicious

export interface AnomalySignal {
  type: AnomalyType;
  code: string; // e.g., "SCREEN_ORIENTATION_MISMATCH"
  severity: number; // 0-1, higher = more suspicious
  evidence: {
    expected: string;
    actual: string;
    field1?: string;
    field2?: string;
  };
}

export interface AnomalyResult {
  signals: AnomalySignal[];
  aggregateScore: number; // Combined anomaly score 0-1
  suggestedFlags: string[];
}
```

---

## New Flags

```typescript
// src/types/flags.ts - additions

export const DeviceFlags = {
  // ... existing flags ...

  // Inconsistency flags
  NAVIGATOR_LIES: "navigator_lies",
  WORKER_MISMATCH: "worker_mismatch",
  SCREEN_CSS_MISMATCH: "screen_css_mismatch",
  MATH_ENGINE_MISMATCH: "math_engine_mismatch",

  // Network anomalies
  FTL_VIOLATION: "ftl_violation", // RTT faster than speed of light allows
  IP_TIMEZONE_MISMATCH: "ip_timezone_mismatch",
  SERVER_CLIENT_TZ_MISMATCH: "server_client_tz_mismatch",
  RTT_ANOMALY: "rtt_anomaly",
  JA4_UA_MISMATCH: "ja4_ua_mismatch",

  // Identity anomalies
  IDENTITY_DRIFT: "identity_drift",
  PARTIAL_STORAGE_CLEAR: "partial_storage_clear",

  // Hardware anomalies
  IMPLAUSIBLE_HARDWARE: "implausible_hardware",
} as const;
```

---

## Detectors

### 1. Cross-Field Detector (`cross-field.ts`)

| Check                           | Fields                                                              | Severity | Notes                        |
| ------------------------------- | ------------------------------------------------------------------- | -------- | ---------------------------- |
| Screen vs CSS orientation       | `screen.width/height` ↔ `cssMedia.orientation`                      | 0.6      | Found in trash.sick          |
| Screen vs CSS dimensions        | `screen` ↔ `cssMedia.screenQuery`                                   | 0.5      | Should match exactly         |
| Navigator vs Worker UA          | `navigator.userAgent` ↔ `workerScope.userAgent`                     | 0.8      | Spoofers often miss workers  |
| Navigator vs Worker platform    | `navigator.platform` ↔ `workerScope.platform`                       | 0.8      | Same                         |
| Navigator vs Worker concurrency | `navigator.hardwareConcurrency` ↔ `workerScope.hardwareConcurrency` | 0.7      | Same                         |
| Navigator vs Worker language    | `navigator.language` ↔ `workerScope.language`                       | 0.6      | Same                         |
| Navigator vs Worker timezone    | `timezone.location` ↔ `workerScope.timezoneLocation`                | 0.7      | Same                         |
| Main vs Worker GPU              | `canvasWebgl.gpu` ↔ `workerScope.gpu`                               | 0.7      | If OffscreenCanvas supported |
| Lie count threshold             | `lies.totalLies > 0`                                                | 0.5-0.9  | Currently unused             |

### 2. Browser Engine Detector (`browser-engine.ts`)

| Check                    | Fields                                                 | Severity | Notes                      |
| ------------------------ | ------------------------------------------------------ | -------- | -------------------------- |
| Math results vs UA       | `maths.data[*].firefox/chrome` ↔ `navigator.userAgent` | 0.9      | Very hard to spoof         |
| Resistance engine vs UA  | `resistance.engine` ↔ `navigator.userAgent`            | 0.8      | Engine should match        |
| WebRTC codecs vs browser | `webrtc.codecsSdp` patterns ↔ UA                       | 0.6      | Browser-specific patterns  |
| Plugin list vs browser   | `navigator.plugins` ↔ UA                               | 0.5      | Chrome vs Firefox patterns |

**Math Engine Check Logic:**

```typescript
// If UA claims Firefox but math results match Chrome patterns
const mathResults = raw.loose?.maths?.data;
const firefoxCount = Object.values(mathResults).filter((v) => v.firefox).length;
const chromeCount = Object.values(mathResults).filter((v) => v.chrome).length;

if (ua.includes("Firefox") && chromeCount > firefoxCount * 2) {
  // Likely spoofed UA
}
```

### 3. Network Detector (`network.ts`)

| Check                 | Fields                                               | Severity | Notes                              |
| --------------------- | ---------------------------------------------------- | -------- | ---------------------------------- |
| **FTL Detection**     | `sigint.geo.lat/lon` + `tcpProbe.rtt`                | **0.95** | Physics violation = definite spoof |
| IP geo vs timezone    | `sigint.geo.timezone` ↔ `fingerprint.timezone`       | 0.6      | VPN/proxy indicator                |
| IP geo vs browser TZ  | `sigint.geo.timezone` ↔ `loose.timezone.location`    | 0.7      | Server vs client timezone          |
| JA4 vs UA browser     | `sigint.tlsFingerprint.ja4` ↔ UA browser family      | 0.7      | TLS fingerprint should match       |
| Proxy score threshold | `sigint.tcpProbe.proxyScore > 0.7`                   | 0.6      | Direct flag                        |
| VPN score threshold   | `sigint.tcpProbe.vpnScore > 0.7`                     | 0.5      | Direct flag                        |
| WebRTC IP vs TCP IP   | `sigint.stun.publicIp` ↔ `sigint.tcpProbe.client_ip` | 0.8      | Should match unless VPN            |
| STUN blocked          | `sigint.stun === null` + no timeout                  | 0.4      | Privacy tool indicator             |

#### FTL (Faster-Than-Light) Detection

**Concept:** If the TCP RTT is faster than light could physically travel from the claimed IP location to our server (Reston, VA), the location is definitely spoofed.

**Server Location:** Reston, VA (AWS us-east-1)

- Latitude: 38.9586
- Longitude: -77.3570

**Physics:**

- Speed of light: ~299,792 km/s
- Fiber optic speed: ~200,000 km/s (⅔ speed of light due to refractive index)
- Real-world routing adds ~1.5-2x path length vs great circle

**Formula:**

```typescript
// Great circle distance (Haversine)
function haversineDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const R = 6371; // Earth radius in km
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Minimum possible RTT (one-way * 2, at 2/3 speed of light)
function minPossibleRttMs(distanceKm: number): number {
  const fiberSpeedKmPerMs = 200; // 200,000 km/s = 200 km/ms
  const oneWayMs = distanceKm / fiberSpeedKmPerMs;
  return oneWayMs * 2; // Round trip
}

// FTL check
function isFasterThanLight(lat: number, lon: number, rttMs: number): boolean {
  const RESTON = { lat: 38.9586, lon: -77.357 };
  const distance = haversineDistance(lat, lon, RESTON.lat, RESTON.lon);
  const minRtt = minPossibleRttMs(distance);

  // Add 10% tolerance for measurement jitter
  return rttMs < minRtt * 0.9;
}
```

**Example Calculations:**

| Location | Distance to Reston | Min RTT (fiber) | If RTT < this, FTL |
| -------- | ------------------ | --------------- | ------------------ |
| NYC      | 350 km             | 3.5 ms          | < 3.2 ms           |
| LA       | 3,700 km           | 37 ms           | < 33 ms            |
| London   | 5,900 km           | 59 ms           | < 53 ms            |
| Sydney   | 15,900 km          | 159 ms          | < 143 ms           |
| Tokyo    | 10,900 km          | 109 ms          | < 98 ms            |

**Sigint Geo Data (New):**

```typescript
interface SigintData {
  // ... existing ...
  geo?: {
    lat: number; // Latitude from IP geolocation
    lon: number; // Longitude from IP geolocation
    timezone: string; // Server-side timezone lookup from IP
    accuracy?: number; // Geo accuracy in km (if available)
  };
}
```

#### Server vs Client Timezone Mismatch

**Concept:** The server determines timezone from IP geolocation (`sigint.geo.timezone`), while the client reports its configured timezone (`fingerprint.timezone` / `loose.timezone.location`). If these don't match, the user is either:

1. Using a VPN/proxy (IP says one place, device configured for another)
2. Spoofing their timezone
3. Traveling (legitimate but rare)

**Timezone Data Sources:**

| Source            | Field                                | Origin                                             |
| ----------------- | ------------------------------------ | -------------------------------------------------- |
| Server (IP-based) | `sigint.geo.timezone`                | MaxMind/IP2Location from TCP probe                 |
| Client (JS)       | `loose.timezone.location`            | `Intl.DateTimeFormat().resolvedOptions().timeZone` |
| Client (JS)       | `loose.timezone.zone`                | Formatted zone name                                |
| Client (Worker)   | `loose.workerScope.timezoneLocation` | Worker thread timezone                             |

**Matching Logic:**

```typescript
function checkTimezoneMismatch(
  serverTz: string, // e.g., "America/New_York" from sigint.geo
  clientTz: string, // e.g., "America/Chicago" from payload
): AnomalySignal | null {
  // Normalize timezone names (handle aliases)
  const normalizedServer = normalizeTimezone(serverTz);
  const normalizedClient = normalizeTimezone(clientTz);

  if (normalizedServer === normalizedClient) {
    return null; // Match
  }

  // Check if same UTC offset (might be acceptable)
  const serverOffset = getUtcOffset(serverTz);
  const clientOffset = getUtcOffset(clientTz);

  if (serverOffset === clientOffset) {
    // Same offset, different zone name - low severity
    return {
      type: "NETWORK",
      code: "TIMEZONE_ZONE_MISMATCH",
      severity: 0.3,
      evidence: {
        expected: serverTz,
        actual: clientTz,
        field1: "sigint.geo.timezone",
        field2: "fingerprint.timezone",
      },
    };
  }

  // Different offset - higher severity
  const hoursDiff = Math.abs(serverOffset - clientOffset) / 60;
  const severity = Math.min(0.8, 0.4 + hoursDiff * 0.1); // More hours = higher severity

  return {
    type: "NETWORK",
    code: "TIMEZONE_OFFSET_MISMATCH",
    severity,
    evidence: {
      expected: `${serverTz} (UTC${formatOffset(serverOffset)})`,
      actual: `${clientTz} (UTC${formatOffset(clientOffset)})`,
      field1: "sigint.geo.timezone",
      field2: "fingerprint.timezone",
    },
  };
}
```

**Example Cases:**

| Server TZ (IP)   | Client TZ (JS)      | Verdict       | Severity |
| ---------------- | ------------------- | ------------- | -------- |
| America/New_York | America/New_York    | Match         | 0        |
| America/New_York | America/Detroit     | Same offset   | 0.3      |
| America/New_York | America/Chicago     | 1 hour diff   | 0.5      |
| America/New_York | America/Los_Angeles | 3 hours diff  | 0.7      |
| America/New_York | Europe/London       | 5 hours diff  | 0.8      |
| America/New_York | Asia/Tokyo          | 14 hours diff | 0.8      |

**Triple Check (Server + Client Main + Client Worker):**

```typescript
// All three should match
const serverTz = sigint.geo?.timezone;
const clientMainTz = raw.loose?.timezone?.location;
const clientWorkerTz = raw.loose?.workerScope?.timezoneLocation;

// If client main !== client worker, that's a CROSS_FIELD issue
// If server !== client, that's a NETWORK issue
```

**JA4 Browser Patterns (to build):**

```typescript
const JA4_BROWSER_PATTERNS = {
  chrome: /^t13d\d+h2_/, // Chrome typically uses HTTP/2
  firefox: /^t13d1[67]\d+h2_/, // Firefox patterns
  safari: /^t13d\d+h2_.*_/, // Safari patterns
};
```

### 4. Hardware Detector (`hardware.ts`)

| Check              | Fields                                 | Severity | Notes                                |
| ------------------ | -------------------------------------- | -------- | ------------------------------------ |
| GPU vs device type | `gpu_renderer` ↔ expected for platform | 0.5      | Intel HD on "iPhone" is wrong        |
| Cores vs GPU class | `hardwareConcurrency` ↔ GPU tier       | 0.4      | 12 cores + Intel HD 400 is unusual   |
| Memory vs cores    | `deviceMemory` ↔ `hardwareConcurrency` | 0.3      | Very low memory + many cores is rare |
| Screen vs device   | `screen_dims` ↔ `navigator.platform`   | 0.4      | Mobile resolution on desktop         |
| Touch vs device    | `navigator.maxTouchPoints` ↔ platform  | 0.5      | Touch on Linux desktop is rare       |

**Plausibility Matrix (to build):**

```typescript
const GPU_PLATFORM_MATRIX = {
  "Intel HD Graphics": ["Windows", "Linux", "Mac"],
  "Apple M1": ["Mac"],
  "Mali-G": ["Android"],
  Adreno: ["Android"],
  SwiftShader: [], // Always suspicious
};
```

### 5. Identity Detector (`identity.ts`)

| Check                             | Fields                                   | Severity | Notes                                 |
| --------------------------------- | ---------------------------------------- | -------- | ------------------------------------- |
| Evercookie vs FaviconCache prefix | `evercookie.id` ↔ `faviconCache.id`      | 0.3      | Should share prefix                   |
| All IDs new together              | All persistent IDs are new               | 0.2      | Normal for new device                 |
| Mixed ID state                    | Some IDs exist, others new               | 0.7      | Partial clear is suspicious           |
| CryptoId rotation                 | `cryptoId` changed but evercookie didn't | 0.8      | Key regeneration without cookie clear |
| Creation time consistency         | `evercookie.created` ↔ `cryptoId.date`   | 0.5      | Should be close                       |

---

## Risk Weight Additions

```typescript
// src/services/profile/flag-computation.ts

export const RISK_WEIGHTS = {
  // ... existing ...

  // Inconsistency weights
  NAVIGATOR_LIES: 0.15,
  WORKER_MISMATCH: 0.2,
  SCREEN_CSS_MISMATCH: 0.1,
  MATH_ENGINE_MISMATCH: 0.25, // High - very hard to fake

  // Network weights
  FTL_VIOLATION: 0.35, // Physics impossible = definite fraud
  IP_TIMEZONE_MISMATCH: 0.1,
  SERVER_CLIENT_TZ_MISMATCH: 0.12,
  RTT_ANOMALY: 0.05,
  JA4_UA_MISMATCH: 0.15,

  // Identity weights
  IDENTITY_DRIFT: 0.1,
  PARTIAL_STORAGE_CLEAR: 0.15,

  // Hardware weights
  IMPLAUSIBLE_HARDWARE: 0.1,
} as const;
```

---

## Implementation Phases

### Phase 1: Foundation (Low Risk)

1. Create `src/services/profile/anomaly/` directory structure
2. Add types (`AnomalySignal`, `AnomalyResult`)
3. Implement `lie_count` check (data exists, just add threshold)
4. Add new flags to `flags.ts`
5. Wire `detectAllAnomalies()` into `computeFlags()`

**Ticket size:** Small-Medium

### Phase 2: Cross-Field Checks (Medium Value)

1. Screen ↔ CSS orientation mismatch
2. Screen ↔ CSS dimensions mismatch
3. Navigator ↔ Worker sync (UA, platform, concurrency)
4. Requires passing raw payload to matching worker

**Ticket size:** Medium

### Phase 3: Browser Engine (High Value)

1. Math engine results ↔ claimed browser
2. Resistance.engine ↔ UA
3. Build browser-specific pattern matchers

**Ticket size:** Medium

### Phase 4: Network Anomalies (High Value)

1. **FTL Detection** - Great circle distance + RTT physics check (HIGH PRIORITY)
2. **Server vs Client timezone** - Compare sigint.geo.timezone with payload timezone
3. JA4 ↔ browser family patterns
4. Proxy/VPN score thresholds
5. WebRTC IP ↔ TCP IP comparison

**Ticket size:** Medium (sigint already provides lat/lon/timezone)

### Phase 5: Hardware Plausibility (Lower Priority)

1. GPU ↔ platform plausibility matrix
2. Cores ↔ memory ↔ GPU tier checks
3. Build device profile database

**Ticket size:** Large (needs research/data)

### Phase 6: Identity Tracking (Lower Priority)

1. Evercookie ↔ FaviconCache correlation
2. Mixed ID state detection
3. Creation timestamp consistency

**Ticket size:** Medium

---

## Testing Strategy

### Unit Tests

Each detector should have unit tests with:

- Known-good fingerprints (no anomalies)
- Known-spoofed fingerprints (anomalies detected)
- Edge cases (missing fields, null values)

### Integration Tests

- End-to-end with sample payloads like `trash.sick`
- Verify flags are correctly set in profile
- Verify risk score changes appropriately

### Validation Data

- Collect labeled dataset of known-good vs spoofed fingerprints
- Use `trash.sick` as baseline for real device
- Generate synthetic spoofed payloads for testing

---

## Observability

### New CloudWatch Metrics

```
AnomalyDetected           - Any anomaly signal fired
AnomalyByType             - Dimension: CROSS_FIELD, NETWORK, etc.
AnomalyByCode             - Dimension: SCREEN_ORIENTATION_MISMATCH, etc.
AnomalySeverityHigh       - Severity >= 0.7
FlagAdded:{flag_name}     - Each new flag type
```

### Evidence in Match Result

Extend `evidence_codes` to include anomaly findings:

```typescript
evidence_codes: [
  "STABLE_HASH_MATCH",
  "ANOMALY:SCREEN_CSS_MISMATCH", // New prefix
  "ANOMALY:MATH_ENGINE_MISMATCH",
];
```

---

## Open Questions

1. **Raw payload storage:** Should we store raw payload for historical anomaly analysis, or just compute at match time?

2. **Severity thresholds:** What severity threshold should trigger each flag? Start conservative and tune?

3. **Flag combinations:** Should certain flag combinations compound risk non-linearly? (e.g., MATH_ENGINE_MISMATCH + WORKER_MISMATCH = very suspicious)

4. **JA4 database:** Where to source JA4 ↔ browser mappings? Build internally or use external database?

5. ~~**Geo lookup:** Need IP → location service for RTT validation. Use existing or add new?~~ **RESOLVED:** Sigint will now return lat, lon, and timezone from server-side IP geolocation.

6. **Timezone normalization:** How to handle timezone aliases? (e.g., "America/New_York" vs "US/Eastern" vs "EST")

7. **FTL tolerance:** What buffer to use for FTL detection? 10% seems reasonable but may need tuning for edge cases (satellite, mobile handoffs).

---

## Quick Wins (Can Implement Now)

These require minimal changes:

1. **lie_count threshold** - Add to `detectBotSignals()`:

   ```typescript
   if (fingerprint.lie_count && fingerprint.lie_count > 0) {
     flags.push(DeviceFlags.NAVIGATOR_LIES);
   }
   ```

2. **Proxy/VPN score threshold** - Add to `detectBotSignals()`:

   ```typescript
   if (fingerprint.proxy_score && fingerprint.proxy_score > 0.7) {
     flags.push(DeviceFlags.LIKELY_PROXY);
   }
   ```

3. **is_headless flag** - Already extracted but only checked via GPU:
   ```typescript
   if (fingerprint.is_headless === true) {
     flags.push(DeviceFlags.HEADLESS_BROWSER);
   }
   ```

## High-Value Wins (Once Sigint Geo Is Available)

These become easy once sigint returns lat/lon/timezone:

4. **FTL Detection** - Physics-based location verification:

   ```typescript
   const RESTON = { lat: 38.9586, lon: -77.357 };
   const distance = haversineDistance(
     sigint.geo.lat,
     sigint.geo.lon,
     RESTON.lat,
     RESTON.lon,
   );
   const minRttMs = (distance / 200) * 2; // 200 km/ms fiber speed, round trip

   if (sigint.tcpProbe.rttMs < minRttMs * 0.9) {
     flags.push(DeviceFlags.FTL_VIOLATION);
     // This is a DEFINITE spoof - RTT is faster than physically possible
   }
   ```

5. **Server vs Client Timezone** - Compare IP-based timezone with JS-reported:

   ```typescript
   if (sigint.geo?.timezone && fingerprint.timezone) {
     if (sigint.geo.timezone !== fingerprint.timezone) {
       // Check if offsets match (might be same zone, different name)
       const serverOffset = getUtcOffset(sigint.geo.timezone);
       const clientOffset = getUtcOffset(fingerprint.timezone);
       if (Math.abs(serverOffset - clientOffset) >= 60) {
         // 1+ hour diff
         flags.push(DeviceFlags.SERVER_CLIENT_TZ_MISMATCH);
       }
     }
   }
   ```

6. **Triple Timezone Check** - Server + Client Main + Client Worker:

   ```typescript
   const serverTz = sigint.geo?.timezone;
   const clientMainTz = raw.loose?.timezone?.location;
   const clientWorkerTz = raw.loose?.workerScope?.timezoneLocation;

   // If all three are present and don't all match, something is wrong
   if (serverTz && clientMainTz && clientWorkerTz) {
     const allMatch =
       serverTz === clientMainTz && clientMainTz === clientWorkerTz;
     if (!allMatch) {
       // Determine which mismatch type
       if (clientMainTz !== clientWorkerTz) {
         flags.push(DeviceFlags.WORKER_MISMATCH);
       }
       if (serverTz !== clientMainTz) {
         flags.push(DeviceFlags.SERVER_CLIENT_TZ_MISMATCH);
       }
     }
   }
   ```

---

## References

- `trash.sick` - Sample real device fingerprint payload
- `src/helpers/normalize-fingerprint.ts` - Raw payload structure
- `src/types/fingerprint.ts` - Normalized fingerprint interface
- `src/services/profile/flag-computation.ts` - Current detection logic
