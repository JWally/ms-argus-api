# PLAN A: The Pragmatist - Anomaly Detection Implementation

## Philosophy

**Ship value early and iterate.** Prioritize quick wins, minimize risk, and deliver incrementally. Better to have something in production learning than perfect code on a branch. Every PR should be independently deployable and add measurable detection capability.

## Summary

This plan prioritizes immediate value delivery by implementing the three "Quick Wins" from the anomaly detection plan within the first week - these require only additions to the existing `detectBotSignals()` function in `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`. We then incrementally add cross-field checks leveraging already-extracted data in the normalized fingerprint, before tackling the more complex network anomaly detectors that require coordination with the sigint service.

## Prioritized Phases

### Phase 1: Quick Wins (Days 1-2) - HIGHEST VALUE/RISK RATIO

**Rationale:** These are pure additions to existing code with zero refactoring. Data already exists in the normalized fingerprint. Ship immediately.

#### 1.1 Add lie_count check to `detectBotSignals()`

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

**Change:** Add to `detectBotSignals()` function (after line 74):

```typescript
// Navigator lies detected - strong spoofing signal
if (fingerprint.lie_count && fingerprint.lie_count > 0) {
  flags.push(DeviceFlags.NAVIGATOR_LIES);
}
```

**Why first:** The `lie_count` field is already extracted by `normalizeFingerprint()` (see line 377-379 in `/home/justin/Dev/ms-argus-api/src/helpers/normalize-fingerprint.ts`). We just need to check it.

#### 1.2 Add is_headless direct check

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

**Change:** Add to `detectBotSignals()`:

```typescript
// Direct headless detection (Puppeteer, Playwright, etc.)
if (fingerprint.is_headless === true) {
  flags.push(DeviceFlags.HEADLESS_BROWSER);
  flags.push(DeviceFlags.BOT_DETECTED);
}
```

**Why:** Already extracted at line 373-376 of `normalize-fingerprint.ts` but only GPU SwiftShader triggers the flag currently.

#### 1.3 Add proxy/VPN score thresholds

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

**Change:** Add to `detectBotSignals()`:

```typescript
// High proxy score indicates likely proxy usage
if (fingerprint.proxy_score !== undefined && fingerprint.proxy_score > 0.7) {
  flags.push(DeviceFlags.LIKELY_PROXY);
}
// High VPN score (lower severity than proxy)
if (fingerprint.vpn_score !== undefined && fingerprint.vpn_score > 0.7) {
  flags.push(DeviceFlags.LIKELY_VPN);
}
```

**Why:** `proxy_score` and `vpn_score` are already in the `Fingerprint` interface (line 52-53 of `/home/justin/Dev/ms-argus-api/src/types/fingerprint.ts`) and extracted from sigint in `normalizeFingerprint()`.

#### 1.4 Add new flags to DeviceFlags

**File:** `/home/justin/Dev/ms-argus-api/src/types/flags.ts`

**Change:** Add new flags:

```typescript
export const DeviceFlags = {
  // ... existing flags ...
  // New anomaly detection flags
  NAVIGATOR_LIES: "navigator_lies",
  LIKELY_PROXY: "likely_proxy",
  LIKELY_VPN: "likely_vpn",
} as const;
```

#### 1.5 Add risk weights

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

**Change:** Add to `RISK_WEIGHTS`:

```typescript
export const RISK_WEIGHTS = {
  // ... existing ...
  NAVIGATOR_LIES: 0.15,
  LIKELY_PROXY: 0.1,
  LIKELY_VPN: 0.05,
} as const;
```

**Deliverable:** Single PR, ~50 lines of code, immediately ships detection for lies, headless, proxy/VPN.

---

### Phase 2: Cross-Field Basics (Days 3-5) - HIGH VALUE, LOW RISK

**Rationale:** Add simple consistency checks using data already in normalized fingerprint. No new data flow needed.

#### 2.1 Create anomaly types file

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/types.ts`

```typescript
export type AnomalyType =
  | "CROSS_FIELD"
  | "TEMPORAL"
  | "NETWORK"
  | "HARDWARE"
  | "IDENTITY";

export interface AnomalySignal {
  type: AnomalyType;
  code: string;
  severity: number; // 0-1
  evidence: {
    expected: string;
    actual: string;
    field1?: string;
    field2?: string;
  };
}

export interface AnomalyResult {
  signals: AnomalySignal[];
  aggregateScore: number;
  suggestedFlags: string[];
}
```

#### 2.2 Create cross-field detector (minimal MVP)

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/cross-field.ts`

**Initial checks (most valuable first):**

1. **Screen vs CSS orientation** - Already have screen dimensions, can derive orientation
2. **Lie count severity scaling** - Higher lie counts = higher severity

**Why minimal:** Start with checks that don't require raw payload access. The normalized fingerprint has `screen_dims` which can be parsed for orientation.

#### 2.3 Wire into computeFlags()

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

**Change:** Call cross-field detector and convert signals to flags:

```typescript
import { detectCrossFieldAnomalies } from './anomaly/cross-field';

export function computeFlags(...) {
  // ... existing code ...

  // Cross-field anomaly detection
  const crossFieldResult = detectCrossFieldAnomalies(fingerprint);
  flags.push(...crossFieldResult.suggestedFlags);

  // ... rest of existing code ...
}
```

**Deliverable:** PR adds anomaly module structure + first cross-field checks.

---

### Phase 3: Raw Payload Access (Days 6-10) - MEDIUM VALUE, MEDIUM RISK

**Rationale:** To implement Navigator vs Worker checks, we need access to the raw payload structure, not just the normalized fingerprint.

#### 3.1 Modify matching worker to pass raw payload

**File:** `/home/justin/Dev/ms-argus-api/src/handlers/matching-worker.ts`

**Change:** Keep both normalized and raw in the profile update payload:

```typescript
// Line 143 currently:
const fingerprint = normalizeFingerprint(payload.fingerprint, payload.sigint);

// Change to also preserve raw:
const fingerprint = normalizeFingerprint(payload.fingerprint, payload.sigint);
const rawFingerprint = payload.fingerprint; // Keep original structure
```

**Risk mitigation:** The raw payload is already being passed through - we just need to ensure it reaches the anomaly detector.

#### 3.2 Add Navigator vs Worker checks

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/cross-field.ts`

**Add checks:**

- Navigator UA vs Worker UA
- Navigator platform vs Worker platform
- Navigator hardwareConcurrency vs Worker hardwareConcurrency
- Main timezone vs Worker timezone

**Why high value:** These are the most common spoofing tells - automation tools often forget to spoof worker scope.

#### 3.3 Add new flags

**File:** `/home/justin/Dev/ms-argus-api/src/types/flags.ts`

```typescript
WORKER_MISMATCH: "worker_mismatch",
SCREEN_CSS_MISMATCH: "screen_css_mismatch",
```

**Deliverable:** PR adds worker scope validation - catches most canvas spoofing tools.

---

### Phase 4: Browser Engine Detection (Days 11-15) - HIGH VALUE, MEDIUM RISK

**Rationale:** Math engine fingerprints are nearly impossible to spoof correctly. High detection value.

#### 4.1 Create browser-engine detector

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/browser-engine.ts`

**Key check:** Math results vs claimed browser in UA

```typescript
// If UA claims Firefox but math results show Chrome patterns
const mathResults = raw.loose?.maths?.data;
// Compare against known browser math fingerprint patterns
```

**Why:** The `maths_hash` is already extracted (line 324-327 of `normalize-fingerprint.ts`). We need to access the full math data for browser attribution.

#### 4.2 Build browser pattern database

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/browser-patterns.ts`

Start with major browsers: Chrome, Firefox, Safari, Edge. Build patterns incrementally from real traffic.

**Deliverable:** PR adds math engine validation - catches sophisticated UA spoofing.

---

### Phase 5: Network Anomalies (Days 16-25) - HIGH VALUE, REQUIRES SIGINT CHANGES

**Rationale:** FTL detection is extremely high value (physics-based proof of spoofing) but requires sigint service to return lat/lon/timezone.

#### 5.1 Verify sigint geo data availability

**Dependency:** Confirm sigint service returns `geo.lat`, `geo.lon`, `geo.timezone` in `SigintData`.

**File to update:** `/home/justin/Dev/ms-argus-api/src/types/matching.ts`

Add to `SigintData` interface:

```typescript
geo?: {
  lat: number;
  lon: number;
  timezone: string;
  accuracy?: number;
} | null;
```

#### 5.2 Create network detector

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/network.ts`

**Checks in order of implementation:**

1. **Server vs Client timezone mismatch** - Simple string comparison
2. **FTL detection** - Haversine distance + RTT physics check
3. **JA4 vs UA browser family** - Pattern matching

#### 5.3 Implement FTL detection

```typescript
const RESTON = { lat: 38.9586, lon: -77.357 }; // AWS us-east-1

function haversineDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const R = 6371; // Earth radius km
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function isFasterThanLight(lat: number, lon: number, rttMs: number): boolean {
  const RESTON = { lat: 38.9586, lon: -77.357 };
  const distance = haversineDistance(lat, lon, RESTON.lat, RESTON.lon);
  const minRtt = (distance / 200) * 2; // 200 km/ms fiber speed, round trip
  return rttMs < minRtt * 0.9; // 10% tolerance
}
```

**Deliverable:** PR adds physics-based location verification.

---

## Quick Wins First (Ship This Week)

**Day 1-2 deliverables:**

1. Add `NAVIGATOR_LIES`, `LIKELY_PROXY`, `LIKELY_VPN` flags
2. Add `lie_count > 0` check to `detectBotSignals()`
3. Add `is_headless === true` check
4. Add `proxy_score > 0.7` and `vpn_score > 0.7` checks
5. Add risk weights for new flags
6. Add switch cases in `computeRiskScore()`

**Estimated impact:** Catch ~30% more automated traffic with zero new infrastructure.

---

## Risk Mitigation

### 1. Feature Flags / Conservative Thresholds

- Start with high thresholds (e.g., `proxy_score > 0.7`) and tune down
- Log anomalies before flagging to validate detection rate

### 2. Backwards Compatibility

- New flags are additive - existing code ignores unknown flags
- No breaking changes to `Fingerprint` or `DeviceProfile` interfaces

### 3. Incremental Rollout

- Each phase is an independent PR
- Can pause implementation if issues arise
- Easy to revert individual detectors

### 4. Shadow Mode Option

- First deploy anomaly detectors in "observe only" mode
- Emit CloudWatch metrics without affecting risk score
- Graduate to production after validation

### 5. Minimal Blast Radius

- Changes are isolated to `flag-computation.ts` and new `anomaly/` module
- Core matching logic (`matching-worker.ts`, `tier*.ts`) unchanged
- Profile schema unchanged

---

## Testing Strategy

### Unit Tests (Required per PR)

**File pattern:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/*.test.ts`

For each detector:

1. Test with clean fingerprint (no anomaly)
2. Test with known-bad fingerprint (anomaly detected)
3. Test edge cases (missing fields, null values)
4. Test threshold boundaries

### Integration Tests

1. Create test fingerprint payloads with known anomalies
2. Verify flags appear in session cache response
3. Verify risk score increases appropriately

### Validation Approach

1. **Week 1:** Deploy Quick Wins, monitor `AnomalyDetected` CloudWatch metric
2. **Week 2:** Review flagged sessions, calculate false positive rate
3. **Week 3:** Tune thresholds based on observed data
4. **Ongoing:** Add new patterns as spoofing techniques evolve

---

## What I Would Defer

### Lower Priority (Phase 5+)

1. **Hardware plausibility matrix** - Requires building device profile database, lower ROI
2. **Identity drift detection** - Complex temporal analysis, defer until we have baseline data
3. **JA4 browser pattern database** - Need to collect patterns from real traffic first
4. **Evercookie vs FaviconCache correlation** - Edge case, low detection value

### Explicitly Out of Scope

1. Raw payload storage for historical analysis - Address separately
2. Non-linear flag combination scoring - Adds complexity, start simple
3. Custom CloudWatch dashboards - Ops concern, not detection logic
4. Timezone normalization edge cases - Handle common cases first

---

## Open Questions

1. **Sigint geo availability:** When will sigint service return lat/lon/timezone? This blocks FTL detection.

2. **Threshold tuning process:** Who validates false positive rates? Need process for threshold adjustments.

3. **Flag documentation:** Should we document what each flag means for downstream consumers?

4. **Metric naming:** Align `AnomalyDetected`, `AnomalyByType`, etc. with existing CloudWatch namespace?

5. **Evidence codes:** Should anomaly signals be added to `evidence_codes` in match result, or kept separate?

6. **Raw payload size:** Passing raw + normalized fingerprint to profile updater - any payload size concerns?

---

### Critical Files for Implementation

- `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts` - Core file to modify
- `/home/justin/Dev/ms-argus-api/src/types/flags.ts` - Add new flag constants
- `/home/justin/Dev/ms-argus-api/src/helpers/normalize-fingerprint.ts` - Reference for extracted data
- `/home/justin/Dev/ms-argus-api/src/types/matching.ts` - Update SigintData interface
- `/home/justin/Dev/ms-argus-api/src/services/profile/profile-service.test.ts` - Test pattern reference
