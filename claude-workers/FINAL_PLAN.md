# FINAL PLAN: Anomaly Detection Implementation

## Synthesized from Debate Between Pragmatist and Architect Approaches

This plan combines the Pragmatist's velocity with the Architect's type safety, resolving disagreements through the debate process documented in `DEBATE_TRANSCRIPT.md`.

---

## Guiding Principles

1. **Ship value in 2 days** - Quick Wins must deploy by Day 2
2. **Minimal structure upfront** - Just enough types to prevent chaos
3. **Type safety where it matters** - Const assertions yes, brand types no
4. **Defer abstractions** - Extract registry/base class after 3+ detectors exist
5. **Isolated blast radius** - Anomaly detection cannot crash matching

---

## Phase 0: Minimal Foundation (Day 1)

**Goal:** Establish just enough structure to prevent spaghetti code growth.

### 0.1 Refactor Switch Statement (PREREQUISITE)

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

Replace the `computeRiskScore()` switch statement with lookup table:

```typescript
export function computeRiskScore(
  flags: string[],
  existingProfile: DeviceProfile | null,
  isNewDevice: boolean,
): number {
  let riskScore = isNewDevice ? 0.5 : (existingProfile?.risk_score ?? 0.3);

  for (const flag of flags) {
    const weight = RISK_WEIGHTS[flag as keyof typeof RISK_WEIGHTS];
    if (weight !== undefined) {
      riskScore += weight;
    }
  }

  return Math.min(riskScore, 1.0);
}
```

**Why first:** Both plans agree this is necessary. Doing it first prevents switch explosion as we add flags.

### 0.2 Create Anomaly Types

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/types.ts`

```typescript
/**
 * Anomaly detection types - minimal structure for Phase 1
 */

export type AnomalyType = "CROSS_FIELD" | "NETWORK" | "HARDWARE" | "IDENTITY";

export const AnomalyCodes = {
  // Cross-field
  NAVIGATOR_LIES: "NAVIGATOR_LIES",
  WORKER_MISMATCH: "WORKER_MISMATCH",
  SCREEN_CSS_MISMATCH: "SCREEN_CSS_MISMATCH",
  // Network
  FTL_VIOLATION: "FTL_VIOLATION",
  IP_TIMEZONE_MISMATCH: "IP_TIMEZONE_MISMATCH",
  SERVER_CLIENT_TZ_MISMATCH: "SERVER_CLIENT_TZ_MISMATCH",
  JA4_UA_MISMATCH: "JA4_UA_MISMATCH",
  // Quick wins
  HEADLESS_DETECTED: "HEADLESS_DETECTED",
  HIGH_PROXY_SCORE: "HIGH_PROXY_SCORE",
  HIGH_VPN_SCORE: "HIGH_VPN_SCORE",
  // Browser engine
  MATH_ENGINE_MISMATCH: "MATH_ENGINE_MISMATCH",
} as const;

export type AnomalyCode = (typeof AnomalyCodes)[keyof typeof AnomalyCodes];

export interface AnomalySignal {
  type: AnomalyType;
  code: AnomalyCode;
  severity: number; // 0-1, runtime clamped
  evidence: {
    expected: string;
    actual: string;
    fields?: string[];
  };
}

export interface AnomalyResult {
  signals: AnomalySignal[];
  aggregateScore: number;
  suggestedFlags: string[];
}

// Helper to create signals with clamped severity
export function createSignal(
  type: AnomalyType,
  code: AnomalyCode,
  severity: number,
  expected: string,
  actual: string,
  fields?: string[],
): AnomalySignal {
  return {
    type,
    code,
    severity: Math.max(0, Math.min(1, severity)),
    evidence: { expected, actual, fields },
  };
}
```

### 0.3 Create Index Export

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/index.ts`

```typescript
export * from "./types";
export { detectAllAnomalies } from "./detector";
```

### 0.4 Create Simple Detector Orchestrator

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detector.ts`

```typescript
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyResult } from "./types";
import { detectQuickWinAnomalies } from "./quick-wins";

// Detector functions - add more as implemented
type DetectorFn = (fingerprint: Fingerprint) => AnomalySignal[];

const detectors: DetectorFn[] = [
  detectQuickWinAnomalies,
  // Add more detector functions here as phases complete
];

export function detectAllAnomalies(fingerprint: Fingerprint): AnomalyResult {
  const signals: AnomalySignal[] = [];

  for (const detector of detectors) {
    try {
      signals.push(...detector(fingerprint));
    } catch (error) {
      // Log but don't fail - detector errors shouldn't block matching
      console.error("Detector failed:", error);
    }
  }

  return {
    signals,
    aggregateScore: computeAggregateScore(signals),
    suggestedFlags: signals.map((s) => codeToFlag(s.code)),
  };
}

function computeAggregateScore(signals: AnomalySignal[]): number {
  if (signals.length === 0) return 0;
  const total = signals.reduce((sum, s) => sum + s.severity, 0);
  return Math.min(total, 1.0);
}

function codeToFlag(code: string): string {
  return code.toLowerCase();
}
```

### 0.5 Add New Flags

**File:** `/home/justin/Dev/ms-argus-api/src/types/flags.ts`

Add to `DeviceFlags`:

```typescript
export const DeviceFlags = {
  // ... existing flags ...

  // Anomaly detection flags
  NAVIGATOR_LIES: "navigator_lies",
  LIKELY_PROXY: "likely_proxy",
  LIKELY_VPN: "likely_vpn",
  WORKER_MISMATCH: "worker_mismatch",
  SCREEN_CSS_MISMATCH: "screen_css_mismatch",
  FTL_VIOLATION: "ftl_violation",
  IP_TIMEZONE_MISMATCH: "ip_timezone_mismatch",
  SERVER_CLIENT_TZ_MISMATCH: "server_client_tz_mismatch",
  MATH_ENGINE_MISMATCH: "math_engine_mismatch",
} as const;
```

### 0.6 Add Risk Weights

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

Add to `RISK_WEIGHTS`:

```typescript
export const RISK_WEIGHTS = {
  // ... existing weights ...

  // Anomaly detection weights
  NAVIGATOR_LIES: 0.15,
  LIKELY_PROXY: 0.1,
  LIKELY_VPN: 0.05,
  WORKER_MISMATCH: 0.2,
  SCREEN_CSS_MISMATCH: 0.1,
  FTL_VIOLATION: 0.35,
  IP_TIMEZONE_MISMATCH: 0.1,
  SERVER_CLIENT_TZ_MISMATCH: 0.12,
  MATH_ENGINE_MISMATCH: 0.25,
} as const;
```

---

## Phase 1: Quick Wins (Day 2)

**Goal:** Ship lie_count, is_headless, proxy_score, vpn_score detection.

### 1.1 Create Quick Wins Detector

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/quick-wins.ts`

```typescript
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/**
 * Quick win anomaly detections using data already in normalized fingerprint
 */
export function detectQuickWinAnomalies(
  fingerprint: Fingerprint,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  // Lie count detection
  if (fingerprint.lie_count && fingerprint.lie_count > 0) {
    const severity = Math.min(0.9, 0.5 + fingerprint.lie_count * 0.1);
    signals.push(
      createSignal(
        "CROSS_FIELD",
        AnomalyCodes.NAVIGATOR_LIES,
        severity,
        "0 lies",
        `${fingerprint.lie_count} lies detected`,
        ["lie_count"],
      ),
    );
  }

  // Direct headless detection
  if (fingerprint.is_headless === true) {
    signals.push(
      createSignal(
        "CROSS_FIELD",
        AnomalyCodes.HEADLESS_DETECTED,
        0.9,
        "is_headless: false",
        "is_headless: true",
        ["is_headless"],
      ),
    );
  }

  // Proxy score threshold
  if (fingerprint.proxy_score !== undefined && fingerprint.proxy_score > 0.7) {
    signals.push(
      createSignal(
        "NETWORK",
        AnomalyCodes.HIGH_PROXY_SCORE,
        fingerprint.proxy_score,
        "proxy_score <= 0.7",
        `proxy_score: ${fingerprint.proxy_score.toFixed(2)}`,
        ["proxy_score"],
      ),
    );
  }

  // VPN score threshold
  if (fingerprint.vpn_score !== undefined && fingerprint.vpn_score > 0.7) {
    signals.push(
      createSignal(
        "NETWORK",
        AnomalyCodes.HIGH_VPN_SCORE,
        fingerprint.vpn_score * 0.8, // Lower severity than proxy
        "vpn_score <= 0.7",
        `vpn_score: ${fingerprint.vpn_score.toFixed(2)}`,
        ["vpn_score"],
      ),
    );
  }

  return signals;
}
```

### 1.2 Wire Into Flag Computation

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

Add anomaly detection call:

```typescript
import { detectAllAnomalies } from "./anomaly";

export function computeFlags(
  fingerprint: Fingerprint,
  existingProfile: DeviceProfile | null,
  isNewDevice: boolean,
  hasDrift: boolean,
): string[] {
  const flags: string[] = [];

  // Existing bot signal detection
  flags.push(...detectBotSignals(fingerprint));

  // New: Anomaly detection
  const anomalyResult = detectAllAnomalies(fingerprint);
  flags.push(...anomalyResult.suggestedFlags);

  // ... rest of existing logic ...

  return [...new Set(flags)]; // Deduplicate
}
```

### 1.3 Add Unit Tests

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/quick-wins.test.ts`

```typescript
import { describe, it, expect } from "vitest";
import { detectQuickWinAnomalies } from "./quick-wins";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectQuickWinAnomalies", () => {
  describe("lie_count detection", () => {
    it("should detect when lie_count > 0", () => {
      const fingerprint = { lie_count: 3 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.NAVIGATOR_LIES);
      expect(signals[0].severity).toBeCloseTo(0.8);
    });

    it("should not flag when lie_count is 0", () => {
      const fingerprint = { lie_count: 0 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(0);
    });

    it("should handle undefined lie_count", () => {
      const fingerprint = {} as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(0);
    });
  });

  describe("is_headless detection", () => {
    it("should detect when is_headless is true", () => {
      const fingerprint = { is_headless: true } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(true);
    });

    it("should not flag when is_headless is false", () => {
      const fingerprint = { is_headless: false } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(false);
    });
  });

  describe("proxy_score detection", () => {
    it("should detect when proxy_score > 0.7", () => {
      const fingerprint = { proxy_score: 0.85 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(true);
    });

    it("should not flag when proxy_score <= 0.7", () => {
      const fingerprint = { proxy_score: 0.7 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });
  });

  describe("vpn_score detection", () => {
    it("should detect when vpn_score > 0.7", () => {
      const fingerprint = { vpn_score: 0.9 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.HIGH_VPN_SCORE)).toBe(
        true,
      );
    });
  });
});
```

---

## Phase 2: Cross-Field Detection (Days 3-5)

**Goal:** Detect Navigator vs Worker mismatches.

### 2.1 Pass Raw Payload to Anomaly Detection

**File:** `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts`

Update `computeFlags()` signature to accept optional raw payload:

```typescript
export function computeFlags(
  fingerprint: Fingerprint,
  existingProfile: DeviceProfile | null,
  isNewDevice: boolean,
  hasDrift: boolean,
  rawPayload?: unknown, // Optional raw payload for cross-field checks
): string[] {
  // ...
  const anomalyResult = detectAllAnomalies(fingerprint, rawPayload);
  // ...
}
```

### 2.2 Create Cross-Field Detector

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/cross-field.ts`

```typescript
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

interface RawPayload {
  loose?: {
    navigator?: {
      userAgent?: string;
      platform?: string;
      hardwareConcurrency?: number;
    };
    workerScope?: {
      userAgent?: string;
      platform?: string;
      hardwareConcurrency?: number;
    };
    timezone?: { location?: string };
  };
}

export function detectCrossFieldAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  const payload = raw as RawPayload | undefined;

  if (!payload?.loose) return signals;

  const nav = payload.loose.navigator;
  const worker = payload.loose.workerScope;

  if (nav && worker) {
    // UA mismatch
    if (
      nav.userAgent &&
      worker.userAgent &&
      nav.userAgent !== worker.userAgent
    ) {
      signals.push(
        createSignal(
          "CROSS_FIELD",
          AnomalyCodes.WORKER_MISMATCH,
          0.8,
          nav.userAgent.substring(0, 50),
          worker.userAgent.substring(0, 50),
          ["navigator.userAgent", "workerScope.userAgent"],
        ),
      );
    }

    // Platform mismatch
    if (nav.platform && worker.platform && nav.platform !== worker.platform) {
      signals.push(
        createSignal(
          "CROSS_FIELD",
          AnomalyCodes.WORKER_MISMATCH,
          0.8,
          nav.platform,
          worker.platform,
          ["navigator.platform", "workerScope.platform"],
        ),
      );
    }

    // Hardware concurrency mismatch
    if (
      nav.hardwareConcurrency &&
      worker.hardwareConcurrency &&
      nav.hardwareConcurrency !== worker.hardwareConcurrency
    ) {
      signals.push(
        createSignal(
          "CROSS_FIELD",
          AnomalyCodes.WORKER_MISMATCH,
          0.7,
          String(nav.hardwareConcurrency),
          String(worker.hardwareConcurrency),
          ["navigator.hardwareConcurrency", "workerScope.hardwareConcurrency"],
        ),
      );
    }
  }

  return signals;
}
```

### 2.3 Register Cross-Field Detector

Update `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detector.ts`:

```typescript
import { detectCrossFieldAnomalies } from "./cross-field";

// Update detector signature to include optional raw
type DetectorFn = (fingerprint: Fingerprint, raw?: unknown) => AnomalySignal[];

const detectors: DetectorFn[] = [
  detectQuickWinAnomalies,
  detectCrossFieldAnomalies,
];

export function detectAllAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalyResult {
  // ... pass raw to each detector
}
```

---

## Phase 3: Browser Engine Detection (Days 6-10)

**Goal:** Detect UA spoofing via math engine fingerprints.

### 3.1 Create Browser Engine Detector

**New file:** `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/browser-engine.ts`

Checks math results pattern against claimed UA browser. See original `anomaly-detection-plan.md` for math engine detection logic.

---

## Phase 4: Network Anomalies (Days 11-15)

**Blocked on:** Sigint team providing `geo.lat`, `geo.lon`, `geo.timezone`

### 4.1 Update SigintData Type

**File:** `/home/justin/Dev/ms-argus-api/src/types/matching.ts`

```typescript
export interface SigintData {
  // ... existing fields ...
  geo?: {
    lat: number;
    lon: number;
    timezone: string;
    accuracy?: number;
  };
}
```

### 4.2 Create Network Detector

Implements:

- FTL detection (physics-based RTT validation)
- Server vs Client timezone comparison
- JA4 vs UA browser family matching

See original `anomaly-detection-plan.md` for Haversine formula and FTL detection logic.

---

## Phase 5: Hardware Plausibility (Days 16+)

**Lower priority.** Implement after Phases 1-4 are validated in production.

---

## Deployment Strategy

### Shadow Mode First

1. Deploy with anomaly detection enabled but **not affecting risk score**
2. Emit CloudWatch metrics: `AnomalyDetected`, `AnomalyByCode`
3. Review flagged sessions for 1 week
4. Calculate false positive rate
5. Graduate to production (affecting risk score) after validation

### Threshold Tuning

All thresholds are constants that can be adjusted:

- `proxy_score > 0.7` - Start high, tune down
- `vpn_score > 0.7` - Start high, tune down
- FTL tolerance `0.9` - 10% buffer for measurement jitter

---

## Files Summary

### New Files to Create

| File                                              | Phase | Purpose                |
| ------------------------------------------------- | ----- | ---------------------- |
| `src/services/profile/anomaly/types.ts`           | 0     | Core types             |
| `src/services/profile/anomaly/index.ts`           | 0     | Exports                |
| `src/services/profile/anomaly/detector.ts`        | 0     | Orchestrator           |
| `src/services/profile/anomaly/quick-wins.ts`      | 1     | Quick win detectors    |
| `src/services/profile/anomaly/quick-wins.test.ts` | 1     | Tests                  |
| `src/services/profile/anomaly/cross-field.ts`     | 2     | Cross-field detectors  |
| `src/services/profile/anomaly/browser-engine.ts`  | 3     | Math engine detection  |
| `src/services/profile/anomaly/network.ts`         | 4     | FTL/timezone detection |

### Files to Modify

| File                                       | Phase | Change                                                    |
| ------------------------------------------ | ----- | --------------------------------------------------------- |
| `src/services/profile/flag-computation.ts` | 0     | Refactor switch, add risk weights, wire anomaly detection |
| `src/types/flags.ts`                       | 0     | Add new flag constants                                    |

---

## Success Criteria

- [ ] Quick Wins deployed by Day 2
- [ ] Unit test coverage > 90% for anomaly module
- [ ] All 517+ existing tests still pass
- [ ] Integration tests pass after deploy
- [ ] CloudWatch metrics showing anomaly detection
- [ ] No increase in matching latency > 5ms
- [ ] False positive rate < 5% after shadow mode

---

## What We Deferred (Build Later If Needed)

1. **Registry class** - Simple array of detector functions is sufficient
2. **Abstract base class** - Each detector is a standalone function
3. **Brand types** - Simple number with runtime clamp
4. **Utility file sprawl** - Inline functions until complexity warrants splitting
5. **GPU platform matrix** - Low value, high maintenance
6. **Property-based tests** - Add for FTL detection, not for simple checks
