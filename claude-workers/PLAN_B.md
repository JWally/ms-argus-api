# PLAN B: The Architect's Approach to Anomaly Detection

## Philosophy

**Do it right the first time.** Build proper foundations, create clean abstractions, and avoid technical debt. Rework costs more than getting it right upfront. Every detector added in the future should slot in without refactoring. Type safety is not optional - it prevents entire classes of bugs at compile time.

---

## Summary

Implement anomaly detection as a composable, type-safe detector framework within `src/services/profile/anomaly/`. The architecture establishes a base `Detector` interface with discriminated union types for anomaly signals, ensuring every detector follows the same contract. The raw `WebFingerprintResult` payload flows through the matching worker alongside the normalized `Fingerprint`, enabling deep cross-field validation while preserving the existing clean API boundaries.

---

## Foundation First

Before implementing any detector logic, the following architectural foundations must be established:

### 1. Core Type System (`/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/types.ts`)

The type system is the foundation of correctness. Define:

```typescript
// Discriminated union for anomaly types - compiler enforces exhaustive handling
export type AnomalyType =
  | "CROSS_FIELD"
  | "TEMPORAL"
  | "NETWORK"
  | "HARDWARE"
  | "IDENTITY";

// Anomaly codes as const object for type safety and autocomplete
export const AnomalyCodes = {
  // Cross-field
  SCREEN_ORIENTATION_MISMATCH: "SCREEN_ORIENTATION_MISMATCH",
  SCREEN_CSS_MISMATCH: "SCREEN_CSS_MISMATCH",
  WORKER_UA_MISMATCH: "WORKER_UA_MISMATCH",
  WORKER_PLATFORM_MISMATCH: "WORKER_PLATFORM_MISMATCH",
  WORKER_CONCURRENCY_MISMATCH: "WORKER_CONCURRENCY_MISMATCH",
  WORKER_LANGUAGE_MISMATCH: "WORKER_LANGUAGE_MISMATCH",
  WORKER_TIMEZONE_MISMATCH: "WORKER_TIMEZONE_MISMATCH",
  WORKER_GPU_MISMATCH: "WORKER_GPU_MISMATCH",
  NAVIGATOR_LIES: "NAVIGATOR_LIES",
  // Browser engine
  MATH_ENGINE_MISMATCH: "MATH_ENGINE_MISMATCH",
  RESISTANCE_ENGINE_MISMATCH: "RESISTANCE_ENGINE_MISMATCH",
  // Network
  FTL_VIOLATION: "FTL_VIOLATION",
  IP_TIMEZONE_MISMATCH: "IP_TIMEZONE_MISMATCH",
  SERVER_CLIENT_TZ_MISMATCH: "SERVER_CLIENT_TZ_MISMATCH",
  JA4_UA_MISMATCH: "JA4_UA_MISMATCH",
  WEBRTC_IP_MISMATCH: "WEBRTC_IP_MISMATCH",
  // Hardware
  GPU_PLATFORM_MISMATCH: "GPU_PLATFORM_MISMATCH",
  IMPLAUSIBLE_HARDWARE: "IMPLAUSIBLE_HARDWARE",
  // Identity
  PARTIAL_STORAGE_CLEAR: "PARTIAL_STORAGE_CLEAR",
  IDENTITY_DRIFT: "IDENTITY_DRIFT",
} as const;

export type AnomalyCode = (typeof AnomalyCodes)[keyof typeof AnomalyCodes];

// Signal with typed evidence
export interface AnomalySignal {
  type: AnomalyType;
  code: AnomalyCode;
  severity: number; // 0-1 scale
  evidence: AnomalyEvidence;
}

export interface AnomalyEvidence {
  expected: string;
  actual: string;
  field1?: string;
  field2?: string;
  metadata?: Record<string, unknown>;
}

export interface AnomalyResult {
  signals: AnomalySignal[];
  aggregateScore: number;
  suggestedFlags: DeviceFlag[];
}
```

### 2. Extended Raw Payload Type (`/home/justin/Dev/ms-argus-api/src/types/raw-fingerprint.ts`)

Create a comprehensive type for the raw `WebFingerprintResult` structure needed by anomaly detectors:

```typescript
// Extended type with all fields needed for anomaly detection
export interface RawFingerprintPayload {
  loose?: {
    canvas2d?: { $hash?: string };
    offlineAudioContext?: { $hash?: string };
    canvasWebgl?: {
      gpu?: { compressedGPU?: string; renderer?: string };
      parameters?: { renderer?: string };
      extensions?: unknown[];
      $hash?: string;
    };
    screen?: {
      width?: number;
      height?: number;
      orientation?: string;
    };
    cssMedia?: {
      orientation?: string;
      screenQuery?: string;
    };
    timezone?: { location?: string; zone?: string };
    navigator?: {
      userAgent?: string;
      platform?: string;
      hardwareConcurrency?: number;
      deviceMemory?: number;
      language?: string;
      languages?: string[];
      maxTouchPoints?: number;
    };
    workerScope?: {
      userAgent?: string;
      platform?: string;
      hardwareConcurrency?: number;
      language?: string;
      timezoneLocation?: string;
      gpu?: string;
    };
    maths?: {
      $hash?: string;
      data?: Record<string, { firefox?: boolean; chrome?: boolean }>;
    };
    resistance?: {
      engine?: string;
    };
    lies?: {
      totalLies?: number;
      lies?: unknown[];
    };
  };
  botSignals?: {
    isHeadless?: boolean;
    lieCount?: number;
    botHash?: string;
  };
  hashes?: {
    stable?: string;
    fuzzy?: string;
  };
}
```

### 3. Extended SigintData Type (`/home/justin/Dev/ms-argus-api/src/types/matching.ts`)

Add geo fields to existing SigintData interface:

```typescript
// Addition to existing SigintData
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

### 4. Base Detector Interface (`/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detector.ts`)

```typescript
import { AnomalySignal } from "./types";
import { RawFingerprintPayload } from "../../../types/raw-fingerprint";
import { Fingerprint, SigintData } from "../../../types";

export interface DetectorContext {
  normalized: Fingerprint;
  raw: RawFingerprintPayload;
  sigint?: SigintData | null;
}

export interface Detector {
  readonly name: string;
  readonly type: AnomalyType;
  detect(ctx: DetectorContext): AnomalySignal[];
}
```

### 5. Detector Registry (`/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/registry.ts`)

```typescript
import { Detector } from "./detector";
import { AnomalySignal, AnomalyResult } from "./types";

export class DetectorRegistry {
  private detectors: Detector[] = [];

  register(detector: Detector): this {
    this.detectors.push(detector);
    return this;
  }

  runAll(ctx: DetectorContext): AnomalyResult {
    const signals: AnomalySignal[] = [];

    for (const detector of this.detectors) {
      try {
        signals.push(...detector.detect(ctx));
      } catch (error) {
        // Log but don't fail - detector errors shouldn't block matching
        console.error(`Detector ${detector.name} failed:`, error);
      }
    }

    return {
      signals,
      aggregateScore: this.computeAggregateScore(signals),
      suggestedFlags: this.mapSignalsToFlags(signals),
    };
  }
}
```

---

## Type System Design

The type system enables correctness through:

### 1. Discriminated Unions for Exhaustive Matching

```typescript
// Compiler forces handling all anomaly types
function getWeightForType(type: AnomalyType): number {
  switch (type) {
    case "CROSS_FIELD":
      return 1.0;
    case "TEMPORAL":
      return 0.8;
    case "NETWORK":
      return 1.2;
    case "HARDWARE":
      return 0.7;
    case "IDENTITY":
      return 0.9;
    // TypeScript error if case is missing
  }
}
```

### 2. Const Assertions for String Literal Types

```typescript
// AnomalyCode is a union of string literals, not just 'string'
// Enables autocomplete and typo detection at compile time
const signal: AnomalySignal = {
  code: AnomalyCodes.FTL_VIOLATION, // autocompletes
  // code: 'FLT_VIOLATION', // TypeScript error - typo caught
};
```

### 3. Brand Types for Semantic Meaning

```typescript
// Prevent mixing up score types
type Severity = number & { readonly __brand: "severity" };
type RiskWeight = number & { readonly __brand: "weight" };

function createSeverity(value: number): Severity {
  if (value < 0 || value > 1) throw new Error("Severity must be 0-1");
  return value as Severity;
}
```

---

## Abstraction Patterns

### 1. Reusable Detector Base Class

```typescript
// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/base-detector.ts

export abstract class BaseDetector implements Detector {
  abstract readonly name: string;
  abstract readonly type: AnomalyType;

  abstract detectSignals(ctx: DetectorContext): AnomalySignal[];

  detect(ctx: DetectorContext): AnomalySignal[] {
    // Common pre-processing, null checks, etc.
    if (!ctx.raw?.loose) return [];
    return this.detectSignals(ctx);
  }

  protected createSignal(
    code: AnomalyCode,
    severity: number,
    expected: string,
    actual: string,
    fields?: { field1?: string; field2?: string },
  ): AnomalySignal {
    return {
      type: this.type,
      code,
      severity: Math.max(0, Math.min(1, severity)),
      evidence: { expected, actual, ...fields },
    };
  }
}
```

### 2. Comparison Utilities

```typescript
// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/utils/comparisons.ts

export function strictEqual<T>(a: T | undefined, b: T | undefined): boolean {
  return a !== undefined && b !== undefined && a === b;
}

export function caseInsensitiveEqual(
  a: string | undefined,
  b: string | undefined,
): boolean {
  return (
    a !== undefined && b !== undefined && a.toLowerCase() === b.toLowerCase()
  );
}

export function extractBrowser(
  ua: string | undefined,
): "chrome" | "firefox" | "safari" | "edge" | "unknown" {
  if (!ua) return "unknown";
  const lower = ua.toLowerCase();
  if (lower.includes("firefox")) return "firefox";
  if (lower.includes("edg")) return "edge";
  if (lower.includes("chrome")) return "chrome";
  if (lower.includes("safari")) return "safari";
  return "unknown";
}
```

### 3. Geo Utilities

```typescript
// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/utils/geo.ts

// Server location (AWS us-east-1, Reston VA)
const RESTON_VA = { lat: 38.9586, lon: -77.357 };

// Speed of light in fiber: ~200,000 km/s
const FIBER_SPEED_KM_PER_MS = 200;

export function haversineDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const R = 6371; // Earth radius in km
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

export function minPossibleRttMs(distanceKm: number): number {
  return (distanceKm / FIBER_SPEED_KM_PER_MS) * 2;
}

export function isFasterThanLight(
  lat: number,
  lon: number,
  rttMs: number,
  tolerance: number = 0.9,
): boolean {
  const distance = haversineDistance(lat, lon, RESTON_VA.lat, RESTON_VA.lon);
  const minRtt = minPossibleRttMs(distance);
  return rttMs < minRtt * tolerance;
}
```

### 4. Timezone Utilities

```typescript
// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/utils/timezone.ts

const TIMEZONE_ALIASES: Record<string, string> = {
  "US/Eastern": "America/New_York",
  "US/Pacific": "America/Los_Angeles",
  "US/Central": "America/Chicago",
  // ... more aliases
};

export function normalizeTimezone(tz: string): string {
  return TIMEZONE_ALIASES[tz] || tz;
}

export function getUtcOffsetMinutes(tz: string): number | null {
  try {
    const now = new Date();
    const formatter = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      timeZoneName: "shortOffset",
    });
    const parts = formatter.formatToParts(now);
    const offsetPart = parts.find((p) => p.type === "timeZoneName");
    // ... parsing logic
    return offset;
  } catch {
    return null;
  }
}
```

---

## Phase Breakdown

### Phase 0: Foundation (Required First)

**Goal:** Establish the architectural scaffolding that all detectors will use.

**Files to Create:**

1. `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/types.ts` - Core types
2. `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detector.ts` - Detector interface
3. `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/base-detector.ts` - Abstract base class
4. `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/registry.ts` - Detector registry
5. `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/index.ts` - Public exports
6. `/home/justin/Dev/ms-argus-api/src/types/raw-fingerprint.ts` - Raw payload type

**Files to Modify:**

1. `/home/justin/Dev/ms-argus-api/src/types/flags.ts` - Add new anomaly flags
2. `/home/justin/Dev/ms-argus-api/src/types/matching.ts` - Add geo to SigintData
3. `/home/justin/Dev/ms-argus-api/src/types/index.ts` - Export new types
4. `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts` - Add RISK_WEIGHTS

**Testing:**

- Unit tests for registry
- Unit tests for type guards
- Unit tests for utility functions

---

### Phase 1: Lie Count Quick Win

**Goal:** Implement the simplest detector using existing data.

**New File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/lie-count-detector.ts`

```typescript
export class LieCountDetector extends BaseDetector {
  readonly name = "LieCount";
  readonly type: AnomalyType = "CROSS_FIELD";

  detectSignals(ctx: DetectorContext): AnomalySignal[] {
    const lieCount = ctx.raw?.botSignals?.lieCount ?? ctx.normalized.lie_count;
    if (lieCount && lieCount > 0) {
      const severity = Math.min(0.9, 0.5 + lieCount * 0.1);
      return [
        this.createSignal(
          AnomalyCodes.NAVIGATOR_LIES,
          severity,
          "0 lies",
          `${lieCount} lies detected`,
          { field1: "botSignals.lieCount" },
        ),
      ];
    }
    return [];
  }
}
```

**Integration Point:**

- Wire into `detectAllAnomalies()` in `index.ts`
- Add `NAVIGATOR_LIES` to DeviceFlags
- Add weight to RISK_WEIGHTS

---

### Phase 2: Cross-Field Detector

**Goal:** Implement the cross-field consistency checks (Navigator vs Worker, Screen vs CSS).

**New File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/cross-field-detector.ts`

**Checks Implemented:**
| Check | Severity | Notes |
|-------|----------|-------|
| Navigator.userAgent vs WorkerScope.userAgent | 0.8 | Spoofers often miss workers |
| Navigator.platform vs WorkerScope.platform | 0.8 | Same |
| Navigator.hardwareConcurrency vs WorkerScope.hardwareConcurrency | 0.7 | Same |
| Navigator.language vs WorkerScope.language | 0.6 | Same |
| Timezone.location vs WorkerScope.timezoneLocation | 0.7 | Same |
| Screen width/height vs CSS orientation | 0.6 | Portrait/landscape mismatch |
| GPU renderer vs WorkerScope.gpu | 0.7 | If OffscreenCanvas present |

**Dependencies:** None - uses only raw payload

---

### Phase 3: Browser Engine Detector

**Goal:** Detect UA spoofing through math engine fingerprints.

**New File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/browser-engine-detector.ts`

**Checks Implemented:**
| Check | Severity | Notes |
|-------|----------|-------|
| Math results pattern vs claimed UA browser | 0.9 | Very hard to spoof |
| Resistance.engine vs UA browser family | 0.8 | Should match |

---

### Phase 4: Network Detector (Highest Value)

**Goal:** Physics-based location verification and timezone cross-validation.

**New File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/network-detector.ts`

**New Utility Files:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/utils/geo.ts`
- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/utils/timezone.ts`

**Checks Implemented:**
| Check | Severity | Notes |
|-------|----------|-------|
| FTL Violation (RTT vs distance physics) | 0.95 | Definite spoof |
| Server timezone (IP) vs Client timezone (JS) | 0.4-0.8 | Based on hour diff |
| Client main thread TZ vs Worker TZ | 0.7 | Cross-field check |
| JA4 fingerprint vs claimed browser | 0.7 | Build pattern DB |
| WebRTC public IP vs TCP IP | 0.8 | VPN/proxy indicator |

**Dependencies:** Requires `sigint.geo` data (lat, lon, timezone)

---

### Phase 5: Hardware Detector

**Goal:** Detect implausible hardware configurations.

**New File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/hardware-detector.ts`

**New Data File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/data/gpu-platform-matrix.ts`

**Checks Implemented:**
| Check | Severity | Notes |
|-------|----------|-------|
| GPU renderer vs platform compatibility | 0.5 | Mali on Windows = wrong |
| CPU cores vs GPU tier plausibility | 0.4 | 12 cores + Intel HD 400 |
| Memory vs cores ratio | 0.3 | Low memory + many cores |
| Touch points vs platform | 0.5 | Touch on Linux desktop |

---

### Phase 6: Identity Detector

**Goal:** Detect suspicious persistent ID behavior.

**New File:**

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/identity-detector.ts`

**Checks Implemented:**
| Check | Severity | Notes |
|-------|----------|-------|
| Mixed ID state (some exist, some new) | 0.7 | Partial storage clear |
| Evercookie vs FaviconCache prefix match | 0.3 | Should correlate |
| CryptoId rotation without cookie clear | 0.8 | Key regeneration |

---

### Phase 7: Integration and Observability

**Goal:** Wire anomaly detection into the matching worker and add observability.

**Files to Modify:**

1. `/home/justin/Dev/ms-argus-api/src/handlers/matching-worker.ts` - Pass raw payload
2. `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts` - Integrate anomaly signals
3. `/home/justin/Dev/ms-argus-api/src/types/matching.ts` - Add anomaly evidence codes

**New Metrics:**

```
AnomalyDetected           - Any anomaly signal fired
AnomalyByType             - Dimension: CROSS_FIELD, NETWORK, etc.
AnomalyByCode             - Dimension: SCREEN_ORIENTATION_MISMATCH, etc.
AnomalySeverityHigh       - Severity >= 0.7
```

**Evidence Code Integration:**

```typescript
// In MatchResult
evidence_codes: [
  "STABLE_HASH_MATCH",
  "ANOMALY:FTL_VIOLATION",
  "ANOMALY:MATH_ENGINE_MISMATCH",
];
```

---

## Testing Strategy

### 1. Unit Tests for Each Detector

Every detector gets a dedicated test file:

```typescript
// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/detectors/cross-field-detector.test.ts

describe("CrossFieldDetector", () => {
  describe("Navigator vs Worker checks", () => {
    it("should detect UA mismatch between navigator and worker", () => {
      const ctx = createDetectorContext({
        raw: {
          loose: {
            navigator: { userAgent: "Mozilla/5.0 Chrome/120" },
            workerScope: { userAgent: "Mozilla/5.0 Firefox/120" },
          },
        },
      });
      const signals = detector.detect(ctx);
      expect(signals).toContainEqual(
        expect.objectContaining({
          code: "WORKER_UA_MISMATCH",
          severity: 0.8,
        }),
      );
    });

    it("should not flag when navigator and worker match", () => {
      const ctx = createDetectorContext({
        raw: {
          loose: {
            navigator: { userAgent: "Mozilla/5.0 Chrome/120" },
            workerScope: { userAgent: "Mozilla/5.0 Chrome/120" },
          },
        },
      });
      const signals = detector.detect(ctx);
      expect(signals).toHaveLength(0);
    });

    it("should handle missing workerScope gracefully", () => {
      const ctx = createDetectorContext({
        raw: {
          loose: {
            navigator: { userAgent: "Mozilla/5.0 Chrome/120" },
            // no workerScope
          },
        },
      });
      const signals = detector.detect(ctx);
      expect(signals).toHaveLength(0); // No error, no false positive
    });
  });
});
```

### 2. Test Fixtures from Real Data

Use `trash.sick` to create sanitized test fixtures:

```typescript
// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/__fixtures__/real-device.ts
export const REAL_DEVICE_PAYLOAD: RawFingerprintPayload = {
  // Extracted and sanitized from trash.sick
};

// /home/justin/Dev/ms-argus-api/src/services/profile/anomaly/__fixtures__/spoofed-ua.ts
export const SPOOFED_UA_PAYLOAD: RawFingerprintPayload = {
  // Firefox UA but Chrome math results
};
```

### 3. Integration Tests

Test the full pipeline from matching worker through flag computation:

```typescript
describe("Anomaly Detection Integration", () => {
  it("should detect FTL violation and set flag", async () => {
    const payload = createFingerprintPayload({
      fingerprint: { timezone: "Asia/Tokyo" },
      sigint: {
        geo: { lat: 35.6762, lon: 139.6503, timezone: "Asia/Tokyo" },
        tcpProbe: { rttMs: 5 }, // 5ms RTT to Tokyo from Reston = impossible
      },
    });

    const result = await matchingService.runTieredMatching(tenant, payload);

    expect(result.flags).toContain("ftl_violation");
    expect(result.evidence_codes).toContain("ANOMALY:FTL_VIOLATION");
  });
});
```

### 4. Property-Based Tests

Use fast-check for edge cases:

```typescript
import fc from "fast-check";

describe("FTL Detection", () => {
  it("should never flag local connections as FTL", () => {
    fc.assert(
      fc.property(
        fc.float({ min: 0.1, max: 100 }), // RTT in ms
        (rttMs) => {
          // Reston to nearby DC: ~50km
          const isFtl = isFasterThanLight(38.9072, -77.0369, rttMs);
          // Even 0.1ms is possible for 50km, so should never flag
          return !isFtl;
        },
      ),
    );
  });
});
```

---

## What You Won't Compromise On

1. **Type safety everywhere.** No `any` types. No unchecked property access. The compiler is your first line of defense.

2. **Detector isolation.** Each detector operates independently and cannot crash the pipeline. Errors are logged but do not propagate.

3. **Explicit severity values.** Every anomaly signal has a documented severity rationale. No magic numbers without comments.

4. **Graceful degradation.** Missing fields in raw payload return empty signals, not errors. Partial data is handled explicitly.

5. **Evidence preservation.** Every signal includes evidence showing exactly what was expected vs. what was found, enabling debugging and audit.

6. **Test coverage for every check.** No detector ships without tests for: positive case, negative case, and null/missing data case.

7. **Backward compatibility.** The normalized Fingerprint interface remains unchanged. Raw payload access is opt-in for anomaly detection.

8. **Observability.** Every anomaly type is metriced. We can graph detection rates before acting on them.

---

## Open Questions

1. **Raw payload storage:** Should we store raw payload for historical anomaly analysis, or just compute at match time?
   - Recommendation: Start with compute-at-match-time, add storage later if needed for ML training

2. **Severity thresholds for flags:** At what aggregate severity should we set flags?
   - Recommendation: Start conservative (0.7+), tune based on false positive rate

3. **Flag combination effects:** Should certain flag combinations compound risk non-linearly?
   - Example: MATH_ENGINE_MISMATCH + WORKER_MISMATCH together is much more suspicious than either alone
   - Recommendation: Add `combinedSeverityBonus` calculation in `computeAggregateScore()`

4. **JA4 database source:** Where to source JA4-to-browser mappings?
   - Options: Build internally from traffic, use FingerprintJS open data, commercial database
   - Recommendation: Start with heuristic patterns, build database from observed traffic

5. **Timezone normalization:** How to handle all timezone aliases and DST edge cases?
   - Recommendation: Use IANA timezone database, build alias map, handle gracefully when lookup fails

6. **FTL tolerance value:** Current plan uses 10% tolerance - is this appropriate?
   - Edge cases: Satellite connections, mobile handoffs, anycast routing
   - Recommendation: Start at 10%, add 20% tolerance for mobile carriers (detect via User-Agent)

7. **Sigint geo availability:** When will `sigint.geo` (lat/lon/timezone) be available?
   - This is required for FTL detection and server-client timezone comparison
   - Recommendation: Phase 4 is blocked until sigint team provides this data

---

### Critical Files for Implementation

- `/home/justin/Dev/ms-argus-api/src/services/profile/anomaly/types.ts` - Core type definitions
- `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts` - Integration point for anomaly signals
- `/home/justin/Dev/ms-argus-api/src/helpers/normalize-fingerprint.ts` - WebFingerprintResult interface to extend
- `/home/justin/Dev/ms-argus-api/src/types/matching.ts` - SigintData interface needs geo fields
- `/home/justin/Dev/ms-argus-api/src/handlers/matching-worker.ts` - Entry point where raw payload must flow through
