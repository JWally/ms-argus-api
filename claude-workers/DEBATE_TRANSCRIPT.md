# DEBATE TRANSCRIPT: Anomaly Detection Implementation

## Participants

- **The Pragmatist (Plan A)**: Ship value early, iterate, minimize risk
- **The Architect (Plan B)**: Do it right the first time, build proper foundations

## Moderator's Role

To identify the strongest arguments from each side and propose resolutions that combine the best of both approaches.

---

## DEBATE POINT 1: Foundation Timing

### The Pragmatist Position

**Claim:** Ship quick wins first, extract abstractions later.

**Evidence:**

- Phase 1 delivers `lie_count`, `is_headless`, `proxy_score`, `vpn_score` detection in Days 1-2 with approximately 50 lines of code
- Data already exists in normalized fingerprint (lines 373-388 of `normalize-fingerprint.ts`)
- Each phase is an independent PR that can ship even if other phases are delayed
- YAGNI principle applies: "Build the simplest thing that works, then refactor when patterns emerge"

### The Architect Position

**Claim:** Build detector framework first, implement inside it.

**Evidence:**

- Adding checks directly to `detectBotSignals()` starts "a death spiral" - the function is already 38 lines and would grow to 100+ lines
- Phase 0 foundation enables: type safety via discriminated unions, detector isolation via try/catch, and clean extensibility
- Without abstraction, adding a new detector requires touching 5 files (shotgun surgery)
- With proper abstraction: create detector file, register it, done

### Resolution

**Hybrid approach: Minimal Structure Day 1, Quick Wins Day 2**

1. **Day 1:** Create `anomaly/types.ts` with `AnomalySignal` interface (10 lines) and a simple detection orchestrator function (not a class/registry). Approximately 30 lines total.
2. **Day 2:** Implement Quick Wins (`lie_count`, `is_headless`, `proxy_score`, `vpn_score`) as functions returning `AnomalySignal[]`, wired through the orchestrator.
3. **Defer:** Registry class, abstract base class, brand types until we have 3+ working detectors.

---

## DEBATE POINT 2: Raw Payload Handling

### The Pragmatist Position

Pass raw + normalized as dual payloads.

### The Architect Position

Extend normalization to extract needed worker fields.

### Resolution

**Pass raw payload to anomaly detection only, not everywhere**

1. Keep `normalizeFingerprint()` unchanged
2. Create dedicated function `detectAnomalies(normalized: Fingerprint, raw: WebFingerprintResult)`
3. Do NOT pass raw payload through the entire pipeline - only to anomaly detection boundary
4. Add type for `WebFingerprintResult` for type-safe raw field access

---

## DEBATE POINT 3: Type System Complexity

### The Pragmatist Position

Simple strings and numbers are fine. Brand types are academic overkill.

### The Architect Position

Discriminated unions and typed evidence are essential.

### Resolution

**Adopt const assertions and discriminated unions. Skip brand types.**

1. Create `AnomalyCodes` as const object - catches typos at compile time
2. Create `AnomalyType` as string union - enables exhaustive switch handling
3. Skip brand types for `Severity` - use simple number with runtime clamp
4. Keep evidence structure simple but typed

---

## DEBATE POINT 4: Testing Approach

### Resolution

**Unit tests required, combinatorial tests encouraged for high-risk combinations**

1. **Required per detector:** Unit tests (clean, anomaly, edge cases, thresholds)
2. **Required for aggregation:** Test that `computeAggregateScore()` handles multiple signals
3. **Encouraged:** Property-based tests for physics calculations (FTL)
4. **Deferred:** Full combinatorial matrix - add when bugs found

---

## DEBATE POINT 5: Switch Statement Growth

### Both Plans Agree

The `computeRiskScore()` switch statement is problematic.

### Resolution

**Refactor switch to lookup table BEFORE adding new flags**

```typescript
function computeRiskScore(flags: string[]): number {
  let riskScore = 0;
  for (const flag of flags) {
    const weight = RISK_WEIGHTS[flag as keyof typeof RISK_WEIGHTS];
    if (weight !== undefined) {
      riskScore += weight;
    }
  }
  return Math.min(riskScore, 1.0);
}
```

This is a prerequisite for either plan's implementation.

---

## CONSENSUS POINTS

1. **Quick Win Targets:** `lie_count`, `is_headless`, `proxy_score`, `vpn_score`
2. **Shadow Mode:** Deploy in observe-only mode first
3. **Sigint Geo Dependency:** FTL detection blocked on sigint team
4. **Evidence Preservation:** Include expected vs actual in signals
5. **Error Isolation:** Detector failures should not crash pipeline
6. **Backward Compatibility:** Keep existing `Fingerprint` interface
7. **CloudWatch Observability:** New metrics for anomaly rates
8. **FTL Algorithm:** Haversine distance + RTT physics check
9. **Risk Weight Pattern:** Continue using `RISK_WEIGHTS` object
10. **Threshold Tuning:** Start conservative, tune based on false positives

---

## RESOLVED DISAGREEMENTS

| Issue                | Resolution                                                            |
| -------------------- | --------------------------------------------------------------------- |
| Foundation Timing    | Minimal structure Day 1, Quick Wins Day 2. Defer registry/base class. |
| Raw Payload Handling | Pass to anomaly detection only, not through entire pipeline.          |
| Type System          | Adopt const assertions and unions. Skip brand types.                  |
| Testing              | Unit tests required. Combinatorial tests encouraged.                  |
| Switch Growth        | Refactor to lookup table FIRST.                                       |

---

## FINAL IMPLEMENTATION RECOMMENDATION

**Phase 0 (Day 1): Minimal Foundation**

- Refactor `computeRiskScore()` switch to lookup table
- Create `anomaly/types.ts` with `AnomalySignal`, `AnomalyCodes`, `AnomalyType`
- Create simple `detectAnomalies()` orchestrator function
- Add typed `WebFingerprintResult` interface

**Phase 1 (Day 2): Quick Wins**

- Implement detectors as functions returning `AnomalySignal[]`
- Add new flags to `DeviceFlags`
- Add weights to `RISK_WEIGHTS`
- Deploy in shadow mode

**Phase 2+ (Days 3+): As Planned**

- Follow Plan A's timeline with Plan B's type safety
- Extract abstractions when patterns emerge from working detectors
