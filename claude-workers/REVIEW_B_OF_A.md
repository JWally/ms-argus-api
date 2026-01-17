# REVIEW B OF A: The Architect's Critique of Plan A (The Pragmatist)

## Philosophy Reminder

**Do it right the first time.** Technical debt is not "future work" - it is interest-bearing liability that compounds with every commit.

---

## 1. What Plan A Gets Right

**1.1 Correct Identification of Quick Wins**
The Phase 1 targets (`lie_count`, `is_headless`, `proxy_score`, `vpn_score`) are indeed low-hanging fruit. The data already exists in the normalized fingerprint at `/home/justin/Dev/ms-argus-api/src/helpers/normalize-fingerprint.ts` lines 373-388. The checks require minimal code.

**1.2 Incremental Rollout Strategy**
The shadow mode option is prudent. Observing anomalies before flagging them prevents false positive disasters. This is defensive engineering I support.

**1.3 Existing Pattern Leverage**
Plan A correctly identifies that `detectBotSignals()` in `/home/justin/Dev/ms-argus-api/src/services/profile/flag-computation.ts` is the natural insertion point. It follows the existing codebase pattern.

**1.4 Risk Weights Table Approach**
The `RISK_WEIGHTS` constant is a clean pattern. Adding new weights there maintains consistency.

---

## 2. Where Plan A Goes Wrong

### 2.1 The "Just Add More If Statements" Anti-Pattern

Plan A proposes adding checks directly to `detectBotSignals()`:

```typescript
if (fingerprint.lie_count && fingerprint.lie_count > 0) {
  flags.push(DeviceFlags.NAVIGATOR_LIES);
}
```

This is the start of a death spiral. The function is already 38 lines. Plan A's Phase 1-4 would add approximately 15-20 more conditional blocks. By Phase 5, `detectBotSignals()` will be an unmaintainable 100+ line monster with no clear organization.

### 2.2 Scattered Type Definitions

Plan A's Phase 2.1 proposes creating `anomaly/types.ts` with `AnomalySignal` and `AnomalyResult`. But Phase 1 directly adds flags to `DeviceFlags` without any anomaly infrastructure.

This creates two parallel systems:

1. Simple flags added directly to `detectBotSignals()` (Phase 1)
2. `AnomalySignal` based system (Phase 2+)

These will never converge cleanly. You will end up with some anomalies being flags and some being signals, with translation code scattered throughout.

### 2.3 Missing Abstraction: The Raw Payload Problem

Plan A Phase 3 admits: "To implement Navigator vs Worker checks, we need access to the raw payload structure."

The proposed solution:

```typescript
const fingerprint = normalizeFingerprint(payload.fingerprint, payload.sigint);
const rawFingerprint = payload.fingerprint; // Keep original structure
```

This is architectural pollution. Now every downstream consumer must handle both `fingerprint` (normalized) and `rawFingerprint` (nested). Passing it alongside the normalized version doubles the cognitive load.

**The proper approach:** Extend `normalizeFingerprint()` to extract worker-specific fields into the flat Fingerprint type. Extract once, use everywhere. No dual-payload nightmare.

### 2.4 Magic Numbers Everywhere

Plan A's thresholds are hardcoded:

```typescript
if (fingerprint.proxy_score > 0.7) { ... }
const minRtt = (distance / 200) * 2; // 200 km/ms fiber speed
return rttMs < minRtt * 0.9; // 10% tolerance
```

Where do these come from? How do we tune them? Plan A's Open Question #2 asks "Who validates false positive rates?" without providing infrastructure to do so.

**The proper approach:** Centralized threshold configuration with named constants.

### 2.5 No Testing Strategy for Compound Detectors

Cross-field anomalies require combinatorial testing:

- What if `lie_count > 0` AND `is_headless === true`?
- What if `proxy_score > 0.7` AND timezone mismatches?

Without a testing framework that generates combinations, you will have gaps.

---

## 3. Specific Concerns

### 3.1 Technical Debt Accumulation

**Immediate debt (Phase 1):**

- 3 new flags added to `DeviceFlags` without namespace organization
- Switch statement in `computeRiskScore()` grows unboundedly

**Medium-term debt (Phase 2-3):**

- Two incompatible anomaly representations (flags vs signals)
- Raw payload passed alongside normalized (dual data paths)

**Long-term debt (Phase 4-5):**

- Browser pattern database with no versioning strategy
- FTL detection tied to hardcoded RESTON coordinates
- No mechanism to disable individual detectors without code changes

### 3.2 Extensibility Failures

**Adding a new detector requires:**

1. Edit `flag-computation.ts` to add if-statement
2. Edit `flags.ts` to add constant
3. Edit `flag-computation.ts` to add risk weight
4. Edit `computeRiskScore()` switch statement
5. Add tests to `profile-service.test.ts`

Five files touched for one detector. This is textbook shotgun surgery.

**With proper abstraction:**

1. Create new file implementing `AnomalyDetector` interface
2. Register in detector registry
3. Done (tests are co-located with detector)

### 3.3 Type Safety Gaps

Plan A's `AnomalySignal.evidence`:

```typescript
evidence: {
  expected: string;
  actual: string;
  field1?: string;
  field2?: string;
}
```

This is stringly-typed. What does `field1` mean? What values are valid for `expected`? Evidence must be type-safe and discriminated by anomaly type.

### 3.4 Testing Structure Deficiencies

The current `detectBotSignals` tests use simple fingerprint fixtures. This pattern will not scale to:

- Cross-field consistency checks requiring specific field combinations
- Temporal anomalies requiring time-series data
- Network anomalies requiring geographic/RTT data

---

## 4. What I'd Steal From Plan A

### 4.1 The Quick Wins Ordering

Phase 1 targets are correctly prioritized. `lie_count` and `is_headless` have the highest signal-to-noise ratio. I would implement these first, but within a proper detector framework.

### 4.2 Phased Rollout Timeline

The 5-phase structure with Week 1 Quick Wins is reasonable scope management. I would keep this timeline but spend Day 1-2 establishing the detector abstraction, then implementing Quick Wins inside it.

### 4.3 Shadow Mode Concept

Deploying detectors in observe-only mode before affecting risk scores is sound. I would formalize this with a detector state enum: `SHADOW | ACTIVE | DISABLED`.

### 4.4 FTL Detection Algorithm

The Haversine distance + RTT physics check is mathematically correct. I would extract this into a well-tested utility function with configurable server locations.

### 4.5 Evidence Codes Pattern

Anomaly signals should be added to `evidence_codes` in match result. This enables downstream consumers to understand why a device was flagged.

---

## 5. What I'd Fight Against (Non-Negotiables)

### 5.1 Direct If-Statement Injection

I will not approve PRs that add conditional blocks directly to `detectBotSignals()`. Each detector must be a discrete unit that can be tested, toggled, and monitored independently.

### 5.2 Dual Payload Passing

I will not approve passing `rawFingerprint` alongside `fingerprint`. Extend the normalization layer properly or extract needed fields during normalization. No dual data paths.

### 5.3 Stringly-Typed Evidence

I will not approve `evidence: { expected: string, actual: string }`. Evidence must be type-safe and discriminated by anomaly type.

### 5.4 Hardcoded Thresholds in Detection Logic

I will not approve `proxy_score > 0.7` inline. All thresholds must be named constants in a configuration module.

### 5.5 Unbounded Switch Statement Growth

The `computeRiskScore()` switch statement is already showing smell. I will not approve adding more cases without refactoring to a weight lookup table:

```typescript
const weight = RISK_WEIGHTS[flag as keyof typeof RISK_WEIGHTS];
if (weight !== undefined) {
  riskScore += weight;
}
```

This is a 5-line change that prevents future switch case additions entirely.

---

## Summary

Plan A will ship something in Week 1. It will work. But by Week 4, you will have:

- A 150-line `detectBotSignals()` function with 15+ conditionals
- Two incompatible anomaly representations
- Magic numbers scattered across 3 files
- Tests that pass individually but miss interaction bugs
- No ability to disable individual detectors without code deploys

The "pragmatic" approach creates more work over any timeline longer than 2 weeks. Spending 2 extra days upfront on proper abstraction is not gold-plating - it is the minimum viable architecture for a system that will continue evolving.

**Recommendation:** Adopt Plan A's timeline and detection targets. Reject Plan A's implementation approach. Build the detector abstraction first, then implement Quick Wins inside it.
