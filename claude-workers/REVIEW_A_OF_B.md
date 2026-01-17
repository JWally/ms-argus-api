# REVIEW A OF B: The Pragmatist's Critique of Plan B (The Architect)

## Philosophy Reminder

**Ship value early and iterate.** Better to have something in production learning than perfect code on a branch.

---

## 1. What Plan B Gets Right

**Credit where due - The Architect has some genuinely good ideas:**

**Type Safety Philosophy**: Plan B's discriminated union for `AnomalyType` and const assertions for `AnomalyCodes` are solid patterns. The existing codebase already uses `as const` for `DeviceFlags` in `/home/justin/Dev/ms-argus-api/src/types/flags.ts` - this is consistent with established patterns.

**Detector Isolation**: The try/catch around each detector in `DetectorRegistry.runAll()` is smart. One broken detector should not kill the entire matching flow. This mirrors how the existing `emitObservation()` in `matching-worker.ts` handles analytics failures.

**Evidence Preservation**: Having structured `AnomalyEvidence` with `expected`/`actual` fields is genuinely useful for debugging and audit trails. This is good design.

**Graceful Degradation**: The emphasis on handling missing fields and returning empty signals rather than throwing is the right approach. The existing `normalizeFingerprint()` already does this extensively.

**Severity Documentation**: Requiring documented severity rationale prevents future maintainers from asking "why is this 0.7?"

---

## 2. Where Plan B Goes Wrong

**The Architecture Astronaut Problem**: Plan B spends 771 lines on architecture before shipping a single detection. That is a red flag.

**Phase 0 is a Trojan Horse**: "Foundation First" sounds responsible, but look at what it actually requires:

- 6 new files to create
- 4 existing files to modify
- "Unit tests for registry, type guards, and utility functions"
- All before detecting a single anomaly

Meanwhile, Plan A ships lie_count detection in ~10 lines added to the existing `detectBotSignals()` function. The `lie_count` field is already extracted at line 377-379 of `normalize-fingerprint.ts`. Plan B wants to build a cathedral before detecting what is already in the payload.

**Over-Abstraction of Simple Operations**: The `BaseDetector` abstract class, `DetectorContext` interface, and `DetectorRegistry` add layers of indirection for what amounts to:

```typescript
if (fingerprint.lie_count > 0) flags.push("navigator_lies");
```

This is an 800-line plan to avoid a 50-line if-statement block.

**Brand Types are Academic Overkill**:

```typescript
type Severity = number & { readonly __brand: "severity" };
```

This is cute for a type theory blog post but adds cognitive overhead for what could be a JSDoc comment. The existing codebase does not use branded types anywhere - this would be an isolated pattern.

**Utility File Sprawl**: Plan B proposes separate utility files for:

- `/anomaly/utils/comparisons.ts`
- `/anomaly/utils/geo.ts`
- `/anomaly/utils/timezone.ts`

Each with 20-40 lines. These could be inline functions or a single `utils.ts` until complexity justifies splitting.

---

## 3. Specific Concerns

### How long until first value ships?

**Plan A**: Days 1-2 ships lie_count, is_headless, proxy/VPN detection. Immediate value.

**Plan B**: Phase 0 (foundation) + Phase 1 (lie count "quick win" - but after building the registry). Realistically 1-2 weeks before anything detects anomalies in production.

**Verdict**: Plan B's "Phase 1: Lie Count Quick Win" is not quick - it depends on the entire Phase 0 foundation being complete. It is architecturally blocked on registry, types, base detector, and more.

### What is the risk of over-engineering?

**High.** Plan B introduces:

- A registry pattern (for initially 1-2 detectors)
- An abstract base class (that mostly just null-checks `ctx.raw?.loose`)
- Discriminated unions (for 5 types that could be string literals)
- Brand types (for numbers that work fine as numbers)

The existing `flag-computation.ts` is 184 lines of straightforward code. It has clear functions, simple conditionals, and is easy to understand. Plan B would replace this simplicity with a framework.

### Where does complexity not justify value?

**Specific Examples:**

1. **DetectorRegistry class**: We have 6 detectors planned. A simple array and for-loop suffices. No need for a registry class with `register()` fluent API.

2. **RawFingerprintPayload type in a new file**: The `WebFingerprintResult` interface already exists at lines 94-165 of `normalize-fingerprint.ts`. Plan B proposes duplicating this structure in a new file rather than extending/exporting the existing type.

3. **Extended SigintData for geo**: This is a hard dependency on the sigint team. Plan B admits "Phase 4 is blocked until sigint team provides this data" but still puts geo utilities in Phase 0 foundation. Building utilities for data that does not exist yet is speculative work.

4. **GPU Platform Matrix data file**: Plan B wants to build a data file mapping GPU renderers to valid platforms. This is N^2 maintenance burden for what severity? 0.5 per Plan B's own table. Low value, high maintenance.

### What happens if Phase 0 takes longer than expected?

**Everything is blocked.** Plan B's phases are sequential dependencies:

- Phase 1 (Lie Count) needs Phase 0 foundation
- Phase 2 (Cross-Field) needs the detector pattern from Phase 1
- Phase 4 (Network) needs geo utilities from Phase 0

If Phase 0 hits any snags - code review feedback on the type system, debate about registry pattern, testing infrastructure setup - nothing else ships.

**Compare to Plan A**: Each phase is an independent PR. Phase 1 ships standalone. Phase 2 can ship even if Phase 1 gets delayed. Phases are decoupled.

---

## 4. What I Would Steal

**Good ideas worth incorporating from Plan B:**

1. **Structured AnomalySignal interface**: The concept of having `type`, `code`, `severity`, and `evidence` in a structured object is valuable for observability. Steal this, but implement it inline rather than in a separate type system.

2. **The FTL Detection Math**: The haversine distance calculation and physics-based RTT validation are well-done. The geo utility code is solid - just defer building it until sigint actually provides lat/lon.

3. **Error isolation per detector**: The try/catch pattern in `runAll()` is good defensive programming. Apply this to a simple loop, not a registry class.

4. **Timezone normalization aliases**: The `TIMEZONE_ALIASES` map is practical. Add this when implementing timezone checks, not in Phase 0.

5. **The severity table documentation**: Having a table showing which check has which severity is useful for tuning. Steal the documentation approach.

---

## 5. What I Would Fight Against (Non-Negotiables)

**These are hills I will die on:**

### 1. NO Phase 0 "Foundation First"

We do not need 6 new files and 4 modified files before detecting anything. The existing `flag-computation.ts` pattern works. Add to it first, extract abstractions later when we have 3+ detectors that share code.

YAGNI (You Aren't Gonna Need It) applies here. Build the simplest thing that works, then refactor when patterns emerge.

### 2. NO Abstract Base Class for Detectors

Plan B's `BaseDetector` abstract class adds one null check. This does not justify inheritance. Just put the null check in each detector function. Composition over inheritance.

### 3. NO Brand Types

```typescript
type Severity = number & { readonly __brand: "severity" };
```

This is TypeScript showing off. The existing codebase does not use this pattern. A severity is a number between 0 and 1 - a JSDoc or runtime clamp is sufficient.

### 4. NO Registry Pattern (Yet)

With 1-6 detectors, a simple array is fine:

```typescript
const detectors = [detectLies, detectCrossField, detectNetwork];
const signals = detectors.flatMap((d) => d(fingerprint, raw, sigint));
```

A registry with `register()` fluent API and named lookups is premature. Add it if/when we need runtime detector configuration, plugin architecture, or feature flags per detector.

### 5. NO Blocking on Sigint Geo Data

Plan B admits Phase 4 is blocked on sigint team. That is fine - but do not build geo utilities in Phase 0 as "foundation" when we cannot test them against real data. Build the utilities when the data exists.

---

## Summary

Plan B is a well-intentioned architecture document that would be appropriate for a greenfield system with a team of 5+ engineers and a 6-month timeline. For this codebase - with its existing patterns, single-digit number of detectors, and need for incremental value - it is over-engineered.

The Architect's instinct for type safety and isolation is correct. The execution adds too much ceremony. My recommendation: take Plan A's incremental approach, steal the signal/evidence structure from Plan B, and extract abstractions only after we have working detectors that share obvious patterns.

**Ship value first. Architect second.**
