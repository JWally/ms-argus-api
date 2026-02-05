# Code Cleanup Assessment: ms-argus-api

## Executive Summary

The codebase has solid domain separation (matching, profile, anomaly detection) and good patterns like dependency injection and feature flags. However, several files have grown beyond their original intent, accumulating multiple responsibilities, duplicated logic, and compatibility shims that make the code harder to review and maintain.

**Key numbers:**

- 3 files over 500 lines in `src/`
- 1 CDK construct at 669 lines
- 3 near-identical batch write implementations (~135 lines of duplication)
- 154 lines of field extraction logic embedded in a handler
- Duplicate utility functions across files

---

## Critical Issues

### 1. God File: `src/handlers/matching-worker.ts` (593 lines)

This handler does too much:

- SQS event loop with error handling and partial batch failure reporting
- Warmup message detection
- **154 lines** of fingerprint extraction/flattening from V3 payloads (`extractFingerprint`)
- Matching orchestration
- Tier metric recording (11 sequential metric calls)
- Firehose observation emission
- Session payload gzipping and S3 writing

The `extractFingerprint` function alone handles:

- Identifier extraction (evercookie, public key, sigint)
- TCP probe data in **both flat AND nested** structures
- STUN data with **two different field naming conventions** (`publicIp` vs `reflexiveIp`)
- Headless detection from **multiple signal structures**
- Lie count from **two different field names** (`count` vs `totalLies`)

**Risk:** Any change to payload format requires touching a 600-line handler. Reviewers must understand the entire file to assess a field mapping change.

**Recommendation:** Extract a `src/services/matching/payload-normalizer.ts` module. Make format compatibility explicit through versioned adapters or a field-mapping configuration. Handler drops to ~400 lines.

---

### 2. Triplicated Batch Write Logic: `src/services/profile/index-writers.ts` (557 lines)

Three functions implement nearly identical retry-with-exponential-backoff over DynamoDB `BatchWriteItemCommand`:

| Function                 | Lines   | Purpose                       |
| ------------------------ | ------- | ----------------------------- |
| `batchWriteTier1Indexes` | 252-292 | Write Tier 1 hash indexes     |
| `batchWriteTier2Buckets` | 305-349 | Write Tier 2 compound buckets |
| `batchWriteSimHashBands` | 509-557 | Write SimHash band entries    |

All three:

1. Marshall entries into `WriteRequest[]`
2. Loop while `unprocessedItems.length > 0 && attempt < maxRetries`
3. Send `BatchWriteItemCommand`
4. Check `result.UnprocessedItems`
5. Exponential backoff: `Math.pow(2, attempt) * 100`
6. Throw if items remain after retries

**~135 lines of copy-paste logic.**

**Recommendation:** Extract a generic `batchWriteWithRetry<T>(deps, tableName, entries, marshaller, opts?)` utility. Each caller becomes a one-liner. The retry policy becomes testable in isolation.

---

### 3. God Construct: `lib/constructs/workers.ts` (669 lines)

This single CDK construct configures three unrelated Lambda workers:

- Matching Worker (SQS consumer, read permissions, vector DB access)
- Profile Updater (SQS consumer, read/write permissions, different tables)
- Cardinality Recalc (scheduled, different IAM needs)

Each worker has its own permission grants, alarms, environment variables, and event sources - but they're all tangled in one file.

**Risk:** Changing one worker's IAM policy requires navigating a 669-line file. Easy to accidentally grant permissions to the wrong Lambda.

**Recommendation:** Split into `MatchingWorkerConstruct`, `ProfileUpdaterConstruct`, `CardinalityRecalcConstruct`. Each is self-contained, independently reviewable, and has a clear blast radius.

---

### 4. Duplicated Handler SQS Pattern

`matching-worker.ts` and `profile-updater.ts` implement the same SQS partial-batch-failure pattern:

```typescript
const batchItemFailures: SQSBatchItemFailure[] = [];
for (const record of event.Records) {
  try {
    await processRecord(record, service);
    metrics.addMetric("Success", MetricUnit.Count, 1);
  } catch (error) {
    logger.error("Failed to process record", {
      error,
      messageId: record.messageId,
    });
    metrics.addMetric("Error", MetricUnit.Count, 1);
    batchItemFailures.push({ itemIdentifier: record.messageId });
  }
}
return { batchItemFailures };
```

**Recommendation:** Extract a `processSqsBatch(event, processFn, metricPrefix)` helper. Each handler only defines `processRecord`. Consistent error handling guaranteed across all SQS consumers.

---

### 5. Duplicate `sleep` Utility

Defined identically in two files:

- `src/services/profile/index-writers.ts:94`
- `src/handlers/cardinality-recalc.ts:57`

```typescript
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

**Recommendation:** Move to `src/helpers/utils.ts` (or similar). Trivial fix, but duplicate utilities tend to multiply.

---

## Moderate Issues

### 6. Schema + Types + Helpers in One File: `src/helpers/payload-schema.ts` (407 lines)

This file combines:

- TypeScript interfaces/types (~100 lines)
- JSON Schema validation objects (~250 lines)
- Helper functions for extraction
- Compatibility handling for payload format versions

**Recommendation:** Split into:

- `src/types/payload.ts` - TypeScript types only
- `src/helpers/payload-schema.ts` - JSON Schema only (derived from types if possible)
- Leave extraction helpers where they're consumed

---

### 7. Multi-Responsibility: `src/services/matching/tier2-compound.ts` (318 lines)

Handles four concerns:

- Tier 2 compound key generation and matching
- Cardinality fetching and in-memory caching
- Candidate scoring with evidence codes
- Confidence penalty calculation

**Recommendation:** Extract cardinality caching to a shared service (it's likely useful elsewhere). Scoring/penalty logic could be a separate `tier2-scoring.ts`.

---

### 8. Metrics Recording: Data-Driven Opportunity

`recordTierMetric()` in `matching-worker.ts` has 11 sequential `metric.addMetric()` calls with a switch-like pattern. This grows with each new tier.

**Recommendation:** Use a tier-to-metric-name map:

```typescript
const TIER_METRICS: Record<MatchTier, string> = {
  [MatchTier.CACHE]: "Tier0CacheHit",
  [MatchTier.IDENTITY]: "Tier05IdentityMatch",
  // ...
};

function recordTierMetric(metrics: Metrics, tier: MatchTier) {
  metrics.addMetric(TIER_METRICS[tier], MetricUnit.Count, 1);
}
```

---

## Minor Issues / Quick Wins

### 9. Compatibility Shims Without Expiry

The payload format compatibility handling in `extractFingerprint` supports multiple naming conventions (`publicIp` vs `reflexiveIp`, `count` vs `totalLies`, flat vs nested TCP). There's no indication of when old formats can be dropped.

**Recommendation:** Add comments with deprecation dates or version thresholds. Track which clients still send old formats. Dead code from old formats is attack surface.

---

### 10. Repeated Marshall/Unmarshall Pattern

DynamoDB operations across files repeat:

```typescript
Item: marshall(entry, { removeUndefinedValues: true });
// and
const item = unmarshall(result.Item);
```

**Recommendation:** If switching to DocumentClient isn't viable, at least extract `marshallItem(entry)` and `unmarshallItem(item)` helpers that bake in the options. Prevents inconsistent options across call sites.

---

## Refactoring Priority Order

| Priority | Item                                    | Effort  | Impact                                                           |
| -------- | --------------------------------------- | ------- | ---------------------------------------------------------------- |
| 1        | Extract generic batch write utility     | Low     | Removes ~90 lines of duplication, single place to fix retry bugs |
| 2        | Extract payload normalizer from handler | Medium  | Handler becomes reviewable, format changes isolated              |
| 3        | Extract SQS batch processing pattern    | Low     | Consistent error handling, less handler boilerplate              |
| 4        | Split workers.ts construct              | Medium  | IAM changes become safer, files independently reviewable         |
| 5        | Consolidate sleep + small utilities     | Trivial | Prevents further duplication                                     |
| 6        | Split payload-schema.ts                 | Low     | Types, schema, and logic separated                               |
| 7        | Data-driven tier metrics                | Low     | Extensible without code changes                                  |
| 8        | Document compatibility shim expiry      | Trivial | Enables future dead code removal                                 |

---

## What's Already Good

- **Dependency injection** throughout services (testable, mockable)
- **Tiered matching architecture** is well-decomposed by concern
- **Feature flags** for safe rollout (SimHash rollout percent, shadow mode)
- **Anomaly detection** modules are focused and single-purpose
- **Constants centralized** in `src/helpers/constants.ts`
- **Test organization** mirrors source structure
- **CDK stage config** is clean and centralized

---

## Guiding Principle

> Code that doesn't exist is code that isn't vulnerable.

Every duplicated batch-write is a place where a retry bug fix might be applied inconsistently. Every compatibility shim is attack surface that should have an expiry date. Every 600-line file is a file where reviewers miss security-relevant changes buried in noise. Reducing surface area isn't just aesthetics - it's defense.
