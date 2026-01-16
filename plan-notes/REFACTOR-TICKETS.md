# Refactoring Tickets for ms-argus-api

**Generated**: 2026-01-16
**Context**: User override of debate consensus - refactoring NOW while 434 tests provide safety net
**Rationale**: "Everything already works with 434 tests, so now is the time to clean it up."

Note: The FINAL-PLAN.md recommended skipping file splitting (3-0 consensus), but the user has overridden this decision. With comprehensive test coverage in place, this is actually an ideal time for refactoring.

---

## AR-XX: Extract shared bucket key utilities

### Summary

Extract duplicated bucket key building logic from matching-service.ts and profile-service.ts into a shared `src/helpers/bucket-keys.ts` utility module.

### Background

Both `matching-service.ts` and `profile-service.ts` contain nearly identical implementations of bucket key building:

- Tier 2 bucket keys (ip_ja4, gpu_screen_tz, audio_canvas, maths_window, html_css, webgl_struct)
- Session anchor key builders (IP + UA hash + screen_dims)
- IP+UA anchor key builders (IP + UA hash)

This duplication creates maintenance burden and risk of the implementations drifting apart. This ticket is a prerequisite for the larger file splits (AR-XX matching-service split, AR-XX profile-service split) because it extracts shared code that both will depend on.

### Scope

**In scope:**

- Create `src/helpers/bucket-keys.ts` with shared bucket key utilities
- Extract `buildTier2BucketKeys()` implementation
- Extract `buildSessionAnchorKey()` implementation
- Extract `buildIpUaAnchorKey()` implementation
- Update matching-service.ts to import from bucket-keys.ts
- Update profile-service.ts to import from bucket-keys.ts
- Create `src/helpers/bucket-keys.test.ts` with extracted tests

**Not in scope:**

- Changing bucket key formats or structure
- Modifying matching or profile service logic
- Any behavioral changes

### Implementation Hints

**Duplicated code locations:**

- `src/services/matching/matching-service.ts`:
  - `buildBucketKeys()` lines 772-776
  - `buildBucketKeysWithTypes()` lines 782-850 (this is the real implementation)
  - `buildSessionAnchorKey()` lines 539-553
  - `buildIpUaAnchorKey()` lines 622-632
- `src/services/profile/profile-service.ts`:
  - `buildTier2BucketKeys()` lines 640-698
  - `buildSessionAnchorKey()` lines 705-721
  - `buildIpUaAnchorKey()` lines 761-771

**Pattern to follow:**

- See `src/helpers/hash.ts` for how shared utilities are structured
- Both services import `fnv1a` from helpers/hash.ts - same pattern applies here
- The `EvidenceCode` type from `src/services/matching/types.ts` will need to be accessible

**Key decisions:**

- The matching-service version includes evidence code tracking (`buildBucketKeysWithTypes`), the profile-service version does not
- Consider exporting both versions, or having the simple version call the typed version and extract just keys
- The `fnv1a` import for UA hashing should stay in bucket-keys.ts

### Acceptance Criteria

- [ ] AC1: New file `src/helpers/bucket-keys.ts` exists with exported functions
- [ ] AC2: `buildTier2BucketKeys(tenantId, fingerprint)` returns identical bucket keys as current implementations
- [ ] AC3: `buildTier2BucketKeysWithTypes(tenantId, fingerprint)` returns bucket keys with their evidence codes
- [ ] AC4: `buildSessionAnchorKey(tenantId, fingerprint)` returns identical keys as current implementations
- [ ] AC5: `buildIpUaAnchorKey(tenantId, fingerprint)` returns identical keys as current implementations
- [ ] AC6: matching-service.ts imports and uses bucket-keys.ts functions
- [ ] AC7: profile-service.ts imports and uses bucket-keys.ts functions
- [ ] AC8: All 434+ existing tests pass without modification
- [ ] AC9: New bucket-keys.test.ts has tests for all exported functions

### Test Coverage

**Existing tests that exercise this code:**

- `src/services/matching/matching-service.test.ts`:
  - `describe("buildBucketKeys")` lines 378-497 (14 tests)
- `src/services/profile/profile-service.test.ts`:
  - `describe("buildTier2BucketKeys")` lines 347-406 (5 tests)

**Gaps:**

- No dedicated tests for session anchor key building (tested implicitly via anchor lookup tests)
- No dedicated tests for IP+UA anchor key building

### Definition of Done

- [ ] Unit tests pass (`npm test`)
- [ ] No duplicate bucket key logic remains in service files
- [ ] TypeScript compilation succeeds
- [ ] Code reviewed
- [ ] Deployed to dev (`npx cdk deploy ms-argus-api-dev-jw`)
- [ ] Integration tests pass (`cd ~/Dev/ms-argus-automation && npm test`)

### QA Notes

**Verify:**

- Run full test suite - all 434+ tests should pass unchanged
- Compare bucket keys generated before and after refactor for sample fingerprints
- Check that both matching and profile services produce identical bucket keys for same input

**Edge cases:**

- Empty fingerprint (should return empty array)
- Partial fingerprint (missing some signals)
- Fingerprint with all 6 bucket types present

**Risk:**

- Low risk - pure refactoring with comprehensive test coverage

---

## AR-XX: Delete dead code (scoreDeviceCandidates)

### Summary

Remove the unused `scoreDeviceCandidates` method from matching-service.ts to reduce code surface and eliminate maintenance burden.

### Background

The `scoreDeviceCandidates` method (lines 856-874) was superseded by `scoreDeviceCandidatesWithEvidence` (lines 880-928) when AR-54 added evidence code tracking to match results. The old method is no longer called anywhere in the codebase.

This is a simple cleanup ticket with minimal risk.

### Scope

**In scope:**

- Delete the `scoreDeviceCandidates` private method from matching-service.ts

**Not in scope:**

- Any changes to `scoreDeviceCandidatesWithEvidence`
- Any other dead code removal

### Implementation Hints

**Dead code location:**

- `src/services/matching/matching-service.ts` lines 856-874

**Verification:**

- Search codebase for "scoreDeviceCandidates" - should only find the declaration and `scoreDeviceCandidatesWithEvidence`
- Run `grep -r "scoreDeviceCandidates" src/` to confirm no callers

### Acceptance Criteria

- [ ] AC1: Method `scoreDeviceCandidates` is removed from matching-service.ts
- [ ] AC2: Method `scoreDeviceCandidatesWithEvidence` remains unchanged
- [ ] AC3: All 434+ existing tests pass
- [ ] AC4: No grep results for `scoreDeviceCandidates` except the `WithEvidence` variant

### Test Coverage

**Existing tests:**

- No tests directly test `scoreDeviceCandidates` (it's a private method)
- Tests for `tier2CompoundMatch` exercise `scoreDeviceCandidatesWithEvidence`

**Gaps:**

- None (dead code has no test coverage by design)

### Definition of Done

- [ ] Unit tests pass (`npm test`)
- [ ] Dead method removed
- [ ] Deployed to dev
- [ ] Integration tests pass

### QA Notes

**Verify:**

- All tests pass after deletion
- Tier 2 compound matching still works correctly

**Risk:**

- Minimal - deleting clearly dead code

---

## AR-XX: Split matching-service.ts into modules

### Summary

Refactor the 1,068-line matching-service.ts into focused modules: orchestration, tier0-cache, tier05-identity, tier1-hash, tier2-compound, session-anchors, and an index barrel file.

### Background

matching-service.ts has grown to 1,068 lines containing multiple logical concerns:

- Session cache operations
- Tier 0.5 identity lookups (evercookie, sigint, public key)
- Tier 1 hash matching (stable, fuzzy)
- Tier 2 compound bucket matching with cardinality tracking
- Session anchor and IP+UA anchor lookups
- Profile loading and device creation
- Queue operations

Splitting this improves readability, testability, and allows parallel development. With 434 tests providing a safety net, now is the ideal time for this refactoring.

**Dependency:** Requires AR-XX (bucket-keys extraction) to be completed first.

### Scope

**In scope:**

- Create `src/services/matching/` directory structure:
  - `matching-service.ts` (orchestration only, ~200 lines)
  - `tier0-cache.ts` (session cache operations)
  - `tier05-identity.ts` (evercookie, sigint, public key lookups)
  - `tier1-hash.ts` (stable and fuzzy hash matching)
  - `tier2-compound.ts` (bucket matching with cardinality)
  - `session-anchors.ts` (session anchor and IP+UA anchor lookups)
  - `index.ts` (re-exports for backward compatibility)
- Move corresponding tests to match new file structure
- Maintain all public API contracts

**Not in scope:**

- Changing any matching logic or behavior
- Modifying confidence scores or evidence codes
- Changing tier ordering or fallback logic

### Implementation Hints

**Current file sections (approximate line ranges):**

- Lines 1-52: Imports and interfaces
- Lines 63-102: Class declaration, checkCache, applyPrivacyPenalty
- Lines 104-207: `runTieredMatching` (orchestration)
- Lines 209-308: Tier 0.5 lookups (tier05PublicKeyLookup, tier05CookieLookup, tier05SigintIdLookup)
- Lines 310-389: Tier 1 hash matching (tier1HashMatch, lookupTier1Index)
- Lines 391-533: Tier 2 compound matching (tier2CompoundMatchWithTimeout, tier2CompoundMatch, fetchBucketCardinalities, countHighCardinalityBuckets)
- Lines 535-695: Session anchors (buildSessionAnchorKey, sessionAnchorLookup, buildIpUaAnchorKey, ipUaAnchorLookup)
- Lines 697-767: Cardinality helpers (already part of tier2)
- Lines 769-850: Bucket key building (moves to bucket-keys.ts)
- Lines 852-928: Device candidate scoring
- Lines 930-973: loadProfile, createNewDevice
- Lines 975-1047: Cache/queue operations (writeMatchResult, writeDegradedResult, queueProfileUpdate)
- Lines 1049-1068: Utility functions (generateIdempotencyKey, generateUUID)

**Pattern to follow:**

- See how `src/services/cache/index.ts` re-exports from the service file
- Each module should export its class/functions and types
- The main `matching-service.ts` orchestrates by composing other modules

**Test file split:**

- Current: `matching-service.test.ts` (1,590 lines)
- Move tests to match their source file location
- The orchestration tests (runTieredMatching) stay with matching-service.test.ts

### Acceptance Criteria

- [ ] AC1: `src/services/matching/tier0-cache.ts` contains session cache operations
- [ ] AC2: `src/services/matching/tier05-identity.ts` contains evercookie, sigint, public key lookups
- [ ] AC3: `src/services/matching/tier1-hash.ts` contains stable/fuzzy hash matching
- [ ] AC4: `src/services/matching/tier2-compound.ts` contains bucket matching and cardinality logic
- [ ] AC5: `src/services/matching/session-anchors.ts` contains both anchor lookup methods
- [ ] AC6: `src/services/matching/matching-service.ts` is orchestration only (<300 lines)
- [ ] AC7: `src/services/matching/index.ts` re-exports all public APIs (backward compatible imports)
- [ ] AC8: All 434+ existing tests pass without logic changes
- [ ] AC9: Existing imports from `./matching-service` continue to work via index.ts

### Test Coverage

**Existing tests:**

- `matching-service.test.ts` lines 100-129: checkCache tests -> tier0-cache.test.ts
- `matching-service.test.ts` lines 131-286: Tier 0.5 tests -> tier05-identity.test.ts
- `matching-service.test.ts` lines 288-376: Tier 1 tests -> tier1-hash.test.ts
- `matching-service.test.ts` lines 378-786: Tier 2 and bucket tests -> tier2-compound.test.ts
- `matching-service.test.ts` lines 1398-1589: Anchor recency tests -> session-anchors.test.ts
- `matching-service.test.ts` lines 946-1172: runTieredMatching tests -> stays in matching-service.test.ts

**Gaps:**

- None - comprehensive coverage exists, just needs reorganization

### Definition of Done

- [ ] Unit tests pass (`npm test`)
- [ ] No file exceeds 400 lines
- [ ] TypeScript compilation succeeds
- [ ] Imports from `@/services/matching` work unchanged
- [ ] Code reviewed
- [ ] Deployed to dev
- [ ] Integration tests pass

### QA Notes

**Verify:**

- All test suites pass
- Import statements in handlers continue to work
- Each tier's matching behavior is unchanged

**Edge cases:**

- Test each tier in isolation (mock the others)
- Test the full orchestration flow end-to-end

**Risk:**

- Medium - substantial refactor but with strong test coverage

---

## AR-XX: Split profile-service.ts into modules

### Summary

Refactor the 881-line profile-service.ts into focused modules: orchestration, drift-detection, flag-computation, index-writers, and an index barrel file.

### Background

profile-service.ts has grown to 881 lines containing multiple logical concerns:

- Mutation gate management
- Profile loading and updating
- Drift detection
- Bot signal detection
- Flag computation
- Risk score computation
- Tier 1 index writing (with batch retry logic)
- Tier 2 bucket writing (with batch retry logic and cardinality tracking)
- Session anchor and IP+UA anchor bucket writing

Splitting this improves readability and allows parallel development. The 434 tests provide confidence for safe refactoring.

**Dependency:** Requires AR-XX (bucket-keys extraction) to be completed first.

### Scope

**In scope:**

- Create `src/services/profile/` directory structure:
  - `profile-service.ts` (orchestration only, ~250 lines)
  - `drift-detection.ts` (hasSignificantDrift, profile comparison)
  - `flag-computation.ts` (detectBotSignals, computeFlags, computeRiskScore)
  - `index-writers.ts` (Tier 1, Tier 2, anchor bucket writers with retry logic)
  - `index.ts` (re-exports for backward compatibility)
- Move corresponding tests to match new file structure
- Maintain all public API contracts

**Not in scope:**

- Changing any profile update logic or behavior
- Modifying risk score calculations
- Changing flag computation rules

### Implementation Hints

**Current file sections (approximate line ranges):**

- Lines 1-75: Imports, constants, interfaces
- Lines 77-114: Class declaration, tryAcquireMutationGate, loadExistingProfile
- Lines 116-137: hasSignificantDrift -> drift-detection.ts
- Lines 139-232: detectBotSignals, computeFlags -> flag-computation.ts
- Lines 234-286: computeRiskScore -> flag-computation.ts
- Lines 288-346: updateProfile
- Lines 348-431: Tier 1 index writing (updateTier1Indexes, batchWriteTier1Indexes, buildTier1IndexEntries) -> index-writers.ts
- Lines 433-635: Tier 2 bucket writing (updateTier2Buckets, incrementBucketCardinalities, batchWriteTier2Buckets, buildTier2BucketKeys) -> index-writers.ts
- Lines 637-804: Session anchor methods (buildSessionAnchorKey, updateSessionAnchorBucket, buildIpUaAnchorKey, updateIpUaAnchorBucket) -> index-writers.ts
- Lines 806-881: processProfileUpdate (orchestration)

**Constants to extract:**

- Lines 28-31: FLAG_THRESHOLDS
- Lines 37-54: RISK_WEIGHTS

These could go in flag-computation.ts or a shared constants file.

**Pattern to follow:**

- Similar to matching-service split
- Each module exports its functions and constants
- The main profile-service.ts orchestrates

**Test file split:**

- Current: `profile-service.test.ts` (1,245 lines)
- Move tests to match their source file location

### Acceptance Criteria

- [ ] AC1: `src/services/profile/drift-detection.ts` contains drift detection logic
- [ ] AC2: `src/services/profile/flag-computation.ts` contains bot detection, flag computation, and risk scoring
- [ ] AC3: `src/services/profile/index-writers.ts` contains all index/bucket write operations
- [ ] AC4: `src/services/profile/profile-service.ts` is orchestration only (<300 lines)
- [ ] AC5: `src/services/profile/index.ts` re-exports all public APIs
- [ ] AC6: All 434+ existing tests pass without logic changes
- [ ] AC7: Existing imports from `./profile-service` continue to work via index.ts

### Test Coverage

**Existing tests:**

- `profile-service.test.ts` lines 154-232: hasSignificantDrift tests -> drift-detection.test.ts
- `profile-service.test.ts` lines 893-973: detectBotSignals tests -> flag-computation.test.ts
- `profile-service.test.ts` lines 975-1113: computeFlags tests -> flag-computation.test.ts
- `profile-service.test.ts` lines 1115-1243: computeRiskScore tests -> flag-computation.test.ts
- `profile-service.test.ts` lines 234-345: buildTier1IndexEntries tests -> index-writers.test.ts
- `profile-service.test.ts` lines 347-763: Tier 2 bucket tests -> index-writers.test.ts
- `profile-service.test.ts` lines 765-891: processProfileUpdate tests -> stays in profile-service.test.ts

**Gaps:**

- None - comprehensive coverage exists

### Definition of Done

- [ ] Unit tests pass (`npm test`)
- [ ] No file exceeds 400 lines
- [ ] TypeScript compilation succeeds
- [ ] Imports from `@/services/profile` work unchanged
- [ ] Code reviewed
- [ ] Deployed to dev
- [ ] Integration tests pass

### QA Notes

**Verify:**

- All test suites pass
- Flag computation produces same results
- Risk scores are calculated identically
- Profile updates work end-to-end

**Edge cases:**

- New device with no existing profile
- Device with drift detection triggering
- Bot detection with various fingerprints
- Batch write retries under simulated throttling

**Risk:**

- Medium - substantial refactor but with strong test coverage

---

## Ticket Dependency Graph

```
AR-XX: Extract bucket-keys utilities
         |
         +--------------------+
         |                    |
         v                    v
AR-XX: Split matching    AR-XX: Split profile
       service                  service
```

**Recommended execution order:**

1. AR-XX: Extract bucket-keys (prerequisite, ~1 hour)
2. AR-XX: Delete dead code (independent, ~5 min)
3. AR-XX: Split matching-service (depends on #1, ~3-4 hours)
4. AR-XX: Split profile-service (depends on #1, ~2-3 hours)

#3 and #4 can be done in parallel after #1 is complete.

---

## Risk Assessment

| Risk                                | Mitigation                                           |
| ----------------------------------- | ---------------------------------------------------- |
| Merge conflicts if done in parallel | Coordinate bucket-keys extraction first              |
| Import path breakage                | Use index.ts barrel files for backward compatibility |
| Test flakiness during transition    | Run full test suite at each step                     |
| Runtime type errors                 | TypeScript compiler will catch these                 |

**Overall risk: LOW** - 434 tests provide comprehensive safety net. Pure refactoring with no behavioral changes.

---

_Tickets generated by TICKET-WRITER persona based on codebase exploration._
