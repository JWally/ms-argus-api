# Codebase Cleanup Plan

Goal: Enterprise-grade, minimalist, DRY, portfolio-ready.

---

## Phase 1: Remove Dead Weight

The fastest wins. Delete things that serve no purpose.

### 1.1 Delete `src/helpers/misc.ts` entirely

`flattenObject` and `getCurrentDateInfo` are never used in production. Only imported by their own test file. Delete both the source and its test.

### 1.2 Purge unused exports from `src/helpers/constants.ts`

Remove these (none are used in production code):

| Export                                    | Why it's dead                                  |
| ----------------------------------------- | ---------------------------------------------- |
| `SECURITY_KEY_NAME`                       | Never imported anywhere                        |
| `DEFAULT_HEADERS`                         | Only in constants.test.ts                      |
| `ALLOWED_HEADERS`                         | Only feeds `MIDDY_CORS_CONFIG` which is unused |
| `parseAllowedOrigins` / `ALLOWED_ORIGINS` | Same                                           |
| `MIDDY_CORS_CONFIG`                       | Custom CORS middleware is used instead         |
| `WARMUP_EVENT`                            | Only in constants.test.ts                      |
| `POWERTOOLS_METRICS_NAMESPACE`            | Handlers read `process.env` directly           |
| `POWERTOOLS_SERVICE_NAME`                 | Same                                           |

Also remove the `import { Options } from "@middy/http-cors"` at the top since nothing will use it.

### 1.3 Delete `sessionResponseJsonSchema` from `src/helpers/payload-schema.ts`

70 lines of JSON schema that is never used for validation. The `validateSessionResponse()` function does it manually. Keep only one approach (the function is fine).

### 1.4 Remove `generateULID()` wrapper

`src/services/matching/matching-service.ts:412-414` -- this wraps `ulid()` with zero added logic. Inline `ulid()` at the call site (line 326). Delete the exported function and its comment block.

### 1.5 Remove `buildTier2BucketKeys` alias

`src/helpers/bucket-keys.ts:100-104` -- `export const buildTier2BucketKeys = buildBucketKeys` is a "refactor compatibility" alias. Find all usages, change them to `buildBucketKeys`, delete the alias.

### 1.6 Clean up `package.json` dependencies

**Move to `devDependencies`:**

- `aws-sdk-client-mock` (test-only)
- `@typescript-eslint/eslint-plugin` (lint-only)

**Remove entirely:**

- `http-errors` (replaced by custom `HttpError`, never imported)
- `@types/http-errors` (companion types for unused package)
- `@middy/http-cors` (custom CORS middleware used instead)
- `@middy/http-error-handler` (custom `jsonErrorHandler` used instead)
- `@middy/http-json-body-parser` (ingestion does its own parsing)
- `@aws-sdk/client-sns` (only CDK uses SNS, SDK client not needed at runtime)

### 1.7 Remove `isWarmingUp` from `src/helpers/middy-helpers.ts`

Only used in tests. Handlers use `@middy/warmup` directly.

### 1.8 Unexport `buildCorsHeaders` from `src/helpers/cors-middleware.ts`

Used only internally by `corsMiddleware`. Remove the `export` keyword.

### 1.9 Remove `registerDetector` and `getDetectorCount` exports

`src/services/profile/anomaly/detector.ts` -- only called in tests. If tests need them, tests can import from a test helper or access the internal array directly. These are not part of the public API.

---

## Phase 2: Strip All Ticket-Reference Comments

Every comment matching `AR-\d+:` or `AR-XXX:` gets deleted. These are changelog entries, not documentation. The git history exists for a reason.

There are 50+ instances across the codebase. Examples:

```
// AR-119: Refactored to orchestration only - delegates to tier modules
// AR-121: Replaced UUID with ULID for time-sortable device IDs
// AR-XXX: Added fuzzy_match_info for drift detection
// AR-52: Replaced Redis with DynamoDB session cache
// AR-65: Apply confidence penalty for privacy browser detection
```

**Rule going forward:** Comments explain _why_ something is non-obvious, never _when_ or _what ticket_.

Exceptions: Keep a comment only if the ticket reference is removed but the _explanation_ remains useful. For example:

```typescript
// Before:
/** AR-82: Session anchor DynamoDB cleanup TTL: 1 hour (3600 seconds)
 * DynamoDB TTL is eventually consistent, so we set a longer TTL for cleanup
 * while enforcing the actual validity window in application code */

// After:
/** DynamoDB TTL is eventually consistent -- set cleanup TTL (1hr) longer
 * than the validity window (10min) which is enforced in application code */
```

---

## Phase 3: Consolidate DRY Violations

### 3.1 Extract `computeFuzzyMatchInfo` to a shared utility

Identical function exists in both `tier05-identity.ts` and `tier1-hash.ts`. Move to `src/helpers/hash.ts` (next to `hammingDistance` which it uses) and import from both.

### 3.2 Consolidate Tier 0.5 lookups into a single parameterized function

`tier05PublicKeyLookup`, `tier05CookieLookup`, `tier05SigintIdLookup` are structurally identical. The only differences:

| Function  | Key prefix    | Confidence | Evidence code      |
| --------- | ------------- | ---------- | ------------------ |
| PublicKey | `pubkey#`     | 0.99       | `PUBLIC_KEY_MATCH` |
| Cookie    | `evercookie#` | 0.99       | `EVERCOOKIE_MATCH` |
| SigintId  | `sigint#`     | 0.98       | `SIGINT_ID_MATCH`  |

Consolidate to:

```typescript
interface IdentityLookupConfig {
  prefix: string;
  confidence: number;
  evidenceCode: EvidenceCode;
}

async function identityLookup(
  deps: Tier05IdentityDeps,
  id: string,
  config: IdentityLookupConfig,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> { ... }

// Then export thin wrappers or just call identityLookup directly from matching-service
```

File drops from 157 lines to ~60.

### 3.3 Unify environment configuration

Three patterns exist for env config:

1. `src/config/env.ts` -- `getMatchingWorkerEnv()` / `getProfileUpdaterEnv()`
2. `src/helpers/env-validation.ts` -- `validateRequiredEnvVars()`
3. Inline in handlers -- ad hoc `getConfig()` functions

Consolidate into a single pattern. `src/config/env.ts` should be the only source of env configs. Each handler gets a typed config function there. Delete `src/helpers/env-validation.ts` and the inline `getConfig()` blocks in `session-get.ts` and `cardinality-recalc.ts`.

### 3.4 Standardize error creation

Two patterns: `createError(status, message)` factory and `new HttpError(status, message)`. Pick one (the constructor is simpler), remove `createError`.

---

## Phase 4: Flatten Unnecessary Indirection

### 4.1 Remove delegate methods from `MatchingService`

Lines 247-322 are 12 methods that do nothing but forward to the tier module functions. They exist for "backward compatibility" but `runTieredMatching()` calls the functions directly -- these methods are never called in production.

If tests use them, update tests to call the module functions directly (they're already exported).

### 4.2 Remove delegate methods from `ProfileService`

Same pattern. Methods like:

```typescript
hasSignificantDrift(existing, incoming) { return hasSignificantDrift(existing, incoming); }
detectBotSignals(fingerprint) { return detectBotSignals(fingerprint); }
```

These pass-throughs add cognitive overhead. The class should only contain methods that use `this.deps`. Everything else is already an importable module function.

### 4.3 Flatten `buildBucketKeys` import alias

`matching-service.ts` does:

```typescript
import { buildBucketKeys as buildBucketKeysHelper } from "../../helpers/bucket-keys";
```

Then wraps it in a class method. Just import it with its original name and call it directly where needed.

---

## Phase 5: Remove Obvious/Noise Comments

Delete comments that restate what the code already says:

```typescript
// DELETE: /** DynamoDB-based session cache service */
export class DynamoCacheService { ... }

// DELETE: /** Check if session is already cached */
async checkCache(sessionId: string) { ... }

// DELETE: /** Dependencies for tier 0 cache operations */
export interface Tier0CacheDeps { ... }

// DELETE: /** Configuration for the matching service */
export interface MatchingServiceConfig { ... }

// DELETE: /** Load existing device profile from DynamoDB */
async loadExistingProfile() { ... }
```

**Keep** comments that explain non-obvious decisions (TTL choices, penalty rationale, DynamoDB consistency quirks).

---

## Phase 6: Trim Remaining Bloat

### 6.1 Simplify `validateSessionResponse`

50 lines of manual field validation. Consider replacing with a simple type guard + assertion:

```typescript
export function validateSessionResponse(response: unknown): SessionResponse {
  const obj = response as SessionResponse;
  if (!obj?.identifiers?.session_id) {
    throw new Error("Invalid session response: missing identifiers.session_id");
  }
  return obj;
}
```

The full validation was presumably for an external API boundary. If it still is, keep it but consolidate the repetitive `if (!field) throw` pattern into a loop. If it's internal-only, the type system handles it.

### 6.2 Remove section-banner comments from constants.ts

```typescript
// ==================== CACHE & TTL CONSTANTS ====================
// ==================== FNV-1A HASH CONSTANTS ====================
// ==================== MATCHING SERVICE CONSTANTS ====================
```

The file is 218 lines. These banners are for 2000-line files. Let the grouping speak for itself.

### 6.3 Reduce file count in `src/services/profile/anomaly/`

5 files for anomaly detection (`detector.ts`, `quick-wins.ts`, `cross-field.ts`, `network.ts`, `types.ts`). The detector imports from the other 3 and they're all small. Consider merging `quick-wins.ts`, `cross-field.ts`, and `network.ts` into `detector.ts` -- or at minimum merge them into a single `checks.ts`. The individual files are 30-50 lines each.

---

## Phase 7: Consistency Pass

### 7.1 Event types

`middy-helpers.ts` uses `APIGatewayProxyEvent` (REST API v1) but the actual handlers use `APIGatewayProxyEventV2` (HTTP API v2). Fix to v2 if the v1 types are vestigial.

### 7.2 Logger/Metrics initialization

Every handler repeats:

```typescript
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});
```

Consider a single factory in `src/config/observability.ts`:

```typescript
export function createObservability(config: EnvConfig) {
  return {
    logger: new Logger({ serviceName: config.POWERTOOLS_SERVICE_NAME }),
    metrics: new Metrics({ namespace: config.POWERTOOLS_METRICS_NAMESPACE }),
  };
}
```

Not critical, but it's 8 duplicated instantiation blocks.

---

## Execution Order

| Order | Phase                     | Risk | Effort |
| ----- | ------------------------- | ---- | ------ |
| 1     | Phase 1 (dead code)       | None | Low    |
| 2     | Phase 2 (ticket comments) | None | Low    |
| 3     | Phase 5 (noise comments)  | None | Low    |
| 4     | Phase 3 (DRY)             | Low  | Medium |
| 5     | Phase 4 (indirection)     | Low  | Medium |
| 6     | Phase 6 (bloat)           | Low  | Low    |
| 7     | Phase 7 (consistency)     | Low  | Low    |

Run tests after each phase. Nothing here changes behavior -- it's all structural. If tests break, they're testing internal wrappers that no longer exist, and those tests should be updated to test the actual module functions.

---

## Estimated Line Reduction

| Phase                       | Lines removed  |
| --------------------------- | -------------- |
| Phase 1 (dead code + deps)  | ~300           |
| Phase 2 (ticket comments)   | ~80            |
| Phase 3 (DRY consolidation) | ~120           |
| Phase 4 (delegate methods)  | ~100           |
| Phase 5 (noise comments)    | ~40            |
| Phase 6 (bloat/banners)     | ~60            |
| **Total**                   | **~700 lines** |

That's roughly 5% of the codebase removed with zero behavior change. What remains will be tighter, consistent, and self-documenting.
