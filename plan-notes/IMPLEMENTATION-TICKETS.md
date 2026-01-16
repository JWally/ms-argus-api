# Implementation Tickets for ms-argus-api

**Generated**: 2026-01-16
**Context**: Implementation items from FINAL-PLAN.md (multi-perspective debate outcome)
**Total Effort**: ~14 hours across all priorities

Note: Refactoring tickets (file splits, bucket-keys extraction, scoreDeviceCandidates deletion) are in REFACTOR-TICKETS.md. This file contains the remaining implementation work.

---

## P0: Do Today (3.5 hours)

These tickets represent critical correctness and safety fixes that should be completed immediately.

---

### AR-XX: Fix ULID bug and add DEVICE_ID_FORMAT metric

#### Summary

Replace `randomUUID()` with `ulid()` for device ID generation to fix session anchor query returning random devices instead of most recent. Add DEVICE_ID_FORMAT metric to track migration from UUID to ULID format.

#### Background

Session anchor queries return the wrong "most recent" device because device IDs use random UUIDs that don't sort by creation time. When we query with `Limit: 10`, we get 10 random devices by alphabet, not by time. The session anchor lookup (lines 569-593 of matching-service.ts) tries to sort by `created_at` but this only works if we can get recent entries - with random UUIDs, we might miss the actual most recent device entirely.

ULID (Universally Unique Lexicographically Sortable Identifier) encodes timestamp in the first 10 characters, making IDs sortable by creation time. This means queries with `ScanIndexForward: false` will naturally return most recent devices first.

**Risk exposure**: ~$3M fraud liability from incorrect device matching per FINAL-PLAN.md.

#### Scope

**In scope:**

- Change device ID generation from `randomUUID()` to `ulid()`
- Update session anchor query to use `ScanIndexForward: false`
- Add DEVICE_ID_FORMAT metric with dimension `ulid` or `uuid`
- Ensure device ID format remains `dev_[ID]` (just the ID portion changes)

**Not in scope:**

- Migrating existing device IDs (old UUIDs will coexist with new ULIDs)
- Changing any other ID formats in the system
- Backfilling historical data

#### Implementation Hints

**Device ID generation:**

- `src/services/matching/matching-service.ts` line 963-964 in `createNewDevice()`:
  ```typescript
  const deviceId = `dev_${generateUUID()}`;
  ```
- `src/services/matching/matching-service.ts` lines 1062-1068 `generateUUID()` function

**Session anchor query:**

- `src/services/matching/matching-service.ts` lines 569-580 - add `ScanIndexForward: false`

**ULID library:**

- Check package.json for `ulid` - if not present: `npm install ulid`
- ULID import: `import { ulid } from 'ulid'`

**Metrics pattern:**

- See `src/handlers/matching-worker.ts` lines 41-43 and 91-97 for Metrics usage pattern
- Use `metrics.addMetric("DEVICE_ID_FORMAT", MetricUnit.Count, 1, { format: "ulid" })`

#### Acceptance Criteria

- [ ] AC1: New devices have IDs in format `dev_[ULID]` (26 alphanumeric chars after `dev_`)
- [ ] AC2: Session anchor query uses `ScanIndexForward: false`
- [ ] AC3: Session anchor returns actual most recent device within validity window
- [ ] AC4: DEVICE_ID_FORMAT metric emitted with dimension `format: ulid`
- [ ] AC5: Old `dev_[uuid]` format devices still work (backward compatible)
- [ ] AC6: ULID IDs sort lexicographically by creation time

#### Test Coverage

**Existing tests:**

- `src/services/matching/matching-service.test.ts` - session anchor tests (will need update)
- Device ID format validation tests exist

**Gaps:**

- No test verifying time-ordering of returned devices
- No test for mixed UUID/ULID coexistence
- Add test: create 3 devices in sequence, verify session anchor returns most recent

#### Definition of Done

- [ ] Unit tests pass (`npm test`)
- [ ] New tests added for time-ordering verification
- [ ] ULID library added to dependencies
- [ ] Deployed to dev (`npx cdk deploy ms-argus-api-dev-jw`)
- [ ] Integration tests pass (`cd ~/Dev/ms-argus-automation && npm test`)
- [ ] DEVICE_ID_FORMAT metric visible in CloudWatch

#### QA Notes

**Verify:**

- Create 3 devices in sequence with known timestamps
- Query session anchor, confirm order matches creation time (most recent first)
- Create device with old UUID format (if possible in test), verify it still resolves
- Check CloudWatch for DEVICE_ID_FORMAT metric with correct dimensions

**Edge cases:**

- Session anchor with mix of old UUID and new ULID format devices
- Boundary case: very close timestamps (within same millisecond)
- Empty session anchor bucket

**Risk:** Medium - core matching logic change but with strong test coverage

---

### AR-XX: Add tenant isolation guard for production

#### Summary

Make the "default" tenant fallback throw an error in production instead of silently accepting requests, preventing cross-tenant data leakage.

#### Background

Currently, when no `x-tenant-id` header is provided and no API key is present, the system falls back to `"default"` tenant:

- `src/handlers/ingestion.ts` line 242: `tenantId = event.headers["x-tenant-id"] ?? "default"`
- `src/helpers/middy-helpers.ts` line 75: `const tenantId = event.headers["x-tenant-id"] ?? "default"`

In production, this is dangerous - it means misconfigured clients silently merge their data into a shared "default" tenant, causing data leakage and corruption of fraud signals.

**Risk exposure**: Unbounded data breach potential per FINAL-PLAN.md.

#### Scope

**In scope:**

- Add environment check for production (use `ENVIRONMENT` env var)
- Throw 401 error if tenant resolution falls back to "default" in production
- Log warning in non-production when falling back to default tenant
- Add metric for tenant fallback events

**Not in scope:**

- Changing tenant resolution logic for API key authenticated requests
- Modifying tenant data structures
- Multi-tenant data migration

#### Implementation Hints

**Tenant fallback locations:**

- `src/handlers/ingestion.ts` lines 232-243 - tenant extraction logic
- `src/helpers/middy-helpers.ts` lines 72-80 - tenant middleware

**Environment detection:**

- `ENVIRONMENT` env var is set in Lambda configuration
- `lib/constructs/workers.ts` lines 120, 178: `ENVIRONMENT: stage`
- Check against `"prod"` or `"production"` values

**Pattern to follow:**

- See existing error handling in `src/handlers/ingestion.ts` lines 237-240 for API key errors
- Use `createError(401, "Missing required tenant identification")` pattern

**Metrics:**

- Add `TenantFallbackToDefault` metric for monitoring
- In prod, this should be 0; any non-zero indicates configuration issues

#### Acceptance Criteria

- [ ] AC1: In production (`ENVIRONMENT === "prod"` or `"production"`), missing tenant throws 401
- [ ] AC2: In non-production, missing tenant still falls back to "default" (backward compatible)
- [ ] AC3: Warning logged when falling back to default tenant in non-prod
- [ ] AC4: `TenantFallbackToDefault` metric emitted on fallback
- [ ] AC5: Error message is clear: "Missing required tenant identification"
- [ ] AC6: API key authenticated requests unaffected (they resolve tenant from key)

#### Test Coverage

**Existing tests:**

- `src/helpers/middy-helpers.test.ts` line 319: test for default tenant fallback
- `src/handlers/ingestion.test.ts` - ingestion handler tests

**Gaps:**

- No test for production environment behavior
- Add tests with `ENVIRONMENT=prod` mocked

#### Definition of Done

- [ ] Unit tests pass (`npm test`)
- [ ] New tests for production tenant guard
- [ ] Code reviewed
- [ ] Deployed to dev (should still allow default tenant)
- [ ] Integration tests pass
- [ ] Manual verification: prod behavior blocks default tenant

#### QA Notes

**Verify:**

- In dev: request without tenant header returns 204 (falls back to default)
- Simulate prod: request without tenant header returns 401
- API key authenticated request works in both environments
- Check CloudWatch for TenantFallbackToDefault metric

**Edge cases:**

- Empty string tenant header (should treat as missing)
- Whitespace-only tenant header
- Request with valid API key but also x-tenant-id header (API key should win)

**Risk:** Low - defensive guard, easily reverted

---

### AR-XX: Enable X-Ray tracing

#### Summary

Enable AWS X-Ray tracing for Lambda workers to gain visibility into request flows, latency breakdown, and error sources.

#### Background

X-Ray tracing is currently disabled in workers.ts:

```typescript
tracing: Tracing.DISABLED,  // line 91
```

This was likely disabled during development to reduce costs and noise. For production readiness, tracing provides critical observability:

- End-to-end latency breakdown (SQS -> Lambda -> DynamoDB)
- Error source identification
- Service map visualization
- Cold start vs warm start analysis

**Cost**: ~$2,400/year at current volume per FINAL-PLAN.md. Worth it for production debugging capability.

#### Scope

**In scope:**

- Change `tracing: Tracing.DISABLED` to `Tracing.ACTIVE` in workers.ts
- Verify X-Ray permissions are in place (should be automatic with CDK)

**Not in scope:**

- Custom X-Ray segments or annotations
- Sampling rate configuration (use defaults)
- X-Ray daemon configuration

#### Implementation Hints

**File to modify:**

- `lib/constructs/workers.ts` line 91:
  ```typescript
  tracing: Tracing.DISABLED,  // Change to Tracing.ACTIVE
  ```

**CDK import already present:**

- Line 6: `import { Runtime, Tracing, Architecture, Alias } from "aws-cdk-lib/aws-lambda";`

**Verification:**

- After deploy, check Lambda console -> Configuration -> Monitoring and operations tools
- X-Ray should show "Active tracing: Enabled"

#### Acceptance Criteria

- [ ] AC1: `workers.ts` has `tracing: Tracing.ACTIVE` in commonConfig
- [ ] AC2: Both matchingWorker and profileUpdater have X-Ray tracing enabled
- [ ] AC3: X-Ray service map shows Lambda -> DynamoDB connections
- [ ] AC4: Traces visible in X-Ray console within 5 minutes of request
- [ ] AC5: No IAM permission errors in Lambda logs

#### Test Coverage

**Existing tests:**

- This is infrastructure config, no unit tests needed
- CDK synth will validate configuration

**Gaps:**

- None - configuration change only

#### Definition of Done

- [ ] `tracing: Tracing.ACTIVE` committed
- [ ] CDK synth succeeds
- [ ] Deployed to dev
- [ ] X-Ray traces visible in console
- [ ] Integration tests pass (no regression)

#### QA Notes

**Verify:**

- Send test request through ingestion pipeline
- Open X-Ray console, verify trace appears
- Check service map shows all components
- Verify no performance regression (X-Ray adds ~1-2ms overhead)

**Risk:** Minimal - standard AWS feature, easily reverted

---

### AR-XX: Add NEW_DEVICE_RATE metric and alarm

#### Summary

Add a CloudWatch metric that fires when `is_new_device` is true, with an alarm for unusual spikes that may indicate fraud attacks or system issues.

#### Background

When the system cannot match a fingerprint to any existing device, it creates a new device ID and sets `is_new_device: true`. A sudden spike in new device creation could indicate:

- Bot attack generating synthetic fingerprints
- Fingerprint library bug causing unique IDs every request
- Data corruption in matching tables
- Legitimate traffic surge from new customer onboarding

Currently we track `NewDevice` metric in `matching-worker.ts` line 218, but there's no alarm on it. Adding an alarm provides early warning of anomalies.

#### Scope

**In scope:**

- Verify `NewDevice` metric is being emitted (already exists in code)
- Add CloudWatch alarm for new device rate spike
- Configure alarm threshold based on baseline (suggest: >20% new device rate over 5 minutes)
- Wire alarm to existing SNS alarms topic

**Not in scope:**

- Changing new device creation logic
- Auto-remediation actions
- Per-tenant new device tracking (can be added later)

#### Implementation Hints

**Existing metric emission:**

- `src/handlers/matching-worker.ts` lines 216-218:
  ```typescript
  if (isNewDevice) {
    metrics.addMetric("NewDevice", MetricUnit.Count, 1);
  }
  ```

**Alarm pattern to follow:**

- `lib/constructs/workers.ts` lines 282-292 for error alarm pattern
- Use `fn.metric("NewDevice", ...)` or custom metric

**CDK alarm configuration:**

```typescript
new cloudwatch.Alarm(this, "NewDeviceRateAlarm", {
  metric: new cloudwatch.Metric({
    namespace: stackName,
    metricName: "NewDevice",
    statistic: "Sum",
    period: Duration.minutes(5),
  }),
  threshold: 1000, // Adjust based on baseline
  evaluationPeriods: 2,
  alarmDescription:
    "High rate of new device creation - possible attack or system issue",
});
```

**Threshold guidance:**

- Check CloudWatch for current baseline NewDevice rate
- Set threshold at 2-3x normal rate
- Start conservative (higher threshold) and tune down

#### Acceptance Criteria

- [ ] AC1: `NewDevice` metric is emitted when `is_new_device: true` (verify existing)
- [ ] AC2: CloudWatch alarm exists for NewDevice rate
- [ ] AC3: Alarm triggers when new device rate exceeds threshold
- [ ] AC4: Alarm sends notification to existing alarms SNS topic
- [ ] AC5: Alarm has clear description explaining what it means

#### Test Coverage

**Existing tests:**

- `matching-worker.ts` tests cover metric emission
- CDK synth validates alarm configuration

**Gaps:**

- No integration test for alarm triggering (manual verification)

#### Definition of Done

- [ ] Alarm configured in CDK
- [ ] CDK synth succeeds
- [ ] Deployed to dev
- [ ] Alarm visible in CloudWatch console
- [ ] Integration tests pass
- [ ] Document threshold rationale in PR

#### QA Notes

**Verify:**

- NewDevice metric appears in CloudWatch Metrics
- Alarm shows in CloudWatch Alarms (state: OK or INSUFFICIENT_DATA initially)
- Manually trigger alarm by sending many unique fingerprints (if safe in dev)
- Verify SNS notification arrives

**Edge cases:**

- First deployment: alarm may be in INSUFFICIENT_DATA until enough data points
- Low traffic periods may not trigger even at low thresholds

**Risk:** Low - observability addition, no business logic change

---

## P1: This Week (1 hour)

These tickets clean up technical debt with minimal risk.

---

### AR-XX: Delete dead dependencies

#### Summary

Remove unused npm dependencies that were left behind from architecture changes (AR-52 removed Redis, other AWS SDK clients are unused).

#### Background

The `package.json` contains several dependencies that are no longer used:

- `ioredis` and `ioredis-mock`: AR-52 replaced Redis with DynamoDB session cache
- `@aws-sdk/client-ec2`, `@aws-sdk/client-ecs`, `@aws-sdk/client-elastic-load-balancing-v2`, `@aws-sdk/client-elasticache`: Infrastructure clients not used in application code

These add to bundle size, dependency audit noise, and potential security vulnerability surface.

#### Scope

**In scope:**

- Run `npm uninstall ioredis ioredis-mock @aws-sdk/client-ec2 @aws-sdk/client-ecs @aws-sdk/client-elastic-load-balancing-v2 @aws-sdk/client-elasticache`
- Verify no imports reference these packages
- Run full test suite to confirm no breakage

**Not in scope:**

- Removing any other dependencies
- Updating remaining dependency versions

#### Implementation Hints

**Verification before removal:**

```bash
# Check for any imports of these packages
grep -r "ioredis" src/
grep -r "client-ec2\|client-ecs\|client-elastic-load\|client-elasticache" src/
```

**Current package.json locations:**

- `ioredis`: line 88 (dependencies)
- `ioredis-mock`: line 60 (devDependencies)
- `@types/ioredis-mock`: line 49 (devDependencies)
- AWS SDK clients: lines 43-46 (devDependencies)

**Removal command:**

```bash
npm uninstall ioredis @types/ioredis-mock ioredis-mock @aws-sdk/client-ec2 @aws-sdk/client-ecs @aws-sdk/client-elastic-load-balancing-v2 @aws-sdk/client-elasticache
```

#### Acceptance Criteria

- [ ] AC1: `ioredis` removed from package.json
- [ ] AC2: `ioredis-mock` and `@types/ioredis-mock` removed from package.json
- [ ] AC3: Unused AWS SDK clients removed from package.json
- [ ] AC4: No grep results for removed package imports in `src/`
- [ ] AC5: `npm test` passes (all 434+ tests)
- [ ] AC6: `npm ci && npm run build` succeeds

#### Test Coverage

**Existing tests:**

- Full test suite must pass
- No specific tests for dependencies themselves

**Gaps:**

- None - if tests pass, dependencies weren't needed

#### Definition of Done

- [ ] Dependencies removed from package.json
- [ ] `npm ci` succeeds (lock file updated)
- [ ] Unit tests pass
- [ ] Build succeeds
- [ ] Deployed to dev
- [ ] Integration tests pass

#### QA Notes

**Verify:**

- `npm ls ioredis` returns "not found" or empty
- No runtime errors in Lambda logs
- Package size reduced (check bundle size before/after if desired)

**Risk:** Minimal - if tests pass, dependencies weren't used

---

### AR-XX: Delete Go ingestion service

#### Summary

Remove the legacy Go ingestion service (`cmd/ingestion/`) and associated npm scripts after verifying CI/CD doesn't reference it.

#### Background

AR-52 replaced the Go/ECS ingestion service with a Lambda-based ingestion handler (`src/handlers/ingestion.ts`). The Go code in `cmd/ingestion/` is no longer deployed or used, but remains in the repository along with npm scripts that reference it.

**Current Go-related npm scripts** (package.json lines 17-34):

- `test:go`, `test:go:coverage`, `test:go:json`, `test:go:bench`
- `format:go`, `format:go:check`
- `lint:go`, `lint:go:fix`
- `go:build`, `go:build:docker`, `go:deps`, `go:tools`, `go:security`, `go:vuln`

#### Scope

**In scope:**

- Verify CI/CD pipelines don't reference Go service (10-minute grep)
- Delete `cmd/ingestion/` directory
- Remove Go-related npm scripts from package.json
- Update composite scripts that reference Go (e.g., `test:all`, `format`, `lint:fix`)

**Not in scope:**

- Any changes to the TypeScript ingestion handler
- Changes to ECS infrastructure (already removed by AR-52)

#### Implementation Hints

**CI/CD verification:**

```bash
# Check GitHub Actions workflows
grep -r "go\|golang\|cmd/ingestion" .github/
# Check any buildspec files
grep -r "go\|golang\|cmd/ingestion" buildspec* 2>/dev/null
# Check CDK for any Go references
grep -r "cmd/ingestion\|go build\|go test" lib/
```

**Directory to delete:**

- `cmd/ingestion/` (entire directory)

**Scripts to remove from package.json:**

- Lines 17-20: `test:go*` scripts
- Lines 21-24: `format:go*` scripts
- Lines 25-28: `lint:go*` scripts
- Lines 29-34: `go:*` scripts

**Scripts to update:**

- Line 16: `test:all` - remove `&& npm run test:go:coverage`
- Line 21: `format` - remove `&& npm run format:go`
- Line 22: `format:check` - remove `&& npm run format:go:check`
- Line 25: `lint:fix` - remove `&& npm run lint:go:fix`
- Line 26: `lint:test` - remove `&& npm run lint:go`

#### Acceptance Criteria

- [ ] AC1: No CI/CD references to Go service found (or addressed if found)
- [ ] AC2: `cmd/ingestion/` directory deleted
- [ ] AC3: All `go:*`, `test:go*`, `format:go*`, `lint:go*` scripts removed
- [ ] AC4: Composite scripts updated to remove Go references
- [ ] AC5: `npm test` still works (434+ tests pass)
- [ ] AC6: `npm run format` and `npm run lint:test` work without Go

#### Test Coverage

**Existing tests:**

- All TypeScript tests unaffected
- Go tests will be removed with the code

**Gaps:**

- None - removing dead code

#### Definition of Done

- [ ] CI/CD verification completed (document findings)
- [ ] Go directory deleted
- [ ] package.json updated
- [ ] Unit tests pass
- [ ] Deployed to dev
- [ ] Integration tests pass
- [ ] PR documents CI/CD verification results

#### QA Notes

**Verify:**

- `ls cmd/` shows ingestion directory is gone
- `npm run format` works
- `npm run lint:test` works
- No broken scripts in package.json

**Risk:** Low - removing clearly dead code, easily reverted via git

---

## P2: This Sprint (3.5 hours)

These tickets improve performance and operational readiness.

---

### AR-XX: Add warmup handler to ingestion Lambda

#### Summary

Wire up `@middy/warmup` middleware in the ingestion handler to improve cold start performance by keeping Lambda instances warm.

#### Background

The ingestion Lambda (`src/handlers/ingestion.ts`) is the entry point for all fingerprint collection. Cold starts add ~200-500ms latency to the first request after a period of inactivity.

`@middy/warmup` is already in package.json (line 82) but not wired into the ingestion handler. The matching worker already handles warmup messages (lines 107-131), so the infrastructure may already be sending warmup events.

#### Scope

**In scope:**

- Add `@middy/warmup` to ingestion.ts middleware chain
- Ensure warmup handler returns early without processing
- Add metric for warmup pings

**Not in scope:**

- EventBridge warmup rule configuration (may already exist)
- Provisioned concurrency changes
- Changes to matching worker warmup handling

#### Implementation Hints

**Package already available:**

- `@middy/warmup` in package.json line 82

**Middleware chain location:**

- `src/handlers/ingestion.ts` lines 289-295

**Pattern from matching-worker:**

```typescript
// src/handlers/matching-worker.ts lines 107-131
function isWarmupMessage(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    return parsed.warmup === true || parsed.source === "warmup-rule";
  } catch {
    return false;
  }
}
```

**Middy warmup usage:**

```typescript
import warmup from "@middy/warmup";

export const handler = middy(baseHandler).use(
  warmup({
    isWarmingUp: (event) => event.source === "serverless-plugin-warmup",
  }),
);
// ... rest of middleware
```

**Note:** Check if warmup events come from EventBridge or serverless-plugin-warmup and configure accordingly.

#### Acceptance Criteria

- [ ] AC1: `@middy/warmup` middleware added to ingestion handler
- [ ] AC2: Warmup requests return early (200 status, no SQS message)
- [ ] AC3: Warmup requests don't count as errors
- [ ] AC4: `WarmupPing` metric emitted for warmup requests
- [ ] AC5: Regular requests unaffected

#### Test Coverage

**Existing tests:**

- `src/handlers/ingestion.test.ts` - add warmup test case

**Gaps:**

- No existing warmup test for ingestion handler

#### Definition of Done

- [ ] Warmup middleware added
- [ ] Unit tests pass including new warmup test
- [ ] Deployed to dev
- [ ] Integration tests pass
- [ ] Verify warmup reduces cold starts (check CloudWatch Lambda metrics)

#### QA Notes

**Verify:**

- Send warmup event manually, verify 200 response
- Check no SQS message sent for warmup
- Check WarmupPing metric in CloudWatch
- Normal requests still work

**Risk:** Low - middleware pattern already proven in matching-worker

---

### AR-XX: Test Lambda at 1024MB memory

#### Summary

Deploy matching worker at 1024MB memory (up from 512MB prod / 256MB dev) to measure p95 latency improvement and determine if the cost/performance tradeoff is worthwhile.

#### Background

Lambda CPU allocation scales with memory. At 512MB, the matching worker may be CPU-constrained during Tier 2 matching which runs 6 parallel DynamoDB queries. Testing at 1024MB will show if:

- p95 latency improves (hypothesis: yes, by 20-40%)
- Cost increase is justified by latency improvement
- Cold start time changes

**Expected savings**: ~$1,000-2,000/year if latency improvement reduces timeout retries per FINAL-PLAN.md.

#### Scope

**In scope:**

- Temporarily configure dev matching worker at 1024MB
- Run load test and collect p95/p99 latency metrics
- Compare against baseline 256MB metrics
- Document findings with recommendation

**Not in scope:**

- Production deployment of memory change
- Changes to profile updater memory
- Permanent configuration change (pending data analysis)

#### Implementation Hints

**Memory configuration:**

- `lib/config/stage-config.ts` line 101: `memorySize: 256` (dev)
- `lib/config/stage-config.ts` line 183: `memorySize: 512` (prod)

**Test process:**

1. Record baseline metrics at current memory (256MB dev)
2. Change dev config to 1024MB
3. Deploy: `npx cdk deploy ms-argus-api-dev-jw`
4. Run load test: `cd ~/Dev/ms-argus-automation && npm test`
5. Collect CloudWatch metrics: MatchingDuration p95, p99
6. Compare and document

**Metrics to collect:**

- `MatchingDuration` p50, p95, p99
- Cold start duration
- Memory utilization %
- Cost estimate at new memory level

**Cost calculation:**

- Lambda pricing: $0.0000166667 per GB-second
- 1024MB vs 512MB = 2x memory cost but potentially shorter duration

#### Acceptance Criteria

- [ ] AC1: Baseline p95 latency documented at 256MB
- [ ] AC2: Test p95 latency documented at 1024MB
- [ ] AC3: Memory utilization % recorded for both configurations
- [ ] AC4: Cost analysis completed (GB-seconds comparison)
- [ ] AC5: Recommendation documented with supporting data
- [ ] AC6: Configuration reverted to original after test (unless changing)

#### Test Coverage

**Existing tests:**

- Integration tests provide load for measurement
- No code changes, just configuration

**Gaps:**

- None - this is a measurement exercise

#### Definition of Done

- [ ] Baseline metrics recorded
- [ ] 1024MB test metrics recorded
- [ ] Analysis document created with recommendation
- [ ] Configuration reverted (or updated if improvement justified)
- [ ] PR includes analysis findings

#### QA Notes

**Verify:**

- CloudWatch metrics accessible for both configurations
- No functional regression during test
- Integration tests pass at both memory levels

**Risk:** Low - configuration change in dev only, easily reverted

---

### AR-XX: Standardize ESM bundling

#### Summary

Change workers.ts bundling from CommonJS to ESM format for better tree-shaking and modern JavaScript compatibility.

#### Background

Current configuration in `lib/constructs/workers.ts` line 86:

```typescript
format: OutputFormat.CJS,
```

ESM (ECMAScript Modules) is the modern standard and offers:

- Better tree-shaking (smaller bundles)
- Native async module loading
- Alignment with Node.js 20 ESM support

The ingestion handler already uses ESM-compatible patterns.

#### Scope

**In scope:**

- Change `OutputFormat.CJS` to `OutputFormat.ESM` in workers.ts
- Run full test suite
- Deploy to dev for 24-hour soak test
- Monitor for any import/require errors

**Not in scope:**

- Changing application code (should work with both)
- Changing other bundling settings
- Other Lambda functions outside workers.ts

#### Implementation Hints

**File to modify:**

- `lib/constructs/workers.ts` line 86:
  ```typescript
  format: OutputFormat.CJS,  // Change to OutputFormat.ESM
  ```

**Import already available:**

- Line 9: `import { OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";`

**Potential issues:**

- Some npm packages may not have ESM exports
- Check for `require()` calls in application code (should use `import`)
- Dynamic imports may behave differently

**Verification:**

1. Change format
2. Run `npm test` locally
3. Deploy to dev
4. Monitor CloudWatch Logs for 24 hours
5. Look for: `ERR_REQUIRE_ESM`, `Cannot find module`, import errors

#### Acceptance Criteria

- [ ] AC1: `OutputFormat.ESM` configured in workers.ts
- [ ] AC2: CDK synth succeeds
- [ ] AC3: All unit tests pass
- [ ] AC4: Deploy to dev succeeds
- [ ] AC5: Integration tests pass
- [ ] AC6: 24-hour soak shows no ESM-related errors in logs
- [ ] AC7: Bundle size same or smaller (check Lambda console)

#### Test Coverage

**Existing tests:**

- All 434+ tests must pass
- Integration tests verify runtime behavior

**Gaps:**

- No specific bundling format tests (rely on integration tests)

#### Definition of Done

- [ ] Format changed to ESM
- [ ] Unit tests pass
- [ ] Deployed to dev
- [ ] Integration tests pass
- [ ] 24-hour soak completed without errors
- [ ] Bundle size documented (before/after)

#### QA Notes

**Verify:**

- Lambda console shows bundle deployed successfully
- No `ERR_REQUIRE_ESM` errors in CloudWatch Logs
- All endpoints functional
- Check bundle size in Lambda console (should be similar or smaller)

**Soak test monitoring:**

- Check CloudWatch Logs every few hours for first 24 hours
- Look for any module resolution errors

**Rollback:**

- If issues found, revert to `OutputFormat.CJS` and redeploy

**Risk:** Medium - bundling change could surface module compatibility issues

---

### AR-XX: Add cardinality recalculation Lambda

#### Summary

Create a daily Lambda function that recalculates Tier 2 bucket cardinalities to prevent drift in fraud scoring.

#### Background

Tier 2 bucket cardinalities are tracked via atomic increments when devices are added. However, cardinality can drift due to:

- Device deletions (TTL expiry doesn't decrement counter)
- Failed writes (increment succeeded, device write failed)
- Race conditions in high-traffic scenarios

The matching service uses cardinality to penalize high-traffic buckets (like carrier NAT IPs) per `TIER2_HIGH_CARDINALITY_THRESHOLD` (500) and `TIER2_CARDINALITY_PENALTY` (0.3).

**Majority decision**: Operator + Optimizer voted for this; Pragmatist dissented but was overruled. The $60/year Lambda cost is justified by accurate fraud scoring.

#### Scope

**In scope:**

- Create new Lambda function for cardinality recalculation
- Scan Tier2Buckets table, count actual devices per bucket
- Update `_stats` entries with accurate cardinality
- Schedule daily execution via EventBridge
- Add CloudWatch metrics for recalculation results

**Not in scope:**

- Real-time cardinality tracking changes
- Changing cardinality threshold or penalty values
- Retroactive fraud score recalculation

#### Implementation Hints

**New Lambda handler:**

- Create `src/handlers/cardinality-recalc.ts`
- Follow pattern from `src/handlers/profile-updater.ts` for structure

**Cardinality storage:**

- `src/helpers/constants.ts` line 40: `TIER2_STATS_SK = "_stats"`
- Each bucket has a `bucket_key#_stats` item with `cardinality` attribute
- See profile-service.ts `incrementBucketCardinalities()` for current write pattern

**Recalculation logic:**

1. Scan Tier2Buckets table
2. Group items by bucket_key
3. Count non-stats items per bucket
4. Compare to stored cardinality in `_stats` item
5. Update if different (batch write)

**CDK infrastructure:**

- Add to `lib/constructs/workers.ts` or create new construct
- EventBridge rule: `schedule(Schedule.rate(Duration.days(1)))`
- Grant read/write on tier2BucketsTable

**Metrics:**

- `CardinalityRecalcBuckets` - number of buckets processed
- `CardinalityDriftDetected` - number of buckets with incorrect cardinality
- `CardinalityRecalcDuration` - total execution time

#### Acceptance Criteria

- [ ] AC1: New Lambda `cardinality-recalc` created
- [ ] AC2: Lambda scans Tier2Buckets and counts devices per bucket
- [ ] AC3: `_stats` entries updated with accurate cardinality
- [ ] AC4: EventBridge rule triggers Lambda daily
- [ ] AC5: Metrics emitted: buckets processed, drift detected, duration
- [ ] AC6: Lambda completes within timeout (suggest 5 minutes)
- [ ] AC7: No impact on real-time matching performance

#### Test Coverage

**New tests needed:**

- Unit tests for recalculation logic
- Test: bucket with 5 devices shows cardinality 5
- Test: bucket with deleted devices gets corrected cardinality
- Test: empty bucket handled correctly

**Gaps:**

- Integration test for scheduled execution (manual verification)

#### Definition of Done

- [ ] Lambda handler created with tests
- [ ] CDK infrastructure added
- [ ] Unit tests pass
- [ ] Deployed to dev
- [ ] Manual trigger shows correct recalculation
- [ ] EventBridge rule created and enabled
- [ ] Metrics visible in CloudWatch

#### QA Notes

**Verify:**

- Manually invoke Lambda, check logs for bucket processing
- Verify `_stats` items updated in DynamoDB console
- Check metrics in CloudWatch
- Confirm no impact on matching latency during recalc

**Edge cases:**

- Empty table (should complete quickly with 0 buckets)
- Very large bucket (1000+ devices) - should still count correctly
- Bucket with only `_stats` entry (cardinality should be 0)

**Risk:** Low - read-heavy operation, writes only to stats entries

---

## P3: This Quarter (5-6 hours + bake time)

These tickets are lower priority but provide security and cost benefits.

---

### AR-XX: Move API_KEYS to Secrets Manager

#### Summary

Move the `API_KEYS` environment variable from Lambda configuration to AWS Secrets Manager for improved security and rotation capability.

#### Background

Currently, API keys are stored in the `API_KEYS` environment variable as a JSON object:

- `src/handlers/ingestion.ts` lines 36-38:
  ```typescript
  const API_KEYS: Record<string, string> = process.env.API_KEYS
    ? JSON.parse(process.env.API_KEYS)
    : {};
  ```

This has security concerns:

- Visible in Lambda console configuration
- Logged in CloudFormation/CDK outputs
- Requires redeploy to rotate keys
- No audit trail for key access

Secrets Manager provides:

- Encrypted storage
- Rotation capability
- Access audit via CloudTrail
- No redeploy needed for key changes

#### Scope

**In scope:**

- Create Secrets Manager secret for API keys
- Modify ingestion handler to fetch keys from Secrets Manager
- Cache keys in Lambda memory (15-minute TTL)
- Grant Lambda permission to read secret
- Document key rotation process

**Not in scope:**

- Implementing automatic key rotation (manual rotation OK)
- Changing API key format or validation logic
- Migrating existing customers to new keys

#### Implementation Hints

**Existing secrets pattern:**

- `lib/constructs/workers.ts` lines 71-75: Secrets Manager reference
- `src/helpers/constants.ts` lines 141-144: `AWS_SECRETS_REQUIRED_KEYS`

**Secret structure suggestion:**

```json
{
  "api_keys": {
    "key1": "tenant1",
    "key2": "tenant2"
  }
}
```

**Caching pattern:**

- `src/helpers/constants.ts` line 9: `KEY_CACHE_DURATION = 1000 * 60 * 15` (15 min)
- Use module-level variable for cache: `let cachedKeys: Record<string, string> | null = null`
- Check cache before Secrets Manager call

**Permission grant:**

```typescript
secret.grantRead(ingestionLambda);
```

#### Acceptance Criteria

- [ ] AC1: API keys stored in Secrets Manager secret
- [ ] AC2: Ingestion handler reads keys from Secrets Manager
- [ ] AC3: Keys cached in Lambda memory for 15 minutes
- [ ] AC4: Cache refreshed when TTL expires
- [ ] AC5: Lambda has IAM permission to read secret
- [ ] AC6: API key validation still works correctly
- [ ] AC7: Key rotation documented (change secret, wait for cache expiry)

#### Test Coverage

**Existing tests:**

- API key validation tests in ingestion.test.ts
- Mock Secrets Manager client for unit tests

**Gaps:**

- Add test for Secrets Manager fetch failure (should fail gracefully)
- Add test for cache refresh

#### Definition of Done

- [ ] Secret created in Secrets Manager
- [ ] Lambda code updated to use Secrets Manager
- [ ] Unit tests pass with mocked Secrets Manager
- [ ] Deployed to dev
- [ ] Integration tests pass with real secret
- [ ] Rotation process documented in PR

#### QA Notes

**Verify:**

- API key authentication still works
- New keys can be added via Secrets Manager console
- Cache refresh works (change key, wait 15 min, verify new key works)
- Old environment variable can be removed

**Edge cases:**

- Secrets Manager unavailable (should fail request, not crash Lambda)
- Malformed secret JSON (should log error, fail gracefully)
- Empty API keys (should work like no keys configured)

**Risk:** Medium - authentication path change, requires careful testing

---

### AR-XX: DynamoDB provisioned capacity (conditional on timing)

#### Summary

Convert DynamoDB tables from on-demand to provisioned capacity with auto-scaling to save ~$31K/year, contingent on go-live timing.

#### Background

DynamoDB on-demand pricing is ~7x more expensive than provisioned capacity for predictable workloads. Per FINAL-PLAN.md consensus:

| Go-live Timeline   | Action                                     |
| ------------------ | ------------------------------------------ |
| < 4 weeks from now | Stay on-demand, switch after stabilization |
| 4-8 weeks from now | Start capacity analysis NOW                |
| > 8 weeks from now | Defer until 4 weeks before go-live         |

**Expected savings**: ~$31K/year (risk-adjusted from $50K gross savings, accounting for potential throttling).

#### Scope

**In scope:**

- Pull 2 weeks of CloudWatch metrics (read/write consumed capacity)
- Calculate base capacity at 150% of p99
- Configure auto-scaling: 70% target utilization, scale to 200%
- Apply to: Profiles, Tier1Index, Tier2Buckets, SessionCache tables
- Monitor for 2 weeks minimum before production

**Not in scope:**

- Immediate production deployment
- Global tables configuration
- Table schema changes

#### Implementation Hints

**CloudWatch metrics to pull:**

```
ConsumedReadCapacityUnits
ConsumedWriteCapacityUnits
```

- Pull at p50, p99, p99.9 for each table
- Use 2-week period for baseline

**Capacity calculation:**

```
Base RCU = p99_read * 1.5
Base WCU = p99_write * 1.5
```

**CDK configuration:**

```typescript
const table = new dynamodb.Table(this, "Table", {
  billingMode: BillingMode.PROVISIONED,
  readCapacity: baseRcu,
  writeCapacity: baseWcu,
});

table
  .autoScaleReadCapacity({
    minCapacity: baseRcu,
    maxCapacity: baseRcu * 2,
  })
  .scaleOnUtilization({
    targetUtilizationPercent: 70,
  });
```

**Tables to configure:**

- `lib/constructs/tables.ts` (or wherever tables are defined)
- ProfilesTable, Tier1IndexTable, Tier2BucketsTable, SessionCacheTable

**Monitoring:**

- Add alarms for `ThrottledRequests`
- Add dashboard for capacity utilization

#### Acceptance Criteria

- [ ] AC1: 2 weeks of capacity metrics collected and analyzed
- [ ] AC2: Base capacity calculated at 150% of p99
- [ ] AC3: Provisioned capacity configured for all tables
- [ ] AC4: Auto-scaling configured (70% target, 200% max)
- [ ] AC5: Throttle alarms configured
- [ ] AC6: 2-week bake period completed without throttling
- [ ] AC7: Cost reduction validated (~$31K/year savings)

#### Test Coverage

**Existing tests:**

- All tests must pass
- No code changes, just infrastructure

**Gaps:**

- Load test to verify auto-scaling works

#### Definition of Done

- [ ] Capacity analysis document created
- [ ] CDK changes applied to dev
- [ ] 2-week bake period completed
- [ ] No throttling events during bake
- [ ] Cost comparison documented
- [ ] Production deployment plan created

#### QA Notes

**Verify:**

- No `ThrottledRequests` in CloudWatch during bake
- Auto-scaling responds to load spikes
- Cost reduction visible in AWS Cost Explorer

**Monitoring during bake:**

- Daily check of throttle metrics
- Weekly cost comparison
- Watch for burst traffic patterns

**Rollback:**

- If throttling occurs: increase base capacity or revert to on-demand
- On-demand can be re-enabled immediately if needed

**Risk:** Medium - capacity miscalculation could cause throttling in production. Mitigated by 2-week bake period.

---

## Ticket Dependency Graph

```
P0 (Do Today) - All independent, can be parallelized
├── AR-XX: ULID bug + metric
├── AR-XX: Tenant isolation guard
├── AR-XX: Enable X-Ray
└── AR-XX: NEW_DEVICE_RATE metric

P1 (This Week) - Both independent
├── AR-XX: Delete dead dependencies
└── AR-XX: Delete Go service

P2 (This Sprint)
├── AR-XX: Warmup handler (independent)
├── AR-XX: Test Lambda memory (independent)
├── AR-XX: ESM bundling (independent)
└── AR-XX: Cardinality recalc Lambda (independent)

P3 (This Quarter) - Both independent
├── AR-XX: API_KEYS to Secrets Manager
└── AR-XX: DynamoDB provisioned (conditional on timing)
```

All tickets are independent within their priority level and can be worked on in parallel.

---

## Summary

| Priority  | Tickets | Total Effort     | Impact                                   |
| --------- | ------- | ---------------- | ---------------------------------------- |
| P0        | 4       | 3.5 hours        | Critical fixes: correctness + security   |
| P1        | 2       | 1 hour           | Technical debt cleanup                   |
| P2        | 4       | 3.5 hours        | Performance + operations                 |
| P3        | 2       | 5-6 hours + bake | Security + cost savings                  |
| **Total** | **12**  | **~14 hours**    | **~$30K/year savings + risk mitigation** |

---

_Tickets generated by TICKET-WRITER persona based on FINAL-PLAN.md and codebase exploration._
