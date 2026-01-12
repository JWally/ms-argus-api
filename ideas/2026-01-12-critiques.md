I've reviewed the ms-argus-api codebase. This is a well-architected device fingerprinting and fraud detection system. Here's my analysis:

## Overall Assessment

**Architecture: Solid.** The tiered matching strategy (T0 cache → T0.5 evercookie → T1 hash → T2 compound → new device) is sensible for balancing latency vs match quality. The Go ingestion service → SQS → Lambda workers pattern handles the 30B req/year scale well.

**Code Quality: Good.** Dependency injection, environment validation at cold start, structured logging, comprehensive tests. The codebase shows evidence of thoughtful iteration (the planning doc shows you're already aware of many issues).

---

## Major Architectural Concerns

### 1. **CORS Configuration Will Break in Production** (P0)

```typescript
// src/helpers/constants.ts
export const ALLOWED_ORIGINS = parseAllowedOrigins();
// Returns: ["https://api-dev-jw.argus.pw", "https://argus.pw", "https://www.argus.pw"]
```

Your fingerprint script runs on _merchant_ sites (`shop-a.com`, `shop-b.com`). When their page calls `/v1/collect`, the browser sends `Origin: https://shop-a.com`. Your allowlist rejects it. The collect endpoint should either reflect the origin or use `*` (it's fire-and-forget with no credentials that matter).

### 2. **Key Rotation is Disabled, But No Migration Path Exists**

The comment in `secrets.ts` correctly identifies the problem (old keys destroyed), but the current state leaves you with long-lived keys and no envelope encryption. If a key is ever compromised, you have no way to rotate without losing historical data. The `version: "1"` field is a good placeholder, but there's no code that reads or uses it.

### 3. **Tier 2 "Fail Open" Creates Silent Device Fragmentation**

```typescript
// src/services/matching/matching-service.ts
if (tier2TimedOut) {
  metrics.addMetric("Tier2Timeout", MetricUnit.Count, 1);
  // But we still create a NEW device below...
}
return { result: this.createNewDevice(), tier2TimedOut: timedOut };
```

When Tier 2 times out, you create a new device ID. Same physical device now has multiple IDs. You're tracking the metric but not the downstream impact. The `tier2TimedOut` flag is returned but `match_source` doesn't distinguish timeout vs genuine no-match.

---

## Major Security Concerns

### 1. **No Input Validation on Fingerprint Fields**

```go
// cmd/ingestion/main.go
var payload FingerprintPayload
if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { ... }
// Fingerprint is json.RawMessage - passed through unchecked
```

The Go service validates `session_id` exists but passes `fingerprint` as raw JSON. A malicious payload with 10MB nested objects or deeply recursive structures will propagate to Lambda workers and potentially DynamoDB. Add size limits and schema validation.

### 2. **Tenant ID Extraction is Trusting Client Input**

```go
if payload.TenantID == "" {
    payload.TenantID = r.Header.Get("X-Tenant-ID")
}
if payload.TenantID == "" {
    payload.TenantID = "default"
}
```

Tenants can claim to be any other tenant by setting `X-Tenant-ID`. For multi-tenant deployment, tenant ID should come from authentication/API key validation, not raw headers.

### 3. **WAF Geo-Blocking CN/RU at Priority 0**

```typescript
// lib/constructs/cloudfront.ts
{ name: "GeoBlockCNRU", priority: 0, statement: { geoMatchStatement: { countryCodes: ["CN", "RU"] } } }
```

This blocks legitimate users from those countries and is easily bypassed via VPN. If it's a business requirement, fine, but it's security theater otherwise. Attackers won't be inconvenienced.

---

## Performance Concerns

### 1. **Individual PutItem for Tier 1 Indexes** (Fixed in Planning)

Your planning doc already identifies BatchWriteItem as the solution. Currently:

```typescript
// Called 3-4 times per device
await this.deps.dynamodb.send(new PutItemCommand({ ... }));
```

### 2. **Redis Connection on Every Cold Start Without lazyConnect**

```typescript
// src/handlers/matching-worker.ts
function getRedis(): Redis {
  if (!redis) {
    redis = new Redis({
      // lazyConnect: true is set, good
      enableReadyCheck: false, // good
```

Actually, this is already optimized. The settings look correct for Lambda.

### 3. **Bloom Filter Code Exists But Isn't Used**

```typescript
// Note: BloomFilter removed per AR-21 - adds complexity without sufficient value
```

Good decision, but the code is still in `src/services/bloom/`. Either delete it or add a comment explaining it's intentionally kept for future Tier 2 optimization.

---

## Nits and Minor Issues

### Code Style

```typescript
// src/helpers/constants.ts
export const FNV1A_OFFSET_BASIS = 2166136261;
export const FNV1A_PRIME = 16777619;
```

**Nit:** These are magic numbers. Add a reference link to the FNV spec for future readers.

### Test Coverage

```typescript
// vitest.config.ts
thresholds: { statements: 25, branches: 40, functions: 25, lines: 25 }
```

**Nit:** 25% coverage thresholds are very low for a fraud detection system. The matching logic should have much higher coverage.

### Error Messages

```typescript
// src/config/env.ts
throw new Error(
  `Missing required environment variables: ${missing.join(", ")}`,
);
```

**Nit:** Add guidance: "This is a deployment configuration error. Check your CDK stack environment settings."

### Unused Import

```typescript
// src/handlers/matching-worker.ts
import {
  FingerprintPayload,
  generateIdempotencyKey,
} from "../services/matching";
```

`FingerprintPayload` is re-exported but `Fingerprint` is also imported from the same module. Minor confusion.

### Console.log Remnants

```typescript
// src/services/get-aws-secrets.ts
// Uses Logger, good

// But check for any remaining console.* calls:
```

Grep shows no `console.log` in production code.

### DynamoDB TTL Field Name Inconsistency

```typescript
// src/services/profile/profile-service.ts
timeToLiveAttribute: "ttl";
// But the interface:
export interface DeviceProfile {
  ttl: number;
}
```

This is correct but worth a comment that `ttl` is the DynamoDB TTL attribute (epoch seconds).

### Go Test Coverage

```go
// cmd/ingestion/main_test.go
func TestCollectHandler_MissingSessionID(t *testing.T) { ... }
```

Tests exist but don't test the SQS integration (mocked client exists but isn't wired up). Add a test that verifies message body format.

---

## Summary Table

| Category         | Issue                                         | Severity | Effort   |
| ---------------- | --------------------------------------------- | -------- | -------- |
| **Security**     | CORS blocks merchant domains                  | P0       | 1hr      |
| **Security**     | No fingerprint input validation               | P1       | 2hr      |
| **Security**     | Tenant ID from untrusted header               | P1       | 4hr      |
| **Architecture** | Key rotation disabled, no envelope encryption | P1       | 1-2 days |
| **Architecture** | Tier 2 timeout creates device fragmentation   | P2       | 2hr      |
| **Performance**  | Individual PutItem for Tier 1                 | P2       | 2hr      |
| **Ops**          | Bloom filter code unused but present          | P3       | 30min    |
| **Ops**          | Low test coverage thresholds                  | P3       | Ongoing  |

The codebase is in good shape for a dev environment. The P0 CORS issue will bite you immediately when merchants try to integrate. The key rotation story needs resolution before you handle real production data.

This is a sophisticated architecture for a high-volume system. It is significantly better than a typical "monolith turned serverless" attempt. You have clearly thought about cost (Go on Fargate vs API Gateway) and latency (tiered matching).

However, there are **critical availability risks** regarding your secrets management and concurrency limits, and a **security bypass** in your networking layer.

Here is the critique.

### I. Major Architectural Flaws

**1. The Lambda Concurrency "Cliff" (Throughput Bottleneck)**
In `lib/constructs/workers.ts`, you explicitly set:

```typescript
reservedConcurrentExecutions: 100, // Limit concurrency to protect downstream

```

For 30 Billion requests/year, you average ~950 requests/second.

- If your matching worker takes 100ms (optimistic, given DynamoDB queries and crypto), 100 concurrency handles exactly 1,000 req/sec.
- **The Flaw:** You are running at ~95% capacity at _average_ load. Any mild spike, retry storm, or latency increase in DynamoDB/Redis will instantly fill the SQS queue. Because the concurrency is hard-capped, Lambda _cannot_ scale up to drain the queue. You will flood your DLQ and drop data during peak hours (Black Friday, etc).
- **Fix:** Increase reserved concurrency significantly (e.g., to 1,000+) or remove the reserve and rely on Account limits + DynamoDB Auto Scaling.

**2. Tier 2 "Hot Partition" Risk**
In `src/services/matching/matching-service.ts`, you query Tier 2 buckets:

```typescript
// Tier 2: Compound filter match
this.deps.dynamodb.send(new QueryCommand({ ... Limit: TIER2_BUCKET_LIMIT }))

```

Your bucket keys are things like `tenant#ip_ja4#...` or `gpu_screen_tz`.

- **The Flaw:** Certain combinations (e.g., `1920x1080` + `America/New_York` + common GPU) will create "Super Buckets" with millions of devices.
- DynamoDB partitions by the partition key (`bucket_key`). You will create hot partitions that throttle writes.
- On read, you limit to 1,000 items. If the bucket has 50,000 devices, you are only checking the "first" 1,000 (determined by sort key `device_id`). You are ignoring the other 49,000 candidates, rendering Tier 2 matching effectively random for common device configurations.

### II. Major Security Vulnerabilities

**1. Catastrophic Data Loss during Key Rotation**
In `src/services/rotate-aws-secrets.ts`, you generate a new key and overwrite the secret immediately.
In `src/services/get-aws-secrets.ts`, you cache the key for **15 minutes**.

- **The Vulnerability:** When you run the rotation script:

1. Secret in AWS updates to `Key_B`.
2. Ingestion Service (Go) might still have `Key_A` cached (or picks up `Key_B`).
3. Matching Worker might have `Key_A` cached (or picks up `Key_B`).

- **Impact:** For up to 15 minutes, you will have a split-brain scenario. Data encrypted by Ingestion with `Key_B` will fail decryption by Workers holding `Key_A` (and vice versa). You will drop 15 minutes of traffic every time you rotate keys.
- **Fix:** Implement **Key Versioning**. The secret should contain `{"current": "...", "previous": "..."}`. Ingestion always uses `current`. Workers try decryption with `current`, and fallback to `previous` on failure.

**2. WAF Bypass via Exposed ALB**
In `lib/constructs/ingestion-service.ts`:

```typescript
albSecurityGroup.addIngressRule(
  ec2.Peer.anyIpv4(), // <--- THE FLAW
  ec2.Port.tcp(80),
  "Allow HTTP from anywhere",
);
```

- **The Vulnerability:** Your ALB is public internet-facing. While you have CloudFront + WAF in front of it, an attacker who discovers your ALB's DNS name (easy via Certificate Transparency logs or DNS enumeration) can send requests _directly_ to the ALB, bypassing your WAF rate limits, geo-blocking, and bot rules.
- **Fix:** Restrict the ALB Security Group to only accept traffic from the **CloudFront Managed Prefix List**.

**3. Insecure Randomness in Logic (Go Service)**
In `cmd/ingestion/main.go`, you didn't include the implementation of `healthHandler` or imports, but typically:

- **The Flaw:** If you are generating `session_id` on the client, you trust the client. If you generate it in Go, ensure you aren't using `math/rand`. (Note: The provided code implies `session_id` comes from the client `FingerprintPayload`).
- **Critique:** Trusting the client-provided `session_id` for deduplication allows an attacker to replay a valid session ID with different payloads to poison your profile data or cause hash collisions.

### III. Logical & concurrency Flaws

**1. Race Condition in Mutation Gate**
In `src/services/profile/profile-service.ts`:

```typescript
async checkMutationGate(deviceId: string): Promise<boolean> {
  const exists = await this.deps.redis.exists(key); // READ
  return exists === 0;
}
// ... later in processProfileUpdate ...
await this.setMutationGate(deviceId); // WRITE

```

- **The Flaw:** This is a classic "Check-Then-Act" race condition. Two requests for the same device arriving simultaneously will both see `exists === 0`, both process the profile, both write to DynamoDB, and both set the gate.
- **Impact:** You fail to prevent write amplification during high-concurrency bursts (e.g., a bot spamming requests).
- **Fix:** Use `SET key value NX EX 3600` (Set if Not Exists) in a single atomic operation. If the SET fails/returns null, the gate is closed.

**2. Silent Failures in BatchWriteItem**
In `src/services/profile/profile-service.ts`:

- You implement retry logic for `UnprocessedItems`. Good.
- **The Flaw:** If DynamoDB returns `UnprocessedItems` consistently (due to throttling), you eventually throw an Error. This error bubbles up and causes the Lambda to fail.
- The SQS message returns to the queue. It is retried. It throttles again.
- **Impact:** This creates a **Poison Pill**. A single device profile that triggers throttling (perhaps due to hot partition on indexes) will jam your SQS processing for that batch, potentially blocking _other_ innocent profiles in the same SQS batch.

### IV. Annotated Nits

1. **File:** `cmd/ingestion/main.go`

- **Nit:** You use `os.Getenv` directly in `main`. It's better to fail fast with a dedicated configuration struct/validator similar to your TS `env.ts`.
- **Nit:** `json.RawMessage` for `Fingerprint` avoids deserialization cost, but if the client sends `{ "fingerprint": "garbage" }`, your Go service accepts it (204), and your Node worker crashes later. Basic validation (is it an object?) would be safer.

2. **File:** `src/handlers/matching-worker.ts`

- **Nit:** `getConfig()` creates a new object on every request. Move this outside the handler or make it a singleton constant.
- **Nit:** `createMatchingService()` instantiates `DynamoDBClient` outside the handler (good), but instantiates `MatchingService` _inside_ the handler. This allocates memory on every invoke. The service is stateless; instantiate it once globally.

3. **File:** `.eslintrc.json`

- **Nit:** `"@typescript-eslint/explicit-function-return-type": "off"`. For a complex financial/fraud system, strict return types prevent accidental data leaks or `void` returns where promises were expected. Turn this `on`.

4. **File:** `lib/constructs/redis.ts`

- **Nit:** You are using `cache.t4g.micro` for dev. Be aware that T-series instances have CPU credits. If you run a load test on Dev, you will exhaust credits and the Redis performance will collapse, giving you false negative performance data.

### Summary of Next Steps

1. **Immediate Security Fix:** Implement key versioning for `ENCRYPTION_KEY` to prevent data loss during rotation.
2. **Immediate Ops Fix:** Lock down the ALB Security Group to CloudFront Prefix Lists only.
3. **Immediate Scale Fix:** Remove or drastically increase the `reservedConcurrentExecutions: 100` limit on the workers.
4. **Refactor:** Change the Mutation Gate to use atomic Redis `SET NX`.

I'll analyze this codebase carefully for over-engineering, waste, inefficiency, and areas where money is being spent unnecessarily.

Let me start by understanding the architecture and then dig into specific concerns.

## Overall Assessment

This is a device fingerprinting and fraud detection system designed for 30B requests/year. The architecture is reasonable for the stated scale, but there are several areas of concern.

---

## 1. The Bloom Filter is Dead Weight

You have a complete Bloom filter implementation in `src/services/bloom/` with tests, but it's explicitly not used:

```typescript
// Note: BloomFilter removed per AR-21 - adds complexity without sufficient value
```

**Problem**: 200+ lines of code sitting unused. It's commented out in handlers but the service files, types, and tests all remain.

**Fix**: Delete `src/services/bloom/` entirely. If you need it later, you have git history.

---

## 2. The Secrets Rotation Lambda is Orphaned

`src/services/rotate-aws-secrets.ts` exists with tests, but the CDK stack doesn't deploy it anywhere. The `SecretConstruct` in `lib/constructs/secrets.ts` has this comment:

```typescript
/**
 * IMPORTANT: Automatic key rotation has been disabled (AR-18).
 */
```

But the rotation code is still maintained, tested, and part of your build.

**Problem**: You're paying CI time to test code that's never deployed.

**Fix**: Either:

- Delete `rotate-aws-secrets.ts` and its tests entirely
- Or add a manual invocation mechanism if you actually use it for quarterly rotations

---

## 3. Firehose Analytics Pipeline Might Be Overkill

You have a full analytics pipeline: SNS → Firehose → S3 (Parquet) → Glue → Athena. But I see:

1. `fingerprintTopic` is created but **nothing publishes to it**
2. The matching worker and profile updater don't send events to SNS
3. You're paying for Firehose, S3, Glue catalog regardless

Looking at the CDK:

```typescript
// Fingerprint data topic for analytics
const fingerprintTopic = new sns.Topic(this, "FingerprintTopic", {
  displayName: `${stackName}-fingerprint-topic`,
});
```

Then later:

```typescript
const fingerprintFirehose = new FirehoseProcessor(...)
```

But **no Lambda or service actually publishes to `fingerprintTopic`**. This entire analytics pipeline is provisioned but receiving zero data.

**Cost**: Firehose has a minimum cost even with zero data (~$5-10/month base). The Glue catalog, S3 buckets, and the complexity all exist for nothing.

**Fix**: Either wire up the analytics (add `fingerprintTopic.grantPublish()` and actually publish from matching worker), or delete the entire analytics stack until you need it.

---

## 4. ARGUS_COLUMNS is Massive but Unused

`src/helpers/constants.ts` has 100+ column definitions for Glue schema:

```typescript
export const ARGUS_COLUMNS: glue.CfnTable.ColumnProperty[] = [
  // 100+ columns for TCP, TLS, JS fingerprints, bot detection, etc.
];
```

Since nothing publishes to the analytics pipeline, this schema definition is pure overhead. It also includes columns for features that don't appear to be implemented yet:

- `bot.stealth_signals` - no stealth detection code
- `inconsistencies.*` - no inconsistency detection
- `timing.*` - no timing fingerprint collection
- `client_hints.*` - no client hints processing

**Fix**: Trim to what you actually collect, or delete until analytics is actually implemented.

---

## 5. Powertools Tracer is Disabled but Still Bundled

Throughout the handlers:

```typescript
// import { Tracer } from '@aws-lambda-powertools/tracer'; // Disabled due to @smithy bundling issues
// const tracer = new Tracer({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME }); // Disabled
```

But `@aws-lambda-powertools/tracer` is still in `package.json` dependencies and bundled into your Lambda artifacts.

**Problem**: You're paying for bundle size and cold start time for a package you don't use.

**Fix**: Remove from dependencies:

```bash
npm uninstall @aws-lambda-powertools/tracer
```

---

## 6. The Profile Queue Architecture Creates Unnecessary Latency

Current flow:

```
Request → Go → SQS (Matching) → Lambda (Match) → SQS (Profile) → Lambda (Profile) → DynamoDB
```

The matching worker queues to the profile worker via SQS:

```typescript
await service.queueProfileUpdate(tenant_id, matchResult.device_id, payload);
```

**Question**: Why two Lambdas with SQS in between?

The matching Lambda already has DynamoDB write permissions (it reads from indexes). It could write the profile directly. The profile updater exists solely to:

1. Check mutation gate (Redis call)
2. Check drift (DynamoDB read)
3. Write profile + indexes (DynamoDB writes)

None of these are expensive enough to justify a second Lambda invocation, second SQS queue, and the associated latency.

**Current cost per request**:

- 2x Lambda invocations
- 2x SQS operations
- Extra 5-10s of latency (SQS visibility + Lambda cold start)

**Simpler approach**: Matching worker does everything synchronously. If it's too slow, you have a problem with your DynamoDB access patterns, not your architecture.

**Counter-argument**: You might say "but writes shouldn't block the match response." True, but the match result is already written to Redis before queueing the profile update. The client doesn't wait for the profile write. So the separation provides no user-facing benefit.

---

## 7. Tier 2 Bucket Design is Questionable

You're using an adjacency list pattern for Tier 2 buckets:

```typescript
// PK: bucket_key (e.g., "tenant#ip_ja4#192.168.1.1#ja4_hash")
// SK: device_id
```

This means for each fingerprint update, you do:

```typescript
const count = await service.updateTier2Buckets(
  tenant_id,
  device_id,
  fingerprint,
);
```

Which creates up to 3 items (one per bucket type). On read, you Query each bucket and intersect:

```typescript
const queries = bucketKeys.map(key => this.deps.dynamodb.send(new QueryCommand({...})));
const results = await Promise.all(queries);
```

**Problem**: At scale, popular buckets (common IP + JA4 combos) could have thousands of devices. You're:

1. Querying up to 1000 devices per bucket (`TIER2_BUCKET_LIMIT`)
2. Loading all into memory
3. Counting intersection in JS

For a system designed for 30B/year, this will become expensive. Each Tier 2 match attempt is 3 DynamoDB Query operations reading potentially 3000 items total.

**Better approach**: Redis sorted sets or HyperLogLog for approximate matching. Or skip Tier 2 entirely until you have data showing it catches meaningful fraud that Tier 1 misses.

**Current state**: Tier 2 has a 100ms timeout that falls open to "new device." If it's timing out frequently, you're creating new device IDs for devices that might actually match. If it rarely matches, why have it?

---

## 8. Mutation Gate + Drift Detection = Redundant Writes Anyway

The mutation gate prevents writes for 1 hour:

```typescript
await redis.setex(`recently_updated:${deviceId}`, 3600, "1");
```

But drift detection compares fingerprints:

```typescript
if (existingProfile && !hasDrift) {
  await this.setMutationGate(device_id);
  return { skipped: true, reason: "no_drift" };
}
```

If there's no drift, you skip the write. If there is drift, you write regardless of mutation gate (because `checkMutationGate` is called first and returns early).

**Wait, no**—looking again:

```typescript
const shouldUpdate = await this.checkMutationGate(device_id);
if (!shouldUpdate) {
  return { skipped: true, reason: "mutation_gate" };
}
```

So mutation gate is checked first. If it's set, you skip entirely—even if there's drift.

**Problem**: A device that drifts multiple times within an hour (e.g., testing from different networks) will only update once. The second drift will be ignored.

**Is this intentional?** Maybe for write reduction, but it could mean you miss legitimate fingerprint changes.

---

## 9. The Risk Score Blending is Odd

```typescript
if (existingProfile && !effectivelyNewDevice) {
  const historicalWeight = 0.3;
  riskScore =
    riskScore * (1 - historicalWeight) +
    existingProfile.risk_score * historicalWeight;
}
```

So 30% of the risk score is historical. But you compute new flags fresh each time:

```typescript
const flags = this.computeFlags(
  fingerprint,
  existingProfile,
  isNewDevice,
  hasDrift,
);
```

Flags include things like `bot_detected` from fingerprint analysis. Then you compute risk from flags. Then you blend with history.

**Problem**: If a device was flagged `bot_detected` yesterday but presents clean today, you'll:

1. Compute flags: no `bot_detected` (clean fingerprint)
2. Compute risk: 0.3 base
3. Blend: 0.3 _ 0.7 + 0.8 _ 0.3 = 0.45

So historical bot detection persists at 30% weight forever. Is this intentional? It means a device can never fully rehabilitate.

**Alternative**: Decay historical risk over time, or use flags more explicitly.

---

## 10. Error Handling in Profile Service is Inconsistent

```typescript
async batchWriteTier1Indexes(entries, maxRetries = 3): Promise<void> {
  // ... retry logic ...
  if (unprocessedItems.length > 0) {
    throw new Error(`Failed to write ${unprocessedItems.length} items`);
  }
}
```

But `updateTier2Buckets` has no retry logic:

```typescript
async updateTier2Buckets(...): Promise<number> {
  // ...
  await Promise.all(updates);  // No retry
  return updates.length;
}
```

If Tier 2 writes fail, they silently fail (promise rejection propagates up, but no retry). Tier 1 gets retries with backoff.

**Inconsistency**: Why does Tier 1 deserve retries but Tier 2 doesn't?

---

## 11. The Go Ingestion Service is Fine, but Docker Build is Wasteful

The Dockerfile:

```dockerfile
FROM golang:1.21-alpine AS builder
# ...
RUN go build -o argus-ingestion

FROM alpine:latest
COPY --from=builder /app/argus-ingestion /usr/local/bin/
```

**Minor issue**: You're building for `linux/amd64` on ARM Macs. The CDK uses:

```typescript
runtimePlatform: {
  cpuArchitecture: ecs.CpuArchitecture.ARM64,
  operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
},
```

But the Dockerfile doesn't specify `GOARCH=arm64`. It might work due to Docker buildx, but it's implicit.

**Fix**: Add `GOARCH=arm64 GOOS=linux` to the build command for clarity.

---

## 12. CloudFront WAF Rules May Be Expensive at Scale

You have:

- AWSManagedRulesCommonRuleSet (AWS Managed)
- Rate limiting (600 req/5min per IP)
- Geo blocking
- Body size limit

AWS WAF charges per rule and per million requests. At 30B requests/year:

- 30B / 12 = 2.5B requests/month
- WAF costs: $1 per million requests = $2,500/month just for WAF request evaluation
- Plus managed rule costs

**Question**: Is WAF at the CloudFront edge worth $30K/year? The Go service already validates requests. Rate limiting could be done in Redis (cheaper).

**Alternative**: Move WAF rules to ALB level (cheaper per-request cost) or implement rate limiting in the Go service with Redis.

---

## 13. ECS Fargate Sizing Might Be Oversized

```typescript
const taskDefinition = new ecs.FargateTaskDefinition(this, "TaskDef", {
  memoryLimitMiB: 1024,
  cpu: 512, // 0.5 vCPU
});
```

With 2 tasks always running, you're paying for 1GB RAM and 1 vCPU total. The Go service does:

1. Parse JSON
2. Send to SQS
3. Return 204

This doesn't need 512MB per container. A 256MB task would likely suffice.

**Annual cost difference**: ~$4K for 0.5 vCPU/1GB vs ~$2K for 0.25 vCPU/0.5GB.

**Fix**: Load test with smaller tasks. Go services are typically very memory-efficient.

---

## 14. DynamoDB On-Demand Pricing at Scale

All three tables use PAY_PER_REQUEST:

```typescript
billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
```

At 30B requests/year:

- Each request = 1 write to matching queue + potential reads/writes
- On-demand: $1.25 per million writes, $0.25 per million reads

If each fingerprint causes:

- 2 Tier 1 index reads (stable + fuzzy hash)
- 1 profile read
- 1-3 Tier 2 bucket queries (1000 items each worst case)
- 1 profile write
- 3-4 Tier 1 index writes
- 1-3 Tier 2 bucket writes

That's potentially 5-10 operations per request. At 30B/year = 150B-300B operations.

**Rough cost**:

- 200B operations at average $0.50/million = $100K/year just for DynamoDB

At this scale, provisioned capacity with auto-scaling would be significantly cheaper. You'd know your baseline and scale up for peaks.

**Fix**: Switch to provisioned capacity with auto-scaling after you have traffic patterns.

---

## 15. Redis ElastiCache Sizing

```typescript
const nodeType = isProd ? "cache.r6g.large" : "cache.t4g.micro";
const numNodes = isProd ? 2 : 1;
```

r6g.large = 13.5 GB RAM, 2 vCPU. For caching session results with 15-minute TTL and mutation gates with 1-hour TTL?

**Math**:

- Each session entry: ~200 bytes JSON
- Each mutation gate: ~50 bytes
- 30B requests/year = ~1M/minute peak
- With 15-min TTL: 15M concurrent sessions max
- 15M \* 200 bytes = 3GB

You're paying for 13.5GB RAM (actually 27GB with 2 nodes for HA).

**Fix**: Start with r6g.medium (6.75GB) or even smaller. You can always scale up.

---

## 16. Unnecessary NAT Gateway in Dev

```typescript
natGateways: stage === "prod" ? 2 : 1,
```

You still have 1 NAT Gateway in dev. NAT Gateways cost ~$32/month + data processing.

**Alternative for dev**: Use VPC endpoints for AWS services (DynamoDB, SQS, Secrets Manager) and skip NAT entirely. Lambda can use VPC endpoints. The Go service can too.

Cost savings: ~$400/year per dev environment.

---

## 17. Code Duplication in Type Definitions

You have `Fingerprint` type in:

- `src/types/fingerprint.ts` (canonical)
- `src/services/matching/types.ts` (re-exports)
- `src/services/profile/types.ts` (re-exports)

Each service has its own `types.ts` that mostly re-exports from `src/types`. This is fine for encapsulation, but then you also have:

```typescript
// src/services/profile/types.ts
import type { Fingerprint } from "../../types";
```

And:

```typescript
// src/services/matching/types.ts
export { Fingerprint } from "../../types";
```

Pick one pattern. Either:

- All services import directly from `src/types`
- Or all services re-export (but then use their local re-export consistently)

Currently it's mixed.

---

## 18. The FNV-1a Implementation is Duplicated

You have FNV-1a in:

- `src/helpers/middy-helpers.ts` (the `fnv1a` function)
- `src/services/matching/matching-service.ts` (inline in `generateIdempotencyKey`)
- `src/services/bloom/bloom-filter.ts` (as a class method)

Three implementations of the same algorithm. They're slightly different too:

```typescript
// middy-helpers.ts
hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);

// bloom-filter.ts
hash = Math.imul(hash, FNV1A_PRIME);

// matching-service.ts
hash = Math.imul(hash, FNV1A_PRIME);
```

The middy version uses a different multiplication approximation!

**Fix**: One utility function in `src/helpers/`, imported everywhere.

---

## 19. The Planning Doc Reveals Unfinished Work

`ideas/2026-01-11-planning.md` lists 15 action items, many marked P0 (critical):

1. Fix CORS for merchant domains - **not done** (code still shows restricted origins)
2. Fix key rotation - done (rotation disabled)
3. Replace Math.random() - done (uses `crypto.randomUUID()`)
4. Environment variable validation - done

But items 5-15 are unclear status. If this doc is your source of truth, it should be updated.

More concerning: the P1 items suggest fundamental issues that may still exist:

- Tier 2 timeout silent failures - partially addressed (tracking added, but still fails open)
- Delete bloom filter - **not done** (code still exists)

---

## 20. Test Coverage Gaps

Looking at your vitest config:

```typescript
thresholds: {
  statements: 25,
  branches: 40,
  functions: 25,
  lines: 25,
}
```

25% coverage threshold is quite low for production code handling fraud detection. The tests I see are mostly unit tests with mocked AWS services.

There's one integration test file (`tests/integration/api.integration.test.ts`) that only tests the Go ingestion endpoint, not the full flow through matching/profile Lambdas.

**Gap**: No integration tests verify that a fingerprint goes through the full pipeline and produces expected Redis/DynamoDB state.

---

## Summary: What I'd Change

**Delete immediately (save CI/maintenance time):**

1. `src/services/bloom/` - unused
2. `src/services/rotate-aws-secrets.ts` + tests - unused
3. Analytics pipeline in CDK - unused, costs money
4. `@aws-lambda-powertools/tracer` dependency - bundled but unused

**Simplify architecture:** 5. Merge matching + profile Lambdas - unnecessary separation 6. Remove Tier 2 matching initially - complex, timeout-prone, questionable value 7. Move rate limiting to Go service + Redis - cheaper than WAF

**Right-size infrastructure:** 8. Smaller Fargate tasks (256MB) 9. Smaller Redis (r6g.medium or smaller) 10. Provisioned DynamoDB capacity at scale 11. VPC endpoints instead of NAT Gateway in dev

**Fix code issues:** 12. Consolidate FNV-1a implementations 13. Consistent type imports 14. Complete the P0/P1 items from your planning doc

**Rough cost savings estimate:**

- Delete unused analytics: ~$100/month
- Smaller Fargate: ~$100/month
- Smaller Redis: ~$200/month
- VPC endpoints vs NAT (dev): ~$35/month
- Move from WAF to application rate limiting: ~$2,500/month (at scale)

That's potentially $3K/month in savings, mostly from WAF and right-sizing.

This is a solid, professional-grade implementation, but it suffers from **"Resume Driven Development" scaling delusions.** You are building for 30 billion requests (Amazon/Netflix scale) while taking on operational debt that will strangle a smaller team.

Here is the critique on waste, over-engineering, and inefficiency.

### 1. Money Waste: The "VPC Tax" is bleeding you

You are running Lambdas in a VPC to access Redis. This forces you to use **NAT Gateways** for those Lambdas to talk to SQS, DynamoDB, and Secrets Manager (unless you have configured specific VPC Endpoints, which are missing from `app-stack.ts` for everything except S3/Dynamo Gateway endpoints usually included by default).

- **The Math:** AWS charges ~$0.045 per GB processed by NAT Gateway.
- **The Scenario:** Your Go service ingests 30B requests → SQS → Lambda (in VPC). The Lambda reads from SQS (traffic traverses NAT) and writes to DynamoDB (traffic traverses NAT if no endpoint).
- **The Waste:** If a request payload is 2KB:

just for NAT processing, on top of the hourly NAT cost (~$350/yr per GW).

- **The Fix:**

1. **Mandatory:** Add Interface VPC Endpoints for SQS and Secrets Manager in `app-stack.ts`. This bypasses the NAT Gateway.
2. **Better:** In Dev, delete the NAT Gateway entirely. Put the Lambda/Fargate in a Public Subnet (with appropriate Security Groups). You are paying ~$400/year per environment for idle NAT Gateways.

### 2. Over-Engineering: The ECS Ingestion Layer

Your `AR-22` document justifies ECS over API Gateway based on a 30B request scale.

- **The Reality:** If you are a startup or solo dev, you do not have 30B requests. You have 0.
- **The Cost:** You are paying ~$700/year (plus ALB costs) for a "Hello World" Go server that validates JSON.
- **The operational burden:** You now maintain a Dockerfile, an ECR repo, a Fargate service, Auto-scaling rules, and an ALB.
- **The "99%" Solution:** Use **API Gateway HTTP APIs** (not REST).
- **Cost:** $1.00/million. It costs $0 until you have users.
- **Break-even:** The break-even point against your ECS setup (~$3,500/yr including ALB) is **3.5 Billion requests/year**.
- **Advice:** Delete `cmd/ingestion`. Delete `lib/constructs/ingestion-service.ts`. Wire API Gateway directly to SQS. If you hit 3.5B requests, you will have the revenue to hire someone to write that Go service then.

### 3. Inefficiency: Tier 2 "Adjacency List" Pattern

You are using DynamoDB for fuzzy matching via an adjacency list (`bucket_key` -> `device_id`).

- **The Problem:** `Query` with `Limit: 1000`.
- **The Scenario:** A common bucket (e.g., "iPhone 14 + NYC Timezone") fills up with 50,000 devices.
- **The Fail:** Your matching logic pulls 1,000 items across the network, deserializes them, and counts them in memory. This is heavy read amplification. You are paying for 1,000 read units to find 1 match.
- **The Fix:** If you need fuzzy matching on high-cardinality data, DynamoDB is the wrong tool.
- **Short term:** Keep it, but lower the TTL on Tier 2 buckets drastically (e.g., 7 days).
- **Long term:** This is what **Redis Sets** (not KV) or a proper search engine (OpenSearch/Qdrant) are for. Don't use DynamoDB as a search index for high-cardinality buckets.

### 4. Dangerous "Pharisee" Code: Custom Secret Rotation

You implemented a manual rotation script (`rotate-aws-secrets.ts`) that generates random bytes using `crypto`.

- **The Risk:** You admitted this broke previously (AR-18). By rolling your own rotation, you risk data loss if the old key isn't retained for a grace period.
- **The Fix:** **KMS Envelope Encryption.**
- Generate a unique Data Key for _every_ row (encrypted by a master KMS key).
- Store the encrypted Data Key alongside the data.
- You never need to rotate the "storage" key manually. You just rotate the KMS master key (which AWS handles).
- _Delete_ `src/services/rotate-aws-secrets.ts` and the complex caching logic.

### 5. Code Waste: `flattenObject` & Glue Schema

In `src/helpers/constants.ts`, you manually define `ARGUS_COLUMNS` with 100+ lines of schema definitions.

- **The Critique:** You are manually keeping a TypeScript definition in sync with a Glue Table schema. This will drift.
- **The 99% Solution:** Store the data in S3 as raw JSON. Let AWS Glue Crawlers infer the schema once a night. Or, if you use Parquet (which you are), use a library that generates the schema from your TypeScript interface/Zod schema automatically. Hardcoding columns in `constants.ts` is brittle.

### 6. Testing Efficiency: `vitest` with `localstack`?

I see no evidence of LocalStack or real integration tests in the pipeline, only unit tests mocking AWS SDKs.

- **The Trap:** Your unit tests pass, but your IAM roles will fail.
- **Advice:** Don't waste time writing 100% unit test coverage for `dynamodb.send(PutItem)`. It mocks the library, not the behavior. Write **one** integration test that actually hits a real (ephemeral) DynamoDB table or LocalStack.

### 7. Performance: The "Double Dip" on Redis

In `matching-worker.ts`:

1. You check Redis for a cache hit.
2. If miss, you match.
3. You write to Redis.

- **The Issue:** `getRedis()` creates a new `ioredis` instance. While you have logic to reuse it, Lambda container reuse isn't guaranteed.
- **Optimization:** Ensure `TCP_KEEPALIVE` is actually working. In a high-throughput VPC Lambda, failing to reuse connections can exhaust ENI limits or file descriptors. You have `keepAlive: 30000` which is good, but verify this with metrics (`NewConnectionCount` on Elasticache).

### Summary of Recommendations

| Severity   | Component        | Issue                                      | Fix                                                                                         |
| ---------- | ---------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------- |
| **High**   | **VPC/Network**  | NAT Gateway charges for SQS/Dynamo traffic | Add **VPC Endpoints** (Interface/Gateway) immediately.                                      |
| **High**   | **Architecture** | ECS Ingestion is premature optimization    | Replace with **API Gateway HTTP API** direct-to-SQS. Save $3k/yr and hours of ops.          |
| **Medium** | **Security**     | Custom Key Rotation                        | Delete it. Use **KMS Envelope Encryption** (generate a data key per record).                |
| **Medium** | **Database**     | DynamoDB Adjacency List for Search         | This will scale poorly cost-wise. Accept it for now, but plan to move Tier 2 to Redis Sets. |
| **Low**    | **DevOps**       | Prod vs Dev Parity                         | Remove NAT Gateway from Dev entirely. Use public subnets for Dev Lambdas to save $400/yr.   |

### Immediate Next Step

Would you like me to refactor `app-stack.ts` to add the missing **VPC Endpoints** and remove the **NAT Gateway** from the Dev environment? This stops the immediate money bleeding.

# Code Review: Readability & Maintainability

## Executive Summary

**Verdict: A mid-tier engineer could pick this up reasonably quickly.** The codebase is well-organized with clear architectural boundaries, good documentation in key places, and consistent patterns. There are some areas that could trip someone up, but nothing that would take more than a day or two to grok.

## Strengths

### 1. Clear Architectural Separation

The code follows a sensible layered architecture:

```
cmd/ingestion/     → Go HTTP layer (thin, fast)
src/handlers/      → Lambda entry points
src/services/      → Business logic (matching, profile)
src/types/         → Shared type definitions
lib/constructs/    → CDK infrastructure
lib/stacks/        → CDK composition
```

A new engineer can immediately understand "where things live."

### 2. Excellent README

The ASCII architecture diagram in `README.md` is genuinely helpful. The tiered matching table, cost estimates, and deployment instructions give someone everything they need to understand the system at a high level.

### 3. Consistent Patterns

Once you understand one service, you understand them all:

- Dependency injection via `*ServiceDeps` interfaces
- Configuration via `*ServiceConfig` interfaces
- Environment validation at module load
- Consistent error handling patterns

### 4. Good Test Coverage Structure

Tests live alongside code (`*.test.ts`), making it easy to find them. The test patterns are consistent (mocking AWS clients, Redis, etc.).

### 5. Well-Documented Constants

`src/helpers/constants.ts` documents the rationale for magic numbers—this is often neglected and you've done it well:

```typescript
/** Session cache TTL in Redis: 15 minutes (900 seconds) */
export const SESSION_TTL_SECONDS = 900;
```

---

## Areas for Improvement

### 1. **Type Sprawl Across Files**

**Problem:** Types are defined in multiple places, requiring mental mapping:

- `src/types/fingerprint.ts` → `Fingerprint`
- `src/services/matching/types.ts` → Re-exports `Fingerprint`, adds `MatchResult`, `SessionCacheValue`
- `src/services/profile/types.ts` → Re-exports `Fingerprint`, adds `DeviceProfile`, `ProfileUpdatePayload`

A new engineer will ask: "Where is `Fingerprint` actually defined?" and have to trace through re-exports.

**Recommendation:** Consolidate into `src/types/` with clear file names:

```
src/types/
  fingerprint.ts      # Fingerprint only
  matching.ts         # MatchResult, SessionCacheValue
  profile.ts          # DeviceProfile, ProfileUpdatePayload
  index.ts            # Re-exports all
```

Then have services import from `../../types` directly, no re-exports.

---

### 2. **Implicit Business Logic in `buildBucketKeys`**

**Problem:** The compound bucket strategy is encoded in code but not documented:

```typescript
// Why these three combinations?
// IP + JA4 (network identity)
// GPU + Screen + Timezone (hardware/locale identity)
// Audio + Canvas (rendering identity)
```

The comments explain _what_ but a new engineer won't understand _why_ these specific combinations were chosen over others (e.g., why not IP + timezone?).

**Recommendation:** Add a `docs/MATCHING_STRATEGY.md` that explains the tiered approach and bucket design decisions, or add a block comment above the function.

---

### 3. **Parallel Patterns That Diverge Slightly**

**Problem:** `MatchingService` and `ProfileService` are structurally similar but have subtle differences that aren't obviously intentional:

```typescript
// MatchingService
async runTieredMatching(...): Promise<{ result: MatchResult; tier2TimedOut: boolean }>

// ProfileService
async processProfileUpdate(...): Promise<{ skipped: boolean; reason?: string; ... }>
```

Both return "status plus data" but with different shapes. A new engineer might wonder if this inconsistency is intentional.

**Recommendation:** Either unify the return type pattern or document why they differ.

---

### 4. **Handler Files Mix Concerns**

**Problem:** `src/handlers/matching-worker.ts` does multiple things:

1. Environment validation
2. Redis client initialization (with retry strategy)
3. Service instantiation
4. Lambda handler logic

At 130 lines it's manageable, but the Redis initialization logic is duplicated between `matching-worker.ts` and `profile-updater.ts`:

```typescript
// Both files have this:
function getRedis(): Redis {
  if (!redis) {
    redis = new Redis({
      host: envConfig.REDIS_ENDPOINT,
      port: envConfig.REDIS_PORT,
      tls: {},
      enableReadyCheck: false,
      // ... same config ...
    });
  }
  return redis;
}
```

**Recommendation:** Extract Redis client creation to `src/services/redis-client.ts`:

```typescript
// src/services/redis-client.ts
export function createRedisClient(endpoint: string, port: number): Redis { ... }
```

---

### 5. **CDK Constructs Are Dense**

**Problem:** `lib/stacks/app-stack.ts` is 240 lines with a lot of wiring. The comments help, but a new engineer trying to understand "how does the matching worker get its Redis endpoint?" has to trace through:

1. `app-stack.ts` creates `RedisConstruct`
2. Passes `redis.endpoint` to `WorkersConstruct`
3. `WorkersConstruct` sets it as an environment variable
4. Handler reads from `process.env.REDIS_ENDPOINT`

This is normal for CDK, but the construct files themselves could benefit from interface documentation at the top explaining inputs/outputs.

**Recommendation:** Add JSDoc to construct props interfaces:

```typescript
interface WorkersConstructProps {
  /** Redis endpoint for session caching (e.g., "redis.abc123.cache.amazonaws.com") */
  redisEndpoint: string;
  /** Redis port (typically 6379) */
  redisPort: number;
  // ...
}
```

---

### 6. **Test Mocking is Verbose but Consistent**

**Problem:** Tests have significant boilerplate for mocking:

```typescript
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-matching-worker-test";
  // ... 8 more env vars ...
});
```

This is repeated in both handler test files.

**Recommendation:** Create a test utility:

```typescript
// tests/helpers/test-env.ts
export function setupMatchingWorkerEnv() {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-matching-worker-test";
  // ...
}
```

---

### 7. **Go Code is Minimal and Clear**

The Go ingestion handler (`cmd/ingestion/main.go`) is refreshingly simple—just 150 lines doing exactly what it says. No complaints here. A Go developer could pick this up in 10 minutes.

---

### 8. **Some Dead/Future Code**

**Problem:** There are references to features not yet implemented:

```typescript
// Tier 3: Vector similarity (TODO: implement when Qdrant is deployed)
```

```typescript
// QDRANT_ENDPOINT: will be added when Qdrant stack is deployed
```

The bloom filter code exists but isn't used (per AR-21).

**Recommendation:** This is fine for now, but consider adding a `docs/ROADMAP.md` that tracks these TODOs so a new engineer knows what's placeholder vs. intentional omission.

---

## Specific Readability Issues

### 1. **Magic Confidence Values**

```typescript
confidence: 0.99,  // Tier 0.5
confidence: 0.95,  // Tier 1 stable
confidence: 0.85,  // Tier 1 fuzzy
confidence: Math.min(0.6 + bestScore * 0.1, 0.85),  // Tier 2
```

These are scattered through `matching-service.ts`. Consider:

```typescript
const CONFIDENCE = {
  TIER_05_EVERCOOKIE: 0.99,
  TIER_1_STABLE: 0.95,
  TIER_1_FUZZY: 0.85,
  TIER_2_BASE: 0.6,
  TIER_2_PER_BUCKET: 0.1,
  TIER_2_MAX: 0.85,
} as const;
```

### 2. **Risk Score Computation is Clear**

The `computeRiskScore` function in `profile-service.ts` is actually well-structured with `RISK_WEIGHTS` constants. This is a good pattern.

### 3. **The `ideas/` Directory**

Having `ideas/2026-01-11-planning.md` in the repo is helpful for context, but consider moving completed items to a `docs/decisions/` ADR-style format.

---

## Onboarding Estimate

| Engineer Level                       | Time to Productive              |
| ------------------------------------ | ------------------------------- |
| Senior with AWS/CDK experience       | 1-2 days                        |
| Mid-level with TypeScript experience | 3-5 days                        |
| Mid-level new to AWS                 | 1-2 weeks                       |
| Junior                               | Would struggle without guidance |

The main friction points for a mid-tier engineer would be:

1. Understanding the CDK → Lambda → DynamoDB/Redis flow
2. Tracing type definitions across files
3. Understanding _why_ the tiered matching strategy exists

---

## Quick Wins for Maintainability

1. **Add a `CONTRIBUTING.md`** with "how to run locally" and "how to add a new matching tier"
2. **Extract Redis client creation** to reduce duplication
3. **Consolidate types** into `src/types/` without re-exports
4. **Add JSDoc to construct interfaces** in `lib/constructs/`
5. **Create test helpers** for environment setup

---

## Bottom Line

This is a **solid codebase** for a fraud detection system. The architecture is sound, the separation of concerns is good, and the documentation (especially the README and planning doc) gives context. A mid-tier engineer with TypeScript and some AWS exposure could be productive within a week. The main improvement opportunity is reducing the cognitive load of tracing types and Redis setup across files.

This is **not discombobulated**. In fact, this is an exceptionally clean, well-architected, and mature codebase for a TypeScript/AWS CDK project.

To answer your specific question: **Yes, a mid-tier engineer could pick this up very quickly.**

Here is the critique broken down by Readability and Maintainability.

### 1. Readability (The "Mid-Tier" Onboarding Experience)

If I were a new engineer dropping into this repo today, here is why I would be happy:

- **The README is Gold:** The ASCII architecture diagrams (`V4 Architecture`) and the explicit table explaining the "Tiered Matching Strategy" provide immediate context. Most repos lack this "Mental Model" documentation.
- **Folder Structure is Intuitive:**
- `lib/constructs`: Infrastructure components are isolated (Redis, SQS, DynamoDB). You don't have a 2,000-line `stack.ts` file.
- `src/handlers`: Thin entry points for Lambda.
- `src/services`: The actual business logic.
- `cmd/ingestion`: The high-performance Go component is clearly separated.

- **Dependency Injection (DI):** The pattern used in `MatchingService` and `ProfileService` is excellent.

```typescript
// Clear dependencies interface
export interface MatchingServiceDeps {
  dynamodb: DynamoDBClient;
  redis: Redis;
  config: MatchingServiceConfig;
}
```

This makes it immediately obvious what external systems the code touches, and it makes the unit tests (`matching-service.test.ts`) readable because you can see exactly what is being mocked.

- **Environment Safety:** You aren't sprinkling `process.env.MY_VAR` throughout the code. The `src/config/env.ts` file consolidates and _validates_ configuration at startup. This prevents the "it crashed 5 minutes in because I forgot a variable" scenario.

### 2. Maintainability (Long-term Health)

- **Infra-Application Sync:** Because you are using CDK, the infrastructure definitions (`lib/`) and the application code (`src/`) live together. A developer changing the DynamoDB schema in `lib/constructs/dynamodb.ts` sees the impact on `src/services/profile/profile-service.ts` immediately.
- **Type Safety:** The TypeScript interfaces in `src/types/fingerprint.ts` are robust. You aren't passing `any` around. The `Fingerprint` interface acts as a contract between the Go ingestion layer and the Node matching layer.
- **Testing Strategy:**
- You have unit tests for the complex logic (`matching-service.test.ts`).
- You are using `vitest` which is fast.
- You are mocking boundaries (`aws-sdk-client-mock`, `ioredis-mock`).

- **Go vs. Node:** While having a hybrid stack (Go for ingestion, Node for processing) adds complexity, it is isolated nicely. The Go code (`cmd/ingestion/main.go`) is "ultra-thin" and essentially finished. A Node developer doesn't need to touch it often.

### 3. Areas for Improvement (The "Critique")

While excellent, here are the friction points a new developer might hit:

**A. The Bloom Filter "Ghost"**

- **Observation:** You have `src/services/bloom/` and tests for it, but the comments say it's "removed per AR-21" and not instantiated.
- **Critique:** Dead code rots. If AR-21 says it's gone, delete the files. Keeping them "just in case" confuses new maintainers ("Do I need to maintain this test?"). Use Git history if you ever need to resurrect it.

**B. Magic Numbers & Configuration**

- **Observation:** You have a `constants.ts` file (Good), but some logic inside `ProfileService` relies on specific weightings (e.g., `RISK_WEIGHTS`).
- **Critique:** These weights (`0.25`, `0.15`) define your business logic. If a Fraud Analyst wants to change them, a dev has to deploy code. Consider moving these weights to DynamoDB or AppConfig eventually so they can be tuned without a deploy.

**C. The "Go" Context Switch**

- **Observation:** The integration relies on the Go service passing data to SQS exactly as the Node service expects it.
- **Critique:** If the `FingerprintPayload` interface changes in TypeScript, the Go struct `FingerprintPayload` must be manually updated. There is no compile-time link between the two.
- **Fix:** Add a CI step or a comment pointer in both files explicitly warning: "If you change this, update the corresponding struct in `cmd/ingestion/main.go`."

**D. Manual Secret Rotation**

- **Observation:** `src/services/rotate-aws-secrets.ts` has a big warning: "WARNING: Rotating keys will invalidate all encrypted data."
- **Critique:** This is a terrifying file for a mid-tier dev to see.
- **Fix:** As per your planning doc, moving to Envelope Encryption (KMS) is the right move to remove this "foot-gun."

### Verdict

**Score: 9/10**

The code is not discombobulated. It is structured, defensive, and uses modern patterns. The `ideas/2026-01-11-planning.md` file you included shows you are already aware of the exact technical debt items (like the Bloom filter and UUID generation) that need fixing.

**Would you like me to generate a specific PR description or Refactoring Checklist for deleting the Bloom Filter code to clean up that bit of confusion?**
