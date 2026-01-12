# Critique Response Plan — 2026-01-12

This document responds to the comprehensive critiques in `2026-01-12-critiques.md` and synthesizes them with the existing action plan in `2026-01-11-planning.md`. The goal is to establish a **prioritized, actionable response** that addresses legitimate concerns while avoiding analysis paralysis.

---

## Executive Summary

The critiques are **largely valid and well-reasoned**. However, they span a wide spectrum from "will break production immediately" to "nice optimization for 30B scale we don't have yet." This response categorizes each critique into one of four buckets:

| Category                     | Count | Action                                     |
| ---------------------------- | ----- | ------------------------------------------ |
| **Accept: Fix Now**          | 6     | Block production deployment until resolved |
| **Accept: Fix Soon**         | 8     | Address within 2 weeks post-launch         |
| **Accept: Defer**            | 7     | Backlog for when we have real traffic data |
| **Disagree / Needs Context** | 5     | Reject or requires product clarification   |

**Estimated effort for "Fix Now" items: 2-3 engineering days.**

---

## Part 1: Fix Now (Pre-Production Blockers)

These issues will cause **immediate failures or security vulnerabilities** in production.

### 1.1 ALB Security Group Bypass (CRITICAL)

**Critique**: The ALB accepts traffic from `0.0.0.0/0`, allowing attackers to bypass CloudFront WAF by hitting the ALB directly.

**Assessment**: **100% valid.** This is a textbook AWS security misconfiguration. An attacker can enumerate the ALB DNS name via Certificate Transparency logs or DNS enumeration.

**Action**:

```typescript
// lib/constructs/ingestion-service.ts
// BEFORE:
albSecurityGroup.addIngressRule(
  ec2.Peer.anyIpv4(),
  ec2.Port.tcp(80),
  "Allow HTTP from anywhere",
);

// AFTER:
albSecurityGroup.addIngressRule(
  ec2.Peer.prefixList("pl-3b927c52"), // CloudFront prefix list (us-east-1)
  ec2.Port.tcp(443),
  "Allow HTTPS from CloudFront only",
);
```

**Note**: The prefix list ID varies by region. Use `aws ec2 describe-managed-prefix-lists --filters "Name=owner-id,Values=AWS"` to find the CloudFront prefix list for your region.

**Effort**: 30 minutes
**Risk if skipped**: WAF bypass, rate limiting bypass, DDoS amplification

---

### 1.2 Lambda Concurrency Cliff (CRITICAL)

**Critique**: Reserved concurrency of 100 with ~100ms processing time = 1,000 req/sec max. At 950 avg QPS, you're at 95% capacity.

**Assessment**: **Valid concern, but severity depends on actual processing time.**

The critique assumes 100ms per invocation. Let's verify:

- Redis cache check: ~5ms
- DynamoDB Tier 1 lookup: ~10-20ms
- Tier 2 queries (if reached): 3x ~20ms = 60ms
- Profile queue write: ~5ms

**Worst case (cache miss + Tier 2)**: ~100ms. **The critique is correct.**

**Action**: Increase reserved concurrency significantly.

```typescript
// lib/constructs/workers.ts
reservedConcurrentExecutions: isProd ? 500 : 50, // Was: 100
```

**Why 500 not unlimited?**: Protect downstream systems (Redis, DynamoDB) from stampede. Increase gradually based on monitoring.

**Additionally**: Set up a CloudWatch alarm for concurrency saturation:

```typescript
const concurrencyAlarm = new cloudwatch.Alarm(this, "ConcurrencyAlarm", {
  metric: matchingWorker.metricConcurrentExecutions(),
  threshold: 400, // 80% of reserved
  evaluationPeriods: 3,
  alarmDescription: "Lambda concurrency approaching limit",
});
```

**Effort**: 1 hour
**Risk if skipped**: SQS queue backup during peak traffic, data loss to DLQ

---

### 1.3 Key Rotation Split-Brain (HIGH)

**Critique**: Key rotation updates the secret atomically, but workers cache for 15 minutes. During rotation, some workers have old key, some have new key. Data encrypted by one is unreadable by the other.

**Assessment**: **Valid.** The existing planning doc (item #2) addresses this but the implementation isn't in place yet.

**Action**: Implement key versioning in secret structure.

```json
{
  "version": "2",
  "current": {
    "ENCRYPTION_KEY": "base64...",
    "HMAC_KEY": "base64...",
    "created_at": "2026-01-12T00:00:00Z"
  },
  "previous": {
    "ENCRYPTION_KEY": "base64...",
    "HMAC_KEY": "base64...",
    "created_at": "2026-01-11T00:00:00Z"
  }
}
```

```typescript
// src/services/encryption/decrypt.ts
export async function decrypt(envelope: EncryptedEnvelope): Promise<Buffer> {
  const secrets = await getSecrets();

  // Try current key first
  try {
    return decryptWithKey(envelope, secrets.current.ENCRYPTION_KEY);
  } catch (e) {
    // Fall back to previous key
    if (secrets.previous) {
      return decryptWithKey(envelope, secrets.previous.ENCRYPTION_KEY);
    }
    throw e;
  }
}
```

**Alternative**: If encryption isn't critical yet (dev/staging only), defer and disable rotation entirely per AR-18.

**Effort**: 4 hours (with tests)
**Risk if skipped**: Data loss during key rotation

---

### 1.4 Mutation Gate Race Condition (HIGH)

**Critique**: `checkMutationGate()` reads, then `setMutationGate()` writes. Two concurrent requests both pass the check.

**Assessment**: **Valid.** Classic TOCTOU bug.

**Action**: Use atomic `SET NX` operation.

```typescript
// src/services/profile/profile-service.ts
async tryAcquireMutationGate(deviceId: string): Promise<boolean> {
  const key = `mutation_gate:${deviceId}`;
  // SET key "1" NX EX 3600 returns "OK" if set, null if key exists
  const result = await this.deps.redis.set(key, "1", "EX", 3600, "NX");
  return result === "OK";
}

// In processProfileUpdate():
const acquired = await this.tryAcquireMutationGate(device_id);
if (!acquired) {
  return { skipped: true, reason: "mutation_gate" };
}
// No separate setMutationGate() call needed
```

**Effort**: 30 minutes
**Risk if skipped**: Write amplification during concurrent bursts, wasted DynamoDB capacity

---

### 1.5 Fingerprint Input Validation (HIGH)

**Critique**: Go service accepts `fingerprint` as raw JSON without validation. Malicious payloads (deeply nested, 10MB) propagate to Lambda.

**Assessment**: **Valid.** Defense in depth requires validation at ingestion.

**Action**: Add size limit and basic structure validation in Go.

```go
// cmd/ingestion/main.go

const maxBodySize = 64 * 1024 // 64KB max payload

func collectHandler(w http.ResponseWriter, r *http.Request) {
    // Limit body size
    r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

    var payload FingerprintPayload
    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields() // Strict parsing

    if err := decoder.Decode(&payload); err != nil {
        if err.Error() == "http: request body too large" {
            http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
            return
        }
        http.Error(w, "invalid JSON", http.StatusBadRequest)
        return
    }

    // Validate fingerprint is an object, not string/array/null
    if len(payload.Fingerprint) < 2 || payload.Fingerprint[0] != '{' {
        http.Error(w, "fingerprint must be an object", http.StatusBadRequest)
        return
    }

    // ... rest of handler
}
```

**Effort**: 1 hour
**Risk if skipped**: DoS via payload size, Lambda OOM, DynamoDB item size limits

---

### 1.6 CORS Configuration (NEEDS CLARIFICATION)

**Critique**: CORS allowlist rejects merchant origins. Merchants can't integrate.

**Assessment**: **This depends on the deployment model.**

Questions for product:

1. Is this a first-party deployment (only our domains call the API)?
2. Or is this a third-party SDK (merchants embed our script)?

**If third-party SDK**: The critique is valid. Fix with origin reflection or `*`.

**If first-party only**: Current CORS is fine. Add our domains to the allowlist.

**Action**: Clarify with product owner. If third-party:

```go
// cmd/ingestion/main.go
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if origin != "" {
            // Permissive for /v1/collect (fire-and-forget, no cookies)
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Tenant-ID")
        }
        // ...
    })
}
```

**Effort**: 1 hour (once decision made)
**Risk if skipped**: Broken integration for merchants (if third-party model)

---

## Part 2: Fix Soon (Post-Launch, Within 2 Weeks)

These issues are real but won't cause immediate production failures.

### 2.1 Tenant ID from Untrusted Header

**Critique**: Any client can claim to be any tenant by setting `X-Tenant-ID`.

**Assessment**: **Valid for multi-tenant production.** Less critical if single-tenant or dev.

**Action**: Tenant ID should be derived from API key authentication, not headers.

```typescript
// Future: src/middleware/auth.ts
export async function extractTenant(apiKey: string): Promise<string> {
  const tenant = await lookupTenantByApiKey(apiKey);
  if (!tenant) throw new UnauthorizedError("Invalid API key");
  return tenant.id;
}
```

**Effort**: 4-8 hours (includes API key management)
**Defer until**: Multi-tenant deployment or paying customers

---

### 2.2 Tier 2 Hot Partition Risk

**Critique**: Common GPU/screen/timezone combos create hot partitions with millions of devices.

**Assessment**: **Valid at scale.** Not a problem until you have millions of devices.

**Action (short-term)**: Reduce Tier 2 bucket TTL to limit accumulation.

```typescript
// src/helpers/constants.ts
export const TIER2_BUCKET_TTL_DAYS = 7; // Was: 60
```

**Action (long-term)**: Move Tier 2 to Redis sorted sets (per backlog item).

**Effort**: 30 minutes (TTL change) / 1 week (Redis migration)
**Defer until**: >1M devices or visible throttling

---

### 2.3 BatchWriteItem Silent Failures for Tier 2

**Critique**: Tier 1 indexes have retry logic; Tier 2 buckets don't.

**Assessment**: **Valid inconsistency.** Should be unified.

**Action**: Apply same retry pattern to Tier 2.

```typescript
// src/services/profile/profile-service.ts
async updateTier2Buckets(...): Promise<number> {
  // Use batchWriteWithRetry instead of raw Promise.all
  await this.batchWriteWithRetry(this.deps.config.tier2BucketsTable, items);
  return items.length;
}
```

**Effort**: 1 hour
**Defer until**: After launch, during stabilization

---

### 2.4 Delete Bloom Filter Code

**Critique**: 200+ lines of unused code in `src/services/bloom/`.

**Assessment**: **Valid.** Dead code is tech debt.

**Action**: Delete the directory entirely. Git history preserves it.

```bash
rm -rf src/services/bloom/
```

**Effort**: 15 minutes
**Defer until**: Post-launch cleanup sprint

---

### 2.5 Delete Unused Tracer Dependency

**Critique**: `@aws-lambda-powertools/tracer` is bundled but not used.

**Assessment**: **Valid.** Bloats bundle size.

**Action**:

```bash
npm uninstall @aws-lambda-powertools/tracer
```

**Effort**: 5 minutes
**Defer until**: Post-launch cleanup sprint

---

### 2.6 Wire or Remove Analytics Pipeline

**Critique**: SNS topic and Firehose exist but nothing publishes to them. Wasting ~$100/month.

**Assessment**: **Valid.** Either use it or delete it.

**Action**:

- **Option A**: Add publishing to matching worker (if analytics needed)
- **Option B**: Delete `FirehoseProcessor` construct and SNS topic (if not needed)

**Effort**: 2 hours (either option)
**Defer until**: Analytics requirements clarified

---

### 2.7 Extract Redis Client to Shared Module

**Critique**: Redis initialization is duplicated between `matching-worker.ts` and `profile-updater.ts`.

**Assessment**: **Valid.** DRY violation.

**Action**:

```typescript
// src/services/redis-client.ts
let redis: Redis | null = null;

export function getRedis(config: { endpoint: string; port: number }): Redis {
  if (!redis) {
    redis = new Redis({
      host: config.endpoint,
      port: config.port,
      // ... shared config
    });
  }
  return redis;
}
```

**Effort**: 30 minutes
**Defer until**: Next code cleanup

---

### 2.8 Increase Test Coverage Thresholds

**Critique**: 25% coverage is too low for fraud detection logic.

**Assessment**: **Valid.** Matching and profile services should have higher coverage.

**Action**: Increase thresholds incrementally.

```typescript
// vitest.config.ts
thresholds: {
  statements: 50, // Was: 25
  branches: 60,   // Was: 40
  functions: 50,  // Was: 25
  lines: 50,      // Was: 25
}
```

**Effort**: Ongoing (write tests as you go)
**Defer until**: Continuous improvement

---

## Part 3: Defer (Backlog for Later)

These are valid optimizations but premature without traffic data.

### 3.1 ECS vs API Gateway

**Critique**: API Gateway direct-to-SQS is cheaper until 3.5B requests/year.

**Assessment**: **Debatable.** The ECS service exists and works. Migration effort is non-trivial.

**Decision**: Keep ECS for now. Revisit if:

- Operational burden becomes significant
- Cost exceeds 2x API Gateway estimate
- Need to add request transformation that's easier in API Gateway

**Rationale**: "If it ain't broke, don't fix it." The Go service has graceful shutdown, custom validation, and header extraction that would need to be replicated.

---

### 3.2 Merge Matching + Profile Lambdas

**Critique**: Two Lambdas with SQS in between is unnecessary. Profile updates could be synchronous in matching worker.

**Assessment**: **Debatable.** Separation provides:

- Independent scaling
- Failure isolation (profile write failures don't affect match responses)
- Clearer metrics per stage

**Decision**: Keep separate for now. Revisit if:

- Profile queue becomes a bottleneck
- Cold start latency becomes unacceptable
- Cost savings >20%

---

### 3.3 VPC Endpoints vs NAT Gateway

**Critique**: NAT Gateway costs ~$400/year per environment. VPC endpoints are cheaper.

**Assessment**: **Valid at scale.** In dev, the cost is acceptable for simplicity.

**Action (prod)**: Add VPC endpoints for SQS and Secrets Manager.

```typescript
// lib/stacks/app-stack.ts (for production)
vpc.addInterfaceEndpoint("SqsEndpoint", {
  service: ec2.InterfaceVpcEndpointAwsService.SQS,
});
vpc.addInterfaceEndpoint("SecretsEndpoint", {
  service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
});
```

**Defer until**: Production cost optimization pass

---

### 3.4 DynamoDB Provisioned Capacity

**Critique**: On-demand is expensive at 30B requests/year. Provisioned with auto-scaling is cheaper.

**Assessment**: **Valid at scale.** Premature to switch before knowing traffic patterns.

**Decision**: Stay on-demand until:

- 3+ months of traffic data
- Clear baseline established
- Cost becomes >$10K/month

---

### 3.5 Move Tier 2 to Redis

**Critique**: DynamoDB queries for high-cardinality buckets are expensive and slow.

**Assessment**: **Valid at scale.** Redis sorted sets are better for this pattern.

**Decision**: Defer until:

- Tier 2 timeout rate >5%
- DynamoDB costs for Tier 2 >$2K/month
- Clear evidence Tier 2 provides fraud detection value

---

### 3.6 WAF Cost Optimization

**Critique**: WAF at CloudFront costs ~$30K/year at scale. Application-level rate limiting is cheaper.

**Assessment**: **Valid at scale.** But WAF provides protections that are hard to replicate:

- Managed rule sets (SQL injection, XSS)
- Geo-blocking
- Bot detection

**Decision**: Keep WAF. Revisit if:

- Hitting rate limit rules incorrectly
- Cost exceeds budget
- Need more sophisticated rate limiting

---

### 3.7 Redis/Fargate Sizing

**Critique**: `cache.r6g.large` and `1024MB` Fargate are oversized.

**Assessment**: **Probably valid.** But right-sizing requires load testing.

**Decision**: Run load test before production. Adjust based on results.

---

## Part 4: Disagree / Needs Context

These critiques are either incorrect or require more information.

### 4.1 Geo-Blocking CN/RU is "Security Theater"

**Critique**: Geo-blocking is easily bypassed via VPN and blocks legitimate users.

**Response**: **Disagree.** This is a business decision, not a security one.

Geo-blocking serves:

- Compliance (OFAC, export controls)
- Reducing attack surface from high-fraud regions
- Not meant to be foolproof

**Decision**: Keep unless product says otherwise.

---

### 4.2 "Insecure Randomness" for session_id

**Critique**: Trusting client-provided `session_id` allows replay attacks.

**Response**: **Context needed.** The `session_id` is provided by the client fingerprint SDK. It's meant to identify the browser session, not be a security token.

If `session_id` is used for:

- **Deduplication only**: Client-provided is fine
- **Authorization**: This would be a bug (but it's not)

**Decision**: No action. Document that `session_id` is untrusted and used for idempotency only.

---

### 4.3 Risk Score "Never Rehabilitates"

**Critique**: Historical risk blending (30% weight) means a bot-flagged device can never fully clear.

**Response**: **This is intentional.** Fraud detection should be sticky. A device that was a bot once is suspicious forever.

If rehabilitation is needed, add explicit flag clearing:

- User completes CAPTCHA → clear `BOT_DETECTED`
- Admin override → reset `risk_score`

**Decision**: No action. Current behavior is by design.

---

### 4.4 Mutation Gate Blocks Legitimate Drift

**Critique**: Device that drifts multiple times within an hour only updates once.

**Response**: **This is intentional.** The mutation gate exists to prevent write amplification. Legitimate drift within an hour is rare.

If this becomes a problem:

- Reduce gate TTL to 15 minutes
- Add bypass for high-drift events

**Decision**: Monitor. No action unless customer reports.

---

### 4.5 `ARGUS_COLUMNS` Schema is "Massive but Unused"

**Critique**: 100+ Glue columns are defined for features not implemented.

**Response**: **Partially valid.** The schema is forward-looking for analytics. It's not "waste" — it's documentation of the target state.

**Decision**: Leave as-is. It costs nothing and serves as a spec.

---

## Implementation Plan

### Day 1: Critical Security & Stability

| Task                                            | Owner | Est. |
| ----------------------------------------------- | ----- | ---- |
| Fix ALB security group (CloudFront prefix list) | -     | 30m  |
| Increase Lambda concurrency to 500              | -     | 30m  |
| Add fingerprint size validation in Go           | -     | 1h   |
| Fix mutation gate race condition (SET NX)       | -     | 30m  |

**Total: ~2.5 hours**

### Day 2: Key Rotation & CORS

| Task                                   | Owner | Est. |
| -------------------------------------- | ----- | ---- |
| Clarify CORS requirements with product | -     | 30m  |
| Implement CORS fix (if needed)         | -     | 1h   |
| Implement key versioning               | -     | 4h   |

**Total: ~5.5 hours**

### Week 1 Post-Launch: Cleanup

| Task                                  | Owner | Est. |
| ------------------------------------- | ----- | ---- |
| Delete bloom filter code              | -     | 15m  |
| Delete tracer dependency              | -     | 5m   |
| Extract Redis client to shared module | -     | 30m  |
| Add retry logic to Tier 2 writes      | -     | 1h   |
| Wire or remove analytics pipeline     | -     | 2h   |

**Total: ~4 hours**

### Week 2 Post-Launch: Hardening

| Task                            | Owner | Est.    |
| ------------------------------- | ----- | ------- |
| Implement tenant authentication | -     | 8h      |
| Reduce Tier 2 bucket TTL        | -     | 30m     |
| Increase test coverage          | -     | Ongoing |

---

## Monitoring Checklist

After implementing fixes, verify with these metrics:

| Metric                            | Target           | Alert Threshold |
| --------------------------------- | ---------------- | --------------- |
| Lambda concurrent executions      | <80% of reserved | >400            |
| Tier2Timeout rate                 | <1%              | >5%             |
| SQS ApproximateAgeOfOldestMessage | <30s             | >60s            |
| DynamoDB ThrottledRequests        | 0                | >0              |
| CloudFront 4xx/5xx error rate     | <0.1%            | >1%             |

---

## Summary

The critiques are professional and thorough. Most are valid. The key insight is **staging**: not everything needs to be fixed before launch.

**Pre-production blockers (6 items)**: Security holes and capacity cliffs that will cause immediate pain.

**Post-launch improvements (8 items)**: Tech debt and optimizations that won't break production.

**Defer (7 items)**: Valid concerns that require traffic data to justify.

**Disagree (5 items)**: Either incorrect assumptions or intentional design decisions.

The codebase is **fundamentally sound**. The critiques identify real issues but don't indicate a broken architecture. Two focused days of work addresses all critical items.
