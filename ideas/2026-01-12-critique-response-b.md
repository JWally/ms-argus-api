# Critique Response Plan B - 2026-01-12

## Executive Summary

The critiques identify **real issues** that require attention. After thorough analysis of the codebase, I've categorized them into three groups:

1. **Valid Critical Issues** - Must fix before production
2. **Valid Improvements** - Should fix, prioritized by impact
3. **Already Addressed or Disagree** - No action needed

**Bottom Line**: The codebase is solid, but has 4-5 critical issues that would cause production incidents if not addressed.

---

## Triage Summary

| Severity         | Count | Estimated Effort |
| ---------------- | ----- | ---------------- |
| P0 (Critical)    | 5     | 1-2 days         |
| P1 (High)        | 4     | 2-3 days         |
| P2 (Medium)      | 6     | 2-3 days         |
| P3 (Low/Cleanup) | 6     | 1 day            |
| Already Fixed    | 5     | -                |
| Disagree         | 2     | -                |

---

## P0: Critical Issues (Must Fix Before Production)

### 1. Lambda Concurrency Cliff

**Critique**: 100 reserved concurrent executions at ~950 req/sec average = 95% capacity. Any spike causes queue backup and data loss.

**Validation**: Confirmed in `lib/constructs/workers.ts:135`:

```typescript
reservedConcurrentExecutions: 100, // Limit concurrency to protect downstream
```

**Assessment**: VALID. This is a ticking time bomb. Black Friday traffic spike = dropped data.

**Fix**:

- Increase to 500-1000 for matching worker
- Increase to 200-500 for profile updater
- Add CloudWatch alarm for `ConcurrentExecutions > 80%`
- Consider removing reserved concurrency entirely (rely on account limits)

**Effort**: 30 minutes

---

### 2. WAF Bypass via Exposed ALB

**Critique**: ALB security group allows `anyIpv4()`, attackers can bypass CloudFront WAF by hitting ALB directly.

**Validation**: Confirmed in `lib/constructs/ingestion-service.ts:122`:

```typescript
albSecurityGroup.addIngressRule(
  ec2.Peer.anyIpv4(), // THE FLAW
  ec2.Port.tcp(80),
  "Allow HTTP from anywhere",
);
```

**Assessment**: VALID SECURITY VULNERABILITY. Certificate transparency logs expose ALB DNS.

**Fix**:

```typescript
// Replace anyIpv4 with CloudFront prefix list
albSecurityGroup.addIngressRule(
  ec2.Peer.prefixList(cloudFrontPrefixListId),
  ec2.Port.tcp(80),
  "Allow HTTP from CloudFront only",
);
```

**Effort**: 1 hour

---

### 3. CORS Blocks Merchant Domains

**Critique**: Fingerprint script runs on merchant sites (`shop-a.com`), but CORS allowlist only includes `argus.pw` domains.

**Validation**: Confirmed in `src/helpers/constants.ts:87-98`:

```typescript
const parseAllowedOrigins = (): string[] => {
  const envOrigins = process.env.ALLOWED_ORIGINS;
  if (envOrigins) {
    return envOrigins.split(",").map((origin) => origin.trim());
  }
  // Falls back to argus.pw domains only
  return [
    "https://api-dev-jw.argus.pw",
    "https://argus.pw",
    "https://www.argus.pw",
  ];
};
```

**Assessment**: VALID. First merchant integration will fail. However, the Go ingestion service handles `/v1/collect`, not Lambda - so this may not apply to the ingestion path. Need to verify if CORS is applied at CloudFront/ALB or Lambda level.

**Clarification**: Verified - Go service has NO CORS handling, CloudFront has NO CORS policy. Browser cross-origin requests WILL fail.

**Fix Required** - Add CORS headers in Go service:

```go
func collectHandler(w http.ResponseWriter, r *http.Request) {
    // Handle preflight
    w.Header().Set("Access-Control-Allow-Origin", "*")  // Fire-and-forget, no credentials
    w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Tenant-ID")

    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return
    }
    // ... rest of handler
}
```

**Effort**: 1 hour

---

### 4. Missing VPC Endpoints (Cost Leak)

**Critique**: Lambda in VPC uses NAT Gateway for SQS and Secrets Manager traffic. Expensive at scale.

**Validation**: No VPC endpoints configured:

```bash
grep -r "VpcEndpoint\|InterfaceVpcEndpoint" lib/  # Returns nothing
```

**Assessment**: VALID. At 30B requests/year with 2KB payloads:

- ~60TB/year through NAT Gateway
- ~$2,700/year in NAT data processing alone
- Plus ~$700/year for NAT Gateway hours

**Fix**: Add interface VPC endpoints for:

- SQS (`com.amazonaws.${region}.sqs`)
- Secrets Manager (`com.amazonaws.${region}.secretsmanager`)
- (DynamoDB gateway endpoint is likely auto-included)

**Effort**: 2 hours

---

### 5. Mutation Gate Race Condition

**Critique**: Check-then-act pattern allows concurrent requests to bypass mutation gate.

**Validation**: Confirmed in `src/services/profile/profile-service.ts:80-93`:

```typescript
async checkMutationGate(deviceId: string): Promise<boolean> {
  const exists = await this.deps.redis.exists(key);  // READ
  return exists === 0;
}
// ... later ...
async setMutationGate(deviceId: string): Promise<void> {
  await this.deps.redis.setex(key, ...);  // WRITE
}
```

**Assessment**: VALID. Two concurrent requests for same device will both see `exists === 0` and both process.

**Fix**: Use atomic `SET NX EX`:

```typescript
async checkAndSetMutationGate(deviceId: string): Promise<boolean> {
  const key = `recently_updated:${deviceId}`;
  // Returns "OK" if set, null if already exists
  const result = await this.deps.redis.set(
    key,
    "1",
    "EX",
    this.deps.config.mutationGateTtlSeconds,
    "NX"
  );
  return result === "OK";
}
```

**Effort**: 1 hour

---

## P1: High Priority Issues

### 6. Tenant ID From Untrusted Header

**Critique**: Anyone can set `X-Tenant-ID` header to impersonate any tenant.

**Assessment**: VALID for multi-tenant deployment. Single-tenant (default) is fine.

**Fix Options**:

1. **API Key validation**: Tenant ID derived from authenticated API key
2. **JWT validation**: Tenant ID from verified token
3. **For now**: Document that single-tenant mode is supported; multi-tenant requires auth layer

**Effort**: 4 hours (proper fix), 30 min (document limitation)

---

### 7. No Fingerprint Input Validation

**Critique**: Go service passes `json.RawMessage` through without size/schema validation.

**Assessment**: VALID. Malicious 10MB nested JSON will propagate to Lambda workers.

**Fix in Go service**:

```go
// Add before json.Decode
if r.ContentLength > 64*1024 {  // 64KB limit
    http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
    return
}

// After decode, validate fingerprint is an object
if !json.Valid(payload.Fingerprint) || payload.Fingerprint[0] != '{' {
    http.Error(w, "Invalid fingerprint format", http.StatusBadRequest)
    return
}
```

**Effort**: 2 hours

---

### 8. FNV-1a Implementations Diverge

**Critique**: Three different FNV-1a implementations with different algorithms.

**Validation**: CONFIRMED - Critical bug found!

```typescript
// middy-helpers.ts - WRONG ALGORITHM (uses addition approximation)
hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);

// matching-service.ts - CORRECT (uses Math.imul)
hash = Math.imul(hash, FNV1A_PRIME);

// bloom-filter.ts - CORRECT (uses Math.imul)
hash = Math.imul(hash, FNV1A_PRIME);
```

**Assessment**: VALID BUG. middy-helpers uses a multiplication _approximation_ that produces different hashes. This could cause deduplication failures.

**Fix**: Single implementation in `src/helpers/hash.ts`, imported everywhere:

```typescript
export function fnv1a(str: string): number {
  let hash = FNV1A_OFFSET_BASIS;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, FNV1A_PRIME);
  }
  return hash >>> 0;
}
```

**Effort**: 1 hour

---

### 9. Tier 2 Bucket Writes Have No Retry

**Critique**: `updateTier2Buckets` uses `Promise.all` with no retry, unlike `batchWriteTier1Indexes`.

**Assessment**: VALID inconsistency. If Tier 2 writes fail, they silently fail.

**Fix**: Add retry logic matching Tier 1, or accept that Tier 2 is best-effort (document decision).

**Effort**: 1 hour (add retry) or 15 min (document)

---

## P2: Medium Priority Issues

### 10. Analytics Pipeline Unused

**Critique**: `fingerprintTopic` is created but nothing publishes to it. Firehose running empty.

**Validation**: Confirmed - no `.publish()` calls to fingerprintTopic in src/.

**Assessment**: VALID. Paying for unused infrastructure.

**Fix Options**:

1. **Wire it up**: Add publish in matching worker for analytics
2. **Delete it**: Remove entire analytics stack until needed

**Recommendation**: Delete for now (YAGNI). Resurrect when analytics is actually needed.

**Effort**: 1 hour to delete, 2 hours to wire up

---

### 11. Bloom Filter Code Still Exists

**Critique**: 459 lines of dead code in `src/services/bloom/`.

**Assessment**: VALID. AR-21 removed usage but left code. Confuses maintainers.

**Fix**: Delete `src/services/bloom/` directory entirely. Git has history.

**Effort**: 15 minutes

---

### 12. Tracer Bundled But Unused

**Critique**: `@aws-lambda-powertools/tracer` in dependencies but commented out.

**Assessment**: VALID. Wastes bundle size and cold start time.

**Fix**: `npm uninstall @aws-lambda-powertools/tracer`

**Effort**: 5 minutes

---

### 13. Rotation Lambda Orphaned

**Critique**: `rotate-aws-secrets.ts` exists with tests but isn't deployed.

**Assessment**: VALID. CI tests code that's never used.

**Fix Options**:

1. Delete entirely (AR-18 disabled rotation)
2. Keep for manual quarterly rotation (add CLI invocation docs)

**Recommendation**: Keep but add README note for manual use. Envelope encryption is the real fix.

**Effort**: 15 minutes

---

### 14. Tier 2 Hot Partition Risk

**Critique**: Common bucket combinations (iPhone 14 + NYC timezone) could have millions of devices, causing DynamoDB throttling.

**Assessment**: VALID at scale. Current `TIER2_BUCKET_LIMIT=1000` is a band-aid.

**Fix Options**:

1. **Short-term**: Lower Tier 2 bucket TTL to 7 days (reduces bucket size)
2. **Medium-term**: Add cardinality check, skip oversized buckets
3. **Long-term**: Move Tier 2 to Redis sorted sets or Qdrant

**Effort**: 1 hour (short-term), 4 hours (medium-term)

---

### 15. Two Lambda Pattern Questionable

**Critique**: Matching worker + Profile worker could be merged. Extra SQS hop adds latency.

**Assessment**: NUANCED. Separation allows:

- Independent scaling
- Isolated failure domains
- Clearer ownership

**Recommendation**: Keep for now. Profile writes are intentionally decoupled from match latency. The SQS hop ensures match results return fast while writes happen async.

**Effort**: N/A (no change recommended)

---

## P3: Low Priority / Cleanup

### 16. Test Coverage Thresholds Low (25%)

**Assessment**: VALID but context matters. Current coverage is actually 52% statements, 95% branches for src/.

**Fix**: Increase thresholds to match reality:

```typescript
thresholds: { statements: 50, branches: 90, functions: 90, lines: 50 }
```

**Effort**: 5 minutes

---

### 17. Go Dockerfile Missing GOARCH

**Assessment**: VALID nit. Build works but implicit.

**Fix**: Add `ENV GOARCH=arm64 GOOS=linux` to Dockerfile.

**Effort**: 5 minutes

---

### 18. Fargate Oversized (1GB RAM)

**Assessment**: VALID. Go service is minimal.

**Fix**: Reduce to 512MB or 256MB after load testing.

**Effort**: 15 minutes + load test

---

### 19. Redis Oversized (r6g.large for prod)

**Assessment**: VALID. 13.5GB RAM when ~3GB needed.

**Fix**: Start with r6g.medium (6.75GB). Monitor and scale.

**Effort**: 15 minutes

---

### 20. NAT Gateway in Dev

**Assessment**: VALID. $400/year waste.

**Fix Options**:

1. Use VPC endpoints (better)
2. Public subnet for dev (cheaper but less realistic)

**Effort**: Included in P0 VPC endpoints fix

---

### 21. ARGUS_COLUMNS Unused

**Assessment**: VALID. 100+ lines of Glue schema for unused analytics.

**Fix**: Delete with analytics pipeline or trim to actual fields.

**Effort**: Included in analytics cleanup

---

## Already Addressed (No Action)

| Issue                     | Status            |
| ------------------------- | ----------------- |
| BatchWriteItem for Tier 1 | Fixed in AR-19    |
| Redis connection settings | Fixed in AR-20    |
| Key rotation              | Disabled in AR-18 |
| Type consolidation        | Fixed in AR-23    |
| Canary deployments        | Added in AR-24    |

---

## Disagree / No Change

### ECS vs API Gateway

**Critique says**: Delete ECS, use API Gateway direct-to-SQS.

**My assessment**: DISAGREE. AR-22 analysis shows:

- ECS: ~$5,200/year at 30B requests
- API Gateway: ~$30,600/year at 30B requests
- **ECS is 6x cheaper at scale**

The break-even is at ~500M requests/year. Unless traffic stays under that, ECS is correct.

### DynamoDB On-Demand Pricing

**Critique says**: Switch to provisioned capacity.

**My assessment**: NOT YET. On-demand is appropriate when:

- Traffic patterns unknown
- System is new
- Spiky traffic expected

Provisioned is cheaper at stable, predictable load. Switch after 3-6 months of production data.

---

## Recommended Execution Order

### Sprint 1: Critical Security & Stability (1-2 days)

1. **Fix ALB security group** (WAF bypass) - 1 hour
2. **Increase Lambda concurrency** - 30 min
3. **Add VPC endpoints** - 2 hours
4. **Fix mutation gate race condition** - 1 hour
5. **Consolidate FNV-1a implementations** - 1 hour

### Sprint 2: Input Validation & Cleanup (1-2 days)

6. **Add fingerprint validation in Go** - 2 hours
7. **Delete bloom filter code** - 15 min
8. **Remove unused tracer dependency** - 5 min
9. **Delete/disable analytics pipeline** - 1 hour
10. **Update test coverage thresholds** - 5 min

### Sprint 3: Optimization (1 day)

11. **Right-size Fargate** (after load test) - 1 hour
12. **Right-size Redis** - 15 min
13. **Add Tier 2 retry logic or document** - 1 hour
14. **Fix Go Dockerfile GOARCH** - 5 min

### Deferred

- CORS configuration (verify if needed for Go ingestion path)
- Tenant authentication (needed for multi-tenant only)
- Tier 2 hot partition mitigation (monitor first)
- Provisioned DynamoDB (after traffic patterns known)

---

## Metrics to Track Post-Fix

1. **ConcurrentExecutions** - Alarm at 80%
2. **Tier2Timeout** count - Should stay near zero
3. **NAT Gateway data processed** - Should drop after VPC endpoints
4. **SQS ApproximateAgeOfOldestMessage** - Queue health
5. **ProfileUpdateError** / **MutationGateSkip** - Verify race condition fix

---

## Sign-Off Checklist

Before production deployment:

- [ ] ALB only accepts CloudFront traffic
- [ ] Lambda concurrency increased
- [ ] VPC endpoints deployed
- [ ] Mutation gate is atomic
- [ ] FNV-1a uses single implementation
- [ ] Go service validates fingerprint size
- [ ] Unused code deleted (bloom, tracer, analytics)
- [ ] Load test passed with right-sized resources
