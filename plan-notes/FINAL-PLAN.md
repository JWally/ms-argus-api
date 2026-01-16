# Final Plan: ms-argus-api Tenant Removal + Bug Fixes + Archive

**Synthesized from 3 perspectives after 2 rounds of critique.**

---

## Summary

| Item           | Decision                                      |
| -------------- | --------------------------------------------- |
| Timeline       | **5 days**                                    |
| Table strategy | Modify in place (no v2 tables)                |
| Test strategy  | Run incrementally, note failures, batch fixes |
| Archive        | Hive partitioning + gzip + error logging      |
| Observability  | Structured logging as you go (no dashboards)  |

---

## Day-by-Day Plan

### Day 1: Types + Bucket Keys

**Goal:** Break the foundation, let TypeScript show you everything that depends on it.

1. **Remove `tenant_id` from all interfaces**
   - `src/types/matching.ts`
   - `src/types/profile.ts`
   - Any other type files

2. **Update `src/helpers/bucket-keys.ts`**

   ```typescript
   // Before
   export function buildIpJa4BucketKey(
     tenantId: string,
     ip: string,
     ja4: string,
   ): string {
     return `${tenantId}#ip_ja4#${ip}#${ja4}`;
   }

   // After
   export function buildIpJa4BucketKey(ip: string, ja4: string): string {
     return `ip_ja4#${ip}#${ja4}`;
   }
   ```

   Remove tenant parameter from ALL bucket key functions.

3. **Run tests, capture failures**
   ```bash
   npm test 2>&1 | tee day1-failures.txt
   ```
   Don't fix yet - just understand the blast radius.

**Output:** Type errors everywhere. This is expected.

---

### Day 2: Services

**Goal:** Update all services to work without tenant_id. Add structured logging as you go.

**Order of operations** (dependency order):

1. `src/services/matching/tier05-identity.ts`
2. `src/services/matching/tier1-hash.ts`
3. `src/services/matching/tier2-compound.ts`
4. `src/services/matching/session-anchors.ts`
5. `src/services/matching/matching-service.ts`
6. `src/services/profile/profile-service.ts`
7. `src/services/profile/index-writers.ts`

**For each service:**

1. Remove `tenant_id` from function signatures
2. Remove `tenant_id` from DynamoDB key construction
3. Add basic structured logging at key points:
   ```typescript
   logger.info("tier1_lookup", { hashType, hashValue, found: !!result });
   ```
4. Run tests after each file, note (don't fix) failures

**Output:** Services updated, logging added, list of failing tests.

---

### Day 3: Handlers + Test Fixes

**Goal:** Complete the tenant removal, get all tests passing.

**Morning: Handlers**

1. Update `src/handlers/ingestion.ts`
   - Remove tenant extraction from headers
   - Remove tenant validation
   - Remove tenant from payload construction

2. **Delete these files entirely:**
   - `src/services/get-api-keys-secret.ts`
   - `src/services/get-api-keys-secret.test.ts`
   - Any tenant-guard tests

**Afternoon: Test Fixes**

Work through the failure list from Days 1-2. Most fixes are mechanical:

- Remove `tenant_id: 'test-tenant'` from test payloads
- Update expected DynamoDB keys (remove tenant prefix)
- Delete tests for removed functionality (API key validation)

```bash
npm test  # Should pass (517+ tests)
```

**Output:** All tests passing, ready to deploy.

---

### Day 4: Bug Fixes + Deploy

**Goal:** Fix critical bugs, deploy, verify.

**Bug Fixes:**

1. **ZIP Bomb (SECURITY)**

   File: `src/helpers/middy-helpers.ts`

   ```typescript
   import { createGunzip } from "zlib";
   import { Readable } from "stream";
   import { pipeline } from "stream/promises";

   async function safeGunzip(buffer: Buffer, maxSize: number): Promise<Buffer> {
     const chunks: Buffer[] = [];
     let totalSize = 0;

     const gunzip = createGunzip();
     gunzip.on("data", (chunk: Buffer) => {
       totalSize += chunk.length;
       if (totalSize > maxSize) {
         gunzip.destroy(
           new Error(`Decompressed size exceeds ${maxSize} bytes`),
         );
         return;
       }
       chunks.push(chunk);
     });

     await pipeline(Readable.from(buffer), gunzip);
     return Buffer.concat(chunks);
   }
   ```

2. **WAF Rate Limit**

   File: `lib/constructs/waf.ts`

   ```typescript
   // Before: Limit: 600,
   // After:
   Limit: config.waf.rateLimitPerFiveMinutes,  // Wire through config
   ```

   File: `lib/config/index.ts`

   ```typescript
   // Update default
   waf: {
     rateLimitPerFiveMinutes: 100000,  // Basically disabled for dev
   }
   ```

3. **S3 Bucket Naming**

   File: `lib/constructs/s3.ts` (or stack)

   ```typescript
   bucketName: `${stackName}-observations-${Stack.of(this).account}-${Stack.of(this).region}`,
   ```

**Deploy + Verify:**

```bash
npm test                                    # All tests pass
npx cdk deploy ms-argus-api-dev-jw --require-approval never
cd ~/Dev/ms-argus-automation && npm test    # Integration tests
```

**Output:** Bug fixes deployed, integration tests passing.

---

### Day 5: Payload Archive

**Goal:** Implement proper payload archiving to S3.

**1. Create S3 Bucket (CDK)**

File: `lib/constructs/s3.ts` or new file

```typescript
const archiveBucket = new s3.Bucket(this, "PayloadArchive", {
  bucketName: `${stackName}-payload-archive-${account}-${region}`,
  encryption: s3.BucketEncryption.S3_MANAGED,
  lifecycleRules: [
    {
      expiration: Duration.days(90),
      transitions: [
        {
          storageClass: s3.StorageClass.INTELLIGENT_TIERING,
          transitionAfter: Duration.days(30),
        },
      ],
    },
  ],
});
```

**2. Add Archive Logic**

File: `src/handlers/ingestion.ts`

```typescript
import { gzipSync } from "zlib";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

const s3 = new S3Client({});
const ARCHIVE_BUCKET = process.env.PAYLOAD_ARCHIVE_BUCKET;
const SAMPLE_RATE = parseFloat(process.env.PAYLOAD_ARCHIVE_SAMPLE_RATE || "0");

async function archivePayload(
  payload: unknown,
  sessionId: string,
): Promise<void> {
  const date = new Date();
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  const d = String(date.getUTCDate()).padStart(2, "0");
  const h = String(date.getUTCHours()).padStart(2, "0");

  // Hive-style partitioning for Athena compatibility
  const key = `year=${y}/month=${m}/day=${d}/hour=${h}/${sessionId}.json.gz`;

  const compressed = gzipSync(JSON.stringify(payload));

  await s3.send(
    new PutObjectCommand({
      Bucket: ARCHIVE_BUCKET,
      Key: key,
      Body: compressed,
      ContentType: "application/json",
      ContentEncoding: "gzip",
    }),
  );
}

// In handler, after parsing payload:
if (ARCHIVE_BUCKET && SAMPLE_RATE > 0 && Math.random() < SAMPLE_RATE) {
  archivePayload(payload, sessionId).catch((err) => {
    logger.error("archive_failed", { sessionId, error: err.message });
  });
}
```

**3. Environment Config**

```typescript
// lib/config/index.ts
payloadArchive: {
  enabled: true,
  sampleRate: 1.0,  // 100% in dev
}
```

**4. Deploy + Test**

```bash
npm test
npx cdk deploy ms-argus-api-dev-jw --require-approval never
# Send test payload, verify it appears in S3
```

**Output:** Archive working, payloads appearing in S3 with proper partitioning.

---

## What We're NOT Doing

| Item                    | Reason                                  |
| ----------------------- | --------------------------------------- |
| DynamoDB pagination fix | Top 10 most recent is the design intent |
| Log retention changes   | It's dev                                |
| Hot partition sharding  | Wait and see if it's a problem          |
| CloudWatch dashboards   | Overkill for dev                        |
| v2 tables / migration   | Data loss acceptable, modify in place   |
| Circuit breakers        | Overkill for dev                        |
| Provisioned concurrency | Waste of money in dev                   |

**Keeping:**

- Warmup rule (per user preference, makes dev feel nicer)

---

## Success Criteria

| Day | Verification                                                   |
| --- | -------------------------------------------------------------- |
| 1   | Types compile (with errors downstream), test failures captured |
| 2   | Services updated, structured logging added                     |
| 3   | All 517+ tests passing                                         |
| 4   | Bug fixes deployed, integration tests passing                  |
| 5   | Payloads archiving to S3 with Hive partitioning                |

**Final verification:**

```bash
# Zero tenant references in code
grep -r "tenant" src --include="*.ts" | grep -v test | wc -l  # Should be 0 or minimal

# Tests pass
npm test

# Integration tests pass
cd ~/Dev/ms-argus-automation && npm test
```

---

## Files Changed Summary

### Delete

- `src/services/get-api-keys-secret.ts`
- `src/services/get-api-keys-secret.test.ts`
- Any tenant-guard tests

### Major Changes

- `src/types/matching.ts` - Remove tenant_id
- `src/types/profile.ts` - Remove tenant_id
- `src/helpers/bucket-keys.ts` - Remove tenant prefix from all functions
- `src/helpers/middy-helpers.ts` - Streaming decompression
- `src/services/matching/*.ts` - Remove tenant from all (6 files)
- `src/services/profile/*.ts` - Remove tenant from all (2 files)
- `src/handlers/ingestion.ts` - Remove tenant extraction, add archive
- `lib/constructs/waf.ts` - Wire config
- `lib/constructs/s3.ts` - Fix naming, add archive bucket
- ~30 test files - Remove tenant from fixtures

---

## Consensus Points (All 3 Perspectives Agreed)

1. **5-6 days is realistic** (not 3, not 7+)
2. **Modify tables in place** (no v2 migration complexity)
3. **Hive partitioning for archive** (Athena-friendly)
4. **Gzip compression** (10x storage savings)
5. **Structured logging as you go** (not a separate phase)
6. **Error logging for async operations** (one line)
7. **Skip: pagination, log retention, hot partitions, dashboards**
8. **Keep: warmup rule**

---

## Risk Mitigation

| Risk                             | Mitigation                        |
| -------------------------------- | --------------------------------- |
| Test fixes take longer           | Budget full afternoon on Day 3    |
| Subtle bugs after tenant removal | Structured logging helps diagnose |
| Archive adds latency             | Fire-and-forget (async)           |
| Archive failures silent          | Error logging (one line)          |
