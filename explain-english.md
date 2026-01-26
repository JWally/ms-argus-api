# Argus API: Full Request Flow Walkthrough

This document traces how a browser payload enters the system, gets matched to a device identity, and becomes retrievable as device-intel. Every function called is described with its actual arguments and what it returns.

---

## Architecture Overview

The system is an async pipeline with 4 Lambda functions connected by SQS:

```
Browser (ms-argus-web)
  │
  ▼
[API Gateway] → ingestion Lambda → SQS (matching queue)
                                        │
                                        ▼
                              matching-worker Lambda → DynamoDB (session cache + payload)
                                        │                    │
                                        │                    ▼
                                        │             SQS (profile queue)
                                        │                    │
                                        │                    ▼
                                        │           profile-updater Lambda → DynamoDB (profiles + indexes)
                                        │
                                        ▼
                              [API Gateway] → session-get Lambda → reads DynamoDB
                                                                       │
                                                                       ▼
                                                                 Device Intel Response
```

DynamoDB tables:

- **Session Cache** (`cache_key` PK) - short-lived match results (15 min TTL)
- **Session Payload** (`session_id` PK) - full gzipped response (30 min TTL)
- **Profiles** (`device_id` PK) - device fingerprint history (60 day TTL)
- **Tier1 Index** (`hash_key` PK) - identity/hash → device_id lookups (60 day TTL)
- **Tier2 Buckets** (`bucket_key` PK, `device_id` SK) - compound signal buckets (7 day TTL)

---

## Phase 1: Ingestion (Browser → SQS)

**Entry point:** `src/handlers/ingestion.ts` — exported as `handler`

The handler is wrapped in a Middy middleware chain that runs in order:

1. **`warmup`** — if the event is a CloudWatch scheduled warmup, the Lambda returns immediately (keeps the container warm without processing)

2. **`injectLambdaContext(logger)`** — adds Lambda request context to all log entries

3. **`logMetrics(metrics)`** — auto-publishes CloudWatch metrics at the end of the invocation

4. **`httpHeaderNormalizer()`** — normalizes HTTP header casing (e.g., `content-type` → `Content-Type`)

5. **`binaryGzipBodyParser({ maxBodyBytes: 256KB, maxDecompressedBytes: 2MB }, metrics)`** — if the body is base64-encoded binary (the normal case from ms-argus-web which sends `application/octet-stream`), it:
   - Validates the raw body size is under `MAX_BODY_BYTES` (256KB)
   - Base64-decodes the body
   - Gunzips the binary data using Node's `zlib.gunzipSync`
   - Validates the decompressed size is under `MAX_DECOMPRESSED_BYTES` (2MB)
   - Parses the decompressed bytes as JSON
   - Writes the parsed object to `event.parsedBody`

6. **`jsonBodyParser(metrics)`** — if the body is already JSON (`content-type: application/json`), it just does `JSON.parse` and writes to `event.parsedBody`

7. **`validator({ eventSchema })`** — validates `event.parsedBody` against `payloadJsonSchema` (from `src/helpers/payload-schema.ts`). The schema requires:
   - `identifiers.session_id` (string, min 1 char)
   - `hashes.stable` (string, min 1 char)
   - `hashes.fuzzy` (string, min 1 char)
   - `device` (object)
   - `sigint` (optional object)

8. **`corsMiddleware({ methods: "POST, OPTIONS", headers: "Content-Type, Content-Encoding" })`** — adds CORS headers to response

9. **`jsonErrorHandler({ logger, exposeErrors: "all" })`** — catches any thrown errors and converts them to JSON responses with appropriate status codes

### The Core Handler

After middleware passes, `createBaseHandler(deps)` in `src/handlers/ingestion/base-handler.ts` runs:

**`routeRequest(event)`** — checks the HTTP method and path:

- `GET /health` → returns `{ status: "healthy" }` immediately
- `OPTIONS *` → returns 204 (preflight)
- anything except `POST /v1/collect` → throws 404 or 405

**`getSessionId(payload)`** — extracts `payload.identifiers.session_id` (already validated by middy)

Then the handler builds the SQS message body:

```typescript
const sqsPayload = {
  ...payload, // The full ArgusPayload (identifiers, hashes, device, sigint)
  _headers: {
    "User-Agent": event.headers["user-agent"],
    "Accept-Language": event.headers["accept-language"],
    "X-Forwarded-For": event.headers["x-forwarded-for"],
  },
  _timestamp: Date.now(),
};
```

**`sqs.send(new SendMessageCommand({ QueueUrl, MessageBody: JSON.stringify(sqsPayload) }))`** — enqueues the payload for async processing. If this fails, throws 503.

**`archivePayload(sessionId, payload, { s3, bucket, sampleRate, logger, metrics })`** — fires and forgets (`.catch(() => {})`) a random-sampled S3 archive write. Only runs if `PAYLOAD_ARCHIVE_BUCKET` is set and `Math.random() < sampleRate`.

Returns **204 No Content** to the browser. The browser's job is done.

---

## Phase 2: Matching (SQS → Device Identity)

**Entry point:** `src/handlers/matching-worker.ts` — exported as `handler`

At cold start, the handler:

1. Calls `getMatchingWorkerEnv()` (from `src/config/env.ts`) to validate required env vars: `TIER1_INDEX_TABLE`, `TIER2_BUCKETS_TABLE`, `PROFILES_TABLE`, `SESSION_CACHE_TABLE`, `PROFILE_QUEUE_URL`, `SESSION_PAYLOAD_TABLE`
2. Instantiates `DynamoDBClient`, `SQSClient`, `FirehoseClient`
3. Creates a `DynamoCacheService(dynamodb, { tableName, sessionTtlSeconds: 900, mutationGateTtlSeconds: 3600 })`

On each invocation, `handler(event)`:

1. Calls `createMatchingService({ dynamodb, sqs, cacheService, envConfig })` — builds a `MatchingService` with all tier-specific dependency objects
2. Calls `processSqsBatch(event.Records, processRecordFn, { metrics, logger, successMetric, errorMetric })` — iterates records sequentially, catching errors per-record so a single failure doesn't block the batch

### processRecord (per SQS message)

**File:** `src/handlers/matching-worker/process-record.ts`

**`parseSqsRecord(record, { logger, metrics })`** — (from `./parse-record.ts`):

1. Checks `isWarmupMessage(record.body)` — if body is `{"warmup":true}`, logs and returns null
2. `JSON.parse(record.body)` → `rawPayload: SqsPayload`
3. Normalizes V2→V3: if `rawPayload.sigint` is missing but `rawPayload.network` exists, copies it
4. Extracts `sessionId = rawPayload.identifiers.session_id`
5. Calls **`extractFingerprint(rawPayload, rawPayload._headers)`** (from `src/services/matching/fingerprint-extractor.ts`)

### extractFingerprint

This is a pure transformation that flattens the nested V3 payload structure into a flat `Fingerprint` object. It calls these sub-extractors in order:

1. **`extractIdentifiers(identifiers, fp)`** — copies `evercookie_id` and `public_key` from `identifiers`
2. **`extractWorkerScope(device, fp)`** — from `device.workerScope`: extracts `userAgent` → `user_agent`, `hardwareConcurrency`, `deviceMemory`, `webglRenderer` → `gpu_renderer`, `timezoneLocation` → `timezone`
3. **`extractGpuFallback(device, fp)`** — if gpu_renderer not set from workerScope, tries `device.canvasWebgl.gpu.compressedGPU`
4. **`extractScreen(device, fp)`** — from `device.screen`: builds `screen_dims = "${width}x${height}"`
5. **`extractHashes(hashes, fp)`** — maps named component hashes to fingerprint fields via `HASH_FIELD_MAP`:
   - `canvas2d` → `canvas_hash`
   - `canvasWebgl` → `webgl_hash`
   - `offlineAudioContext` → `audio_hash`
   - `maths` → `maths_hash`
   - `windowFeatures` → `window_features_hash`
   - `htmlElementVersion` → `html_element_hash`
   - `css` → `css_hash`
   - `svg` → `svg_hash`
   - `intl` → `intl_hash`
   - `features` → `features_hash`
   - `consoleErrors` → `console_errors_hash`
   - `clientRects` → `client_rects_hash`
6. **`extractWebglExtensions(device, fp)`** — from `device.canvasWebgl.extensions`: counts array length → `webgl_extensions_count`
7. **`extractSigint(sigint, fp)`** — from the sigint section:
   - `tlsFingerprint.ip` → `ip_address`
   - `tlsFingerprint.ja3` → `ja3`
   - `tlsFingerprint.ja4` → `ja4`
   - `tlsFingerprint.id` → `sigint_id`
   - `tcpProbe.rtt_fingerprint` (or legacy flat structure): `proxy_score`, `vpn_score`, `tcp_rtt_us`
   - `faviconCache.id` → `favicon_cache_id`
   - `stun.publicIp` / `reflexiveIp` → `stun_public_ip`; `stun.localIp` / `localIps[0]` → `stun_local_ip`
8. **`extractIpFallback(headers, fp)`** — if `ip_address` still not set, uses `X-Forwarded-For` header (first IP)
9. **`extractPrivacySignals(device, fp)`** — `device.incognito.privateBrowsing` → `is_private_browsing`; `device.resistance.privacy` → `privacy_browser`
10. **`extractBotSignals(device, fp)`** — `device.headless` → `is_headless`; `device.lies.count` / `totalLies` → `lie_count`

**Result:** A flat `Fingerprint` with all available signals extracted.

### Back in processRecord

After `parseSqsRecord` returns, we have `{ rawPayload, sessionId, fingerprint, payload }`.

**`generateIdempotencyKey(sessionId, fingerprint)`** — computes `fnv1a("${sessionId}:${stable_hash}:${canvas_hash}")` — used to detect duplicate processing.

**`service.checkCache(sessionId)`** — calls `DynamoCacheService.checkSessionCache(sessionId)`:

- Reads DynamoDB key `session:${sessionId}` from Session Cache table
- If found and not expired (checks TTL application-side because DynamoDB TTL is eventually consistent), returns the `SessionCacheValue`
- If `status === "complete"`, we already processed this session → short-circuit with "Tier0CacheHit" metric

### runTieredMatching — The Core Matching Engine

**`service.runTieredMatching(fingerprint)`** (in `src/services/matching/matching-service.ts:160`)

This is where the device gets identified. The tiers run sequentially — first match wins, stopping the cascade:

---

## The Tier System (Deep Dive)

### Tier 0.5: Identity Lookups (confidence 0.98-0.99)

**Trigger:** Fingerprint contains a `public_key`, `evercookie_id`, or `sigint_id` field.

**What it does:** Direct key-value lookup in the Tier1 Index table for an exact match on a persistent device identifier.

**`runTier05Lookups(fingerprint)`** — iterates over three identity sources in priority order:

1. **`tier05PublicKeyLookup(deps, publicKey, fuzzyHash)`** — looks up `pubkey#${publicKey}` in Tier1 Index table
   - If found: returns `{ device_id, confidence: 0.99, match_tier: 0.5, evidence_codes: ["PUBLIC_KEY_MATCH"] }`
   - ECDSA P-256 public key generated by the browser's Web Crypto API — near-perfect identifier

2. **`tier05CookieLookup(deps, evercookieId, fuzzyHash)`** — looks up `evercookie#${evercookieId}`
   - If found: returns `{ device_id, confidence: 0.99, match_tier: 0.5, evidence_codes: ["EVERCOOKIE_MATCH"] }`
   - First-party persistent cookie set by the collection library

3. **`tier05SigintIdLookup(deps, sigintId, fuzzyHash)`** — looks up `sigint#${sigintId}`
   - If found: returns `{ device_id, confidence: 0.98, match_tier: 0.5, evidence_codes: ["SIGINT_ID_MATCH"] }`
   - Third-party cookie (`_fpid`) from `id.argus.pw` CloudFront function with `SameSite=None` — survives first-party cookie clearing

All three call the shared `identityLookup(deps, id, config, incomingFuzzyHash)` which:

- Does `GetItemCommand` on `{ hash_key: "${prefix}${id}" }` in the Tier1 Index table
- If found, also calls `computeFuzzyMatchInfo(incomingFuzzyHash, item.fuzzy_hash)` to compute drift info (Hamming distance between stored and incoming fuzzy hash)
- Returns `MatchResult` with the stored device_id, risk_score, and flags

### Tier 1: Hash Match (confidence 0.85-0.95)

**Trigger:** Fingerprint contains a `stable_hash` or `fuzzy_hash`.

**What it does:** Looks up the full fingerprint hash in the Tier1 Index table. These hashes are computed client-side from multiple browser signals combined.

**`tier1HashMatch(deps, fingerprint)`** (in `src/services/matching/tier1-hash.ts`):

1. First tries **stable hash**: `GetItemCommand` on `{ hash_key: "stable#${fingerprint.stable_hash}" }`
   - If found: returns `{ device_id, confidence: 0.95, match_tier: 1, evidence_codes: ["STABLE_HASH_MATCH"] }`
   - The stable hash includes signals that almost never change for the same browser (engine internals, hardware)

2. If no stable match, tries **fuzzy hash**: `GetItemCommand` on `{ hash_key: "fuzzy#${fingerprint.fuzzy_hash}" }`
   - If found: returns `{ device_id, confidence: 0.85, match_tier: 1, evidence_codes: ["FUZZY_HASH_MATCH"] }`
   - The fuzzy hash includes signals that may drift slightly (screen, some CSS features)

Both compute `fuzzy_match_info` showing the Hamming distance drift from the stored fuzzy_hash.

### Tier 1.5: SimHash LSH Match (confidence 0.60-0.95)

**Trigger:** `SIMHASH_ENABLED=true` env var, fingerprint has a `fuzzy_hash`, and the fingerprint passes rollout bucketing.

**What it does:** Locality-Sensitive Hashing to find devices with _similar_ (not identical) fuzzy hashes. Catches same-browser drift that changes a few bits.

**`tier15SimHashMatch(deps, fingerprint)`** (in `src/services/matching/tier15-simhash.ts`):

1. **Rollout check**: `isRolloutEnabled(fingerprint, flags)` — hashes the fuzzy_hash to a 0-99 bucket, only proceeds if bucket < `SIMHASH_ROLLOUT_PERCENT`

2. **`buildSimHashBandKeys(fingerprint.fuzzy_hash)`** — splits the 64-bit hex hash into 4 bands of 16 bits each:
   - Band 0: chars 0-3 → PK `SIMHASH_BAND#0#${hex}`
   - Band 1: chars 4-7 → PK `SIMHASH_BAND#1#${hex}`
   - Band 2: chars 8-11 → PK `SIMHASH_BAND#2#${hex}`
   - Band 3: chars 12-15 → PK `SIMHASH_BAND#3#${hex}`

3. **`Promise.all(bandKeys.map(band => queryBand(deps, band)))`** — queries all 4 band partitions in parallel
   - Each band query: `QueryCommand` on `{ bucket_key: band.pk }` in the Tier2 Buckets table, `Limit: 100` (per-band cap)
   - Returns `BandCandidate[]` with `{ deviceId, fuzzyHash, lastSeen, bandIndex }`

4. **Latency bypass**: if all 4 queries took > `LATENCY_BYPASS_MS` (150ms), abandons Tier 1.5 (fail open)

5. **`aggregateCandidates(bandResults.flat())`** — groups by device_id, keeps only those appearing in 2+ bands (the `MIN_BANDS_MATCH = 2` threshold)

6. **`scoreCandidates(candidates, incomingHash, threshold, maxCandidates)`** — for each candidate:
   - Computes `hammingDistance(incomingHash, candidate.fuzzyHash)` — bitwise XOR and popcount
   - Filters: only keeps candidates with distance ≤ `HAMMING_THRESHOLD` (4 bits)
   - Sorts by distance ascending, then by recency descending
   - Caps at `MAX_CANDIDATES` (100)

7. **Recency gate**: if the best candidate was last seen > 30 days ago AND hamming distance > 1, rejects it

8. **Confidence formula**: `baseConfidence = 0.90 - hammingDistance * 0.05` + band bonus (up to +0.04 for 4 bands). Clamped to [0.60, 0.95].

9. **Shadow mode**: if `SIMHASH_SHADOW=true`, logs the match but returns null (doesn't use it for real matching)

Result: `{ device_id, confidence, match_tier: 1.5, evidence_codes: ["SIMHASH_MATCH"], simhash_details: { incoming_hash, matched_hash, hamming_distance, similarity, bands_matched } }`

### Tier 2: Compound Bucket Match (confidence 0.30-0.85)

**Trigger:** Always runs if no match found in Tiers 0.5, 1, or 1.5. Requires the fingerprint to have enough non-null fields to form at least one compound bucket key.

**What it does:** Queries multiple compound signal buckets (combinations of weak signals that together identify a device). Scores candidates by how many buckets they appear in.

**`tier2CompoundMatchWithTimeout(deps, fingerprint)`** (in `src/services/matching/tier2-compound.ts`):

Wraps the actual matching in a `Promise.race` with a `TIER2_TIMEOUT_MS` (500ms) timeout. Uses `AbortController` to cancel in-flight DynamoDB requests on timeout.

**`tier2CompoundMatch(deps, fingerprint, { abortSignal })`**:

1. **`buildBucketKeysWithTypes(fingerprint)`** — (from `src/helpers/bucket-keys.ts`) builds compound bucket keys from the defined `BUCKET_DEFS`:

   | Bucket Name     | Fields Required                                      | Example Key                                                 |
   | --------------- | ---------------------------------------------------- | ----------------------------------------------------------- |
   | `ip_ja4`        | `ip_address` + `ja4`                                 | `ip_ja4#203.0.113.5#t13d1517h2_8daaf6152771_b186095e22b0`   |
   | `gpu_screen_tz` | `gpu_renderer` + `screen_dims` + `timezone`          | `gpu_screen_tz#ANGLE (NVIDIA...#1920x1080#America/New_York` |
   | `audio_canvas`  | `audio_hash` + `canvas_hash`                         | `audio_canvas#a1b2c3#d4e5f6`                                |
   | `maths_window`  | `maths_hash` + `window_features_hash`                | `maths_window#abc123#def456`                                |
   | `html_css`      | `html_element_hash` + `css_hash`                     | `html_css#h1h2h3#c1c2c3`                                    |
   | `webgl_struct`  | `webgl_hash` + `webgl_extensions_count` + `svg_hash` | `webgl_struct#w1w2#47#s1s2`                                 |

   Only builds a key if ALL fields for that bucket are non-null/non-empty.

2. **Parallel query + cardinality fetch**:
   - Queries each bucket: `QueryCommand` on `{ bucket_key: key }`, projects only `device_id`, `Limit: 1000`
   - Simultaneously: `fetchBucketCardinalities(deps, bucketKeys)` — `BatchGetItemCommand` to get the `_stats` item for each bucket, which tracks the cardinality count

3. **`scoreDeviceCandidatesWithEvidence(results, bucketInfos)`** — for each device_id found in bucket query results:
   - Increments score by 1 for each bucket the device appears in
   - Tracks which evidence codes (bucket types) matched

4. **`selectBestCandidate(candidates)`** — picks the device with highest score, but ONLY if score ≥ 2 (must appear in at least 2 different compound buckets)

5. **`buildTier2Result(deps, best, fingerprint, { bucketInfos, cardinalities })`**:
   - Loads the device's profile via `loadProfile(deps, best.deviceId)` — `GetItemCommand` on profiles table
   - Computes confidence: `min(0.6 + score * 0.1, 0.85)`
   - **Cardinality penalty**: checks how many of the matched buckets exceed `TIER2_HIGH_CARDINALITY_THRESHOLD` (500 devices). For each high-cardinality bucket, applies proportional penalty of `TIER2_CARDINALITY_PENALTY` (0.3). This prevents carrier-NAT IPs from creating false matches.
   - Final confidence clamped to [0.30, 0.85]

Result: `{ device_id, confidence, match_tier: 2, evidence_codes: [...matched bucket types] }`

### Session Anchors (confidence 0.60-0.65)

**Trigger:** Always runs if Tier 2 didn't find a match. These are short-lived ephemeral entries.

**`sessionAnchorLookup(deps, fingerprint)`** (in `src/services/matching/session-anchors.ts`):

1. **`buildSessionAnchorKey(fingerprint)`** — requires `ip_address`, `user_agent`, `screen_dims`. Builds: `session_anchor#${ip}#${fnv1a(user_agent)}#${screen_dims}`
2. Queries the Tier2 Buckets table for that key, `Limit: 10`, newest first
3. Filters entries: only accepts those with `created_at` within the last `SESSION_ANCHOR_VALIDITY_SECONDS` (10 minutes)
4. If a valid entry found: loads the device profile, returns `{ device_id, confidence: 0.65, evidence_codes: ["SESSION_ANCHOR_BUCKET"] }`

**`ipUaAnchorLookup(deps, fingerprint)`**:

1. **`buildIpUaAnchorKey(fingerprint)`** — requires `ip_address`, `user_agent`. Builds: `ip_ua_anchor#${ip}#${fnv1a(user_agent)}`
2. Same query pattern, but `IP_UA_ANCHOR_VALIDITY_SECONDS` = 3 minutes
3. If found: `{ device_id, confidence: 0.60, evidence_codes: ["IP_UA_ANCHOR_BUCKET"] }`
4. Catches dock/undock screen changes where screen_dims changes but IP+UA stays same

### New Device (tier -1, confidence 0)

**Trigger:** All tiers failed to find a match.

**`createNewDevice()`**:

- Generates a ULID-based device ID: `dev_${ulid()}`
- Returns: `{ device_id, confidence: 0, match_tier: -1, is_new_device: true, risk_score: 0.5, flags: [], evidence_codes: ["NEW_DEVICE"] }`

---

### Privacy Penalty

After the tier cascade returns a result, **`applyPrivacyPenalty(result, fingerprint)`** reduces confidence if privacy measures are detected:

- `privacy_browser` set (Brave, Firefox RFP, Tor, extensions): `-0.15` confidence
- `is_private_browsing` true: `-0.10` confidence
- Stacks (both = -0.25)
- Confidence floored at 0

---

## After Matching: Persist Results

Back in `processRecord` (after `runTieredMatching` returns):

### 1. Anomaly Detection

**`buildAnomalySignals(fingerprint, rawPayload)`** — calls `detectAllAnomalies(fingerprint, rawPayload.device)` which checks for cross-field inconsistencies (navigator lies, screen/CSS mismatches, IP/timezone mismatches, worker scope inconsistencies). Returns `SessionAnomalySignal[]`.

### 2. Write Session Cache

**`service.writeMatchResult({ sessionId, result: matchResult, idempotencyKey, anomalies })`** — calls `DynamoCacheService.writeSessionCache(sessionId, value)`:

- Writes to DynamoDB with key `session:${sessionId}`
- TTL: 15 minutes (900 seconds)
- **Conditional write**: `ConditionExpression: "attribute_not_exists(cache_key) OR confidence < :conf"` — only overwrites if new confidence is higher
- This means if the same session is processed twice (retries, duplicates), the highest-confidence result wins

The `SessionCacheValue` stored contains:

```typescript
{
  status: "complete",
  device_id, risk_score, confidence, match_tier,
  match_version: Date.now(),
  idempotency_key,
  flags, evidence_codes,
  anomalies,           // only if signals detected
  simhash_details,     // only if matched via Tier 1.5
  fuzzy_match_info,    // drift info when fuzzy hash comparison possible
  updated_at: Date.now()
}
```

### 3. Write Session Payload

**`writeSessionPayload({ sessionId, rawPayload, matchResult, anomalies }, deps)`** (in `src/handlers/matching-worker/session.ts`):

Builds a full `SessionResponse` object combining the match result with the original payload data:

```typescript
{
  identifiers: { session_id, device_id, evercookie_id?, public_key? },
  analysis: { status, confidence, match_tier, is_new_device, risk_score, flags, evidence_codes, anomalies?, simhash_details?, fuzzy_match_info? },
  hashes: rawPayload.hashes,
  device: rawPayload.device,
  sigint: rawPayload.sigint,
}
```

This gets gzipped, base64-encoded, and written to the Session Payload table:

```typescript
{
  session_id: { S: sessionId },
  payload_gzip_b64: { S: gzippedBase64 },
  ttl: { N: now + 1800 },           // 30 min TTL
  created_at: { S: iso8601 },
}
```

### 4. Queue Profile Update

**`service.queueProfileUpdate(deviceId, payload, isNewDevice, matchResult)`** — sends SQS message to the profile queue:

```typescript
{
  device_id,
  fingerprint: payload.fingerprint,
  sigint: payload.sigint,
  tcp_blob: payload.tcp_blob,
  tls_blob: payload.tls_blob,
  timestamp: payload.timestamp,
  is_new_device,
  match_tier: matchResult.match_tier,       // for tier-gated identity writes
  evidence_codes: matchResult.evidence_codes,
}
```

### 5. Emit Observation

**`emitObservation({ sessionId, matchResult, tier2TimedOut, durationMs }, deps)`** — if `OBSERVATIONS_STREAM_NAME` is set, writes a record to Kinesis Firehose for analytics/audit trail. Fire-and-forget.

---

## Phase 3: Profile Update (SQS → DynamoDB)

**Entry point:** `src/handlers/profile-updater.ts` — exported as `handler`

Same pattern as matching-worker: validates env, creates clients, wraps in `processSqsBatch`.

### processRecord (per SQS message)

**File:** `src/handlers/profile-updater/process-record.ts`

1. `JSON.parse(record.body)` → `rawPayload: ProfileUpdatePayload`
2. **`normalizeFingerprint(rawPayload.fingerprint, rawPayload.sigint)`** — normalizes the fingerprint from matching (adds any sigint-derived fields that fingerprint-extractor may have computed differently)
3. Calls **`service.processProfileUpdate(payload)`** on the `ProfileService`

### ProfileService.processProfileUpdate

**File:** `src/services/profile/profile-service.ts:298`

This is the orchestrator for all profile writes:

#### Step 1: Mutation Gate

**`tryAcquireMutationGate(device_id)`** — calls `DynamoCacheService.tryAcquireMutationGate(deviceId)`:

- Attempts `PutItemCommand` with key `gate:${deviceId}` and `ConditionExpression: "attribute_not_exists(cache_key)"`
- TTL: 1 hour (3600 seconds)
- If the gate already exists (another Lambda processed this device recently), returns `false` → **short-circuit with `{ skipped: true, reason: "mutation_gate" }`**
- This prevents write amplification when the same device sends many requests

#### Step 2: Load Existing Profile

**`loadExistingProfile(device_id)`** — `GetItemCommand` on `{ device_id }` in the Profiles table. Returns the full `DeviceProfile` or null.

#### Step 3: Drift Detection

**`hasSignificantDrift(existingProfile, fingerprint)`** (from `src/services/profile/drift-detection.ts`):

- If `stable_hash` changed → significant drift (immediate true)
- Otherwise counts changed signals: `canvas_hash`, `webgl_hash`, `audio_hash`, `gpu_renderer`, `screen_dims`
- Drift threshold: 2+ signals changed → true

#### Step 4: Always Refresh Anchors + Tier2 Buckets

Regardless of drift:

**`updateSessionAnchorBucket(deviceId, fingerprint)`** — builds `session_anchor#${ip}#${uaHash}#${screen}` and writes `{ bucket_key, device_id, created_at: Date.now() }` to Tier2 Buckets table

**`updateIpUaAnchorBucket(deviceId, fingerprint)`** — builds `ip_ua_anchor#${ip}#${uaHash}` and writes same pattern

**`updateTier2Buckets(deviceId, fingerprint)`** — for each compound bucket key:

- Writes device membership: `{ bucket_key, device_id, ttl: 7 days }`
- Increments cardinality counter: atomic `ADD cardinality :one` on the `_stats` item for each bucket

#### Step 5: Skip if No Drift

If `existingProfile` exists and no significant drift detected:
→ Returns `{ skipped: true, reason: "no_drift", tier2Writes }` — the tier2/anchor refreshes happened but profile and tier1 index writes are skipped

#### Step 6: Write Profile

**`updateProfile({ deviceId, fingerprint, timestamp, existingProfile, isNewDevice, hasDrift, rawFingerprint })`**:

1. **`computeFlags(fingerprint, existingProfile, { isNewDevice, hasDrift, raw })`** — (from `flag-computation.ts`) detects:
   - Bot signals: SwiftShader GPU, 800x600 screen, bot user-agent patterns, `is_headless` true, high `lie_count`
   - Network anomalies: high proxy_score, high vpn_score
   - Cross-field mismatches (via `detectAllAnomalies`)
   - `RAPID_REQUESTS` if request_count/hours exceeds threshold
   - `RETURNING_USER` if existing profile with history
   - `FINGERPRINT_MISMATCH` if drift detected

2. **`computeRiskScore(flags, existingProfile, isNewDevice)`** — starts with base (0.5 new, 0.3 returning) and adds/subtracts weights per flag. Clamped [0, 1].

3. Writes to Profiles table via `PutItemCommand`:
   ```typescript
   {
     device_id,
     ...fingerprint,                    // all fingerprint fields
     first_seen_at,                     // preserved from existing or set to now
     last_seen_at,                      // only updates if hour changed (reduces write amp)
     request_count: existing + 1,
     updated_at: now,
     ttl: now + 60 days,
     flags,
     risk_score,
   }
   ```

#### Step 7: Write Tier1 Indexes

**`updateTier1IndexesWithEvidence(deviceId, fingerprint, evidence_codes)`**:

Uses the config-driven `INDEX_FIELDS` array to build index entries:

**Hash indexes** (always written):

- `stable#${stable_hash}` → device_id
- `fuzzy#${fuzzy_hash}` → device_id

**Identity indexes** (only written if evidence_codes contains a high-confidence code like `PUBLIC_KEY_MATCH`, `EVERCOOKIE_MATCH`, `SIGINT_ID_MATCH`, `STABLE_HASH_MATCH`):

- `pubkey#${public_key}` → device_id
- `evercookie#${evercookie_id}` → device_id
- `sigint#${sigint_id}` → device_id

This tier-gating prevents "viral spreading" of device_ids from low-confidence Tier 2 matches — you only get identity associations written back when you matched with strong evidence.

Each index entry includes: `{ hash_key, device_id, ttl: 60 days, fuzzy_hash }` (fuzzy_hash stored for drift comparison on next match).

Written via `BatchWriteItemCommand` in batches of 25.

#### Step 8: Write SimHash Bands

**`updateSimHashBands(deviceId, fingerprint)`**:

Only runs if `SIMHASH_ENABLED=true`.

**`buildSimHashBandEntries(deviceId, fingerprint, timestamp)`** — for each of the 4 bands of the fuzzy_hash:

- PK: `SIMHASH_BAND#${bandIndex}#${bandHex}` (same as the band query keys)
- SK: `t#${invertedTimestamp}#${deviceId}` (inverted so newest sorts first)
- Also stores: `fuzzy_hash`, `last_seen`

Written to the Tier2 Buckets table via `BatchWriteItemCommand`.

---

## Phase 4: Session Retrieval (API Gateway → Device Intel)

**Entry point:** `src/handlers/session-get.ts` — exported as `handler`

The consumer (ms-argus-bots, ms-argus-automation, or any API client) calls:

```
GET /v1/session/{session_id}
```

Middleware chain: `injectLambdaContext` → `logMetrics` → `corsMiddleware` → `jsonErrorHandler`

### The Core Handler

**`createBaseHandler(deps)`** in `src/handlers/session-get/base-handler.ts`:

1. **`extractSessionId(event, metrics)`** — validates the path parameter:
   - OPTIONS → throws preflight signal (middleware returns 204)
   - Non-GET → throws 405
   - Missing session_id → throws 400
   - Invalid format (>128 chars or non-alphanumeric) → throws 400

2. **`lookupSession(sessionId, deps)`** — calls `cacheService.checkSessionCache(sessionId)`:
   - Reads DynamoDB key `session:${sessionId}`
   - If not found → throws 404 "Session not found"
   - Returns the `SessionCacheValue` (device_id, confidence, match_tier, flags, etc.)

3. **`fetchPayload(sessionId, deps)`** — reads the Session Payload table:
   - `GetItemCommand` on `{ session_id }`, reads `payload_gzip_b64`
   - Base64-decodes → gunzips → JSON.parse
   - Validates the structure via `validateSessionResponse(parsed)` — checks required fields exist (identifiers.session_id, identifiers.device_id, analysis.status, analysis.confidence, hashes.stable, hashes.fuzzy, device)
   - Returns the full `SessionResponse` or undefined on failure

4. **If payload found**: Returns 200 with the full JSON body (the complete `SessionResponse` with identifiers, analysis, hashes, device, sigint)

5. **If payload not found** (expired, write failed): `buildFallbackResponse(session, sessionId, metrics)`:
   - Returns 200 with `X-Argus-Degraded: true` header
   - Body has the session cache data (device_id, confidence, tier, etc.) but `hashes: { stable: "unavailable", fuzzy: "unavailable" }` and empty device

---

## Complete Response Structure

When the consumer calls `GET /v1/session/{session_id}`, they get:

```json
{
  "identifiers": {
    "session_id": "abc-123-session-id",
    "device_id": "dev_01HXYZ...",
    "evercookie_id": "ec_abc123",
    "public_key": "MFkwEwYHKo..."
  },
  "analysis": {
    "status": "complete",
    "confidence": 0.95,
    "match_tier": 1,
    "is_new_device": false,
    "risk_score": 0.3,
    "flags": ["RETURNING_USER"],
    "evidence_codes": ["STABLE_HASH_MATCH"],
    "anomalies": [],
    "fuzzy_match_info": {
      "incoming_hash": "1234567890abcdef",
      "stored_hash": "1234567890abcdef",
      "hamming_distance": 0,
      "similarity": 1.0
    }
  },
  "hashes": {
    "stable": "a1b2c3d4...",
    "fuzzy": "1234567890abcdef",
    "canvas2d": "...",
    "maths": "..."
  },
  "device": {
    "workerScope": { ... },
    "screen": { "width": 1920, "height": 1080 },
    "canvasWebgl": { ... },
    ...
  },
  "sigint": {
    "tlsFingerprint": { "id": "...", "ip": "203.0.113.5", "ja4": "..." },
    "tcpProbe": { "rtt_fingerprint": { ... } },
    "stun": { "publicIp": "..." }
  }
}
```

---

## Tier Summary Table

| Tier    | Name        | Signals Used                                                           | Confidence             | DynamoDB Pattern                            | Trigger                            |
| ------- | ----------- | ---------------------------------------------------------------------- | ---------------------- | ------------------------------------------- | ---------------------------------- |
| 0       | Cache       | session_id                                                             | N/A (returns existing) | GetItem `session:{id}`                      | Always checked first               |
| 0.5     | Identity    | public_key, evercookie_id, sigint_id                                   | 0.98-0.99              | GetItem `pubkey#`, `evercookie#`, `sigint#` | Any of these fields present        |
| 1       | Hash        | stable_hash, fuzzy_hash                                                | 0.85-0.95              | GetItem `stable#`, `fuzzy#`                 | Hash fields present                |
| 1.5     | SimHash LSH | fuzzy_hash (4 x 16-bit bands)                                          | 0.60-0.95              | Query `SIMHASH_BAND#N#hex`                  | SIMHASH_ENABLED + rollout %        |
| 2       | Compound    | ip+ja4, gpu+screen+tz, audio+canvas, maths+window, html+css, webgl+svg | 0.30-0.85              | Query each bucket key                       | At least one full bucket buildable |
| Session | Anchors     | ip+ua+screen (10min) or ip+ua (3min)                                   | 0.60-0.65              | Query `session_anchor#`, `ip_ua_anchor#`    | Always after Tier 2 fails          |
| -1      | New Device  | None                                                                   | 0                      | None (generates ULID)                       | All tiers failed                   |

---

## Write Amplification Controls

The system has several mechanisms to minimize DynamoDB writes:

1. **Mutation Gate** (1 hour TTL) — only one profile update per device per hour
2. **Drift Detection** — if fingerprint hasn't significantly changed (stable_hash same + <2 signals differ), skips profile/tier1/simhash writes. Only refreshes tier2 buckets and anchors.
3. **Hour-based last_seen** — only updates `last_seen_at` when the hour changes, not every request
4. **Conditional session cache write** — only overwrites if new confidence is higher
5. **Tier-gated identity indexes** — identity indexes (pubkey#, evercookie#, sigint#) only written when match came from strong evidence

---

## DynamoDB Access Patterns Summary

| Table           | Key                             | Operation               | Who Writes      | Who Reads                                       |
| --------------- | ------------------------------- | ----------------------- | --------------- | ----------------------------------------------- |
| Session Cache   | `session:{session_id}`          | Conditional Put         | matching-worker | matching-worker (Tier0), session-get            |
| Session Cache   | `gate:{device_id}`              | Conditional Put         | profile-updater | profile-updater                                 |
| Session Payload | `session_id`                    | Put (gzip+b64)          | matching-worker | session-get                                     |
| Profiles        | `device_id`                     | Put                     | profile-updater | tier2-compound, session-anchors                 |
| Tier1 Index     | `hash_key` (e.g., `stable#abc`) | BatchWrite              | profile-updater | tier05-identity, tier1-hash                     |
| Tier2 Buckets   | `bucket_key` + `device_id` SK   | BatchWrite + Query      | profile-updater | tier2-compound, tier15-simhash, session-anchors |
| Tier2 Buckets   | `bucket_key` + `_stats` SK      | Update (ADD) + BatchGet | profile-updater | tier2-compound                                  |
