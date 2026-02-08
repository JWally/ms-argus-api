# ms-argus-api

High-throughput serverless device fingerprinting and fraud detection platform. Ingests browser fingerprints, performs multi-tier device matching, maintains device profiles, and computes risk scores with anomaly detection.

## Architecture

```
                                    +--------------------------------------------------------------+
                                    |                         AWS Cloud                            |
+----------+   +------------+      |  +-------------------------------------------------------+   |
|  Browser |-->| CloudFront |------+->|  API Gateway (HTTP API)                               |   |
|          |   |   + WAF    |      |  |  - Binary media type support (gzip)                   |   |
+----------+   +------------+      |  |  - CORS configuration                                 |   |
                                   |  +-------------------+-----------------------------------+   |
                                   |                      |                                        |
                                   |          +-----------+-----------+                            |
                                   |          v                       v                            |
                                   |  +---------------+      +---------------+                    |
                                   |  |    Lambda     |      |    Lambda     |                    |
                                   |  |  (Ingestion)  |      | (Session Get) |                    |
                                   |  |  POST /v1/    |      | GET /v1/      |                    |
                                   |  |    collect    |      | session/{id}  |                    |
                                   |  +-------+-------+      +-------+-------+                    |
                                   |          |                      |                             |
                                   |          v                      v                             |
                                   |  +---------------+      +---------------+                    |
                                   |  |     SQS       |      |   DynamoDB    |                    |
                                   |  |   (Matching)  |      | SessionCache  |                    |
                                   |  +-------+-------+      +-------+-------+                    |
                                   |          |                      ^                             |
                                   |          v                      |                             |
                                   |  +--------------------------------------+                    |
                                   |  |  Lambda (Matching Worker)            |                    |
                                   |  |  T0.5: Identity (key/cookie/sigint)  |                    |
                                   |  |  T1:   Hash match (stable/fuzzy/JA4) |                    |
                                   |  |  T1.5: SimHash LSH (256-bit fuzzy)   |                    |
                                   |  |  T2:   Vector search (Qdrant)        |                    |
                                   |  |  T2:   Session anchors (IP+UA)       |                    |
                                   |  |  Write result -> SessionCache        |                    |
                                   |  +----------+---+-----------------------+                    |
                                   |   Read/Write ^   | Queue                                     |
                                   |  +----------+|   |  +--------------+   +------------------+  |
                                   |  | DynamoDB  |   +->| SQS (Profile)|-->| Lambda (Profile  |  |
                                   |  |  Tables   |      +--------------+   |  Updater)        |  |
                                   |  +----------++                         | - Mutation gate   |  |
                                   |             ^                          | - Drift detection |  |
                                   |             +--------------------------| - Index writes    |  |
                                   |                                        +------------------+  |
                                   |                                                              |
                                   |   +------------------------------------------------------+   |
                                   |   |  Optional                                            |   |
                                   |   |  - Qdrant vector search (VPC Lambda)                 |   |
                                   |   |  - Valkey/ElastiCache (statistical anomaly tracking) |   |
                                   |   |  - Firehose -> S3 Parquet -> Athena (analytics)      |   |
                                   |   +------------------------------------------------------+   |
                                   +--------------------------------------------------------------+
```

### Key Design Decisions

- **Serverless-first**: Removed VPC, NAT Gateway, ALB, ECS, Redis from the core path. VPC only used for optional Qdrant vector search.
- **HTTP API over REST API**: ~$1/million vs ~$3.50/million (60% cost reduction).
- **DynamoDB over Redis**: Zero idle cost, no VPC required for the hot path.
- **Asynchronous matching**: Ingestion returns 204 immediately; matching happens via SQS. Clients poll `GET /v1/session/{id}` for results.

## Matching Pipeline

### Tiered Matching Waterfall

The matching worker runs a waterfall of progressively weaker signal checks. First match wins — once a tier returns a result, all lower tiers are skipped.

**T0 — Session Cache.** If we've already matched this exact session, return the cached result from DynamoDB. Avoids re-running the entire pipeline on duplicate or retry SQS messages.

**T0.5 — Identity Signals.** Looks up persistent identifiers that the browser has stored or that were injected by edge infrastructure: ECDSA P-256 public key (`pubkey#`), evercookie ID (`evercookie#`), or sigint ID from a third-party cookie (`sigint#`). These are direct key lookups in the Tier1Index table. When present, they're the strongest signal we have — confidence 0.98-0.99.

**T1 — Hash Match.** Two sequential point lookups against the Tier1Index table. First tries `stable#<hash>` — an exact match on a composite of the most stable browser signals (canvas, WebGL, audio context, math constants). If that misses, tries `fuzzy#<hash>` — a broader set of signals that's less strict but catches more devices. Also checks JA4 TLS fingerprint hash. Confidence ranges from 0.80 (JA4) to 0.95 (stable hash), with fuzzy matches scored by how many signals drifted.

**T1.5 — SimHash LSH (Locality-Sensitive Hashing).** For devices whose fingerprint has drifted enough that no exact hash matches, but is still recognizably similar. The 256-bit fuzzy hash is split into 16 bands of 16 bits each. The system queries DynamoDB for devices sharing at least 2 of 16 bands, then scores candidates by Hamming distance on the full 256-bit hash. Two hashes differing by fewer than 16 bits (out of 256) are considered a match. This enables sub-linear fuzzy matching without pairwise comparison across all devices. Confidence: 0.80. Tunable at runtime via environment variables (`SIMHASH_ENABLED`, `SIMHASH_SHADOW`, `SIMHASH_ROLLOUT`, `SIMHASH_HAMMING_THRESHOLD`, `SIMHASH_MAX_CANDIDATES`).

**T2 — Vector Search (optional).** If Qdrant is configured, the full fingerprint is embedded into a 256-dimensional vector and searched by cosine similarity. This is the most expensive tier and requires VPC infrastructure. Confidence: 0.75. Times out after a configurable threshold to avoid blocking the pipeline.

**T2 fallback — Anchor Buckets.** If vector search isn't configured or misses, two short-lived anchor lookups fire as a last resort:

- **Session anchor** (10-min validity, confidence 0.65): composite key of IP + user agent hash + screen dimensions. Catches returning visitors within the same browsing session.
- **IP+UA anchor** (3-min validity, confidence 0.60): just IP + user agent hash. The loosest match — only useful for very recent revisits where nothing else stuck.

These are stored in the Tier2Buckets table with application-enforced TTLs (much shorter than the DynamoDB TTL cleanup).

**New Device.** If every tier misses, a new device ID (`dev_<ULID>`) is minted with confidence 0 and a neutral 0.5 risk score.

### Quick Reference

| Tier | Method         | Confidence | Description                                           |
| ---- | -------------- | ---------- | ----------------------------------------------------- |
| T0   | Session Cache  | N/A        | Already processed (DynamoDB cache hit)                |
| T0.5 | Public Key     | 0.99       | ECDSA P-256 cryptographic identity                    |
| T0.5 | Evercookie     | 0.99       | Hard-to-clear browser storage                         |
| T0.5 | Sigint ID      | 0.98       | Third-party cookie from edge                          |
| T1   | Stable Hash    | 0.95       | Multiple stable browser signals combined              |
| T1   | Fuzzy Hash     | 0.85       | Broader signal set, less strict                       |
| T1   | JA4 Hash       | 0.80       | TLS fingerprint                                       |
| T1.5 | SimHash LSH    | 0.80       | 256-bit locality-sensitive hashing (Hamming distance) |
| T2   | Vector Search  | 0.75       | Qdrant cosine similarity (optional, requires VPC)     |
| T2   | Session Anchor | 0.65       | IP + UA hash + screen (10-min window)                 |
| T2   | IP+UA Anchor   | 0.60       | IP + UA hash only (3-min window)                      |
| New  | Generate ULID  | 0.0        | No match found, new device created                    |

## Anomaly Detection

Server-side fraud detection runs during matching to identify spoofing attempts. Anomaly signals are returned in the session response and contribute to `risk_score`.

| Detector            | Signals                                                   | Description                                                           |
| ------------------- | --------------------------------------------------------- | --------------------------------------------------------------------- |
| Fingerprint Signals | `HEADLESS_DETECTED`, `HIGH_PROXY_SCORE`, `HIGH_VPN_SCORE` | Pre-computed signal checks: headless browser, proxy/VPN scores        |
| Worker Scope        | `WORKER_MISMATCH`                                         | Navigator vs Worker/SharedWorker/ServiceWorker scope mismatches       |
| Network             | `IP_TIMEZONE_MISMATCH`, `SERVER_CLIENT_TZ_MISMATCH`       | IP geolocation timezone vs reported timezone                          |
| Baseline Rules      | `WORKER_UA_MISMATCH`                                      | User-Agent mismatch between main thread and worker contexts           |
| Statistical V2      | Shannon entropy scoring                                   | Detects rare fingerprint combinations using Valkey frequency counters |
| Network Baseline    | ASN consistency scoring                                   | Per-browser network profile baselines via Valkey                      |

### Multi-Worker Environment Detection

Compares attributes across all JavaScript execution contexts (main thread, Dedicated Workers, Shared Workers, Service Workers). Spoofers who modify the main thread navigator but forget to patch worker contexts are detected.

## Profile Management

### Profile Updater

Maintains device profiles and search indexes. Triggered by SQS from the matching worker.

- **Mutation gating**: DynamoDB conditional write prevents updates for 1 hour after last write, reducing hot-partition writes.
- **Drift detection**: Skips update if stable_hash hasn't changed AND fewer than 2 secondary signals differ.
- **Index writes**: Updates Tier1Index (O(1) hash lookups) and Tier2Buckets (SimHash band entries, session anchors).

### Data Layer

| Table          | Key Schema                           | Purpose                                     | TTL                             |
| -------------- | ------------------------------------ | ------------------------------------------- | ------------------------------- |
| SessionCache   | `cache_key` (PK)                     | Match results + mutation gates              | 15 min (sessions), 1 hr (gates) |
| SessionPayload | `session_id` (PK)                    | Full fingerprint payloads                   | 30 min                          |
| Profiles       | `device_id` (PK)                     | Device profile blobs                        | 60 days                         |
| Tier1Index     | `hash_key` (PK)                      | Hash-to-device lookups (e.g., `stable#abc`) | 60 days                         |
| Tier2Buckets   | `bucket_key` (PK) + `device_id` (SK) | SimHash bands, session anchors              | 90 days (bands), 1 hr (anchors) |
| VectorResults  | `session_id` (PK)                    | Qdrant search results                       | Short                           |

Tier2Buckets uses an **adjacency list pattern** to avoid DynamoDB's 400KB item size limit. Each device in a bucket is a separate item, supporting unlimited devices per bucket via Query operations.

## API

### `POST /v1/collect`

Collect a fingerprint. Returns immediately; matching is async.

**Content Types:**

- `application/json` - Plain JSON
- `application/octet-stream` with `Content-Encoding: gzip` - Binary gzip (recommended for production)

**Request:**

```json
{
  "session_id": "unique-session-id",
  "fingerprint": {
    "loose": {
      "maths": { "$hash": "..." },
      "windowFeatures": { "$hash": "..." },
      "htmlElementVersion": { "$hash": "..." },
      "css": { "$hash": "..." },
      "canvas2d": { "$hash": "..." },
      "offlineAudioContext": { "$hash": "..." },
      "canvasWebgl": {
        "gpu": { "compressedGPU": "ANGLE (NVIDIA...)" },
        "parameters": { "$hash": "..." },
        "extensions": { "$hash": "..." },
        "shaderPrecisions": { "$hash": "..." }
      },
      "screen": { "width": 1920, "height": 1080 }
    },
    "hashes": {
      "stable": "abc123",
      "fuzzy": "def456"
    },
    "botSignals": {
      "isHeadless": false,
      "isAutomation": false
    }
  },
  "sigint": {
    "evercookie_id": "...",
    "ja4": "t13d1516h2_...",
    "public_key": "...",
    "sigint_id": "..."
  }
}
```

**Response:** `204 No Content`

**Headers:**

- `X-Tenant-ID`: Optional tenant identifier (defaults to `default`)
- `X-API-Key`: API key for authentication (optional)

### `GET /v1/session/{session_id}`

Retrieve match results for a session.

**Response:**

```json
{
  "session_id": "unique-session-id",
  "status": "matched",
  "device_id": "dev_abc123",
  "confidence": 0.95,
  "match_tier": "STABLE_HASH",
  "risk_score": 15,
  "flags": ["returning_user"],
  "evidence_codes": ["STABLE_HASH_MATCH"],
  "anomalies": [
    {
      "type": "CROSS_FIELD",
      "code": "NAVIGATOR_LIES",
      "severity": 0.7,
      "evidence": {
        "expected": "0 lies",
        "actual": "2 lies detected",
        "fields": ["lie_count"]
      }
    }
  ]
}
```

### `GET /health`

Health check. Returns `{ "status": "healthy" }`.

## Risk Flags

| Flag                   | Category | Description                              |
| ---------------------- | -------- | ---------------------------------------- |
| `new_device`           | Neutral  | Device just created                      |
| `verified`             | Positive | Additional authentication passed         |
| `returning_user`       | Positive | Seen in previous sessions                |
| `bot_detected`         | Negative | Automated bot behavior                   |
| `headless_browser`     | Negative | Headless browser environment             |
| `fingerprint_mismatch` | Negative | Doesn't match stored profile             |
| `rapid_requests`       | Negative | Unusually high request rate              |
| `navigator_lies`       | Anomaly  | Navigator API tampering                  |
| `likely_proxy`         | Anomaly  | Proxy detected                           |
| `likely_vpn`           | Anomaly  | VPN detected                             |
| `worker_mismatch`      | Anomaly  | Worker context doesn't match main thread |
| `ip_timezone_mismatch` | Anomaly  | IP geo vs client timezone                |
| `new_asn_for_device`   | Anomaly  | Device on a new ASN                      |
| `ip_churn`             | Anomaly  | Cycling through excessive IPs            |

## Project Structure

```
src/
  handlers/
    ingestion.ts              # POST /v1/collect - validates, decompresses, queues
    session-get.ts            # GET /v1/session/{id} - returns match results
    matching-worker.ts        # SQS consumer - runs tiered matching
    profile-updater.ts        # SQS consumer - updates profiles and indexes
    vector-worker.ts          # Optional VPC Lambda - Qdrant vector operations
  services/
    matching/
      matching-service.ts     # Orchestrates tiered matching waterfall
      index-lookup.ts         # T0.5 identity + T1 hash lookups
      simhash-match.ts        # T1.5 SimHash LSH fuzzy matching
      vector-match.ts         # T2 Qdrant vector similarity
      session-anchors.ts      # T2 ephemeral IP+UA matching
      fingerprint-extractor.ts
      profile-loader.ts
    profile/
      profile-service.ts      # Device profile CRUD + index management
      drift-detection.ts      # Detects significant fingerprint changes
      flag-computation.ts     # Computes risk flags
      index-writers.ts        # Writes Tier1Index and Tier2Buckets entries
      anomaly/
        detector.ts           # Orchestrates all anomaly detectors
        fingerprint-signals.ts       # Headless, proxy, VPN detection
        worker-scope-consistency.ts  # Navigator vs worker scope mismatches
        network.ts            # IP timezone mismatch
        baseline-rules.ts     # Worker UA mismatch detection
        statistical-v2.ts     # Shannon entropy via Valkey
        network-baseline-detector.ts  # ASN consistency baselines
    cache/
      dynamo-cache.ts         # Session cache + mutation gates (DynamoDB)
      valkey-client.ts        # Optional Valkey (Redis) for frequency tracking
    vector/
      qdrant-client.ts        # Qdrant HTTP API client
      embedding.ts            # Fingerprint -> 256-dim vector embedding
  types/
    fingerprint.ts            # 120+ fingerprint signal types
    matching.ts               # Evidence codes, anomaly signals, match results
    matching-tiers.ts         # Tier constants (CACHE, IDENTITY, HASH, SIMHASH, VECTOR)
    profile.ts                # DeviceProfile schema
    flags.ts                  # Risk flag enum
  helpers/
    constants.ts              # TTLs, thresholds, SimHash config, feature flags
    payload-schema.ts         # V3 payload validation schema
    normalize-fingerprint.ts  # Input sanitization
    hash.ts                   # FNV-1a, Hamming distance
    bucket-keys.ts            # Key builders for SimHash bands, session anchors
    sqs-batch.ts              # SQS batch processing with partial failure reporting
    batch-write.ts            # DynamoDB batch write helper
lib/
  stacks/
    app-stack.ts              # Main CDK stack (composes all constructs)
  constructs/
    dynamodb.ts               # 6 DynamoDB tables with auto-scaling
    http-api.ts               # API Gateway routes + binary support
    queues.ts                 # SQS queues + DLQs + alarms
    workers.ts                # Lambda functions + provisioned concurrency
    cloudfront.ts             # CDN + WAF
    analytics.ts              # Firehose -> S3 Parquet pipeline
    vector-worker.ts          # Optional VPC Lambda for Qdrant
    valkey.ts                 # Optional ElastiCache Serverless
  config/
    stage-config.ts           # Dev vs Prod settings
```

## Development

### Prerequisites

- Node.js 20+
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

### Install & Build

```bash
npm install
npm run build
```

### Run Tests

```bash
npm test                # Unit tests (860+ tests)
npm run test:coverage   # With coverage report
npm run test:watch      # Watch mode
npm run test:ui         # Vitest UI
```

### Code Quality

```bash
npm run quality         # Runs all quality checks:
                        #   lint + dependency analysis + dead code + duplication

npm run lint:test       # ESLint (dry run)
npm run lint:fix        # ESLint (auto-fix)
npm run format          # Prettier (fix)
npm run format:check    # Prettier (check)
npm run deps            # Dependency cruiser (circular dependency check)
npm run dead-code       # Knip (unused exports/imports)
npm run duplication     # JSCPD (copy-paste detection)
npm run mutate          # Stryker mutation testing
npm run docs            # TypeDoc HTML generation
```

### Git Hooks (Lefthook)

**Pre-commit** (parallel): TypeScript build, ESLint, Prettier
**Pre-push** (parallel): Tests, build, dependency analysis, dead code check, duplication check

### Deploy

```bash
# Development
npx cdk deploy ms-argus-api-dev-jw --require-approval never

# Production
npx cdk deploy ms-argus-api-prod --require-approval never
```

### Configuration

Stage-specific settings are in `lib/config/stage-config.ts`. Key differences:

| Setting                 | Dev                      | Prod                                                      |
| ----------------------- | ------------------------ | --------------------------------------------------------- |
| DynamoDB billing        | On-demand                | On-demand (switch to provisioned after capacity analysis) |
| WAF                     | Disabled                 | Enabled (600 req/5min rate limit)                         |
| SQS retention           | 1 day                    | 7 days                                                    |
| SQS max receive         | 1 (fail fast)            | 3 (retry)                                                 |
| Matching Lambda         | 1024 MB / 25 concurrency | 512 MB / 1000 concurrency                                 |
| Provisioned concurrency | 0                        | 2                                                         |
| Valkey sample rate      | 100%                     | 1%                                                        |
| Statistical V2          | Enabled                  | Shadow mode                                               |
| Network baseline        | Enabled                  | Shadow mode                                               |

## Environment Variables

### All Handlers

| Variable                       | Description                                |
| ------------------------------ | ------------------------------------------ |
| `SESSION_CACHE_TABLE`          | DynamoDB table for session cache           |
| `PROFILES_TABLE`               | DynamoDB table for device profiles         |
| `TIER1_INDEX_TABLE`            | DynamoDB table for hash indexes            |
| `TIER2_BUCKETS_TABLE`          | DynamoDB table for SimHash bands / anchors |
| `POWERTOOLS_SERVICE_NAME`      | Lambda Powertools service name             |
| `POWERTOOLS_METRICS_NAMESPACE` | CloudWatch namespace                       |

### Ingestion

| Variable                 | Description                               |
| ------------------------ | ----------------------------------------- |
| `SQS_QUEUE_URL`          | SQS queue URL for matching worker         |
| `MAX_BODY_BYTES`         | Max request body (default: 256KB)         |
| `MAX_DECOMPRESSED_BYTES` | Max gzip decompressed size (default: 2MB) |

### Matching Worker

| Variable                      | Description                              |
| ----------------------------- | ---------------------------------------- |
| `PROFILE_QUEUE_URL`           | SQS queue URL for profile updater        |
| `SESSION_PAYLOAD_TABLE`       | DynamoDB table for full payloads         |
| `OBSERVATIONS_STREAM_NAME`    | Optional Firehose delivery stream        |
| `VECTOR_WORKER_ARN`           | Optional Lambda ARN for vector search    |
| `VECTOR_COLLECTION`           | Optional Qdrant collection name          |
| `PAYLOAD_ARCHIVE_BUCKET`      | Optional S3 bucket for payload archiving |
| `PAYLOAD_ARCHIVE_SAMPLE_RATE` | Archive sampling rate (0.0-1.0)          |

### SimHash Feature Flags

| Variable                    | Default   | Description                        |
| --------------------------- | --------- | ---------------------------------- |
| `SIMHASH_ENABLED`           | `"true"`  | Master kill switch                 |
| `SIMHASH_SHADOW`            | `"false"` | Compute but don't use for matching |
| `SIMHASH_ROLLOUT`           | `"100"`   | Percentage rollout (0-100)         |
| `SIMHASH_LATENCY_BYPASS_MS` | `"150"`   | Timeout bypass threshold           |
| `SIMHASH_HAMMING_THRESHOLD` | `"16"`    | Max Hamming distance for match     |
| `SIMHASH_MAX_CANDIDATES`    | `"100"`   | Max candidates to score            |

### Anomaly Detection (Valkey)

| Variable             | Default  | Description              |
| -------------------- | -------- | ------------------------ |
| `VALKEY_ENDPOINT`    | -        | Redis/Valkey endpoint    |
| `GLOBAL_SAMPLE_RATE` | `"0.01"` | Write-side sampling rate |

## Observability

- **Logging**: AWS Lambda Powertools structured JSON logs
- **Metrics**: CloudWatch custom metrics via Powertools (auto-published via Middy)
- **Tracing**: AWS X-Ray active tracing on all Lambda functions
- **Alarms**: SNS topic for CloudWatch alarms (Lambda errors/throttles, SQS backlog, DynamoDB throttles, new device rate anomaly)

## Known Issues

### Incomplete Features

1. **IP History Tracking** - Partially implemented, imports exist but source files are missing:
   - `services/profile/ip-history.ts` (imported in profile-service.ts, vector-match.ts)
   - `services/profile/anomaly/ip-history-detector.ts` (imported in detector.ts, index.ts)
   - Related flags (`new_asn_for_device`, `ip_churn`) are defined but detection not wired up

### Code Quality

2. **Privacy penalties disabled** - `PRIVACY_BROWSER_PENALTY` and `PRIVATE_BROWSING_PENALTY` are hardcoded to 0 in `constants.ts`. Tests expect 0.15 and 0.1 respectively (2 test failures).

3. **Complexity violations** - 3 functions exceed eslint cyclomatic/cognitive complexity limits:
   - `handleSyncInvoke()` in vector-worker sync handler (14 cyclomatic, max 10)
   - `detectWorkerUaMismatch()` in baseline-rules.ts (11 cyclomatic, max 10)
   - `normalizeBrowserName()` in ua-family.ts (12 cyclomatic, max 10)

4. **Unused exports** - `getClient()` in `valkey-client.ts` is exported but never used externally.

5. **Code duplication** - 9 clones at 0.49% (async Lambda invocation pattern, config setup pattern, Lambda client creation).

## Cost Estimate (30B requests/year)

| Component     | Cost/Year    |
| ------------- | ------------ |
| CloudFront    | ~$22,500     |
| API Gateway   | ~$30,000     |
| Lambda        | ~$20,000     |
| SQS           | ~$10,000     |
| DynamoDB      | ~$15,000     |
| S3 + Firehose | ~$2,000      |
| **Total**     | **~$99,500** |

~$3.32/million requests

## Related Repositories

- [`ms-argus-web`](../ms-argus-web) - Browser fingerprinting library (generates the fingerprints this API ingests)
- [`ms-argus-demo`](../ms-argus-demo) - Demo site for testing fingerprint collection
- `ms-argus-automation` - Integration test suite
