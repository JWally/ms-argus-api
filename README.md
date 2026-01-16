# ms-argus-api

High-throughput device fingerprint ingestion and matching pipeline for fraud detection.

## Architecture

```
                                    ┌──────────────────────────────────────────────────────────────┐
                                    │                         AWS Cloud                            │
┌──────────┐   ┌────────────┐      │  ┌───────────────────────────────────────────────────────┐   │
│  Browser │──▶│ CloudFront │──────┼─▶│  API Gateway (HTTP API)                               │   │
│          │   │   + WAF    │      │  │  - Binary media type support (gzip)                   │   │
└──────────┘   └────────────┘      │  │  - CORS configuration                                 │   │
                                   │  └───────────────────┬───────────────────────────────────┘   │
                                   │                      │                                        │
                                   │          ┌───────────┴───────────┐                           │
                                   │          ▼                       ▼                           │
                                   │  ┌───────────────┐      ┌───────────────┐                   │
                                   │  │    Lambda     │      │    Lambda     │                   │
                                   │  │  (Ingestion)  │      │ (Session Get) │                   │
                                   │  │  POST /v1/    │      │ GET /v1/      │                   │
                                   │  │    collect    │      │ session/{id}  │                   │
                                   │  └───────┬───────┘      └───────┬───────┘                   │
                                   │          │                      │                            │
                                   │          ▼                      ▼                            │
                                   │  ┌───────────────┐      ┌───────────────┐                   │
                                   │  │     SQS       │      │   DynamoDB    │                   │
                                   │  │   (Matching)  │      │ SessionCache  │                   │
                                   │  └───────┬───────┘      └───────────────┘                   │
                                   │          │                                                   │
                                   │          ▼                                                   │
                                   │  ┌─────────────────────────────────────┐                    │
                                   │  │  Lambda (Matching Worker)           │                    │
                                   │  │  - T0: Session cache check          │                    │
                                   │  │  - T0.5: Evercookie lookup          │                    │
                                   │  │  - T1: Hash match (stable/fuzzy)    │                    │
                                   │  │  - T2: Compound filter match        │                    │
                                   │  │  - Write result → SessionCache      │                    │
                                   │  └────────────┬────┬───────────────────┘                    │
                                   │   Read/Write ◀┘    └▶ Queue                                 │
                                   │  ┌────────────┐    ┌──────────────────┐                     │
                                   │  │  DynamoDB  │    │ SQS (Profile Q)  │                     │
                                   │  │  Tables    │    └────────┬─────────┘                     │
                                   │  └────────────┘             │                               │
                                   │                             ▼                               │
                                   │  ┌─────────────────────────────────────┐                    │
                                   │  │  Lambda (Profile Updater)           │                    │
                                   │  │  - Mutation gating (1hr)            │                    │
                                   │  │  - Drift detection                  │                    │
                                   │  │  - Update profiles + indexes        │                    │
                                   │  └────────────────┬────────────────────┘                    │
                                   │                   │                                         │
                                   │                   ▼                                         │
                                   │  ┌─────────────────────────────────────┐                    │
                                   │  │            DynamoDB                 │                    │
                                   │  │  - Profiles (device data)           │                    │
                                   │  │  - Tier1Index (hash lookups)        │                    │
                                   │  │  - Tier2Buckets (compound filters)  │                    │
                                   │  │  - SessionCache (results + gates)   │                    │
                                   │  └─────────────────────────────────────┘                    │
                                   │                                                             │
                                   │   ┌─────────────────────────────────────────────────────┐   │
                                   │   │         Analytics Pipeline                          │   │
                                   │   │   Firehose → S3 (Parquet) → Athena                 │   │
                                   │   └─────────────────────────────────────────────────────┘   │
                                   └──────────────────────────────────────────────────────────────┘
```

## Components

### Ingestion Lambda (`src/handlers/ingestion.ts`)

Serverless HTTP handler for fingerprint collection:

- **Routes**: `/health`, `/v1/collect`
- **Behavior**: Validate → Decompress (if gzip) → Extract tenant → Send to SQS → Return 204
- **Features**:
  - Binary gzip payload support (`application/octet-stream` + `Content-Encoding: gzip`)
  - Web library format normalization (nested `loose`, `hashes`, `botSignals` objects)
  - API key authentication with multi-tenant support
  - Request deduplication middleware
  - CORS support

### Session Get Lambda (`src/handlers/session-get.ts`)

Returns match results for a session:

- **Route**: `GET /v1/session/{session_id}`
- **Returns**: Match status, device_id, confidence, risk_score, flags, evidence_codes

### Matching Worker (`src/handlers/matching-worker.ts`)

Processes fingerprints from SQS and performs device matching:

**Tiered Matching Strategy:**

| Tier | Method         | Confidence | Description                          |
| ---- | -------------- | ---------- | ------------------------------------ |
| T0   | Session Cache  | N/A        | Session already processed (DynamoDB) |
| T0.5 | Evercookie     | 0.99       | Hard-to-clear browser storage        |
| T1   | Stable Hash    | 0.95       | Multiple stable signals combined     |
| T1   | Fuzzy Hash     | 0.85       | Similar signals, less strict         |
| T1   | JA4 Hash       | 0.80       | TLS fingerprint                      |
| T2   | Session Anchor | 0.75       | IP + UA hash + screen (5-min TTL)    |
| T2   | IP+UA Anchor   | 0.70       | IP + UA hash only (5-min TTL)        |
| T2   | Maths+Window   | 0.70       | Math quirks + window features        |
| T2   | HTML+CSS       | 0.70       | HTML element + CSS support           |
| T2   | GPU+Screen+TZ  | 0.65       | Hardware + location signals          |
| T2   | Audio+Canvas   | 0.65       | Audio context + canvas hash          |
| T2   | WebGL Struct   | 0.60       | WebGL parameters + extensions        |
| T2   | IP+JA4         | 0.60       | Network + TLS combination            |
| New  | Generate UUID  | 1.0        | No match found, create new device    |

**Output**: Writes result to SessionCache and queues profile update.

### Profile Updater (`src/handlers/profile-updater.ts`)

Maintains device profiles and search indexes:

- **Mutation Gating**: DynamoDB key prevents writes for 1 hour after update
- **Drift Detection**: Skips update if <2 signals changed
- **Updates**:
  - `Profiles` table: Full device profile with TTL
  - `Tier1Index`: O(1) hash lookups (evercookie, stable/fuzzy hash, JA4)
  - `Tier2Buckets`: Compound filter buckets for multi-signal matching

### Data Layer

| Component                 | Purpose                         | TTL                               |
| ------------------------- | ------------------------------- | --------------------------------- |
| **DynamoDB SessionCache** | Session results, mutation gates | 15 min (sessions), 1 hour (gates) |
| **DynamoDB Profiles**     | Device profiles                 | 60 days                           |
| **DynamoDB Tier1Index**   | Hash-based lookups              | 60 days                           |
| **DynamoDB Tier2Buckets** | Compound filter matching        | 7 days (anchor: 5 min)            |
| **S3**                    | Analytics (Parquet)             | Configurable                      |

#### Tier2Buckets Schema

Uses an **adjacency list pattern** to avoid DynamoDB's 400KB item size limit:

- **PK**: `bucket_key` (e.g., `tenant#ip_ja4#192.168.1.1#ja4_hash`)
- **SK**: `device_id`

Each device in a bucket is stored as a separate item, allowing unlimited devices per bucket via `Query` operations.

## API

### `POST /v1/collect`

Collect fingerprint data from a client.

**Content Types Supported:**

- `application/json` - Plain JSON
- `application/octet-stream` with `Content-Encoding: gzip` - Binary gzip (recommended)

**Request (Web Library Format):**

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
  "flags": ["CANVAS_BLOCKED"],
  "evidence_codes": ["STABLE_HASH_MATCH"]
}
```

### `GET /health`

Health check endpoint.

**Response:**

```json
{ "status": "healthy" }
```

## Development

### Prerequisites

- Node.js 20+
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

### Install Dependencies

```bash
npm install
```

### Run Tests

```bash
# Unit tests (434+ tests)
npm test

# Unit tests with coverage
npm run test:coverage

# Integration tests (requires deployed stack)
cd ~/Dev/ms-argus-automation && npm test
```

### Lint & Format

```bash
# Check
npm run lint:test
npm run format:check

# Fix
npm run lint:fix
npm run format
```

### Build

```bash
npm run build
```

## Deployment

### Bootstrap CDK (first time)

```bash
cdk bootstrap
```

### Deploy

```bash
# Development
npx cdk deploy ms-argus-api-dev-jw --require-approval never

# Production
npx cdk deploy ms-argus-api-prod --require-approval never
```

### Configuration

Update `bin/config.ts` with:

- AWS Account ID
- Region
- Root domain (for custom domain setup)

## Infrastructure

The CDK stack (`lib/stacks/app-stack.ts`) provisions:

- **API Gateway**: HTTP API with Lambda integrations
- **Lambda**: Ingestion, Session Get, Matching Worker, Profile Updater
- **SQS**: Matching queue + Profile queue (with DLQs)
- **DynamoDB**: Profiles, Tier1Index, Tier2Buckets, SessionCache tables
- **CloudFront + WAF**: Edge protection with rate limiting
- **VPC Endpoints**: DynamoDB, SQS, Secrets Manager (cost optimization)
- **Firehose + S3**: Analytics pipeline to Parquet
- **Route53 + ACM**: Custom domain with SSL

## Observability

- **Logging**: AWS Lambda Powertools with structured JSON
- **Metrics**: CloudWatch metrics via Powertools (auto-published via Middy middleware)
- **Alarms**: SNS topic for CloudWatch alarms

## Git Hooks

Pre-commit and pre-push hooks via [Lefthook](https://github.com/evilmartians/lefthook):

- **Pre-commit**: TypeScript build, ESLint, Prettier
- **Pre-push**: Full test suite

## Related Repositories

- `ms-argus-web` - Browser fingerprinting library
- `ms-argus-automation` - Integration test suite

## Cost Estimate (30B requests/year)

| Component     | Cost/Year |
| ------------- | --------- |
| CloudFront    | ~$22,500  |
| API Gateway   | ~$30,000  |
| Lambda        | ~$20,000  |
| SQS           | ~$10,000  |
| DynamoDB      | ~$15,000  |
| S3 + Firehose | ~$2,000   |
| **Total**     | ~$99,500  |

~$3.32/million requests
