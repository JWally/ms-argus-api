# ms-argus-api

High-throughput device fingerprint ingestion and matching pipeline for fraud detection.

## V4 Architecture

```
                                    ┌──────────────────────────────────────────────────────────────┐
                                    │                         AWS Cloud                            │
┌──────────┐   ┌────────────┐      │  ┌───────────┐    ┌─────────────────────────────────────┐   │
│  Browser │──▶│ CloudFront │──────┼─▶│    ALB    │───▶│  ECS Fargate (Go Ingestion)         │   │
│          │   │   + WAF    │      │  └───────────┘    │  - Validate JSON                    │   │
└──────────┘   └────────────┘      │                   │  - Extract tenant                   │   │
                                   │                   │  - Send to SQS → 204                │   │
                                   │                   └─────────────────┬───────────────────┘   │
                                   │                                     │                        │
                                   │                                     ▼                        │
                                   │                   ┌─────────────────────────────────────┐   │
                                   │                   │     SQS (Matching Queue)            │   │
                                   │                   └─────────────────┬───────────────────┘   │
                                   │                                     │                        │
                                   │                                     ▼                        │
                                   │                   ┌─────────────────────────────────────┐   │
                                   │                   │  Lambda (Matching Worker)           │   │
                                   │                   │  - T0: Redis cache check            │   │
                                   │                   │  - T0.5: Evercookie lookup          │   │
                                   │                   │  - T1: Hash match (stable/fuzzy)    │   │
                                   │                   │  - T2: Compound filter match        │   │
                                   │                   │  - Write result → Redis             │   │
                                   │                   └────────────┬────┬──────────────────┘   │
                                   │                    Read/Write ◀┘    └▶ Queue               │
                                   │                   ┌────────────┐    ┌──────────────────┐   │
                                   │                   │   Redis    │    │ SQS (Profile Q)  │   │
                                   │                   │  (Cache)   │    └────────┬─────────┘   │
                                   │                   └────────────┘             │              │
                                   │                                              ▼              │
                                   │                   ┌─────────────────────────────────────┐   │
                                   │                   │  Lambda (Profile Updater)           │   │
                                   │                   │  - Mutation gating (1hr)            │   │
                                   │                   │  - Drift detection                  │   │
                                   │                   │  - Update profiles + indexes        │   │
                                   │                   └────────────────┬────────────────────┘   │
                                   │                                    │                        │
                                   │                                    ▼                        │
                                   │                   ┌─────────────────────────────────────┐   │
                                   │                   │            DynamoDB                 │   │
                                   │                   │  - Profiles (device data)           │   │
                                   │                   │  - Tier1Index (hash lookups)        │   │
                                   │                   │  - Tier2Buckets (compound filters)  │   │
                                   │                   └─────────────────────────────────────┘   │
                                   │                                                             │
                                   │   ┌─────────────────────────────────────────────────────┐   │
                                   │   │              Analytics Pipeline                     │   │
                                   │   │   SNS → Firehose → S3 (Parquet) → Athena           │   │
                                   │   └─────────────────────────────────────────────────────┘   │
                                   └──────────────────────────────────────────────────────────────┘
```

## Components

### Go Ingestion Service (`cmd/ingestion/`)

Ultra-thin HTTP handler running on ECS Fargate behind an ALB:

- **Routes**: `/health`, `/v1/collect`
- **Behavior**: Validate JSON → Extract tenant → Send to SQS → Return 204
- **Throughput**: Designed for 30B requests/year scale
- **Features**:
  - Graceful shutdown handling
  - Structured JSON logging
  - Automatic tenant extraction from `X-Tenant-ID` header or payload

### Matching Worker (`src/handlers/matching-worker.ts`)

Node.js Lambda that processes fingerprints from SQS and performs device matching:

**Tiered Matching Strategy:**

| Tier | Method          | Confidence | Description                                                 |
| ---- | --------------- | ---------- | ----------------------------------------------------------- |
| T0   | Redis Cache     | N/A        | Session already processed                                   |
| T0.5 | Evercookie      | 0.99       | Hard-to-clear browser storage                               |
| T1   | Stable Hash     | 0.95       | Multiple stable signals combined                            |
| T1   | Fuzzy Hash      | 0.85       | Similar signals, less strict                                |
| T2   | Compound Filter | 0.6-0.85   | Multiple weak signals (IP+JA4, GPU+Screen+TZ, Audio+Canvas) |
| New  | Generate UUID   | 1.0        | No match found, create new device                           |

**Output**: Writes result to Redis (15-min TTL) and queues profile update.

### Profile Updater (`src/handlers/profile-updater.ts`)

Node.js Lambda that maintains device profiles and search indexes:

- **Mutation Gating**: Redis key prevents writes for 1 hour after update
- **Drift Detection**: Skips update if <2 signals changed
- **Updates**:
  - `Profiles` table: Full device profile with TTL
  - `Tier1Index`: O(1) hash lookups (evercookie, stable/fuzzy hash, JA4)
  - `Tier2Buckets`: Compound filter buckets for multi-signal matching

### Data Layer

| Component                 | Purpose                       | TTL                               |
| ------------------------- | ----------------------------- | --------------------------------- |
| **Redis**                 | Session cache, mutation gates | 15 min (sessions), 1 hour (gates) |
| **DynamoDB Profiles**     | Device profiles               | 60 days                           |
| **DynamoDB Tier1Index**   | Hash-based lookups            | 60 days                           |
| **DynamoDB Tier2Buckets** | Compound filter matching      | 60 days                           |
| **S3**                    | Analytics (Parquet)           | Configurable                      |

## API

### `POST /v1/collect`

Collect fingerprint data from a client.

**Request:**

```json
{
  "session_id": "unique-session-id",
  "tenant_id": "optional-tenant-id",
  "fingerprint": {
    "stable_hash": "abc123",
    "fuzzy_hash": "def456",
    "canvas_hash": "...",
    "webgl_hash": "...",
    "audio_hash": "...",
    "gpu_renderer": "...",
    "screen_dims": "1920x1080",
    "timezone": "America/New_York",
    "evercookie_id": "...",
    "ja4": "..."
  },
  "tcp_blob": "base64-encrypted-tcp-fingerprint",
  "tls_blob": "base64-encrypted-tls-fingerprint"
}
```

**Response:** `204 No Content`

**Headers:**

- `X-Tenant-ID`: Optional tenant identifier (defaults to `default`)

### `GET /health`

Health check endpoint.

**Response:**

```json
{ "status": "healthy" }
```

## Development

### Prerequisites

- Node.js 20+
- Go 1.21+
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

### Install Dependencies

```bash
npm install
cd cmd/ingestion && go mod download
```

### Run Tests

```bash
# Node.js tests
npm test

# Go tests
npm run test:go

# All tests with coverage
npm run test:all
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
# TypeScript
npm run build

# Go
npm run go:build
```

## Deployment

### Bootstrap CDK (first time)

```bash
cdk bootstrap
```

### Deploy

```bash
# Development
cdk deploy ms-argus-api-dev

# Production
cdk deploy ms-argus-api-prod
```

### Configuration

Update `bin/config.ts` with:

- AWS Account ID
- Region
- Root domain (for custom domain setup)

## Infrastructure

The CDK stack (`lib/stacks/app-stack.ts`) provisions:

- **VPC**: 2 AZs, public/private subnets, NAT Gateway
- **ECS Fargate**: Go ingestion service behind ALB
- **Lambda**: Matching worker + Profile updater
- **SQS**: Matching queue + Profile queue (with DLQs)
- **ElastiCache**: Redis cluster for session caching
- **DynamoDB**: Profiles, Tier1Index, Tier2Buckets tables
- **CloudFront + WAF**: Edge protection with rate limiting
- **S3 + Firehose + Glue**: Analytics pipeline
- **Route53 + ACM**: Custom domain with SSL

## Observability

- **Logging**: AWS Lambda Powertools with structured JSON
- **Metrics**: Custom CloudWatch metrics for each tier hit, errors, durations
- **Alarms**: SNS topic for CloudWatch alarms
- **Tracing**: X-Ray (temporarily disabled due to bundling issues)

## Git Hooks

Pre-commit and pre-push hooks via [Lefthook](https://github.com/evilmartians/lefthook):

- **Pre-commit**: TypeScript build, ESLint, Prettier
- **Pre-push**: Full test suite

## Related Repositories

- `argus` - Browser fingerprinting library
- `ms-argus-tcp-probe` - TCP/TLS fingerprinting service

## Cost Estimate (30B requests/year)

| Component     | Cost/Year |
| ------------- | --------- |
| CloudFront    | ~$22,500  |
| ECS Fargate   | ~$35,000  |
| Lambda        | ~$15,000  |
| SQS           | ~$10,000  |
| ElastiCache   | ~$8,000   |
| DynamoDB      | ~$12,000  |
| S3 + Firehose | ~$2,000   |
| **Total**     | ~$104,500 |

~$3.48/million requests
