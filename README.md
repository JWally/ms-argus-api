# ms-argus-api

Argus Fraud Detection API - High-throughput fingerprint ingestion pipeline for device identification and fraud detection.

## Architecture

```
Browser → CloudFront/WAF → HTTP API → Lambda → SNS → Firehose → S3 (Parquet)
                                                      ↓
                                               [Future: Analysis Lambda]
```

## Endpoints

- `POST /v1/collect` - Collect fingerprint data (JS fingerprint + TCP/TLS blobs)
- `GET /health` - Health check

## Request Format

```json
{
  "session_id": "unique-session-id",
  "js_fingerprint": {
    "canvas_hash": "abc123",
    "webgl_hash": "def456",
    // ... other fingerprint data from argus library
  },
  "tcp_blob": "base64-encrypted-tcp-fingerprint",
  "tls_blob": "base64-encrypted-tls-fingerprint"
}
```

## Deployment

### Prerequisites

- Node.js 20+
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

### Install dependencies

```bash
npm install
```

### Bootstrap CDK (first time only)

```bash
cdk bootstrap
```

### Deploy

```bash
# Development
cdk deploy ms-argus-api-dev

# Production (when ready)
# cdk deploy ms-argus-api-prod
```

## Configuration

Update `bin/config.ts` with your:
- AWS Account ID
- Region
- Root domain (for custom domain setup)

## Data Storage

Fingerprint data is stored in S3 in Parquet format, partitioned by:
- `year=YYYY/month=MM/day=DD/hour=HH/`

Query with Athena using the auto-created Glue tables.

## Related Repos

- `argus` - Browser fingerprinting library
- `ms-argus-tcp-probe` - TCP/TLS fingerprinting service

## Cost Estimate (30B requests/year)

| Component | Cost/Year |
|-----------|-----------|
| CloudFront | ~$22,500 |
| API Gateway | ~$30,000 |
| Lambda | ~$40,000 |
| SNS | ~$15,000 |
| Firehose | ~$870 |
| S3 | ~$830 |
| **Total** | ~$109,200 |

~$3.64/million requests
