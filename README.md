# ms-argus-api

Serverless integrity collection, fraud-signal analysis, and merchant-safe
verdict API for Argus.

The older fingerprint matching/SQS/profile pipeline has been removed. The
current service has two request paths:

```text
Browser SDK
  -> HTTP API POST /v1/integrity-collect
  -> ECDH decrypt + probe redemption + analysis
  -> merchant projection snapshot
  -> DynamoDB + best-effort Firehose archive

Merchant backend
  -> REST API GET /v1/session/{cpi}/{session_id}
  -> API-key gate + signed merchant token + optional SDK attestation
  -> atomic credit debit + consistent DynamoDB read
  -> merchant-safe verdict
```

## Architecture

This is a Lambda application, so a ports/use-cases/adapters split is a better
fit than web-framework MVC:

- `handlers/` are transport adapters. Entry files configure Middy and AWS
  clients; `base-handler.ts` files orchestrate request use cases.
- `analysis/` converts internal browser and network evidence into typed anomaly
  results. It does not shape the merchant response.
- `scoring/` owns verdict-axis math and shared scoring predicates.
- `projections/` owns focused merchant-facing views. These modules hide stored
  row shapes from the main projection orchestrator.
- `services/` owns longer-lived data and network integrations.
- `helpers/` contains wire-protocol, cryptographic, storage, and compatibility
  utilities that do not depend on handlers.
- `lib/` contains CDK configuration, constructs, and stack composition.

The current cleanup direction is incremental: extract one cohesive concern at
a time, keep the public response stable, and lower the source-size ratchets
after every successful move. See [SIMPLIFICATION_REVIEW.md](SIMPLIFICATION_REVIEW.md)
for the audited backlog and security constraints.

## Request paths

### `POST /v1/integrity-collect`

The browser-facing collection endpoint accepts ECDH-encrypted v1/v2/v3 bodies
only. The request pipeline:

1. normalizes headers and decrypts the body;
2. requires TCP, CloudFront/TLS, and H2 probe evidence;
3. redeems and authenticates server-issued probe data;
4. verifies the optional device MAC, device identity, PAT, and STUN nonce;
5. runs browser, worker, network, locale, TLS, and recurrence analyses;
6. computes and stores a merchant-safe projection snapshot;
7. conditionally writes `(cpi, session_id)` to DynamoDB;
8. archives the record to Firehose on a best-effort path.

Same-session retries are idempotent. A different CPI cannot retrieve the row
because CPI is part of the DynamoDB key and the merchant token binding.

### `GET /v1/session/{cpi}/{session_id}`

The merchant-facing endpoint is protected by API Gateway API keys and an
Ed25519-signed Argus merchant token. It verifies optional SDK attestation,
atomically burns a merchant credit, performs a strongly consistent row read,
and returns only the merchant-safe projection. A valid attestation is also
bound to the device public key stored on the scan.

### PAT endpoints

- `GET /v1/pat-attestation` verifies Apple Private Access Tokens and returns a
  short-lived, session-bound Argus token.
- `GET /v1/pat-test` is a transient first-party smoke page owned by the same
  Lambda.

### `GET /health`

Returns `{ "status": "healthy" }` through the ingestion Lambda.

## Project structure

```text
src/
  handlers/
    ingestion.ts                 # browser HTTP adapter + Middy stack
    ingestion/                   # collect use case, middleware, persistence
    session-get.ts               # merchant REST adapter + Middy stack
    session-get/                 # auth/debit/read/project orchestration
    pat-attest.ts                # PAT HTTP adapter
    pat-attest/                  # challenge, verification, replay ledger
    browser-baseline-builder.ts  # scheduled baseline builder
    ip-class-builder.ts          # scheduled ASN dataset builder
    ip-class-discoverer.ts       # scheduled archive discovery
  analysis/                      # browser/network consistency analyzers
  scoring/
    automation.ts               # automation/CDP verdict axis
    shared.ts                    # cross-axis types and predicates
    network-tampering.ts         # network verdict axis
  projections/
    activity.ts                  # velocity + device-history public views
  services/network/              # ASN, relay, overlay, RDAP, CIDR data
  helpers/
    merchant-projection.ts       # projection orchestrator; being drained
    payload-schema.ts            # internal request and row contracts
    ecdh-decrypt.ts              # versioned encrypted-ingestion transport
    sdk-attestation.ts           # optional session-get attestation
    token-verifier.ts            # merchant-token verification
    ...                          # focused crypto/storage/protocol helpers
  types/                         # shared source-only type declarations
lib/
  config/                        # stage and shared-data contracts
  constructs/                    # CDK resources and Lambda wiring
  stacks/app-stack.ts            # stack composition
tests/e2e/
  integrity-flow.e2e.test.ts     # encrypted collect -> persisted verdict -> get
scripts/
  assert-cleanup-ratchets.mjs    # mega-file non-regression gate
```

## Development

Requires Node.js 20+, AWS credentials for synth/deploy, and the AWS CDK CLI.

```bash
npm ci
npm run build
```

### Tests

```bash
npm test                       # unit/characterization + service e2e
npm run test:unit              # 1,200+ focused tests
npm run test:e2e               # public collect-to-session workflow
npm run test:coverage          # unit coverage with enforced thresholds
npm run test:cleanup-ratchets  # mega-file line-count ceilings
```

The service e2e suite invokes both exported Lambda handlers and their real
Middy middleware. It creates a real P-256 ECDH request, runs ingestion and the
real merchant projector, and joins the two handlers with an in-memory AWS SDK
adapter. It covers:

- encrypted collect -> analyze -> conditional write -> credit debit -> get;
- same-session idempotency;
- composite CPI tenant isolation;
- unencrypted-ingress rejection before persistence;
- rejection before debit/read when merchant authentication fails;
- exhausted-credit rejection before verdict retrieval.

External trust issuers—probe-token minting and merchant-token signing—have
their own focused cryptographic suites and are deterministic adapters in this
service-level test.

### Quality gates

```bash
npm run quality          # lint, dependency rules, dead code, duplication, ratchets
npm run format:check
npm run mutate           # Stryker mutation suite
npm run synth            # CDK synth
```

ESLint caps production functions at 50 non-comment lines, complexity at 10,
nesting at 3, and parameters at 4 (CDK has a narrow exception). Dependency
Cruiser rejects cycles and layer inversions. The cleanup ratchet currently
prevents either primary hotspot from growing:

- `src/helpers/merchant-projection.ts` — 1,791 lines maximum;
- `src/handlers/ingestion/base-handler.ts` — 1,233 lines maximum.

These are ceilings, not targets. Tighten them after each extraction.

## Deploy

```bash
# Development
npx cdk deploy ms-argus-api-dev-jw --require-approval never

# Production
npx cdk deploy ms-argus-api-prod --require-approval never
```

Deployment creates the Lambda aliases, API Gateways, DynamoDB tables, Firehose
archive, dataset jobs, alarms, and shared-data contracts defined under `lib/`.
Stage-specific sizing and feature flags live in `lib/config/stage-config.ts`.

## Related repositories

- `ms-argus-web-integrity` — browser collection and encrypted transport.
- `ms-argus-sigint` — server-issued network probe evidence.
- `ms-argus-platform` — merchant identity, API keys, plans, and signing keys.
- `ms-argus-pair` — consumer of stored merchant projections.
