# Changelog

All notable changes to ms-argus-api will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- AR-148: Expose anomaly detection results in session response
- AR-145: Cross-field anomaly detection (Navigator vs Worker scope mismatches)
- AR-144: Network anomaly detection (timezone mismatch)
- AR-143: Multi-worker environment detection (dedicated, shared, service workers)
- AR-142: Quick win anomaly detectors (lies, headless, proxy/VPN)
- AR-141: Anomaly detection foundation (types, signal aggregation, risk weights)
- AR-98: Use TIER2_STATS_SK constant consistently
- AR-97: Tenant ID in deduplication cache key (prevents cross-tenant collisions)
- AR-96: Middy middleware for session-get (auto metrics publishing on all paths)
- AR-95: Anchor lookup recency sorting (returns most recent device, not alphabetically first)
- AR-94: IP+UA-only anchor bucket for short-window matching
- AR-82: Session anchor bucket (IP + UA hash + screen, 5-min TTL)

### Removed

- FTL (faster-than-light) network detection - broken with CloudFront edge locations
- Math engine fingerprint detection - opaque markers with no documentation

### Fixed

- AR-95: Anchor lookups now sort by `created_at` descending before iterating
- AR-96: Metrics now publish on error paths (400, 404, 503) via Middy logMetrics
- AR-97: Different tenants with identical payloads no longer trigger duplicate detection
- ESM bundling: Replaced `http-errors` module with custom HttpError class

---

## [2025-01-15] - Lambda Architecture & Web Library Support

### Added

- AR-90: Binary gzip payload support (`application/octet-stream` + `Content-Encoding: gzip`)
- AR-87: Gzip decompression middleware with zip bomb protection (512KB limit)
- AR-83: Full loose object normalization from web library format
- AR-77: Field name normalization (`canvas2d.$hash` → `canvas_hash`, etc.)
- AR-76: Web library format integration tests
- AR-73: Fingerprint normalization layer for nested web library objects
- AR-72: SQS warmup for reduced async pipeline latency
- AR-69: Bot detection verification tests
- AR-68: Demo polling for session endpoint
- AR-67: GET /v1/session/{session_id} endpoint for retrieving match results
- AR-66: Demo wired to submit fingerprints to API
- AR-65: Privacy browser and bot signals in Fingerprint type

### Changed

- AR-52: Replaced Go/ECS ingestion with HTTP API + Lambda
- AR-52: Replaced Redis cache with DynamoDB SessionCache
- Handlers now use Middy middleware pattern for cleaner code

---

## [2025-01-14] - Tier 2 Bucket Improvements

### Added

- Structural WebGL bucket type (parameters + extensions + shader precisions)
- Audio + Canvas compound bucket
- GPU + Screen + Timezone bucket
- HTML element + CSS support bucket
- Maths quirks + Window features bucket

### Changed

- Tier2Buckets now use adjacency list pattern (device per item, not string sets)
- Bucket cardinality tracked via `_stats` sort key entries

---

## [2025-01-12] - Infrastructure Improvements

### Added

- AR-50: Consolidated domain types into `src/types/`
- AR-48: Extracted Redis client to shared module
- AR-44: Stage-based configuration for dev/prod differences
- AR-36: API key authentication with multi-tenant support
- AR-30: VPC Endpoints for DynamoDB, SQS, Secrets Manager (cost optimization)
- AR-29: CORS middleware support
- AR-31: Request validation (64KB body limit, JSON depth limits)

### Changed

- AR-51: Disabled WAF in non-prod environments (cost savings)
- AR-49: Removed orphaned `rotate-aws-secrets.ts`

### Fixed

- Various infrastructure optimizations and code organization improvements
