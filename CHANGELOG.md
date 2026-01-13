# Changelog

All notable changes to ms-argus-api will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Core Principles, Sprint Planning, and Documentation sections in CLAUDE.md
- `docs/features/` for user-facing feature documentation
- `docs/adr/` for Architecture Decision Records
- This changelog
- Cost trade-off note in README (~$15K/year premium for simplicity/reliability)

### Changed

- AR-47: Consolidated Redis client wrapper - handlers now use shared `getRedis()` from redis-client.ts

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
