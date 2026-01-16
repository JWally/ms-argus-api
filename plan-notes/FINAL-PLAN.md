# FINAL PLAN: ms-argus-api Architecture Review Implementation

**Generated via 3-round multi-perspective debate**
**Date**: 2026-01-16
**Source**: ideas/FINDINGS.txt

---

## Executive Summary

Three perspectives (Pragmatist, Operator, Optimizer) debated implementation priorities over 3 rounds. The result: **~14 hours of work** across the quarter for significant improvements in correctness, safety, observability, and cost savings of **~$30K/year**.

**Key outcomes:**

- 17 items of full consensus
- 2 items decided by 2-1 majority
- 6 items unanimously skipped

---

## Consensus Items (All 3 Agree)

### P0: Do Today (3.5 hours)

| Item                                                                                                                                                                                    | Effort  | Owner | Rollback      |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----- | ------------- |
| **Fix ULID bug** - Replace `randomUUID()` with `ulid()` in device ID generation. Add `ScanIndexForward: false` to session anchor query. Add DEVICE_ID_FORMAT metric to track migration. | 2 hours | -     | Code revert   |
| **Tenant isolation guard** - Make "default" tenant fallback throw error in production instead of silently merging traffic                                                               | 30 min  | -     | Code revert   |
| **Enable X-Ray tracing** - Change `tracing: Tracing.DISABLED` to `Tracing.ACTIVE` in workers.ts                                                                                         | 5 min   | -     | Config revert |
| **NEW_DEVICE_RATE metric** - Add CloudWatch metric + alarm when `is_new_device` is true                                                                                                 | 30 min  | -     | Code revert   |

### P1: This Week (1 hour)

| Item                                                                                                                                                                              | Effort | Owner | Rollback    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ----- | ----------- |
| **Delete dead dependencies** - `npm uninstall ioredis ioredis-mock @aws-sdk/client-ec2 @aws-sdk/client-ecs @aws-sdk/client-elastic-load-balancing-v2 @aws-sdk/client-elasticache` | 30 min | -     | npm install |
| **Delete Go service** - Verify CI/CD doesn't reference it (10-min grep), then `rm -rf cmd/ingestion/` and remove Go npm scripts                                                   | 30 min | -     | Git revert  |
| **Delete dead method** - Remove `scoreDeviceCandidates` from matching-service.ts:856-874                                                                                          | 5 min  | -     | Git revert  |

### P2: This Sprint (3.5 hours)

| Item                                                                                                       | Effort | Owner | Rollback          |
| ---------------------------------------------------------------------------------------------------------- | ------ | ----- | ----------------- |
| **Add warmup handler** - Wire up `@middy/warmup` in ingestion.ts middleware chain                          | 30 min | -     | Remove middleware |
| **Test Lambda memory** - Deploy matching worker at 1024MB to dev, measure p95 latency, decide with data    | 1 hour | -     | Config revert     |
| **Standardize ESM bundling** - Change workers.ts to use `OutputFormat.ESM`, run full test suite + 24h soak | 1 hour | -     | Revert to CJS     |

### P3: This Quarter (5-6 hours + bake time)

| Item                                                                                                                             | Effort   | Owner | Rollback            |
| -------------------------------------------------------------------------------------------------------------------------------- | -------- | ----- | ------------------- |
| **Secrets Manager for API keys** - Move API_KEYS from env var to Secrets Manager, cache in Lambda memory                         | 2 hours  | -     | Config revert       |
| **Extract bucket-keys.ts** - Consolidate bucket key building from matching-service.ts and profile-service.ts into shared utility | 1 hour   | -     | Code revert         |
| **DynamoDB provisioned capacity** - See conditional timing below                                                                 | 4+ hours | -     | Revert to on-demand |

---

## Majority Decisions (2-1)

### Cardinality Recalculation Job: DO IT

**Vote**: Operator + Optimizer vs Pragmatist

| For                                                     | Against                       |
| ------------------------------------------------------- | ----------------------------- |
| $60/year Lambda eliminates drift in fraud scoring       | System self-corrects via TTL  |
| Fraud decisions happen in milliseconds; TTL takes hours | Adds operational surface area |

**Resolution**: A daily Lambda recalculates bucket cardinalities. The Pragmatist's dissent is noted but overruled.

**Implementation**: Add to P2 (this sprint), ~1 hour effort.

---

### DynamoDB Provisioned Capacity: CONDITIONAL TIMING

All three converged on a conditional approach based on go-live timeline:

| Go-live Timeline   | Action                                     |
| ------------------ | ------------------------------------------ |
| < 4 weeks from now | Stay on-demand, switch after stabilization |
| 4-8 weeks from now | Start capacity analysis NOW                |
| > 8 weeks from now | Defer until 4 weeks before go-live         |

**Process** (when ready):

1. Pull 2 weeks of CloudWatch metrics (p50, p99, p99.9)
2. Set base capacity at 150% of p99 (conservative)
3. Configure auto-scaling: 70% target utilization, scale to 200%
4. Deploy and bake for 2 weeks minimum

**Expected savings**: ~$31K/year risk-adjusted (not $50K - accounting for throttling risk)

---

## Explicitly Skip (All 3 Agree)

| Item                                                         | Reason                                                                  | Vote |
| ------------------------------------------------------------ | ----------------------------------------------------------------------- | ---- |
| **File splitting** (matching-service.ts, profile-service.ts) | 434 tests, working code. Refactoring risk > maintenance benefit.        | 3-0  |
| **DAX for session cache**                                    | Requires VPC. Cold start penalty (200-500ms) >> cache savings (5ms)     | 3-0  |
| **Step Functions**                                           | $25/million state transitions = ~$750K/year at 30B requests             | 3-0  |
| **Per-tenant rate limiting**                                 | WAF global limiting is correct for third-party API with large customers | 3-0  |
| **CORS changes**                                             | `allow: *` is intentional. CloudFront handles real CORS.                | 3-0  |
| **TIER2_BUCKET_CARDINALITY metric**                          | Redundant if doing cardinality recalculation job                        | 3-0  |

---

## Timeline Summary

```
TODAY (P0)
├── Fix ULID bug + DEVICE_ID_FORMAT metric
├── Add tenant isolation guard
├── Enable X-Ray tracing
└── Add NEW_DEVICE_RATE metric + alarm

THIS WEEK (P1)
├── Delete ioredis and dead AWS SDK deps
├── Delete Go service (after CI check)
└── Delete scoreDeviceCandidates method

THIS SPRINT (P2)
├── Add warmup handler
├── Test Lambda at 1024MB
├── Standardize ESM bundling
└── Add cardinality recalculation Lambda

THIS QUARTER (P3)
├── Move API_KEYS to Secrets Manager
├── Extract bucket-keys.ts
└── DynamoDB provisioned (4 weeks before go-live)
```

---

## Cost Impact

| Category                           | Annual Impact |
| ---------------------------------- | ------------- |
| DynamoDB provisioned capacity      | +$31,000      |
| X-Ray tracing                      | -$2,400       |
| Cardinality Lambda                 | -$60          |
| Memory optimization (if validated) | +$1,000-2,000 |
| **Net Annual Savings**             | **~$30,000**  |

### Risk Avoidance (not in savings number)

| Risk                              | Mitigation           | Potential Exposure    |
| --------------------------------- | -------------------- | --------------------- |
| ULID bug (wrong device returns)   | P0 fix               | ~$3M fraud liability  |
| Tenant isolation failure          | P0 guard             | Unbounded data breach |
| DynamoDB throttling during attack | Provisioned capacity | $100K+ per incident   |

---

## Effort Summary

| Phase     | Effort                    | When         |
| --------- | ------------------------- | ------------ |
| P0        | 3.5 hours                 | Today        |
| P1        | 1 hour                    | This week    |
| P2        | 3.5 hours                 | This sprint  |
| P3        | 5-6 hours + 2 weeks bake  | This quarter |
| **Total** | **~14 hours active work** |              |

---

## Open Question

**What is the go-live date?** This determines when to start DynamoDB capacity planning.

---

## One-Sentence Summary

Fix the ULID bug today, delete dead code this week, add observability and the cardinality job this sprint, then switch to provisioned DynamoDB four weeks before go-live for ~$30K/year in savings with proper risk mitigation.

---

_Plan generated via multi-perspective debate: Pragmatist (simplicity), Operator (reliability), Optimizer (cost). See plan-notes/round-{0,1,2,3}/ for full debate history._
