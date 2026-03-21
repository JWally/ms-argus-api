# Statistical Detection Simplification Plan

**Date:** 2026-03-21
**Status:** Planned

## Why

The statistical v2 system (Shannon scoring, Bayesian confidence blending, per-UA baseline
tracking) requires Valkey (ElastiCache Serverless, ~$50-100/month) to be running and needs
thousands of observations per UA bucket before it produces reliable signals. At current
traffic, the confidence is low, baselines are thin, and the system adds operational
complexity without meaningfully improving detection quality over the deterministic checks
that already run on every request.

The deterministic signals — JA4/H2 coherence, lie detection, headless detection, proxy/VPN
scoring — work on request one and have zero data dependency. Those stay.

Revisit this when: real traffic volume (tens of thousands req/day), some labeled fraud data
to validate signal correlation, and a second person to own baseline drift.

---

## What Gets Deleted

### Source files (delete entirely)

- `src/services/profile/anomaly/statistical-v2.ts`
- `src/services/profile/anomaly/statistical-v2.test.ts`
- `src/services/profile/anomaly/baseline-rules.ts`
- `src/services/profile/anomaly/baseline-rules.test.ts`
- `src/config/fingerprint-analysis.ts`
- `src/config/fingerprint-analysis.test.ts` (if it exists)
- `src/services/cache/valkey-client.ts`
- `src/services/cache/valkey-client.test.ts`
- `src/config/baseline-rules.json`
- `lib/constructs/valkey.ts`

### CDK infrastructure (destroy before deleting code)

- `ValkeyConstruct` in `lib/constructs/valkey.ts` — this provisions ElastiCache Serverless
- The VPC and Lambda security group created solely for Valkey access (`lib/constructs/vpc.ts`)
- Check whether anything else uses the VPC before removing it

---

## What Gets Modified

### `src/services/cache/index.ts`

Remove exports for `valkey-client`. Keep `dynamo-cache`, `ua-parser`.

### `src/services/profile/anomaly/detector.ts`

- Remove `detectStatisticalAnomaliesV2` call
- Remove `StatisticalContextV2` from the options type
- The `contextOpts` parameter may simplify or disappear entirely

### `src/services/profile/anomaly/index.ts`

- Remove `fetchStatisticalContextV2` and `StatisticalContextV2` exports

### `src/handlers/matching-worker/process-record.ts`

- Remove `fetchStatisticalContextV2` import and call
- Remove `StatisticalContextV2` type references
- Remove `statisticalContextV2` from `fetchAndBuildAnomalies` and `persistResults`
- The `fetchAndBuildAnomalies` function simplifies: no async pre-fetch needed,
  anomaly detection becomes synchronous

### `src/handlers/matching-worker/session.ts`

- Remove `buildNormalities` function
- Remove `statisticalContextV2` parameter from `buildSessionResponseData` and
  `writeSessionPayload`
- Remove `analysis.normalities` from the session response payload

### `src/handlers/matching-worker/types.ts`

- Remove any `StatisticalContextV2` references

### `src/handlers/matching-worker.ts`

- Remove `STATISTICAL_V2_ENABLED`, `VALKEY_ENDPOINT`, `VALKEY_TTL_SECONDS`,
  `STATISTICAL_SCORE_THRESHOLD`, `STATISTICAL_DISTINCT_THRESHOLD`,
  `GLOBAL_SAMPLE_RATE` from required env vars (if validated at startup)

### `lib/constructs/workers.ts`

- Remove `valkeyEndpoint`, `valkeySecurityGroup`, `vpc`, `lambdaSecurityGroup`,
  `stageConfig` props (verify nothing else uses these before removing)
- Remove the `createValkeyLambdaConfig` branch — matching worker always uses
  `createBaseLambdaConfig`
- Remove all `VALKEY_*`, `STATISTICAL_*`, `GLOBAL_SAMPLE_RATE` env vars from
  matching worker environment block

### `lib/stacks/app-stack.ts`

- Remove `createVpcInfrastructure` method (or gut it — verify VPC isn't used elsewhere)
- Remove `ValkeyConstruct` instantiation
- Remove `valkey` outputs (`ValkeyEndpoint`, `ValkeyValkeyEndpoint`)
- Remove `stageConfig` pass-through to workers if it only carried valkey settings

### `lib/config/stage-config.ts`

- Remove the `valkey` block from `StageConfig` and all three stage configs
- If `stageConfig` is now empty/unused, remove the type and its usages

### `src/helpers/ua-family.ts`

- Check if `parseUAFamily` is only used by statistical-v2. If so, delete it too.
  If used elsewhere (browser-identity, etc.), keep it.

---

## Sequence

Do these in order to avoid a broken intermediate state.

**1. Destroy the infrastructure first (before any code changes)**

```
cdk deploy ms-argus-api-dev-jw
```

Set `valkey.enabled: false` in stage-config for dev-jw, deploy, confirm Valkey and VPC
are destroyed. This stops the billing immediately and validates the CDK teardown path
before touching application code.

**2. Delete statistical source files**
Remove the files listed above. The build will break — that's expected.

**3. Fix compilation errors bottom-up**
Work from leaves to root:

- `cache/index.ts` → `anomaly/index.ts` → `anomaly/detector.ts` →
  `matching-worker/process-record.ts` → `matching-worker/session.ts` →
  `matching-worker.ts`

**4. Clean up CDK**
Remove Valkey construct, VPC, workers props, stage-config valkey block.

**5. Run quality checks**

```
npm run quality
npm test
```

Dead-code check (knip) will catch anything left dangling.

**6. Deploy and verify**

```
npx cdk deploy ms-argus-api-dev-jw --require-approval never
```

Confirm matching worker cold-starts are faster (no VPC ENI attachment),
anomaly signals still fire for JA4/H2 coherence cases.

---

## What We Keep

Everything in `src/services/profile/anomaly/` except the statistical files:

- `detector.ts` (trimmed)
- `ja4-coherence.ts` — untouched
- `fingerprint-signals.ts` — untouched
- `ip-history-detector.ts` — untouched
- `anomaly.test.ts` — untouched

These run deterministically, need no external service, and are the actual detection moat.

---

## Risks / Watch-outs

- **VPC tear-down**: the VPC was created specifically for Valkey. If nothing else is in it,
  CDK will destroy it cleanly. Double-check `cdk diff` output before applying.
- **`normalities` in session payload**: downstream consumers of the session-get response
  may be reading `analysis.normalities`. Check ms-argus-demo and any other consumers
  before removing the field. Safe to leave the key absent (undefined) rather than
  explicitly null.
- **`stageConfig` prop on WorkersConstruct**: currently only carries valkey settings.
  Once those are gone, the prop can be deleted. If it grows other settings later,
  keep the type but remove the valkey block.
- **`parseUAFamily`**: used by statistical-v2 for grouping keys. Grep for other usages
  before deleting — it may be independently useful.
