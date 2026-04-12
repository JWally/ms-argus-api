# Deploy Instructions — ms-argus-api

Serverless device fingerprinting + fraud detection API. 5 Lambdas (ingestion, session-get, matching-worker, profile-updater, vector-worker), DynamoDB (6 tables), SQS (matching + profile queues), Qdrant (vector search), optional Valkey. Deploys to **https://api-dev-jw.argus.pw**.

## Prerequisites

- Node 22.x
- AWS credentials — `aws sts get-caller-identity` → account `263318538229`, region `us-east-1`
- CDK bootstrap already run in the account/region (`npx cdk bootstrap` once)
- Access to the platform SSM parameters — this stack reads from `/argus-platform/dev-jw/*` which is provisioned by the separate `ms-argus-platform` stack. If platform isn't deployed, this will fail at synth with "SSM parameter not found".
- No local `.env` required — runtime secrets come from Secrets Manager at Lambda cold-start. The SIGINT AES key is fetched from `argus/dev-jw/sigint-aes-key` via the ARN exported at SSM `/argus-platform/dev-jw/sigint-aes-key-arn`.

## Deploy

```bash
npx cdk deploy ms-argus-api-dev-jw --require-approval never
```

Or, if deploying all stacks (there's typically only one for this repo):

```bash
npx cdk deploy --all --require-approval never
```

The package.json exposes short aliases:

```bash
npm run deploy   # cdk deploy
npm run synth    # cdk synth
npm run diff     # cdk diff
```

…but these don't pre-build anything TypeScript-wise; CDK uses `ts-node` at synth time (see `cdk.json`'s `"app": "npx ts-node --prefer-ts-exts bin/ms-argus-api.ts"`).

## What gets deployed

Single stack `ms-argus-api-dev-jw`:

- 5 Lambdas with function URLs / API Gateway routes
- 6 DynamoDB tables including `integrity_results`, `sessions`, `profiles`
- 2 SQS queues (matching, profile updates)
- CloudFront distribution fronting the API Gateway with `api-dev-jw.argus.pw` alias
- 3 S3 buckets (payloads, integrity archive, observations for Athena)

## Verify deploy

```bash
curl -i https://api-dev-jw.argus.pw/
# expect a 404 with CloudFront headers — means the CDN is live; the root path
# isn't routed, but the stack is up
```

A real functional check:

```bash
curl -i -X OPTIONS https://api-dev-jw.argus.pw/v1/integrity-collect \
  -H "Origin: https://arcades.click" \
  -H "Access-Control-Request-Method: POST"
# expect HTTP/2 204 with access-control-allow-* headers
```

## Pre-deploy hooks

lefthook:

- Pre-commit: build, lint, format
- Pre-push: test, build, deps, dead-code, duplication

`npm run quality` runs the full pre-push bundle locally.

## Common gotchas (from session notes)

- **AWS CLI snap broken** (exit code 120 with no output): invoke Lambdas via the Node SDK instead — `@aws-sdk/client-lambda` + `LambdaClient` + `InvokeCommand`.
- **Stale cdk.context.json entries**: after manually editing to remove a stale lookup, check for trailing commas — CDK fails to parse with "Expected double-quoted property name".
- **`ssm.StringParameter.valueFromLookup`** only takes 2 arguments (scope, parameterName). Three-argument calls silently mis-use the third as a default value; tsc won't catch it. See `memory/feedback_cdk_ssm_lookup.md`.

## Integrity archive S3 bucket (for analysis)

Integrity sessions are archived to:

```
s3://ms-argus-api-dev-jw-integrity-archive-263318538229-us-east-1/<session_id>.json
```

Useful for post-hoc analysis:

```bash
aws s3api list-objects-v2 \
  --bucket ms-argus-api-dev-jw-integrity-archive-263318538229-us-east-1 \
  --query 'sort_by(Contents, &LastModified)[-10:].[LastModified, Key]' \
  --output text
```

## Troubleshooting

**Platform SSM lookup fails at synth** — the `ms-argus-platform` stack must be deployed first. Run `npx cdk deploy --all` in `~/Dev/ms-argus-platform` to populate `/argus-platform/dev-jw/*` parameters.

**Qdrant cluster unreachable at Lambda runtime** — verify the Qdrant API key in Secrets Manager and the VPC endpoint if the cluster is private.

**Deploy succeeds but integrity payloads stop appearing in the archive S3 bucket** — check `ingestion` Lambda CloudWatch logs. The archive is an async write; failures don't propagate to the caller.

> ⚠️ I have not personally run a full deploy of this repo in this session. Commands are from `package.json`, `cdk.json`, and CLAUDE.md notes. Verify and amend if anything differs.
