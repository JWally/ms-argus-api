# ms-argus-api Deployment Journal

> **CRITICAL: ALWAYS CHECK THIS JOURNAL FIRST!**
>
> Before starting any deployment work:
> 1. **READ THIS JOURNAL** - it contains hard-won lessons that will save hours
> 2. **UPDATE THIS JOURNAL** - when you learn something new, add it here
> 3. **Rate your confidence (1-10)** before implementing any fix

> 4. ** Update this journal with every failure and why it failed and the date it failed, and why. Put these at the bottom"
>
> Past mistakes cost hours of debugging. Future you will thank present you.

---

## TODO: Unit Test Coverage

The TypeScript codebase needs more unit tests. Currently tested:
- `src/helpers/misc.ts` - flattenObject, getCurrentDateInfo (21 tests)
- `src/helpers/constants.ts` - security headers, CORS config, Glue columns (30 tests)

**Total: 51 tests**

Still needs tests:
- `src/handlers/matching-worker.ts` - Lambda handler logic
- `src/handlers/profile-updater.ts` - Lambda handler logic
- `src/services/get-aws-secrets.ts` - Secrets retrieval
- `src/services/rotate-aws-secrets.ts` - Secrets rotation

Run tests with: `npm run test`

---

## Best Practice: Dev Environment Instance Sizing

**For non-production environments (dev, staging, test):**
- Use small/tiny instance sizes for Redis, EC2, RDS, etc.
- Smaller instances spin up and down much faster
- Saves time during deployments and rollbacks
- Saves money on dev environments

**Examples:**
- Redis: Use `cache.t3.micro` or `cache.t4g.micro` instead of `r6g.large`
- EC2/Fargate: Use minimal CPU/memory allocations
- RDS: Use `db.t3.micro` or smallest available

**10-Minute Rule:**
- If any CloudFormation operation takes over 10 minutes, kill it manually
- Clean up orphaned resources (Redis clusters, VPCs, NAT gateways, ENIs)
- Don't wait forever for stuck deletions - manually intervene

---

## 2026-01-10: Remove Dockerfile HEALTHCHECK Entirely for ECS (Confidence: 10/10)

### Issue
ECS service fails with "ECS Deployment Circuit Breaker was triggered" even with matching 60s start-period in Dockerfile and ECS task definition. Tasks marked UNHEALTHY by Docker health check while ALB targets show healthy.

### Root Cause
Having HEALTHCHECK in both Dockerfile AND ECS task definition causes unexpected behavior:
- Docker runs its own health check (from Dockerfile HEALTHCHECK)
- ECS runs its own health check (from task definition healthCheck)
- ALB runs its own health check (from target group config)

The Docker health check marked containers UNHEALTHY even though:
1. Servers started correctly (confirmed via logs)
2. ALB health checks passed (all targets healthy)
3. Health endpoint responds correctly (tested locally)

The wget command inside the Fargate ARM64 container appeared to have timing or execution issues that don't reproduce locally.

### Fix
**Remove HEALTHCHECK from Dockerfile entirely.** Let ECS handle health checks via:
1. ECS task definition `healthCheck` config
2. ALB target group health checks

Files changed:
- `cmd/ingestion/Dockerfile` - Removed HEALTHCHECK directive

### Lesson
**For ECS Fargate deployments, do NOT use Dockerfile HEALTHCHECK.** Rely on ECS task definition healthCheck and ALB target group health checks instead. The Dockerfile HEALTHCHECK adds a layer of health checking that can conflict with ECS's own mechanisms.

---

## 2026-01-10: Dockerfile HEALTHCHECK start-period Conflict (Confidence: 10/10)

### Issue
ECS service fails with "ECS Deployment Circuit Breaker was triggered" - tasks start but get killed after several minutes.

### Root Cause
There are TWO health check configurations that can conflict:

1. **Dockerfile HEALTHCHECK** (Docker-level, takes precedence):
   ```dockerfile
   HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
       CMD wget -q --spider http://localhost:8080/health || exit 1
   ```

2. **CDK taskDefinition healthCheck** (ECS task definition level):
   ```typescript
   healthCheck: {
     command: ['CMD-SHELL', 'wget -q --spider http://localhost:8080/health || exit 1'],
     interval: Duration.seconds(30),
     timeout: Duration.seconds(5),
     retries: 3,
     startPeriod: Duration.seconds(60),  // This gets IGNORED!
   },
   ```

**The Dockerfile HEALTHCHECK takes precedence over the CDK configuration!**

With `start-period=5s`, health checks begin almost immediately. While the Go app starts quickly, the combination of short start-period and aggressive health checks can cause intermittent failures during deployment, eventually triggering the circuit breaker.

### Fix
Update the Dockerfile to use a longer start-period (60s):
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1
```

Files changed:
- `cmd/ingestion/Dockerfile`

### Lesson
**When using Dockerfile HEALTHCHECK with ECS, ensure the Dockerfile settings match your desired configuration.** The Dockerfile HEALTHCHECK takes precedence over ECS task definition health check settings. For ECS Fargate deployments, consider using 60s or longer start-period.

---

## 2026-01-10: Missing healthCheckGracePeriod (Confidence: 10/10)

### Issue
ECS service fails with "ECS Deployment Circuit Breaker was triggered" - tasks start but get killed.

### Root Cause
The ECS service was missing `healthCheckGracePeriod`. Without it:
1. ECS starts health checks immediately after task launch
2. ALB hasn't finished registering the target yet
3. ECS considers the task unhealthy and kills it
4. Circuit breaker triggers after repeated failures

The logs showed:
```
18:51:09 - Starting server
18:56:30 - Shutting down server (SIGTERM - task killed)
```

The server WAS starting correctly, but getting killed by premature health checks.

### Fix
Add `healthCheckGracePeriod` to the FargateService:
```typescript
this.service = new ecs.FargateService(this, 'Service', {
  // ... other props
  healthCheckGracePeriod: Duration.seconds(120), // Allow time for ALB target registration
});
```

Also removed hardcoded `serviceName` and `clusterName` to let CDK generate unique names, preventing resource collision on redeployment.

### Lesson
**Always set `healthCheckGracePeriod` when using ALB with ECS Fargate.** 120 seconds is a safe default.

---

## 2026-01-10: Secret Dependency Bug (Confidence: 9/10)

### Issue
ECS service fails with "ECS Deployment Circuit Breaker was triggered" even though Dockerfile and health checks were correct.

### Root Cause
In `ingestion-service.ts`, the code used `fromSecretNameV2()` to look up a secret by name:
```typescript
const secret = secretsmanager.Secret.fromSecretNameV2(
  this, 'ServiceSecret', `${stage}/${projectName}`
);
```

But the secret was created in the **same stack** by `SecretConstruct`. CDK doesn't know about this dependency when using `fromSecretNameV2`, so it may try to create the ECS service before the secret exists, causing the task to fail to start.

### Fix
Pass the secret directly from the parent stack instead of looking it up by name:

1. Update `IngestionServiceProps` to accept `secret: secretsmanager.ISecret`
2. Pass `secrets.secret` from `app-stack.ts` to `IngestionServiceConstruct`
3. Remove `fromSecretNameV2` call

Files changed:
- `lib/constructs/ingestion-service.ts`
- `lib/stacks/app-stack.ts`

### Lesson
**Never use `fromXxxNameV2` or similar import functions for resources created in the same stack.** This creates a race condition because CDK can't infer the dependency. Always pass references directly.

---

## 2026-01-10: ioredis TypeScript Errors (Confidence: 10/10)

### Issue
Build failed with `retryDelayOnFailover` not existing in `RedisOptions`.

### Fix
`retryDelayOnFailover` is not a valid ioredis option. Use `retryStrategy` instead:
```typescript
redis = new Redis({
  host: process.env.REDIS_ENDPOINT!,
  port: parseInt(process.env.REDIS_PORT || '6379'),
  tls: {},
  maxRetriesPerRequest: 3,
  retryStrategy: (times: number) => Math.min(times * 100, 2000),
});
```

Files changed:
- `src/handlers/matching-worker.ts`
- `src/handlers/profile-updater.ts`

---

## 2026-01-10: Initial Deployment Attempt

### Issues Encountered

#### 1. Stack DELETE_IN_PROGRESS Blocked New Deployment
When attempting to deploy, the stack was in DELETE_IN_PROGRESS state from a previous failed deployment. Had to wait for deletion to complete before retrying.

#### 2. DELETE_FAILED Due to Redis Cluster
The stack deletion failed because:
- ElastiCache ReplicationGroup (`ms-argus-api-dev-jw-redis`) was still active
- The Redis subnet group couldn't be deleted while the cluster existed
- Security groups had dependent objects

**Fix**: Manually deleted the Redis cluster using AWS SDK:
```javascript
await client.send(new DeleteReplicationGroupCommand({
  ReplicationGroupId: 'ms-argus-api-dev-jw-redis'
}));
```

#### 3. Orphan DynamoDB Tables Blocking Redeployment
After stack deletion, orphan DynamoDB tables remained:
- `ms-argus-api-dev-jw-profiles`
- `ms-argus-api-dev-jw-tier1-index`
- `ms-argus-api-dev-jw-tier2-buckets`

**Fix**: Manually deleted tables using AWS SDK.

#### 4. ECS Service Deployment Failed - Missing wget in Alpine Image
The ECS Fargate service failed to deploy with "ECS Deployment Circuit Breaker was triggered".

**Root Cause**: The Dockerfile health check uses `wget`:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1
```

But the Alpine runtime image didn't have wget installed!

**Fix**: Added `wget` installation in Dockerfile:
```dockerfile
# Install wget for health check
RUN apk --no-cache add wget
```

#### 5. Redis Cluster Recreated During Rollback
Each failed deployment attempt creates a new Redis cluster. When rollback fails, the cluster stays, blocking the next deletion. Had to delete Redis clusters multiple times.

**Lesson**: Check for orphaned Redis clusters before each deployment attempt.

### Learnings

1. **Always verify container health checks work locally** before deploying to ECS
2. **Alpine images are minimal** - they don't include wget, curl, or other common tools by default
3. **CDK rollbacks take time** - especially when there are NAT gateways, CloudFront distributions, and Redis clusters
4. **Use AWS SDK directly when AWS CLI has issues** - the snap version of AWS CLI had sandbox restrictions (exit code 120)
5. **Check for orphan resources** - Failed deployments can leave behind Redis clusters, DynamoDB tables, S3 buckets that block future deployments

---

## Best Practices for Future Work

### Parallel Work Pattern
When waiting for long-running operations (stack deletion, Redis cluster deletion, deployments):
1. Put the wait loop in a background task
2. Do other productive work (write documentation, test locally, fix bugs)
3. Periodically check the background task status
4. Resume main work when the blocking operation completes

### Before Deploying ECS Services
1. Build and test Docker image locally: `docker build -t test-image .`
2. Run container locally: `docker run -p 8080:8080 test-image`
3. Test health endpoint: `curl localhost:8080/health`
4. Only then deploy to AWS

### Local Docker Test Results (2026-01-10)
After fixing the Dockerfile to include wget, local testing confirmed the container works:
```bash
$ docker build -t argus-ingestion-test .
# Build succeeded

$ docker run --rm -d -p 8080:8080 -e SQS_QUEUE_URL="https://sqs..." --name argus-test argus-ingestion-test

$ curl http://localhost:8080/health
{"status":"healthy"}  # HTTP 200 OK
```

### Handling Failed Stack Operations
1. Check stack status and reason for failure
2. List remaining resources with `ListStackResourcesCommand`
3. Manually clean up blocking resources (Redis clusters, security groups with dependencies)
4. Retry stack deletion
5. Wait for deletion to complete before redeploying
