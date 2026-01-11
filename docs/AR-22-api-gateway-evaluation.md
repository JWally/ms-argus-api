# AR-22: API Gateway Direct-to-SQS Evaluation

## Executive Summary

**Recommendation: Keep Go ECS service.** API Gateway direct-to-SQS is ~3x more expensive at scale and provides less functionality.

## Current Architecture

```
CloudFront → ALB → ECS Fargate (Go) → SQS → Lambda Workers
```

The Go service is an ultra-thin ingestion layer that:

- Validates JSON structure
- Extracts tenant from headers/payload
- Captures HTTP headers (UA, IP, Accept-Language)
- Adds timestamp if missing
- Sends to SQS (fire-and-forget)
- Returns 204 immediately (~10ms p99)

## Alternative: API Gateway Direct Integration

```
CloudFront → API Gateway → SQS (direct) → Lambda Workers
```

API Gateway HTTP APIs support direct SQS integration via VTL mapping templates.

## Cost Analysis (30B requests/year)

### Current: ECS Fargate

| Component                         | Monthly Cost | Annual Cost |
| --------------------------------- | ------------ | ----------- |
| Fargate (2 tasks × 0.5 vCPU, 1GB) | $58          | $696        |
| ALB (fixed + LCU)                 | $25 + ~$200  | $2,700      |
| NAT Gateway (data)                | ~$100        | $1,200      |
| CloudWatch Logs                   | ~$50         | $600        |
| **Total**                         | **~$433**    | **~$5,200** |

### Alternative: API Gateway HTTP API

| Component                                   | Monthly Cost | Annual Cost  |
| ------------------------------------------- | ------------ | ------------ |
| HTTP API requests (2.5B/month × $1/million) | $2,500       | $30,000      |
| CloudWatch Logs                             | ~$50         | $600         |
| **Total**                                   | **~$2,550**  | **~$30,600** |

### Cost Comparison

| Approach             | Annual Cost | Ratio    |
| -------------------- | ----------- | -------- |
| ECS Fargate          | ~$5,200     | 1.0x     |
| API Gateway HTTP API | ~$30,600    | **5.9x** |

**API Gateway is ~6x more expensive**, well above the 1.5x threshold.

## Feature Comparison

| Feature                | Go ECS                         | API Gateway Direct               |
| ---------------------- | ------------------------------ | -------------------------------- |
| Request validation     | ✅ Full JSON validation        | ⚠️ VTL limited                   |
| Header extraction      | ✅ Full control                | ⚠️ VTL mapping complex           |
| Tenant extraction      | ✅ Multi-source fallback       | ⚠️ Single source per mapping     |
| Timestamp injection    | ✅ Server-side                 | ⚠️ VTL $context.requestTimeEpoch |
| Latency                | ~10ms p99                      | ~30-50ms (integration overhead)  |
| Cold starts            | None (always-on)               | None (direct integration)        |
| Error handling         | ✅ Graceful degradation        | ⚠️ Generic 500s                  |
| Observability          | ✅ Structured logging          | ⚠️ Access logs only              |
| Rate limiting          | CloudFront WAF                 | ✅ Built-in throttling           |
| Payload transformation | ✅ json.RawMessage passthrough | ⚠️ VTL re-serialization          |

## Technical Concerns with API Gateway Direct

1. **VTL Complexity**: Request transformation requires Velocity Template Language
   - Header extraction: `$input.params().header.get('X-Tenant-ID')`
   - Conditional logic is verbose and error-prone
   - No unit testing for VTL templates

2. **Limited Validation**: API Gateway validates schema but not business logic
   - Can't validate `session_id` is non-empty string
   - Can't apply fallback logic for tenant extraction

3. **Payload Size**: API Gateway has 10MB limit (vs ECS unlimited)
   - Large TCP/TLS blobs could exceed limit

4. **Debugging**: API Gateway errors are opaque
   - Go service provides structured JSON logs
   - Stack traces, request IDs, tenant context

## When API Gateway Direct Would Make Sense

- **Low volume**: <100M requests/year (cost crossover point)
- **Simple payloads**: No transformation needed
- **No validation**: Just pass-through to SQS
- **Ops simplicity priority**: Willing to pay 6x for managed service

## Recommendation

**Keep the Go ECS service** because:

1. **Cost**: 6x cheaper at 30B req/year scale
2. **Control**: Full request validation and transformation
3. **Observability**: Structured logging with request context
4. **Reliability**: Proven in production, graceful degradation
5. **Performance**: 10ms p99 latency

## Action Items

- [x] Evaluate API Gateway pricing (this document)
- [x] Document decision rationale
- [ ] No changes needed - current architecture is optimal

## References

- [AWS API Gateway Pricing](https://aws.amazon.com/api-gateway/pricing/)
- [AWS Fargate Pricing](https://aws.amazon.com/fargate/pricing/)
- Current implementation: `/cmd/ingestion/main.go`
- CDK construct: `/lib/constructs/ingestion-service.ts`
