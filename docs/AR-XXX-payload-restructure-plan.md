# Argus Payload Restructure: Final Implementation Plan

## 1. Executive Summary

The Argus payload schema is being restructured from an organically-evolved, disorganized structure (with data scattered across `loose`, `stable`, `fingerprint`, and top-level fields) into a clean four-section architecture: `identifiers`, `device`, `network`, and `analysis`. This restructure eliminates duplication (such as `loose.navigator.userAgent` duplicating `stable.navigator.userAgent`), establishes clear ownership boundaries (web library owns `device`, server owns `network`, backend workers own `analysis`), and provides a single source of truth for the schema via a shared `@argus/schema` npm package.

The migration will be executed over **10 working days (2 calendar weeks)** with a **30-day backward compatibility window** that automatically expires via a hard sunset date. A single configuration point (`V1_SUNSET_DATE`) controls the compatibility behavior, eliminating the complexity of multiple feature flags while providing instant rollback capability. This approach balances the Pragmatist's emphasis on simplicity, the Operator's focus on operational safety, and the Optimizer's cost-consciousness.

The total investment is approximately **56 hours of development time (~$8,400 at $150/hour)** with an estimated annual savings of **$11,000-$17,000** from reduced debugging time, faster feature development, and eliminated schema drift incidents. The contract system pays for itself within 9-12 months.

---

## 2. Points of Consensus

After three rounds of debate, all perspectives converged on these foundational decisions:

### Architecture

- **Single source of truth**: `@argus/schema` package, all repos depend on it
- **Schema definition**: Zod as primary (best TypeScript ergonomics), JSON Schema export for interoperability and documentation
- **Type generation**: TypeScript types derived automatically from Zod schemas
- **Version header**: `X-Argus-Schema-Version: 2.0.0` on all requests and responses

### Schema Structure

- **Four top-level sections**: `identifiers`, `device`, `network`, `analysis`
- **Flattened within sections**: `device.user_agent` not `device.navigator.userAgent`
- **Grouped hashes**: `device.hashes.stable` (not `hash_stable` at root level)
- **Clear naming**: `network` instead of `sigint` (clearer for all readers)

### Validation Strategy

- **Web library**: Development-time Zod validation only (tree-shaken in production builds for bundle size)
- **API ingestion**: Full Zod validation at the API layer
- **Test factories**: Always validate generated payloads against schema

### Observability

- **Schema version tracking**: Counter by version for adoption metrics
- **Normalization tracking**: Counter for v1-to-v2 conversions
- **Dashboard panel**: Single panel showing version distribution over time

### Backward Compatibility

- **Time-limited v1 support**: Accept and normalize v1 payloads during transition
- **Hard deadline**: Automatic rejection after sunset date (not "until metrics show zero")
- **Single configuration point**: Date-based, self-enforcing

### Testing

- **Round-trip contract tests**: Web payload -> API -> Response validated against schema
- **Factory validation**: All test payloads validated at creation time

---

## 3. Resolved Disagreements

### Timeline: 10 Working Days

**Initial positions**: Pragmatist (2 days), Operator (8 weeks), Optimizer (7 days)
**Final decision**: 10 working days (2 calendar weeks)

**Rationale**: The actual work hours across all plans converged to 52-65 hours. Ten working days provides realistic time for PR review cycles, integration testing, and inevitable bug fixes without excessive padding. The Operator's concern about "bake time" is addressed by the 30-day backward compatibility window, not calendar spread.

### Feature Flags: One Configuration Point

**Initial positions**: Pragmatist (0 flags), Operator (8 flags), Optimizer (1 flag)
**Final decision**: One configuration point - `V1_SUNSET_DATE`

**Rationale**: Multiple flags create 2^n possible states. A single date-based configuration provides:

- Automatic enforcement (no manual flag flipping required)
- Instant rollback (extend the date if needed)
- Clear deadline (prevents "forever v1")

```typescript
const V1_SUNSET_DATE = new Date(process.env.V1_SUNSET_DATE);
const V1_COMPATIBILITY_ENABLED = Date.now() < V1_SUNSET_DATE.getTime();
```

### V1 Support Duration: 30 Days

**Initial positions**: Pragmatist (14 days), Operator (14-21 days), Optimizer (30 days)
**Final decision**: 30 days

**Rationale**:

- Mobile webview embedding requires app store review cycles (1-7 days) plus dev time
- Enterprise customers may have monthly deployment cycles
- The marginal cost of 30 days vs 14 days is effectively zero (normalization code is ~50 lines)
- The hard sunset guarantees cleanup happens

### Observability Depth: Right-Sized

**Initial positions**: Pragmatist (minimal), Operator (extensive), Optimizer (right-sized)
**Final decision**: 3-4 hours of observability setup on Day 1-2

**What we ARE building**:

- Schema version counter (`argus.schema_version{version}`)
- Normalization counter (`argus.normalization{action}`)
- Validation failure counter (`argus.validation{result}`)
- Single dashboard panel showing version distribution

**What we are NOT building**:

- Custom PagerDuty rules (existing API alerts cover failures)
- Extensive runbooks (code comments are sufficient)
- Percentage rollout infrastructure (unnecessary at 10M req/month)

---

## 4. The Contract System: @argus/schema Package

The contract system was a key user requirement and the highest-ROI component of this project.

### Package Structure

```
@argus/schema/
  package.json
  tsconfig.json
  src/
    payload-v2.ts       # Zod schema definitions
    types.ts            # TypeScript type exports
    json-schema.ts      # JSON Schema exports for interop
    validate.ts         # Validation helper functions
    index.ts            # Main entry point
  dist/
    schemas/
      argus-payload-v2.schema.json
      web-payload.schema.json
      api-response.schema.json
```

### package.json

```json
{
  "name": "@argus/schema",
  "version": "2.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": "./dist/index.js",
    "./schemas/*": "./dist/schemas/*"
  },
  "peerDependencies": {
    "zod": "^3.22.0"
  },
  "devDependencies": {
    "zod-to-json-schema": "^3.22.0",
    "typescript": "^5.0.0"
  }
}
```

### How Each Repo Uses It

**ms-argus-api (backend)**:

```typescript
import { ArgusPayloadV2Schema, SCHEMA_VERSION } from "@argus/schema";

function handleIngestion(body: unknown) {
  const result = ArgusPayloadV2Schema.safeParse(body);
  if (!result.success) {
    throw new ValidationError("Invalid payload", result.error);
  }
  return result.data; // Fully typed ArgusPayloadV2
}
```

**ms-argus-web (library)**:

```typescript
import { WebPayloadSchema, SCHEMA_VERSION } from '@argus/schema';

export function buildPayload(fingerprint: DeviceFingerprint): WebPayload {
  const payload = { identifiers: {...}, device: {...} };

  // Dev-time validation catches drift before production
  if (process.env.NODE_ENV !== 'production') {
    const result = WebPayloadSchema.safeParse(payload);
    if (!result.success) {
      throw new Error('Payload schema violation');
    }
  }

  return payload;
}
```

**ms-argus-automation (tests)**:

```typescript
import { ArgusPayloadV2Schema, ApiResponseSchema } from "@argus/schema";

test("API returns schema-compliant responses", async () => {
  const payload = createTestPayload();
  await api.post("/collect", payload);

  const session = await api.get(`/sessions/${payload.identifiers.session_id}`);
  const result = ApiResponseSchema.safeParse(session.data);

  expect(result.success).toBe(true);
});
```

### Contract Enforcement

Schema changes are caught at multiple levels:

1. **Compile time**: TypeScript errors if code uses wrong field paths
2. **Test time**: Schema validation in factories and contract tests
3. **Runtime (API)**: Full Zod validation at ingestion
4. **Development (Web)**: Validation catches issues before commit

---

## 5. Final Schema

```typescript
// @argus/schema/src/payload-v2.ts
import { z } from "zod";

export const SCHEMA_VERSION = "2.0.0";

// === IDENTIFIERS ===
// Who is this? Session and device identification
export const IdentifiersSchema = z.object({
  session_id: z.string().uuid(),
  device_id: z.string().uuid().optional(),
  evercookie_id: z.string().optional(),
  public_key: z.string().optional(),
});

// === DEVICE ===
// What device/browser are they using? All fingerprint data

export const DeviceHashesSchema = z.object({
  stable: z.string().min(1), // Deterministic hash
  fuzzy: z.string().min(1), // SimHash for similarity
  canvas: z.string().optional(), // Canvas fingerprint hash
  webgl: z.string().optional(), // WebGL fingerprint hash
  audio: z.string().optional(), // AudioContext fingerprint hash
  fonts: z.string().optional(), // Font detection hash
});

export const DeviceSchema = z.object({
  hashes: DeviceHashesSchema,

  // Navigator properties (flattened)
  user_agent: z.string(),
  platform: z.string(),
  language: z.string(),
  languages: z.array(z.string()),
  hardware_concurrency: z.number().optional(),
  device_memory: z.number().optional(),
  max_touch_points: z.number().optional(),

  // Screen properties (flattened)
  screen_width: z.number(),
  screen_height: z.number(),
  color_depth: z.number(),
  pixel_ratio: z.number(),

  // GPU properties (flattened)
  gpu_vendor: z.string().optional(),
  gpu_renderer: z.string().optional(),

  // Fingerprint raw data
  canvas_data: z.string().optional(),
  audio_data: z.string().optional(),
  fonts_list: z.array(z.string()).optional(),

  // Timezone (flattened)
  timezone_offset: z.number(),
  timezone_name: z.string(),

  // Bot detection signals
  webdriver: z.boolean(),
  headless_signals: z.array(z.string()),
});

// === NETWORK ===
// How did they connect? Server-enriched network signals

export const NetworkSchema = z.object({
  ip: z.string().ip(),
  geo: z
    .object({
      country: z.string(),
      city: z.string().optional(),
      asn: z.string().optional(),
    })
    .optional(),
  is_proxy: z.boolean().optional(),
  is_vpn: z.boolean().optional(),
  ja3: z.string().optional(), // TLS fingerprint
  ja4: z.string().optional(), // TLS fingerprint v2
  headers: z.record(z.string()), // Request headers
  webrtc_local_ip: z.string().optional(),
  webrtc_public_ip: z.string().optional(),
});

// === ANALYSIS ===
// What's our verdict? Matching results and risk assessment

export const AnalysisSchema = z.object({
  status: z.enum(["pending", "complete", "degraded", "error"]),
  confidence: z.number().min(0).max(1),
  match_tier: z.number().int().min(0).max(5),
  risk_score: z.number().min(0).max(100),
  flags: z.array(z.string()),
  evidence_codes: z.array(z.string()),
  processing_ms: z.number().optional(),
});

// === FULL PAYLOAD ===

export const ArgusPayloadV2Schema = z.object({
  identifiers: IdentifiersSchema,
  device: DeviceSchema,
  network: NetworkSchema.optional(), // Added by server
  analysis: AnalysisSchema.optional(), // Added by backend workers
});

// === CONTEXT-SPECIFIC SUBSETS ===

// What the web library sends (no network, no analysis)
export const WebPayloadSchema = ArgusPayloadV2Schema.pick({
  identifiers: true,
  device: true,
});

// What the API returns (all fields required)
export const ApiResponseSchema = ArgusPayloadV2Schema.required({
  network: true,
  analysis: true,
});

// === TYPE EXPORTS ===

export type ArgusPayloadV2 = z.infer<typeof ArgusPayloadV2Schema>;
export type WebPayload = z.infer<typeof WebPayloadSchema>;
export type ApiResponse = z.infer<typeof ApiResponseSchema>;
export type Identifiers = z.infer<typeof IdentifiersSchema>;
export type DeviceFingerprint = z.infer<typeof DeviceSchema>;
export type NetworkData = z.infer<typeof NetworkSchema>;
export type AnalysisResult = z.infer<typeof AnalysisSchema>;
```

---

## 6. Implementation Plan

### Day-by-Day Breakdown

#### Day 1: Schema Package Foundation (6 hours)

| Task                        | Hours | Details                                   |
| --------------------------- | ----- | ----------------------------------------- |
| Create `@argus/schema` repo | 1     | Package structure, tsconfig, CI/CD setup  |
| Define Zod schemas          | 2     | All schema definitions as specified above |
| Add JSON Schema export      | 1     | Use `zod-to-json-schema` for interop      |
| Add validation utilities    | 1     | `safeParse` wrappers, version constants   |
| Publish v2.0.0              | 1     | Private npm registry                      |

**Deliverable**: `@argus/schema@2.0.0` published

#### Day 2: Observability Baseline (4 hours)

| Task                      | Hours | Details                                             |
| ------------------------- | ----- | --------------------------------------------------- |
| Schema version middleware | 1.5   | Extract `X-Argus-Schema-Version`, emit metric       |
| Normalization tracking    | 1.5   | Counter for v1-to-v2 conversions, latency histogram |
| Dashboard panel           | 1     | v1 vs v2 traffic ratio visualization                |

**Deliverable**: Metrics flowing, dashboard ready

---

### ms-argus-api (Days 3-5: 18 hours)

#### Day 3-4: Core API Changes (12 hours)

| Task                        | Hours | Details                               |
| --------------------------- | ----- | ------------------------------------- |
| Install `@argus/schema`     | 0.5   | Add dependency                        |
| Add V1 sunset configuration | 0.5   | `V1_SUNSET_DATE` environment variable |
| Implement normalizer        | 3     | v1-to-v2 mapping with metrics         |
| Update ingestion handler    | 3     | Schema validation, normalization path |
| Update storage layer        | 2.5   | Store v2 format in DynamoDB           |
| Update tests                | 2     | All tests use schema types            |

**Key files to modify**:

- `src/config/schema.ts` (new)
- `src/services/normalizer.ts` (new)
- `src/handlers/ingestion.ts`
- `src/handlers/session-get.ts`
- `src/services/matching/`
- `src/**/*.test.ts`

#### Day 5: API Response + Deploy (6 hours)

| Task                   | Hours | Details                |
| ---------------------- | ----- | ---------------------- |
| Update GET response    | 2     | Return v2 structure    |
| Update matching worker | 2     | Field path updates     |
| Deploy to staging      | 1     | Verify metrics flowing |
| Deploy to production   | 1     | Accept both v1 and v2  |

**Deliverable**: API in production, accepting both formats

---

### ms-argus-web (Days 6-7: 12 hours)

#### Day 6: Collector Refactoring (8 hours)

| Task                      | Hours | Details                                    |
| ------------------------- | ----- | ------------------------------------------ |
| Install `@argus/schema`   | 0.5   | Add dependency                             |
| Refactor collectors       | 3.5   | Output flattened structure matching schema |
| Refactor hash computation | 2     | Place hashes in `device.hashes`            |
| Add version header        | 0.5   | `X-Argus-Schema-Version` on requests       |
| Add dev-time validation   | 1.5   | Zod validation in dev builds only          |

**Key files to modify**:

- `src/collectors/navigator.ts`
- `src/collectors/screen.ts`
- `src/collectors/canvas.ts`
- `src/collectors/audio.ts`
- `src/hashing/`
- `src/payload-builder.ts`
- `src/api/client.ts`

#### Day 7: Integration + Deploy (4 hours)

| Task                     | Hours | Details                               |
| ------------------------ | ----- | ------------------------------------- |
| Update demo site         | 1.5   | Display v2 response structure         |
| Integration test         | 1     | Test against staging API              |
| Bundle size verification | 0.5   | Confirm Zod tree-shaken in production |
| Publish and deploy       | 1     | New library version live              |

**Deliverable**: Web library in production, sending v2 payloads

---

### ms-argus-automation (Days 8-9: 12 hours)

#### Day 8: Test Updates (8 hours)

| Task                    | Hours | Details                            |
| ----------------------- | ----- | ---------------------------------- |
| Install `@argus/schema` | 0.5   | Add dependency                     |
| Update payload factory  | 3     | `createTestPayload()` generates v2 |
| Update assertions       | 3.5   | All field path assertions          |
| Add contract tests      | 1     | Round-trip validation suite        |

**Key files to modify**:

- `services/api.service.ts` (update types)
- `factories/fingerprint.factory.ts`
- `tests/**/*.spec.ts` (all test files)
- `tests/contract/schema.spec.ts` (new)

#### Day 9: Full Regression (4 hours)

| Task                  | Hours | Details                    |
| --------------------- | ----- | -------------------------- |
| Run full test suite   | 1     | Against staging API        |
| Fix discovered issues | 2     | Edge cases, field mappings |
| Re-run and verify     | 1     | All tests green            |

**Deliverable**: Full automation suite passing with v2

---

#### Day 10: Verification + Sunset Setup (4 hours)

| Task                    | Hours | Details                             |
| ----------------------- | ----- | ----------------------------------- |
| Verify metrics          | 1     | v1 normalization rate in production |
| Set sunset date         | 0.5   | 30 days from today                  |
| Document process        | 1     | Code comments for sunset            |
| Calendar reminders      | 0.5   | Day 15, 25, 30 check-ins            |
| End-to-end verification | 1     | Production integration test         |

**Deliverable**: Migration complete, sunset scheduled

---

### Post-Migration Timeline

| Day    | Action                                                    |
| ------ | --------------------------------------------------------- |
| Day 15 | Check v1 normalization metrics. If >5%, identify sources  |
| Day 25 | Final warning. If v1 >1%, extend or accept rejection rate |
| Day 30 | V1_SUNSET_DATE passes. v1 payloads auto-rejected          |
| Day 37 | Remove normalization code, v1 types, single code path     |

---

## 7. Observability & Rollback

### Observability Implementation

```typescript
// ms-argus-api/src/middleware/schema-tracking.ts

export function schemaTrackingMiddleware(req, res, next) {
  const schemaVersion = req.headers["x-argus-schema-version"] || "v1";

  metrics.increment("argus.schema_version", { version: schemaVersion });

  req.context = { ...req.context, schemaVersion };
  next();
}
```

```typescript
// ms-argus-api/src/services/normalizer.ts

export function normalizePayload(input: unknown): ArgusPayloadV2 {
  const v2Result = ArgusPayloadV2Schema.safeParse(input);

  if (v2Result.success) {
    metrics.increment("argus.schema_version", { version: "v2" });
    return v2Result.data;
  }

  if (V1_COMPATIBILITY_ENABLED) {
    metrics.increment("argus.normalization", { action: "v1_to_v2" });
    const start = Date.now();
    const normalized = mapV1ToV2(input);
    metrics.histogram("argus.normalization_latency_ms", Date.now() - start);
    return normalized;
  }

  metrics.increment("argus.v1_rejected");
  throw new SchemaError("V1 payloads no longer accepted");
}
```

### Dashboard Panel

Single panel in existing Datadog/Grafana showing:

- v1 vs v2 request ratio over time (stacked area chart)
- v1 normalization count (should trend to zero)
- Validation failure rate (should stay near zero)

### Rollback Strategy

| Scenario                        | Action                                        | Recovery Time |
| ------------------------------- | --------------------------------------------- | ------------- |
| Issues during Days 1-5          | Fix in staging, no production impact          | N/A           |
| Issues on Day 5-7 (API in prod) | Set `V1_COMPAT=true` env var                  | <5 minutes    |
| Issues on Day 7-10              | Same as above, rollback web library if needed | <15 minutes   |
| Issues after Day 10             | Extend `V1_SUNSET_DATE` via env var           | <5 minutes    |
| Complete disaster               | Rollback API to pre-migration version         | <30 minutes   |

The single configuration point (`V1_SUNSET_DATE` / `V1_COMPAT`) provides instant rollback. No complex flag matrix to manage.

---

## 8. Timeline & Cost

### Timeline Summary

| Phase                          | Days        | Hours        |
| ------------------------------ | ----------- | ------------ |
| Schema Package + Observability | 1-2         | 10           |
| API Migration                  | 3-5         | 18           |
| Web Library                    | 6-7         | 12           |
| Automation                     | 8-9         | 12           |
| Verification                   | 10          | 4            |
| **Total**                      | **10 days** | **56 hours** |

### Cost Summary

| Item                | Hours  | Cost ($150/hr) |
| ------------------- | ------ | -------------- |
| Schema package      | 6      | $900           |
| Observability setup | 4      | $600           |
| API migration       | 18     | $2,700         |
| Web library         | 12     | $1,800         |
| Automation          | 12     | $1,800         |
| Verification        | 4      | $600           |
| **Total**           | **56** | **$8,400**     |

### ROI Analysis

**Investment**: $8,400 (one-time)

**Annual Savings**:

- Schema drift bugs eliminated: ~$3,000 (estimated 12 incidents/year _ 4 hours _ $150)
- Faster field additions: ~$900 (6 additions/year _ 1 hour saved _ $150)
- Reduced cognitive overhead: ~$6,000 (40 hours/year \* $150)
- Faster onboarding: ~$1,800 (4 new devs/year _ 3 hours _ $150)

**Total Annual Savings**: ~$11,700

**Payback Period**: ~9 months

---

## 9. Success Criteria

### Day 10 (Migration Complete)

- [ ] All three repos importing from `@argus/schema`
- [ ] Zero TypeScript compilation errors
- [ ] Full automation suite passing
- [ ] Production metrics showing schema version distribution
- [ ] `V1_SUNSET_DATE` set to Day 40

### Day 25 (Check-in)

- [ ] v1 traffic <5% of total
- [ ] If >5%: sources identified, customers contacted
- [ ] Sunset date confirmed or extended if justified

### Day 40 (V1 Sunset)

- [ ] `V1_COMPATIBILITY_ENABLED` auto-disabled
- [ ] v1 payloads returning 400 errors
- [ ] No action required (automatic enforcement)

### Day 50 (Cleanup)

- [ ] Normalization code removed
- [ ] v1 type definitions removed
- [ ] Single code path for v2
- [ ] No v1 references in codebase

### Day 60 (Steady State)

- [ ] Zero schema drift incidents
- [ ] New field additions taking <30 minutes
- [ ] Schema changes require one PR to `@argus/schema`

---

## Appendix A: V1 to V2 Field Mapping Reference

| V1 Path                      | V2 Path                  |
| ---------------------------- | ------------------------ |
| `session_id` (root)          | `identifiers.session_id` |
| `device_id` (root)           | `identifiers.device_id`  |
| `loose.navigator.userAgent`  | `device.user_agent`      |
| `stable.navigator.userAgent` | `device.user_agent`      |
| `loose.navigator.platform`   | `device.platform`        |
| `fingerprint.screen.width`   | `device.screen_width`    |
| `fingerprint.screen.height`  | `device.screen_height`   |
| `fingerprint.canvas.hash`    | `device.hashes.canvas`   |
| `fingerprint.webgl.hash`     | `device.hashes.webgl`    |
| `fingerprint.audio.hash`     | `device.hashes.audio`    |
| `stable_hash` (root)         | `device.hashes.stable`   |
| `fuzzy_hash` (root)          | `device.hashes.fuzzy`    |
| N/A (server adds)            | `network.ip`             |
| N/A (server adds)            | `network.ja3`            |
| N/A (worker adds)            | `analysis.confidence`    |
| N/A (worker adds)            | `analysis.match_tier`    |

---

## Appendix B: Key Code Snippets

### Sunset Configuration

```typescript
// ms-argus-api/src/config/schema.ts
export const V1_SUNSET_DATE = new Date(
  process.env.V1_SUNSET_DATE || "2024-XX-XX",
);

export const V1_COMPATIBILITY_ENABLED =
  process.env.V1_COMPAT !== "false" && Date.now() < V1_SUNSET_DATE.getTime();
```

### Web Library Dev Validation

```typescript
// ms-argus-web/src/payload-builder.ts
import { WebPayloadSchema, SCHEMA_VERSION } from '@argus/schema';

export function buildPayload(fingerprint: DeviceFingerprint): WebPayload {
  const payload = {
    identifiers: { session_id: crypto.randomUUID(), ... },
    device: { hashes: fingerprint.hashes, ... },
  };

  if (process.env.NODE_ENV !== 'production') {
    const result = WebPayloadSchema.safeParse(payload);
    if (!result.success) {
      console.error('[Argus] Schema violation:', result.error.format());
      throw new Error('Payload does not match schema');
    }
  }

  return payload;
}
```

### Contract Test

```typescript
// ms-argus-automation/tests/contract/schema.spec.ts
import { WebPayloadSchema, ApiResponseSchema } from "@argus/schema";

describe("Schema Contract", () => {
  it("round-trip preserves data and validates", async () => {
    const payload = createTestPayload();

    // Validate what we send
    expect(WebPayloadSchema.safeParse(payload).success).toBe(true);

    // Send to API
    await api.post("/collect", payload);

    // Get session
    const session = await api.get(
      `/sessions/${payload.identifiers.session_id}`,
    );

    // Validate what we receive
    expect(ApiResponseSchema.safeParse(session.data).success).toBe(true);

    // Data integrity
    expect(session.data.device.hashes.stable).toBe(
      payload.device.hashes.stable,
    );
  });
});
```

---

_This plan represents the consensus achieved after three rounds of debate between Pragmatist, Operator, and Optimizer perspectives. All three perspectives agree on the core architecture and approach, with minor variations in timeline buffer and sunset window length that do not materially affect the implementation._
