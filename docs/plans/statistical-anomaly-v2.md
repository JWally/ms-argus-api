# Statistical Anomaly Detection v2: Shannon Scoring with Tiered TTLs

## Overview

Refactor the existing statistical anomaly detection to use Shannon information-theoretic scoring with Bayesian blending, tiered TTL graduation, and dual-layer fingerprint analysis (JA4 + HTTP/2).

## Current State

The existing statistical detector (`src/services/profile/anomaly/statistical.ts`) tracks `ua_family::ja4` combinations using a simple frequency ratio:

```typescript
expected = total / distinct
score = combo_count / expected
if (score < 0.01) → flag as suspicious
```

**Limitations:**

1. **Cold-start problem**: New UA families have insufficient data but we still make decisions
2. **Linear scaling**: 1-in-1000 vs 1-in-1000000 events score very differently
3. **No global fallback**: Unlike ASN baseline, we don't blend with global patterns
4. **Single layer**: Only JA4 (TLS), misses HTTP/2 application layer
5. **Unbounded storage**: No TTL strategy for sparse JA4 space

## Proposed Solution

### 1. Dual-Layer Fingerprint Analysis

Track both TLS and application layer fingerprints **separately**:

```
ua_family:ja4:{fingerprint}  → Shannon score → signal 1
ua_family:h2:{fingerprint}   → Shannon score → signal 2
```

**Why separate, not combined:**

- Independent signals at different stack layers
- Spoof one layer, get caught by the other
- Less sparse than cartesian product (`ja4 × h2`)
- Independent graduation (H2 changes more often than JA4)

### 2. Shannon Information-Theoretic Scoring

Replace linear ratio with Shannon self-information (surprise):

```typescript
// Probability of this fingerprint given this UA family
P = fingerprint_count / ua_family_total

// Shannon surprise (bits of information)
surprise = -log₂(P)

// Normalize against fixed ceiling (12 bits = 1 in 4096)
score = min(1.0, surprise / MAX_SURPRISE_BITS)
```

**Why Shannon:**

- Log scale gives calibrated scores across orders of magnitude
- 1-in-100 event: ~6.6 bits → 0.55 score
- 1-in-1000 event: ~10 bits → 0.83 score
- 1-in-10000 event: 12+ bits → 1.0 score (capped)

### 3. Bayesian Blending with Global Baseline

For new/rare UA families, blend with global fingerprint distribution:

```typescript
// Confidence based on sample size (sqrt curve)
confidence = min(1.0, sqrt(ua_family_total / SATURATION_THRESHOLD))

// Where SATURATION_THRESHOLD = 500 (same as ASN baseline)

// Bayesian blend
final_score = (ua_score × confidence) + (global_score × (1 - confidence))
```

**Behavior:**

- New "Arc" browser with 10 samples → confidence=0.14 → 86% global weight
- Established "Chrome" with 10000 samples → confidence=1.0 → 100% UA-specific
- Handles cold-start gracefully

### 4. Tiered TTL Graduation System

Fingerprints "earn trust" by accumulating hits:

| Tier        | Count Threshold | TTL      | Purpose                         |
| ----------- | --------------- | -------- | ------------------------------- |
| Probation   | 0 - 999         | 3 hours  | New fingerprints, bots, spoofed |
| Proving     | 1,000 - 19,999  | 24 hours | Legitimate but less common      |
| Established | 20,000+         | 90 days  | Mainstream browser fingerprints |

```typescript
async function incrWithTieredTTL(key: string): Promise<number> {
  const count = await valkey.incr(key);

  let ttl: number;
  if (count >= 20_000) {
    ttl = 90 * 24 * 3600; // 3 months
  } else if (count >= 1_000) {
    ttl = 24 * 3600; // 24 hours
  } else {
    ttl = 3 * 3600; // 3 hours
  }

  await valkey.expire(key, ttl);
  return count;
}
```

**Emergent properties:**

- Self-organizing "known good" database
- Garbage/attacks never accumulate enough to graduate
- Storage naturally bounded
- Adapts to browser ecosystem changes

## Data Model

### Valkey Key Schema

```
# Per-UA-family fingerprint counts
stat:v2:{ua_family}:ja4:{fingerprint}  → counter (with tiered TTL)
stat:v2:{ua_family}:h2:{fingerprint}   → counter (with tiered TTL)

# UA family totals (for probability calculation)
stat:v2:{ua_family}:ja4:_total         → counter (24h TTL, touch on write)
stat:v2:{ua_family}:h2:_total          → counter (24h TTL, touch on write)

# Global fingerprint counts (for Bayesian fallback)
stat:v2:_global:ja4:{fingerprint}      → counter (with tiered TTL, 1% sampling)
stat:v2:_global:h2:{fingerprint}       → counter (with tiered TTL, 1% sampling)

# Global totals
stat:v2:_global:ja4:_total             → counter (24h TTL)
stat:v2:_global:h2:_total              → counter (24h TTL)
```

### Global Sampling Strategy

To avoid global keys becoming bottlenecks, sample at 1% and multiply:

```typescript
// Record to global with 1% sampling
if (Math.random() < 0.01) {
  await valkey.incrby(`stat:v2:_global:ja4:${fingerprint}`, 100);
  await valkey.incrby(`stat:v2:_global:ja4:_total`, 100);
}
```

## Algorithm

### Recording (on each request)

```typescript
async function recordFingerprints(
  uaFamily: string,
  ja4: string,
  h2: string | undefined,
): Promise<StatisticalContextV2> {
  const pipeline = valkey.pipeline();

  // JA4: Increment and get count
  const ja4Key = `stat:v2:${uaFamily}:ja4:${ja4}`;
  const ja4TotalKey = `stat:v2:${uaFamily}:ja4:_total`;
  pipeline.incr(ja4Key);
  pipeline.incr(ja4TotalKey);

  // H2: Increment and get count (if available)
  if (h2) {
    const h2Key = `stat:v2:${uaFamily}:h2:${h2}`;
    const h2TotalKey = `stat:v2:${uaFamily}:h2:_total`;
    pipeline.incr(h2Key);
    pipeline.incr(h2TotalKey);
  }

  // Global sampling (1%)
  if (Math.random() < 0.01) {
    pipeline.incrby(`stat:v2:_global:ja4:${ja4}`, 100);
    pipeline.incrby(`stat:v2:_global:ja4:_total`, 100);
    if (h2) {
      pipeline.incrby(`stat:v2:_global:h2:${h2}`, 100);
      pipeline.incrby(`stat:v2:_global:h2:_total`, 100);
    }
  }

  const results = await pipeline.exec();

  // Apply tiered TTLs based on new counts
  await applyTieredTTLs(ja4Key, results[0], uaFamily, ja4, h2);

  return buildContext(results, uaFamily, ja4, h2);
}
```

### Scoring

```typescript
const MAX_SURPRISE_BITS = 12.0;
const SATURATION_THRESHOLD = 500;

function computeShannonScore(count: number, total: number): number {
  if (total === 0) return 0.5; // Neutral
  if (count === 0) return 1.0; // Maximum surprise

  const p = count / total;
  const surpriseBits = -Math.log2(p);
  return Math.min(1.0, surpriseBits / MAX_SURPRISE_BITS);
}

function computeConfidence(total: number): number {
  return Math.min(1.0, Math.sqrt(total / SATURATION_THRESHOLD));
}

function computeBlendedScore(
  uaCount: number,
  uaTotal: number,
  globalCount: number,
  globalTotal: number,
): { score: number; confidence: number } {
  const uaScore = computeShannonScore(uaCount, uaTotal);
  const globalScore = computeShannonScore(globalCount, globalTotal);
  const confidence = computeConfidence(uaTotal);

  const score = uaScore * confidence + globalScore * (1 - confidence);

  return { score, confidence };
}
```

### Detection

```typescript
const ANOMALY_THRESHOLD = 0.6; // 60% normalized surprise

function detectStatisticalAnomaliesV2(
  context: StatisticalContextV2 | null,
): AnomalySignal[] {
  if (!context) return [];

  const signals: AnomalySignal[] = [];

  // JA4 anomaly check
  if (context.ja4.score >= ANOMALY_THRESHOLD) {
    signals.push({
      type: "STATISTICAL",
      code: AnomalyCodes.RARE_JA4_FOR_UA,
      severity: context.ja4.score,
      evidence: {
        expected: `typical JA4 for ${context.uaFamily}`,
        actual: `ja4=${context.ja4.fingerprint.slice(0, 20)}..., score=${context.ja4.score.toFixed(3)}, confidence=${context.ja4.confidence.toFixed(3)}`,
        fields: ["ja4", "user_agent"],
      },
    });
  }

  // H2 anomaly check
  if (context.h2 && context.h2.score >= ANOMALY_THRESHOLD) {
    signals.push({
      type: "STATISTICAL",
      code: AnomalyCodes.RARE_H2_FOR_UA,
      severity: context.h2.score,
      evidence: {
        expected: `typical HTTP/2 fingerprint for ${context.uaFamily}`,
        actual: `h2=${context.h2.fingerprint.slice(0, 20)}..., score=${context.h2.score.toFixed(3)}, confidence=${context.h2.confidence.toFixed(3)}`,
        fields: ["h2_fingerprint", "user_agent"],
      },
    });
  }

  return signals;
}
```

## Context Interface

```typescript
interface FingerprintScore {
  fingerprint: string;
  count: number;
  total: number;
  globalCount: number;
  globalTotal: number;
  score: number; // Blended Shannon score
  confidence: number; // Bayesian confidence
  tier: "probation" | "proving" | "established";
}

interface StatisticalContextV2 {
  uaFamily: string;
  ja4: FingerprintScore;
  h2: FingerprintScore | null;
}
```

## Anomaly Codes

Add new codes to `types.ts`:

```typescript
export const AnomalyCodes = {
  // ... existing codes

  // Statistical v2 anomalies
  RARE_JA4_FOR_UA: "RARE_JA4_FOR_UA",
  RARE_H2_FOR_UA: "RARE_H2_FOR_UA",

  // Deprecate old code (keep for backwards compatibility)
  RARE_FINGERPRINT_COMBO: "RARE_FINGERPRINT_COMBO", // v1
} as const;
```

## Configuration

### Environment Variables

```typescript
// Enable/disable statistical v2 detection
STATISTICAL_V2_ENABLED: boolean; // default: false

// Shannon scoring
STATISTICAL_V2_THRESHOLD: number; // default: 0.6 (60% surprise)
STATISTICAL_V2_MAX_BITS: number; // default: 12

// Bayesian blending
STATISTICAL_V2_SATURATION: number; // default: 500

// Tiered TTL thresholds
STATISTICAL_V2_TIER1_COUNT: number; // default: 1000
STATISTICAL_V2_TIER2_COUNT: number; // default: 20000
STATISTICAL_V2_TIER0_TTL: number; // default: 10800 (3h)
STATISTICAL_V2_TIER1_TTL: number; // default: 86400 (24h)
STATISTICAL_V2_TIER2_TTL: number; // default: 7776000 (90d)
```

### Stage Config

```typescript
valkey: {
  // ... existing config
  statisticalV2: {
    enabled: true,  // dev
    threshold: 0.6,
    tierThresholds: [1000, 20000],
    tierTTLs: [3 * 3600, 24 * 3600, 90 * 24 * 3600],
  },
}
```

## Migration Strategy

### Phase 1: Shadow Mode (Week 1)

- Deploy with `STATISTICAL_V2_ENABLED=false`
- Record metrics but don't emit anomaly signals
- Monitor key counts, TTL distribution, score distribution

### Phase 2: Parallel Mode (Week 2-3)

- Run v1 and v2 simultaneously
- Compare signal rates, false positive rates
- Tune thresholds based on real data

### Phase 3: Cutover (Week 4)

- Switch to v2 as primary
- Deprecate v1 (keep code for rollback)
- Monitor for regressions

### Phase 4: Cleanup (Week 5+)

- Remove v1 code paths
- Clean up old Valkey keys
- Update documentation

## Files to Modify/Create

### New Files

- `src/services/profile/anomaly/statistical-v2.ts` - New detector
- `src/services/profile/anomaly/statistical-v2.test.ts` - Tests

### Modified Files

- `src/services/cache/valkey-client.ts` - Add tiered TTL functions
- `src/services/profile/anomaly/types.ts` - Add new anomaly codes
- `src/services/profile/anomaly/detector.ts` - Integrate v2 detector
- `src/services/profile/anomaly/index.ts` - Export v2 functions
- `src/handlers/matching-worker/process-record.ts` - Fetch v2 context
- `lib/config/stage-config.ts` - Add v2 configuration
- `lib/constructs/workers.ts` - Add v2 environment variables

## Metrics

### CloudWatch Metrics

```
StatisticalV2Ja4Score       - Blended JA4 score distribution
StatisticalV2H2Score        - Blended H2 score distribution
StatisticalV2Ja4Confidence  - JA4 Bayesian confidence
StatisticalV2H2Confidence   - H2 Bayesian confidence
StatisticalV2Ja4Anomaly     - JA4 anomaly detected count
StatisticalV2H2Anomaly      - H2 anomaly detected count
StatisticalV2TierPromotion  - Fingerprint graduated to higher tier
```

### Monitoring Queries

```sql
-- Tier distribution over time
SELECT tier, COUNT(*)
FROM statistical_v2_metrics
GROUP BY tier, time_bucket('1h', timestamp)

-- False positive candidates (high score but high count)
SELECT * FROM statistical_v2_metrics
WHERE score > 0.6 AND count > 1000
```

## Test Cases

### Unit Tests

1. **Shannon scoring**
   - 50% probability → ~0.083 score (1 bit / 12 bits)
   - 1% probability → ~0.55 score (6.6 bits / 12 bits)
   - 0% (unseen) → 1.0 score

2. **Bayesian blending**
   - 0 samples → 100% global weight
   - 500 samples → 100% UA-specific weight
   - 125 samples → 50/50 blend

3. **Tiered TTL**
   - count=500 → 3 hour TTL
   - count=5000 → 24 hour TTL
   - count=50000 → 90 day TTL

4. **Dual-layer detection**
   - Spoofed JA4 only → JA4 signal, no H2 signal
   - Spoofed H2 only → H2 signal, no JA4 signal
   - Both spoofed → Both signals

### Integration Tests

1. **Cold-start behavior**: New UA family relies on global baseline
2. **Graduation**: Fingerprint accumulates hits and extends TTL
3. **Expiration**: Low-hit fingerprint expires after 3 hours

## Example Scenarios

### Scenario 1: Legitimate Chrome User

```
UA: Chrome/120
JA4: t13d1516h2_8daaf... (common Chrome JA4)
H2: 1:65536,2:0,3:1000... (common Chrome H2)

JA4 count: 45,000 (established tier)
JA4 total: 100,000
→ P = 0.45, surprise = 1.15 bits, score = 0.096
→ No anomaly

H2 count: 52,000 (established tier)
H2 total: 100,000
→ P = 0.52, surprise = 0.94 bits, score = 0.078
→ No anomaly
```

### Scenario 2: Bot Spoofing Chrome

```
UA: Chrome/120
JA4: t13d1516h2_abc123... (never seen with Chrome)
H2: 1:65536,2:0,3:1000... (correct Chrome H2)

JA4 count: 1 (probation tier, 3h TTL)
JA4 total: 100,000
→ P = 0.00001, surprise = 16.6 bits, score = 1.0 (capped)
→ RARE_JA4_FOR_UA anomaly

H2 count: 52,000 (established)
→ score = 0.078
→ No anomaly
```

### Scenario 3: New Browser "Arc"

```
UA: Arc/1.0
JA4: t13d1516h2_xyz789... (Arc's actual JA4)
H2: 1:65536,4:1,6:256... (Arc's actual H2)

UA family total: 50 (very new)
→ confidence = sqrt(50/500) = 0.316

JA4 UA count: 45 (most Arc users have this)
JA4 global count: 10 (rare globally)
→ UA score = 0.096, global score = 0.83
→ Blended = 0.096 * 0.316 + 0.83 * 0.684 = 0.60
→ Borderline - might flag initially, clears as Arc gains users
```

## Payload Field Paths

```typescript
// JA4 TLS fingerprint
const ja4 = payload.network?.tlsFingerprint?.ja4;

// HTTP/2 fingerprint (protocol + header order)
const h2 = payload.network?.tcpProbe?.http2_fingerprint?.fingerprint;
// Example: "HTTP/2.0|accept,accept-encoding,accept-language,origin,..."

// User-Agent for extracting UA family
const userAgent = payload.network?.tcpProbe?.user_agent;
```

**Observed fingerprint distribution (from 95 sample payloads):**

| Browser | Unique JA4s | Unique H2s | Notes                     |
| ------- | ----------- | ---------- | ------------------------- |
| Safari  | 1           | 1          | Most consistent           |
| Chrome  | 2           | 1          | JA4 varies (QUIC vs TCP?) |
| Firefox | 3           | 2          | Most variation            |

H2 fingerprints are more stable than JA4 (fewer unique values per browser). Both signals are independent and valuable for different spoofing scenarios.

## Open Questions

1. **Threshold tuning**: 0.6 threshold is a starting point. May need adjustment based on production data.

2. **Cross-layer correlation**: Should we add a third signal for "does this JA4 typically appear with this H2"? Adds complexity but catches sophisticated spoofing.

3. **Rate limiting graduation**: Should we cap how fast a fingerprint can graduate to prevent flooding attacks? e.g., max 1000 increments per minute per key.

## Appendix: Why Not Combined Key?

Considered `ua_family::{ja4}::{h2}` as single key but rejected because:

1. **Sparsity**: `num_ja4s × num_h2s` combinations, most empty
2. **Partial spoofing**: Can't detect when only one layer is wrong
3. **Independent updates**: Browser TLS and HTTP/2 stacks update on different schedules
4. **Storage**: Would need much longer TTLs to accumulate meaningful counts
