# ASN Network Baseline Anomaly Detection

## Problem Statement

Current proxy/VPN detection relies on absolute thresholds (e.g., `tls_ratio > 3.0`). This misses:

1. **High-quality residential proxies** - ratio ~2.5 slips under threshold
2. **Geographic variance** - AU users legitimately have higher ratios than US users
3. **ASN-specific baselines** - Comcast mobile vs Comcast residential have different "normal"

We observed in payload data:

- 92 sessions from same IP: ratio 0.9-1.3, proxy_score=0
- 1 session from same IP: ratio 11.9, proxy_score=0.5

The 11.9 is a **10σ outlier for that specific IP/ASN**. Absolute thresholds caught it, but barely. A ratio of 3.0 from that IP would be a 6σ outlier but wouldn't trigger current detection.

---

## Proposed Solution

**Shannon information-theoretic scoring based on per-ASN histograms with Bayesian blending.**

For each `{ASN, device_type}` pair, maintain histogram buckets of network metrics:

- `tls_to_tcp_ratio`
- `snd_mss`

~~`tcp_rtt_us`~~ **Dropped** - RTT is a function of user↔server distance, not network stack. Geographic variance creates noise (AT&T user in Dallas vs Seattle = wildly different RTT, both legitimate).

When a new connection arrives, compute:

```
surprise = -log₂(P(bucket))
score = surprise / MAX_SURPRISE_BITS  // Fixed constant, not dynamic!
```

**Key insight:** Blend ASN-specific score with global baseline using confidence weight:

```
confidence = min(1.0, sqrt(N / 500))
final_score = (score_asn × confidence) + (score_global × (1 - confidence))
```

This solves cold-start: new ASNs fall back to global norms, established ASNs use their own baseline.

---

## Why This Approach

### Why histograms over mean/variance?

Real distributions are **multimodal**:

```
Residential: μ=1.0, σ=0.1
Mobile:      μ=8.0, σ=0.5
Combined:    μ=4.5, σ=3.5  ← useless
```

A proxy at ratio 3.0 looks "normal" with combined stats (z=0.4) but is actually anomalous (between both clusters).

Histograms don't assume distribution shape. They answer: "Have I seen many connections in this bucket before?"

### Why Shannon information?

1. **Principled** - Information theory provides mathematically grounded "surprise" measure
2. **Log scale** - Naturally handles fat tails; going from 250→25 observations doubles surprise, not 10x
3. **Normalized** - Easy to combine with other scores (0-1 range)
4. **Interpretable** - "This observation required 7 bits of information" = rare

### Why Valkey (Redis)?

Already deployed for statistical anomaly detection. Provides:

- **Sorted sets** - Natural histogram storage with O(log N) updates
- **Atomic operations** - ZINCRBY for concurrent updates
- **TTL management** - Auto-expire stale data (48h)
- **HyperLogLog** - Already using for cardinality estimation
- **Pipelining** - Batch reads/writes efficiently

Could use DynamoDB but:

- No native sorted set (would need scan + filter)
- More expensive for high-frequency counter updates
- Valkey already in VPC, already warm

---

## Data Model

### Redis Key Schema

```
# ASN-Specific Histograms (updated on every request)
asn:{asn}:{device_type}:tls_ratio:hist     → ZSET { "0.8-1.0": 4500, "1.0-1.2": 3200, ... }
asn:{asn}:{device_type}:mss:hist           → ZSET { "1440-1460": 8000, "1380-1400": 200, ... }
asn:{asn}:{device_type}:total              → INT

# Global Baseline (fallback for cold-start ASNs)
# Updated via 1% sampling to reduce write load
global:{device_type}:tls_ratio:hist        → ZSET { "0.8-1.0": 500000, ... }
global:{device_type}:mss:hist              → ZSET { "1440-1460": 800000, ... }
global:{device_type}:total                 → INT

# TTL: 48 hours (configurable)
```

**Note:** `tcp_rtt` dropped - it's a function of geography, not network stack.

### Bucket Definitions

```typescript
const TLS_RATIO_BUCKETS = [
  { id: "0.0-0.5", min: 0.0, max: 0.5 },
  { id: "0.5-0.8", min: 0.5, max: 0.8 },
  { id: "0.8-1.0", min: 0.8, max: 1.0 },
  { id: "1.0-1.2", min: 1.0, max: 1.2 },
  { id: "1.2-1.5", min: 1.2, max: 1.5 },
  { id: "1.5-2.0", min: 1.5, max: 2.0 },
  { id: "2.0-3.0", min: 2.0, max: 3.0 },
  { id: "3.0-5.0", min: 3.0, max: 5.0 },
  { id: "5.0-10.0", min: 5.0, max: 10.0 },
  { id: "10.0+", min: 10.0, max: Infinity },
];

const MSS_BUCKETS = [
  { id: "0-1200", min: 0, max: 1200 }, // Heavy tunnel
  { id: "1200-1300", min: 1200, max: 1300 }, // VPN (OpenVPN, WireGuard)
  { id: "1300-1400", min: 1300, max: 1400 }, // Light tunnel
  { id: "1400-1450", min: 1400, max: 1450 }, // Normal residential
  { id: "1450-1500", min: 1450, max: 1500 }, // Standard
  { id: "1500+", min: 1500, max: Infinity }, // Jumbo/unusual
];

// TCP_RTT_BUCKETS - REMOVED
// RTT is a function of user↔server distance, not network stack.
// AT&T user in Dallas vs Seattle = wildly different RTT, both legitimate.
```

### Device Type Extraction

```typescript
function extractDeviceType(fingerprint: Fingerprint): string {
  const ua = fingerprint.navigator?.userAgent || "";
  if (/Mobile|Android|iPhone|iPad/.test(ua)) return "mobile";
  if (/Tablet/.test(ua)) return "tablet";
  return "desktop";
}
```

**Note on UA Spoofing:** This is a feature, not a bug.

If a proxy on a hacked Linux IoT device spoofs an iPhone User-Agent:

- We categorize it as `mobile`
- We compare its network stack (Linux TCP fingerprint, datacenter MSS) against the "Real iPhone" baseline
- **Result:** The mismatch between claimed identity (UA) and network reality (baselines) drives the score up

The system detects **impersonation** as much as it detects anomalies.

---

## Scoring Algorithm

### Why Fixed Normalization Matters

**The flaw with dynamic normalization:**

If we normalize by `log₂(totalCount)`, the same probability event gets different scores:

- Small ASN (N=1,000): `score = 3.32/10 = 0.33`
- Large ASN (N=1,000,000): `score = 3.32/20 = 0.16`

This penalizes small ISPs and whitewashes large ISPs. **A 10% probability event should have consistent surprise regardless of sample size.**

**Fix:** Normalize against a fixed constant representing "maximum meaningful surprise":

- 10 bits = 1 in 1,024 (~0.1%)
- 12 bits = 1 in 4,096 (~0.02%)
- 13 bits = 1 in 8,192 (~0.01%)

We use **12 bits** as our ceiling.

### Core Function

```typescript
// Fixed constant - do NOT use log₂(totalCount)
const MAX_SURPRISE_BITS = 12.0;
const SATURATION_THRESHOLD = 500; // Samples for 100% confidence

interface NetworkBaselineContext {
  asn: string;
  deviceType: string;
  tlsRatioBucket: string;
  mssBucket: string;
  histograms: {
    tlsRatio: Map<string, number>;
    mss: Map<string, number>;
  };
  total: number;
}

interface BaselineResult {
  score: number; // Final blended anomaly score [0, 1]
  confidence: number; // How much we trust ASN-specific data [0, 1]
  signals: string[];
  meta: {
    asnTotal: number;
    rawAsnScore: number;
    rawGlobalScore: number;
  };
}

function computeShannonScore(bucketCount: number, totalCount: number): number {
  if (totalCount === 0) return 0.5; // Neutral if no data
  if (bucketCount === 0) return 1.0; // Maximum surprise for unseen bucket

  const p = bucketCount / totalCount;
  const surpriseBits = -Math.log2(p);

  // Normalize against fixed ceiling, not dynamic log₂(N)
  return Math.min(1.0, surpriseBits / MAX_SURPRISE_BITS);
}

function computeRawScore(ctx: NetworkBaselineContext): number {
  const tlsScore = computeShannonScore(
    ctx.histograms.tlsRatio.get(ctx.tlsRatioBucket) || 0,
    ctx.total,
  );

  const mssScore = computeShannonScore(
    ctx.histograms.mss.get(ctx.mssBucket) || 0,
    ctx.total,
  );

  // Weighted: tls_ratio is more discriminative than mss
  return tlsScore * 0.6 + mssScore * 0.4;
}

/**
 * Bayesian blend: smoothly transition from global → ASN-specific
 * as we accumulate data for this ASN.
 */
function computeBlendedScore(
  asnCtx: NetworkBaselineContext,
  globalCtx: NetworkBaselineContext,
): BaselineResult {
  const signals: string[] = [];

  // Confidence: sqrt curve rewards early data, plateaus at saturation
  const n = asnCtx.total;
  const confidence = Math.min(1.0, Math.sqrt(n / SATURATION_THRESHOLD));

  // Compute raw scores for both baselines
  const rawAsnScore = computeRawScore(asnCtx);
  const rawGlobalScore = computeRawScore(globalCtx);

  // Bayesian blend:
  // - If confidence=0 (new ASN): 100% global score
  // - If confidence=1 (established ASN): 100% ASN-specific score
  const blendedScore =
    rawAsnScore * confidence + rawGlobalScore * (1 - confidence);

  // Build signals
  if (blendedScore > 0.5) {
    if (confidence > 0.8) {
      signals.push(`high_confidence_asn_anomaly:${asnCtx.asn}`);
    } else {
      signals.push("global_baseline_deviation");
    }
  }
  if (rawAsnScore > 0.6) signals.push(`rare_for_asn:${asnCtx.tlsRatioBucket}`);
  if (rawGlobalScore > 0.6)
    signals.push(`rare_globally:${asnCtx.tlsRatioBucket}`);

  return {
    score: blendedScore,
    confidence,
    signals,
    meta: {
      asnTotal: n,
      rawAsnScore,
      rawGlobalScore,
    },
  };
}
```

### Threshold for Anomaly Flag

```typescript
const NETWORK_BASELINE_THRESHOLD = 0.5; // 50% normalized surprise = flag

if (result.score >= NETWORK_BASELINE_THRESHOLD) {
  return createSignal(
    "NETWORK",
    AnomalyCodes.ASN_NETWORK_ANOMALY,
    result.score, // severity = blended score
    {
      asn: asnCtx.asn,
      deviceType: asnCtx.deviceType,
      confidence: result.confidence,
      signals: result.signals,
      meta: result.meta, // Raw scores for debugging
    },
  );
}
```

### What Confidence Means for Downstream

The `confidence` field tells consumers how to interpret the score:

| Confidence | Meaning                   | Action                               |
| ---------- | ------------------------- | ------------------------------------ |
| 0.0-0.3    | "We barely know this ASN" | Score is mostly global baseline      |
| 0.3-0.7    | "Mixed knowledge"         | Blended score, treat with caution    |
| 0.7-1.0    | "We know this ASN well"   | High-quality signal, trust the score |

Downstream systems (fraud rules, manual review queues) can use confidence to weight decisions:

- `score=0.8, confidence=0.9` → Strong signal, act on it
- `score=0.8, confidence=0.2` → Suspicious globally but unknown ASN, maybe flag for review rather than block

---

## Implementation Plan

### Phase 1: Valkey Schema Extension

**File:** `src/services/cache/valkey-client.ts`

Add new functions:

```typescript
/**
 * Record metrics to both ASN-specific and global histograms.
 * Global is sampled at 1% to reduce write load.
 */
export async function recordNetworkMetrics(
  asn: string,
  deviceType: string,
  tlsRatioBucket: string,
  mssBucket: string,
): Promise<void>;

/**
 * Fetch both ASN-specific and global baselines in one pipelined call.
 */
export async function getNetworkBaselines(
  asn: string,
  deviceType: string,
): Promise<{ asn: NetworkBaselineContext; global: NetworkBaselineContext }>;
```

### Phase 2: Bucket Helpers & Scoring

**File:** `src/services/profile/anomaly/network-baseline.ts`

```typescript
export function getBucket(value: number, buckets: Bucket[]): string;
export function extractDeviceType(fingerprint: Fingerprint): string;
export function computeShannonScore(
  bucketCount: number,
  totalCount: number,
): number;
export function computeConfidence(sampleCount: number): number;
export function computeBlendedScore(
  asnCtx: NetworkBaselineContext,
  globalCtx: NetworkBaselineContext,
): BaselineResult;
```

### Phase 3: Anomaly Detector

**File:** `src/services/profile/anomaly/detectors/network-baseline.ts`

```typescript
export async function fetchNetworkBaselineContext(
  fingerprint: Fingerprint,
  sigint: SigintData,
): Promise<NetworkBaselineContext | null>;

export function detectNetworkBaselineAnomalies(
  ctx: NetworkBaselineContext | null,
): AnomalySignal[];
```

### Phase 4: Integration

**File:** `src/services/profile/anomaly/detector-registry.ts`

Add `network-baseline` to detector list, after `network.ts` (existing).

**File:** `src/handlers/matching-worker.ts`

Pre-fetch network baseline context alongside existing statistical context.

### Phase 5: Configuration

**File:** `src/config/env.ts`

```typescript
NETWORK_BASELINE_ENABLED: boolean;
NETWORK_BASELINE_MIN_DISTINCT_IPS: number; // default 50
NETWORK_BASELINE_THRESHOLD: number; // default 0.5
NETWORK_BASELINE_TTL_SECONDS: number; // default 172800 (48h)
```

**File:** `lib/config/stage-config.ts`

Add to valkey config section.

---

## Risk Scoring Integration

**File:** `src/services/profile/flag-computation.ts`

Add flag weight:

```typescript
ASN_NETWORK_ANOMALY: +0.15; // Similar weight to LIKELY_PROXY
```

This stacks with existing `LIKELY_PROXY` and `LIKELY_VPN` flags from tcp-probe thresholds, providing defense in depth.

---

## Example Scenarios

### Scenario 1: Normal Comcast Desktop User (Established ASN)

```
ASN: 7018, DeviceType: desktop
TLS Ratio: 1.05 → bucket "1.0-1.2"
MSS: 1448 → bucket "1400-1450"

ASN Histogram (N=60,000):
  "1.0-1.2": 45000 (dominant)

P(bucket) = 45000/60000 = 0.75
Surprise = -log₂(0.75) = 0.41 bits
Raw ASN Score = 0.41 / 12.0 = 0.034

Confidence = sqrt(60000/500) = 1.0 (maxed out)
Final Score = (0.034 × 1.0) + (global × 0.0) = 0.034

Result: score=0.034, confidence=1.0 → No anomaly
```

### Scenario 2: Residential Proxy on Comcast (Established ASN)

```
ASN: 7018, DeviceType: desktop
TLS Ratio: 3.2 → bucket "3.0-5.0"
MSS: 1448 → bucket "1400-1450"

ASN Histogram (N=60,000):
  "3.0-5.0": 150 (rare!)
  "1.0-1.2": 45000

P(bucket) = 150/60000 = 0.0025
Surprise = -log₂(0.0025) = 8.64 bits
Raw ASN Score = 8.64 / 12.0 = 0.72

Confidence = 1.0 (established)
Final Score = 0.72

Result: score=0.72, confidence=1.0 → ASN_NETWORK_ANOMALY flagged!
Signals: ["high_confidence_asn_anomaly:7018", "rare_for_asn:3.0-5.0"]
```

### Scenario 3: New Regional ISP (Cold Start with Global Fallback)

```
ASN: 99999 (tiny NZ ISP), DeviceType: desktop
TLS Ratio: 3.5 → bucket "3.0-5.0"
MSS: 1448 → bucket "1400-1450"

ASN Histogram (N=15):
  "3.0-5.0": 2
  Total: 15

Raw ASN Score = computeShannonScore(2, 15) = 0.24

Global Histogram (N=5,000,000):
  "3.0-5.0": 2500 (0.05%)

Raw Global Score = -log₂(0.0005) / 12.0 = 0.91

Confidence = sqrt(15/500) = 0.17 (low - we don't trust this ASN's data yet)

Final Score = (0.24 × 0.17) + (0.91 × 0.83) = 0.04 + 0.76 = 0.80

Result: score=0.80, confidence=0.17 → Flagged via global baseline
Signals: ["global_baseline_deviation", "rare_globally:3.0-5.0"]
```

**Key insight:** Even though this is a new ASN with only 15 samples, we correctly flag the anomaly by falling back to global norms. The low confidence tells downstream systems "we caught this via global patterns, not ASN-specific knowledge."

### Scenario 4: Legitimate Mobile User (Different Baseline)

```
ASN: 7018, DeviceType: mobile
TLS Ratio: 2.1 → bucket "2.0-3.0"
MSS: 1448 → bucket "1400-1450"

ASN:7018:mobile Histogram (N=20,000):
  "2.0-3.0": 8000 (common for mobile!)
  "1.5-2.0": 5000

P(bucket) = 8000/20000 = 0.40
Surprise = -log₂(0.40) = 1.32 bits
Raw ASN Score = 1.32 / 12.0 = 0.11

Confidence = 1.0
Final Score = 0.11

Result: score=0.11, confidence=1.0 → No anomaly
```

Mobile users have a different "normal" - the device_type segmentation prevents false positives.

---

## Metrics & Observability

### CloudWatch Metrics

```typescript
metrics.addMetric("NetworkBaselineScore", score);
metrics.addMetric("NetworkBaselineAnomalyDetected", anomalyDetected ? 1 : 0);
metrics.addMetric("NetworkBaselineInsufficientData", insufficientData ? 1 : 0);
metrics.addDimension("ASN", asn);
metrics.addDimension("DeviceType", deviceType);
```

### Logging

```typescript
logger.info("Network baseline computed", {
  asn,
  deviceType,
  tlsRatioBucket,
  mssBucket,
  score,
  signals,
  distinctIps,
});
```

---

## Rollout Strategy

1. **Week 1:** Deploy with `NETWORK_BASELINE_ENABLED=false` (shadow mode)
   - Record metrics only
   - No impact on risk scores

2. **Week 2:** Enable in dev, analyze distributions
   - Verify histogram populations
   - Tune thresholds if needed

3. **Week 3:** Enable in prod with high threshold (0.7)
   - Conservative flagging
   - Monitor false positive rate

4. **Week 4:** Lower threshold to 0.5 if FP rate acceptable

---

## Open Questions

1. ~~**Fallback for rare ASNs:** Use global baseline?~~ **RESOLVED:** Bayesian blend with confidence weighting. New ASNs automatically fall back to global baseline proportionally to their sample size.

2. ~~**Cold start:** New ASN with <50 distinct IPs - skip detection or use global?~~ **RESOLVED:** Confidence = sqrt(N/500). At N=50, confidence=0.31, so we use 69% global + 31% ASN-specific.

3. **Bucket granularity:** Current buckets are hand-tuned. Should we use quantile-based buckets derived from data? (Keep for future iteration)

4. **Cross-metric correlation:** Should we detect "unusual combination" (e.g., low MSS + normal ratio = VPN with good peering)? (Keep for future iteration)

5. **Global baseline write scaling:** 1% sampling for global updates - is this sufficient, or do we need adaptive sampling based on traffic volume?

---

## Summary

| Component     | Choice                         | Rationale                                                           |
| ------------- | ------------------------------ | ------------------------------------------------------------------- |
| Storage       | Valkey sorted sets             | Already deployed, atomic ops, TTL, O(log N) histogram updates       |
| Algorithm     | Shannon self-information       | Principled, handles multimodal, log-scale for fat tails             |
| Normalization | Fixed 12-bit ceiling           | Consistent scoring across ASN sizes (no large-ASN whitewashing)     |
| Cold Start    | Bayesian blend with confidence | Smooth transition from global→ASN-specific as data accumulates      |
| Confidence    | sqrt(N/500)                    | Rewards early data collection, plateaus at statistical significance |
| Segmentation  | ASN + device_type              | Captures network + usage pattern differences                        |
| Metrics       | tls_ratio, mss                 | Intrinsic network stack properties (RTT dropped - geographic noise) |
| Threshold     | 0.5 (50% normalized surprise)  | Tunable, conservative start                                         |
| Integration   | Detector registry pattern      | Matches existing anomaly detection architecture                     |

**Estimated effort:** 3-4 days implementation, 1 week shadow mode, 1 week gradual rollout.
