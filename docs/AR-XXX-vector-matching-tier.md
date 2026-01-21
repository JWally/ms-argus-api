# AR-XXX: Vector Similarity Matching Tier

## Overview

Restructure the matching pipeline to incorporate vector similarity search via QDrant, providing better fuzzy matching capabilities for cross-browser and heavily mutated fingerprints.

## Current Tier Structure

```
Tier 0    → Session Cache (DynamoDB)
Tier 0.5  → Identity: public_key, evercookie_id, sigint_id
Tier 1    → Hash Match: stable_hash, fuzzy_hash (exact)
Tier 2    → Compound Buckets: ip+ja4, gpu+screen+tz, etc.
Anchors   → Session anchor, IP+UA anchor
New       → Generate dev_ULID
```

## Proposed Tier Structure

```
Tier 0    → Session Cache (DynamoDB) - unchanged
Tier 0.5  → Identity: public_key, evercookie_id, sigint_id - unchanged
Tier 1    → Hash Match: stable_hash, fuzzy_hash (exact) - unchanged
Tier 1.5a → Session Anchor (strong, can short-circuit)
Tier 1.5b → IP+UA Anchor (weak, produces candidates only - feeds into scoring)
Tier 2    → Vector Similarity: same-browser drift matching (NEW)
            Catches fingerprints where exact hash failed but fuzzy_hash is close
Tier 3    → Compound Buckets: ip+ja4, gpu+screen+tz, etc. (bounded fallback)
New       → Generate dev_ULID
```

## Rationale

### Why move anchors to Tier 1.5?

- Session and IP+UA anchors are fast exact lookups (single DynamoDB query each)
- They have a tight time budget and should complete quickly
- **Critical distinction:**
  - **Session anchor (1.5a)**: Strong signal, can short-circuit matching if valid
  - **IP+UA anchor (1.5b)**: Weak signal, high recall but lower precision
    - Should produce _candidates_, not final match
    - Must be gated by time-window (e.g., last_seen within N minutes)
    - Must not short-circuit if conflicting strong evidence exists

### Why vector at Tier 2?

- Vector similarity can catch matches that exact hashes miss:
  - Cross-browser fingerprints (same device, different browser)
  - Fingerprints with minor mutations (browser updates, config changes)
  - Privacy browser variations
- Faster than compound bucket fan-out (single vector query vs multiple bucket queries)
- More accurate than bucket overlap scoring (learned similarity vs hand-crafted rules)

### Why compound buckets at Tier 3?

- Fallback when vectors don't have a match (new device not yet in vector DB)
- Still valuable for catching matches based on network/hardware signals
- **Must be bounded harder than current implementation:**
  - Every bucket query: strict LIMIT
  - Deterministic max candidates per bucket
  - Global cap on merged candidate set before scoring/hydration
  - Prefer "read fewer, score better" over "read more, hope overlap works"

### SimHash / fuzzy_hash - THE KEY SIGNAL

- **fuzzy_hash IS the core of Tier 2 vector matching**
- SimHash is specifically designed for drift detection:
  - Small input changes → small bit changes → high cosine similarity
  - Hamming distance on bipolar vectors = cosine distance
- Occupies 64 dims (25% of vector) because it's the most valuable signal
- When fuzzy_hash exact match fails (Tier 1), vector similarity catches near-matches

## Vector Embedding Strategy

### Goal: Same-browser drift matching

Primary use case: Link the **same browser** to itself as it changes over time.

When exact hash match (Tier 1) fails due to:

- Browser updates (Chrome 130 → 131)
- Minor config changes
- Canvas/audio rendering drift
- WebGL driver updates

The vector tier catches these "close but not exact" fingerprints.

### Design principles

1. **Browser-specific signals ARE the point**: Canvas, audio, WebGL hashes - these drift but stay similar
2. **SimHash is key**: fuzzy_hash is designed for exactly this - Hamming distance on drifted fingerprints
3. **Structural anchors**: maths_hash, css_hash, etc. are stable even when canvas drifts
4. **Network is secondary**: Same device might be on different network, so less weight
5. **Graceful degradation**: Missing fields → zero in that subvector (don't fail)

### Normalized Fingerprint fields available

From `normalizeFingerprint()` output:

```typescript
// Hashes (exact match - less useful for similarity)
(stable_hash, fuzzy_hash, canvas_hash, webgl_hash, audio_hash);
(maths_hash, window_features_hash, html_element_hash, css_hash);
(features_hash, svg_hash, client_rects_hash, intl_hash, console_errors_hash);

// Numeric (good for similarity)
hardware_concurrency: number; // 1-128, typically 2-16
device_memory: number; // 0.5-64 GB, often null on Firefox
screen_dims: string; // "1920x1080" → parse to width, height
webgl_extensions_count: number; // 0-50+
tcp_rtt_us: number; // network latency in microseconds
proxy_score: number; // 0-1
vpn_score: number; // 0-1
lie_count: number; // 0-10+

// Categorical (need feature hashing)
timezone: string; // "America/Chicago" - ~400 values
gpu_renderer: string; // "ANGLE (Apple, Apple M1...)" - high cardinality
ip_address: string; // for /24 subnet similarity
ja4: string; // TLS fingerprint - ~1000s of values
user_agent: string; // browser family extraction

// Boolean
is_headless: boolean;
is_private_browsing: boolean;
```

### Embedding architecture (256 dimensions)

Focused on same-browser drift matching - browser fingerprint signals that stay similar over time:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   256-dim Browser Fingerprint Vector                     │
├─────────────────────────────────────────────────────────────────────────┤
│ [0-63]    SimHash subvector (64 dims)                                   │
│           - fuzzy_hash bits (64 dims, bipolar: 1/-1)                    │
│           THE KEY SIGNAL: SimHash is designed for drift matching        │
│           Small changes → small Hamming distance → high cosine sim      │
├─────────────────────────────────────────────────────────────────────────┤
│ [64-127]  Structural anchors (64 dims)                                  │
│           - maths_hash (8 dims)         - FPU-level, very stable        │
│           - window_features_hash (8)    - engine-level                  │
│           - css_hash (8 dims)           - browser-specific              │
│           - features_hash (8 dims)      - capability flags              │
│           - intl_hash (8 dims)          - locale internals              │
│           - client_rects_hash (8 dims)  - rendering quirks              │
│           - svg_hash (8 dims)           - SVG implementation            │
│           - html_element_hash (8 dims)  - DOM version                   │
│           These survive most updates, anchor the fingerprint            │
├─────────────────────────────────────────────────────────────────────────┤
│ [128-191] Rendering hashes (64 dims)                                    │
│           - canvas_hash (feature hashed, 24 dims) - drifts with updates │
│           - audio_hash (feature hashed, 16 dims)  - drifts with updates │
│           - webgl_hash (feature hashed, 24 dims)  - drifts with drivers │
│           These change more often, but similar → partial match          │
├─────────────────────────────────────────────────────────────────────────┤
│ [192-223] Hardware/environment (32 dims)                                │
│           - gpu_renderer (feature hashed, 16 dims)                      │
│           - screen_width (normalized, 1 dim)                            │
│           - screen_height (normalized, 1 dim)                           │
│           - hardware_concurrency (normalized, 1 dim)                    │
│           - device_memory (normalized, 1 dim)                           │
│           - timezone (feature hashed, 12 dims)                          │
│           Stable hardware signals, same device = same values            │
├─────────────────────────────────────────────────────────────────────────┤
│ [224-255] Network/TLS (32 dims)                                         │
│           - ja4 (feature hashed, 24 dims) - stable for same browser     │
│           - tcp_rtt_bucket (8 dims)       - network proximity           │
│           JA4 is browser-version specific, good for same-browser match  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key insight**: SimHash (fuzzy_hash) occupies 25% of the vector because it's specifically designed for this use case - detecting similar documents/fingerprints with small changes.

### Feature hashing implementation

```typescript
// MurmurHash3 into N buckets with sign (allows collision cancellation)
function featureHash(value: string, dims: number): number[] {
  const vec = new Array(dims).fill(0);
  if (!value) return vec;

  // Hash to bucket index
  const hash = murmurhash3(value);
  const bucket = hash % dims;

  // Sign from second hash (collision resistance)
  const sign = murmurhash3(value + "_sign") % 2 === 0 ? 1 : -1;

  vec[bucket] = sign;
  return vec;
}

// THE KEY FUNCTION: Convert SimHash fuzzy_hash to bipolar vector
// fuzzy_hash is 64 hex chars = 256 bits, we take first 64 bits
// Bipolar encoding: '1' → +1, '0' → -1
// This preserves Hamming distance as cosine distance!
function fuzzyHashToVector(fuzzyHash: string): number[] {
  if (!fuzzyHash || fuzzyHash.length < 16) {
    return new Array(64).fill(0);
  }
  // Take first 16 hex chars = 64 bits
  const bits = hexToBinary(fuzzyHash.slice(0, 16));
  return bits.split("").map((b) => (b === "1" ? 1 : -1));
}

function hexToBinary(hex: string): string {
  return hex
    .split("")
    .map((c) => parseInt(c, 16).toString(2).padStart(4, "0"))
    .join("");
}

// Structural hash to fixed-size vector (8 dims each)
function structuralHashToVector(hash: string | undefined): number[] {
  if (!hash) return new Array(8).fill(0);
  return featureHash(hash, 8);
}
```

### Normalization

```typescript
const NORMALIZERS = {
  hardware_concurrency: (v: number) => Math.min(v || 4, 32) / 32, // cap at 32, default 4
  device_memory: (v: number) => Math.min(v || 4, 64) / 64, // cap at 64GB, default 4
  screen_width: (v: number) => Math.min(v || 1920, 4096) / 4096, // cap at 4K
  screen_height: (v: number) => Math.min(v || 1080, 2160) / 2160, // cap at 4K
};

// TCP RTT buckets (one-hot, 8 dims)
const RTT_BUCKETS = [10, 25, 50, 100, 200, 500, 1000, Infinity]; // ms
function rttToBucket(rttUs: number): number[] {
  const rttMs = (rttUs || 50000) / 1000; // default 50ms
  const bucket = RTT_BUCKETS.findIndex((b) => rttMs < b);
  const vec = new Array(8).fill(0);
  vec[bucket >= 0 ? bucket : 7] = 1;
  return vec;
}
```

### Why this structure?

1. **SimHash-heavy (64 dims, 25%)**: THE key signal for drift detection, deserves most weight
2. **Structural anchors (64 dims)**: Stable signals that survive updates, anchor identity
3. **Rendering hashes (64 dims)**: Change with updates but partial match still valuable
4. **Hardware (32 dims)**: Stable device characteristics
5. **Network/TLS (32 dims)**: JA4 stable within same browser version

### Same-browser drift example

Chrome 130 → Chrome 131 update on same device:

| Signal       | Chrome 130         | Chrome 131         | Similarity               |
| ------------ | ------------------ | ------------------ | ------------------------ |
| fuzzy_hash   | `aa68681e56fff...` | `aa68681e56ffe...` | ~0.95 (1-2 bits differ)  |
| maths_hash   | `abc123...`        | `abc123...`        | 1.0 (identical)          |
| css_hash     | `def456...`        | `def456...`        | 1.0 (identical)          |
| canvas_hash  | `ea7e3f9...`       | `fa8e4f0...`       | ~0.7 (rendering changed) |
| audio_hash   | `9d6aa47...`       | `9d6aa47...`       | 1.0 (often stable)       |
| gpu_renderer | "ANGLE..."         | "ANGLE..."         | 1.0 (same hardware)      |
| ja4          | `t13d1516h2_...`   | `t13d1517h2_...`   | ~0.8 (minor TLS change)  |

**Expected cosine similarity: ~0.85-0.90**

This catches the device when:

- stable_hash changed (Tier 1 miss)
- fuzzy_hash exact match failed (Tier 1 miss)
- But overall fingerprint is "close enough" → Tier 2 vector match

### Collection structure in QDrant:

**Multi-vector per device (recommended)**
Store points as "observations," not "devices":

```
Collection: "fingerprints"
  - vector_size: 256
  - distance: Cosine

Point:
  - id: observation_id (ULID of fingerprint event)
  - vector: 256-dim float32
  - payload:
    - device_id: string
    - created_at: timestamp
    - browser_family: string (extracted from user_agent)
    - fuzzy_hash: string (for debugging/analysis)
```

Search returns top points; aggregate to device_id by max score (or top-N per device).
This handles drift and cross-browser variation better than forcing one canonical device vector.

**Why multi-vector?**

- Device fingerprints evolve over time (browser updates, config changes)
- Cross-browser: same device, Chrome vs Firefox = different fingerprints
- Privacy mode variations
- Single canonical vector would miss these variations

**Retention policy:**

- Keep observations for 30 days (TTL on created_at)
- Max 100 observations per device (prune oldest on insert)
- Monitor storage growth, adjust as traffic patterns emerge

## Integration Architecture

### Chosen approach: Async with cache

**Why not synchronous?**

- Would require matching worker in VPC (adds cost, cold start latency)
- Ties hot path latency to stateful service availability
- Qdrant downtime would degrade all matching, not just vector tier

**Async approach:**

```
Matching Worker                          Vector Worker
    │                                         │
    ├── Tier 0-1.5: DynamoDB               Profile Queue
    │                                         │
    ├── Tier 2: DynamoDB vector cache    ←── Async upsert to QDrant
    │   └── Lookup: fingerprint_hash          + write to vector cache
    │       → device_id candidates
    │
    └── Tier 3-4: DynamoDB
```

**Flow:**

1. Profile updater sends fingerprint to vector queue
2. Vector worker computes embedding, upserts to QDrant
3. Vector worker queries QDrant for similar vectors
4. Vector worker writes top-k candidates to DynamoDB "vector_cache" table
5. Matching worker queries vector_cache (fast DynamoDB lookup)

**Pros:**

- No VPC needed in matching worker
- No added latency in hot path
- Vector results pre-computed and cached
- Graceful degradation if vector service down

**Cons:**

- Results slightly stale (async)
- Extra DynamoDB table
- More complex data flow

## Recommended Implementation: Option B (Async with cache)

### Phase 1: Vector embedding pipeline

1. Add embedding computation to profile-updater
2. Send embedding + device_id to vector queue
3. Vector worker upserts to QDrant collection

### Phase 2: Vector cache table

1. Create DynamoDB table: `vector_cache`

   **Option A: Single-item top-K list (recommended)**

   ```
   PK: v1#<embedding_hash>
   Attributes:
     - candidates: [{ device_id, score, last_seen }]  // top-K list, ~20-100 items
     - updated_at: timestamp
     - ttl: expiration timestamp
   ```

   - Matching worker: single GetItem, no sorting needed
   - Avoids per-candidate item churn
   - Item size ~2-10KB for K=100 (well under 400KB limit)
   - `v1` prefix = embedding_version for model changes without cache poisoning

   **Option B: Per-candidate items with score-ordered SK**

   ```
   PK: v1#<embedding_hash>
   SK: s#<score_inverted>#<device_id>   // e.g., s#0.15#dev_abc (1.0-0.85=0.15)
   Attributes:
     - score: similarity score
     - last_seen: timestamp
     - ttl: expiration
   ```

   - Query returns candidates in score order (highest first)
   - Must strictly cap writes to top-K only
   - Must purge old SKs when updating (otherwise items leak)

2. Vector worker writes top-k similar devices to cache after QDrant operations
3. **Read-through cache behavior:** If matching worker misses cache:
   - Enqueue async vector job for this fingerprint
   - Proceed to Tier 3 (compound buckets)
   - Next request for similar fingerprint will hit cache

### Phase 3: Integrate into matching

1. Add `tier2VectorLookup()` to matching service
2. Compute embedding hash from fingerprint
3. Query vector_cache for candidates
4. Score candidates, return best match if above threshold

## Data Flow Diagram

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Browser   │────▶│  Ingestion  │────▶│  Matching   │
└─────────────┘     │   Lambda    │     │   Queue     │
                    └─────────────┘     └──────┬──────┘
                                               │
┌──────────────────────────────────────────────┼──────────────────────────────────────────────┐
│  ms-argus-api (no VPC)                       ▼                                              │
│                                       ┌─────────────┐                                       │
│                                       │  Matching   │                                       │
│                                       │   Worker    │                                       │
│                                       └──────┬──────┘                                       │
│                                              │                                              │
│  ┌───────────────────────────────────────────┼───────────────────────────────────────────┐  │
│  │ Tier 0-1.5: Fast deterministic lookups    │                                           │  │
│  │    ▼              ▼              ▼        │        ▼                                  │  │
│  │ ┌────────┐  ┌──────────┐  ┌──────────┐    │   ┌──────────┐                            │  │
│  │ │Session │  │ Identity │  │  Hash    │    │   │ Anchors  │                            │  │
│  │ │ Cache  │  │  (0.5)   │  │  (T1)    │    │   │  (1.5)   │                            │  │
│  │ └────────┘  └──────────┘  └──────────┘    │   └──────────┘                            │  │
│  └───────────────────────────────────────────┼───────────────────────────────────────────┘  │
│                                              │                                              │
│  ┌───────────────────────────────────────────┼───────────────────────────────────────────┐  │
│  │ Tier 2: Vector (async cache)              │                                           │  │
│  │                                           ▼                                           │  │
│  │                                    ┌─────────────┐                                    │  │
│  │                                    │Vector Cache │──── miss ────▶ enqueue job        │  │
│  │                                    │   (DDB)     │               proceed to T3       │  │
│  │                                    └─────────────┘                                    │  │
│  └───────────────────────────────────────────┼───────────────────────────────────────────┘  │
│                                              │                                              │
│  ┌───────────────────────────────────────────┼───────────────────────────────────────────┐  │
│  │ Tier 3: Compound buckets (bounded)        ▼                                           │  │
│  │                                    ┌─────────────┐                                    │  │
│  │                                    │  Buckets    │  strict LIMIT, global cap          │  │
│  │                                    │   (DDB)     │                                    │  │
│  │                                    └─────────────┘                                    │  │
│  └───────────────────────────────────────────┼───────────────────────────────────────────┘  │
│                                              │                                              │
│                                              ▼                                              │
│                                       ┌─────────────┐                                       │
│                                       │   Scorer    │  SimHash distance, calibrator        │
│                                       └──────┬──────┘                                       │
│                                              │                                              │
│              ┌───────────────────────────────┴───────────────────────────┐                  │
│              ▼                                                           ▼                  │
│       ┌─────────────┐                                             ┌─────────────┐           │
│       │   Profile   │                                             │   Vector    │           │
│       │   Queue     │                                             │   Queue     │           │
│       └──────┬──────┘                                             └──────┬──────┘           │
│              │                                                           │                  │
│              ▼                                                           │                  │
│       ┌─────────────┐                                                    │                  │
│       │   Profile   │────── sends observation ───────────────────────────┘                  │
│       │   Updater   │                                                                       │
│       └─────────────┘                                                                       │
│                                                                                             │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                               │
┌──────────────────────────────────────────────┼──────────────────────────────────────────────┐
│  ms-argus-vector VPC                         ▼                                              │
│                                       ┌─────────────┐                                       │
│                                       │   Vector    │                                       │
│                                       │   Worker    │                                       │
│                                       └──────┬──────┘                                       │
│                                              │                                              │
│                          ┌───────────────────┴───────────────────┐                          │
│                          ▼                                       ▼                          │
│                   ┌─────────────┐                          ┌─────────────┐                  │
│                   │   QDrant    │                          │   Vector    │                  │
│                   │  (upsert +  │                          │   Cache     │                  │
│                   │   search)   │                          │  (write)    │                  │
│                   └─────────────┘                          └─────────────┘                  │
│                                                                                             │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Implementation Tasks

### Infrastructure

- [ ] Create `vector_cache` DynamoDB table (single-item top-K schema)
- [ ] Add DynamoDB write permissions to vector worker
- [ ] Update vector worker to write to cache after QDrant operations
- [ ] Implement read-through cache miss behavior (enqueue on miss)

### Embedding Service

- [ ] Create `src/services/vector/embedding.ts` - feature extraction
- [ ] Implement 256-dim same-browser drift embedding:
  - [ ] SimHash subvector (64 dims): fuzzy_hash → bipolar bits
  - [ ] Structural subvector (64 dims): 8 structural hashes × 8 dims each
  - [ ] Rendering subvector (64 dims): canvas/audio/webgl hashes
  - [ ] Hardware subvector (32 dims): GPU, screen, cores, memory, timezone
  - [ ] Network subvector (32 dims): JA4, RTT bucket
- [ ] Add embedding computation to profile-updater
- [ ] Extract browser_family from user_agent for payload metadata

### Matching Integration

- [ ] Create `src/services/matching/tier15-anchors.ts`
  - [ ] Session anchor: can short-circuit
  - [ ] IP+UA anchor: produces candidates only, time-gated
- [ ] Create `src/services/matching/tier2-vector.ts`
  - [ ] `tier2VectorLookup()`: query vector_cache
  - [ ] Cache miss: enqueue async job, return null
- [ ] Refactor `tier2-compound.ts` → `tier3-compound.ts`
  - [ ] Add stricter bounds: LIMIT per bucket, global candidate cap
- [ ] Update `runTieredMatching()` flow with new tier order

### Scoring and Calibration

- [ ] Create `src/services/matching/scorer.ts`
  - [ ] Log scoring features: vector_score, score_gap, candidate_count, tier_source
  - [ ] Also log: fuzzy_hash Hamming distance (can compute from stored payload)
  - [ ] Initial: threshold-based (accept if cosine > 0.80)
  - [ ] Future: calibrated model combining vector score + Hamming distance
- [ ] Instrument matching pipeline to log features for tuning

### QDrant Multi-Vector

- [ ] Store points as observations (not devices)
- [ ] Implement device_id aggregation on search results (max score per device)
- [ ] Add observation retention policy (last N or time-bounded)

### Testing

- [ ] Unit tests for embedding computation
- [ ] Unit tests for anchor time-gating logic
- [ ] Integration tests for vector cache flow (hit, miss, read-through)
- [ ] Load tests for latency impact
- [ ] A/B test vector tier vs control (measure recall/precision)

## Confidence Scoring

### Initial placeholder thresholds (will require calibration)

| Tier | Match Type                                | Initial Confidence                 |
| ---- | ----------------------------------------- | ---------------------------------- |
| 0.5  | Identity (public_key, evercookie, sigint) | 0.99                               |
| 1    | Stable hash exact                         | 0.95                               |
| 1    | Fuzzy hash exact                          | 0.85                               |
| 1.5a | Session anchor (valid window)             | 0.80                               |
| 1.5b | IP+UA anchor                              | candidates only, scored downstream |
| 2    | Vector similarity                         | scored by calibrator               |
| 3    | Compound buckets                          | scored by calibrator               |

### Calibration plan (required before production)

**Fixed thresholds will break** when:

- Embedding model changes
- Population grows
- Browser/region mix shifts

**Required approach:**

1. Log features for every match decision:
   - `vector_score`: cosine similarity from QDrant
   - `score_gap`: top1 - top2 score (confidence signal)
   - `fuzzy_hash_distance`: Hamming distance between query and candidate
   - `structural_match_count`: how many structural hashes match exactly
   - `tier_source`: which tier produced the candidate
   - `recency`: time since candidate's last_seen
   - `candidate_count`: how many candidates considered
   - `browser_family_match`: whether candidate is same browser family

2. Fit lightweight calibrator (logistic regression sufficient):
   - Input: feature vector above
   - Output: P(correct match)

3. Choose decision thresholds in probability space:
   - Accept if P > 0.85 (tune per risk tier)
   - Reject if P < 0.50
   - Flag for review if 0.50-0.85

4. Retrain calibrator periodically as population shifts

**This also enables:** principled comparison of Tier 2 vs Tier 3 performance, data-driven deprecation of compound buckets

## Operational Concerns

### Degradation and correctness

| Scenario                     | Behavior                                                  |
| ---------------------------- | --------------------------------------------------------- |
| vector_cache miss            | Enqueue async vector job, proceed to Tier 3               |
| vector pipeline behind (lag) | Monitor lag metric, alert if > N minutes                  |
| QDrant down                  | Stop populating cache, Tier 3 continues as fallback       |
| QDrant slow                  | Timeout on upsert/search, log error, don't block pipeline |

**Key principle:** Vector tier is an optimization, not a correctness requirement. System must function (with degraded recall) when vector infrastructure is unavailable.

### Backfill strategy

Vector Tier 2 requires baseline coverage, otherwise it will be a miss factory initially.

**Plan:**

1. Backfill last N fingerprints per device (or last N days)
2. Throttle backfill rate to avoid destabilizing QDrant
3. Track backfill progress: `devices_backfilled / total_devices`
4. Consider backfilling in batches by device cohort (recent first)

**Expected ramp:**

- Day 1: Tier 2 coverage ~0% (all falls through to Tier 3)
- Week 1: Coverage ramps with ingestion rate
- Backfill complete: Coverage matches device population

### Security and tenancy

**Single-tenant (confirmed):**

- No tenant partitioning needed
- Cache key: `v1#<embedding_hash>` (v1 = embedding version)
- Single QDrant collection for all fingerprints
- Embedding version prefix allows model upgrades without cache poisoning

## Open Questions

1. **Vector cache TTL**: How long to cache vector results?
   - Too short = stale, too long = missed updates
   - Recommend: 1 hour TTL, refresh on profile update

2. **Observation retention in QDrant**: How many observations per device?
   - Store all? Last N? Time-bounded?
   - Recommend: 30 days or last 100 per device, whichever is smaller
   - Adjust based on traffic patterns

3. **Similarity threshold for drift matching**: What cosine similarity = same device?
   - Same browser with minor drift should give ~0.85+
   - Start with 0.80 threshold, tune based on false positive rate
   - May want different thresholds based on fuzzy_hash Hamming distance

## Stakeholder Decisions

1. **Multi-tenant / hard isolation boundaries?**
   - **Decision: Single-tenant** - no tenant partitioning needed
   - Simplifies: cache keys, vector collection, no audit overhead

2. **Fingerprint observations per device (median and p95)?**
   - **Decision: Unknown (early stage)** - design for flexibility
   - Start with time-bounded retention (e.g., last 30 days)
   - Monitor and adjust based on actual traffic patterns

## Timeline Estimate

- Phase 1 (Embedding pipeline + vector queue integration): 3-4 days
- Phase 2 (Vector cache table + read-through logic): 2-3 days
- Phase 3 (Anchor refactor to Tier 1.5): 1-2 days
- Phase 4 (Matching integration + tier renumbering): 3-4 days
- Phase 5 (Scoring instrumentation + SimHash post-scoring): 2-3 days
- Phase 6 (Backfill existing devices): 1-2 days
- Testing & tuning: 3-4 days

**Total: ~2.5-3.5 weeks**

Note: Calibration is ongoing after launch - initial deployment uses placeholder thresholds, calibrator trained on production data.

## References

- [QDrant Documentation](https://qdrant.tech/documentation/)
- [SimHash Paper](https://www.cs.princeton.edu/courses/archive/spring04/cos598B/bib/ChsijuclT.pdf)
- [HNSW Algorithm](https://arxiv.org/abs/1603.09320)
