# Device Matching Rationale

## Overview

This document explains the rationale behind the tiered matching strategy used in Argus for device fingerprint identification. Each tier represents a different trade-off between confidence, coverage, and computational cost.

## Matching Tier Hierarchy

```
┌─────────────────────────────────────────────────────────────────────┐
│ Tier 0.5: Identity Match (confidence: 0.99)                         │
│ ├─ evercookie_id - Super-persistent cookie (EVERCOOKIE_MATCH)       │
│ ├─ public_key - ECDSA P-256 crypto identity (PUBLIC_KEY_MATCH)      │
│ └─ sigint_id - Third-party cookie from edge (SIGINT_ID_MATCH)       │
├─────────────────────────────────────────────────────────────────────┤
│ Tier 1: Hash Match (confidence: 0.85-0.95)                          │
│ ├─ stable_hash - Hardware fingerprint (conf: 0.95)                  │
│ └─ fuzzy_hash - Locality-sensitive hash (conf: 0.85)                │
├─────────────────────────────────────────────────────────────────────┤
│ Tier 2: Compound Bucket Match (confidence: 0.60-0.85)               │
│ ├─ ip_address + ja4 - Network fingerprint                          │
│ ├─ gpu_renderer + screen_dims + timezone - Environment             │
│ └─ audio_hash + canvas_hash - Rendering fingerprint                │
├─────────────────────────────────────────────────────────────────────┤
│ Tier 3: New Device (confidence: 0.00)                               │
│ └─ No match found - create new device_id                            │
└─────────────────────────────────────────────────────────────────────┘
```

## Signal Selection Rationale

### Tier 0.5: Identity Signals

Tier 0.5 uses persistent identity signals that provide near-certain device identification.

#### Evercookie

**Signal**: `evercookie_id`

**Rationale**: Evercookies (super-cookies) are extremely difficult to clear because they're stored across multiple storage mechanisms (localStorage, IndexedDB, cookies, ETags, etc.). When present, they provide the highest confidence match.

| Metric         | Value     | Notes                                              |
| -------------- | --------- | -------------------------------------------------- |
| Confidence     | 0.99      | Near-certain identification                        |
| Stability      | Very High | Survives browser restarts, some survives incognito |
| Collision Rate | ~0%       | UUIDs are unique per device                        |
| Privacy Impact | Low       | Blocks: Brave (partial), Tor (full)                |

**Why 0.99 confidence**: Evercookies are intentionally persistent and unique. False positives are essentially impossible since each evercookie_id is a generated UUID tied to a specific device visit.

#### Public Key (AR-64)

**Signal**: `public_key` (ECDSA P-256, Base64 SPKI format)

**Rationale**: Cryptographic device identity generated client-side using Web Crypto API. The private key is stored in IndexedDB and never leaves the device. The public key serves as a verifiable identity anchor.

| Metric         | Value     | Notes                                               |
| -------------- | --------- | --------------------------------------------------- |
| Confidence     | 0.99      | Cryptographically unique                            |
| Stability      | Very High | Survives until IndexedDB cleared or browser profile |
| Collision Rate | ~0%       | P-256 curve provides 128-bit security               |
| Privacy Impact | Medium    | Blocks: Tor (no IndexedDB), strict privacy browsers |

**Why 0.99 confidence**: Each public key is cryptographically unique. The only false positive scenario would require key extraction from the device, which is practically impossible.

#### Sigint ID (AR-81)

**Signal**: `sigint_id` (third-party cookie from CloudFront edge)

**Rationale**: Third-party cookie set at the edge layer, providing a server-controlled identity signal. More persistent than first-party cookies in some browsers.

| Metric         | Value | Notes                                       |
| -------------- | ----- | ------------------------------------------- |
| Confidence     | 0.99  | Server-controlled unique identifier         |
| Stability      | High  | Third-party cookie policies vary by browser |
| Collision Rate | ~0%   | UUID generated server-side                  |
| Privacy Impact | High  | Blocks: Safari ITP, Firefox ETP, Brave      |

**Why 0.99 confidence**: Server-generated UUIDs are unique. Cross-device tracking is the intended behavior for fraud detection.

### Tier 1: Strong Hash Match

#### Stable Hash

**Signal**: `stable_hash` (computed from hardware signals)

**Inputs typically include**:

- Hardware concurrency (CPU cores)
- Device memory
- WebGL renderer/vendor
- Screen properties
- Platform/OS

**Rationale**: Hardware signals are extremely stable over time. The same device will produce the same stable_hash unless hardware is upgraded or replaced.

| Metric         | Value  | Notes                                        |
| -------------- | ------ | -------------------------------------------- |
| Confidence     | 0.95   | High certainty                               |
| Stability      | High   | Changes only with hardware upgrades          |
| Collision Rate | 1-3%   | Varies by segment (corporate laptops higher) |
| Privacy Impact | Medium | Blocks: Brave (randomized), Firefox RFP      |

**Why 0.95 confidence**: Hardware signals are stable but not unique. Corporate environments often have identical hardware configurations, leading to potential collisions. The 5% uncertainty accounts for:

- Identical hardware in corporate/school environments
- VM environments with cloned configurations
- Hardware configuration changes (RAM upgrade, driver update)

#### Fuzzy Hash

**Signal**: `fuzzy_hash` (locality-sensitive hash)

**Rationale**: Fuzzy hashing (e.g., SimHash, MinHash) allows matching devices even when some signals have drifted. Useful for matching returning users whose browser or environment has changed slightly.

| Metric         | Value    | Notes                              |
| -------------- | -------- | ---------------------------------- |
| Confidence     | 0.85     | Moderate-high certainty            |
| Stability      | Moderate | Tolerates 10-20% signal drift      |
| Collision Rate | 3-5%     | Higher due to similarity tolerance |
| Privacy Impact | Medium   | Same as stable_hash                |

**Why 0.85 confidence**: The fuzzy matching intentionally accepts similar (not identical) fingerprints, increasing collision risk. The 15% uncertainty accounts for:

- False positives from similar devices
- Drift tolerance accepting different devices
- Lower precision than exact matching

### Tier 2: Compound Bucket Match

Tier 2 uses an adjacency-list pattern where multiple weak signals are combined into "buckets". A device must appear in 2+ buckets to be considered a match.

#### IP + JA4 Bucket

**Signals**: `ip_address`, `ja4`

**Rationale**: JA4 is a TLS fingerprint that captures browser/OS characteristics. Combined with IP, it narrows down to a small cohort of devices sharing the same network location and browser configuration.

| Metric                  | Value            | Notes                                        |
| ----------------------- | ---------------- | -------------------------------------------- |
| Confidence Contribution | +0.60 per match  | Base contribution                            |
| Stability               | Low-Medium       | IP changes frequently, JA4 with updates      |
| Collision Rate          | 5-10% per bucket | Higher on mobile/corporate networks          |
| Privacy Impact          | Low              | VPN users will share IP, JA4 harder to spoof |

**Why this combination**: IP alone has high collision (shared networks). JA4 alone has moderate collision (many users with same browser). Together, they provide reasonable specificity.

#### GPU + Screen + Timezone Bucket

**Signals**: `gpu_renderer`, `screen_dims`, `timezone`

**Rationale**: This combination captures the device's display environment. GPU renderer is highly specific (includes driver version), screen dimensions and timezone add geographic/hardware context.

| Metric                  | Value           | Notes                                   |
| ----------------------- | --------------- | --------------------------------------- |
| Confidence Contribution | +0.60 per match | Base contribution                       |
| Stability               | Medium          | GPU driver updates change renderer      |
| Collision Rate          | 2-5%            | Lower due to GPU specificity            |
| Privacy Impact          | High            | Blocks: Firefox RFP, Brave (randomized) |

**Why this combination**: GPU renderer alone is extremely specific but changes with driver updates. Screen dims alone has high collision. Timezone alone is too broad. Combined, they identify a specific device setup.

#### Audio + Canvas Bucket

**Signals**: `audio_hash`, `canvas_hash`

**Rationale**: Audio and canvas fingerprinting capture subtle rendering differences in the browser's audio/graphics stack. These are highly unique but also heavily targeted by privacy tools.

| Metric                  | Value           | Notes                                   |
| ----------------------- | --------------- | --------------------------------------- |
| Confidence Contribution | +0.60 per match | Base contribution                       |
| Stability               | High            | Rarely changes unless browser update    |
| Collision Rate          | <1%             | Highly unique                           |
| Privacy Impact          | Very High       | Blocks: Brave, Firefox, Safari ITP, Tor |

**Why this combination**: Both signals are highly unique individually. Combined, collision risk approaches zero. However, privacy browsers actively block or randomize these, making coverage limited.

### Tier 2 Confidence Calculation

```
base_confidence = 0.6 + (bucket_matches - 2) * 0.1
max_confidence = 0.85
final_confidence = min(base_confidence, max_confidence) - cardinality_penalty
```

**Cardinality Penalty**: When a bucket has >500 devices, confidence is penalized to account for high-traffic scenarios (e.g., corporate NAT, popular ISP).

```
penalty = (high_cardinality_buckets / total_buckets) * 0.30
```

## Privacy Browser Impact

| Browser/Mode     | Evercookie | Stable Hash | Fuzzy Hash | IP+JA4 | GPU+Screen+TZ | Audio+Canvas |
| ---------------- | ---------- | ----------- | ---------- | ------ | ------------- | ------------ |
| Chrome Standard  | ✅         | ✅          | ✅         | ✅     | ✅            | ✅           |
| Firefox Standard | ✅         | ✅          | ✅         | ✅     | ✅            | ✅           |
| Safari (ITP)     | ⚠️         | ✅          | ✅         | ✅     | ✅            | ❌           |
| Brave (Standard) | ⚠️         | ⚠️          | ⚠️         | ✅     | ⚠️            | ⚠️           |
| Firefox (RFP)    | ❌         | ❌          | ❌         | ✅     | ❌            | ❌           |
| Brave (Strict)   | ❌         | ❌          | ❌         | ⚠️     | ❌            | ❌           |
| Tor Browser      | ❌         | ❌          | ❌         | ⚠️     | ❌            | ❌           |

Legend: ✅ Works | ⚠️ Degraded/Randomized | ❌ Blocked

## Stability Analysis

### How often do signals change for the same device?

| Signal          | Typical Stability | Change Triggers                               |
| --------------- | ----------------- | --------------------------------------------- |
| `evercookie_id` | Months-Years      | Manual clear, incognito, new browser profile  |
| `stable_hash`   | Months-Years      | Hardware upgrade, driver update, OS reinstall |
| `fuzzy_hash`    | Weeks-Months      | Browser updates, minor config changes         |
| `ip_address`    | Minutes-Days      | Network change, DHCP renewal, VPN toggle      |
| `ja4`           | Weeks-Months      | Browser updates, TLS config changes           |
| `gpu_renderer`  | Months-Years      | Driver updates (changes version string)       |
| `screen_dims`   | Days-Months       | External monitor connect, DPI scaling change  |
| `timezone`      | Days-Months       | Travel, system config change                  |
| `audio_hash`    | Months-Years      | Browser update, audio driver update           |
| `canvas_hash`   | Months-Years      | Browser update, graphics driver update        |

## Collision Rate Analysis

### How often do different devices share the same value?

| Signal/Bucket          | Estimated Collision Rate | Factors                       |
| ---------------------- | ------------------------ | ----------------------------- |
| `evercookie_id`        | ~0%                      | UUID per device               |
| `stable_hash`          | 1-3%                     | Corporate/school environments |
| `fuzzy_hash`           | 3-5%                     | Intentional tolerance         |
| IP+JA4 bucket          | 5-10%                    | NAT, corporate proxy          |
| GPU+Screen+TZ bucket   | 2-5%                     | Popular configs               |
| Audio+Canvas bucket    | <1%                      | Highly unique                 |
| 2+ bucket intersection | <0.5%                    | Statistical improbability     |

## Confidence Score Recommendations

### Current Configuration

| Tier             | Confidence    | Rationale                                                       |
| ---------------- | ------------- | --------------------------------------------------------------- |
| 0.5 (evercookie) | 0.99          | Near-certain, consider 1.0                                      |
| 1 (stable_hash)  | 0.95          | Good balance, could raise to 0.97 in low-collision environments |
| 1 (fuzzy_hash)   | 0.85          | Appropriate for similarity matching                             |
| 2 (2 buckets)    | 0.60-0.80     | Conservative for weak signals                                   |
| 2 (3 buckets)    | 0.85 (capped) | Ceiling prevents over-confidence                                |

### Tuning Recommendations

1. **Raise evercookie confidence to 1.0**: No false positive scenario exists for valid evercookies. The 0.99 is overly conservative.

2. **Consider environment-specific stable_hash confidence**:
   - Consumer traffic: Raise to 0.97
   - Enterprise/B2B: Keep at 0.95 (higher collision risk)

3. **Lower Tier 2 cap in high-cardinality scenarios**: If average bucket cardinality exceeds 500, consider lowering the confidence cap from 0.85 to 0.75.

4. **Add signal quality flags**: Track when signals are likely randomized (e.g., Brave's audio randomization) and downweight those buckets.

## Tier-Gated Identity Association (AR-149/AR-150)

### Problem: Viral Spreading of Device IDs

When a device matches via a low-confidence Tier 2 bucket (e.g., IP+JA4), creating identity associations (pubkey#, evercookie#, sigint#) can cause "viral spreading":

1. User A visits site, matches via IP+JA4 bucket → gets device_id_123
2. User A's crypto-id is associated with device_id_123
3. User B (different person, same IP+JA4) visits → matches device_id_123 via IP+JA4
4. User B's crypto-id is now associated with device_id_123
5. User B later visits from different IP → matches via crypto-id → still gets device_id_123

This causes unrelated users to share device IDs, polluting the identity graph.

### Solution: Tier-Gated Index Writing

Identity indexes are only written for high-confidence matches:

| Evidence Code         | Creates Identity Indexes? | Rationale                          |
| --------------------- | ------------------------- | ---------------------------------- |
| PUBLIC_KEY_MATCH      | ✅ Yes                    | Cryptographic identity (Tier 0.5)  |
| EVERCOOKIE_MATCH      | ✅ Yes                    | Persistent storage (Tier 0.5)      |
| SIGINT_ID_MATCH       | ✅ Yes                    | Server cookie (Tier 0.5)           |
| STABLE_HASH_MATCH     | ✅ Yes                    | Hardware fingerprint (Tier 1)      |
| FUZZY_HASH_MATCH      | ✅ Yes                    | Similar fingerprint (Tier 1)       |
| SESSION_ANCHOR_BUCKET | ✅ Yes                    | Time-bounded (10 min TTL)          |
| IP_UA_ANCHOR_BUCKET   | ✅ Yes                    | Time-bounded (3 min TTL)           |
| NEW_DEVICE            | ✅ Yes                    | First time - must create indexes   |
| IP_JA4_BUCKET         | ❌ No                     | Unbounded, high collision risk     |
| GPU_SCREEN_TZ_BUCKET  | ❌ No                     | Unbounded, moderate collision risk |
| AUDIO_CANVAS_BUCKET   | ❌ No                     | Unbounded, can be spoofed together |
| MATHS_WINDOW_BUCKET   | ❌ No                     | Unbounded                          |
| HTML_CSS_BUCKET       | ❌ No                     | Unbounded                          |
| WEBGL_STRUCT_BUCKET   | ❌ No                     | Unbounded                          |

**Hash indexes** (stable#, fuzzy#) are always written regardless of match tier, enabling future fingerprint-based lookups.

### Implementation

```typescript
// In profile-service.ts
const shouldWriteIdentity =
  !evidenceCodes ||
  evidenceCodes.length === 0 ||
  evidenceCodes.some((code) => ASSOCIATION_ALLOWED_EVIDENCE.includes(code));

// Identity indexes: pubkey#, evercookie#, sigint#
const identityEntries = shouldWriteIdentity
  ? buildIdentityIndexEntries(deviceId, fingerprint, ttl)
  : [];

// Hash indexes: stable#, fuzzy# - always written
const hashEntries = buildHashIndexEntries(deviceId, fingerprint, ttl);
```

## Future Improvements

1. **Tier 3: Vector Similarity** - Use ML embeddings for soft matching when hash lookups fail
2. **Signal Quality Scoring** - Weight signals based on detected browser/privacy mode
3. **Temporal Decay** - Reduce confidence for stale matches (>30 days since last seen)
4. **Behavioral Signals** - Mouse movement patterns, typing cadence for additional confirmation

## References

- [FingerprintJS Research](https://fingerprintjs.com/blog/) - Industry analysis of fingerprinting techniques
- [JA4 Fingerprinting](https://blog.foxio.io/ja4-fingerprints) - TLS fingerprint methodology
- [EFF Panopticlick](https://panopticlick.eff.org/) - Browser uniqueness research
- [Brave Fingerprinting Protection](https://brave.com/privacy-features/) - Privacy browser mitigations
