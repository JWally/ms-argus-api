# Device Matching Pipeline

## How does matching work at a high level?

Every incoming fingerprint runs through a tiered waterfall. The system tries the fastest and most confident match first. If that misses, it falls through to the next tier. The first tier to produce a match wins.

```
Fingerprint arrives
       |
  [Tier 0.5]  Identity lookup (DynamoDB)
       |  miss
  [Tier 1]    Stable hash exact match (PostgreSQL)   ──┐
       |  miss                                         ├── single SQL query
  [Tier 1.5]  SimHash LSH fuzzy match (PostgreSQL)   ──┘
       |  miss
  [Tier 2]    Vector similarity search (Qdrant)
       |  miss or timeout
  [Anchors]   Session / IP+UA bucket lookup (DynamoDB)
       |  miss
  [New Device] Assign a new device_id
```

---

## Tier 0.5 -- What are identity lookups?

If the fingerprint contains a **public key**, **evercookie ID**, or **sigint ID**, we do a direct DynamoDB `GetItem` against an identity index table. These are keyed like `pubkey#<value>`, `evercookie#<value>`, `sigint#<value>`.

If found, the match is returned immediately with 0.98--0.99 confidence. This is the fastest path and the highest confidence because it's a deterministic identifier, not a probabilistic fingerprint.

---

## Tier 1 -- What is the stable hash match?

The `stable_hash` is a SHA-256 of a curated set of browser signals that rarely change (hardware, core rendering features, etc.). We do an exact-match lookup in the `device_hashes` PostgreSQL table.

If the hash matches, that's a Tier 1 hit with 0.95 confidence and evidence code `STABLE_HASH_MATCH`. Simple and fast -- a single indexed column lookup.

---

## Tier 1.5 -- What is the SimHash LSH match?

This is where it gets interesting. The `fuzzy_hash` is a 256-bit SimHash -- a locality-sensitive hash where **similar inputs produce similar outputs**. Two fingerprints that differ slightly will have a small Hamming distance between their SimHashes, unlike SHA-256 where a single bit flip produces a completely different hash.

### How does the band lookup work?

We split the 256-bit hash into **16 bands of 16 bits each** and store each band in its own column (`band_0` through `band_15`) in the `device_hashes` table. The SQL query checks all 16 bands simultaneously:

```sql
(CASE WHEN band_0  = $2::BIT(16)  THEN 1 ELSE 0 END +
 CASE WHEN band_1  = $3::BIT(16)  THEN 1 ELSE 0 END +
 ...
 CASE WHEN band_15 = $17::BIT(16) THEN 1 ELSE 0 END) AS band_matches
```

The `WHERE` clause filters to rows where **at least 2 bands match** (the `MIN_BANDS_MATCH` threshold). This is the LSH trick: instead of computing Hamming distance against every row (expensive), we use band equality as a cheap filter to find _candidates_ that are likely to be similar.

Results come back sorted by `exact_match DESC`, then `band_matches DESC`, then `last_seen DESC`, capped at 100 rows.

### What happens after the SQL query?

Hamming distance is too expensive to compute in SQL across every row, but on a result set of ~100 candidates it's trivial in application code. We iterate through the candidates and compute the actual Hamming distance between the incoming `fuzzy_hash` and each candidate's stored hash.

A candidate is valid if:

- Hamming distance <= **16 bits** (out of 256), meaning >= 93.75% similarity
- If the record is older than **30 days**, the Hamming distance must be <= 1 bit (tighter threshold for stale records)

The best candidate (lowest Hamming distance) wins.

### How is confidence scored for SimHash matches?

```
baseConfidence = 0.9 - (hammingDistance * 0.0125)
bandBonus      = min((bandMatches - 2) * 0.02, 0.04)
confidence     = clamp(baseConfidence + bandBonus, 0.6, 0.95)
```

A perfect 0-bit Hamming distance with lots of band matches gets you 0.94. A 16-bit distance with minimal bands gets 0.6. The band bonus rewards candidates that matched on more bands, since that's independent evidence of similarity.

---

## Tier 1 + 1.5 are a single query?

Yes. The stable hash lookup and the SimHash band lookup happen in **one SQL query**. The query returns both exact stable hash matches and SimHash candidates, ordered so exact matches sort first. The application checks for a stable hash hit first; if none, it scores the SimHash candidates.

This avoids a round-trip: no need to do a stable hash lookup, wait, then conditionally fire a SimHash query.

---

## Tier 2 -- What is the vector similarity search?

If T1 and T1.5 both miss, we fall through to Qdrant -- a vector similarity database.

### What is the embedding?

The fingerprint is converted into a **256-dimensional vector** that encodes the full fingerprint across several signal categories:

| Dims     | Category   | What's encoded                                                                      |
| -------- | ---------- | ----------------------------------------------------------------------------------- |
| 0--47    | Structural | HTML elements, math features, fonts, window properties, CSS, SVG, Intl hashes       |
| 48--95   | Rendering  | Canvas, WebGL, audio, client rects, GPU renderer                                    |
| 96--109  | Hardware   | CPU cores, memory, WebGL extensions, screen dimensions, user agent                  |
| 110--155 | Network    | JA3/JA4 TLS fingerprint, IPv4 (subnet-preserving), ASN, HTTP/2 settings, TCP tuning |
| 156--177 | Behavioral | Timezone, private browsing flags, headless detection, feature hash                  |
| 178--253 | Identity   | 76 dims from the fuzzy_hash SimHash (30% of the 256-bit hash)                       |
| 254--255 | Reserved   | Future expansion                                                                    |

Key design choices:

- **SimHash variants preferred** over SHA-256 for hash-to-vector conversion, because SimHash preserves locality (similar hashes -> nearby vectors)
- **Rendering dims zeroed for privacy browsers** (Brave, private mode) since canvas/audio/WebGL are randomized
- **IPv4 encoding preserves subnet structure** -- two IPs on the same /24 share 7 of 8 dimensions
- **ASN encoding** includes log-normalization and RIR geographic grouping

### How does the search work?

1. Compute the 256-dim embedding from the fingerprint
2. Invoke the vector-worker Lambda synchronously with a search request
3. Qdrant returns the top 5 results above a **0.7 similarity threshold**
4. The best match (highest score) is used

### How is vector confidence scored?

The 0.7--1.0 similarity score maps linearly to 0.5--0.95 confidence:

```
confidence = 0.5 + ((score - 0.7) / 0.3) * 0.45
```

A score >= 0.9 also adds a `HIGH_SIMILARITY` evidence code.

### What about IP history?

After finding a vector match, we load the matched device's profile and check whether the incoming IP and ASN have been seen before on that device. This context (known IP, known ASN, unique IP count) is included in the match result and can adjust confidence.

### What if the vector search is slow?

The entire vector search runs with a **5-second timeout**. If it doesn't respond in time, the system **fails open** -- it returns `null` and falls through to anchors. The vector tier is designed to be non-blocking.

---

## What are session and IP+UA anchors?

These are short-lived DynamoDB entries for same-session matching:

- **Session anchor** (10-minute validity, 0.65 confidence): Keyed by a combination of session signals (IP, TLS fingerprint, platform). Catches the same user revisiting within a session.
- **IP+UA anchor** (3-minute validity, 0.6 confidence): Keyed by just IP + User-Agent. Lower specificity fallback for robotic or VPN traffic.

If both miss, the fingerprint is classified as a **new device** and assigned a fresh `device_id`.

---

## How does the data get populated?

### When does a write happen?

After every match (or new device assignment), the matching worker queues a **profile update message** to SQS. The profile-updater Lambda picks it up and orchestrates several writes:

### Mutation gate

Before writing anything, the system tries to acquire a **mutation gate** -- an atomic DynamoDB lock per device. If the device was recently updated (within the configured TTL), the write is skipped entirely. This prevents write amplification from rapid-fire requests for the same device.

### Drift detection

If the device already has a profile, the system checks whether the new fingerprint has **significant drift** from the stored one. If nothing meaningful changed, it skips the profile write but still refreshes the hash indexes and anchors (to keep TTLs fresh).

### What gets written?

1. **Device profile** (DynamoDB) -- The canonical device record: all fingerprint fields, first/last seen timestamps, request count, risk score, flags, IP history.

2. **Identity indexes** (DynamoDB) -- `pubkey#`, `evercookie#`, `sigint#` entries pointing to the device_id. Only written when the match confidence is high enough (high-confidence match or new device). These are what Tier 0.5 reads.

3. **Device hashes** (PostgreSQL) -- `stable_hash`, `fuzzy_hash` (as BIT(256)), and all 16 band columns (as BIT(16) each). Upserted on every non-gated write to keep the `last_seen` timestamp and `expires_at` fresh. These are what Tier 1 and Tier 1.5 read.

4. **Anchor buckets** (DynamoDB) -- Session anchor and IP+UA anchor entries with short TTLs. Always refreshed regardless of drift.

5. **Vector upsert** (async via SQS -> Qdrant) -- If the vector infrastructure is configured, the profile-updater computes an embedding and queues a vector upsert message. The vector-worker Lambda picks it up and upserts the point into Qdrant. There's a **quality gate**: if the fingerprint doesn't have enough structural (2+), rendering (1+), and hardware (2+) signals, the upsert is skipped to prevent sparse fingerprints from polluting the vector index.

### Data lifecycle

- **Profiles**: TTL in days (configurable), DynamoDB TTL auto-deletes
- **Identity indexes**: Same TTL as profiles
- **Device hashes**: Explicit `expires_at` column, query filters `WHERE expires_at > NOW()`
- **Anchor buckets**: 1-hour TTL (DynamoDB TTL)
- **Vectors**: Persist in Qdrant until the collection is rotated

---

## Summary of thresholds

| Tier   | Method                          | Confidence | Key threshold                                       |
| ------ | ------------------------------- | ---------- | --------------------------------------------------- |
| 0.5    | Identity (pubkey/cookie/sigint) | 0.98--0.99 | Exact DynamoDB key match                            |
| 1      | Stable hash                     | 0.95       | Exact PostgreSQL match                              |
| 1.5    | SimHash LSH                     | 0.60--0.95 | Hamming distance <= 16/256 bits (93.75% similarity) |
| 2      | Vector similarity               | 0.50--0.95 | Qdrant score >= 0.7, 5s timeout                     |
| Anchor | Session bucket                  | 0.65       | 10-minute validity window                           |
| Anchor | IP+UA bucket                    | 0.60       | 3-minute validity window                            |
| --     | New device                      | 0          | No match found                                      |
