import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SIMHASH_CONFIG, getSimHashFlags } from "../../helpers/constants";
import {
  buildSimHashBandKeys,
  parseSimHashBandSK,
  type SimHashBandKey,
} from "../../helpers/bucket-keys";
import { hammingDistance, computeFuzzyMatchInfo } from "../../helpers/hash";
import { MatchTier } from "../../types/matching-tiers";
import type { Fingerprint, MatchResult, SimHashDetails } from "./types";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "argus-tier15-simhash",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

export interface SimHashMatchDeps {
  dynamodb: DynamoDBClient;
  tier2BucketsTable: string;
}

interface BandCandidate {
  deviceId: string;
  fuzzyHash: string;
  lastSeen: number;
  bandIndex: number;
}

interface ScoredCandidate {
  deviceId: string;
  fuzzyHash: string;
  lastSeen: number;
  bandMatches: number;
  hammingDistance: number;
}

/**
 * Tier 1.5: SimHash LSH match for same-browser drift detection
 *
 * Architecture:
 * 1. Split incoming fuzzy_hash into 4 bands
 * 2. Query each band in parallel with per-band LIMIT
 * 3. Aggregate candidates appearing in 2+ bands
 * 4. Score by Hamming distance (inline hash - no extra lookup)
 * 5. Apply last_seen recency gate
 * 6. Return best match if within threshold
 *
 * Safeguards:
 * - Per-band LIMIT prevents hot-band explosion
 * - MAX_CANDIDATES caps scoring work
 * - Latency bypass (fail open if slow)
 * - Shadow mode for safe rollout
 * - Percentage rollout for gradual enablement
 */
function isRolloutEnabled(
  fingerprint: Fingerprint,
  flags: ReturnType<typeof getSimHashFlags>,
): boolean {
  if (!flags.ENABLED) return false;
  if (flags.ROLLOUT_PERCENT >= 100) return true;
  const bucket = Math.abs(hashCode(fingerprint.fuzzy_hash || "")) % 100;
  return bucket < flags.ROLLOUT_PERCENT;
}

function findBestCandidate(
  bandResults: BandCandidate[],
  fuzzyHash: string,
  flags: ReturnType<typeof getSimHashFlags>,
): ScoredCandidate | null {
  const candidates = aggregateCandidates(bandResults);
  metrics.addMetric(
    "SimHash.CandidatesPerQuery",
    MetricUnit.Count,
    candidates.size,
  );
  if (candidates.size === 0) return null;

  const scored = scoreCandidates(
    candidates,
    fuzzyHash,
    flags.HAMMING_THRESHOLD,
    flags.MAX_CANDIDATES,
  );
  if (scored.length === 0) return null;

  const best = scored[0];
  const ageInDays = (Math.floor(Date.now() / 1000) - best.lastSeen) / 86400;
  if (
    ageInDays > SIMHASH_CONFIG.RECENCY_WINDOW_DAYS &&
    best.hammingDistance > 1
  ) {
    return null;
  }

  return best;
}

function buildSimHashMatchResult(
  best: ScoredCandidate,
  fingerprint: Fingerprint,
): MatchResult {
  // Compute total bits from hash length (4 bits per hex char)
  const totalBits = fingerprint.fuzzy_hash!.replace(/^0x/i, "").length * 4;

  const simhash_details: SimHashDetails = {
    incoming_hash: fingerprint.fuzzy_hash!,
    matched_hash: best.fuzzyHash,
    hamming_distance: best.hammingDistance,
    similarity: 1 - best.hammingDistance / totalBits,
    bands_matched: best.bandMatches,
  };

  return {
    device_id: best.deviceId,
    confidence: computeConfidence(best.hammingDistance, best.bandMatches),
    match_tier: MatchTier.SIMHASH,
    is_new_device: false,
    risk_score: 0.35,
    flags: [],
    evidence_codes: ["SIMHASH_MATCH"],
    simhash_details,
    fuzzy_match_info: computeFuzzyMatchInfo(
      fingerprint.fuzzy_hash,
      best.fuzzyHash,
    ),
  };
}

/** Returns null in shadow mode (logs the match but doesn't act on it). */
function resolveSimHashMatch(
  best: ScoredCandidate,
  fingerprint: Fingerprint,
  flags: ReturnType<typeof getSimHashFlags>,
): MatchResult | null {
  metrics.addMetric(
    "SimHash.HammingDistance",
    MetricUnit.Count,
    best.hammingDistance,
  );
  metrics.addMetric("SimHash.TierHit", MetricUnit.Count, 1);

  const result = buildSimHashMatchResult(best, fingerprint);

  if (flags.SHADOW_MODE) {
    logger.info("SimHash shadow mode match", {
      deviceId: best.deviceId,
      hammingDistance: best.hammingDistance,
      bandMatches: best.bandMatches,
      confidence: result.confidence,
    });
    metrics.publishStoredMetrics();
    return null;
  }

  metrics.publishStoredMetrics();
  return result;
}

export async function simHashMatch(
  deps: SimHashMatchDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  const flags = getSimHashFlags();
  if (!isRolloutEnabled(fingerprint, flags)) return null;

  const bandKeys = buildSimHashBandKeys(fingerprint.fuzzy_hash);
  if (!bandKeys) return null;

  try {
    const startTime = Date.now();
    const bandResults = await Promise.all(
      bandKeys.map((band) => queryBand(deps, band)),
    );
    const elapsed = Date.now() - startTime;

    if (elapsed > flags.LATENCY_BYPASS_MS) {
      metrics.addMetric("SimHash.LatencyBypass", MetricUnit.Count, 1);
      logger.warn("SimHash latency bypass triggered", { elapsedMs: elapsed });
      metrics.publishStoredMetrics();
      return null;
    }
    metrics.addMetric(
      "SimHash.BandQueryLatencyMs",
      MetricUnit.Milliseconds,
      elapsed,
    );

    const best = findBestCandidate(
      bandResults.flat(),
      fingerprint.fuzzy_hash!,
      flags,
    );
    if (!best) {
      metrics.publishStoredMetrics();
      return null;
    }

    return resolveSimHashMatch(best, fingerprint, flags);
  } catch (error) {
    logger.error("SimHash tier error - failing open", { error });
    metrics.addMetric("SimHash.Error", MetricUnit.Count, 1);
    metrics.publishStoredMetrics();
    return null;
  }
}

async function queryBand(
  deps: SimHashMatchDeps,
  band: SimHashBandKey,
): Promise<BandCandidate[]> {
  const result = await deps.dynamodb.send(
    new QueryCommand({
      TableName: deps.tier2BucketsTable,
      KeyConditionExpression: "bucket_key = :bk",
      ExpressionAttributeValues: {
        ":bk": { S: band.pk },
      },
      ProjectionExpression: "device_id, fuzzy_hash, last_seen",
      // Per-band LIMIT prevents hot-band explosion
      Limit: SIMHASH_CONFIG.PER_BAND_LIMIT,
      // Inverted timestamp SK means ascending order returns newest first
      ScanIndexForward: true,
    }),
  );

  const candidates: BandCandidate[] = [];

  if (result.Items) {
    for (const item of result.Items) {
      const unmarshalled = unmarshall(item);

      const sk = unmarshalled.device_id as string;
      const parsed = parseSimHashBandSK(sk);

      if (parsed && unmarshalled.fuzzy_hash) {
        candidates.push({
          deviceId: parsed.deviceId,
          fuzzyHash: unmarshalled.fuzzy_hash as string,
          lastSeen: unmarshalled.last_seen ?? parsed.timestamp,
          bandIndex: band.bandIndex,
        });
      }
    }
  }

  return candidates;
}

/** Keep only candidates appearing in 2+ bands. */
function aggregateCandidates(
  candidates: BandCandidate[],
): Map<
  string,
  { fuzzyHash: string; lastSeen: number; bandMatches: Set<number> }
> {
  const aggregated = new Map<
    string,
    { fuzzyHash: string; lastSeen: number; bandMatches: Set<number> }
  >();

  for (const c of candidates) {
    const existing = aggregated.get(c.deviceId);
    if (existing) {
      existing.bandMatches.add(c.bandIndex);
      existing.lastSeen = Math.max(existing.lastSeen, c.lastSeen);
    } else {
      aggregated.set(c.deviceId, {
        fuzzyHash: c.fuzzyHash,
        lastSeen: c.lastSeen,
        bandMatches: new Set([c.bandIndex]),
      });
    }
  }

  for (const [deviceId, data] of aggregated) {
    if (data.bandMatches.size < SIMHASH_CONFIG.MIN_BANDS_MATCH) {
      aggregated.delete(deviceId);
    }
  }

  return aggregated;
}

function scoreCandidates(
  candidates: Map<
    string,
    { fuzzyHash: string; lastSeen: number; bandMatches: Set<number> }
  >,
  incomingHash: string,
  threshold: number,
  maxCandidates: number,
): ScoredCandidate[] {
  const scored: ScoredCandidate[] = [];

  for (const [deviceId, data] of candidates) {
    const distance = hammingDistance(incomingHash, data.fuzzyHash);

    if (distance >= 0 && distance <= threshold) {
      scored.push({
        deviceId,
        fuzzyHash: data.fuzzyHash,
        lastSeen: data.lastSeen,
        bandMatches: data.bandMatches.size,
        hammingDistance: distance,
      });
    }
  }

  scored.sort((a, b) => {
    if (a.hammingDistance !== b.hammingDistance) {
      return a.hammingDistance - b.hammingDistance;
    }
    return b.lastSeen - a.lastSeen;
  });

  return scored.slice(0, maxCandidates);
}

/**
 * Compute confidence based on Hamming distance and band match count.
 * Penalty is normalized to hash bit-width so 256-bit and 64-bit hashes
 * produce equivalent confidence for the same proportional distance.
 *
 * At 256-bit: distance 0 → 0.90, distance 4 → 0.85, distance 8 → 0.80
 * At  64-bit: distance 0 → 0.90, distance 1 → 0.85, distance 2 → 0.80
 *
 * Bonus for more band matches (up to +0.04).
 */
function computeConfidence(
  hammingDistance: number,
  bandMatches: number,
): number {
  const penaltyPerBit = 0.05 / (SIMHASH_CONFIG.TOTAL_BITS / 64);
  const baseConfidence = 0.9 - hammingDistance * penaltyPerBit;
  const bandBonus = Math.min((bandMatches - 2) * 0.02, 0.04);
  return Math.max(0.6, Math.min(0.95, baseConfidence + bandBonus));
}

function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return hash;
}
