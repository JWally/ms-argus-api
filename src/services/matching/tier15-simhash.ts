// src/services/matching/tier15-simhash.ts
// AR-XXX: SimHash LSH matching tier for same-browser drift detection
// Uses fuzzy_hash field with locality-sensitive hashing for efficient similarity search

import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SIMHASH_CONFIG, getSimHashFlags } from "../../helpers/constants";
import {
  buildSimHashBandKeys,
  parseSimHashBandSK,
  hammingDistance,
  type SimHashBandKey,
} from "../../helpers/bucket-keys";
import type { Fingerprint, MatchResult, SimHashDetails } from "./types";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "argus-tier15-simhash",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/**
 * Dependencies for Tier 1.5 SimHash operations
 */
export interface Tier15SimHashDeps {
  dynamodb: DynamoDBClient;
  tier2BucketsTable: string;
}

/**
 * Candidate entry from band query with inline hash
 */
interface BandCandidate {
  deviceId: string;
  fuzzyHash: string;
  lastSeen: number;
  bandIndex: number;
}

/**
 * Aggregated candidate with match count and scoring data
 */
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
export async function tier15SimHashMatch(
  deps: Tier15SimHashDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  const flags = getSimHashFlags();
  const startTime = Date.now();

  // Check if SimHash tier is enabled
  if (!flags.ENABLED) {
    return null;
  }

  // Percentage rollout check (deterministic based on session)
  if (flags.ROLLOUT_PERCENT < 100) {
    // Use a hash of fuzzy_hash to determine rollout bucket
    const rolloutBucket =
      Math.abs(hashCode(fingerprint.fuzzy_hash || "")) % 100;
    if (rolloutBucket >= flags.ROLLOUT_PERCENT) {
      return null;
    }
  }

  // Build band keys from fuzzy_hash
  const bandKeys = buildSimHashBandKeys(fingerprint.fuzzy_hash);
  if (!bandKeys) {
    return null;
  }

  try {
    // Query all bands in parallel with per-band LIMIT
    const bandResults = await Promise.all(
      bandKeys.map((band) => queryBand(deps, band)),
    );

    const elapsed = Date.now() - startTime;

    // Check latency bypass
    if (elapsed > flags.LATENCY_BYPASS_MS) {
      metrics.addMetric("SimHash.LatencyBypass", MetricUnit.Count, 1);
      logger.warn("SimHash latency bypass triggered", {
        elapsedMs: elapsed,
        threshold: flags.LATENCY_BYPASS_MS,
      });
      metrics.publishStoredMetrics();
      return null; // Fail open, proceed to next tier
    }

    // Record band query latency
    metrics.addMetric(
      "SimHash.BandQueryLatencyMs",
      MetricUnit.Milliseconds,
      elapsed,
    );

    // Aggregate candidates appearing in 2+ bands
    const candidates = aggregateCandidates(bandResults.flat());
    metrics.addMetric(
      "SimHash.CandidatesPerQuery",
      MetricUnit.Count,
      candidates.size,
    );

    if (candidates.size === 0) {
      metrics.publishStoredMetrics();
      return null;
    }

    // Score candidates by Hamming distance
    const scored = scoreCandidates(
      candidates,
      fingerprint.fuzzy_hash!,
      flags.HAMMING_THRESHOLD,
      flags.MAX_CANDIDATES,
    );

    if (scored.length === 0) {
      metrics.publishStoredMetrics();
      return null;
    }

    // Find best match (lowest Hamming distance)
    const best = scored[0];

    // Apply last_seen recency gate
    // Require tighter Hamming threshold for older devices
    const nowSeconds = Math.floor(Date.now() / 1000);
    const ageInDays = (nowSeconds - best.lastSeen) / 86400;

    if (
      ageInDays > SIMHASH_CONFIG.RECENCY_WINDOW_DAYS &&
      best.hammingDistance > 1
    ) {
      // Device too old for loose match - require near-exact match
      logger.debug(
        "SimHash match rejected: device too old for Hamming distance",
        {
          deviceId: best.deviceId,
          ageInDays,
          hammingDistance: best.hammingDistance,
        },
      );
      metrics.publishStoredMetrics();
      return null;
    }

    // Record match quality
    metrics.addMetric(
      "SimHash.HammingDistance",
      MetricUnit.Count,
      best.hammingDistance,
    );
    metrics.addMetric("SimHash.TierHit", MetricUnit.Count, 1);

    // Build SimHash details for API response
    const simhash_details: SimHashDetails = {
      incoming_hash: fingerprint.fuzzy_hash!,
      matched_hash: best.fuzzyHash,
      hamming_distance: best.hammingDistance,
      similarity: 1 - best.hammingDistance / 64,
      bands_matched: best.bandMatches,
    };

    // Build result
    const result: MatchResult = {
      device_id: best.deviceId,
      confidence: computeConfidence(best.hammingDistance, best.bandMatches),
      match_tier: 1.5,
      is_new_device: false,
      risk_score: 0.35, // Slightly lower than exact match
      flags: [],
      evidence_codes: ["SIMHASH_MATCH"],
      simhash_details,
    };

    // Shadow mode: log but don't return
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
  } catch (error) {
    // Fail open - log and proceed to next tier
    logger.error("SimHash tier error - failing open", { error });
    metrics.addMetric("SimHash.Error", MetricUnit.Count, 1);
    metrics.publishStoredMetrics();
    return null;
  }
}

/**
 * Query a single band partition with LIMIT
 */
async function queryBand(
  deps: Tier15SimHashDeps,
  band: SimHashBandKey,
): Promise<BandCandidate[]> {
  const result = await deps.dynamodb.send(
    new QueryCommand({
      TableName: deps.tier2BucketsTable,
      KeyConditionExpression: "bucket_key = :bk",
      ExpressionAttributeValues: {
        ":bk": { S: band.pk },
      },
      // Project only what we need: SK (has device_id + timestamp), fuzzy_hash, last_seen
      ProjectionExpression: "device_id, fuzzy_hash, last_seen",
      // Per-band LIMIT - critical for preventing hot-band explosion
      Limit: SIMHASH_CONFIG.PER_BAND_LIMIT,
      // ScanIndexForward: true means ascending SK order
      // With inverted timestamp SK, this returns newest first
      ScanIndexForward: true,
    }),
  );

  const candidates: BandCandidate[] = [];

  if (result.Items) {
    for (const item of result.Items) {
      const unmarshalled = unmarshall(item);

      // Parse SK to get device_id and timestamp
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

/**
 * Aggregate candidates, keeping only those appearing in 2+ bands
 */
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
      // Keep most recent last_seen
      existing.lastSeen = Math.max(existing.lastSeen, c.lastSeen);
    } else {
      aggregated.set(c.deviceId, {
        fuzzyHash: c.fuzzyHash,
        lastSeen: c.lastSeen,
        bandMatches: new Set([c.bandIndex]),
      });
    }
  }

  // Filter to candidates with 2+ band matches
  for (const [deviceId, data] of aggregated) {
    if (data.bandMatches.size < SIMHASH_CONFIG.MIN_BANDS_MATCH) {
      aggregated.delete(deviceId);
    }
  }

  return aggregated;
}

/**
 * Score candidates by Hamming distance, filter by threshold, sort best first
 */
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

  // Sort by Hamming distance (lower is better), then by recency (newer is better)
  scored.sort((a, b) => {
    if (a.hammingDistance !== b.hammingDistance) {
      return a.hammingDistance - b.hammingDistance;
    }
    return b.lastSeen - a.lastSeen;
  });

  // Cap candidates
  return scored.slice(0, maxCandidates);
}

/**
 * Compute confidence based on Hamming distance and band match count
 * - Distance 0: 0.90 confidence
 * - Distance 1: 0.85 confidence
 * - Distance 2: 0.80 confidence
 * - Distance 3: 0.75 confidence
 * - Distance 4: 0.70 confidence
 * Bonus for more band matches
 */
function computeConfidence(
  hammingDistance: number,
  bandMatches: number,
): number {
  const baseConfidence = 0.9 - hammingDistance * 0.05;
  const bandBonus = Math.min((bandMatches - 2) * 0.02, 0.04); // Max 4% bonus for 4 bands
  return Math.max(0.6, Math.min(0.95, baseConfidence + bandBonus));
}

/**
 * Simple hash code for rollout bucketing
 */
function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return hash;
}
