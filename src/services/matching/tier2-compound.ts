// src/services/matching/tier2-compound.ts
// AR-119: Extracted from matching-service.ts - Compound bucket matching (Tier 2)
// AR-153: Added structured logging and metrics for cardinality fetch failures
// AR-157: Moved loadProfile to shared profile-loader module
import {
  DynamoDBClient,
  QueryCommand,
  QueryCommandOutput,
  BatchGetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
// AR-157: Import for local use and re-export from shared module
import { loadProfile } from "./profile-loader";
export { loadProfile, type ProfileData } from "./profile-loader";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  TIER2_BUCKET_LIMIT,
  TIER2_HIGH_CARDINALITY_THRESHOLD,
  TIER2_CARDINALITY_PENALTY,
  TIER2_STATS_SK,
} from "../../helpers/constants";
import { buildBucketKeysWithTypes as buildBucketKeysWithTypesHelper } from "../../helpers/bucket-keys";
import { EvidenceCode, Fingerprint, MatchResult } from "./types";
import { computeFuzzyMatchInfo } from "../../helpers/hash";

// AR-153: Structured logging for visibility into cardinality fetch failures
const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "argus-tier2-compound",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/**
 * Dependencies for tier 2 compound operations
 */
export interface Tier2CompoundDeps {
  dynamodb: DynamoDBClient;
  tier2BucketsTable: string;
  profilesTable: string;
  tier2TimeoutMs: number;
}

/**
 * Tier 2: Compound filter match with timeout protection
 * Returns result with timedOut flag to track "fail open" scenarios
 * Uses AbortController to cancel in-flight DynamoDB requests on timeout
 */
export async function tier2CompoundMatchWithTimeout(
  deps: Tier2CompoundDeps,
  fingerprint: Fingerprint,
): Promise<{ result: MatchResult | null; timedOut: boolean }> {
  const timeoutMs = deps.tier2TimeoutMs;
  const abortController = new AbortController();

  // Use a sentinel to distinguish timeout from null result
  const TIMEOUT_SENTINEL = Symbol("timeout");

  const raceResult = await Promise.race([
    tier2CompoundMatch(deps, fingerprint, {
      abortSignal: abortController.signal,
    }).then((r) => ({
      value: r,
      timedOut: false,
    })),
    new Promise<{ value: typeof TIMEOUT_SENTINEL; timedOut: true }>((resolve) =>
      setTimeout(() => {
        abortController.abort();
        resolve({ value: TIMEOUT_SENTINEL, timedOut: true });
      }, timeoutMs),
    ),
  ]);

  if (raceResult.timedOut) {
    return { result: null, timedOut: true };
  }

  return { result: raceResult.value as MatchResult | null, timedOut: false };
}

/**
 * Tier 2: Match by compound signal buckets
 * Lower confidence - relies on multiple weak signals
 * Uses Query with adjacency list pattern (bucket_key, device_id)
 * AR-56: Applies cardinality penalty for high-traffic buckets
 */
export async function tier2CompoundMatch(
  deps: Tier2CompoundDeps,
  fingerprint: Fingerprint,
  options?: { abortSignal?: AbortSignal },
): Promise<MatchResult | null> {
  const bucketInfos = buildBucketKeysWithTypesHelper(fingerprint);
  if (bucketInfos.length === 0) return null;

  // Query all buckets in parallel using adjacency list pattern
  // Pass abortSignal to allow cancellation on timeout
  const queries = bucketInfos.map((info) =>
    deps.dynamodb.send(
      new QueryCommand({
        TableName: deps.tier2BucketsTable,
        KeyConditionExpression: "bucket_key = :bk",
        ExpressionAttributeValues: {
          ":bk": { S: info.key },
        },
        ProjectionExpression: "device_id",
        Limit: TIER2_BUCKET_LIMIT,
      }),
      { abortSignal: options?.abortSignal },
    ),
  );

  // AR-56: Fetch bucket cardinalities in parallel with device queries
  const cardinalityPromise = fetchBucketCardinalities(
    deps,
    bucketInfos.map((info) => info.key),
    options,
  );

  let results;
  let cardinalities: Map<string, number>;
  try {
    [results, cardinalities] = await Promise.all([
      Promise.all(queries),
      cardinalityPromise,
    ]);
  } catch (error) {
    // If the request was aborted, return null gracefully
    if (error instanceof Error && error.name === "AbortError") {
      return null;
    }
    throw error;
  }

  // Track which buckets each device matched in
  const candidates = scoreDeviceCandidatesWithEvidence(results, bucketInfos);

  // Find best match (highest bucket overlap)
  let bestDeviceId: string | null = null;
  let bestScore = 0;
  let bestEvidence: EvidenceCode[] = [];

  for (const [deviceId, data] of candidates) {
    if (data.score > bestScore) {
      bestScore = data.score;
      bestDeviceId = deviceId;
      bestEvidence = data.evidenceCodes;
    }
  }

  // Require at least 2 bucket matches for confidence
  if (bestDeviceId && bestScore >= 2) {
    const profile = await loadProfile(deps, bestDeviceId);

    // AR-56: Calculate base confidence
    let confidence = Math.min(0.6 + bestScore * 0.1, 0.85);

    // AR-56: Apply cardinality penalty if any matched bucket exceeds threshold
    const highCardinalityCount = countHighCardinalityBuckets(
      bestEvidence,
      bucketInfos,
      cardinalities,
    );
    if (highCardinalityCount > 0) {
      // Penalize proportionally to how many buckets are high-cardinality
      const penaltyFactor =
        (highCardinalityCount / bestEvidence.length) *
        TIER2_CARDINALITY_PENALTY;
      confidence = Math.max(0.3, confidence - penaltyFactor);
    }

    return {
      device_id: bestDeviceId,
      confidence,
      match_tier: 2,
      is_new_device: false,
      risk_score: profile?.risk_score ?? 0.4,
      flags: profile?.flags ?? [],
      evidence_codes: bestEvidence,
      fuzzy_match_info: computeFuzzyMatchInfo(
        fingerprint.fuzzy_hash,
        profile?.fuzzy_hash,
      ),
    };
  }

  return null;
}

/**
 * AR-56: Fetch cardinality stats for multiple buckets using BatchGetItem
 */
async function fetchBucketCardinalities(
  deps: Tier2CompoundDeps,
  bucketKeys: string[],
  options?: { abortSignal?: AbortSignal },
): Promise<Map<string, number>> {
  const cardinalities = new Map<string, number>();
  if (bucketKeys.length === 0) return cardinalities;

  try {
    const result = await deps.dynamodb.send(
      new BatchGetItemCommand({
        RequestItems: {
          [deps.tier2BucketsTable]: {
            Keys: bucketKeys.map((key) => ({
              bucket_key: { S: key },
              device_id: { S: TIER2_STATS_SK },
            })),
            ProjectionExpression: "bucket_key, cardinality",
          },
        },
      }),
      { abortSignal: options?.abortSignal },
    );

    // Parse results
    const responses = result.Responses?.[deps.tier2BucketsTable] ?? [];
    for (const item of responses) {
      const unmarshalled = unmarshall(item);
      if (unmarshalled.bucket_key && unmarshalled.cardinality) {
        cardinalities.set(
          unmarshalled.bucket_key,
          unmarshalled.cardinality as number,
        );
      }
    }
  } catch (error) {
    // If aborted or error, return empty map (fail open)
    if (error instanceof Error && error.name === "AbortError") {
      return cardinalities;
    }
    // AR-153: Log error and emit metric but don't fail matching - cardinality check is optional
    // This fails open silently which affects fraud penalty scoring
    logger.warn(
      "Failed to fetch bucket cardinalities - fraud penalty scoring disabled",
      {
        error,
        bucketCount: bucketKeys.length,
      },
    );
    metrics.addMetric("Tier2CardinalityFetchFailed", MetricUnit.Count, 1);
    metrics.publishStoredMetrics();
  }

  return cardinalities;
}

/**
 * AR-56: Count how many matched buckets exceed the cardinality threshold
 */
function countHighCardinalityBuckets(
  evidenceCodes: EvidenceCode[],
  bucketInfos: { key: string; evidenceCode: EvidenceCode }[],
  cardinalities: Map<string, number>,
): number {
  let count = 0;
  for (const code of evidenceCodes) {
    // Find the bucket key for this evidence code
    const bucketInfo = bucketInfos.find((info) => info.evidenceCode === code);
    if (bucketInfo) {
      const cardinality = cardinalities.get(bucketInfo.key) ?? 0;
      if (cardinality > TIER2_HIGH_CARDINALITY_THRESHOLD) {
        count++;
      }
    }
  }
  return count;
}

/**
 * Score device candidates and track which buckets matched
 * AR-54: Used to populate evidence_codes in match results
 */
function scoreDeviceCandidatesWithEvidence(
  results: QueryCommandOutput[],
  bucketInfos: { key: string; evidenceCode: EvidenceCode }[],
): Map<string, { score: number; evidenceCodes: EvidenceCode[] }> {
  const candidates = new Map<
    string,
    { score: number; evidenceCodes: Set<EvidenceCode> }
  >();

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const evidenceCode = bucketInfos[i].evidenceCode;

    if (result.Items && result.Items.length > 0) {
      for (const item of result.Items) {
        const unmarshalled = unmarshall(item);
        const deviceId = unmarshalled.device_id;
        // AR-77: Filter out _stats entries (used for bucket cardinality tracking)
        // AR-98: Use TIER2_STATS_SK constant instead of hardcoded string
        if (deviceId && deviceId !== TIER2_STATS_SK) {
          const existing = candidates.get(deviceId);
          if (existing) {
            existing.score += 1;
            existing.evidenceCodes.add(evidenceCode);
          } else {
            candidates.set(deviceId, {
              score: 1,
              evidenceCodes: new Set([evidenceCode]),
            });
          }
        }
      }
    }
  }

  // Convert Sets to arrays for the return value
  const resultMap = new Map<
    string,
    { score: number; evidenceCodes: EvidenceCode[] }
  >();
  for (const [deviceId, data] of candidates) {
    resultMap.set(deviceId, {
      score: data.score,
      evidenceCodes: Array.from(data.evidenceCodes),
    });
  }

  return resultMap;
}
