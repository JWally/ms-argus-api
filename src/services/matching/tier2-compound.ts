import {
  DynamoDBClient,
  QueryCommand,
  QueryCommandOutput,
  BatchGetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { loadProfile } from "./profile-loader";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  TIER2_BUCKET_LIMIT,
  TIER2_HIGH_CARDINALITY_THRESHOLD,
  TIER2_CARDINALITY_PENALTY,
  TIER2_STATS_SK,
} from "../../helpers/constants";
import {
  buildBucketKeysWithTypes as buildBucketKeysWithTypesHelper,
  BucketKeyInfo,
} from "../../helpers/bucket-keys";
import { EvidenceCode, Fingerprint, MatchResult } from "./types";
import { computeFuzzyMatchInfo } from "../../helpers/hash";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "argus-tier2-compound",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/**
 * Dependencies for Tier 2 compound matching operations
 */
export interface Tier2CompoundDeps {
  /** DynamoDB client instance */
  dynamodb: DynamoDBClient;
  /** Name of the tier 2 buckets table */
  tier2BucketsTable: string;
  /** Name of the profiles table */
  profilesTable: string;
  /** Timeout in milliseconds for tier 2 queries */
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
 * Select the best candidate from scored devices
 * Requires minimum score of 2 (device must match in 2+ buckets)
 * @param candidates - Map of device IDs to scores and evidence codes
 * @returns Best candidate if score >= 2, null otherwise
 */
function selectBestCandidate(
  candidates: Map<string, { score: number; evidenceCodes: EvidenceCode[] }>,
): { deviceId: string; score: number; evidenceCodes: EvidenceCode[] } | null {
  let best: {
    deviceId: string;
    score: number;
    evidenceCodes: EvidenceCode[];
  } | null = null;
  for (const [deviceId, data] of candidates) {
    if (!best || data.score > best.score) {
      best = { deviceId, score: data.score, evidenceCodes: data.evidenceCodes };
    }
  }
  return best && best.score >= 2 ? best : null;
}

/**
 * Compute confidence score for tier 2 match
 * Applies penalty for high-cardinality buckets to reduce false positives
 * @param score - Number of matching buckets
 * @param evidenceCodes - Evidence codes from matched buckets
 * @param bucketInfos - Bucket key information for matched buckets
 * @param cardinalities - Cardinality counts for each bucket
 * @returns Confidence score between 0.3 and 0.85
 */
function computeTier2Confidence(
  score: number,
  evidenceCodes: EvidenceCode[],
  bucketInfos: BucketKeyInfo[],
  cardinalities: Map<string, number>,
): number {
  let confidence = Math.min(0.6 + score * 0.1, 0.85);
  const highCount = countHighCardinalityBuckets(
    evidenceCodes,
    bucketInfos,
    cardinalities,
  );
  if (highCount > 0) {
    const penalty =
      (highCount / evidenceCodes.length) * TIER2_CARDINALITY_PENALTY;
    confidence = Math.max(0.3, confidence - penalty);
  }
  return confidence;
}

/**
 * Build complete match result from tier 2 candidate
 * Loads profile for risk score and flags, computes confidence with cardinality penalty
 * @param deps - Dependencies including DynamoDB client and table names
 * @param best - Best matching candidate with score and evidence
 * @param fingerprint - The incoming fingerprint for fuzzy match info
 * @param context - Bucket info and cardinality data for confidence calculation
 * @returns Complete match result
 */
async function buildTier2Result(
  deps: Tier2CompoundDeps,
  best: { deviceId: string; score: number; evidenceCodes: EvidenceCode[] },
  fingerprint: Fingerprint,
  context: { bucketInfos: BucketKeyInfo[]; cardinalities: Map<string, number> },
): Promise<MatchResult> {
  const profile = await loadProfile(deps, best.deviceId);
  const confidence = computeTier2Confidence(
    best.score,
    best.evidenceCodes,
    context.bucketInfos,
    context.cardinalities,
  );
  return {
    device_id: best.deviceId,
    confidence,
    match_tier: 2,
    is_new_device: false,
    risk_score: profile?.risk_score ?? 0.4,
    flags: profile?.flags ?? [],
    evidence_codes: best.evidenceCodes,
    fuzzy_match_info: computeFuzzyMatchInfo(
      fingerprint.fuzzy_hash,
      profile?.fuzzy_hash,
    ),
  };
}

/**
 * Tier 2: Match by compound signal buckets
 * Lower confidence - relies on multiple weak signals (IP+JA4, GPU+screen+tz, etc.)
 * Uses Query with adjacency list pattern (bucket_key, device_id)
 * @param deps - Dependencies including DynamoDB client and table names
 * @param fingerprint - The fingerprint to match
 * @param options - Optional abort signal for timeout cancellation
 * @returns Match result if device found in 2+ buckets, null otherwise
 */
export async function tier2CompoundMatch(
  deps: Tier2CompoundDeps,
  fingerprint: Fingerprint,
  options?: { abortSignal?: AbortSignal },
): Promise<MatchResult | null> {
  const bucketInfos = buildBucketKeysWithTypesHelper(fingerprint);
  if (bucketInfos.length === 0) return null;

  const queries = bucketInfos.map((info) =>
    deps.dynamodb.send(
      new QueryCommand({
        TableName: deps.tier2BucketsTable,
        KeyConditionExpression: "bucket_key = :bk",
        ExpressionAttributeValues: { ":bk": { S: info.key } },
        ProjectionExpression: "device_id",
        Limit: TIER2_BUCKET_LIMIT,
      }),
      { abortSignal: options?.abortSignal },
    ),
  );

  let results;
  let cardinalities: Map<string, number>;
  try {
    [results, cardinalities] = await Promise.all([
      Promise.all(queries),
      fetchBucketCardinalities(
        deps,
        bucketInfos.map((i) => i.key),
        options,
      ),
    ]);
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") return null;
    throw error;
  }

  const candidates = scoreDeviceCandidatesWithEvidence(results, bucketInfos);
  const best = selectBestCandidate(candidates);
  if (!best) return null;

  return buildTier2Result(deps, best, fingerprint, {
    bucketInfos,
    cardinalities,
  });
}

/**
 * Fetch cardinality stats for multiple buckets using BatchGetItem
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
    if (error instanceof Error && error.name === "AbortError") {
      return cardinalities;
    }
    // Fail open: log error but don't fail matching - cardinality check is optional
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
 * Count how many matched buckets exceed the cardinality threshold
 * High-cardinality buckets indicate less unique matches, reducing confidence
 * @param evidenceCodes - Evidence codes from the match
 * @param bucketInfos - Bucket key info with evidence codes
 * @param cardinalities - Cardinality counts per bucket
 * @returns Number of buckets exceeding the threshold
 */
function countHighCardinalityBuckets(
  evidenceCodes: EvidenceCode[],
  bucketInfos: { key: string; evidenceCode: EvidenceCode }[],
  cardinalities: Map<string, number>,
): number {
  let count = 0;
  for (const code of evidenceCodes) {
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
 * Extract device IDs from a DynamoDB query result
 * Filters out stats entries (TIER2_STATS_SK)
 * @param result - DynamoDB query result
 * @returns Array of device IDs
 */
function extractDeviceIds(result: QueryCommandOutput): string[] {
  if (!result.Items || result.Items.length === 0) return [];
  return result.Items.map(
    (item) => unmarshall(item).device_id as string,
  ).filter((id) => id && id !== TIER2_STATS_SK);
}

/**
 * Score device candidates by counting bucket matches and collecting evidence
 * @param results - DynamoDB query results from bucket queries
 * @param bucketInfos - Bucket key info with evidence codes
 * @returns Map of device IDs to scores and evidence codes
 */
function scoreDeviceCandidatesWithEvidence(
  results: QueryCommandOutput[],
  bucketInfos: BucketKeyInfo[],
): Map<string, { score: number; evidenceCodes: EvidenceCode[] }> {
  const candidates = new Map<
    string,
    { score: number; evidenceCodes: Set<EvidenceCode> }
  >();

  for (let i = 0; i < results.length; i++) {
    const evidenceCode = bucketInfos[i].evidenceCode;
    for (const deviceId of extractDeviceIds(results[i])) {
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

  const resultMap = new Map<
    string,
    { score: number; evidenceCodes: EvidenceCode[] }
  >();
  for (const [deviceId, data] of candidates) {
    resultMap.set(deviceId, {
      score: data.score,
      evidenceCodes: [...data.evidenceCodes],
    });
  }

  return resultMap;
}
