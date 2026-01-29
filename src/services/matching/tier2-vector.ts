/**
 * @fileoverview Tier 2 Vector Matching - Replaces compound bucket matching.
 *
 * Uses Qdrant vector similarity search for device matching instead of
 * DynamoDB compound buckets. This provides:
 * - Better accuracy on privacy browsers (no more bucket collisions)
 * - Simpler architecture (no bucket cardinality management)
 * - O(1) scaling vs O(n) bucket queries
 *
 * @module services/matching/tier2-vector
 */

import {
  LambdaClient,
  InvokeCommand,
  InvocationType,
} from "@aws-sdk/client-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { computeEmbedding, assessEmbeddingQuality } from "../vector/embedding";
import { loadProfile } from "./profile-loader";
import { computeFuzzyMatchInfo } from "../../helpers/hash";
import type {
  Fingerprint,
  MatchResult,
  EvidenceCode,
  VectorMatchDetails,
} from "./types";
import type {
  SyncSearchRequest,
  SyncSearchResponse,
  SyncUpsertRequest,
  SyncUpsertResponse,
  SyncErrorResponse,
} from "../../handlers/vector-worker/types";

/** Minimum similarity score to consider a match */
const MIN_SCORE_THRESHOLD = 0.7;

/** High confidence threshold for very similar vectors */
const HIGH_SCORE_THRESHOLD = 0.9;

/** Timeout for vector search Lambda invocation */
const VECTOR_INVOKE_TIMEOUT_MS = 5000;

/**
 * Dependencies for Tier 2 vector matching
 */
export interface Tier2VectorDeps {
  /** Lambda client for invoking vector-worker */
  lambda: LambdaClient;
  /** DynamoDB client for profile lookups */
  dynamodb: DynamoDBClient;
  /** ARN of the vector-worker Lambda function */
  vectorWorkerArn: string;
  /** Qdrant collection name */
  collection: string;
  /** Profiles table name */
  profilesTable: string;
  /** Logger for debugging */
  logger: Logger;
  /** Metrics for CloudWatch */
  metrics: Metrics;
}

/**
 * Primary features used in the embedding, ordered by discriminating power.
 */
const PRIMARY_EMBEDDING_FEATURES = [
  "canvas_hash",
  "webgl_hash",
  "gpu_renderer",
  "audio_hash",
  "user_agent",
  "stable_hash",
  "screen_dims",
  "hardware_concurrency",
];

/**
 * Tier 2: Vector similarity match with timeout protection.
 * Returns result with timedOut flag for "fail open" scenarios.
 */
export async function tier2VectorMatchWithTimeout(
  deps: Tier2VectorDeps,
  fingerprint: Fingerprint,
): Promise<{ result: MatchResult | null; timedOut: boolean }> {
  const abortController = new AbortController();
  const TIMEOUT_SENTINEL = Symbol("timeout");

  const raceResult = await Promise.race([
    tier2VectorMatch(deps, fingerprint, abortController.signal).then((r) => ({
      value: r,
      timedOut: false,
    })),
    new Promise<{ value: typeof TIMEOUT_SENTINEL; timedOut: true }>((resolve) =>
      setTimeout(() => {
        abortController.abort();
        resolve({ value: TIMEOUT_SENTINEL, timedOut: true });
      }, VECTOR_INVOKE_TIMEOUT_MS),
    ),
  ]);

  if (raceResult.timedOut) {
    deps.metrics.addMetric("Tier2VectorTimeout", MetricUnit.Count, 1);
    deps.logger.warn("Tier 2 vector search timed out");
    return { result: null, timedOut: true };
  }

  return { result: raceResult.value as MatchResult | null, timedOut: false };
}

/** Options for Lambda invocation */
interface InvokeLambdaOptions {
  functionName: string;
  payload: unknown;
  errorMetric: string;
  abortSignal?: AbortSignal;
}

/** Invoke Lambda and parse response, returns null on error */
async function invokeLambda<T>(
  deps: Pick<Tier2VectorDeps, "lambda" | "logger" | "metrics">,
  opts: InvokeLambdaOptions,
): Promise<T | null> {
  const invokeResult = await deps.lambda.send(
    new InvokeCommand({
      FunctionName: opts.functionName,
      InvocationType: InvocationType.RequestResponse,
      Payload: Buffer.from(JSON.stringify(opts.payload)),
    }),
    { abortSignal: opts.abortSignal },
  );

  if (invokeResult.FunctionError) {
    deps.logger.error("Lambda invocation error", {
      error: invokeResult.FunctionError,
      payload: invokeResult.Payload
        ? Buffer.from(invokeResult.Payload).toString()
        : null,
    });
    deps.metrics.addMetric(opts.errorMetric, MetricUnit.Count, 1);
    return null;
  }

  if (!invokeResult.Payload) {
    deps.logger.error("Lambda returned empty payload");
    deps.metrics.addMetric(
      `${opts.errorMetric}EmptyPayload`,
      MetricUnit.Count,
      1,
    );
    return null;
  }

  return JSON.parse(Buffer.from(invokeResult.Payload).toString()) as T;
}

/** Handle error response from vector search */
function handleSearchError(
  deps: Pick<Tier2VectorDeps, "logger" | "metrics">,
  errorResponse: SyncErrorResponse,
): void {
  if (errorResponse.code === "COLLECTION_NOT_FOUND") {
    deps.logger.info("Vector collection not found - will be created on upsert");
    deps.metrics.addMetric("Tier2VectorCollectionMissing", MetricUnit.Count, 1);
  } else {
    deps.logger.error("Vector search failed", {
      error: errorResponse.error,
      code: errorResponse.code,
    });
    deps.metrics.addMetric("Tier2VectorSearchFailed", MetricUnit.Count, 1);
  }
}

/** Record search completion metrics */
function recordSearchMetrics(
  deps: Pick<Tier2VectorDeps, "metrics">,
  count: number,
  duration: number,
): void {
  deps.metrics.addMetric("Tier2VectorSearchComplete", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "Tier2VectorSearchDuration",
    MetricUnit.Milliseconds,
    duration,
  );
  deps.metrics.addMetric("Tier2VectorResultCount", MetricUnit.Count, count);
}

type SearchMatch = {
  best: SyncSearchResponse["results"][0];
  response: SyncSearchResponse;
};

/** Process search response and return best match or null */
function processSearchResponse(
  deps: Pick<Tier2VectorDeps, "logger" | "metrics">,
  response: SyncSearchResponse | SyncErrorResponse,
  startTime: number,
): SearchMatch | null {
  if (!response.success) {
    handleSearchError(deps, response as SyncErrorResponse);
    return null;
  }

  const successResponse = response as SyncSearchResponse;
  recordSearchMetrics(deps, successResponse.count, Date.now() - startTime);

  if (successResponse.count === 0) {
    deps.logger.info("No vector matches found above threshold", {
      threshold: MIN_SCORE_THRESHOLD,
    });
    return null;
  }

  const best = successResponse.results[0];
  deps.logger.info("Vector match found", {
    device_id: best.device_id,
    score: best.score,
    result_count: successResponse.count,
  });

  return { best, response: successResponse };
}

/**
 * Tier 2: Vector similarity match using Qdrant.
 */
async function tier2VectorMatch(
  deps: Tier2VectorDeps,
  fingerprint: Fingerprint,
  abortSignal?: AbortSignal,
): Promise<MatchResult | null> {
  const startTime = Date.now();

  // Step 1: Compute embedding
  const embeddingResult = computeEmbedding(fingerprint);
  deps.metrics.addMetric("EmbeddingComputed", MetricUnit.Count, 1);

  // Step 2: Invoke vector-worker for search
  const searchRequest: SyncSearchRequest = {
    action: "search",
    vector: embeddingResult.vector,
    collection: deps.collection,
    limit: 5,
    score_threshold: MIN_SCORE_THRESHOLD,
    auto_create_collection: true,
  };

  let searchResponse: SyncSearchResponse | SyncErrorResponse | null;
  try {
    searchResponse = await invokeLambda<SyncSearchResponse | SyncErrorResponse>(
      deps,
      {
        functionName: deps.vectorWorkerArn,
        payload: searchRequest,
        errorMetric: "Tier2VectorInvokeError",
        abortSignal,
      },
    );
    if (!searchResponse) return null;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") return null;
    deps.logger.error("Failed to invoke vector worker", { error });
    deps.metrics.addMetric("Tier2VectorInvokeFailed", MetricUnit.Count, 1);
    return null;
  }

  // Step 3: Process results
  const match = processSearchResponse(deps, searchResponse, startTime);
  if (!match) return null;

  // Step 4: Build match result
  return buildVectorMatchResult({
    deps,
    deviceId: match.best.device_id,
    score: match.best.score,
    fingerprint,
    searchResponse: match.response,
  });
}

/** Options for building a vector match result */
interface BuildMatchResultOptions {
  deps: Pick<Tier2VectorDeps, "dynamodb" | "profilesTable" | "logger">;
  deviceId: string;
  score: number;
  fingerprint: Fingerprint;
  searchResponse: SyncSearchResponse;
}

/** Build vector match details for transparency */
function buildVectorDetails(
  score: number,
  searchResponse: SyncSearchResponse,
): VectorMatchDetails {
  return {
    similarity_score: score,
    candidates_in_range: searchResponse.count,
    runner_up_score:
      searchResponse.results.length > 1
        ? searchResponse.results[1].score
        : null,
    top_scores: searchResponse.results.slice(0, 5).map((r) => r.score),
    embedding_dimension: 256,
    primary_match_features: PRIMARY_EMBEDDING_FEATURES,
  };
}

/**
 * Build a complete MatchResult from a vector search match.
 */
async function buildVectorMatchResult(
  opts: BuildMatchResultOptions,
): Promise<MatchResult> {
  const { deps, deviceId, score, fingerprint, searchResponse } = opts;

  const profile = await loadProfile(
    { dynamodb: deps.dynamodb, profilesTable: deps.profilesTable },
    deviceId,
  );

  const confidence = computeVectorConfidence(score);
  const evidenceCodes: EvidenceCode[] = ["VECTOR_SIMILARITY"];
  if (score >= HIGH_SCORE_THRESHOLD) {
    evidenceCodes.push("HIGH_SIMILARITY");
  }

  return {
    device_id: deviceId,
    confidence,
    match_tier: 2,
    is_new_device: false,
    risk_score: profile?.risk_score ?? 0.4,
    flags: profile?.flags ?? [],
    evidence_codes: evidenceCodes,
    fuzzy_match_info: computeFuzzyMatchInfo(
      fingerprint.fuzzy_hash,
      profile?.fuzzy_hash,
    ),
    vector_match_details: buildVectorDetails(score, searchResponse),
  };
}

/**
 * Convert vector similarity score to confidence score.
 * Score range: 0.7-1.0 maps to confidence 0.5-0.95
 */
function computeVectorConfidence(score: number): number {
  const minScore = MIN_SCORE_THRESHOLD;
  const maxScore = 1.0;
  const minConfidence = 0.5;
  const maxConfidence = 0.95;

  const normalized = (score - minScore) / (maxScore - minScore);
  return minConfidence + normalized * (maxConfidence - minConfidence);
}

/**
 * Upsert a device's vector embedding to Qdrant.
 *
 * Includes a quality gate to prevent sparse/incomplete fingerprints from
 * polluting the vector index. Fingerprints missing critical signals
 * (structural hashes, rendering data, hardware info) will be rejected.
 *
 * @returns true if upsert succeeded, false if skipped or failed
 */
export async function upsertDeviceVector(
  deps: Pick<
    Tier2VectorDeps,
    "lambda" | "vectorWorkerArn" | "collection" | "logger" | "metrics"
  >,
  deviceId: string,
  fingerprint: Fingerprint,
): Promise<boolean> {
  // Quality gate: reject sparse fingerprints that would pollute the index
  const quality = assessEmbeddingQuality(fingerprint);
  if (!quality.acceptable) {
    deps.logger.info("Skipping vector upsert - fingerprint quality too low", {
      device_id: deviceId,
      quality_score: quality.score.toFixed(2),
      structural_count: quality.structuralCount,
      rendering_count: quality.renderingCount,
      hardware_count: quality.hardwareCount,
      reason: quality.reason,
    });
    deps.metrics.addMetric(
      "VectorUpsertSkippedLowQuality",
      MetricUnit.Count,
      1,
    );
    return false;
  }

  deps.metrics.addMetric(
    "VectorEmbeddingQualityScore",
    MetricUnit.Count,
    Math.round(quality.score * 100),
  );

  const embeddingResult = computeEmbedding(fingerprint);

  const upsertRequest: SyncUpsertRequest = {
    action: "upsert",
    device_id: deviceId,
    vector: embeddingResult.vector,
    collection: deps.collection,
    payload: {
      stable_hash: fingerprint.stable_hash,
      fuzzy_hash: fingerprint.fuzzy_hash,
      user_agent: fingerprint.user_agent,
      updated_at: Date.now(),
    },
    auto_create_collection: true,
  };

  try {
    const response = await invokeLambda<SyncUpsertResponse | SyncErrorResponse>(
      deps,
      {
        functionName: deps.vectorWorkerArn,
        payload: upsertRequest,
        errorMetric: "VectorUpsertError",
      },
    );

    if (!response) return false;

    if (!response.success) {
      deps.logger.error("Vector upsert failed", {
        error: (response as SyncErrorResponse).error,
      });
      deps.metrics.addMetric("VectorUpsertFailed", MetricUnit.Count, 1);
      return false;
    }

    deps.metrics.addMetric("VectorUpsertSuccess", MetricUnit.Count, 1);
    deps.logger.info("Vector upsert complete", { device_id: deviceId });
    return true;
  } catch (error) {
    deps.logger.error("Failed to invoke vector upsert", { error });
    deps.metrics.addMetric("VectorUpsertInvokeFailed", MetricUnit.Count, 1);
    return false;
  }
}
