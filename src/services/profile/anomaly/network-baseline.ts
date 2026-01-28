/**
 * ASN Network Baseline Anomaly Detection
 *
 * Uses Shannon information-theoretic scoring to detect connections
 * that deviate from their ASN's typical network characteristics.
 *
 * Key features:
 * - Per-ASN histograms of tls_ratio and mss
 * - Fixed normalization (12-bit ceiling) for consistent scoring across ASN sizes
 * - Bayesian blending: smoothly transitions from global→ASN-specific baselines
 * - Confidence scoring based on sample size (sqrt curve)
 *
 * @module services/profile/anomaly/network-baseline
 */

import { Logger } from "@aws-lambda-powertools/logger";
import type { SigintTcpProbe } from "../../../helpers/payload-schema";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "network-baseline",
});

// ============================================================================
// Constants
// ============================================================================

/**
 * Fixed ceiling for Shannon surprise normalization.
 * 12 bits = 1 in 4096 (~0.02%) is considered maximum meaningful surprise.
 *
 * This ensures consistent scoring across ASNs of different sizes.
 * A 10% event has the same score whether it's on a small ISP or AT&T.
 */
const MAX_SURPRISE_BITS = 12.0;

/**
 * Sample count at which we have 100% confidence in ASN-specific data.
 * Below this, we blend with global baseline.
 *
 * At N=500, we've likely seen enough samples to have stable histogram bins.
 * Confidence uses sqrt curve: sqrt(N/500)
 */
const SATURATION_THRESHOLD = 500;

// ============================================================================
// Bucket Definitions
// ============================================================================

export interface Bucket {
  id: string;
  min: number;
  max: number;
}

/**
 * TLS-to-TCP ratio buckets.
 *
 * tls_ratio = tls_handshake_time / tcp_rtt
 * - Direct connection: ~1.0
 * - VPN tunnel: ~1.5-2.5 (tunnel adds latency)
 * - Proxy: ~3.0+ (forwarding at application layer)
 */
export const TLS_RATIO_BUCKETS: Bucket[] = [
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

/**
 * Maximum Segment Size buckets.
 *
 * MSS reveals tunnel encapsulation overhead:
 * - Standard ethernet: ~1460 (MTU 1500 - 40 byte headers)
 * - WireGuard: ~1380 (80 byte overhead)
 * - OpenVPN: ~1350-1400
 * - Heavy tunnels: <1300
 */
export const MSS_BUCKETS: Bucket[] = [
  { id: "0-1200", min: 0, max: 1200 }, // Heavy tunnel
  { id: "1200-1300", min: 1200, max: 1300 }, // VPN (OpenVPN, WireGuard)
  { id: "1300-1400", min: 1300, max: 1400 }, // Light tunnel
  { id: "1400-1450", min: 1400, max: 1450 }, // Normal residential
  { id: "1450-1500", min: 1450, max: 1500 }, // Standard
  { id: "1500+", min: 1500, max: Infinity }, // Jumbo/unusual
];

// ============================================================================
// Types
// ============================================================================

export interface NetworkBaselineContext {
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

export interface BaselineResult {
  /** Final blended anomaly score [0, 1] */
  score: number;
  /** Confidence in ASN-specific data [0, 1] */
  confidence: number;
  /** Human-readable signals for debugging */
  signals: string[];
  /** Metadata for debugging/logging */
  meta: {
    asnTotal: number;
    globalTotal: number;
    rawAsnScore: number;
    rawGlobalScore: number;
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Find the bucket for a given numeric value.
 *
 * @param value - The numeric value to bucket
 * @param buckets - Array of bucket definitions
 * @returns Bucket ID string, or last bucket if value exceeds all
 */
export function getBucket(value: number, buckets: Bucket[]): string {
  for (const bucket of buckets) {
    if (value >= bucket.min && value < bucket.max) {
      return bucket.id;
    }
  }
  // Fallback to last bucket (should have max: Infinity)
  return buckets[buckets.length - 1].id;
}

/**
 * Extract device type from User-Agent string.
 *
 * Note: UA spoofing is a feature, not a bug. If a Linux bot spoofs an iPhone UA,
 * its network stack (Linux TCP fingerprint) will look anomalous against the
 * "Real iPhone" baseline, increasing the anomaly score.
 *
 * @param userAgent - User-Agent string
 * @returns Device type: 'mobile', 'tablet', or 'desktop'
 */
export function extractDeviceType(userAgent: string | undefined): string {
  const ua = userAgent || "";
  if (/Mobile|Android|iPhone|iPad|iPod/.test(ua)) {
    return /iPad|Tablet/.test(ua) ? "tablet" : "mobile";
  }
  return "desktop";
}

// ============================================================================
// Scoring Functions
// ============================================================================

/**
 * Compute Shannon self-information (surprise) score for a bucket.
 *
 * Uses fixed normalization (MAX_SURPRISE_BITS) to ensure consistent
 * scoring across ASNs of different sizes.
 *
 * @param bucketCount - Number of observations in this bucket
 * @param totalCount - Total observations across all buckets
 * @returns Score in [0, 1] where 1 = maximum surprise (anomalous)
 */
export function computeShannonScore(
  bucketCount: number,
  totalCount: number,
): number {
  if (totalCount === 0) {
    return 0.5; // Neutral if no data
  }
  if (bucketCount === 0) {
    return 1.0; // Maximum surprise for unseen bucket
  }

  const p = bucketCount / totalCount;
  const surpriseBits = -Math.log2(p);

  // Normalize against fixed ceiling, not dynamic log₂(N)
  // This ensures a 10% event has the same score regardless of ASN size
  return Math.min(1.0, surpriseBits / MAX_SURPRISE_BITS);
}

/**
 * Compute confidence in ASN-specific data based on sample size.
 *
 * Uses sqrt curve which:
 * - Rewards early data collection
 * - Plateaus at statistical significance (~500 samples)
 * - Matches statistical intuition (error ∝ 1/√N)
 *
 * @param sampleCount - Number of observations for this ASN
 * @returns Confidence in [0, 1]
 */
export function computeConfidence(sampleCount: number): number {
  return Math.min(1.0, Math.sqrt(sampleCount / SATURATION_THRESHOLD));
}

/**
 * Compute raw anomaly score for a single context (ASN or global).
 *
 * Weighted combination of tls_ratio (60%) and mss (40%) scores.
 * tls_ratio is weighted higher as it's more discriminative for proxy detection.
 *
 * @param ctx - Baseline context with histograms
 * @returns Raw score in [0, 1]
 */
export function computeRawScore(ctx: NetworkBaselineContext): number {
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
 * Compute blended anomaly score using Bayesian approach.
 *
 * Smoothly transitions from global baseline (for new ASNs) to
 * ASN-specific baseline (for established ASNs) based on sample size.
 *
 * Formula: final = (asn_score × confidence) + (global_score × (1 - confidence))
 *
 * @param asnCtx - ASN-specific baseline context
 * @param globalCtx - Global baseline context (fallback)
 * @returns Blended result with score, confidence, and signals
 */
export function computeBlendedScore(
  asnCtx: NetworkBaselineContext,
  globalCtx: NetworkBaselineContext,
): BaselineResult {
  const signals: string[] = [];

  // Confidence: sqrt curve rewards early data, plateaus at saturation
  const confidence = computeConfidence(asnCtx.total);

  // Compute raw scores for both baselines
  const rawAsnScore = computeRawScore(asnCtx);
  const rawGlobalScore = computeRawScore(globalCtx);

  // Bayesian blend:
  // - If confidence=0 (new ASN): 100% global score
  // - If confidence=1 (established ASN): 100% ASN-specific score
  const blendedScore =
    rawAsnScore * confidence + rawGlobalScore * (1 - confidence);

  // Build signals for debugging
  if (blendedScore > 0.5) {
    if (confidence > 0.8) {
      signals.push(`high_confidence_asn_anomaly:${asnCtx.asn}`);
    } else {
      signals.push("global_baseline_deviation");
    }
  }

  // Add specific metric signals
  const asnTlsScore = computeShannonScore(
    asnCtx.histograms.tlsRatio.get(asnCtx.tlsRatioBucket) || 0,
    asnCtx.total,
  );
  const globalTlsScore = computeShannonScore(
    globalCtx.histograms.tlsRatio.get(globalCtx.tlsRatioBucket) || 0,
    globalCtx.total,
  );

  if (asnTlsScore > 0.6 && confidence > 0.5) {
    signals.push(`rare_tls_ratio_for_asn:${asnCtx.tlsRatioBucket}`);
  }
  if (globalTlsScore > 0.6) {
    signals.push(`rare_tls_ratio_globally:${asnCtx.tlsRatioBucket}`);
  }

  logger.debug("Network baseline score computed", {
    asn: asnCtx.asn,
    deviceType: asnCtx.deviceType,
    tlsRatioBucket: asnCtx.tlsRatioBucket,
    mssBucket: asnCtx.mssBucket,
    asnTotal: asnCtx.total,
    globalTotal: globalCtx.total,
    confidence,
    rawAsnScore,
    rawGlobalScore,
    blendedScore,
  });

  return {
    score: blendedScore,
    confidence,
    signals,
    meta: {
      asnTotal: asnCtx.total,
      globalTotal: globalCtx.total,
      rawAsnScore,
      rawGlobalScore,
    },
  };
}

// ============================================================================
// Sigint Data Types and Extraction
// ============================================================================

/**
 * Sigint data structure matching the raw payload from ms-argus-web.
 * This is the full structure, not the simplified API types.
 */
export interface RawSigintData {
  tlsFingerprint?: {
    asn?: string | null;
    ip?: string | null;
    country?: string | null;
    ja3?: string | null;
    ja4?: string | null;
  } | null;
  tcpProbe?: SigintTcpProbe | null;
}

/**
 * Extract network metrics from sigint data.
 *
 * @param sigint - Raw sigint data from the payload
 * @returns Extracted metrics or null if data is missing
 */
export function extractNetworkMetrics(
  sigint: RawSigintData | undefined,
): { asn: string; tlsRatio: number; mss: number } | null {
  if (!sigint?.tcpProbe?.rtt_fingerprint || !sigint?.tlsFingerprint?.asn) {
    return null;
  }

  const rttFp = sigint.tcpProbe.rtt_fingerprint;
  const tlsRatio = rttFp.tls_to_tcp_ratio;
  const mss = rttFp.snd_mss;
  const asn = sigint.tlsFingerprint.asn;

  // Validate values exist
  if (typeof tlsRatio !== "number" || typeof mss !== "number" || !asn) {
    return null;
  }

  return { asn: String(asn), tlsRatio, mss };
}
