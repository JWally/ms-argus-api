/**
 * Network Baseline Anomaly Detector
 *
 * Detects connections that deviate from their ASN's typical network characteristics
 * using Shannon information-theoretic scoring with Bayesian blending.
 *
 * @module services/profile/anomaly/network-baseline-detector
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import type { Fingerprint } from "../../../types/fingerprint";
import {
  getNetworkBaselines,
  recordNetworkMetrics,
  isNetworkBaselineEnabled,
} from "../../cache/valkey-client";
import {
  extractDeviceType,
  extractNetworkMetrics,
  getBucket,
  computeBlendedScore,
  TLS_RATIO_BUCKETS,
  MSS_BUCKETS,
  type NetworkBaselineContext,
  type BaselineResult,
  type RawSigintData,
} from "./network-baseline";
import { AnomalyCodes, type AnomalySignal } from "./types";

const logger = new Logger({
  serviceName:
    process.env.POWERTOOLS_SERVICE_NAME || "network-baseline-detector",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/** Threshold for flagging an anomaly */
const ANOMALY_THRESHOLD = parseFloat(
  process.env.NETWORK_BASELINE_THRESHOLD || "0.5",
);

/** Context for network baseline detection (pre-fetched) */
export interface NetworkBaselineDetectorContext {
  enabled: boolean;
  asn: string;
  deviceType: string;
  tlsRatioBucket: string;
  mssBucket: string;
  asnContext: NetworkBaselineContext;
  globalContext: NetworkBaselineContext;
}

/**
 * Pre-fetch network baseline context.
 *
 * This should be called early in the request pipeline to allow
 * async I/O to complete while other processing happens.
 *
 * @param fingerprint - Device fingerprint
 * @param sigint - Raw sigint data from the payload
 * @returns Context for detection, or null if not available
 */
export async function fetchNetworkBaselineContext(
  fingerprint: Fingerprint,
  sigint: RawSigintData | undefined,
): Promise<NetworkBaselineDetectorContext | null> {
  if (!isNetworkBaselineEnabled()) {
    return null;
  }

  // Extract network metrics from sigint
  const networkMetrics = extractNetworkMetrics(sigint);
  if (!networkMetrics) {
    logger.debug("No network metrics available for baseline detection");
    return null;
  }

  const { asn, tlsRatio, mss } = networkMetrics;
  const deviceType = extractDeviceType(fingerprint.user_agent);
  const tlsRatioBucket = getBucket(tlsRatio, TLS_RATIO_BUCKETS);
  const mssBucket = getBucket(mss, MSS_BUCKETS);

  try {
    // Record metrics and fetch baselines in parallel
    const [, baselines] = await Promise.all([
      recordNetworkMetrics(asn, deviceType, tlsRatioBucket, mssBucket),
      getNetworkBaselines(asn, deviceType),
    ]);

    // Build contexts
    const asnContext: NetworkBaselineContext = {
      asn,
      deviceType,
      tlsRatioBucket,
      mssBucket,
      histograms: {
        tlsRatio: baselines.asn.tlsRatio.buckets,
        mss: baselines.asn.mss.buckets,
      },
      total: baselines.asn.tlsRatio.total,
    };

    const globalContext: NetworkBaselineContext = {
      asn: "global",
      deviceType,
      tlsRatioBucket,
      mssBucket,
      histograms: {
        tlsRatio: baselines.global.tlsRatio.buckets,
        mss: baselines.global.mss.buckets,
      },
      total: baselines.global.tlsRatio.total,
    };

    return {
      enabled: true,
      asn,
      deviceType,
      tlsRatioBucket,
      mssBucket,
      asnContext,
      globalContext,
    };
  } catch (error) {
    logger.warn("Failed to fetch network baseline context", { error, asn });
    metrics.addMetric("NetworkBaselineContextError", MetricUnit.Count, 1);
    return null;
  }
}

/**
 * Detect network baseline anomalies.
 *
 * Uses Shannon information-theoretic scoring with Bayesian blending
 * to detect connections that deviate from their ASN's typical characteristics.
 *
 * @param context - Pre-fetched context from fetchNetworkBaselineContext
 * @returns Array of anomaly signals (empty if no anomaly detected)
 */
export function detectNetworkBaselineAnomalies(
  context: NetworkBaselineDetectorContext | null,
): AnomalySignal[] {
  if (!context || !context.enabled) {
    return [];
  }

  try {
    const result = computeBlendedScore(
      context.asnContext,
      context.globalContext,
    );

    // Record metrics
    metrics.addMetric("NetworkBaselineScore", MetricUnit.NoUnit, result.score);
    metrics.addMetric(
      "NetworkBaselineConfidence",
      MetricUnit.NoUnit,
      result.confidence,
    );

    if (result.score >= ANOMALY_THRESHOLD) {
      metrics.addMetric("NetworkBaselineAnomalyDetected", MetricUnit.Count, 1);

      logger.info("Network baseline anomaly detected", {
        asn: context.asn,
        deviceType: context.deviceType,
        score: result.score,
        confidence: result.confidence,
        signals: result.signals,
        tlsRatioBucket: context.tlsRatioBucket,
        mssBucket: context.mssBucket,
      });

      return [
        {
          type: "NETWORK",
          code: AnomalyCodes.ASN_NETWORK_ANOMALY,
          severity: result.score,
          evidence: {
            expected: `typical network profile for ASN ${context.asn}`,
            actual: `tls_ratio=${context.tlsRatioBucket}, mss=${context.mssBucket}, score=${result.score.toFixed(3)}, confidence=${result.confidence.toFixed(3)}`,
            fields: result.signals,
          },
        },
      ];
    }

    return [];
  } catch (error) {
    logger.warn("Network baseline detection failed", { error });
    metrics.addMetric("NetworkBaselineDetectionError", MetricUnit.Count, 1);
    return [];
  }
}
