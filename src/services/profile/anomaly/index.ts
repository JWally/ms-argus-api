/**
 * @fileoverview Anomaly detection module exports.
 * Provides detection of cross-field, network, identity, and statistical anomalies
 * to identify potentially fraudulent or suspicious sessions.
 * @module services/profile/anomaly
 */

export * from "./types";
export { detectAllAnomalies } from "./detector";
export {
  fetchStatisticalContext,
  detectStatisticalAnomalies,
  type StatisticalContext,
} from "./statistical";
export {
  fetchNetworkBaselineContext,
  detectNetworkBaselineAnomalies,
  type NetworkBaselineDetectorContext,
} from "./network-baseline-detector";
export {
  computeShannonScore,
  computeConfidence,
  computeBlendedScore,
  getBucket,
  extractDeviceType,
  TLS_RATIO_BUCKETS,
  MSS_BUCKETS,
  type RawSigintData,
} from "./network-baseline";
export {
  fetchStatisticalContextV2,
  detectStatisticalAnomaliesV2,
  computeShannonScore as computeShannonScoreV2,
  computeConfidence as computeConfidenceV2,
  computeBlendedScore as computeBlendedScoreV2,
  type StatisticalContextV2,
  type FingerprintScore,
  type RawNetworkData,
} from "./statistical-v2";
export {
  evaluateBaselineRules,
  buildRuleContext,
  type RuleContext,
  type RuleEvaluationResult,
} from "./baseline-rules";
