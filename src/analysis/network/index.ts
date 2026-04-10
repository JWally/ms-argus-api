/**
 * Network probe analysis for integrity ingestion.
 *
 * Wraps the anomaly detector to produce a structured result
 * with proxy/VPN scores from TCP probe data.
 */

import { detectNetworkProbeAnomalies } from "../../services/profile/anomaly/network-probe-detector";
import type { Fingerprint } from "../../types";

export function analyzeNetworkProbes(sigint: unknown) {
  const networkSignals = detectNetworkProbeAnomalies(
    {} as Fingerprint,
    undefined,
    sigint,
  );
  const maxScore = (code: string) => {
    const matching = networkSignals.filter((s) => s.code === code);
    return matching.length ? Math.max(...matching.map((s) => s.severity)) : 0;
  };
  return {
    proxy_score: maxScore("LIKELY_PROXY"),
    vpn_score: maxScore("LIKELY_VPN"),
    signals: networkSignals.map((s) => ({
      code: s.code,
      severity: s.severity,
      evidence: s.evidence.actual,
    })),
  };
}
