import { Fingerprint } from "../../../types";
import {
  AnomalySignal,
  AnomalyType,
  AnomalyCodes,
  createSignal,
} from "./types";

/**
 * Configuration for a score threshold check
 */
interface ScoreCheck {
  /** Score value to check (undefined treated as 0) */
  score: number | undefined;
  /** Type of anomaly to create */
  type: AnomalyType;
  /** Anomaly code to use */
  code: (typeof AnomalyCodes)[keyof typeof AnomalyCodes];
  /** Field name for reporting */
  field: string;
  /** Optional multiplier for severity (default 1) */
  severityMultiplier?: number;
}

/**
 * Check if a score exceeds threshold and create anomaly signal
 * @param check - Score check configuration
 * @returns Anomaly signal if score > 0.7, null otherwise
 */
function checkScoreThreshold(check: ScoreCheck): AnomalySignal | null {
  const { score, type, code, field, severityMultiplier = 1 } = check;
  if (score === undefined || score <= 0.7) return null;
  return createSignal(type, code, score * severityMultiplier, {
    expected: `${field} <= 0.7`,
    actual: `${field}: ${score.toFixed(2)}`,
    fields: [field],
  });
}

/**
 * Quick win anomaly detections
 * These checks use data already available in the normalized fingerprint
 * - lie_count: Navigator API tampering detection
 * - is_headless: Direct headless browser detection
 * - proxy_score: High proxy likelihood
 * - vpn_score: VPN usage detection
 * @param fingerprint - Normalized fingerprint with lie_count, is_headless, proxy_score, vpn_score
 * @returns Array of detected anomaly signals
 */
export function detectQuickWinAnomalies(
  fingerprint: Fingerprint,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  if (fingerprint.is_headless === true) {
    signals.push(
      createSignal("CROSS_FIELD", AnomalyCodes.HEADLESS_DETECTED, 0.9, {
        expected: "is_headless: false",
        actual: "is_headless: true",
        fields: ["is_headless"],
      }),
    );
  }

  const proxySignal = checkScoreThreshold({
    score: fingerprint.proxy_score,
    type: "NETWORK",
    code: AnomalyCodes.HIGH_PROXY_SCORE,
    field: "proxy_score",
  });
  if (proxySignal) signals.push(proxySignal);

  const vpnSignal = checkScoreThreshold({
    score: fingerprint.vpn_score,
    type: "NETWORK",
    code: AnomalyCodes.HIGH_VPN_SCORE,
    field: "vpn_score",
    severityMultiplier: 0.8,
  });
  if (vpnSignal) signals.push(vpnSignal);

  return signals;
}
