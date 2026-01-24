import { Fingerprint } from "../../../types";
import {
  AnomalySignal,
  AnomalyType,
  AnomalyCodes,
  createSignal,
} from "./types";

interface ScoreCheck {
  score: number | undefined;
  type: AnomalyType;
  code: (typeof AnomalyCodes)[keyof typeof AnomalyCodes];
  field: string;
  severityMultiplier?: number;
}

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
 */
export function detectQuickWinAnomalies(
  fingerprint: Fingerprint,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  if (fingerprint.lie_count !== undefined && fingerprint.lie_count > 0) {
    // Severity scales with lie count: 0.5 base + 0.1 per lie, max 0.9
    const severity = Math.min(0.9, 0.5 + fingerprint.lie_count * 0.1);
    signals.push(
      createSignal("CROSS_FIELD", AnomalyCodes.NAVIGATOR_LIES, severity, {
        expected: "0 lies",
        actual: `${fingerprint.lie_count} lies detected`,
        fields: ["lie_count"],
      }),
    );
  }

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
