// src/services/profile/anomaly/quick-wins.ts
// AR-142: Quick win anomaly detections using data already in normalized fingerprint

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

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

  // Lie count detection - navigator API tampering
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

  // Direct headless detection
  if (fingerprint.is_headless === true) {
    signals.push(
      createSignal("CROSS_FIELD", AnomalyCodes.HEADLESS_DETECTED, 0.9, {
        expected: "is_headless: false",
        actual: "is_headless: true",
        fields: ["is_headless"],
      }),
    );
  }

  // Proxy score threshold - high likelihood of proxy usage
  if (fingerprint.proxy_score !== undefined && fingerprint.proxy_score > 0.7) {
    signals.push(
      createSignal("NETWORK", AnomalyCodes.HIGH_PROXY_SCORE, fingerprint.proxy_score, {
        expected: "proxy_score <= 0.7",
        actual: `proxy_score: ${fingerprint.proxy_score.toFixed(2)}`,
        fields: ["proxy_score"],
      }),
    );
  }

  // VPN score threshold - lower severity than proxy
  if (fingerprint.vpn_score !== undefined && fingerprint.vpn_score > 0.7) {
    // VPN is less suspicious than proxy, so multiply by 0.8
    signals.push(
      createSignal("NETWORK", AnomalyCodes.HIGH_VPN_SCORE, fingerprint.vpn_score * 0.8, {
        expected: "vpn_score <= 0.7",
        actual: `vpn_score: ${fingerprint.vpn_score.toFixed(2)}`,
        fields: ["vpn_score"],
      }),
    );
  }

  return signals;
}
