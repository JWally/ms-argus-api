import type { Fingerprint } from "../../../types/fingerprint";
import type { DeviceProfile } from "../../../types/profile";
import { AnomalyCodes, createSignal, type AnomalySignal } from "./types";
import { hasSeenAsn, countRecentUniqueIps } from "../ip-history";

const IP_CHURN_THRESHOLD = 100;

/**
 * Detect IP/ASN history anomalies.
 * Flags devices appearing on new ASNs or cycling through excessive IPs.
 */
export function detectIpHistoryAnomalies(
  fingerprint: Fingerprint,
  profile: DeviceProfile | null,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  const history = profile?.ip_history ?? [];

  if (history.length === 0 || !fingerprint.ip_address) return signals;

  // NEW_ASN_FOR_DEVICE: device appeared on an ASN not in its history
  if (fingerprint.asn !== undefined && !hasSeenAsn(history, fingerprint.asn)) {
    signals.push(
      createSignal("NETWORK", AnomalyCodes.NEW_ASN_FOR_DEVICE, 0.3, {
        expected: "known ASN",
        actual: `ASN ${fingerprint.asn}`,
      }),
    );
  }

  // IP_CHURN: device cycling through excessive unique IPs in 24h
  const recentIps = countRecentUniqueIps(history, Date.now());
  if (recentIps >= IP_CHURN_THRESHOLD) {
    signals.push(
      createSignal("NETWORK", AnomalyCodes.IP_CHURN, 0.5, {
        expected: `<${IP_CHURN_THRESHOLD} unique IPs in 24h`,
        actual: `${recentIps} unique IPs`,
      }),
    );
  }

  return signals;
}
