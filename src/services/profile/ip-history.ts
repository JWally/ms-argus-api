import type { IpHistoryEntry, DeviceProfile } from "../../types/profile";
import type { Fingerprint } from "../../types/fingerprint";

const MAX_HISTORY_ENTRIES = 10;
const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

/**
 * Update IP history ring buffer with a new observation.
 * Deduplicates by IP+ASN (updates timestamp if already present).
 * Keeps at most MAX_HISTORY_ENTRIES, newest-first.
 */
export function updateIpHistory(
  existing: IpHistoryEntry[],
  ip: string,
  asn: number,
  ts: number,
): IpHistoryEntry[] {
  const filtered = existing.filter(
    (entry) => !(entry.ip === ip && entry.asn === asn),
  );
  const updated: IpHistoryEntry[] = [{ ip, asn, ts }, ...filtered];
  return updated.slice(0, MAX_HISTORY_ENTRIES);
}

/** Check if an IP has been seen in the device's history. */
export function hasSeenIp(history: IpHistoryEntry[], ip: string): boolean {
  return history.some((entry) => entry.ip === ip);
}

/** Check if an ASN has been seen in the device's history. */
export function hasSeenAsn(history: IpHistoryEntry[], asn: number): boolean {
  return history.some((entry) => entry.asn === asn);
}

/** Count unique IPs seen in the last 24 hours. */
export function countRecentUniqueIps(
  history: IpHistoryEntry[],
  now: number,
): number {
  const cutoff = now - TWENTY_FOUR_HOURS_MS;
  const recentIps = new Set(
    history.filter((e) => e.ts >= cutoff).map((e) => e.ip),
  );
  return recentIps.size;
}

/** Count unique ASNs seen in the last 24 hours. */
export function countRecentUniqueAsns(
  history: IpHistoryEntry[],
  now: number,
): number {
  const cutoff = now - TWENTY_FOUR_HOURS_MS;
  const recentAsns = new Set(
    history.filter((e) => e.ts >= cutoff).map((e) => e.asn),
  );
  return recentAsns.size;
}

/**
 * Compute confidence modifier based on IP history.
 * Known IPs/ASNs boost confidence; unknown ones reduce it.
 */
export function computeIpConfidenceModifier(
  profile: DeviceProfile | null,
  fingerprint: Fingerprint,
): { adjustment: number } {
  if (!profile?.ip_history?.length || !fingerprint.ip_address) {
    return { adjustment: 0 };
  }

  const history = profile.ip_history;
  const knownIp = hasSeenIp(history, fingerprint.ip_address);
  const knownAsn =
    fingerprint.asn !== undefined
      ? hasSeenAsn(history, fingerprint.asn)
      : false;

  if (knownIp) return { adjustment: 0.02 };
  if (knownAsn) return { adjustment: 0 };
  return { adjustment: -0.05 };
}
