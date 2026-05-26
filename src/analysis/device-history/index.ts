/**
 * Device-history signal computation.
 *
 * Reads a decrypted DeviceHistoryBlob and computes recurrence /
 * stability metrics in-process — no DB lookups. These signals are
 * stored on the integrity row's `analysis.device_history` field for
 * merchant API surfacing in a follow-on PR.
 *
 * Scoring: this PR wires only `deviceHistoryTampered` (auth-tag fail)
 * into the tampering ladder at tier-60. Velocity / cardinality based
 * scoring is intentionally deferred to Phase 2c so we can first
 * observe the natural distribution of these signals in production
 * traffic before tuning thresholds.
 */
import type {
  DeviceHistoryBlob,
  DeviceHistoryVisit,
} from "../../helpers/device-history";

export interface DeviceHistoryAnalysis {
  /** Set true when the client presented a blob but it failed AES-GCM
   *  auth-tag verification (or otherwise failed to decode). Honest
   *  clients either present a valid server-issued blob or no blob at
   *  all — corrupt blobs are a tampering signal. */
  tampered: boolean;
  /** Set true when the blob decrypted cleanly but blob.id !== payload's
   *  pubkey. The client is trying to use a blob bound to a different
   *  device. Tampering tier the same as `tampered`. */
  identityMismatch: boolean;
  /** Set true when the client presented no blob (or it was absent /
   *  empty). Honest first-visit case; not a tampering signal. */
  freshDevice: boolean;
  /** Total visits in the blob INCLUDING the current submission. */
  scanCount: number;
  /** Age in seconds since blob.created. */
  ageSeconds: number;
  /** Distinct IPs seen across visits[]. Single residential IP = 1. */
  distinctIpCount: number;
  /** Distinct ISO countries seen across visits[]. */
  distinctCountryCount: number;
  /** Distinct net_class values seen across visits[]. */
  distinctNetClassCount: number;
  /** Distinct cpis seen — usually 1 due to browser-origin partitioning. */
  distinctCpiCount: number;
  /** Distinct ua_hash values across visits[]. >1 = browser-flapping. */
  distinctUaCount: number;
  /** Visit count in the last 5 minutes (300_000 ms). */
  recent5MinCount: number;
  /** Visit count in the last hour. */
  recent1HourCount: number;
  /** Visit count in the last 24 hours. */
  recent24HourCount: number;
}

/** Result of `computeDeviceHistoryAnalysis` over a missing/corrupt blob. */
function unanalyzable(
  reason: "tampered" | "identityMismatch" | "freshDevice",
): DeviceHistoryAnalysis {
  return {
    tampered: reason === "tampered",
    identityMismatch: reason === "identityMismatch",
    freshDevice: reason === "freshDevice",
    scanCount: 0,
    ageSeconds: 0,
    distinctIpCount: 0,
    distinctCountryCount: 0,
    distinctNetClassCount: 0,
    distinctCpiCount: 0,
    distinctUaCount: 0,
    recent5MinCount: 0,
    recent1HourCount: 0,
    recent24HourCount: 0,
  };
}

function distinctCountOf<T>(values: (T | null | undefined)[]): number {
  const set = new Set<T>();
  for (const v of values) if (v != null) set.add(v);
  return set.size;
}

function countNewerThan(
  visits: DeviceHistoryVisit[],
  cutoffMs: number,
): number {
  let n = 0;
  for (const v of visits) if (v.t >= cutoffMs) n++;
  return n;
}

interface AnalyzeArgs {
  /** Decryption outcome from helpers/device-history. */
  outcome:
    | { kind: "ok"; blob: DeviceHistoryBlob }
    | { kind: "absent" }
    | { kind: "auth_fail" };
  /** Pubkey of the current submission's device_identity — for binding check. */
  pubkey: string | null;
  /** Server's `now` at processing time. Defaults to Date.now(). */
  now?: number;
}

/**
 * Compute recurrence signals from a decrypted blob. The current
 * submission's visit is NOT included here — call AFTER you've decided
 * to use the blob but BEFORE appending the current visit (we want
 * the signals to reflect prior history, the current row's data is
 * already on the row itself).
 */
export function computeDeviceHistoryAnalysis(
  args: AnalyzeArgs,
): DeviceHistoryAnalysis {
  const { outcome, pubkey } = args;
  const now = args.now ?? Date.now();
  if (outcome.kind === "absent") return unanalyzable("freshDevice");
  if (outcome.kind === "auth_fail") return unanalyzable("tampered");
  const { blob } = outcome;
  if (typeof pubkey === "string" && pubkey.length > 0 && blob.id !== pubkey) {
    return unanalyzable("identityMismatch");
  }
  const v = blob.visits;
  return {
    tampered: false,
    identityMismatch: false,
    freshDevice: false,
    scanCount: v.length,
    ageSeconds: Math.max(0, Math.floor((now - blob.created) / 1000)),
    distinctIpCount: distinctCountOf(v.map((x) => x.ip)),
    distinctCountryCount: distinctCountOf(v.map((x) => x.country)),
    distinctNetClassCount: distinctCountOf(v.map((x) => x.net_class)),
    distinctCpiCount: distinctCountOf(v.map((x) => x.cpi)),
    distinctUaCount: distinctCountOf(v.map((x) => x.ua_hash)),
    recent5MinCount: countNewerThan(v, now - 5 * 60 * 1000),
    recent1HourCount: countNewerThan(v, now - 60 * 60 * 1000),
    recent24HourCount: countNewerThan(v, now - 24 * 60 * 60 * 1000),
  };
}
