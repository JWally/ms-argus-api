/**
 * Merchant-facing projection of temporal activity signals.
 *
 * Ingestion owns collection and analysis; this module owns the deliberately
 * smaller public view. Keeping these mappers together prevents the main
 * merchant projection orchestrator from knowing the storage shape of the
 * device-history and IP-velocity records.
 */
import type { MerchantProjectionInput } from "../scoring/shared";

export interface IpVelocityProjection {
  /** Hour bucket label, e.g. "1h:2026052914". */
  bucket: string;
  /** Total submissions on this IP in this hour. */
  hits: number;
  /** Submissions that ended verdict=block. */
  blocked: number;
  /** Estimated distinct device pubkeys seen on this IP in this hour. */
  distinct_devices_est: number;
  /** blocked / hits when hits > 0, else 0. */
  block_rate: number;
  /** Residential IP with more than ten distinct devices in the hour. */
  residential_proxy_suspect: boolean;
  /** Epoch ms when this IP first appeared in this hour bucket. */
  first_seen_ms: number;
  /** Epoch ms of the most recent session on this IP in this hour bucket. */
  last_seen_ms: number;
}

export interface MerchantDeviceHistory {
  /** The client supplied a blob whose AES-GCM authentication failed. */
  tampered: boolean;
  /** The blob was valid but belonged to another device identity. */
  identityMismatch: boolean;
  /** The client supplied no prior history blob. */
  freshDevice: boolean;
  scanCount: number;
  ageSeconds: number;
  distinctIpCount: number;
  distinctCountryCount: number;
  distinctNetClassCount: number;
  recent5MinCount: number;
  recent1HourCount: number;
  recent24HourCount: number;
}

function numField(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/** Project encrypted device-history aggregates without exposing visits. */
export function deriveDeviceHistory(
  input: MerchantProjectionInput,
): MerchantDeviceHistory | null {
  const history = (
    input.integrity?.analysis as
      | { device_history?: Record<string, unknown> }
      | undefined
  )?.device_history;
  if (!history || typeof history !== "object") return null;
  return {
    tampered: history.tampered === true,
    identityMismatch: history.identityMismatch === true,
    freshDevice: history.freshDevice === true,
    scanCount: numField(history, "scanCount"),
    ageSeconds: numField(history, "ageSeconds"),
    distinctIpCount: numField(history, "distinctIpCount"),
    distinctCountryCount: numField(history, "distinctCountryCount"),
    distinctNetClassCount: numField(history, "distinctNetClassCount"),
    recent5MinCount: numField(history, "recent5MinCount"),
    recent1HourCount: numField(history, "recent1HourCount"),
    recent24HourCount: numField(history, "recent24HourCount"),
  };
}

/** Project the stored hourly IP-velocity snapshot and derived conveniences. */
export function deriveIpVelocity(
  input: MerchantProjectionInput,
): IpVelocityProjection | null {
  const raw = (input.integrity as { ip_velocity_1h?: unknown } | undefined)
    ?.ip_velocity_1h;
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Record<string, unknown>;
  const hits = numField(record, "hits");
  if (hits <= 0) return null;
  const blocked = numField(record, "blocked");
  const distinct = numField(record, "distinct_devices_est");
  const asnCategory = input.integrity?.analysis?.ip?.asn?.category;
  return {
    bucket: typeof record.bucket === "string" ? record.bucket : "",
    hits,
    blocked,
    distinct_devices_est: distinct,
    block_rate: Math.round((blocked / hits) * 10000) / 10000,
    residential_proxy_suspect: asnCategory === "residential" && distinct > 10,
    first_seen_ms: numField(record, "first_seen_ms"),
    last_seen_ms: numField(record, "last_seen_ms"),
  };
}
