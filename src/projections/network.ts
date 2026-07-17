/** Merchant-safe projection of IP, location, ASN, and network integrity. */
import { readJa4UaSignals } from "../scoring/identity";
import {
  detectCorporateShield,
  type MerchantProjectionInput,
} from "../scoring/shared";

export interface MerchantIpLocation {
  city: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
}

export interface MerchantIpInfo {
  asn: {
    number: number | null;
    organization: string | null;
    /** Legacy categorization retained for existing integrations. */
    category: string | null;
    /** Broader consumer-network taxonomy; prefer this for routing. */
    network_class: string | null;
    /** Sparse RDAP and PeeringDB enrichment; treat as a hint. */
    metadata: {
      parent_org?: string;
      customer_org?: string;
      pdb_type?: string;
      ix_count?: number;
    } | null;
  };
  /** Convenience booleans derived only from `asn.network_class`. */
  datacenter: { result: boolean };
  mobile: { result: boolean };
  residential: { result: boolean };
  vpn: { result: boolean };
  hosting: { result: boolean };
  privacy_relay: { result: boolean };
  corporate_shield: { result: boolean };
}

export interface AwsCfSigint {
  asn?: string | null;
  country?: string | null;
  city?: string | null;
  lat?: string | null;
  lon?: string | null;
  tz?: string | null;
  ip?: string | null;
  ts?: number | null;
  id?: string | null;
  issuedAt?: number | null;
  cookieTampered?: boolean | null;
  cookieMatchesToken?: boolean | null;
}

export function readAwsCf(
  input: MerchantProjectionInput,
): AwsCfSigint | undefined {
  return (input.integrity?.sigint as { aws_cf?: AwsCfSigint } | undefined)
    ?.aws_cf;
}

function parseAsnNumber(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const number = Number(String(raw).replace(/^AS/i, ""));
  return Number.isFinite(number) && number > 0 ? number : null;
}

function toFloat(raw: string | number | null | undefined): number | null {
  if (raw === null || raw === undefined || raw === "") return null;
  const number = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(number) ? number : null;
}

function deriveIpLocation(input: MerchantProjectionInput): MerchantIpLocation {
  const awsCf = readAwsCf(input);
  return {
    city: awsCf?.city ?? null,
    country: awsCf?.country ?? null,
    latitude: toFloat(awsCf?.lat),
    longitude: toFloat(awsCf?.lon),
    timezone: awsCf?.tz ?? null,
  };
}

type NetworkFlags = Omit<MerchantIpInfo, "asn">;

/** Keep every routing flag on the broader taxonomy's single source of truth. */
function deriveNetworkFlags(networkClass: string | null): NetworkFlags {
  return {
    datacenter: { result: networkClass === "datacenter" },
    mobile: { result: networkClass === "mobile" },
    residential: { result: networkClass === "residential" },
    vpn: { result: networkClass === "vpn_proxy" },
    hosting: { result: networkClass === "hosting_proxy" },
    privacy_relay: { result: networkClass === "privacy_relay" },
    corporate_shield: { result: networkClass === "security_filter" },
  };
}

function deriveIpInfo(input: MerchantProjectionInput): MerchantIpInfo {
  const asn = input.integrity?.analysis?.ip?.asn;
  if (asn) {
    const networkClass = asn.network_class ?? null;
    return {
      asn: {
        number: parseAsnNumber(asn.number),
        organization: asn.org,
        category: asn.category,
        network_class: networkClass,
        metadata: asn.metadata ?? null,
      },
      ...deriveNetworkFlags(networkClass),
    };
  }
  const awsCf = readAwsCf(input);
  return {
    asn: {
      number: parseAsnNumber(awsCf?.asn),
      organization: null,
      category: null,
      network_class: null,
      metadata: null,
    },
    ...deriveNetworkFlags(null),
  };
}

export interface MerchantNetworkProjection {
  ip: string | null;
  ipLocation: MerchantIpLocation;
  ipInfo: MerchantIpInfo;
}

export function deriveNetworkProjection(
  input: MerchantProjectionInput,
): MerchantNetworkProjection {
  return {
    ip: input.integrity?.analysis?.ip?.ip ?? readAwsCf(input)?.ip ?? null,
    ipLocation: deriveIpLocation(input),
    ipInfo: deriveIpInfo(input),
  };
}

function hasSignalCode(
  signals: Array<{ code: string }> | undefined,
  code: string,
): boolean {
  return !!signals?.some((signal) => signal.code === code);
}

const NON_PRIVACY_CATEGORIES = new Set([
  "datacenter",
  "hosting",
  "proxy",
  "vpn",
]);

function applyProxyVpnDowngrade(
  input: MerchantProjectionInput,
  score: number,
): number {
  const proxy = input.integrity?.analysis.network.proxy_component ?? 0;
  const vpn = input.integrity?.analysis.network.vpn_component ?? 0;
  return score * (1 - proxy) * (1 - vpn);
}

function applyWebrtcBlockedPenalty(
  input: MerchantProjectionInput,
  score: number,
): number {
  const blocked = hasSignalCode(
    input.integrity?.analysis.ip.signals,
    "WEBRTC_BLOCKED",
  );
  if (!blocked) return score;
  const category = input.integrity?.analysis.ip.asn.category;
  if (!category || !NON_PRIVACY_CATEGORIES.has(category)) return score;
  return score * 0.5;
}

/**
 * Internal network-evidence score retained for compatibility and focused
 * tests. Hard forgery and TLS mismatch survive corporate-shield treatment;
 * proxy, VPN, and WebRTC penalties apply only outside known benign gateways.
 */
export function computeNetworkIntegrityScore(
  input: MerchantProjectionInput,
  rawScore: number,
): number {
  if (rawScore === 0) return 0;
  const shielded = detectCorporateShield(input);
  let score = shielded ? 1 : rawScore;
  if (input.integrity && readJa4UaSignals(input.integrity).strongMismatch) {
    score = Math.min(score, 0.2);
  }
  if (!shielded) {
    score = applyProxyVpnDowngrade(input, score);
    score = applyWebrtcBlockedPenalty(input, score);
  }
  return Math.max(0, Math.min(1, score));
}
