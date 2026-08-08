import {
  MERCHANT_PROJECTION_SCHEMA_VERSION,
  type MerchantProjectionSchemaVersion,
} from "../contracts/merchant-projection";
import {
  deriveIpVelocity,
  type IpVelocityProjection,
} from "../projections/activity";
import {
  deriveNetworkProjection,
  type MerchantIpInfo,
  type MerchantIpLocation,
} from "../projections/network";
import { networkTamperingScore, vpnScore } from "../scoring/network-tampering";
import {
  detectNoWebrtc,
  probabilityFromUnit,
  type MerchantProjectionInput,
} from "../scoring/shared";

export type ProxyMerchantTag =
  | "vpn"
  | "proxy"
  | "hyperscaler"
  | "corporate_shield"
  | "privacy_relay"
  | "cellular"
  | "no_webrtc";

export interface ProxyMerchantSafeResponse {
  schema_version: MerchantProjectionSchemaVersion;
  product: "proxy_v1";
  session_id: string;
  created_at: number | null;
  ttl: number | null;
  network_tampering: number;
  verdict: "clean" | "suspect" | "block";
  identification: {
    client_uuid: string | null;
    network_id: string | null;
    network_id_source: "category_residential" | "asn_fallback" | "none";
  };
  ip: string | null;
  ipLocation: MerchantIpLocation;
  ipInfo: MerchantIpInfo;
  tags: ProxyMerchantTag[];
  ip_velocity_1h: IpVelocityProjection | null;
}

function verdict(score: number): ProxyMerchantSafeResponse["verdict"] {
  if (score >= 70) return "block";
  if (score >= 30) return "suspect";
  return "clean";
}

function clientUuid(input: MerchantProjectionInput): string | null {
  const value = (
    input.integrity?.device as { client_uuid?: unknown } | undefined
  )?.client_uuid;
  return typeof value === "string" && value.length > 0 ? value : null;
}

function identification(
  input: MerchantProjectionInput,
): ProxyMerchantSafeResponse["identification"] {
  const ip = input.integrity?.analysis.ip;
  return {
    client_uuid: clientUuid(input),
    network_id: ip?.network_id ?? null,
    network_id_source:
      (ip?.network_id_source as
        | "category_residential"
        | "asn_fallback"
        | "none"
        | undefined) ?? "none",
  };
}

function tags(
  input: MerchantProjectionInput,
  ipInfo: MerchantIpInfo,
): ProxyMerchantTag[] {
  const result: ProxyMerchantTag[] = [];
  if (probabilityFromUnit(vpnScore(input)) >= 50) result.push("vpn");
  if ((input.integrity?.analysis.proxy_waterfall?.threat_score ?? 0) >= 50) {
    result.push("proxy");
  }
  if (ipInfo.datacenter.result) result.push("hyperscaler");
  if (ipInfo.corporate_shield.result) result.push("corporate_shield");
  if (ipInfo.privacy_relay.result) result.push("privacy_relay");
  if (ipInfo.mobile.result) result.push("cellular");
  if (detectNoWebrtc(input)) result.push("no_webrtc");
  return result;
}

/** Exact allow-list for the reduced network-only merchant product. */
export function buildProxyMerchantResponse(
  input: MerchantProjectionInput,
): ProxyMerchantSafeResponse {
  const network = deriveNetworkProjection(input);
  const score = networkTamperingScore(input);
  return {
    schema_version: MERCHANT_PROJECTION_SCHEMA_VERSION,
    product: "proxy_v1",
    session_id: input.session_id,
    created_at: input.integrity?.created_at ?? null,
    ttl: (input.integrity as { ttl?: number } | undefined)?.ttl ?? null,
    network_tampering: score,
    verdict: verdict(score),
    identification: identification(input),
    ...network,
    tags: tags(input, network.ipInfo),
    ip_velocity_1h: deriveIpVelocity(input),
  };
}
