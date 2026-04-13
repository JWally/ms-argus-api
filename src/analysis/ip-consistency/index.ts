/**
 * IP consistency analysis for integrity ingestion.
 *
 * Compares IP addresses observed across independent channels:
 * - API Gateway (X-Forwarded-For)
 * - TLS fingerprint edge (CloudFront)
 * - TCP probe (EC2)
 * - WebRTC STUN (client-side, bypasses HTTP proxies)
 *
 * Subnet-aware: WebRTC on the same /16 as probes is likely cellular
 * CGNAT, not a proxy. Different subnet = real mismatch.
 *
 * ASN classification: known datacenter, VPN, or corporate proxy ASNs
 * are flagged with appropriate severity.
 */

import {
  AnomalyCodes,
  createSignal,
  type AnomalySignal,
} from "../../services/profile/anomaly/types";
import { lookupAsn, type AsnCategory } from "./asn-catalog";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

export interface IpConsistencyResult {
  lied: boolean;
  ips: {
    api: string | null;
    tls: string | null;
    tcp: string | null;
    webrtc: string | null;
  };
  asn: {
    number: string | null;
    category: AsnCategory | "residential" | null;
    org: string | null;
  };
  checks: {
    probesConsistent: boolean;
    webrtcMatchesProbes: boolean | null;
  };
  signals: Array<{ code: string; severity: number; evidence: string }>;
}

function extractTlsIp(sigint: unknown): string | null {
  if (!isObj(sigint) || !isObj(sigint.aws_cf)) return null;
  const direct = str(sigint.aws_cf.ip);
  if (direct) return direct;
  return isObj(sigint.aws_cf.data) ? str(sigint.aws_cf.data.ip) : null;
}

function extractAsn(sigint: unknown): string | null {
  if (!isObj(sigint) || !isObj(sigint.aws_cf)) return null;
  const direct = str(sigint.aws_cf.asn);
  if (direct) return direct;
  return isObj(sigint.aws_cf.data) ? str(sigint.aws_cf.data.asn) : null;
}

function extractTcpIp(sigint: unknown): string | null {
  if (!isObj(sigint)) return null;
  const tcp = sigint.tcp_probe;
  return isObj(tcp) ? str(tcp.client_ip) : null;
}

function extractWebrtcIp(device: unknown): string | null {
  if (!isObj(device)) return null;
  const webrtc = device.webrtc;
  if (!isObj(webrtc)) return null;
  const ice = webrtc.iceCandidates;
  return isObj(ice) ? str(ice.publicIP) : null;
}

function webrtcAvailable(device: unknown): boolean {
  if (!isObj(device)) return false;
  return isObj(device.webrtc) && device.webrtc !== null;
}

// Field paths used in anomaly-signal metadata — extracted so sonarjs's
// duplicate-literal rule doesn't trip across the multiple emit sites.
const WEBRTC_IP_FIELD = "device.webrtc.iceCandidates.publicIP";
const CF_IP_FIELD = "sigint.aws_cf.ip";
const TCP_PROBE_IP_FIELD = "sigint.tcp_probe.client_ip";

/** Parse IPv4 into 4 octets. Returns null for non-IPv4. */
function parseIpv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) return null;
  return octets;
}

/** Check if two IPs share the same /16 subnet. */
function sameSubnet16(a: string, b: string): boolean {
  const oa = parseIpv4(a);
  const ob = parseIpv4(b);
  if (!oa || !ob) return false;
  return oa[0] === ob[0] && oa[1] === ob[1];
}

function checkProbeScatter(probeIps: (string | null)[]): AnomalySignal | null {
  const present = probeIps.filter((ip): ip is string => ip !== null);
  if (present.length < 2) return null;
  const unique = [...new Set(present)];
  if (unique.length <= 1) return null;

  const severity = unique.length >= 3 ? 0.8 : 0.6;
  return createSignal("NETWORK", AnomalyCodes.IP_PROBE_SCATTER, severity, {
    expected: "all probes observe same IP",
    actual: `${unique.length} distinct IPs: ${unique.join(", ")}`,
    fields: ["client_ip", CF_IP_FIELD, TCP_PROBE_IP_FIELD],
  });
}

function checkWebrtcVsProbes(
  webrtcIp: string,
  probeIps: (string | null)[],
): AnomalySignal | null {
  const present = probeIps.filter((ip): ip is string => ip !== null);
  if (present.length === 0) return null;
  if (present.includes(webrtcIp)) return null;

  // Same /16 subnet = very likely CGNAT or cellular carrier NAT, not a
  // proxy. Emit a positive SAME_SUBNET_CGNAT signal instead of silently
  // suppressing — downstream consumers (dashboards, demo UI) use it to
  // label the visitor as mobile/CGNAT. Low severity because it's a
  // benign classification, not a threat.
  const sameSubnet = present.some((ip) => sameSubnet16(webrtcIp, ip));
  if (sameSubnet) {
    return createSignal("NETWORK", AnomalyCodes.SAME_SUBNET_CGNAT, 0.1, {
      expected: "positive indicator, not a threat",
      actual: `webrtc=${webrtcIp} vs probes=${[...new Set(present)].join(", ")} — same /16 (CGNAT/cellular)`,
      fields: [WEBRTC_IP_FIELD, CF_IP_FIELD, TCP_PROBE_IP_FIELD],
    });
  }

  return createSignal("NETWORK", AnomalyCodes.WEBRTC_IP_MISMATCH, 0.7, {
    expected: "WebRTC IP matches server-observed IP",
    actual: `webrtc=${webrtcIp} vs probes=${[...new Set(present)].join(", ")}`,
    fields: [WEBRTC_IP_FIELD, CF_IP_FIELD, TCP_PROBE_IP_FIELD],
  });
}

function checkWebrtcBlocked(device: unknown): AnomalySignal | null {
  if (webrtcAvailable(device)) return null;
  return createSignal("CROSS_FIELD", AnomalyCodes.WEBRTC_BLOCKED, 0.2, {
    expected: "WebRTC available",
    actual: "WebRTC blocked or unavailable",
    fields: ["device.webrtc"],
  });
}

function checkAsnCategory(asn: string | null): AnomalySignal | null {
  const entry = lookupAsn(asn);
  if (!entry) return null;

  const severityMap: Record<AsnCategory, number> = {
    datacenter: 0.7,
    vpn_proxy: 0.6,
    corporate_proxy: 0.15,
  };

  return createSignal(
    "NETWORK",
    AnomalyCodes.IP_PROBE_SCATTER,
    severityMap[entry.category],
    {
      expected: "residential ISP ASN",
      actual: `ASN ${asn} — ${entry.org} (${entry.category})`,
      fields: ["sigint.aws_cf.asn"],
    },
  );
}

function formatSignals(
  signals: AnomalySignal[],
): IpConsistencyResult["signals"] {
  return signals.map((s) => ({
    code: s.code,
    severity: s.severity,
    evidence: s.evidence.actual,
  }));
}

function collectWebrtcSignals(
  device: unknown,
  webrtcIp: string | null,
  probeIps: (string | null)[],
): AnomalySignal[] {
  if (webrtcIp) {
    const sig = checkWebrtcVsProbes(webrtcIp, probeIps);
    return sig ? [sig] : [];
  }
  const blocked = checkWebrtcBlocked(device);
  return blocked ? [blocked] : [];
}

/**
 * Analyze IP consistency across probes and WebRTC.
 */
export function analyzeIpConsistency(
  device: unknown,
  sigint: unknown,
  clientIp: string,
): IpConsistencyResult {
  const apiIp = str(clientIp);
  const tlsIp = extractTlsIp(sigint);
  const tcpIp = extractTcpIp(sigint);
  const webrtcIp = extractWebrtcIp(device);
  const asn = extractAsn(sigint);
  const probeIps = [apiIp, tlsIp, tcpIp];

  const signals: AnomalySignal[] = [];
  const scatterSig = checkProbeScatter(probeIps);
  if (scatterSig) signals.push(scatterSig);
  signals.push(...collectWebrtcSignals(device, webrtcIp, probeIps));
  const asnSig = checkAsnCategory(asn);
  if (asnSig) signals.push(asnSig);

  const asnEntry = lookupAsn(asn);

  return {
    lied: signals.some((s) => s.severity >= 0.5),
    ips: { api: apiIp, tls: tlsIp, tcp: tcpIp, webrtc: webrtcIp },
    asn: {
      number: asn,
      category: asnEntry?.category ?? (asn ? "residential" : null),
      org: asnEntry?.org ?? null,
    },
    checks: {
      probesConsistent: !scatterSig,
      webrtcMatchesProbes: webrtcIp
        ? !signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH)
        : null,
    },
    signals: formatSignals(signals),
  };
}
