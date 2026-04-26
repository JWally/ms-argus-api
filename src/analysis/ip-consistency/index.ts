/**
 * IP consistency analysis for integrity ingestion.
 *
 * Compares IP addresses observed across independent channels:
 * - API Gateway (X-Forwarded-For) — client-editable
 * - TLS fingerprint edge (CloudFront)
 * - TCP probe (EC2)
 * - WebRTC STUN — MAC-verified authentic client IP via our own STUN
 *
 * Produces:
 *  - Anomaly signals (WEBRTC_IP_MISMATCH, SAME_SUBNET_CGNAT,
 *    IP_PROBE_SCATTER, WEBRTC_SIGINT_FORGERY, WEBRTC_BLOCKED, ASN-category).
 *  - `integrity` score 0.0–1.0 — narrow network-trust gauge. Separate from
 *    the global risk_score. Tiers are discrete: see `computeIntegrityScore`.
 *  - `ip` — one representative client IP, surfaced only when integrity ≥ 0.5.
 *    Prefers the MAC-verified WebRTC IP; falls back to tls/tcp consensus.
 *    Never surfaced at 0.0 (forgery) or 0.1 (/16 mismatch) — either we
 *    don't trust the value or which of the conflicting IPs to expose is
 *    ambiguous.
 */

import {
  AnomalyCodes,
  createSignal,
  type AnomalySignal,
} from "../../services/profile/anomaly/types";
import { lookupAsn, type AsnCategory } from "./asn-catalog";
import {
  classifyAsnSync,
  type NetworkCategory,
} from "../../services/network/asn-classifier";
import { lookupCidrOverlay } from "../../services/network/cidr-overlay";
import { lookupAutoOverlaySync } from "../../services/network/auto-overlay";
import {
  deriveNetworkId,
  type NetworkIdSource,
} from "../../services/network/network-id";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** MAC-verified WebRTC evidence fed in from the sigint-v6-decode path. */
export interface WebrtcSigintEvidence {
  /** Decoded client IP when MAC was valid and payload was fresh, else null. */
  ip: string | null;
  /** True when sigintCandidates were submitted but HMAC verification failed. */
  forgery: boolean;
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
    /**
     * Broader consumer-network classification from the dynamic IPtoASN+regex
     * dataset (built weekly by ip-class-builder Lambda). Distinguishes
     * residential vs mobile vs datacenter etc., including within mixed-use
     * ASNs like AT&T 7018. Null when the ASN isn't in the dataset.
     */
    network_class: NetworkCategory | null;
  };
  /**
   * Network-derived stable user ID. Backup identifier when crypto_device_id
   * and tpc_id aren't available. See services/network/network-id.ts.
   * Computed only when `userAgent` is passed to analyzeIpConsistency.
   */
  network_id: string | null;
  network_id_source: NetworkIdSource;
  checks: {
    probesConsistent: boolean;
    webrtcMatchesProbes: boolean | null;
  };
  /** Discrete 0.0–1.0 network-trust score. See computeIntegrityScore. */
  integrity: number;
  /**
   * Representative client IP. MAC-verified WebRTC IP when available; else
   * the tls/tcp consensus. Null at integrity < 0.5 or when no trusted
   * source is available.
   */
  ip: string | null;
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

function webrtcAvailable(device: unknown): boolean {
  if (!isObj(device)) return false;
  return isObj(device.webrtc) && device.webrtc !== null;
}

const WEBRTC_IP_FIELD = "analysis.webrtc_sigint.ip";
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

/** Every IP in the set falls in the same /16. Empty set returns true. */
function allSameSubnet16(ips: string[]): boolean {
  if (ips.length < 2) return true;
  const ref = parseIpv4(ips[0]);
  if (!ref) return false;
  return ips.every((ip) => {
    const o = parseIpv4(ip);
    return o !== null && o[0] === ref[0] && o[1] === ref[1];
  });
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

function checkForgery(forgery: boolean): AnomalySignal | null {
  if (!forgery) return null;
  return createSignal("NETWORK", AnomalyCodes.WEBRTC_SIGINT_FORGERY, 0.9, {
    expected: "STUN response HMAC verifies against shared secret",
    actual: "sigint candidate submitted but MAC invalid — forged or spoofed",
    fields: [WEBRTC_IP_FIELD],
  });
}

/**
 * Resolve the broader `network_class` for an IP+ASN pair. Resolution order
 * (most authoritative first):
 *
 *   1. Hand-curated CIDR overlay (cidr-overlay.ts) — small, manually-vetted
 *      rules for known mixed-use ASNs (AT&T 7018, T-Mobile cellular blocks,
 *      etc.). Wins because it's the most-vetted source.
 *   2. Auto-discovered overlay (auto-overlay.ts) — S3-loaded rules
 *      populated by the nightly ip-class-discoverer Lambda from RDAP
 *      lookups. Covers the long tail and international carriers without
 *      hand maintenance.
 *   3. Dynamic IPtoASN dataset (asn-classifier) — regex-on-org-name +
 *      manual overrides, ~3000 ASNs classified at ASN granularity.
 *   4. Legacy AsnCategory from the static catalog — pre-existing classifier
 *      kept for backwards compat with checkAsnCategory + vpnByCategory.
 *
 * Tries each candidate IP for the CIDR-based layers (1, 2) so that a
 * proxied session leaking an off-network IP via webrtc still classifies
 * based on the server-observed probe IPs that ARE in the overlay.
 */
function classifyByHandCuratedOverlay(
  ips: (string | null)[],
): NetworkCategory | null {
  for (const ip of ips) {
    if (!ip) continue;
    const hit = lookupCidrOverlay(ip);
    if (hit) return hit.category;
  }
  return null;
}

function classifyByAutoOverlay(ips: (string | null)[]): NetworkCategory | null {
  for (const ip of ips) {
    if (!ip) continue;
    const hit = lookupAutoOverlaySync(ip);
    if (hit) return hit.category;
  }
  return null;
}

function classifyByDynamicDict(asn: string | null): NetworkCategory | null {
  if (!asn) return null;
  const dynamic = classifyAsnSync(Number(asn));
  return dynamic === "unknown" ? null : dynamic;
}

function classifyByLegacyCatalog(
  legacyCategory: AsnCategory | undefined,
): NetworkCategory | null {
  if (legacyCategory === "corporate_proxy") return "security_filter";
  return legacyCategory ?? null;
}

function deriveNetworkClass(
  asn: string | null,
  ips: (string | null)[],
  legacyCategory: AsnCategory | undefined,
): NetworkCategory | null {
  return (
    classifyByHandCuratedOverlay(ips) ??
    classifyByAutoOverlay(ips) ??
    classifyByDynamicDict(asn) ??
    classifyByLegacyCatalog(legacyCategory)
  );
}

function checkAsnCategory(asn: string | null): AnomalySignal | null {
  const entry = lookupAsn(asn);
  if (!entry) return null;

  const severityMap: Partial<Record<AsnCategory, number>> = {
    datacenter: 0.7,
    vpn_proxy: 0.6,
    corporate_proxy: 0.15,
    // mobile: no anomaly — mobile is context, not a threat
  };
  const severity = severityMap[entry.category];
  if (severity === undefined) return null;

  return createSignal("NETWORK", AnomalyCodes.IP_PROBE_SCATTER, severity, {
    expected: "residential ISP ASN",
    actual: `ASN ${asn} — ${entry.org} (${entry.category})`,
    fields: ["sigint.aws_cf.asn"],
  });
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
  forgery: boolean,
): AnomalySignal[] {
  const out: AnomalySignal[] = [];
  const forgerySig = checkForgery(forgery);
  if (forgerySig) out.push(forgerySig);
  if (webrtcIp) {
    const sig = checkWebrtcVsProbes(webrtcIp, probeIps);
    if (sig) out.push(sig);
    return out;
  }
  // No MAC-verified webrtc evidence to compare with. If the client didn't
  // submit a webrtc block at all, emit WEBRTC_BLOCKED (low severity context).
  // When forgery was emitted the device.webrtc block is present, so this
  // won't double-fire.
  const blocked = checkWebrtcBlocked(device);
  if (blocked) out.push(blocked);
  return out;
}

/**
 * Count IP occurrences and return the sorted bucket sizes + webrtc's bucket.
 */
function bucketStats(
  all: string[],
  webrtcIp: string,
): { buckets: number[]; webrtcCount: number; distinct: number } {
  const counts = new Map<string, number>();
  for (const ip of all) counts.set(ip, (counts.get(ip) ?? 0) + 1);
  return {
    buckets: [...counts.values()].sort((a, b) => b - a),
    webrtcCount: counts.get(webrtcIp) ?? 0,
    distinct: counts.size,
  };
}

function scoreFour(
  buckets: number[],
  webrtcCount: number,
  distinct: number,
): number {
  if (buckets[0] === 3 && buckets[1] === 1) {
    return webrtcCount === 1 ? 1.0 : 0.8;
  }
  if (buckets[0] === 2 && buckets[1] === 2) return 0.7;
  if (distinct === 3) return 0.6;
  return 0.5; // 4 distinct
}

function scoreThree(buckets: number[], webrtcCount: number): number {
  if (buckets[0] === 2 && buckets[1] === 1) {
    return webrtcCount === 1 ? 1.0 : 0.8;
  }
  return 0.5; // 3 distinct
}

/**
 * Compute the discrete network-integrity score. Tiers:
 *
 *   0.0 — WebRTC sigint forgery (cryptographic evidence of tampering).
 *   0.1 — Any IP lies on a different /16 than the majority.
 *   0.5 — No WebRTC evidence submitted (merchant cross-correlates w/ ASN).
 *   0.5 — All 4 IPs distinct but within the same /16 (heavy CGNAT).
 *   0.6 — 3 distinct IPs (2+1+1 pattern) within one /16.
 *   0.7 — 2+2 split within one /16.
 *   0.8 — 3+1 split where the solo IP is NOT webrtc (probe scatter).
 *   1.0 — All IPs identical, OR 3+1 split where the solo IP IS webrtc
 *         (classic mobile-CGNAT NAT mapping — benign).
 *
 * With fewer than 4 signals (e.g. tcp probe missing), tiers collapse
 * sensibly: the same counting logic applies and fully-distinct sets
 * land at 0.5.
 */
function computeIntegrityScore(
  probeIps: (string | null)[],
  webrtcIp: string | null,
  forgery: boolean,
): number {
  if (forgery) return 0.0;
  if (!webrtcIp) return 0.5;

  const probes = probeIps.filter((x): x is string => x !== null);
  const all = [...probes, webrtcIp];
  if (all.length < 2) return 0.5;
  if (!allSameSubnet16(all)) return 0.1;

  const { buckets, webrtcCount, distinct } = bucketStats(all, webrtcIp);
  if (distinct === 1) return 1.0;
  if (all.length === 4) return scoreFour(buckets, webrtcCount, distinct);
  if (all.length === 3) return scoreThree(buckets, webrtcCount);
  return 0.7; // exactly 2 present, both different — treat as 2+2-ish
}

/**
 * Pick the IP to surface externally (merchant projection).
 * Only called when the caller has decided it's trustworthy to surface.
 * Prefers the MAC-verified webrtc IP; falls back to tls (CloudFront), then
 * tcp probe, then X-Forwarded-For last (client-editable).
 */
function pickSurfaceIp(
  webrtcIp: string | null,
  tlsIp: string | null,
  tcpIp: string | null,
  apiIp: string | null,
): string | null {
  return webrtcIp ?? tlsIp ?? tcpIp ?? apiIp;
}

/**
 * Analyze IP consistency across probes and WebRTC.
 *
 * `webrtcSigint` carries the MAC-verified client IP decoded from our
 * STUN response (and a `forgery` flag when HMAC verification failed).
 * When absent or null, analysis falls back to signals based on probes only.
 */
interface IpSignalInputs {
  device: unknown;
  webrtcIp: string | null;
  probeIps: (string | null)[];
  forgery: boolean;
  asn: string | null;
}

function gatherIpSignals(input: IpSignalInputs): AnomalySignal[] {
  const { device, webrtcIp, probeIps, forgery, asn } = input;
  const signals: AnomalySignal[] = [];
  const scatter = checkProbeScatter(probeIps);
  if (scatter) signals.push(scatter);
  signals.push(...collectWebrtcSignals(device, webrtcIp, probeIps, forgery));
  const asnSig = checkAsnCategory(asn);
  if (asnSig) signals.push(asnSig);
  return signals;
}

function buildAsnBlock(
  asn: string | null,
  candidateIps: (string | null)[],
): IpConsistencyResult["asn"] {
  const asnEntry = lookupAsn(asn);
  return {
    number: asn,
    category: asnEntry?.category ?? (asn ? "residential" : null),
    org: asnEntry?.org ?? null,
    network_class: deriveNetworkClass(asn, candidateIps, asnEntry?.category),
  };
}

function buildNetworkId(opts: {
  asn: string | null;
  networkClass: NetworkCategory | null;
  ip: string | null;
  userAgent: string | null | undefined;
}): { id: string | null; source: NetworkIdSource } {
  if (!opts.userAgent) return { id: null, source: "none" };
  return deriveNetworkId({
    asn: opts.asn ? Number(opts.asn) : null,
    networkClass: opts.networkClass,
    ip: opts.ip,
    userAgent: opts.userAgent,
  });
}

// eslint-disable-next-line max-params -- optional 5th param (UA) enables network_id derivation; refactoring the public signature would ripple through ~30 call sites
export function analyzeIpConsistency(
  device: unknown,
  sigint: unknown,
  clientIp: string,
  webrtcSigint?: WebrtcSigintEvidence,
  userAgent?: string | null,
): IpConsistencyResult {
  const apiIp = str(clientIp);
  const tlsIp = extractTlsIp(sigint);
  const tcpIp = extractTcpIp(sigint);
  const webrtcIp = webrtcSigint?.ip ?? null;
  const forgery = webrtcSigint?.forgery ?? false;
  const asn = extractAsn(sigint);
  const probeIps = [apiIp, tlsIp, tcpIp];

  const signals = gatherIpSignals({
    device,
    webrtcIp,
    probeIps,
    forgery,
    asn,
  });
  const integrity = computeIntegrityScore(probeIps, webrtcIp, forgery);
  const surfaceIp =
    integrity >= 0.5 ? pickSurfaceIp(webrtcIp, tlsIp, tcpIp, apiIp) : null;
  const asnBlock = buildAsnBlock(asn, [webrtcIp, tlsIp, tcpIp, apiIp]);
  const networkId = buildNetworkId({
    asn,
    networkClass: asnBlock.network_class,
    ip: surfaceIp ?? webrtcIp ?? tlsIp ?? tcpIp ?? apiIp,
    userAgent,
  });
  const probesConsistent = !signals.some(
    (s) => s.code === AnomalyCodes.IP_PROBE_SCATTER,
  );
  const webrtcMatchesProbes = webrtcIp
    ? !signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH)
    : null;

  return {
    lied: signals.some((s) => s.severity >= 0.5),
    ips: { api: apiIp, tls: tlsIp, tcp: tcpIp, webrtc: webrtcIp },
    asn: asnBlock,
    network_id: networkId.id,
    network_id_source: networkId.source,
    checks: { probesConsistent, webrtcMatchesProbes },
    integrity,
    ip: surfaceIp,
    signals: formatSignals(signals),
  };
}
