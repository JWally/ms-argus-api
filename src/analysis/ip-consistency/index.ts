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
  lookupAsnOrgSync,
  lookupAsnPdbSync,
  type AsnPdbInfo,
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

/**
 * Optional enrichment surfaced alongside the ASN block. None of these fields
 * feed risk scoring today — they're context for merchant dashboards and
 * investigation tooling. Drawn from two passive sources:
 *
 *   - Auto-discovered CIDR overlay (RDAP-walked nightly): `parent_org` is the
 *     allocation operator (e.g. "Quality Technology Services"); `customer_org`
 *     is the sub-allocated tenant ("BrowserStack") when ARIN records one.
 *   - PeeringDB join (weekly bulk pull): `pdb_type` is operator-self-declared
 *     ("NSP" / "Cable/DSL/ISP" / "Enterprise" / etc.); `ix_count` is the
 *     number of IXes the operator self-reports being present at.
 *
 * Coverage is intentionally sparse — only sessions on IPs the discoverer has
 * walked carry `parent_org`/`customer_org`; only ASNs with PeeringDB records
 * carry `pdb_type`/`ix_count`. Missing fields are omitted, not null-stamped.
 */
export interface AsnMetadata {
  parent_org?: string;
  customer_org?: string;
  pdb_type?: string;
  ix_count?: number;
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
    /**
     * Optional enrichment surfaced from the auto-discovered CIDR overlay
     * (parent/customer operators on sub-allocated blocks like BrowserStack
     * inside QTS) and the PeeringDB join (operator-self-declared type +
     * IX presence count). Present only when at least one field is known —
     * sessions on un-enriched ASNs see `metadata: null` rather than an
     * object full of nulls. Stability caveat: PeeringDB values are
     * operator-self-declared and may change between weekly rebuilds.
     */
    metadata: AsnMetadata | null;
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

/** IPv4 dotted-quad → unsigned 32-bit integer. Returns null for non-IPv4. */
function ipv4ToInt(ip: string): number | null {
  const o = parseIpv4(ip);
  if (!o) return null;
  // `* 16777216` instead of `<< 24` to avoid the 32-bit signed-int overflow
  // that would turn IPs ≥ 128.0.0.0 negative.
  return o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3];
}

function checkProbeScatter(probeIps: (string | null)[]): AnomalySignal | null {
  const present = probeIps.filter((ip): ip is string => ip !== null);
  if (present.length < 2) return null;
  const unique = [...new Set(present)];
  if (unique.length <= 1) return null;

  // Carrier-NAT pool carve-out: when all distinct probe IPs fit inside a
  // 256-IP numeric window, treat as one customer egressing through a tight
  // CGNAT pool rather than scattered probes. Drift well over 256 only
  // happens when traffic is genuinely riding two different network paths.
  const ints = unique.map(ipv4ToInt);
  if (ints.every((n): n is number => n !== null)) {
    const drift = Math.max(...ints) - Math.min(...ints);
    if (drift < 256) return null;
  }

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
 * Resolve the broader `network_class` for an IP+ASN pair.
 *
 * Resolution priority — three tiers:
 *
 *   TIER 1: First non-null IP's CIDR-layer hit (hand-curated → auto-overlay).
 *           The first IP in `ips` is the highest-priority observation
 *           (caller passes probe IPs before client-reported IPs — see
 *           analyzeIpConsistency). A CIDR hit on the high-priority IP is
 *           authoritative for both physical-link facts (mobile/satellite
 *           CIDRs) and proxy/shield identification.
 *
 *   TIER 2: ASN-level dictionaries (dynamic IPtoASN dict → legacy catalog).
 *           Run when the high-priority IP had no CIDR hit. The ASN dict
 *           knows about ~3000 ASNs at ASN granularity (Cisco Umbrella,
 *           Cloudflare, AWS, etc.) and beats a CIDR-overlay hit on a
 *           lower-priority IP.
 *
 *   TIER 3: Lower-priority IPs' CIDR hits (api/webrtc).
 *           Last resort. Useful when the ASN is unknown but a client-side
 *           IP happens to match a hand-curated mixed-use ASN rule.
 *
 * Why three tiers instead of "walk all IPs then ASN dict"?
 *
 *   Cisco Umbrella session with probe IPs in a not-yet-discovered PoP
 *   (e.g., 155.190.7.96, no auto-overlay rule yet) but apiIp/webrtcIp
 *   leaking the user's residential IP (matches AT&T 107.192.0.0/11
 *   hand-curated → residential): if we walked all IPs through CIDR before
 *   trying the ASN dict, the leaked residential IP wins and the session
 *   misclassifies as residential. Three-tier resolution lets the ASN dict
 *   (which knows 36692 → security_filter) beat the leaked residential CIDR
 *   hit, while still preserving CIDR precedence on the authoritative
 *   probe IP when one exists.
 */
function classifyIpByCidrLayers(ip: string): NetworkCategory | null {
  const hand = lookupCidrOverlay(ip);
  if (hand) return hand.category;
  const auto = lookupAutoOverlaySync(ip);
  if (auto) return auto.category;
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

function firstCidrHit(ips: (string | null)[]): {
  topPriorityHit: NetworkCategory | null;
  fallbackHit: NetworkCategory | null;
} {
  let topPriorityHit: NetworkCategory | null = null;
  let fallbackHit: NetworkCategory | null = null;
  let isFirstNonNull = true;
  for (const ip of ips) {
    if (!ip) continue;
    const hit = classifyIpByCidrLayers(ip);
    if (hit) {
      if (isFirstNonNull) topPriorityHit = hit;
      else if (fallbackHit === null) fallbackHit = hit;
    }
    isFirstNonNull = false;
  }
  return { topPriorityHit, fallbackHit };
}

function deriveNetworkClass(
  asn: string | null,
  ips: (string | null)[],
  legacyCategory: AsnCategory | undefined,
): NetworkCategory | null {
  const { topPriorityHit, fallbackHit } = firstCidrHit(ips);
  if (topPriorityHit) return topPriorityHit;
  return (
    classifyByDynamicDict(asn) ??
    fallbackHit ??
    classifyByLegacyCatalog(legacyCategory)
  );
}

interface RegistrantMeta {
  customer_org?: string;
  parent_org?: string;
}

function registrantFromAutoOverlay(ip: string): RegistrantMeta | null {
  const hit = lookupAutoOverlaySync(ip);
  if (!hit?.customerOrg && !hit?.parentOrg) return null;
  const meta: RegistrantMeta = {};
  if (hit.customerOrg) meta.customer_org = hit.customerOrg;
  if (hit.parentOrg) meta.parent_org = hit.parentOrg;
  return meta;
}

/** Look up auto-overlay metadata for the first IP that has any. Hand-curated
 *  overlay (cidr-overlay.ts) deliberately doesn't carry registrant fields —
 *  only the auto-discovered overlay does, so we skip the hand layer here. */
function firstAutoOverlayMetadata(
  ips: (string | null)[],
): RegistrantMeta | null {
  for (const ip of ips) {
    if (!ip) continue;
    const meta = registrantFromAutoOverlay(ip);
    if (meta) return meta;
  }
  return null;
}

function lookupPdbForAsn(asn: string | null): AsnPdbInfo | null {
  const n = asn ? Number(asn) : NaN;
  return Number.isFinite(n) ? lookupAsnPdbSync(n) : null;
}

function deriveAsnMetadata(
  asn: string | null,
  ips: (string | null)[],
): AsnMetadata | null {
  const cidrMeta = firstAutoOverlayMetadata(ips);
  const pdb = lookupPdbForAsn(asn);
  const meta: AsnMetadata = cidrMeta ? { ...cidrMeta } : {};
  if (pdb?.info_type) meta.pdb_type = pdb.info_type;
  if (pdb && pdb.ix_count > 0) meta.ix_count = pdb.ix_count;
  // Bail out when nothing concrete survived (e.g. PDB hit had empty type
  // and zero ix_count). Keeps the merchant-facing shape clean.
  return Object.keys(meta).length > 0 ? meta : null;
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

/**
 * Resolve the org name for an ASN. Preference ladder:
 *
 *   1. Static catalog hand-curated name — cleanest, but only ~100 ASNs.
 *   2. PeeringDB display name (post-strip) — covers ~26k ASNs with names
 *      operators chose for themselves. Strictly better than the raw
 *      BGP-derived IPtoASN name for human display: AS7018 reports
 *      "AT&T US" here vs "ATT-INTERNET4" in IPtoASN.
 *   3. IPtoASN raw — last-resort fallback for ASNs PeeringDB doesn't list
 *      (long-tail regional carriers, freshly-allocated ASNs).
 */
function resolveAsnOrg(
  asn: string | null,
  catalogOrg: string | null,
): string | null {
  if (catalogOrg) return catalogOrg;
  if (!asn) return null;
  const n = Number(asn);
  if (!Number.isFinite(n) || n <= 0) return null;
  const pdb = lookupAsnPdbSync(n);
  if (pdb?.name) return pdb.name;
  return lookupAsnOrgSync(n);
}

function buildAsnBlock(
  asn: string | null,
  candidateIps: (string | null)[],
): IpConsistencyResult["asn"] {
  const asnEntry = lookupAsn(asn);
  return {
    number: asn,
    category: asnEntry?.category ?? (asn ? "residential" : null),
    org: resolveAsnOrg(asn, asnEntry?.org ?? null),
    network_class: deriveNetworkClass(asn, candidateIps, asnEntry?.category),
    metadata: deriveAsnMetadata(asn, candidateIps),
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
  // CIDR-overlay classification walks IPs in order and returns the first
  // hit. Put server-observed probe IPs (TCP, TLS) first because those are
  // what the upstream actually sees — when a corporate proxy / VPN sits in
  // the path, the probes hit the proxy's egress (security_filter / vpn_proxy
  // CIDR), but WebRTC and the API GW see the client's local IP (the
  // residential network behind the proxy). For *classification*, the
  // proxy-side label is the security-relevant one; for *consistency*, the
  // mismatch itself is what the IP_PROBE_SCATTER signal handles.
  const asnBlock = buildAsnBlock(asn, [tcpIp, tlsIp, apiIp, webrtcIp]);
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
