/**
 * Network-tampering axis scorer.
 *
 * Composes `network_tampering` (0-100) from three independent signals on the
 * `integrity` projection input:
 *
 *   - vpn_component:  MSS-derived tunnel encapsulation fingerprint
 *   - proxy_threat:   proxy_waterfall's integrated analyzer (consumes WebRTC
 *                     consensus, RTT jitter, ASN class)
 *   - ip_scatter:     probe-IP disagreement penalty (gated on network_class
 *                     to avoid mobile/corporate-shield false positives)
 *
 * Today: max() aggregator across the three. Any one saturating is enough.
 *
 * Cross-axis predicates and the projection input type live in `./shared` so
 * scoring/ never imports back up from helpers/ (no cycles).
 */

import {
  detectCellular,
  detectCorporateShield,
  detectNoWebrtc,
  probabilityFromUnit,
  type MerchantProjectionInput,
} from "./shared";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** rcv_rtt/rtt_refreshed at or above this is strong RTT-derived proxy
 *  evidence. It belongs only to the proxy sub-scorer; it must never create
 *  MSS-derived VPN evidence when vpn_component is zero. */
const RTT_RATIO_CEILING = 5.0;

/** Component above this counts as "elevated" for the no-webrtc uplift.
 *  0.3 corresponds to rcv_rtt/rtt ≈ 1.6 on the current scorer. */
const COMPONENT_ELEVATED_THRESHOLD = 0.3;

/** Floor applied when no WebRTC + elevated RTT ("GTFO" rule). */
const NO_WEBRTC_UPLIFT_FLOOR = 0.9;

/** Proxy floor applied when ratio >= RTT_RATIO_CEILING. Above any damper. */
const CEILING_UPLIFT_FLOOR = 0.95;

/** Ceiling applied when WebRTC is present and matches probes — caps proxy
 *  component at "suspect, not damning" for plausibly-legit ratios. */
const WEBRTC_MATCH_DAMPER_CAP = 0.3;

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/** Unclamped rcv_rtt_refreshed/rtt_refreshed ratio from the TCP probe. Null
 *  when data is missing (legacy records, probe failure). */
function readRttRatio(input: MerchantProjectionInput): number | null {
  const sigint = input.integrity?.sigint as
    | { tcp_probe?: { rtt_fingerprint?: Record<string, number> } }
    | undefined;
  const rtt = sigint?.tcp_probe?.rtt_fingerprint;
  if (!rtt) return null;
  const rcv = rtt.rcv_rtt_refreshed;
  const ref = rtt.rtt_refreshed;
  if (!rcv || !ref || rcv <= 0 || ref <= 0) return null;
  return rcv / ref;
}

/** Whether the MAC-verified WebRTC IP is present and agrees with the probe
 *  IPs at /16 granularity (the existing analyzer's contract). */
function webrtcMatchesNetwork(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.checks.webrtcMatchesProbes === true;
}

/** Datacenter / declared-VPN ASNs — both run traffic through explicit
 *  tunnels. WebRTC matching on these ASNs proves tunnel uniformity
 *  (HTTP and WebRTC ride the same tunnel → same egress IP), not
 *  non-proxy-ness. The damper must not fire here or it silences the
 *  MSS-reduction signal that catches AWS-VPN / WireGuard-over-TLS. */
function isTunneledAsn(input: MerchantProjectionInput): boolean {
  const cat = input.integrity?.analysis.ip.asn.category;
  return cat === "datacenter" || cat === "vpn_proxy";
}

/**
 * Apply the WebRTC-anchored fusion rules on top of the raw RTT-derived proxy
 * component. vpn_component is MSS-derived and deliberately bypasses this
 * function so RTT jitter cannot manufacture VPN evidence.
 *
 * Rules (in precedence order):
 *   1. Corporate shield → 0. Strongest carve-out; benign enterprise egress.
 *   2. Ratio ≥ 5.0 → floor at 0.95. Physics ceiling: no legitimate network
 *      produces a 5× gap between rcv_rtt and rtt_refreshed. Overrides
 *      cellular carve-out AND WebRTC match (covers the motivated-attacker
 *      case who rents a proxy exit in the victim's /16 to fake a match).
 *   3. Cellular / CGNAT → pass through.
 *   4. WebRTC matches probes at /16 AND ASN is NOT
 *      datacenter/vpn_proxy → cap at 0.3. Suspect but not damning.
 *      Damper is scoped in two dimensions: (a) proxy component only —
 *      MSS/vpn signal stays authoritative; (b) non-tunneled ASNs only —
 *      a VPN on AWS tunnels WebRTC through the same exit so matching is
 *      tunnel uniformity, not non-proxy-ness.
 *   5. No WebRTC submitted and component elevated (> 0.3) → floor at 0.9.
 *   6. Otherwise → pass through.
 */
function applyProxyWebrtcFusion(
  input: MerchantProjectionInput,
  rawComponent: number,
): number {
  if (detectCorporateShield(input)) return 0;

  const ratio = readRttRatio(input);

  // Physics ceiling wins over every non-corporate carve-out.
  if (ratio !== null && ratio >= RTT_RATIO_CEILING) {
    return Math.max(rawComponent, CEILING_UPLIFT_FLOOR);
  }

  if (detectCellular(input)) return rawComponent;

  if (webrtcMatchesNetwork(input) && !isTunneledAsn(input)) {
    return Math.min(rawComponent, WEBRTC_MATCH_DAMPER_CAP);
  }

  if (detectNoWebrtc(input) && rawComponent > COMPONENT_ELEVATED_THRESHOLD) {
    return Math.max(rawComponent, NO_WEBRTC_UPLIFT_FLOOR);
  }

  return rawComponent;
}

// ---------------------------------------------------------------------------
// Public sub-scorers (exported for use elsewhere in merchant-projection)
// ---------------------------------------------------------------------------

export function vpnScore(input: MerchantProjectionInput): number {
  const raw = input.integrity?.analysis.network.vpn_component ?? 0;
  return detectCorporateShield(input) ? 0 : raw;
}

export function proxyScore(input: MerchantProjectionInput): number {
  const raw = input.integrity?.analysis.network.proxy_component ?? 0;
  return applyProxyWebrtcFusion(input, raw);
}

/**
 * Penalty from IP_PROBE_SCATTER — when probes (XFF / CF / TCP) observe
 * distinct client IPs, that's a structural sign of a proxy/VPN in the path
 * that proxy_waterfall sometimes misses (e.g., when its RTT-ratio gate is
 * null because the TCP probe didn't ship).
 *
 * Gated on `network_class` to avoid penalizing benign explanations:
 *   - `mobile`: cellular CGNAT legitimately produces per-flow egress IPs.
 *     The analyzer already emits SAME_SUBNET_CGNAT (severity 0.1) for the
 *     same-/16 case; we trust that path and don't second-guess.
 *   - `security_filter`: corporate proxies (Cisco Umbrella et al.)
 *     re-originate TLS and naturally scatter probes; merchant-projection's
 *     `isCorporateShieldedAsn` carve-out documents this elsewhere.
 *
 * Severity maps directly: 0.6 (2 distinct IPs) → 60, 0.8 (3+) → 80. Both
 * cross SUSPECT_THRESHOLD; 0.8 crosses BLOCK. Math.max with proxy_waterfall
 * prevents double-count when both fire.
 */
function ipScatterPenalty(input: MerchantProjectionInput): number {
  const ip = input.integrity?.analysis?.ip;
  if (!ip) return 0;
  const networkClass = ip.asn?.network_class;
  if (networkClass === "mobile" || networkClass === "security_filter") return 0;
  const scatter = (ip.signals ?? []).find((s) => s.code === "IP_PROBE_SCATTER");
  if (!scatter) return 0;
  return Math.round(scatter.severity * 100);
}

// ---------------------------------------------------------------------------
// Axis composer
// ---------------------------------------------------------------------------

/**
 * Compose `network_tampering` from the merchant-facing network signals:
 *   - vpn_component (MSS-derived tunnel encapsulation fingerprint)
 *   - proxy waterfall threat (the integrated analyzer; itself already
 *     factors WebRTC consensus / RTT jitter / ASN class)
 *   - ip_scatter penalty (probe-IP disagreement, gated on network_class
 *     to avoid mobile/corporate-shield false positives)
 * Max wins — any one of these saturating is enough to flag the path.
 *
 * networkIntegrity (the WebRTC/probe consensus scalar) is intentionally
 * NOT layered in here: proxy_waterfall already consumes it as an input
 * tier, so adding it directly would double-count and re-trigger on the
 * very scenarios proxy_waterfall's damper was designed to filter.
 */
export function networkTamperingScore(input: MerchantProjectionInput): number {
  const vpn = probabilityFromUnit(vpnScore(input));
  const proxyThreat =
    input.integrity?.analysis?.proxy_waterfall?.threat_score ?? 0;
  const ipScatter = ipScatterPenalty(input);
  return Math.max(vpn, proxyThreat, ipScatter);
}
