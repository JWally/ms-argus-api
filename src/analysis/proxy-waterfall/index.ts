/**
 * Proxy detection waterfall.
 *
 * Tiered rule cascade producing a single verdict from the TCP/WebRTC
 * IP relationship and the rcv_rtt/rtt ratio. Each rule is a single
 * boolean expression; the first to fire wins.
 *
 *   0. forgery / parse_fail                                 → KILL  (liar)
 *   1. UDP == TCP                                           → SAFE  (no split)
 *   2. UDP present, ratio ≤ 1.05                            → SAFE  (freak veto: clean ratio, can't be proxy)
 *   3. UDP present, shared_prefix ≥ /24, ratio < 3          → SAFE  (cellular CGNAT tolerance)
 *   4. UDP present, shared_prefix ≥ /16, ratio < 2          → SAFE  (fiber / ISP pool tolerance)
 *   5. UDP present, ratio ≥ 2                               → KILL  (split + elevated ratio)
 *   6. UDP absent (no_candidates), ratio > 2.5              → KILL  (silent + high ratio)
 *   7. UDP absent (no_candidates), ratio > 1.5              → HIGH  (silent + moderate ratio)
 *   8. otherwise                                            → SAFE
 *
 * "ratio" throughout refers to rcv_rtt / rtt from the server-side TCP
 * probe (sigint.tcp_probe.rtt_fingerprint). Clean connections sit near
 * 1.0; proxy hops inflate it via ACK-spacing asymmetry.
 *
 * Null handling: if `rttRatio` is null (no TCP probe RTT data), the
 * ratio-gated kill rules cannot fire — we prefer false negatives over
 * false positives when evidence is missing.
 */

export type ProxyVerdict = "SAFE" | "HIGH" | "KILL";

/**
 * Merchant-facing threat score in [0, 100].
 *   0    → no threat (clean)
 *   100  → confirmed threat
 *   mid  → ambiguous
 */
export type ProxyThreatScore = number;

export type WebrtcSigintStatus =
  | "ok"
  | "no_candidates"
  | "forgery"
  | "parse_fail"
  | "decode_fail";

export interface ProxyWaterfallInput {
  tcpIp: string | null;
  webrtcIp: string | null;
  webrtcStatus: WebrtcSigintStatus | null;
  rttRatio: number | null;
}

export interface ProxyWaterfallResult {
  /** Internal verdict label (SAFE/HIGH/KILL). Not merchant-facing. */
  verdict: ProxyVerdict;
  /** Rule # that fired (0-8). Diagnostic; not merchant-facing. */
  rule: number;
  /** Short reason code. Diagnostic; not merchant-facing. */
  reason: string;
  /** Quantized threat score to surface to merchants. */
  threat_score: ProxyThreatScore;
  shared_prefix: number | null;
  ratio: number | null;
}

/**
 * Map internal verdict+rule to a merchant-facing threat score in [0, 100].
 *
 *   rule 0, 5, 6 → 100  (confirmed: liar, split+ratio, silent+high-ratio)
 *   rule 7        →  50  (ambiguous: silent+moderate-ratio)
 *   rule 1,2,3,4,8→   0  (safe or no signal)
 */
function threatScoreFor(rule: number): ProxyThreatScore {
  if (rule === 0 || rule === 5 || rule === 6) return 100;
  if (rule === 7) return 50;
  return 0;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    acc = (acc << 8) + n;
  }
  return acc >>> 0;
}

export function sharedPrefixBits(a: string, b: string): number | null {
  const ia = ipv4ToInt(a);
  const ib = ipv4ToInt(b);
  if (ia === null || ib === null) return null;
  const xor = (ia ^ ib) >>> 0;
  if (xor === 0) return 32;
  let bits = 0;
  let x = xor;
  while ((x & 0x80000000) === 0 && bits < 32) {
    x = (x << 1) >>> 0;
    bits++;
  }
  return bits;
}

interface RuleHit {
  verdict: ProxyVerdict;
  rule: number;
  reason: string;
}

interface WithWebrtcCtx {
  tcpIp: string;
  webrtcIp: string;
  shared: number | null;
  ratio: number | null;
}

const HIT = (verdict: ProxyVerdict, rule: number, reason: string): RuleHit => ({
  verdict,
  rule,
  reason,
});

/** Rule predicates — each returns a hit when it fires, null otherwise. */
const WITH_WEBRTC_RULES: Array<(c: WithWebrtcCtx) => RuleHit | null> = [
  // 1. UDP == TCP (exact match, regardless of ratio).
  ({ tcpIp, webrtcIp }) =>
    webrtcIp === tcpIp ? HIT("SAFE", 1, "udp_eq_tcp") : null,
  // 2. Freak veto: clean ratio, can't physically be a proxy.
  ({ ratio }) =>
    ratio !== null && ratio <= 1.05
      ? HIT("SAFE", 2, "freak_veto_low_ratio")
      : null,
  // 3. Cellular CGNAT tolerance (/24 same, ratio < 3 or unknown).
  ({ shared, ratio }) =>
    shared !== null && shared >= 24 && (ratio === null || ratio < 3)
      ? HIT("SAFE", 3, "cgnat_slash24")
      : null,
  // 4. Fiber / ISP pool tolerance (/16 same, ratio < 2).
  ({ shared, ratio }) =>
    shared !== null && shared >= 16 && ratio !== null && ratio < 2
      ? HIT("SAFE", 4, "cgnat_slash16")
      : null,
  // 5. Split with elevated ratio.
  ({ ratio }) =>
    ratio !== null && ratio >= 2 ? HIT("KILL", 5, "split_and_ratio") : null,
];

function classifyWithWebrtc(ctx: WithWebrtcCtx): RuleHit | null {
  for (const rule of WITH_WEBRTC_RULES) {
    const hit = rule(ctx);
    if (hit) return hit;
  }
  return null;
}

/** Rules 6–7: evaluated when WebRTC is silent ("no_candidates"). */
function classifySilentWebrtc(ratio: number): RuleHit | null {
  if (ratio > 2.5) return HIT("KILL", 6, "silent_and_high_ratio");
  if (ratio > 1.5) return HIT("HIGH", 7, "silent_and_moderate_ratio");
  return null;
}

function earlyForgery(status: WebrtcSigintStatus | null): RuleHit | null {
  if (status === "forgery" || status === "parse_fail") {
    return HIT("KILL", 0, `webrtc_${status}`);
  }
  return null;
}

function selectHit(ctx: {
  tcpIp: string | null;
  webrtcIp: string | null;
  webrtcStatus: WebrtcSigintStatus | null;
  ratio: number | null;
  shared: number | null;
}): RuleHit {
  const { tcpIp, webrtcIp, webrtcStatus, ratio, shared } = ctx;
  const forged = earlyForgery(webrtcStatus);
  if (forged) return forged;
  const bothIps =
    webrtcIp && tcpIp
      ? classifyWithWebrtc({ tcpIp, webrtcIp, shared, ratio })
      : null;
  if (bothIps) return bothIps;
  const silent =
    webrtcStatus === "no_candidates" && ratio !== null
      ? classifySilentWebrtc(ratio)
      : null;
  if (silent) return silent;
  return HIT("SAFE", 8, "clean");
}

export function classifyProxy(
  input: ProxyWaterfallInput,
): ProxyWaterfallResult {
  const { tcpIp, webrtcIp, webrtcStatus, rttRatio: ratio } = input;
  const shared = tcpIp && webrtcIp ? sharedPrefixBits(tcpIp, webrtcIp) : null;
  const hit = selectHit({ tcpIp, webrtcIp, webrtcStatus, ratio, shared });
  return {
    ...hit,
    threat_score: threatScoreFor(hit.rule),
    shared_prefix: shared,
    ratio,
  };
}
