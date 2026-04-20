/**
 * Network probe analysis for integrity ingestion.
 *
 * Produces continuous 0-1 scores from raw TCP probe measurements and
 * fuses them via noisy-OR into a single merchant-facing `proxy_score`.
 *
 * Why continuous over the old threshold-bucket approach:
 *   1. No sharp cliffs — a bot can no longer infer "caught at MSS=1380"
 *      vs "safe at 1400" by probing. Score transitions smoothly.
 *   2. Merchant sees one number; they set their own threshold for
 *      action. No arbitrary internal [LOW/MED/HIGH] buckets baked in.
 *   3. Evidence stacks properly. RTT-ratio 40% + MSS 60% → combined 76%,
 *      vs. the old max-of-two approach that would have returned 60%.
 *
 * Storage shape (what lands in DDB / S3):
 *   proxy_score       — merchant-facing noisy-OR combined score [0,1]
 *   proxy_component   — raw RTT-ratio-derived score [0,1]
 *   vpn_component     — raw MSS-derived score [0,1]
 *   signals           — detailed internal signals (not exposed to merchants)
 *
 * The future response-shaping pass (see TODO(merchant-response-shaping)
 * in session-get handler) projects this to `{proxy_score}` only.
 */

import type { AsnCategory } from "../ip-consistency/asn-catalog";
import { detectNetworkProbeAnomalies } from "../../services/profile/anomaly/network-probe-detector";
import { AnomalyCodes } from "../../services/profile/anomaly/types";
import type { AnomalyCode } from "../../services/profile/anomaly/types";
import type { Fingerprint } from "../../types";

/** RTT ratio where the continuous score saturates at 1.0. */
const RTT_RATIO_MAX = 3.0;
/** RTT ratio where the score is 0. Direct connections sit here. */
const RTT_RATIO_MIN = 1.0;

/** MSS where the score is 0. Tolerates PPPoE/DS-Lite/6rd overhead. */
const MSS_HIGH = 1440;
/** MSS where the continuous score saturates at 1.0. Heavy tunnels. */
const MSS_LOW = 1300;

/**
 * VPN score by ASN category. When the ASN is in a known-VPN class,
 * MSS math is bypassed — categorical evidence is stronger than
 * tunnel-overhead inference, and MSS alone missed tuned-MTU WG.
 *
 *   datacenter / vpn_proxy → 1.0  (no real consumer originates here)
 *   privacy_relay          → 0.5  (Apple Private Relay, Cloudflare WARP)
 *   corporate_proxy        → skip (user is a real employee; don't auto-fail)
 *   mobile / undefined     → skip (fall through to MSS math)
 */
function vpnByCategory(category: AsnCategory | null | undefined): {
  score: number;
  code: AnomalyCode;
  severity: number;
} | null {
  if (category === "datacenter" || category === "vpn_proxy") {
    return {
      score: 1.0,
      code: AnomalyCodes.CATEGORY_VPN,
      severity: 1.0,
    };
  }
  if (category === "privacy_relay") {
    return {
      score: 0.5,
      code: AnomalyCodes.CATEGORY_PRIVACY_RELAY,
      severity: 0.5,
    };
  }
  return null;
}

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

function dig(obj: unknown, ...keys: string[]): number | undefined {
  let cur: unknown = obj;
  for (const key of keys) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return typeof cur === "number" ? cur : undefined;
}

/**
 * Resolve the rtt / rcv_rtt pair the old detector uses. Kept identical
 * so the continuous score reads the same raw data as the legacy signals.
 */
function resolveRtt(tcp: Record<string, unknown>): {
  rtt?: number;
  rcvRtt?: number;
} {
  const pick = (a?: number, b?: number): number | undefined =>
    a && a > 0 ? a : b;
  const rtt = pick(
    dig(tcp, "rtt_fingerprint", "rtt_refreshed"),
    dig(tcp, "tcp_info", "rtt"),
  );
  const rcvRtt = pick(
    dig(tcp, "rtt_fingerprint", "rcv_rtt_refreshed"),
    pick(
      dig(tcp, "tcp_info", "rcv_rtt"),
      dig(tcp, "rtt_fingerprint", "app_rtt_us"),
    ),
  );
  return { rtt, rcvRtt };
}

function computeProxyComponent(tcp: Record<string, unknown>): number {
  const { rtt, rcvRtt } = resolveRtt(tcp);
  if (!rtt || rtt <= 0 || !rcvRtt || rcvRtt <= 0) return 0;
  const ratio = rcvRtt / rtt;
  return clamp01((ratio - RTT_RATIO_MIN) / (RTT_RATIO_MAX - RTT_RATIO_MIN));
}

function computeVpnComponent(tcp: Record<string, unknown>): number {
  const sndMss =
    dig(tcp, "rtt_fingerprint", "snd_mss") ?? dig(tcp, "tcp_info", "snd_mss");
  if (!sndMss || sndMss <= 0) return 0;
  return clamp01((MSS_HIGH - sndMss) / (MSS_HIGH - MSS_LOW));
}

export function analyzeNetworkProbes(
  sigint: unknown,
  asnCategory: AsnCategory | null | undefined = null,
) {
  const tcp = (sigint as Record<string, unknown> | undefined)?.tcp_probe as
    | Record<string, unknown>
    | undefined;

  // Legacy threshold-based signals — kept for internal diagnostics and
  // the older profile/matching path. Not exposed via merchant API.
  const legacySignals = detectNetworkProbeAnomalies(
    {} as Fingerprint,
    undefined,
    sigint,
  );

  const proxyComponent = tcp ? computeProxyComponent(tcp) : 0;
  const mssVpnComponent = tcp ? computeVpnComponent(tcp) : 0;

  // Category override: when the ASN is in a known-VPN class, override
  // the MSS-derived score. A tuned-MTU WG on AWS shows MSS ~1400 and
  // would score 0.29 on MSS alone, but the datacenter ASN is ground
  // truth — use the max of the two signals so we never under-score.
  const categoryHit = vpnByCategory(asnCategory);
  const vpnComponent = categoryHit
    ? Math.max(categoryHit.score, mssVpnComponent)
    : mssVpnComponent;

  // Noisy-OR: independence-assumed evidence fusion. Both components
  // reading strong evidence gives a combined score approaching 1; either
  // alone gives its own contribution. Correct shape for "multiple
  // independent indicators stack" and symmetric between p and v.
  const combined = 1 - (1 - proxyComponent) * (1 - vpnComponent);

  const signals = legacySignals.map((s) => ({
    code: s.code,
    severity: s.severity,
    evidence: s.evidence.actual as unknown,
  }));
  if (categoryHit) {
    signals.push({
      code: categoryHit.code,
      severity: categoryHit.severity,
      evidence: `asn.category=${asnCategory}`,
    });
  }

  return {
    proxy_score: combined,
    proxy_component: proxyComponent,
    vpn_component: vpnComponent,
    signals,
  };
}
