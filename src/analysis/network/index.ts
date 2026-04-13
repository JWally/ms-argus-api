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

import { detectNetworkProbeAnomalies } from "../../services/profile/anomaly/network-probe-detector";
import type { Fingerprint } from "../../types";

/** RTT ratio where the continuous score saturates at 1.0. */
const RTT_RATIO_MAX = 3.0;
/** RTT ratio where the score is 0. Direct connections sit here. */
const RTT_RATIO_MIN = 1.0;

/** MSS where the score is 0. Standard ethernet path. */
const MSS_HIGH = 1460;
/** MSS where the continuous score saturates at 1.0. Heavy tunnels. */
const MSS_LOW = 1300;

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

export function analyzeNetworkProbes(sigint: unknown) {
  const tcp = (sigint as Record<string, unknown> | undefined)?.tcp_probe as
    | Record<string, unknown>
    | undefined;

  // Legacy threshold-based signals — kept for internal diagnostics and
  // the older profile/matching path. Not exposed via merchant API.
  const signals = detectNetworkProbeAnomalies(
    {} as Fingerprint,
    undefined,
    sigint,
  );

  const proxyComponent = tcp ? computeProxyComponent(tcp) : 0;
  const vpnComponent = tcp ? computeVpnComponent(tcp) : 0;

  // Noisy-OR: independence-assumed evidence fusion. Both components
  // reading strong evidence gives a combined score approaching 1; either
  // alone gives its own contribution. Correct shape for "multiple
  // independent indicators stack" and symmetric between p and v.
  const combined = 1 - (1 - proxyComponent) * (1 - vpnComponent);

  return {
    proxy_score: combined,
    proxy_component: proxyComponent,
    vpn_component: vpnComponent,
    signals: signals.map((s) => ({
      code: s.code,
      severity: s.severity,
      evidence: s.evidence.actual,
    })),
  };
}
