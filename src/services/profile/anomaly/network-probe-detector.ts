/**
 * Network probe anomaly detector.
 *
 * Detects proxy and VPN usage from raw TCP/H2 probe attributes.
 * All scoring logic lives here in the API — the sigint probe only
 * emits raw measurements (rcv_rtt, snd_mss, pmtu, etc.).
 *
 * Proxy detection: rcv_rtt >> rtt indicates a relay between the probe
 * and the real client. The server sees fast ACKs from the proxy but
 * data must travel the full path to the browser, inflating rcv_rtt.
 *
 * VPN detection: reduced MSS from tunnel encapsulation overhead.
 * Standard ethernet MSS is ~1460. Each tunnel layer removes 20-80 bytes.
 */
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/** Extract a numeric field from an unknown nested object, or undefined. */
function dig(obj: unknown, ...keys: string[]): number | undefined {
  let cur: unknown = obj;
  for (const key of keys) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return typeof cur === "number" ? cur : undefined;
}

/** Extract a string[] from an unknown nested object, or undefined. */
function digStrArr(obj: unknown, ...keys: string[]): string[] | undefined {
  let cur: unknown = obj;
  for (const key of keys) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return Array.isArray(cur) ? (cur as string[]) : undefined;
}

const EXPECTED_DIRECT_RTT = "rcv_rtt ≈ rtt for direct connections";
const EXPECTED_STANDARD_MSS = "snd_mss ~1460 for standard ethernet";
const MSS_FIELDS = ["tcp_probe.rtt_fingerprint.snd_mss"];

/** Threshold table: [minRatio, severity] — first match wins (descending order). */
const RTT_RATIO_THRESHOLDS: [number, number][] = [
  [2.5, 0.6],
  [2.0, 0.35],
  [1.5, 0.15],
];

/** Threshold table: [maxMss, severity, description] — first match wins. */
const MSS_THRESHOLDS: [number, number, string][] = [
  [1300, 0.7, "heavy tunnel encapsulation"],
  [1380, 0.5, "VPN encapsulation likely (WireGuard/OpenVPN range)"],
  [1440, 0.25, "slightly reduced, possible light tunnel"],
];

function checkRttRatio(rtt: number, rcvRtt: number): AnomalySignal | null {
  const ratio = rcvRtt / rtt;
  const match = RTT_RATIO_THRESHOLDS.find(([min]) => ratio >= min);
  if (!match) return null;
  return createSignal("NETWORK", AnomalyCodes.LIKELY_PROXY, match[1], {
    expected: EXPECTED_DIRECT_RTT,
    actual: `rcv_rtt/rtt = ${ratio.toFixed(1)}× (${Math.round(rcvRtt / 1000)}ms / ${Math.round(rtt / 1000)}ms)`,
    fields: ["tcp_probe.tcp_info.rcv_rtt", "tcp_probe.tcp_info.rtt"],
  });
}

function checkTimingAnomaly(
  tcpRttUs: number,
  totalUs: number,
): AnomalySignal | null {
  if (tcpRttUs <= 0 || tcpRttUs >= 30000 || totalUs <= 150000) return null;
  return createSignal("NETWORK", AnomalyCodes.LIKELY_PROXY, 0.35, {
    expected: "total_connection_us proportional to tcp_rtt_us",
    actual: `tcp_rtt=${Math.round(tcpRttUs / 1000)}ms but total=${Math.round(totalUs / 1000)}ms`,
    fields: [
      "tcp_probe.rtt_fingerprint.tcp_rtt_us",
      "tcp_probe.rtt_fingerprint.total_connection_us",
    ],
  });
}

function checkMss(sndMss: number): AnomalySignal | null {
  const match = MSS_THRESHOLDS.find(([max]) => sndMss < max);
  if (!match) return null;
  return createSignal("NETWORK", AnomalyCodes.LIKELY_VPN, match[1], {
    expected: EXPECTED_STANDARD_MSS,
    actual: `snd_mss=${sndMss} — ${match[2]}`,
    fields: MSS_FIELDS,
  });
}

function checkProbePassthrough(
  tcpInfo: Record<string, unknown>,
): AnomalySignal | null {
  const probeSignals = digStrArr(tcpInfo, "rtt_fingerprint", "proxy_signals");
  const active = probeSignals?.filter((s) => s !== "none") ?? [];
  if (active.length === 0) return null;
  return createSignal("NETWORK", AnomalyCodes.LIKELY_PROXY, 0.2, {
    expected: "no proxy signals from tcp probe",
    actual: active.join(", "),
    fields: ["tcp_probe.rtt_fingerprint.proxy_signals"],
  });
}

function pushIfPresent(signals: AnomalySignal[], signal: AnomalySignal | null) {
  if (signal) signals.push(signal);
}

/**
 * Resolve best available RTT measurements for proxy detection.
 *
 * Prefers kernel rcv_rtt (accurate for direct vs proxy distinction).
 * Falls back to app_rtt_us only when rcv_rtt is 0/unavailable.
 * Using max() caused false positives on cellular where app_rtt includes
 * radio wake-up latency that inflates the ratio without a proxy.
 */
function resolveRtt(tcpInfo: Record<string, unknown>): {
  rtt: number | undefined;
  rcvRtt: number | undefined;
} {
  const pick = (a: number | undefined, b: number | undefined) =>
    a && a > 0 ? a : b;

  const rtt = pick(
    dig(tcpInfo, "rtt_fingerprint", "rtt_refreshed"),
    dig(tcpInfo, "tcp_info", "rtt"),
  );

  const rcvRtt = pick(
    dig(tcpInfo, "rtt_fingerprint", "rcv_rtt_refreshed"),
    pick(
      dig(tcpInfo, "tcp_info", "rcv_rtt"),
      dig(tcpInfo, "rtt_fingerprint", "app_rtt_us"),
    ),
  );

  return { rtt, rcvRtt };
}

function detectProxySignals(tcpInfo: Record<string, unknown>): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  const { rtt, rcvRtt } = resolveRtt(tcpInfo);
  const validRtt = rtt && rtt > 0 && rcvRtt && rcvRtt > 0;

  pushIfPresent(signals, validRtt ? checkRttRatio(rtt, rcvRtt) : null);

  const tcpRttUs = dig(tcpInfo, "rtt_fingerprint", "tcp_rtt_us") ?? rtt;
  const totalUs = dig(tcpInfo, "rtt_fingerprint", "total_connection_us");
  pushIfPresent(
    signals,
    tcpRttUs && totalUs ? checkTimingAnomaly(tcpRttUs, totalUs) : null,
  );

  pushIfPresent(signals, checkProbePassthrough(tcpInfo));

  return signals;
}

function detectVpnSignals(tcpInfo: Record<string, unknown>): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  const sndMss =
    dig(tcpInfo, "rtt_fingerprint", "snd_mss") ??
    dig(tcpInfo, "tcp_info", "snd_mss");
  const pmtu =
    dig(tcpInfo, "rtt_fingerprint", "pmtu") ?? dig(tcpInfo, "tcp_info", "pmtu");

  if (sndMss !== undefined && sndMss > 0) {
    const signal = checkMss(sndMss);
    if (signal) signals.push(signal);
  }

  if (pmtu !== undefined && pmtu > 0 && pmtu < 1500 && pmtu !== 1280) {
    signals.push(
      createSignal("NETWORK", AnomalyCodes.LIKELY_VPN, 0.2, {
        expected: "pmtu=1500 for standard internet path",
        actual: `pmtu=${pmtu} — reduced path MTU suggests tunnel`,
        fields: ["tcp_probe.rtt_fingerprint.pmtu"],
      }),
    );
  }

  return signals;
}

export function detectNetworkProbeAnomalies(
  _fingerprint: Fingerprint,
  _raw?: unknown,
  sigint?: unknown,
): AnomalySignal[] {
  if (!sigint) return [];

  const tcpInfo = (sigint as Record<string, unknown>)["tcp_probe"] as
    | Record<string, unknown>
    | undefined;
  if (!tcpInfo) return [];

  return [...detectProxySignals(tcpInfo), ...detectVpnSignals(tcpInfo)];
}
