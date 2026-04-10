/**
 * IP consistency analysis for integrity ingestion.
 *
 * Compares IP addresses observed across independent channels:
 * - API Gateway (X-Forwarded-For)
 * - TLS fingerprint edge (CloudFront)
 * - TCP probe (EC2)
 * - WebRTC STUN (client-side, bypasses HTTP proxies)
 *
 * Rotating proxy pools produce different exit IPs per connection.
 * WebRTC leaks the real IP when the proxy doesn't block it.
 */

import {
  AnomalyCodes,
  createSignal,
  type AnomalySignal,
} from "../../services/profile/anomaly/types";

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
  checks: {
    probesConsistent: boolean;
    webrtcMatchesProbes: boolean | null;
  };
  signals: Array<{ code: string; severity: number; evidence: string }>;
}

function extractTlsIp(sigint: unknown): string | null {
  if (!isObj(sigint) || !isObj(sigint.aws_cf)) return null;
  // Direct field or nested under .data (raw client fetch result)
  const direct = str(sigint.aws_cf.ip);
  if (direct) return direct;
  return isObj(sigint.aws_cf.data) ? str(sigint.aws_cf.data.ip) : null;
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

function checkProbeScatter(probeIps: (string | null)[]): AnomalySignal | null {
  const present = probeIps.filter((ip): ip is string => ip !== null);
  if (present.length < 2) return null;
  const unique = [...new Set(present)];
  if (unique.length <= 1) return null;

  const severity = unique.length >= 3 ? 0.8 : 0.6;
  return createSignal("NETWORK", AnomalyCodes.IP_PROBE_SCATTER, severity, {
    expected: "all probes observe same IP",
    actual: `${unique.length} distinct IPs: ${unique.join(", ")}`,
    fields: ["client_ip", "sigint.aws_cf.ip", "sigint.tcp_probe.client_ip"],
  });
}

function checkWebrtcMismatch(
  webrtcIp: string,
  probeIps: (string | null)[],
): AnomalySignal | null {
  const present = probeIps.filter((ip): ip is string => ip !== null);
  if (present.length === 0) return null;
  if (present.includes(webrtcIp)) return null;

  return createSignal("NETWORK", AnomalyCodes.WEBRTC_IP_MISMATCH, 0.7, {
    expected: "WebRTC IP matches server-observed IP",
    actual: `webrtc=${webrtcIp} vs probes=${[...new Set(present)].join(", ")}`,
    fields: [
      "device.webrtc.iceCandidates.publicIP",
      "sigint.aws_cf.ip",
      "sigint.tcp_probe.client_ip",
    ],
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

function formatSignals(
  signals: AnomalySignal[],
): IpConsistencyResult["signals"] {
  return signals.map((s) => ({
    code: s.code,
    severity: s.severity,
    evidence: s.evidence.actual,
  }));
}

/**
 * Analyze IP consistency across probes and WebRTC.
 *
 * @param device - Device object (contains webrtc.iceCandidates.publicIP)
 * @param sigint - Hydrated sigint (contains aws_cf.ip, tcp_probe.client_ip)
 * @param clientIp - API Gateway X-Forwarded-For IP
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
  const probeIps = [apiIp, tlsIp, tcpIp];

  const signals: AnomalySignal[] = [];

  const scatterSig = checkProbeScatter(probeIps);
  if (scatterSig) signals.push(scatterSig);

  if (webrtcIp) {
    const mismatchSig = checkWebrtcMismatch(webrtcIp, probeIps);
    if (mismatchSig) signals.push(mismatchSig);
  } else {
    const blockedSig = checkWebrtcBlocked(device);
    if (blockedSig) signals.push(blockedSig);
  }

  const probesConsistent = !scatterSig;
  const webrtcMatchesProbes = webrtcIp
    ? !signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH)
    : null;

  return {
    lied: signals.some((s) => s.severity >= 0.5),
    ips: { api: apiIp, tls: tlsIp, tcp: tcpIp, webrtc: webrtcIp },
    checks: { probesConsistent, webrtcMatchesProbes },
    signals: formatSignals(signals),
  };
}
