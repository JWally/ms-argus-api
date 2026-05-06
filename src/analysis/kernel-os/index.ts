/**
 * Kernel-OS coherence check.
 *
 * The Linux server kernel reports `tcp_info.tcpi_options` for every
 * accepted socket. This bitmask is a kernel-layer property of the
 * client TCP stack — the JS application above the socket cannot lie
 * about it. Cross-checking it against the OS claimed in the User-Agent
 * gives one of the cheapest, highest-confidence device-tamper signals.
 *
 * Rules:
 *   ua_os in {iOS, macOS} AND no ECN bit  → KERNEL_OS_MISMATCH_DARWIN
 *   ua_os in {Linux, Android} AND ECN bit → KERNEL_OS_MISMATCH_LINUX
 *
 * Empirical baseline from 2026-04-12 calibration (project_sigint_
 * detector_findings.md): real iOS = 15 or 31, real Linux/Chromium = 7,
 * real Windows = 6. The Darwin = ECN-on rule is the strongest because
 * iOS and macOS both ship with ECN enabled by default and no client
 * configuration toggles it off in practice.
 *
 * Windows is intentionally NOT checked here — the TS-off-by-default
 * convention is easy for Linux to mimic by clearing
 * `net.ipv4.tcp_timestamps`, and we'd see false positives from
 * customers who tune their kernel.
 */

import {
  AnomalyCodes,
  createSignal,
  type AnomalySignal,
} from "../../services/profile/anomaly/types";

// tcp_info option flags from <linux/tcp.h>:
const TCPI_OPT_ECN = 0x08;

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function extractOpts(sigint: unknown): number | null {
  if (!isObj(sigint)) return null;
  const tcp = sigint.tcp_probe;
  if (!isObj(tcp)) return null;
  // Flat field (post-hydration via redeemSigintTokens)
  const direct = num(tcp.options);
  if (direct !== null) return direct;
  // Nested under tcp_info (raw probe response)
  if (!isObj(tcp.tcp_info)) return null;
  return num(tcp.tcp_info.options);
}

const DARWIN_FAMILIES = new Set(["iOS", "macOS"]);
const LINUX_FAMILIES = new Set(["Linux", "Android"]);

export interface KernelOsAnalysisResult {
  /** `tcpi_options` bitmask the server kernel observed for this socket. */
  tcpOptions: number | null;
  /** UA OS family parsed by the ja4-ua analyzer (passed through). */
  uaOs: string | null;
  /** Did ECN get negotiated (Apple-typical when present). */
  ecnNegotiated: boolean | null;
  signals: Array<{ code: string; severity: number; evidence: string }>;
}

const EMPTY: KernelOsAnalysisResult = {
  tcpOptions: null,
  uaOs: null,
  ecnNegotiated: null,
  signals: [],
};

function darwinSignal(opts: number, uaOs: string): AnomalySignal {
  return createSignal(
    "CROSS_FIELD",
    AnomalyCodes.KERNEL_OS_MISMATCH_DARWIN,
    0.85,
    {
      expected: `Apple Darwin kernel (ECN bit 0x08 set in tcpi_options)`,
      actual: `ua_os=${uaOs}, tcpi_options=${opts} (no ECN — Linux-typical)`,
      fields: ["sigint.tcp_probe.tcp_info.options", "user_agent"],
    },
  );
}

function linuxSignal(opts: number, uaOs: string): AnomalySignal {
  return createSignal(
    "CROSS_FIELD",
    AnomalyCodes.KERNEL_OS_MISMATCH_LINUX,
    0.5,
    {
      expected: `Linux kernel (ECN bit 0x08 not set in tcpi_options)`,
      actual: `ua_os=${uaOs}, tcpi_options=${opts} (ECN negotiated — Apple-typical)`,
      fields: ["sigint.tcp_probe.tcp_info.options", "user_agent"],
    },
  );
}

/**
 * Analyze claimed UA OS vs observed kernel-layer TCP options.
 *
 * `uaOs` should be the value already parsed by the ja4-ua analyzer
 * (one of "iOS", "macOS", "Windows", "Android", "Linux", "Chrome OS")
 * so this analyzer doesn't duplicate UA parsing.
 */
export function analyzeKernelOs(
  sigint: unknown,
  uaOs: string | null,
): KernelOsAnalysisResult {
  const opts = extractOpts(sigint);
  if (opts === null || !uaOs) {
    return { ...EMPTY, tcpOptions: opts, uaOs };
  }

  const ecn = (opts & TCPI_OPT_ECN) !== 0;
  const signals: AnomalySignal[] = [];

  if (DARWIN_FAMILIES.has(uaOs) && !ecn) {
    signals.push(darwinSignal(opts, uaOs));
  } else if (LINUX_FAMILIES.has(uaOs) && ecn) {
    signals.push(linuxSignal(opts, uaOs));
  }

  return {
    tcpOptions: opts,
    uaOs,
    ecnNegotiated: ecn,
    signals: signals.map((s) => ({
      code: s.code,
      severity: s.severity,
      evidence: s.evidence.actual,
    })),
  };
}
