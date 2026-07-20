const BENCH_BOTH_HOT_US = 40;
const BENCH_REALM_HOT_US = 20;
const BENCH_REALM_COLD_US = 12;
const ERROR_STACK_BURST_CDP_DELTA_MS = 30;

export const CDP_SUSPECT_TIER = 60;

export interface ConsoleTimingFields {
  log_heavy_us?: number;
  tl_heavy_us?: number;
  perf_now_native?: boolean;
  date_now_native?: boolean;
  con_log_native?: boolean;
  con_dir_native?: boolean;
  cdp_proto_proxy_trap?: boolean;
  error_stack_burst_delta_ms?: number;
  console_lies?: number;
}

interface CdpTimingSignals {
  cdp?: {
    consoleTiming?: ConsoleTimingFields;
    consoleTimingWorker?: ConsoleTimingFields;
    workerModuleImportChain?: { cdp_shaped?: boolean };
  };
}

function hasBenchDependencyTamper(timing: ConsoleTimingFields): boolean {
  return (
    timing.perf_now_native === false ||
    timing.date_now_native === false ||
    timing.con_log_native === false ||
    timing.con_dir_native === false
  );
}

function hasCrossClockDivergence(timing: ConsoleTimingFields): boolean {
  const heavy = timing.log_heavy_us;
  const timelineHeavy = timing.tl_heavy_us;
  if (typeof heavy !== "number" || typeof timelineHeavy !== "number") {
    return false;
  }
  return Math.abs(timelineHeavy - heavy) > 3;
}

function benchPrimitiveTampered(
  timing: ConsoleTimingFields | undefined,
): boolean {
  if (!timing) return false;
  return hasBenchDependencyTamper(timing) || hasCrossClockDivergence(timing);
}

export function hasErrorStackBurstSignal(
  worker: ConsoleTimingFields | undefined,
): boolean {
  const delta = worker?.error_stack_burst_delta_ms;
  return typeof delta === "number" && delta >= ERROR_STACK_BURST_CDP_DELTA_MS;
}

function hasStrongTimingSignal(
  headless: CdpTimingSignals | undefined,
): boolean {
  const iframe = headless?.cdp?.consoleTiming;
  const worker = headless?.cdp?.consoleTimingWorker;
  if (benchPrimitiveTampered(iframe) || benchPrimitiveTampered(worker)) {
    return true;
  }
  if (hasErrorStackBurstSignal(worker)) return true;
  if (headless?.cdp?.workerModuleImportChain?.cdp_shaped === true) return true;
  const iframeHeavy = iframe?.log_heavy_us;
  const workerHeavy = worker?.log_heavy_us;
  if (typeof iframeHeavy !== "number" || typeof workerHeavy !== "number") {
    return false;
  }
  return Math.min(iframeHeavy, workerHeavy) > BENCH_BOTH_HOT_US;
}

function hasOneSidedTimingSignal(
  headless: CdpTimingSignals | undefined,
): boolean {
  const iframeHeavy = headless?.cdp?.consoleTiming?.log_heavy_us;
  const workerHeavy = headless?.cdp?.consoleTimingWorker?.log_heavy_us;
  if (typeof iframeHeavy !== "number" || typeof workerHeavy !== "number") {
    return false;
  }
  return (
    Math.max(iframeHeavy, workerHeavy) > BENCH_REALM_HOT_US &&
    Math.min(iframeHeavy, workerHeavy) < BENCH_REALM_COLD_US
  );
}

/** Score desktop-calibrated timing evidence without promoting one hot realm. */
export function desktopCdpTimingScore(
  headless: CdpTimingSignals | undefined,
  isMobile: boolean,
): number {
  if (isMobile) return 0;
  if (hasStrongTimingSignal(headless)) return 75;
  return hasOneSidedTimingSignal(headless) ? CDP_SUSPECT_TIER : 0;
}
