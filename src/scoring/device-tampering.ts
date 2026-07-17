/** Device-tampering evidence collection and merchant-safe tier composition. */

import type { IntegrityResultsData } from "../helpers/payload-schema";
import { hasIframeCryptoStuck } from "./automation";
import { detectBraveIos } from "./brave-ios";
import {
  detectUaFamilyHeaderMismatch,
  hasJa4UaMismatch,
  hasTlsUaMismatch,
  isCorporateShieldedAsn,
  isVerifiedAppleRelay,
  readBrowserEngineSignals,
  readChUaMismatch,
  readKernelOsSignals,
  readLocaleGeoSignals,
  readTzGeoMismatch,
} from "./identity";
import type { MerchantProjectionInput } from "./shared";

interface TamperingEvidence {
  lies: number;
  divergences: number;
  ja4Mismatch: boolean;
  webrtcApiTampered: boolean;
  uaDivergence: boolean;
  platformLie: boolean;
  uaHeaderMismatch: boolean;
  chUaMismatch: boolean;
  localeTamper: boolean;
  tlsUaMismatch: boolean;
  browserEngineHardBreak: boolean;
  browserEngineSoft: boolean;
  kernelOsMismatchHard: boolean;
  kernelOsMismatchSoft: boolean;
  kernelOsDarwinCorroborated: boolean;
  tzGeoMismatch: boolean;
  langGeoCrossContinent: boolean;
  langGeoCrossCountry: boolean;
  iframeCryptoStuck: boolean;
  workerOracleMissing: "main_only" | false;
  cfTampered: boolean;
  cfReplayed: boolean;
  cfSlowPage: boolean;
  patAttestationFailed: boolean;
  deviceIdentitySigFailed: boolean;
  deviceHistoryTampered: boolean;
}

function readLieKeys(integrity: IntegrityResultsData): string[] {
  const data = (
    integrity.device as
      | { lies?: { data?: Record<string, unknown> } }
      | undefined
  )?.lies?.data;
  return data ? Object.keys(data) : [];
}

const WEBRTC_API_LIE_PATTERN =
  /createDataChannel|createOffer|setLocalDescription|setRemoteDescription|iceConnectionState|connectionState|localDescription|addIceCandidate|generateCertificate/;

function detectWebrtcApiTampering(integrity: IntegrityResultsData): boolean {
  return readLieKeys(integrity).some((key) => WEBRTC_API_LIE_PATTERN.test(key));
}

function hasPlatformLie(integrity: IntegrityResultsData): boolean {
  return readLieKeys(integrity).some((key) => /Navigator\.platform/i.test(key));
}

function hasUaWorkerDivergence(integrity: IntegrityResultsData): boolean {
  return !!integrity.analysis.worker.divergences?.some(
    (divergence) => divergence.field === "userAgent",
  );
}

function readPatAttestationFailed(integrity: IntegrityResultsData): boolean {
  const attempt = (
    integrity as { patAttempt?: { attempted?: unknown; verified?: unknown } }
  ).patAttempt;
  return attempt?.attempted === true && attempt.verified === false;
}

function readDeviceIdentitySigFailed(integrity: IntegrityResultsData): boolean {
  const identification = (
    integrity as {
      identification?: { sig_present?: unknown; verified?: unknown };
    }
  ).identification;
  return (
    identification?.sig_present === true && identification.verified === false
  );
}

function readDeviceHistoryTampered(integrity: IntegrityResultsData): boolean {
  const history = (
    integrity.analysis as {
      device_history?: { tampered?: unknown };
    }
  ).device_history;
  return history?.tampered === true;
}

function scoreablePathSignal(
  signal: boolean,
  shielded: boolean,
  appleRelay: boolean,
): boolean {
  return signal && !shielded && !appleRelay;
}

function scoreableKernelEvidence(
  kernelOs: ReturnType<typeof readKernelOsSignals>,
  shielded: boolean,
  appleRelay: boolean,
): Pick<
  TamperingEvidence,
  "kernelOsMismatchHard" | "kernelOsMismatchSoft" | "kernelOsDarwinCorroborated"
> {
  return {
    kernelOsMismatchHard: scoreablePathSignal(
      kernelOs.hard,
      shielded,
      appleRelay,
    ),
    kernelOsMismatchSoft: scoreablePathSignal(
      kernelOs.soft,
      shielded,
      appleRelay,
    ),
    kernelOsDarwinCorroborated: scoreablePathSignal(
      kernelOs.corroboratedDarwin,
      shielded,
      appleRelay,
    ),
  };
}

function readCfTamperEvidence(integrity: IntegrityResultsData): {
  cfTampered: boolean;
  cfReplayed: boolean;
  cfSlowPage: boolean;
} {
  const cf = (
    integrity.sigint as
      | { aws_cf?: { tampered?: unknown; expired?: unknown; ageSec?: unknown } }
      | undefined
  )?.aws_cf;
  if (!cf) return { cfTampered: false, cfReplayed: false, cfSlowPage: false };
  if (cf.tampered === true) {
    return { cfTampered: true, cfReplayed: false, cfSlowPage: false };
  }
  const ageSec = typeof cf.ageSec === "number" ? cf.ageSec : null;
  const replayed = ageSec !== null && (ageSec < -90 || ageSec > 300);
  return {
    cfTampered: false,
    cfReplayed: replayed,
    cfSlowPage: !replayed && cf.expired === true && typeof ageSec === "number",
  };
}

function readWorkerOracleMissing(
  integrity: IntegrityResultsData,
): "main_only" | false {
  return (integrity.analysis.worker.signals ?? []).some(
    (signal) => signal.code === "WORKER_ORACLE_MAIN_ONLY",
  )
    ? "main_only"
    : false;
}

function collectTamperingEvidence(
  integrity: IntegrityResultsData,
): TamperingEvidence {
  const rawLies =
    (integrity.device as { lies?: { totalLies?: number } } | undefined)?.lies
      ?.totalLies ?? 0;
  const braveIos = detectBraveIos(integrity);
  const locale = readLocaleGeoSignals(integrity);
  const shielded = isCorporateShieldedAsn(integrity);
  const appleRelay = isVerifiedAppleRelay(integrity);
  const browserEngine = readBrowserEngineSignals(integrity);
  const kernelOs = readKernelOsSignals(integrity);
  const divergences = (integrity.analysis.worker.divergences ?? []).filter(
    (divergence) => divergence.field !== "onLine",
  ).length;

  return {
    lies: Math.max(0, rawLies - braveIos.attributedLies),
    divergences,
    ja4Mismatch: hasJa4UaMismatch(integrity),
    webrtcApiTampered: detectWebrtcApiTampering(integrity),
    uaDivergence: hasUaWorkerDivergence(integrity),
    platformLie: hasPlatformLie(integrity),
    uaHeaderMismatch: detectUaFamilyHeaderMismatch(integrity),
    chUaMismatch: readChUaMismatch(integrity),
    localeTamper: locale.localeTamper,
    tlsUaMismatch: hasTlsUaMismatch(integrity) && !shielded,
    browserEngineHardBreak: browserEngine.hard,
    browserEngineSoft: browserEngine.soft,
    ...scoreableKernelEvidence(kernelOs, shielded, appleRelay),
    tzGeoMismatch: readTzGeoMismatch(integrity) && !shielded,
    langGeoCrossContinent: locale.crossContinent,
    langGeoCrossCountry: locale.crossCountry,
    iframeCryptoStuck: hasIframeCryptoStuck(integrity),
    workerOracleMissing: readWorkerOracleMissing(integrity),
    ...readCfTamperEvidence(integrity),
    patAttestationFailed: readPatAttestationFailed(integrity),
    deviceIdentitySigFailed: readDeviceIdentitySigFailed(integrity),
    deviceHistoryTampered: readDeviceHistoryTampered(integrity),
  };
}

function hasDivergenceTampering(evidence: TamperingEvidence): boolean {
  return (
    evidence.divergences >= 1 || evidence.uaDivergence || evidence.platformLie
  );
}

function hasStructuralTampering(evidence: TamperingEvidence): boolean {
  return (
    evidence.chUaMismatch ||
    evidence.browserEngineHardBreak ||
    evidence.cfTampered ||
    evidence.cfReplayed ||
    evidence.kernelOsMismatchHard
  );
}

function isDefinitiveTampering(evidence: TamperingEvidence): boolean {
  if (evidence.lies >= 20 || evidence.ja4Mismatch) return true;
  if (hasDivergenceTampering(evidence)) return true;
  if (evidence.webrtcApiTampered) return true;
  return hasStructuralTampering(evidence);
}

function hasTier60Signal(evidence: TamperingEvidence): boolean {
  return (
    evidence.lies >= 5 ||
    evidence.uaHeaderMismatch ||
    evidence.localeTamper ||
    evidence.tlsUaMismatch ||
    evidence.browserEngineSoft ||
    evidence.kernelOsMismatchSoft ||
    evidence.cfSlowPage ||
    evidence.patAttestationFailed ||
    evidence.deviceIdentitySigFailed ||
    evidence.deviceHistoryTampered
  );
}

function tamperingProbabilityFromEvidence(evidence: TamperingEvidence): number {
  if (isDefinitiveTampering(evidence)) return 100;
  if (hasTier60Signal(evidence)) return 60;
  if (
    evidence.iframeCryptoStuck ||
    evidence.workerOracleMissing === "main_only"
  ) {
    return 50;
  }
  if (evidence.kernelOsDarwinCorroborated || evidence.tzGeoMismatch) return 35;
  if (evidence.lies >= 1) return 25;
  return 0;
}

export function deviceTamperingProbability(
  input: MerchantProjectionInput,
): number {
  if (!input.integrity) return 0;
  return tamperingProbabilityFromEvidence(
    collectTamperingEvidence(input.integrity),
  );
}

export function tamperingWithoutWorkerDivergence(
  integrity: IntegrityResultsData,
): number {
  const evidence = collectTamperingEvidence(integrity);
  return tamperingProbabilityFromEvidence({
    ...evidence,
    divergences: 0,
    uaDivergence: false,
  });
}

export function detectLocationMismatch(
  input: MerchantProjectionInput,
): boolean {
  if (!input.integrity) return false;
  return collectTamperingEvidence(input.integrity).tzGeoMismatch;
}

export function detectLanguageMismatch(
  input: MerchantProjectionInput,
): boolean {
  if (!input.integrity) return false;
  const evidence = collectTamperingEvidence(input.integrity);
  return evidence.langGeoCrossContinent || evidence.langGeoCrossCountry;
}
