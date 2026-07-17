/** Typed readers for identity, browser-engine, locale, and wire evidence. */

import type { IntegrityResultsData } from "../helpers/payload-schema";

interface Signal {
  code: string;
  severity?: number;
}

interface Ja4UaView {
  signals?: Signal[];
  ja4_browser_family?: string | null;
  h2_browser_family?: string | null;
  ua_browser_family?: string | null;
  ua_os?: string | null;
}

function readAnalysisBlock<T>(
  integrity: IntegrityResultsData,
  key: string,
): T | undefined {
  return (integrity.analysis as unknown as Record<string, T | undefined>)[key];
}

function readJa4Ua(integrity: IntegrityResultsData): Ja4UaView | undefined {
  return readAnalysisBlock<Ja4UaView>(integrity, "ja4_ua");
}

export interface Ja4UaSignalInfo {
  ja4Mismatch: boolean;
  h2Mismatch: boolean;
  strongMismatch: boolean;
}

export function readJa4UaSignals(
  integrity: IntegrityResultsData,
): Ja4UaSignalInfo {
  const signals = [
    ...(readJa4Ua(integrity)?.signals ?? []),
    ...(integrity.analysis.worker?.signals ?? []),
  ];
  const ja4 = signals.find(
    (signal) => signal.code === "JA4_UA_BROWSER_MISMATCH",
  );
  const h2 = signals.find((signal) => signal.code === "H2_UA_BROWSER_MISMATCH");
  return {
    ja4Mismatch: !!ja4,
    h2Mismatch: !!h2,
    strongMismatch: (ja4?.severity ?? 0) >= 0.9 || (h2?.severity ?? 0) >= 0.9,
  };
}

export function hasJa4UaMismatch(integrity: IntegrityResultsData): boolean {
  return readJa4UaSignals(integrity).ja4Mismatch;
}

export function hasTlsUaMismatch(integrity: IntegrityResultsData): boolean {
  return (readJa4Ua(integrity)?.signals ?? []).some(
    (signal) => signal.code === "TLS_UA_MISMATCH",
  );
}

export function isCorporateShieldedAsn(
  integrity: IntegrityResultsData,
): boolean {
  return integrity.analysis?.ip?.asn?.category === "corporate_proxy";
}

function isSafariDarwin(ja4Ua: Ja4UaView | undefined): boolean {
  return (
    ja4Ua?.ja4_browser_family === "safari" &&
    ja4Ua.h2_browser_family === "safari" &&
    (ja4Ua.ua_os === "iOS" || ja4Ua.ua_os === "macOS")
  );
}

/** Apple relay ground truth, with Safari wire convergence as fallback. */
export function isVerifiedAppleRelay(integrity: IntegrityResultsData): boolean {
  if ((integrity as { apple_relay_egress?: unknown }).apple_relay_egress) {
    return true;
  }
  if (integrity.analysis?.ip?.asn?.category !== "privacy_relay") return false;
  return isSafariDarwin(readJa4Ua(integrity));
}

export function readBrowserEngineSignals(integrity: IntegrityResultsData): {
  hard: boolean;
  soft: boolean;
} {
  const browserEngine = readAnalysisBlock<{ signals?: Signal[] }>(
    integrity,
    "browser_engine",
  );
  const signals = browserEngine?.signals ?? [];
  return {
    hard: signals.some(
      (signal) => signal.code === "BROWSER_ENGINE_INCONSISTENT_HARD",
    ),
    soft: signals.some(
      (signal) => signal.code === "BROWSER_ENGINE_INCONSISTENT_SOFT",
    ),
  };
}

export function readKernelOsSignals(integrity: IntegrityResultsData): {
  hard: boolean;
  soft: boolean;
} {
  const kernelOs = readAnalysisBlock<{ signals?: Signal[] }>(
    integrity,
    "kernel_os",
  );
  const signals = kernelOs?.signals ?? [];
  const darwinMismatch = signals.some(
    (signal) => signal.code === "KERNEL_OS_MISMATCH_DARWIN",
  );
  const linuxMismatch = signals.some(
    (signal) => signal.code === "KERNEL_OS_MISMATCH_LINUX",
  );
  const corroborated = darwinMismatch && isSafariDarwin(readJa4Ua(integrity));
  return {
    hard: darwinMismatch && !corroborated,
    soft: linuxMismatch || corroborated,
  };
}

function hasBodyClientHints(integrity: IntegrityResultsData): boolean {
  const navigator = (
    integrity.device as
      | { navigator?: { userAgentData?: { brands?: unknown } } }
      | undefined
  )?.navigator;
  const brands = navigator?.userAgentData?.brands;
  return Array.isArray(brands) && brands.length > 0;
}

export function detectUaFamilyHeaderMismatch(
  integrity: IntegrityResultsData,
): boolean {
  const headers = integrity.request_headers?.headers ?? {};
  if ((headers["sec-ch-ua"]?.length ?? 0) > 0) return false;
  const ua = integrity.user_agent ?? headers["user-agent"] ?? "";
  const chromium =
    /Chrome\/\d/.test(ua) && !/Edg(e|A|iOS)?\//.test(`${ua} nope`);
  return chromium && !hasBodyClientHints(integrity);
}

export function readChUaMismatch(integrity: IntegrityResultsData): boolean {
  const clientHints = readAnalysisBlock<{ hasStrongMismatch?: boolean }>(
    integrity,
    "client_hints_ua",
  );
  return clientHints?.hasStrongMismatch === true;
}

export interface LocaleGeoSignals {
  localeTamper: boolean;
  crossContinent: boolean;
  crossCountry: boolean;
}

export function readLocaleGeoSignals(
  integrity: IntegrityResultsData,
): LocaleGeoSignals {
  const localeGeo = readAnalysisBlock<{
    hasLocaleTamper?: boolean;
    signals?: Signal[];
  }>(integrity, "locale_geo");
  const codes = new Set(
    (localeGeo?.signals ?? []).map((signal) => signal.code),
  );
  return {
    localeTamper: localeGeo?.hasLocaleTamper === true,
    crossContinent: codes.has("ACCEPT_LANG_GEO_CROSS_CONTINENT"),
    crossCountry: codes.has("ACCEPT_LANG_GEO_CROSS_COUNTRY"),
  };
}

export function readTzGeoMismatch(integrity: IntegrityResultsData): boolean {
  return (integrity.analysis.timezone?.signals ?? []).some(
    (signal) => signal.code === "TZ_GEOLOCATION_MISMATCH",
  );
}

export function readUaIdentity(integrity: IntegrityResultsData): {
  browserFamily: string | null;
  os: string | null;
} {
  const ja4Ua = readJa4Ua(integrity);
  return {
    browserFamily: ja4Ua?.ua_browser_family ?? null,
    os: ja4Ua?.ua_os ?? null,
  };
}
