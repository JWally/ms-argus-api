/**
 * @fileoverview Merchant-safe response projection.
 *
 * Projects the full internal session + integrity record down to a small,
 * categorical surface that a merchant API consumer (or a merchant's bot-
 * building adversary who signed up for a $100 account) can safely see.
 *
 * Design principles:
 *  - No raw signal names. Adversaries should not be able to read which
 *    specific check fired ("TLS_PLATFORM_MISMATCH") — they get
 *    categorical tags instead.
 *  - No raw numeric scores. The server's noisy-OR proxy score
 *    ([0,1] float) stays internal; merchants get bucketed tags.
 *  - No component-level fingerprint breakdowns, Hamming distances,
 *    or Qdrant similarity features. These are the single biggest
 *    reconnaissance gift in the existing surface.
 *  - Forward-compat nulls (`policy`, `velocity`, `first_seen_at`) are
 *    deliberate promises — customers integrate against the shape now,
 *    real values arrive in follow-up work without a breaking change.
 *
 * See ms-argus-games/src/utils/classifyScan.ts for the client-side
 * analogue; this function is its authoritative server-side equivalent.
 *
 * @module helpers/merchant-projection
 */

import type { SessionCacheValue } from "../types/matching";
import type { SessionResponse, IntegrityResultsData } from "./payload-schema";

/**
 * Categorical merchant-safe tag vocabulary. Composable — a request can be
 * `["vpn", "browser_tampering"]` simultaneously.
 */
export type MerchantTag =
  | "vpn"
  | "proxy"
  | "hyperscaler"
  | "corporate_shield"
  | "browser_tampering"
  | "automation"
  | "incognito";

/** Ternary bot-status enum, matching FingerprintJS Pro's `bot.result` shape. */
export type BotStatus = "none" | "suspected" | "confirmed";

/**
 * The merchant-safe response shape. Attached as `merchant` on session-get
 * and integrity-session responses.
 */
export interface MerchantSafeResponse {
  session_id: string;
  device_id: string | null;
  /** True when this session minted a new device ID. */
  is_new_device: boolean;
  /** First time this device was seen, epoch ms. Null until DeviceProfile wiring lands. */
  first_seen_at: number | null;
  /** Match confidence [0,1]. Higher = stronger re-identification. */
  confidence: number;
  /** Overall device risk [0,1]. Composed from flags by flag-computation. */
  risk_score: number;
  /** Categorical bot status. */
  bot: BotStatus;
  /** Categorical classifications — composable. */
  tags: MerchantTag[];
  network: {
    asn: number | null;
    asn_org: string | null;
    country: string | null;
  };
  /** Placeholder for future policy engine. Null until a rule engine ships. */
  policy: null;
  /** Placeholder for velocity counters (FPJS-style). Null until implemented. */
  velocity: null;
}

/** Input bundle for the projection. All fields optional — richer data = richer projection. */
export interface MerchantProjectionInput {
  session_id: string;
  session?: SessionCacheValue;
  payload?: SessionResponse;
  integrity?: IntegrityResultsData;
}

// --- Tag derivation helpers (pure, testable) ---

function hasFlag(flags: string[] | undefined, flag: string): boolean {
  return !!flags?.includes(flag);
}

/**
 * VPN tag: emitted when the MSS-derived VPN component is meaningful, or
 * when the classic likely_vpn flag fired. We keep VPN distinct from proxy
 * because their risk profile and remediation differ.
 */
function detectVpn(input: MerchantProjectionInput): boolean {
  const vpnComponent = input.integrity?.analysis.network.vpn_component ?? 0;
  if (vpnComponent >= 0.5) return true;
  return hasFlag(input.session?.flags, "likely_vpn");
}

/**
 * Proxy tag: RTT-asymmetry-derived proxy_component, or the likely_proxy
 * flag. Kept distinct from VPN at the user's preference.
 */
function detectProxy(input: MerchantProjectionInput): boolean {
  const proxyComponent = input.integrity?.analysis.network.proxy_component ?? 0;
  if (proxyComponent >= 0.5) return true;
  return hasFlag(input.session?.flags, "likely_proxy");
}

function detectHyperscaler(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "datacenter";
}

function detectCorporateShield(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "corporate_proxy";
}

function tamperingFromIntegrity(integrity: IntegrityResultsData): boolean {
  const lies =
    (integrity.device as { lies?: { totalLies?: number } } | undefined)?.lies
      ?.totalLies ?? 0;
  if (lies >= 5) return true;
  const divergences = (integrity.analysis.worker.divergences ?? []).filter(
    (d) => /navigator|css|screen/i.test(d.field),
  ).length;
  if (divergences >= 1) return true;
  const ja4UaSignals = [
    ...((
      integrity.analysis as { ja4_ua?: { signals?: Array<{ code: string }> } }
    ).ja4_ua?.signals ?? []),
    ...(integrity.analysis.worker.signals ?? []),
  ];
  return ja4UaSignals.some((s) => s.code === "JA4_UA_BROWSER_MISMATCH");
}

const TAMPERING_FLAGS: readonly string[] = [
  "navigator_lies",
  "tls_platform_mismatch",
  "tls_browser_mismatch",
  "worker_mismatch",
  "worker_locale_mismatch",
  "engine_mismatch",
];

/**
 * Browser tampering: user-agent/navigator lies, worker scope divergence,
 * or TLS/UA mismatch. Thresholds track classifyScan's MEDIUM tier — below
 * this, false-positive noise is too high for a merchant-facing tag.
 */
function detectBrowserTampering(input: MerchantProjectionInput): boolean {
  if (input.integrity && tamperingFromIntegrity(input.integrity)) return true;
  return TAMPERING_FLAGS.some((f) => hasFlag(input.session?.flags, f));
}

interface HeadlessSignals {
  webDriverIsOn?: boolean;
  likeHeadlessRating?: number;
  stealthRating?: number;
}

function readHeadless(
  integrity: IntegrityResultsData,
): HeadlessSignals | undefined {
  return (integrity.device as { headless?: HeadlessSignals } | undefined)
    ?.headless;
}

function automationFromIntegrity(integrity: IntegrityResultsData): boolean {
  const headless = readHeadless(integrity);
  if (headless?.webDriverIsOn) return true;
  if ((headless?.likeHeadlessRating ?? 0) >= 20) return true;
  if ((headless?.stealthRating ?? 0) > 0) return true;
  const vmSignalCount = (integrity.vm_signals ?? []).filter((s) =>
    /worker_lied|no_taskbar|webdriver|no_chrome/.test(s),
  ).length;
  return vmSignalCount >= 2;
}

/**
 * Automation: webdriver detection, headless rating, or VM indicators.
 * Matches classifyScan's MEDIUM-or-higher thresholds.
 */
function detectAutomation(input: MerchantProjectionInput): boolean {
  if (input.integrity && automationFromIntegrity(input.integrity)) return true;
  return (
    hasFlag(input.session?.flags, "bot_detected") ||
    hasFlag(input.session?.flags, "headless_browser")
  );
}

function detectIncognito(input: MerchantProjectionInput): boolean {
  // No dedicated incognito detector exists yet — use the mismatch flag as
  // an approximation. This tag will become more accurate when a first-class
  // incognito detector ships.
  return hasFlag(input.session?.flags, "incognito_browser_mismatch");
}

function buildTags(input: MerchantProjectionInput): MerchantTag[] {
  const tags: MerchantTag[] = [];
  if (detectVpn(input)) tags.push("vpn");
  if (detectProxy(input)) tags.push("proxy");
  if (detectHyperscaler(input)) tags.push("hyperscaler");
  if (detectCorporateShield(input)) tags.push("corporate_shield");
  if (detectBrowserTampering(input)) tags.push("browser_tampering");
  if (detectAutomation(input)) tags.push("automation");
  if (detectIncognito(input)) tags.push("incognito");
  return tags;
}

function deriveBot(input: MerchantProjectionInput): BotStatus {
  const { integrity, session } = input;
  // Confirmed: hard signals (flag set or webdriver on)
  if (
    hasFlag(session?.flags, "bot_detected") ||
    hasFlag(session?.flags, "headless_browser")
  ) {
    return "confirmed";
  }
  const headless = (
    integrity?.device as
      | { headless?: { webDriverIsOn?: boolean; likeHeadlessRating?: number } }
      | undefined
  )?.headless;
  if (headless?.webDriverIsOn) return "confirmed";
  // Suspected: heuristic signals
  if ((headless?.likeHeadlessRating ?? 0) >= 20) return "suspected";
  const vmSignalCount = (integrity?.vm_signals ?? []).length;
  if (vmSignalCount >= 2) return "suspected";
  return "none";
}

function parseAsnNumber(raw: string | null | undefined): number | null {
  if (!raw) return null;
  // ASN can come through as "AS12345" or "12345" — strip prefix.
  const cleaned = String(raw).replace(/^AS/i, "");
  const n = Number(cleaned);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function deriveNetwork(
  input: MerchantProjectionInput,
): MerchantSafeResponse["network"] {
  const { integrity, payload } = input;
  // Prefer integrity analysis (already resolved + categorized), fall back
  // to raw sigint data in the session payload.
  const asnFromIntegrity = integrity?.analysis.ip.asn;
  if (asnFromIntegrity) {
    return {
      asn: parseAsnNumber(asnFromIntegrity.number),
      asn_org: asnFromIntegrity.org ?? null,
      country: null, // country isn't in integrity analysis.ip today
    };
  }
  const awsCf = (
    payload?.sigint as
      | { aws_cf?: { asn?: string | null; country?: string | null } }
      | undefined
  )?.aws_cf;
  return {
    asn: parseAsnNumber(awsCf?.asn),
    asn_org: null,
    country: awsCf?.country ?? null,
  };
}

/**
 * Project the internal session / integrity record down to the merchant-
 * safe shape. Safe to call with partial inputs — missing data yields
 * conservative defaults (no tags, bot: "none", nulls in network).
 */
export function buildMerchantResponse(
  input: MerchantProjectionInput,
): MerchantSafeResponse {
  const { session, payload, session_id } = input;
  const device_id =
    session?.device_id || payload?.identifiers.device_id || null;

  const is_new_device =
    payload?.analysis.is_new_device ??
    session?.evidence_codes?.includes("NEW_DEVICE") ??
    false;

  const confidence = payload?.analysis.confidence ?? session?.confidence ?? 0;

  const risk_score = payload?.analysis.risk_score ?? session?.risk_score ?? 0;

  return {
    session_id,
    device_id,
    is_new_device,
    first_seen_at: null, // TODO: fetch DeviceProfile.first_seen_at
    confidence,
    risk_score,
    bot: deriveBot(input),
    tags: buildTags(input),
    network: deriveNetwork(input),
    policy: null,
    velocity: null,
  };
  // intentional trailing comment marker: projection is deliberately lean —
  // every field added here becomes an adversary oracle.
}
