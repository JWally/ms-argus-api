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

import { createHash } from "node:crypto";
import type { SessionCacheValue } from "../types/matching";
import type { SessionResponse, IntegrityResultsData } from "./payload-schema";

/**
 * SHA-256 hex of the SPKI-base64 pubkey. Exposed to merchants as a stable
 * cross-session identifier without handing them the raw key bytes. Same
 * input always → same output, so correlation works; merchants can't use the
 * hash to impersonate the client or reconstruct the key.
 */
function hashPubkey(pubkey: string): string {
  return createHash("sha256").update(pubkey).digest("hex");
}

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
  | "incognito"
  /** Client appears to be on a cellular carrier (ASN is a known mobile
   *  carrier or webrtc-vs-probes pattern matches CGNAT mobile NAT). */
  | "cellular"
  /** Client did not submit a MAC-verified WebRTC srflx candidate.
   *  Merchants should cross-correlate with ASN (corp proxies strip it)
   *  and browser tags to decide policy. */
  | "no_webrtc";

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
    /**
     * Discrete network-trust score 0.0–1.0. Tiers:
     *   1.0 = all probes + webrtc agree (or CGNAT-pattern webrtc solo),
     *   0.5–0.8 = partial scatter within same /16,
     *   0.5 = no webrtc submitted,
     *   0.1 = any IP on a different /16 (proxy, VPN, corp gateway),
     *   0.0 = cryptographic forgery evidence.
     * Distinct from `risk_score` — this is network-layer only.
     */
    integrity: number;
    /**
     * Representative client IP. MAC-verified webrtc IP when available;
     * else tls/tcp consensus. Null at integrity < 0.5.
     */
    ip: string | null;
  };
  /**
   * Cryptographic device identity. Distinct from `device_id` above — that's
   * the match-derived ID (probabilistic); this is the client-asserted ECDSA
   * pubkey (cryptographic). Null when the client didn't send a device_identity
   * block (legacy bundle) or when we couldn't attribute one. Merchants can
   * use `device_id` as a stable re-identifier across sessions when `verified`
   * is true. The field is SHA-256(pubkey) rather than the raw key — correlation
   * works across sessions (same input → same hash) without exposing the
   * pubkey bytes. No internal verification reasons are exposed here.
   */
  identification: {
    device_id: string;
    verified: boolean;
  } | null;
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
  return (
    !!headless?.webDriverIsOn ||
    (headless?.likeHeadlessRating ?? 0) >= 20 ||
    (headless?.stealthRating ?? 0) > 0
  );
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

/**
 * Cellular tag: fires when the ASN is a known mobile carrier, or when the
 * WebRTC-vs-probes pattern matches CGNAT (SAME_SUBNET_CGNAT signal). Either
 * gate alone is enough — many iOS browsers don't emit WebRTC, so ASN is the
 * only available signal in those cases.
 */
function detectCellular(input: MerchantProjectionInput): boolean {
  if (input.integrity?.analysis.ip.asn.category === "mobile") return true;
  const signals = input.integrity?.analysis.ip.signals ?? [];
  return signals.some((s) => s.code === "SAME_SUBNET_CGNAT");
}

/**
 * `no_webrtc` tag: no MAC-verified WebRTC IP available. Fires whether
 * WebRTC was absent entirely, blocked at UDP, or submitted with bad
 * candidates. Suppressed when forgery was detected (score 0.0) — at that
 * tier we give no hints.
 */
function detectNoWebrtc(input: MerchantProjectionInput): boolean {
  const ipAnalysis = input.integrity?.analysis.ip;
  if (!ipAnalysis) return false;
  if (ipAnalysis.integrity === 0) return false;
  return ipAnalysis.ips.webrtc === null;
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
  if (detectCellular(input)) tags.push("cellular");
  if (detectNoWebrtc(input)) tags.push("no_webrtc");
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
  const ipAnalysis = integrity?.analysis.ip;
  // Defaults when integrity data is absent (legacy bundle / session-only).
  // Integrity score defaults to 0.5 (unknown) rather than 0 so a merchant
  // that hasn't hit integrity-collect yet doesn't get flagged as forged.
  const integrityScore = ipAnalysis?.integrity ?? 0.5;
  const ip = ipAnalysis?.ip ?? null;

  const asnFromIntegrity = ipAnalysis?.asn;
  if (asnFromIntegrity) {
    return {
      asn: parseAsnNumber(asnFromIntegrity.number),
      asn_org: asnFromIntegrity.org ?? null,
      country: null, // country isn't in integrity analysis.ip today
      integrity: integrityScore,
      ip,
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
    integrity: integrityScore,
    ip,
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

  const identification = input.integrity?.identification
    ? {
        device_id: hashPubkey(input.integrity.identification.pubkey),
        verified: input.integrity.identification.verified,
      }
    : null;

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
    identification,
    policy: null,
    velocity: null,
  };
  // intentional trailing comment marker: projection is deliberately lean —
  // every field added here becomes an adversary oracle.
}
