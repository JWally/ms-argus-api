/**
 * @fileoverview Merchant-safe response projection.
 *
 * Projects the full internal session + integrity record down to a small,
 * FingerprintJS-Pro-shaped surface that a merchant API consumer (or a
 * merchant's bot-building adversary who signed up for a $100 account)
 * can safely see.
 *
 * Design principles:
 *  - Shape tracks FPJS Pro product blocks: `identification`, `bot`, `vpn`,
 *    `proxy`, `incognito`, `tampering`, `ipLocation`, `ipInfo`. Makes
 *    integration familiar for customers coming from the market leader.
 *  - Deliberately tighter than FPJS: we do NOT expose `vpn.methods`,
 *    `tampering.anomalyScore`, `ipInfo.datacenter.name`, or
 *    `rawDeviceAttributes`/`components`. All addable later without
 *    breaking — removal would break consumers.
 *  - No raw signal names. Adversaries should not read which specific
 *    check fired ("TLS_PLATFORM_MISMATCH") — they get categorical
 *    `result` booleans and bucketed `confidence` instead.
 *  - No raw numeric component scores. The server's noisy-OR proxy score,
 *    vpn_component, etc. stay internal; merchants get a categorical
 *    low/medium/high `confidence`. This kills the scalar tuning oracle.
 *  - `networkIntegrity.score` is our differentiator — FPJS doesn't
 *    publish a WebRTC↔probe consensus score.
 *  - Forward-compat nulls (`policy`, `velocity`, `first_seen_at`,
 *    `last_seen_at`) are deliberate promises — customers integrate
 *    against the shape now, real values arrive in follow-up work
 *    without a breaking change.
 *
 * @module helpers/merchant-projection
 */

import { createHash } from "node:crypto";
import type { SessionCacheValue } from "../types/matching";
import type { SessionResponse, IntegrityResultsData } from "./payload-schema";

/** Truncated SHA-256 length (hex chars). 40 bits of entropy — ample for
 *  cross-session correlation at merchant scale; compact enough to read. */
const CRYPTO_DEVICE_ID_LEN = 10;

/**
 * Truncated SHA-256 hex of the SPKI-base64 pubkey. Exposed to merchants as a
 * stable cross-session identifier without handing them the raw key bytes.
 * Same input always → same output, so correlation works; merchants can't
 * use the hash to impersonate the client or reconstruct the key.
 */
function hashPubkey(pubkey: string): string {
  return createHash("sha256")
    .update(pubkey)
    .digest("hex")
    .slice(0, CRYPTO_DEVICE_ID_LEN);
}

/** Round a [0,1] unit score up to a nearest-5 percentage in [0,100]. */
function probabilityFromUnit(score: number): number {
  const clamped = Math.max(0, Math.min(1, score));
  return Math.round((clamped * 100) / 5) * 5;
}

/** Round an already-percentage value to the nearest 5 in [0,100]. */
function roundProbability(pct: number): number {
  const clamped = Math.max(0, Math.min(100, pct));
  return Math.round(clamped / 5) * 5;
}

/**
 * Categorical merchant-safe tag vocabulary. Composable — a request can be
 * `["vpn", "browser_tampering"]` simultaneously. Kept alongside the
 * FPJS-style product blocks as a convenience summary for dashboards.
 */
export type MerchantTag =
  | "vpn"
  | "proxy"
  | "hyperscaler"
  | "corporate_shield"
  | "browser_tampering"
  | "automation"
  | "incognito"
  | "cellular"
  | "no_webrtc";

export interface BrowserDetails {
  browserName: string | null;
  browserVersion: string | null;
  os: string | null;
  osVersion: string | null;
  device: string | null;
  userAgent: string | null;
}

export interface MerchantIdentification {
  /** Probabilistic, match-derived device ID — stable across sessions. */
  device_id: string | null;
  is_new_device: boolean;
  /** Epoch ms. Null until DeviceProfile wiring lands. */
  first_seen_at: number | null;
  /** Epoch ms. Null until DeviceProfile wiring lands. */
  last_seen_at: number | null;
  /** Match confidence — did we re-identify this device accurately? */
  confidence: { score: number };
  /** SHA-256 of the client's ECDSA pubkey. Cryptographic identity, distinct
   *  from `device_id` (match-derived). Null on legacy bundles. */
  crypto_device_id: string | null;
  /** Whether the cryptographic identity signature verified. Null when the
   *  client didn't send a `device_identity` block. No verification reasons
   *  are exposed — those are internal pipeline state. */
  crypto_verified: boolean | null;
  /** Opaque id carried across sessions in the CloudFront-stamped third-party
   *  cookie. Null when the cookie is absent or failed verification. */
  tpc_id: string | null;
  /** Unix seconds when the cookie was originally minted at the CF edge.
   *  Null when the cookie is absent or failed verification. */
  tpc_created: number | null;
  /** "pass" iff the cookie verified against the current TLS token; "fail"
   *  when the cookie arrived but tampered/mismatched; null when absent. */
  tpc_verified: "pass" | "fail" | null;
  browserDetails: BrowserDetails;
}

export interface MerchantIpLocation {
  city: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
}

export interface MerchantIpInfo {
  asn: {
    number: number | null;
    organization: string | null;
    category: string | null;
  };
  datacenter: { result: boolean };
}

export interface MerchantRequestHeaders {
  /** Curated subset of request headers (see CAPTURED_REQUEST_HEADER_NAMES). */
  headers: Record<string, string>;
  /** Cookie *names* present on the request — values are never captured. */
  cookie_names: string[];
}

/**
 * The merchant-safe response shape. Returned as the top-level body of
 * `/v1/integrity-session` (spread, not wrapped).
 */
export interface MerchantSafeResponse {
  session_id: string;
  /** Epoch ms. Null when the record pre-dates the field. */
  created_at: number | null;
  /** TTL epoch seconds (when this record will be purged). */
  ttl: number | null;

  identification: MerchantIdentification;

  /** Representative client IP. MAC-verified WebRTC IP when available, else
   *  probe consensus. Null when integrity score < 0.5. */
  ip: string | null;
  ipLocation: MerchantIpLocation;
  ipInfo: MerchantIpInfo;

  /**
   * Probabilistic detectors. `probability` is a merchant-readable percentage
   * (0–100), rounded to the nearest 5 to prevent fractional tuning oracles.
   * Customers treat >= 50 as "likely"; we fire the corresponding tag at
   * the same threshold.
   */
  bot: { probability: number };
  vpn: { probability: number };
  proxy: { probability: number };
  tampering: { probability: number };
  /** Direct observation (client flag), not probabilistic. */
  incognito: { result: boolean };
  /**
   * Discrete network-trust score 0.0–1.0 from WebRTC↔probe↔TLS consensus.
   * Unique to us — FPJS doesn't publish this. Distinct from `suspectScore`
   * (composite risk) — this is network-layer only.
   *   1.0 = all probes + webrtc agree (or CGNAT-pattern webrtc solo)
   *   0.5–0.8 = partial scatter within same /16
   *   0.5 = no webrtc submitted
   *   0.1 = any IP on a different /16 (proxy, VPN, corp gateway)
   *   0.0 = cryptographic forgery evidence
   */
  networkIntegrity: { score: number };
  /** Composite risk score [0,1] — higher = riskier. Null when no risk model
   *  has run on this session yet (e.g. integrity-only flow without matching). */
  suspectScore: { result: number | null };

  /** Convenience summary of classifications. Composable with product blocks. */
  tags: MerchantTag[];

  /** Curated request headers preserved at ingestion. Null for pre-capture records. */
  requestHeaders: MerchantRequestHeaders | null;

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

function detectHyperscaler(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "datacenter";
}

function detectCorporateShield(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "corporate_proxy";
}

/**
 * Corporate egress gateways (e.g. Cisco Umbrella, Zscaler) route traffic
 * through rotating PoPs, which look identical to VPN/proxy TCP/MSS signals.
 * When we've already classified the ASN as a corporate shield, the VPN/proxy
 * component scores are false positives — zero them out rather than double-
 * flagging the same benign condition.
 */
function vpnScore(input: MerchantProjectionInput): number {
  if (detectCorporateShield(input)) return 0;
  const component = input.integrity?.analysis.network.vpn_component ?? 0;
  if (component > 0) return component;
  return hasFlag(input.session?.flags, "likely_vpn") ? 0.5 : 0;
}

function proxyScore(input: MerchantProjectionInput): number {
  if (detectCorporateShield(input)) return 0;
  const component = input.integrity?.analysis.network.proxy_component ?? 0;
  if (component > 0) return component;
  return hasFlag(input.session?.flags, "likely_proxy") ? 0.5 : 0;
}

const TAMPERING_FLAGS: readonly string[] = [
  "navigator_lies",
  "tls_platform_mismatch",
  "tls_browser_mismatch",
  "worker_mismatch",
  "worker_locale_mismatch",
  "engine_mismatch",
];

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

function detectIncognito(input: MerchantProjectionInput): boolean {
  const isPrivate = (
    input.integrity?.device as
      | { incognito?: { isPrivate?: boolean } }
      | undefined
  )?.incognito?.isPrivate;
  if (isPrivate === true) return true;
  return hasFlag(input.session?.flags, "incognito_browser_mismatch");
}

function detectCellular(input: MerchantProjectionInput): boolean {
  if (input.integrity?.analysis.ip.asn.category === "mobile") return true;
  const signals = input.integrity?.analysis.ip.signals ?? [];
  return signals.some((s) => s.code === "SAME_SUBNET_CGNAT");
}

function detectNoWebrtc(input: MerchantProjectionInput): boolean {
  const ipAnalysis = input.integrity?.analysis.ip;
  if (!ipAnalysis) return false;
  if (ipAnalysis.integrity === 0) return false;
  return ipAnalysis.ips.webrtc === null;
}

function buildTags(
  input: MerchantProjectionInput,
  probs: { bot: number; vpn: number; proxy: number; tampering: number },
): MerchantTag[] {
  const tags: MerchantTag[] = [];
  if (probs.vpn >= 50) tags.push("vpn");
  if (probs.proxy >= 50) tags.push("proxy");
  if (detectHyperscaler(input)) tags.push("hyperscaler");
  if (detectCorporateShield(input)) tags.push("corporate_shield");
  if (probs.tampering >= 50) tags.push("browser_tampering");
  if (probs.bot >= 50) tags.push("automation");
  if (detectIncognito(input)) tags.push("incognito");
  if (detectCellular(input)) tags.push("cellular");
  if (detectNoWebrtc(input)) tags.push("no_webrtc");
  return tags;
}

function botProbability(input: MerchantProjectionInput): number {
  const { integrity, session } = input;
  if (
    hasFlag(session?.flags, "bot_detected") ||
    hasFlag(session?.flags, "headless_browser")
  ) {
    return 100;
  }
  const headless = readHeadless(integrity ?? ({} as IntegrityResultsData));
  if (headless?.webDriverIsOn) return 100;
  const rating = headless?.likeHeadlessRating ?? 0;
  const stealth = headless?.stealthRating ?? 0;
  // likeHeadlessRating is already ~0..100 in practice; stealth bumps it.
  return roundProbability(rating + (stealth > 0 ? 20 : 0));
}

interface Ja4UaSignalInfo {
  ja4Mismatch: boolean;
  h2Mismatch: boolean;
  /** True iff any of the above arrived with sev >= 0.9 (high-confidence). */
  strongMismatch: boolean;
}

function readJa4UaSignals(integrity: IntegrityResultsData): Ja4UaSignalInfo {
  const sigs: Array<{ code: string; severity: number }> = [
    ...((
      integrity.analysis as {
        ja4_ua?: { signals?: Array<{ code: string; severity: number }> };
      }
    ).ja4_ua?.signals ?? []),
    ...(integrity.analysis.worker.signals ?? []),
  ];
  const ja4 = sigs.find((s) => s.code === "JA4_UA_BROWSER_MISMATCH");
  const h2 = sigs.find((s) => s.code === "H2_UA_BROWSER_MISMATCH");
  return {
    ja4Mismatch: !!ja4,
    h2Mismatch: !!h2,
    strongMismatch: (ja4?.severity ?? 0) >= 0.9 || (h2?.severity ?? 0) >= 0.9,
  };
}

function hasJa4UaMismatch(integrity: IntegrityResultsData): boolean {
  return readJa4UaSignals(integrity).ja4Mismatch;
}

/** Read the device.lies.data keys — each key identifies a tampered API. */
function readLieKeys(integrity: IntegrityResultsData | undefined): string[] {
  const data = (
    integrity?.device as
      | { lies?: { data?: Record<string, unknown> } }
      | undefined
  )?.lies?.data;
  return data ? Object.keys(data) : [];
}

/** (A) Detect RTCPeerConnection API tampering — the bot patched WebRTC itself. */
const WEBRTC_API_LIE_PATTERN =
  /createDataChannel|createOffer|setLocalDescription|setRemoteDescription|iceConnectionState|connectionState|localDescription|addIceCandidate|generateCertificate/;

function detectWebrtcApiTampering(
  integrity: IntegrityResultsData | undefined,
): boolean {
  return readLieKeys(integrity).some((k) => WEBRTC_API_LIE_PATTERN.test(k));
}

/**
 * (E) UA claims a Chromium browser but the request carries no Sec-CH-UA
 * header. Real Chromium always emits Sec-CH-UA on same/cross-origin POSTs.
 * Pairs with JA4 mismatch: this catches the case where UA + JA4 agree on
 * Chromium but the client hints are missing (stealth-strip headers).
 */
function detectUaFamilyHeaderMismatch(
  integrity: IntegrityResultsData | undefined,
): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const secChUa = headers["sec-ch-ua"];
  if (secChUa && secChUa.length > 0) return false;
  const ua = integrity.user_agent ?? headers["user-agent"] ?? "";
  // UA token "Chrome/<ver>" reliably indicates Chromium-stack Chrome/Edge.
  return /Chrome\/\d/.test(ua) && !/Edg(e|A|iOS)\//.test(ua + " nope");
}

/** Has-lie helpers for the tampering decision (D). */
function hasPlatformLie(integrity: IntegrityResultsData | undefined): boolean {
  return readLieKeys(integrity).some((k) => /Navigator\.platform/i.test(k));
}

function hasUaWorkerDivergence(
  integrity: IntegrityResultsData | undefined,
): boolean {
  return !!integrity?.analysis.worker.divergences?.some(
    (d) => d.field === "userAgent",
  );
}

/**
 * Tampering probability. Hard signals (many lies / JA4-UA mismatch /
 * multiple scope divergences / WebRTC API tampering) → 100. Compound
 * (5+ lies AND {UA divergence | platform lie}) → 100. Sec-CH-UA absence
 * on Chromium-claimed UA → floor 60. Otherwise the graded tiers.
 */
interface TamperingEvidence {
  lies: number;
  divergences: number;
  ja4Mismatch: boolean;
  webrtcApiTampered: boolean;
  uaDivergence: boolean;
  platformLie: boolean;
  uaHeaderMismatch: boolean;
}

function collectTamperingEvidence(
  integrity: IntegrityResultsData,
): TamperingEvidence {
  const lies =
    (integrity.device as { lies?: { totalLies?: number } } | undefined)?.lies
      ?.totalLies ?? 0;
  const divergences = (integrity.analysis.worker.divergences ?? []).filter(
    (d) => /navigator|css|screen/i.test(d.field),
  ).length;
  return {
    lies,
    divergences,
    ja4Mismatch: hasJa4UaMismatch(integrity),
    webrtcApiTampered: detectWebrtcApiTampering(integrity),
    uaDivergence: hasUaWorkerDivergence(integrity),
    platformLie: hasPlatformLie(integrity),
    uaHeaderMismatch: detectUaFamilyHeaderMismatch(integrity),
  };
}

function isDefinitiveTampering(e: TamperingEvidence): boolean {
  if (e.lies >= 20 || e.ja4Mismatch || e.divergences >= 3) return true;
  if (e.webrtcApiTampered) return true;
  // (D) Compound: lies + a second-order spoof-indicator
  return e.lies >= 5 && (e.uaDivergence || e.platformLie);
}

function tamperingProbabilityFromEvidence(e: TamperingEvidence): number {
  if (isDefinitiveTampering(e)) return 100;
  if (e.lies >= 5 || e.divergences >= 1) return 60;
  // (E) Header/UA inconsistency on Chromium — credible spoof even without lies
  if (e.uaHeaderMismatch) return 60;
  if (e.lies >= 1) return 25;
  return 0;
}

function tamperingProbability(input: MerchantProjectionInput): number {
  if (!input.integrity) {
    return TAMPERING_FLAGS.some((f) => hasFlag(input.session?.flags, f))
      ? 60
      : 0;
  }
  return tamperingProbabilityFromEvidence(
    collectTamperingEvidence(input.integrity),
  );
}

function parseAsnNumber(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const cleaned = String(raw).replace(/^AS/i, "");
  const n = Number(cleaned);
  return Number.isFinite(n) && n > 0 ? n : null;
}

interface AwsCfSigint {
  asn?: string | null;
  country?: string | null;
  city?: string | null;
  lat?: string | null;
  lon?: string | null;
  tz?: string | null;
  ip?: string | null;
  ts?: number | null;
  /** Opaque id stamped into the third-party cookie at TLS edge. */
  id?: string | null;
  /** Unix seconds when the cookie was minted. */
  issuedAt?: number | null;
  /** True when the submitted cookie didn't verify (absent counts as tampered). */
  cookieTampered?: boolean | null;
  /** True when the cookie's id+issuedAt match the current TLS token. */
  cookieMatchesToken?: boolean | null;
}

function readAwsCf(input: MerchantProjectionInput): AwsCfSigint | undefined {
  const fromIntegrity = (
    input.integrity?.sigint as { aws_cf?: AwsCfSigint } | undefined
  )?.aws_cf;
  if (fromIntegrity) return fromIntegrity;
  return (input.payload?.sigint as { aws_cf?: AwsCfSigint } | undefined)
    ?.aws_cf;
}

function toFloat(raw: string | number | null | undefined): number | null {
  if (raw === null || raw === undefined || raw === "") return null;
  const n = typeof raw === "number" ? raw : Number(raw);
  return Number.isFinite(n) ? n : null;
}

function deriveIpLocation(input: MerchantProjectionInput): MerchantIpLocation {
  const awsCf = readAwsCf(input);
  return {
    city: awsCf?.city ?? null,
    country: awsCf?.country ?? null,
    latitude: toFloat(awsCf?.lat),
    longitude: toFloat(awsCf?.lon),
    timezone: awsCf?.tz ?? null,
  };
}

function deriveIpInfo(input: MerchantProjectionInput): MerchantIpInfo {
  const asnFromIntegrity = input.integrity?.analysis.ip.asn;
  if (asnFromIntegrity) {
    return {
      asn: {
        number: parseAsnNumber(asnFromIntegrity.number),
        organization: asnFromIntegrity.org,
        category: asnFromIntegrity.category,
      },
      datacenter: { result: asnFromIntegrity.category === "datacenter" },
    };
  }
  const awsCf = readAwsCf(input);
  return {
    asn: {
      number: parseAsnNumber(awsCf?.asn),
      organization: null,
      category: null,
    },
    datacenter: { result: false },
  };
}

function deriveIp(input: MerchantProjectionInput): string | null {
  return input.integrity?.analysis.ip.ip ?? readAwsCf(input)?.ip ?? null;
}

interface NavigatorShape {
  userAgent?: string;
  userAgentParsed?: string;
  system?: string;
  device?: string;
  oscpu?: string;
}

function readNavigator(
  integrity: IntegrityResultsData | undefined,
): NavigatorShape | undefined {
  return (integrity?.device as { navigator?: NavigatorShape } | undefined)
    ?.navigator;
}

function deriveBrowserDetails(input: MerchantProjectionInput): BrowserDetails {
  const nav = readNavigator(input.integrity);
  const parsed = nav?.userAgentParsed ?? "";
  // "Firefox 148" → ["Firefox", "148"]
  const [browserName, browserVersion] = parsed
    ? [
        parsed.replace(/\s+\d.*$/, "") || null,
        (parsed.match(/\d.*$/) ?? [null])[0],
      ]
    : [null, null];
  return {
    browserName,
    browserVersion,
    os: nav?.system ?? null,
    osVersion: null,
    device: nav?.device ?? null,
    userAgent: nav?.userAgent ?? input.integrity?.user_agent ?? null,
  };
}

interface TpcFields {
  tpc_id: string | null;
  tpc_created: number | null;
  tpc_verified: "pass" | "fail" | null;
}

const TPC_EMPTY: TpcFields = {
  tpc_id: null,
  tpc_created: null,
  tpc_verified: null,
};

function hasSignalCode(
  signals: Array<{ code: string }> | undefined,
  code: string,
): boolean {
  return !!signals?.some((s) => s.code === code);
}

function readAsnCategory(
  input: MerchantProjectionInput,
): string | null | undefined {
  return input.integrity?.analysis.ip.asn.category;
}

/**
 * Compose the merchant-facing networkIntegrity score from:
 *   - raw probe-consistency score (ip-consistency/index.ts tiers)
 *   - corp-shield clamp (residential-ish footprint: probe scatter expected)
 *   - JA4/H2 browser-family mismatch clamp (C): strong TLS forgery evidence
 *   - compound proxy/VPN noisy-OR downgrade (B): multiple hiding signals stack
 *   - webrtc-blocked on non-residential ASN (F): privacy excuse doesn't fit
 *
 * Forgery evidence (raw=0) is never up-rated — crypto failures can't be
 * masked by ASN category or tier math.
 */
/** (F) Non-residential ASN categories where "webrtc blocked" is suspicious. */
const NON_PRIVACY_CATEGORIES = new Set([
  "datacenter",
  "hosting",
  "proxy",
  "vpn",
]);

function applyProxyVpnDowngrade(
  input: MerchantProjectionInput,
  score: number,
): number {
  const proxyP = input.integrity?.analysis.network.proxy_component ?? 0;
  const vpnP = input.integrity?.analysis.network.vpn_component ?? 0;
  return score * (1 - proxyP) * (1 - vpnP);
}

function applyWebrtcBlockedPenalty(
  input: MerchantProjectionInput,
  score: number,
): number {
  const webrtcBlocked = hasSignalCode(
    input.integrity?.analysis.ip.signals,
    "WEBRTC_BLOCKED",
  );
  if (!webrtcBlocked) return score;
  const category = readAsnCategory(input);
  if (!category || !NON_PRIVACY_CATEGORIES.has(category)) return score;
  return score * 0.5;
}

function computeNetworkIntegrityScore(
  input: MerchantProjectionInput,
  rawScore: number,
): number {
  if (rawScore === 0) return 0; // forgery — do not override

  // Corp-shield clamp. Known corporate gateway → probe scatter is expected
  // and the tier's 0.1 floor is a false positive for that context.
  const corpShield = detectCorporateShield(input);
  let score = corpShield ? 1.0 : rawScore;

  // (C) JA4/H2 mismatch at sev >= 0.9 is strong TLS-layer forgery — clamp
  // aggressively even under corp shield (still spoofing your TLS stack).
  if (input.integrity && readJa4UaSignals(input.integrity).strongMismatch) {
    score = Math.min(score, 0.2);
  }

  // (B + F) Noisy-OR proxy/VPN downgrade + webrtc-blocked-on-non-residential
  // penalty. Skipped on corp shield since the ASN is a known-benign gateway.
  if (!corpShield) {
    score = applyProxyVpnDowngrade(input, score);
    score = applyWebrtcBlockedPenalty(input, score);
  }

  return Math.max(0, Math.min(1, score));
}

/**
 * Derive the third-party-cookie identification fields from aws_cf sigint.
 * On "pass" we surface the cookie id and issuedAt. On "fail" (tampered or
 * mismatched) we null the id/created because their values come from the
 * untrusted cookie itself. On absence we null everything (the cookie
 * mechanism never engaged).
 */
function deriveThirdPartyCookie(input: MerchantProjectionInput): TpcFields {
  const awsCf = readAwsCf(input);
  if (!awsCf) return TPC_EMPTY;

  const tampered = awsCf.cookieTampered === true;
  const matches = awsCf.cookieMatchesToken;

  let tpc_verified: "pass" | "fail" | null;
  if (tampered) tpc_verified = "fail";
  else if (matches === true) tpc_verified = "pass";
  else if (matches === false) tpc_verified = "fail";
  else tpc_verified = null;

  if (tpc_verified !== "pass") {
    return { tpc_id: null, tpc_created: null, tpc_verified };
  }
  return {
    tpc_id: awsCf.id ?? null,
    tpc_created: awsCf.issuedAt ?? null,
    tpc_verified: "pass",
  };
}

function deriveIdentification(
  input: MerchantProjectionInput,
): MerchantIdentification {
  const { session, payload, integrity } = input;
  const device_id =
    session?.device_id || payload?.identifiers.device_id || null;

  const is_new_device =
    payload?.analysis.is_new_device ??
    session?.evidence_codes?.includes("NEW_DEVICE") ??
    false;

  const confidence = payload?.analysis.confidence ?? session?.confidence ?? 0;

  const crypto_device_id = integrity?.identification
    ? hashPubkey(integrity.identification.pubkey)
    : null;
  const crypto_verified = integrity?.identification?.verified ?? null;

  const tpc = deriveThirdPartyCookie(input);

  return {
    device_id,
    is_new_device,
    first_seen_at: null,
    last_seen_at: null,
    confidence: { score: confidence },
    crypto_device_id,
    crypto_verified,
    tpc_id: tpc.tpc_id,
    tpc_created: tpc.tpc_created,
    tpc_verified: tpc.tpc_verified,
    browserDetails: deriveBrowserDetails(input),
  };
}

function deriveRequestHeaders(
  input: MerchantProjectionInput,
): MerchantRequestHeaders | null {
  const captured = input.integrity?.request_headers;
  if (!captured) return null;
  return {
    headers: { ...captured.headers },
    cookie_names: [...captured.cookie_names],
  };
}

/**
 * Project the internal session / integrity record down to the merchant-
 * safe shape. Safe to call with partial inputs — missing data yields
 * conservative defaults.
 */
export function buildMerchantResponse(
  input: MerchantProjectionInput,
): MerchantSafeResponse {
  const { session, payload, session_id, integrity } = input;

  const rawNetworkScore = integrity?.analysis.ip.integrity ?? 0.5;
  const networkIntegrityScore = computeNetworkIntegrityScore(
    input,
    rawNetworkScore,
  );
  // Null (not zero) when neither the payload nor session has a risk score —
  // lets the client distinguish "risk model didn't run" from "ran, returned 0".
  const risk = payload?.analysis.risk_score ?? session?.risk_score ?? null;

  const probs = {
    bot: botProbability(input),
    vpn: probabilityFromUnit(vpnScore(input)),
    proxy: probabilityFromUnit(proxyScore(input)),
    tampering: tamperingProbability(input),
  };

  return {
    session_id,
    created_at: integrity?.created_at ?? null,
    ttl: (integrity as { ttl?: number } | undefined)?.ttl ?? null,

    identification: deriveIdentification(input),

    ip: deriveIp(input),
    ipLocation: deriveIpLocation(input),
    ipInfo: deriveIpInfo(input),

    bot: { probability: probs.bot },
    vpn: { probability: probs.vpn },
    proxy: { probability: probs.proxy },
    tampering: { probability: probs.tampering },
    incognito: { result: detectIncognito(input) },
    networkIntegrity: { score: networkIntegrityScore },
    suspectScore: { result: risk },

    tags: buildTags(input, probs),

    requestHeaders: deriveRequestHeaders(input),

    policy: null,
    velocity: null,
  };
}
