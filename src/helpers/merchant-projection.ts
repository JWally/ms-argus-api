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
 *
 * @module helpers/merchant-projection
 */

import { createHash } from "node:crypto";
import type { IntegrityResultsData } from "./payload-schema";
import {
  networkTamperingScore,
  proxyScore,
  vpnScore,
} from "../scoring/network-tampering";
import {
  detectCellular,
  detectCorporateShield,
  detectNoWebrtc,
  probabilityFromUnit,
  type MerchantProjectionInput,
} from "../scoring/shared";
import {
  deriveWorkerScopeEvidence,
  type WorkerScopeEvidence,
} from "./worker-scope-evidence";
import {
  deriveDeviceHistory,
  deriveIpVelocity,
  type IpVelocityProjection,
  type MerchantDeviceHistory,
} from "../projections/activity";
import {
  computeNetworkIntegrityScore,
  deriveNetworkProjection,
  readAwsCf,
  type MerchantIpInfo,
  type MerchantIpLocation,
} from "../projections/network";
import {
  automationProbability,
  detectDeveloperTools,
} from "../scoring/automation";
import {
  detectBraveIos,
  detectLanguageMismatch,
  detectLocationMismatch,
  deviceTamperingProbability,
  tamperingWithoutWorkerDivergence,
} from "../scoring/device-tampering";

// Re-export so external test files and downstream consumers that import the
// type from helpers/merchant-projection keep compiling unchanged.
export type {
  IpVelocityProjection,
  MerchantDeviceHistory,
  MerchantProjectionInput,
};
export type { MerchantIpInfo, MerchantIpLocation };
export { computeNetworkIntegrityScore };

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
  | "privacy_relay"
  | "browser_tampering"
  | "automation"
  | "incognito"
  | "cellular"
  | "location_mismatch"
  | "language_mismatch"
  | "no_webrtc"
  // Apple Private Access Token outcomes. Tag-only at the moment — neither
  // moves device_tampering. apple_attestation_missing is observational
  // only; we'll decide whether/how to penalize after collecting real-world
  // data on its prevalence vs. confirmed-tampered traffic.
  | "apple_attested"
  | "apple_attestation_missing"
  // Positive privacy-browser identification — these are emitted when we
  // recognize the browser by its known fingerprinting-protection
  // signature (audio API wraps, plugin spoofing, etc.). Mutually
  // exclusive with `browser_tampering`: when one of these tags is set
  // we deliberately attribute the underlying lies to the browser
  // rather than counting them toward `device_tampering`. Merchants
  // can filter on these for analytics / policy (some merchants
  // welcome privacy browsers, some don't).
  | "brave_ios";

export interface BrowserDetails {
  browserName: string | null;
  browserVersion: string | null;
  os: string | null;
  osVersion: string | null;
  device: string | null;
  userAgent: string | null;
}

export interface MerchantIdentification {
  /** SHA-256 of the client's ECDSA pubkey. Cryptographic identity.
   *  Null on legacy bundles. */
  crypto_device_id: string | null;
  /** Whether the cryptographic identity signature verified. Null when the
   *  client didn't send a `device_identity` block. No verification reasons
   *  are exposed — those are internal pipeline state. */
  crypto_verified: boolean | null;
  /** Three-store client UUID (IndexedDB + localStorage + first-party cookie),
   *  respawned across stores by the client so it survives any single-store
   *  clear. Stable across sessions for the same browser profile. Null when
   *  every store failed (private mode + sandboxed iframe, etc). */
  client_uuid: string | null;
  /** Opaque id carried across sessions in the CloudFront-stamped third-party
   *  cookie. Null when the cookie is absent or failed verification. */
  tpc_id: string | null;
  /** Unix seconds when the cookie was originally minted at the CF edge.
   *  Null when the cookie is absent or failed verification. */
  tpc_created: number | null;
  /** "pass" iff the cookie verified against the current TLS token; "fail"
   *  when the cookie arrived but tampered/mismatched; null when absent. */
  tpc_verified: "pass" | "fail" | null;
  /**
   * Network-derived stable ID — backup identifier for fraud prevention when
   * crypto_device_id and tpc_id aren't available. Two-pass derivation:
   *   - "category_residential": hash(ip_/24 + ua) for residential / satellite
   *     networks. Stable for weeks-to-months per household.
   *   - "asn_fallback": hash(asn + ip_/24 + ua) for ASNs the classifier
   *     doesn't recognize. Lower trust — merchant should weight accordingly.
   *   - null + source "none": mobile / vpn / datacenter / corporate / etc.
   *     IP+UA hashing collapses strangers in these populations; rely on
   *     crypto_device_id or device fingerprinting instead.
   */
  network_id: string | null;
  network_id_source: "category_residential" | "asn_fallback" | "none";
  browserDetails: BrowserDetails;
}

export interface MerchantRequestHeaders {
  /** Curated subset of request headers (see CAPTURED_REQUEST_HEADER_NAMES). */
  headers: Record<string, string>;
  /** Cookie *names* present on the request — values are never captured. */
  cookie_names: string[];
}

/**
 * Verdict bucket derived from the three threat axes. Blocks at any
 * axis ≥ BLOCK_THRESHOLD; suspect at any axis ≥ SUSPECT_THRESHOLD.
 * Customers route on this; the three numerical axes are for explanation.
 */
export type Verdict = "clean" | "suspect" | "block";

const SUSPECT_THRESHOLD = 30;
const BLOCK_THRESHOLD = 70;

/**
 * The merchant-safe response shape. Returned as the top-level body of
 * `GET /v1/session/{cpi}/{session_id}` (spread, not wrapped).
 *
 * Three threat axes — all 0–100, all "lower is better":
 *   - automation:        is an automation framework driving this?
 *                        (headless markers, CDP, webdriver, framework tells)
 *   - device_tampering:  is the device lying about itself?
 *                        (Function.toString patches, CH-UA / JA4 / H2 vs UA
 *                         disagreement, worker-scope divergence)
 *   - network_tampering: is the network path being masked?
 *                        (VPN, proxy waterfall, datacenter ASN, geo / TZ
 *                         mismatch, WebRTC vs probe IP disagreement)
 *
 * Visitor-side manipulation only — third-party MITM/interception surfaces
 * separately as a tag, not on the network_tampering axis.
 */
export interface MerchantSafeResponse {
  session_id: string;
  /** Epoch ms. Null when the record pre-dates the field. */
  created_at: number | null;
  /** TTL epoch seconds (when this record will be purged). */
  ttl: number | null;

  /** Lower = better. Driven by headless / CDP / framework detection. */
  automation: number;
  /** Lower = better. Driven by tampering evidence (lies, CH-UA / JA4 / H2
   *  mismatch, worker divergence, locale spoofing). */
  device_tampering: number;
  /** Lower = better. Driven by VPN / proxy / WebRTC-probe consensus. */
  network_tampering: number;
  /** Routing convenience: derived from the three axes via fixed thresholds. */
  verdict: Verdict;

  identification: MerchantIdentification;

  /** Representative client IP. MAC-verified WebRTC IP when available, else
   *  probe consensus. Null when integrity score < 0.5. */
  ip: string | null;
  ipLocation: MerchantIpLocation;
  ipInfo: MerchantIpInfo;

  /** Direct observation, not probabilistic. */
  incognito: { result: boolean };
  /** Direct observation. Surfaces the existing devTools detector — useful
   *  for high-value flows where dev-tools open is a step-up-auth trigger. */
  developer_tools: { result: boolean };

  /** Derived cross-realm consistency evidence. No raw navigator values. */
  worker_scope_evidence: WorkerScopeEvidence | null;

  /** Categorical labels — composable with the threat axes. Useful for
   *  routing rules that need finer-grained context than the axis numbers. */
  tags: MerchantTag[];

  /** Curated request headers preserved at ingestion. Null for pre-capture records. */
  requestHeaders: MerchantRequestHeaders | null;

  /**
   * Per-IP velocity rollup for the current hour. Stamped at ingest from the
   * (ip, bucket) row in the ip-velocity table. Useful directly as a fraud
   * signal:
   *   - high `hits` + low `distinct_devices_est` ⇒ same device, retries
   *   - high `distinct_devices_est` on residential ⇒ proxy / botnet exit
   *   - high `block_rate` ⇒ historically problematic IP
   *
   * Null when the velocity table wasn't reachable at ingest, or for rows
   * ingested before this feature shipped (mid-2026).
   */
  ip_velocity_1h: IpVelocityProjection | null;

  /**
   * Per-device recurrence summary. Computed from the encrypted device-
   * history blob the SDK carries between scans (HKDF-derived AES-GCM key,
   * 50-visit ring buffer). Aggregates only — no individual visit records.
   *
   * Null when the client presented no blob (legitimate first visit shows
   * `freshDevice: true` inside `null`-equivalent counters; see field flags).
   */
  device_history: MerchantDeviceHistory | null;
}

// --- Tag derivation helpers (pure, testable) ---

function detectHyperscaler(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.asn.category === "datacenter";
}

function detectIncognito(input: MerchantProjectionInput): boolean {
  const isPrivate = (
    input.integrity?.device as
      | { incognito?: { isPrivate?: boolean } }
      | undefined
  )?.incognito?.isPrivate;
  return isPrivate === true;
}

/**
 * "proxy" tag fires when the waterfall's merchant-facing threat score
 * is >= 50. Decouples the tag from the legacy proxyScore() so tags
 * agree with the threat value shown on the merchant response.
 */
function detectProxy(input: MerchantProjectionInput): boolean {
  return (input.integrity?.analysis?.proxy_waterfall?.threat_score ?? 0) >= 50;
}

/**
 * Apple Private Relay / Cloudflare WARP / similar consumer privacy
 * relays. Not a fraud signal on its own — merchants decide.
 */
function detectPrivacyRelay(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis?.ip?.asn?.category === "privacy_relay";
}

const UA_HEADER_KEY = "user-agent";
/**
 * Heuristic: does the visitor's UA claim an Apple platform (iOS Safari or
 * macOS Safari)? Used to gate the apple_attestation_missing tag — we only
 * surface "no attestation" as informational on UAs that *should* be able
 * to produce one. Excludes Chrome/Firefox/Edge on Mac (those don't
 * trigger PAT regardless of OS) by requiring AppleWebKit + Safari without
 * the Chrom* / Firefox / Edg fingerprints.
 */
function isAppleClaimedUA(
  integrity: IntegrityResultsData | undefined,
): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const ua = integrity.user_agent ?? headers[UA_HEADER_KEY] ?? "";
  if (!ua) return false;
  if (!/AppleWebKit\/[\d.]+/.test(ua)) return false;
  if (!/Safari\/[\d.]+/.test(ua)) return false;
  // Exclude Chromium-stack browsers (Chrome / Edge / Opera all carry
  // AppleWebKit + Safari tokens for legacy reasons).
  if (/Chrom(e|ium)\/|Edg(e|A|iOS)?\/|OPR\//.test(ua)) return false;
  // Firefox iOS uses a different UA format (FxiOS), but include it as
  // Apple-claimed since it runs on top of WKWebView and the OS handles
  // PAT for it the same way.
  return /iPhone|iPad|iPod|Macintosh/.test(ua);
}

/** PAT absence is scoreable only on iOS/iPadOS, where issuance is expected. */
function isAppleMobileClaimedUA(
  integrity: IntegrityResultsData | undefined,
): boolean {
  if (!isAppleClaimedUA(integrity)) return false;
  const headers = integrity?.request_headers?.headers ?? {};
  const ua = integrity?.user_agent ?? headers[UA_HEADER_KEY] ?? "";
  return /iPhone|iPad|iPod/.test(ua);
}

type TagPredicate = [MerchantTag, (i: MerchantProjectionInput) => boolean];

function buildTags(
  input: MerchantProjectionInput,
  probs: { bot: number; vpn: number; proxy: number; tampering: number },
): MerchantTag[] {
  const predicates: TagPredicate[] = [
    ["vpn", () => probs.vpn >= 50],
    ["proxy", detectProxy],
    ["hyperscaler", detectHyperscaler],
    ["corporate_shield", detectCorporateShield],
    ["privacy_relay", detectPrivacyRelay],
    ["browser_tampering", () => probs.tampering >= 50],
    ["automation", () => probs.bot >= 50],
    ["incognito", detectIncognito],
    ["cellular", detectCellular],
    ["location_mismatch", detectLocationMismatch],
    ["language_mismatch", detectLanguageMismatch],
    ["no_webrtc", detectNoWebrtc],
    // Positive trust signal — successful PAT round-trip end-to-end.
    ["apple_attested", (i) => i.integrity?.pat?.attested === true],
    // Observational only — Apple-claimed UA without an attestation. No
    // shield carve-out by design (PAT is L7 and most enterprise proxies
    // bypass Apple services); the data will tell us whether one's needed.
    [
      "apple_attestation_missing",
      (i) =>
        isAppleClaimedUA(i.integrity) && !(i.integrity?.pat?.attested === true),
    ],
    // Privacy-browser positive identification. See `detectBraveIos` for
    // the signature. When this fires the underlying lies are attributed
    // to the browser and do NOT contribute to device_tampering (handled
    // upstream in `collectTamperingEvidence`).
    [
      "brave_ios",
      (i) => (i.integrity ? detectBraveIos(i.integrity).matched : false),
    ],
  ];
  return predicates.filter(([, p]) => p(input)).map(([tag]) => tag);
}

/**
 * A verified PAT caps soft automation evidence but cannot erase hard residue.
 * Missing PAT adds a suspect-tier penalty only for iOS/iPadOS outside known
 * corporate shields, where the origin round trip is expected to work.
 */
const PAT_AUTOMATION_HARD_FLOOR = 75;
const PAT_VALID_AUTOMATION_CAP = 25;
const PAT_MISSING_AUTOMATION_PENALTY = 25;

function applyPatAdjustment(
  automation: number,
  input: MerchantProjectionInput,
): number {
  if (input.integrity?.pat?.attested === true) {
    if (automation >= PAT_AUTOMATION_HARD_FLOOR) return automation;
    return Math.min(automation, PAT_VALID_AUTOMATION_CAP);
  }

  if (
    isAppleMobileClaimedUA(input.integrity) &&
    !detectCorporateShield(input)
  ) {
    return Math.min(100, automation + PAT_MISSING_AUTOMATION_PENALTY);
  }
  return automation;
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

function readClientUuid(
  integrity: IntegrityResultsData | undefined,
): string | null {
  const raw = (integrity?.device as { client_uuid?: unknown } | undefined)
    ?.client_uuid;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

function deriveIdentification(
  input: MerchantProjectionInput,
): MerchantIdentification {
  const { integrity } = input;
  const crypto_device_id = integrity?.identification
    ? hashPubkey(integrity.identification.pubkey)
    : null;
  const crypto_verified = integrity?.identification?.verified ?? null;
  const tpc = deriveThirdPartyCookie(input);

  // network_id and network_id_source are pre-computed by analyzeIpConsistency
  // during ingestion (so the helpers/ layer doesn't need to import services/).
  // Older records that pre-date the field default to ("none", null).
  const ipBlock = integrity?.analysis.ip;
  const network_id = ipBlock?.network_id ?? null;
  const network_id_source =
    (ipBlock?.network_id_source as MerchantIdentification["network_id_source"]) ??
    "none";

  return {
    crypto_device_id,
    crypto_verified,
    client_uuid: readClientUuid(integrity),
    tpc_id: tpc.tpc_id,
    tpc_created: tpc.tpc_created,
    tpc_verified: tpc.tpc_verified,
    network_id,
    network_id_source,
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

function deriveVerdict(
  automation: number,
  device_tampering: number,
  network_tampering: number,
): Verdict {
  const peak = Math.max(automation, device_tampering, network_tampering);
  if (peak >= BLOCK_THRESHOLD) return "block";
  if (peak >= SUSPECT_THRESHOLD) return "suspect";
  return "clean";
}

/**
 * Project the internal session / integrity record down to the merchant-
 * safe shape. Safe to call with partial inputs — missing data yields
 * conservative defaults.
 */
export function buildMerchantResponse(
  input: MerchantProjectionInput,
): MerchantSafeResponse {
  const { session_id, integrity } = input;

  const rawNetworkScore = integrity?.analysis.ip.integrity ?? 0.5;
  const networkIntegrityScore = computeNetworkIntegrityScore(
    input,
    rawNetworkScore,
  );
  const networkProjection = deriveNetworkProjection(input);

  // networkIntegrityScore stays computed (used by `analysis.ip.integrity`-
  // dependent paths upstream and for any future internal consumer); it is
  // not exposed and not summed into network_tampering — see the
  // networkTamperingScore() docstring for the double-count rationale.
  void networkIntegrityScore;

  const automation = applyPatAdjustment(automationProbability(input), input);
  const device_tampering = deviceTamperingProbability(input);
  const network_tampering = networkTamperingScore(input);
  const verdict = deriveVerdict(
    automation,
    device_tampering,
    network_tampering,
  );

  // Tags still need the constituent probabilities to fire individual labels
  // (vpn / proxy / browser_tampering / automation) at their own thresholds.
  const tagProbs = {
    bot: automation,
    vpn: probabilityFromUnit(vpnScore(input)),
    proxy: probabilityFromUnit(proxyScore(input)),
    tampering: device_tampering,
  };

  return {
    session_id,
    created_at: integrity?.created_at ?? null,
    ttl: (integrity as { ttl?: number } | undefined)?.ttl ?? null,

    automation,
    device_tampering,
    network_tampering,
    verdict,

    identification: deriveIdentification(input),

    ...networkProjection,

    incognito: { result: detectIncognito(input) },
    developer_tools: { result: detectDeveloperTools(input) },
    worker_scope_evidence: integrity
      ? deriveWorkerScopeEvidence(
          integrity,
          tamperingWithoutWorkerDivergence(integrity),
        )
      : null,

    tags: buildTags(input, tagProbs),

    requestHeaders: deriveRequestHeaders(input),

    ip_velocity_1h: deriveIpVelocity(input),

    device_history: deriveDeviceHistory(input),
  };
}
