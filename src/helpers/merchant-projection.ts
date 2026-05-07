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
  | "privacy_relay"
  | "browser_tampering"
  | "automation"
  | "incognito"
  | "cellular"
  | "location_mismatch"
  | "language_mismatch"
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
    /**
     * Legacy 5-value categorization (datacenter / vpn_proxy / corporate_proxy
     * / privacy_relay / mobile). Kept for backwards compatibility with
     * pre-existing integrations. New consumers should prefer `network_class`
     * (broader, 12-value taxonomy) and the convenience booleans below.
     */
    category: string | null;
    /**
     * Broader consumer-network class derived from the IPtoASN+regex dataset
     * (mobile / residential / datacenter / vpn_proxy / hosting_proxy / cdn /
     * satellite / privacy_relay / security_filter / business / education /
     * government). Distinguishes residential vs cellular within mixed-use
     * ASNs (notably AT&T 7018). Null when the ASN isn't in the dataset.
     */
    network_class: string | null;
  };
  /** Convenience booleans for routing — all derived from `asn.network_class`. */
  datacenter: { result: boolean };
  /** True when network_class is mobile. Useful for stable-ID branching. */
  mobile: { result: boolean };
  /** True when network_class is residential. */
  residential: { result: boolean };
  /** True when network_class is vpn_proxy (declared VPN provider). */
  vpn: { result: boolean };
  /** True when network_class is hosting_proxy (residential proxy networks
   *  resold by Bright Data, SOAX, etc.). */
  hosting: { result: boolean };
  /** True when network_class is privacy_relay (Apple iCloud Private Relay). */
  privacy_relay: { result: boolean };
  /** True when network_class is security_filter (Cisco Umbrella, Zscaler,
   *  Cloudflare Access — corporate cloud-egress shields). */
  corporate_shield: { result: boolean };
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

  /** Categorical labels — composable with the threat axes. Useful for
   *  routing rules that need finer-grained context than the axis numbers. */
  tags: MerchantTag[];

  /** Curated request headers preserved at ingestion. Null for pre-capture records. */
  requestHeaders: MerchantRequestHeaders | null;
}

/** Input bundle for the projection. Accepts an integrity record only — the
 *  old session/payload shapes were tied to the fingerprint matching pipeline
 *  which was removed in remove-fingerprint. */
export interface MerchantProjectionInput {
  session_id: string;
  integrity?: IntegrityResultsData;
}

// --- Tag derivation helpers (pure, testable) ---

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

/** rcv_rtt/rtt_refreshed at or above this is structurally impossible for
 *  direct/CGNAT/jittery networks. Overrides both the WebRTC damper and
 *  the cellular carve-out — physics wins. */
const RTT_RATIO_CEILING = 5.0;
/** Component above this counts as "elevated" for the no-webrtc uplift.
 *  0.3 corresponds to rcv_rtt/rtt ≈ 1.6 on the current scorer. */
const COMPONENT_ELEVATED_THRESHOLD = 0.3;
/** Floor applied when no WebRTC + elevated RTT ("GTFO" rule). */
const NO_WEBRTC_UPLIFT_FLOOR = 0.9;
/** Floor applied when ratio >= RTT_RATIO_CEILING. Above any damper. */
const CEILING_UPLIFT_FLOOR = 0.95;
/** Ceiling applied when WebRTC is present and matches probes — caps proxy
 *  component at "suspect, not damning" for plausibly-legit ratios. */
const WEBRTC_MATCH_DAMPER_CAP = 0.3;

/** Unclamped rcv_rtt_refreshed/rtt_refreshed ratio from the TCP probe. Null
 *  when data is missing (legacy records, probe failure). */
function readRttRatio(input: MerchantProjectionInput): number | null {
  const sigint = input.integrity?.sigint as
    | { tcp_probe?: { rtt_fingerprint?: Record<string, number> } }
    | undefined;
  const rtt = sigint?.tcp_probe?.rtt_fingerprint;
  if (!rtt) return null;
  const rcv = rtt.rcv_rtt_refreshed;
  const ref = rtt.rtt_refreshed;
  if (!rcv || !ref || rcv <= 0 || ref <= 0) return null;
  return rcv / ref;
}

/** Whether the MAC-verified WebRTC IP is present and agrees with the probe
 *  IPs at /16 granularity (the existing analyzer's contract). */
function webrtcMatchesNetwork(input: MerchantProjectionInput): boolean {
  return input.integrity?.analysis.ip.checks.webrtcMatchesProbes === true;
}

/** Datacenter / declared-VPN ASNs — both run traffic through explicit
 *  tunnels. WebRTC matching on these ASNs proves tunnel uniformity
 *  (HTTP and WebRTC ride the same tunnel → same egress IP), not
 *  non-proxy-ness. The damper must not fire here or it silences the
 *  MSS-reduction signal that catches AWS-VPN / WireGuard-over-TLS. */
function isTunneledAsn(input: MerchantProjectionInput): boolean {
  const cat = input.integrity?.analysis.ip.asn.category;
  return cat === "datacenter" || cat === "vpn_proxy";
}

/**
 * Apply the WebRTC-anchored fusion rules on top of a raw network component
 * score. The damper only fires when `applyDamper` is true, which is proxy-
 * only: proxy_component is RTT-derived (noise-prone) and benefits from
 * WebRTC context. vpn_component is MSS-derived — a physical-layer
 * fingerprint of tunnel encapsulation — and should pass through
 * regardless of WebRTC match state.
 *
 * Rules (in precedence order):
 *   1. Corporate shield → 0. Strongest carve-out; benign enterprise egress.
 *   2. Ratio ≥ 5.0 → floor at 0.95. Physics ceiling: no legitimate network
 *      produces a 5× gap between rcv_rtt and rtt_refreshed. Overrides
 *      cellular carve-out AND WebRTC match (covers the motivated-attacker
 *      case who rents a proxy exit in the victim's /16 to fake a match).
 *   3. Cellular / CGNAT → pass through.
 *   4. (proxy only) WebRTC matches probes at /16 AND ASN is NOT
 *      datacenter/vpn_proxy → cap at 0.3. Suspect but not damning.
 *      Damper is scoped in two dimensions: (a) proxy component only —
 *      MSS/vpn signal stays authoritative; (b) non-tunneled ASNs only —
 *      a VPN on AWS tunnels WebRTC through the same exit so matching is
 *      tunnel uniformity, not non-proxy-ness.
 *   5. No WebRTC submitted and component elevated (> 0.3) → floor at 0.9.
 *   6. Otherwise → pass through.
 */
function applyWebrtcFusion(
  input: MerchantProjectionInput,
  rawComponent: number,
  applyDamper: boolean,
): number {
  if (detectCorporateShield(input)) return 0;

  const ratio = readRttRatio(input);

  // Physics ceiling wins over every non-corporate carve-out.
  if (ratio !== null && ratio >= RTT_RATIO_CEILING) {
    return Math.max(rawComponent, CEILING_UPLIFT_FLOOR);
  }

  if (detectCellular(input)) return rawComponent;

  if (applyDamper && webrtcMatchesNetwork(input) && !isTunneledAsn(input)) {
    return Math.min(rawComponent, WEBRTC_MATCH_DAMPER_CAP);
  }

  if (detectNoWebrtc(input) && rawComponent > COMPONENT_ELEVATED_THRESHOLD) {
    return Math.max(rawComponent, NO_WEBRTC_UPLIFT_FLOOR);
  }

  return rawComponent;
}

function vpnScore(input: MerchantProjectionInput): number {
  const raw = input.integrity?.analysis.network.vpn_component ?? 0;
  return applyWebrtcFusion(input, raw, false);
}

function proxyScore(input: MerchantProjectionInput): number {
  const raw = input.integrity?.analysis.network.proxy_component ?? 0;
  return applyWebrtcFusion(input, raw, true);
}

/**
 * Shape of the headless block stored under `device.headless`. The strict
 * markers (webdriver, headless UA, headless worker UA) live under the
 * inner `.headless` field — matching the fingerprint emitter's nested
 * naming. The `*Rating` numbers are pre-aggregated percentages.
 */
interface HeadlessSignals {
  headlessRating?: number;
  likeHeadlessRating?: number;
  stealthRating?: number;
  /** Strict markers — any one alone is high-confidence automation. */
  headless?: {
    webDriverIsOn?: boolean;
    hasHeadlessUA?: boolean;
    hasHeadlessWorkerUA?: boolean;
  };
  likeHeadless?: { devToolsOpen?: boolean };
}

function readHeadless(
  integrity: IntegrityResultsData,
): HeadlessSignals | undefined {
  return (integrity.device as { headless?: HeadlessSignals } | undefined)
    ?.headless;
}

function detectDeveloperTools(input: MerchantProjectionInput): boolean {
  if (!input.integrity) return false;
  return readHeadless(input.integrity)?.likeHeadless?.devToolsOpen === true;
}

function detectIncognito(input: MerchantProjectionInput): boolean {
  const isPrivate = (
    input.integrity?.device as
      | { incognito?: { isPrivate?: boolean } }
      | undefined
  )?.incognito?.isPrivate;
  return isPrivate === true;
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

/**
 * Visitor's claimed timezone contradicts CloudFront-observed IP timezone.
 * Restricted to TZ disagreement only — accept-language vs IP country lives
 * under the separate `language_mismatch` tag, since en-GB-on-US-IP and
 * similar are common-enough preferences that they shouldn't share a tag
 * with timezone manipulation.
 */
function detectLocationMismatch(input: MerchantProjectionInput): boolean {
  if (!input.integrity) return false;
  const e = collectTamperingEvidence(input.integrity);
  return e.tzGeoMismatch;
}

/**
 * Accept-Language vs CloudFront IP country differs. Surfaced as a soft
 * advisory tag — does *not* contribute to device_tampering. The US has
 * Vietnamese-speaking households in Houston and British-spelling enthusiasts
 * everywhere; an en-GB UI on a US IP is not fraud. Merchants who care can
 * filter on this tag themselves.
 */
function detectLanguageMismatch(input: MerchantProjectionInput): boolean {
  if (!input.integrity) return false;
  const e = collectTamperingEvidence(input.integrity);
  return e.langGeoCrossContinent || e.langGeoCrossCountry;
}

/**
 * Mobile-browser detection (iPhone/iPad/Android). Reads main-thread UA
 * and every captured worker-scope UA — if any one says iPhone we treat
 * the visitor as mobile. Used to carve out signals that are reliable on
 * desktop but legitimately absent on mobile (no plugins, no taskbar,
 * blank UA-CH, etc).
 */
function isMobileBrowser(integrity: IntegrityResultsData | undefined): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const candidates: string[] = [
    integrity.user_agent ?? "",
    headers["user-agent"] ?? "",
  ];
  const device = integrity.device as
    | { workerScope?: { scopes?: Record<string, { userAgent?: unknown }> } }
    | undefined;
  const scopes = device?.workerScope?.scopes ?? {};
  for (const scope of Object.values(scopes)) {
    if (typeof scope?.userAgent === "string") candidates.push(scope.userAgent);
  }
  return candidates.some((ua) => /iPhone|iPad|iPod|Android|Mobile/i.test(ua));
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
  ];
  return predicates.filter(([, p]) => p(input)).map(([tag]) => tag);
}

/**
 * Automation score. Three signal tiers, max wins:
 *   1. STRICT markers (`headlessRating`) — webdriver / headless UA /
 *      headless worker UA. Any one alone is a confident automation tell;
 *      no legitimate human browser exposes these.
 *      - 3/3 (100): full headless. → 100
 *      - 2/3 (67):  → 100
 *      - 1/3 (33):  → 75 (block-tier — still-strong evidence)
 *   2. WEAK markers (`likeHeadlessRating`) — 11 environment signals
 *      (no Chrome object, no plugins, blank UA-CH, etc). Real but
 *      not damning on its own; the % maps directly into the score.
 *      **Mobile carve-out:** these signals were calibrated for desktop
 *      browsers. iPhone Safari has no taskbar, no plugins, and blank
 *      UA-CH for legitimate reasons — every real iPhone visitor would
 *      otherwise floor at automation ≈ 10. We zero out weak markers
 *      when the UA (main or worker) shows mobile.
 *   3. STEALTH markers (`stealthRating`) — Function.toString proxy,
 *      bad WebGL, missing chrome runtime. +20 bonus when any fire.
 */
function botProbability(input: MerchantProjectionInput): number {
  const headless = readHeadless(
    input.integrity ?? ({} as IntegrityResultsData),
  );
  const strict = headless?.headlessRating ?? 0;
  if (strict >= 67) return 100;
  if (strict > 0) return 75;
  const stealth = headless?.stealthRating ?? 0;
  const weak = isMobileBrowser(input.integrity)
    ? 0
    : (headless?.likeHeadlessRating ?? 0);
  return roundProbability(weak + (stealth > 0 ? 20 : 0));
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

/**
 * Probe-side TLS-vs-UA mismatch (cipher count + GREASE presence). Distinct
 * from JA4_UA_BROWSER_MISMATCH — that needs the JA4 cipher hash to be in
 * the known-browser table, which fails open when a TLS-terminating proxy
 * re-originates with a stripped cipher list (Cisco Umbrella, Zscaler,
 * mitmproxy/Burp). The probe-side TLS_UA_MISMATCH signal is the safety
 * net for that case — emitted by `analyzeJa4Ua` from the probe's
 * `tls_signals.ua_mismatch` flag.
 */
function hasTlsUaMismatch(integrity: IntegrityResultsData): boolean {
  const sigs = (
    integrity.analysis as {
      ja4_ua?: { signals?: Array<{ code: string }> };
    }
  ).ja4_ua?.signals;
  return Array.isArray(sigs) && sigs.some((s) => s.code === "TLS_UA_MISMATCH");
}

/**
 * Corporate-shield carve-out for the TLS_UA_MISMATCH signal. When a corp
 * security gateway (Cisco Umbrella / Zscaler / Cloudflare Access) is in the
 * path, TLS interception with a stripped cipher list is *expected behavior*,
 * not a tampering signal. The shield is already surfaced as a tag and tells
 * merchants why the TLS layer looks munged. Same shape as the network-axis
 * carve-out in applyWebrtcFusion / corporate-shield zeroing.
 */
function isCorporateShieldedAsn(integrity: IntegrityResultsData): boolean {
  return integrity.analysis?.ip?.asn?.category === "corporate_proxy";
}

/**
 * Browser-engine consistency signals from `analyzeBrowserEngine`. Two
 * tiers, both feed device_tampering:
 *   - HARD: claimed browser_version's baseline has count=0 for an
 *     observed value (and baseline is well-populated). Joins
 *     isDefinitiveTampering → device_tampering = 100.
 *   - SOFT: combined naive-Bayes log-likelihood is below threshold but
 *     no individual field is structurally impossible. Slot at 60.
 */
function readBrowserEngineSignals(integrity: IntegrityResultsData): {
  hard: boolean;
  soft: boolean;
} {
  const sigs = (
    integrity.analysis as {
      browser_engine?: { signals?: Array<{ code: string }> };
    }
  ).browser_engine?.signals;
  if (!Array.isArray(sigs)) return { hard: false, soft: false };
  return {
    hard: sigs.some((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD"),
    soft: sigs.some((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_SOFT"),
  };
}

function readKernelOsSignals(integrity: IntegrityResultsData): {
  hard: boolean;
  soft: boolean;
} {
  const sigs = (
    integrity.analysis as {
      kernel_os?: { signals?: Array<{ code: string }> };
    }
  ).kernel_os?.signals;
  if (!Array.isArray(sigs)) return { hard: false, soft: false };
  return {
    hard: sigs.some((s) => s.code === "KERNEL_OS_MISMATCH_DARWIN"),
    soft: sigs.some((s) => s.code === "KERNEL_OS_MISMATCH_LINUX"),
  };
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
  /** Any client-hints vs UA mismatch (Group 3, sev >= 0.8). */
  chUaMismatch: boolean;
  /** Any locale-internal mismatch (Group A, sev >= 0.75). */
  localeTamper: boolean;
  /** Probe-side TLS profile vs UA mismatch — cipher-count / GREASE delta.
   *  Already corporate-shield-suppressed at collection time, so any value
   *  surviving here is a real TLS interception / spoofing signal. */
  tlsUaMismatch: boolean;
  /** Browser-engine claim vs observed engine-invariants: at least one
   *  field has zero prevalence in the claimed browser_version's baseline
   *  (e.g. UA claims Safari but jsEngine=V8). Definitive tampering. */
  browserEngineHardBreak: boolean;
  /** Browser-engine claim vs observed: combined naive-Bayes likelihood
   *  is low but no individual field is structurally impossible.
   *  Outlier-but-possibly-legit; floor 60. */
  browserEngineSoft: boolean;
  /** Server kernel reports `tcpi_options` with no ECN bit on a UA
   *  claiming iOS or macOS. Real Darwin negotiates ECN by default — a
   *  WebKit JA4 + UA combination on a non-ECN socket cannot be a real
   *  Apple device. Definitive tampering: highest-confidence device
   *  signal because the kernel reports it about its own socket and the
   *  client cannot lie about it from JS. */
  kernelOsMismatchHard: boolean;
  /** Claimed Linux/Android UA but server kernel sees ECN-on. Most Linux
   *  installs ship with `tcp_ecn=2` (passive only), so an actively-ECN
   *  Linux client is unusual but not structurally impossible. Floor 60. */
  kernelOsMismatchSoft: boolean;
  /** Timezone location doesn't match IP geo (existing TZ_GEOLOCATION_MISMATCH). */
  tzGeoMismatch: boolean;
  /** Accept-Language vs CF country cross-continent mismatch (severe). */
  langGeoCrossContinent: boolean;
  /** Accept-Language vs CF country same-continent mismatch (mild). */
  langGeoCrossCountry: boolean;
}

function readChUaMismatch(integrity: IntegrityResultsData): boolean {
  const chUa = (
    integrity.analysis as {
      client_hints_ua?: { hasStrongMismatch?: boolean };
    }
  ).client_hints_ua;
  return chUa?.hasStrongMismatch === true;
}

function readLocaleGeoSignals(integrity: IntegrityResultsData): {
  localeTamper: boolean;
  crossContinent: boolean;
  crossCountry: boolean;
} {
  const lg = (
    integrity.analysis as {
      locale_geo?: {
        hasLocaleTamper?: boolean;
        signals?: Array<{ code: string }>;
      };
    }
  ).locale_geo;
  const codes = (lg?.signals ?? []).map((s) => s.code);
  return {
    localeTamper: lg?.hasLocaleTamper === true,
    crossContinent: codes.includes("ACCEPT_LANG_GEO_CROSS_CONTINENT"),
    crossCountry: codes.includes("ACCEPT_LANG_GEO_CROSS_COUNTRY"),
  };
}

function readTzGeoMismatch(integrity: IntegrityResultsData): boolean {
  const tz = integrity.analysis.timezone;
  return (tz?.signals ?? []).some((s) => s.code === "TZ_GEOLOCATION_MISMATCH");
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
  const locale = readLocaleGeoSignals(integrity);
  // Corporate-shield carve-outs.
  //
  // (a) TLS_UA_MISMATCH: TLS interception by Cisco Umbrella / Zscaler /
  //     Cloudflare Access produces the same probe-side TLS_UA_MISMATCH as
  //     a genuine MITM. The shield is already surfaced as its own tag.
  //
  // (b) TZ_GEOLOCATION_MISMATCH: corporate shields egress through PoPs in
  //     timezones that often don't match the user's home timezone (a Chicago
  //     employee whose corp shield egresses through Ashburn → client TZ
  //     America/Chicago vs CF TZ America/New_York). Same shape as (a) — a
  //     real signal in general, structurally false for shielded users. Also
  //     drops the noisy `location_mismatch` tag for those rows since the
  //     tag detector reads the same evidence.
  //
  // Both carve-outs only gate the SCORE contribution. The raw signals stay
  // in the analyzer output (analysis.ja4_ua.signals, analysis.timezone.signals)
  // so diagnostics are unchanged.
  const shielded = isCorporateShieldedAsn(integrity);
  const tlsUaMismatch = hasTlsUaMismatch(integrity) && !shielded;
  const tzGeoMismatch = readTzGeoMismatch(integrity) && !shielded;
  const engineSignals = readBrowserEngineSignals(integrity);
  const kernelSignals = readKernelOsSignals(integrity);
  return {
    lies,
    divergences,
    ja4Mismatch: hasJa4UaMismatch(integrity),
    webrtcApiTampered: detectWebrtcApiTampering(integrity),
    uaDivergence: hasUaWorkerDivergence(integrity),
    platformLie: hasPlatformLie(integrity),
    uaHeaderMismatch: detectUaFamilyHeaderMismatch(integrity),
    chUaMismatch: readChUaMismatch(integrity),
    localeTamper: locale.localeTamper,
    tlsUaMismatch,
    tzGeoMismatch,
    langGeoCrossContinent: locale.crossContinent,
    langGeoCrossCountry: locale.crossCountry,
    browserEngineHardBreak: engineSignals.hard,
    browserEngineSoft: engineSignals.soft,
    // Corporate-shield TLS-intercepting proxies (Umbrella, Zscaler, etc.)
    // re-originate the connection from their egress, so the socket the
    // server kernel observes is the proxy's, not the user's. ECN almost
    // never gets propagated through these stacks, which falsely flips
    // the Apple-without-ECN heuristic on every legitimate iOS/macOS user
    // behind the proxy. Suppress at scoring time only — the raw signal
    // stays on `analysis.kernel_os.signals` for forensic review.
    kernelOsMismatchHard: kernelSignals.hard && !shielded,
    kernelOsMismatchSoft: kernelSignals.soft && !shielded,
  };
}

function isDefinitiveTampering(e: TamperingEvidence): boolean {
  if (e.lies >= 20 || e.ja4Mismatch || e.divergences >= 3) return true;
  if (e.webrtcApiTampered) return true;
  // Client-hints vs UA disagreement (platform/mobile/brand) is proof of
  // partial spoofing — real browsers never have this split.
  if (e.chUaMismatch) return true;
  // Browser-engine hard break: claimed UA's baseline says some observed
  // value has 0 prevalence (e.g. Safari UA + V8 jsEngine). Structurally
  // impossible per accumulated good traffic.
  if (e.browserEngineHardBreak) return true;
  // Kernel-OS hard break: server's own kernel sees a non-Darwin TCP
  // options bitmask on a UA claiming iOS/macOS. The client cannot lie
  // about this from JS — the bits are negotiated at SYN time. Strongest
  // device-axis signal we have.
  if (e.kernelOsMismatchHard) return true;
  // (D) Compound: lies + a second-order spoof-indicator
  return e.lies >= 5 && (e.uaDivergence || e.platformLie);
}

/**
 * Tier-60 signals: each one is "credible spoof but not structurally
 * impossible." Any one trips the floor. Listed here as an array so
 * `tamperingProbabilityFromEvidence` stays under the cyclomatic-
 * complexity cap.
 *
 * - lies/divergences: enough small lies or worker-vs-main divergences
 * - uaHeaderMismatch: Chromium UA with sec-ch-ua header missing/wrong
 * - localeTamper: intl APIs vs navigator vs worker disagreement
 * - tlsUaMismatch: probe-side TLS profile lie (corp-shield carve-out
 *   already applied upstream)
 * - browserEngineSoft: naive-Bayes baseline below threshold but no
 *   single field structurally impossible
 * - kernelOsMismatchSoft: Linux UA + ECN negotiated (most distros ship
 *   tcp_ecn=2; ops teams who flip ECN on are the carve-out)
 */
function hasTier60Signal(e: TamperingEvidence): boolean {
  return (
    e.lies >= 5 ||
    e.divergences >= 1 ||
    e.uaHeaderMismatch ||
    e.localeTamper ||
    e.tlsUaMismatch ||
    e.browserEngineSoft ||
    e.kernelOsMismatchSoft
  );
}

function tamperingProbabilityFromEvidence(e: TamperingEvidence): number {
  if (isDefinitiveTampering(e)) return 100;
  if (hasTier60Signal(e)) return 60;
  // TZ location vs IP TZ disagreement — VPN/proxy tell, often benign for
  // travelers but still worth surfacing.
  if (e.tzGeoMismatch) return 35;
  if (e.lies >= 1) return 25;
  // langGeoCrossContinent / langGeoCrossCountry intentionally do NOT feed
  // device_tampering. en-GB on a US IP and similar accept-language quirks
  // are widespread legitimate user preferences (British-spelling fans,
  // expat communities, multi-lingual households in major US cities). They
  // surface as the soft `language_mismatch` tag for merchants who want
  // to filter on them, with no score penalty.
  return 0;
}

function tamperingProbability(input: MerchantProjectionInput): number {
  if (!input.integrity) return 0;
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
  return (input.integrity?.sigint as { aws_cf?: AwsCfSigint } | undefined)
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

/**
 * All convenience-boolean flags derive from `network_class` (the broader
 * 12-value taxonomy) so the `category` field can stay legacy without
 * influencing routing. `datacenter` previously read from `category` —
 * standardized here so all booleans share one source of truth.
 */
function deriveNetworkFlags(networkClass: string | null): {
  datacenter: { result: boolean };
  mobile: { result: boolean };
  residential: { result: boolean };
  vpn: { result: boolean };
  hosting: { result: boolean };
  privacy_relay: { result: boolean };
  corporate_shield: { result: boolean };
} {
  return {
    datacenter: { result: networkClass === "datacenter" },
    mobile: { result: networkClass === "mobile" },
    residential: { result: networkClass === "residential" },
    vpn: { result: networkClass === "vpn_proxy" },
    hosting: { result: networkClass === "hosting_proxy" },
    privacy_relay: { result: networkClass === "privacy_relay" },
    corporate_shield: { result: networkClass === "security_filter" },
  };
}

function deriveIpInfo(input: MerchantProjectionInput): MerchantIpInfo {
  const asnFromIntegrity = input.integrity?.analysis.ip.asn;
  if (asnFromIntegrity) {
    const networkClass = asnFromIntegrity.network_class ?? null;
    return {
      asn: {
        number: parseAsnNumber(asnFromIntegrity.number),
        organization: asnFromIntegrity.org,
        category: asnFromIntegrity.category,
        network_class: networkClass,
      },
      ...deriveNetworkFlags(networkClass),
    };
  }
  const awsCf = readAwsCf(input);
  return {
    asn: {
      number: parseAsnNumber(awsCf?.asn),
      organization: null,
      category: null,
      network_class: null,
    },
    ...deriveNetworkFlags(null),
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

/**
 * @internal — exported only for unit tests of the network-integrity tiers.
 * Not part of the merchant API surface; the score is folded into
 * `network_tampering` in the projected response. Do not depend on it from
 * other modules.
 */
export function computeNetworkIntegrityScore(
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

/**
 * Compose `network_tampering` from the merchant-facing network signals:
 *   - vpn_component (MSS-derived tunnel encapsulation fingerprint)
 *   - proxy waterfall threat (the integrated analyzer; itself already
 *     factors WebRTC consensus / IP scatter / RTT jitter / ASN class)
 * Max wins — any one of these saturating is enough to flag the path.
 *
 * networkIntegrity (the WebRTC/probe consensus scalar) is intentionally
 * NOT layered in here: proxy_waterfall already consumes it as an input
 * tier, so adding it directly would double-count and re-trigger on the
 * very scenarios proxy_waterfall's damper was designed to filter.
 */
function networkTamperingScore(input: MerchantProjectionInput): number {
  const vpn = probabilityFromUnit(vpnScore(input));
  const proxyThreat =
    input.integrity?.analysis?.proxy_waterfall?.threat_score ?? 0;
  return Math.max(vpn, proxyThreat);
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

  // networkIntegrityScore stays computed (used by `analysis.ip.integrity`-
  // dependent paths upstream and for any future internal consumer); it is
  // not exposed and not summed into network_tampering — see the
  // networkTamperingScore() docstring for the double-count rationale.
  void networkIntegrityScore;

  const automation = botProbability(input);
  const device_tampering = tamperingProbability(input);
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

    ip: deriveIp(input),
    ipLocation: deriveIpLocation(input),
    ipInfo: deriveIpInfo(input),

    incognito: { result: detectIncognito(input) },
    developer_tools: { result: detectDeveloperTools(input) },

    tags: buildTags(input, tagProbs),

    requestHeaders: deriveRequestHeaders(input),
  };
}
