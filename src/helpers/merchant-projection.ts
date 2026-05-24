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
    /**
     * Optional enrichment from the RDAP auto-overlay (registrant operator +
     * sub-allocated customer when ARIN records one) and PeeringDB (operator-
     * self-declared type + IX presence count). Coverage is sparse: present
     * only when at least one field is known for this session's IP/ASN.
     * PeeringDB values are operator-self-declared and may shift between
     * weekly rebuilds — treat as a hint, not a contract.
     */
    metadata: {
      parent_org?: string;
      customer_org?: string;
      pdb_type?: string;
      ix_count?: number;
    } | null;
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

/** Console-bench noise floor in microseconds. Below this, `log_heavy_us`
 *  measurements are dominated by thread-scheduling jitter and clock
 *  resolution rather than CDP serialization cost. Real-Brave telemetry
 *  (May 2026, 10 same-machine submissions) showed worker `heavy_over_tiny`
 *  randomly walking 0.81–2.00 at heavy=4–9µs. The CDP signal we're after
 *  lives at heavy≈63µs (Playwright CDP baseline) — ratios on sub-floor
 *  measurements can't discriminate stub-vs-real. Used by `benchTrips`
 *  to gate the ratio check and by `hasBenchDisagreement` to skip the
 *  cross-bench compare when both sides are noise. */
const BENCH_NOISE_FLOOR_US = 10;

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
 * One bench's output. The iframe bench (`consoleTiming`) and the worker
 * bench (`consoleTimingWorker`) share this shape — the same fields,
 * computed in different realms, submitted side-by-side.
 */
interface ConsoleTimingFields {
  log_tiny_us?: number;
  log_heavy_us?: number;
  dir_heavy_us?: number;
  heavy_over_tiny?: number;
  /**
   * `log_heavy` loop measured with a second clock (Date.now in the
   * current SDK, originally `document.timeline.currentTime`). Lives on
   * a completely different prototype chain from Performance.now —
   * disagreement with `log_heavy_us` means one of the two clocks has
   * been replaced.
   */
  tl_heavy_us?: number;
  /**
   * Hardware anchor: µs/iter of a Math-only loop (Math.sqrt + Math.sin)
   * over 5000 iterations. CDP does not intercept Math intrinsics, so
   * this reflects pure V8/CPU throughput — a value the attacker can't
   * predict from the timing fields alone. Both bench paths emit it,
   * and on the same device they should agree closely.
   */
  math_loop_us?: number;
  /**
   * `Performance.prototype.now` toStrings as `[native code]` in the
   * bench realm. False = timing-oracle tampering. The lie scanner
   * can't reach Performance (not in `API_SEARCH_TARGETS`), so this is
   * verified inline by the detector.
   */
  perf_now_native?: boolean;
  /**
   * `Date.now` toStrings as `[native code]`. Date.now is a static
   * method on the Date constructor and is structurally unreachable
   * by the prototype-walking lie scanner — this is the only place
   * it's verified.
   */
  date_now_native?: boolean;
  /** `console.log` is native in the bench realm. */
  con_log_native?: boolean;
  /** `console.dir` is native in the bench realm. */
  con_dir_native?: boolean;
  /**
   * Count of `console.*` methods (log/warn/error/info/debug/dir)
   * detected as wrapped/patched in the bench realm. Only the worker
   * bench (`consoleTimingWorker`) populates this; the iframe bench
   * sits in the main thread where extensions and CriOS's Google-iOS
   * analytics shim legitimately wrap console, so the probe lives in
   * the worker realm where no such legitimate wrappers exist.
   *
   * Detection is the v3-closure scan, moved out of the SDK's main-
   * thread lie scanner. Probes each method for native toString shape,
   * absence of an own `prototype` property, and non-constructability.
   * Each method that fails any probe counts as 1 lie (dedupe vs. the
   * old scanner's 11-checks-per-method explosion that broke CriOS).
   *
   * Anything > 0 in the worker realm is direct evidence of attacker-
   * injected source — via wrapped `Worker` / `Blob` /
   * `URL.createObjectURL`. Tier: automation 100. This isn't "looks
   * like CDP," it's "attacker demonstrably reached the worker realm."
   */
  console_lies?: number;
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
  /**
   * CDP attach detector via console-serialization timing. When a CDP
   * client (Playwright, Puppeteer, patchright, etc.) has issued
   * Runtime.enable, Chrome serializes every console.* arg over the wire;
   * cost scales with structural complexity. Without CDP, console output
   * is dropped at near-zero cost regardless. The SDK runs a ratio bench
   * inside a hidden srcdoc iframe; see headless/getConsoleTiming.ts.
   * Absent on non-Blink (Firefox/WebKit use different debug protocols).
   */
  cdp?: {
    consoleTiming?: ConsoleTimingFields;
    /**
     * Same bench shape as `consoleTiming` but run in a dedicated Worker
     * spawned via `URL.createObjectURL(blob)`. The worker realm is
     * unreachable by main-thread Proxy patches, and `blob:` URLs cannot
     * be intercepted by `page.route` (browser-internal scheme), so this
     * resists both the function-replacement and bundle-rewrite attacks
     * that the iframe bench is susceptible to. Cross-checked against
     * `consoleTiming`: a stub-the-function attack on either path leaves
     * the other intact, and the disagreement is the tell. Absent when:
     * non-Blink, CSP blocks blob workers, or worker timed out.
     */
    consoleTimingWorker?: ConsoleTimingFields;
    /** ChromeDriver `cdc_`-prefixed globals on document. */
    cdcGlobals?: boolean;
    /** Playwright `__pw_*` bindings on window. */
    pwBindings?: boolean;
    /** navigator.webdriver differs between main frame and a phantom iframe. */
    phantomMismatch?: boolean;
    /** Bot-injected globals matching known patterns (max 5). */
    clientLitter?: string[];
    /** Known automation framework globals (playwright, puppeteer, _phantom…). */
    automationGlobals?: string[];
    /** Native APIs whose toString disagrees across realms — addInitScript patches. */
    crossRealmTampered?: string[];
    /**
     * `Object.getOwnPropertyNames` is native. False = the enumeration
     * primitive that `cdcGlobals` / `pwBindings` / `clientLitter` /
     * `automationGlobals` all rely on has been replaced (likely
     * filter-stub), so their negative results cannot be trusted.
     * Treat as hard-residue evidence in itself.
     */
    ownPropsNative?: boolean;
  };
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
const UA_HEADER_KEY = "user-agent";

function isMobileBrowser(integrity: IntegrityResultsData | undefined): boolean {
  if (!integrity) return false;
  const headers = integrity.request_headers?.headers ?? {};
  const candidates: string[] = [
    integrity.user_agent ?? "",
    headers[UA_HEADER_KEY] ?? "",
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
 * CDP attach detector via console-serialization timing.
 *
 * The SDK (headless/getConsoleTiming.ts) benches console.log('a') vs
 * console.log(heavyObject) inside a pristine iframe. Under CDP (every
 * Playwright/Puppeteer/Selenium-CDP/patchright client) the heavy call
 * takes ≳2× longer because Chrome serializes the object to push over
 * the inspector wire. Without CDP, both calls are dropped at the same
 * near-zero cost. The ratio self-normalizes for hardware speed.
 *
 * Initial calibration (Chrome 148 / Linux desktop):
 *   - Playwright CDP attached: ratio 2.11, log_heavy_us 63
 *   - Plain Chrome:            ratio 0.79, log_heavy_us 7
 *   - --headless=new (no CDP): ratio 1.22, log_heavy_us 8
 *
 * Thresholds chosen for wide margin from initial measurements. Tune
 * from real-user telemetry on the `device.headless.cdp.consoleTiming`
 * field before locking in further.
 */
/**
 * Any of the four use-site native checks reporting false means the
 * bench depended on a primitive that's been replaced. Extracted to
 * keep `hasCdpTimingSignal` under the cyclomatic-complexity cap.
 */
function hasBenchDependencyTamper(t: ConsoleTimingFields): boolean {
  return (
    t.perf_now_native === false ||
    t.date_now_native === false ||
    t.con_log_native === false ||
    t.con_dir_native === false
  );
}

/**
 * Per-bench trip test. Same thresholds applied to either the iframe
 * bench or the worker bench output. Extracted so `hasCdpTimingSignal`
 * can call it once per available bench path.
 *
 *   - Bench-dependency tampering: any of the four use-site native
 *     checks reporting false means the bench primitive (Performance.now,
 *     Date.now, console.log, console.dir) was replaced.
 *   - Cross-clock divergence: `tl_heavy_us` is the heavy loop measured
 *     with a second clock (Date.now). Both clocks read wall time
 *     independently, so they should agree within ~3µs/call. An attacker
 *     who only patches `Performance.prototype.now` leaves the second
 *     clock untouched and the deltas diverge.
 *   - Ratio / absolute thresholds: `heavy_over_tiny > 1.5` (only when
 *     `log_heavy_us` is above the BENCH_NOISE_FLOOR; below that the
 *     ratio is dividing two sub-floor measurements and means nothing —
 *     real-Brave/Chrome telemetry sees worker ratios randomly walking
 *     0.8–2.0 at heavy=4–9µs from thread-scheduling jitter alone) OR
 *     `log_heavy_us > 25` (absolute). Real-Chrome baseline 0.79 / 7,
 *     Playwright CDP 2.11 / 63. The CDP signal lives at heavy≈63µs;
 *     anything under 10µs can't discriminate stub-vs-real.
 */
function benchTrips(t: ConsoleTimingFields): boolean {
  if (hasBenchDependencyTamper(t)) return true;
  const heavy = t.log_heavy_us ?? 0;
  const tlHeavy = t.tl_heavy_us;
  if (typeof tlHeavy === "number" && Math.abs(tlHeavy - heavy) > 3) {
    return true;
  }
  const ratio = t.heavy_over_tiny ?? 0;
  return (ratio > 1.5 && heavy > BENCH_NOISE_FLOOR_US) || heavy > 25;
}

/**
 * CDP timing signal. True if either bench (iframe or worker) trips its
 * own thresholds. The two paths are independently susceptible:
 *
 *   - The iframe bench runs on the main thread and can be defeated by
 *     a `page.route` rewrite of the integrity bundle or by main-thread
 *     Proxy patches on console/Performance/Element prototypes.
 *   - The worker bench runs in a Worker realm spawned via blob URL.
 *     `page.route` cannot intercept `blob:` (browser-internal), and
 *     main-thread Proxy patches don't reach the worker realm. To stub
 *     the worker, the attacker has to wrap the `Worker` constructor or
 *     `URL.createObjectURL` (both more elaborate than a regex rewrite).
 *
 * Either path tripping → automation. See `hasBenchDisagreement` for
 * the cross-check that catches stub-one-leave-the-other attacks.
 */
function hasCdpTimingSignal(headless: HeadlessSignals | undefined): boolean {
  const iframe = headless?.cdp?.consoleTiming;
  const worker = headless?.cdp?.consoleTimingWorker;
  return (!!iframe && benchTrips(iframe)) || (!!worker && benchTrips(worker));
}

/**
 * Cross-bench disagreement detector.
 *
 * The iframe and worker benches measure the same thing (console-log
 * serialization cost) on the same device. They will produce slightly
 * different numbers — different realms, different thread schedulers,
 * different cold-cache behavior — but the *qualitative* answer should
 * agree: either both see CDP serialization overhead, or neither does.
 *
 * A `heavy_over_tiny` gap > 0.5 is the signature of a one-sided stub:
 * the attacker rewrote one bench function to return clean numbers
 * (~1.0) but didn't reach the other path, which still measures the
 * real ~2.0 ratio under CDP.
 *
 * Tolerance picked above hardware/jitter variance (empirically <0.3
 * between iframe and worker on real Chrome) and well below the gap
 * between a stub (~1.0) and a real CDP measurement (~2.0+).
 *
 * Only fires when both benches are present — if a merchant's CSP
 * blocks blob workers and only the iframe ships, we don't have
 * anything to disagree against.
 */
function hasBenchDisagreement(headless: HeadlessSignals | undefined): boolean {
  const iframe = headless?.cdp?.consoleTiming;
  const worker = headless?.cdp?.consoleTimingWorker;
  if (!iframe || !worker) return false;
  // Magnitude floor: BOTH sides must be above the CDP detection floor for
  // a ratio disagreement to be meaningful. If either side is sub-floor,
  // its ratio is noise dividing noise (real-Brave telemetry: worker ratios
  // randomly walking 0.81–2.00 at heavy=4–9µs from thread-scheduling
  // jitter alone), and comparing a noise ratio against a real ratio
  // produces false-positive deltas with no attack signal underneath.
  //
  // What we lose: nothing. The attack model — stub one bench to ratio ~1
  // while leaving the other unstubbed and seeing real CDP — requires the
  // unstubbed side to actually show CDP overhead (heavy ≥ 25µs). That
  // case is already caught by `benchTrips` per-bench on the unstubbed
  // side, regardless of disagreement. This detector's marginal coverage
  // is for attacks where BOTH sides are above the noise floor but ratios
  // diverge — that case is preserved.
  const aHeavy = iframe.log_heavy_us ?? 0;
  const bHeavy = worker.log_heavy_us ?? 0;
  if (aHeavy < BENCH_NOISE_FLOOR_US || bHeavy < BENCH_NOISE_FLOOR_US) {
    return false;
  }
  const a = iframe.heavy_over_tiny;
  const b = worker.heavy_over_tiny;
  if (typeof a !== "number" || typeof b !== "number") return false;
  return Math.abs(a - b) > 0.5;
}

/**
 * Hard CDP residue: globals or bindings that no legitimate browser
 * exposes. These are collected by the SDK's `detectCdp()` (headless/
 * index.ts).
 *
 * - `consoleTimingWorker.console_lies` — `console.*` patches detected
 *                         inside the bench's worker realm. Worker
 *                         realms have no legitimate wrappers (extensions
 *                         don't reach them, app shims don't either), so
 *                         any count > 0 is attacker source injected via
 *                         wrapped `Worker` / `Blob` / `URL.createObjectURL`.
 * - `cdcGlobals`        — `$cdc_*` keys on `document` (ChromeDriver / Selenium).
 * - `pwBindings`        — `__pw_*` keys on `window` (Playwright IPC).
 * - `automationGlobals` — `window.__playwright`, `window.__puppeteer`,
 *                         `_phantom`, `callPhantom`, `__selenium_unwrapped`,
 *                         `__webdriver_evaluate`, etc.
 * - `clientLitter`      — bespoke bot scaffolding keys matching the
 *                         BOT_LITTER_RE pattern (cdc_, puppeteer_, scrape_,
 *                         __solver, __captcha, etc.).
 *
 * Real Chrome with extensions does not produce any of these. Every fire
 * is high-confidence automation evidence.
 */
function hasHardCdpResidue(headless: HeadlessSignals | undefined): boolean {
  const cdp = headless?.cdp;
  if (!cdp) return false;
  // Console patches inside the worker realm. The SDK's v3 closure check
  // moved here from the main-thread lie scanner (which false-positived
  // on CriOS's Google-iOS analytics shim). Worker realms have no
  // legitimate `console.*` wrappers — extensions can't reach them,
  // app shims don't either. Anything detected here is attacker source
  // injected via wrapped `Worker` / `Blob` / `URL.createObjectURL`.
  // Worth full-block tier on its own.
  const workerConsoleLies = cdp.consoleTimingWorker?.console_lies ?? 0;
  if (workerConsoleLies > 0) return true;
  return (
    cdp.cdcGlobals === true ||
    cdp.pwBindings === true ||
    (cdp.automationGlobals?.length ?? 0) > 0 ||
    (cdp.clientLitter?.length ?? 0) > 0 ||
    // `Object.getOwnPropertyNames` is the enumeration primitive the four
    // checks above all depend on. A filtered replacement (e.g. `function
    // getOwnPropertyNames(obj) { return native(obj).filter(k => !/^__pw_/
    // .test(k)); }`) blinds all four signals at once — they return clean
    // state because the keys were filtered out before iteration. False
    // here flags the "blinded oracle" condition directly.
    cdp.ownPropsNative === false
  );
}

/**
 * Soft CDP residue: behavioral divergence that bot stealth tools cause.
 *
 * - `phantomMismatch`    — `navigator.webdriver` differs between the
 *                          main frame and a nested phantom iframe. Indicates
 *                          per-frame webdriver patching (some stealth
 *                          plugins miss nested realms).
 * - `crossRealmTampered` — for a fixed list of native APIs (Element.
 *                          getBoundingClientRect, HTMLCanvasElement.
 *                          getContext/toDataURL, Performance.now,
 *                          Date.getTimezoneOffset, Navigator.toString),
 *                          the SDK compares Function.prototype.toString
 *                          across a fresh realm. A divergence means the
 *                          attacker patched in the parent realm only —
 *                          the classic `addInitScript` footprint.
 *
 * Both can sporadically fire on unusual but legitimate setups (some
 * privacy-hardened browsers re-implement Performance.now via JS), so
 * keep these at the 75 tier rather than 100.
 */
function hasSoftCdpResidue(headless: HeadlessSignals | undefined): boolean {
  const cdp = headless?.cdp;
  if (!cdp) return false;
  return (
    cdp.phantomMismatch === true || (cdp.crossRealmTampered?.length ?? 0) > 0
  );
}

/**
 * Iframe-crypto liveness probe failure.
 *
 * The SDK constructs a double-nested hidden iframe and times
 * `subtle.generateKey({ECDH, P-256}, false, ['deriveBits'])` inside it
 * against a 1s timeout (see `ms-argus-web-integrity/src/status/
 * iframe-crypto-probe.ts`). Real browsers resolve in <100ms.
 * Marionette-augmented runtimes (Playwright Firefox; Camoufox even
 * with full UA spoofing) leave the iframe's WebCrypto thread orphaned
 * and the Promise never resolves — the probe reports
 * `responsive: false`.
 *
 * `iframe_created: false` (vs `responsive: false`) is a separate
 * environmental case — privacy sandbox, CSP restrictions, etc. We
 * only fire on `iframe_created: true && responsive: false`, the
 * specific signature of "the iframe was constructable but WebCrypto
 * never resolved inside it." This is exactly the Marionette pattern.
 *
 * Confidence tier: full automation 100 + tampering 50. Camoufox's
 * entire purpose is detection evasion — its presence is itself a
 * tampering signal, not just an automation signal.
 */
function hasIframeCryptoStuck(
  integrity: IntegrityResultsData | undefined,
): boolean {
  const ic = (
    integrity?.device as
      | {
          status?: {
            iframeCrypto?: {
              responsive?: boolean;
              elapsed_ms?: number | null;
              iframe_created?: boolean;
            };
          };
        }
      | undefined
  )?.status?.iframeCrypto;
  if (!ic) return false;
  return ic.iframe_created === true && ic.responsive === false;
}

/**
 * Automation score. Tiered checks, MAX WINS (composes, doesn't short-circuit):
 *   1. STRICT markers (`headlessRating`) — webdriver / headless UA /
 *      headless worker UA. Each is unambiguous on its own — no legitimate
 *      human browser exposes any of them. Any single marker → 100.
 *      (The previous 1/3 → 75 tier was wrong on this point: a "1-of-N
 *      weak" ladder belongs on `likeHeadless` where the constituent
 *      signals are individually soft. The three `headless` markers were
 *      picked precisely because each is by itself definitive.)
 *   2. CDP TIMING — console-serialization overhead test. Catches
 *      Playwright/Puppeteer/patchright/selenium-CDP regardless of how
 *      thoroughly static residue has been scrubbed, because Chrome's
 *      inspector serialization can't be hidden by JS-level patches.
 *      Two independent benches run per session (iframe on main thread,
 *      Worker on its own thread) and the check trips if either crosses
 *      the threshold. → 75 (block-tier). See hasCdpTimingSignal.
 *   2a. BENCH DISAGREEMENT — both benches present and their
 *       `heavy_over_tiny` differs by more than 0.5. Signature of a
 *       stub-one-leave-the-other attack (e.g. `page.route` rewriting
 *       the iframe bundle while the blob-URL worker survives intact).
 *       → 75. See hasBenchDisagreement.
 *   2b. HARD CDP RESIDUE — `$cdc_*` / `__pw_*` / known automation globals
 *       / bot litter scaffolding. These don't appear in real browsers,
 *       extensions included. → 100 (full-block tier). See hasHardCdpResidue.
 *   2c. SOFT CDP RESIDUE — phantom-iframe webdriver mismatch or cross-
 *       realm toString divergence on Element/Canvas/Performance/Date/
 *       Navigator. Detects per-frame init-script patching footprint.
 *       → 75 (block-tier). See hasSoftCdpResidue.
 *   3. WEAK markers (`likeHeadlessRating`) — 11 environment signals
 *      (no Chrome object, no plugins, blank UA-CH, etc). Real but
 *      not damning on its own; the % maps directly into the score.
 *      **Mobile carve-out:** these signals were calibrated for desktop
 *      browsers. iPhone Safari has no taskbar, no plugins, and blank
 *      UA-CH for legitimate reasons — every real iPhone visitor would
 *      otherwise floor at automation ≈ 10. We zero out weak markers
 *      when the UA (main or worker) shows mobile.
 *   4. STEALTH markers (`stealthRating`) — Function.toString proxy,
 *      bad WebGL, missing chrome runtime. +20 bonus when any fire.
 */
/**
 * CDP-residue + iframe-crypto-liveness score (the 2x/2b/2c tiers in the
 * botProbability docstring). Returns 0 if no residue, 75 for soft/timing
 * tier, 100 for the hard tier. Extracted to keep `botProbability` under
 * the cyclomatic-complexity cap.
 */
function cdpAutomationScore(
  input: MerchantProjectionInput,
  headless: HeadlessSignals | undefined,
): number {
  // Marionette-augmented runtimes (PW-FF, Camoufox, etc.) hang the
  // nested iframe's WebCrypto generateKey. No legitimate browser does
  // this. Full automation tier.
  if (hasIframeCryptoStuck(input.integrity)) return 100;
  if (hasHardCdpResidue(headless)) return 100;
  if (hasCdpTimingSignal(headless)) return 75;
  // Iframe vs. worker bench disagreement: one was stubbed, the other
  // measures real CDP overhead. Direct evidence of bundle-rewrite or
  // function-replacement tampering — fire even when neither bench trips
  // on its own, because the "clean" side is the stub.
  if (hasBenchDisagreement(headless)) return 75;
  if (hasSoftCdpResidue(headless)) return 75;
  return 0;
}

function botProbability(input: MerchantProjectionInput): number {
  const headless = readHeadless(
    input.integrity ?? ({} as IntegrityResultsData),
  );
  // Strict and CDP tiers MAX-COMPOSE rather than short-circuit. The prior
  // shape returned the first non-zero of the two, which inverted scoring
  // in cases like PW-FF (webdriver=true AND iframe-crypto-stuck): the
  // strict check fired first at the old 1/3 → 75 tier and the function
  // returned, never reaching cdpAutomationScore where iframe-crypto-stuck
  // would have promoted to 100. Camoufox (which spoofs webdriver→false)
  // bypassed the strict check, fell through to CDP, and ended up
  // scoring HIGHER than the less-stealthy PW-FF. Inverted from intent.
  const strict = headless?.headlessRating ?? 0;
  // Any single strict marker is on its own conclusive evidence of
  // automation — see docstring. The old 33/67/100 ladder collapses
  // to a binary 0/100.
  const strictScore = strict > 0 ? 100 : 0;
  const cdpScore = cdpAutomationScore(input, headless);
  const hardScore = Math.max(strictScore, cdpScore);
  if (hardScore > 0) return hardScore;
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
 * TLS-vs-UA mismatch (cipher count + GREASE presence). Distinct from
 * JA4_UA_BROWSER_MISMATCH — that needs the JA4 cipher hash to be in the
 * known-browser table, which fails open when a TLS-terminating proxy
 * re-originates with a stripped cipher list (Cisco Umbrella, Zscaler,
 * mitmproxy/Burp). TLS_UA_MISMATCH is the safety net for that case —
 * emitted by `analyzeJa4Ua` from the rules in
 * `analysis/ja4-ua/tls-rules.ts` over the raw `cipher_count` / `has_grease`
 * fields the h2-probe captures.
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
 * Apple Private Relay / Cloudflare WARP carve-out for the kernel-OS-mismatch
 * signal. Privacy-relay terminates the client's TCP at a Linux egress box
 * (Cloudflare/Akamai), so the kernel observes Linux-typical TCP options
 * even when the actual client is iOS/macOS — same architectural shape as the
 * corporate-shield case.
 *
 * BUT: unlike corporate-shield ASNs (Cisco Umbrella / Zscaler), where ASN
 * ownership is essentially 1:1 with proxy infrastructure, CDN ASNs like
 * Cloudflare AS13335 and Akamai AS16625 host millions of unrelated tenants
 * (Workers, Pages, R2, third-party CDN customers). Granting a kernel-OS-
 * mismatch carve-out on `category=privacy_relay` alone would let an attacker
 * spin up a Cloudflare Worker, proxy traffic through it claiming iOS UA,
 * and bypass the device-tampering check.
 *
 * To close that gap we require three independent fingerprints to converge
 * before treating the relay path as legitimate Apple traffic:
 *   1. JA4 family is safari (TLS ClientHello matches Safari's BoringSSL stack —
 *      extension order, GREASE positions, cipher list)
 *   2. H2 family is safari (HTTP/2 SETTINGS + frame ordering matches Safari)
 *   3. UA OS is iOS or macOS
 *
 * Defeating all three requires literally running Safari on a real Apple
 * device — a Linux/Python script behind a Cloudflare Worker fails JA4 + H2
 * immediately. Sophisticated attackers running Safari on real iPhones can
 * still clear this gate, but at that point the cost-per-session is high
 * enough that the kernel-OS axis stops being the right detection layer.
 *
 * Like the corporate-shield carve-out, this only suppresses the SCORE
 * contribution. The raw KERNEL_OS_MISMATCH_DARWIN signal stays on
 * `analysis.kernel_os.signals` for forensic review.
 */
function isVerifiedAppleRelay(integrity: IntegrityResultsData): boolean {
  if (integrity.analysis?.ip?.asn?.category !== "privacy_relay") return false;
  const ja4Ua = (
    integrity.analysis as {
      ja4_ua?: {
        ja4_browser_family?: string | null;
        h2_browser_family?: string | null;
        ua_os?: string | null;
      };
    }
  ).ja4_ua;
  if (!ja4Ua) return false;
  return (
    ja4Ua.ja4_browser_family === "safari" &&
    ja4Ua.h2_browser_family === "safari" &&
    (ja4Ua.ua_os === "iOS" || ja4Ua.ua_os === "macOS")
  );
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
  /** Iframe-crypto liveness probe reported the nested iframe was constructable
   *  but `subtle.generateKey({ECDH, P-256})` never resolved within 1s. The
   *  Marionette / Camoufox signature — no legitimate browser does this. Used
   *  to boost tampering alongside the automation=100 signal already wired
   *  in `botProbability`. */
  iframeCryptoStuck: boolean;
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

/**
 * Brave on iOS positive-identification signature.
 *
 * Background: Apple requires all iOS browsers to use WebKit, so "Brave for
 * iOS" is structurally Safari with Brave's privacy shields layered over the
 * top via content-blocker rules + JS shims. The user-visible Brave logo
 * does not show up in UA, sec-ch-ua, JA4, h2, or kernel-OS signals —
 * every network/protocol surface looks identical to plain iOS Safari.
 *
 * Brave does, however, leave one unambiguous fingerprint: its Shields
 * wrap a specific set of fingerprinting-related APIs to add noise or
 * return sanitized values:
 *   - `AnalyserNode.{getFloatFrequencyData, getByteFrequencyData,
 *      getFloatTimeDomainData, getByteTimeDomainData}` — audio noise
 *      injection (defeats audio fingerprinting)
 *   - `AudioBuffer.getChannelData` — same
 *   - `PluginArray.{item, namedItem}` + `Navigator.plugins` — sanitized
 *      empty plugin list (defeats plugin enumeration)
 *   - `Navigator.hardwareConcurrency` — quantized to coarse buckets
 *
 * Real Safari does none of these. The lies-scanner's seven structural
 * checks (toString shape, descriptor presence, own-property keys, etc.)
 * fire on every one of these wrapped APIs, producing ~35-50 "lies"
 * concentrated in this exact key set. Without a carve-out this trips
 * `isDefinitiveTampering` (lies >= 20) and the user gets
 * `device_tampering = 100` for using a privacy browser correctly.
 *
 * This detector matches when:
 *   - UA family is Safari AND UA OS is iOS, AND
 *   - At least 4 of the 5 Brave-Shields audio APIs are in the lies
 *     dictionary (the audio bundle is what Brave reliably wraps), AND
 *   - At least 1 of the Brave-Shields plugin APIs is in the lies
 *     dictionary (covers Brave's plugin sanitization)
 *
 * The intersection requirement defeats a bot that wraps audio APIs
 * alone or plugins alone — Brave reliably hits both surfaces because
 * each defends a different fingerprinting class.
 *
 * Returns the set of attributable lies + the matched flag. Callers
 * subtract `attributedLies` from `totalLies` before the
 * `lies >= 20 = definitive tampering` rule. Brave's lies still appear
 * in the raw `device.lies.data` for diagnostics; only the score is
 * carved out.
 */
const BRAVE_IOS_AUDIO_KEYS = [
  "AnalyserNode.getFloatFrequencyData",
  "AnalyserNode.getByteFrequencyData",
  "AnalyserNode.getFloatTimeDomainData",
  "AnalyserNode.getByteTimeDomainData",
  "AudioBuffer.getChannelData",
] as const;

const BRAVE_IOS_PLUGIN_KEYS = [
  "PluginArray.item",
  "PluginArray.namedItem",
  "Navigator.plugins",
] as const;

const BRAVE_IOS_NAV_KEYS = ["Navigator.hardwareConcurrency"] as const;

const BRAVE_IOS_ALL_KEYS: ReadonlySet<string> = new Set<string>([
  ...BRAVE_IOS_AUDIO_KEYS,
  ...BRAVE_IOS_PLUGIN_KEYS,
  ...BRAVE_IOS_NAV_KEYS,
]);

interface BraveIosDetection {
  matched: boolean;
  attributedLies: number;
}

function detectBraveIos(integrity: IntegrityResultsData): BraveIosDetection {
  const ja4 = (
    integrity.analysis as {
      ja4_ua?: { ua_browser_family?: string; ua_os?: string };
    }
  ).ja4_ua;
  // Brave-iOS requires the underlying UA to claim Safari on iOS. We use
  // `ja4_ua.ua_*` (the parsed UA values the JA4 analyzer already
  // produced) rather than re-parsing the UA here. A spoofed UA pretending
  // to be iOS Safari would also fail browser-engine baseline, JA4, and
  // kernel-OS checks downstream — those signals still fire even when
  // this carve-out matches.
  if (ja4?.ua_browser_family !== "safari" || ja4?.ua_os !== "iOS") {
    return { matched: false, attributedLies: 0 };
  }

  const liesData =
    (
      integrity.device as
        | { lies?: { data?: Record<string, string[]> } }
        | undefined
    )?.lies?.data ?? {};

  const audioHits = BRAVE_IOS_AUDIO_KEYS.filter(
    (k) => liesData[k] !== undefined,
  ).length;
  const pluginHits = BRAVE_IOS_PLUGIN_KEYS.filter(
    (k) => liesData[k] !== undefined,
  ).length;

  // Conservative threshold: Brave Shields reliably wraps the entire
  // audio cluster (all 5 methods) and the plugin cluster (both
  // PluginArray methods + Navigator.plugins). Require ≥4 audio AND
  // ≥1 plugin to avoid attributing a partial-audio-spoof bot to
  // Brave. Bots that mimic Brave's full pattern aren't penalized via
  // lies — but they remain visible to every other detector
  // (worker divergence, kernel-OS, JA4 fork-of-Safari, etc.).
  if (audioHits < 4 || pluginHits < 1) {
    return { matched: false, attributedLies: 0 };
  }

  let attributedLies = 0;
  for (const [key, lies] of Object.entries(liesData)) {
    if (BRAVE_IOS_ALL_KEYS.has(key) && Array.isArray(lies)) {
      attributedLies += lies.length;
    }
  }
  return { matched: true, attributedLies };
}

function collectTamperingEvidence(
  integrity: IntegrityResultsData,
): TamperingEvidence {
  const rawLies =
    (integrity.device as { lies?: { totalLies?: number } } | undefined)?.lies
      ?.totalLies ?? 0;
  // Brave-iOS positive-identification carve-out. Brave's Shields wrap
  // audio + plugin APIs to defeat fingerprinting; the wraps trip ~50
  // structural lies that would otherwise tip definitive tampering.
  // We attribute those lies to the browser, not the device. See
  // `detectBraveIos` for the signature + the rationale.
  const braveIos = detectBraveIos(integrity);
  const lies = Math.max(0, rawLies - braveIos.attributedLies);
  // Worker-scope divergences emitted by analysis/worker/index.ts. The
  // analyzer's COMPARE_FIELDS list is `userAgent`, `platform`,
  // `hardwareConcurrency`, `deviceMemory`, `languages`, `webglRenderer`,
  // `webglVendor`, `webgl2Renderer`, `webgl2Vendor`, `appVersion`,
  // `product`, `onLine` — every one of these is structurally constant
  // across realms in real browsers EXCEPT `onLine`, which can flip if
  // the network state changes between scope captures. Exclude `onLine`
  // and count everything else: each remaining divergence is conclusive
  // evidence of automation tooling overriding navigator on the main
  // realm without propagating to workers.
  const divergences = (integrity.analysis.worker.divergences ?? []).filter(
    (d) => d.field !== "onLine",
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
  // Privacy-relay carve-out for the kernel-OS axis only — see
  // isVerifiedAppleRelay for why this is gated on JA4+H2+UA convergence
  // rather than the asn.category alone (which is true for any Cloudflare
  // Worker / Akamai tenant traffic that the classifier may incidentally
  // tag as privacy_relay).
  const appleRelay = isVerifiedAppleRelay(integrity);
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
    kernelOsMismatchHard: kernelSignals.hard && !shielded && !appleRelay,
    kernelOsMismatchSoft: kernelSignals.soft && !shielded && !appleRelay,
    iframeCryptoStuck: hasIframeCryptoStuck(integrity),
  };
}

function isDefinitiveTampering(e: TamperingEvidence): boolean {
  if (e.lies >= 20 || e.ja4Mismatch) return true;
  // Worker-scope divergence on ANY of the structurally-constant navigator
  // fields (see `collectTamperingEvidence` for the list) is conclusive on
  // its own. Real browsers propagate navigator state from the parent realm
  // to dedicated/shared workers identically — no browser has ever shipped
  // otherwise, and no privacy mode / extension produces this split. The
  // only mechanism that does is automation tooling (Playwright/Puppeteer/
  // Selenium) overriding the UA on the main thread without propagating to
  // workers. `uaDivergence` is the userAgent-specific narrow check; the
  // count covers the other COMPARE_FIELDS (platform, hardwareConcurrency,
  // webgl renderer/vendor, languages, appVersion, etc.).
  if (e.divergences >= 1 || e.uaDivergence || e.platformLie) return true;
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
  return e.kernelOsMismatchHard;
}

/**
 * Tier-60 signals: each one is "credible spoof but not structurally
 * impossible." Any one trips the floor. Listed here as an array so
 * `tamperingProbabilityFromEvidence` stays under the cyclomatic-
 * complexity cap.
 *
 * - lies: enough small lies
 * - uaHeaderMismatch: Chromium UA with sec-ch-ua header missing/wrong
 * - localeTamper: intl APIs vs navigator vs worker disagreement
 * - tlsUaMismatch: probe-side TLS profile lie (corp-shield carve-out
 *   already applied upstream)
 * - browserEngineSoft: naive-Bayes baseline below threshold but no
 *   single field structurally impossible
 * - kernelOsMismatchSoft: Linux UA + ECN negotiated (most distros ship
 *   tcp_ecn=2; ops teams who flip ECN on are the carve-out)
 *
 * Worker divergences are NOT in this tier — they're handled by
 * `isDefinitiveTampering` directly (any divergence on a structurally-
 * constant COMPARE_FIELD is 100, not 60).
 */
function hasTier60Signal(e: TamperingEvidence): boolean {
  return (
    e.lies >= 5 ||
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
  // Iframe-crypto liveness probe failed: the nested iframe was constructable
  // but `subtle.generateKey({ECDH,P-256})` never resolved within 1s. The
  // Marionette / Camoufox signature. Camoufox's whole purpose is detection
  // evasion — its presence implies tampering even when the spoofed UA and
  // fingerprint values pass every other check. Tier 50: more confident than
  // tzGeoMismatch (35, often benign for travelers), less than tier60Signal
  // signals which include cipher-level evidence.
  if (e.iframeCryptoStuck) return 50;
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
        metadata: asnFromIntegrity.metadata ?? null,
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
      metadata: null,
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
