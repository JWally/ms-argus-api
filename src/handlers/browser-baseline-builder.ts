/**
 * Browser baseline aggregator.
 *
 * Daily cron Lambda. Walks recent integrity-archive sessions, extracts
 * engine-invariant fields per session, and builds per-(browser, version,
 * incognito) histograms of observed values. Output written to
 * `browser-baselines.json.gz` in the IP_CLASS_BUCKET.
 *
 * Runtime analyzer (`analyzeBrowserEngine`) consumes the file via the
 * `services/network/browser-baselines.ts` module to detect engine-claim
 * inconsistencies (e.g. UA claims Safari but jsEngine=V8 → hard tampering
 * signal) and outlier values for the claimed browser version.
 *
 * Anti-poisoning:
 *   1. Per-(browser_version_key, ip, day) dedup — a single (browser,
 *      version, incognito, ip, date) tuple contributes at most one
 *      observation. Botnet must spread across many IPs to move histograms.
 *   2. Incognito split — `Chrome 147` and `Chrome 147 incognito` are
 *      separate keys. Engine fields stay in their natural buckets while
 *      incognito-affected fields (plugin count, quota) tighten on their
 *      own population.
 *
 * The aggregator does NOT enforce verdict=clean filtering yet; the dedup
 * is the meaningful protection at this scale. Stricter session-quality
 * filters can be added later if needed.
 *
 * Cost: ~7 days × ~500 firehose batches × ~50KB/batch = ~175MB scanned
 * per run. Single Lambda execution, well under timeout.
 */
import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import { gunzipSync, gzipSync } from "node:zlib";
import { parseUaToBrowser } from "../analysis/browser-engine/ua-parser";

const ARCHIVE_LOOKBACK_HOURS = 7 * 24;

const s3 = new S3Client({});

/**
 * Fields the analyzer reads — keep in sync with analyzeBrowserEngine.
 *
 * Split by trustworthiness on different traffic conditions:
 *
 * - JS_FIELDS: always trustworthy. Browser's JS environment isn't
 *   touched by network-layer interception. Train on every clean
 *   session, including corp-shielded ones.
 *
 * - TLS_FIELDS: only trustworthy when the network path doesn't munge
 *   TLS. Corporate shields (Cisco Umbrella / Zscaler / Cloudflare
 *   Access) terminate-and-re-originate TLS with their own profile,
 *   collapsing every browser to one shield-specific JA4. WebDriver-
 *   driven browsers also ship slightly different TLS in some setups.
 *   Skip these sessions for TLS field training; their JS fields still
 *   contribute normally.
 */
const JS_FIELDS = [
  "engine.jsEngine",
  "engine.layoutEngine",
  "engine.evalToStringLength",
  "engine.functionToStringLength",
  "engine.stackFormatHash",
  "navigator.vendor",
  "navigator.oscpuPresent",
  "windowPrefixes.apple",
  "windowPrefixes.moz",
  "windowPrefixes.webkit",
  "css.keyCount",
  "navigator.propertiesLength",
  "headless.chromium",
] as const;

const TLS_FIELDS = [
  "tls.ja4_cipher_hash",
  "tls.h2_pseudo_header_order",
  "tls.h2_protocol",
  "tls.cipher_count",
  "tls.has_grease",
] as const;

const INVARIANT_FIELDS = [...JS_FIELDS, ...TLS_FIELDS] as const;

interface InvariantTuple {
  [field: string]: string | number | boolean | null;
}

interface SessionObservation {
  /** "Chrome 147" or "Chrome 147 incognito" — the histogram bucket. */
  browserKey: string;
  /** "chromium" / "gecko" / "webkit" / "unknown" — for engine-family fallback. */
  engineFamily: string;
  /** "YYYY-MM-DD" — for per-IP-day dedup. */
  date: string;
  ip: string;
  invariants: InvariantTuple;
  /** When false, TLS fields are skipped during histogram bumping (corp
   *  shield in path or WebDriver-driven session). JS fields still count. */
  tlsTrustworthy: boolean;
}

interface FieldHistogram {
  [valueAsString: string]: number;
}

interface BrowserBaseline {
  n_sessions: number;
  fields: { [field: string]: FieldHistogram };
}

interface BaselinesPayload {
  generated_at: string;
  lookback_hours: number;
  /** Total firehose records read before any filtering. */
  n_total: number;
  /** Records that survived parse + cleanliness filter (drop class excluded). */
  n_after_filter: number;
  /** Of n_after_filter, how many were JS-only (corp_shield / privacy_relay). */
  n_js_only: number;
  /** Of n_after_filter, how many got both JS + TLS counted (clean residential). */
  n_both: number;
  /** After per-(browser_key, ip, day) dedup. */
  n_after_dedup: number;
  /** Per-browser-version (with incognito split) histograms. */
  browsers: { [key: string]: BrowserBaseline };
  /** Engine-family fallback (union across all versions of same family). */
  engine_families: { [family: string]: BrowserBaseline };
}

interface BuildResult {
  archive_sessions_scanned: number;
  observations_kept: number;
  observations_dropped: number;
  observations_js_only: number;
  observations_both: number;
  browser_keys: number;
  engine_families: number;
  bytes_uploaded: number;
  bucket: string;
  key: string;
}

// ─── Firehose archive enumeration (mirrors ip-class-discoverer pattern) ───

function buildHourlyPrefixes(now: number, hours: number): string[] {
  const prefixes: string[] = [];
  for (let i = 0; i < hours; i++) {
    const t = new Date(now - i * 60 * 60 * 1000);
    const y = t.getUTCFullYear();
    const m = String(t.getUTCMonth() + 1).padStart(2, "0");
    const d = String(t.getUTCDate()).padStart(2, "0");
    const h = String(t.getUTCHours()).padStart(2, "0");
    prefixes.push(`firehose/year=${y}/month=${m}/day=${d}/hour=${h}/`);
  }
  return prefixes;
}

async function listAllUnderPrefix(
  bucket: string,
  prefix: string,
): Promise<string[]> {
  const keys: string[] = [];
  let continuationToken: string | undefined;
  do {
    const r = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
      }),
    );
    for (const obj of r.Contents ?? []) {
      if (obj.Key) keys.push(obj.Key);
    }
    continuationToken = r.NextContinuationToken;
  } while (continuationToken);
  return keys;
}

async function loadRawSessions(
  bucket: string,
  key: string,
): Promise<Record<string, unknown>[]> {
  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
    );
    if (!obj.Body) return [];
    const buf = Buffer.from(await obj.Body.transformToByteArray());
    const text = gunzipSync(buf).toString("utf-8");
    const out: Record<string, unknown>[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        out.push(JSON.parse(trimmed) as Record<string, unknown>);
      } catch {
        /* skip malformed line */
      }
    }
    return out;
  } catch {
    return [];
  }
}

// ─── Per-session extraction ──────────────────────────────────────────────

function asObj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

function toScalar(v: unknown): string | number | boolean | null {
  if (v === null || v === undefined) return null;
  if (
    typeof v === "string" ||
    typeof v === "number" ||
    typeof v === "boolean"
  ) {
    return v;
  }
  return null;
}

function arrayLen(v: unknown): number | null {
  return Array.isArray(v) ? v.length : null;
}

function extractInvariants(row: Record<string, unknown>): InvariantTuple {
  const device = asObj(row.device);
  const engine = asObj(device.engine);
  const navigator = asObj(device.navigator);
  const windowPrefixes = asObj(device.windowPrefixes);
  const css = asObj(device.css);
  const headless = asObj(device.headless);
  const sigint = asObj(row.sigint);
  const h2 = asObj(sigint.h2);
  const tcpProbe = asObj(sigint.tcp_probe);
  const h2TlsSignals = asObj(h2.tls_signals);
  const tcpTlsSignals = asObj(tcpProbe.tls_signals);

  return {
    "engine.jsEngine": toScalar(engine.jsEngine),
    "engine.layoutEngine": toScalar(engine.layoutEngine),
    "engine.evalToStringLength": toScalar(engine.evalToStringLength),
    "engine.functionToStringLength": toScalar(engine.functionToStringLength),
    "engine.stackFormatHash": toScalar(engine.stackFormatHash),
    "navigator.vendor": toScalar(navigator.vendor),
    "navigator.oscpuPresent":
      navigator.oscpu !== undefined && navigator.oscpu !== null,
    "windowPrefixes.apple": toScalar(windowPrefixes.apple),
    "windowPrefixes.moz": toScalar(windowPrefixes.moz),
    "windowPrefixes.webkit": toScalar(windowPrefixes.webkit),
    "css.keyCount": toScalar(css.keyCount),
    "navigator.propertiesLength": arrayLen(navigator.properties),
    "headless.chromium": toScalar(headless.chromium),
    "tls.ja4_cipher_hash": ja4CipherHash(h2.ja4 ?? tcpProbe.ja4),
    "tls.h2_pseudo_header_order": toScalar(h2.pseudo_header_order),
    "tls.h2_protocol": toScalar(h2.protocol),
    // Cipher count from h2 first, fall back to tcp_probe — both probe paths
    // see the same client TLS but h2 is the more recent observation.
    "tls.cipher_count":
      toScalar(h2TlsSignals.cipher_count) ??
      toScalar(tcpTlsSignals.cipher_count),
    "tls.has_grease":
      toScalar(h2TlsSignals.has_grease) ?? toScalar(tcpTlsSignals.has_grease),
  };
}

/** Extract the cipher_hash segment (2nd component) from a JA4 string. */
function ja4CipherHash(ja4: unknown): string | null {
  if (typeof ja4 !== "string" || ja4.length === 0) return null;
  const parts = ja4.split("_");
  return parts.length >= 2 ? parts[1] : null;
}

/**
 * Decide whether a session can train baselines, and if so, which fields.
 *
 * Three outcomes:
 *
 *   "drop"  — session contributes nothing. Indicates one of:
 *     - device tampering (lies, worker.lied, JA4 mismatch, etc.)
 *     - automation (WebDriver / headless markers)
 *     - network-level proxy detection and legacy MSS-path telemetry
 *     - ASN category is vpn_proxy / hosting_proxy / datacenter / unknown
 *       (residential proxies, declared VPNs, hyperscalers — sessions
 *       originating here are predominantly bots, NOT representative of
 *       legit browser populations)
 *
 *   "js_only" — JS fields trained, TLS skipped. Network is benign
 *     (legitimate user) but TLS is intercepted-and-re-originated:
 *     - corporate_proxy (Cisco Umbrella / Zscaler / Cloudflare Access)
 *     - privacy_relay (Apple iCloud Private Relay)
 *     The browser's JS environment is real and trustworthy; only the
 *     TLS layer is munged by the security gateway / relay.
 *
 *   "both" — full training (residential / mobile / business / etc.
 *     with no tampering or automation signals). The default trust class.
 *
 * The filter is strict by design — the user explicitly wants no
 * pollution from proxies/VPNs/tampered devices in either bucket. Tail
 * cases (unknown ASN, missing analysis) drop conservatively.
 */
type TrainOutcome = "drop" | "js_only" | "both";

const ASN_CLEAN_NETWORK = new Set([
  "residential",
  "mobile",
  "business",
  "education",
  "government",
  "satellite",
  "cdn", // CDN egress is rare in merchant traffic but TLS reaches the user
]);
const ASN_TLS_MUNGED_NETWORK = new Set(["corporate_proxy", "privacy_relay"]);

const TAMPERING_CODES = new Set([
  "JA4_UA_BROWSER_MISMATCH",
  "H2_UA_BROWSER_MISMATCH",
  "JA4_H2_FAMILY_MISMATCH",
  "SAFARI_OS_MISMATCH",
  "TLS_UA_MISMATCH",
]);

function isDeviceTampered(row: Record<string, unknown>): boolean {
  const analysis = asObj(row.analysis);
  const device = asObj(row.device);
  if (Number(asObj(device.lies).totalLies ?? 0) > 0) return true;
  if (asObj(analysis.worker).lied === true) return true;
  if (asObj(analysis.timezone).lied === true) return true;
  if (asObj(analysis.client_hints_ua).hasStrongMismatch === true) return true;
  if (asObj(analysis.locale_geo).hasLocaleTamper === true) return true;
  const ja4Signals = Array.isArray(asObj(analysis.ja4_ua).signals)
    ? (asObj(analysis.ja4_ua).signals as Array<{ code?: unknown }>)
    : [];
  return ja4Signals.some(
    (s) => typeof s.code === "string" && TAMPERING_CODES.has(s.code),
  );
}

function isAutomated(row: Record<string, unknown>): boolean {
  const headlessOuter = asObj(asObj(row.device).headless);
  const headlessInner = asObj(headlessOuter.headless);
  return (
    headlessInner.webDriverIsOn === true ||
    headlessInner.hasHeadlessUA === true ||
    headlessInner.hasHeadlessWorkerUA === true ||
    Number(headlessOuter.headlessRating ?? 0) > 0
  );
}

function isNetworkProxyDetected(row: Record<string, unknown>): boolean {
  const analysis = asObj(row.analysis);
  const proxyWaterfall = asObj(analysis.proxy_waterfall);
  if (Number(proxyWaterfall.threat_score ?? 0) >= 50) return true;
  const network = asObj(analysis.network);
  return (
    Number(network.vpn_component ?? 0) >= 0.5 ||
    Number(network.proxy_score ?? 0) >= 0.5
  );
}

function classifyByAsnCategory(row: Record<string, unknown>): TrainOutcome {
  const asn = asObj(asObj(asObj(row.analysis).ip).asn);
  const category = typeof asn.category === "string" ? asn.category : null;
  if (!category) return "drop";
  if (ASN_TLS_MUNGED_NETWORK.has(category)) return "js_only";
  if (ASN_CLEAN_NETWORK.has(category)) return "both";
  return "drop";
}

function classifySessionForTraining(
  row: Record<string, unknown>,
): TrainOutcome {
  // Device-level rejections always apply (no exceptions for any ASN).
  if (isDeviceTampered(row)) return "drop";
  if (isAutomated(row)) return "drop";

  const byAsn = classifyByAsnCategory(row);

  // ASN-class-specific network-level checks.
  //
  //   "drop"     — hosting_proxy / vpn_proxy / datacenter / unknown.
  //                Already rejected, no further checks needed.
  //   "js_only"  — corporate_proxy / privacy_relay. These ASNs ALWAYS
  //                trip the network-level proxy/VPN detectors because
  //                of TLS-MITM artifacts (reduced MSS, stripped cipher
  //                lists). That's expected behavior of the shield, not
  //                evidence of a bot. Skip the network-level checks
  //                here, just like the projector's corp-shield carve-out.
  //   "both"     — residential/mobile/business. Apply network-level
  //                proxy/VPN detection — catches residential-proxy
  //                networks hiding behind legitimate ISP ASNs (e.g.
  //                Bright Data exits, hosting-as-residential-proxy).
  if (byAsn === "both" && isNetworkProxyDetected(row)) return "drop";
  return byAsn;
}

function parseObservation(
  row: Record<string, unknown>,
): SessionObservation | null {
  const ua = typeof row.user_agent === "string" ? row.user_agent : "";
  const headers = asObj(asObj(row.request_headers).headers);
  const secChUa =
    typeof headers["sec-ch-ua"] === "string"
      ? (headers["sec-ch-ua"] as string)
      : null;
  const browser = parseUaToBrowser(ua, secChUa);
  if (!browser) return null;

  const ip = typeof row.client_ip === "string" ? row.client_ip : null;
  if (!ip) return null;

  const createdAt = typeof row.created_at === "number" ? row.created_at : null;
  if (!createdAt) return null;

  const incognito = asObj(asObj(row.device).incognito).isPrivate === true;
  const browserKey = `${browser.browser} ${browser.version}${incognito ? " incognito" : ""}`;

  const date = new Date(createdAt).toISOString().slice(0, 10);

  const outcome = classifySessionForTraining(row);
  if (outcome === "drop") return null;

  return {
    browserKey,
    engineFamily: browser.engineFamily,
    date,
    ip,
    invariants: extractInvariants(row),
    tlsTrustworthy: outcome === "both",
  };
}

// ─── Aggregation ─────────────────────────────────────────────────────────

function emptyBaseline(): BrowserBaseline {
  const fields: { [k: string]: FieldHistogram } = {};
  for (const f of INVARIANT_FIELDS) fields[f] = {};
  return { n_sessions: 0, fields };
}

function bumpField(
  histogram: FieldHistogram,
  value: string | number | boolean | null,
): void {
  // null is a meaningful observation for some fields (e.g. browser didn't
  // expose `oscpu`) — represent as the literal string "null" so the
  // runtime can distinguish "field missing" from "field absent".
  const key = value === null ? "null" : String(value);
  histogram[key] = (histogram[key] ?? 0) + 1;
}

function bumpHistogram(
  baseline: BrowserBaseline,
  invariants: InvariantTuple,
  tlsTrustworthy: boolean,
): void {
  baseline.n_sessions += 1;
  for (const field of JS_FIELDS) {
    bumpField(baseline.fields[field], invariants[field]);
  }
  // TLS fields only contribute when the session's TLS observation is
  // trustworthy — corp shields and WebDriver paths produce artifacts
  // that would poison the JA4/H2 histograms.
  if (tlsTrustworthy) {
    for (const field of TLS_FIELDS) {
      bumpField(baseline.fields[field], invariants[field]);
    }
  }
}

function aggregate(observations: SessionObservation[]): {
  browsers: { [key: string]: BrowserBaseline };
  engine_families: { [family: string]: BrowserBaseline };
  n_after_dedup: number;
} {
  const seen = new Set<string>();
  const browsers: { [key: string]: BrowserBaseline } = {};
  const engineFamilies: { [family: string]: BrowserBaseline } = {};
  let kept = 0;

  for (const obs of observations) {
    const dedupKey = `${obs.browserKey}|${obs.ip}|${obs.date}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    kept += 1;

    if (!browsers[obs.browserKey]) browsers[obs.browserKey] = emptyBaseline();
    bumpHistogram(browsers[obs.browserKey], obs.invariants, obs.tlsTrustworthy);

    if (!engineFamilies[obs.engineFamily]) {
      engineFamilies[obs.engineFamily] = emptyBaseline();
    }
    bumpHistogram(
      engineFamilies[obs.engineFamily],
      obs.invariants,
      obs.tlsTrustworthy,
    );
  }

  return { browsers, engine_families: engineFamilies, n_after_dedup: kept };
}

// ─── Handler ─────────────────────────────────────────────────────────────

async function uploadBaselines(
  bucket: string,
  key: string,
  body: Buffer,
): Promise<void> {
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: body,
      ContentEncoding: "gzip",
      ContentType: "application/json",
      CacheControl: "max-age=86400",
    }),
  );
}

function parseAll(rawSessions: Record<string, unknown>[]): {
  observations: SessionObservation[];
  nJsOnly: number;
  nBoth: number;
} {
  const observations: SessionObservation[] = [];
  let nJsOnly = 0;
  let nBoth = 0;
  for (const row of rawSessions) {
    const obs = parseObservation(row);
    if (!obs) continue;
    observations.push(obs);
    if (obs.tlsTrustworthy) nBoth += 1;
    else nJsOnly += 1;
  }
  return { observations, nJsOnly, nBoth };
}

async function listRecentArchiveKeys(
  bucket: string,
  hours: number,
): Promise<string[]> {
  const prefixes = buildHourlyPrefixes(Date.now(), hours);
  const groups = await Promise.all(
    prefixes.map((p) => listAllUnderPrefix(bucket, p)),
  );
  return groups.flat();
}

async function loadAllSessions(
  bucket: string,
  keys: string[],
): Promise<Record<string, unknown>[]> {
  // Conservative concurrency — S3 GETs are cheap but Lambda memory isn't
  // unbounded. 16 in flight matches the discoverer's pattern.
  const out: Record<string, unknown>[] = [];
  const CONCURRENCY = 16;
  for (let i = 0; i < keys.length; i += CONCURRENCY) {
    const batch = keys.slice(i, i + CONCURRENCY);
    const sessions = await Promise.all(
      batch.map((k) => loadRawSessions(bucket, k)),
    );
    for (const s of sessions) out.push(...s);
  }
  return out;
}

export async function handler(): Promise<BuildResult> {
  const archiveBucket = process.env.INTEGRITY_ARCHIVE_BUCKET;
  const outBucket = process.env.IP_CLASS_BUCKET;
  const outKey =
    process.env.BROWSER_BASELINES_KEY ?? "browser-baselines.json.gz";
  if (!archiveBucket) {
    throw new Error("INTEGRITY_ARCHIVE_BUCKET env var required");
  }
  if (!outBucket) throw new Error("IP_CLASS_BUCKET env var required");

  const keys = await listRecentArchiveKeys(
    archiveBucket,
    ARCHIVE_LOOKBACK_HOURS,
  );
  const rawSessions = await loadAllSessions(archiveBucket, keys);

  const { observations, nJsOnly, nBoth } = parseAll(rawSessions);

  const { browsers, engine_families, n_after_dedup } = aggregate(observations);

  const payload: BaselinesPayload = {
    generated_at: new Date().toISOString(),
    lookback_hours: ARCHIVE_LOOKBACK_HOURS,
    n_total: rawSessions.length,
    n_after_filter: observations.length,
    n_js_only: nJsOnly,
    n_both: nBoth,
    n_after_dedup,
    browsers,
    engine_families,
  };
  const gz = gzipSync(Buffer.from(JSON.stringify(payload)), { level: 9 });

  await uploadBaselines(outBucket, outKey, gz);

  return {
    archive_sessions_scanned: rawSessions.length,
    observations_kept: n_after_dedup,
    observations_dropped: rawSessions.length - observations.length,
    observations_js_only: nJsOnly,
    observations_both: nBoth,
    browser_keys: Object.keys(browsers).length,
    engine_families: Object.keys(engine_families).length,
    bytes_uploaded: gz.length,
    bucket: outBucket,
    key: outKey,
  };
}
