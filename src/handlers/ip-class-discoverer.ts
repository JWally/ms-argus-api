/**
 * Auto-overlay discoverer.
 *
 * Nightly cron Lambda. Walks recent integrity-archive sessions to find IPs
 * the runtime classifier couldn't categorize, then RDAPs them. For each
 * discovered carrier name, runs a reverse name-search across all 5 RIRs
 * to backfill ALL related CIDRs at once (the multiplicative-magic
 * optimization — one IP discovery often yields 5-50 rule additions).
 *
 * Output: merges new rules with the existing `auto-overlay.json.gz` and
 * writes back to S3. The runtime classifier picks up the new file on next
 * cold start (or 24h TTL refresh, whichever comes first).
 */
import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
  type _Object,
} from "@aws-sdk/client-s3";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  rdapIpLookup,
  rdapNameSearch,
  simplifyRdapName,
  type RdapIpInfo,
} from "../services/network/rdap-client";
import {
  categorize,
  type NetworkCategory,
} from "../services/network/categorize";
import {
  cidrToRange,
  ipToInt,
  type CompiledRange,
} from "../services/network/cidr-tree";

interface OverlayRule {
  cidr: string;
  category: NetworkCategory;
  name: string;
  source: "rdap_ip" | "rdap_search";
  discovered_at: string;
}

interface OverlayFileShape {
  generated_at: string;
  rules_total: number;
  rules: OverlayRule[];
}

interface DiscoverResult {
  archive_sessions_scanned: number;
  ips_walked: number;
  ips_skipped_existing: number;
  rdap_ip_lookups: number;
  rdap_name_searches: number;
  new_rules: number;
  total_rules: number;
}

const POLITE_DELAY_MS = 400;
const ARCHIVE_LOOKBACK_HOURS = 48;

const s3 = new S3Client({});

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
  let token: string | undefined;
  do {
    const out = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: token,
        MaxKeys: 1000,
      }),
    );
    for (const c of (out.Contents ?? []) as _Object[]) {
      if (c.Key) keys.push(c.Key);
    }
    token = out.NextContinuationToken;
  } while (token);
  return keys;
}

/**
 * Firehose archive layout: gzipped NDJSON batches at
 * `firehose/year=YYYY/month=MM/day=DD/hour=HH/...gz`. List by enumerating
 * the hour-prefixes for the lookback window — vastly fewer S3 LIST calls
 * than a flat namespace once volume scales (1B/mo would be ~150M flat
 * keys vs ~3K Firehose batches in 48h).
 */
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

interface SessionMinimal {
  cf_ip?: string;
  tcp_ip?: string;
  webrtc_ip?: string;
  api_ip?: string;
  network_class?: string | null;
}

function strOrUndef(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function strIpv4OrUndef(v: unknown): string | undefined {
  return typeof v === "string" && /^\d+\.\d+\.\d+\.\d+$/.test(v)
    ? v
    : undefined;
}

function parseSessionRecord(d: Record<string, unknown>): SessionMinimal {
  const sigint = (d.sigint as Record<string, unknown> | undefined) ?? {};
  const cf = (sigint.aws_cf as Record<string, unknown> | undefined) ?? {};
  const analysis = d.analysis as Record<string, unknown> | undefined;
  const ip = (analysis?.ip as Record<string, unknown> | undefined) ?? {};
  const ips = (ip.ips as Record<string, unknown> | undefined) ?? {};
  const asn = ip.asn as Record<string, unknown> | undefined;
  return {
    cf_ip: strOrUndef(cf.ip),
    tcp_ip: strOrUndef(ips.tcp),
    webrtc_ip: strIpv4OrUndef(ips.webrtc),
    api_ip: strOrUndef(ips.api),
    network_class: (asn?.network_class as string | null | undefined) ?? null,
  };
}

/**
 * Read one Firehose batch (gzipped NDJSON), parse every line, return all
 * sessions. Bad lines are skipped — Firehose can rarely include
 * partial records around delivery boundaries.
 */
async function loadSessionsFromKey(
  bucket: string,
  key: string,
): Promise<SessionMinimal[]> {
  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
    );
    if (!obj.Body) return [];
    const buf = Buffer.from(await obj.Body.transformToByteArray());
    const text = gunzipSync(buf).toString("utf-8");
    const out: SessionMinimal[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        out.push(parseSessionRecord(parsed));
      } catch {
        // skip malformed line
      }
    }
    return out;
  } catch {
    return [];
  }
}

const PRIVATE_RANGES: ReadonlyArray<(a: number, b: number) => boolean> = [
  (a) => a === 10 || a === 127,
  (a, b) => a === 172 && b >= 16 && b <= 31,
  (a, b) => a === 192 && b === 168,
  (a, b) => a === 169 && b === 254, // link-local
];

function isPublicIpv4(ip: string): boolean {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return !PRIVATE_RANGES.some((isPrivate) => isPrivate(a, b));
}

async function loadExistingOverlay(
  bucket: string,
  key: string,
): Promise<OverlayRule[]> {
  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
    );
    if (!obj.Body) return [];
    const buf = Buffer.from(await obj.Body.transformToByteArray());
    const parsed = JSON.parse(
      gunzipSync(buf).toString("utf-8"),
    ) as OverlayFileShape;
    return parsed.rules ?? [];
  } catch {
    return []; // first run — no overlay file yet
  }
}

async function writeOverlay(
  bucket: string,
  key: string,
  rules: OverlayRule[],
): Promise<number> {
  const payload: OverlayFileShape = {
    generated_at: new Date().toISOString(),
    rules_total: rules.length,
    rules,
  };
  const gz = gzipSync(Buffer.from(JSON.stringify(payload)), { level: 9 });
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: gz,
      ContentEncoding: "gzip",
      ContentType: "application/json",
      CacheControl: "max-age=86400",
    }),
  );
  return gz.length;
}

function compileForLookup(
  rules: OverlayRule[],
): CompiledRange<{ rule: OverlayRule }>[] {
  const out: CompiledRange<{ rule: OverlayRule }>[] = [];
  for (const r of rules) {
    const range = cidrToRange(r.cidr);
    if (!range) continue;
    out.push({
      start: range[0],
      end: range[1],
      category: r.category,
      meta: { rule: r },
    });
  }
  out.sort((a, b) => a.start - b.start);
  return out;
}

function ipCovered(
  ranges: CompiledRange<{ rule: OverlayRule }>[],
  ip: string,
): boolean {
  if (!isPublicIpv4(ip)) return true; // skip private as if covered
  const n = ipToInt(ip);
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (ranges[mid].start > n) hi = mid - 1;
    else if (ranges[mid].end < n) lo = mid + 1;
    else return true;
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function categorizeRdapInfo(info: RdapIpInfo): NetworkCategory | null {
  return categorize(info.name, info.org, ...info.nameservers);
}

function buildDirectRules(
  info: RdapIpInfo,
  category: NetworkCategory | null,
  now: string,
): OverlayRule[] {
  // Skip when the categorizer can't decide. Previously fell back to
  // "residential" which manufactured a trust signal for any datacenter
  // operator absent from the regex allowlist (QTS, Equinix, CoreSite,
  // BrowserStack, …) — wrong direction for fraud detection. The runtime
  // classifier falls through to the ASN dict / catalog when no overlay
  // rule matches, so dropping unclassified rules is the correct semantic.
  if (!category) return [];
  return info.cidrs.map((cidr) => ({
    cidr,
    category,
    name: info.name,
    source: "rdap_ip" as const,
    discovered_at: now,
  }));
}

async function buildReverseSearchRules(
  info: RdapIpInfo,
  fallback: NetworkCategory | null,
  now: string,
  orgsSeen: Set<string>,
): Promise<{ rules: OverlayRule[]; called: boolean }> {
  const simple = simplifyRdapName(info.name);
  if (!simple || simple.length < 4 || orgsSeen.has(simple)) {
    return { rules: [], called: false };
  }
  orgsSeen.add(simple);
  const networks = await rdapNameSearch(simple);
  const rules: OverlayRule[] = [];
  for (const n of networks) {
    // Same fail-closed posture as buildDirectRules — only emit a rule when
    // we know the category. `fallback` is the seed-IP's category (often
    // also null when the seed wasn't matchable); when it IS known, we
    // propagate it to siblings discovered via name-search since they share
    // the same operator.
    const cat = categorize(n.name) ?? fallback;
    if (!cat) continue;
    for (const cidr of n.cidrs) {
      rules.push({
        cidr,
        category: cat,
        name: n.name,
        source: "rdap_search",
        discovered_at: now,
      });
    }
  }
  return { rules, called: true };
}

function isFullyCovered(
  ranges: CompiledRange<{ rule: OverlayRule }>[],
  cidr: string,
): boolean {
  const range = cidrToRange(cidr);
  if (!range) return true; // malformed — treat as covered (drop)
  return (
    ipCovered(ranges, intToIp(range[0])) && ipCovered(ranges, intToIp(range[1]))
  );
}

async function discoverFromRdap(
  ip: string,
  ranges: CompiledRange<{ rule: OverlayRule }>[],
  orgsSeen: Set<string>,
): Promise<{
  added: OverlayRule[];
  rdapCalls: number;
  nameSearches: number;
}> {
  const info = await rdapIpLookup(ip);
  if (!info) return { added: [], rdapCalls: 1, nameSearches: 0 };

  const category = categorizeRdapInfo(info);
  const now = new Date().toISOString();
  const direct = buildDirectRules(info, category, now);
  const search = await buildReverseSearchRules(info, category, now, orgsSeen);
  const candidate = [...direct, ...search.rules];
  const added = candidate.filter((r) => !isFullyCovered(ranges, r.cidr));

  return {
    added,
    rdapCalls: 1,
    nameSearches: search.called ? 1 : 0,
  };
}

function intToIp(n: number): string {
  return `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
}

function dedupe(rules: OverlayRule[]): OverlayRule[] {
  const seen = new Set<string>();
  const out: OverlayRule[] = [];
  for (const r of rules) {
    const key = `${r.cidr}|${r.category}|${r.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

function pushAddedRules(
  added: OverlayRule[],
  newRules: OverlayRule[],
  workingRanges: CompiledRange<{ rule: OverlayRule }>[],
): void {
  for (const r of added) {
    newRules.push(r);
    const range = cidrToRange(r.cidr);
    if (range) {
      workingRanges.push({
        start: range[0],
        end: range[1],
        category: r.category,
        meta: { rule: r },
      });
    }
  }
  if (added.length > 0) workingRanges.sort((a, b) => a.start - b.start);
}

interface DiscoveryStats {
  skipped: number;
  rdapCalls: number;
  nameSearches: number;
  newRules: OverlayRule[];
}

async function walkCandidateIps(
  ips: string[],
  existingRanges: CompiledRange<{ rule: OverlayRule }>[],
): Promise<DiscoveryStats> {
  const newRules: OverlayRule[] = [];
  const orgsSeen = new Set<string>();
  const workingRanges = [...existingRanges];
  const stats = { skipped: 0, rdapCalls: 0, nameSearches: 0 };

  for (const ip of ips) {
    if (ipCovered(workingRanges, ip)) {
      stats.skipped += 1;
      continue;
    }
    const result = await discoverFromRdap(ip, workingRanges, orgsSeen);
    stats.rdapCalls += result.rdapCalls;
    stats.nameSearches += result.nameSearches;
    pushAddedRules(result.added, newRules, workingRanges);
    await sleep(POLITE_DELAY_MS);
  }
  return { ...stats, newRules };
}

function isUnmappedSession(s: SessionMinimal): boolean {
  return !s.network_class || s.network_class === "unknown";
}

function addSessionIps(s: SessionMinimal, candidates: Set<string>): void {
  if (!isUnmappedSession(s)) return;
  for (const ip of [s.cf_ip, s.tcp_ip, s.webrtc_ip, s.api_ip]) {
    if (ip && isPublicIpv4(ip)) candidates.add(ip);
  }
}

async function fetchSessionBatch(
  archiveBucket: string,
  batch: string[],
  candidates: Set<string>,
): Promise<number> {
  const groups = await Promise.all(
    batch.map((k) => loadSessionsFromKey(archiveBucket, k)),
  );
  let total = 0;
  for (const sessions of groups) {
    for (const s of sessions) {
      total += 1;
      addSessionIps(s, candidates);
    }
  }
  return total;
}

async function collectCandidateIps(archiveBucket: string): Promise<{
  keys: string[];
  candidates: Set<string>;
  sessionsScanned: number;
}> {
  const keys = await listRecentArchiveKeys(
    archiveBucket,
    ARCHIVE_LOOKBACK_HOURS,
  );
  const candidates = new Set<string>();
  const CONCURRENCY = 16;
  let sessionsScanned = 0;
  for (let i = 0; i < keys.length; i += CONCURRENCY) {
    sessionsScanned += await fetchSessionBatch(
      archiveBucket,
      keys.slice(i, i + CONCURRENCY),
      candidates,
    );
  }
  return { keys, candidates, sessionsScanned };
}

export async function handler(): Promise<DiscoverResult> {
  const archiveBucket = process.env.INTEGRITY_ARCHIVE_BUCKET;
  const overlayBucket = process.env.IP_CLASS_BUCKET;
  const overlayKey =
    process.env.IP_CLASS_AUTO_OVERLAY_KEY ?? "auto-overlay.json.gz";
  if (!archiveBucket)
    throw new Error("INTEGRITY_ARCHIVE_BUCKET env var required");
  if (!overlayBucket) throw new Error("IP_CLASS_BUCKET env var required");

  const existingRules = await loadExistingOverlay(overlayBucket, overlayKey);
  const existingRanges = compileForLookup(existingRules);
  const { candidates, sessionsScanned } =
    await collectCandidateIps(archiveBucket);
  const ips = [...candidates];
  const stats = await walkCandidateIps(ips, existingRanges);
  const merged = dedupe([...existingRules, ...stats.newRules]);
  await writeOverlay(overlayBucket, overlayKey, merged);

  return {
    archive_sessions_scanned: sessionsScanned,
    ips_walked: ips.length,
    ips_skipped_existing: stats.skipped,
    rdap_ip_lookups: stats.rdapCalls,
    rdap_name_searches: stats.nameSearches,
    new_rules: stats.newRules.length,
    total_rules: merged.length,
  };
}
