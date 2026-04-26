/**
 * RDAP client — IP-lookup + name-search across the 5 RIRs.
 *
 * IP-lookup: ARIN's bootstrap server auto-redirects to the right RIR
 *   (RIPE / APNIC / LACNIC / AFRINIC) based on the IP's region. urllib /
 *   fetch follows the redirect transparently, so we just hit ARIN.
 *
 * Name-search: each RIR exposes its own /networks?name= endpoint. ARIN's
 *   support is the cleanest (verified empirically); RIPE works similarly;
 *   APNIC / LACNIC / AFRINIC have varying coverage. We try each in turn and
 *   merge results — partial coverage is fine because the discoverer's
 *   per-IP fallback always picks up what the name-search misses.
 *
 * No auth required for any of these endpoints. RIR rate-limits are
 * generous (~1-2 req/sec polite); we sleep ~400ms between calls in the
 * caller.
 */

const UA = "ms-argus-api/discoverer";
const TIMEOUT_MS = 15_000;

export interface RdapIpInfo {
  /** Sub-allocation handle from RDAP, e.g. "ATT-MOBILITY-LLC" */
  name: string;
  /** CIDRs covering this IP (usually one, sometimes two for combined ranges) */
  cidrs: string[];
  /** Legal entity org name (vCard fn) — useful when `name` is a numeric handle */
  org: string;
  /** Nameserver hostnames — sometimes the only branding signal (e.g. LACNIC BR) */
  nameservers: string[];
  /** Country code from RDAP, e.g. "US", "DE" */
  country: string | null;
  /** Which RIR served the response (after redirects) */
  rir: string;
}

export interface RdapNetworkRef {
  name: string;
  cidrs: string[];
}

const RIR_NAME_SEARCH_BASES: ReadonlyArray<{ rir: string; url: string }> = [
  { rir: "arin", url: "https://rdap.arin.net/registry/networks?name=" },
  { rir: "ripe", url: "https://rdap.db.ripe.net/ips?name=" },
  { rir: "apnic", url: "https://rdap.apnic.net/networks?name=" },
  { rir: "lacnic", url: "https://rdap.lacnic.net/rdap/networks?name=" },
  { rir: "afrinic", url: "https://rdap.afrinic.net/rdap/networks?name=" },
];

async function rdapFetch(url: string): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: {
        Accept: "application/rdap+json,application/json",
        "User-Agent": UA,
      },
      redirect: "follow",
    });
    if (!res.ok) {
      // 404 means the resource doesn't exist (not an error worth retrying)
      if (res.status === 404) return null;
      return { _error: `HTTP ${res.status}` };
    }
    return await res.json();
  } catch (e) {
    return { _error: String((e as Error).message ?? e).slice(0, 80) };
  }
}

function isError(d: unknown): d is { _error: string } {
  return (
    !!d &&
    typeof d === "object" &&
    "_error" in (d as Record<string, unknown>) &&
    typeof (d as Record<string, unknown>)._error === "string"
  );
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, unknown[]];
}

function vcardFn(entity: RdapEntity): string | null {
  const vcard = (
    entity.vcardArray as unknown as [string, [string, ...unknown[]][]]
  )?.[1];
  if (!Array.isArray(vcard)) return null;
  const fn = vcard.find(
    (e) => Array.isArray(e) && e[0] === "fn" && typeof e[3] === "string",
  );
  return fn ? (fn[3] as string) : null;
}

function extractEntityOrg(entities: RdapEntity[] | undefined): string {
  if (!Array.isArray(entities)) return "";
  for (const e of entities) {
    if (!Array.isArray(e?.roles) || !e.roles.includes("registrant")) continue;
    const fn = vcardFn(e);
    if (fn) return fn;
  }
  return "";
}

interface NicbrReverseDelegation {
  nameservers?: { ldhName?: string }[];
}

function pushLdhNames(
  nameservers: { ldhName?: string }[] | undefined,
  out: string[],
): void {
  if (!Array.isArray(nameservers)) return;
  for (const ns of nameservers) {
    if (ns?.ldhName) out.push(ns.ldhName);
  }
}

function extractNameservers(d: Record<string, unknown>): string[] {
  const out: string[] = [];
  pushLdhNames(d.nameservers as { ldhName?: string }[] | undefined, out);
  // BR's nic.br RDAP returns nameservers under a custom key
  const nicbr = d.nicbr_reverseDelegations as
    | NicbrReverseDelegation[]
    | undefined;
  if (Array.isArray(nicbr)) {
    for (const rd of nicbr) pushLdhNames(rd.nameservers, out);
  }
  return out;
}

function extractCidrs(d: Record<string, unknown>): string[] {
  const out: string[] = [];
  const cidr0 = d.cidr0_cidrs as
    | { v4prefix?: string; length?: number | string }[]
    | undefined;
  if (Array.isArray(cidr0)) {
    for (const c of cidr0) {
      if (c?.v4prefix && c.length !== undefined && c.length !== null) {
        out.push(`${c.v4prefix}/${c.length}`);
      }
    }
  }
  return out;
}

function detectRir(linkOrUrl: string): string {
  if (linkOrUrl.includes("rdap.arin.net")) return "arin";
  if (linkOrUrl.includes("rdap.db.ripe.net")) return "ripe";
  if (linkOrUrl.includes("rdap.apnic.net")) return "apnic";
  if (
    linkOrUrl.includes("rdap.lacnic.net") ||
    linkOrUrl.includes("registro.br")
  )
    return "lacnic";
  if (linkOrUrl.includes("rdap.afrinic.net")) return "afrinic";
  return "unknown";
}

function detectRirFromLinks(d: Record<string, unknown>): string {
  const links = d.links as { href?: string; rel?: string }[] | undefined;
  if (!Array.isArray(links)) return "arin";
  const self = links.find((l) => l?.rel === "self");
  return self?.href ? detectRir(self.href) : "arin";
}

/**
 * IP-lookup. Hits ARIN's bootstrap server which auto-redirects to the
 * correct RIR for the IP's region. Returns null on 404 / fetch failure.
 */
export async function rdapIpLookup(ip: string): Promise<RdapIpInfo | null> {
  const d = await rdapFetch(`https://rdap.arin.net/registry/ip/${ip}`);
  if (!d || isError(d)) return null;
  const obj = d as Record<string, unknown>;
  const cidrs = extractCidrs(obj);
  // Some RIRs return only startAddress/endAddress; skip those entirely
  // since the discoverer needs a valid CIDR to write a rule.
  if (cidrs.length === 0) return null;
  return {
    name: typeof obj.name === "string" ? obj.name : "",
    cidrs,
    org: extractEntityOrg(obj.entities as RdapEntity[] | undefined),
    nameservers: extractNameservers(obj),
    country: typeof obj.country === "string" ? obj.country : null,
    rir: detectRirFromLinks(obj),
  };
}

function readSearchResults(
  d: Record<string, unknown>,
): Record<string, unknown>[] {
  return (
    (d.networkSearchResults as Record<string, unknown>[] | undefined) ??
    (d.ipSearchResults as Record<string, unknown>[] | undefined) ??
    []
  );
}

function mergeSearchResultsInto(
  d: Record<string, unknown>,
  seen: Map<string, RdapNetworkRef>,
): void {
  for (const n of readSearchResults(d)) {
    const cidrs = extractCidrs(n);
    if (cidrs.length === 0) continue;
    const name = typeof n.name === "string" ? n.name : "";
    const key = `${name}|${cidrs[0]}`;
    if (!seen.has(key)) seen.set(key, { name, cidrs });
  }
}

/**
 * Name-search across all 5 RIRs. Returns a deduplicated list of networks
 * matching the wildcard pattern (e.g. "ATT-MOBILITY*" → 20 networks at ARIN).
 *
 * `pattern` is the search prefix WITHOUT the trailing asterisk — this
 * function appends it. Pattern must be at least 4 characters to keep
 * results sensible (RIRs typically reject overly broad searches).
 */
export async function rdapNameSearch(
  pattern: string,
): Promise<RdapNetworkRef[]> {
  if (!pattern || pattern.length < 4) return [];
  const seen = new Map<string, RdapNetworkRef>();
  const encoded = encodeURIComponent(pattern) + "*";

  await Promise.all(
    RIR_NAME_SEARCH_BASES.map(async (rir) => {
      const d = await rdapFetch(rir.url + encoded);
      if (!d || isError(d)) return;
      mergeSearchResultsInto(d as Record<string, unknown>, seen);
    }),
  );

  return [...seen.values()];
}

/**
 * Strip trailing `-N-N-N-N` IP-like suffixes from an RDAP `name` so we can
 * use it as a search pattern. ARIN often returns child-network names like
 * `ATT-MOBILITY-LLC-135-157-0-0`; the parent search needs `ATT-MOBILITY-LLC`.
 */
const NAME_TAIL_RE = /(-\d+){2,}$/;
export function simplifyRdapName(name: string): string {
  return name.replace(NAME_TAIL_RE, "");
}
