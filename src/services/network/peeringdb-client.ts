/**
 * PeeringDB client.
 *
 * Bulk-pulls the `/api/net` endpoint (returns every registered network —
 * ~35k entries, ~40MB JSON, no auth). Used by the weekly ip-class-builder
 * Lambda as a cross-check on regex categorization:
 *
 *   - `info_type` is operator-self-declared (NSP / Content / Cable/DSL/ISP /
 *     Enterprise / Educational / Government / Non-Profit / Route Server /
 *     Network Services / Route Collector). When our regex says "datacenter"
 *     but PeeringDB says "Cable/DSL/ISP", that's a flag worth surfacing.
 *
 *   - `ix_count` is the number of IXes the operator self-reports being
 *     present at. Soft proxy-infrastructure signal: residential ISPs and
 *     small enterprises peer at 0-3 IXes; M247-style proxy backbones and
 *     content/transit operators peer at 30+.
 *
 * Failure mode: returns an empty map and emits a structured warning on any
 * fetch / parse error. The weekly build must not block on PeeringDB uptime
 * — the asn dict still ships, just without the cross-check column.
 */
const PEERINGDB_URL = "https://www.peeringdb.com/api/net";
const TIMEOUT_MS = 90_000;
const UA = "ms-argus-api ip-class-builder";

export interface PdbInfo {
  /** Operator-self-declared display name, with the trailing " - <asn>"
   *  suffix that PeeringDB sometimes appends stripped off. Examples:
   *  "AT&T US - 7018" → "AT&T US", "Comcast" → "Comcast", "M247 Global"
   *  → "M247 Global". Empty string when PeeringDB returned no name. */
  name: string;
  /** Operator-self-declared network type. Empty string is normal for ASNs
   *  that have a PeeringDB record but haven't filled in the type field. */
  info_type: string;
  /** Number of IXes the operator self-reports being present at. */
  ix_count: number;
}

interface PdbApiEntry {
  asn?: unknown;
  name?: unknown;
  info_type?: unknown;
  ix_count?: unknown;
}

/** PeeringDB names commonly end with " - <asn>" (e.g. "AT&T US - 7018").
 *  Strip that suffix only — conservative anchor on the exact ASN keeps us
 *  from accidentally chopping legitimate trailing numbers in other names. */
function stripAsnSuffix(name: string, asn: number): string {
  const suffix = ` - ${asn}`;
  return name.endsWith(suffix) ? name.slice(0, -suffix.length).trim() : name;
}

interface PdbApiResponse {
  data?: PdbApiEntry[];
}

function coerceAsn(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return v;
  return null;
}

function coerceString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function coerceCount(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
}

function parseEntries(entries: PdbApiEntry[]): Map<number, PdbInfo> {
  const out = new Map<number, PdbInfo>();
  for (const e of entries) {
    const asn = coerceAsn(e.asn);
    if (asn === null) continue;
    const info_type = coerceString(e.info_type);
    const ix_count = coerceCount(e.ix_count);
    const rawName = coerceString(e.name);
    const name = rawName ? stripAsnSuffix(rawName, asn) : "";
    // Skip entries that carry no useful signal (no name AND no type AND no
    // IX presence). Most empty entries are stub records for ASNs that
    // registered an account but never filled in metadata.
    if (name === "" && info_type === "" && ix_count === 0) continue;
    out.set(asn, { name, info_type, ix_count });
  }
  return out;
}

/**
 * Fetch the full PeeringDB net table. Returns an ASN → {info_type, ix_count}
 * map. On any failure (network, HTTP, JSON parse), returns an empty map and
 * logs a structured warning — the caller treats absence as "no PeeringDB
 * data for this ASN" rather than failing the build.
 */
export async function fetchPeeringDbTypes(): Promise<Map<number, PdbInfo>> {
  try {
    const res = await fetch(PEERINGDB_URL, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: {
        Accept: "application/json",
        "User-Agent": UA,
      },
    });
    if (!res.ok) {
      console.warn(
        JSON.stringify({
          msg: "peeringdb_fetch_failed",
          status: res.status,
          statusText: res.statusText,
        }),
      );
      return new Map();
    }
    const body = (await res.json()) as PdbApiResponse;
    if (!Array.isArray(body?.data)) {
      console.warn(JSON.stringify({ msg: "peeringdb_unexpected_shape" }));
      return new Map();
    }
    return parseEntries(body.data);
  } catch (e) {
    console.warn(
      JSON.stringify({
        msg: "peeringdb_fetch_error",
        error: String((e as Error).message ?? e).slice(0, 200),
      }),
    );
    return new Map();
  }
}
