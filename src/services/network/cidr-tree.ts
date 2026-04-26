/**
 * Shared CIDR helpers — sorted-array binary search over uint32 IP ranges.
 *
 * Used by:
 *   - cidr-overlay.ts (hand-curated rules, ~30 entries)
 *   - auto-overlay.ts (S3-loaded auto-discovered rules, ~thousands of entries)
 *
 * The structure is a list of CompiledRange (start, end) tuples sorted by
 * start. Lookup is O(log n) binary search. After build the list is frozen.
 *
 * `>>> 0` is required on every bitwise op to surface JS int32 results as
 * unsigned uint32 — without it, high IPs (>2^31) become negative and break
 * the sort/comparison invariants. Verified by 174.193.0.1 regression test.
 */

import type { NetworkCategory } from "./categorize";

export interface CompiledRange<T = unknown> {
  start: number; // inclusive uint32
  end: number; // inclusive uint32
  category: NetworkCategory;
  /** Free-form metadata (sub-allocation name, RIR source, etc.) */
  meta?: T;
}

export function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return NaN;
  return (
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  );
}

export function intToIp(n: number): string {
  return `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
}

/** Convert a CIDR string like "107.64.0.0/10" to an inclusive uint32 range. */
export function cidrToRange(cidr: string): [number, number] | null {
  const slash = cidr.indexOf("/");
  if (slash < 0) return null;
  const ip = cidr.slice(0, slash);
  const prefix = Number(cidr.slice(slash + 1));
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  const ipInt = ipToInt(ip);
  if (!Number.isFinite(ipInt)) return null;
  const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0) >>> 0;
  const start = (ipInt & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return [start, end];
}

/**
 * Binary search a sorted CompiledRange[] for the entry containing `ip`.
 * Returns null if no range covers it.
 *
 * Pre-condition: ranges must be sorted by `start` ascending.
 */
export function lookupInRanges<T>(
  ranges: readonly CompiledRange<T>[],
  ip: string,
): CompiledRange<T> | null {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return null;
  const ipInt = ipToInt(ip);
  if (!Number.isFinite(ipInt)) return null;

  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (ranges[mid].start > ipInt) hi = mid - 1;
    else if (ranges[mid].end < ipInt) lo = mid + 1;
    else return ranges[mid];
  }
  // After the loop, lo points one past the last range with start <= ipInt.
  // Re-check the predecessor — it may contain ipInt even though we didn't
  // hit it via the equality branches above (this can happen with overlapping
  // ranges or a duplicate start key).
  if (lo > 0 && ranges[lo - 1].end >= ipInt && ranges[lo - 1].start <= ipInt) {
    return ranges[lo - 1];
  }
  return null;
}

interface RawEntry<T> {
  cidr: string;
  category: NetworkCategory;
  meta?: T;
}

/**
 * Compile a list of (cidr, category, meta) tuples into a sorted, frozen
 * CompiledRange[] ready for binary-search lookup. Drops malformed CIDRs.
 */
export function compileCidrList<T>(
  entries: readonly RawEntry<T>[],
): readonly CompiledRange<T>[] {
  const out: CompiledRange<T>[] = [];
  for (const e of entries) {
    const range = cidrToRange(e.cidr);
    if (!range) continue;
    out.push({
      start: range[0],
      end: range[1],
      category: e.category,
      meta: e.meta,
    });
  }
  out.sort((a, b) => a.start - b.start);
  return Object.freeze(out);
}
