/**
 * Fetch + cache the issuer's token-issuer-directory (RFC 9578 §6.2).
 *
 * Loose-coupling contract: the only outward-facing function is
 * `getActiveTokenKey()`. Callers receive a key bytes Buffer or null.
 * Failures never throw — null means "best-effort signal unavailable".
 *
 *   getActiveTokenKey()
 *     ├─ cache fresh?    → return cached key
 *     ├─ cache stale?    → trigger background refresh, return cached key (SWR)
 *     ├─ cache missing?  → live fetch, populate cache, return key
 *     └─ live fetch fails AND no cache? → return null (caller serves 503)
 *
 * This file owns the only network call in the PAT subsystem.
 */
import type { Logger } from "@aws-lambda-powertools/logger";

import { ISSUER_CONFIG } from "./issuer-config";

// Hyphenated field names from the IETF directory schema (RFC 9578 §6.2).
const KEY_TYPE = "token-type";
const KEY_KEY = "token-key";
const KEY_KEYS = "token-keys";
const KEY_NOT_BEFORE = "not-before";

interface RawDirectoryKey {
  [KEY_TYPE]: number;
  [KEY_KEY]: string;
  [KEY_NOT_BEFORE]?: number;
}

interface RawDirectory {
  "issuer-request-uri"?: string;
  [KEY_KEYS]: RawDirectoryKey[];
}

interface CachedKey {
  /** Issuer SPKI public key, raw DER bytes — the input to verify.ts. */
  spkiDer: Buffer;
  /** When the upstream directory said this key becomes valid (epoch s). */
  notBefore: number;
  /** When we fetched it; expiry = fetchedAt + cacheSeconds. */
  fetchedAt: number;
}

let cache: CachedKey | null = null;
let inflight: Promise<CachedKey | null> | null = null;

const FETCH_TIMEOUT_MS = 3_000;

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function isFresh(c: CachedKey): boolean {
  return nowSec() - c.fetchedAt < ISSUER_CONFIG.directoryCacheSeconds;
}

/** Decode a base64url string to a Buffer. RFC 9578 token-key field is base64url. */
function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64");
}

/**
 * Pick the active key from a directory: the most recent token-key whose
 * not-before <= now AND whose token-type matches our config. Ignores keys
 * with future not-before (rotation lookahead). Ignores wrong token-types.
 */
function pickActiveKey(
  dir: RawDirectory,
  expectedType: number,
  now: number,
): RawDirectoryKey | null {
  const candidates = dir[KEY_KEYS].filter((k) => k[KEY_TYPE] === expectedType)
    .filter((k) => (k[KEY_NOT_BEFORE] ?? 0) <= now)
    .sort((a, b) => (b[KEY_NOT_BEFORE] ?? 0) - (a[KEY_NOT_BEFORE] ?? 0));
  return candidates[0] ?? null;
}

async function fetchDirectory(logger?: Logger): Promise<CachedKey | null> {
  const url = `https://${ISSUER_CONFIG.host}${ISSUER_CONFIG.directoryPath}`;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctl.signal });
    if (!res.ok) {
      logger?.warn("PAT issuer directory non-2xx", {
        url,
        status: res.status,
      });
      return null;
    }
    const body = (await res.json()) as RawDirectory;
    const active = pickActiveKey(
      body,
      ISSUER_CONFIG.expectedTokenType,
      nowSec(),
    );
    if (!active) {
      logger?.warn("PAT issuer directory has no active key", { url });
      return null;
    }
    return {
      spkiDer: b64urlDecode(active[KEY_KEY]),
      notBefore: active[KEY_NOT_BEFORE] ?? 0,
      fetchedAt: nowSec(),
    };
  } catch (err) {
    logger?.warn("PAT issuer directory fetch failed", {
      url,
      err: err instanceof Error ? err.message : String(err),
    });
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Get the active issuer key. Implements SWR: returns cached on stale,
 * triggers background refresh; only blocks on a live fetch when cache
 * is empty.
 */
export async function getActiveTokenKey(
  logger?: Logger,
): Promise<CachedKey | null> {
  if (cache && isFresh(cache)) return cache;

  if (cache && !isFresh(cache)) {
    if (!inflight) {
      inflight = fetchDirectory(logger).then((next) => {
        if (next) cache = next;
        inflight = null;
        return next;
      });
    }
    return cache;
  }

  if (!inflight) {
    inflight = fetchDirectory(logger).then((next) => {
      if (next) cache = next;
      inflight = null;
      return next;
    });
  }
  return inflight;
}

/** Test-only hook: reset module state. Not exported via index. */
export function __resetCacheForTesting(): void {
  cache = null;
  inflight = null;
}
