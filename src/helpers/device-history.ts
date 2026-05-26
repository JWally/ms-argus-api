/**
 * Server-managed, client-carried device history blob.
 *
 * Closes the "useful trust signal" half of ARGUS_URGENT_FIXES #5 (the
 * other half — sig replay across payloads — was closed in Phase 1,
 * commit e0b9411). Phase 2 makes device_identity actually load-bearing
 * by accumulating observed history per pubkey: timestamp, server-seen
 * IP, cpi, session_id, UA cluster, network class. The client carries
 * the encrypted blob in IndexedDB; the server is the only party who can
 * decrypt or modify it.
 *
 * Why this design:
 *   - Server state stays zero — no DDB per-pubkey table to manage
 *   - Verification is one AES-GCM-decrypt per request — no DB lookup
 *   - Visits are server-observed (IP from requestContext, not
 *     client-claimed), so the blob accumulates trustworthy data
 *   - Bounded size — server prunes to MAX_VISITS on every update
 *   - Auth-tag failure is a fraud signal — only way for the client to
 *     present a corrupt blob is to have tampered with it
 *
 * Wire format (per blob):
 *   base64( iv[12] || aes-gcm-ciphertext || authTag[16] )
 *
 * Plaintext (JSON, then deflateRaw, then AES-256-GCM):
 *   { v: 1, id: "<spki-pubkey-b64>", created: <unix_ms>,
 *     updated: <unix_ms>,
 *     visits: [
 *       { t, ip, cpi, session, ua_hash?, net_class?, country? },
 *       ...
 *     ]
 *   }
 *
 * AES key: derived from SIGINT_AES_KEY via HKDF-SHA256 with a distinct
 * info string ("argus-device-history-v1"). No new Secrets Manager
 * entry; we reuse the existing shared sigint key as the root.
 */

import {
  createDecipheriv,
  createCipheriv,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";

/** Plaintext shape stored inside the encrypted blob. */
export interface DeviceHistoryBlob {
  v: 1;
  id: string;
  created: number;
  updated: number;
  visits: DeviceHistoryVisit[];
}

export interface DeviceHistoryVisit {
  /** Server-observed timestamp at submission processing time (unix ms). */
  t: number;
  /** Server-observed source IP from requestContext.http.sourceIp. */
  ip: string;
  /** Merchant cpi for this submission. */
  cpi: string;
  /** Per-submission session_id. */
  session: string;
  /** First 16 hex chars of SHA-256(user-agent). null when UA absent. */
  ua_hash?: string | null;
  /** Network classification (residential / mobile / datacenter / shielded / unknown). */
  net_class?: string | null;
  /** ISO 3166-1 alpha-2 country, when the CF probe authentically attested it. */
  country?: string | null;
}

/** Visit fields the server has at integrity-collect processing time. */
export interface PendingVisit {
  cpi: string;
  session: string;
  ip: string;
  ua_hash: string | null;
  net_class: string | null;
  country: string | null;
}

/** Bounded blob size — oldest visit pruned when the array exceeds this. */
export const DEVICE_HISTORY_MAX_VISITS = 50;

/** HKDF info string. Distinct from any other usage of SIGINT_AES_KEY. */
const HKDF_INFO = new TextEncoder().encode("argus-device-history-v1");

/** Decryption result discriminator. */
export type DecryptOutcome =
  | { kind: "ok"; blob: DeviceHistoryBlob }
  | { kind: "absent" }
  | { kind: "auth_fail"; reason: string };

function deriveAesKey(sigintAesKeyHex: string): Buffer {
  // Use the first 32 bytes (64 hex chars) of SIGINT_AES_KEY as ikm. HKDF
  // expands to a fresh 32-byte AES-256 key, isolated by the info string
  // from any other usage of SIGINT_AES_KEY.
  const ikm = Buffer.from(sigintAesKeyHex.slice(0, 64), "hex");
  return Buffer.from(hkdfSync("sha256", ikm, Buffer.alloc(0), HKDF_INFO, 32));
}

/**
 * Encrypt a blob plaintext into the wire format.
 * Returns base64(iv || ciphertext || tag).
 */
export function encryptDeviceHistory(
  blob: DeviceHistoryBlob,
  sigintAesKeyHex: string,
): string {
  const key = deriveAesKey(sigintAesKeyHex);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const json = JSON.stringify(blob);
  const deflated = deflateRawSync(Buffer.from(json, "utf-8"));
  const ciphertext = Buffer.concat([cipher.update(deflated), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString("base64");
}

/**
 * Decrypt a wire blob. Returns `kind: "auth_fail"` on any failure —
 * caller decides whether to treat as fresh start or as a tampering
 * signal based on context.
 */
export function decryptDeviceHistory(
  wireB64: string | undefined | null,
  sigintAesKeyHex: string,
): DecryptOutcome {
  if (!wireB64 || typeof wireB64 !== "string" || wireB64.length === 0) {
    return { kind: "absent" };
  }
  let buf: Buffer;
  try {
    buf = Buffer.from(wireB64, "base64");
  } catch {
    return { kind: "auth_fail", reason: "bad_base64" };
  }
  if (buf.length < 12 + 16 + 1) {
    return { kind: "auth_fail", reason: "short" };
  }
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ciphertext = buf.subarray(12, buf.length - 16);
  const key = deriveAesKey(sigintAesKeyHex);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const deflated = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    const json = inflateRawSync(deflated).toString("utf-8");
    const parsed = JSON.parse(json) as DeviceHistoryBlob;
    if (!isValidBlob(parsed)) {
      return { kind: "auth_fail", reason: "shape" };
    }
    return { kind: "ok", blob: parsed };
  } catch (err) {
    const msg = (err as Error).message ?? "unknown";
    return {
      kind: "auth_fail",
      reason: msg.includes("auth") ? "auth_tag" : "decode",
    };
  }
}

function isValidBlob(x: unknown): x is DeviceHistoryBlob {
  if (!x || typeof x !== "object") return false;
  const o = x as Record<string, unknown>;
  return (
    o.v === 1 &&
    typeof o.id === "string" &&
    typeof o.created === "number" &&
    typeof o.updated === "number" &&
    Array.isArray(o.visits)
  );
}

/**
 * Append a fresh visit to the blob and prune the oldest if we're at
 * the cap. Returns a NEW blob (does not mutate the input).
 *
 * `now` defaults to Date.now() — pass an explicit value for tests.
 */
export function appendVisit(
  blob: DeviceHistoryBlob,
  visit: PendingVisit,
  now: number = Date.now(),
): DeviceHistoryBlob {
  const fresh: DeviceHistoryVisit = {
    t: now,
    ip: visit.ip,
    cpi: visit.cpi,
    session: visit.session,
    ua_hash: visit.ua_hash,
    net_class: visit.net_class,
    country: visit.country,
  };
  const next = [...blob.visits, fresh];
  // Prune oldest entries if we exceed cap. Keep most-recent MAX.
  const trimmed =
    next.length > DEVICE_HISTORY_MAX_VISITS
      ? next.slice(next.length - DEVICE_HISTORY_MAX_VISITS)
      : next;
  return { ...blob, updated: now, visits: trimmed };
}

/**
 * Build a fresh blob for a first-time visitor. Server-issued — the
 * client did not have a blob (or presented one we couldn't decrypt and
 * are choosing to recover from).
 */
export function buildFreshBlob(
  pubkey: string,
  now: number = Date.now(),
): DeviceHistoryBlob {
  return { v: 1, id: pubkey, created: now, updated: now, visits: [] };
}

/**
 * Compute the SHA-256-derived `ua_hash` field. Returns null when the
 * UA header is absent or empty.
 */
export function hashUserAgent(ua: string | undefined | null): string | null {
  if (!ua || ua.length === 0) return null;
  // Lazy import to keep startup snappy.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  return createHash("sha256").update(ua, "utf-8").digest("hex").slice(0, 16);
}

/** Per-request orchestrator output for handleIntegrity. */
export interface ProcessDeviceHistoryResult {
  /** Outcome category, mirrors decryptDeviceHistory's discriminant. */
  outcomeKind: "ok" | "absent" | "auth_fail";
  /** Whether the incoming blob's id matched the current pubkey. */
  identityMatched: boolean;
  /** Encrypted blob to return in the API response (undefined when we
   *  can't process — missing key or missing pubkey). */
  outboundBlob: string | undefined;
  /** The decrypted-or-fresh blob's pre-current-visit state, for the
   *  analyzer to read recurrence signals from. */
  preVisitBlob: DeviceHistoryBlob | null;
}

/**
 * Drive the device-history round-trip for one integrity-collect
 * submission. Decrypts the incoming blob, validates pubkey binding,
 * computes recurrence signals from the pre-visit state, appends the
 * current visit, re-encrypts.
 *
 * Returns the encrypted outbound blob for the response AND the
 * pre-visit blob (so the analyzer can read history WITHOUT seeing the
 * current visit it's analyzing).
 *
 * If we can't process (no pubkey from device_identity, or no
 * SIGINT_AES_KEY env), returns outcomeKind=absent + outboundBlob
 * undefined — caller treats this as "feature disabled" and the
 * response simply doesn't include the blob field.
 */
export function processDeviceHistory(input: {
  incomingBlob: string | undefined | null;
  pubkey: string | null;
  sigintAesKey: string | undefined;
  visit: PendingVisit;
  now?: number;
}): ProcessDeviceHistoryResult {
  const { incomingBlob, pubkey, sigintAesKey, visit } = input;
  const now = input.now ?? Date.now();
  if (!pubkey || !sigintAesKey) {
    return {
      outcomeKind: "absent",
      identityMatched: false,
      outboundBlob: undefined,
      preVisitBlob: null,
    };
  }
  const outcome = decryptDeviceHistory(incomingBlob, sigintAesKey);
  // Pre-visit blob is the decrypted blob iff it's ours; otherwise a
  // fresh one bound to this pubkey. We pass the PRE-visit state to the
  // analyzer so the recurrence signals reflect history BEFORE this
  // submission.
  let preVisitBlob: DeviceHistoryBlob;
  let identityMatched = false;
  if (outcome.kind === "ok" && outcome.blob.id === pubkey) {
    preVisitBlob = outcome.blob;
    identityMatched = true;
  } else {
    // absent | auth_fail | identity-mismatch → fresh blob bound to
    // the current pubkey.
    preVisitBlob = buildFreshBlob(pubkey, now);
  }
  const updated = appendVisit(preVisitBlob, visit, now);
  const outboundBlob = encryptDeviceHistory(updated, sigintAesKey);
  return {
    outcomeKind: outcome.kind,
    identityMatched,
    outboundBlob,
    preVisitBlob,
  };
}
