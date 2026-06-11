/**
 * @fileoverview Verifier for merchant API tokens issued by ms-argus-platform.
 *
 * The merchant ships ONE credential string of the form `<keyId>.<token>`,
 * where `<token>` is `<base64url-claims>.<base64url-signature>` (Ed25519
 * over the encoded claims). The merchant SDK splits at the first `.` and
 * sends two headers:
 *
 *   x-api-key:     <keyId>           — matched natively by APIGW Keys
 *   x-argus-token: <token>           — verified here in the handler
 *
 * Two headers because APIGW does an exact match on `x-api-key` against its
 * key store; the keyId alone has to live there. The signed claims ride in
 * a separate header. The verifier asserts `claims.keyId === keyIdHeader`
 * so a stolen token can't be paired with a different gateway key.
 *
 * The platform signs with its private key (Secrets Manager); we fetch the
 * matching public key from SSM and cache it in-process. The cache is
 * stale-while-revalidate (see loadPublicKey): once any key is cached, no
 * request ever blocks on SSM again — a stale key is served immediately and
 * refreshed in the background. The platform's Ed25519 key rotates rarely,
 * so a 1h TTL plus SWR keeps the ~230ms SSM read off the user path entirely
 * (it was the dominant warm-path cost on session-get; DDB + projection are
 * tens of ms). Eager fetch at module load is deliberately avoided — a PC
 * container can freeze mid-init and the signed request expires (see
 * sdk-http-handler.ts).
 *
 * @module helpers/token-verifier
 */

import {
  createPublicKey,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { boundedRequestHandler } from "./sdk-http-handler";

// Bounded timeouts: the background key refresh can fire after an idle gap,
// when the keep-alive socket is most likely dead (see sdk-http-handler.ts) —
// fail fast and retry next request instead of a ~7.5s blackhole.
const ssm = new SSMClient({ requestHandler: boundedRequestHandler });

let cachedKey: KeyObject | null = null;
let cacheExpiry = 0;
let refreshInFlight: Promise<unknown> | null = null;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1h — pubkey rotates rarely

export interface VerifiedClaims {
  merchantId: string;
  cpi: string;
  keyId: string;
  plan: string;
  iat: number;
}

export interface VerifierOptions {
  /** SSM path to the platform's Ed25519 SPKI PEM public key. */
  ssmPubkeyPath: string;
  /** When provided, the verifier asserts `claims.cpi === expectedCpi`. */
  expectedCpi?: string;
}

interface ParsedToken {
  encodedClaims: string;
  encodedSig: string;
  claims: VerifiedClaims;
}

function parseToken(tokenHeader: string): ParsedToken | null {
  const parts = tokenHeader.split(".");
  if (parts.length !== 2) return null;
  const [encodedClaims, encodedSig] = parts;
  if (!encodedClaims || !encodedSig) return null;
  let claims: VerifiedClaims;
  try {
    claims = JSON.parse(base64urlDecode(encodedClaims).toString("utf8"));
  } catch {
    return null;
  }
  if (!isClaimsShape(claims)) return null;
  return { encodedClaims, encodedSig, claims };
}

function isClaimsShape(c: unknown): c is VerifiedClaims {
  if (!c || typeof c !== "object") return false;
  const o = c as Record<string, unknown>;
  return (
    typeof o.merchantId === "string" &&
    typeof o.cpi === "string" &&
    typeof o.keyId === "string" &&
    typeof o.plan === "string" &&
    typeof o.iat === "number"
  );
}

export async function verifyMerchantToken(
  keyIdHeader: string | undefined,
  tokenHeader: string | undefined,
  opts: VerifierOptions,
): Promise<VerifiedClaims | null> {
  if (!keyIdHeader || !tokenHeader) return null;
  const parsed = parseToken(tokenHeader);
  if (!parsed) return null;
  if (parsed.claims.keyId !== keyIdHeader) return null;
  if (opts.expectedCpi && parsed.claims.cpi !== opts.expectedCpi) return null;

  const pubkey = await loadPublicKey(opts.ssmPubkeyPath);
  const ok = cryptoVerify(
    null,
    Buffer.from(parsed.encodedClaims, "utf8"),
    pubkey,
    base64urlDecode(parsed.encodedSig),
  );
  return ok ? parsed.claims : null;
}

async function fetchAndCacheKey(ssmPath: string): Promise<KeyObject> {
  const r = await ssm.send(new GetParameterCommand({ Name: ssmPath }));
  const pem = r.Parameter?.Value;
  if (!pem) throw new Error(`signing pubkey not found at ${ssmPath}`);
  cachedKey = createPublicKey({ key: pem, format: "pem" });
  cacheExpiry = Date.now() + CACHE_TTL_MS;
  return cachedKey;
}

/**
 * Stale-while-revalidate. First call per container awaits the SSM read; every
 * call thereafter returns the cached key immediately. When the key goes stale,
 * a single background refresh is kicked off (deduped via refreshInFlight) and
 * the stale key is served meanwhile — so the ~230ms SSM read never lands on a
 * request once the container is primed. A failed refresh keeps the stale key
 * and retries on the next request.
 */
async function loadPublicKey(ssmPath: string): Promise<KeyObject> {
  if (cachedKey) {
    if (Date.now() >= cacheExpiry && !refreshInFlight) {
      refreshInFlight = fetchAndCacheKey(ssmPath)
        .catch(() => {}) // keep serving stale; retry next request
        .finally(() => {
          refreshInFlight = null;
        });
    }
    return cachedKey;
  }
  return fetchAndCacheKey(ssmPath);
}

/**
 * Prime the in-process pubkey cache. Called during container init (see
 * session-get's init-prime) so the first real request never pays the SSM
 * read. Safe to call repeatedly — it's just loadPublicKey without a verify.
 */
export async function primePublicKey(ssmPath: string): Promise<void> {
  await loadPublicKey(ssmPath);
}

function base64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

export const __testing__ = {
  resetCache(): void {
    cachedKey = null;
    cacheExpiry = 0;
    refreshInFlight = null;
  },
};
