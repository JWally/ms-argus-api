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
 * matching public key from SSM and cache it for 5 minutes.
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

// Bounded timeouts: the 5-min key cache refetches on the first request after
// an idle gap, when the keep-alive socket is most likely dead (see
// sdk-http-handler.ts) — fail fast and retry instead of a ~7.5s blackhole.
const ssm = new SSMClient({ requestHandler: boundedRequestHandler });

let cachedKey: KeyObject | null = null;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000;

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

async function loadPublicKey(ssmPath: string): Promise<KeyObject> {
  const now = Date.now();
  if (cachedKey && now < cacheExpiry) return cachedKey;
  const r = await ssm.send(new GetParameterCommand({ Name: ssmPath }));
  const pem = r.Parameter?.Value;
  if (!pem) throw new Error(`signing pubkey not found at ${ssmPath}`);
  cachedKey = createPublicKey({ key: pem, format: "pem" });
  cacheExpiry = now + CACHE_TTL_MS;
  return cachedKey;
}

function base64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

export const __testing__ = {
  resetCache(): void {
    cachedKey = null;
    cacheExpiry = 0;
  },
};
