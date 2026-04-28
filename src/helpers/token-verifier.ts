/**
 * @fileoverview Verifier for merchant API tokens issued by ms-argus-platform.
 *
 * Token format: `<base64url-claims>.<base64url-signature>` (Ed25519 over the
 * encoded claims). The platform signs with its private key (Secrets Manager);
 * we fetch the matching public key from SSM and cache it for 5 minutes.
 *
 * Verification covers signature integrity and (when called with `expectedCpi`)
 * binding between the token's `cpi` claim and the path's cpi — so a token
 * minted for store-A cannot be used to read store-B's sessions.
 *
 * @module helpers/token-verifier
 */

import {
  createPublicKey,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const ssm = new SSMClient({});

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
  keyIdPrefix: string;
  encodedClaims: string;
  encodedSig: string;
  claims: VerifiedClaims;
}

function parseToken(authHeader: string): ParsedToken | null {
  const parts = authHeader.split(".");
  if (parts.length !== 3) return null;
  const [keyIdPrefix, encodedClaims, encodedSig] = parts;
  if (!keyIdPrefix || !encodedClaims || !encodedSig) return null;
  let claims: VerifiedClaims;
  try {
    claims = JSON.parse(base64urlDecode(encodedClaims).toString("utf8"));
  } catch {
    return null;
  }
  if (!isClaimsShape(claims)) return null;
  return { keyIdPrefix, encodedClaims, encodedSig, claims };
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
  authHeader: string | undefined,
  opts: VerifierOptions,
): Promise<VerifiedClaims | null> {
  if (!authHeader) return null;
  // The merchant SDK joins the APIGW key id and the signed claims with a `.`
  // (the `.` is invalid in APIGW key values, so it's an unambiguous separator).
  // Layout: <keyId>.<base64-claims>.<base64-sig>
  const parsed = parseToken(authHeader);
  if (!parsed) return null;
  if (opts.expectedCpi && parsed.claims.cpi !== opts.expectedCpi) return null;
  if (parsed.keyIdPrefix !== parsed.claims.keyId) return null;

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
