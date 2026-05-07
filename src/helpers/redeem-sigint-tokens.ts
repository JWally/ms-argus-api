/**
 * Sigint token redemption helper.
 *
 * Verifies HMAC-signed tokens produced by ms-argus-sigint probes, fetches the
 * full probe data from PROBE_TOKENS_TABLE (owned by ms-argus-platform), and
 * hydrates payload.sigint with real TCP / H2 / TLS data before matching runs.
 */

import { createHmac, timingSafeEqual } from "crypto";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { ArgusPayload, PayloadPat } from "./payload-schema";
import {
  verifyCfToken,
  verifyCfCookie,
  type CfTokenFields,
} from "./verify-cf-token";

/**
 * Type guard for PAT fingerprint blobs persisted by the pat-attest Lambda.
 * Loose-coupling: this is the ONLY ingestion-side knowledge of the PAT
 * fingerprint shape — keeping it inline so the field can be deleted by
 * removing the type guard plus its caller below.
 */
function isPatFingerprint(x: unknown): x is PayloadPat & { type: "pat" } {
  if (!x || typeof x !== "object") return false;
  const r = x as Record<string, unknown>;
  return (
    r.type === "pat" &&
    r.attested === true &&
    typeof r.issuer === "string" &&
    typeof r.tokenHash === "string" &&
    typeof r.redeemedAt === "number"
  );
}

/**
 * Check only the expiry portion of a token (fast path, no key needed).
 *
 * Token format: `{nonce_hex}.{expiry_ms}.{hmac_hex}`
 */
function checkTokenExpiry(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const expiry = parseInt(parts[1], 10);
  return Number.isFinite(expiry) && Date.now() <= expiry;
}

/**
 * Verify the HMAC of a sigint probe token, given the client IP from DynamoDB.
 *
 * Go probes sign over `{nonce}.{expiry_ms}.{clientIP}` (not just nonce.expiry).
 * The clientIP is stored alongside the fingerprint in PROBE_TOKENS_TABLE and
 * must be fetched before this check can be performed.
 *
 * Token format: `{nonce_hex}.{expiry_ms}.{hmac_hex}`
 * HMAC-SHA256 over `{nonce}.{expiry_ms}.{clientIP}` using first 32 bytes of SIGINT_AES_KEY.
 *
 * @returns true if the HMAC is valid
 */
function verifyTokenHmac(
  token: string,
  sigintAesKeyHex: string,
  clientIp: string,
): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [nonce, expiryStr, hmac] = parts;

  const key = Buffer.from(sigintAesKeyHex, "hex").subarray(0, 32);
  const expected = createHmac("sha256", key)
    .update(`${nonce}.${expiryStr}.${clientIp}`)
    .digest("hex");
  try {
    return timingSafeEqual(
      Buffer.from(expected, "hex"),
      Buffer.from(hmac, "hex"),
    );
  } catch {
    return false;
  }
}

/**
 * Fetch the probe item stored in PROBE_TOKENS_TABLE for a given token.
 *
 * DynamoDB item schema: { token (PK), fingerprint (JSON string), client_ip, ttl }
 *
 * Returns both the parsed fingerprint and the client_ip, which is needed to
 * verify the HMAC (Go probes sign over nonce.expiry.clientIP).
 */
async function fetchProbeItem(
  token: string,
  tableName: string,
  dynamo: DynamoDBClient,
): Promise<{ fingerprint: unknown; clientIp: string } | null> {
  const result = await dynamo.send(
    new GetItemCommand({
      TableName: tableName,
      Key: { token: { S: token } },
    }),
  );
  if (!result.Item) return null;
  const item = unmarshall(result.Item);
  try {
    return {
      fingerprint: JSON.parse(item.fingerprint as string),
      clientIp: (item.client_ip as string) ?? "",
    };
  } catch {
    return null;
  }
}

interface RedeemCtx {
  sigintAesKeyHex: string;
  tableName: string;
  dynamo: DynamoDBClient;
  logger?: Logger;
}

/**
 * Extract a token string from an inline ProbeTokenResponse `{ token: "..." }`.
 *
 * The ms-argus-web library stores `ProbeTokenResponse` objects directly inside
 * `payload.sigint.tcp_probe` / `payload.sigint.h2` when the sigint probe
 * returns a token rather than raw data. This helper detects that shape so the
 * token can be redeemed even when no top-level `sigintTcpToken` field is set.
 */
export function extractInlineToken(probe: unknown): string | undefined {
  if (
    probe !== null &&
    typeof probe === "object" &&
    "token" in probe &&
    typeof (probe as Record<string, unknown>).token === "string" &&
    !("v" in probe) // exclude encrypted blobs { v: 1, data: "..." }
  ) {
    return (probe as Record<string, unknown>).token as string;
  }
  return undefined;
}

/**
 * Redeem sigint tokens and hydrate payload.sigint with full probe data.
 *
 * Handles three token types:
 * - sigintTls      → JSON.parse → payload.sigint.aws_cf (no DynamoDB, direct data)
 * - sigintTcpToken → expiry check → DynamoDB GetItem → HMAC verify → payload.sigint.tcp_probe
 * - sigintH2Token  → expiry check → DynamoDB GetItem → HMAC verify → payload.sigint.h2
 *
 * Also handles inline ProbeTokenResponse objects in payload.sigint.tcp_probe /
 * payload.sigint.h2 (set by ms-argus-web when probes return tokens).
 *
 * Non-fatal: if any step fails, the original payload is returned unchanged for that field.
 * Runs TCP and H2 lookups in parallel.
 *
 * Note on verification order: Go probes sign HMAC over `nonce.expiry.clientIP`, and
 * clientIP is stored in DynamoDB alongside the fingerprint. We fetch the DB item first
 * (after expiry check) to get clientIP, then verify the HMAC.
 */
async function redeemToken(
  token: string | undefined,
  ctx: RedeemCtx,
): Promise<unknown | null> {
  if (!token) return null;

  // Fast expiry check before touching DynamoDB
  if (!checkTokenExpiry(token)) {
    ctx.logger?.warn("Sigint token expired or malformed", {
      nonce: token.split(".")[0],
    });
    return null;
  }

  // Fetch item (includes client_ip needed for HMAC verification)
  const item = await fetchProbeItem(token, ctx.tableName, ctx.dynamo);
  if (!item) {
    ctx.logger?.warn("Sigint token not found in DynamoDB", {
      nonce: token.split(".")[0],
    });
    return null;
  }

  // Verify HMAC — Go signs over nonce.expiry.clientIP
  if (!verifyTokenHmac(token, ctx.sigintAesKeyHex, item.clientIp)) {
    ctx.logger?.warn("Sigint token HMAC verification failed", {
      nonce: token.split(".")[0],
      clientIp: item.clientIp,
    });
    return null;
  }

  return item.fingerprint;
}

/**
 * Resolve the effective token for a probe field.
 * Prefers the explicit top-level token; falls back to an inline ProbeTokenResponse.
 * If an inline token is used, clears the probe field so it isn't treated as real data.
 */
function resolveProbeToken(
  topLevelToken: string | undefined,
  probe: unknown,
  sigint: ArgusPayload["sigint"],
  field: "tcp_probe" | "h2",
): string | undefined {
  if (topLevelToken) return topLevelToken;
  const inlineToken = extractInlineToken(probe);
  if (inlineToken && sigint) sigint[field] = undefined;
  return inlineToken;
}

/**
 * Apply TLS JSON string to sigint in place.
 *
 * The client-side VM bridge wraps the TLS fetch in a SigintResult
 * envelope `{data, error, durationMs}` before JSON-encoding. Unwrap
 * `data` here so downstream consumers (analyzers, merchant API, dash
 * UIs) see a flat `aws_cf.{ip, asn, country, city, lat, lon, tz, ...}`
 * shape. Prior behavior left the wrapper intact, forcing every reader
 * to do `aws_cf.X || aws_cf.data.X` fallbacks — and new consumers that
 * didn't know about it (e.g., the BOT-BUSTER OBSERVED panel) silently
 * showed blanks for every field but ASN.
 *
 * Failed-fetch case (data=null, error=...) is preserved as-is so
 * operators can still see the error message in stored records.
 */
/** Extract the aws_cf record from either an unwrapped envelope or a flat payload. */
function unwrapTlsPayload(raw: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    if ("data" in parsed && parsed.data && typeof parsed.data === "object") {
      return { ...(parsed.data as Record<string, unknown>) };
    }
    return { ...(parsed as Record<string, unknown>) };
  } catch {
    return null;
  }
}

/** Stamp cookie verification flags on aws_cf. Absent cookie = cookieTampered. */
function stampCookieFlags(
  awsCf: Record<string, unknown>,
  sigintAesKeyHex: string,
  fpidCookie: string | undefined,
): void {
  if (!fpidCookie) {
    awsCf.cookieTampered = true;
    return;
  }
  const check = verifyCfCookie(fpidCookie, sigintAesKeyHex);
  awsCf.cookieTampered = !check.valid;
  if (check.valid) {
    awsCf.cookieMatchesToken =
      awsCf.id === check.id && awsCf.issuedAt === check.issuedAt;
  }
}

function applyTlsJson(
  sigintTls: string | undefined,
  sigint: ArgusPayload["sigint"],
  sigintAesKeyHex: string | undefined,
  fpidCookie?: string,
): void {
  if (!sigintTls || !sigint || sigint.aws_cf) return;
  const awsCf = unwrapTlsPayload(sigintTls);
  if (!awsCf) return;
  if (sigintAesKeyHex) {
    const { expired, tampered } = verifyCfToken(
      awsCf as CfTokenFields,
      sigintAesKeyHex,
    );
    awsCf.expired = expired;
    awsCf.tampered = tampered;
    stampCookieFlags(awsCf, sigintAesKeyHex, fpidCookie);
  }
  sigint.aws_cf = awsCf;
}

export async function redeemSigintTokens(
  payload: ArgusPayload,
  ctx: Omit<RedeemCtx, "tableName"> & {
    probeTokensTableName: string;
    fpidCookie?: string;
  },
): Promise<ArgusPayload> {
  const { sigintAesKeyHex, probeTokensTableName, dynamo, logger, fpidCookie } =
    ctx;
  const sigint: ArgusPayload["sigint"] = payload.sigint
    ? { ...payload.sigint }
    : {};

  const tcpToken = resolveProbeToken(
    payload.sigintTcpToken,
    payload.sigint?.tcp_probe,
    sigint,
    "tcp_probe",
  );
  const h2Token = resolveProbeToken(
    payload.sigintH2Token,
    payload.sigint?.h2,
    sigint,
    "h2",
  );

  applyTlsJson(payload.sigintTls, sigint, sigintAesKeyHex, fpidCookie);

  const redeemCtx: RedeemCtx = {
    sigintAesKeyHex,
    tableName: probeTokensTableName,
    dynamo,
    logger,
  };
  const [tcpData, h2Data, patData] = await Promise.all([
    redeemToken(tcpToken, redeemCtx),
    redeemToken(h2Token, redeemCtx),
    redeemToken(payload.patToken, redeemCtx),
  ]);

  if (tcpData) sigint.tcp_probe = tcpData as typeof sigint.tcp_probe;
  if (h2Data) sigint.h2 = h2Data as typeof sigint.h2;

  return {
    ...payload,
    sigint: Object.keys(sigint).length > 0 ? sigint : undefined,
    pat: shapePatResult(patData),
  };
}

/**
 * Map a redeemed probe-fingerprint blob to a PayloadPat. Returns undefined
 * for shapes that don't match (e.g. a TCP-probe fingerprint replayed in the
 * patToken field). PAT is additive-only — silent drop is correct.
 */
function shapePatResult(data: unknown): PayloadPat | undefined {
  if (!isPatFingerprint(data)) return undefined;
  return {
    attested: true,
    issuer: data.issuer,
    tokenHash: data.tokenHash,
    redeemedAt: data.redeemedAt,
  };
}
