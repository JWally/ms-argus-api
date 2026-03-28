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
import type { ArgusPayload } from "./payload-schema";

/**
 * Verify a sigint probe token.
 *
 * Token format: `{nonce_hex}.{expiry_ms}.{hmac_hex}`
 * HMAC-SHA256 over `{nonce}.{expiry_ms}` using first 32 bytes of SIGINT_AES_KEY.
 *
 * @returns true if the token is unexpired and the HMAC is valid
 */
function verifyToken(token: string, sigintAesKeyHex: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [nonce, expiryStr, hmac] = parts;

  // Expiry check
  const expiry = parseInt(expiryStr, 10);
  if (!Number.isFinite(expiry) || Date.now() > expiry) return false;

  // HMAC check (timing-safe)
  const key = Buffer.from(sigintAesKeyHex, "hex").subarray(0, 32);
  const expected = createHmac("sha256", key)
    .update(`${nonce}.${expiryStr}`)
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
 * Fetch and parse the probe data stored in PROBE_TOKENS_TABLE for a given token.
 *
 * DynamoDB item schema: { token (PK), fingerprint (JSON string), client_ip, ttl }
 */
async function fetchProbeData(
  token: string,
  tableName: string,
  dynamo: DynamoDBClient,
): Promise<unknown | null> {
  const result = await dynamo.send(
    new GetItemCommand({
      TableName: tableName,
      Key: { token: { S: token } },
    }),
  );
  if (!result.Item) return null;
  const item = unmarshall(result.Item);
  try {
    return JSON.parse(item.fingerprint as string);
  } catch {
    return null;
  }
}

interface RedeemCtx {
  sigintAesKeyHex: string;
  tableName: string;
  dynamo: DynamoDBClient;
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
 * - sigintTcpToken → HMAC verify → DynamoDB GetItem → payload.sigint.tcp_probe
 * - sigintH2Token  → HMAC verify → DynamoDB GetItem → payload.sigint.h2
 *
 * Also handles inline ProbeTokenResponse objects in payload.sigint.tcp_probe /
 * payload.sigint.h2 (set by ms-argus-web when probes return tokens).
 *
 * Non-fatal: if any step fails, the original payload is returned unchanged for that field.
 * Runs TCP and H2 lookups in parallel.
 */
async function redeemToken(
  token: string | undefined,
  ctx: RedeemCtx,
): Promise<unknown | null> {
  if (!token || !verifyToken(token, ctx.sigintAesKeyHex)) {
    return null;
  }
  return fetchProbeData(token, ctx.tableName, ctx.dynamo);
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

/** Apply TLS JSON string to sigint in place. */
function applyTlsJson(
  sigintTls: string | undefined,
  sigint: ArgusPayload["sigint"],
): void {
  if (!sigintTls || !sigint || sigint.aws_cf) return;
  try {
    sigint.aws_cf = JSON.parse(sigintTls);
  } catch {
    // ignore malformed TLS JSON
  }
}

export async function redeemSigintTokens(
  payload: ArgusPayload,
  sigintAesKeyHex: string,
  probeTokensTableName: string,
  dynamo: DynamoDBClient,
): Promise<ArgusPayload> {
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

  applyTlsJson(payload.sigintTls, sigint);

  const ctx: RedeemCtx = {
    sigintAesKeyHex,
    tableName: probeTokensTableName,
    dynamo,
  };
  const [tcpData, h2Data] = await Promise.all([
    redeemToken(tcpToken, ctx),
    redeemToken(h2Token, ctx),
  ]);

  if (tcpData) sigint.tcp_probe = tcpData as typeof sigint.tcp_probe;
  if (h2Data) sigint.h2 = h2Data as typeof sigint.h2;

  return {
    ...payload,
    sigint: Object.keys(sigint).length > 0 ? sigint : undefined,
  };
}
