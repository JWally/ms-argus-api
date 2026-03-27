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
 * Redeem sigint tokens and hydrate payload.sigint with full probe data.
 *
 * Handles three token types:
 * - sigintTls      → JSON.parse → payload.sigint.tlsFingerprint (no DynamoDB, direct data)
 * - sigintTcpToken → HMAC verify → DynamoDB GetItem → payload.sigint.tcpProbe
 * - sigintH2Token  → HMAC verify → DynamoDB GetItem → payload.sigint.h2Probe
 *
 * Non-fatal: if any step fails, the original payload is returned unchanged for that field.
 * Runs TCP and H2 lookups in parallel.
 */
async function redeemToken(
  token: string | undefined,
  existing: unknown,
  ctx: RedeemCtx,
): Promise<unknown | null> {
  if (!token || existing || !verifyToken(token, ctx.sigintAesKeyHex)) {
    return null;
  }
  return fetchProbeData(token, ctx.tableName, ctx.dynamo);
}

export async function redeemSigintTokens(
  payload: ArgusPayload,
  sigintAesKeyHex: string,
  probeTokensTableName: string,
  dynamo: DynamoDBClient,
): Promise<ArgusPayload> {
  const { sigintTcpToken, sigintH2Token, sigintTls } = payload;
  const sigint: ArgusPayload["sigint"] = payload.sigint
    ? { ...payload.sigint }
    : {};

  // TLS: direct JSON string — no token verification needed
  if (sigintTls && !sigint.tlsFingerprint) {
    try {
      sigint.tlsFingerprint = JSON.parse(sigintTls);
    } catch {
      // ignore malformed TLS JSON
    }
  }

  // TCP + H2: HMAC-verify → DynamoDB lookup (parallel)
  const ctx: RedeemCtx = {
    sigintAesKeyHex,
    tableName: probeTokensTableName,
    dynamo,
  };
  const [tcpData, h2Data] = await Promise.all([
    redeemToken(sigintTcpToken, sigint.tcpProbe, ctx),
    redeemToken(sigintH2Token, sigint.h2Probe, ctx),
  ]);

  if (tcpData) sigint.tcpProbe = tcpData as typeof sigint.tcpProbe;
  if (h2Data) sigint.h2Probe = h2Data as typeof sigint.h2Probe;

  return {
    ...payload,
    sigint: Object.keys(sigint).length > 0 ? sigint : undefined,
  };
}
