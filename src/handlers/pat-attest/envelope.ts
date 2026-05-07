/**
 * Mint a sigint-format probe token and persist its fingerprint in
 * PROBE_TOKENS_TABLE.
 *
 * Loose-coupling contract: outputs an opaque token string compatible with
 * the existing `redeemSigintTokens()` machinery in
 * src/helpers/redeem-sigint-tokens.ts. The PAT-specific fields live INSIDE
 * the fingerprint blob (`type: "pat"`, `attested`, `issuer`, …) so the
 * ingestion-side reader is the only place that needs to know about PAT.
 *
 * Token format (matches Go sigint probes byte-for-byte):
 *   {nonce_hex}.{expiry_ms}.{hmac_hex}
 *
 * HMAC-SHA256 over `{nonce}.{expiry_ms}.{clientIP}` using the first 32 bytes
 * of SIGINT_AES_KEY_HEX (decoded). Binding to client IP prevents stolen-token
 * replay from a different network.
 */

import { createHmac, randomBytes } from "crypto";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import type { Logger } from "@aws-lambda-powertools/logger";

const TOKEN_TTL_MS = 60_000;

export interface PatFingerprint {
  /** Stable tag so ingestion can branch on probe type. */
  type: "pat";
  /** Issuer hostname that signed the underlying PAT. */
  issuer: string;
  /** Always true if we got here — false-attested entries should not be persisted. */
  attested: true;
  /** SHA-256 hex of the PAT token bytes (NOT the token itself; preserves unlinkability). */
  tokenHash: string;
  /** When we successfully verified the PAT (epoch ms). */
  redeemedAt: number;
}

export interface MintInput {
  fingerprint: PatFingerprint;
  clientIp: string;
  sigintAesKeyHex: string;
  tableName: string;
  dynamo: DynamoDBClient;
  logger?: Logger;
}

export interface MintResult {
  token: string;
  expiryMs: number;
}

/** First 32 bytes of the hex-encoded SIGINT_AES_KEY (matches Go probe convention). */
function hmacKey(sigintAesKeyHex: string): Buffer {
  return Buffer.from(sigintAesKeyHex, "hex").subarray(0, 32);
}

export async function mintProbeToken(input: MintInput): Promise<MintResult> {
  const { fingerprint, clientIp, sigintAesKeyHex, tableName, dynamo, logger } =
    input;

  const nonce = randomBytes(16).toString("hex");
  const expiryMs = Date.now() + TOKEN_TTL_MS;
  const hmac = createHmac("sha256", hmacKey(sigintAesKeyHex))
    .update(`${nonce}.${expiryMs}.${clientIp}`)
    .digest("hex");
  const token = `${nonce}.${expiryMs}.${hmac}`;

  await dynamo.send(
    new PutItemCommand({
      TableName: tableName,
      Item: {
        token: { S: token },
        fingerprint: { S: JSON.stringify(fingerprint) },
        client_ip: { S: clientIp },
        ttl: { N: String(Math.floor(expiryMs / 1000) + 300) },
      },
    }),
  );

  logger?.info("PAT probe token minted", {
    nonce,
    expiryMs,
    issuer: fingerprint.issuer,
  });

  return { token, expiryMs };
}
