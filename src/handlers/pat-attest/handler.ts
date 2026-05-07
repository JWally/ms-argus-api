/**
 * Lambda entry point for /v1/pat-attestation.
 *
 * Mode 1 (no Authorization header):
 *   200 + WWW-Authenticate: PrivateToken challenge=…, token-key=…, max-age=…
 *   The 200 (rather than 401) lets cross-origin fetch read the response body
 *   from JS. The OS-level URLSession on iOS Safari ignores the status and
 *   acts on the WWW-Authenticate header alone — RFC 9577 §3 doesn't mandate
 *   any specific status, only the header. JSON body mirrors the same
 *   challenge for clients that want to redeem explicitly.
 *
 * Mode 2 (Authorization: PrivateToken token=<b64url>):
 *   Verify the token. On success: mint a sigint-format probe token bound to
 *   the source IP, persist a `{ type: "pat", attested: true, … }` fingerprint
 *   to PROBE_TOKENS_TABLE, and return `{ token }`. The client forwards that
 *   token to /v1/integrity-collect; ingestion redeems it via the existing
 *   redeemSigintTokens machinery.
 *
 * Loose-coupling guarantees:
 *   - Issuer config in one file (issuer-config.ts).
 *   - All failures null-safe — disabled or directory-down → 503 with no-store.
 *   - Zero dependencies on this Lambda from other Lambdas at runtime; only
 *     coupling is the DDB row format which redeem-sigint-tokens.ts already
 *     consumes.
 */

import { createHash } from "crypto";
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";

import { encodeTokenChallenge } from "./challenge";
import { ISSUER_CONFIG } from "./issuer-config";
import { getActiveTokenKey } from "./issuer-directory";
import { mintProbeToken, type PatFingerprint } from "./envelope";
import { testPageResponse } from "./test-page";
import { verifyPatToken } from "./verify";

const SERVICE = "pat-attest";
const logger = new Logger({ serviceName: SERVICE });
const metrics = new Metrics({ namespace: "Argus/PAT", serviceName: SERVICE });
const dynamo = new DynamoDBClient({});
const secretsClient = new SecretsManagerClient({});

let cachedAesKeyHex: string | null = null;
async function getSigintAesKeyHex(): Promise<string | null> {
  if (cachedAesKeyHex) return cachedAesKeyHex;
  const arn = process.env.SIGINT_AES_KEY_SECRET_ARN;
  if (!arn) {
    logger.error("SIGINT_AES_KEY_SECRET_ARN not configured");
    return null;
  }
  try {
    const out = await secretsClient.send(
      new GetSecretValueCommand({ SecretId: arn }),
    );
    cachedAesKeyHex = out.SecretString ?? null;
    return cachedAesKeyHex;
  } catch (err) {
    logger.error("Failed to fetch SIGINT_AES_KEY", {
      err: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
}

function b64urlEncode(b: Buffer): string {
  return b
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  return Buffer.from(
    s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad),
    "base64",
  );
}

function unavailable(): APIGatewayProxyResultV2 {
  return {
    statusCode: 503,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify({ error: "pat_unavailable" }),
  };
}

function getHeader(
  event: APIGatewayProxyEventV2,
  name: string,
): string | undefined {
  return event.headers?.[name] ?? event.headers?.[name.toLowerCase()];
}

function parseAuthorizationToken(
  authHeader: string | undefined,
): Buffer | null {
  if (!authHeader) return null;
  const m = /^PrivateToken\s+token=([A-Za-z0-9_\-=]+)\s*$/.exec(authHeader);
  if (!m) return null;
  try {
    return b64urlDecode(m[1]);
  } catch {
    return null;
  }
}

async function buildChallengeResponse(): Promise<APIGatewayProxyResultV2 | null> {
  const key = await getActiveTokenKey(logger);
  if (!key) return null;

  const challenge = encodeTokenChallenge({
    issuerName: ISSUER_CONFIG.host,
  });
  const challengeB64 = b64urlEncode(challenge);
  const tokenKeyB64 = b64urlEncode(key.spkiDer);
  const maxAge = ISSUER_CONFIG.directoryCacheSeconds;

  const wwwAuth = `PrivateToken challenge=${challengeB64}, token-key=${tokenKeyB64}, max-age=${maxAge}`;

  metrics.addMetric("ChallengeIssued", MetricUnit.Count, 1);

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": wwwAuth,
      "Cache-Control": "no-store",
    },
    body: JSON.stringify({
      challenge: challengeB64,
      tokenKey: tokenKeyB64,
      maxAge,
    }),
  };
}

function rejectInvalidToken(reason: string): APIGatewayProxyResultV2 {
  logger.warn("PAT verify failed", { reason });
  metrics.addMetric("VerifyFailed", MetricUnit.Count, 1);
  metrics.addMetadata("reason", reason);
  return {
    statusCode: 401,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify({ error: "invalid_token", reason }),
  };
}

async function buildRedemptionResponse(
  tokenBytes: Buffer,
  clientIp: string,
  tableName: string,
): Promise<APIGatewayProxyResultV2 | null> {
  const key = await getActiveTokenKey(logger);
  if (!key) return null;

  const challenge = encodeTokenChallenge({ issuerName: ISSUER_CONFIG.host });
  const result = verifyPatToken(tokenBytes, challenge, key.spkiDer);
  if (!result.ok) return rejectInvalidToken(result.reason);

  const aesKey = await getSigintAesKeyHex();
  if (!aesKey) return null;

  const fingerprint: PatFingerprint = {
    type: "pat",
    issuer: ISSUER_CONFIG.host,
    attested: true,
    tokenHash: createHash("sha256").update(tokenBytes).digest("hex"),
    redeemedAt: Date.now(),
  };

  const probeToken = await mintProbeToken({
    fingerprint,
    clientIp,
    sigintAesKeyHex: aesKey,
    tableName,
    dynamo,
    logger,
  });

  metrics.addMetric("VerifySucceeded", MetricUnit.Count, 1);

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify({
      token: probeToken.token,
      expiryMs: probeToken.expiryMs,
    }),
  };
}

export const baseHandler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.path === "/v1/pat-test") {
    return testPageResponse();
  }

  if (ISSUER_CONFIG.disabled) {
    metrics.addMetric("Disabled", MetricUnit.Count, 1);
    return unavailable();
  }

  const tableName = process.env.PROBE_TOKENS_TABLE_NAME;
  if (!tableName) {
    logger.error("PROBE_TOKENS_TABLE_NAME not configured");
    return unavailable();
  }

  const authHeader = getHeader(event, "authorization");
  const tokenBytes = parseAuthorizationToken(authHeader);

  let response: APIGatewayProxyResultV2 | null;
  if (tokenBytes) {
    const clientIp = event.requestContext.http.sourceIp;
    response = await buildRedemptionResponse(tokenBytes, clientIp, tableName);
  } else {
    response = await buildChallengeResponse();
  }

  return response ?? unavailable();
};
