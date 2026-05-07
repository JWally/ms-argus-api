/**
 * Lambda entry point for /v1/pat-attestation.
 *
 * Mode 1 (no Authorization header):
 *   401 + WWW-Authenticate: PrivateToken challenge=…, token-key=…, max-age=…
 *   401 is required: iOS URLSession only invokes the PAT handler on a 401
 *   response (standard HTTP auth flow per RFC 9577 §3). 200 with the
 *   WWW-Authenticate header — verified empirically against the live
 *   Fastly demo at https://patdemo-o.edgecompute.app/ — does not fire the
 *   OS handler. The JSON body still carries the challenge for non-iOS
 *   clients that want to redeem explicitly.
 *
 * Mode 2 (Authorization: PrivateToken token=<b64url>):
 *   Verify the token. On success: HMAC-sign a self-contained attestation
 *   blob (`{type:"pat", issuer, src_ip, iat, exp, token_hash}`) and return
 *   it as `{ token }`. The client forwards that string in
 *   `payload.patToken`; ingestion verifies the HMAC, freshness, and IP
 *   binding without any DB round trip — see helpers/redeem-pat-token.ts.
 *
 * Loose-coupling guarantees:
 *   - Issuer config in one file (issuer-config.ts).
 *   - All failures null-safe — disabled or directory-down → 503 with no-store.
 *   - Stateless: this Lambda holds no DB grants. Only IAM is read on the
 *     SIGINT_AES_KEY secret. Removing PAT = delete this directory + drop
 *     the SecretsManager grant.
 */

import { createHash } from "crypto";
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";

import { encodeTokenChallenge } from "./challenge";
import { ISSUER_CONFIG } from "./issuer-config";
import { getActiveTokenKey } from "./issuer-directory";
import {
  signPatAttestation,
  CLIENT_REFRESH_SECONDS,
} from "../../helpers/pat-signed-token";
import { testPageResponse } from "./test-page";
import { verifyPatToken } from "./verify";

const SERVICE = "pat-attest";
const logger = new Logger({ serviceName: SERVICE });
const metrics = new Metrics({ namespace: "Argus/PAT", serviceName: SERVICE });
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
    statusCode: 401,
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
): Promise<APIGatewayProxyResultV2 | null> {
  const key = await getActiveTokenKey(logger);
  if (!key) return null;

  const challenge = encodeTokenChallenge({ issuerName: ISSUER_CONFIG.host });
  const result = verifyPatToken(tokenBytes, challenge, key.spkiDer);
  if (!result.ok) return rejectInvalidToken(result.reason);

  const aesKey = await getSigintAesKeyHex();
  if (!aesKey) return null;

  const tokenHash = createHash("sha256").update(tokenBytes).digest("hex");
  const signed = signPatAttestation({
    issuer: ISSUER_CONFIG.host,
    srcIp: clientIp,
    tokenHash,
    sigintAesKeyHex: aesKey,
  });

  metrics.addMetric("VerifySucceeded", MetricUnit.Count, 1);
  logger.info("PAT attestation signed", {
    issuer: ISSUER_CONFIG.host,
    srcIp: clientIp,
    tokenHashPrefix: tokenHash.slice(0, 16),
  });

  // `exp` here is the CLIENT refresh-trigger (45s), not the server-
  // enforced hard-expiry (60s — baked into the signed token itself and
  // checked by verifyPatAttestation). The SDK uses this to decide when
  // to invalidate its sessionStorage cache and fetch fresh.
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify({
      token: signed,
      exp: Math.floor(Date.now() / 1000) + CLIENT_REFRESH_SECONDS,
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

  const authHeader = getHeader(event, "authorization");
  const tokenBytes = parseAuthorizationToken(authHeader);

  let response: APIGatewayProxyResultV2 | null;
  if (tokenBytes) {
    const clientIp = event.requestContext.http.sourceIp;
    response = await buildRedemptionResponse(tokenBytes, clientIp);
  } else {
    response = await buildChallengeResponse();
  }

  return response ?? unavailable();
};
