/**
 * Load ECDH P-256 key pair from SSM Parameter Store with a 30-min TTL cache.
 *
 * Keys are generated once via scripts/generate-ecdh-key.ts and stored at:
 *   /${STACK_NAME}/ecdh-keypair  (SecureString)
 *
 * Structure: { current: EcdhKeyData, previous?: EcdhKeyData }
 * The `previous` slot is populated during key rotation to allow in-flight
 * requests encrypted with the old key to still decrypt successfully.
 */

import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { Logger } from "@aws-lambda-powertools/logger";
import { boundedRequestHandler } from "./sdk-http-handler";

const logger = new Logger({ serviceName: "argus-ecdh-keys" });

export interface EcdhKeyData {
  /** PKCS8 base64 — imported server-side as `deriveBits` private key */
  privateKey: string;
  /** SPKI base64 — reference only, not used at runtime */
  publicKey: string;
  /** Raw P-256 uncompressed point (04 prefix), 65 bytes, 88-char base64 */
  rawPublicKey: string;
  /** Unix ms timestamp of key creation */
  createdAt: number;
}

export interface EcdhKeys {
  current: EcdhKeyData;
  previous?: EcdhKeyData;
}

const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

let ssmClient: SSMClient | null = null;
let cachedKeys: EcdhKeys | null = null;
let cacheTimestamp = 0;
let inFlightFetch: Promise<EcdhKeys | null> | null = null;

async function fetchFromSsm(paramName: string): Promise<EcdhKeys | null> {
  if (!ssmClient) {
    // Bounded timeouts: the 30-min key cache refetches on the first request
    // after an idle gap, when the keep-alive socket is most likely dead (see
    // sdk-http-handler.ts) — fail fast and retry instead of a ~7.5s blackhole.
    ssmClient = new SSMClient({ requestHandler: boundedRequestHandler });
  }
  try {
    const result = await ssmClient.send(
      new GetParameterCommand({ Name: paramName, WithDecryption: true }),
    );
    const parsed = JSON.parse(result.Parameter?.Value ?? "{}") as EcdhKeys;
    if (!parsed.current) return null;
    cachedKeys = parsed;
    cacheTimestamp = Date.now();
    return cachedKeys;
  } catch (err) {
    logger.warn("Failed to load ECDH keys from SSM", { error: err });
    return cachedKeys; // return stale cache on transient failure
  }
}

/**
 * Return the ECDH key pair, using a 30-min in-memory cache.
 * Returns null if ECDH_KEY_PARAM is not set (feature disabled).
 *
 * Concurrent callers during a cache miss share a single in-flight SSM
 * fetch via `inFlightFetch`.
 *
 * NO module-load eager-fetch. A previous version fired a fire-and-
 * forget SSM call at module init thinking PC would hide the latency
 * in the unbilled Init phase. Lambda actually FROZE the container
 * mid-flight after Init completed, and when a real request thawed
 * the container 30+ minutes later the in-flight signed request fell
 * outside the SigV4 5-minute window. SSM responded
 * `InvalidSignatureException`, middleware retried, ingestion took
 * 8+ seconds. Caused a ~p90=3.6s ingestion regression. Reverted.
 *
 * If we ever want to pre-warm again, the only safe pattern is a
 * synchronous module-top `await` (Node ESM top-level await), which
 * blocks Init phase until the call completes — no mid-flight freeze
 * possible. Trade-off: SSM outages at deploy time crash the module.
 */
export async function getEcdhKeys(): Promise<EcdhKeys | null> {
  const paramName = process.env.ECDH_KEY_PARAM;
  if (!paramName) return null;

  if (cachedKeys && Date.now() - cacheTimestamp < CACHE_TTL_MS) {
    return cachedKeys;
  }

  if (!inFlightFetch) {
    inFlightFetch = fetchFromSsm(paramName).finally(() => {
      inFlightFetch = null;
    });
  }
  return inFlightFetch;
}

/**
 * Return the raw public key string for the current key.
 * Used by GET /v1/handshake to embed in the opaque session token.
 */
export async function getCurrentRawPublicKey(): Promise<string | null> {
  const keys = await getEcdhKeys();
  return keys?.current.rawPublicKey ?? null;
}

/** Clear cache — for testing only */
export function clearEcdhCache(): void {
  cachedKeys = null;
  cacheTimestamp = 0;
}
