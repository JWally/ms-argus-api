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
    ssmClient = new SSMClient({});
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
 * fetch via `inFlightFetch`. Without this dedup, the eager prefetch
 * below + a fast first request would both fire the SSM call.
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

// Eager pre-warm at module load. With Provisioned Concurrency, AWS
// imports this module during container init (the unbilled Init phase)
// before any request routes here, so the SSM round-trip + key parse
// is hidden from request-time. Cache miss tail on /v1/integrity-collect
// was the source of an 800ms p90 that dropped to ~240ms once warm.
//
// Fire-and-forget is fine: if the first request lands before SSM
// returns, it awaits the same `inFlightFetch` promise instead of
// starting a second fetch. The catch keeps an SSM init failure from
// crashing the module — request-time path will retry naturally.
if (process.env.ECDH_KEY_PARAM) {
  void getEcdhKeys().catch(() => {
    /* surfaced + logged by fetchFromSsm; module load must not throw */
  });
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
