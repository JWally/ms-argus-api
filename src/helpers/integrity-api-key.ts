/**
 * Integrity API key validation.
 *
 * Loads the API key from SSM (cached) and validates incoming requests.
 * Used by session-get to protect GET /v1/session/{session_id}.
 */

import { timingSafeEqual } from "node:crypto";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const ssm = new SSMClient({});
const STACK_NAME = process.env.STACK_NAME ?? "";
const PARAM_NAME =
  process.env.INTEGRITY_API_KEY_PARAM ?? `/${STACK_NAME}/integrity-api-key`;

let cachedKey: string | null = null;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function loadApiKey(): Promise<string | null> {
  const now = Date.now();
  if (cachedKey && now < cacheExpiry) return cachedKey;

  try {
    const result = await ssm.send(
      new GetParameterCommand({
        Name: PARAM_NAME,
        WithDecryption: true,
      }),
    );
    cachedKey = result.Parameter?.Value ?? null;
    cacheExpiry = now + CACHE_TTL_MS;
    return cachedKey;
  } catch {
    return null;
  }
}

/**
 * Validate an API key from the X-Api-Key header.
 * Returns true if valid, false otherwise.
 */
export async function validateIntegrityApiKey(
  headerValue: string | undefined,
): Promise<boolean> {
  if (!headerValue) return false;

  const expected = await loadApiKey();
  if (!expected) return false;

  // Constant-time comparison to prevent timing attacks
  if (headerValue.length !== expected.length) return false;

  const a = Buffer.from(headerValue);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
