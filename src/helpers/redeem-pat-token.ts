/**
 * Redeem the self-contained PAT-attestation token attached to an
 * incoming `/v1/integrity-collect` payload.
 *
 * Verifies the HMAC, freshness, and source-IP binding produced by the
 * PAT Lambda's `signPatAttestation`, then attaches the trusted contents
 * to `payload.pat`. Failures drop the field silently — PAT is an
 * additive signal; absence is the default state.
 *
 * Loose-coupling: lives next to redeem-sigint-tokens.ts but does not
 * touch the existing sigint code path. Deleting PAT means deleting this
 * file + the patToken/pat fields on payload-schema.ts and removing the
 * call site in base-handler.ts.
 */

import type { Logger } from "@aws-lambda-powertools/logger";
import { verifyPatAttestation } from "./pat-signed-token";
import type { ArgusPayload, PayloadPat } from "./payload-schema";

export interface RedeemPatCtx {
  /** The TLS-observed source IP at the ingestion request — must match the
   *  `src_ip` baked into the token at /v1/pat-attestation time. */
  expectedSrcIp: string;
  /** First 32 bytes of SIGINT_AES_KEY in hex. */
  sigintAesKeyHex: string;
  logger?: Logger;
}

export function redeemPatToken(
  payload: ArgusPayload,
  ctx: RedeemPatCtx,
): ArgusPayload {
  const token = payload.patToken;
  if (!token) return payload;

  const result = verifyPatAttestation(
    token,
    ctx.expectedSrcIp,
    ctx.sigintAesKeyHex,
  );

  if (!result.ok) {
    ctx.logger?.warn("PAT token verification failed", {
      reason: result.reason,
      // Don't log the token itself — preserves the unlinkability property
      // even in our own logs.
      tokenHashPrefix:
        token.length > 16 ? token.slice(0, 8) + "…" + token.slice(-8) : token,
    });
    return payload;
  }

  const pat: PayloadPat = {
    attested: true,
    issuer: result.payload.issuer,
    tokenHash: result.payload.token_hash,
    redeemedAt: result.payload.iat * 1000,
  };

  return { ...payload, pat };
}
