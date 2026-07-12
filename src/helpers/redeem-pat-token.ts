/**
 * Redeem the self-contained PAT-attestation token attached to an
 * incoming `/v1/integrity-collect` payload.
 *
 * Verifies the HMAC, freshness, and source-IP binding produced by the
 * PAT Lambda's `signPatAttestation`, then attaches the trusted contents
 * to `payload.pat` (only on success).
 *
 * Also stamps `payload.patAttempt` REGARDLESS of outcome — captures
 * whether the client TRIED to attest, with the verification result.
 * Pre-2026-05-25 failures dropped silently, leaving the row unable to
 * distinguish "non-iOS user, no PAT" from "attacker shipped a forged
 * PAT-shaped string." merchant-projection now reads `patAttempt` to
 * score the failure case at tier-60 tampering (credible spoof).
 *
 * Loose-coupling: lives next to redeem-sigint-tokens.ts but does not
 * touch the existing sigint code path. Deleting PAT means deleting this
 * file + the patToken/pat/patAttempt fields on payload-schema.ts and
 * removing the call site in base-handler.ts.
 */

import type { Logger } from "@aws-lambda-powertools/logger";
import { verifyPatAttestation } from "./pat-signed-token";
import type {
  ArgusPayload,
  PayloadPat,
  PayloadPatAttempt,
} from "./payload-schema";

export interface RedeemPatCtx {
  /** The TLS-observed source IP at the ingestion request — must match the
   *  `src_ip` baked into the token at /v1/pat-attestation time. */
  expectedSrcIp: string;
  expectedCpi: string;
  expectedSessionId: string;
  /** First 32 bytes of SIGINT_AES_KEY in hex. */
  sigintAesKeyHex: string;
  logger?: Logger;
}

export function redeemPatToken(
  payload: ArgusPayload,
  ctx: RedeemPatCtx,
): ArgusPayload {
  const token = payload.patToken;
  if (!token) {
    // Client did not attempt PAT attestation. Stamp a "not attempted"
    // record for symmetry — merchant-projection treats this case as
    // no signal (the default for non-iOS / SDK without PAT support).
    const patAttempt: PayloadPatAttempt = { attempted: false, verified: false };
    return { ...payload, patAttempt };
  }

  const result = verifyPatAttestation(
    token,
    {
      srcIp: ctx.expectedSrcIp,
      cpi: ctx.expectedCpi,
      sessionId: ctx.expectedSessionId,
    },
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
    const patAttempt: PayloadPatAttempt = {
      attempted: true,
      verified: false,
      reason: result.reason,
    };
    return { ...payload, patAttempt };
  }

  const pat: PayloadPat = {
    attested: true,
    issuer: result.payload.issuer,
    tokenHash: result.payload.token_hash,
    redeemedAt: result.payload.iat * 1000,
  };
  const patAttempt: PayloadPatAttempt = { attempted: true, verified: true };

  return { ...payload, pat, patAttempt };
}
