/** Atomic replay ledger for verified raw Apple Private Access Tokens. */
import { getValkey } from "../../helpers/valkey-client";
import { Logger } from "@aws-lambda-powertools/logger";

const KEY_PREFIX = "pat:used:";
const REPLAY_TTL_SECONDS = 30 * 24 * 60 * 60;
const logger = new Logger({ serviceName: "pat-token-replay" });

export type TokenClaimResult = "claimed" | "replayed" | "unavailable";

export async function claimPatTokenHash(
  tokenHash: string,
): Promise<TokenClaimResult> {
  if (!process.env.VALKEY_ENDPOINT) return "unavailable";
  try {
    const result = await getValkey().set(
      `${KEY_PREFIX}${tokenHash}`,
      "1",
      "EX",
      REPLAY_TTL_SECONDS,
      "NX",
    );
    return result === "OK" ? "claimed" : "replayed";
  } catch (error) {
    // PAT is optional evidence, so fail closed for PAT credit without failing
    // the surrounding integrity scan.
    logger.warn("PAT token replay ledger unavailable", { error });
    return "unavailable";
  }
}
