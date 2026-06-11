/**
 * @fileoverview Container-init warm-up for session-get.
 *
 * Runs once per container during init (the entry module top-level-awaits it —
 * the bundle is ESM, so init does not complete until this resolves). Because
 * it's awaited to completion *before* the container is marked READY, there is
 * no in-flight request to freeze — this is the safe inverse of the
 * fire-and-forget eager-init that expired signed requests on PC-frozen
 * containers (see sdk-http-handler.ts / token-verifier.ts).
 *
 * It warms the three things a first request would otherwise pay for cold:
 *   1. the platform pubkey (SSM read, ~500ms — the dominant cost)
 *   2. the DynamoDB client / keep-alive socket / TLS (~100-150ms)
 *   3. the V8 JIT on the merchant projection (~50ms first run)
 *
 * Everything is bounded and fail-open: a slow/failed prime can't block
 * provisioning past the budget, and anything that didn't warm is covered by
 * the handler's normal lazy paths (SWR key fetch, regular DDB read).
 *
 * @module handlers/session-get/prime
 */

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { primePublicKey } from "../../helpers/token-verifier";
import { fetchIntegrityResultsByComposite } from "./session-ops";
import { buildMerchantResponse } from "../../helpers/merchant-projection";

// Total budget for the whole prime. Init has a hard ceiling and provisioning
// shouldn't stall on a flaky dependency — past this we give up and let the
// lazy paths cover whatever didn't warm.
const PRIME_BUDGET_MS = 3000;

// Sentinel composite key for the throwaway warm-up read. It won't exist, so
// the GetItem returns fast (item-not-found) while still establishing the DDB
// socket + TLS. The cpi shape matches CPI_FORMAT so nothing rejects it early.
const PRIME_CPI = "argus_cpi_test_prime000000";
const PRIME_SESSION = "__init_prime__";

interface PrimeDeps {
  dynamodb: DynamoDBClient;
  integrityResultsTable: string;
  logger: Logger;
  metrics: Metrics;
  ssmPubkeyPath?: string;
}

function withBudget<T>(p: Promise<T>, ms: number): Promise<T | void> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
  return Promise.race([p.finally(() => clearTimeout(timer)), timeout]);
}

/**
 * Warm the pubkey cache, DDB socket, and projection JIT. Never throws — each
 * leg is independently fail-open so one slow dependency can't sink the others.
 */
export async function primeSessionGet(deps: PrimeDeps): Promise<void> {
  const t0 = performance.now();

  // Projection is synchronous — run it inline to JIT the hot path (null-
  // integrity branch). Best-effort: a throw here must not sink the prime.
  try {
    buildMerchantResponse({ session_id: PRIME_SESSION });
  } catch {
    // ignore — JIT warm only
  }

  // The two I/O legs run concurrently, each independently fail-open so one
  // slow dependency can't sink the other.
  const key = deps.ssmPubkeyPath
    ? primePublicKey(deps.ssmPubkeyPath).catch(() => {})
    : Promise.resolve();

  const ddb = fetchIntegrityResultsByComposite(PRIME_CPI, PRIME_SESSION, {
    dynamodb: deps.dynamodb,
    integrityResultsTable: deps.integrityResultsTable,
    logger: deps.logger,
    metrics: deps.metrics,
  }).catch(() => {});

  await withBudget(Promise.all([key, ddb]), PRIME_BUDGET_MS);
  deps.logger.info("session-get init-prime complete", {
    elapsedMs: Math.round(performance.now() - t0),
  });
}
