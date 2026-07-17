/**
 * Server-side sigint hydration and PAT binding for integrity submissions.
 *
 * This module owns the fail-closed boundary between attacker-controlled
 * request data and the trusted probe evidence consumed by the analyzers.
 */
import type { Logger } from "@aws-lambda-powertools/logger";
import { MetricUnit, type Metrics } from "@aws-lambda-powertools/metrics";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { extractFpidCookie } from "../../helpers/verify-cf-token";
import { HttpError } from "../../helpers/http-error";
import type { ArgusPayload } from "../../helpers/payload-schema";
import { redeemPatToken } from "../../helpers/redeem-pat-token";
import {
  isAwsCfAuthenticallyHydrated,
  redeemSigintTokens,
} from "../../helpers/redeem-sigint-tokens";

interface SigintHydrationDeps {
  logger: Logger;
  metrics: Metrics;
}

interface SigintHydrationEvent {
  cookies?: string[];
  requestContext: { http: { sourceIp: string } };
}

interface SigintHydrationOptions {
  dynamo: DynamoDBClient;
  cpi?: string;
}

function requireSigintEnv(deps: SigintHydrationDeps): {
  sigintAesKey: string;
  probeTokensTable: string;
} {
  const sigintAesKey = process.env.SIGINT_AES_KEY;
  const probeTokensTable = process.env.PROBE_TOKENS_TABLE_NAME;
  if (sigintAesKey && probeTokensTable) {
    return { sigintAesKey, probeTokensTable };
  }
  deps.logger.error(
    "Sigint env not configured — refusing rather than green-lighting original payload",
    {
      sigintAesKeyPresent: !!sigintAesKey,
      probeTokensTablePresent: !!probeTokensTable,
    },
  );
  deps.metrics.addMetric("SigintNotConfigured", MetricUnit.Count, 1);
  throw new HttpError(503, "sigint verification not configured");
}

/**
 * Strip client-controlled sigint fields, redeem authoritative probe data, and
 * bind any PAT evidence to the request. Throws rather than returning the
 * original payload whenever verification infrastructure is unavailable.
 */
export async function hydrateSigint(
  payload: ArgusPayload,
  deps: SigintHydrationDeps,
  event: SigintHydrationEvent,
  options: SigintHydrationOptions,
): Promise<ArgusPayload> {
  const { sigintAesKey, probeTokensTable } = requireSigintEnv(deps);
  const cpi = options.cpi ?? payload.identifiers.cpi ?? "";

  let hydrated: ArgusPayload;
  try {
    hydrated = await redeemSigintTokens(payload, {
      sigintAesKeyHex: sigintAesKey,
      probeTokensTableName: probeTokensTable,
      dynamo: options.dynamo,
      logger: deps.logger,
      fpidCookie: extractFpidCookie(event.cookies),
      requestSourceIp: event.requestContext.http.sourceIp,
    });
    deps.metrics.addMetric("IntegritySigintRedeemed", MetricUnit.Count, 1);
  } catch (err) {
    // Returning the original payload here would restore attacker-controlled
    // inline probe blobs that redeemSigintTokens strips before verification.
    deps.logger.warn(
      "Sigint token redemption threw — refusing rather than green-lighting original payload",
      { error: err },
    );
    deps.metrics.addMetric("SigintHydrationError", MetricUnit.Count, 1);
    throw new HttpError(503, "sigint verification temporarily unavailable");
  }

  // A real SDK execution redeems authoritative probe evidence. Reject a row
  // with none rather than allowing clean-by-omission scoring. aws_cf only
  // counts when its server verification flags are explicitly clean.
  const anyHydrated =
    !!hydrated.sigint?.tcp_probe ||
    !!hydrated.sigint?.h2 ||
    isAwsCfAuthenticallyHydrated(hydrated.sigint);
  if (!anyHydrated) {
    deps.metrics.addMetric("SigintRedeemAllFailed", MetricUnit.Count, 1);
    throw new HttpError(400, "sigint probe redemption failed");
  }

  // PAT redemption is independent of probe-token storage. Invalid PAT input
  // is dropped by redeemPatToken; valid evidence is bound to this request.
  return redeemPatToken(hydrated, {
    expectedSrcIp: event.requestContext.http.sourceIp,
    expectedCpi: cpi,
    expectedSessionId: hydrated.identifiers.session_id,
    sigintAesKeyHex: sigintAesKey,
    logger: deps.logger,
  });
}
