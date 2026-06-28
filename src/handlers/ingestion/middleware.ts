/**
 * @fileoverview Middy middleware for the ingestion handler.
 * Provides body parsing for both JSON and gzip-compressed binary payloads.
 * @module handlers/ingestion/middleware
 */

import { APIGatewayProxyEventV2 } from "aws-lambda";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import middy from "@middy/core";
import { HttpError } from "../../helpers/http-error";
import { decompressPayload } from "./gzip";
import { getEcdhKeys } from "../../helpers/get-ecdh-keys";
import {
  decryptArgusPayload,
  decryptIntegrityPayload,
  decryptIntegrityPayloadV2,
  decryptIntegrityPayloadV3,
} from "../../helpers/ecdh-decrypt";

const INTEGRITY_COLLECT_PATH = "/v1/integrity-collect";

/**
 * Middy middleware that handles binary gzip-encoded payloads.
 *
 * For `application/octet-stream` content types:
 * - Validates Content-Encoding header includes "gzip"
 * - Decompresses the payload with size limits
 * - Replaces event.body with decompressed UTF-8 string
 *
 * For other content types:
 * - Only validates body size against maxBodyBytes limit
 *
 * @param config - Size limit configuration
 * @param config.maxBodyBytes - Maximum compressed body size in bytes
 * @param config.maxDecompressedBytes - Maximum decompressed size (prevents zip bombs)
 * @param metrics - Metrics instance for tracking payload types and errors
 * @returns Middy middleware object with `before` handler
 *
 * @throws {HttpError} 413 if payload exceeds size limits
 * @throws {HttpError} 400 if gzip decompression fails
 *
 * @example
 * ```typescript
 * const handler = middy(baseHandler)
 *   .use(binaryGzipBodyParser({ maxBodyBytes: 1024 * 100, maxDecompressedBytes: 1024 * 500 }, metrics));
 * ```
 */
async function decryptIntegrity(
  event: APIGatewayProxyEventV2,
  clientPubKey: string,
  keys: Awaited<ReturnType<typeof getEcdhKeys>> & {},
): Promise<unknown | null> {
  const sessionToken = event.headers["x-argus-session"] ?? "";
  const version = event.headers["x-argus-v"] ?? "1";
  const body = event.body ?? "";
  const { isBase64Encoded } = event;

  if (version === "3") {
    return decryptIntegrityPayloadV3({
      body,
      isBase64Encoded,
      clientPubKey,
      keys,
      sessionToken,
    });
  }
  if (version === "2") {
    return decryptIntegrityPayloadV2({
      body,
      isBase64Encoded,
      clientPubKey,
      keys,
      sessionToken,
    });
  }
  const deploySecret = process.env.INTEGRITY_DEPLOY_SECRET ?? "";
  return decryptIntegrityPayload({
    body,
    isBase64Encoded,
    clientPubKey,
    keys,
    innerKey: sessionToken + deploySecret,
  });
}

async function handleEcdhPayload(
  event: APIGatewayProxyEventV2,
  clientPubKey: string,
  metrics: Metrics,
): Promise<void> {
  const keys = await getEcdhKeys();
  if (!keys) {
    metrics.addMetric("EcdhNotConfigured", MetricUnit.Count, 1);
    throw new HttpError(503, "Encrypted ingestion not configured");
  }

  const isIntegrity = event.rawPath === INTEGRITY_COLLECT_PATH;
  let parsed: unknown | null;

  if (isIntegrity) {
    parsed = await decryptIntegrity(event, clientPubKey, keys);
    if (!parsed) {
      metrics.addMetric("IntegrityDecryptFailed", MetricUnit.Count, 1);
      throw new HttpError(400, "Integrity payload decryption failed");
    }
    metrics.addMetric("IntegrityPayloadReceived", MetricUnit.Count, 1);
  } else {
    parsed = await decryptArgusPayload(
      event.body ?? "",
      event.isBase64Encoded,
      clientPubKey,
      keys,
    );
    if (!parsed) {
      metrics.addMetric("EcdhDecryptFailed", MetricUnit.Count, 1);
      throw new HttpError(400, "Payload decryption failed");
    }
    metrics.addMetric("EcdhPayloadReceived", MetricUnit.Count, 1);
  }

  event.body = JSON.stringify(parsed);
  event.isBase64Encoded = false;
}

/**
 * SECURITY: /v1/integrity-collect POSTs are sealed to the ECDH path only —
 * application/octet-stream + X-Argus-Origin (client pubkey). The
 * unencrypted JSON and gzip-only paths were historically supported for
 * "server-to-server tests, debugging tools, future direct integrators"
 * (see payload-schema.resolveCpi docstring) but provided no additional
 * auth gate over the encrypted path: same trust level, same analyzer,
 * same storage. That made them a free curl-from-anywhere submission
 * channel for anyone who could scrape a public CPI from a merchant
 * embed. Sealed 2026-05-25 — internal/server-to-server callers must
 * either use the SDK (ECDH) or land behind a separate authenticated
 * endpoint (not this one).
 */
function enforceIntegrityCollectSeal(
  event: APIGatewayProxyEventV2,
  contentType: string,
  metrics: Metrics,
): void {
  const isIntegrityCollectPost =
    event.rawPath === INTEGRITY_COLLECT_PATH &&
    event.requestContext.http.method === "POST";
  if (!isIntegrityCollectPost) return;

  const hasOrigin = !!event.headers["x-argus-origin"];
  if (contentType.startsWith("application/octet-stream") && hasOrigin) return;

  metrics.addMetric("UnencryptedSubmissionRejected", MetricUnit.Count, 1);
  throw new HttpError(
    415,
    "Unsupported Media Type: integrity submissions must be ECDH-encrypted (application/octet-stream + X-Argus-Origin)",
  );
}

export const binaryGzipBodyParser = (
  config: { maxBodyBytes: number; maxDecompressedBytes: number },
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const contentType = (event.headers["content-type"] ?? "").toLowerCase();

    enforceIntegrityCollectSeal(event, contentType, metrics);

    if (!contentType.startsWith("application/octet-stream")) {
      if (Buffer.byteLength(event.body ?? "", "utf8") > config.maxBodyBytes) {
        metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
        throw new HttpError(413, "Request entity too large");
      }
      metrics.addMetric("JsonPayloadReceived", MetricUnit.Count, 1);
      return;
    }

    // ECDH-encrypted argus-web payload: X-Argus-Origin header carries client pubkey
    const clientPubKey = event.headers["x-argus-origin"];
    if (clientPubKey) {
      await handleEcdhPayload(event, clientPubKey, metrics);
      return;
    }

    await decompressPayload(event, config, metrics);
  },
});

/**
 * Middy middleware that parses JSON request bodies for the /v1/collect endpoint.
 *
 * Only processes POST requests to /v1/collect. For matching requests:
 * - Parses JSON body and attaches to event.parsedBody
 * - Tracks invalid JSON payloads via metrics
 *
 * @param metrics - Metrics instance for tracking parse errors
 * @returns Middy middleware object with `before` handler
 *
 * @throws {HttpError} 400 if JSON parsing fails
 *
 * @example
 * ```typescript
 * const handler = middy(baseHandler)
 *   .use(jsonBodyParser(metrics));
 *
 * // In handler:
 * const payload = (event as any).parsedBody;
 * ```
 */
export const jsonBodyParser = (
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const method = event.requestContext.http.method;

    if (method !== "POST") {
      return;
    }

    if (
      event.rawPath !== "/v1/collect" &&
      event.rawPath !== INTEGRITY_COLLECT_PATH
    ) {
      return;
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (event as any).parsedBody = JSON.parse(event.body ?? "{}");
    } catch {
      metrics.addMetric("InvalidJson", MetricUnit.Count, 1);
      throw new HttpError(400, "Invalid JSON payload");
    }
  },
});

/**
 * Middy middleware that enforces real SDK probe evidence on /v1/integrity-collect.
 *
 * Hard-requires all three sigint probe tokens — any missing → HTTP 400.
 * The SDK ships a token for each probe even when the underlying probe
 * couldn't run (e.g., H2 token still emitted when client is stuck on
 * HTTP/1.1; the token carries that state). So a real SDK execution always
 * produces all three; absence on the wire is determinative evidence of
 * SDK bypass.
 *
 *  - **TCP probe** (`sigintTcpToken` | inline `sigint.tcp_probe.token`):
 *    carries `rcv_rtt/rtt` and `snd_mss` — the signals `proxy_waterfall`
 *    rule 7 uses to catch userspace HTTP CONNECT proxies.
 *  - **CF probe** (`sigintTls` JSON, populates `sigint.aws_cf`):
 *    carries the ASN classification CloudFront resolved (residential /
 *    datacenter / proxy-provider / hosting).
 *  - **H2 probe** (`sigintH2Token` | inline `sigint.h2.token`):
 *    carries H2-side JA4 and overlapping TLS info — `JA4_UA_BROWSER_MISMATCH`
 *    and `H2_UA_BROWSER_MISMATCH` analyzer signals.
 *
 * STUN/`sigintCandidates` are intentionally NOT required — the analyzer has
 * documented contingencies for missing WebRTC data (the `no_webrtc` tag,
 * `proxy_waterfall` silent-webrtc branch with `rttRatio=null` falling to
 * rule 8). WebRTC does what it does.
 *
 * Per-probe absence metrics (`SigintTcpProbeAbsent`, `SigintCfProbeAbsent`,
 * `SigintH2ProbeAbsent`) are emitted on every rejection so post-deploy
 * dashboards can see which probe(s) are tripping rejections — useful for
 * spotting real-traffic regressions (e.g., a probe endpoint outage).
 *
 * Skips non-POST and non-/v1/integrity-collect requests. Runs after
 * `jsonBodyParser` (needs `event.parsedBody`).
 */
function hasInlineProbeToken(probe: unknown): boolean {
  if (probe === null || typeof probe !== "object") return false;
  const token = (probe as Record<string, unknown>).token;
  // Match extractInlineToken in redeem-sigint-tokens.ts: token must be a
  // string AND the envelope must not be the `{v, data}` encrypted-blob shape.
  return (
    typeof token === "string" &&
    token.length > 0 &&
    !("v" in (probe as Record<string, unknown>))
  );
}

function nonEmptyString(v: unknown): boolean {
  return typeof v === "string" && v.length > 0;
}

interface ProbePresence {
  tcp: boolean;
  cf: boolean;
  h2: boolean;
}

function checkProbePresence(payload: unknown): ProbePresence {
  if (payload === null || typeof payload !== "object") {
    return { tcp: false, cf: false, h2: false };
  }
  const p = payload as Record<string, unknown>;
  const sigint = p.sigint as Record<string, unknown> | undefined;
  return {
    tcp:
      nonEmptyString(p.sigintTcpToken) ||
      (sigint ? hasInlineProbeToken(sigint.tcp_probe) : false),
    cf: nonEmptyString(p.sigintTls),
    h2:
      nonEmptyString(p.sigintH2Token) ||
      (sigint ? hasInlineProbeToken(sigint.h2) : false),
  };
}

export const sigintTokenValidator = (
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    if (event.requestContext.http.method !== "POST") return;
    if (event.rawPath !== INTEGRITY_COLLECT_PATH) return;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parsed = (event as any).parsedBody;
    const present = checkProbePresence(parsed);

    const missing: string[] = [];
    if (!present.tcp) {
      missing.push("sigintTcpToken");
      metrics.addMetric("SigintTcpProbeAbsent", MetricUnit.Count, 1);
    }
    if (!present.cf) {
      missing.push("sigintTls");
      metrics.addMetric("SigintCfProbeAbsent", MetricUnit.Count, 1);
    }
    if (!present.h2) {
      missing.push("sigintH2Token");
      metrics.addMetric("SigintH2ProbeAbsent", MetricUnit.Count, 1);
    }
    if (missing.length === 0) return;
    throw new HttpError(
      400,
      `Missing required sigint probe evidence: ${missing.join(", ")}`,
    );
  },
});
