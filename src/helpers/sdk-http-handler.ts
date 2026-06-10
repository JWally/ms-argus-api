/**
 * Bounded HTTP-handler options for AWS SDK v3 clients on the ingestion hot path.
 *
 * Why this exists: SDK clients keep TCP+TLS connections alive and reuse them
 * across invocations for warm-path latency. But Lambda *freezes* the container
 * between invocations, and an idle keep-alive socket is silently torn down by
 * the path (NAT / LB idle-timeout) without a FIN/RST the frozen process can
 * observe. On thaw the SDK reuses that dead socket; the write blackholes and
 * TCP retransmits for ~7.5s before the OS gives up — turning a 60ms PutRecord
 * into an 8-second hang on the first request after an idle gap. (Observed on
 * ingestion's Firehose archive: server-side latency stayed <65ms while the
 * call took 7.5s — proving the time was spent client-side on a dead socket.)
 *
 * The fix: bound the per-attempt timeouts so a dead socket is detected in
 * ~1.5s instead of ~7.5s. The SDK then retries on a fresh connection (timeout
 * errors are retryable), so the call still succeeds — just fast. keepAlive
 * stays ON: the warm path (the overwhelming majority of calls) is unaffected.
 *
 * Passed as a plain `requestHandler` options object — NOT a constructed
 * `NodeHttpHandler`. The SDK accepts `NodeHttpHandlerOptions` for
 * `requestHandler` and builds the handler internally with its own (runtime-
 * provided) `@smithy/node-http-handler`. Importing `@smithy/node-http-handler`
 * directly fails at init: esbuild treats it as external and it isn't in the
 * Lambda runtime → ERR_MODULE_NOT_FOUND → provisioned concurrency can't warm.
 */

// connectionTimeout: cap establishing a *fresh* socket.
// requestTimeout: cap waiting for a response — this is what catches the
// dead-socket-write blackhole. Both sit well above DDB (<30ms) and Firehose
// (<60ms) healthy latency, so honest calls are never clipped.
export const boundedRequestHandler = {
  connectionTimeout: 1000,
  requestTimeout: 1500,
} as const;
