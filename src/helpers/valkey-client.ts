/**
 * Lazy Valkey client for ms-argus-api ingestion.
 *
 * - One ioredis instance per warm container, reused across invocations.
 * - TLS mandatory (ElastiCache Serverless requires it).
 * - No auth — SG isolation IS the auth boundary (Valkey lives in the
 *   shared VPC, ingress 6379 from the lambda SG only).
 * - Gate on `client.status === 'ready'`; rebuild if not. Lambda
 *   containers freeze between invocations and the TCP socket can die
 *   during the freeze — the next pipeline then trips "Stream isn't
 *   writeable" forever unless we explicitly rebuild.
 * - `lazyConnect: false` + `enableOfflineQueue: true` together let
 *   commands queue during a fresh handshake. `commandTimeout: 2s`
 *   bounds the worst case.
 *
 * Pattern mirrors ms-argus-pair/cdk/lib/valkey-client.ts — kept
 * separate per-repo for build-asset clarity and because the two
 * Lambdas are deployed independently.
 */
import Redis from "ioredis";

let cached: Redis | null = null;

export function getValkey(): Redis {
  if (cached && cached.status === "ready") return cached;
  if (cached) {
    try {
      cached.disconnect();
    } catch {
      /* socket already gone — ignore */
    }
    cached = null;
  }
  const host = process.env.VALKEY_ENDPOINT;
  if (!host) throw new Error("VALKEY_ENDPOINT not configured");
  const port = Number(process.env.VALKEY_PORT ?? "6379");
  const client = new Redis({
    host,
    port,
    tls: {},
    lazyConnect: false,
    maxRetriesPerRequest: 1,
    connectTimeout: 5_000,
    commandTimeout: 2_000,
    enableOfflineQueue: true,
    reconnectOnError: () => 1,
  });
  client.on("error", (err) => {
    // eslint-disable-next-line no-console
    console.warn(`[valkey] client error: ${err.message}`);
  });
  client.on("end", () => {
    if (cached === client) cached = null;
  });
  cached = client;
  return cached;
}
