/**
 * Lazy Valkey client for ms-argus-api ingestion.
 *
 * - One ioredis instance per warm container, reused across invocations.
 * - TLS mandatory (ElastiCache Serverless requires it).
 * - No auth — SG isolation IS the auth boundary (Valkey lives in the
 *   shared VPC, ingress 6379 from the lambda SG only).
 *
 * Stale-socket defense (the integrity-collect 10s hang). A Lambda container
 * freezes between invocations; during a long freeze the idle TCP socket is
 * silently reaped by the NAT gateway (~350s idle) with no FIN the frozen
 * process can see. On thaw ioredis still reports `status === 'ready'` and
 * writes into a corpse → the write blackholes for ~10s. Defenses, in order of
 * importance for the FROZEN case:
 *   1. Age-based recycle (below): if the client hasn't been used within
 *      STALE_MS, proactively rebuild — the only check that survives a freeze,
 *      since it's wall-clock (Date.now) based and runs on thaw. The heater
 *      pings every 60s, so a healthy container is used well inside STALE_MS.
 *   2. keepAlive: OS TCP keep-alive < the 350s NAT cutoff. Helps while the
 *      container is RUNNING-but-idle; does nothing during a freeze (no packets
 *      are sent while suspended) — hence #1 carries the freeze case.
 *   3. socketTimeout: backstop so an unresponsive socket is destroyed instead
 *      of hanging; bounded above commandTimeout so normal commands win first.
 * The hot-path velocity call also has a hard 1.5s outer deadline + fail-open.
 *
 * TODO(valkey-offline-queue): evaluate `enableOfflineQueue: false`. It's left
 * `true` for now (commands queue through a brief reconnect). Best practice for
 * a Lambda hot path leans false — fail fast when disconnected and let the
 * caller's fail-open handle it, rather than queue toward the timeout (this is
 * the mechanism in ioredis#634). Deferred: needs a check that no caller relies
 * on offline queuing. See also [[project_argus_valkey_stale_socket]].
 *
 * Pattern mirrors ms-argus-pair/cdk/lib/valkey-client.ts — kept
 * separate per-repo for build-asset clarity and because the two
 * Lambdas are deployed independently.
 */
import Redis from "ioredis";

let cached: Redis | null = null;
// Wall-clock of the last getValkey() use. Survives a freeze (Date.now is real
// on thaw), unlike status/keepAlive, so it's the reliable freeze detector.
let lastUsedAt = 0;
// Recycle a client unused longer than this. Comfortably above the 60s heater
// interval (so healthy containers aren't churned) and well under the 350s NAT
// idle cutoff (so we rebuild before the socket can be reaped).
const STALE_MS = 90_000;

export function getValkey(): Redis {
  const now = Date.now();
  if (cached && cached.status === "ready" && now - lastUsedAt < STALE_MS) {
    lastUsedAt = now;
    return cached;
  }
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
    // Kept well under the ingestion Lambda's 10s budget: a stale-socket
    // reconnect must resolve fast, not stack toward the timeout.
    connectTimeout: 1_500,
    commandTimeout: 1_500,
    // OS TCP keep-alive, < the 350s NAT idle cutoff (see header).
    keepAlive: 30_000,
    // Connection-level backstop: destroy an unresponsive socket rather than
    // hang. Above commandTimeout so per-command timeout fires first normally.
    socketTimeout: 4_000,
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
  lastUsedAt = now;
  return cached;
}
