import type { Logger } from "@aws-lambda-powertools/logger";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { IdentityOutcome } from "../../helpers/device-identity";
import {
  bumpVelocityBlocked,
  pickDeviceId,
  updateIpVelocity,
  type IpVelocitySnapshot,
} from "../../helpers/ip-velocity";
import type { ArgusPayload } from "../../helpers/payload-schema";

const DEFAULT_VELOCITY_TIMEOUT_MS = 1500;

export interface IpVelocityContext {
  payload: ArgusPayload;
  sessionId: string;
  deps: { logger: Logger };
}

export interface IpVelocityEnrichmentDeps {
  dynamo: DynamoDBClient;
  timeoutMs?: number;
}

interface ApplyIpVelocitySnapshotInput {
  ctx: IpVelocityContext;
  item: Record<string, unknown>;
  identity: IdentityOutcome;
  deps: IpVelocityEnrichmentDeps;
}

/**
 * Stamp the current IP-hour velocity snapshot before merchant projection.
 * Velocity is non-critical enrichment, so missing identifiers, disabled
 * storage, timeouts, and downstream failures all leave the record unchanged.
 */
export async function applyIpVelocitySnapshot(
  input: ApplyIpVelocitySnapshotInput,
): Promise<Record<string, unknown>> {
  const { ctx, item, identity, deps } = input;
  const ip = (item as { client_ip?: string }).client_ip;
  if (!ip) return item;
  const clientUuid = (ctx.payload as { device?: { client_uuid?: string } })
    .device?.client_uuid;
  const deviceId = pickDeviceId(identity.pubkey, clientUuid);
  if (!deviceId) return item;

  try {
    const velocityPromise = updateIpVelocity({
      ip,
      deviceId,
      ddb: deps.dynamo,
    });
    velocityPromise.catch(() => {});
    const timeoutMs = deps.timeoutMs ?? DEFAULT_VELOCITY_TIMEOUT_MS;
    const snapshot: IpVelocitySnapshot | null = await Promise.race([
      velocityPromise,
      new Promise<null>((resolve) =>
        setTimeout(() => resolve(null), timeoutMs),
      ),
    ]);
    return snapshot ? { ...item, ip_velocity_1h: snapshot } : item;
  } catch (error) {
    ctx.deps.logger.warn(
      "ip-velocity snapshot failed; persisting row without it",
      { error, session_id: ctx.sessionId },
    );
    return item;
  }
}

interface BumpIpVelocityBlockedInput {
  ctx: IpVelocityContext;
  item: Record<string, unknown>;
  deps: IpVelocityEnrichmentDeps;
}

/** Increment the velocity bucket only after projection produces `block`. */
export async function bumpIpVelocityBlocked(
  input: BumpIpVelocityBlockedInput,
): Promise<void> {
  const { ctx, item, deps } = input;
  const projection = (item as { merchant_projection?: { verdict?: string } })
    .merchant_projection;
  if (projection?.verdict !== "block") return;
  const velocity = (
    item as { ip_velocity_1h?: { ip?: string; bucket?: string } }
  ).ip_velocity_1h;
  if (!velocity?.ip || !velocity.bucket) return;

  try {
    await bumpVelocityBlocked({
      ip: velocity.ip,
      bucket: velocity.bucket,
      ddb: deps.dynamo,
    });
  } catch (error) {
    ctx.deps.logger.warn("ip-velocity blocked bump failed", {
      error,
      session_id: ctx.sessionId,
    });
  }
}
