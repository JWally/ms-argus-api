import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { IdentityOutcome } from "../../helpers/device-identity";
import type { ArgusPayload } from "../../helpers/payload-schema";

const velocityMocks = vi.hoisted(() => ({
  update: vi.fn(),
  bumpBlocked: vi.fn(),
}));

vi.mock("../../helpers/ip-velocity", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../helpers/ip-velocity")>();
  return {
    ...actual,
    updateIpVelocity: velocityMocks.update,
    bumpVelocityBlocked: velocityMocks.bumpBlocked,
  };
});

import {
  applyIpVelocitySnapshot,
  bumpIpVelocityBlocked,
  type IpVelocityEnrichmentDeps,
  type IpVelocityContext,
} from "./ip-velocity";

const logger = {
  warn: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

const deps = {
  dynamo: {} as DynamoDBClient,
  timeoutMs: 10,
} satisfies IpVelocityEnrichmentDeps;

function makeContext(clientUuid?: string): IpVelocityContext {
  return {
    sessionId: "session-123",
    payload: {
      identifiers: { session_id: "session-123", cpi: "argus_cpi_test" },
      hashes: { stable: "stable", fuzzy: "fuzzy" },
      device: clientUuid ? { client_uuid: clientUuid } : {},
    } as ArgusPayload,
    deps: { logger },
  };
}

function identity(pubkey?: string): IdentityOutcome {
  if (pubkey) {
    return { present: true, verified: true, pubkey, sig_present: true };
  }
  return {
    present: false,
    verified: false,
    pubkey: null,
    sig_present: false,
    reason: "absent",
  };
}

const snapshot = {
  ip: "203.0.113.7",
  bucket: "1h:2026071713",
  hits: 2,
  blocked: 0,
  distinct_devices_est: 2,
  first_seen_ms: 1,
  last_seen_ms: 2,
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("applyIpVelocitySnapshot", () => {
  it("skips enrichment when the record has no client IP", async () => {
    const item = { session_id: "session-123" };

    await expect(
      applyIpVelocitySnapshot({
        ctx: makeContext("client-uuid"),
        item,
        identity: identity("device-pubkey"),
        deps,
      }),
    ).resolves.toBe(item);
    expect(velocityMocks.update).not.toHaveBeenCalled();
  });

  it("skips enrichment when no stable device identifier is available", async () => {
    const item = { client_ip: "203.0.113.7" };

    await expect(
      applyIpVelocitySnapshot({
        ctx: makeContext(),
        item,
        identity: identity(),
        deps,
      }),
    ).resolves.toBe(item);
    expect(velocityMocks.update).not.toHaveBeenCalled();
  });

  it("prefers the device pubkey and stamps the returned snapshot", async () => {
    velocityMocks.update.mockResolvedValueOnce(snapshot);
    const item = { client_ip: "203.0.113.7" };

    const result = await applyIpVelocitySnapshot({
      ctx: makeContext("client-uuid"),
      item,
      identity: identity("device-pubkey"),
      deps,
    });

    expect(velocityMocks.update).toHaveBeenCalledWith({
      ip: "203.0.113.7",
      deviceId: "device-pubkey",
      ddb: deps.dynamo,
    });
    expect(result).toEqual({ ...item, ip_velocity_1h: snapshot });
  });

  it("falls back to client_uuid for legacy identities", async () => {
    velocityMocks.update.mockResolvedValueOnce(snapshot);

    await applyIpVelocitySnapshot({
      ctx: makeContext("legacy-client"),
      item: { client_ip: "203.0.113.7" },
      identity: identity(),
      deps,
    });

    expect(velocityMocks.update).toHaveBeenCalledWith(
      expect.objectContaining({ deviceId: "legacy-client" }),
    );
  });

  it("leaves the record unchanged when velocity is disabled", async () => {
    velocityMocks.update.mockResolvedValueOnce(null);
    const item = { client_ip: "203.0.113.7" };

    await expect(
      applyIpVelocitySnapshot({
        ctx: makeContext("client-uuid"),
        item,
        identity: identity(),
        deps,
      }),
    ).resolves.toBe(item);
  });

  it("fails open when enrichment exceeds its deadline", async () => {
    vi.useFakeTimers();
    velocityMocks.update.mockReturnValueOnce(new Promise(() => {}));
    const item = { client_ip: "203.0.113.7" };
    const pending = applyIpVelocitySnapshot({
      ctx: makeContext("client-uuid"),
      item,
      identity: identity(),
      deps,
    });

    await vi.advanceTimersByTimeAsync(10);

    await expect(pending).resolves.toBe(item);
  });

  it("logs and fails open when enrichment rejects", async () => {
    velocityMocks.update.mockRejectedValueOnce(new Error("velocity down"));
    const item = { client_ip: "203.0.113.7" };

    await expect(
      applyIpVelocitySnapshot({
        ctx: makeContext("client-uuid"),
        item,
        identity: identity(),
        deps,
      }),
    ).resolves.toBe(item);
    expect(logger.warn).toHaveBeenCalledWith(
      "ip-velocity snapshot failed; persisting row without it",
      expect.objectContaining({ session_id: "session-123" }),
    );
  });
});

describe("bumpIpVelocityBlocked", () => {
  it("does nothing for non-block verdicts", async () => {
    await bumpIpVelocityBlocked({
      ctx: makeContext(),
      item: { merchant_projection: { verdict: "suspect" } },
      deps,
    });

    expect(velocityMocks.bumpBlocked).not.toHaveBeenCalled();
  });

  it("does nothing when the velocity bucket is incomplete", async () => {
    await bumpIpVelocityBlocked({
      ctx: makeContext(),
      item: {
        merchant_projection: { verdict: "block" },
        ip_velocity_1h: { ip: "203.0.113.7" },
      },
      deps,
    });

    expect(velocityMocks.bumpBlocked).not.toHaveBeenCalled();
  });

  it("increments the exact IP bucket for block verdicts", async () => {
    velocityMocks.bumpBlocked.mockResolvedValueOnce(undefined);

    await bumpIpVelocityBlocked({
      ctx: makeContext(),
      item: {
        merchant_projection: { verdict: "block" },
        ip_velocity_1h: snapshot,
      },
      deps,
    });

    expect(velocityMocks.bumpBlocked).toHaveBeenCalledWith({
      ip: snapshot.ip,
      bucket: snapshot.bucket,
      ddb: deps.dynamo,
    });
  });

  it("logs and remains non-fatal when the blocked increment rejects", async () => {
    velocityMocks.bumpBlocked.mockRejectedValueOnce(new Error("bump down"));

    await expect(
      bumpIpVelocityBlocked({
        ctx: makeContext(),
        item: {
          merchant_projection: { verdict: "block" },
          ip_velocity_1h: snapshot,
        },
        deps,
      }),
    ).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(
      "ip-velocity blocked bump failed",
      expect.objectContaining({ session_id: "session-123" }),
    );
  });
});
