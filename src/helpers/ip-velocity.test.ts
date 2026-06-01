import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DynamoDBClient,
  GetItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import {
  deviceHashFor,
  hourBucket,
  pickDeviceId,
  updateIpVelocity,
} from "./ip-velocity";
import { Hll } from "./hll";

const ORIGINAL_ENV = process.env.IP_VELOCITY_TABLE;

beforeEach(() => {
  process.env.IP_VELOCITY_TABLE = "test-ip-velocity";
});

afterEach(() => {
  if (ORIGINAL_ENV) process.env.IP_VELOCITY_TABLE = ORIGINAL_ENV;
  else delete process.env.IP_VELOCITY_TABLE;
});

describe("hourBucket", () => {
  it("formats the bucket label deterministically", () => {
    // 2026-05-29 14:37:01 UTC → 1h:2026052914
    const ms = Date.UTC(2026, 4, 29, 14, 37, 1);
    expect(hourBucket(ms)).toBe("1h:2026052914");
  });

  it("rounds down to the hour, ignores minutes/seconds", () => {
    const a = hourBucket(Date.UTC(2026, 4, 29, 14, 0, 0));
    const b = hourBucket(Date.UTC(2026, 4, 29, 14, 59, 59));
    expect(a).toBe(b);
  });
});

describe("pickDeviceId", () => {
  it("prefers pubkey over client_uuid", () => {
    expect(pickDeviceId("pk-abc", "uuid-xyz")).toBe("pk-abc");
  });
  it("falls back to client_uuid", () => {
    expect(pickDeviceId(null, "uuid-xyz")).toBe("uuid-xyz");
    expect(pickDeviceId("", "uuid-xyz")).toBe("uuid-xyz");
  });
  it("returns null when neither present", () => {
    expect(pickDeviceId(null, null)).toBeNull();
    expect(pickDeviceId(undefined, "")).toBeNull();
  });
});

describe("updateIpVelocity", () => {
  it("returns null when env is unconfigured", async () => {
    delete process.env.IP_VELOCITY_TABLE;
    const ddb = { send: vi.fn() } as unknown as DynamoDBClient;
    const r = await updateIpVelocity({
      ip: "1.2.3.4",
      deviceId: "pk-1",
      ddb,
    });
    expect(r).toBeNull();
  });

  it("first-visit path: empty Get, UpdateItem ALL_NEW returns hits=1", async () => {
    const NOW = Date.UTC(2026, 4, 29, 14, 0, 0);
    const ddb = {
      send: vi
        .fn()
        // Get returns no item
        .mockResolvedValueOnce({})
        // Update returns the new attributes
        .mockResolvedValueOnce({
          Attributes: {
            hits: { N: "1" },
            blocked: { N: "0" },
            first_seen_ms: { N: String(NOW) },
            last_seen_ms: { N: String(NOW) },
          },
        }),
    } as unknown as DynamoDBClient;

    const snap = await updateIpVelocity({
      ip: "1.2.3.4",
      deviceId: "pk-first-visit",
      ddb,
      nowMs: NOW,
    });

    expect(snap).not.toBeNull();
    expect(snap!.hits).toBe(1);
    expect(snap!.blocked).toBe(0);
    expect(snap!.distinct_devices_est).toBe(1);
    expect(snap!.bucket).toBe("1h:2026052914");
    const sendMock = ddb.send as unknown as ReturnType<typeof vi.fn>;
    expect(sendMock).toHaveBeenCalledTimes(2);
    expect(sendMock.mock.calls[0][0]).toBeInstanceOf(GetItemCommand);
    expect(sendMock.mock.calls[1][0]).toBeInstanceOf(UpdateItemCommand);
  });

  it("returning visit: preserves prior HLL distinctness, increments hits", async () => {
    const NOW = Date.UTC(2026, 4, 29, 14, 0, 0);
    // Pre-seed an HLL with 3 prior devices using the same hashing the
    // helper will use, so re-adding "device-A" is recognised as the
    // same register-position hit.
    const priorHll = Hll.empty();
    priorHll.add(deviceHashFor("device-A"));
    priorHll.add(deviceHashFor("device-B"));
    priorHll.add(deviceHashFor("device-C"));

    const ddb = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          Item: { hll_devices: { B: priorHll.toBytes() } },
        })
        .mockResolvedValueOnce({
          Attributes: {
            hits: { N: "4" },
            blocked: { N: "1" },
            first_seen_ms: { N: String(NOW - 30 * 60 * 1000) },
            last_seen_ms: { N: String(NOW) },
          },
        }),
    } as unknown as DynamoDBClient;

    const snap = await updateIpVelocity({
      ip: "1.2.3.4",
      deviceId: "device-D", // new device, should tick distinct to 4
      ddb,
      nowMs: NOW,
    });

    expect(snap!.hits).toBe(4);
    expect(snap!.blocked).toBe(1);
    expect(snap!.distinct_devices_est).toBe(4);
  });

  it("duplicate device on returning visit: distinct stays the same", async () => {
    const NOW = Date.UTC(2026, 4, 29, 14, 0, 0);
    const priorHll = Hll.empty();
    priorHll.add(deviceHashFor("device-A"));
    priorHll.add(deviceHashFor("device-B"));

    const ddb = {
      send: vi
        .fn()
        .mockResolvedValueOnce({
          Item: { hll_devices: { B: priorHll.toBytes() } },
        })
        .mockResolvedValueOnce({
          Attributes: {
            hits: { N: "10" },
            blocked: { N: "0" },
            first_seen_ms: { N: String(NOW) },
            last_seen_ms: { N: String(NOW) },
          },
        }),
    } as unknown as DynamoDBClient;

    const snap = await updateIpVelocity({
      ip: "1.2.3.4",
      deviceId: "device-A", // already in HLL
      ddb,
      nowMs: NOW,
    });

    // Hits ticks from server side; distinct stays at 2.
    expect(snap!.hits).toBe(10);
    expect(snap!.distinct_devices_est).toBe(2);
  });
});
