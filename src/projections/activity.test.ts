import { describe, expect, it } from "vitest";
import { deriveDeviceHistory, deriveIpVelocity } from "./activity";
import type { MerchantProjectionInput } from "../scoring/shared";

function input(integrity: Record<string, unknown>): MerchantProjectionInput {
  return {
    session_id: "activity-test",
    integrity: integrity as unknown as MerchantProjectionInput["integrity"],
  };
}

describe("activity projection", () => {
  it("returns null for absent temporal activity", () => {
    const empty = { session_id: "activity-test" };
    expect(deriveDeviceHistory(empty)).toBeNull();
    expect(deriveIpVelocity(empty)).toBeNull();
  });

  it("projects device-history flags and finite counters", () => {
    const projected = deriveDeviceHistory(
      input({
        analysis: {
          device_history: {
            tampered: true,
            identityMismatch: false,
            freshDevice: false,
            scanCount: 12,
            ageSeconds: Number.NaN,
            distinctIpCount: 3,
            recent1HourCount: 4,
          },
        },
      }),
    );

    expect(projected).toEqual({
      tampered: true,
      identityMismatch: false,
      freshDevice: false,
      scanCount: 12,
      ageSeconds: 0,
      distinctIpCount: 3,
      distinctCountryCount: 0,
      distinctNetClassCount: 0,
      recent5MinCount: 0,
      recent1HourCount: 4,
      recent24HourCount: 0,
    });
  });

  it("rejects empty and malformed velocity snapshots", () => {
    expect(deriveIpVelocity(input({ ip_velocity_1h: "bad" }))).toBeNull();
    expect(deriveIpVelocity(input({ ip_velocity_1h: { hits: 0 } }))).toBeNull();
  });

  it("derives block rate and the residential proxy flag", () => {
    const projected = deriveIpVelocity(
      input({
        ip_velocity_1h: {
          bucket: "1h:2026071601",
          hits: 40,
          blocked: 3,
          distinct_devices_est: 11,
          first_seen_ms: 100,
          last_seen_ms: 200,
        },
        analysis: { ip: { asn: { category: "residential" } } },
      }),
    );

    expect(projected).toEqual({
      bucket: "1h:2026071601",
      hits: 40,
      blocked: 3,
      distinct_devices_est: 11,
      block_rate: 0.075,
      residential_proxy_suspect: true,
      first_seen_ms: 100,
      last_seen_ms: 200,
    });
  });
});
