import { afterEach, describe, expect, it } from "vitest";
import {
  isAppleRelayIp,
  lookupAppleRelaySync,
  _resetAppleRelayForTesting,
  _seedAppleRelayForTesting,
} from "./apple-relay";

afterEach(() => {
  _resetAppleRelayForTesting();
});

describe("apple-relay lookup", () => {
  it("returns false before prewarm / when cache is empty", () => {
    expect(isAppleRelayIp("146.75.248.145")).toBe(false);
    expect(lookupAppleRelaySync("146.75.248.145")).toBe(null);
  });

  it("matches the Cumming, GA egress block (146.75.248.144/31) and surfaces metadata", () => {
    _seedAppleRelayForTesting([
      {
        cidr: "146.75.248.144/31",
        country: "US",
        region: "US-GA",
        city: "CUMMING",
      },
    ]);
    expect(isAppleRelayIp("146.75.248.144")).toBe(true);
    expect(isAppleRelayIp("146.75.248.145")).toBe(true);
    // boundary outside the /31
    expect(isAppleRelayIp("146.75.248.146")).toBe(false);
    expect(lookupAppleRelaySync("146.75.248.145")).toEqual({
      country: "US",
      region: "US-GA",
      city: "CUMMING",
    });
  });

  it("returns false for IPs not in any seeded range", () => {
    _seedAppleRelayForTesting([
      { cidr: "146.75.248.144/31", country: "US", city: "CUMMING" },
    ]);
    expect(isAppleRelayIp("8.8.8.8")).toBe(false);
    expect(isAppleRelayIp("1.1.1.1")).toBe(false);
  });

  it("handles null / empty IP gracefully", () => {
    _seedAppleRelayForTesting([
      { cidr: "146.75.248.144/31", country: "US", city: "CUMMING" },
    ]);
    expect(isAppleRelayIp(null)).toBe(false);
    expect(isAppleRelayIp(undefined)).toBe(false);
    expect(isAppleRelayIp("")).toBe(false);
  });
});
