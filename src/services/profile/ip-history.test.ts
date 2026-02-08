import { describe, it, expect } from "vitest";
import {
  updateIpHistory,
  hasSeenIp,
  hasSeenAsn,
  countRecentUniqueIps,
  countRecentUniqueAsns,
  computeIpConfidenceModifier,
} from "./ip-history";
import type { IpHistoryEntry } from "../../types/profile";
import type { Fingerprint } from "../../types/fingerprint";

const now = Date.now();
const ONE_HOUR = 60 * 60 * 1000;
const TWENTY_FIVE_HOURS = 25 * 60 * 60 * 1000;

function entry(ip: string, asn: number, ts = now): IpHistoryEntry {
  return { ip, asn, ts };
}

describe("updateIpHistory", () => {
  it("should add a new entry to an empty history", () => {
    const result = updateIpHistory([], "1.1.1.1", 100, now);
    expect(result).toEqual([{ ip: "1.1.1.1", asn: 100, ts: now }]);
  });

  it("should prepend new entries (newest first)", () => {
    const existing = [entry("1.1.1.1", 100, now - ONE_HOUR)];
    const result = updateIpHistory(existing, "2.2.2.2", 200, now);
    expect(result[0].ip).toBe("2.2.2.2");
    expect(result[1].ip).toBe("1.1.1.1");
  });

  it("should deduplicate by IP+ASN and update timestamp", () => {
    const existing = [entry("1.1.1.1", 100, now - ONE_HOUR)];
    const result = updateIpHistory(existing, "1.1.1.1", 100, now);
    expect(result).toHaveLength(1);
    expect(result[0].ts).toBe(now);
  });

  it("should not deduplicate same IP with different ASN", () => {
    const existing = [entry("1.1.1.1", 100)];
    const result = updateIpHistory(existing, "1.1.1.1", 200, now);
    expect(result).toHaveLength(2);
  });

  it("should limit to MAX_HISTORY_ENTRIES (10)", () => {
    const existing = Array.from({ length: 10 }, (_, i) =>
      entry(`10.0.0.${i}`, i, now - i * ONE_HOUR),
    );
    const result = updateIpHistory(existing, "99.99.99.99", 999, now);
    expect(result).toHaveLength(10);
    expect(result[0].ip).toBe("99.99.99.99");
  });
});

describe("hasSeenIp", () => {
  const history = [entry("1.1.1.1", 100), entry("2.2.2.2", 200)];

  it("should return true for known IP", () => {
    expect(hasSeenIp(history, "1.1.1.1")).toBe(true);
  });

  it("should return false for unknown IP", () => {
    expect(hasSeenIp(history, "3.3.3.3")).toBe(false);
  });

  it("should return false for empty history", () => {
    expect(hasSeenIp([], "1.1.1.1")).toBe(false);
  });
});

describe("hasSeenAsn", () => {
  const history = [entry("1.1.1.1", 100), entry("2.2.2.2", 200)];

  it("should return true for known ASN", () => {
    expect(hasSeenAsn(history, 100)).toBe(true);
  });

  it("should return false for unknown ASN", () => {
    expect(hasSeenAsn(history, 999)).toBe(false);
  });
});

describe("countRecentUniqueIps", () => {
  it("should count unique IPs within 24 hours", () => {
    const history = [
      entry("1.1.1.1", 100, now - ONE_HOUR),
      entry("2.2.2.2", 200, now - 2 * ONE_HOUR),
      entry("1.1.1.1", 200, now - 3 * ONE_HOUR), // dup IP
    ];
    expect(countRecentUniqueIps(history, now)).toBe(2);
  });

  it("should exclude entries older than 24 hours", () => {
    const history = [
      entry("1.1.1.1", 100, now - ONE_HOUR),
      entry("2.2.2.2", 200, now - TWENTY_FIVE_HOURS),
    ];
    expect(countRecentUniqueIps(history, now)).toBe(1);
  });

  it("should return 0 for empty history", () => {
    expect(countRecentUniqueIps([], now)).toBe(0);
  });
});

describe("countRecentUniqueAsns", () => {
  it("should count unique ASNs within 24 hours", () => {
    const history = [
      entry("1.1.1.1", 100, now - ONE_HOUR),
      entry("2.2.2.2", 200, now - 2 * ONE_HOUR),
      entry("3.3.3.3", 100, now - 3 * ONE_HOUR), // dup ASN
    ];
    expect(countRecentUniqueAsns(history, now)).toBe(2);
  });

  it("should exclude entries older than 24 hours", () => {
    const history = [
      entry("1.1.1.1", 100, now - ONE_HOUR),
      entry("2.2.2.2", 200, now - TWENTY_FIVE_HOURS),
    ];
    expect(countRecentUniqueAsns(history, now)).toBe(1);
  });
});

describe("computeIpConfidenceModifier", () => {
  it("should return 0 adjustment when profile is null", () => {
    const fp = { ip_address: "1.1.1.1" } as Fingerprint;
    expect(computeIpConfidenceModifier(null, fp)).toEqual({ adjustment: 0 });
  });

  it("should return 0 adjustment when ip_history is empty", () => {
    const profile = { ip_history: [] } as any;
    const fp = { ip_address: "1.1.1.1" } as Fingerprint;
    expect(computeIpConfidenceModifier(profile, fp)).toEqual({ adjustment: 0 });
  });

  it("should return 0 adjustment when fingerprint has no ip_address", () => {
    const profile = { ip_history: [entry("1.1.1.1", 100)] } as any;
    const fp = {} as Fingerprint;
    expect(computeIpConfidenceModifier(profile, fp)).toEqual({ adjustment: 0 });
  });

  it("should return +0.02 for known IP", () => {
    const profile = { ip_history: [entry("1.1.1.1", 100)] } as any;
    const fp = { ip_address: "1.1.1.1" } as Fingerprint;
    expect(computeIpConfidenceModifier(profile, fp)).toEqual({
      adjustment: 0.02,
    });
  });

  it("should return 0 for unknown IP but known ASN", () => {
    const profile = { ip_history: [entry("1.1.1.1", 100)] } as any;
    const fp = { ip_address: "2.2.2.2", asn: 100 } as Fingerprint;
    expect(computeIpConfidenceModifier(profile, fp)).toEqual({ adjustment: 0 });
  });

  it("should return -0.05 for unknown IP and unknown ASN", () => {
    const profile = { ip_history: [entry("1.1.1.1", 100)] } as any;
    const fp = { ip_address: "2.2.2.2", asn: 999 } as Fingerprint;
    expect(computeIpConfidenceModifier(profile, fp)).toEqual({
      adjustment: -0.05,
    });
  });

  it("should return -0.05 when ASN is undefined", () => {
    const profile = { ip_history: [entry("1.1.1.1", 100)] } as any;
    const fp = { ip_address: "2.2.2.2" } as Fingerprint;
    expect(computeIpConfidenceModifier(profile, fp)).toEqual({
      adjustment: -0.05,
    });
  });
});
