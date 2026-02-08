import { describe, it, expect } from "vitest";
import { detectIpHistoryAnomalies } from "./ip-history-detector";
import type { Fingerprint } from "../../../types/fingerprint";
import type { DeviceProfile } from "../../../types/profile";
import type { IpHistoryEntry } from "../../../types/profile";
import { AnomalyCodes } from "./types";

const now = Date.now();
const ONE_HOUR = 60 * 60 * 1000;

function entry(ip: string, asn: number, ts = now): IpHistoryEntry {
  return { ip, asn, ts };
}

describe("detectIpHistoryAnomalies", () => {
  it("should return empty signals when profile is null", () => {
    const fp = { ip_address: "1.1.1.1", asn: 100 } as Fingerprint;
    expect(detectIpHistoryAnomalies(fp, null)).toEqual([]);
  });

  it("should return empty signals when ip_history is empty", () => {
    const fp = { ip_address: "1.1.1.1", asn: 100 } as Fingerprint;
    const profile = { ip_history: [] } as unknown as DeviceProfile;
    expect(detectIpHistoryAnomalies(fp, profile)).toEqual([]);
  });

  it("should return empty signals when fingerprint has no ip_address", () => {
    const fp = {} as Fingerprint;
    const profile = {
      ip_history: [entry("1.1.1.1", 100)],
    } as unknown as DeviceProfile;
    expect(detectIpHistoryAnomalies(fp, profile)).toEqual([]);
  });

  it("should detect NEW_ASN_FOR_DEVICE when ASN is unknown", () => {
    const fp = { ip_address: "2.2.2.2", asn: 999 } as Fingerprint;
    const profile = {
      ip_history: [entry("1.1.1.1", 100)],
    } as unknown as DeviceProfile;

    const signals = detectIpHistoryAnomalies(fp, profile);
    expect(signals).toHaveLength(1);
    expect(signals[0].code).toBe(AnomalyCodes.NEW_ASN_FOR_DEVICE);
    expect(signals[0].severity).toBe(0.3);
  });

  it("should not flag NEW_ASN when ASN is known", () => {
    const fp = { ip_address: "2.2.2.2", asn: 100 } as Fingerprint;
    const profile = {
      ip_history: [entry("1.1.1.1", 100)],
    } as unknown as DeviceProfile;

    const signals = detectIpHistoryAnomalies(fp, profile);
    expect(signals).toHaveLength(0);
  });

  it("should not flag NEW_ASN when ASN is undefined", () => {
    const fp = { ip_address: "2.2.2.2" } as Fingerprint;
    const profile = {
      ip_history: [entry("1.1.1.1", 100)],
    } as unknown as DeviceProfile;

    const signals = detectIpHistoryAnomalies(fp, profile);
    expect(signals).toHaveLength(0);
  });

  it("should detect IP_CHURN when >= 100 unique IPs in 24h", () => {
    // Create 100 unique IPs all within the last hour
    const history = Array.from({ length: 100 }, (_, i) =>
      entry(`10.0.${Math.floor(i / 256)}.${i % 256}`, 100, now - ONE_HOUR),
    );
    const fp = { ip_address: "99.99.99.99", asn: 100 } as Fingerprint;
    const profile = { ip_history: history } as unknown as DeviceProfile;

    // IP_CHURN check uses countRecentUniqueIps against the history entries
    // The ring buffer normally caps at 10, but for detection purposes this still works
    // with 100 entries in the history (test bypasses ring buffer limit)
    const signals = detectIpHistoryAnomalies(fp, profile);
    const churnSignal = signals.find((s) => s.code === AnomalyCodes.IP_CHURN);
    expect(churnSignal).toBeDefined();
    expect(churnSignal!.severity).toBe(0.5);
  });
});
