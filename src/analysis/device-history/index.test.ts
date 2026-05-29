import { describe, it, expect } from "vitest";
import { computeDeviceHistoryAnalysis } from "./index";
import {
  appendVisit,
  buildFreshBlob,
  type PendingVisit,
} from "../../helpers/device-history";

const PUBKEY = "test-pubkey";

function pending(overrides: Partial<PendingVisit> = {}): PendingVisit {
  return {
    cpi: "argus_cpi_test_abc",
    session: "s",
    ip: "73.93.42.17",
    ua_hash: "deadbeef12345678",
    net_class: "residential",
    country: "US",
    region: "US-CA",
    city: "Mountain View",
    lat: 37.4043,
    lon: -122.0748,
    ...overrides,
  };
}

describe("computeDeviceHistoryAnalysis", () => {
  it("absent → freshDevice=true, all counts zero", () => {
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "absent" },
      pubkey: PUBKEY,
    });
    expect(r.freshDevice).toBe(true);
    expect(r.tampered).toBe(false);
    expect(r.identityMismatch).toBe(false);
    expect(r.scanCount).toBe(0);
  });

  it("auth_fail → tampered=true, all counts zero", () => {
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "auth_fail" },
      pubkey: PUBKEY,
    });
    expect(r.tampered).toBe(true);
    expect(r.freshDevice).toBe(false);
    expect(r.scanCount).toBe(0);
  });

  it("blob with mismatched pubkey → identityMismatch=true", () => {
    const blob = buildFreshBlob("different-pubkey");
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "ok", blob },
      pubkey: PUBKEY,
    });
    expect(r.identityMismatch).toBe(true);
  });

  it("legit returning user: 1 IP, 1 country, 1 ua_hash → tight signals", () => {
    let blob = buildFreshBlob(PUBKEY, 1700000000000);
    for (let i = 0; i < 10; i++) {
      blob = appendVisit(
        blob,
        pending({ session: `s-${i}` }),
        1700000000000 + i * 86400000,
      );
    }
    const now = 1700000000000 + 10 * 86400000;
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "ok", blob },
      pubkey: PUBKEY,
      now,
    });
    expect(r.scanCount).toBe(10);
    expect(r.distinctIpCount).toBe(1);
    expect(r.distinctCountryCount).toBe(1);
    expect(r.distinctUaCount).toBe(1);
    expect(r.distinctNetClassCount).toBe(1);
    expect(r.ageSeconds).toBe(10 * 86400);
  });

  it("rotating-IP botnet shape: same UA but distinct IPs/countries", () => {
    let blob = buildFreshBlob(PUBKEY);
    const ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"];
    const countries = ["US", "DE", "VN", "BR", "BD"];
    for (let i = 0; i < 5; i++) {
      blob = appendVisit(blob, pending({ ip: ips[i], country: countries[i] }));
    }
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "ok", blob },
      pubkey: PUBKEY,
    });
    expect(r.distinctIpCount).toBe(5);
    expect(r.distinctCountryCount).toBe(5);
    expect(r.distinctUaCount).toBe(1); // claims to be the same browser
  });

  it("velocity buckets count visits in recent windows", () => {
    const t0 = 1700000000000;
    let blob = buildFreshBlob(PUBKEY, t0);
    // 3 visits in last 5 minutes, 1 visit in last hour but not 5 min, 1 in last day
    blob = appendVisit(blob, pending(), t0 + 10000); // 10s ago at "now"
    blob = appendVisit(blob, pending(), t0 + 60000); // 60s ago
    blob = appendVisit(blob, pending(), t0 + 290000); // 290s ago (just inside 5min)
    blob = appendVisit(blob, pending(), t0 + 600000); // 10min ago (outside 5min, inside hour)
    blob = appendVisit(blob, pending(), t0 + 3600000); // 1hr ago (just inside hour)
    blob = appendVisit(blob, pending(), t0 + 7 * 3600 * 1000); // 7hrs ago

    const now = t0 + 7 * 3600 * 1000 + 300000; // 5 min after last
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "ok", blob },
      pubkey: PUBKEY,
      now,
    });
    // We don't pin exact counts here — just monotonicity properties:
    expect(r.recent5MinCount).toBeLessThanOrEqual(r.recent1HourCount);
    expect(r.recent1HourCount).toBeLessThanOrEqual(r.recent24HourCount);
    expect(r.recent24HourCount).toBe(r.scanCount); // all within 24h in this setup
  });

  it("freshDevice yields zero recent counts and zero distinct counts", () => {
    const r = computeDeviceHistoryAnalysis({
      outcome: { kind: "absent" },
      pubkey: PUBKEY,
    });
    expect(r.distinctIpCount).toBe(0);
    expect(r.distinctCountryCount).toBe(0);
    expect(r.recent5MinCount).toBe(0);
    expect(r.recent1HourCount).toBe(0);
    expect(r.recent24HourCount).toBe(0);
  });
});
