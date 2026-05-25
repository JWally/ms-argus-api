import { describe, it, expect } from "vitest";
import {
  analyzeWorkerScopes,
  WORKER_ORACLE_MAIN_ONLY,
  WORKER_ORACLE_NO_SHARED,
} from "./index";

// Realistic, identical scope values so pairsDiverge has nothing to flag.
// `languages` deliberately omitted — see worker-scope-oracle-omission.mjs
// PoC comments: detectCrossFieldAnomalies compares arrays by reference,
// which would false-positive on identical-content arrays post-JSON.
const SCOPE = {
  userAgent: "Mozilla/5.0 X",
  platform: "MacIntel",
  hardwareConcurrency: 8,
  deviceMemory: 8,
  webglRenderer: "ANGLE (Apple)",
  webglVendor: "Google Inc. (Apple)",
  webgl2Renderer: "ANGLE (Apple)",
  webgl2Vendor: "Google Inc. (Apple)",
  appVersion: "5.0 X",
  product: "Gecko",
  onLine: true,
};

const NAV = { ...SCOPE, languages: ["en-US", "en"] };

describe("analyzeWorkerScopes — oracle availability scoring", () => {
  it("device.workerScope absent entirely → WORKER_ORACLE_MAIN_ONLY, lied=true", () => {
    const r = analyzeWorkerScopes({ navigator: NAV });
    expect(r.lied).toBe(true);
    const codes = r.signals.map((s) => s.code);
    expect(codes).toContain(WORKER_ORACLE_MAIN_ONLY);
    expect(r.divergences).toEqual([]);
  });

  it("scopes = {main} only → WORKER_ORACLE_MAIN_ONLY, lied=true", () => {
    const r = analyzeWorkerScopes({
      navigator: NAV,
      workerScope: { scopes: { main: SCOPE } },
    });
    expect(r.lied).toBe(true);
    expect(r.signals.some((s) => s.code === WORKER_ORACLE_MAIN_ONLY)).toBe(
      true,
    );
    expect(r.signals.some((s) => s.code === WORKER_ORACLE_NO_SHARED)).toBe(
      false,
    );
  });

  it("scopes = {main, web} (no shared) → WORKER_ORACLE_NO_SHARED, lied=true", () => {
    const r = analyzeWorkerScopes({
      navigator: NAV,
      workerScope: { scopes: { main: SCOPE, web: SCOPE } },
    });
    expect(r.lied).toBe(true);
    expect(r.signals.some((s) => s.code === WORKER_ORACLE_NO_SHARED)).toBe(
      true,
    );
    expect(r.signals.some((s) => s.code === WORKER_ORACLE_MAIN_ONLY)).toBe(
      false,
    );
  });

  it("scopes = {main, web, shared} all matching → no oracle signal, lied=false", () => {
    const r = analyzeWorkerScopes({
      navigator: NAV,
      workerScope: { scopes: { main: SCOPE, web: SCOPE, shared: SCOPE } },
    });
    expect(r.lied).toBe(false);
    expect(r.signals.some((s) => s.code.startsWith("WORKER_ORACLE_"))).toBe(
      false,
    );
    expect(r.divergences).toEqual([]);
  });

  it("all three present AND a divergence → divergences win, no oracle signal", () => {
    const tampered = { ...SCOPE, userAgent: "Different UA" };
    const r = analyzeWorkerScopes({
      navigator: NAV,
      workerScope: { scopes: { main: SCOPE, web: tampered, shared: SCOPE } },
    });
    expect(r.lied).toBe(true);
    expect(r.divergences.length).toBeGreaterThan(0);
    expect(r.signals.some((s) => s.code.startsWith("WORKER_ORACLE_"))).toBe(
      false,
    );
  });

  it("WORKER_ORACLE_MAIN_ONLY severity is 0.6 (tier-60 in tampering ladder)", () => {
    const r = analyzeWorkerScopes({ navigator: NAV });
    const sig = r.signals.find((s) => s.code === WORKER_ORACLE_MAIN_ONLY);
    expect(sig?.severity).toBe(0.6);
  });

  it("WORKER_ORACLE_NO_SHARED severity is 0.25 (tier-25 in tampering ladder)", () => {
    const r = analyzeWorkerScopes({
      navigator: NAV,
      workerScope: { scopes: { main: SCOPE, web: SCOPE } },
    });
    const sig = r.signals.find((s) => s.code === WORKER_ORACLE_NO_SHARED);
    expect(sig?.severity).toBe(0.25);
  });

  it("non-object device → EMPTY result (no signals)", () => {
    expect(analyzeWorkerScopes(null).lied).toBe(false);
    expect(analyzeWorkerScopes(undefined).lied).toBe(false);
    expect(analyzeWorkerScopes("string").signals).toEqual([]);
  });
});
