import { describe, it, expect } from "vitest";
import { detectCrossFieldAnomalies } from "./worker-scope-consistency";
import type { Fingerprint } from "../../../types";

const FP = {} as Fingerprint;

const HONEST_NAV = {
  userAgent: "Mozilla/5.0 Chrome/147",
  platform: "MacIntel",
  hardwareConcurrency: 8,
  deviceMemory: 16,
  languages: "en-US,en",
  webglRenderer: "Apple GPU",
  webglVendor: "Apple",
  webgl2Renderer: "Apple GPU",
  webgl2Vendor: "Apple",
};

describe("detectCrossFieldAnomalies", () => {
  it("returns no signals when raw is missing or non-object", () => {
    expect(detectCrossFieldAnomalies(FP)).toEqual([]);
    expect(detectCrossFieldAnomalies(FP, undefined)).toEqual([]);
    expect(detectCrossFieldAnomalies(FP, null)).toEqual([]);
    expect(detectCrossFieldAnomalies(FP, "string")).toEqual([]);
    expect(detectCrossFieldAnomalies(FP, 42)).toEqual([]);
  });

  it("returns no signals for a device with only navigator (no workers)", () => {
    expect(detectCrossFieldAnomalies(FP, { navigator: HONEST_NAV })).toEqual(
      [],
    );
  });

  it("returns no signals when navigator and dedicated worker agree", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: { scopes: { web: { ...HONEST_NAV } } },
    };
    expect(detectCrossFieldAnomalies(FP, raw)).toEqual([]);
  });

  it("does NOT flag identical-content arrays across scopes (regression)", () => {
    // Pre-2026-05-25 the comparison used `v1 !== v2` which is reference
    // equality on arrays. Distinct array literals with identical contents
    // (the post-JSON-deserialize shape on the server) fired
    // WORKER_MISMATCH on every legitimate session whose `languages`
    // array shipped on both navigator and worker scopes. Now
    // canonicalized via JSON for arrays.
    const raw = {
      navigator: { ...HONEST_NAV, languages: ["en-US", "en"] },
      workerScope: {
        scopes: { web: { ...HONEST_NAV, languages: ["en-US", "en"] } },
      },
    };
    expect(detectCrossFieldAnomalies(FP, raw)).toEqual([]);
  });

  it("flags arrays with different contents", () => {
    const raw = {
      navigator: { ...HONEST_NAV, languages: ["en-US", "en"] },
      workerScope: {
        scopes: { web: { ...HONEST_NAV, languages: ["fr-FR", "fr"] } },
      },
    };
    const signals = detectCrossFieldAnomalies(FP, raw);
    expect(signals.length).toBeGreaterThan(0);
    expect(signals.some((s) => s.code === "WORKER_MISMATCH")).toBe(true);
  });

  it("flags userAgent mismatch between navigator and dedicated worker", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: {
        scopes: { web: { ...HONEST_NAV, userAgent: "Mozilla/5.0 Spoof/1.0" } },
      },
    };
    const signals = detectCrossFieldAnomalies(FP, raw);
    expect(signals).toHaveLength(1);
    expect(signals[0].code).toBe("WORKER_MISMATCH");
    expect(signals[0].severity).toBe(0.8);
    expect(signals[0].evidence.fields).toEqual([
      "navigator.userAgent",
      "dedicatedWorker.userAgent",
    ]);
  });

  it("flags platform mismatch with severity 0.75", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: {
        scopes: { web: { ...HONEST_NAV, platform: "Win32" } },
      },
    };
    const sigs = detectCrossFieldAnomalies(FP, raw);
    expect(sigs).toHaveLength(1);
    expect(sigs[0].severity).toBe(0.75);
    expect(sigs[0].evidence.actual).toContain("MacIntel");
    expect(sigs[0].evidence.actual).toContain("Win32");
  });

  it("flags multiple fields per scope pair", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: {
        scopes: {
          web: {
            ...HONEST_NAV,
            userAgent: "spoof",
            platform: "Win32",
            hardwareConcurrency: 4,
          },
        },
      },
    };
    const sigs = detectCrossFieldAnomalies(FP, raw);
    expect(sigs).toHaveLength(3);
    expect(sigs.map((s) => s.severity)).toEqual([0.8, 0.75, 0.7]);
  });

  it("compares each pair of scopes (navigator vs web vs shared vs service)", () => {
    const raw = {
      navigator: { userAgent: "A" },
      workerScope: {
        scopes: {
          web: { userAgent: "B" },
          shared: { userAgent: "C" },
          service: { userAgent: "A" },
        },
      },
    };
    // Pairs: (navigator,web)=A!=B, (navigator,shared)=A!=C, (navigator,service)=A==A,
    //        (web,shared)=B!=C, (web,service)=B!=A, (shared,service)=C!=A
    // → 5 mismatches
    const sigs = detectCrossFieldAnomalies(FP, raw);
    expect(sigs).toHaveLength(5);
  });

  it("ignores fields where one side is undefined (only compares present-on-both)", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: {
        scopes: { web: { userAgent: HONEST_NAV.userAgent } },
        // dedicated worker only reports userAgent — other fields undefined
      },
    };
    expect(detectCrossFieldAnomalies(FP, raw)).toEqual([]);
  });

  it("supports the legacy top-level workerScope shape (no nested scopes)", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: {
        userAgent: "Mozilla/5.0 Spoof/1.0",
        platform: HONEST_NAV.platform,
        hardwareConcurrency: HONEST_NAV.hardwareConcurrency,
      },
    };
    const sigs = detectCrossFieldAnomalies(FP, raw);
    expect(sigs).toHaveLength(1);
    expect(sigs[0].evidence.fields).toEqual([
      "navigator.userAgent",
      "workerScope.userAgent",
    ]);
  });

  it("ignores the legacy workerScope when navigator is absent", () => {
    const raw = {
      workerScope: { userAgent: "x", platform: "y" },
    };
    expect(detectCrossFieldAnomalies(FP, raw)).toEqual([]);
  });

  it("ignores the legacy workerScope when it has no identifying fields", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: { someUnrelated: "value" },
    };
    expect(detectCrossFieldAnomalies(FP, raw)).toEqual([]);
  });

  it("ignores nested-scopes entries that aren't objects", () => {
    const raw = {
      navigator: HONEST_NAV,
      workerScope: { scopes: { web: null, shared: "string", service: 42 } },
    };
    expect(detectCrossFieldAnomalies(FP, raw)).toEqual([]);
  });

  it("truncates long evidence values to 50 chars", () => {
    const long = "a".repeat(120);
    const raw = {
      navigator: { userAgent: long },
      workerScope: { scopes: { web: { userAgent: "different" } } },
    };
    const sigs = detectCrossFieldAnomalies(FP, raw);
    expect(sigs[0].evidence.actual.length).toBeLessThan(120);
    expect(sigs[0].evidence.actual).toContain("...");
  });

  it("renders undefined values as '(undefined)' in evidence", () => {
    // Exercise the truncate(undefined) branch via a custom shape where the
    // legacy worker has an explicit undefined platform but matches userAgent.
    // Cross-pair compares only present-on-both, so we instead exercise via
    // the navigator side having `null` against worker's value.
    const raw = {
      navigator: { userAgent: null as unknown as string },
      workerScope: {
        scopes: { web: { userAgent: "real" } },
      },
    };
    const sigs = detectCrossFieldAnomalies(FP, raw);
    expect(sigs).toHaveLength(1);
    expect(sigs[0].evidence.actual).toContain("(undefined)");
  });
});
