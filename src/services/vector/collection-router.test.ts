import { describe, it, expect } from "vitest";
import { routeFingerprint } from "./collection-router";
import type { Fingerprint } from "../../types/fingerprint";

function fp(overrides: Partial<Fingerprint> = {}): Fingerprint {
  return { stable_hash: "abc", ...overrides };
}

describe("routeFingerprint", () => {
  it("routes iPhone to ios collection", () => {
    const result = routeFingerprint(fp({ platform: "iPhone" }), "fp_v13");
    expect(result.os).toBe("ios");
    expect(result.collection).toBe("fp_v13_ios");
    expect(result.weights).toHaveLength(512);
    expect(result.threshold).toBe(0.96);
  });

  it("routes Android UA to android collection", () => {
    const result = routeFingerprint(
      fp({ user_agent: "Mozilla/5.0 (Linux; Android 14)" }),
      "fp_v13",
    );
    expect(result.os).toBe("android");
    expect(result.collection).toBe("fp_v13_android");
  });

  it("routes Windows UA to windows collection", () => {
    const result = routeFingerprint(
      fp({ user_agent: "Mozilla/5.0 (Windows NT 10.0)" }),
      "fp_v13",
    );
    expect(result.os).toBe("windows");
    expect(result.collection).toBe("fp_v13_windows");
  });

  it("routes Mac UA to mac collection", () => {
    const result = routeFingerprint(
      fp({ user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" }),
      "fp_v13",
    );
    expect(result.os).toBe("mac");
    expect(result.collection).toBe("fp_v13_mac");
  });

  it("routes unknown OS to linux collection (baseline)", () => {
    const result = routeFingerprint(fp({}), "fp_v13");
    expect(result.os).toBe("linux");
    expect(result.collection).toBe("fp_v13_linux");
    // Linux weights are all 1.0
    expect(result.weights.every((w) => w === 1.0)).toBe(true);
  });

  it("uses the provided prefix in collection name", () => {
    const result = routeFingerprint(fp({ platform: "iPhone" }), "test_prefix");
    expect(result.collection).toBe("test_prefix_ios");
  });

  it("returns OS-specific weights (not baseline for non-linux)", () => {
    const ios = routeFingerprint(fp({ platform: "iPhone" }), "p");
    const linux = routeFingerprint(fp({}), "p");
    // iOS weights should differ from baseline
    const different = ios.weights.some((w, i) => w !== linux.weights[i]);
    expect(different).toBe(true);
  });
});
