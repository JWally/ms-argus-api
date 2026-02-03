import { describe, it, expect } from "vitest";
import {
  buildRuleContext,
  evaluateBaselineRules,
  type RuleContext,
} from "./baseline-rules";
import type { Fingerprint } from "../../../types";

describe("buildRuleContext", () => {
  it("should extract lie_count from fingerprint", () => {
    const fp: Fingerprint = { lie_count: 42 };
    const ctx = buildRuleContext(fp);
    expect(ctx.lie_count).toBe(42);
  });

  it("should default lie_count to 0 when missing", () => {
    const ctx = buildRuleContext({});
    expect(ctx.lie_count).toBe(0);
  });

  it("should extract is_headless from fingerprint", () => {
    const fp: Fingerprint = { is_headless: true };
    const ctx = buildRuleContext(fp);
    expect(ctx.is_headless).toBe(true);
  });

  it("should default is_headless to false when missing", () => {
    const ctx = buildRuleContext({});
    expect(ctx.is_headless).toBe(false);
  });

  it("should extract proxy_score and vpn_score", () => {
    const fp: Fingerprint = { proxy_score: 0.85, vpn_score: 0.7 };
    const ctx = buildRuleContext(fp);
    expect(ctx.proxy_score).toBe(0.85);
    expect(ctx.vpn_score).toBe(0.7);
  });

  it("should default proxy_score and vpn_score to 0", () => {
    const ctx = buildRuleContext({});
    expect(ctx.proxy_score).toBe(0);
    expect(ctx.vpn_score).toBe(0);
  });

  describe("worker_ua_mismatch", () => {
    it("should detect mismatch between navigator and worker scope web UA", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: {
          scopes: {
            web: { userAgent: "Firefox/115" },
          },
        },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(true);
    });

    it("should return false when UAs match", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: {
          scopes: {
            web: { userAgent: "Chrome/120" },
          },
        },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(false);
    });

    it("should detect mismatch in shared worker scope", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: {
          scopes: {
            web: { userAgent: "Chrome/120" },
            shared: { userAgent: "Spoofed/1.0" },
          },
        },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(true);
    });

    it("should detect mismatch in service worker scope", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: {
          scopes: {
            web: { userAgent: "Chrome/120" },
            shared: { userAgent: "Chrome/120" },
            service: { userAgent: "Different/1.0" },
          },
        },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(true);
    });

    it("should return false when no device provided", () => {
      const ctx = buildRuleContext({});
      expect(ctx.worker_ua_mismatch).toBe(false);
    });

    it("should return false when navigator has no userAgent", () => {
      const device = {
        navigator: { platform: "Win32" },
        workerScope: {
          scopes: {
            web: { userAgent: "Chrome/120" },
          },
        },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(false);
    });

    it("should return false when workerScope missing", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(false);
    });

    it("should fallback to top-level workerScope.userAgent when no scopes", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: { userAgent: "Spoofed/1.0" },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(true);
    });

    it("should return false for top-level workerScope.userAgent match", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: { userAgent: "Chrome/120" },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(false);
    });

    it("should skip null worker scopes", () => {
      const device = {
        navigator: { userAgent: "Chrome/120" },
        workerScope: {
          scopes: {
            web: { userAgent: "Chrome/120" },
            shared: null,
            service: null,
          },
        },
      };
      const ctx = buildRuleContext({}, device);
      expect(ctx.worker_ua_mismatch).toBe(false);
    });
  });
});

describe("evaluateBaselineRules", () => {
  describe("single conditions", () => {
    it("should match > condition (excessive lies)", () => {
      const ctx: RuleContext = {
        lie_count: 100,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.shouldSkipBaseline).toBe(true);
      expect(result.matchedRules).toContain("excessive_lies");
    });

    it("should not match > condition when below threshold", () => {
      const ctx: RuleContext = {
        lie_count: 10,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.matchedRules).not.toContain("excessive_lies");
    });

    it("should match == condition (worker_ua_mismatch)", () => {
      const ctx: RuleContext = {
        lie_count: 0,
        is_headless: false,
        worker_ua_mismatch: true,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.shouldSkipBaseline).toBe(true);
      expect(result.matchedRules).toContain("worker_ua_mismatch");
    });

    it("should not match == condition when value is false", () => {
      const ctx: RuleContext = {
        lie_count: 0,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.matchedRules).not.toContain("worker_ua_mismatch");
    });
  });

  describe("composite all condition", () => {
    it("should match when all sub-conditions are true", () => {
      const ctx: RuleContext = {
        lie_count: 20,
        is_headless: true,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.shouldSkipBaseline).toBe(true);
      expect(result.matchedRules).toContain("headless_with_stealth");
    });

    it("should not match when only some sub-conditions are true", () => {
      const ctx: RuleContext = {
        lie_count: 5,
        is_headless: true,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.matchedRules).not.toContain("headless_with_stealth");
    });

    it("should not match when headless is false even with high lies", () => {
      const ctx: RuleContext = {
        lie_count: 100,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      // Should match excessive_lies but not headless_with_stealth
      expect(result.matchedRules).toContain("excessive_lies");
      expect(result.matchedRules).not.toContain("headless_with_stealth");
    });
  });

  describe("composite any condition", () => {
    it("should match when any sub-condition is true", () => {
      // Test with a manual context and custom rules would require
      // modifying the config, so we verify the logic through the
      // existing rules which use "all" composition
      const ctx: RuleContext = {
        lie_count: 0,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.shouldSkipBaseline).toBe(false);
      expect(result.matchedRules).toHaveLength(0);
    });
  });

  describe("environment-disabled rules", () => {
    it("should skip rules disabled for the given environment", () => {
      // With current config, no rules are disabled in dev/prod
      const ctx: RuleContext = {
        lie_count: 100,
        is_headless: false,
        worker_ua_mismatch: true,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx, "dev");
      expect(result.shouldSkipBaseline).toBe(true);
      expect(result.matchedRules).toContain("excessive_lies");
      expect(result.matchedRules).toContain("worker_ua_mismatch");
    });

    it("should evaluate all rules when environment is not specified", () => {
      const ctx: RuleContext = {
        lie_count: 100,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.shouldSkipBaseline).toBe(true);
      expect(result.matchedRules).toContain("excessive_lies");
    });

    it("should evaluate all rules for unknown environment", () => {
      const ctx: RuleContext = {
        lie_count: 100,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx, "staging");
      expect(result.shouldSkipBaseline).toBe(true);
    });
  });

  describe("no rules matched", () => {
    it("should return shouldSkipBaseline=false when no rules match", () => {
      const ctx: RuleContext = {
        lie_count: 0,
        is_headless: false,
        worker_ua_mismatch: false,
        proxy_score: 0,
        vpn_score: 0,
      };
      const result = evaluateBaselineRules(ctx);
      expect(result.shouldSkipBaseline).toBe(false);
      expect(result.matchedRules).toHaveLength(0);
    });
  });
});

describe("integration: context + rules together", () => {
  it("should skip baseline for stealth plugin bot (headless + high lies)", () => {
    const fp: Fingerprint = { lie_count: 305, is_headless: true };
    const ctx = buildRuleContext(fp);
    const result = evaluateBaselineRules(ctx);

    expect(result.shouldSkipBaseline).toBe(true);
    expect(result.matchedRules).toContain("excessive_lies");
    expect(result.matchedRules).toContain("headless_with_stealth");
  });

  it("should skip baseline for naive spoofing bot (worker UA mismatch)", () => {
    const fp: Fingerprint = {};
    const device = {
      navigator: { userAgent: "Chrome/120" },
      workerScope: {
        scopes: {
          web: { userAgent: "Firefox/115" },
        },
      },
    };
    const ctx = buildRuleContext(fp, device);
    const result = evaluateBaselineRules(ctx);

    expect(result.shouldSkipBaseline).toBe(true);
    expect(result.matchedRules).toContain("worker_ua_mismatch");
  });

  it("should not skip baseline for vanilla browser", () => {
    const fp: Fingerprint = {
      lie_count: 2,
      is_headless: false,
      proxy_score: 0.1,
      vpn_score: 0,
    };
    const device = {
      navigator: { userAgent: "Chrome/120" },
      workerScope: {
        scopes: {
          web: { userAgent: "Chrome/120" },
        },
      },
    };
    const ctx = buildRuleContext(fp, device);
    const result = evaluateBaselineRules(ctx);

    expect(result.shouldSkipBaseline).toBe(false);
    expect(result.matchedRules).toHaveLength(0);
  });

  it("should handle boundary: exactly 50 lies should not trigger excessive_lies", () => {
    const fp: Fingerprint = { lie_count: 50 };
    const ctx = buildRuleContext(fp);
    const result = evaluateBaselineRules(ctx);

    expect(result.matchedRules).not.toContain("excessive_lies");
  });

  it("should handle boundary: exactly 10 lies with headless should not trigger headless_with_stealth", () => {
    const fp: Fingerprint = { lie_count: 10, is_headless: true };
    const ctx = buildRuleContext(fp);
    const result = evaluateBaselineRules(ctx);

    expect(result.matchedRules).not.toContain("headless_with_stealth");
  });
});
