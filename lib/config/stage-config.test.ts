// lib/config/stage-config.test.ts
import { describe, it, expect } from "vitest";
import { getStageConfig, isProdStage, configs } from "./stage-config";

describe("stage-config", () => {
  describe("getStageConfig", () => {
    it("should return dev config for 'dev' stage", () => {
      const config = getStageConfig("dev");
      expect(config).toBe(configs.dev);
      expect(config.lambda.matching.memorySize).toBe(1024);
    });

    it("should return dev config for 'dev-jw' stage", () => {
      const config = getStageConfig("dev-jw");
      expect(config).toBe(configs.dev);
    });

    it("should return dev config for 'dev-anything' stage", () => {
      const config = getStageConfig("dev-test-123");
      expect(config).toBe(configs.dev);
    });

    it("should return prod config for 'prod' stage", () => {
      const config = getStageConfig("prod");
      expect(config).toBe(configs.prod);
      expect(config.lambda.matching.memorySize).toBe(512);
    });

    it("should return prod config for 'production' stage", () => {
      const config = getStageConfig("production");
      expect(config).toBe(configs.prod);
    });

    it("should return dev config for unknown stage (safe default)", () => {
      const config = getStageConfig("unknown-stage");
      expect(config).toBe(configs.dev);
    });

    it("should return dev config for staging", () => {
      const config = getStageConfig("staging");
      expect(config).toBe(configs.dev);
    });
  });

  describe("isProdStage", () => {
    it("should return true for 'prod'", () => {
      expect(isProdStage("prod")).toBe(true);
    });

    it("should return true for 'production'", () => {
      expect(isProdStage("production")).toBe(true);
    });

    it("should return false for 'dev'", () => {
      expect(isProdStage("dev")).toBe(false);
    });

    it("should return false for 'dev-jw'", () => {
      expect(isProdStage("dev-jw")).toBe(false);
    });

    it("should return false for 'staging'", () => {
      expect(isProdStage("staging")).toBe(false);
    });
  });

  describe("config values", () => {
    describe("dev config", () => {
      const dev = configs.dev;

      it("should have smaller Lambda memory", () => {
        expect(dev.lambda.matching.memorySize).toBe(1024);
        expect(dev.lambda.profile.memorySize).toBe(128);
      });

      it("should have API Lambda memory configurations", () => {
        expect(dev.lambda.ingestion.memorySize).toBe(1536);
        expect(dev.lambda.sessionGet.memorySize).toBe(1024);
      });

      it("should use scheduled heaters instead of provisioned concurrency", () => {
        expect(dev.lambda.provisionedConcurrency).toBe(0);
      });

      it("should have shorter retention periods", () => {
        expect(dev.sqs.retentionPeriod.toDays()).toBe(1);
      });

      it("should have tighter alarm thresholds for faster feedback", () => {
        expect(dev.alarms.lambda.errorThreshold).toBeLessThan(
          configs.prod.alarms.lambda.errorThreshold,
        );
        expect(dev.alarms.queue.messageAgeSeconds).toBeLessThan(
          configs.prod.alarms.queue.messageAgeSeconds,
        );
      });

      it("should have higher WAF rate limit for testing", () => {
        expect(dev.waf.rateLimitPerFiveMinutes).toBeGreaterThan(
          configs.prod.waf.rateLimitPerFiveMinutes,
        );
      });
    });

    describe("prod config", () => {
      const prod = configs.prod;

      it("should have larger Lambda memory", () => {
        expect(prod.lambda.matching.memorySize).toBe(512);
        expect(prod.lambda.profile.memorySize).toBe(256);
      });

      it("should have API Lambda memory configurations", () => {
        expect(prod.lambda.ingestion.memorySize).toBe(1536);
        expect(prod.lambda.sessionGet.memorySize).toBe(1024);
      });

      it("should avoid provisioned concurrency by default", () => {
        expect(prod.lambda.provisionedConcurrency).toBe(0);
      });

      it("should have longer retention periods", () => {
        expect(prod.sqs.retentionPeriod.toDays()).toBeGreaterThanOrEqual(7);
      });

      it("should have appropriate concurrency limits", () => {
        expect(prod.lambda.matching.reservedConcurrency).toBeGreaterThanOrEqual(
          500,
        );
        expect(prod.lambda.profile.reservedConcurrency).toBeGreaterThanOrEqual(
          200,
        );
      });
    });

    describe("batching windows", () => {
      it("should have zero batching window for minimal latency", () => {
        expect(configs.dev.sqs.batchingWindow.matching.toSeconds()).toBe(0);
        expect(configs.dev.sqs.batchingWindow.profile.toSeconds()).toBe(0);
        expect(configs.prod.sqs.batchingWindow.matching.toSeconds()).toBe(0);
        expect(configs.prod.sqs.batchingWindow.profile.toSeconds()).toBe(0);
      });
    });
  });
});
