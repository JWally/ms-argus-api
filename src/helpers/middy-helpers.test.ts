// src/helpers/middy-helpers.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { APIGatewayProxyEvent } from "aws-lambda";
import {
  isWarmingUp,
  onWarmup,
  fnv1a,
  deduplicateMiddleware,
  _clearDeduplicateCache,
} from "./middy-helpers";

// Mock getAwsSecrets
vi.mock("../services/get-aws-secrets", () => ({
  getAwsSecrets: vi.fn(),
}));

import { getAwsSecrets } from "../services/get-aws-secrets";

describe("middy-helpers", () => {
  describe("isWarmingUp", () => {
    it("should return true for serverless-plugin-warmup source", () => {
      const event = { source: "serverless-plugin-warmup" };
      expect(isWarmingUp(event)).toBe(true);
    });

    it("should return true for warmup-plugin source", () => {
      const event = { source: "warmup-plugin" };
      expect(isWarmingUp(event)).toBe(true);
    });

    it("should return true when warmup flag is true", () => {
      const event = { source: "other", warmup: true };
      expect(isWarmingUp(event)).toBe(true);
    });

    it("should return false for non-warmup events", () => {
      const event = { source: "api-gateway" };
      expect(isWarmingUp(event)).toBe(false);
    });

    it("should return false when warmup flag is false", () => {
      const event = { source: "other", warmup: false };
      expect(isWarmingUp(event)).toBe(false);
    });

    it("should return false for empty source", () => {
      const event = { source: "" };
      expect(isWarmingUp(event)).toBe(false);
    });
  });

  describe("onWarmup", () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it("should call getAwsSecrets during warmup", async () => {
      (getAwsSecrets as any).mockResolvedValue({
        ENCRYPTION_KEY: "key",
        HMAC_KEY: "hmac",
      });

      await onWarmup();

      expect(getAwsSecrets).toHaveBeenCalledTimes(1);
    });

    it("should not throw when getAwsSecrets succeeds", async () => {
      (getAwsSecrets as any).mockResolvedValue({
        ENCRYPTION_KEY: "key",
        HMAC_KEY: "hmac",
      });

      await expect(onWarmup()).resolves.not.toThrow();
    });

    it("should not throw when getAwsSecrets fails", async () => {
      (getAwsSecrets as any).mockRejectedValue(new Error("Secrets error"));

      // onWarmup catches errors and logs them, doesn't throw
      await expect(onWarmup()).resolves.not.toThrow();
    });
  });

  describe("fnv1a", () => {
    it("should produce consistent hash for same input", () => {
      const input = "test-string";
      const hash1 = fnv1a(input);
      const hash2 = fnv1a(input);
      expect(hash1).toBe(hash2);
    });

    it("should produce different hashes for different inputs", () => {
      const hash1 = fnv1a("input1");
      const hash2 = fnv1a("input2");
      expect(hash1).not.toBe(hash2);
    });

    it("should handle empty string", () => {
      const hash = fnv1a("");
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });

    it("should produce hex string output", () => {
      const hash = fnv1a("test");
      expect(hash).toMatch(/^[0-9a-f]+$/);
    });

    it("should handle unicode characters", () => {
      const hash = fnv1a("こんにちは");
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });

    it("should handle long strings", () => {
      const longString = "a".repeat(10000);
      const hash = fnv1a(longString);
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });

    it("should produce different hashes for similar strings", () => {
      const hash1 = fnv1a("test1");
      const hash2 = fnv1a("test2");
      const hash3 = fnv1a("Test1");
      expect(hash1).not.toBe(hash2);
      expect(hash1).not.toBe(hash3);
    });
  });

  describe("deduplicateMiddleware", () => {
    beforeEach(() => {
      _clearDeduplicateCache();
    });

    const createMockRequest = (body: string | null) => ({
      event: {
        body,
        headers: {},
        httpMethod: "POST",
        isBase64Encoded: false,
        path: "/test",
        pathParameters: null,
        queryStringParameters: null,
        requestContext: {} as any,
        resource: "/test",
        stageVariables: null,
        multiValueHeaders: {},
        multiValueQueryStringParameters: null,
      } as APIGatewayProxyEvent,
      context: {} as any,
      response: null,
      error: null,
      internal: {},
    });

    it("should return middleware object with before handler", () => {
      const middleware = deduplicateMiddleware();
      expect(middleware).toHaveProperty("before");
      expect(typeof middleware.before).toBe("function");
    });

    it("should allow first request through", () => {
      const middleware = deduplicateMiddleware();
      const request = createMockRequest('{"data": "test"}');

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).not.toThrow();
    });

    it("should block duplicate requests", () => {
      const middleware = deduplicateMiddleware();
      const request = createMockRequest('{"data": "test"}');

      // First request should pass
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      middleware.before!(request as any);

      // Second identical request should throw
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).toThrow(
        /Duplicate request detected/,
      );
    });

    it("should throw TooManyRequests error (429)", () => {
      const middleware = deduplicateMiddleware();
      const request = createMockRequest('{"data": "test"}');

      // First request should pass
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      middleware.before!(request as any);

      // Second request should throw with 429 status
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        middleware.before!(request as any);
        expect.fail("Should have thrown");
      } catch (error) {
        expect((error as { statusCode: number }).statusCode).toBe(429);
      }
    });

    it("should allow requests with different bodies", () => {
      const middleware = deduplicateMiddleware();
      const request1 = createMockRequest('{"data": "test1"}');
      const request2 = createMockRequest('{"data": "test2"}');

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request1 as any)).not.toThrow();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request2 as any)).not.toThrow();
    });

    it("should skip deduplication when body is null", () => {
      const middleware = deduplicateMiddleware();
      const request = createMockRequest(null);

      // Should not throw and not add to cache
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).not.toThrow();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).not.toThrow();
    });

    it("should skip deduplication when body is empty string", () => {
      const middleware = deduplicateMiddleware();
      const request = createMockRequest("");

      // Empty string is falsy, so should skip deduplication
      // Note: empty string is falsy in JS, so !event.body returns true
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).not.toThrow();
    });

    it("should increment duplicate count on repeated requests", () => {
      const middleware = deduplicateMiddleware();
      const request = createMockRequest('{"data": "repeat"}');

      // First request passes
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      middleware.before!(request as any);

      // Second request - duplicate count 2
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        middleware.before!(request as any);
      } catch (error) {
        expect((error as Error).message).toBe("Duplicate request detected: 2");
      }

      // Third request - duplicate count 3
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        middleware.before!(request as any);
      } catch (error) {
        expect((error as Error).message).toBe("Duplicate request detected: 3");
      }
    });
  });

  describe("_clearDeduplicateCache", () => {
    it("should clear the cache allowing same request again", () => {
      const middleware = deduplicateMiddleware();
      const request = {
        event: {
          body: '{"data": "test-clear"}',
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          headers: {} as any,
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        context: {} as any,
        response: null,
        error: null,
        internal: {},
      };

      // First request passes
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      middleware.before!(request as any);

      // Second request should be blocked
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).toThrow();

      // Clear cache
      _clearDeduplicateCache();

      // Same request should now pass again
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(() => middleware.before!(request as any)).not.toThrow();
    });
  });
});
