// src/helpers/middy-helpers.test.ts
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */
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

  // AR-97: Tenant-based deduplication tests
  describe("deduplicateMiddleware tenant isolation", () => {
    beforeEach(() => {
      _clearDeduplicateCache();
    });

    const createMockRequestWithTenant = (body: string, tenantId: string) => ({
      event: {
        body,
        headers: {
          "x-tenant-id": tenantId,
        },
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

    it("should allow same body from different tenants", () => {
      const middleware = deduplicateMiddleware();
      const sameBody = '{"session_id": "123", "fingerprint": {}}';

      // Tenant A sends request
      const requestTenantA = createMockRequestWithTenant(sameBody, "tenant-a");
      expect(() => middleware.before!(requestTenantA as any)).not.toThrow();

      // Tenant B sends identical body - should NOT be flagged as duplicate
      const requestTenantB = createMockRequestWithTenant(sameBody, "tenant-b");
      expect(() => middleware.before!(requestTenantB as any)).not.toThrow();
    });

    it("should block duplicate from same tenant", () => {
      const middleware = deduplicateMiddleware();
      const sameBody = '{"session_id": "456", "fingerprint": {}}';

      // Same tenant sends two identical requests
      const request1 = createMockRequestWithTenant(sameBody, "tenant-a");
      const request2 = createMockRequestWithTenant(sameBody, "tenant-a");

      expect(() => middleware.before!(request1 as any)).not.toThrow();
      expect(() => middleware.before!(request2 as any)).toThrow(
        /Duplicate request detected/,
      );
    });

    it("should treat missing tenant header as 'default' tenant", () => {
      const middleware = deduplicateMiddleware();
      const sameBody = '{"session_id": "789", "fingerprint": {}}';

      // Request without tenant header
      const requestNoTenant = {
        event: {
          body: sameBody,
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
      };

      // First request passes
      expect(() => middleware.before!(requestNoTenant as any)).not.toThrow();

      // Second identical request (also no tenant) should be blocked
      expect(() => middleware.before!(requestNoTenant as any)).toThrow(
        /Duplicate request detected/,
      );
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

  // AR-124: Non-prod (STAGE not set or not "prod") should still allow default fallback
  describe("deduplicateMiddleware non-production fallback (AR-124)", () => {
    beforeEach(() => {
      _clearDeduplicateCache();
    });

    it("should allow default tenant fallback when STAGE is not set", () => {
      // STAGE is not set in the test environment (or is not "prod")
      // so default fallback should still work
      const middleware = deduplicateMiddleware();
      const request = {
        event: {
          body: '{"session_id": "dev-test", "fingerprint": {}}',
          headers: {}, // No x-tenant-id header
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
      };

      // Should NOT throw - dev environment allows default fallback
      expect(() => middleware.before!(request as any)).not.toThrow();
    });

    it("should still use tenant-isolated deduplication in non-prod", () => {
      const middleware = deduplicateMiddleware();
      const sameBody =
        '{"session_id": "dev-isolation-test", "fingerprint": {}}';

      // Request with tenant A
      const requestTenantA = {
        event: {
          body: sameBody,
          headers: { "x-tenant-id": "tenant-a" },
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
      };

      // Request with no tenant (should use "default")
      const requestNoTenant = {
        event: {
          body: sameBody,
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
      };

      // Both should pass (different tenants)
      expect(() => middleware.before!(requestTenantA as any)).not.toThrow();
      expect(() => middleware.before!(requestNoTenant as any)).not.toThrow();
    });
  });
});
