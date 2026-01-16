// src/helpers/middy-helpers-tenant-guard.test.ts
// AR-124: Tests for tenant isolation guard in deduplicateMiddleware - throws in production
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import {
  describe,
  it,
  expect,
  beforeEach,
  vi,
  beforeAll,
  afterAll,
} from "vitest";

// Store original env
const originalEnv = { ...process.env };

describe("AR-124: deduplicateMiddleware tenant isolation guard in production", () => {
  beforeAll(() => {
    // Set production stage BEFORE importing module
    process.env.STAGE = "prod";
  });

  afterAll(() => {
    // Restore original env
    process.env = originalEnv;
    vi.resetModules();
  });

  beforeEach(() => {
    vi.resetModules();
  });

  it("should throw 500 when STAGE=prod and no x-tenant-id header", async () => {
    // Dynamic import after env is set
    const { deduplicateMiddleware, _clearDeduplicateCache } =
      await import("./middy-helpers");
    _clearDeduplicateCache();

    const middleware = deduplicateMiddleware();
    const request = {
      event: {
        body: '{"session_id": "prod-test", "fingerprint": {}}',
        headers: {}, // No x-tenant-id header
        httpMethod: "POST",
        isBase64Encoded: false,
        path: "/test",
        pathParameters: null,
        queryStringParameters: null,
        requestContext: {},
        resource: "/test",
        stageVariables: null,
        multiValueHeaders: {},
        multiValueQueryStringParameters: null,
      },
      context: {},
      response: null,
      error: null,
      internal: {},
    };

    // Should throw 500 in production with no tenant ID
    try {
      middleware.before!(request as any);
      expect.fail("Should have thrown");
    } catch (error) {
      expect((error as { statusCode: number }).statusCode).toBe(500);
      expect((error as Error).message).toContain("Tenant configuration error");
      expect((error as Error).message).toContain("contact support");
    }
  });

  it("should allow requests with x-tenant-id header in production", async () => {
    const { deduplicateMiddleware, _clearDeduplicateCache } =
      await import("./middy-helpers");
    _clearDeduplicateCache();

    const middleware = deduplicateMiddleware();
    const request = {
      event: {
        body: '{"session_id": "prod-tenant-test", "fingerprint": {}}',
        headers: { "x-tenant-id": "valid-tenant" }, // Has tenant ID
        httpMethod: "POST",
        isBase64Encoded: false,
        path: "/test",
        pathParameters: null,
        queryStringParameters: null,
        requestContext: {},
        resource: "/test",
        stageVariables: null,
        multiValueHeaders: {},
        multiValueQueryStringParameters: null,
      },
      context: {},
      response: null,
      error: null,
      internal: {},
    };

    // Should NOT throw when tenant ID is provided
    expect(() => middleware.before!(request as any)).not.toThrow();
  });

  it("should have actionable error message mentioning contact support", async () => {
    const { deduplicateMiddleware, _clearDeduplicateCache } =
      await import("./middy-helpers");
    _clearDeduplicateCache();

    const middleware = deduplicateMiddleware();
    const request = {
      event: {
        body: '{"session_id": "prod-error-test", "fingerprint": {}}',
        headers: {},
        httpMethod: "POST",
        isBase64Encoded: false,
        path: "/test",
        pathParameters: null,
        queryStringParameters: null,
        requestContext: {},
        resource: "/test",
        stageVariables: null,
        multiValueHeaders: {},
        multiValueQueryStringParameters: null,
      },
      context: {},
      response: null,
      error: null,
      internal: {},
    };

    try {
      middleware.before!(request as any);
      expect.fail("Should have thrown");
    } catch (error) {
      const message = (error as Error).message;
      // Error should be actionable - tells user what to do
      expect(message).toContain("contact support");
      expect(message).toContain("Missing tenant identification");
      expect(message).toContain("production environment");
    }
  });
});
