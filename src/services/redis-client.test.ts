// src/services/redis-client.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  getRedisClient,
  getRedis,
  closeRedisClient,
} from "./redis-client";

// Mock ioredis
vi.mock("ioredis", () => {
  const RedisMock = vi.fn().mockImplementation((config) => ({
    options: config,
    disconnect: vi.fn(),
  }));
  return { default: RedisMock };
});

describe("redis-client", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset singleton state before each test
    closeRedisClient();
    // Reset environment
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    closeRedisClient();
  });

  describe("getRedisClient", () => {
    it("should create a new Redis client with provided config", () => {
      const client = getRedisClient({ endpoint: "localhost", port: 6379 });
      expect(client).toBeDefined();
      expect(client.options.host).toBe("localhost");
      expect(client.options.port).toBe(6379);
    });

    it("should return same client for same config (singleton)", () => {
      const client1 = getRedisClient({ endpoint: "localhost", port: 6379 });
      const client2 = getRedisClient({ endpoint: "localhost", port: 6379 });
      expect(client1).toBe(client2);
    });

    it("should create new client when config changes", () => {
      const client1 = getRedisClient({ endpoint: "localhost", port: 6379 });
      const client2 = getRedisClient({ endpoint: "other-host", port: 6379 });
      expect(client1).not.toBe(client2);
    });

    it("should create new client when port changes", () => {
      const client1 = getRedisClient({ endpoint: "localhost", port: 6379 });
      const client2 = getRedisClient({ endpoint: "localhost", port: 6380 });
      expect(client1).not.toBe(client2);
    });

    it("should configure TLS for ElastiCache", () => {
      const client = getRedisClient({ endpoint: "localhost", port: 6379 });
      expect(client.options.tls).toEqual({});
    });

    it("should use Lambda-optimized settings", () => {
      const client = getRedisClient({ endpoint: "localhost", port: 6379 });
      expect(client.options.enableReadyCheck).toBe(false);
      expect(client.options.maxRetriesPerRequest).toBe(2);
      expect(client.options.connectTimeout).toBe(5000);
      expect(client.options.commandTimeout).toBe(3000);
      expect(client.options.keepAlive).toBe(30000);
    });
  });

  describe("getRedis", () => {
    it("should throw when REDIS_ENDPOINT is not set", () => {
      delete process.env.REDIS_ENDPOINT;
      expect(() => getRedis()).toThrow(
        "REDIS_ENDPOINT environment variable is required",
      );
    });

    it("should use REDIS_ENDPOINT from environment", () => {
      process.env.REDIS_ENDPOINT = "my-redis.cache.amazonaws.com";
      process.env.REDIS_PORT = "6379";
      const client = getRedis();
      expect(client.options.host).toBe("my-redis.cache.amazonaws.com");
    });

    it("should default port to 6379 when REDIS_PORT is not set", () => {
      process.env.REDIS_ENDPOINT = "localhost";
      delete process.env.REDIS_PORT;
      const client = getRedis();
      expect(client.options.port).toBe(6379);
    });

    it("should use REDIS_PORT from environment when set", () => {
      process.env.REDIS_ENDPOINT = "localhost";
      process.env.REDIS_PORT = "6380";
      const client = getRedis();
      expect(client.options.port).toBe(6380);
    });
  });

  describe("closeRedisClient", () => {
    it("should reset singleton state", () => {
      const client1 = getRedisClient({ endpoint: "localhost", port: 6379 });
      closeRedisClient();
      const client2 = getRedisClient({ endpoint: "localhost", port: 6379 });
      expect(client1).not.toBe(client2);
    });

    it("should call disconnect on existing client", () => {
      const client = getRedisClient({ endpoint: "localhost", port: 6379 });
      closeRedisClient();
      expect(client.disconnect).toHaveBeenCalled();
    });

    it("should handle being called when no client exists", () => {
      expect(() => closeRedisClient()).not.toThrow();
    });
  });
});
