import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mockPipeline = {
  get: vi.fn().mockReturnThis(),
  incr: vi.fn().mockReturnThis(),
  expire: vi.fn().mockReturnThis(),
  exec: vi.fn(),
};

const mockRedisInstance = {
  on: vi.fn(),
  quit: vi.fn().mockResolvedValue(undefined),
  pipeline: vi.fn().mockReturnValue(mockPipeline),
};

vi.mock("ioredis", () => ({
  default: vi.fn().mockImplementation(() => mockRedisInstance),
}));

let getTieredTTL: typeof import("./valkey-client").getTieredTTL;
let isStatisticalV2Enabled: typeof import("./valkey-client").isStatisticalV2Enabled;
let recordFingerprintV2: typeof import("./valkey-client").recordFingerprintV2;
let fetchStatisticalV2Data: typeof import("./valkey-client").fetchStatisticalV2Data;
let closeClient: typeof import("./valkey-client").closeClient;

describe("valkey-client", () => {
  const originalEnv = process.env;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    process.env = { ...originalEnv };
    const mod = await import("./valkey-client");
    getTieredTTL = mod.getTieredTTL;
    isStatisticalV2Enabled = mod.isStatisticalV2Enabled;
    recordFingerprintV2 = mod.recordFingerprintV2;
    fetchStatisticalV2Data = mod.fetchStatisticalV2Data;
    closeClient = mod.closeClient;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("getTieredTTL", () => {
    it("should return 90 days for >= 20000 observations", () => {
      expect(getTieredTTL(20000)).toBe(90 * 24 * 3600);
      expect(getTieredTTL(50000)).toBe(90 * 24 * 3600);
    });

    it("should return 24 hours for >= 1000 observations", () => {
      expect(getTieredTTL(1000)).toBe(24 * 3600);
      expect(getTieredTTL(19999)).toBe(24 * 3600);
    });

    it("should return 3 hours for < 1000 observations", () => {
      expect(getTieredTTL(0)).toBe(3 * 3600);
      expect(getTieredTTL(999)).toBe(3 * 3600);
    });
  });

  describe("isStatisticalV2Enabled", () => {
    it("should return false when VALKEY_ENDPOINT is not set", () => {
      delete process.env.VALKEY_ENDPOINT;
      process.env.STATISTICAL_V2_ENABLED = "true";
      expect(isStatisticalV2Enabled()).toBe(false);
    });

    it("should return false when STATISTICAL_V2_ENABLED is not true", () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      process.env.STATISTICAL_V2_ENABLED = "false";
      expect(isStatisticalV2Enabled()).toBe(false);
    });

    it("should return true when both are set correctly", () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      process.env.STATISTICAL_V2_ENABLED = "true";
      expect(isStatisticalV2Enabled()).toBe(true);
    });
  });

  describe("recordFingerprintV2", () => {
    it("should return NEUTRAL_V2_DATA when no endpoint configured", async () => {
      delete process.env.VALKEY_ENDPOINT;
      const result = await recordFingerprintV2("ua:chrome", "ja4", "fp-123");
      expect(result).toEqual({
        count: 1,
        total: 1,
        globalCount: 0,
        globalTotal: 0,
      });
    });

    it("should record and return data on success", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "5"], // group count
        [null, "100"], // group total
        [null, 6], // incr result (ignored)
        [null, 101], // incr result (ignored)
      ]);

      const result = await recordFingerprintV2("ua:chrome", "ja4", "fp-123");
      expect(result.count).toBe(6); // 5 + 1
      expect(result.total).toBe(101); // 100 + 1
    });

    it("should return NEUTRAL_V2_DATA when pipeline returns null", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue(null);

      const result = await recordFingerprintV2("ua:chrome", "ja4", "fp-123");
      expect(result).toEqual({
        count: 1,
        total: 1,
        globalCount: 0,
        globalTotal: 0,
      });
    });

    it("should return NEUTRAL_V2_DATA on error", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockRejectedValue(new Error("Connection refused"));

      const result = await recordFingerprintV2("ua:chrome", "ja4", "fp-123");
      expect(result).toEqual({
        count: 1,
        total: 1,
        globalCount: 0,
        globalTotal: 0,
      });
    });
  });

  describe("fetchStatisticalV2Data", () => {
    it("should return null when no endpoint configured", async () => {
      delete process.env.VALKEY_ENDPOINT;
      const result = await fetchStatisticalV2Data("ua:chrome", "ja4", "fp-123");
      expect(result).toBeNull();
    });

    it("should fetch and return data on success", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "10"], // group count
        [null, "200"], // group total
      ]);

      const result = await fetchStatisticalV2Data("ua:chrome", "ja4", "fp-123");
      expect(result).toEqual({
        count: 10,
        total: 200,
        globalCount: 0,
        globalTotal: 0,
      });
    });

    it("should return null when pipeline results are insufficient", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue(null);

      const result = await fetchStatisticalV2Data("ua:chrome", "ja4", "fp-123");
      expect(result).toBeNull();
    });

    it("should return null on error", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockRejectedValue(new Error("Timeout"));

      const result = await fetchStatisticalV2Data("ua:chrome", "ja4", "fp-123");
      expect(result).toBeNull();
    });
  });

  describe("Redis client configuration", () => {
    it("should register error, reconnecting, and connect event handlers", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);

      // Force client creation
      await recordFingerprintV2("ua:chrome", "ja4", "fp-test");

      // Check that event handlers were registered
      const onCalls = mockRedisInstance.on.mock.calls;
      const events = onCalls.map((call: unknown[]) => call[0]);
      expect(events).toContain("error");
      expect(events).toContain("reconnecting");
      expect(events).toContain("connect");
    });

    it("should fire error handler without throwing", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);

      await recordFingerprintV2("ua:chrome", "ja4", "fp-test");

      // Find and call the error handler
      const errorCall = mockRedisInstance.on.mock.calls.find(
        (call: unknown[]) => call[0] === "error",
      );
      expect(errorCall).toBeTruthy();
      // Calling the error handler should not throw
      expect(() => errorCall![1](new Error("connection lost"))).not.toThrow();
    });

    it("should fire reconnecting handler without throwing", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);

      await recordFingerprintV2("ua:chrome", "ja4", "fp-test");

      const reconnectingCall = mockRedisInstance.on.mock.calls.find(
        (call: unknown[]) => call[0] === "reconnecting",
      );
      expect(reconnectingCall).toBeTruthy();
      expect(() => reconnectingCall![1]()).not.toThrow();
    });

    it("should fire connect handler without throwing", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);

      await recordFingerprintV2("ua:chrome", "ja4", "fp-test");

      const connectCall = mockRedisInstance.on.mock.calls.find(
        (call: unknown[]) => call[0] === "connect",
      );
      expect(connectCall).toBeTruthy();
      expect(() => connectCall![1]()).not.toThrow();
    });
  });

  describe("retry strategy", () => {
    it("should be configured via the Redis constructor", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);

      await recordFingerprintV2("ua:chrome", "ja4", "fp-test");

      // The Redis constructor is called with config including retryStrategy
      const Redis = (await import("ioredis")).default;
      const constructorCalls = (Redis as unknown as ReturnType<typeof vi.fn>)
        .mock.calls;
      expect(constructorCalls.length).toBeGreaterThan(0);
      const config = constructorCalls[0][0];
      expect(config.retryStrategy).toBeDefined();

      // Test retry strategy: returns exponential backoff for <= 10 attempts
      const retryStrategy = config.retryStrategy;
      expect(retryStrategy(1)).toBe(100);
      expect(retryStrategy(3)).toBe(300);
      expect(retryStrategy(10)).toBe(1000);

      // Test retry strategy: returns null (stop) for > 10 attempts
      expect(retryStrategy(11)).toBeNull();
    });
  });

  describe("closeClient", () => {
    it("should do nothing when no client exists", async () => {
      delete process.env.VALKEY_ENDPOINT;
      await closeClient(); // should not throw
    });

    it("should close existing client", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      // Force client creation
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);
      await recordFingerprintV2("ua:chrome", "ja4", "fp-123");
      await closeClient();
      expect(mockRedisInstance.quit).toHaveBeenCalledTimes(1);
    });

    it("should handle close errors gracefully", async () => {
      process.env.VALKEY_ENDPOINT = "redis.example.com";
      mockPipeline.exec.mockResolvedValue([
        [null, "1"],
        [null, "1"],
        [null, 2],
        [null, 2],
      ]);
      await recordFingerprintV2("ua:chrome", "ja4", "fp-123");
      mockRedisInstance.quit.mockRejectedValueOnce(new Error("close error"));
      await closeClient(); // should not throw
    });
  });
});
