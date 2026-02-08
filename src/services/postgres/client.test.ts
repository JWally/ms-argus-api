import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock pg before importing
const mockPoolInstance = {
  on: vi.fn(),
  end: vi.fn().mockResolvedValue(undefined),
  query: vi.fn(),
};

vi.mock("pg", () => ({
  Pool: vi.fn().mockImplementation(() => mockPoolInstance),
}));

const mockSend = vi.fn();
vi.mock("@aws-sdk/client-secrets-manager", () => ({
  SecretsManagerClient: vi.fn().mockImplementation(() => ({ send: mockSend })),
  GetSecretValueCommand: vi.fn().mockImplementation((params: any) => params),
}));

// Need to clear module cache between tests since getPool uses module-level singleton
let getPool: typeof import("./client").getPool;
let closePool: typeof import("./client").closePool;

describe("postgres client", () => {
  const originalEnv = process.env;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset module to clear the singleton
    vi.resetModules();
    process.env = { ...originalEnv };
    const mod = await import("./client");
    getPool = mod.getPool;
    closePool = mod.closePool;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("getPool", () => {
    it("should return null when POSTGRES_HOST is not set", async () => {
      delete process.env.POSTGRES_HOST;
      const pool = await getPool();
      expect(pool).toBeNull();
    });

    it("should return null when POSTGRES_SECRET_ARN is missing", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      delete process.env.POSTGRES_SECRET_ARN;
      const pool = await getPool();
      expect(pool).toBeNull();
    });

    it("should create pool with credentials from Secrets Manager", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";
      process.env.POSTGRES_DB = "argus";

      mockSend.mockResolvedValue({
        SecretString: JSON.stringify({ username: "admin", password: "secret" }),
      });

      const pool = await getPool();
      expect(pool).not.toBeNull();
    });

    it("should return cached pool on second call", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";

      mockSend.mockResolvedValue({
        SecretString: JSON.stringify({ username: "admin", password: "secret" }),
      });

      const pool1 = await getPool();
      const pool2 = await getPool();
      expect(pool1).toBe(pool2);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it("should return null when fetchSecret fails", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";

      mockSend.mockRejectedValue(new Error("Access denied"));

      const pool = await getPool();
      expect(pool).toBeNull();
    });

    it("should throw when SecretString is empty", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";

      mockSend.mockResolvedValue({ SecretString: undefined });

      const pool = await getPool();
      // Error is caught in getPool, returns null
      expect(pool).toBeNull();
    });
  });

  describe("closePool", () => {
    it("should do nothing when no pool exists", async () => {
      await closePool();
      expect(mockPoolInstance.end).not.toHaveBeenCalled();
    });

    it("should close existing pool", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";

      mockSend.mockResolvedValue({
        SecretString: JSON.stringify({ username: "admin", password: "secret" }),
      });

      await getPool();
      await closePool();
      expect(mockPoolInstance.end).toHaveBeenCalledTimes(1);
    });

    it("should handle close errors gracefully", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";

      mockSend.mockResolvedValue({
        SecretString: JSON.stringify({ username: "admin", password: "secret" }),
      });

      await getPool();
      mockPoolInstance.end.mockRejectedValueOnce(new Error("close failed"));
      await closePool(); // should not throw
    });

    it("should null out pool after close so next getPool creates new one", async () => {
      process.env.POSTGRES_HOST = "db.example.com";
      process.env.POSTGRES_SECRET_ARN =
        "arn:aws:secretsmanager:us-east-1:123:secret:test";

      mockSend.mockResolvedValue({
        SecretString: JSON.stringify({ username: "admin", password: "secret" }),
      });

      await getPool();
      await closePool();
      // After close, getting pool again should re-create
      const pool2 = await getPool();
      expect(pool2).not.toBeNull();
      expect(mockSend).toHaveBeenCalledTimes(2); // fetched secret twice
    });
  });
});
