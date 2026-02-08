import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../services/postgres", () => ({
  getPool: vi.fn(),
}));

import { handleAdminRequest } from "./admin-handler";
import { getPool } from "../../services/postgres";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

const mockMetrics = {
  addMetric: vi.fn(),
} as unknown as Metrics;

const deps = { logger: mockLogger, metrics: mockMetrics };

describe("handleAdminRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return not-implemented for unknown action", async () => {
    const result = await handleAdminRequest({ action: "flush_cache" }, deps);
    expect(result.success).toBe(false);
    expect(result.message).toContain("not yet implemented");
  });

  describe("run_pg_migration", () => {
    it("should fail when sql field is missing", async () => {
      const result = await handleAdminRequest(
        { action: "run_pg_migration" },
        deps,
      );
      expect(result.success).toBe(false);
      expect(result.message).toBe("Missing 'sql' field in request");
    });

    it("should fail when postgres is not configured", async () => {
      vi.mocked(getPool).mockResolvedValue(null);
      const result = await handleAdminRequest(
        { action: "run_pg_migration", sql: "SELECT 1" },
        deps,
      );
      expect(result.success).toBe(false);
      expect(result.message).toContain("Postgres not configured");
    });

    it("should execute SQL successfully", async () => {
      const mockPool = {
        query: vi.fn().mockResolvedValue({
          command: "CREATE TABLE",
          rowCount: 0,
          rows: [],
        }),
      };
      vi.mocked(getPool).mockResolvedValue(mockPool as any);

      const result = await handleAdminRequest(
        { action: "run_pg_migration", sql: "CREATE TABLE test (id INT)" },
        deps,
      );
      expect(result.success).toBe(true);
      expect(result.message).toContain("Migration completed");
      expect(result.data).toEqual({ rowCount: 0, rows: [] });
    });

    it("should handle SQL execution error", async () => {
      const mockPool = {
        query: vi.fn().mockRejectedValue(new Error("syntax error")),
      };
      vi.mocked(getPool).mockResolvedValue(mockPool as any);

      const result = await handleAdminRequest(
        { action: "run_pg_migration", sql: "BAD SQL" },
        deps,
      );
      expect(result.success).toBe(false);
      expect(result.message).toContain("Migration failed: syntax error");
    });

    it("should handle non-Error thrown values", async () => {
      const mockPool = {
        query: vi.fn().mockRejectedValue("string error"),
      };
      vi.mocked(getPool).mockResolvedValue(mockPool as any);

      const result = await handleAdminRequest(
        { action: "run_pg_migration", sql: "BAD SQL" },
        deps,
      );
      expect(result.success).toBe(false);
      expect(result.message).toContain("string error");
    });
  });
});
