import { describe, it, expect, vi } from "vitest";

import { handleAdminRequest } from "./admin-handler";
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
  it("should return not-implemented for unknown action", async () => {
    const result = await handleAdminRequest({ action: "flush_cache" }, deps);
    expect(result.success).toBe(false);
    expect(result.message).toContain("not yet implemented");
  });
});
