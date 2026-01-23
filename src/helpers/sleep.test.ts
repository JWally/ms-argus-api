// src/helpers/sleep.test.ts
// AR-210: Tests for consolidated sleep utility
import { describe, it, expect } from "vitest";
import { sleep } from "./sleep";

describe("sleep", () => {
  it("should resolve immediately for sleep(0)", async () => {
    const start = Date.now();
    await sleep(0);
    const elapsed = Date.now() - start;
    // Should complete within a reasonable tolerance (< 50ms)
    expect(elapsed).toBeLessThan(50);
  });

  it("should resolve after approximately the specified duration", async () => {
    const start = Date.now();
    await sleep(50);
    const elapsed = Date.now() - start;
    // Should be at least 40ms (allowing for timer imprecision)
    expect(elapsed).toBeGreaterThanOrEqual(40);
    // Should not take excessively long (< 200ms)
    expect(elapsed).toBeLessThan(200);
  });

  it("should return a Promise", () => {
    const result = sleep(10);
    expect(result).toBeInstanceOf(Promise);
  });
});
