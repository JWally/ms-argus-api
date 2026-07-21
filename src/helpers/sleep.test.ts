import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sleep } from "./sleep";

describe("sleep", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("resolves on the next timer turn for sleep(0)", async () => {
    let resolved = false;
    const pending = sleep(0).then(() => {
      resolved = true;
      return undefined;
    });

    expect(resolved).toBe(false);
    await vi.advanceTimersByTimeAsync(0);
    await pending;
    expect(resolved).toBe(true);
  });

  it("does not resolve before the specified duration", async () => {
    let resolved = false;
    const pending = sleep(50).then(() => {
      resolved = true;
      return undefined;
    });

    await vi.advanceTimersByTimeAsync(49);
    expect(resolved).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await pending;
    expect(resolved).toBe(true);
  });

  it("returns a Promise", () => {
    expect(sleep(10)).toBeInstanceOf(Promise);
  });
});
