import { describe, it, expect } from "vitest";
import { detectOS } from "./os-detection";
import type { Fingerprint } from "../../types/fingerprint";

function fp(overrides: Partial<Fingerprint> = {}): Fingerprint {
  return { stable_hash: "abc", ...overrides };
}

describe("detectOS", () => {
  it("detects iOS from iPhone platform", () => {
    expect(detectOS(fp({ platform: "iPhone" }))).toBe("ios");
  });

  it("detects iOS from iPad platform", () => {
    expect(detectOS(fp({ platform: "iPad7,5" }))).toBe("ios");
  });

  it("detects iOS from iPad even with Mac UA (desktop mode)", () => {
    expect(
      detectOS(
        fp({
          platform: "iPad7,5",
          user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        }),
      ),
    ).toBe("ios");
  });

  it("detects Android from user agent", () => {
    expect(
      detectOS(
        fp({
          user_agent: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
        }),
      ),
    ).toBe("android");
  });

  it("detects Windows from user agent", () => {
    expect(
      detectOS(
        fp({
          user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }),
      ),
    ).toBe("windows");
  });

  it("detects Mac from user agent", () => {
    expect(
      detectOS(
        fp({
          user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        }),
      ),
    ).toBe("mac");
  });

  it("detects Linux from user agent", () => {
    expect(
      detectOS(fp({ user_agent: "Mozilla/5.0 (X11; Linux x86_64)" })),
    ).toBe("linux");
  });

  it("detects Linux from ChromeOS user agent", () => {
    expect(
      detectOS(
        fp({
          user_agent: "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/120.0",
        }),
      ),
    ).toBe("linux");
  });

  it("defaults to linux for unknown OS", () => {
    expect(detectOS(fp({}))).toBe("linux");
    expect(detectOS(fp({ user_agent: "SomeWeirdBot/1.0" }))).toBe("linux");
  });

  it("prioritises platform over UA (iPhone with Chrome UA)", () => {
    expect(
      detectOS(
        fp({
          platform: "iPhone",
          user_agent: "Mozilla/5.0 (Linux; Android 14) Chrome/120.0",
        }),
      ),
    ).toBe("ios");
  });
});
