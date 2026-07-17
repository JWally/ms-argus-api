import { describe, expect, it } from "vitest";
import type { IntegrityResultsData } from "../helpers/payload-schema";
import type { MerchantProjectionInput } from "./shared";
import {
  automationProbability,
  detectDeveloperTools,
  hasIframeCryptoStuck,
} from "./automation";

function withDevice(
  device: unknown,
  userAgent = "Mozilla/5.0 (X11; Linux x86_64) Chrome/140 Safari/537.36",
): MerchantProjectionInput {
  return {
    session_id: "session",
    integrity: { device, user_agent: userAgent } as IntegrityResultsData,
  };
}

describe("automationProbability", () => {
  it("returns zero when the integrity payload is absent", () => {
    expect(automationProbability({ session_id: "session" })).toBe(0);
  });

  it("promotes any strict headless marker to 100", () => {
    const input = withDevice({ headless: { headlessRating: 33 } });
    expect(automationProbability(input)).toBe(100);
  });

  it("scores hard CDP residue at 100", () => {
    const input = withDevice({
      headless: { headlessRating: 0, cdp: { pwBindings: true } },
    });
    expect(automationProbability(input)).toBe(100);
  });

  it("scores a two-realm hot CDP timing shape at 75", () => {
    const input = withDevice({
      headless: {
        headlessRating: 0,
        cdp: {
          consoleTiming: { log_heavy_us: 63 },
          consoleTimingWorker: { log_heavy_us: 60 },
        },
      },
    });
    expect(automationProbability(input)).toBe(75);
  });

  it("keeps the DevTools-compatible proxy trap at suspect tier 60", () => {
    const input = withDevice({
      headless: {
        headlessRating: 0,
        cdp: { consoleTiming: { cdp_proto_proxy_trap: true } },
      },
    });
    expect(automationProbability(input)).toBe(60);
  });

  it("carves mobile browsers out of desktop weak evidence", () => {
    const input = withDevice(
      { headless: { headlessRating: 0, likeHeadlessRating: 80 } },
      "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 Mobile",
    );
    expect(automationProbability(input)).toBe(0);
  });
});

describe("automation projection predicates", () => {
  it("reads the developer-tools marker", () => {
    const input = withDevice({
      headless: { likeHeadless: { devToolsOpen: true } },
    });
    expect(detectDeveloperTools(input)).toBe(true);
  });

  it("requires iframe creation plus an unresponsive crypto probe", () => {
    const stuck = withDevice({
      status: { iframeCrypto: { iframe_created: true, responsive: false } },
    });
    const blocked = withDevice({
      status: { iframeCrypto: { iframe_created: false, responsive: false } },
    });
    expect(hasIframeCryptoStuck(stuck.integrity)).toBe(true);
    expect(hasIframeCryptoStuck(blocked.integrity)).toBe(false);
  });
});
