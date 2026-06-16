import { describe, it, expect } from "vitest";
import { analyzeClientHintsUa, parseChUaBrands } from "./index";

const MAC_CHROME_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const WIN_CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const IPHONE_SAFARI_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1";
const LINUX_CHROME_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const ANDROID_CHROME_UA =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

const CHROME_BRANDS =
  '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"';
const EDGE_BRANDS =
  '"Microsoft Edge";v="131", "Chromium";v="131", "Not?A_Brand";v="24"';
const CHROMIUM_ONLY_BRANDS = '"Chromium";v="131", "Not_A Brand";v="24"';

describe("parseChUaBrands", () => {
  it("null / empty → []", () => {
    expect(parseChUaBrands(null)).toEqual([]);
    expect(parseChUaBrands("")).toEqual([]);
    expect(parseChUaBrands(undefined)).toEqual([]);
  });

  it("extracts Chrome brands, strips Not_A_Brand", () => {
    expect(parseChUaBrands(CHROME_BRANDS)).toEqual([
      "Chromium",
      "Google Chrome",
    ]);
  });

  it("extracts Edge brands", () => {
    expect(parseChUaBrands(EDGE_BRANDS)).toEqual([
      "Microsoft Edge",
      "Chromium",
    ]);
  });

  it("strips variant GREASE brands (Not A(Brand, Not?A_Brand, Not_A Brand)", () => {
    expect(parseChUaBrands('"Not A(Brand";v="24", "Chromium";v="131"')).toEqual(
      ["Chromium"],
    );
  });
});

describe("analyzeClientHintsUa — no signals", () => {
  it("empty inputs → no signals", () => {
    const r = analyzeClientHintsUa(null, null, null);
    expect(r.signals).toEqual([]);
    expect(r.hasStrongMismatch).toBe(false);
  });

  it("Mac Chrome with matching CH header → clean", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
      },
      {
        client_hints: {
          ua: CHROME_BRANDS,
          ua_mobile: "?0",
          ua_platform: '"macOS"',
        },
      },
    );
    expect(r.signals).toEqual([]);
  });

  it("iPhone Safari with no Sec-CH-UA (typical Safari behavior) → no signal", () => {
    const r = analyzeClientHintsUa(IPHONE_SAFARI_UA, {}, null);
    expect(r.signals).toEqual([]);
  });

  it("Linux Chrome matching → clean", () => {
    const r = analyzeClientHintsUa(
      LINUX_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
      },
      null,
    );
    expect(r.signals).toEqual([]);
  });

  it("Android Chrome matching (mobile) → clean", () => {
    const r = analyzeClientHintsUa(
      ANDROID_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
      },
      null,
    );
    expect(r.signals).toEqual([]);
  });
});

describe("CH_UA_PLATFORM_MISMATCH", () => {
  it("header says macOS, UA says Windows → fires", () => {
    const r = analyzeClientHintsUa(
      WIN_CHROME_UA,
      {
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua": CHROME_BRANDS,
      },
      null,
    );
    const sig = r.signals.find((s) => s.code === "CH_UA_PLATFORM_MISMATCH");
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.85);
    expect(sig?.evidence).toContain("macOS");
    expect(sig?.evidence).toContain("Windows");
  });

  it("header says iOS, UA says Mac → fires", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua-platform": '"iOS"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua": CHROME_BRANDS,
      },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_PLATFORM_MISMATCH"),
    ).toBeDefined();
  });

  it("header missing → no check fires", () => {
    const r = analyzeClientHintsUa(WIN_CHROME_UA, {}, null);
    expect(
      r.signals.find((s) => s.code === "CH_UA_PLATFORM_MISMATCH"),
    ).toBeUndefined();
  });

  it("falls back to probe platform when header missing", () => {
    const r = analyzeClientHintsUa(WIN_CHROME_UA, null, {
      client_hints: {
        ua_platform: '"macOS"',
        ua_mobile: "?0",
        ua: CHROME_BRANDS,
      },
    });
    expect(
      r.signals.find((s) => s.code === "CH_UA_PLATFORM_MISMATCH"),
    ).toBeDefined();
  });
});

describe("CH_UA_MOBILE_MISMATCH", () => {
  it("header says mobile=?1 but UA is desktop → fires", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua": CHROME_BRANDS,
      },
      null,
    );
    const sig = r.signals.find((s) => s.code === "CH_UA_MOBILE_MISMATCH");
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.8);
  });

  it("header says mobile=?0 but UA is Android mobile → fires", () => {
    const r = analyzeClientHintsUa(
      ANDROID_CHROME_UA,
      {
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua": CHROME_BRANDS,
      },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_MOBILE_MISMATCH"),
    ).toBeDefined();
  });

  it("invalid mobile value → no crash, no signal", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      { "sec-ch-ua-mobile": "garbage" },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_MOBILE_MISMATCH"),
    ).toBeUndefined();
  });
});

describe("CH_UA_BRAND_MISMATCH", () => {
  it("brand says Edge but UA says Chrome → fires", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": EDGE_BRANDS,
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
      },
      null,
    );
    const sig = r.signals.find((s) => s.code === "CH_UA_BRAND_MISMATCH");
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.9);
    expect(sig?.evidence).toContain("edge");
    expect(sig?.evidence).toContain("chromium");
  });

  it("chromium-only brand with Chrome UA → no signal (both chromium family)", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROMIUM_ONLY_BRANDS,
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
      },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_BRAND_MISMATCH"),
    ).toBeUndefined();
  });

  // Modern Chromium-based Edge ships UA with the bare `Edg/` token (no
  // suffix). The original UA-family regex required `Edge|EdgA|EdgiOS`
  // and missed bare `Edg/`, classifying every real Edge desktop visitor
  // as `chromium` family — which then mismatched the `edge` brand
  // family and fired CH_UA_BRAND_MISMATCH on all of them.
  // Confirmed live 2026-05-19 from session 83eaba12 (Linux Edge 148).
  it("real Linux Edge desktop (Edg/) + Edge brands → no mismatch", () => {
    const r = analyzeClientHintsUa(
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
      {
        "sec-ch-ua": '"Microsoft Edge";v="148"',
        "sec-ch-ua-platform": '"Linux"',
        "sec-ch-ua-mobile": "?0",
      },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_BRAND_MISMATCH"),
    ).toBeUndefined();
  });

  it("Windows Edge desktop (Edg/) + 3-brand Sec-CH-UA → no mismatch", () => {
    const r = analyzeClientHintsUa(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
      { "sec-ch-ua": EDGE_BRANDS },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_BRAND_MISMATCH"),
    ).toBeUndefined();
  });

  it("Edge mobile (EdgA/) + Edge brand → no mismatch (regression-guard)", () => {
    const r = analyzeClientHintsUa(
      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36 EdgA/148.0.0.0",
      { "sec-ch-ua": EDGE_BRANDS },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_BRAND_MISMATCH"),
    ).toBeUndefined();
  });
});

describe("CH_DOUBLE_CAPTURE_MISMATCH", () => {
  it("probe and header platforms disagree → fires", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
      },
      {
        client_hints: {
          ua: CHROME_BRANDS,
          ua_platform: '"Windows"',
          ua_mobile: "?0",
        },
      },
    );
    const sig = r.signals.find((s) => s.code === "CH_DOUBLE_CAPTURE_MISMATCH");
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.9);
    expect(sig?.evidence).toContain("macOS");
    expect(sig?.evidence).toContain("Windows");
  });

  it("probe mobile hint disagrees with header mobile → fires", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
      },
      {
        client_hints: {
          ua: CHROME_BRANDS,
          ua_platform: '"macOS"',
          ua_mobile: "?1",
        },
      },
    );
    expect(
      r.signals.find((s) => s.code === "CH_DOUBLE_CAPTURE_MISMATCH"),
    ).toBeDefined();
  });

  it("probe brand family differs from header brand family → fires", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
      },
      {
        client_hints: {
          ua: EDGE_BRANDS,
          ua_platform: '"macOS"',
          ua_mobile: "?0",
        },
      },
    );
    expect(
      r.signals.find((s) => s.code === "CH_DOUBLE_CAPTURE_MISMATCH"),
    ).toBeDefined();
  });

  it("only one side populated → no double-capture signal", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
      },
      null,
    );
    expect(
      r.signals.find((s) => s.code === "CH_DOUBLE_CAPTURE_MISMATCH"),
    ).toBeUndefined();
  });
});

describe("hasStrongMismatch", () => {
  it("true when any signal >= 0.8", () => {
    const r = analyzeClientHintsUa(
      WIN_CHROME_UA,
      {
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua": CHROME_BRANDS,
      },
      null,
    );
    expect(r.hasStrongMismatch).toBe(true);
  });

  it("false when no signals", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua": CHROME_BRANDS,
      },
      null,
    );
    expect(r.hasStrongMismatch).toBe(false);
  });
});

describe("real-session replays", () => {
  it("Playwright HeadlessChrome session (7375ba1e) — fully internally consistent, no mismatches", () => {
    // Real payload we observed — all fields agree. No signals should fire.
    const r = analyzeClientHintsUa(
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/143.0.7499.4 Safari/537.36",
      {
        "sec-ch-ua":
          '"HeadlessChrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
      },
      {
        client_hints: {
          ua: '"HeadlessChrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
          ua_mobile: "?0",
          ua_platform: '"Linux"',
        },
      },
    );
    expect(r.signals).toEqual([]);
  });

  it("SOAX Mac Chrome session (b6bc08e5) — fully consistent", () => {
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROMIUM_ONLY_BRANDS,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
      },
      {
        client_hints: {
          ua: CHROMIUM_ONLY_BRANDS,
          ua_mobile: "?0",
          ua_platform: '"macOS"',
        },
      },
    );
    expect(r.signals).toEqual([]);
  });

  it("hypothetical Multilogin-style profile-mismatch (platform header rotated but UA not)", () => {
    // Anti-detect browser rotates the Sec-CH-UA-Platform to 'Windows' for
    // a session but leaves the UA string as macOS. Classic partial-spoof tell.
    const r = analyzeClientHintsUa(
      MAC_CHROME_UA,
      {
        "sec-ch-ua": CHROME_BRANDS,
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-mobile": "?0",
      },
      {
        client_hints: {
          ua: CHROME_BRANDS,
          ua_mobile: "?0",
          ua_platform: '"Windows"',
        },
      },
    );
    expect(
      r.signals.find((s) => s.code === "CH_UA_PLATFORM_MISMATCH"),
    ).toBeDefined();
    expect(r.hasStrongMismatch).toBe(true);
  });
});

describe("CH_UA_VERSION_MISMATCH (#5) — UA version vs UA-CH version", () => {
  const CHROME131_UA =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
  const CHROME149_UA =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

  it("fires when UA says Chrome 131 but userAgentData reports Chromium 143 (Playwright mask)", () => {
    const r = analyzeClientHintsUa(
      CHROME131_UA,
      {
        "sec-ch-ua":
          '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
      },
      undefined,
      {
        navigator: {
          userAgentData: {
            brands: ["Chromium"],
            brandsVersion: ["Chromium 143"],
            uaFullVersion: "",
          },
        },
      },
    );
    const s = r.signals.find((x) => x.code === "CH_UA_VERSION_MISMATCH");
    expect(s).toBeDefined();
    expect(s?.evidence).toContain("ua-string=131");
    expect(s?.evidence).toContain("navigator=143");
    expect(r.hasStrongMismatch).toBe(true);
  });

  it("does not fire when UA and userAgentData agree (real Chrome 149)", () => {
    const r = analyzeClientHintsUa(
      CHROME149_UA,
      {
        "sec-ch-ua":
          '"Google Chrome";v="149", "Chromium";v="149", "Not_A Brand";v="24"',
      },
      undefined,
      { navigator: { userAgentData: { uaFullVersion: "149.0.7827.103" } } },
    );
    expect(
      r.signals.find((x) => x.code === "CH_UA_VERSION_MISMATCH"),
    ).toBeUndefined();
  });

  it("fires when the main thread matches but a worker scope leaks the real version", () => {
    const r = analyzeClientHintsUa(
      CHROME131_UA,
      { "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"' },
      undefined,
      {
        navigator: { userAgentData: { uaFullVersion: "131.0.0.0" } },
        workerScope: {
          scopes: {
            web: { userAgentData: { brandsVersion: ["Chromium 143"] } },
          },
        },
      },
    );
    const s = r.signals.find((x) => x.code === "CH_UA_VERSION_MISMATCH");
    expect(s).toBeDefined();
    expect(s?.evidence).toContain("worker.web=143");
  });

  it("does not fire on non-Chromium (Firefox) — no UA-CH to cross-check", () => {
    const r = analyzeClientHintsUa(
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
      {},
      undefined,
      { navigator: {} },
    );
    expect(
      r.signals.find((x) => x.code === "CH_UA_VERSION_MISMATCH"),
    ).toBeUndefined();
  });
});
