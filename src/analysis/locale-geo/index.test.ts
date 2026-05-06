import { describe, it, expect } from "vitest";
import { analyzeLocaleGeo } from "./index";
import { parseAcceptLanguage, COUNTRY_TO_CONTINENT } from "./reference";

describe("parseAcceptLanguage", () => {
  it("null / empty → null", () => {
    expect(parseAcceptLanguage(null)).toBeNull();
    expect(parseAcceptLanguage(undefined)).toBeNull();
    expect(parseAcceptLanguage("")).toBeNull();
  });

  it("parses language with explicit country", () => {
    expect(parseAcceptLanguage("en-US,en;q=0.9,fr;q=0.7")).toEqual({
      lang: "en",
      country: "US",
    });
  });

  it("parses language without country", () => {
    expect(parseAcceptLanguage("zh,en;q=0.9")).toEqual({
      lang: "zh",
      country: null,
    });
  });

  it("handles single-language header", () => {
    expect(parseAcceptLanguage("fr-FR")).toEqual({ lang: "fr", country: "FR" });
  });

  it("handles extended tags (en-GB-oxendict)", () => {
    expect(parseAcceptLanguage("en-GB-oxendict")).toEqual({
      lang: "en",
      country: "GB",
    });
  });

  it("lowercases language, uppercases country", () => {
    expect(parseAcceptLanguage("EN-us")).toEqual({ lang: "en", country: "US" });
  });

  it("rejects malformed primary token", () => {
    expect(parseAcceptLanguage("!!!")).toBeNull();
    expect(parseAcceptLanguage("q=0.5")).toBeNull();
  });
});

describe("COUNTRY_TO_CONTINENT smoke test", () => {
  it("US is NA", () => expect(COUNTRY_TO_CONTINENT.US).toBe("NA"));
  it("DE is EU", () => expect(COUNTRY_TO_CONTINENT.DE).toBe("EU"));
  it("CN is AS", () => expect(COUNTRY_TO_CONTINENT.CN).toBe("AS"));
  it("ZA is AF", () => expect(COUNTRY_TO_CONTINENT.ZA).toBe("AF"));
  it("BR is SA", () => expect(COUNTRY_TO_CONTINENT.BR).toBe("SA"));
  it("AU is OC", () => expect(COUNTRY_TO_CONTINENT.AU).toBe("OC"));
});

describe("analyzeLocaleGeo — empty / null inputs", () => {
  it("no device → no signals", () => {
    const r = analyzeLocaleGeo(null, null, null);
    expect(r.signals).toEqual([]);
    expect(r.hasLocaleTamper).toBe(false);
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("device but no locale fields → no signals", () => {
    const r = analyzeLocaleGeo({}, null, null);
    expect(r.signals).toEqual([]);
  });

  it("missing accept-language → no geo signal", () => {
    const r = analyzeLocaleGeo({ intl: { locale: "en-US" } }, null, "US");
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("missing cfCountry → no geo signal", () => {
    const r = analyzeLocaleGeo({ intl: { locale: "en-US" } }, "en-US", null);
    expect(r.hasLocationMismatch).toBe(false);
  });
});

describe("A1 — intl.locale vs navigator.language", () => {
  it("matching locales → no signal", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "en-US" },
        navigator: { language: "en-US (en-US)" },
      },
      null,
      null,
    );
    expect(
      r.signals.filter((s) => s.code === "LOCALE_NAV_INTL_MISMATCH"),
    ).toEqual([]);
  });

  it("different languages → LOCALE_NAV_INTL_MISMATCH", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "fr-FR" },
        navigator: { language: "en-US (en-US)" },
      },
      null,
      null,
    );
    const sig = r.signals.find((s) => s.code === "LOCALE_NAV_INTL_MISMATCH");
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.85);
  });

  it("country differs but language matches → no signal (real expat case)", () => {
    // en-GB vs en-US: both are English, legitimate expat/mid-Atlantic profile.
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "en-GB" },
        navigator: { language: "en-US (en-US)" },
      },
      null,
      null,
    );
    expect(
      r.signals.filter((s) => s.code === "LOCALE_NAV_INTL_MISMATCH"),
    ).toEqual([]);
  });

  it("strips 'lang (parens)' format from navigator.language", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "en-US" },
        navigator: { language: "en-US (en-US)" },
      },
      null,
      null,
    );
    expect(r.hasLocaleTamper).toBe(false);
  });
});

describe("A2 — worker locale vs main-thread locale", () => {
  it("all workers match main → no signal", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "en-US" },
        navigator: { language: "en-US" },
        workerScope: {
          scopes: {
            web: { locale: "en-US" },
            shared: { locale: "en-US" },
          },
        },
      },
      null,
      null,
    );
    expect(
      r.signals.filter((s) => s.code === "LOCALE_WORKER_MAIN_MISMATCH"),
    ).toEqual([]);
  });

  it("worker locale disagrees with main → LOCALE_WORKER_MAIN_MISMATCH", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "en-US" },
        workerScope: {
          scopes: {
            web: { locale: "fr-FR" },
            shared: { locale: "en-US" },
          },
        },
      },
      null,
      null,
    );
    const sig = r.signals.find((s) => s.code === "LOCALE_WORKER_MAIN_MISMATCH");
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.75);
    expect(sig?.evidence).toContain("fr-FR");
  });

  it("no workers → no signal (benign)", () => {
    const r = analyzeLocaleGeo({ intl: { locale: "en-US" } }, null, null);
    expect(
      r.signals.filter((s) => s.code === "LOCALE_WORKER_MAIN_MISMATCH"),
    ).toEqual([]);
  });
});

describe("B1 — Accept-Language vs CF country", () => {
  it("exact match country → no signal", () => {
    const r = analyzeLocaleGeo({}, "en-US,en;q=0.9", "US");
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("cross-continent language → ACCEPT_LANG_GEO_CROSS_CONTINENT (sev 0.7)", () => {
    const r = analyzeLocaleGeo({}, "zh-CN,zh;q=0.9", "US");
    const sig = r.signals.find(
      (s) => s.code === "ACCEPT_LANG_GEO_CROSS_CONTINENT",
    );
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.7);
    expect(sig?.evidence).toContain("Asia");
    expect(sig?.evidence).toContain("North America");
  });

  it("same-continent different country → ACCEPT_LANG_GEO_CROSS_COUNTRY (sev 0.4)", () => {
    // French speaker visiting from Germany (different country, same continent)
    const r = analyzeLocaleGeo({}, "fr-FR", "DE");
    const sig = r.signals.find(
      (s) => s.code === "ACCEPT_LANG_GEO_CROSS_COUNTRY",
    );
    expect(sig).toBeDefined();
    expect(sig?.severity).toBe(0.4);
  });

  it("plausibility-set hit (no country, but lang matches CF) → no signal", () => {
    // 'en' with IP=GB: GB is in the en plausibility set → clean.
    const r = analyzeLocaleGeo({}, "en", "GB");
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("plausibility-set miss (no country in header) → uses most-populous mapping", () => {
    // Header 'zh' (no country) from US IP: CN not US, cross-continent.
    const r = analyzeLocaleGeo({}, "zh", "US");
    expect(
      r.signals.find((s) => s.code === "ACCEPT_LANG_GEO_CROSS_CONTINENT"),
    ).toBeDefined();
  });

  it("unknown language → no assertion (skip)", () => {
    const r = analyzeLocaleGeo({}, "xx", "US");
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("malformed accept-language → no crash, no signal", () => {
    const r = analyzeLocaleGeo({}, "!!!garbage", "US");
    expect(r.signals).toEqual([]);
  });

  it("real-world Chicago carder pattern (en-US from Nigeria IP)", () => {
    const r = analyzeLocaleGeo({}, "en-US,en;q=0.9", "NG");
    // en-US claims US, IP shows NG (Africa) → cross-continent
    expect(
      r.signals.find((s) => s.code === "ACCEPT_LANG_GEO_CROSS_CONTINENT"),
    ).toBeDefined();
  });

  it("regional spelling preference (en-GB on a US iPhone) → no signal", () => {
    // Common iPhone config: user prefers British English spelling but lives
    // in the US. The country subtag is a preference, not a geo claim.
    const r = analyzeLocaleGeo({}, "en-GB", "US");
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("regional spelling preference (en-AU on a US user) → no signal", () => {
    const r = analyzeLocaleGeo({}, "en-AU,en;q=0.9", "US");
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("language implausible for IP country still fires (zh-CN from US)", () => {
    // Sanity: the suppression only applies when the language itself is
    // plausible for the IP country. zh isn't a US language → still fires.
    const r = analyzeLocaleGeo({}, "zh-CN", "US");
    expect(
      r.signals.find((s) => s.code === "ACCEPT_LANG_GEO_CROSS_CONTINENT"),
    ).toBeDefined();
  });
});

describe("analyzeLocaleGeo — convenience flags", () => {
  it("hasLocaleTamper true when only A1 fires", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "fr-FR" },
        navigator: { language: "en-US" },
      },
      null,
      null,
    );
    expect(r.hasLocaleTamper).toBe(true);
    expect(r.hasLocationMismatch).toBe(false);
  });

  it("hasLocationMismatch true when only B1 fires", () => {
    const r = analyzeLocaleGeo({}, "zh-CN", "US");
    expect(r.hasLocationMismatch).toBe(true);
    expect(r.hasLocaleTamper).toBe(false);
  });

  it("both flags true when both groups fire", () => {
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "fr-FR" },
        navigator: { language: "en-US" },
      },
      "zh-CN",
      "US",
    );
    expect(r.hasLocaleTamper).toBe(true);
    expect(r.hasLocationMismatch).toBe(true);
    expect(r.signals.length).toBe(2);
  });
});

describe("real-session replays", () => {
  it("WG EC2 session (7375ba1e) — client TZ Chicago, IP Virginia, en-US everywhere: clean locale, clean B1", () => {
    // This session had TZ_GEOLOCATION_MISMATCH at the TZ analyzer, but
    // locale-geo only checks language vs country. Both en-US, both US → clean.
    const r = analyzeLocaleGeo(
      {
        intl: { locale: "en-US" },
        navigator: { language: "en-US (en-US)" },
        workerScope: {
          scopes: {
            web: { locale: "en-US" },
            shared: { locale: "en-US" },
          },
        },
      },
      "en-US,en;q=0.9",
      "US",
    );
    expect(r.signals).toEqual([]);
  });
});
