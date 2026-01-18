// src/services/profile/anomaly/browser-engine.test.ts
// AR-143: Tests for browser engine anomaly detection (math fingerprint validation)

import { describe, it, expect } from "vitest";
import { detectBrowserEngineAnomalies } from "./browser-engine";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectBrowserEngineAnomalies", () => {
  describe("AC1: Chrome UA with non-V8 math results", () => {
    it("should detect Chrome UA with Firefox math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, firefox: true, chrome: false },
              acosh: { value: 709.889355822726, firefox: true, chrome: false },
              atan: {
                value: -1.4711276743037347,
                firefox: true,
                chrome: false,
              },
              atanh: {
                value: -0.5493061443340548,
                firefox: true,
                chrome: false,
              },
              cbrt: { value: 12.182493960703473, firefox: true, chrome: false },
              // Large exponents below - eslint-disable for precision warnings
              cosh: {
                // eslint-disable-next-line no-loss-of-precision
                value: 1.9275814160560204e154,
                firefox: true,
                chrome: false,
              },
              expm1: {
                // eslint-disable-next-line no-loss-of-precision
                value: 8.218407461554972e307,
                firefox: true,
                chrome: false,
              },
              sinh: {
                // eslint-disable-next-line no-loss-of-precision
                value: -2.534358117654804e307,
                firefox: true,
                chrome: false,
              },
              tan: {
                // eslint-disable-next-line no-loss-of-precision
                value: -4.9896907939522056e291,
                firefox: true,
                chrome: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
      expect(signals[0].severity).toBe(0.85);
      expect(signals[0].evidence.expected).toContain("Chrome");
      expect(signals[0].evidence.actual).toContain("Firefox");
    });

    it("should detect Chrome UA with Safari math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, safari: true, chrome: false },
              acosh: { value: 709.889355822726, safari: true, chrome: false },
              atan: { value: -1.4711276743037347, safari: true, chrome: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
      expect(signals[0].severity).toBe(0.85);
      expect(signals[0].evidence.expected).toContain("Chrome");
      expect(signals[0].evidence.actual).toContain("Safari");
    });
  });

  describe("AC2: Firefox UA with non-SpiderMonkey math results", () => {
    it("should detect Firefox UA with Chrome math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
              atan: {
                value: -1.4711276743037347,
                chrome: true,
                firefox: false,
              },
              atanh: {
                value: -0.5493061443340548,
                chrome: true,
                firefox: false,
              },
              cbrt: { value: 12.182493960703473, chrome: true, firefox: false },
              // Large exponents below - eslint-disable for precision warnings
              cosh: {
                // eslint-disable-next-line no-loss-of-precision
                value: 1.9275814160560204e154,
                chrome: true,
                firefox: false,
              },
              expm1: {
                // eslint-disable-next-line no-loss-of-precision
                value: 8.218407461554972e307,
                chrome: true,
                firefox: false,
              },
              sinh: {
                // eslint-disable-next-line no-loss-of-precision
                value: -2.534358117654804e307,
                chrome: true,
                firefox: false,
              },
              tan: {
                // eslint-disable-next-line no-loss-of-precision
                value: -4.9896907939522056e291,
                chrome: true,
                firefox: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
      expect(signals[0].severity).toBe(0.85);
      expect(signals[0].evidence.expected).toContain("Firefox");
      expect(signals[0].evidence.actual).toContain("Chrome");
    });

    it("should detect Firefox UA with Safari math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, safari: true, firefox: false },
              acosh: { value: 709.889355822726, safari: true, firefox: false },
              atan: {
                value: -1.4711276743037347,
                safari: true,
                firefox: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
      expect(signals[0].severity).toBe(0.85);
    });
  });

  describe("AC3: Matching UA and math engine produces no signal", () => {
    it("should not flag Chrome UA with Chrome math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
              atan: {
                value: -1.4711276743037347,
                chrome: true,
                firefox: false,
              },
              atanh: {
                value: -0.5493061443340548,
                chrome: true,
                firefox: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag Firefox UA with Firefox math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, firefox: true, chrome: false },
              acosh: { value: 709.889355822726, firefox: true, chrome: false },
              atan: {
                value: -1.4711276743037347,
                firefox: true,
                chrome: false,
              },
              atanh: {
                value: -0.5493061443340548,
                firefox: true,
                chrome: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag Safari UA with Safari math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, safari: true, chrome: false },
              acosh: { value: 709.889355822726, safari: true, chrome: false },
              atan: { value: -1.4711276743037347, safari: true, chrome: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag Edge/Chromium UA with Chrome math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
              atan: {
                value: -1.4711276743037347,
                chrome: true,
                firefox: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag Brave UA with Chrome math fingerprint", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });
  });

  describe("AC4: Unknown browser or missing math data returns no signal", () => {
    it("should not flag when browser family is unknown", () => {
      const fingerprint = {
        user_agent: "CustomBot/1.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when user_agent is missing", () => {
      const fingerprint = {} as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when user_agent is undefined", () => {
      const fingerprint = { user_agent: undefined } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when math data is missing", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          // no maths field
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when maths.data is missing", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            // no data field
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when maths.data is empty", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {},
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when raw payload is undefined", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const signals = detectBrowserEngineAnomalies(fingerprint, undefined);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when raw payload is null", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const signals = detectBrowserEngineAnomalies(fingerprint, null);

      expect(signals).toHaveLength(0);
    });

    it("should not flag when raw payload is not an object", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const signals = detectBrowserEngineAnomalies(
        fingerprint,
        "not an object",
      );

      expect(signals).toHaveLength(0);
    });

    it("should not flag when loose is missing", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        // no loose field
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });
  });

  describe("AC5: Evidence includes claimed browser and detected engine", () => {
    it("should include browser name and engine name in evidence for mismatch", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, firefox: true, chrome: false },
              acosh: { value: 709.889355822726, firefox: true, chrome: false },
              atan: {
                value: -1.4711276743037347,
                firefox: true,
                chrome: false,
              },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.expected).toBeTruthy();
      expect(signals[0].evidence.actual).toBeTruthy();
      // Evidence should contain browser family and engine name
      expect(
        signals[0].evidence.expected.includes("Chrome") ||
          signals[0].evidence.expected.includes("V8"),
      ).toBe(true);
      expect(
        signals[0].evidence.actual.includes("Firefox") ||
          signals[0].evidence.actual.includes("SpiderMonkey"),
      ).toBe(true);
    });

    it("should include evidence fields array", () => {
      const fingerprint = {
        user_agent: "Mozilla/5.0 Firefox/120.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toBeDefined();
      expect(Array.isArray(signals[0].evidence.fields)).toBe(true);
      expect(signals[0].evidence.fields?.length).toBeGreaterThan(0);
    });
  });

  describe("edge cases and mixed signals", () => {
    it("should handle math results with mixed engine markers", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
              atan: {
                value: -1.4711276743037347,
                firefox: true,
                chrome: false,
              }, // Mixed
              atanh: {
                value: -0.5493061443340548,
                chrome: true,
                firefox: false,
              },
            },
          },
        },
      };

      // Should use majority vote - Chrome wins 3:1, so no signal
      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should detect when majority of math results contradict UA", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, firefox: true, chrome: false },
              acosh: { value: 709.889355822726, firefox: true, chrome: false },
              atan: {
                value: -1.4711276743037347,
                firefox: true,
                chrome: false,
              },
              atanh: {
                value: -0.5493061443340548,
                firefox: true,
                chrome: false,
              },
              cbrt: { value: 12.182493960703473, chrome: true, firefox: false }, // Minority
            },
          },
        },
      };

      // 4 Firefox vs 1 Chrome - should detect Firefox engine
      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
    });

    it("should handle Safari UA detection correctly", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, safari: false },
              acosh: { value: 709.889355822726, chrome: true, safari: false },
              atan: { value: -1.4711276743037347, chrome: true, safari: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
      expect(signals[0].evidence.expected).toContain("Safari");
      expect(signals[0].evidence.actual).toContain("Chrome");
    });

    it("should not crash on malformed math data structure", () => {
      const fingerprint = {
        user_agent: "Mozilla/5.0 Chrome/120.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: "not an object", // Malformed
              acosh: null, // Malformed
              atan: { value: 123 }, // Missing engine markers
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      // Should handle gracefully - no signal due to insufficient data
      expect(signals).toHaveLength(0);
    });

    it("should handle user agent with multiple browser names", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
              acosh: { value: 709.889355822726, chrome: true, firefox: false },
            },
          },
        },
      };

      // Should prioritize actual browser (Chrome) over engine reference (AppleWebKit, Safari)
      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });
  });

  describe("all browsers covered", () => {
    it("should handle Opera/Chromium UA with Chrome math", () => {
      const fingerprint = {
        user_agent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, chrome: true, firefox: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(0);
    });

    it("should detect Safari UA with Firefox math as mismatch", () => {
      const fingerprint = {
        user_agent: "Mozilla/5.0 Safari/605.1.15",
      } as Fingerprint;

      const raw = {
        loose: {
          maths: {
            data: {
              acos: { value: 1.4473588658278522, firefox: true, safari: false },
              acosh: { value: 709.889355822726, firefox: true, safari: false },
            },
          },
        },
      };

      const signals = detectBrowserEngineAnomalies(fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.MATH_ENGINE_MISMATCH);
    });
  });
});
