/**
 * Browser-family / engine lookup tables used by signal-learning validation.
 *
 * The full detectEngineCoherence detector + its helpers were removed along
 * with the fingerprint matching pipeline — only the categorical maps here
 * are still consumed (by signal-learning/validate.ts).
 */

/** JS engine → browser family. */
export const ENGINE_FAMILY: Record<string, string> = {
  V8: "chromium",
  SpiderMonkey: "firefox",
  JavaScriptCore: "apple",
};

/** Set of engine combinations (jsEngine + layoutEngine) that are coherent. */
export const VALID_ENGINE_COMBOS = new Set([
  "V8|Blink",
  "SpiderMonkey|Gecko",
  "JavaScriptCore|WebKit",
]);

/** navigator.vendor → browser family. */
export const VENDOR_FAMILY: Record<string, string> = {
  "Google Inc.": "chromium",
  "Apple Computer, Inc.": "apple",
  "": "firefox",
};
