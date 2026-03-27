import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

function num(v: unknown): v is number {
  return typeof v === "number";
}

const F_SCREEN_W = "screen.width";
const F_SCREEN_H = "screen.height";

/** Check screen dimensions vs CSS media screen query. */
function checkScreenCssMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const screen = device.screen;
  const cssMedia = device.cssMedia;
  if (!isObj(screen) || !isObj(cssMedia)) return null;
  const screenQuery = cssMedia.screenQuery;
  if (!isObj(screenQuery)) return null;

  const sw = screen.width;
  const sh = screen.height;
  const cw = screenQuery.width;
  const ch = screenQuery.height;
  if (!num(sw) || !num(sh) || !num(cw) || !num(ch)) return null;

  if (sw !== cw || sh !== ch) {
    return createSignal("CROSS_FIELD", AnomalyCodes.SCREEN_CSS_MISMATCH, 0.9, {
      expected: `screen ${sw}x${sh} matches CSS screenQuery`,
      actual: `screen ${sw}x${sh} vs CSS ${cw}x${ch}`,
      fields: [
        F_SCREEN_W,
        F_SCREEN_H,
        "cssMedia.screenQuery.width",
        "cssMedia.screenQuery.height",
      ],
    });
  }
  return null;
}

/** Check for audio fingerprint noise (anti-fingerprint extension indicator). */
function checkAudioNoise(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const audio = device.offlineAudioContext;
  if (!isObj(audio)) return null;
  const noise = audio.noise;
  if (typeof noise !== "number") return null;
  if (noise > 0) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.AUDIO_NOISE_DETECTED,
      0.85,
      {
        expected: "audio noise: 0",
        actual: `audio noise: ${noise}`,
        fields: ["offlineAudioContext.noise"],
      },
    );
  }
  return null;
}

/** Check timezone offset consistency between main thread and worker scope. */
function checkTimezoneOffsetMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const tz = device.timezone;
  const ws = device.workerScope;
  if (!isObj(tz) || !isObj(ws)) return null;

  const mainOffset = tz.offset;
  const workerOffset = ws.timezoneOffset;
  if (typeof mainOffset !== "number" || typeof workerOffset !== "number")
    return null;

  if (mainOffset !== workerOffset) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.TIMEZONE_OFFSET_MISMATCH,
      0.9,
      {
        expected: `timezone offset consistent (${mainOffset})`,
        actual: `main: ${mainOffset} vs worker: ${workerOffset}`,
        fields: ["timezone.offset", "workerScope.timezoneOffset"],
      },
    );
  }
  return null;
}

/** Collect touch-related contradictions from screen and CSS media signals. */
function collectTouchMismatches(
  screen: Record<string, unknown> | null,
  cssMedia: Record<string, unknown> | null,
): string[] {
  const mismatches: string[] = [];
  const touchFalse = screen !== null && screen.touch === false;

  if (touchFalse) {
    mismatches.push("screen.touch=false");
  }

  if (cssMedia !== null && touchFalse) {
    const { anyPointer, anyHover } = cssMedia;
    if (anyPointer === "fine" && anyHover === "hover") {
      mismatches.push(`pointer=${anyPointer},hover=${anyHover}`);
    }
  }

  return mismatches;
}

/** Check touch capability coherence (maxTouchPoints vs touch/pointer signals). */
function checkTouchMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const nav = device.navigator;
  if (!isObj(nav)) return null;

  const maxTouch = nav.maxTouchPoints;
  if (typeof maxTouch !== "number" || maxTouch <= 0) return null;

  const screen = isObj(device.screen) ? device.screen : null;
  const cssMedia = isObj(device.cssMedia) ? device.cssMedia : null;
  const mismatches = collectTouchMismatches(screen, cssMedia);

  if (mismatches.length === 0) return null;

  return createSignal("CROSS_FIELD", AnomalyCodes.TOUCH_MISMATCH, 0.7, {
    expected: `maxTouchPoints=${maxTouch} consistent with touch signals`,
    actual: `maxTouchPoints=${maxTouch} but ${mismatches.join(", ")}`,
    fields: [
      "navigator.maxTouchPoints",
      "screen.touch",
      "cssMedia.anyPointer",
      "cssMedia.anyHover",
    ],
  });
}

/** Check WebGL renderer consistency between main context and worker scope. */
function checkWebglRendererMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const webgl = device.canvasWebgl;
  const ws = device.workerScope;
  if (!isObj(webgl) || !isObj(ws)) return null;
  const params = webgl.parameters;
  if (!isObj(params)) return null;

  const mainRenderer = params.UNMASKED_RENDERER_WEBGL;
  const workerRenderer = ws.webglRenderer;
  if (typeof mainRenderer !== "string" || typeof workerRenderer !== "string")
    return null;

  if (mainRenderer !== workerRenderer) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.WEBGL_RENDERER_MISMATCH,
      0.85,
      {
        expected: "WebGL renderer consistent across contexts",
        actual: `main: ${mainRenderer.substring(0, 60)} vs worker: ${workerRenderer.substring(0, 60)}`,
        fields: [
          "canvasWebgl.parameters.UNMASKED_RENDERER_WEBGL",
          "workerScope.webglRenderer",
        ],
      },
    );
  }
  return null;
}

/** Check timezone.offset vs timezone.offsetComputed (independently derived). */
function checkTzOffsetComputed(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const tz = device.timezone;
  if (!isObj(tz)) return null;
  const { offset, offsetComputed } = tz;
  if (typeof offset !== "number" || typeof offsetComputed !== "number")
    return null;
  if (offset !== offsetComputed) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
      0.9,
      {
        expected: `offset (${offset}) === offsetComputed`,
        actual: `offset: ${offset} vs computed: ${offsetComputed}`,
        fields: ["timezone.offset", "timezone.offsetComputed"],
      },
    );
  }
  return null;
}

function str(v: unknown): v is string {
  return typeof v === "string";
}

/** Compare mediaCSS vs matchMediaCSS — two APIs that should produce identical results. */
function checkCssMediaApiMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const cm = device.cssMedia;
  if (!isObj(cm)) return null;
  const mediaCSS = cm.mediaCSS;
  const matchCSS = cm.matchMediaCSS;
  if (!isObj(mediaCSS) || !isObj(matchCSS)) return null;

  const diffs: string[] = [];
  for (const key of Object.keys(mediaCSS)) {
    const a = mediaCSS[key];
    const b = matchCSS[key];
    if (str(a) && str(b) && a !== b) diffs.push(key);
  }
  if (diffs.length === 0) return null;

  return createSignal(
    "CROSS_FIELD",
    AnomalyCodes.CSS_MEDIA_API_MISMATCH,
    0.85,
    {
      expected: "mediaCSS matches matchMediaCSS",
      actual: `${diffs.length} field(s) differ: ${diffs.slice(0, 5).join(", ")}`,
      fields: diffs.map((k) => `cssMedia.${k}`),
    },
  );
}

/** Browser family map for normalizing incognito detector browser names to UA families. */
// Order matters: edge before chrome (Edge UA contains "Chrome")
const BROWSER_FAMILIES: [string, string[]][] = [
  ["edge", ["edge", "edg"]],
  ["firefox", ["firefox", "fxios"]],
  ["safari", ["safari", "mobile safari"]],
  ["chrome", ["chrome", "chromium", "crios"]],
];

/** Normalize a browser name to its family key. */
function browserFamily(name: string): string {
  const lower = name.toLowerCase();
  for (const [family, aliases] of BROWSER_FAMILIES) {
    if (aliases.some((a) => lower.includes(a))) return family;
  }
  return lower;
}

/** Check JS/layout engine from error messages vs UA-claimed engine. */
function checkEngineMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const ce = device.consoleErrors;
  if (!isObj(ce)) return null;

  // The payload already self-reports if engines mismatch
  if (ce.engineMismatch === true) {
    const claimed = isObj(ce.claimedEngine) ? ce.claimedEngine : {};
    return createSignal("CROSS_FIELD", AnomalyCodes.ENGINE_MISMATCH, 0.9, {
      expected: `error-detected engine matches UA claim`,
      actual: `jsEngine: ${ce.jsEngine}, layoutEngine: ${ce.layoutEngine}, claimed: ${JSON.stringify(claimed)}`,
      fields: [
        "consoleErrors.jsEngine",
        "consoleErrors.layoutEngine",
        "consoleErrors.claimedEngine",
      ],
    });
  }
  return null;
}

/** Extract connection IP from sigint TLS or TCP probe data. */
function extractConnectionIp(sigint: Record<string, unknown>): string | null {
  const tls = sigint.tlsFingerprint;
  if (isObj(tls) && str(tls.ip)) return tls.ip;
  const tcp = sigint.tcpProbe;
  if (isObj(tcp) && str(tcp.client_ip)) return tcp.client_ip;
  return null;
}

/** Extract WebRTC public IP from device payload. */
function extractRtcIp(device: Record<string, unknown>): string | null {
  const webrtc = device.webrtc;
  if (!isObj(webrtc)) return null;
  const candidates = webrtc.iceCandidates;
  if (!isObj(candidates)) return null;
  const ip = candidates.publicIP;
  return str(ip) && ip ? ip : null;
}

/** Check WebRTC public IP vs TCP/TLS connection IP. */
function checkWebrtcIpMismatch(
  device: Record<string, unknown>,
  sigint: Record<string, unknown> | null,
): AnomalySignal | null {
  if (!sigint) return null;
  const rtcIp = extractRtcIp(device);
  if (!rtcIp) return null;
  const connIp = extractConnectionIp(sigint);
  if (!connIp) return null;

  if (rtcIp !== connIp) {
    return createSignal("NETWORK", AnomalyCodes.WEBRTC_IP_MISMATCH, 0.95, {
      expected: `WebRTC IP matches connection IP (${connIp})`,
      actual: `WebRTC: ${rtcIp} vs connection: ${connIp}`,
      fields: ["webrtc.iceCandidates.publicIP", "sigint.tlsFingerprint.ip"],
    });
  }
  return null;
}

/** Check screen.colorDepth === screen.pixelDepth. */
function checkScreenDepthMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const screen = device.screen;
  if (!isObj(screen)) return null;
  const { colorDepth, pixelDepth } = screen;
  if (!num(colorDepth) || !num(pixelDepth)) return null;
  if (colorDepth !== pixelDepth) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.SCREEN_DEPTH_MISMATCH,
      0.8,
      {
        expected: `colorDepth (${colorDepth}) === pixelDepth`,
        actual: `colorDepth: ${colorDepth} vs pixelDepth: ${pixelDepth}`,
        fields: ["screen.colorDepth", "screen.pixelDepth"],
      },
    );
  }
  return null;
}

/** Check screen.availWidth/Height <= screen.width/height. */
function checkScreenAvailOverflow(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const screen = device.screen;
  if (!isObj(screen)) return null;
  const { width, height, availWidth, availHeight } = screen;
  if (!num(width) || !num(height) || !num(availWidth) || !num(availHeight))
    return null;

  if (availWidth > width || availHeight > height) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.SCREEN_AVAIL_OVERFLOW,
      0.85,
      {
        expected: `avail (${availWidth}x${availHeight}) <= screen (${width}x${height})`,
        actual: `avail ${availWidth}x${availHeight} > screen ${width}x${height}`,
        fields: [
          "screen.availWidth",
          "screen.availHeight",
          "screen.width",
          "screen.height",
        ],
      },
    );
  }
  return null;
}

/** Check cssMedia.mediaCSS["device-screen"] string matches screen.width/height. */
function checkDeviceScreenString(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const screen = device.screen;
  const cssMedia = device.cssMedia;
  if (!isObj(screen) || !isObj(cssMedia)) return null;
  const mediaCSS = cssMedia.mediaCSS;
  if (!isObj(mediaCSS)) return null;

  const deviceScreen = mediaCSS["device-screen"];
  if (!str(deviceScreen)) return null;

  const sw = screen.width;
  const sh = screen.height;
  if (!num(sw) || !num(sh)) return null;

  const expected = `${sw} x ${sh}`;
  if (deviceScreen !== expected) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.DEVICE_SCREEN_STRING_MISMATCH,
      0.85,
      {
        expected: `device-screen "${expected}" matches screen dims`,
        actual: `device-screen: "${deviceScreen}" vs screen: ${sw}x${sh}`,
        fields: ["cssMedia.mediaCSS.device-screen", F_SCREEN_W, F_SCREEN_H],
      },
    );
  }
  return null;
}

/** Parse "N/D" ratio string into [numerator, denominator] or null. */
function parseRatio(s: string): [number, number] | null {
  const idx = s.indexOf("/");
  if (idx < 0) return null;
  const n = parseInt(s.substring(0, idx), 10);
  const d = parseInt(s.substring(idx + 1), 10);
  return !isNaN(n) && !isNaN(d) && d !== 0 ? [n, d] : null;
}

/** Check cssMedia.mediaCSS["device-aspect-ratio"] matches screen.width/height. */
function checkAspectRatio(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const screen = device.screen;
  const cssMedia = device.cssMedia;
  if (!isObj(screen) || !isObj(cssMedia)) return null;
  const mediaCSS = cssMedia.mediaCSS;
  if (!isObj(mediaCSS)) return null;

  const ratio = mediaCSS["device-aspect-ratio"];
  if (!str(ratio)) return null;
  const parsed = parseRatio(ratio);
  if (!parsed) return null;

  const sw = screen.width;
  const sh = screen.height;
  if (!num(sw) || !num(sh) || sh === 0) return null;

  const [n, d] = parsed;
  // Cross-multiply to avoid floating point: n/d should equal sw/sh
  if (n * sh !== d * sw) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.ASPECT_RATIO_MISMATCH,
      0.8,
      {
        expected: `aspect-ratio ${ratio} matches ${sw}x${sh}`,
        actual: `${n}/${d} ≠ ${sw}/${sh}`,
        fields: [
          "cssMedia.mediaCSS.device-aspect-ratio",
          F_SCREEN_W,
          F_SCREEN_H,
        ],
      },
    );
  }
  return null;
}

const LOCALE_FIELDS = ["language", "timezoneLocation", "locale"] as const;

/** Collect unique string values for a field across scopes. */
function uniqueFieldValues(
  scopeEntries: [string, Record<string, unknown>][],
  field: string,
): Set<string> {
  const values = new Set<string>();
  for (const [, scope] of scopeEntries) {
    const v = scope[field];
    if (str(v)) values.add(v);
  }
  return values;
}

/** Check worker scope locale/language/timezone consistency across all scopes. */
function checkWorkerLocaleMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const ws = device.workerScope;
  if (!isObj(ws)) return null;
  const scopes = ws.scopes;
  if (!isObj(scopes)) return null;

  const scopeEntries = Object.entries(scopes).filter(
    (e): e is [string, Record<string, unknown>] => isObj(e[1]),
  );
  if (scopeEntries.length < 2) return null;

  const diffs = LOCALE_FIELDS.map((f) => ({
    f,
    vals: uniqueFieldValues(scopeEntries, f),
  }))
    .filter(({ vals }) => vals.size > 1)
    .map(({ f, vals }) => `${f}: ${[...vals].join(" vs ")}`);

  if (diffs.length === 0) return null;

  return createSignal(
    "CROSS_FIELD",
    AnomalyCodes.WORKER_LOCALE_MISMATCH,
    0.75,
    {
      expected: "locale fields consistent across worker scopes",
      actual: diffs.join("; "),
      fields: LOCALE_FIELDS.map((f) => `workerScope.scopes.*.${f}`),
    },
  );
}

/** Check incognito detector's browser matches UA-parsed browser. */
function checkIncognitoBrowserMismatch(
  device: Record<string, unknown>,
): AnomalySignal | null {
  const incognito = device.incognito;
  const nav = device.navigator;
  if (!isObj(incognito) || !isObj(nav)) return null;

  const incBrowser = incognito.browser;
  const uaParsed = nav.userAgentParsed;
  if (!str(incBrowser) || !str(uaParsed)) return null;

  if (browserFamily(incBrowser) !== browserFamily(uaParsed)) {
    return createSignal(
      "CROSS_FIELD",
      AnomalyCodes.INCOGNITO_BROWSER_MISMATCH,
      0.7,
      {
        expected: `incognito browser matches UA`,
        actual: `incognito: ${incBrowser} vs UA: ${uaParsed}`,
        fields: ["incognito.browser", "navigator.userAgentParsed"],
      },
    );
  }
  return null;
}

/** Device-only consistency checks (no sigint needed). */
const deviceChecks: ((d: Record<string, unknown>) => AnomalySignal | null)[] = [
  checkScreenCssMismatch,
  checkAudioNoise,
  checkTimezoneOffsetMismatch,
  checkTouchMismatch,
  checkWebglRendererMismatch,
  checkTzOffsetComputed,
  checkCssMediaApiMismatch,
  checkEngineMismatch,
  checkScreenDepthMismatch,
  checkScreenAvailOverflow,
  checkDeviceScreenString,
  checkAspectRatio,
  checkWorkerLocaleMismatch,
  checkIncognitoBrowserMismatch,
];

/** Collect signals from pre-computed fingerprint scores. */
function collectScoreSignals(fingerprint: Fingerprint): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  if (fingerprint.is_headless === true) {
    signals.push(
      createSignal("CROSS_FIELD", AnomalyCodes.HEADLESS_DETECTED, 0.9, {
        expected: "is_headless: false",
        actual: "is_headless: true",
        fields: ["is_headless"],
      }),
    );
  }
  return signals;
}

/** Run all device-level consistency checks against raw payload. */
function collectDeviceSignals(
  raw: Record<string, unknown>,
  sigint: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  for (const check of deviceChecks) {
    const s = check(raw);
    if (s) signals.push(s);
  }
  const sigintObj = isObj(sigint) ? sigint : null;
  const ipSignal = checkWebrtcIpMismatch(raw, sigintObj);
  if (ipSignal) signals.push(ipSignal);
  return signals;
}

/**
 * Detect anomalies from pre-computed fingerprint signals (headless, proxy, VPN)
 * and within-payload consistency checks.
 */
export function detectFingerprintSignals(
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: unknown,
): AnomalySignal[] {
  const signals = collectScoreSignals(fingerprint);
  if (isObj(raw)) signals.push(...collectDeviceSignals(raw, sigint));
  return signals;
}
