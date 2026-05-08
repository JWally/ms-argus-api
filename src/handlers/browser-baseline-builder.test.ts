import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import { gzipSync, gunzipSync } from "node:zlib";
import { handler } from "./browser-baseline-builder";

const s3Mock = mockClient(S3Client);

const ARCHIVE_BUCKET = "archive-test";
const OUT_BUCKET = "ipclass-test";

interface SessionInput {
  ua: string;
  ip: string;
  category: string; // analysis.ip.asn.category
  tampered?: boolean;
  automated?: boolean;
  jsEngine?: string;
  ja4?: string;
  incognito?: boolean;
  proxyScore?: number;
  vpnComponent?: number;
  createdAt?: number;
}

function makeSession(s: SessionInput): Record<string, unknown> {
  const ja4 = s.ja4 ?? "t13d1516h2_8daaf6152771_f59aafdcbdd7"; // Chromium default
  return {
    user_agent: s.ua,
    client_ip: s.ip,
    created_at: s.createdAt ?? Date.now(),
    request_headers: { headers: {} },
    device: {
      engine: {
        jsEngine: s.jsEngine ?? "V8",
        layoutEngine: "Blink",
        evalToStringLength: 33,
        functionToStringLength: 33,
        stackFormatHash: "abc123",
      },
      navigator: {
        vendor: "Google Inc.",
        properties: ["a", "b", "c"],
      },
      windowPrefixes: { apple: 0, moz: 0, webkit: 12 },
      css: { keyCount: 800 },
      headless: { chromium: false },
      lies: { totalLies: s.tampered ? 5 : 0 },
      incognito: s.incognito ? { isPrivate: true } : { isPrivate: false },
    },
    sigint: {
      h2: { ja4, pseudo_header_order: "m,a,s,p", protocol: "h2" },
      tcp_probe: {
        tls_signals: { cipher_count: 19, has_grease: true },
      },
    },
    analysis: {
      worker: { lied: false },
      timezone: { lied: false },
      client_hints_ua: { hasStrongMismatch: false },
      locale_geo: { hasLocaleTamper: false },
      ja4_ua: {
        signals: s.tampered ? [{ code: "JA4_UA_BROWSER_MISMATCH" }] : [],
      },
      ip: { asn: { category: s.category } },
      network: {
        proxy_component: 0,
        vpn_component: s.vpnComponent ?? 0,
      },
      proxy_waterfall: { threat_score: s.proxyScore ?? 0 },
      browser_engine: { signals: [] },
    },
    device_identity: { headless: false },
  };
}

function gzippedBatch(sessions: Record<string, unknown>[]): Buffer {
  return gzipSync(
    Buffer.from(sessions.map((s) => JSON.stringify(s)).join("\n")),
  );
}

function s3Body(buf: Buffer) {
  return {
    transformToByteArray: () => Promise.resolve(new Uint8Array(buf)),
  } as any;
}

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
const SAFARI_IOS_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1";

describe("browser-baseline-builder handler", () => {
  beforeEach(() => {
    s3Mock.reset();
    process.env.INTEGRITY_ARCHIVE_BUCKET = ARCHIVE_BUCKET;
    process.env.IP_CLASS_BUCKET = OUT_BUCKET;
    delete process.env.BROWSER_BASELINES_KEY;

    // Default: every Listing returns empty (no keys). Tests override the
    // single non-empty hour.
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    // Capture the upload by default to avoid unmocked errors.
    s3Mock.on(PutObjectCommand).resolves({});
  });

  afterEach(() => {
    delete process.env.INTEGRITY_ARCHIVE_BUCKET;
    delete process.env.IP_CLASS_BUCKET;
    delete process.env.BROWSER_BASELINES_KEY;
  });

  it("throws when INTEGRITY_ARCHIVE_BUCKET is missing", async () => {
    delete process.env.INTEGRITY_ARCHIVE_BUCKET;
    await expect(handler()).rejects.toThrow("INTEGRITY_ARCHIVE_BUCKET");
  });

  it("throws when IP_CLASS_BUCKET is missing", async () => {
    delete process.env.IP_CLASS_BUCKET;
    await expect(handler()).rejects.toThrow("IP_CLASS_BUCKET");
  });

  it("uploads an empty payload when no archive keys are present", async () => {
    const r = await handler();

    expect(r.archive_sessions_scanned).toBe(0);
    expect(r.observations_kept).toBe(0);
    expect(r.browser_keys).toBe(0);
    expect(r.engine_families).toBe(0);

    const puts = s3Mock.commandCalls(PutObjectCommand);
    expect(puts).toHaveLength(1);
    expect(puts[0].args[0].input.Bucket).toBe(OUT_BUCKET);
    expect(puts[0].args[0].input.Key).toBe("browser-baselines.json.gz");
    expect(puts[0].args[0].input.ContentEncoding).toBe("gzip");
  });

  it("aggregates clean residential sessions into both browser and engine_family histograms", async () => {
    const sessions = [
      makeSession({ ua: CHROME_UA, ip: "1.1.1.1", category: "residential" }),
      makeSession({ ua: CHROME_UA, ip: "1.1.1.2", category: "residential" }),
      makeSession({
        ua: SAFARI_IOS_UA,
        ip: "2.2.2.1",
        category: "mobile",
        jsEngine: "JavaScriptCore",
        ja4: "t13d2013h2_a09f3c656075_3798386c97ff",
      }),
    ];

    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "firehose/y/m/d/h/batch1.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    const r = await handler();

    expect(r.archive_sessions_scanned).toBe(3);
    expect(r.observations_kept).toBe(3);
    expect(r.browser_keys).toBeGreaterThanOrEqual(2);
    expect(r.engine_families).toBeGreaterThanOrEqual(2);

    const puts = s3Mock.commandCalls(PutObjectCommand);
    const body = puts[0].args[0].input.Body as Buffer;
    const payload = JSON.parse(gunzipSync(body).toString("utf-8"));
    expect(payload.browsers["Chrome 147"]).toBeDefined();
    expect(payload.browsers["Chrome 147"].n_sessions).toBe(2);
    expect(payload.browsers["Safari iOS 26.0"].n_sessions).toBe(1);
    expect(payload.engine_families.chromium.n_sessions).toBe(2);
    expect(payload.engine_families.webkit.n_sessions).toBe(1);
  });

  it("dedupes (browser_key, ip, day) tuples", async () => {
    // Same IP + same browser_key + same day = one observation
    const sessions = [
      makeSession({ ua: CHROME_UA, ip: "1.1.1.1", category: "residential" }),
      makeSession({ ua: CHROME_UA, ip: "1.1.1.1", category: "residential" }),
      makeSession({ ua: CHROME_UA, ip: "1.1.1.1", category: "residential" }),
    ];
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    const r = await handler();
    expect(r.archive_sessions_scanned).toBe(3);
    expect(r.observations_kept).toBe(1);
  });

  it("splits incognito sessions into a separate bucket key", async () => {
    const sessions = [
      makeSession({ ua: CHROME_UA, ip: "1.1.1.1", category: "residential" }),
      makeSession({
        ua: CHROME_UA,
        ip: "1.1.1.2",
        category: "residential",
        incognito: true,
      }),
    ];
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    await handler();
    const puts = s3Mock.commandCalls(PutObjectCommand);
    const payload = JSON.parse(
      gunzipSync(puts[0].args[0].input.Body as Buffer).toString("utf-8"),
    );
    expect(payload.browsers["Chrome 147"]).toBeDefined();
    expect(payload.browsers["Chrome 147 incognito"]).toBeDefined();
  });

  it("drops tampered sessions", async () => {
    const sessions = [
      makeSession({
        ua: CHROME_UA,
        ip: "1.1.1.1",
        category: "residential",
        tampered: true,
      }),
    ];
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    const r = await handler();
    expect(r.archive_sessions_scanned).toBe(1);
    expect(r.observations_kept).toBe(0);
    expect(r.observations_dropped).toBe(1);
  });

  it("drops sessions from datacenter / vpn_proxy / hosting_proxy ASNs", async () => {
    const sessions = [
      makeSession({ ua: CHROME_UA, ip: "1.1.1.1", category: "datacenter" }),
      makeSession({ ua: CHROME_UA, ip: "1.1.1.2", category: "vpn_proxy" }),
      makeSession({ ua: CHROME_UA, ip: "1.1.1.3", category: "hosting_proxy" }),
    ];
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    const r = await handler();
    expect(r.observations_kept).toBe(0);
  });

  it("treats corporate_proxy / privacy_relay as JS-only (TLS skipped)", async () => {
    const sessions = [
      makeSession({
        ua: CHROME_UA,
        ip: "1.1.1.1",
        category: "corporate_proxy",
      }),
      makeSession({ ua: CHROME_UA, ip: "1.1.1.2", category: "privacy_relay" }),
    ];
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    const r = await handler();
    expect(r.observations_kept).toBe(2);
    expect(r.observations_js_only).toBe(2);
    expect(r.observations_both).toBe(0);

    const puts = s3Mock.commandCalls(PutObjectCommand);
    const payload = JSON.parse(
      gunzipSync(puts[0].args[0].input.Body as Buffer).toString("utf-8"),
    );
    // JS field counted, TLS field skipped
    const chrome = payload.browsers["Chrome 147"];
    expect(chrome.fields["engine.jsEngine"].V8).toBe(2);
    expect(Object.keys(chrome.fields["tls.ja4_cipher_hash"])).toHaveLength(0);
  });

  it("ignores rows missing required fields (UA, IP, created_at)", async () => {
    const sessions: Record<string, unknown>[] = [
      { client_ip: "1.1.1.1", created_at: Date.now() }, // no UA
      { user_agent: CHROME_UA, created_at: Date.now() }, // no IP
      { user_agent: CHROME_UA, client_ip: "1.1.1.1" }, // no created_at
      { user_agent: "Wget/1.21", client_ip: "1.1.1.1", created_at: Date.now() }, // unrecognized UA
    ];
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(gzippedBatch(sessions)),
    } as any);

    const r = await handler();
    expect(r.archive_sessions_scanned).toBe(4);
    expect(r.observations_kept).toBe(0);
  });

  it("survives a malformed JSON line in a batch", async () => {
    // Mix valid + malformed JSON-lines
    const valid = makeSession({
      ua: CHROME_UA,
      ip: "1.1.1.1",
      category: "residential",
    });
    const text = JSON.stringify(valid) + "\nnot-json\n" + JSON.stringify(valid);
    const buf = gzipSync(Buffer.from(text));

    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "k.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({ Body: s3Body(buf) } as any);

    const r = await handler();
    expect(r.archive_sessions_scanned).toBe(2);
  });

  it("returns empty for a batch GetObject failure (continues processing)", async () => {
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [{ Key: "broken.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).rejects(new Error("S3 NoSuchKey"));

    const r = await handler();
    expect(r.archive_sessions_scanned).toBe(0);
  });

  it("honors BROWSER_BASELINES_KEY env override for output key", async () => {
    process.env.BROWSER_BASELINES_KEY = "custom/baselines.gz";
    await handler();
    const puts = s3Mock.commandCalls(PutObjectCommand);
    expect(puts[0].args[0].input.Key).toBe("custom/baselines.gz");
  });

  it("paginates ListObjectsV2 via NextContinuationToken", async () => {
    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({
        Contents: [{ Key: "page1/a.gz" }],
        NextContinuationToken: "tok1",
      })
      .resolvesOnce({ Contents: [{ Key: "page1/b.gz" }] })
      .resolves({ Contents: [] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: s3Body(
        gzippedBatch([
          makeSession({
            ua: CHROME_UA,
            ip: "1.1.1.1",
            category: "residential",
          }),
        ]),
      ),
    } as any);

    const r = await handler();
    expect(r.archive_sessions_scanned).toBe(2);
  });
});
