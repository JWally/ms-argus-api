import { describe, it, expect } from "vitest";
import { getByPath } from "./get-by-path";

describe("getByPath", () => {
  it("extracts shallow property", () => {
    const obj = { foo: "bar" };
    expect(getByPath(obj, "foo")).toBe("bar");
  });

  it("extracts nested property", () => {
    const obj = { a: { b: { c: "deep" } } };
    expect(getByPath(obj, "a.b.c")).toBe("deep");
  });

  it("returns undefined for missing property", () => {
    const obj = { a: { b: 1 } };
    expect(getByPath(obj, "a.c")).toBeUndefined();
    expect(getByPath(obj, "x.y.z")).toBeUndefined();
  });

  it("returns undefined for null/undefined object", () => {
    expect(getByPath(null, "a.b")).toBeUndefined();
    expect(getByPath(undefined, "a.b")).toBeUndefined();
  });

  it("returns undefined for empty path", () => {
    const obj = { a: 1 };
    expect(getByPath(obj, "")).toBeUndefined();
  });

  it("handles null values in path", () => {
    const obj = { a: { b: null } };
    expect(getByPath(obj, "a.b.c")).toBeUndefined();
  });

  it("works with realistic fingerprint paths", () => {
    const network = {
      tlsFingerprint: { ja4: "t13d1516h2_abc123" },
      h2Probe: { fingerprint: "akamai", protocol: "h2" },
    };

    expect(getByPath(network, "tlsFingerprint.ja4")).toBe("t13d1516h2_abc123");
    expect(getByPath(network, "h2Probe.fingerprint")).toBe("akamai");
    expect(getByPath(network, "tcpProbe.ja3")).toBeUndefined();
  });
});
