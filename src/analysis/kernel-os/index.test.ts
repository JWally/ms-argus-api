import { describe, expect, it } from "vitest";
import { analyzeKernelOs } from "./index";

const baseTcp = (options: number) => ({
  tcp_probe: { tcp_info: { options } },
});

describe("analyzeKernelOs", () => {
  it("flags iOS UA with no-ECN options as KERNEL_OS_MISMATCH_DARWIN", () => {
    const r = analyzeKernelOs(baseTcp(7), "iOS");
    expect(r.tcpOptions).toBe(7);
    expect(r.ecnNegotiated).toBe(false);
    expect(r.signals).toHaveLength(1);
    expect(r.signals[0].code).toBe("KERNEL_OS_MISMATCH_DARWIN");
    expect(r.signals[0].severity).toBe(0.85);
  });

  it("flags macOS UA the same way as iOS", () => {
    const r = analyzeKernelOs(baseTcp(7), "macOS");
    expect(r.signals[0]?.code).toBe("KERNEL_OS_MISMATCH_DARWIN");
  });

  it("does not flag iOS when ECN bit is set (options=15)", () => {
    const r = analyzeKernelOs(baseTcp(15), "iOS");
    expect(r.ecnNegotiated).toBe(true);
    expect(r.signals).toHaveLength(0);
  });

  it("does not flag iOS when ECN_SEEN is set (options=31)", () => {
    const r = analyzeKernelOs(baseTcp(31), "iOS");
    expect(r.ecnNegotiated).toBe(true);
    expect(r.signals).toHaveLength(0);
  });

  it("flags Linux UA with ECN bit as KERNEL_OS_MISMATCH_LINUX (soft)", () => {
    const r = analyzeKernelOs(baseTcp(15), "Linux");
    expect(r.ecnNegotiated).toBe(true);
    expect(r.signals).toHaveLength(1);
    expect(r.signals[0].code).toBe("KERNEL_OS_MISMATCH_LINUX");
    expect(r.signals[0].severity).toBe(0.5);
  });

  it("does not flag Linux without ECN", () => {
    const r = analyzeKernelOs(baseTcp(7), "Linux");
    expect(r.signals).toHaveLength(0);
  });

  it("does not flag Windows (TS-off heuristic intentionally skipped)", () => {
    expect(analyzeKernelOs(baseTcp(6), "Windows").signals).toHaveLength(0);
    expect(analyzeKernelOs(baseTcp(7), "Windows").signals).toHaveLength(0);
  });

  it("returns empty when sigint is missing", () => {
    expect(analyzeKernelOs(undefined, "iOS").signals).toHaveLength(0);
    expect(analyzeKernelOs(null, "iOS").signals).toHaveLength(0);
    expect(analyzeKernelOs({}, "iOS").signals).toHaveLength(0);
  });

  it("returns empty when uaOs is unknown", () => {
    expect(analyzeKernelOs(baseTcp(7), null).signals).toHaveLength(0);
    expect(analyzeKernelOs(baseTcp(7), "Chrome OS").signals).toHaveLength(0);
  });

  it("reads options from flat (post-hydration) shape too", () => {
    const r = analyzeKernelOs({ tcp_probe: { options: 7 } }, "iOS");
    expect(r.tcpOptions).toBe(7);
    expect(r.signals[0]?.code).toBe("KERNEL_OS_MISMATCH_DARWIN");
  });
});
