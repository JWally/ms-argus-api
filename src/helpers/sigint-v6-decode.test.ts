import { describe, it, expect } from "vitest";
import {
  buildWebrtcSigintField,
  decodeV6Payload,
  decodeWebrtcSigintCandidates,
  ipv6StringToBytes,
} from "./sigint-v6-decode";

/**
 * Reference vector produced by src-go/stun/tools/simserver with
 *   SIGINT_AES_KEY = 00*32, ip = 107.210.133.127, epoch = 1776275382
 * Re-generate via: `cd ms-argus-sigint/src-go/stun/tools/simserver && SIGINT_AES_KEY=00... go run main.go`
 */
const KEY_ZERO = "00".repeat(32);
const VECTOR = {
  ciphertext: Buffer.from("8db6b0e3e5cbf8a9a034ab8a74bc42f3", "hex"),
  expectedIp: "107.210.133.127",
  expectedEpoch: 1776275382,
  expectedNonce: "f48969e8",
};

describe("decodeV6Payload", () => {
  it("decrypts + MAC-validates a known Go-produced vector", () => {
    const now = new Date(VECTOR.expectedEpoch * 1000);
    const out = decodeV6Payload(VECTOR.ciphertext, KEY_ZERO, now);
    expect(out).not.toBeNull();
    expect(out!.ip).toBe(VECTOR.expectedIp);
    expect(out!.epoch).toBe(VECTOR.expectedEpoch);
    expect(out!.nonce).toBe(VECTOR.expectedNonce);
    expect(out!.macValid).toBe(true);
    expect(out!.ageSec).toBe(0);
    expect(out!.fresh).toBe(true);
  });

  it("flags MAC invalid when ciphertext is tampered", () => {
    const tampered = Buffer.from(VECTOR.ciphertext);
    tampered[0] ^= 0x01;
    const out = decodeV6Payload(
      tampered,
      KEY_ZERO,
      new Date(VECTOR.expectedEpoch * 1000),
    );
    expect(out).not.toBeNull();
    expect(out!.macValid).toBe(false);
    expect(out!.fresh).toBe(false);
  });

  it("flags stale payloads as not fresh even with valid MAC", () => {
    const wayLater = new Date((VECTOR.expectedEpoch + 3600) * 1000);
    const out = decodeV6Payload(VECTOR.ciphertext, KEY_ZERO, wayLater);
    expect(out!.macValid).toBe(true);
    expect(out!.fresh).toBe(false);
    expect(out!.ageSec).toBe(3600);
  });

  it("rejects wrong-size input", () => {
    expect(decodeV6Payload(Buffer.alloc(15), KEY_ZERO)).toBeNull();
    expect(decodeV6Payload(Buffer.alloc(17), KEY_ZERO)).toBeNull();
  });

  it("rejects malformed key", () => {
    expect(decodeV6Payload(VECTOR.ciphertext, "nothex")).toBeNull();
    expect(decodeV6Payload(VECTOR.ciphertext, "ab".repeat(16))).toBeNull();
  });
});

describe("ipv6StringToBytes", () => {
  it("parses full form", () => {
    const bytes = ipv6StringToBytes("61d9:eb92:dbca:fec2:0313:b0e6:d571:6397");
    expect(bytes?.toString("hex")).toBe("61d9eb92dbcafec20313b0e6d5716397");
  });

  it("parses :: shorthand", () => {
    expect(ipv6StringToBytes("::1")?.toString("hex")).toBe(
      "00000000000000000000000000000001",
    );
    expect(ipv6StringToBytes("fe80::1")?.toString("hex")).toBe(
      "fe800000000000000000000000000001",
    );
    expect(ipv6StringToBytes("::")?.toString("hex")).toBe("0".repeat(32));
  });

  it("rejects garbage", () => {
    expect(ipv6StringToBytes("not-an-ip")).toBeNull();
    expect(ipv6StringToBytes("1:2:3:4:5:6:7:8:9")).toBeNull();
    expect(ipv6StringToBytes("1::2::3")).toBeNull();
    expect(ipv6StringToBytes("")).toBeNull();
  });
});

describe("decodeWebrtcSigintCandidates", () => {
  const vectorAddress = "8db6:b0e3:e5cb:f8a9:a034:ab8a:74bc:42f3";
  const now = new Date(VECTOR.expectedEpoch * 1000);

  it("decodes a single srflx candidate", () => {
    const device = {
      webrtc: {
        iceCandidates: {
          sigintCandidates: [{ address: vectorAddress, port: 443 }],
        },
      },
    };
    const r = decodeWebrtcSigintCandidates(device, KEY_ZERO, now);
    expect(r.reason).toBe("ok");
    expect(r.decoded?.ip).toBe(VECTOR.expectedIp);
    expect(r.decoded?.macValid).toBe(true);
  });

  it("returns no_candidates when array empty", () => {
    const device = { webrtc: { iceCandidates: { sigintCandidates: [] } } };
    const r = decodeWebrtcSigintCandidates(device, KEY_ZERO, now);
    expect(r.reason).toBe("no_candidates");
    expect(r.decoded).toBeNull();
  });

  it("picks the first MAC-valid candidate when multiple submitted", () => {
    // Multi-NIC clients legitimately submit several srflx candidates;
    // the first valid one is authentic evidence of that egress.
    const device = {
      webrtc: {
        iceCandidates: {
          sigintCandidates: [
            { address: vectorAddress, port: 443 },
            { address: "1111:2222::3333", port: 443 }, // garbage, fails MAC
          ],
        },
      },
    };
    const r = decodeWebrtcSigintCandidates(device, KEY_ZERO, now);
    expect(r.reason).toBe("ok");
    expect(r.candidateCount).toBe(2);
    expect(r.decoded?.ip).toBe(VECTOR.expectedIp);
  });

  it("flags forgery when candidates submitted but none verify", () => {
    // All candidates parse as IPv6 but none came from our STUN — synthetic.
    const device = {
      webrtc: {
        iceCandidates: {
          sigintCandidates: [
            { address: "1111:2222::3333", port: 443 },
            { address: "4444:5555::6666", port: 443 },
          ],
        },
      },
    };
    const r = decodeWebrtcSigintCandidates(device, KEY_ZERO, now);
    expect(r.reason).toBe("forgery");
    expect(r.candidateCount).toBe(2);
    expect(r.decoded).toBeNull();
  });

  it("handles missing key gracefully", () => {
    const device = {
      webrtc: {
        iceCandidates: {
          sigintCandidates: [{ address: vectorAddress, port: 443 }],
        },
      },
    };
    const r = decodeWebrtcSigintCandidates(device, undefined, now);
    expect(r.decoded).toBeNull();
    expect(r.reason).toBe("decode_fail");
  });

  it("handles missing webrtc gracefully", () => {
    const r = decodeWebrtcSigintCandidates({}, KEY_ZERO, now);
    expect(r.reason).toBe("no_candidates");
    expect(r.candidateCount).toBe(0);
  });
});

describe("buildWebrtcSigintField", () => {
  it("returns undefined when no candidates were present", () => {
    expect(
      buildWebrtcSigintField({
        decoded: null,
        candidateCount: 0,
        reason: "no_candidates",
      }),
    ).toBeUndefined();
  });

  it("flattens decoded payload into the stored record", () => {
    const out = buildWebrtcSigintField({
      decoded: {
        ip: "1.2.3.4",
        epoch: 1776275382,
        ageSec: 5,
        nonce: "deadbeef",
        macValid: true,
        fresh: true,
        cipherB64: "AAECAwQFBgcICQoLDA0ODw==",
      },
      candidateCount: 1,
      reason: "ok",
    });
    expect(out).toEqual({
      status: "ok",
      candidate_count: 1,
      ip: "1.2.3.4",
      epoch: 1776275382,
      age_sec: 5,
      nonce: "deadbeef",
      mac_valid: true,
      fresh: true,
    });
  });

  it("records status without payload fields on forgery", () => {
    expect(
      buildWebrtcSigintField({
        decoded: null,
        candidateCount: 3,
        reason: "forgery",
      }),
    ).toEqual({ status: "forgery", candidate_count: 3 });
  });

  it("records parse_fail with no ip field", () => {
    const out = buildWebrtcSigintField({
      decoded: null,
      candidateCount: 1,
      reason: "parse_fail",
    });
    expect(out).toEqual({ status: "parse_fail", candidate_count: 1 });
    expect(out).not.toHaveProperty("ip");
  });
});
