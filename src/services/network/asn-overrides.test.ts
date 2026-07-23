import { describe, expect, it } from "vitest";
import { ASN_OVERRIDES } from "./asn-overrides";

describe("ASN_OVERRIDES — provider-owned VPN networks", () => {
  it.each([
    "199218",
    "203619",
    "209103",
    "214879",
    "216025",
    "57138",
    "397282",
    "397540",
  ])("keeps AS%s classified even if the upstream org label changes", (asn) => {
    expect(ASN_OVERRIDES[asn]).toBe("vpn_proxy");
  });
});
