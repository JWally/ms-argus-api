import { describe, expect, it } from "vitest";
import type { IntegrityResultsData } from "../helpers/payload-schema";
import type { MerchantProjectionInput } from "../scoring/shared";
import {
  computeNetworkIntegrityScore,
  deriveNetworkProjection,
} from "./network";

function baseIntegrity(
  overrides: Partial<IntegrityResultsData> = {},
): IntegrityResultsData {
  return {
    session_id: "session-1",
    device: {},
    meta: {},
    sigint: {},
    analysis: {
      network: {
        proxy_score: 0,
        proxy_component: 0,
        vpn_component: 0,
        signals: [],
      },
      worker: { lied: false, divergences: [], signals: [] },
      timezone: {
        lied: false,
        checks: {
          offsetMatchesComputed: true,
          locationMatchesCfTimezone: true,
          offsetMatchesWorker: true,
          clientReportedLie: false,
        },
        cfTimezone: null,
        clientTimezone: null,
        signals: [],
      },
      ip: {
        lied: false,
        ips: {
          api: "203.0.113.7",
          tls: "203.0.113.7",
          tcp: "203.0.113.7",
          webrtc: "203.0.113.7",
        },
        asn: { number: null, category: null, org: null },
        checks: { probesConsistent: true, webrtcMatchesProbes: true },
        integrity: 1,
        ip: "203.0.113.7",
        signals: [],
      },
    },
    client_ip: "203.0.113.7",
    user_agent: "Argus Browser",
    created_at: 1,
    ...overrides,
  };
}

function input(integrity?: IntegrityResultsData): MerchantProjectionInput {
  return { session_id: "session-1", ...(integrity ? { integrity } : {}) };
}

describe("deriveNetworkProjection", () => {
  it("returns conservative nulls and false flags when evidence is absent", () => {
    expect(deriveNetworkProjection(input())).toEqual({
      ip: null,
      ipLocation: {
        city: null,
        country: null,
        latitude: null,
        longitude: null,
        timezone: null,
      },
      ipInfo: {
        asn: {
          number: null,
          organization: null,
          category: null,
          network_class: null,
          metadata: null,
        },
        datacenter: { result: false },
        mobile: { result: false },
        residential: { result: false },
        vpn: { result: false },
        hosting: { result: false },
        privacy_relay: { result: false },
        corporate_shield: { result: false },
      },
    });
  });

  it("prefers analyzed IP/ASN while projecting CloudFront location", () => {
    const base = baseIntegrity();
    const projection = deriveNetworkProjection(
      input(
        baseIntegrity({
          sigint: {
            aws_cf: {
              ip: "198.51.100.4",
              city: "Dallas",
              country: "US",
              lat: "32.972",
              lon: "-96.791",
              tz: "America/Chicago",
            },
          } as unknown as Record<string, string>,
          analysis: {
            ...base.analysis,
            ip: {
              ...base.analysis.ip,
              ip: "203.0.113.9",
              asn: {
                number: "AS16509",
                org: "AMAZON-02",
                category: "datacenter",
                network_class: "datacenter",
                metadata: { parent_org: "Amazon", ix_count: 42 },
              },
            },
          },
        }),
      ),
    );

    expect(projection).toEqual({
      ip: "203.0.113.9",
      ipLocation: {
        city: "Dallas",
        country: "US",
        latitude: 32.972,
        longitude: -96.791,
        timezone: "America/Chicago",
      },
      ipInfo: expect.objectContaining({
        asn: {
          number: 16509,
          organization: "AMAZON-02",
          category: "datacenter",
          network_class: "datacenter",
          metadata: { parent_org: "Amazon", ix_count: 42 },
        },
        datacenter: { result: true },
      }),
    });
  });

  it("falls back to CloudFront IP and ASN for partial legacy records", () => {
    const integrity = {
      sigint: {
        aws_cf: {
          ip: "198.51.100.4",
          asn: "AS13335",
          lat: "not-a-number",
          lon: "",
        },
      },
    } as unknown as IntegrityResultsData;

    const projection = deriveNetworkProjection(input(integrity));
    expect(projection.ip).toBe("198.51.100.4");
    expect(projection.ipInfo.asn).toEqual({
      number: 13335,
      organization: null,
      category: null,
      network_class: null,
      metadata: null,
    });
    expect(projection.ipLocation.latitude).toBeNull();
    expect(projection.ipLocation.longitude).toBeNull();
  });

  it("derives every convenience flag only from network_class", () => {
    const classes = {
      datacenter: "datacenter",
      mobile: "mobile",
      residential: "residential",
      vpn: "vpn_proxy",
      hosting: "hosting_proxy",
      privacy_relay: "privacy_relay",
      corporate_shield: "security_filter",
    } as const;
    for (const [flag, networkClass] of Object.entries(classes)) {
      const base = baseIntegrity();
      const projection = deriveNetworkProjection(
        input(
          baseIntegrity({
            analysis: {
              ...base.analysis,
              ip: {
                ...base.analysis.ip,
                asn: {
                  ...base.analysis.ip.asn,
                  category: "datacenter",
                  network_class: networkClass,
                },
              },
            },
          }),
        ),
      );
      const flags = projection.ipInfo as unknown as Record<
        string,
        { result: boolean }
      >;
      expect(flags[flag].result).toBe(true);
      expect(
        Object.keys(classes)
          .filter((candidate) => candidate !== flag)
          .every((candidate) => flags[candidate].result === false),
      ).toBe(true);
    }
  });
});

describe("computeNetworkIntegrityScore", () => {
  it("never rehabilitates a cryptographic forgery", () => {
    const base = baseIntegrity();
    const shield = input(
      baseIntegrity({
        analysis: {
          ...base.analysis,
          ip: {
            ...base.analysis.ip,
            asn: { number: "36692", org: "Cisco", category: "corporate_proxy" },
          },
        },
      }),
    );
    expect(computeNetworkIntegrityScore(shield, 0)).toBe(0);
  });

  it("clamps benign corporate gateways unless wire identity strongly disagrees", () => {
    const base = baseIntegrity();
    const shield = input(
      baseIntegrity({
        analysis: {
          ...base.analysis,
          ip: {
            ...base.analysis.ip,
            asn: { number: "36692", org: "Cisco", category: "corporate_proxy" },
          },
        },
      }),
    );
    expect(computeNetworkIntegrityScore(shield, 0.1)).toBe(1);

    const mismatch = input({
      ...shield.integrity!,
      analysis: {
        ...shield.integrity!.analysis,
        worker: {
          lied: false,
          divergences: [],
          signals: [
            { code: "JA4_UA_BROWSER_MISMATCH", severity: 0.9, evidence: "" },
          ],
        },
      },
    });
    expect(computeNetworkIntegrityScore(mismatch, 0.1)).toBe(0.2);
  });

  it("composes proxy, VPN, and suspicious WebRTC-blocked downgrades", () => {
    const base = baseIntegrity();
    const suspicious = input(
      baseIntegrity({
        analysis: {
          ...base.analysis,
          network: {
            ...base.analysis.network,
            proxy_component: 0.2,
            vpn_component: 0.25,
          },
          ip: {
            ...base.analysis.ip,
            asn: { number: "16509", org: "AWS", category: "datacenter" },
            signals: [{ code: "WEBRTC_BLOCKED", severity: 0.5, evidence: "" }],
          },
        },
      }),
    );
    expect(computeNetworkIntegrityScore(suspicious, 1)).toBeCloseTo(0.3);
  });
});
