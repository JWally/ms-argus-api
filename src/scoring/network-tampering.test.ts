import { describe, expect, it } from "vitest";
import type { IntegrityResultsData } from "../helpers/payload-schema";
import {
  networkTamperingScore,
  proxyScore,
  vpnScore,
} from "./network-tampering";
import type { MerchantProjectionInput } from "./shared";

function safariResidentialRttOutlier(
  vpnComponent = 0,
): MerchantProjectionInput {
  return {
    session_id: "afcb61ec-34f0-4d80-a0b1-3541b9b36c3b",
    integrity: {
      sigint: {
        tcp_probe: {
          rtt_fingerprint: {
            rcv_rtt_refreshed: 758_000,
            rtt_refreshed: 106_000,
          },
        },
      },
      analysis: {
        network: {
          proxy_score: 1,
          proxy_component: 1,
          vpn_component: vpnComponent,
          signals: [
            {
              code: "LIKELY_PROXY",
              severity: 0.6,
              evidence: "rcv_rtt/rtt = 7.2x (758ms / 106ms)",
            },
            ...(vpnComponent > 0
              ? [
                  {
                    code: "LIKELY_VPN",
                    severity: vpnComponent,
                    evidence: "snd_mss=1360",
                  },
                ]
              : []),
          ],
        },
        proxy_waterfall: {
          rule: 1,
          reason: "udp_eq_tcp",
          shared_prefix: 32,
          threat_score: 0,
          verdict: "SAFE",
          ratio: 7.150336292201605,
        },
        ip: {
          lied: false,
          ip: "107.210.133.127",
          ips: {
            api: "107.210.133.127",
            tls: "107.210.133.127",
            tcp: "107.210.133.127",
            webrtc: "107.210.133.127",
          },
          asn: {
            number: "7018",
            category: "residential",
            org: "AT&T US",
          },
          checks: {
            probesConsistent: true,
            webrtcMatchesProbes: true,
          },
          integrity: 1,
          signals: [],
        },
      },
    } as unknown as IntegrityResultsData,
  };
}

function categorizedNetworkInput(options: {
  category: string | null;
  networkClass: string | null;
  vpnComponent?: number;
  proxyThreat?: number;
}): MerchantProjectionInput {
  const categoryEvidence =
    options.category === "datacenter" || options.category === "vpn_proxy";
  return {
    session_id: "network-category-test",
    integrity: {
      analysis: {
        network: {
          proxy_score: 0,
          proxy_component: 0,
          vpn_component: options.vpnComponent ?? (categoryEvidence ? 1 : 0),
          signals: categoryEvidence
            ? [
                {
                  code: "CATEGORY_VPN",
                  severity: 1,
                  evidence: `asn.category=${options.category}`,
                },
              ]
            : [],
        },
        proxy_waterfall: {
          rule: 1,
          reason: "udp_eq_tcp",
          shared_prefix: 32,
          threat_score: options.proxyThreat ?? 0,
          verdict: options.proxyThreat ? "PROXY" : "SAFE",
          ratio: 1,
        },
        ip: {
          lied: false,
          ip: "203.0.113.10",
          ips: {
            api: "203.0.113.10",
            tls: "203.0.113.10",
            tcp: "203.0.113.10",
            webrtc: "203.0.113.10",
          },
          asn: {
            number: "64500",
            category: options.category,
            network_class: options.networkClass,
            org: "Example Network",
          },
          checks: {
            probesConsistent: true,
            webrtcMatchesProbes: true,
          },
          integrity: 1,
          signals: [],
        },
      },
    } as unknown as IntegrityResultsData,
  };
}

describe("network tampering", () => {
  it("does not turn a Safari residential RTT outlier into VPN evidence", () => {
    const input = safariResidentialRttOutlier();

    expect(proxyScore(input)).toBe(1);
    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it("keeps MSS reduction observational on residential networks", () => {
    const input = safariResidentialRttOutlier(0.7);

    expect(input.integrity?.analysis.network.vpn_component).toBe(0.7);
    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it("replays the Iliad MSS=1360 session without a merchant-facing flag", () => {
    const input = categorizedNetworkInput({
      category: "residential",
      networkClass: null,
      vpnComponent: 0.5714285714285714,
    });

    expect(input.integrity?.analysis.network.vpn_component).toBeCloseTo(0.5714);
    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it.each(["datacenter", "vpn_proxy"])(
    "keeps %s classification authoritative without MSS evidence",
    (networkClass) => {
      const input = categorizedNetworkInput({
        category: networkClass,
        networkClass,
      });

      expect(vpnScore(input)).toBe(1);
      expect(networkTamperingScore(input)).toBe(100);
    },
  );

  it("keeps the proxy waterfall authoritative when MSS is observational", () => {
    const input = categorizedNetworkInput({
      category: "mobile",
      networkClass: "mobile",
      vpnComponent: 0.6,
      proxyThreat: 100,
    });

    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(100);
  });
});
