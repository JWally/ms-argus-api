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
  return {
    session_id: "network-category-test",
    integrity: {
      analysis: {
        network: {
          proxy_score: 0,
          proxy_component: 0,
          vpn_component: options.vpnComponent ?? 0,
          signals: options.vpnComponent
            ? [
                {
                  code: "LIKELY_VPN",
                  severity: 0.125,
                  evidence:
                    "snd_mss=1356 — VPN encapsulation likely (WireGuard/OpenVPN range)",
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
          ip: "174.224.8.150",
          ips: {
            api: "174.224.8.150",
            tls: "174.224.8.150",
            tcp: "174.224.8.150",
            webrtc: "174.224.8.150",
          },
          asn: {
            number: "6167",
            category: options.category,
            network_class: options.networkClass,
            org: "Cellco Partnership (Verizon Wireless)",
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

  it("does not promote MSS-only evidence to VPN on a residential ASN", () => {
    const input = safariResidentialRttOutlier(0.7);

    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it("replays the clean Verizon cellular MSS=1356 false positive as score zero", () => {
    const input = categorizedNetworkInput({
      category: "mobile",
      networkClass: "mobile",
      vpnComponent: 0.6,
    });

    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it("scores a known VPN ASN without MSS evidence", () => {
    const input = categorizedNetworkInput({
      category: "vpn_proxy",
      networkClass: "vpn_proxy",
    });

    expect(vpnScore(input)).toBe(1);
    expect(networkTamperingScore(input)).toBe(100);
  });

  it("keeps datacenter ASN classification authoritative", () => {
    const input = categorizedNetworkInput({
      category: "datacenter",
      networkClass: "datacenter",
    });

    expect(vpnScore(input)).toBe(1);
    expect(networkTamperingScore(input)).toBe(100);
  });

  it("keeps privacy relay tag-only and score-neutral", () => {
    const input = categorizedNetworkInput({
      category: "privacy_relay",
      networkClass: "privacy_relay",
    });

    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it("uses the broader local network class when the legacy category is absent", () => {
    const input = categorizedNetworkInput({
      category: null,
      networkClass: "vpn_proxy",
    });

    expect(vpnScore(input)).toBe(1);
    expect(networkTamperingScore(input)).toBe(100);
  });

  it("keeps the proxy waterfall authoritative on mobile networks", () => {
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
