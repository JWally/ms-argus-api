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

describe("network tampering", () => {
  it("does not turn a Safari residential RTT outlier into VPN evidence", () => {
    const input = safariResidentialRttOutlier();

    expect(proxyScore(input)).toBe(1);
    expect(vpnScore(input)).toBe(0);
    expect(networkTamperingScore(input)).toBe(0);
  });

  it("preserves real MSS-derived VPN evidence during an RTT outlier", () => {
    expect(vpnScore(safariResidentialRttOutlier(0.7))).toBe(0.7);
  });
});
