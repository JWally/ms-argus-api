# Signal Taxonomy Cleanup

Status: proposed
Owner: —
Context: 2026-04-12 empirical review of integrity archive against labeled traffic (SOAX proxy, AT&T Fiber, iPhone AT&T cellular/wifi, iPhone+WireGuard-on-AWS). See S3 bucket `ms-argus-api-dev-jw-integrity-archive-*` and `memory/project_sigint_detector_findings.md` for source data.

## Problem

`IP_PROBE_SCATTER` is being emitted for two materially different facts by two different functions in `src/analysis/ip-consistency/index.ts`:

1. **`checkProbeScatter()`** (line 102–114) — fires on actual IP scatter: `unique([apiIp, tlsIp, tcpIp]).length > 1`. Severity 0.6–0.8.
2. **`checkAsnCategory()`** (line 148–168) — fires on ASN classification (via `asn-catalog.ts`). Emits the _same_ `IP_PROBE_SCATTER` code with severity based on category (`datacenter: 0.7`, `vpn_proxy: 0.6`, `corporate_proxy: 0.15`).

Observed consequence: a payload with `probesConsistent: true` produced a signal `IP_PROBE_SCATTER: ASN 16509 — Amazon.com (datacenter)`. The name contradicts the evidence.

## Proposal

Split the single `IP_PROBE_SCATTER` code into four codes aligned to the `AsnCategory` taxonomy already in `src/analysis/ip-consistency/asn-catalog.ts`:

| New code             | Source                                                    | When it fires                                                                 |
| -------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `IP_PROBE_SCATTER`   | `checkProbeScatter()`                                     | Distinct IPs observed across api/tls/tcp probes (unchanged)                   |
| `HYPERSCALER_EGRESS` | `checkAsnCategory()` when `category == "datacenter"`      | ASN is AWS/GCP/Azure/OVH/Hetzner/etc. — real browsers don't originate here    |
| `CORPORATE_PROXY`    | `checkAsnCategory()` when `category == "corporate_proxy"` | Zscaler, Cisco Umbrella, Netskope, etc. — low severity, legitimate enterprise |
| `VPN_PROXY_ASN`      | `checkAsnCategory()` when `category == "vpn_proxy"`       | Known consumer-VPN infrastructure ASNs                                        |

Implicit default remains: anything not in the catalog → assumed residential, no signal emitted. (No new "is_residential" catalog needed.)

## Changes

### `src/services/profile/anomaly/types.ts` (around line 75)

Replace `IP_PROBE_SCATTER` with three additional codes. Keep `IP_PROBE_SCATTER` since the name will now match its behavior:

```ts
IP_PROBE_SCATTER: "IP_PROBE_SCATTER",
HYPERSCALER_EGRESS: "HYPERSCALER_EGRESS",
CORPORATE_PROXY: "CORPORATE_PROXY",
VPN_PROXY_ASN: "VPN_PROXY_ASN",
```

### `src/analysis/ip-consistency/index.ts::checkAsnCategory()` (line 148–168)

Replace the single `IP_PROBE_SCATTER` emission with a category-to-code map:

```ts
const codeMap: Record<AsnCategory, AnomalyCode> = {
  datacenter: AnomalyCodes.HYPERSCALER_EGRESS,
  corporate_proxy: AnomalyCodes.CORPORATE_PROXY,
  vpn_proxy: AnomalyCodes.VPN_PROXY_ASN,
};
const severityMap: Record<AsnCategory, number> = {
  datacenter: 0.7,
  corporate_proxy: 0.15,
  vpn_proxy: 0.6,
};
return createSignal(
  "NETWORK",
  codeMap[entry.category],
  severityMap[entry.category],
  {
    expected: "residential ISP ASN",
    actual: `ASN ${asn} — ${entry.org} (${entry.category})`,
    fields: ["sigint.aws_cf.asn"],
  },
);
```

### Tests

- Update any `expect(signal.code).toBe("IP_PROBE_SCATTER")` assertions that were really asserting on ASN category outcomes (grep for the code string).
- Add targeted test fixtures for each of the three new codes using representative ASNs from `asn-catalog.ts`.

### Downstream consumers

- Grep for `"IP_PROBE_SCATTER"` across the codebase (matching, scoring, alerting, dashboards). Any consumer that was bucketing on this code for "ASN reason" needs to handle the three new codes. Consumers that were bucketing for "actual scatter" keep working unchanged.
- Check DynamoDB query patterns / Athena dashboards for the old code string.

## Out of scope (future todos)

- `CF_BEACON_FAILED` signal (separate proposal — see session notes).
- Cellular CGNAT classifier based on WebRTC /24 vs /16 comparison — not a lie flag, a device-class input.
- `tcp_options` OS-consistency check inside `ja4-ua` module.
- Scoring on `tls_to_tcp_ratio` — deferred; empirically too noisy on cellular where TCP RTT is small.
