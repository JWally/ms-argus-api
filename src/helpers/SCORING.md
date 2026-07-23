# Scoring rules cheatsheet

Every Argus verdict is one number per axis (0-100, lower = better) plus a verdict bucket. This document is the **rules** — not the code. For the code, see `merchant-projection.ts`.

## Verdict thresholds

```
max(automation, device_tampering, network_tampering) >= 70  → BLOCK
                                                      >= 30  → SUSPECT
                                                      <  30  → CLEAN
```

Three thresholds, one rule. Any single axis saturating is enough to flag.

---

## Network tampering — "is the path lying about itself?"

### MSS / path-MTU telemetry (diagnostic only)

Reduced `snd_mss` and path MTU remain stored as internal path telemetry. They
can result from VPN encapsulation, but also from ordinary carrier, CGNAT,
PPPoE, IPv6-transition, and other access-network overhead. Therefore neither
the historical `network.vpn_component` field nor its legacy `LIKELY_VPN`
signal can originate a merchant verdict or `vpn` tag.

### RTT ratio (LIKELY_PROXY)

| `rcv_rtt / rtt >=` | severity |
| ------------------ | -------- |
| 2.5×               | 0.6      |
| 2.0×               | 0.35     |
| 1.5×               | 0.15     |

RTT ratio is proxy evidence only. It cannot create VPN evidence; transient
receive-side RTT samples are left to the integrated proxy waterfall for
corroboration.

### ASN category

The broader local `network_class` wins when present; the legacy ASN `category`
is the fallback for historical rows.

Runtime classification is an in-memory lookup from the gzipped ASN database in
S3. The weekly/on-deploy builder joins the full IPtoASN routing table with
conservative name rules and current provider-owned overrides; there is no
request-time reputation REST call. Broad hosting networks remain covered by
the datacenter policy, while residential proxies stay with the separate proxy
waterfall because ASN ownership alone cannot identify them safely.

| ASN class                         | VPN/network score | policy                                  |
| --------------------------------- | ----------------- | --------------------------------------- |
| datacenter                        | 1.0               | block + `hyperscaler` tag               |
| vpn_proxy                         | 1.0               | block + `vpn` tag                       |
| privacy_relay                     | 0                 | tag-only; legitimate consumer privacy   |
| corporate_proxy / security_filter | 0                 | tag-only corporate-shield carve-out     |
| mobile / residential / other      | 0                 | no VPN score from path-shape heuristics |

### Probe consistency

| condition                                | severity | code                                |
| ---------------------------------------- | -------- | ----------------------------------- |
| WebRTC MAC invalid                       | 0.9      | WEBRTC_SIGINT_FORGERY               |
| 3+ distinct probe IPs, drift ≥ 256       | 0.8      | IP_PROBE_SCATTER                    |
| 2 distinct probe IPs, drift ≥ 256        | 0.6      | IP_PROBE_SCATTER                    |
| probe IPs all within 256 of each other   | —        | suppressed (carrier-NAT pool)       |
| WebRTC IP differs but same /16 as probes | 0.1      | SAME_SUBNET_CGNAT (positive signal) |
| WebRTC IP differs, different /16         | 0.7      | WEBRTC_IP_MISMATCH                  |

### Axis composition

`nt = max(asn_network_score, proxy_threat, ip_scatter_penalty)` — pure winner-take-all today.
The raw RTT-derived `proxy_component` and MSS-derived `vpn_component` are
diagnostic inputs, not substitutes for a zero ASN score.

---

## Automation — "is a bot driving this?"

### Hard residue (any one ⇒ 100)

- `webDriverIsOn`
- `automationGlobals` non-empty (`__playwright`, `__puppeteer`, `_phantom`, …)
- `cdcGlobals` true (`$cdc_*` props on document)
- `headlessRating >= 100`
- `iframe_created && !responsive` ⇒ automation 100 + tampering 50 (Marionette hang)

### CDP-timing magnitude

- **Clause A** (desktop CDP / DevTools-emu): `min(iframe.log_heavy_us, worker.log_heavy_us) > 40µs`
- **Clause B** (one-sided): `max > 20µs && min < 12µs`

Clause A is corroborated across two realms and scores **75**. Clause B is a
single-realm timing outlier and scores **60** unless another strong CDP signal
independently raises the score. This keeps the evidence visible without making
one noisy desktop sample a blocking automation verdict.

### Soft markers

- `likeHeadlessRating >= 50` contributes — built from 10 environment flags (`noMimeTypes`, `noChrome`, `noPlugins`, `hasSoftwareRenderer`, `pdfIsDisabled`, etc.). Calibrated for desktop; mobile carve-out applies.

### PAT (Apple Private Access Token) adjustments

| condition                  | effect                                                                      |
| -------------------------- | --------------------------------------------------------------------------- |
| PAT verified               | automation capped at **25** (unless hard residue => floor 75 still applies) |
| PAT missing on an Apple UA | score-neutral; emits the `apple_attestation_missing` diagnostic tag         |

---

## Device tampering — "is the device lying about itself?"

### Tier-100 (definitive)

- ja4-ua family mismatch + corroborator
- aws_cf TLS attestation forged (tamper flag set)
- aws_cf `ageSec > 300` OR future-dated (replay)
- Lies count `>= 20` (5 wrapped console methods × 11 lie checks ≥ 20 lights this)
- Browser engine baseline mismatch (definitive)

### Tier-60 (strong but not definitive)

- Browser engine baseline mismatch (possibly-legit)
- ja4-ua mismatch alone
- PAT + `device_identity` signature failed together
- aws_cf `ageSec 90-300s` (slow page, suspicious)
- Worker oracle missing (main-only execution, no Worker scope at all)

### Tier-50

- Worker oracle reachable only via dedicated worker, no shared worker

### Tier-35

- Single weak corroborator (incognito-claimed + device-history mismatch, etc.)
- `kernel_os.KERNEL_OS_MISMATCH_DARWIN` (severity 0.85): claimed iOS/macOS but TCP options indicate Linux kernel; if JA4/H2/UA all corroborate Safari/WebKit, this is treated as low-confidence path evidence

### Tier-25

- Worker hardwareConcurrency / UA divergence (severity 0.7-0.8)

---

## Tags (categorical labels, derived after scoring)

| tag                         | trigger                                                                        |
| --------------------------- | ------------------------------------------------------------------------------ |
| `vpn`                       | `network_class = vpn_proxy`                                                    |
| `hyperscaler`               | `network_class = datacenter`/`hyperscaler`                                     |
| `cellular`                  | ASN mobile OR `SAME_SUBNET_CGNAT` fired                                        |
| `proxy`                     | `network_class = corporate_proxy`/`hosting_proxy`/`cdn` (when not whitelisted) |
| `corporate_shield`          | ASN matches known corporate proxy (Cisco Umbrella, Zscaler, etc.)              |
| `privacy_relay`             | iCloud Private Relay egress confirmed                                          |
| `incognito`                 | direct browser detection                                                       |
| `developer_tools`           | direct detection (debugger-statement timing OR ≥300px geometry)                |
| `location_mismatch`         | timezone/locale-derived country ≠ CloudFront-observed country                  |
| `language_mismatch`         | `Accept-Language` country ≠ CloudFront country                                 |
| `browser_tampering`         | device_tampering composite ≥ 30                                                |
| `automation`                | automation composite ≥ 70                                                      |
| `apple_attested`            | PAT verified                                                                   |
| `apple_attestation_missing` | PAT failed/absent on Apple-claimed UA                                          |

---

## Notable carve-outs (negative evidence today; will be first-class in weighted rewrite)

- **Cisco Umbrella corporate shield**: bypasses JA4/H2 mismatch rules (the JA4 belongs to the shield, not the browser).
- **iCloud Private Relay**: when confirmed, bypasses kernel-OS-mismatch rule (PR egress strips ECN).
- **Mobile UA**: CDP-timing soft thresholds raised (`BENCH_*_MOBILE_US`) — real mobile Chrome roams 16-27µs naturally.
- **Brave on iOS**: navigator-API gaps absorbed (Brave restricts certain APIs).
- **PAT-verified Apple device**: cap soft automation evidence at 25; hard evidence remains authoritative.
- **Same-NAT-pool probes** (drift < 256 IPs): suppress IP_PROBE_SCATTER (carrier-NAT carve-out, shipped 2026-05-28).

## Known sharp edges

- ASN classification is deliberately coarse. A mixed-use ASN can still need a CIDR override, while VPN endpoints on residential ISPs need the separate proxy waterfall or an IP-level reputation dataset.
- `max()` aggregation across the three axes means no amount of negative evidence on axes B and C can wash out a single saturating signal on axis A.
- Tor exit nodes (e.g. `185.220.101.0/24` Zwiebelfreunde) are not currently tagged as Tor — they get caught via headless detection, not anonymity-network classification.
