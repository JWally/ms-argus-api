/**
 * Manual ASN→category overrides for ASNs whose IPtoASN organization name
 * doesn't pattern-match cleanly via the regex categorizer.
 *
 * Edit this file to fix misclassifications. Applied last by the builder, so
 * entries here win over regex output. Empirically derived from the integrity
 * archive sample on 2026-04-25 (validated against 200 sessions / 67 unique IPs).
 */
export const ASN_OVERRIDES: Record<string, string> = {
  // ─── US residential ISPs whose ASN names don't pattern-match
  "5089": "residential", //  Virgin Media UK (org name "NTL" — legacy National Telecommunications Limited)
  "22773": "residential", // Cox (org name "ASN-CXA-ALL-CCI-22773-RDC")
  "5650": "residential", //  Frontier (org name "FRONTIER-FRTR")
  "209": "residential", //   CenturyLink/Lumen ("CENTURYLINK-US-LEGACY-QWEST")
  "22561": "residential", // CenturyLink/Lumen ("CENTURYLINK-LEGACY-LIGHTCORE")
  "20001": "residential", // TWC PacWest residential
  "33588": "residential", // BresNet residential
  "30036": "residential", // Mediacom residential
  "12271": "residential", // Charter Communications regional
  "11427": "residential", // Charter Communications regional (Texas)
  "16591": "residential", // Google Fiber residential

  // ─── Mobile carriers
  "1239": "mobile", //  Sprint (org name "SPRINTLINK")
  "12576": "mobile", // OneTone Telecommunications mobile
  "16086": "mobile", // DNA Finland mobile
  "15994": "mobile", // TeliaSonera Mobile

  // ─── Cloud / privacy
  "31898": "datacenter", //   Oracle Cloud
  "199524": "datacenter", //  G-Core Labs
  "714": "privacy_relay", //  Apple (iCloud Private Relay egress)
  "6185": "privacy_relay", // Apple
  "36692": "security_filter", // Cisco Umbrella
};
