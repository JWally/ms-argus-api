/**
 * Single source of truth for the PAT issuer.
 *
 * Loose-coupling contract: this is the ONLY place the issuer hostname appears.
 * Swap providers (Fastly → Cloudflare → self-hosted → none) by editing this file.
 *
 * Currently pointing at Fastly's Apple-listed demo issuer. Per Fastly's own
 * docs this is "a demo" with no SLA — it could vanish without notice. The
 * surrounding architecture is built on the premise that PAT is a best-effort
 * additive signal: if the issuer 404s, the rest of Argus runs unchanged and
 * the `pat` field on the payload is simply absent.
 *
 * To disable PAT entirely: set DISABLED=true. The Lambda still deploys, the
 * route still exists, but every request returns 503 with no-store. Clients
 * see a null signal.
 */

export interface IssuerConfig {
  /** Hostname iOS's attester (gateway.icloud.com) will accept. */
  readonly host: string;
  /** Path to the directory JSON. RFC 9578 §6.2 says this exact path. */
  readonly directoryPath: string;
  /** Token type we accept. RFC 9578 type 0x0002 = RSA Blind Signatures. */
  readonly expectedTokenType: number;
  /** Cache the directory this long before refetching (seconds). */
  readonly directoryCacheSeconds: number;
  /** If true, the handler short-circuits to 503 without ever calling the issuer. */
  readonly disabled: boolean;
  /**
   * Known-good `token_key_id`s (hex SHA-256 of the directory's token-key SPKI).
   * Defends against a hijacked/compromised issuer directory serving an
   * attacker-controlled key (which would let it mint forgeable PATs): an active
   * key whose id is NOT in this set is "unrecognized" and we WARN on it.
   *
   * Empty set → no pinning (trust the directory, legacy behaviour).
   *
   * This issuer rotates ~weekly and publishes ~3 keys at a time, so a HARD pin
   * would dark PAT within a week or two of a rotation we didn't track — hence
   * the default is alert-only (`enforceKeyPin: false`): always accept, but emit
   * a tripwire so a rotation OR a hijack is visible in logs. Flip
   * `enforceKeyPin` to true to fail-closed (reject unrecognized → no PAT) once
   * you're willing to bump this list on each rotation.
   */
  readonly knownTokenKeyIds: readonly string[];
  /** If true, reject an unrecognized active key (fail-closed) instead of just warning. */
  readonly enforceKeyPin: boolean;
}

export const ISSUER_CONFIG: IssuerConfig = {
  host: "demo-issuer.private-access-tokens.fastly.com",
  directoryPath: "/.well-known/token-issuer-directory",
  expectedTokenType: 0x0002,
  directoryCacheSeconds: 3600,
  disabled: false,
  // demo-issuer.private-access-tokens.fastly.com — captured live 2026-06-24.
  // Refresh on rotation (watch for the "PAT issuer key UNRECOGNIZED" warn log).
  knownTokenKeyIds: [
    "d9d8813a74c2e23e73db564a36c751613b5ba04da2993227e1d315c236fb1338",
    "12d38dbada868875f9a18ce5c4c48179b2953c643f4333a3faf88f94322efffb",
    "575e3d438030b354248e58961f60d5f3d28fcc3bb62621f12c816fce03144346",
  ],
  enforceKeyPin: false,
};
