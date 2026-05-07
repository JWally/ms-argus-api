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
}

export const ISSUER_CONFIG: IssuerConfig = {
  host: "demo-issuer.private-access-tokens.fastly.com",
  directoryPath: "/.well-known/token-issuer-directory",
  expectedTokenType: 0x0002,
  directoryCacheSeconds: 3600,
  disabled: false,
};
