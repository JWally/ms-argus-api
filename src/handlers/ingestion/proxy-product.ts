import { HttpError } from "../../helpers/http-error";
import type { ArgusPayload } from "../../helpers/payload-schema";
import { isAwsCfAuthenticallyHydrated } from "../../helpers/redeem-sigint-tokens";

const PROXY_PRODUCT = "proxy_v1" as const;

export function isProxyProduct(payload: ArgusPayload): boolean {
  return payload.product === PROXY_PRODUCT;
}

/**
 * Proxy-only scans have no browser-fingerprint fallback, so every
 * server-authoritative probe must redeem before the row can be scored.
 */
export function assertProxyEvidenceHydrated(payload: ArgusPayload): void {
  const sigint = payload.sigint;
  if (
    isAwsCfAuthenticallyHydrated(sigint) &&
    !!sigint?.tcp_probe &&
    !!sigint?.h2
  ) {
    return;
  }
  throw new HttpError(400, "proxy probe redemption failed");
}
