/** Public schema version for GET /v1/session/{cpi}/{session_id}. */
export const MERCHANT_PROJECTION_SCHEMA_VERSION = 1 as const;

export type MerchantProjectionSchemaVersion =
  typeof MERCHANT_PROJECTION_SCHEMA_VERSION;
