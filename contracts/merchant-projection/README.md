# Merchant projection contract

`GET /v1/session/{cpi}/{session_id}` returns a top-level merchant projection.
`schema_version` is the compatibility boundary; consumers must reject unknown
versions instead of interpreting a changed shape with stale policy.

Version 1 guarantees the threat axes, verdict, creation timestamp,
identification/browser details, network blocks, tags, and worker-scope evidence
documented by `MerchantSafeResponse`. Additional fields may be added without a
version bump. Removing or changing the meaning/type of a guaranteed field
requires a new version.

`v1/valid-minimal.json` is generated conceptually from an empty integrity input
and is asserted against `buildMerchantResponse` by the provider test suite. A
consumer may impose stricter policy requirements: Pair, for example, rejects a
null or stale `created_at` even though null remains a valid API value for legacy
records.
