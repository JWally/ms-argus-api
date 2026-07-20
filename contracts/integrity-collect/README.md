# Integrity collect transport contract

`v1/transport.json` is the provider-owned contract for browser submissions to
`POST /v1/integrity-collect`. The contract schema is independent from the only
supported wire version, `X-Argus-V: 3`.

The `/v1/integrity-collect` path is the current API route namespace; it is not
an alternate `X-Argus-V` payload shape or a compatibility decoder.

Ciphertext cannot be a timeless static fixture because the AES key derivation
uses the current UTC date and an ECDH keypair. The API contract suite therefore
generates a keypair, applies the v3 scramble pipeline, encrypts the bytes, and
replays the request through the real ingestion middleware. The same manifest is
copied into the browser SDK as a test-only consumer fixture; the API copy is the
source of truth.

The retired v1/v2 compatibility paths were removed in July 2026. A future wire
change replaces v3 across the provider and all consumers; the API does not keep
unused wire decoders. The browser SDK must not emit a changed contract until
both provider and consumer contract suites pass.
