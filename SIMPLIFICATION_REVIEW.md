# Simplification & De-duplication Review — ms-argus-api

**Date:** 2026-07-12
**Scope:** `src/` + `lib/` (≈22.7k non-test LOC). Goal per the review brief:
find (a) DB round trips that a signature/MAC could replace without losing a
security property, (b) clusters of near-duplicate functions worth collapsing,
and (c) any genuine mega-functions. Every proposal below states **what is
gained** and, where relevant, **what would be lost** — because in a security
codebase "less code" is only a win if the trust properties survive.

**Guiding principle for this whole document:** a signature can replace a DB read
_only_ when the read is being used as an integrity/authenticity check. It
**cannot** replace a read that enforces single-use, revocation, a monotonic
counter, or genuinely fresh server-side state. Each item is labelled
accordingly.

---

## Executive summary

| #   | Item                                                                                      | Type              | Effort            | Risk   | Payoff                                                                 |
| --- | ----------------------------------------------------------------------------------------- | ----------------- | ----------------- | ------ | ---------------------------------------------------------------------- |
| 1   | Probe-token DDB reads → self-contained sealed tokens                                      | Architecture / DB | High (cross-repo) | Medium | **–2 of 5 hot-path round trips**, kills a cross-stack table dependency |
| 2   | Firehose archive is awaited but documented fire-and-forget                                | Latency bug       | Trivial           | None   | p99 = `max(ddb, firehose)` → `ddb`                                     |
| 3   | ECDH inflate has no `maxOutputLength` (zip bomb)                                          | **Security bug**  | Trivial           | None   | Closes an unauthenticated decompression-bomb vector                    |
| 4   | `token-verifier` never checks `iat`/expiry                                                | **Security bug**  | Low               | Low    | Merchant tokens actually expire                                        |
| 5   | Four ECDH decrypt fns → one core + adapters                                               | De-dup            | Low               | Low    | ~160 LOC, single place for the key-trial loop                          |
| 6   | Five identical `toResultSignals` mappers → one                                            | De-dup            | Trivial           | None   | 5 copies → 1                                                           |
| 7   | Four S3 gz-dataset loaders → one factory                                                  | De-dup            | Medium            | Low    | ~120 LOC, one cache-stampede impl                                      |
| 8   | Firehose-archive S3 walker duplicated in 2 crons                                          | De-dup            | Low               | None   | ~90 LOC                                                                |
| 9   | base64url + constant-time compare scattered                                               | De-dup            | Low               | Low    | One codec, one ct-compare file                                         |
| 10  | Dead code: `payloadJsonSchema`, `isArgusPayload`, `createVectorLambdaConfig`, `getByPath` | Cleanup           | Trivial           | None   | Delete or wire up                                                      |
| 11  | `merchant-projection.ts` (2,579 LOC) — finish the `scoring/` extraction                   | Structure         | High              | Low    | Drain the god-file                                                     |

**Explicitly NOT recommended:** a generic `verifySignedBlob()`. See §12.

---

## 1. Probe-token DDB reads → self-contained sealed tokens

**Type:** architecture / removes 2 hot-path DB round trips.
**The DB read here is an integrity check, not a single-use/revocation gate — so it is replaceable.**

### Current behaviour

`hydrateSigint` (`src/handlers/ingestion/base-handler.ts:289`) calls
`redeemSigintTokens`, which for **each** of the TCP and H2 probes does a
DynamoDB `GetItem` against `PROBE_TOKENS_TABLE` (owned by `ms-argus-platform`):

```ts
// src/helpers/redeem-sigint-tokens.ts:167-195
const item = await fetchProbeItem(token, ctx.tableName, ctx.dynamo);  // ← DDB GetItem
if (!item) { ... return null; }

// Layer 3: reject when redeeming IP != minting IP
if (item.clientIp !== ctx.requestSourceIp) { ... return null; }        // line 179

// Verify HMAC — Go signs over nonce.expiry.clientIP
if (!verifyTokenHmac(token, ctx.sigintAesKeyHex, item.clientIp)) { ... return null; }  // line 189

return item.fingerprint;
```

Both reads run on **every** ingestion request (the `sigintTokenValidator`
middleware 400s any request missing `sigintTcpToken`/`sigintH2Token`, so they
are effectively unconditional).

### Why the DB read is not buying a security property

1. **The IP check makes the fetched `clientIp` redundant for the HMAC.**
   Line 179 proves `item.clientIp === ctx.requestSourceIp` _before_ line 189
   uses `item.clientIp` to verify the HMAC. So the HMAC is verified against a
   value provably equal to `ctx.requestSourceIp` — which the server already has
   from `event.requestContext.http.sourceIp`. The DB is not needed to
   authenticate the token.

2. **No single-use.** `fetchProbeItem` is a plain `GetItem` — no `DeleteItem`,
   no `ConditionExpression`, no consume-on-redeem. A harvested token is
   replayable from the same IP within its expiry window _today_.

3. **No revocation.** Nothing ever deletes a row early; rows age out by `ttl`.

So the only thing the DB read carries that the token doesn't is the
**`fingerprint` payload itself** (rtt/rcv*rtt/snd_mss for TCP, JA4/TLS for H2).
That is a \_data-carrier* read, and a signed/encrypted blob carries data just as
well as a table row.

### The pattern already exists in this repo — three times

- **`pat-signed-token.ts`** — its docstring literally says it _"Replaces the
  previous DB-backed `{nonce}.{expiry}.{hmac}` flow… no DynamoDB round trip."_
  It packs the payload into `<b64url(JSON)>.<hexmac>` and verifies inline, with
  mandatory `src_ip`/`cpi`/`session_id` binding.
- **`aws_cf` / TLS probe** — carries its whole payload client-side, SipHash-2-4
  signed, verified inline (`redeem-sigint-tokens.ts:264` → `verify-cf-token.ts:129`),
  freshness = ±90s `ts` window. Zero I/O. `isAwsCfAuthenticallyHydrated`
  (`redeem-sigint-tokens.ts:377`) is the trust gate.
- **`device-history.ts`** — an entire per-device visit history in a client-held
  AES-256-GCM blob, zero server state; the GCM auth-tag failure _is_ the tamper
  signal.

The TCP/H2 probes are the only holdout. And `src/helpers/decrypt-probe.ts`
already implements the AES-256-GCM `{v, data}` sealed-envelope decrypt — it is
referenced only by its own test today (§10), i.e. the machinery is built and
waiting.

### Proposed design

Have the Go sigint probes (in `ms-argus-sigint`) emit, instead of a DB-backed
opaque token:

```
sealed = base64( iv(12) | AES-256-GCM( key = HKDF(SIGINT_AES_KEY, "argus-sigint-probe-v1"),
                                       aad = clientIP,
                                       plaintext = JSON({ fp, nonce, exp, ip }) ) )
```

The API decrypts inline and checks:

- GCM tag verifies (authenticity + integrity — replaces the HMAC),
- `exp >= now` (freshness — replaces `checkTokenExpiry`),
- `ip === event.requestContext.http.sourceIp` (IP binding — replaces Layer 3),
- optionally bind `aad = clientIP` so a tag mismatch also catches IP tampering.

`redeemToken` collapses from "expiry-check → DDB GetItem → IP check → HMAC" to a
pure function:

```ts
// src/helpers/redeem-sigint-tokens.ts — new, no ctx.dynamo, no ctx.tableName
function redeemSealedProbe(
  sealed: string | undefined,
  sigintAesKeyHex: string,
  requestSourceIp: string,
  logger?: Logger,
): unknown | null {
  if (!sealed) return null;
  const opened = openSealedProbe(sealed, sigintAesKeyHex, requestSourceIp); // decrypt-probe.ts
  if (!opened) {
    logger?.warn("sigint sealed probe failed to open");
    return null;
  }
  if (!Number.isFinite(opened.exp) || Date.now() > opened.exp) return null;
  if (opened.ip !== requestSourceIp) return null;
  return opened.fp;
}
```

`RedeemCtx` loses `dynamo` and `tableName`; `redeemSigintTokens` loses its
`Promise.all` of two DDB reads.

### Rollout (this is a cross-repo change — plan it as its own project)

1. Ship the API able to open **both** formats: try `redeemSealedProbe`; if the
   token isn't the sealed shape, fall back to the DB path. (The `{v, data}`
   shape is already distinguished from legacy tokens at
   `redeem-sigint-tokens.ts:127` and `middleware.ts:277`.)
2. Ship `ms-argus-sigint` emitting sealed tokens.
3. Once the `SigintLegacyTokenRedeemed` metric hits zero for a full token-TTL
   window, delete the DB path and the `PROBE_TOKENS_TABLE` grant.

### Test cases

Positive:

- `redeemSealedProbe` returns the `fp` for a well-formed sealed token minted
  with the same key and the request source IP.
- Dual-format window: a legacy `{nonce}.{expiry}.{hmac}` token still redeems via
  the DB fallback while the metric is emitted.

Negative (these are the security-critical ones — each must return `null`):

- **Tampered ciphertext** → GCM tag fails → `null` (previously the HMAC caught
  this; assert the new path does too).
- **Expired** `exp < now` → `null`.
- **IP replay**: token minted for `1.2.3.4`, redeemed from `5.6.7.8` → `null`
  (mirror the existing "harvest → replay from elsewhere" test in
  `redeem-sigint-tokens.test.ts`).
- **Wrong key**: sealed with a different `SIGINT_AES_KEY` → `null`.
- **Cross-field confusion**: a TCP sealed token presented as the H2 token — bind
  a `kind: "tcp" | "h2"` field inside the plaintext and assert a mismatch → `null`.
- **Layer-1 preservation**: assert `stripClientControlledSigintFields` still runs
  first, so a failed open leaves `sigint.tcp_probe`/`h2` genuinely absent (this is
  ARGUS_URGENT_FIXES #1 — the regression test must stay green).

### Benefit

- **–2 of 5 steady-state round trips** on the single busiest endpoint.
- **Removes the cross-stack coupling** to a `ms-argus-platform`-owned table (one
  fewer thing that can throttle/fail and 503 your ingestion path — today a DDB
  throw here is a hard `HttpError(503)` at `base-handler.ts:326`).
- No security property lost: the GCM auth tag gives you exactly what the HMAC
  gave you, and the DB was never enforcing single-use or revocation.

> ⚠️ **If you later decide you _want_ single-use on TCP/H2** (you have it on STUN
> via `claimStunNonce`, but not here today), that is a **separate, deliberate**
> addition and it must be a **conditional write**, not a read — do not let this
> simplification be mistaken for having removed single-use, because there was
> none to remove.

---

## 2. Firehose archive is awaited but documented as fire-and-forget (latency bug)

**Type:** latency bug. Trivial fix.

`firehose-archive.ts:9` states _"the response to the client does not depend on
the archive succeeding."_ That is true of **errors** but not **latency**:

```ts
// src/handlers/ingestion/base-handler.ts:901-917
await Promise.all([
  ddbClient.send(new PutItemCommand({ ... })),   // the write the response needs
  archiveToFirehose(item, { ... }),              // documented fire-and-forget
]);
```

`await Promise.all([...])` blocks on the slower of the two, so p99 latency is
`max(ddbPut, firehose)` rather than `ddbPut`.

### Proposed swap

```ts
export async function persistIntegrityRecord(
  ctx: HandleContext,
  item: Record<string, unknown>,
): Promise<{ duplicate: boolean }> {
  // Fire-and-forget: never gates the response. Errors are logged + metered
  // inside the helper; the row is already durable in DDB.
  void archiveToFirehose(item, {
    streamName: INTEGRITY_FIREHOSE_STREAM,
    logger: ctx.deps.logger,
    metrics: ctx.deps.metrics,
  }).catch(() => {}); // archiveToFirehose already swallows; belt-and-suspenders

  try {
    await ddbClient.send(
      new PutItemCommand({
        TableName: INTEGRITY_RESULTS_TABLE,
        Item: marshall(item, { removeUndefinedValues: true }),
        ConditionExpression: "attribute_not_exists(cpi)",
      }),
    );
    return { duplicate: false };
  } catch (err) {
    // ... unchanged ConditionalCheckFailedException / 503 handling ...
  }
}
```

> **Caveat to verify before shipping:** in Lambda, work not awaited before the
> handler returns can be frozen mid-flight and only resumed on the next
> invocation (or dropped). Firehose `PutRecord` is a single fast call, so in
> practice it completes within the response window, but if you observe a drop in
> `IntegrityArchived` after this change, the fix is to keep the `await` but move
> it _after_ the response is computed, or batch archives via the DDB stream (the
> shadow path the docstring mentions). Measure `IntegrityArchived` before/after.

### Test cases

- Handler still returns 200 when `archiveToFirehose` **rejects** (already
  covered — assert it stays green).
- New: handler latency is bounded by the DDB put — mock Firehose with a 2s delay
  and assert the response resolves without waiting for it.

### Benefit

Removes Firehose latency from every ingestion response, for one line of change.

---

## 3. ECDH inflate has no `maxOutputLength` — unauthenticated zip-bomb (security bug)

**Type:** security bug. Trivial fix.

The `/v1/integrity-collect` endpoint was sealed to the ECDH path only in May
2026 (`middleware.ts:126` `enforceIntegrityCollectSeal`). The size bound,
however, still lives on the now-dead gzip path:

```ts
// src/handlers/ingestion/gzip.ts:157 — the SEALED-OFF path DOES bound it
const decompressed = await streamingGunzip(
  gzipBuffer,
  config.maxDecompressedBytes,
);
```

while the **live** ECDH path inflates with no bound, in all three decrypt
functions:

```ts
// src/helpers/ecdh-decrypt.ts:165, 224, 283 — the LIVE path does NOT
const inflated = inflateRawSync(Buffer.from(decrypted));
```

`deriveAesKey` accepts any attacker-supplied `X-Argus-Origin` public key against
the server's public ECDH key, so **any unauthenticated caller** can produce a
validly-encrypted deflate bomb: API Gateway caps the body at ~10 MB compressed,
which `inflateRawSync` will happily expand to hundreds of MB of heap on a single
Lambda invocation, and N concurrent requests multiply that toward the memory
ceiling → OOM / cost amplification.

### Proposed swap

`inflateRawSync` accepts a `maxOutputLength` option; on overflow it throws
`RangeError`, which the existing `try/catch` inside the key-trial loop already
handles (it falls through to the next key/date and ultimately returns `null` →
`HttpError(400)`). So the fix is additive and needs no new error handling:

```ts
// src/helpers/ecdh-decrypt.ts — top of file
const MAX_INFLATED_BYTES = Number(
  process.env.MAX_DECOMPRESSED_BYTES ?? 2 * 1024 * 1024,
);

// all three call sites:
const inflated = inflateRawSync(Buffer.from(decrypted), {
  maxOutputLength: MAX_INFLATED_BYTES,
});
```

(After §5's consolidation there is only **one** call site to change — another
reason to do §5.)

### Test cases

Positive:

- A normal ~50 KB payload inflating to <2 MB decrypts and parses fine
  (regression — assert unchanged).

Negative:

- A validly-ECDH-encrypted body whose plaintext inflates past
  `MAX_INFLATED_BYTES` → `decryptIntegrityPayload*` returns `null` → middleware
  throws `HttpError(400)` and increments `IntegrityDecryptFailed`. Build the
  fixture by deflate-compressing e.g. 5 MB of `"A"`, encrypting it with a test
  ECDH keypair.
- Boundary: plaintext exactly at the limit succeeds; limit+1 fails.

### Benefit

Closes a real, unauthenticated resource-exhaustion vector on your only live
ingestion path, matching the protection the sealed-off gzip path already had.

---

## 4. `token-verifier` never checks `iat` / has no expiry (security bug)

**Type:** security bug. Low effort.

`VerifiedClaims.iat` is parsed and shape-checked (`token-verifier.ts:54, 93`)
but **never used**. `verifyMerchantToken` verifies the Ed25519 signature and the
`keyId`/`cpi` binding, then returns the claims — with no freshness check. A
merchant token, once minted, verifies **forever** (until the signing key
rotates). If a token leaks, there is no time-boxing.

### Proposed swap

Add an `exp` (or a max-age derived from `iat`) check. Prefer an explicit `exp`
claim minted by the platform; if the platform only mints `iat`, enforce a
max-age:

```ts
// src/helpers/token-verifier.ts
const DEFAULT_MAX_TOKEN_AGE_MS = 24 * 60 * 60 * 1000; // tune to your issuance cadence

export interface VerifierOptions {
  ssmPubkeyPath: string;
  expectedCpi?: string;
  /** Reject tokens older than this (ms). Defaults to 24h. */
  maxAgeMs?: number;
}

export async function verifyMerchantToken(
  keyIdHeader: string | undefined,
  tokenHeader: string | undefined,
  opts: VerifierOptions,
): Promise<VerifiedClaims | null> {
  if (!keyIdHeader || !tokenHeader) return null;
  const parsed = parseToken(tokenHeader);
  if (!parsed) return null;
  if (parsed.claims.keyId !== keyIdHeader) return null;
  if (opts.expectedCpi && parsed.claims.cpi !== opts.expectedCpi) return null;

  // NEW: freshness. iat is seconds or ms depending on the minter — normalize.
  const iatMs =
    parsed.claims.iat < 1e12 ? parsed.claims.iat * 1000 : parsed.claims.iat;
  const maxAge = opts.maxAgeMs ?? DEFAULT_MAX_TOKEN_AGE_MS;
  if (!Number.isFinite(iatMs) || Date.now() - iatMs > maxAge) return null;
  // also reject absurd future-dated tokens (clock-skew tolerant):
  if (iatMs - Date.now() > 5 * 60 * 1000) return null;

  const pubkey = await loadPublicKey(opts.ssmPubkeyPath);
  const ok = cryptoVerify(
    null,
    Buffer.from(parsed.encodedClaims, "utf8"),
    pubkey,
    base64urlDecode(parsed.encodedSig),
  );
  return ok ? parsed.claims : null;
}
```

> **Coordinate with `ms-argus-platform` first** to learn whether `iat` is in
> seconds or milliseconds and whether an `exp` claim can be added — a wrong unit
> assumption here would reject every valid token. The normalization above is a
> hedge, but confirm the contract.

### Test cases

Positive:

- Fresh token (`iat = now`) with a valid signature → returns claims.
- Token at `maxAgeMs - 1` → still valid.

Negative:

- Token at `maxAgeMs + 1` → `null`.
- Future-dated token beyond skew tolerance → `null`.
- Otherwise-valid signature but stale `iat` → `null` (proves signature validity
  alone is no longer sufficient).

### Benefit

Merchant session tokens gain a real lifetime; a leaked token stops working.

---

## 5. Four ECDH decrypt functions → one core + adapters

**Type:** de-duplication. The clearest "six functions doing the same thing" in
the repo (it's four).

`ecdh-decrypt.ts` has four functions —
`decryptArgusPayload`, `decryptIntegrityPayload`, `decryptIntegrityPayloadV2`,
`decryptIntegrityPayloadV3` — whose bodies are **character-for-character
identical** for the buffer split, the `keySets` filter, the today/yesterday salt
computation, and the 2×2 key/date trial loop. The **only** variance is a single
post-decrypt transform:

| fn                          | post-decrypt transform                                 |
| --------------------------- | ------------------------------------------------------ |
| `decryptArgusPayload`       | `inflateRawSync(b)`                                    |
| `decryptIntegrityPayload`   | `xorUnscramble(inflateRawSync(b), innerKey)`           |
| `decryptIntegrityPayloadV2` | `deriveAndUnscramble(inflateRawSync(b), sessionToken)` |
| `decryptIntegrityPayloadV3` | `deriveAndUnscramble(b, sessionToken)` (no inflate)    |

### Proposed swap

```ts
// src/helpers/ecdh-decrypt.ts

/** Reverses the client's post-encryption transform. Called INSIDE the
 *  per-key try/catch so a failed unwrap falls through to the next key. */
type Unwrap = (plaintext: Buffer) => Buffer;

const MAX_INFLATED_BYTES = Number(
  process.env.MAX_DECOMPRESSED_BYTES ?? 2 * 1024 * 1024,
);
const inflate = (b: Buffer) =>
  inflateRawSync(b, { maxOutputLength: MAX_INFLATED_BYTES }); // §3

async function decryptEcdh(
  body: string,
  isBase64Encoded: boolean,
  clientPubKey: string,
  keys: EcdhKeys,
  unwrap: Unwrap,
): Promise<unknown | null> {
  const packed = isBase64Encoded
    ? Buffer.from(body, "base64")
    : Buffer.from(body, "binary");
  const iv = packed.subarray(0, 12);
  const ciphertextWithTag = packed.subarray(12);

  const keySets = [keys.current, keys.previous].filter(
    (k): k is EcdhKeyData => k != null,
  );
  const today = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86_400_000)
    .toISOString()
    .slice(0, 10);

  for (const keySet of keySets) {
    for (const dateSalt of [today, yesterday]) {
      try {
        const aesKey = await deriveAesKey(
          keySet.privateKey,
          clientPubKey,
          dateSalt,
        );
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          aesKey,
          ciphertextWithTag,
        );
        return JSON.parse(unwrap(Buffer.from(decrypted)).toString("utf-8"));
      } catch {
        // wrong key/date OR malformed unwrap → try next combo
      }
    }
  }
  return null;
}

// Thin, exported adapters — call sites and version dispatch are UNCHANGED.
export const decryptArgusPayload = (body, isB64, pub, keys) =>
  decryptEcdh(body, isB64, pub, keys, inflate);

export const decryptIntegrityPayload = (o: IntegrityDecryptOpts) =>
  decryptEcdh(o.body, o.isBase64Encoded, o.clientPubKey, o.keys, (b) =>
    xorUnscramble(inflate(b), o.innerKey),
  );

export const decryptIntegrityPayloadV2 = (o: IntegrityDecryptV2Opts) =>
  decryptEcdh(o.body, o.isBase64Encoded, o.clientPubKey, o.keys, (b) =>
    deriveAndUnscramble(inflate(b), o.sessionToken),
  );

export const decryptIntegrityPayloadV3 = (o: IntegrityDecryptV2Opts) =>
  decryptEcdh(o.body, o.isBase64Encoded, o.clientPubKey, o.keys, (b) =>
    deriveAndUnscramble(Buffer.from(b), o.sessionToken),
  );
```

### What must be preserved (and is)

- **The `try/catch` stays _inside_ the key/date loop.** A failed unwrap on the
  wrong key must fall through to the next key, not abort. The refactor keeps
  `unwrap` inside the `try`, so this property holds.
- **Do NOT** collapse the version _dispatch_ (`middleware.ts:58-83`) into
  "try every unwrap until one parses." That would let a client downgrade to the
  weaker v1 XOR path. Keep the four named exports and the explicit `X-Argus-V`
  switch.
- Keeping the four exported names means **zero churn** at call sites and in the
  existing `ecdh-decrypt.test.ts`.

### Test cases

- Existing decrypt tests pass unchanged (that's the point — the exports are
  behaviour-identical). If there isn't already a round-trip test per version,
  add one: encrypt with a test keypair applying each version's client transform,
  assert the matching decrypt function recovers the JSON.
- Cross-version negative: a v2-scrambled body handed to `decryptIntegrityPayloadV3`
  → `null` (proves the dispatch still discriminates).
- Previous-key / yesterday-salt paths still succeed (rotation grace).
- Plus the §3 zip-bomb negative test now lives in one place.

### Benefit

~230 LOC → ~70. One place to reason about the key-trial loop, and the §3 fix
becomes a one-line change instead of three.

---

## 6. Five identical `toResultSignals` mappers → one shared function

**Type:** de-duplication. Trivial, zero semantic loss.

Five analysis modules each map `AnomalySignal[]` → the public
`{code, severity, evidence}[]` shape with the same body:

- `src/analysis/timezone/index.ts:110` (`formatSignals`)
- `src/analysis/worker/index.ts:103`
- `src/analysis/ip-consistency/index.ts:420`
- `src/analysis/kernel-os/index.ts:130` (inlined)
- `src/analysis/network/index.ts:168` (inlined, casts `evidence.actual as unknown`)

All are `s => ({ code: s.code, severity: s.severity, evidence: s.evidence.actual })`.

### Proposed swap

Add next to `createSignal` in the shared types module:

```ts
// src/services/profile/anomaly/types.ts
/** Public projection of an internal AnomalySignal — drops the internal
 *  `type` and flattens `evidence` to its `.actual` value. */
export function toResultSignals(
  signals: AnomalySignal[],
): Array<{ code: AnomalyCode; severity: number; evidence: unknown }> {
  return signals.map((s) => ({
    code: s.code,
    severity: s.severity,
    evidence: s.evidence.actual,
  }));
}
```

Replace all five bodies with `return toResultSignals(signals);` (or, for the two
inlined sites, `const signals = toResultSignals(legacySignals);` then push any
extra module-specific signals as they already do — e.g. `network/index.ts`'s
`categoryHit` append stays).

### Test cases

- A tiny unit test on `toResultSignals` (empty array → empty; one signal →
  flattened shape).
- The existing per-module analyzer tests already assert the output shape — they
  keep them honest after the swap.

### Benefit

5 copies → 1. Removes the `as unknown` drift in `network/index.ts` by giving all
callers one typed projection.

---

## 7. Four S3 gzipped-dataset loaders → one factory

**Type:** de-duplication. Medium effort, low risk.

Four files implement the _same_ TTL-cached, stampede-guarded, gunzip-and-parse
S3 loader, differing only in the parsed type and the missing-data policy:

- `src/services/network/asn-classifier.ts`
- `src/services/network/auto-overlay.ts`
- `src/services/network/apple-relay.ts`
- `src/services/network/browser-baselines.ts`

Each has the identical quartet of module globals (`REFRESH_INTERVAL_MS = 24h`,
`cached`, `cachedAt`, `inflight`), the identical 9-line `getX()` SWR body, the
identical `new S3Client({ requestHandler: boundedRequestHandler })`, the
identical `GetObject → transformToByteArray → gunzipSync → JSON.parse`, the
identical `prewarmX()`, and the identical `_resetXForTesting()` /
`_seedXForTesting()` seams (see `browser-baselines.ts:46-134` for the exemplar).

### The one genuine difference — preserve it explicitly

`asn-classifier` **throws** on a missing bucket/body (fail-closed); the other
three **swallow and return empty** (deliberate graceful degradation, because a
missing overlay/relay/baseline must not fail an ingestion request). Model this as
a policy parameter, don't flatten it.

### Proposed swap

```ts
// src/services/network/s3-dataset.ts
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { boundedRequestHandler } from "../../helpers/sdk-http-handler";
import { gunzipSync } from "node:zlib";

const s3 = new S3Client({ requestHandler: boundedRequestHandler });

export interface S3GzDataset<T> {
  prewarm(): Promise<void>;
  get(): T | null;
  _resetForTesting(): void;
  _seedForTesting(value: T): void;
}

export function createS3GzDataset<T>(opts: {
  bucketEnv: string;
  keyEnv: string;
  defaultKey: string;
  parse: (json: unknown) => T;
  /** "throw" = fail-closed (asn-classifier). fn = graceful-degrade default. */
  onMissing: "throw" | (() => T);
  ttlMs?: number;
}): S3GzDataset<T> {
  const ttl = opts.ttlMs ?? 24 * 60 * 60 * 1000;
  let cached: T | null = null;
  let cachedAt = 0;
  let inflight: Promise<T> | null = null;

  async function load(): Promise<T> {
    const bucket = process.env[opts.bucketEnv];
    const key = process.env[opts.keyEnv] ?? opts.defaultKey;
    if (!bucket) {
      if (opts.onMissing === "throw")
        throw new Error(`${opts.bucketEnv} is required`);
      return opts.onMissing();
    }
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
    );
    if (!obj.Body) {
      if (opts.onMissing === "throw")
        throw new Error(`empty body s3://${bucket}/${key}`);
      return opts.onMissing();
    }
    const buf = Buffer.from(await obj.Body.transformToByteArray());
    return opts.parse(JSON.parse(gunzipSync(buf).toString("utf-8")));
  }

  async function getFresh(): Promise<T> {
    if (cached && Date.now() - cachedAt < ttl) return cached;
    if (inflight) return inflight;
    inflight = load().then((d) => {
      cached = d;
      cachedAt = Date.now();
      inflight = null;
      return d;
    });
    return inflight;
  }

  return {
    prewarm: async () => {
      await getFresh();
    },
    get: () => cached,
    _resetForTesting: () => {
      cached = null;
      cachedAt = 0;
      inflight = null;
    },
    _seedForTesting: (v) => {
      cached = v;
      cachedAt = Date.now();
      inflight = null;
    },
  };
}
```

Then each module becomes a thin wrapper preserving its public API, e.g.:

```ts
// src/services/network/browser-baselines.ts
const dataset = createS3GzDataset<CachedBaselines>({
  bucketEnv: "IP_CLASS_BUCKET",
  keyEnv: "BROWSER_BASELINES_KEY",
  defaultKey: "browser-baselines.json.gz",
  onMissing: () => ({ browsers: {}, engine_families: {}, generated_at: "" }),
  parse: (j) => {
    const p = j as BaselinesPayload;
    return {
      browsers: p.browsers ?? {},
      engine_families: p.engine_families ?? {},
      generated_at: p.generated_at,
    };
  },
});
export const prewarmBrowserBaselines = dataset.prewarm;
export const _resetBrowserBaselinesForTesting = dataset._resetForTesting;
export const lookupBrowserBaselineSync = (key: string) =>
  dataset.get()?.browsers[key] ?? null;
export const lookupEngineFamilyBaselineSync = (family: string) =>
  dataset.get()?.engine_families[family] ?? null;
// _seedBrowserBaselinesForTesting wraps dataset._seedForTesting to keep the
// existing {browsers?, engine_families?} partial-seed signature.
```

### Test cases

- Unit-test the factory once: TTL expiry triggers reload; concurrent `prewarm()`
  calls share one `inflight` (stampede guard); `onMissing: "throw"` throws while
  a degrade function returns its default.
- Each module's existing `_seed*ForTesting`-based analyzer tests pass unchanged —
  keeping the seams is what makes this safe.
- Explicit regression: `asn-classifier` with an unset bucket still **throws**;
  `apple-relay` with an unset bucket returns empty and the analyzer degrades to
  "not relay" (matches `base-handler.ts` fail-open behaviour).

### Benefit

~120 LOC removed and — more valuable — **one** place to fix the cache-stampede /
TTL logic instead of four subtly-independent copies.

---

## 8. Firehose-archive S3 walker duplicated across the two builder crons

**Type:** de-duplication. Low risk (offline cron path, not the request path).

`ip-class-discoverer.ts` and `browser-baseline-builder.ts` both implement:

| helper                    | ip-class-discoverer | browser-baseline-builder |
| ------------------------- | ------------------- | ------------------------ |
| `buildHourlyPrefixes`     | `:76-87`            | `:147-158`               |
| `listAllUnderPrefix`      | `:89-110`           | `:160-181`               |
| gunzip + NDJSON line loop | `:170-190`          | `:184-200`               |

The two `buildHourlyPrefixes`/`listAllUnderPrefix` blocks differ **only** by
identifier names; the hardcoded `firehose/year=…/month=…/day=…/hour=…/` prefix
appears in both.

### Proposed swap

```ts
// src/services/archive/walker.ts
export function buildHourlyPrefixes(nowMs: number, hours: number): string[] {
  /* ...shared... */
}
export async function listAllUnderPrefix(
  s3: S3Client,
  bucket: string,
  prefix: string,
): Promise<string[]> {
  /* ...shared... */
}
export async function readNdjsonGz<T>(
  s3: S3Client,
  bucket: string,
  key: string,
  parse: (o: unknown) => T,
): Promise<T[]> {
  /* gunzip → split lines → JSON.parse → parse() */
}
```

The only real difference between the two crons is the per-line `parse` callback
(`parseSessionRecord` vs identity) — a parameter to `readNdjsonGz`.

### Test cases

- `buildHourlyPrefixes(fixedNow, 3)` returns exactly the 3 expected
  `year=…/hour=…` strings (use a fixed epoch — do **not** rely on `Date.now()`).
- `readNdjsonGz` parses a multi-line gzipped fixture and applies the callback;
  a malformed line is skipped/counted the way each cron currently does (preserve
  that behaviour — check each caller's current tolerance before merging).

### Benefit

~90 LOC removed; the S3 archive layout is defined in exactly one place, so an
archive-path change can't desync the two consumers.

---

## 9. base64url + constant-time compare — scattered reimplementations

**Type:** de-duplication. Low risk, but read the caveats.

### 9a. base64url decode — three spellings of the same math

- `token-verifier.ts:158`
- `pat-signed-token.ts:101` (+ the only `b64urlEncode` at `:92`)
- `sdk-attestation.ts:199`

Extract one pure codec — safe, no secret-dependent branching:

```ts
// src/helpers/b64url.ts
export function b64urlEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
export function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}
```

Test: round-trip random buffers; decode known vectors from each current call
site to prove byte-identical output (these feed signature verification — a
behaviour change here breaks token verification).

### 9b. constant-time compare — five sites, two real semantics

- `pat-signed-token.ts:109` (`ctEqHex`, `timingSafeEqual` over hex buffers)
- `redeem-sigint-tokens.ts:57` (same thing, **copy-pasted without the wrapper**)
- `sigint-v6-decode.ts:79` (`timingSafeEqual` over raw buffers)
- `pat-attest/verify.ts:106,111` (a fifth `ctEq`)
- `verify-cf-token.ts:112` (`constantTimeStrEq` over **strings**)

Extract `src/helpers/ct-compare.ts` exporting `ctEqHex(a, b)` and
`ctEqBytes(a, b)`. Collapse the first four into calls.

> ⚠️ **Keep `verify-cf-token.ts`'s string variant separate.** It operates on
> strings, not hex-decoded buffers, _deliberately_: the CF SipHash tag is an
> attacker-suppliable arbitrary-length hex string, and `Buffer.from(garbage,
"hex")` **silently truncates at the first non-hex char** — routing it through
> `ctEqHex` would compare shorter buffers and weaken the check. Unify the file;
> do not unify the semantics.

> ⚠️ **Do not add a constant-time compare to `device-mac.ts:242`.** The comment
> at `:164` explains the MAC is derivable from public inputs, so constant-time
> is unnecessary, and the dual-order rollout compat at `:249` intentionally does
> two compares. Leave it.

Test: `ctEqHex` true for equal hex, false for differing; `ctEqBytes` likewise;
a targeted test that a non-hex-char input to the _string_ comparator is handled
without truncation (guards the caveat above).

### Benefit

One codec and one ct-compare module; removes the un-wrapped copy in
`redeem-sigint-tokens.ts`; documents the two places that must stay bespoke.

---

## 10. Dead code

**Type:** cleanup. Trivial.

- **`payloadJsonSchema` + `isArgusPayload`** (`payload-schema.ts:276, 433`) — a
  full declarative JSON schema **and** hand-rolled type guards, **neither called
  on the request path**. The middleware just `JSON.parse`s and casts
  (`middleware.ts:229`). **Recommendation:** wire `payloadJsonSchema` into a
  middy `@middy/validator` in `ingestion.ts` (cheapest real input-validation
  win available — it rejects malformed bodies before your handler touches them),
  or delete both if the downstream null-guards are considered sufficient. Do one;
  don't leave two unused validators implying coverage that isn't wired.
- **`createVectorLambdaConfig`** (`lambda-config.ts:129`) — Qdrant/matching
  pipeline was removed; **zero references**. Delete (and the `qdrant` comment).
- **`getByPath`** (`helpers/get-by-path.ts`) — **zero callers**, while
  `merchant-projection.ts` hand-rolls 45 inline `integrity.analysis.X.Y.Z` digs
  and 21 `as {…}` casts. Either adopt it there (see §11) or delete it.
- **`decrypt-probe.ts`** — referenced only by its own test. **Do NOT delete** —
  it is precisely the sealed-envelope machinery §1 needs. Promote it.

Test: none needed for deletions beyond a green typecheck/build; for the middy
validator, add positive (valid payload passes) and negative (missing
`identifiers.session_id` → 400) cases.

### Benefit

Removes two validators that imply input validation that isn't actually wired,
plus genuinely orphaned config/util code.

---

## 11. `merchant-projection.ts` (2,579 LOC) — finish the stalled `scoring/` extraction

**Type:** structure. Not duplication — an **incomplete migration**. No single
mega-_function_ (the per-function line cap is clearly enforced), but a
god-_file_: 50 hand-rolled `has*/detect*/read*` predicates over a deep
`integrity.analysis.*` shape, with 21 inline `as {…}` structural casts and 45
optional-chain digs.

`scoring/shared.ts` is the half-built destination — its own header comment
(`scoring/shared.ts:16`) even names the next functions to move:
`detectHyperscaler`, `isCorporateShieldedAsn`, `isVerifiedAppleRelay`,
`readHeadless`, `readJa4UaSignals`.

### Proposed direction (incremental — not a big-bang rewrite)

1. **Adopt `getByPath` (§10) or a typed accessor** to kill the 21 `as {…}` casts.
   Better: define a single `IntegrityView` accessor that returns typed
   sub-objects (`analysisIp(integrity)`, `analysisJa4Ua(integrity)`, …) so the
   50 predicates stop each re-deriving the shape. This is where the real
   readability win is.
2. **Move the axis predicates into `scoring/` per the existing plan**, one axis
   per PR (network-tampering already moved — follow its shape):
   `scoring/automation.ts` (the `hasCdp*`/`cdpAutomationScore` cluster),
   `scoring/device-tampering.ts` (the `readCfTamperEvidence`/`collectTamperingEvidence`
   cluster), `scoring/identity.ts` (ja4/tls/kernel/browser-engine readers).
3. Leave `buildMerchantResponse` (`:2446`) as the thin orchestrator that calls
   the axis composers — which is exactly what it already is.

### Reconcile one real inconsistency found during the sweep

`scoring/network-tampering.ts:174` does `Math.round(scatter.severity * 100)`,
bypassing `probabilityFromUnit` (`scoring/shared.ts:32`), which rounds to the
nearest 5. **Check intent** — the nearest-5 coarsening may be deliberate
merchant-facing rounding that `ipScatterPenalty` intentionally skips. If not,
route it through `probabilityFromUnit`.

### Test cases

- The extraction is behaviour-preserving, so the existing
  `merchant-projection.test.ts` (4,759 LOC!) and `merchant-projection.doc.test.ts`
  are the safety net — run them after each axis move; they should stay green with
  zero edits. If a move requires editing an assertion, that move changed
  behaviour and needs scrutiny.
- Add a focused test for the `IntegrityView` accessor (missing sub-object →
  documented default, not a throw) so the cast-removal is covered directly.

### Benefit

Drains the largest file in the repo into the home already built for it, kills 21
unsafe casts, and finishes work someone already started and documented.

---

## 12. What NOT to consolidate: a generic `verifySignedBlob()`

**This is the most tempting refactor in the repo and the most dangerous. Do not
do it.**

There are seven verifiers that share a shallow skeleton
(`split → decode → recompute → compare → check expiry → check binding → tagged
union`):

| module                    | primitive           | key source       | replay defense     | expiry             |
| ------------------------- | ------------------- | ---------------- | ------------------ | ------------------ |
| `token-verifier.ts`       | Ed25519             | SSM pubkey (SWR) | keyId binding      | none today (§4)    |
| `pat-signed-token.ts`     | HMAC-SHA256         | SIGINT_AES_KEY   | src_ip+cpi+session | `exp`              |
| `verify-cf-token.ts`      | SipHash-2-4         | SIGINT_AES_KEY   | none               | ±90s               |
| `sdk-attestation.ts`      | ECDSA P-256         | header-supplied  | key-id self-derive | iat/exp + 30s skew |
| `redeem-sigint-tokens.ts` | HMAC-SHA256         | SIGINT_AES_KEY   | DDB + client-IP    | expiry             |
| `sigint-v6-decode.ts`     | HKDF + trunc HMAC   | derived          | nonce tracker      | ±300s              |
| `device-identity.ts`      | ECDSA P-256 (v1/v2) | payload field    | h2Token+hash bind  | via h2Token TTL    |

Below the shared skeleton, **everything differs**: five primitives, four key
sources, three replay stories — and three of them (`verify-cf-token`,
`redeem-sigint-tokens`, `sdk-attestation`) must byte-match an _external_
implementation (a CloudFront Function, a Go probe, an iOS SDK).

Why separation is a security property, not an accident:

1. **A shared verifier invites primitive-agility bugs** — the JWT
   `alg:none` / HS256-vs-RS256 confusion class. Seven hardcoded verifiers cannot
   be tricked into using the wrong primitive; one that dispatches over an
   algorithm field can.
2. **Binding checks are mandatory and non-interchangeable.**
   `pat-signed-token.ts:196` returns `WRONG_IP`/`WRONG_CPI`/`WRONG_SESSION` as
   required steps. A generic verifier with an `opts.bindings?` parameter makes
   those **skippable by omission** — the highest-severity failure mode here.
3. **Three are wire-protocol-pinned.** Pulling `verify-cf-token` into a shared
   abstraction means an unrelated edit silently breaks CF-token verification in
   prod.

The safe extractions from this cluster are the _leaf utilities only_ — the
b64url codec and ct-compare of §9. Extract those; leave the seven verifiers
apart.

Related trap, same reasoning (§2C of the sweep): the `sha256 → hex → slice(0,16)`
shape appears in several places, but `sdk-attestation.ts:148`,
`pat-attest/issuer-directory.ts:128`, and `pat-attest/handler.ts:183` are
**protocol-pinned key/token-ID derivations** that must byte-match the SDK/issuer.
Only `network-id.shortHash`, `device-history`'s UA hash, and
`merchant-projection.hashPubkey` are true convenience hashes safe to share — and
even then, make the separator and length **required explicit parameters**, and
annotate the pinned sites "do not route through the shared helper."

---

## Suggested order of execution

1. **§3 zip-bomb bound** — security, one line per site, do today.
2. **§2 un-block Firehose** — one-line latency win (measure `IntegrityArchived`).
3. **§4 `iat` enforcement** — security; coordinate the `iat` unit with platform.
4. **§5–§9 mechanical de-dups** (~450 LOC) — safe, satisfying, low-risk; do §5
   before/with §3 so the inflate fix lands in one place.
5. **§10 dead code** — trivial; decide the middy-validator question.
6. **§1 probe-token sealed tokens** — biggest architectural win, but cross-repo;
   scope against `ms-argus-sigint` and run a dual-format rollout.
7. **§11 drain `merchant-projection.ts`** — largest effort, incremental, guarded
   by the existing 4.7k-line test.

**Net:** ~450 LOC deleted with zero behaviour change, two security bugs closed,
one latency bug closed, and a path to –2 hot-path round trips — with every
load-bearing DB read (credits debit, integrity write + its `attribute_not_exists`
idempotency gate, IP-velocity counters, STUN single-use, merchant read) left
exactly where it is, because none of those can be replaced by a signature.
