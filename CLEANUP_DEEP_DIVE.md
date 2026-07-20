# Argus Cleanup Deep Dive

**Baseline:** 2026-07-20
**Scope:** `ms-argus-api`, `ms-argus-web-integrity`, and `ms-argus-pair`
**Reference implementation:** `ms-poc-proxy-maker`
**Engineering standard:** `/home/justin/Dev/ARGUS_ENGINEERING_GUIDE.md`

This document replaces the point-in-time `SIMPLIFICATION_REVIEW.md`. It is a
living architecture and test-improvement plan. Update the baseline and item
status in the same pull request that completes a slice; do not leave completed
work described as current debt.

## Executive decision

Do not reorganize these repositories into web-framework MVC. Their runtime
shape is a better fit for ports, use cases, and adapters:

```text
transport adapter -> named application use case -> domain policy
                                      |          -> port interface
                                      |                 |
                                      |                 v
                                      +---------- infrastructure adapter
```

The transferable strengths from `ms-poc-proxy-maker` are:

- one visible use case per handler;
- tests colocated with the behavior they prove;
- a meaningful global and per-file unit-coverage floor;
- deployed contract suites separated from unit coverage;
- explicit dependency and dead-code gates.

Its exact architecture is not the target. Proxy Maker still has direct service
imports from handlers, a 1,122-line CDK construct, no dedicated local
integration layer, permissive TypeScript unused-symbol settings, no function
size gate, and 1.49% duplication. Argus should borrow the clear behavior/test
shape while keeping stronger domain ports and size ratchets.

## Measured baseline

The line and test counts below are a 2026-07-20 snapshot. Generated files are
excluded. Test-case counts are static `it(`/`test(` occurrences and are useful
for comparison, not billing-grade metrics. Coverage denominators differ by
repository; the percentages are not directly comparable without reading the
coverage include/exclude lists.

| Repository               | Production files / LOC | Test files / LOC | Test cases | Reported line coverage | Live/contract layer           | Main pressure                                                                         |
| ------------------------ | ---------------------: | ---------------: | ---------: | ---------------------: | ----------------------------- | ------------------------------------------------------------------------------------- |
| `ms-argus-api`           |           124 / 21,649 |      84 / 20,799 |      1,217 |                 93.26% | 1 service E2E                 | AWS orchestration excluded from coverage; browser-ingestion contract remains implicit |
| `ms-argus-web-integrity` |           111 / 21,980 |      54 / 10,673 |        702 |                 32.86% | 21 browser/adversarial specs  | no global coverage floor; permissive lint; many zero-covered collectors               |
| `ms-argus-pair`          |            91 / 13,555 |       46 / 3,510 |        167 |                 35.96% | 2 deployed E2E files          | 958-line Lambda function; no local integration suite; source-text assertions          |
| `ms-poc-proxy-maker`     |             52 / 9,650 |       52 / 8,472 |        414 |                 95.21% | 21 deployed contracts + 1 E2E | strong tests, but direct coupling and weak size/unused gates                          |

Current duplication reports:

- API: 282 duplicated production lines, 1.31%.
- Web Integrity: 328 duplicated lines across production and tests, 1.15%.
- Pair: 68 duplicated production lines, 0.43%.
- Proxy Maker: 197 duplicated lines across production and tests, 1.49%.

## Stakeholders and contract ownership

### Web Integrity -> API: integrity collection

`ms-argus-web-integrity` owns browser collection, signal provenance, the
versioned encrypted transport, and submission behavior. `ms-argus-api` owns
payload acceptance, proof redemption, validation, scoring, persistence, and
the public collect response.

The contract needing executable coverage includes:

- payload version and encrypted-body framing;
- `X-Argus-Cpi`, origin key, session token, and version headers;
- stable `identifiers.session_id` across worker/fallback submission;
- TCP, H2, CloudFront/TLS, PAT, STUN, and device-proof field shapes;
- positive response and fail-closed error classes.

Provider-owned schemas and fixtures belong in API. Browser tests should prove
that the SDK emits those fixtures, while a deployed contract test proves the
real SDK bundle can submit to `dev-jw`. Do not create a shared runtime package
that allows browser code to import server implementation details.

### API -> Pair: merchant projection

`ms-argus-api` owns the merchant projection schema, score semantics, freshness
metadata, and authentication contract. `ms-argus-pair` owns its local policy:
which projection combinations satisfy a desktop/phone/SSO proof.

The contract needing executable coverage includes:

- credential splitting and `/v1/session/{cpi}/{session_id}` request shape;
- required projection version/timestamps and score axes;
- optional identification/network/worker evidence;
- 401/402/404/409/5xx behavior;
- Pair fail-closed behavior for malformed, missing, stale, or partial responses.

Pair currently casts `res.json()` directly to `MerchantProjection`. Replace
that assertion with a tested boundary parser before changing more scoring or
SSO behavior.

### Web Integrity -> Pair: browser SDK surface

Pair consumes the loader's `run`, attestation, session ID, proof-of-life, and
error behavior. This public browser surface needs fixture-based unit contracts
and a small real-browser contract suite. Page components should not interpret
raw SDK transport errors independently; a browser application service should
map them to named Pair outcomes.

## Repository findings

### `ms-argus-api`

#### What is working

- The scoring/projection extraction has moved the repository toward named
  domain modules.
- Unit-test volume is strong, with 1,200+ cases and high coverage on the files
  currently included in the unit denominator.
- The service E2E runs both real Middy entry points, real ECDH framing, an
  in-memory DynamoDB adapter, persistence, debit, and projection.
- Production functions have strict complexity, depth, parameter, and 50-line
  gates outside CDK.
- Cleanup ratchets stop extracted files from silently regrowing.
- Knip now treats only deployable handler, CDK, and CLI roots as entry points;
  a dedicated architecture check prevents broad helper/type globs from hiding
  dead code again.

#### Code smells and test gaps

1. **The coverage percentage omits core orchestration.** Ingestion and
   session-get base handlers, middleware, SDK-backed loaders, and several
   infrastructure helpers are excluded. The reported 93.26% is real for the
   selected pure core, but not a repository-wide TDD score.
2. **The API application core still reaches global adapters.** The ingestion
   base handler constructs or closes over DynamoDB, datasets, Firehose,
   Secrets, Valkey, environment values, and the merchant resolver. The
   `createBaseHandler` dependency object only injects logger and metrics.
3. **Ratchets are ceilings at the exact current size.** They prevent growth but
   do not create a prioritized reduction queue. `base-handler.ts` is exactly
   480/480 and several extracted modules are exactly at their limit.
4. **Generic folders obscure ownership.** `helpers/` includes protocol,
   cryptography, persistence, projection, cache, environment, and transport
   concerns. New work should move by domain; a bulk folder rename would create
   churn without value.
5. **Twenty production clone groups remain.** The S3 dataset loaders and archive
   walkers are real shared mechanisms; analyzer evidence-shape similarities
   need domain review before abstraction.
6. **The cross-repo contracts are implicit TypeScript shapes.** The provider
   does not publish executable projection/ingestion fixtures for consumers.

### `ms-argus-web-integrity`

#### What is working

- It has the broadest real-browser/adversarial suite: Chromium, Firefox,
  WebKit, automation variants, proxies, mobile networks, and real API storage.
- Browser capability modules are mostly organized by signal domain.
- Dependency Cruiser reports no cycles or layer violations.
- Loader, iframe, worker, VM, and build-integrity paths have focused tests and
  smoke scripts.

#### Code smells and test gaps

1. **No global coverage floor exists.** Only four files have explicit
   thresholds. Current aggregate coverage is 32.86% lines / 25.02% functions /
   27.98% branches.
2. **Important modules report zero unit coverage.** These include navigator,
   headless, worker, status, engine, audio, canvas, WebRTC, screen, fonts, and
   several VM/iframe entry paths. Some require real-browser testing, but pure
   normalization and decision logic inside them should not hide behind that.
3. **Lint is intentionally permissive.** Unused symbols, explicit `any`, empty
   blocks, unsafe comments, and several correctness rules are disabled across
   all `src`. There are no file/function size or complexity gates.
4. **Mega-files mix browser adapters and decisions.** `utils/sigint.ts` (848),
   `navigator/index.ts` (802), `vm/bridge.ts` (774), `loader/index.ts` (712),
   and `headless/index.ts` (687) need seams around protocol, normalization,
   collection, and orchestration—not arbitrary 300-line cuts.
5. **Unit and browser E2E exist, but the contract middle is thin.** There is no
   named transport-contract suite proving the serialized SDK request against
   API-owned fixtures without live AWS.
6. **Quality is not a pre-push requirement.** The hook runs coverage and
   duplication but not lint, dependency, or dead-code gates.

### `ms-argus-pair`

#### What is working

- Pair has the strongest lint/boundary/duplication ratchets of the three Argus
  repos for new code.
- Pure proof, attestation, scoring, claim, and token helpers have focused unit
  tests.
- A deployed-infrastructure E2E exists and the repository documents the desired
  `createPairApi({ ...ports })` integration-test shape.
- The cleanup loop requires branch, focused tests, deploy, live E2E, and
  trust-boundary regression evidence.

#### Code smells and test gaps

1. **The main Lambda is still one 958-line function.** `pair-api.ts` multiplexes
   session, attestation, OAuth, SSO, raffle, proof, claim, projection, storage,
   and response behavior. Extracted helpers reduce local detail but the route
   state machine remains coupled to module-global AWS/Valkey/config adapters.
2. **The three worst production files are fully exempt from size/complexity
   lint.** `pair-api.ts`, `src/lib/pair.ts`, and `phone-main.tsx` can regress
   internally as long as the separate line-count ratchet is not crossed.
3. **There is no local integration suite.** The repository guidance names
   `tests/integration/**/*.integration.ts`, but that directory has zero tests.
4. **The coverage floor is a legacy baseline.** 33.47% lines leaves the main
   Lambda at 0%, WS at 9%, Pair pages at 0%, and large browser workflows mostly
   uncovered.
5. **Many hygiene tests assert source text.** These are useful build/wiring
   tripwires, but they are not substitutes for behavior tests and make safe
   refactors expensive.
6. **The browser application service is another state-machine god-file.**
   `src/lib/pair.ts` has a 429-line `startDesktopSession` and mixes loader
   discovery, fetch, timers, WebSocket coordination, proof UX, SSO, passkeys,
   and error mapping.
7. **The API projection boundary trusts JSON by assertion.** A malformed or
   drifted API response is cast to `MerchantProjection` rather than parsed into
   a named failure.

### `ms-poc-proxy-maker` as a reference

Use these patterns:

- route/use-case named files;
- behavior-first unit tests through the public handler;
- 85% aggregate and 75% per-file unit coverage;
- `contracts/` tests against deployed infrastructure, separate from unit
  coverage and E2E;
- test cleanup state owned by a reusable context;
- API contract descriptions close to executable contract tests.

Do not copy these patterns:

- importing concrete service modules directly into every handler;
- relying on module mocks as the only dependency seam;
- treating every handler as a `knip` entry point;
- leaving TypeScript unused-symbol checks disabled;
- omitting function/file complexity gates;
- placing 1,000+ lines of generated/static-site content in a construct.

## Target architecture

### API

```text
handlers/<transport>.ts
  -> application/<use-case>.ts
       -> domain scoring/projection/proof modules
       -> ports/*.ts
  -> adapters/aws|network|cache/*.ts
contracts/
  -> provider-owned schemas and positive/negative fixtures
tests/integration/
  -> application use cases with in-memory ports and fake clocks
tests/contracts/
  -> deployed public API contract
```

Do not move every existing helper at once. New/extracted code should enter the
target folders; old paths disappear one narrow slice at a time.

### Pair

```text
HTTP route adapter
  -> pair application core
       -> session/proof/SSO state transitions
       -> ports: sessionStore, projectionStore, claimLedger,
                 passkeyStore, tokenStore, clock, wsPublisher
  -> DDB/Valkey/HTTP/Secrets adapters

React page
  -> browser application service/state machine
       -> ports: argusSdk, pairApi, websocket, clock, credentialStore
```

The route router should select a small use case. It should not contain the use
case. Integration tests should describe named states and use fake ports.

### Web Integrity

```text
browser adapters (DOM/Web APIs)
  -> signal-domain collectors
       -> pure normalization/decision modules
  -> collection orchestrator
  -> versioned transport encoder/submission adapter
contracts/
  -> SDK public API and API submission fixtures
```

Browser-only observation stays in Playwright. Pure field normalization,
fallback selection, error classification, and transport construction belong in
unit tests with injected capabilities.

## Execution plan

Each slice follows: document test plan -> red unit/integration/gate -> minimal
implementation -> focused tests -> repository quality -> live contract/E2E when
the process boundary changes -> tighten ratchet.

### Slice 0: make the API architecture gate truthful — complete 2026-07-20

Need: `knip` must identify unused internal helpers rather than declaring the
entire helper/type trees public.

- Narrow API entry points to actual Lambda/CDK/application entry points.
- Run the gate and capture the expected failure.
- Delete genuine dead files/exports or document the exact dynamic entry.
- Keep tests green and add a regression check for the entry-point policy if
  configuration alone is too easy to widen.

No deploy is required: this changes development gates and dead code only.

Evidence:

- the tightened gate failed first on two orphan files and six unused exports;
- deleted the orphan bucket-key and warmup helpers, an unused JSON schema, two
  test-only validators, and their obsolete tests;
- made four implementation-only symbols private and removed two unused ECDH
  cache/handshake exports;
- added `test:architecture` to quality and pre-push, plus a 466-line payload
  schema ratchet;
- build, quality, 1,260 unit tests, 6 service E2E tests, coverage, and format
  check pass. No runtime path changed, so no deployment was performed.

### Slice 1: executable API -> Pair projection contract — complete 2026-07-20

Need: Pair must reject malformed, stale, or incompatible merchant responses
before they influence proof policy.

- API owns a versioned projection contract and positive fixture; Pair owns the
  negative compatibility cases it must fail closed on.
- Pair adds a pure boundary parser and tests every required/optional field.
- Pair's projection client returns a tagged result, not `null` for every error.
- Add a deployed contract test against `dev-jw` for success, auth failure,
  missing session, and exhausted credit without hiding unit branches in E2E.

Delivered:

- API adds `schema_version: 1`, owns a checked v1 fixture, and documents the
  additive-versus-breaking compatibility rule.
- Pair now separates a pure 91-line wire parser from a dependency-injectable
  125-line HTTP adapter. Unknown versions, malformed nested fields, missing
  timestamps, invalid scores, bad JSON, network failures, and HTTP
  401/402/404/409/5xx responses fail closed with named results.
- Pair policy types now describe the browser/network fields they actually use;
  transport and validation no longer hide behind `res.json() as ...`.
- New file ratchets keep the parser, client, and policy separated.
- The deployed Pair suite now creates an isolated two-credit merchant and scan,
  then proves invalid auth (401), a versioned successful projection (200), a
  billable missing session (404), and real credit exhaustion (402).
- API quality, 1,260 unit tests, 6 service E2E tests, and 93.26% selected-file
  coverage pass. Pair quality/hygiene, build, 208 unit/integration tests, 9
  deployed E2E tests, and 36.64% repository coverage pass.
- API and Pair reached `UPDATE_COMPLETE` in `dev-jw`. A live merchant lookup
  returned 200 with schema v1, and all three Pair deployed suites pass. The
  API stack owns a non-production gateway identity so routine runs do not wait
  for new API-key propagation; signed tokens, merchants, credits, CPIs, and
  scans remain per-run fixtures and are removed in teardown.

### Slice 2: first Pair application-core route — complete 2026-07-20

Need: prove the Pair state machine without AWS or browser infrastructure.

- Work from current `main` after the QR-warmup branch is resolved, in a separate
  clean worktree if necessary.
- Define the smallest ports needed by `/api/session/start`.
- Write integration tests for success, rate-limit rejection, store failure,
  entropy/expiry, and duplicate/replay behavior.
- Extract only that route from `lambdaHandler`; keep the HTTP adapter thin.
- Lower `pair-api.ts` and function-size ratchets.

Delivered:

- Added the first `tests/integration` suite with eight request-level cases for
  scoped success, rate denial, limiter failure-open telemetry, validation,
  storage rejection, collision, expiry/entropy inputs, and role-bound token
  minting.
- Extracted `POST /api/session/start` into a 116-line application use case with
  explicit rate-limit, persistence, entropy, clock, token, configuration, and
  logging ports. The Lambda switch now adapts HTTP input/output in three lines.
- Reduced `pair-api.ts` from 1,380 to 1,335 lines and ratcheted the handler,
  application use case, and persistence adapter at their new sizes.
- Replaced the challenge-binding source assertion with the new module location;
  the behavior is now also covered by the integration test instead of only
  source text.
- Pair build, quality, hygiene, 208 tests, and 36.64% coverage pass. The Pair
  stack reached `UPDATE_COMPLETE`, and all 9 deployed E2E cases pass against
  `dev-jw`, including session creation and stolen-token rejection.

Then repeat route-by-route for desktop attestation, phone attestation, SSO
challenge/return, and claim redemption. Do not build an all-purpose framework
first.

### Slice 3: Web Integrity -> API transport contract — complete 2026-07-20

The SDK and API now agree locally before a deployed browser test:

- API owns a v3-only transport manifest covering required headers, content
  type, current encryption, and fail-closed negative mutations. Missing,
  retired v1/v2, and unknown versions return 400.
- Eight provider contract cases generate real ECDH/AES-GCM ciphertext, replay
  v3 through the ingestion middleware, and prove the negative envelope cases.
  The v1 XOR/deploy-secret and v2 deflate decoders and their infrastructure
  wiring are deleted rather than retained as dormant compatibility branches.
- Web Integrity consumes a byte-identical test fixture through the extracted
  58-line `buildIntegrityCollectRequest` module. Its five tests cover the
  current emitted version, required/optional headers, missing bindings, and
  exact `Uint8Array` view copying; the module has 100% line/branch/function
  coverage.
- `vm/bridge.ts` delegates only the encrypted request envelope. Serialization,
  scrambling, and encryption remain in the existing VM/pristine-reference
  path, preserving the CASTLE-TO-ARGUS serialization-chokepoint defenses.
- API build, 1,270 unit/contract tests, six service E2E cases, and all quality
  gates pass. Web Integrity's 746 tests, quality gates, production build, and
  cleanup ratchets pass.
- Both `dev-jw` stacks reached `UPDATE_COMPLETE`. A Chromium run loaded the
  deployed SDK, submitted through the deployed API, returned a session ID, and
  verified the persisted record in DynamoDB. Deployed missing, v1, v2, and
  version-99 requests returned the contracted 400 error.

The v3-only contraction removed 107 production API lines and 210 lines from
the measured cross-repository transport surface after adding explicit negative
contract cases. The smaller validator, middleware, and decrypt helper are now
cleanup-ratcheted. The `/v1/integrity-collect` route name remains the current
endpoint namespace; it is not legacy wire-version support.

The broad browser/adversarial suite remains runtime evidence rather than being
duplicated in the small contract suite.

### Slice 4: coverage truth and ratchets

Progress: Web Integrity now enforces the measured global baseline (33%
statements, 28% branches, 25% functions, 33% lines) without changing the
coverage denominator, plus 100% per-file floors for the extracted transport
builder. The broader application-handler work below remains.

- API: progressively include application handlers/loaders currently excluded;
  add integration tests through injected ports before raising the denominator.
- Pair: add per-file floors for newly extracted core modules; raise the global
  floor after every route extraction.
- Web Integrity: establish a global floor at the verified current baseline,
  then add per-file floors to extracted pure modules. Do not demand happy-dom
  coverage for browser-only observations.
- All three: report coverage include/exclude changes in PR notes; never raise a
  percentage by shrinking the denominator silently.

### Slice 5: Web Integrity workflow seams

Start with transport/fallback behavior, not signal novelty:

Progress 2026-07-20: submission outcome handling is now an injected 79-line
client with 11 tests and 100% statements/branches/functions/lines. It owns HTTP
status classification, response validation, thrown fetch/malformed JSON
handling, and bounded best-effort cache forwarding. `vm/bridge.ts` is reduced
from 766 to 724 lines and only adapts VM arguments/callbacks. The stricter
ratchets, production build, `dev-jw` deployment, and persisted-record Chromium
smoke all pass.

- extract submission error classification and worker/fallback continuity from
  `vm/bridge.ts` (submission complete; fallback continuity remains);
- extract probe orchestration and token/result normalization from
  `utils/sigint.ts`;
- split loader lifecycle from public API parsing in `loader/index.ts`;
- add function/file ratchets and turn unused-symbol checks on for new modules.

Every extraction keeps byte/build behavior and is checked with unit, build,
real-browser, and bundle-size evidence as appropriate.

### Slice 6: mechanical duplication and remaining mega-files

Only after behavior seams are covered:

- API S3 dataset loader and archive walker;
- API payload contracts versus validation/dead declarations;
- Pair browser workflow and route-by-route source-text test replacement;
- Web VM and collector duplication where byte/runtime behavior permits;
- Proxy Maker reference improvements are out of this scope and should not be
  mixed into Argus cleanup branches.

## Cross-repository completion rules

A slice is done only when:

- the smallest behavior test failed first when practical;
- trust-boundary negatives are explicit;
- local unit/integration gates pass;
- size, coverage, dependency, dead-code, or duplication ratchets improve or stay
  flat for a documented reason;
- provider and consumer contract tests agree;
- runtime changes deploy to `dev-jw` and the relevant real-browser/API contract
  passes;
- docs describe the resulting architecture, not the architecture before the
  change.

## Deferred security projects

Two findings from the deleted review remain real but are not three-repository
cleanup slices:

- Replacing TCP/H2 probe-token DynamoDB reads requires coordinated changes in
  `ms-argus-sigint`, dual-format rollout, and live redemption metrics.
- Merchant-token expiry requires `ms-argus-platform` issuance/renewal design.
  The platform currently mints a long-lived credential with `iat` only; adding
  an API-only 24-hour rejection would break every existing merchant.

Track those as explicit cross-repository security projects, not opportunistic
refactors inside this cleanup sequence.
