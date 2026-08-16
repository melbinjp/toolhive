# Handover: RFC 7523 §2.1 JWT-bearer grant + trust declarations + self-issued client-assertion auth

You have a fresh context. Read this whole document before writing any code. It
supersedes any instinct to re-derive the design — the decisions below were
already made and reviewed; your job is to build and verify them, not
relitigate them.

## Where you are

This worktree is branch `6336-6337-jwt-bearer-grant`, stacked on
`6322-actor-matcher` (tip `3d4e63cd3`). That parent branch already ships:
RFC 8693 token exchange, `actor_token`/`act` claim delegation, `AllowMayAct`,
`ActorMatcher` (CEL), all exposed through the `TrustedIssuerConfig` CRD field
on `MCPExternalAuthConfig`, all verified through real kind e2e tests (see
`test/e2e/thv-operator/virtualmcp/virtualmcp_trusted_issuer_actormatcher_test.go`
and `..._mayact_test.go` for the pattern to copy).

This branch adds three new, related capabilities on top of that. They map to
GitHub issues #6336 and #6337, plus a third capability that has no issue
number yet (file one when this lands — draft text can wait until the code
exists and is proven).

## The three capabilities, in the order to build them

**Do not reorder these.** Hardening (item 3 below) comes last, deliberately —
there is no point hardening a mechanism that hasn't been proven to work yet.

### 1. RFC 7523 §2.1 JWT-bearer grant (#6336 core)

A new fosite `TokenEndpointHandler` for
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, handling a *plain,
unbound* assertion — no client authentication required (per §2.1, not §2.2).
This is the "possession of a valid, trusted-issuer-signed JWT is enough"
grant, distinct from RFC 8693 token exchange.

Concretely:
- New handler in `pkg/authserver/server/tokenexchange/` (or a sibling
  package if you find the file getting unwieldy — your call, small diff
  either way).
- `CanHandleTokenEndpointRequest` keys off the JWT-bearer grant type.
- `CanSkipClientAuth` returns `true` for this grant (no confidential client
  needed — that's the point of §2.1 vs §2.2).
- Assertion validation: `iss`/`sub`/`aud`/`exp`/signature, reusing the
  existing JWKS-fetching machinery already used for token exchange
  (`multi_issuer_validator.go` — do not reimplement JWKS fetching).
- Wire it into the fosite compose pipeline alongside the existing handlers.

**IMPORTANT — read this before writing the handler:** do NOT assume this is
the only handler that will ever key off `GrantTypeJWTBearer`. A parallel,
currently-parked branch (`xaa-spike-1`, not merged, not being worked on right
now) implements ID-JAG, which is a *bound* variant of the same grant type
and requires a *confidential* client. Its own handover doc
(`.worktrees/xaa-spike-1/HANDOVER.md` if that worktree still exists, or ask
the user) explains why: fosite's `access_request_handler.go` evaluates
`CanSkipClientAuth` per-handler and fails closed on the first handler that
can't skip it — so if a second, bound-requiring handler were later
registered for the same grant type, it would silently break this one. You
don't need to build for that now (xaa-spike-1 is explicitly sequenced to
land *after* this work, not concurrently), but do NOT hardcode an assumption
that "JWT-bearer grant" implies "no client auth" anywhere except inside this
one handler's own logic — keep the discrimination local, e.g. by checking
the JOSE `typ` header the way `idJAGGrantHandler` already does in that
branch, so a future merge is additive, not a rewrite. A one-line comment
noting this is enough; do not build actual `typ`-dispatch machinery now,
that would be over-building for a merge that isn't happening yet.

**Verify with:** unit tests for the handler (valid assertion → token; bad
signature, wrong audience, expired, wrong issuer → rejected). No CRD/e2e
needed yet — that comes with item 2, once there's a way to configure which
issuers are allowed to use this grant.

### 2. Minimal trust declaration + issuance (#6336 acceptance criteria + #6337 core)

#6336's own stated acceptance criteria already requires three things that
are nominally "#6337's job" — don't skip them waiting for a separate pass:

- **A minimal `TrustedIssuer.Grant` field** (or similarly named — your
  call) marking an issuer as JWT-bearer-enabled. Nil/absent = disabled.
  Follow the existing pattern: this is analogous to how `AllowMayAct` gates
  `may_act` handling — enablement lives on the `TrustedIssuer`/
  `TrustedIssuerConfig` struct pair (Go type in
  `pkg/authserver/server/tokenexchange/multi_issuer_validator.go`, CRD
  mirror in `cmd/thv-operator/api/v1beta1/mcpexternalauthconfig_types.go`,
  converter in `cmd/thv-operator/pkg/controllerutil/authserver.go`).
- **`(iss, sub)` → resource/audience ceiling.** The grant must not let an
  assertion for subject X claim a broader resource/audience than what's
  configured for that specific issuer+subject pairing. Keep this as a flat
  allowlist for this pass (e.g. `AllowedResources []string` on the grant
  config) — do NOT build CEL-based claim mapping now, that's explicitly
  deferred to the hardening pass (item 3) if it turns out to be needed at
  all.
- **Max assertion age** — reject assertions whose `iat`/`exp` spread
  exceeds a configured ceiling, independent of the JWT's own `exp`.
- **`jti` replay tracking** — a `jti`-seen store, checked before issuance.
  Build a small interface (`Seen(ctx, issuer, jti string) (bool, error)`,
  `Mark(ctx, issuer, jti string, ttl time.Duration) error`) with an
  in-memory implementation (map + mutex + TTL sweep, or reuse whatever
  ephemeral-cache pattern already exists in the codebase — check
  `pkg/authserver/storage` first per the ladder: reuse before you write).
  A Redis-backed implementation is in scope for THIS pass if it's a small
  addition on top of the interface — check whether `pkg/authserver/storage`
  already has a Redis client wired up before building a new one from
  scratch.
- **Token issuance** — mint the actual access token via the existing fosite
  token-issuance path. Decide what the `client_id` claim on the issued
  token should contain (there is no real OAuth client involved in a plain
  §2.1 grant) — the reviewed direction was to derive an identifier from the
  trusted issuer + subject, not to fabricate a fake client. Document
  whatever you land on in a short comment; this is a real open call, use
  your judgement and note it for review.
- **CRD exposure** — nested field on `TrustedIssuerConfig`, converter
  wiring, `task operator-generate` to regenerate manifests/CRDs.

**Verify with:** Go integration tests (real HTTP round trip against the
compose pipeline, not just unit tests of the validator) AND real kind e2e —
copy the pattern from `virtualmcp_trusted_issuer_mayact_test.go` /
`_actormatcher_test.go`: deploy the parameterized OIDC test server
(`test/e2e/thv-operator/testutil/oidc.go` — already supports arbitrary extra
claims via `extra_claim_name`/`extra_claim_value`, extend it further only if
you actually need a claim shape it doesn't support), configure a
`TrustedIssuerConfig` with the new grant field through the CRD, hit the
token endpoint through the real proxy, assert on success/rejection. This is
the epic's standing rule — no capability ships without a real kind cluster
proving the CRD-exposed path, not just RunConfig.

Expect at least one real bug to surface here that unit tests didn't catch —
that's been the pattern for every single piece of this epic so far
(`insecureAllowHTTP`/`allowPrivateIPs` missing on the mayAct test being the
most recent example). Don't be surprised by it, don't treat it as scope
creep, just fix it.

*Checkpoint: commit here.* This satisfies #6336's stated acceptance
criteria in full. It's a reasonable point to stop, run `task lint-fix`,
and let the user review before continuing.

### 3. Self-issued ToolHive token as `client_assertion` (new capability, no issue yet)

This is the rescoped design from earlier in this epic's design discussion
(NOT the original, flawed draft that tried to use an Entra
`client_credentials` token directly as a `client_assertion` — that fails
RFC 7523 §2.2's `sub == client_id` + short-lived-per-request-`jti`
requirement, confirmed via oauth-expert review). The corrected design:

- A confidential MCP client mints itself a token via the item-1/item-2 grant
  above (a self-issued ToolHive token, `sub == client_id`, short-lived).
- That token is then presented as the `client_assertion` on a *separate*
  OAuth request (e.g. a subsequent RFC 8693 token exchange call) to
  authenticate the client per RFC 7523 §2.2.
- Build: a new `ClientAuthenticationStrategy` (fosite's client-auth
  extension point — check how the existing client-secret/JWKS-based
  strategies are wired in this codebase before adding a new one) that
  accepts this self-issued token as a valid `client_assertion`, checks
  `sub == client_id` (per §2.2, MUST), checks the token hasn't expired,
  and checks it wasn't already consumed if you're tracking one-time-use
  (reuse the `jti` store from item 2 if it fits — don't build a second one
  just because the call site is different).
- Explicitly reject wildcard/pattern-derived client IDs here — a
  self-issued token must assert a specific, singular client identity, not
  a class of clients. (This was flagged during design review as an easy
  way to accidentally widen the trust boundary — don't skip the check.)

**Verify with:** unit + integration tests for the new strategy, then kind
e2e chaining the full path: item-1/2's grant issues the token → that token
authenticates a subsequent request via this strategy → the subsequent
request succeeds. This is also the point where writing the actual demo
script (mentioned elsewhere in this epic's planning, not part of this
handover) becomes possible for the first time — the self-issued-token path
is the missing link the demo needs.

*Checkpoint: commit here, separately from item 2's commit.*

### Explicitly NOT in scope for this pass

Do not build these now — they were deliberately deferred to a later
hardening pass, precisely because hardening a mechanism nobody has proven
yet is wasted work:

- First-seen-subject rate limiting/caps.
- Revocation-latency documentation or tooling.
- CEL-based (vs. flat-allowlist) claim/resource mapping for the grant.
- Any operator-facing toggle that lets someone disable `jti` replay
  tracking on an unbound assertion — this must never become configurable,
  it's structurally required for an unbound grant (see the xaa-spike-1
  handover for why: a bound ID-JAG assertion can safely skip replay
  tracking because client-binding does that job instead; this grant has no
  such binding, so `jti` tracking is not optional here).

If you get partway through item 1 or 2 and think of a hardening item not
listed above, note it in a comment or a running list at the bottom of this
file — do not build it, and do not skip ahead to it.

## Process rules for whoever (whatever) builds this

- Small, individually-reviewable commits, matching how every other piece of
  this epic has landed (see `git log --oneline` on `6322-actor-matcher` for
  the granularity to match — lint fixes, stale-test fixes, and feature
  commits are separate).
- Run `task lint-fix` and `task test` before each commit, not just at the
  end.
- Real kind e2e is mandatory per capability, not optional, not deferred to
  "later." A cluster named `toolhive` should already exist
  (`kind get clusters` to check); if not, `kind create cluster --name
  toolhive` and `kind get kubeconfig --name toolhive > kconfig.yaml`, then
  the usual `task operator-generate` / `task operator-manifests` /
  `task operator-deploy-local` / `task operator-install-crds` /
  `ko build --local` + `kind load docker-image` cycle used throughout this
  epic.
- Stop after item 2's checkpoint and after item 3's checkpoint for human
  review — do not barrel through all three items and present a single
  giant diff at the end.
- If you hit a design fork not resolved above (e.g. exact shape of the
  `client_id` claim, Redis vs. memory-only `jti` store), make the call,
  document it in a comment, and flag it clearly in your final summary —
  don't block waiting for an answer, but don't hide the decision either.
