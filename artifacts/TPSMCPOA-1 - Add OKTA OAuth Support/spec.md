# Spec: Pluggable Identity Provider Support for the TPS Report MCP Server

**Jira key:** TPSMCPOA-1
**Status:** Draft — for originator review
**Input:** [`intent.md`](./intent.md) (same directory)

> Note on naming: the design-stage prompt that produced this document assumed
> a path of `intent/TPS-1-okta-auth-support/spec.md` and a Jira key of
> `TPS-1`. Neither exists in this repo — the actual intent lives at
> `intent/TPSMCPOA-1 - Add OKTA OAuth Support/intent.md` with key
> `TPSMCPOA-1`. This spec uses the real key and sits next to the real intent
> file. Flagging this rather than silently reconciling it, per the intent
> file's own instruction to surface conflicts instead of resolving them
> quietly.

## 0. Decision already made

Before drafting, one architecture question was put to the originator: where
Okta is spec-compliant and Entra isn't (RFC 8414 discovery, RFC 8707
`resource` param, DCR), should the Okta path behave idiomatically (use
Okta's real capabilities) or deliberately mirror Entra's workarounds for
symmetry?

**Decision: idiomatic per provider.** Each provider implementation does
what's natural for that provider. The MCP client still sees one consistent
proxy surface on the TPS server (same routes regardless of active provider),
but what happens behind that surface is provider-specific and documented
below, not forced into a shared shape calibrated to Entra's limitations.

## 1. Where Entra is currently hardwired

Read in full before drafting this spec: [`src/auth.ts`](../../src/auth.ts),
[`src/oauthProxy.ts`](../../src/oauthProxy.ts), [`src/index.ts`](../../src/index.ts),
and [`glossary.html`](../../glossary.html) / `oauth-field-notes.pdf` (same
content, the field notes assembled during the original Entra integration).

Entra-specific code, today:

| Location | What's hardwired |
|---|---|
| `auth.ts:10-16` | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_REQUIRED_SCOPE` read directly from env; throws at module load if tenant/client ID missing. |
| `auth.ts:22-26` | Accepted audiences hardcoded to `[CLIENT_ID, api://{CLIENT_ID}]`; accepted issuers hardcoded to `[login.microsoftonline.com/{tenant}/v2.0, sts.windows.net/{tenant}/]`. |
| `auth.ts:28-32` | JWKS URI hardcoded to Entra's discovery path (`/discovery/v2.0/keys`). |
| `auth.ts:93` | Scope claim read as `decoded.scp` and split on a space — assumes a space-delimited string. |
| `auth.ts:109-122` | `protectedResourceMetadata` hardcodes `resource: api://{CLIENT_ID}` (not the server's own URL) and `authorization_servers: [Entra's v2 issuer]`. |
| `oauthProxy.ts:12-13` | Entra's real authorize/token URLs hardcoded. |
| `oauthProxy.ts:22-38` | `proxyAuthorize` unconditionally deletes `resource` from the query string and backfills `scope` if absent, both because Entra rejects/requires them respectively. |
| `oauthProxy.ts:40-73` | `proxyToken` does the same `resource`-strip / `scope`-backfill on the token exchange body, then forwards verbatim to Entra's token endpoint. |
| `oauthProxy.ts:79-91` | `authorizationServerMetadata` is entirely self-hosted, hardcoded content — because Entra publishes no RFC 8414 document to draw from. |
| `index.ts:7-8, 63` | Imports `requireEntraAuth`, `protectedResourceMetadata`, `authorizationServerMetadata`, `proxyAuthorize`, `proxyToken` by their Entra-specific names and wires them directly into routes. |

Every one of these traces to a documented Entra quirk in the glossary
(AADSTS9010010 → `resource` rejection; AADSTS900144 → scope backfill; no
RFC 8414 endpoint; dual v1/v2 issuer; dual audience forms; no DCR). None of
it is generic OAuth — it's all Entra accommodation, confirming the intent's
"Problem" statement precisely.

## 2. Provider abstraction

Minimum surface for exactly two providers, per the intent's explicit
exclusion of a general-purpose abstraction. Five operations, matching the
five things `index.ts` currently imports by Entra-specific name:

```
interface IdentityProvider {
  readonly name: "entra" | "okta";

  protectedResourceMetadata(serverBaseUrl: string): ProtectedResourceMetadata;

  authorizationServerMetadata(serverBaseUrl: string): Promise<AuthorizationServerMetadata>;

  buildAuthorizeRedirectUrl(clientQuery: URLSearchParams): string;

  exchangeToken(clientBody: URLSearchParams): Promise<{
    status: number;
    contentType: string;
    body: string;
  }>;

  verifyAccessToken(bearerToken: string): Promise<{ subject: string; scopes: string[] }>;
}
```

- `protectedResourceMetadata` / `authorizationServerMetadata`: produce the
  RFC 9728 / RFC 8414 JSON bodies served at the two `.well-known` routes.
  Both take the TPS server's own base URL because both metadata documents
  must always point authorize/token endpoints back at *this* server's proxy
  routes (`/authorize`, `/token`), regardless of provider — the MCP client's
  redirect URI and connector config must not need to change when the
  provider switches. That much is shared and constant across providers; it
  is not a divergence, it's the reason a proxy exists at all.
- `buildAuthorizeRedirectUrl`: takes the client's incoming `/authorize`
  query, returns the full URL to 302 the browser to. Each provider decides
  what to strip, backfill, or pass through.
- `exchangeToken`: takes the client's incoming `/token` body, performs the
  real POST to the provider's token endpoint, returns the raw response for
  `index.ts` to relay. Kept as a passthrough of status/content-type/body
  (as `oauthProxy.ts` does today) rather than a parsed shape, since the spec
  does not require the proxy to understand token response internals — only
  to relay them.
- `verifyAccessToken`: performs JWKS-based signature verification, then
  issuer/audience/scope checks, returning normalized claims. This is where
  the `scp`-shape divergence (string vs. array, see §4) gets absorbed —
  callers never see the raw claim shape, only a normalized `scopes: string[]`.

Route wiring in `index.ts` becomes generic: it holds one `provider:
IdentityProvider` instance, selected at startup, and calls these five
methods instead of importing Entra-named functions.

## 3. Configuration

```
IDENTITY_PROVIDER=entra|okta      # required, no default

# required when IDENTITY_PROVIDER=entra
ENTRA_TENANT_ID=
ENTRA_CLIENT_ID=
ENTRA_REQUIRED_SCOPE=access_as_user   # optional, this default preserved

# required when IDENTITY_PROVIDER=okta
OKTA_DOMAIN=                # e.g. dev-12345.okta.com — no scheme, no path
OKTA_AUTH_SERVER_ID=        # custom authorization server ID (see §7, open question)
OKTA_CLIENT_ID=
OKTA_AUDIENCE=              # the audience value configured on that auth server
OKTA_REQUIRED_SCOPE=access_as_user   # optional, same default as Entra for parity

# unchanged, provider-agnostic
PORT=5150
PUBLIC_URL=
```

**Fail-fast behavior**, resolved once at startup before the HTTP listener
starts (replacing the current pattern of scattered `throw new Error(...)`
checks at module load in both `auth.ts` and `oauthProxy.ts`):

1. `IDENTITY_PROVIDER` unset, or not exactly `entra` or `okta` → throw
   immediately: `Configuration error: IDENTITY_PROVIDER must be "entra" or
   "okta" (got: ${value ?? "unset"})`.
2. Once the provider is known, check that provider's required variables are
   all present. On any missing, throw naming every missing variable in one
   message: `Configuration error: IDENTITY_PROVIDER=okta requires
   OKTA_DOMAIN, OKTA_AUTH_SERVER_ID, OKTA_CLIENT_ID, OKTA_AUDIENCE. Missing:
   OKTA_AUDIENCE.` — one error, not one exception per missing var, so a
   misconfigured deploy shows the whole problem at once.
3. The inactive provider's variables are never required. Setting
   `IDENTITY_PROVIDER=entra` with `OKTA_*` vars unset is valid; a leftover
   `OKTA_*` block from a prior run is ignored, not validated.
4. No partial startup: the process must not begin listening on `PORT` if
   validation fails. Same as today's behavior (the `throw` at module load
   prevents `app.listen` from ever being reached) — this spec keeps that
   guarantee, just centralizes where it happens.

## 4. Divergence between Entra ID and Okta

This is the substance of the design. Six concrete points of divergence,
each with where it's reconciled.

### 4.1 Discovery metadata (RFC 8414)

- **Entra**: publishes no RFC 8414 document. `authorizationServerMetadata`
  stays fully self-hosted/hardcoded, as it is today — `issuer`, `jwks_uri`,
  `response_types_supported`, etc. are all literal values in the provider
  module, with only `authorization_endpoint`/`token_endpoint` computed from
  `serverBaseUrl`.
- **Okta**: publishes a real document at
  `https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER_ID}/.well-known/oauth-authorization-server`.
  Idiomatic treatment: the Okta provider fetches that document and returns
  it with only `authorization_endpoint` and `token_endpoint` rewritten to
  point at this server's own `/authorize` and `/token`. Every other field
  (`issuer`, `jwks_uri`, `scopes_supported`, `code_challenge_methods_supported`,
  `token_endpoint_auth_methods_supported`, etc.) is Okta's own, live,
  correct data — not re-typed by hand and liable to drift from what Okta
  actually enforces.
- **Reconciled**: inside each provider implementation. The interface just
  demands *a* valid RFC 8414 document with endpoints pointed here; how each
  provider assembles it is private to that provider.

### 4.2 Resource indicators (RFC 8707)

- **Entra**: rejects the `resource` parameter outright on both `/authorize`
  and `/token` (AADSTS9010010), matching or not. `buildAuthorizeRedirectUrl`
  and `exchangeToken` must delete it, exactly as `oauthProxy.ts` does today.
- **Okta**: supports RFC 8707 on a Custom Authorization Server. Idiomatic
  treatment: pass `resource` through unmodified rather than stripping it.
  This has a real payoff — it means `protectedResourceMetadata.resource`
  for Okta can honestly be this server's own public URL (what RFC 9728
  intends), rather than the Entra workaround value `api://{CLIENT_ID}` that
  exists only because Entra can't be pointed at an arbitrary resource URL.
- **Reconciled**: inside each provider implementation's
  `buildAuthorizeRedirectUrl`/`exchangeToken`/`protectedResourceMetadata`.
  Not surfaced to the caller — `index.ts` doesn't know or care which
  provider strips or forwards `resource`.

### 4.3 Scope backfill on `/authorize` and `/token`

- **Entra**: requires `scope` explicitly on both legs (AADSTS900144 if
  missing on `/token`), even though plain OAuth2 treats it as optional at
  token-exchange time. Backfilled as `api://{CLIENT_ID}/{REQUIRED_SCOPE}` —
  a value namespaced under Entra's App ID URI.
- **Okta**: a Custom Authorization Server also won't grant a custom scope
  it wasn't explicitly asked for, so the same backfill *behavior* is needed
  — but the *value* differs. Okta scopes on a custom authorization server
  are plain names (e.g. `access_as_user`), not namespaced under an App ID
  URI the way Entra's are. Backfilled as `OKTA_REQUIRED_SCOPE` verbatim, no
  prefix.
- **Reconciled**: inside each provider's `buildAuthorizeRedirectUrl` /
  `exchangeToken`. Same *shape* of fix (backfill if absent), different
  literal value — this is exactly the kind of seam the intent's "Known
  risks" section expects to surface, not paper over.

### 4.4 Audience (`aud`) claim

- **Entra**: two accepted forms — bare `CLIENT_ID` or `api://{CLIENT_ID}` —
  because Entra can issue either. Both derived automatically from
  `ENTRA_CLIENT_ID`; no separate audience config needed.
- **Okta**: a Custom Authorization Server has one operator-configured
  Audience value, which is *not* derived from the client ID — it's whatever
  string was set when the authorization server was created. Hence
  `OKTA_AUDIENCE` is its own required config variable (§3), not computed.
  Only one accepted value, not two.
- **Reconciled**: inside `verifyAccessToken`. Entra checks membership in a
  derived 2-element set; Okta checks equality against one configured value.

### 4.5 Issuer (`iss`) claim

- **Entra**: two accepted forms — the v2.0 issuer
  (`login.microsoftonline.com/{tenant}/v2.0`) and the legacy v1 issuer
  (`sts.windows.net/{tenant}/`) — because Entra can issue v1-shaped tokens
  even from the v2 endpoint (see memory note on this exact issue from a
  prior project).
- **Okta**: one canonical issuer per authorization server —
  `https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER_ID}` — no legacy dual-issuer
  quirk to accommodate.
- **Reconciled**: inside `verifyAccessToken`, same as audience — Entra
  checks a 2-element set, Okta checks one value.

### 4.6 Scope claim (`scp`) shape — flagged as uncertain, see §7

- **Entra**: `scp` is a single space-delimited string (`auth.ts:93`,
  `.split(" ")`).
- **Okta**: access tokens from a Custom Authorization Server carry `scp` as
  a JSON array of strings, not a space-delimited string. If this is copied
  as-is from the Entra logic, `"access_as_user".split(" ")` would silently
  produce a one-element array containing the whole array-as-string —
  actually worse, calling `.split` on an array would throw, since arrays
  don't have that method. This would fail loudly, but only against a real
  Okta token — not caught by any test written against assumptions instead
  of a live tenant.
- **Reconciled**: `verifyAccessToken` normalizes both shapes into
  `scopes: string[]` before the caller ever checks scope membership. The
  interface's callers (the `requireAuth` middleware replacing
  `requireEntraAuth`) never see the raw claim.
- **This divergence is the one most worth verifying against a real Okta
  tenant before the demo** — see §7.

## 5. Token validation

| | Entra | Okta |
|---|---|---|
| Signing key retrieval | `jwks-rsa`, cached, rate-limited, keyed by `kid`, fetched from `/discovery/v2.0/keys` | Same `jwks-rsa` pattern, fetched from `/oauth2/{OKTA_AUTH_SERVER_ID}/v1/keys` |
| Signing key rotation | Handled by `jwks-rsa`'s cache invalidation on unknown `kid` (existing behavior, unchanged) | Same — no provider-specific rotation logic needed, `jwks-rsa` handles both identically |
| Algorithm | RS256 (unchanged) | RS256 |
| Audience | 2 accepted values, derived (§4.4) | 1 accepted value, configured (§4.4) |
| Issuer | 2 accepted values (§4.5) | 1 accepted value (§4.5) |
| Scope claim | space-delimited string (§4.6) | JSON array (§4.6, unverified) |

No divergence in *mechanism* (both use `jsonwebtoken` + `jwks-rsa`,
RS256-only) — only in the literal values checked and the claim shape
normalized. This keeps `verifyAccessToken` implementations structurally
similar across both providers even though they're not forced through
identical code.

## 6. Impact on the existing tool

**None.** `get_tps_report` (`index.ts:18-40`) takes no input, reads no
claims, and returns a fake report. Nothing about provider divergence
reaches it — scope/audience/issuer checks all happen in `verifyAccessToken`
before the tool is ever invoked, and the tool has no reason to know which
provider authenticated the caller.

The one piece of provider-visible behavior today is a `console.log` of
`sub` and `aud` on successful validation (`auth.ts:102`) — useful for
proving live, during a demo, that the same real identity is flowing through
regardless of provider. That logging moves into the generic
`verifyAccessToken` caller and is preserved unchanged; it satisfies the
intent's "demonstrable live" success criterion without the tool itself
needing to change. This is a deliberate non-change, stated explicitly per
the intent's requirement that divergence (or lack of it) be documented
rather than assumed.

## 7. Open questions / things flagged as uncertain

Per the design-stage instructions, these are surfaced rather than
silently decided:

1. **Okta `scp` claim shape (§4.6)**: this spec assumes Custom Authorization
   Server access tokens carry `scp` as an array. This should be confirmed
   against a real token from the actual Okta org before or during
   implementation — if wrong, `verifyAccessToken`'s normalization logic for
   Okta needs to change, but the *interface* (`scopes: string[]` out) does
   not.
2. **Okta authorization server type**: this spec assumes a **Custom
   Authorization Server** is provisioned (required for a custom `aud` value
   and custom scopes like `access_as_user` — Okta's default Org
   Authorization Server doesn't support either). If no Okta org/tenant
   exists yet for this demo, provisioning one with a Custom Authorization
   Server is a prerequisite this spec assumes but doesn't itself deliver.
3. **DCR deliberately not exposed for Okta.** Okta supports Dynamic Client
   Registration; this spec does not use it, keeping both providers on a
   static, pre-registered `CLIENT_ID` (matching Entra, which has no choice).
   Rationale: exposing DCR would mean the MCP client's registration
   behavior differs by provider, which risks the live demo needing
   different connector setup steps per provider — working against the
   "switch requires no code changes" *and* implicitly no client
   reconfiguration. This is a judgment call in the direction of demo
   reliability over showing off Okta's fuller capability; flagging it
   explicitly in case the originator wants DCR exposed instead.
4. **Okta app registration platform type**: Entra's public/no-secret client
   only works once redirect URIs sit under the "Mobile and desktop
   applications" platform, not "SPA" (AADSTS7000218, per the glossary). The
   equivalent Okta app type is assumed to be "Native" (public client, PKCE,
   no client secret) to preserve the same secret-less model — this needs
   confirming when the Okta app is actually registered, not before.
5. **Redirect URI registration** is a provisioning step, not a code change,
   but both provider app registrations must have the calling MCP client's
   (Claude.ai's / Inspector's) redirect URI(s) registered before either
   provider path is testable end-to-end. Out of scope for this spec beyond
   noting it as a shared prerequisite for §8's live-tenant tests.

## 8. Testing approach

**Testable without a live tenant** (pure logic, fixture-driven):

- `verifyAccessToken` for both providers: construct self-signed JWTs with a
  local test keypair, inject a stub JWKS resolver (bypassing the real
  network call), and assert accept/reject behavior for: valid claims, wrong
  audience, wrong issuer, missing scope, expired token, bad signature. This
  covers §4.4, §4.5, and §4.6's normalization directly — including a fixture
  Okta-shaped token with `scp` as an array, to lock in the assumption from
  §7.1 as an explicit, visible test rather than an implicit one.
- `buildAuthorizeRedirectUrl` / `exchangeToken` query/body transforms for
  both providers: assert `resource` is stripped for Entra and passed
  through for Okta (§4.2), and `scope` is backfilled with the
  provider-correct value when absent, left alone when present (§4.3).
- `protectedResourceMetadata` / `authorizationServerMetadata` shape for
  both providers: for Entra, assert the hardcoded document; for Okta,
  assert the endpoint-rewrite logic against a **fixture** copy of an Okta
  discovery document (recorded once from a real org, checked into the test
  suite) rather than a live fetch, so the test doesn't depend on network
  access or a live tenant either.
- Configuration fail-fast behavior (§3): unset/invalid `IDENTITY_PROVIDER`,
  missing required vars per provider, inactive provider's vars ignored —
  all pure function tests against a config-loading module.

**Requires a live tenant** (cannot be faked without misrepresenting the
result):

- The full authorize → consent → redirect → token → tool-call flow through
  each real IdP's actual UI and endpoints — PKCE, consent screens, and
  redirect handling are real user-agent behavior that fixtures can't stand
  in for.
- Confirming the §7 assumptions (`scp` shape, audience/issuer literal
  values, app registration platform type) against the actual provisioned
  Okta org.
- The live demo itself: switching `IDENTITY_PROVIDER` and restarting,
  showing both providers work end to end with no source change.

## 9. Acceptance criteria

Traceable to the intent's "Success criteria":

1. With `IDENTITY_PROVIDER` unset or invalid, the server fails to start and
   the printed error names the problem (§3, item 1) — checked by an
   automated test.
2. With `IDENTITY_PROVIDER=entra` and required Entra vars set, the server
   starts and the existing Entra flow (discovery → authorize → token →
   `get_tps_report`) continues to work exactly as it does today — no
   regression. *(Intent: "The server runs successfully against Microsoft
   Entra ID.")*
3. With `IDENTITY_PROVIDER=okta` and required Okta vars set, the server
   starts and the same flow works against a real Okta org, using the same
   MCP client configuration (no client-side reconfiguration). *(Intent:
   "The same codebase runs successfully against Okta, selected by
   configuration alone.")*
4. Switching between (2) and (3) requires changing only environment
   variables and restarting the process — verified by a clean `git diff`
   across the switch. *(Intent: "Switching providers requires no code
   changes.")*
5. Token validation correctly rejects wrong-audience, wrong-issuer,
   insufficient-scope, and invalid-signature tokens under both providers —
   covered by the fixture-based unit tests in §8, including the
   Okta-array-shaped `scp` case from §7.1.
6. Each divergence enumerated in §4 has either a passing automated test or
   an explicit note in §7/§8 explaining why it can only be verified live —
   nothing is silently assumed to work.
7. `get_tps_report` requires no code change under either provider (§6),
   confirmed as an explicit non-change rather than left unstated.
8. The provider switch can be demonstrated live end-to-end. *(Intent: "The
   provider switch can be performed and shown end to end during a live
   demonstration.")* This criterion is inherently a live-tenant check
   (§8) and cannot be satisfied by automated tests alone.
