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
  readonly supportsDynamicRegistration: boolean;

  protectedResourceMetadata(serverBaseUrl: string): ProtectedResourceMetadata;

  authorizationServerMetadata(serverBaseUrl: string): Promise<AuthorizationServerMetadata>;

  buildAuthorizeRedirectUrl(clientQuery: URLSearchParams): string;

  exchangeToken(clientBody: URLSearchParams): Promise<{
    status: number;
    contentType: string;
    body: string;
  }>;

  verifyAccessToken(bearerToken: string): Promise<{ subject: string; scopes: string[] }>;

  // Present only when supportsDynamicRegistration is true (Okta today).
  // Relays an RFC 7591 registration request/response, same passthrough
  // shape as exchangeToken — see §4.7 for why this can't be a thinner
  // pure-relay operation for Okta specifically.
  registerClient?(clientRequestBody: unknown): Promise<{
    status: number;
    contentType: string;
    body: string;
  }>;
}
```

Amended (originator reversed §7's DCR decision — see §4.7 and §7 item 3):
`supportsDynamicRegistration` plus an optional `registerClient` is the
originator's suggested shape, and it holds up against the actual code: it's
the minimum addition that lets `index.ts` register `POST /register`
*conditionally* — the route exists at all only when the active provider
sets the flag, so it 404s under Entra rather than existing and erroring.
`registerClient` is typed identically to `exchangeToken` (status/content-type/body
passthrough) rather than a parsed RFC 7591 shape, for the same reason
`exchangeToken` is: the proxy relays, it doesn't need to understand the
registration response's internals to do its job.

`authorizationServerMetadata` does not gain a new parameter — instead, each
provider's own implementation is now responsible for including (Okta) or
omitting (Entra) `registration_endpoint` in the document it returns, exactly
as it already decides what to include for every other field (§4.1). Okta's
implementation rewrites `registration_endpoint` to point at this server's
own `/register`, the same way it already rewrites `authorization_endpoint`
and `token_endpoint` — one more field added to a rewrite it was already
doing, not a new mechanism.

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
OKTA_AUDIENCE=              # the audience value configured on that auth server
OKTA_REQUIRED_SCOPE=access_as_user   # optional, same default as Entra for parity
OKTA_API_TOKEN=             # NEW (§4.7) — admin/management credential, used
                             # server-side only, to perform Dynamic Client
                             # Registration on a calling client's behalf

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
   OKTA_DOMAIN, OKTA_AUTH_SERVER_ID, OKTA_AUDIENCE, OKTA_API_TOKEN. Missing:
   OKTA_AUDIENCE.` — one error, not one exception per missing var, so a
   misconfigured deploy shows the whole problem at once.
3. The inactive provider's variables are never required. Setting
   `IDENTITY_PROVIDER=entra` with `OKTA_*` vars unset is valid; a leftover
   `OKTA_*` block from a prior run is ignored, not validated.
4. No partial startup: the process must not begin listening on `PORT` if
   validation fails. Same as today's behavior (the `throw` at module load
   prevents `app.listen` from ever being reached) — this spec keeps that
   guarantee, just centralizes where it happens.

**Amended: `OKTA_CLIENT_ID` is no longer part of this list** (it was, in
the original draft of this spec). Reversing the DCR decision (§7 item 3,
§4.7) removes the need for it: every client now obtains its own `client_id`
by calling `POST /register`, rather than the operator hand-configuring one
fixed value shared across all clients. This is a direct, load-bearing
consequence of the reversal, not a cosmetic cleanup — the Entra path keeps
requiring a fixed `ENTRA_CLIENT_ID` precisely because Entra has no
registration path to get one dynamically (§4.7). `OKTA_API_TOKEN` is what
replaces it as the credential the Okta path actually depends on — but it
authenticates the *server* to Okta's Management API, not a specific client
to the authorization server, which is a different trust relationship than
the value it's replacing. See §4.7 for why that distinction matters.

## 4. Divergence between Entra ID and Okta

This is the substance of the design. Seven concrete points of divergence,
each with where it's reconciled. (§4.7 was added on amendment, when the
originator reversed the DCR decision recorded in §7 item 3 — the first six
were the original draft's full count.)

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

### 4.7 Dynamic Client Registration (RFC 7591) — client-visible, added on reversal of §7 item 3

Unlike §4.1–4.6, this divergence is not fully absorbed inside the provider
implementation — it is visible to the calling MCP client, because it shows
up in the one document every conformant client reads before deciding how to
authenticate: the RFC 8414 metadata. A DCR-aware client checks for a
`registration_endpoint` field and changes its behavior depending on whether
one is present. That's a client-visible branch, not an internal seam.

- **Entra**: no DCR support at any layer. `registration_endpoint` is never
  present in Entra's self-hosted metadata (unchanged from the original
  draft). A client falls back to whatever pre-shared `client_id` it's been
  given out of band — today's behavior, exactly.
- **Okta**: does expose a `registration_endpoint` — but verified against
  Okta's own developer documentation, an Okta Developer Community answer,
  and a documented MCP-ecosystem integration report (sources below), it is
  **not** anonymous self-service registration the way RFC 7591 and MCP
  clients generally assume:
  - The endpoint is `{OKTA_DOMAIN}/oauth2/v1/clients` — an org-level
    Management API path, not one scoped to whichever custom authorization
    server the resulting client will actually get tokens from. Per Okta's
    own developer forum: *"OIDC applications are not registered with custom
    authorization servers"* — registration and token issuance are separate
    concerns in Okta's model, whatever RFC 7591 assumes about them being
    unified in a single authorization server.
  - Calling it requires an authenticated admin/management credential — not
    an anonymous POST. A documented MCP-ecosystem GitHub issue against this
    exact endpoint states it plainly: Okta "requires out-of-band
    administrator credentials before DCR can proceed," which "defeats the
    purpose of dynamic registration" as MCP clients expect it.
  - So `registration_endpoint` being present in Okta's metadata does not by
    itself mean a client can register itself. A client that discovers the
    field and POSTs to it with no credentials gets rejected, not registered.

**What "supporting DCR" means here, concretely.** The TPS server's Okta
provider does not just relay the raw registration request to Okta — doing
that would hand the client Okta's 401/403 straight back, which is
discovery-compliant but useless. Instead, the TPS server holds a
pre-provisioned Okta API token (`OKTA_API_TOKEN`, §3) and performs the real
`/oauth2/v1/clients` call **on the calling client's behalf**, returning
Okta's response in the standard RFC 7591 shape. From the MCP client's side,
`POST /register` against the TPS proxy looks like ordinary anonymous DCR
succeeding.

**The incompatibility, stated rather than engineered away.** This only
works because the credential requirement didn't disappear — it moved from
the client to the TPS server. Okta has no mode where a client registers
itself with zero pre-existing trust, the way RFC 7591's anonymous case and
MCP's own assumption both expect. TPS can *simulate* that experience by
spending its own admin credential on the client's behalf, but that's a
materially different trust model than "any client can show up and
register": it's "the operator of this resource server has decided to vouch
for every registration request it receives," a much broader trust
extension than it looks like from the client side, and one Entra's
complete lack of DCR support never even raises as a question. This is the
real incompatibility the originator's reversal was looking for — not "Okta
doesn't support DCR" (it does, in a sense), but "Okta's support for DCR
doesn't mean what a client that only checks for `registration_endpoint`
would assume it means," and the only way to make it *behave* as if it does
is for this server to take on a credential it wouldn't otherwise need.

**Conflict this creates elsewhere in the spec, surfaced rather than
resolved quietly**: the original §2 design assumed both providers use a
single, statically pre-registered `client_id` known ahead of time (mirroring
Entra's `proxyAuthorize` check of `clientId !== CLIENT_ID`, `oauthProxy.ts:22-27`
today). That assumption no longer holds for Okta — different clients can
now legitimately arrive with different, dynamically-issued `client_id`
values. `buildAuthorizeRedirectUrl` for Okta must therefore drop that
static equality check entirely and trust Okta's own `/authorize` to reject
a `client_id` it never issued. Entra keeps the check, because Entra still
has exactly one legitimate value to check against. See §3 for the
resulting removal of `OKTA_CLIENT_ID` as a required variable.

- **Reconciled**: partially inside the Okta provider (the credential-
  mediated `registerClient` implementation), partially pushed to the
  operator (§3: a new secret to provision, scoped as narrowly as Okta
  allows — least-privilege app-management permissions rather than a
  full super-admin API token, confirmed at implementation time), and
  partially left as an honest, stated limitation rather than something the
  design can make disappear (§9, revised acceptance criteria).

Sources consulted: Okta's Dynamic Client Registration API reference
(developer.okta.com/docs/api/openapi/okta-oauth/oauth/tag/Client), the
Okta Developer Community thread on dynamic registration with a custom
authorization server (devforum.okta.com/t/dynamic-client-registration-with-custom-authorization-server/15426),
and a documented MCP-ecosystem GitHub issue describing this exact
credential gap against Okta specifically
(github.com/modelcontextprotocol/modelcontextprotocol/issues/695).

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
3. **Reversed: DCR is now in scope for Okta.** The original draft of this
   spec deliberately suppressed Okta's DCR support to keep both providers
   looking identical to the calling client. The originator reviewed that
   decision and reversed it: the real question this demo exists to answer
   is whether one MCP server can genuinely support two OAuth providers, or
   whether the differences are large enough that one must in practice be
   picked — and suppressing DCR for symmetry hides exactly the
   client-visible divergence (§4.7) that would answer it. A demo that
   surfaces a real incompatibility is more useful here than one engineered
   to look smooth. The goal is no longer "make both providers behave the
   same" but "support each provider properly and document honestly where
   that forces the abstraction to leak."

   Support for DCR is added as §4.7, with the interface extended in §2.
   **Entra still has no DCR support of any kind** — this is an asymmetric
   capability between the two providers, not a missing implementation on
   this server's part; nothing changes on the Entra side. What actually
   researching Okta's DCR turned up (§4.7) is itself a finding worth
   keeping in the spec rather than smoothing away: Okta's `registration_endpoint`
   is real, but calling it requires an admin credential this server now has
   to hold and spend on the client's behalf — DCR "works" for the demo, but
   not for the reason a client checking only for `registration_endpoint`
   would assume. That gap is the incompatibility the originator was asking
   to see surfaced, and §4.7 states it directly rather than absorbing it
   silently into a "yes, Okta supports DCR" checkbox.
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
   starts and the same flow works against a real Okta org. *(Intent: "The
   same codebase runs successfully against Okta, selected by configuration
   alone.")* **Revised on DCR reversal**: this criterion no longer implies
   the calling MCP client needs zero reconfiguration between providers — a
   DCR-capable client (§4.7) performs a fresh dynamic registration against
   the Okta path and receives its own `client_id`, rather than reusing
   whatever `client_id` it used against Entra. That's stated here
   explicitly rather than left as an unstated assumption the original
   criterion happened to imply but the intent never actually required —
   the intent's phrase is about the **codebase** running successfully, which
   this still satisfies; it says nothing about client-side credential
   continuity across providers.
4. Switching between (2) and (3) requires changing only environment
   variables and restarting the **server** process — verified by a clean
   `git diff` across the switch. *(Intent: "Switching providers requires no
   code changes.")* Unaffected by the DCR reversal: this was always, and
   remains, a claim about the codebase, not about client-side state. A
   DCR-capable client re-registering once against the newly-active Okta
   path is ordinary DCR behavior, not a code change.
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
9. **Added on DCR reversal.** A DCR-capable MCP client can `POST /register`
   against the Okta-backed server with no pre-existing credentials of its
   own, and receive back a usable `client_id` it can immediately use on
   `/authorize` — verified against a real Okta org. Against Entra, the same
   request to `/register` returns 404 (no such route is registered),
   consistent with Entra having no `registration_endpoint` at all. The
   credential cost this requires of the server itself (`OKTA_API_TOKEN`,
   §3, §4.7) is a deliberate, documented design tradeoff — its presence is
   itself part of what this criterion is checking for, not an
   implementation detail to hide.
