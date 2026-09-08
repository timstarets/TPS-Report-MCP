# Implementation Plan: Pluggable Identity Provider Support for the TPS Report MCP Server

**Jira key:** TPSMCPOA-1
**Status:** Implemented on branch `TPSMCPOA-1` (uncommitted, pending review)
**Input:** [`spec.md`](./spec.md) (same directory)

## Overview

`spec.md` calls for replacing the Entra-only auth code with a two-provider
abstraction (§2), an Entra implementation that behaves identically to
today's `auth.ts`/`oauthProxy.ts` (§1), and a new Okta implementation that
uses Okta's real capabilities rather than mirroring Entra's workarounds
(§0, §4). This plan is the file-by-file breakdown that was followed to get
there, plus what's verified and what isn't yet.

## Files

| File | Action | Why |
|---|---|---|
| `src/providers/types.ts` | new | `IdentityProvider` interface (spec §2) and shared types (`VerifiedClaims`, `ProxyRelayResult`, `AuthorizeError`) — the contract both providers implement. |
| `src/providers/entra.ts` | new | Entra's logic moved here unchanged in *behavior* from `auth.ts` + `oauthProxy.ts` — same accepted audiences/issuers, same `resource`-strip and `scope`-backfill, same self-hosted metadata (spec §1, §4.1–§4.6, Entra side). |
| `src/providers/okta.ts` | new | Okta's logic, written idiomatically per §0: proxies Okta's real RFC 8414 document instead of self-hosting one, passes `resource` through instead of stripping it, and implements `registerClient` as a credentialed relay to Okta's Management API (§4.7). |
| `src/config.ts` | new | `loadConfig()` — fail-fast validation exactly as specified in §3 (unset/invalid `IDENTITY_PROVIDER`, missing per-provider vars named in one error) — plus `createProvider()` and `requiredScopeOf()`. |
| `src/requireAuth.ts` | new | Provider-agnostic bearer-token middleware. Calls `provider.verifyAccessToken`, then checks the normalized `scopes` list against the configured required scope — the scope-membership check and 401/`WWW-Authenticate` handling don't need to know which provider is active (§4.6). |
| `src/index.ts` | modified | Route wiring made generic against `IdentityProvider` instead of importing Entra-named functions. `POST /register` is mounted only when `provider.supportsDynamicRegistration` is true, so it 404s under Entra rather than existing and erroring (§2, §4.7). |
| `src/auth.ts`, `src/oauthProxy.ts` | deleted | Superseded — their logic now lives in `src/providers/entra.ts`. |
| `.env.example` | modified | Documents the full schema from §3: `IDENTITY_PROVIDER`, both provider blocks, `OKTA_API_TOKEN` in place of the `OKTA_CLIENT_ID` the original spec draft had (removed on the DCR reversal). |
| `.env` (gitignored, local only) | modified | Added `IDENTITY_PROVIDER=entra` so the existing tenant/client ID already in this file keeps working without a live Okta org. |

## Order followed

1. **Interface first** (`types.ts`) — contract before either implementation, so both providers are written against the same shape rather than the shape being inferred backward from whichever provider got written first.
2. **Entra port** (`entra.ts`) — mechanical, not new design: every accepted value, every strip/backfill, every hardcoded metadata field carried over from `auth.ts`/`oauthProxy.ts` with no behavior change. Done first because it's checkable against the *existing* running server (see Verification below) — a regression here would be a real problem, not a design question.
3. **Okta implementation** (`okta.ts`) — new logic, built directly against spec §4's divergence table (§4.1 discovery proxying, §4.2 resource passthrough, §4.3 scope backfill value, §4.4/§4.5 audience/issuer, §4.6 scope-claim normalization, §4.7 DCR).
4. **Config loader** (`config.ts`) — written after both providers so its required-variable lists reflect what each provider's constructor actually needs, not a guess made before either existed.
5. **Generic middleware** (`requireAuth.ts`) — extracted once it was clear both providers' `verifyAccessToken` returned the same normalized shape, confirming the abstraction didn't leak.
6. **Route wiring** (`index.ts`) — last, since it's the thinnest layer: construct the config-selected provider once at startup, wire five routes generically, conditionally mount the sixth (`/register`).
7. **Cleanup** — delete the two superseded files, update both env files.

## Verification performed

- `npm run build` (`tsc`, strict mode) — clean, no type errors.
- Entra discovery endpoints (`/health`, `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`) tested against the real tenant/client ID already in `.env` — output is byte-identical to the pre-refactor server. This is the direct check for acceptance criterion 2 (no regression against the existing Entra integration).
- `POST /register` against the Entra-configured server returns 404 — acceptance criterion 9's Entra half.
- `config.loadConfig()` exercised directly for all four documented cases (§3): unset provider, invalid provider value, Okta config missing multiple vars (all named in one error), and a complete Okta config resolving correctly. Matches spec wording exactly, including the multi-variable "Missing: ..." error format.

## Not yet verified — needs a live Okta tenant (spec §7, §8)

- Okta discovery proxying (`authorizationServerMetadata`) against a real org's actual RFC 8414 document.
- Okta token exchange (`exchangeToken`) and the `/authorize` redirect against Okta's real endpoints.
- DCR round-trip: a real `POST /oauth2/v1/clients` call using `OKTA_API_TOKEN`, and whether the response shape `registerClient` relays is what a DCR-aware MCP client expects.
- The `scp` claim shape assumption (§4.6/§7 item 1) — `okta.ts` currently accepts either an array or a space-delimited string defensively, but which one Okta actually issues on a Custom Authorization Server access token is still unconfirmed against a real token.
- Whether the assumed Custom Authorization Server type, audience configuration, and "Native" app platform type (§7 items 2, 4) match what an actual Okta org provisioned for this demo would need.

## Mapping to spec §9 acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Fails fast on unset/invalid `IDENTITY_PROVIDER` | Done — verified directly |
| 2 | Entra path runs with no regression | Done — verified against real tenant, byte-identical output |
| 3 | Okta path runs, selected by config alone | Code complete; **unverified** — needs a live Okta org |
| 4 | Provider switch is config-only, clean `git diff` | Satisfied by construction (one `IDENTITY_PROVIDER` var; no other code path branches on provider elsewhere) — not yet demonstrated end-to-end live |
| 5 | Token validation rejects bad audience/issuer/scope/signature under both providers | Entra path exercised only informally (no live token yet); **no automated tests written for either provider** — see Follow-on work |
| 6 | Every §4 divergence has a test or an explicit live-tenant note | Not yet — no test suite exists yet (see Follow-on work); the live-tenant notes above cover the "explicit note" half |
| 7 | `get_tps_report` unchanged under either provider | Done — tool code untouched, confirmed by inspection |
| 8 | Live demo, switch shown end-to-end | Not yet attempted — needs both a live Entra flow (interactive, human-in-the-loop OAuth consent) and a live Okta org |
| 9 | DCR works against Okta with no client credentials; 404s under Entra | Entra half done and verified; Okta half code-complete, **unverified** |

## Follow-on work not covered by this plan

- **The automated test suite spec §8 calls for** (fixture-based JWT verification for both providers including an Okta-array-shaped `scp` fixture, authorize/token transform tests, metadata-shape tests using a checked-in Okta discovery fixture, config fail-fast tests) — none of this is written yet. It was left out of this pass to keep the implementation change reviewable on its own; happy to write it as a follow-up once the code itself is reviewed, or now if you'd rather have it together.
- **Provisioning a real Okta org** with a Custom Authorization Server, an audience value, the `access_as_user` scope, an app registration (assumed "Native"/public/PKCE platform type), and an `OKTA_API_TOKEN` scoped as narrowly as Okta allows for app management — none of this exists yet and nothing in this repo can create it; it's an external setup step the live-tenant verification above depends on.
