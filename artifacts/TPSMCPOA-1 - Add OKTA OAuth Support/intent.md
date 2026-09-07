# Intent: Pluggable Identity Provider Support for the TPS Report MCP Server

## Status
Draft — pending originator review

## Originator
Tim, President, RIA Solutions Group

## Problem — what we cannot do today
The TPS Report MCP server implements OAuth against Microsoft Entra ID and only
Microsoft Entra ID. The identity provider is hardwired into the authorization
path, so the demo cannot be shown running against any other enterprise IdP.

As a result, the demo reads as a Microsoft-specific integration rather than as
what it is meant to be: evidence that an MCP server can be built to
enterprise-grade standards independent of any single identity vendor.

## Who is affected
RIA Solutions Group, and Tim specifically, when demonstrating technical
capability to prospects and stakeholders. The affected party is the presenter,
not an end user — this is a capability demonstration, not a production feature
serving customer traffic.

## What better looks like
- The MCP server can authenticate against either Microsoft Entra ID or Okta.
- The active provider is selected by configuration at startup. Switching
  providers requires no code changes.
- Exactly one provider is active per running instance.
- The single existing tool (get TPS report) remains functional under either
  provider.
- The switch is demonstrable live, so an audience can see vendor independence
  rather than be told about it.

## Out of scope
- A fully provider-agnostic identity abstraction supporting arbitrary IdPs.
  Desirable long term, deliberately excluded here.
- Simultaneous support for both providers in one running instance. There is no
  business scenario requiring an MCP server to authenticate against two IdPs at
  once.
- Multi-tenancy of any kind.
- Additional tools beyond the existing one.

## Constraints
- Two providers only: Microsoft Entra ID and Okta.
- Configuration-driven provider selection, resolved at startup.
- The tool contract is not required to remain byte-identical across providers.
  Divergence is acceptable where the providers genuinely differ, provided it is
  deliberate and documented.

## Known risks
- Microsoft Entra ID diverges in specific and material ways from the standard
  OAuth flows that AI clients expect. Any shared abstraction across the two
  providers will surface these seams. Reconciling them is expected development
  work, not an unforeseen problem — the differences should be surfaced and
  documented during design rather than papered over.

## Success criteria
- The server runs successfully against Microsoft Entra ID.
- The same codebase runs successfully against Okta, selected by configuration
  alone.
- The provider switch can be performed and shown end to end during a live
  demonstration.
