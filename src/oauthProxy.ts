import type { Request, Response } from "express";

const TENANT_ID = process.env.ENTRA_TENANT_ID;
const CLIENT_ID = process.env.ENTRA_CLIENT_ID;

if (!TENANT_ID || !CLIENT_ID) {
  throw new Error("ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be set");
}

const REQUIRED_SCOPE = process.env.ENTRA_REQUIRED_SCOPE ?? "access_as_user";

const ENTRA_AUTHORIZE_URL = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize`;
const ENTRA_TOKEN_URL = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;

// MCP clients that implement RFC 8707 resource indicators send a `resource`
// parameter alongside `scope`. Entra's v2.0 endpoint rejects that combination
// outright (AADSTS9010010), regardless of whether the values agree. `scope`
// already encodes the target resource, so dropping `resource` here loses
// nothing Entra needs - this proxy exists specifically to strip it before
// forwarding to the real authorization server.

export function proxyAuthorize(req: Request, res: Response) {
  const clientId = req.query.client_id;
  if (clientId !== CLIENT_ID) {
    res.status(400).json({ error: "invalid_client", error_description: "Unknown client_id" });
    return;
  }

  const params = new URLSearchParams(req.query as Record<string, string>);
  params.delete("resource");
  // Claude.ai's authorize request doesn't include `scope` (it relies on the
  // server knowing what it's asking for), but Entra requires it explicitly
  // on this leg too, not just at /token.
  if (!params.has("scope")) {
    params.set("scope", `api://${CLIENT_ID}/${REQUIRED_SCOPE}`);
  }
  res.redirect(302, `${ENTRA_AUTHORIZE_URL}?${params.toString()}`);
}

export async function proxyToken(req: Request, res: Response) {
  const body = req.body as Record<string, string>;
  const params = new URLSearchParams(body);
  params.delete("resource");

  // Plain OAuth2 treats `scope` as optional on the token exchange (it was
  // already established during authorization), and MCP clients omit it on
  // that basis - but Entra's v2.0 token endpoint requires it explicitly
  // (AADSTS900144). Backfill the scope we know we asked for if it's missing.
  if (!params.has("scope")) {
    params.set("scope", `api://${CLIENT_ID}/${REQUIRED_SCOPE}`);
  }

  const entraResponse = await fetch(ENTRA_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const responseBody = await entraResponse.text();
  if (entraResponse.ok) {
    try {
      const keys = Object.keys(JSON.parse(responseBody));
      console.log(`/token -> Entra ${entraResponse.status}, response keys: ${keys.join(", ")}`);
    } catch {
      console.log(`/token -> Entra ${entraResponse.status}, non-JSON body`);
    }
  } else {
    console.error(`/token -> Entra ${entraResponse.status}: ${responseBody}`);
  }
  res.status(entraResponse.status);
  res.setHeader("Content-Type", entraResponse.headers.get("content-type") ?? "application/json");
  res.send(responseBody);
}

// Self-issued Authorization Server Metadata (RFC 8414). Points clients at
// this proxy's own /authorize and /token rather than Entra's directly, so
// discovery-driven clients land here too, not just ones that default to
// trying conventional paths on the resource server's origin.
export function authorizationServerMetadata(req: Request, res: Response) {
  const base = process.env.PUBLIC_URL ?? `${req.protocol}://${req.get("host")}`;
  res.status(200).json({
    issuer: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    jwks_uri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  });
}
