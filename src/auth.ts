import type { NextFunction, Request, Response } from "express";
import jwt, {
  type JwtHeader,
  type JwtPayload,
  type SigningKeyCallback,
  type VerifyErrors,
} from "jsonwebtoken";
import jwksClient from "jwks-rsa";

const TENANT_ID = process.env.ENTRA_TENANT_ID;
const CLIENT_ID = process.env.ENTRA_CLIENT_ID;
const REQUIRED_SCOPE = process.env.ENTRA_REQUIRED_SCOPE ?? "access_as_user";

if (!TENANT_ID || !CLIENT_ID) {
  throw new Error("ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be set");
}

// Entra issues tokens for a default (api://<client-id>) Application ID URI
// with `aud` set to either the bare client ID or the api:// URI, and can
// issue v1-format tokens (sts.windows.net issuer) even off the v2 endpoint.
// Accept every form it's known to produce rather than one expected value.
const ACCEPTED_AUDIENCES: [string, ...string[]] = [CLIENT_ID, `api://${CLIENT_ID}`];
const ACCEPTED_ISSUERS: [string, ...string[]] = [
  `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
  `https://sts.windows.net/${TENANT_ID}/`,
];

const jwks = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
  cache: true,
  rateLimit: true,
});

function getSigningKey(header: JwtHeader, callback: SigningKeyCallback) {
  if (!header.kid) {
    callback(new Error("Token header missing kid"));
    return;
  }
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err || !key) {
      callback(err ?? new Error("Signing key not found"));
      return;
    }
    callback(null, key.getPublicKey());
  });
}

function resourceMetadataUrl(req: Request): string {
  const base = process.env.PUBLIC_URL ?? `${req.protocol}://${req.get("host")}`;
  return `${base}/.well-known/oauth-protected-resource`;
}

function unauthorized(
  req: Request,
  res: Response,
  error: string,
  description: string
) {
  const challenge = [
    `Bearer realm="tps-report-mcp"`,
    `error="${error}"`,
    `error_description="${description}"`,
    `resource_metadata="${resourceMetadataUrl(req)}"`,
  ].join(", ");
  res.setHeader("WWW-Authenticate", challenge);
  res.status(401).json({
    jsonrpc: "2.0",
    error: { code: -32001, message: description },
    id: null,
  });
}

export function requireEntraAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    console.error(`No bearer token on ${req.method} ${req.originalUrl}. Authorization header: ${header ?? "(absent)"}`);
    unauthorized(req, res, "invalid_request", "Missing bearer token");
    return;
  }
  const token = header.slice("Bearer ".length);

  jwt.verify(
    token,
    getSigningKey,
    { algorithms: ["RS256"], audience: ACCEPTED_AUDIENCES, issuer: ACCEPTED_ISSUERS },
    (err: VerifyErrors | null, decoded: JwtPayload | string | undefined) => {
      if (err || !decoded || typeof decoded === "string") {
        console.error(`Token verification FAILED: ${err?.message ?? "no payload decoded"}`);
        unauthorized(req, res, "invalid_token", err?.message ?? "Token verification failed");
        return;
      }

      const scopes = typeof decoded.scp === "string" ? decoded.scp.split(" ") : [];
      if (!scopes.includes(REQUIRED_SCOPE)) {
        console.error(
          `Token missing required scope. aud=${decoded.aud} iss=${decoded.iss} scp=${decoded.scp ?? "(none)"} roles=${JSON.stringify(decoded.roles ?? null)}`
        );
        unauthorized(req, res, "insufficient_scope", `Token missing required scope: ${REQUIRED_SCOPE}`);
        return;
      }

      console.log(`Token validated OK. aud=${decoded.aud} sub=${decoded.sub}`);

      next();
    }
  );
}

export function protectedResourceMetadata(_req: Request, res: Response) {
  // `resource` is set to the Entra App ID URI (not this server's own base
  // URL) because Entra's /authorize endpoint rejects a `resource` parameter
  // that doesn't match the requested scope's resource (AADSTS9010010) —
  // Entra doesn't support RFC 8707 resource indicators pointed at an
  // arbitrary server URL, only at one of its own registered App ID URIs.
  const resource = `api://${CLIENT_ID}`;
  res.status(200).json({
    resource,
    authorization_servers: [`https://login.microsoftonline.com/${TENANT_ID}/v2.0`],
    bearer_methods_supported: ["header"],
    scopes_supported: [`${resource}/${REQUIRED_SCOPE}`],
  });
}
