import express from "express";
import * as jose from "jose";

// Slim Keycloak-only auth service. All PDS crypto (Vault key material,
// envelope encode/decode, JWE, SEK storage, sessionJwt/deviceJwt signing)
// lives in Cryptography-Service, which is the only caller of the two
// internal endpoints below — see docs/encryption-workflow.md.

const app = express();
const port = Number(process.env.PORT ?? 8080);

const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER ?? "";
const KEYCLOAK_JWKS_URL = process.env.KEYCLOAK_JWKS_URL ?? "";
const KEYCLOAK_TOKEN_URL = process.env.KEYCLOAK_TOKEN_URL ?? "";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID ?? "poc-client";

// See Cryptography-Service's checkRevocation() for why introspection targets
// the refresh token, not the access token, and why a separate confidential
// client is needed here (Keycloak rejects introspection calls from the
// public poc-client used for login).
const KEYCLOAK_INTROSPECT_URL = process.env.KEYCLOAK_INTROSPECT_URL ?? "";
const KEYCLOAK_INTROSPECTION_CLIENT_ID = process.env.KEYCLOAK_INTROSPECTION_CLIENT_ID ?? "poc-introspection";
const KEYCLOAK_INTROSPECTION_CLIENT_SECRET = process.env.KEYCLOAK_INTROSPECTION_CLIENT_SECRET;

const JWKS = jose.createRemoteJWKSet(new URL(KEYCLOAK_JWKS_URL), {
  cooldownDuration: 30_000,
  cacheMaxAge: 600_000
});

const KNOWN_ROLES = new Set(["customer", "admin"]);
const KNOWN_SCOPES = new Set(["account.read", "account.write"]);

function requireCryptographyServiceCaller(req: express.Request, res: express.Response): boolean {
  if (req.header("X-Auth-Caller") !== "cryptography-service") {
    res.status(403).json({ error: "caller is not trusted" });
    return false;
  }
  return true;
}

app.get("/health", (_req, res) => {
  res.json({ status: "UP" });
});

// Category 1 login step: ROPC against Keycloak, then verify the returned
// access token against Keycloak's JWKS and extract sub/roles/scopes.
app.post("/internal/login", express.json(), async (req, res) => {
  if (!requireCryptographyServiceCaller(req, res)) return;

  const { username, password } = (req.body ?? {}) as { username?: string; password?: string };

  let accessToken: string;
  let refreshToken: string | undefined;
  try {
    const tokenResp = await fetch(KEYCLOAK_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: KEYCLOAK_CLIENT_ID,
        username: username ?? "",
        password: password ?? ""
      })
    });
    if (!tokenResp.ok) {
      return res.status(401).json({ error: "invalid credentials" });
    }
    const tokenJson = (await tokenResp.json()) as { access_token?: string; refresh_token?: string };
    if (!tokenJson.access_token) {
      return res.status(401).json({ error: "invalid credentials" });
    }
    accessToken = tokenJson.access_token;
    refreshToken = tokenJson.refresh_token;
  } catch (err) {
    console.error("Keycloak ROPC login failed:", (err as Error).message);
    return res.status(401).json({ error: "authentication failed" });
  }

  try {
    const { payload } = await jose.jwtVerify(accessToken, JWKS, { issuer: KEYCLOAK_ISSUER });
    const realmRoles = Array.isArray((payload as any).realm_access?.roles)
      ? ((payload as any).realm_access.roles as string[])
      : [];
    const sub = String(payload.sub ?? "");
    const roles = realmRoles.filter((r) => KNOWN_ROLES.has(r));
    const scopes = realmRoles.filter((r) => KNOWN_SCOPES.has(r));
    res.json({ sub, roles, scopes, refreshToken });
  } catch (err) {
    console.error("Keycloak access token verification failed:", (err as Error).message);
    res.status(401).json({ error: "authentication failed" });
  }
});

// RFC 7662 introspection of a refresh token, for the opt-in
// X-Require-Revocation-Check on Category 2/3. Cryptography-Service owns the
// per-sessionId result cache; this endpoint is a plain, uncached Keycloak
// call.
app.post("/internal/introspect", express.json(), async (req, res) => {
  if (!requireCryptographyServiceCaller(req, res)) return;

  const { refreshToken } = (req.body ?? {}) as { refreshToken?: string };
  if (!refreshToken) {
    return res.json({ active: false });
  }

  try {
    const resp = await fetch(KEYCLOAK_INTROSPECT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: refreshToken,
        token_type_hint: "refresh_token",
        client_id: KEYCLOAK_INTROSPECTION_CLIENT_ID,
        ...(KEYCLOAK_INTROSPECTION_CLIENT_SECRET ? { client_secret: KEYCLOAK_INTROSPECTION_CLIENT_SECRET } : {})
      })
    });
    const json = (await resp.json()) as { active?: boolean };
    res.json({ active: json.active === true });
  } catch (err) {
    console.error("Keycloak introspection call failed:", (err as Error).message);
    res.json({ active: false }); // fail closed — can't confirm the session is still valid
  }
});

app.listen(port, () => {
  console.log(`Auth Service listening on ${port}`);
});
