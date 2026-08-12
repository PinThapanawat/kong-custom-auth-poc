import express from "express";
import * as jose from "jose";

const app = express();
const port = Number(process.env.PORT ?? 8080);

app.use(express.json());

const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER ?? "";
const KEYCLOAK_JWKS_URL = process.env.KEYCLOAK_JWKS_URL ?? "";
const KEYCLOAK_INTROSPECT_URL = process.env.KEYCLOAK_INTROSPECT_URL ?? "";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID ?? "poc-client";

// Introspection requires a confidential client (Keycloak rejects
// introspection calls from the public poc-client used for login), so a
// separate introspection-only client/secret is used here.
const KEYCLOAK_INTROSPECTION_CLIENT_ID = process.env.KEYCLOAK_INTROSPECTION_CLIENT_ID ?? "poc-introspection";
const KEYCLOAK_INTROSPECTION_CLIENT_SECRET = process.env.KEYCLOAK_INTROSPECTION_CLIENT_SECRET;

const JWKS = jose.createRemoteJWKSet(new URL(KEYCLOAK_JWKS_URL), {
  cooldownDuration: 30_000,
  cacheMaxAge: 600_000
});

// Ephemeral JWE decryption keypair. Regenerated on every restart, which
// invalidates any JWE minted before the restart. Production needs a
// persisted, rotated key (KMS/HSM), not an in-memory keypair.
let jwePrivateKey: jose.KeyLike;
let jwePublicJwk: jose.JWK;

type AuthResponse = {
  authenticated: boolean;
  user?: {
    id: string;
    client_id: string;
  };
  authorization?: {
    roles: string[];
    scopes: string[];
  };
  exp?: number;
  payload_plaintext?: string;
  payload_error?: boolean;
};

const KNOWN_ROLES = new Set(["customer", "admin"]);
const KNOWN_SCOPES = new Set(["account.read", "account.write"]);

const introspectionCache = new Map<string, { active: boolean; expiresAt: number }>();
const INTROSPECTION_TTL_MS = 30_000;

async function checkRevocation(accessToken: string, jti: string): Promise<boolean> {
  const cached = introspectionCache.get(jti);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.active;
  }

  const body = new URLSearchParams({
    token: accessToken,
    client_id: KEYCLOAK_INTROSPECTION_CLIENT_ID,
    ...(KEYCLOAK_INTROSPECTION_CLIENT_SECRET ? { client_secret: KEYCLOAK_INTROSPECTION_CLIENT_SECRET } : {})
  });

  const resp = await fetch(KEYCLOAK_INTROSPECT_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const json = (await resp.json()) as { active?: boolean };
  const active = json.active === true;

  introspectionCache.set(jti, { active, expiresAt: Date.now() + INTROSPECTION_TTL_MS });
  return active;
}

app.get("/health", (_req, res) => {
  res.json({ status: "UP" });
});

app.get("/.well-known/jwe-jwks.json", (_req, res) => {
  res.json({ keys: [jwePublicJwk] });
});

app.post("/validate", async (req, res) => {
  const caller = req.header("X-Auth-Caller");

  // Only Kong should be allowed to call this endpoint.
  // In production, enforce this with mTLS/network policy as well.
  if (caller !== "kong") {
    return res.status(403).json({
      authenticated: false,
      message: "Caller is not trusted"
    });
  }

  const jwe = req.body?.token;

  console.log(`/validate called (correlation_id=${req.body?.correlation_id ?? "?"})`);

  if (typeof jwe !== "string" || jwe.length === 0) {
    return res.status(401).json({
      authenticated: false
    } satisfies AuthResponse);
  }

  try {
    const { plaintext } = await jose.compactDecrypt(jwe, jwePrivateKey);
    const innerJwt = new TextDecoder().decode(plaintext);

    const { payload } = await jose.jwtVerify(innerJwt, JWKS, {
      issuer: KEYCLOAK_ISSUER
    });

    if (req.header("X-Require-Revocation-Check") === "true") {
      const jti = typeof payload.jti === "string" ? payload.jti : "";
      const active = jti ? await checkRevocation(innerJwt, jti) : false;
      if (!active) {
        return res.status(401).json({ authenticated: false } satisfies AuthResponse);
      }
    }

    const realmRoles = Array.isArray((payload as any).realm_access?.roles)
      ? ((payload as any).realm_access.roles as string[])
      : [];

    const roles = realmRoles.filter((r) => KNOWN_ROLES.has(r));
    const scopes = realmRoles.filter((r) => KNOWN_SCOPES.has(r));

    const result: AuthResponse = {
      authenticated: true,
      user: {
        id: String(payload.sub ?? ""),
        client_id: KEYCLOAK_CLIENT_ID
      },
      authorization: { roles, scopes },
      exp: payload.exp
    };

    // Request payload is encrypted with the same key as the token. Decrypt
    // it here too (identity is already verified above) rather than handing
    // any business service a key of its own.
    const payloadJwe = req.body?.payload;
    if (typeof payloadJwe === "string" && payloadJwe.length > 0) {
      try {
        const { plaintext: payloadPlaintext } = await jose.compactDecrypt(payloadJwe, jwePrivateKey);
        result.payload_plaintext = new TextDecoder().decode(payloadPlaintext);
      } catch (err) {
        console.error("Payload decryption failed:", (err as Error).message);
        result.payload_error = true;
      }
    }

    return res.status(200).json(result);
  } catch (err) {
    console.error("Token validation failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false } satisfies AuthResponse);
  }
});

async function initKeys() {
  const { publicKey, privateKey } = await jose.generateKeyPair("RSA-OAEP-256", {
    extractable: true
  });
  jwePrivateKey = privateKey;
  jwePublicJwk = {
    ...(await jose.exportJWK(publicKey)),
    alg: "RSA-OAEP-256",
    use: "enc",
    kid: "auth-service-jwe-1"
  };
}

initKeys().then(() => {
  app.listen(port, () => {
    console.log(`Custom Auth Service listening on ${port}`);
  });
});
