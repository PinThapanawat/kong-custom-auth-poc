import * as jose from "jose";

const KEYCLOAK_TOKEN_URL =
  process.env.KEYCLOAK_TOKEN_URL ?? "http://keycloak:8080/realms/poc/protocol/openid-connect/token";
const AUTH_SERVICE_JWE_JWKS_URL =
  process.env.AUTH_SERVICE_JWE_JWKS_URL ?? "http://auth-service:8080/.well-known/jwe-jwks.json";
const KONG_URL = process.env.KONG_URL ?? "http://kong:8000/api/accounts";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID ?? "poc-client";

const DEMO_USERS: Record<string, string> = {
  "demo-user": "demo-pass",
  "admin-user": "admin-pass"
};

async function main() {
  const [username] = process.argv.slice(2);

  if (!username || !DEMO_USERS[username]) {
    console.error(`Usage: client-simulator <${Object.keys(DEMO_USERS).join("|")}>`);
    process.exit(1);
  }

  const password = DEMO_USERS[username];

  console.error(`Logging into Keycloak as ${username}...`);
  const tokenResp = await fetch(KEYCLOAK_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      client_id: KEYCLOAK_CLIENT_ID,
      username,
      password
    })
  });

  if (!tokenResp.ok) {
    throw new Error(`Keycloak login failed: ${tokenResp.status} ${await tokenResp.text()}`);
  }

  const { access_token: accessToken } = (await tokenResp.json()) as { access_token: string };

  console.error("Fetching Auth Service JWE public key...");
  const jwksResp = await fetch(AUTH_SERVICE_JWE_JWKS_URL);
  if (!jwksResp.ok) {
    throw new Error(`Failed to fetch Auth Service JWKS: ${jwksResp.status}`);
  }
  const { keys } = (await jwksResp.json()) as { keys: jose.JWK[] };
  const publicKey = await jose.importJWK(keys[0], "RSA-OAEP-256");

  console.error("Encrypting access token as JWE...");
  const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(accessToken))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);

  console.log(`\nJWE for ${username}:\n${jwe}\n`);
  console.log(`curl -H "Authorization: Bearer ${jwe}" ${KONG_URL}\n`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
