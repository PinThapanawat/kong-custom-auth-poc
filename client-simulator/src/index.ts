import * as jose from "jose";

const KEYCLOAK_TOKEN_URL =
  process.env.KEYCLOAK_TOKEN_URL ?? "http://keycloak:8080/realms/poc/protocol/openid-connect/token";
const AUTH_SERVICE_JWE_JWKS_URL =
  process.env.AUTH_SERVICE_JWE_JWKS_URL ?? "http://auth-service:8080/.well-known/jwe-jwks.json";
const KONG_URL = process.env.KONG_URL ?? "http://localhost:8000/api/accounts";
const KONG_INTERNAL_API_URL = process.env.KONG_INTERNAL_API_URL ?? "http://kong:8000/api";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID ?? "poc-client";

const DEMO_USERS: Record<string, string> = {
  "demo-user": "demo-pass",
  "admin-user": "admin-pass"
};

async function login(username: string, password: string): Promise<string> {
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
  return accessToken;
}

async function fetchAuthServicePublicKey(): Promise<jose.KeyLike> {
  const jwksResp = await fetch(AUTH_SERVICE_JWE_JWKS_URL);
  if (!jwksResp.ok) {
    throw new Error(`Failed to fetch Auth Service JWKS: ${jwksResp.status}`);
  }
  const { keys } = (await jwksResp.json()) as { keys: jose.JWK[] };
  return (await jose.importJWK(keys[0], "RSA-OAEP-256")) as jose.KeyLike;
}

async function encryptFor(publicKey: jose.KeyLike, plaintext: string): Promise<string> {
  return new jose.CompactEncrypt(new TextEncoder().encode(plaintext))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);
}

async function runGetAccountsDemo(username: string, accessToken: string) {
  console.error("Fetching Auth Service JWE public key...");
  const authServicePublicKey = await fetchAuthServicePublicKey();

  console.error("Encrypting access token as JWE...");
  const jwe = await encryptFor(authServicePublicKey, accessToken);

  console.log(`\nJWE for ${username}:\n${jwe}\n`);
  console.log(`curl -H "Authorization: Bearer ${jwe}" ${KONG_URL}\n`);
}

async function runTransferDemo(username: string, accessToken: string, amount: number, tamper = false) {
  console.error("Fetching Auth Service JWE public key (same key used for the token)...");
  const authServicePublicKey = await fetchAuthServicePublicKey();

  console.error("Encrypting token...");
  const tokenJwe = await encryptFor(authServicePublicKey, accessToken);

  console.error("Encrypting request payload with the same key...");
  const payload = JSON.stringify({ to: "ACC-77002", amount });
  let payloadJwe = await encryptFor(authServicePublicKey, payload);

  if (tamper) {
    const parts = payloadJwe.split(".");
    const ct = parts[3];
    parts[3] = (ct[5] === "A" ? "B" : "A") + ct.slice(1);
    payloadJwe = parts.join(".");
    console.error("TAMPERED: flipped a character in the payload ciphertext");
  }

  console.error(`POSTing encrypted transfer request as ${username}...`);
  const resp = await fetch(`${KONG_INTERNAL_API_URL}/accounts/transfer`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenJwe}`,
      "Content-Type": "application/jwe"
    },
    body: payloadJwe
  });

  console.log(`\nHTTP ${resp.status}: ${await resp.text()}\n`);
}

async function main() {
  const [username, mode, amountArg] = process.argv.slice(2);

  if (!username || !DEMO_USERS[username]) {
    console.error(`Usage: client-simulator <${Object.keys(DEMO_USERS).join("|")}> [transfer|transfer-tamper <amount>]`);
    process.exit(1);
  }

  console.error(`Logging into Keycloak as ${username}...`);
  const accessToken = await login(username, DEMO_USERS[username]);

  if (mode === "transfer") {
    const amount = Number(amountArg ?? 100);
    await runTransferDemo(username, accessToken, amount);
  } else if (mode === "transfer-tamper") {
    const amount = Number(amountArg ?? 100);
    await runTransferDemo(username, accessToken, amount, true);
  } else {
    await runGetAccountsDemo(username, accessToken);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
