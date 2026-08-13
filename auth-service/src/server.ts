import express from "express";
import * as jose from "jose";
import * as crypto from "node:crypto";
import {
  decodeSignedRequestEnvelope,
  encodeSignedResponseEnvelope,
  verifyEnvelopeSignature,
  RESPONSE_STRUCTURE_TYPE_STANDARD,
  RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING
} from "./pds/envelope";
import { loadPdsKeyMaterial, type EcKeyPair } from "./pds/vaultClient";
import { initSekStore, storeSek, lookupSek, generateSessionId, type SekLookupResult } from "./pds/sekStore";
import { startCleanupJob } from "./pds/cleanupJob";
import { API_IDS, apiIdForBffRequest } from "./pds/apiRegistry";

const app = express();
const port = Number(process.env.PORT ?? 8080);

const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER ?? "";
const KEYCLOAK_JWKS_URL = process.env.KEYCLOAK_JWKS_URL ?? "";
const KEYCLOAK_TOKEN_URL = process.env.KEYCLOAK_TOKEN_URL ?? "";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID ?? "poc-client";
const PDS_SEK_SOURCE = process.env.PDS_SEK_SOURCE === "http" ? "http" : "db";
const PDS_SEK_INQUIRY_URL = process.env.PDS_SEK_INQUIRY_URL ?? "http://auth-service:8080/pds/internal/sek-inquiry";

const JWKS = jose.createRemoteJWKSet(new URL(KEYCLOAK_JWKS_URL), {
  cooldownDuration: 30_000,
  cacheMaxAge: 600_000
});

const KNOWN_ROLES = new Set(["customer", "admin"]);
const KNOWN_SCOPES = new Set(["account.read", "account.write"]);

// Loaded once at startup from Vault — see initPds() below.
let pdsEncKeyPair: EcKeyPair;
let pdsSignKeyPair: EcKeyPair;

app.get("/health", (_req, res) => {
  res.json({ status: "UP" });
});

app.get("/.well-known/pds-jwks.json", async (_req, res) => {
  const encJwk = await jose.exportJWK(pdsEncKeyPair.publicKey);
  const signJwk = await jose.exportJWK(pdsSignKeyPair.publicKey);
  res.json({
    keys: [
      { ...encJwk, alg: "ECDH-ES+A256KW", use: "enc", kid: "pds-enc-1" },
      { ...signJwk, alg: "ES256", use: "sig", kid: "pds-sign-1" }
    ]
  });
});

// ---- Device enrollment ----
// No real device attestation here (no App Attest / Play Integrity) — this
// is a bare "post your public key, get a JWT" endpoint. The returned
// deviceJwt is self-contained (ES256-signed by the PDS, carrying the
// device's public key as a claim), so later calls need no separate device
// lookup: verifying the JWT signature is enough to trust the embedded key.

app.post("/pds/device/enrollment", express.json(), async (req, res) => {
  const devicePublicKeyJwk = req.body?.devicePublicKeyJwk;
  if (!devicePublicKeyJwk || typeof devicePublicKeyJwk !== "object") {
    return res.status(400).json({ error: "devicePublicKeyJwk is required" });
  }

  const deviceId = crypto.randomUUID();
  try {
    const deviceJwt = await new jose.SignJWT({ deviceId, devicePublicKeyJwk })
      .setProtectedHeader({ alg: "ES256", kid: "pds-sign-1" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .sign(pdsSignKeyPair.privateKey);
    res.json({ deviceId, deviceJwt });
  } catch (err) {
    console.error("Device enrollment failed:", (err as Error).message);
    res.status(400).json({ error: "invalid devicePublicKeyJwk" });
  }
});

// ---- Category 1: Session Acquiring API ----
// PDF pp.2-3. Request: ECDH-ES+A256KW/A256GCM JWE, signed envelope, to the
// PDS's own public key. Response: 0x01 envelope embedding the new SEK,
// signed by the PDS, JWE-encrypted to the device's public key.

app.post("/pds/session", express.text({ type: "application/jose", limit: "1mb" }), async (req, res) => {
  const requestUniqueIdHeader = req.header("X-Client-Transaction-Id");

  const authHeader = req.header("Authorization");
  const deviceJwt = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
  if (!deviceJwt) {
    return res.status(401).json({ authenticated: false, message: "device not enrolled" });
  }

  let devicePublicKeyJwk: jose.JWK;
  try {
    const { payload } = await jose.jwtVerify(deviceJwt, pdsSignKeyPair.publicKey, { algorithms: ["ES256"] });
    devicePublicKeyJwk = payload.devicePublicKeyJwk as jose.JWK;
    if (!devicePublicKeyJwk) throw new Error("deviceJwt missing devicePublicKeyJwk claim");
  } catch (err) {
    console.error("deviceJwt verification failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false, message: "invalid deviceJwt" });
  }

  let devicePublicKeyForVerify: crypto.KeyObject;
  let devicePublicKeyForEnc: crypto.KeyObject;
  try {
    devicePublicKeyForVerify = (await jose.importJWK(devicePublicKeyJwk, "ES256")) as crypto.KeyObject;
    devicePublicKeyForEnc = (await jose.importJWK(devicePublicKeyJwk, "ECDH-ES+A256KW")) as crypto.KeyObject;
  } catch (err) {
    console.error("device public key import failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false, message: "invalid device public key" });
  }

  let plaintext: Uint8Array;
  try {
    ({ plaintext } = await jose.compactDecrypt(String(req.body), pdsEncKeyPair.privateKey));
  } catch (err) {
    console.error("Session-acquiring payload decryption failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false, message: "payload decryption failed" });
  }

  let decoded: ReturnType<typeof decodeSignedRequestEnvelope>;
  try {
    decoded = decodeSignedRequestEnvelope(Buffer.from(plaintext));
  } catch (err) {
    console.error("Session-acquiring envelope decode failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false, message: "malformed request envelope" });
  }

  if (!verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, devicePublicKeyForVerify)) {
    return res.status(401).json({ authenticated: false, message: "envelope signature invalid" });
  }
  if (decoded.apiId !== API_IDS.SESSION_ACQUIRING) {
    return res.status(401).json({ authenticated: false, message: "apiId mismatch" });
  }
  if (requestUniqueIdHeader && requestUniqueIdHeader !== decoded.requestUniqueId) {
    return res.status(401).json({ authenticated: false, message: "X-Client-Transaction-Id mismatch" });
  }

  let credentials: { username?: string; password?: string };
  try {
    credentials = JSON.parse(Buffer.from(decoded.originalRequestPayload).toString("utf8"));
  } catch {
    return res.status(400).json({ authenticated: false, message: "invalid session-acquiring payload" });
  }

  let accessToken: string;
  try {
    const tokenResp = await fetch(KEYCLOAK_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: KEYCLOAK_CLIENT_ID,
        username: credentials.username ?? "",
        password: credentials.password ?? ""
      })
    });
    if (!tokenResp.ok) {
      return res.status(401).json({ authenticated: false, message: "invalid credentials" });
    }
    const tokenJson = (await tokenResp.json()) as { access_token?: string };
    if (!tokenJson.access_token) {
      return res.status(401).json({ authenticated: false, message: "invalid credentials" });
    }
    accessToken = tokenJson.access_token;
  } catch (err) {
    console.error("Keycloak ROPC login failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false, message: "authentication failed" });
  }

  let sub: string;
  let roles: string[];
  let scopes: string[];
  try {
    const { payload } = await jose.jwtVerify(accessToken, JWKS, { issuer: KEYCLOAK_ISSUER });
    const realmRoles = Array.isArray((payload as any).realm_access?.roles)
      ? ((payload as any).realm_access.roles as string[])
      : [];
    sub = String(payload.sub ?? "");
    roles = realmRoles.filter((r) => KNOWN_ROLES.has(r));
    scopes = realmRoles.filter((r) => KNOWN_SCOPES.has(r));
  } catch (err) {
    console.error("Keycloak access token verification failed:", (err as Error).message);
    return res.status(401).json({ authenticated: false, message: "authentication failed" });
  }

  const sessionId = generateSessionId();
  const sek = crypto.randomBytes(32);
  const devicePublicKeyDer = devicePublicKeyForVerify.export({ type: "spki", format: "der" }) as Buffer;

  try {
    await storeSek(sessionId, sek, devicePublicKeyDer);
  } catch (err) {
    console.error("SEK store failed:", (err as Error).message);
    return res.status(500).json({ authenticated: false, message: "session store unavailable" });
  }

  const sessionJwt = await new jose.SignJWT({ sessionId, sub, roles, scopes })
    .setProtectedHeader({ alg: "ES256", kid: "pds-sign-1" })
    .setIssuedAt()
    .setExpirationTime("4h")
    .sign(pdsSignKeyPair.privateKey);

  const responseEnvelope = encodeSignedResponseEnvelope(
    {
      responseStructureType: RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING,
      responseTimestampMs: BigInt(Date.now()),
      sessionEncryptionKey: sek,
      requestUniqueId: decoded.requestUniqueId,
      originalResponsePayload: Buffer.from(JSON.stringify({ sessionJwt }))
    },
    pdsSignKeyPair.privateKey
  );

  const responseJwe = await new jose.CompactEncrypt(responseEnvelope)
    .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A256GCM" })
    .encrypt(devicePublicKeyForEnc);

  res.setHeader("Content-Type", "application/jose");
  res.status(200).send(responseJwe);
});

// ---- Category 2/3: BFF API ----
// PDF pp.4-5. Request/response JWE uses alg=dir, enc=A256GCM, keyed
// directly by the per-session SEK. Category 3 (MiniApp) is the same code
// path with SEK sourced via HTTP inquiry instead of DB/Redis — see
// PDS_SEK_SOURCE below and lookupSekViaInquiry().
//
// Kong's `custom-auth` plugin (kong/plugins/custom-auth/handler.lua) brokers
// this category: it calls /pds/internal/verify to check auth is complete
// and get back plaintext + trusted headers, forwards the request to
// account-service itself, then calls /pds/internal/encrypt-response to
// re-encrypt the reply before returning it to the client. Both endpoints
// below are internal — only Kong should call them (X-Auth-Caller check,
// same convention this repo has used since the original /validate).

function requireKongCaller(req: express.Request, res: express.Response): boolean {
  if (req.header("X-Auth-Caller") !== "kong") {
    res.status(403).json({ error: "caller is not trusted" });
    return false;
  }
  return true;
}

async function buildEncryptedResponseEnvelope(
  sek: Buffer,
  requestUniqueId: string,
  originalResponsePayload: Buffer
): Promise<string> {
  const envelope = encodeSignedResponseEnvelope(
    {
      responseStructureType: RESPONSE_STRUCTURE_TYPE_STANDARD,
      responseTimestampMs: BigInt(Date.now()),
      requestUniqueId,
      originalResponsePayload
    },
    pdsSignKeyPair.privateKey
  );
  return new jose.CompactEncrypt(envelope).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).encrypt(sek);
}

async function lookupSekViaInquiry(sessionId: string): Promise<SekLookupResult> {
  try {
    const resp = await fetch(`${PDS_SEK_INQUIRY_URL}/${sessionId}`, { signal: AbortSignal.timeout(3000) });
    if (resp.status === 404) return { status: "not_found" };
    if (!resp.ok) return { status: "db_error" };
    const json = (await resp.json()) as { sekBase64: string; devicePublicKeyBase64: string };
    return {
      status: "found",
      sek: Buffer.from(json.sekBase64, "base64"),
      devicePublicKeyDer: Buffer.from(json.devicePublicKeyBase64, "base64")
    };
  } catch (err) {
    console.warn("SEK inquiry call failed:", (err as Error).message);
    return { status: "db_error" };
  }
}

// Self-referential stub for Category 3's "Session Encryption Key Inquiry
// API" — proves the alternate-source code path exists without standing up
// a second deployment, per the scope agreed for this rebuild.
app.get("/pds/internal/sek-inquiry/:sessionId", async (req, res) => {
  const lookup = await lookupSek(req.params.sessionId);
  if (lookup.status === "not_found") return res.status(404).json({ error: "not found" });
  if (lookup.status === "db_error") return res.status(500).json({ error: "db error" });
  res.json({
    sekBase64: lookup.sek.toString("base64"),
    devicePublicKeyBase64: lookup.devicePublicKeyDer.toString("base64")
  });
});

interface VerifyResult {
  outcome: "authenticated" | "unauthenticated" | "rejected";
  httpStatus: number;
  responseContentType: string;
  responseBody: string;
  sessionId?: string;
  requestUniqueId?: string;
  userId?: string;
  clientId?: string;
  roles?: string[];
  scopes?: string[];
  plaintextRequestBodyBase64?: string;
}

// Category 2/3 steps 1-5 (PDF pp.4-5): validate sessionJwt, look up the SEK,
// decrypt the payload, verify the envelope signature, check apiId. Called by
// Kong's custom-auth plugin once per request, before it forwards anything to
// account-service.
app.post("/pds/internal/verify", express.json({ limit: "6mb" }), async (req, res) => {
  if (!requireKongCaller(req, res)) return;

  const { sessionJwt, jwe, method, upstreamPath, requestUniqueId: requestUniqueIdHeader } = (req.body ?? {}) as {
    sessionJwt?: string;
    jwe?: string;
    method?: string;
    upstreamPath?: string;
    requestUniqueId?: string;
  };

  const unauthenticated = (httpStatus: number, body: unknown) =>
    res.json({
      outcome: "unauthenticated",
      httpStatus,
      responseContentType: "application/json",
      responseBody: JSON.stringify(body)
    } satisfies VerifyResult);

  // Step 1 (PDF p.4): validate sessionJwt. Plaintext JSON — no SEK exists
  // (or is trusted yet) to encrypt an error response with.
  if (typeof sessionJwt !== "string" || !sessionJwt) {
    return unauthenticated(401, { authenticated: false });
  }

  let sessionId: string;
  let sub: string;
  let roles: string[];
  let scopes: string[];
  try {
    const { payload } = await jose.jwtVerify(sessionJwt, pdsSignKeyPair.publicKey, { algorithms: ["ES256"] });
    sessionId = String(payload.sessionId ?? "");
    sub = String(payload.sub ?? "");
    roles = Array.isArray(payload.roles) ? (payload.roles as string[]) : [];
    scopes = Array.isArray(payload.scopes) ? (payload.scopes as string[]) : [];
    if (!sessionId) throw new Error("sessionJwt missing sessionId claim");
  } catch {
    return unauthenticated(401, { authenticated: false });
  }

  // Steps 2-3 (PDF p.5): Redis, falling back to DB (or the Category 3 HTTP
  // inquiry, per PDS_SEK_SOURCE).
  const lookup = PDS_SEK_SOURCE === "http" ? await lookupSekViaInquiry(sessionId) : await lookupSek(sessionId);
  if (lookup.status === "not_found") {
    return unauthenticated(401, { authenticated: false });
  }
  if (lookup.status === "db_error") {
    return unauthenticated(500, { error: "session store unavailable" });
  }
  const { sek, devicePublicKeyDer } = lookup;

  let devicePublicKeyForVerify: crypto.KeyObject;
  try {
    devicePublicKeyForVerify = crypto.createPublicKey({ key: devicePublicKeyDer, format: "der", type: "spki" });
  } catch {
    return unauthenticated(500, { error: "corrupt device public key" });
  }

  const rejected = async (httpStatus: number, message: string) => {
    const responseJwe = await buildEncryptedResponseEnvelope(
      sek,
      requestUniqueIdHeader ?? "",
      Buffer.from(JSON.stringify({ error: message }))
    );
    res.json({
      outcome: "rejected",
      httpStatus,
      responseContentType: "application/jose",
      responseBody: responseJwe
    } satisfies VerifyResult);
  };

  // Step 4 (PDF p.5): decrypt payload with SEK.
  if (typeof jwe !== "string" || !jwe) {
    return rejected(400, "missing payload");
  }
  let plaintext: Uint8Array;
  try {
    ({ plaintext } = await jose.compactDecrypt(jwe, sek));
  } catch {
    return rejected(400, "payload decryption failed");
  }

  // Step 5 (PDF p.5): verify envelope signature against the stored device pubkey.
  let decoded: ReturnType<typeof decodeSignedRequestEnvelope>;
  try {
    decoded = decodeSignedRequestEnvelope(Buffer.from(plaintext));
  } catch {
    return rejected(400, "malformed envelope");
  }
  if (!verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, devicePublicKeyForVerify)) {
    return rejected(400, "envelope signature invalid");
  }

  const expectedApiId = apiIdForBffRequest(method ?? "", upstreamPath ?? "");
  if (expectedApiId === undefined || decoded.apiId !== expectedApiId) {
    return rejected(400, "apiId mismatch");
  }

  res.json({
    outcome: "authenticated",
    httpStatus: 200,
    responseContentType: "",
    responseBody: "",
    sessionId,
    requestUniqueId: requestUniqueIdHeader || decoded.requestUniqueId,
    userId: sub,
    clientId: KEYCLOAK_CLIENT_ID,
    roles,
    scopes,
    plaintextRequestBodyBase64: Buffer.from(decoded.originalRequestPayload).toString("base64")
  } satisfies VerifyResult);
});

// Step 7 (PDF p.5): encrypt+sign the response. Called by Kong's custom-auth
// plugin once it has account-service's plaintext reply (or has synthesized
// a 502/504 error itself because account-service was unreachable) — Kong
// never holds a SEK, so it round-trips back here to get the encrypted body.
app.post("/pds/internal/encrypt-response", express.json({ limit: "6mb" }), async (req, res) => {
  if (!requireKongCaller(req, res)) return;

  const { sessionId, requestUniqueId, plaintextBodyBase64 } = (req.body ?? {}) as {
    sessionId?: string;
    requestUniqueId?: string;
    plaintextBodyBase64?: string;
  };
  if (typeof sessionId !== "string" || !sessionId) {
    return res.status(400).json({ error: "sessionId is required" });
  }

  const lookup = PDS_SEK_SOURCE === "http" ? await lookupSekViaInquiry(sessionId) : await lookupSek(sessionId);
  if (lookup.status !== "found") {
    // Rare race: the SEK was evicted between /pds/internal/verify and this
    // call. Nothing left to encrypt with.
    return res.status(410).json({ error: "session no longer available" });
  }

  const plaintext = typeof plaintextBodyBase64 === "string" ? Buffer.from(plaintextBodyBase64, "base64") : Buffer.alloc(0);
  const responseJwe = await buildEncryptedResponseEnvelope(
    lookup.sek,
    typeof requestUniqueId === "string" ? requestUniqueId : "",
    plaintext
  );
  res.json({ responseJwe });
});

async function initPds(): Promise<void> {
  const keyMaterial = await loadPdsKeyMaterial();
  pdsEncKeyPair = keyMaterial.pdsEncKeyPair;
  pdsSignKeyPair = keyMaterial.pdsSignKeyPair;
  initSekStore(keyMaterial.sekWrapKek);
  startCleanupJob();
}

initPds().then(() => {
  app.listen(port, () => {
    console.log(`Payload Decryptor Service listening on ${port}`);
  });
}).catch((err) => {
  console.error("PDS startup failed:", err);
  process.exit(1);
});
