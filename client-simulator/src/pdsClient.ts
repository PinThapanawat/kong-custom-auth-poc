import * as crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as jose from "jose";
import {
  encodeSignedRequestEnvelope,
  decodeSignedResponseEnvelope,
  verifyEnvelopeSignature,
  RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING
} from "./envelope";
import { API_IDS, type ApiId } from "./apiRegistry";
import { rawHttpRequest } from "./httpRaw";

const DEVICE_IDENTITY_PATH = process.env.DEVICE_IDENTITY_PATH ?? "./data/device-identity.json";
const SESSION_PATH = process.env.SESSION_PATH ?? "./data/session.json";

interface DeviceIdentity {
  privateKeyPem: string;
  publicKeyPem: string;
  deviceId: string;
  deviceJwt: string;
}

interface StoredSession {
  sessionJwt: string;
  sekBase64: string;
  acquiredAt: string;
}

interface PdsJwks {
  pdsEncJwk: jose.JWK;
  pdsSignJwk: jose.JWK;
}

function ensureDataDir(path: string): void {
  const dir = path.slice(0, path.lastIndexOf("/"));
  if (dir) mkdirSync(dir, { recursive: true });
}

let cachedPdsSignPublicKey: crypto.KeyObject | undefined;

async function fetchPdsJwks(pdsBaseUrl: string): Promise<PdsJwks> {
  const resp = await fetch(`${pdsBaseUrl}/.well-known/pds-jwks.json`);
  if (!resp.ok) {
    throw new Error(`Failed to fetch PDS JWKS: ${resp.status}`);
  }
  const { keys } = (await resp.json()) as { keys: jose.JWK[] };
  const pdsEncJwk = keys.find((k) => k.use === "enc");
  const pdsSignJwk = keys.find((k) => k.use === "sig");
  if (!pdsEncJwk || !pdsSignJwk) {
    throw new Error("PDS JWKS missing enc or sig key");
  }
  return { pdsEncJwk, pdsSignJwk };
}

/** Response envelopes (both Category 1 and Category 2/3) are always signed
 * by the PDS's sign keypair — cache its public half across calls in this
 * process rather than re-fetching the JWKS on every request. */
async function getPdsSignPublicKey(pdsBaseUrl: string): Promise<crypto.KeyObject> {
  if (!cachedPdsSignPublicKey) {
    const { pdsSignJwk } = await fetchPdsJwks(pdsBaseUrl);
    cachedPdsSignPublicKey = (await jose.importJWK(pdsSignJwk, "ES256")) as crypto.KeyObject;
  }
  return cachedPdsSignPublicKey;
}

export async function ensureDeviceIdentity(
  pdsBaseUrl: string
): Promise<{ identity: DeviceIdentity; privateKey: crypto.KeyObject; publicKey: crypto.KeyObject }> {
  if (existsSync(DEVICE_IDENTITY_PATH)) {
    const identity: DeviceIdentity = JSON.parse(readFileSync(DEVICE_IDENTITY_PATH, "utf8"));
    return {
      identity,
      privateKey: crypto.createPrivateKey(identity.privateKeyPem),
      publicKey: crypto.createPublicKey(identity.publicKeyPem)
    };
  }

  console.error("No device identity found — generating keypair and enrolling...");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const devicePublicKeyJwk = await jose.exportJWK(publicKey);

  const resp = await fetch(`${pdsBaseUrl}/pds/device/enrollment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ devicePublicKeyJwk })
  });
  if (!resp.ok) {
    throw new Error(`Device enrollment failed: ${resp.status} ${await resp.text()}`);
  }
  const { deviceId, deviceJwt } = (await resp.json()) as { deviceId: string; deviceJwt: string };

  const identity: DeviceIdentity = { privateKeyPem, publicKeyPem, deviceId, deviceJwt };
  ensureDataDir(DEVICE_IDENTITY_PATH);
  writeFileSync(DEVICE_IDENTITY_PATH, JSON.stringify(identity, null, 2));
  console.error(`Enrolled as device ${deviceId}`);
  return { identity, privateKey, publicKey };
}

export async function acquireSession(
  pdsBaseUrl: string,
  identity: DeviceIdentity,
  devicePrivateKey: crypto.KeyObject,
  username: string,
  password: string
): Promise<StoredSession> {
  const { pdsEncJwk, pdsSignJwk } = await fetchPdsJwks(pdsBaseUrl);
  const pdsEncPublicKey = (await jose.importJWK(pdsEncJwk, "ECDH-ES+A256KW")) as crypto.KeyObject;
  const pdsSignPublicKey = (cachedPdsSignPublicKey ??= (await jose.importJWK(pdsSignJwk, "ES256")) as crypto.KeyObject);

  const requestUniqueId = crypto.randomUUID();
  const requestEnvelope = encodeSignedRequestEnvelope(
    {
      requestTimestampMs: BigInt(Date.now()),
      apiId: API_IDS.SESSION_ACQUIRING,
      requestUniqueId,
      originalRequestPayload: Buffer.from(JSON.stringify({ username, password }))
    },
    devicePrivateKey
  );

  const requestJwe = await new jose.CompactEncrypt(requestEnvelope)
    .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A256GCM" })
    .encrypt(pdsEncPublicKey);

  const resp = await fetch(`${pdsBaseUrl}/pds/session`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${identity.deviceJwt}`,
      "Content-Type": "application/jose",
      "X-Client-Transaction-Id": requestUniqueId
    },
    body: requestJwe
  });

  const responseText = await resp.text();
  if (!resp.ok) {
    throw new Error(`Session acquiring failed: HTTP ${resp.status}: ${responseText}`);
  }

  const { plaintext } = await jose.compactDecrypt(responseText, devicePrivateKey);
  const decoded = decodeSignedResponseEnvelope(Buffer.from(plaintext));
  if (decoded.responseStructureType !== RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING) {
    throw new Error(`Expected session-acquiring response (0x01), got 0x${decoded.responseStructureType.toString(16)}`);
  }
  const ok = verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, pdsSignPublicKey);
  if (!ok) {
    throw new Error("Session-acquiring response signature invalid — response did not come from the trusted PDS");
  }

  const { sessionJwt } = JSON.parse(Buffer.from(decoded.originalResponsePayload).toString("utf8")) as {
    sessionJwt: string;
  };

  const session: StoredSession = {
    sessionJwt,
    sekBase64: decoded.sessionEncryptionKey.toString("base64"),
    acquiredAt: new Date().toISOString()
  };
  ensureDataDir(SESSION_PATH);
  writeFileSync(SESSION_PATH, JSON.stringify(session, null, 2));
  return session;
}

export function loadSession(): StoredSession {
  if (!existsSync(SESSION_PATH)) {
    throw new Error(`No session found at ${SESSION_PATH} — run "login" first`);
  }
  return JSON.parse(readFileSync(SESSION_PATH, "utf8"));
}

export interface BffCallResult {
  status: number;
  body: unknown;
}

export async function callBffApi(
  pdsBaseUrl: string,
  devicePrivateKey: crypto.KeyObject,
  session: StoredSession,
  method: string,
  upstreamPath: string,
  apiId: ApiId,
  jsonBody?: unknown,
  tamper = false,
  requireRevocationCheck = false
): Promise<BffCallResult> {
  const sek = Buffer.from(session.sekBase64, "base64");
  const requestUniqueId = crypto.randomUUID();
  const originalRequestPayload = jsonBody !== undefined ? Buffer.from(JSON.stringify(jsonBody)) : Buffer.alloc(0);

  const requestEnvelope = encodeSignedRequestEnvelope(
    { requestTimestampMs: BigInt(Date.now()), apiId, requestUniqueId, originalRequestPayload },
    devicePrivateKey
  );

  let requestJwe = await new jose.CompactEncrypt(requestEnvelope)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .encrypt(sek);

  if (tamper) {
    const parts = requestJwe.split(".");
    const ciphertext = parts[3];
    parts[3] = (ciphertext[5] === "A" ? "B" : "A") + ciphertext.slice(1);
    requestJwe = parts.join(".");
    console.error("TAMPERED: flipped a character in the request ciphertext");
  }

  const resp = await rawHttpRequest(`${pdsBaseUrl}/pds/bff${upstreamPath}`, method, {
    Authorization: `Bearer ${session.sessionJwt}`,
    "Content-Type": "application/jose",
    "X-Client-Transaction-Id": requestUniqueId,
    ...(requireRevocationCheck ? { "X-Require-Revocation-Check": "true" } : {})
  }, Buffer.from(requestJwe));

  const contentType = resp.headers["content-type"] ?? "";
  if (contentType.includes("application/jose")) {
    const { plaintext } = await jose.compactDecrypt(resp.body.toString("utf8"), sek);
    const decoded = decodeSignedResponseEnvelope(Buffer.from(plaintext));
    const pdsSignPublicKey = await getPdsSignPublicKey(pdsBaseUrl);
    if (!verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, pdsSignPublicKey)) {
      throw new Error("BFF response signature invalid — response did not come from the trusted PDS");
    }
    const bodyText = Buffer.from(decoded.originalResponsePayload).toString("utf8");
    return { status: resp.status, body: bodyText.length > 0 ? JSON.parse(bodyText) : null };
  }

  const bodyText = resp.body.toString("utf8");
  return { status: resp.status, body: bodyText.length > 0 ? JSON.parse(bodyText) : null };
}
