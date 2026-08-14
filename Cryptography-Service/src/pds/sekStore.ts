import * as crypto from "node:crypto";
import { aesWrap, aesUnwrap } from "./aesWrap";
import { encryptToken, decryptToken } from "./tokenCrypto";
import { pgPool } from "./db";
import { redis } from "./redisClient";

// Session Encryption Key (SEK) storage, per requirement PDF pp.2-3 (issuance)
// and pp.4-5 (lookup) and pp.12-14 (storage design). Redis is a 4h cache;
// Postgres is the primary source of record. Both directions here must agree
// on the wire format: 40 bytes AESWrap(SEK) + 91 bytes device public key
// (ASN.1 DER, SPKI) = 131 bytes total.

const SEK_TTL_SECONDS = 4 * 60 * 60; // 4 hour maximum session lifetime, per spec
const PDS_ENV = process.env.PDS_ENV ?? "poc";

let sekWrapKek: Buffer | undefined;

export function initSekStore(kek: Buffer): void {
  sekWrapKek = kek;
}

function requireKek(): Buffer {
  if (!sekWrapKek) {
    throw new Error("sekStore not initialized — call initSekStore() with the Vault-held KEK at startup");
  }
  return sekWrapKek;
}

function redisKey(sessionId: string): string {
  return `${PDS_ENV}.oneapp.payload-decryptor-service.sek-${sessionId}`;
}

/**
 * Hour-of-day bucket assignment (0-23, UTC), per PDF p.13's partitioning
 * key. Must stay in sync with cleanupJob.ts's `(hour + 23) % 24` deletion
 * math — both read the clock the same way (UTC) so a row written now is
 * guaranteed to survive at least ~3h and at most 4h before its bucket is
 * swept, matching the spec's "maximum session lifetime is 4 hour".
 */
export function currentHourBucketUTC(): number {
  return new Date().getUTCHours();
}

export function generateSessionId(): string {
  return crypto.randomBytes(16).toString("hex"); // 32 hex chars, matches CHAR(32)
}

/**
 * Category 1 write path (PDF p.3, steps 2-4). DB insert is authoritative;
 * Redis write is best-effort — "If Redis is not available (Ex down), We
 * will skip this step" (PDF p.3 step 4).
 *
 * `refreshToken` is optional: it's the Keycloak refresh token from ROPC
 * login, stored AES-256-GCM-encrypted under the same KEK as the SEK so
 * Category 2/3's opt-in X-Require-Revocation-Check can later introspect it
 * (see checkRevocation() in server.ts). Its absence just means that opt-in
 * check will fail closed for this session.
 */
export async function storeSek(
  sessionId: string,
  sek: Buffer,
  devicePublicKeyDer: Buffer,
  refreshToken?: string
): Promise<void> {
  if (sek.length !== 32) {
    throw new Error(`SEK must be exactly 32 bytes, got ${sek.length}`);
  }
  if (devicePublicKeyDer.length !== 91) {
    throw new Error(`device public key DER must be exactly 91 bytes, got ${devicePublicKeyDer.length}`);
  }

  const wrapped = aesWrap(requireKek(), sek); // 40 bytes
  const wrappedRefreshToken = refreshToken ? encryptToken(requireKek(), refreshToken) : undefined;
  await pgPool.query(
    `INSERT INTO session_encryption_key (session_id, wrapped_encryption_key, device_public_key, expiration_bucket, wrapped_refresh_token)
     VALUES ($1, $2, $3, $4, $5)`,
    [sessionId, wrapped, devicePublicKeyDer, currentHourBucketUTC(), wrappedRefreshToken ?? null]
  );

  try {
    await redis.set(redisKey(sessionId), encodeCachedValue(wrapped, devicePublicKeyDer, wrappedRefreshToken), "EX", SEK_TTL_SECONDS);
  } catch (err) {
    console.warn(`SEK Redis write skipped for session ${sessionId} (Redis unavailable):`, (err as Error).message);
  }
}

export type SekLookupResult =
  | { status: "found"; sek: Buffer; devicePublicKeyDer: Buffer; refreshToken?: string }
  | { status: "not_found" } // -> 401 plaintext (PDF p.5 step 3.2)
  | { status: "db_error" }; // -> 500 plaintext (PDF p.5 step 3.1)

/**
 * Redis wire format: wrapped SEK (40 bytes) + device public key (91 bytes)
 * + a uint16BE length prefix for the wrapped refresh token (0 if absent) +
 * that many bytes. The refresh token is variable-length (unlike the SEK),
 * hence the length prefix instead of relying on a fixed total size.
 */
function encodeCachedValue(wrapped: Buffer, devicePublicKeyDer: Buffer, wrappedRefreshToken?: Buffer): Buffer {
  const rtLen = Buffer.alloc(2);
  rtLen.writeUInt16BE(wrappedRefreshToken?.length ?? 0);
  return Buffer.concat([wrapped, devicePublicKeyDer, rtLen, wrappedRefreshToken ?? Buffer.alloc(0)]);
}

function splitCachedValue(
  raw: Buffer
): { wrapped: Buffer; devicePublicKeyDer: Buffer; wrappedRefreshToken?: Buffer } | undefined {
  if (raw.length < 133) return undefined;
  const wrapped = raw.subarray(0, 40);
  const devicePublicKeyDer = raw.subarray(40, 131);
  const rtLen = raw.readUInt16BE(131);
  if (raw.length !== 133 + rtLen) return undefined;
  const wrappedRefreshToken = rtLen > 0 ? raw.subarray(133, 133 + rtLen) : undefined;
  return { wrapped, devicePublicKeyDer, wrappedRefreshToken };
}

/** Category 2/3 read path (PDF p.5, steps 2-3.2). */
export async function lookupSek(sessionId: string): Promise<SekLookupResult> {
  try {
    const raw = await redis.getBuffer(redisKey(sessionId));
    if (raw) {
      const parsed = splitCachedValue(raw);
      if (parsed) {
        return {
          status: "found",
          sek: aesUnwrap(requireKek(), parsed.wrapped),
          devicePublicKeyDer: parsed.devicePublicKeyDer,
          refreshToken: parsed.wrappedRefreshToken ? decryptToken(requireKek(), parsed.wrappedRefreshToken) : undefined
        };
      }
      console.warn(`SEK cache entry for session ${sessionId} had unexpected length ${raw.length}, ignoring`);
    }
  } catch (err) {
    console.warn(`SEK Redis read failed for session ${sessionId}, falling back to DB:`, (err as Error).message);
  }

  try {
    const { rows } = await pgPool.query<{
      wrapped_encryption_key: Buffer;
      device_public_key: Buffer;
      wrapped_refresh_token: Buffer | null;
    }>(
      "SELECT wrapped_encryption_key, device_public_key, wrapped_refresh_token FROM session_encryption_key WHERE session_id = $1",
      [sessionId]
    );
    if (rows.length === 0) {
      return { status: "not_found" };
    }

    const { wrapped_encryption_key: wrapped, device_public_key: devicePublicKeyDer, wrapped_refresh_token: wrappedRefreshToken } = rows[0];
    const sek = aesUnwrap(requireKek(), wrapped);

    redis
      .set(redisKey(sessionId), encodeCachedValue(wrapped, devicePublicKeyDer, wrappedRefreshToken ?? undefined), "EX", SEK_TTL_SECONDS)
      .catch((err: Error) => console.warn(`SEK Redis repopulate failed for session ${sessionId}:`, err.message));

    return {
      status: "found",
      sek,
      devicePublicKeyDer,
      refreshToken: wrappedRefreshToken ? decryptToken(requireKek(), wrappedRefreshToken) : undefined
    };
  } catch (err) {
    console.error(`SEK DB read failed for session ${sessionId}:`, (err as Error).message);
    return { status: "db_error" };
  }
}
