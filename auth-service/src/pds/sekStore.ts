import * as crypto from "node:crypto";
import { aesWrap, aesUnwrap } from "./aesWrap";
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
 */
export async function storeSek(sessionId: string, sek: Buffer, devicePublicKeyDer: Buffer): Promise<void> {
  if (sek.length !== 32) {
    throw new Error(`SEK must be exactly 32 bytes, got ${sek.length}`);
  }
  if (devicePublicKeyDer.length !== 91) {
    throw new Error(`device public key DER must be exactly 91 bytes, got ${devicePublicKeyDer.length}`);
  }

  const wrapped = aesWrap(requireKek(), sek); // 40 bytes
  await pgPool.query(
    `INSERT INTO session_encryption_key (session_id, wrapped_encryption_key, device_public_key, expiration_bucket)
     VALUES ($1, $2, $3, $4)`,
    [sessionId, wrapped, devicePublicKeyDer, currentHourBucketUTC()]
  );

  try {
    await redis.set(redisKey(sessionId), Buffer.concat([wrapped, devicePublicKeyDer]), "EX", SEK_TTL_SECONDS);
  } catch (err) {
    console.warn(`SEK Redis write skipped for session ${sessionId} (Redis unavailable):`, (err as Error).message);
  }
}

export type SekLookupResult =
  | { status: "found"; sek: Buffer; devicePublicKeyDer: Buffer }
  | { status: "not_found" } // -> 401 plaintext (PDF p.5 step 3.2)
  | { status: "db_error" }; // -> 500 plaintext (PDF p.5 step 3.1)

function splitCachedValue(raw: Buffer): { wrapped: Buffer; devicePublicKeyDer: Buffer } | undefined {
  if (raw.length !== 131) return undefined;
  return { wrapped: raw.subarray(0, 40), devicePublicKeyDer: raw.subarray(40, 131) };
}

/** Category 2/3 read path (PDF p.5, steps 2-3.2). */
export async function lookupSek(sessionId: string): Promise<SekLookupResult> {
  try {
    const raw = await redis.getBuffer(redisKey(sessionId));
    if (raw) {
      const parsed = splitCachedValue(raw);
      if (parsed) {
        return { status: "found", sek: aesUnwrap(requireKek(), parsed.wrapped), devicePublicKeyDer: parsed.devicePublicKeyDer };
      }
      console.warn(`SEK cache entry for session ${sessionId} had unexpected length ${raw.length}, ignoring`);
    }
  } catch (err) {
    console.warn(`SEK Redis read failed for session ${sessionId}, falling back to DB:`, (err as Error).message);
  }

  try {
    const { rows } = await pgPool.query<{ wrapped_encryption_key: Buffer; device_public_key: Buffer }>(
      "SELECT wrapped_encryption_key, device_public_key FROM session_encryption_key WHERE session_id = $1",
      [sessionId]
    );
    if (rows.length === 0) {
      return { status: "not_found" };
    }

    const { wrapped_encryption_key: wrapped, device_public_key: devicePublicKeyDer } = rows[0];
    const sek = aesUnwrap(requireKek(), wrapped);

    redis
      .set(redisKey(sessionId), Buffer.concat([wrapped, devicePublicKeyDer]), "EX", SEK_TTL_SECONDS)
      .catch((err: Error) => console.warn(`SEK Redis repopulate failed for session ${sessionId}:`, err.message));

    return { status: "found", sek, devicePublicKeyDer };
  } catch (err) {
    console.error(`SEK DB read failed for session ${sessionId}:`, (err as Error).message);
    return { status: "db_error" };
  }
}
