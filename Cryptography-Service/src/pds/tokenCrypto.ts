import * as crypto from "node:crypto";

// AES-256-GCM encryption for the Keycloak refresh token persisted per
// session (see sekStore.ts). Unlike the SEK, a refresh token is an
// arbitrary-length string, not a 32-byte key, so RFC 3394 key wrap
// (aesWrap.ts) doesn't apply here — GCM handles arbitrary-length plaintext
// and gives us authentication too. Reuses the same Vault-held KEK as the
// SEK wrap since both protect the same session record.

const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export function encryptToken(kek: Buffer, plaintext: string): Buffer {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", kek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

export function decryptToken(kek: Buffer, blob: Buffer): string {
  if (blob.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error(`encrypted token blob too short: ${blob.length} bytes`);
  }
  const iv = blob.subarray(0, IV_LENGTH);
  const authTag = blob.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = blob.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv("aes-256-gcm", kek, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
