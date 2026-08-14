import * as crypto from "node:crypto";

// RFC 3394 AES Key Wrap, used to wrap the per-session AES-256 Session
// Encryption Key (SEK) before it's stored in Postgres (`WrappedEncryptionKey
// BINARY(40)` per requirement PDF p.12). Node's OpenSSL binding implements
// this natively as the "id-aes256-wrap" cipher — confirmed available both
// on host Node and inside the `node:22-alpine` image this service builds on,
// so no hand-rolled fallback or extra dependency is needed.

const RFC3394_DEFAULT_IV = Buffer.from("A6A6A6A6A6A6A6A6", "hex"); // RFC 3394 §2.2.3.1

export function aesWrap(kek: Buffer, key: Buffer): Buffer {
  const cipher = crypto.createCipheriv("id-aes256-wrap", kek, RFC3394_DEFAULT_IV);
  return Buffer.concat([cipher.update(key), cipher.final()]);
}

export function aesUnwrap(kek: Buffer, wrapped: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("id-aes256-wrap", kek, RFC3394_DEFAULT_IV);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}
