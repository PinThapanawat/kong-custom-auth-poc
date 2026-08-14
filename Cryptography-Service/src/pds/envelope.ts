import * as crypto from "node:crypto";

// Signed binary envelope framing, per requirement PDF pp.8-11 ("Payload
// structure"). Every request/response payload is wrapped in this binary
// structure *before* JWE encryption (request) / *after* JWE decryption
// (response is the reverse: JWE decrypt first, then parse this envelope).
//
// This service (the PDS) primarily decodes requests it receives and encodes
// responses it sends. `client-simulator/src/envelope.ts` is the mirror
// image. Both directions are implemented in each file (not just the
// "primary" one) so each side can be unit-tested with self-contained
// round-trip tests, without a shared package — this repo has no monorepo
// tooling and each service builds independently.

export const REQUEST_STRUCTURE_TYPE_V1 = 0x00 as const;
export const RESPONSE_STRUCTURE_TYPE_STANDARD = 0x00 as const;
export const RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING = 0x01 as const;

const SIGN_ALGORITHM = "sha256"; // ECDSA P-256 + SHA-256, i.e. ES256

export interface DecodedRequestEnvelope {
  requestStructureType: number;
  requestTimestampMs: bigint;
  apiId: number;
  requestUniqueId: string;
  originalRequestPayload: Buffer;
  signature: Buffer;
  signedRegion: Buffer;
}

export interface EncodeRequestFields {
  requestTimestampMs: bigint;
  apiId: number;
  requestUniqueId: string;
  originalRequestPayload: Buffer;
}

export type DecodedResponseEnvelope =
  | {
      responseStructureType: typeof RESPONSE_STRUCTURE_TYPE_STANDARD;
      responseTimestampMs: bigint;
      requestUniqueId: string;
      originalResponsePayload: Buffer;
      signature: Buffer;
      signedRegion: Buffer;
    }
  | {
      responseStructureType: typeof RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING;
      responseTimestampMs: bigint;
      sessionEncryptionKey: Buffer; // exactly 32 bytes
      requestUniqueId: string;
      originalResponsePayload: Buffer;
      signature: Buffer;
      signedRegion: Buffer;
    };

export type EncodeResponseFields =
  | {
      responseStructureType: typeof RESPONSE_STRUCTURE_TYPE_STANDARD;
      responseTimestampMs: bigint;
      requestUniqueId: string;
      originalResponsePayload: Buffer;
    }
  | {
      responseStructureType: typeof RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING;
      responseTimestampMs: bigint;
      sessionEncryptionKey: Buffer; // exactly 32 bytes
      requestUniqueId: string;
      originalResponsePayload: Buffer;
    };

export function signEnvelope(signedRegion: Buffer, privateKey: crypto.KeyObject): Buffer {
  return crypto.sign(SIGN_ALGORITHM, signedRegion, { key: privateKey, dsaEncoding: "der" });
}

export function verifyEnvelopeSignature(
  signedRegion: Buffer,
  signature: Buffer,
  publicKey: crypto.KeyObject
): boolean {
  try {
    return crypto.verify(SIGN_ALGORITHM, signedRegion, { key: publicKey, dsaEncoding: "der" }, signature);
  } catch {
    return false;
  }
}

function encodeRequestUniqueId(requestUniqueId: string): Buffer {
  const idBuf = Buffer.from(requestUniqueId, "utf8");
  if (idBuf.length > 255) {
    throw new Error(`requestUniqueId too long (${idBuf.length} bytes, max 255)`);
  }
  const lenBuf = Buffer.alloc(1);
  lenBuf.writeUInt8(idBuf.length, 0);
  return Buffer.concat([lenBuf, idBuf]);
}

/** Builds the signed region + prepends {signatureLength}{signature}. */
function withSignature(signedRegion: Buffer, privateKey: crypto.KeyObject): Buffer {
  const signature = signEnvelope(signedRegion, privateKey);
  if (signature.length > 0xffff) {
    throw new Error(`signature too long (${signature.length} bytes)`);
  }
  const sigLenBuf = Buffer.alloc(2);
  sigLenBuf.writeUInt16BE(signature.length, 0);
  return Buffer.concat([sigLenBuf, signature, signedRegion]);
}

/** Splits {signatureLength}{signature}{signedRegion} into its parts. */
function splitSignature(buf: Buffer): { signature: Buffer; signedRegion: Buffer } {
  if (buf.length < 2) {
    throw new Error("envelope too short to contain signatureLength");
  }
  const sigLen = buf.readUInt16BE(0);
  if (buf.length < 2 + sigLen) {
    throw new Error("envelope too short to contain declared signature");
  }
  const signature = buf.subarray(2, 2 + sigLen);
  const signedRegion = buf.subarray(2 + sigLen);
  return { signature, signedRegion };
}

// ---- Request envelope ----

export function encodeSignedRequestEnvelope(fields: EncodeRequestFields, privateKey: crypto.KeyObject): Buffer {
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(fields.requestTimestampMs, 0);

  const apiIdBuf = Buffer.alloc(4);
  apiIdBuf.writeUInt32BE(fields.apiId, 0);

  const signedRegion = Buffer.concat([
    Buffer.from([REQUEST_STRUCTURE_TYPE_V1]),
    tsBuf,
    apiIdBuf,
    encodeRequestUniqueId(fields.requestUniqueId),
    fields.originalRequestPayload
  ]);

  return withSignature(signedRegion, privateKey);
}

export function decodeSignedRequestEnvelope(buf: Buffer): DecodedRequestEnvelope {
  const { signature, signedRegion } = splitSignature(buf);

  if (signedRegion.length < 1 + 8 + 4 + 1) {
    throw new Error("request envelope too short");
  }

  let offset = 0;
  const requestStructureType = signedRegion.readUInt8(offset);
  offset += 1;

  const requestTimestampMs = signedRegion.readBigUInt64BE(offset);
  offset += 8;

  const apiId = signedRegion.readUInt32BE(offset);
  offset += 4;

  const requestUniqueIdLength = signedRegion.readUInt8(offset);
  offset += 1;

  if (signedRegion.length < offset + requestUniqueIdLength) {
    throw new Error("request envelope too short for declared requestUniqueId");
  }
  const requestUniqueId = signedRegion.subarray(offset, offset + requestUniqueIdLength).toString("utf8");
  offset += requestUniqueIdLength;

  const originalRequestPayload = signedRegion.subarray(offset);

  return {
    requestStructureType,
    requestTimestampMs,
    apiId,
    requestUniqueId,
    originalRequestPayload,
    signature,
    signedRegion
  };
}

// ---- Response envelope ----

export function encodeSignedResponseEnvelope(fields: EncodeResponseFields, privateKey: crypto.KeyObject): Buffer {
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(fields.responseTimestampMs, 0);

  const parts: Buffer[] = [Buffer.from([fields.responseStructureType]), tsBuf];

  if (fields.responseStructureType === RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING) {
    if (fields.sessionEncryptionKey.length !== 32) {
      throw new Error(`sessionEncryptionKey must be exactly 32 bytes, got ${fields.sessionEncryptionKey.length}`);
    }
    parts.push(fields.sessionEncryptionKey);
  }

  parts.push(encodeRequestUniqueId(fields.requestUniqueId));
  parts.push(fields.originalResponsePayload);

  const signedRegion = Buffer.concat(parts);
  return withSignature(signedRegion, privateKey);
}

export function decodeSignedResponseEnvelope(buf: Buffer): DecodedResponseEnvelope {
  const { signature, signedRegion } = splitSignature(buf);

  if (signedRegion.length < 1 + 8 + 1) {
    throw new Error("response envelope too short");
  }

  let offset = 0;
  const responseStructureType = signedRegion.readUInt8(offset);
  offset += 1;

  const responseTimestampMs = signedRegion.readBigUInt64BE(offset);
  offset += 8;

  if (responseStructureType === RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING) {
    if (signedRegion.length < offset + 32 + 1) {
      throw new Error("response envelope too short for sessionEncryptionKey");
    }
    const sessionEncryptionKey = signedRegion.subarray(offset, offset + 32);
    offset += 32;

    const requestUniqueIdLength = signedRegion.readUInt8(offset);
    offset += 1;
    if (signedRegion.length < offset + requestUniqueIdLength) {
      throw new Error("response envelope too short for declared requestUniqueId");
    }
    const requestUniqueId = signedRegion.subarray(offset, offset + requestUniqueIdLength).toString("utf8");
    offset += requestUniqueIdLength;

    const originalResponsePayload = signedRegion.subarray(offset);

    return {
      responseStructureType,
      responseTimestampMs,
      sessionEncryptionKey,
      requestUniqueId,
      originalResponsePayload,
      signature,
      signedRegion
    };
  }

  if (responseStructureType !== RESPONSE_STRUCTURE_TYPE_STANDARD) {
    throw new Error(`unsupported responseStructureType 0x${responseStructureType.toString(16)}`);
  }

  const requestUniqueIdLength = signedRegion.readUInt8(offset);
  offset += 1;
  if (signedRegion.length < offset + requestUniqueIdLength) {
    throw new Error("response envelope too short for declared requestUniqueId");
  }
  const requestUniqueId = signedRegion.subarray(offset, offset + requestUniqueIdLength).toString("utf8");
  offset += requestUniqueIdLength;

  const originalResponsePayload = signedRegion.subarray(offset);

  return {
    responseStructureType,
    responseTimestampMs,
    requestUniqueId,
    originalResponsePayload,
    signature,
    signedRegion
  };
}
