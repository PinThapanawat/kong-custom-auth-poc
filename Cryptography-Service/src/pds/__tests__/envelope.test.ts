import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  encodeSignedRequestEnvelope,
  decodeSignedRequestEnvelope,
  encodeSignedResponseEnvelope,
  decodeSignedResponseEnvelope,
  verifyEnvelopeSignature,
  RESPONSE_STRUCTURE_TYPE_STANDARD,
  RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING
} from "../envelope";

function genKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

test("request envelope round-trips and verifies", () => {
  const { publicKey, privateKey } = genKeyPair();
  const original = {
    requestTimestampMs: BigInt(Date.now()),
    apiId: 42,
    requestUniqueId: "abc-123-def-456",
    originalRequestPayload: Buffer.from(JSON.stringify({ to: "ACC1", amount: 100 }))
  };

  const encoded = encodeSignedRequestEnvelope(original, privateKey);
  const decoded = decodeSignedRequestEnvelope(encoded);

  assert.equal(decoded.requestStructureType, 0x00);
  assert.equal(decoded.requestTimestampMs, original.requestTimestampMs);
  assert.equal(decoded.apiId, original.apiId);
  assert.equal(decoded.requestUniqueId, original.requestUniqueId);
  assert.ok(decoded.originalRequestPayload.equals(original.originalRequestPayload));
  assert.ok(verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, publicKey));
});

test("request envelope with empty requestUniqueId and empty payload", () => {
  const { privateKey } = genKeyPair();
  const encoded = encodeSignedRequestEnvelope(
    { requestTimestampMs: 0n, apiId: 1, requestUniqueId: "", originalRequestPayload: Buffer.alloc(0) },
    privateKey
  );
  const decoded = decodeSignedRequestEnvelope(encoded);
  assert.equal(decoded.requestUniqueId, "");
  assert.equal(decoded.originalRequestPayload.length, 0);
});

test("standard response envelope (0x00) round-trips", () => {
  const { publicKey, privateKey } = genKeyPair();
  const original = {
    responseStructureType: RESPONSE_STRUCTURE_TYPE_STANDARD,
    responseTimestampMs: BigInt(Date.now()),
    requestUniqueId: "req-1",
    originalResponsePayload: Buffer.from(JSON.stringify({ status: "ok" }))
  };

  const encoded = encodeSignedResponseEnvelope(original, privateKey);
  const decoded = decodeSignedResponseEnvelope(encoded);

  assert.equal(decoded.responseStructureType, 0x00);
  assert.equal(decoded.responseTimestampMs, original.responseTimestampMs);
  assert.equal(decoded.requestUniqueId, original.requestUniqueId);
  if (decoded.responseStructureType === RESPONSE_STRUCTURE_TYPE_STANDARD) {
    assert.ok(decoded.originalResponsePayload.equals(original.originalResponsePayload));
  } else {
    assert.fail("expected standard response structure type");
  }
  assert.ok(verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, publicKey));
});

test("session-acquiring response envelope (0x01) embeds a 32-byte SEK", () => {
  const { publicKey, privateKey } = genKeyPair();
  const sek = crypto.randomBytes(32);
  const original = {
    responseStructureType: RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING,
    responseTimestampMs: BigInt(Date.now()),
    sessionEncryptionKey: sek,
    requestUniqueId: "req-2",
    originalResponsePayload: Buffer.from(JSON.stringify({ sessionJwt: "header.payload.sig" }))
  };

  const encoded = encodeSignedResponseEnvelope(original, privateKey);
  const decoded = decodeSignedResponseEnvelope(encoded);

  assert.equal(decoded.responseStructureType, 0x01);
  if (decoded.responseStructureType === RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING) {
    assert.ok(decoded.sessionEncryptionKey.equals(sek));
    assert.equal(decoded.sessionEncryptionKey.length, 32);
  } else {
    assert.fail("expected session-acquiring response structure type");
  }
  assert.ok(verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, publicKey));
});

test("rejects a sessionEncryptionKey that is not exactly 32 bytes", () => {
  const { privateKey } = genKeyPair();
  assert.throws(() =>
    encodeSignedResponseEnvelope(
      {
        responseStructureType: RESPONSE_STRUCTURE_TYPE_SESSION_ACQUIRING,
        responseTimestampMs: 0n,
        sessionEncryptionKey: Buffer.alloc(16),
        requestUniqueId: "x",
        originalResponsePayload: Buffer.alloc(0)
      },
      privateKey
    )
  );
});

test("flipped byte in the signed region fails signature verification", () => {
  const { publicKey, privateKey } = genKeyPair();
  const encoded = encodeSignedRequestEnvelope(
    {
      requestTimestampMs: BigInt(Date.now()),
      apiId: 7,
      requestUniqueId: "tamper-test",
      originalRequestPayload: Buffer.from("original payload")
    },
    privateKey
  );

  // Flip one byte inside originalRequestPayload (well past the signature+header).
  const tampered = Buffer.from(encoded);
  const flipIndex = tampered.length - 1;
  tampered[flipIndex] = tampered[flipIndex] ^ 0xff;

  const decoded = decodeSignedRequestEnvelope(tampered);
  assert.equal(verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, publicKey), false);
});

test("signature does not verify against a different device's public key", () => {
  const deviceA = genKeyPair();
  const deviceB = genKeyPair();
  const encoded = encodeSignedRequestEnvelope(
    {
      requestTimestampMs: BigInt(Date.now()),
      apiId: 1,
      requestUniqueId: "req-x",
      originalRequestPayload: Buffer.from("payload")
    },
    deviceA.privateKey
  );
  const decoded = decodeSignedRequestEnvelope(encoded);
  assert.equal(verifyEnvelopeSignature(decoded.signedRegion, decoded.signature, deviceB.publicKey), false);
});

test("envelope truncated inside the fixed header throws instead of reading out of bounds", () => {
  const { privateKey } = genKeyPair();
  const encoded = encodeSignedRequestEnvelope(
    {
      requestTimestampMs: BigInt(Date.now()),
      apiId: 1,
      requestUniqueId: "abcdef",
      originalRequestPayload: Buffer.from("payload")
    },
    privateKey
  );
  // Cut off partway through the fixed-size header fields (well before
  // requestUniqueId/originalRequestPayload, which are legitimately
  // variable-length) so this can only be truncation, not a short payload.
  const truncated = encoded.subarray(0, 10);
  assert.throws(() => decodeSignedRequestEnvelope(truncated));
});

test("declared requestUniqueId length longer than the remaining buffer throws", () => {
  const { privateKey } = genKeyPair();
  const encoded = encodeSignedRequestEnvelope(
    {
      requestTimestampMs: BigInt(Date.now()),
      apiId: 1,
      requestUniqueId: "abcdef",
      originalRequestPayload: Buffer.from("payload")
    },
    privateKey
  );
  // Truncate right after the requestUniqueIdLength byte, so the decoder
  // believes 6 bytes of requestUniqueId follow but none actually do. Read
  // the real signature length from the header rather than assuming a fixed
  // DER size (P-256 ECDSA signatures vary between 70 and 72 bytes).
  const sigLen = encoded.readUInt16BE(0);
  const requestUniqueIdLengthOffset = 2 + sigLen + 1 + 8 + 4;
  const truncated = encoded.subarray(0, requestUniqueIdLengthOffset + 1);
  assert.throws(() => decodeSignedRequestEnvelope(truncated));
});
