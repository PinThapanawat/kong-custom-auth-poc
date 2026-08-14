import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { encryptToken, decryptToken } from "../tokenCrypto";

test("decryptToken(encryptToken(x)) round-trips", () => {
  const kek = crypto.randomBytes(32);
  const token = "a-fake-refresh-token-that-is-not-a-multiple-of-8-bytes";
  const blob = encryptToken(kek, token);
  assert.equal(decryptToken(kek, blob), token);
});

test("decrypt fails with the wrong KEK", () => {
  const kek = crypto.randomBytes(32);
  const wrongKek = crypto.randomBytes(32);
  const blob = encryptToken(kek, "some-refresh-token");
  assert.throws(() => decryptToken(wrongKek, blob));
});

test("decrypt fails if ciphertext is tampered with", () => {
  const kek = crypto.randomBytes(32);
  const blob = encryptToken(kek, "some-refresh-token");
  blob[blob.length - 1] ^= 0xff;
  assert.throws(() => decryptToken(kek, blob));
});
