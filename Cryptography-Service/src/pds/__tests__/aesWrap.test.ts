import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { aesWrap, aesUnwrap } from "../aesWrap";

test("aesWrap produces exactly 40 bytes for a 32-byte key", () => {
  const kek = crypto.randomBytes(32);
  const sek = crypto.randomBytes(32);
  const wrapped = aesWrap(kek, sek);
  assert.equal(wrapped.length, 40);
});

test("aesUnwrap(aesWrap(x)) round-trips", () => {
  const kek = crypto.randomBytes(32);
  const sek = crypto.randomBytes(32);
  const wrapped = aesWrap(kek, sek);
  const unwrapped = aesUnwrap(kek, wrapped);
  assert.ok(unwrapped.equals(sek));
});

test("unwrap fails with the wrong KEK", () => {
  const kek = crypto.randomBytes(32);
  const wrongKek = crypto.randomBytes(32);
  const sek = crypto.randomBytes(32);
  const wrapped = aesWrap(kek, sek);
  assert.throws(() => aesUnwrap(wrongKek, wrapped));
});
