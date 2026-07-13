import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { sign, verifySignature } from "../src/sign.js";
import { attest } from "../src/attest.js";
import { canonicalize } from "../src/registry.js";

const CREATED = "2026-07-11T12:00:00Z";
const SECRET = "correct horse battery staple";

function record() {
  return attest("content", { agent: "a1", intent: "w", created: CREATED });
}

test("sign returns a 64-hex HMAC-sha256 digest", () => {
  assert.match(sign(record(), SECRET), /^[0-9a-f]{64}$/);
});

test("sign is deterministic: identical record + secret ⇒ identical signature", () => {
  const r = record();
  assert.equal(sign(r, SECRET), sign(r, SECRET));
});

test("sign matches a hand-computed HMAC over the canonical pre-image", () => {
  const r = record();
  const expected = createHmac("sha256", SECRET).update(canonicalize(r)).digest("hex");
  assert.equal(sign(r, SECRET), expected);
});

test("sign ignores the id and an existing signature in its pre-image", () => {
  const r = record();
  const bare = sign(r, SECRET);
  assert.equal(sign({ ...r, id: "different" }, SECRET), bare);
  assert.equal(sign({ ...r, signature: "abc" }, SECRET), bare);
});

test("round-trip: a record signed and re-attached verifies under the same secret", () => {
  const r = record();
  const signature = sign(r, SECRET);
  assert.equal(verifySignature({ ...r, signature }, SECRET), true);
});

test("verifySignature fails under the wrong secret", () => {
  const r = record();
  const signature = sign(r, SECRET);
  assert.equal(verifySignature({ ...r, signature }, "wrong-secret"), false);
});

test("verifySignature fails when any signed field is tampered", () => {
  const r = record();
  const signature = sign(r, SECRET);
  const forged = { ...r, agent: "impostor", signature };
  assert.equal(verifySignature(forged, SECRET), false);
});

test("verifySignature fails when the signature itself is altered", () => {
  const r = record();
  const signature = sign(r, SECRET);
  // Flip the first hex char.
  const bad = (signature[0] === "0" ? "1" : "0") + signature.slice(1);
  assert.equal(verifySignature({ ...r, signature: bad }, SECRET), false);
});

test("verifySignature is false on a missing / non-string signature", () => {
  const r = record();
  assert.equal(verifySignature(r, SECRET), false);
  assert.equal(verifySignature({ ...r, signature: 123 }, SECRET), false);
  assert.equal(verifySignature({ ...r, signature: "" }, SECRET), false);
});

test("verifySignature is false on a signature of the wrong length", () => {
  const r = record();
  assert.equal(verifySignature({ ...r, signature: "abcd" }, SECRET), false);
});

test("verifySignature is false on a null/undefined record", () => {
  assert.equal(verifySignature(null, SECRET), false);
  assert.equal(verifySignature(undefined, SECRET), false);
});
