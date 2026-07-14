import { test } from "node:test";
import assert from "node:assert/strict";
import { verify as cryptoVerify } from "node:crypto";
import { generateKeypair, signAsym, verifyAsym } from "../src/sign-asym.js";
import { attest } from "../src/attest.js";
import { canonicalize } from "../src/registry.js";

const CREATED = "2026-07-11T12:00:00Z";

function record() {
  return attest("content", { agent: "a1", intent: "w", created: CREATED });
}

// A keypair shared by most tests (generation is covered on its own below).
const KEYS = generateKeypair();

// --- generateKeypair -------------------------------------------------------

test("generateKeypair returns SPKI/PKCS#8 PEM strings", () => {
  const { publicKey, privateKey } = generateKeypair();
  assert.equal(typeof publicKey, "string");
  assert.equal(typeof privateKey, "string");
  assert.match(publicKey, /^-----BEGIN PUBLIC KEY-----/);
  assert.match(privateKey, /^-----BEGIN PRIVATE KEY-----/);
});

test("generateKeypair yields a fresh, distinct keypair each call", () => {
  const k1 = generateKeypair();
  const k2 = generateKeypair();
  assert.notEqual(k1.privateKey, k2.privateKey);
  assert.notEqual(k1.publicKey, k2.publicKey);
});

// --- signAsym --------------------------------------------------------------

test("signAsym returns a hex string signature", () => {
  const sig = signAsym(record(), KEYS.privateKey);
  assert.match(sig, /^[0-9a-f]+$/);
  // ed25519 signatures are 64 bytes → 128 hex chars.
  assert.equal(sig.length, 128);
});

test("signAsym is deterministic: identical record + key ⇒ identical signature", () => {
  const r = record();
  assert.equal(signAsym(r, KEYS.privateKey), signAsym(r, KEYS.privateKey));
});

test("signAsym signs the canonical pre-image (id and signature excluded)", () => {
  const r = record();
  const bare = signAsym(r, KEYS.privateKey);
  // Neither the id nor an attached signature perturbs the signed payload.
  assert.equal(signAsym({ ...r, id: "different" }, KEYS.privateKey), bare);
  assert.equal(signAsym({ ...r, signature: "abc" }, KEYS.privateKey), bare);
});

test("signAsym signature verifies with node:crypto directly over the pre-image", () => {
  const r = record();
  const sig = signAsym(r, KEYS.privateKey);
  const { id: _id, ...rest } = r;
  const ok = cryptoVerify(null, Buffer.from(canonicalize(rest)), KEYS.publicKey, Buffer.from(sig, "hex"));
  assert.equal(ok, true);
});

test("signAsym throws on a missing / invalid private key", () => {
  assert.throws(() => signAsym(record(), null), /privateKeyPem/);
  assert.throws(() => signAsym(record(), ""), /privateKeyPem/);
});

// --- verifyAsym (detached form) --------------------------------------------

test("round-trip (detached): sign then verify with the matching public key", () => {
  const r = record();
  const sig = signAsym(r, KEYS.privateKey);
  assert.equal(verifyAsym(r, KEYS.publicKey, sig), true);
});

test("verifyAsym fails under the wrong public key", () => {
  const r = record();
  const sig = signAsym(r, KEYS.privateKey);
  const other = generateKeypair();
  assert.equal(verifyAsym(r, other.publicKey, sig), false);
});

test("verifyAsym fails when any signed field is tampered", () => {
  const r = record();
  const sig = signAsym(r, KEYS.privateKey);
  const forged = { ...r, agent: "impostor" };
  assert.equal(verifyAsym(forged, KEYS.publicKey, sig), false);
});

test("verifyAsym fails when the signature itself is altered", () => {
  const r = record();
  const sig = signAsym(r, KEYS.privateKey);
  const bad = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  assert.equal(verifyAsym(r, KEYS.publicKey, bad), false);
});

test("verifyAsym is false on a malformed / short signature rather than throwing", () => {
  const r = record();
  assert.doesNotThrow(() => verifyAsym(r, KEYS.publicKey, "abcd"));
  assert.equal(verifyAsym(r, KEYS.publicKey, "abcd"), false);
  assert.equal(verifyAsym(r, KEYS.publicKey, "not-hex-zz"), false);
});

// --- verifyAsym (embedded form) --------------------------------------------

test("round-trip (embedded): a record carrying its own signature verifies", () => {
  const r = record();
  const signature = signAsym(r, KEYS.privateKey);
  const signed = { ...r, signature };
  assert.equal(verifyAsym(signed, KEYS.publicKey), true);
});

test("embedded and detached forms agree on the same record", () => {
  const r = record();
  const signature = signAsym(r, KEYS.privateKey);
  assert.equal(verifyAsym({ ...r, signature }, KEYS.publicKey), verifyAsym(r, KEYS.publicKey, signature));
});

test("verifyAsym (embedded) fails when a signed field is tampered after signing", () => {
  const r = record();
  const signature = signAsym(r, KEYS.privateKey);
  const forged = { ...r, agent: "impostor", signature };
  assert.equal(verifyAsym(forged, KEYS.publicKey), false);
});

test("verifyAsym is false on a missing / non-string embedded signature", () => {
  const r = record();
  assert.equal(verifyAsym(r, KEYS.publicKey), false);
  assert.equal(verifyAsym({ ...r, signature: 123 }, KEYS.publicKey), false);
  assert.equal(verifyAsym({ ...r, signature: "" }, KEYS.publicKey), false);
});

test("verifyAsym is false on a missing / invalid public key", () => {
  const r = record();
  const sig = signAsym(r, KEYS.privateKey);
  assert.equal(verifyAsym(r, null, sig), false);
  assert.equal(verifyAsym(r, "", sig), false);
  assert.equal(verifyAsym(r, "-----BEGIN PUBLIC KEY-----\nnonsense\n-----END PUBLIC KEY-----", sig), false);
});
