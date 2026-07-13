import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { computeHash } from "../src/hash.js";
import { canonicalize, computeRecordId } from "../src/registry.js";

// --- computeHash -----------------------------------------------------------

test("computeHash returns a 64-hex sha256 digest", () => {
  assert.match(computeHash("hello"), /^[0-9a-f]{64}$/);
});

test("computeHash matches the canonical sha256 of the UTF-8 bytes", () => {
  const expected = createHash("sha256").update("hello world").digest("hex");
  assert.equal(computeHash("hello world"), expected);
});

test("computeHash is deterministic: identical content ⇒ identical digest", () => {
  assert.equal(computeHash("abc"), computeHash("abc"));
});

test("computeHash: different content ⇒ different digest", () => {
  assert.notEqual(computeHash("abc"), computeHash("abd"));
  assert.notEqual(computeHash("abc"), computeHash("ABC"));
});

test("computeHash hashes a string and its UTF-8 Buffer identically", () => {
  assert.equal(computeHash("café"), computeHash(Buffer.from("café", "utf8")));
});

test("computeHash of empty content is the well-known empty sha256", () => {
  assert.equal(
    computeHash(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
});

test("computeHash on raw Buffer bytes", () => {
  const buf = Buffer.from([0x00, 0x01, 0x02, 0xff]);
  assert.equal(computeHash(buf), createHash("sha256").update(buf).digest("hex"));
});

// --- canonicalize ----------------------------------------------------------

test("canonicalize excludes the id field", () => {
  const base = { agent: "a1", artifact: "x" };
  assert.equal(canonicalize({ ...base, id: "anything" }), canonicalize(base));
});

test("canonicalize sorts keys at every depth (order-independent)", () => {
  const a = { b: 1, a: 2, nested: { z: 1, y: 2 } };
  const b = { a: 2, nested: { y: 2, z: 1 }, b: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
});

test("canonicalize preserves array element order", () => {
  assert.notEqual(canonicalize({ parents: ["a", "b"] }), canonicalize({ parents: ["b", "a"] }));
});

// --- computeRecordId -------------------------------------------------------

test("computeRecordId is a 64-hex digest, deterministic + key-order-independent", () => {
  const a = { type: "attestation", agent: "a1", intent: "w" };
  const b = { intent: "w", agent: "a1", type: "attestation" };
  assert.match(computeRecordId(a), /^[0-9a-f]{64}$/);
  assert.equal(computeRecordId(a), computeRecordId(b));
});

test("computeRecordId ignores the id field (id IS the content hash)", () => {
  const base = { agent: "a1", intent: "w" };
  assert.equal(computeRecordId({ ...base, id: "xyz" }), computeRecordId(base));
});

test("changing any content field changes the record id", () => {
  const base = computeRecordId({ agent: "a1", artifact: "x", intent: "w" });
  assert.notEqual(computeRecordId({ agent: "a2", artifact: "x", intent: "w" }), base);
  assert.notEqual(computeRecordId({ agent: "a1", artifact: "y", intent: "w" }), base);
  assert.notEqual(computeRecordId({ agent: "a1", artifact: "x", intent: "z" }), base);
});

test("computeRecordId equals sha256 of the canonical pre-image", () => {
  const rec = { type: "attestation", agent: "a1", intent: "w" };
  const expected = createHash("sha256").update(canonicalize(rec)).digest("hex");
  assert.equal(computeRecordId(rec), expected);
});
