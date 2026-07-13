import { test } from "node:test";
import assert from "node:assert/strict";
import { attest, revoke } from "../src/attest.js";
import { computeHash } from "../src/hash.js";
import { computeRecordId } from "../src/registry.js";
import { validateAttestation, validateRevocation } from "../src/schema.js";

const CREATED = "2026-07-11T12:00:00Z";
const HEX = "a".repeat(64);
const HEX2 = "b".repeat(64);

// --- attest ----------------------------------------------------------------

test("attest(string, …) hashes the content into `artifact` and builds a valid record", () => {
  const r = attest("hello world", { agent: "claude", intent: "greet", created: CREATED });
  assert.equal(r.type, "attestation");
  assert.equal(r.agent, "claude");
  assert.equal(r.intent, "greet");
  assert.equal(r.created, CREATED);
  assert.deepEqual(r.parents, []);
  assert.equal(r.artifact, computeHash("hello world"));
  assert.equal(validateAttestation(r).valid, true);
});

test("attest sets id to the record's content hash (id === computeRecordId)", () => {
  const r = attest("x", { agent: "a", intent: "i", created: CREATED });
  assert.equal(r.id, computeRecordId(r));
  assert.match(r.id, /^[0-9a-f]{64}$/);
});

test("attest is deterministic over its inputs (pure, injected clock)", () => {
  const a = attest("same", { agent: "a", intent: "i", created: CREATED });
  const b = attest("same", { agent: "a", intent: "i", created: CREATED });
  assert.equal(a.id, b.id);
});

test("attest accepts a Buffer and hashes its bytes like the string form", () => {
  const s = attest("café", { agent: "a", intent: "i", created: CREATED });
  const b = attest(Buffer.from("café", "utf8"), { agent: "a", intent: "i", created: CREATED });
  assert.equal(s.artifact, b.artifact);
  assert.equal(s.id, b.id);
});

test("attest accepts a pre-computed { hash } and uses it verbatim", () => {
  const hash = computeHash("hello world");
  const r = attest({ hash }, { agent: "a", intent: "i", created: CREATED });
  assert.equal(r.artifact, hash);
  // Same artifact + fields as hashing the raw content directly.
  const direct = attest("hello world", { agent: "a", intent: "i", created: CREATED });
  assert.equal(r.id, direct.id);
});

test("attest with { hash } rejects a non-sha256 hash", () => {
  assert.throws(
    () => attest({ hash: "not-a-hash" }, { agent: "a", intent: "i", created: CREATED }),
    /sha256/
  );
});

test("attest records parents (copied, not aliased)", () => {
  const parents = [HEX, HEX2];
  const r = attest("x", { agent: "a", intent: "i", parents, created: CREATED });
  assert.deepEqual(r.parents, [HEX, HEX2]);
  parents.push("mutated");
  assert.deepEqual(r.parents, [HEX, HEX2], "the record's parents are a copy");
});

test("attest carries an optional meta object", () => {
  const r = attest("x", {
    agent: "a",
    intent: "i",
    created: CREATED,
    meta: { harness: "git", commit: "deadbeef" },
  });
  assert.deepEqual(r.meta, { harness: "git", commit: "deadbeef" });
  assert.equal(validateAttestation(r).valid, true);
});

test("attest omits meta entirely when not given", () => {
  const r = attest("x", { agent: "a", intent: "i", created: CREATED });
  assert.ok(!("meta" in r));
});

test("attest throws on a missing/empty agent", () => {
  assert.throws(() => attest("x", { intent: "i", created: CREATED }), /agent/);
  assert.throws(() => attest("x", { agent: "  ", intent: "i", created: CREATED }), /agent/);
});

test("attest throws on a missing/empty intent", () => {
  assert.throws(() => attest("x", { agent: "a", created: CREATED }), /intent/);
  assert.throws(() => attest("x", { agent: "a", intent: "", created: CREATED }), /intent/);
});

test("attest throws on an invalid created timestamp", () => {
  assert.throws(() => attest("x", { agent: "a", intent: "i", created: "not-a-date" }), /created/);
  assert.throws(() => attest("x", { agent: "a", intent: "i", created: "2026-07-11T12:00:00+00:00" }), /created/);
  assert.throws(() => attest("x", { agent: "a", intent: "i" }), /created/);
});

test("attest throws when a parent is not an attestation id", () => {
  assert.throws(
    () => attest("x", { agent: "a", intent: "i", parents: ["bad"], created: CREATED }),
    /parent/
  );
});

test("attest throws when parents is not an array", () => {
  assert.throws(
    () => attest("x", { agent: "a", intent: "i", parents: "x", created: CREATED }),
    /parents/
  );
});

test("attest throws when meta is not an object", () => {
  assert.throws(
    () => attest("x", { agent: "a", intent: "i", created: CREATED, meta: [] }),
    /meta/
  );
});

test("attest throws on an artifact that is neither content nor { hash }", () => {
  assert.throws(() => attest(42, { agent: "a", intent: "i", created: CREATED }), /artifact/);
  assert.throws(() => attest({}, { agent: "a", intent: "i", created: CREATED }), /artifact/);
});

// --- revoke ----------------------------------------------------------------

test("revoke builds a valid revocation record with a content-hash id", () => {
  const r = revoke(HEX, { agent: "a", reason: "superseded", at: CREATED });
  assert.equal(r.type, "revocation");
  assert.equal(r.attestation_id, HEX);
  assert.equal(r.agent, "a");
  assert.equal(r.reason, "superseded");
  assert.equal(r.at, CREATED);
  assert.equal(r.id, computeRecordId(r));
  assert.equal(validateRevocation(r).valid, true);
});

test("revoke is deterministic over its inputs", () => {
  const a = revoke(HEX, { agent: "a", reason: "r", at: CREATED });
  const b = revoke(HEX, { agent: "a", reason: "r", at: CREATED });
  assert.equal(a.id, b.id);
});

test("revoke throws on a non-sha256 attestationId", () => {
  assert.throws(() => revoke("nope", { agent: "a", reason: "r", at: CREATED }), /attestationId/);
});

test("revoke throws on missing agent / reason / at", () => {
  assert.throws(() => revoke(HEX, { reason: "r", at: CREATED }), /agent/);
  assert.throws(() => revoke(HEX, { agent: "a", at: CREATED }), /reason/);
  assert.throws(() => revoke(HEX, { agent: "a", reason: "r" }), /at/);
  assert.throws(() => revoke(HEX, { agent: "a", reason: "r", at: "bad" }), /at/);
});
