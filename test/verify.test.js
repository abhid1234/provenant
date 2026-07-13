import { test } from "node:test";
import assert from "node:assert/strict";
import { verify, chainOf, coverage } from "../src/verify.js";
import { attest, revoke } from "../src/attest.js";
import { resolveRecords } from "../src/registry.js";
import { computeHash } from "../src/hash.js";

const T0 = "2026-07-11T12:00:00Z";
const T1 = "2026-07-11T12:05:00Z";
const T2 = "2026-07-11T12:10:00Z";

// Resolve a set of raw records the way loadLedger would (revocations folded).
function resolve(records) {
  return resolveRecords(records).attestations;
}

// --- verify ----------------------------------------------------------------

test("verify: a live attestation for the digest → attested, the record, not revoked", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  const attestations = resolve([a]);
  const res = verify(a.artifact, attestations);
  assert.equal(res.attested, true);
  assert.equal(res.revoked, false);
  assert.equal(res.record.id, a.id);
});

test("verify: no attestation for the digest → unattested, record null", () => {
  const res = verify(computeHash("nothing"), []);
  assert.deepEqual(res, { attested: false, record: null, revoked: false });
});

test("verify: only a revoked attestation → not attested, revoked true, the revoked record", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "a1", reason: "r", at: T1 });
  const attestations = resolve([a, rev]);
  const res = verify(a.artifact, attestations);
  assert.equal(res.attested, false);
  assert.equal(res.revoked, true);
  assert.equal(res.record.id, a.id);
});

test("verify: a live re-attestation of a revoked artifact wins → attested", () => {
  const a1 = attest("content", { agent: "a1", intent: "first", created: T0 });
  const rev = revoke(a1.id, { agent: "a1", reason: "r", at: T1 });
  // Re-attest the SAME content later, so a live record exists again.
  const a2 = attest("content", { agent: "a1", intent: "redo", created: T2 });
  const attestations = resolve([a1, rev, a2]);
  const res = verify(a1.artifact, attestations);
  assert.equal(res.attested, true);
  assert.equal(res.revoked, false);
  assert.equal(res.record.intent, "redo");
});

test("verify: with multiple live attestations, returns the most recently created", () => {
  const early = attest("content", { agent: "a1", intent: "early", created: T0 });
  const late = attest("content", { agent: "a2", intent: "late", created: T2 });
  const attestations = resolve([early, late]);
  const res = verify(early.artifact, attestations);
  assert.equal(res.record.intent, "late");
});

// --- chainOf ---------------------------------------------------------------

test("chainOf: an attestation with no parents → just itself", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const chain = chainOf(a.id, resolve([a]));
  assert.equal(chain.length, 1);
  assert.equal(chain[0].id, a.id);
});

test("chainOf: walks parents across multiple generations, child first", () => {
  const g0 = attest("v0", { agent: "a1", intent: "gen0", created: T0 });
  const g1 = attest("v1", { agent: "a1", intent: "gen1", parents: [g0.id], created: T1 });
  const g2 = attest("v2", { agent: "a1", intent: "gen2", parents: [g1.id], created: T2 });
  const chain = chainOf(g2.id, resolve([g0, g1, g2]));
  assert.deepEqual(chain.map((r) => r.intent), ["gen2", "gen1", "gen0"]);
});

test("chainOf: a diamond (two parents sharing an ancestor) is deduped", () => {
  const root = attest("root", { agent: "a1", intent: "root", created: T0 });
  const left = attest("left", { agent: "a1", intent: "left", parents: [root.id], created: T1 });
  const right = attest("right", { agent: "a1", intent: "right", parents: [root.id], created: T1 });
  const merge = attest("merge", { agent: "a1", intent: "merge", parents: [left.id, right.id], created: T2 });
  const chain = chainOf(merge.id, resolve([root, left, right, merge]));
  const ids = chain.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "no duplicates");
  assert.equal(chain.length, 4, "root visited once");
});

test("chainOf: cycle-safe (a parent that points back does not loop)", () => {
  // Hand-build a self-consistent cycle: two records that reference each other.
  const a = { id: "aaaa", parents: ["bbbb"], intent: "A" };
  const b = { id: "bbbb", parents: ["aaaa"], intent: "B" };
  assert.doesNotThrow(() => chainOf("aaaa", [a, b]));
  const chain = chainOf("aaaa", [a, b]);
  assert.equal(chain.length, 2);
  assert.deepEqual(chain.map((r) => r.id), ["aaaa", "bbbb"]);
});

test("chainOf: a parent id with no matching record is skipped (best-effort)", () => {
  const child = attest("child", { agent: "a1", intent: "c", parents: ["f".repeat(64)], created: T1 });
  const chain = chainOf(child.id, resolve([child]));
  assert.equal(chain.length, 1);
  assert.equal(chain[0].id, child.id);
});

test("chainOf: an unknown starting id yields an empty array", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  assert.deepEqual(chainOf("deadbeef", resolve([a])), []);
});

// --- coverage --------------------------------------------------------------

test("coverage: an empty request scores 1 (nothing to attest)", () => {
  const res = coverage([], []);
  assert.deepEqual(res, { score: 1, total: 0, attested: 0, unattested: [], revoked: [] });
});

test("coverage: full coverage → score 1", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const b = attest("b", { agent: "x", intent: "w", created: T0 });
  const attestations = resolve([a, b]);
  const res = coverage([a.artifact, b.artifact], attestations);
  assert.equal(res.total, 2);
  assert.equal(res.attested, 2);
  assert.equal(res.score, 1);
  assert.deepEqual(res.unattested, []);
  assert.deepEqual(res.revoked, []);
});

test("coverage: partial → correct fraction, unattested listed", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const attestations = resolve([a]);
  const missing = computeHash("missing");
  const res = coverage([a.artifact, missing], attestations);
  assert.equal(res.total, 2);
  assert.equal(res.attested, 1);
  assert.equal(res.score, 0.5);
  assert.deepEqual(res.unattested, [missing]);
});

test("coverage: a revoked-only artifact counts as revoked, not attested", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "x", reason: "r", at: T1 });
  const attestations = resolve([a, rev]);
  const res = coverage([a.artifact], attestations);
  assert.equal(res.attested, 0);
  assert.equal(res.score, 0);
  assert.deepEqual(res.revoked, [a.artifact]);
  assert.deepEqual(res.unattested, []);
});

test("coverage: de-duplicates the requested digests so total counts distinct artifacts", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const attestations = resolve([a]);
  const res = coverage([a.artifact, a.artifact, a.artifact], attestations);
  assert.equal(res.total, 1);
  assert.equal(res.attested, 1);
});

test("coverage: a live re-attestation outweighs a revoked one for the same artifact", () => {
  const a1 = attest("a", { agent: "x", intent: "first", created: T0 });
  const rev = revoke(a1.id, { agent: "x", reason: "r", at: T1 });
  const a2 = attest("a", { agent: "x", intent: "redo", created: T2 });
  const attestations = resolve([a1, rev, a2]);
  const res = coverage([a1.artifact], attestations);
  assert.equal(res.attested, 1);
  assert.deepEqual(res.revoked, []);
});
