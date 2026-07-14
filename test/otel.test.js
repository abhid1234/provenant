import { test } from "node:test";
import assert from "node:assert/strict";
import { attestationToSpanAttributes, coverageToSpanAttributes } from "../src/otel.js";
import { attest, revoke } from "../src/attest.js";
import { resolveRecords } from "../src/registry.js";
import { verify, coverage } from "../src/verify.js";
import { sign } from "../src/sign.js";
import { computeHash } from "../src/hash.js";

const T0 = "2026-07-11T12:00:00Z";
const T1 = "2026-07-11T12:05:00Z";
const T2 = "2026-07-11T12:10:00Z";
const SECRET = "correct horse battery staple";

// Resolve raw records the way loadLedger would (revocations folded).
function resolve(records) {
  return resolveRecords(records).attestations;
}

// Every value in a span-attribute map must be a bare scalar (string/number/bool)
// and the whole map must JSON round-trip unchanged (flat + serializable).
function assertFlatScalar(attrs) {
  for (const [k, v] of Object.entries(attrs)) {
    const t = typeof v;
    assert.ok(
      t === "string" || t === "number" || t === "boolean",
      `attribute ${k} must be a scalar, got ${t}`
    );
  }
  assert.deepEqual(JSON.parse(JSON.stringify(attrs)), attrs);
}

// --- attestationToSpanAttributes -------------------------------------------

test("attestation attrs: carries the core provenance fields under provenant.*", () => {
  const a = attest("content", { agent: "claude", intent: "add OAuth", created: T0 });
  const attrs = attestationToSpanAttributes(a);
  assert.equal(attrs["provenant.id"], a.id);
  assert.equal(attrs["provenant.agent"], "claude");
  assert.equal(attrs["provenant.artifact"], a.artifact);
  assert.equal(attrs["provenant.intent"], "add OAuth");
  assert.equal(attrs["provenant.created"], T0);
});

test("attestation attrs: are flat and JSON-serializable (only scalar values)", () => {
  const a = attest("content", {
    agent: "a1",
    intent: "w",
    created: T0,
    meta: { harness: "git", path: "src/x.js", n: 3, ok: true },
  });
  assertFlatScalar(attestationToSpanAttributes(a));
});

test("attestation attrs: parents array is joined to a comma string + counted", () => {
  const g0 = attest("v0", { agent: "a1", intent: "g0", created: T0 });
  const g1 = attest("v1", { agent: "a1", intent: "g1", created: T1 });
  const child = attest("v2", {
    agent: "a1",
    intent: "child",
    parents: [g0.id, g1.id],
    created: T2,
  });
  const attrs = attestationToSpanAttributes(child);
  assert.equal(attrs["provenant.parents"], `${g0.id},${g1.id}`);
  assert.equal(typeof attrs["provenant.parents"], "string");
  assert.equal(attrs["provenant.parent_count"], 2);
});

test("attestation attrs: no parents → empty string and count 0", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  const attrs = attestationToSpanAttributes(a);
  assert.equal(attrs["provenant.parents"], "");
  assert.equal(attrs["provenant.parent_count"], 0);
});

test("attestation attrs: signed flag reflects a present signature", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  assert.equal(attestationToSpanAttributes(a)["provenant.signed"], false);
  const signed = { ...a, signature: sign(a, SECRET) };
  assert.equal(attestationToSpanAttributes(signed)["provenant.signed"], true);
});

test("attestation attrs: an empty-string signature is not counted as signed", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  assert.equal(attestationToSpanAttributes({ ...a, signature: "" })["provenant.signed"], false);
});

test("attestation attrs: revoked flag + revocation context on a revoked record", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "a2", reason: "superseded", at: T1 });
  const [resolved] = resolve([a, rev]);
  const attrs = attestationToSpanAttributes(resolved);
  assert.equal(attrs["provenant.revoked"], true);
  assert.equal(attrs["provenant.revoked_by"], "a2");
  assert.equal(attrs["provenant.revoked_at"], T1);
  assert.equal(attrs["provenant.revoked_reason"], "superseded");
  assertFlatScalar(attrs);
});

test("attestation attrs: a live record is revoked:false and omits revocation keys", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  const [resolved] = resolve([a]);
  const attrs = attestationToSpanAttributes(resolved);
  assert.equal(attrs["provenant.revoked"], false);
  assert.equal("provenant.revoked_by" in attrs, false);
  assert.equal("provenant.revoked_at" in attrs, false);
  assert.equal("provenant.revoked_reason" in attrs, false);
});

test("attestation attrs: scalar meta values are flattened under provenant.meta.*", () => {
  const a = attest("content", {
    agent: "a1",
    intent: "w",
    created: T0,
    meta: { harness: "git", commit: "deadbeef", count: 2, ok: false },
  });
  const attrs = attestationToSpanAttributes(a);
  assert.equal(attrs["provenant.meta.harness"], "git");
  assert.equal(attrs["provenant.meta.commit"], "deadbeef");
  assert.equal(attrs["provenant.meta.count"], 2);
  assert.equal(attrs["provenant.meta.ok"], false);
});

test("attestation attrs: nested / array meta values are skipped (kept flat)", () => {
  const a = attest("content", {
    agent: "a1",
    intent: "w",
    created: T0,
    meta: { path: "src/x.js", nested: { a: 1 }, tags: ["x", "y"] },
  });
  const attrs = attestationToSpanAttributes(a);
  assert.equal(attrs["provenant.meta.path"], "src/x.js");
  assert.equal("provenant.meta.nested" in attrs, false);
  assert.equal("provenant.meta.tags" in attrs, false);
  assertFlatScalar(attrs);
});

test("attestation attrs: deterministic for a given record", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  assert.deepEqual(attestationToSpanAttributes(a), attestationToSpanAttributes(a));
});

test("attestation attrs: tolerates a null/undefined record without throwing", () => {
  assert.doesNotThrow(() => attestationToSpanAttributes(null));
  const attrs = attestationToSpanAttributes(undefined);
  assert.equal(attrs["provenant.parent_count"], 0);
  assert.equal(attrs["provenant.revoked"], false);
  assert.equal(attrs["provenant.signed"], false);
});

// --- coverageToSpanAttributes ----------------------------------------------

test("coverage attrs: mirrors a real coverage() report as flat scalars", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const b = attest("b", { agent: "x", intent: "w", created: T0 });
  const attestations = resolve([a, b]);
  const missing = computeHash("missing");
  const report = coverage([a.artifact, b.artifact, missing], attestations);
  const attrs = coverageToSpanAttributes(report);
  assert.equal(attrs["provenant.coverage.total"], 3);
  assert.equal(attrs["provenant.coverage.attested"], 2);
  assert.equal(attrs["provenant.coverage.unattested"], 1);
  assert.equal(attrs["provenant.coverage.revoked"], 0);
  assert.ok(Math.abs(attrs["provenant.coverage.score"] - 2 / 3) < 1e-9);
  assertFlatScalar(attrs);
});

test("coverage attrs: unattested/revoked arrays are projected to counts, not arrays", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "x", reason: "r", at: T1 });
  const attestations = resolve([a, rev]);
  const report = coverage([a.artifact], attestations);
  // The real report carries arrays…
  assert.ok(Array.isArray(report.revoked));
  const attrs = coverageToSpanAttributes(report);
  // …but the span attrs carry their lengths.
  assert.equal(attrs["provenant.coverage.revoked"], 1);
  assert.equal(typeof attrs["provenant.coverage.revoked"], "number");
  assert.equal(attrs["provenant.coverage.attested"], 0);
  assert.equal(attrs["provenant.coverage.score"], 0);
});

test("coverage attrs: an empty audit scores 1 with zero counts", () => {
  const attrs = coverageToSpanAttributes(coverage([], []));
  assert.equal(attrs["provenant.coverage.score"], 1);
  assert.equal(attrs["provenant.coverage.total"], 0);
  assert.equal(attrs["provenant.coverage.attested"], 0);
  assert.equal(attrs["provenant.coverage.unattested"], 0);
  assert.equal(attrs["provenant.coverage.revoked"], 0);
});

test("coverage attrs: tolerates a bare/empty report object", () => {
  const attrs = coverageToSpanAttributes({});
  assert.equal(attrs["provenant.coverage.unattested"], 0);
  assert.equal(attrs["provenant.coverage.revoked"], 0);
});

test("otel bridge: a verify() record decorates a span end-to-end", () => {
  // The intended use: verify an artifact, then attach the record's span attrs.
  const a = attest("content", { agent: "claude", intent: "ship", created: T0 });
  const attestations = resolve([a]);
  const res = verify(a.artifact, attestations);
  assert.equal(res.attested, true);
  const attrs = attestationToSpanAttributes(res.record);
  assert.equal(attrs["provenant.agent"], "claude");
  assert.equal(attrs["provenant.revoked"], false);
  assertFlatScalar(attrs);
});
