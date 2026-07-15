import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalize,
  computeRecordId,
  resolveRecords,
  loadLedger,
  appendRecord,
  defaultLedgerPath,
  listAttestations,
  shortId,
} from "../src/registry.js";
import { attest, revoke } from "../src/attest.js";

const T0 = "2026-07-11T12:00:00Z";
const T1 = "2026-07-11T12:05:00Z";
const T2 = "2026-07-11T12:10:00Z";

// --- shortId / listAttestations --------------------------------------------

test("shortId is the first 8 hex chars", () => {
  assert.equal(shortId("0123456789abcdef"), "01234567");
  assert.equal(shortId(12345), "12345");
});

test("listAttestations returns only the live (non-revoked) records", () => {
  const live = { id: "1", revoked: false };
  const dead = { id: "2", revoked: true };
  assert.deepEqual(listAttestations([live, dead]), [live]);
});

// --- resolveRecords --------------------------------------------------------

test("a single attestation resolves to one live record", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const { attestations, notes } = resolveRecords([a]);
  assert.equal(attestations.length, 1);
  assert.equal(attestations[0].id, a.id);
  assert.ok(!attestations[0].revoked);
  assert.deepEqual(notes, []);
});

test("a duplicate attestation record resolves to a single record (idempotent)", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const { attestations } = resolveRecords([a, { ...a }]);
  assert.equal(attestations.length, 1);
});

test("attestations come back sorted by created ascending", () => {
  const late = attest("late", { agent: "a1", intent: "w", created: T2 });
  const early = attest("early", { agent: "a1", intent: "w", created: T0 });
  const { attestations } = resolveRecords([late, early]);
  assert.deepEqual(attestations.map((a) => a.created), [T0, T2]);
});

test("a matching revocation marks the attestation revoked with by/at/reason", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "a1", reason: "superseded", at: T1 });
  const { attestations } = resolveRecords([a, rev]);
  assert.equal(attestations.length, 1);
  assert.equal(attestations[0].revoked, true);
  assert.equal(attestations[0].revoked_by, "a1");
  assert.equal(attestations[0].revoked_at, T1);
  assert.equal(attestations[0].revoked_reason, "superseded");
  assert.equal(listAttestations(attestations).length, 0);
});

test("resolveRecords does not mutate the input record", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "a1", reason: "r", at: T1 });
  resolveRecords([a, rev]);
  assert.ok(!("revoked" in a));
});

test("a revocation for an unknown attestation_id is ignored with a note", () => {
  const rev = revoke("f".repeat(64), { agent: "a1", reason: "r", at: T1 });
  const { attestations, notes } = resolveRecords([rev]);
  assert.equal(attestations.length, 0);
  assert.ok(notes.some((n) => /unknown attestation_id/.test(n)));
});

test("a revocation by a different agent than the attester applies but is noted", () => {
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const rev = revoke(a.id, { agent: "a2", reason: "r", at: T1 });
  const { attestations, notes } = resolveRecords([a, rev]);
  assert.equal(attestations[0].revoked, true);
  assert.equal(attestations[0].revoked_by, "a2");
  assert.ok(notes.some((n) => /revoked by a2, attested by a1/.test(n)));
});

test("TAMPER: a record whose id ≠ its content hash is dropped with a note; the rest survive", () => {
  const good = attest("good", { agent: "a1", intent: "w", created: T0 });
  const original = attest("bad", { agent: "a1", intent: "w", created: T1 });
  const tampered = { ...original, agent: "mutated" }; // id no longer matches content
  const { attestations, notes } = resolveRecords([good, tampered]);
  assert.equal(attestations.length, 1);
  assert.equal(attestations[0].id, good.id);
  assert.ok(notes.some((n) => /id\/content mismatch/.test(n)));
});

test("resolveRecords skips non-objects with a note and never throws", () => {
  assert.doesNotThrow(() => resolveRecords([null, 42, "str", []]));
  const { attestations, notes } = resolveRecords([null, 42, [], { id: "x" }]);
  assert.equal(attestations.length, 0);
  assert.ok(notes.some((n) => /not an object/.test(n)));
});

test("a record with an unknown type is skipped with a note", () => {
  const weird = { type: "frobnicate", data: 1 };
  weird.id = computeRecordId(weird);
  const { attestations, notes } = resolveRecords([weird]);
  assert.equal(attestations.length, 0);
  assert.ok(notes.some((n) => /unknown type/.test(n)));
});

test("a record with no type is folded as an attestation", () => {
  const rec = { agent: "a1", artifact: "a".repeat(64), intent: "w", parents: [], created: T0 };
  rec.id = computeRecordId(rec);
  const { attestations } = resolveRecords([rec]);
  assert.equal(attestations.length, 1);
});

// --- appendRecord / loadLedger (I/O) ---------------------------------------

let dir;
test.before(() => {
  dir = mkdtempSync(join(tmpdir(), "provenant-reg-"));
});
test.after(() => {
  rmSync(dir, { recursive: true, force: true });
});

test("loadLedger on a missing file → empty, no throw", () => {
  const res = loadLedger(join(dir, "nope.jsonl"));
  assert.deepEqual(res, { attestations: [], notes: [] });
});

test("appendRecord assigns a content-hash id when absent and returns the stored record", () => {
  const p = join(dir, "append-id.jsonl");
  const stored = appendRecord(p, { type: "revocation", attestation_id: "a".repeat(64), agent: "a1", reason: "r", at: T0 });
  assert.equal(stored.id, computeRecordId(stored));
});

test("appendRecord preserves an already-present id", () => {
  const p = join(dir, "append-keep-id.jsonl");
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  const stored = appendRecord(p, a);
  assert.equal(stored.id, a.id);
});

test("two appends both survive; append-only (first line byte-identical); round-trips through loadLedger", () => {
  const p = join(dir, "two-appends.jsonl");
  const a = appendRecord(p, attest("a", { agent: "a1", intent: "w", created: T0 }));
  const firstLineBefore = readFileSync(p, "utf8").split("\n")[0];
  const b = appendRecord(p, attest("b", { agent: "a1", intent: "w", created: T1 }));

  const raw = readFileSync(p, "utf8");
  const lines = raw.split("\n");
  assert.equal(lines[0], firstLineBefore, "append-only: first line unchanged");
  assert.equal(lines[2], "", "file ends in a trailing newline");
  assert.equal(raw.trim().split("\n").length, 2);

  const { attestations } = loadLedger(p);
  assert.equal(attestations.length, 2);
  assert.deepEqual(new Set(attestations.map((r) => r.id)), new Set([a.id, b.id]));
});

test("a duplicate append is idempotent on read", () => {
  const p = join(dir, "dupe.jsonl");
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  appendRecord(p, a);
  appendRecord(p, a);
  const { attestations } = loadLedger(p);
  assert.equal(attestations.length, 1);
});

test("an unparseable line is skipped with a note; other lines still resolve", () => {
  const p = join(dir, "garbage.jsonl");
  appendRecord(p, attest("good", { agent: "a1", intent: "w", created: T0 }));
  writeFileSync(p, readFileSync(p, "utf8") + "{ not json\n");
  const { attestations, notes } = loadLedger(p);
  assert.equal(attestations.length, 1);
  assert.ok(notes.some((n) => /unparseable line/.test(n)));
});

test("appendRecord + loadLedger round-trip a revocation into a revoked attestation", () => {
  const p = join(dir, "roundtrip-rev.jsonl");
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  appendRecord(p, a);
  appendRecord(p, revoke(a.id, { agent: "a1", reason: "r", at: T1 }));
  const { attestations } = loadLedger(p);
  assert.equal(attestations.length, 1);
  assert.equal(attestations[0].revoked, true);
});

test("appendRecord creates the parent directory when absent", () => {
  const p = join(dir, "nested", "deep", "ledger.jsonl");
  appendRecord(p, attest("x", { agent: "a1", intent: "w", created: T0 }));
  assert.equal(existsSync(p), true);
});

test("blank lines in the ledger are ignored", () => {
  const p = join(dir, "blank-lines.jsonl");
  const a = attest("x", { agent: "a1", intent: "w", created: T0 });
  writeFileSync(p, "\n" + JSON.stringify(a) + "\n\n");
  const { attestations } = loadLedger(p);
  assert.equal(attestations.length, 1);
});

// --- defaultLedgerPath -----------------------------------------------------

test("defaultLedgerPath honors PROVENANT_LEDGER, else .provenant/ledger.jsonl", () => {
  const saved = process.env.PROVENANT_LEDGER;
  try {
    process.env.PROVENANT_LEDGER = "/tmp/custom.jsonl";
    assert.equal(defaultLedgerPath(), "/tmp/custom.jsonl");
    delete process.env.PROVENANT_LEDGER;
    assert.equal(defaultLedgerPath("/repo"), join("/repo", ".provenant", "ledger.jsonl"));
  } finally {
    if (saved === undefined) delete process.env.PROVENANT_LEDGER;
    else process.env.PROVENANT_LEDGER = saved;
  }
});

test("canonicalize is re-exported from registry and excludes id", () => {
  assert.equal(canonicalize({ a: 1, id: "z" }), canonicalize({ a: 1 }));
});
