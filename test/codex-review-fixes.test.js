// Regression tests for the Codex (Sol) review findings. Each fails against the
// pre-fix code and passes after.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { computeRecordId, resolveRecords } from "../src/registry.js";
import { sign, verifySignature } from "../src/sign.js";
import { generateKeypair, signAsym, verifyAsym } from "../src/sign-asym.js";
import { validateAttestation } from "../src/schema.js";
import { attestCommit } from "../src/adapters/git-hook.js";

const HEX = "a".repeat(64);
const att = (o = {}) => ({ type: "attestation", agent: "a", artifact: HEX, intent: "i", parents: [], created: "2026-01-01T00:00:00Z", ...o });
const sha = (b) => createHash("sha256").update(b).digest("hex");

// --- MEDIUM [5]: a signature must not change the record id -------------------
test("attaching a signature does not change computeRecordId", () => {
  const rec = att();
  const id = computeRecordId(rec);
  assert.equal(computeRecordId({ ...rec, signature: "f".repeat(64) }), id);
  // and the id survives a store round-trip
  const reloaded = JSON.parse(JSON.stringify({ ...rec, id, signature: "f".repeat(64) }));
  assert.equal(computeRecordId(reloaded), id);
});

// --- MEDIUM [4]: canonicalize matches the JSON round-trip --------------------
test("a nested undefined does not break the id round-trip", () => {
  const rec = att({ meta: { commit: "abc", stale: undefined } });
  const id = computeRecordId(rec);
  const reloaded = JSON.parse(JSON.stringify({ ...rec, id })); // drops `stale`
  assert.equal(computeRecordId(reloaded), id, "reloaded id must still match");
});

// --- MEDIUM [1]/[2]: hex signatures are length-checked before decode ---------
test("verifySignature rejects a valid signature followed by non-hex garbage", () => {
  const rec = att();
  const good = sign(rec, "secret");
  assert.equal(verifySignature({ ...rec, signature: good }, "secret"), true);
  assert.equal(verifySignature({ ...rec, signature: good + "gg" }, "secret"), false);
  assert.equal(verifySignature({ ...rec, signature: good.slice(0, 60) }, "secret"), false);
});

test("verifyAsym rejects a valid signature followed by non-hex garbage", () => {
  const { publicKey, privateKey } = generateKeypair();
  const rec = att();
  const good = signAsym(rec, privateKey);
  assert.equal(good.length, 128);
  assert.equal(verifyAsym(rec, publicKey, good), true);
  assert.equal(verifyAsym(rec, publicKey, good + "gg"), false);
});

// --- MEDIUM [3]: malformed records are skipped in resolveRecords -------------
test("resolveRecords skips a hash-valid but schema-invalid attestation", () => {
  const bad = { agent: "a", intent: "i", created: "2026-01-01T00:00:00Z" }; // no artifact/parents
  bad.id = computeRecordId(bad);
  const { attestations, notes } = resolveRecords([bad]);
  assert.equal(attestations.length, 0);
  assert.ok(notes.some((n) => n.includes("skipped attestation")));
});

// --- LOW [6]: id must be a sha256 digest ------------------------------------
test("validateAttestation requires a sha256 id", () => {
  assert.equal(validateAttestation(att({ id: "not-a-hash" })).valid, false);
  assert.equal(validateAttestation(att({ id: HEX })).valid, true);
});

// --- HIGH [0]: attestCommit hashes committed bytes, not the working tree -----
test("attestCommit attests the COMMITTED content, not a dirty working tree", () => {
  const dir = mkdtempSync(join(tmpdir(), "prov-hook-"));
  const git = (...args) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  assert.equal(git("init").status, 0);
  git("config", "user.email", "t@t"); git("config", "user.name", "t");
  writeFileSync(join(dir, "a.txt"), "committed\n");
  git("add", "a.txt");
  assert.equal(git("commit", "-m", "add a").status, 0);
  // dirty the working tree AFTER the commit
  writeFileSync(join(dir, "a.txt"), "DIRTY EDIT MADE AFTER COMMIT\n");
  const ledger = join(dir, "ledger.jsonl");
  const { written } = attestCommit({ cwd: dir, agent: "x", ledger, now: 0 });
  const rec = written.find((w) => w.meta && w.meta.path === "a.txt");
  assert.ok(rec, "a.txt should be attested");
  assert.equal(rec.artifact, sha(Buffer.from("committed\n")), "must hash committed bytes");
  assert.notEqual(rec.artifact, sha(Buffer.from("DIRTY EDIT MADE AFTER COMMIT\n")));
  rmSync(dir, { recursive: true, force: true });
});
