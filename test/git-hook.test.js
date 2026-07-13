import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  writeFileSync,
  readFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  changedPaths,
  attestCommit,
  hookPath,
  renderHookBlock,
  installHook,
} from "../src/adapters/git-hook.js";
import { loadLedger } from "../src/registry.js";
import { validateAttestation } from "../src/schema.js";

const CREATED = "2026-07-11T12:00:00Z";

// A throwaway git repo with a configured identity so commits work.
function initRepo() {
  const dir = mkdtempSync(join(tmpdir(), "provenant-hook-"));
  const git = (...a) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "Tester");
  git("config", "commit.gpgsign", "false");
  return { dir, git };
}

function write(dir, rel, content) {
  const abs = join(dir, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content);
}

// --- changedPaths ----------------------------------------------------------

test("changedPaths: lists files changed by the HEAD commit (incl. the root commit)", () => {
  const { dir, git } = initRepo();
  write(dir, "a.txt", "hello");
  write(dir, "src/b.js", "code");
  git("add", "-A");
  git("commit", "-q", "-m", "initial");
  const paths = changedPaths({ cwd: dir }).sort();
  assert.deepEqual(paths, ["a.txt", "src/b.js"]);
  rmSync(dir, { recursive: true, force: true });
});

test("changedPaths: a non-git directory → [] (never throws)", () => {
  const dir = mkdtempSync(join(tmpdir(), "provenant-nogit-"));
  assert.deepEqual(changedPaths({ cwd: dir }), []);
  rmSync(dir, { recursive: true, force: true });
});

// --- attestCommit ----------------------------------------------------------

test("attestCommit: attests each changed file with a valid record + git meta", () => {
  const { dir, git } = initRepo();
  write(dir, "a.txt", "hello");
  git("add", "-A");
  git("commit", "-q", "-m", "add a");
  const ledger = join(dir, "ledger.jsonl");

  const { written, notes, ledger: outPath } = attestCommit({
    cwd: dir,
    agent: "claude-code",
    ledger,
    created: CREATED,
  });
  assert.equal(outPath, ledger);
  assert.equal(written.length, 1);
  const rec = written[0];
  assert.equal(validateAttestation(rec).valid, true);
  assert.equal(rec.agent, "claude-code");
  assert.equal(rec.intent, "add a"); // commit subject
  assert.equal(rec.meta.harness, "git");
  assert.equal(rec.meta.path, "a.txt");
  assert.match(rec.meta.commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(rec.parents, []); // no predecessor
  assert.deepEqual(notes, []);
  rmSync(dir, { recursive: true, force: true });
});

test("attestCommit: a second version of a file derives from its predecessor (chain via parents)", () => {
  const { dir, git } = initRepo();
  const ledger = join(dir, "ledger.jsonl");

  write(dir, "a.txt", "v1");
  git("add", "-A");
  git("commit", "-q", "-m", "v1");
  const first = attestCommit({ cwd: dir, agent: "a", ledger, created: CREATED }).written[0];

  write(dir, "a.txt", "v2");
  git("add", "-A");
  git("commit", "-q", "-m", "v2");
  const second = attestCommit({ cwd: dir, agent: "a", ledger, created: "2026-07-11T12:05:00Z" }).written[0];

  assert.deepEqual(second.parents, [first.id], "new version points at the previous attestation of the same path");
  assert.notEqual(second.artifact, first.artifact);
  rmSync(dir, { recursive: true, force: true });
});

test("attestCommit: uses the explicit intent option over the commit subject", () => {
  const { dir, git } = initRepo();
  write(dir, "a.txt", "x");
  git("add", "-A");
  git("commit", "-q", "-m", "the subject");
  const ledger = join(dir, "ledger.jsonl");
  const rec = attestCommit({ cwd: dir, agent: "a", ledger, created: CREATED, intent: "override" }).written[0];
  assert.equal(rec.intent, "override");
  rmSync(dir, { recursive: true, force: true });
});

test("attestCommit: default agent falls back to PROVENANT_AGENT then 'unknown'", () => {
  const { dir, git } = initRepo();
  write(dir, "a.txt", "x");
  git("add", "-A");
  git("commit", "-q", "-m", "m");
  const ledger = join(dir, "ledger.jsonl");
  const saved = process.env.PROVENANT_AGENT;
  try {
    delete process.env.PROVENANT_AGENT;
    assert.equal(attestCommit({ cwd: dir, ledger, created: CREATED }).written[0].agent, "unknown");
  } finally {
    if (saved === undefined) delete process.env.PROVENANT_AGENT;
    else process.env.PROVENANT_AGENT = saved;
  }
  rmSync(dir, { recursive: true, force: true });
});

test("attestCommit: a file deleted by the commit is skipped with a note", () => {
  const { dir, git } = initRepo();
  write(dir, "keep.txt", "keep");
  write(dir, "gone.txt", "bye");
  git("add", "-A");
  git("commit", "-q", "-m", "seed");
  // Keep the ledger outside the repo so it is never itself a "changed path".
  const ledger = join(mkdtempSync(join(tmpdir(), "provenant-led-")), "ledger.jsonl");
  attestCommit({ cwd: dir, agent: "a", ledger, created: CREATED });

  // Delete a file and commit only that deletion.
  git("rm", "-q", "gone.txt");
  git("commit", "-q", "-m", "remove gone");
  const { written, notes } = attestCommit({ cwd: dir, agent: "a", ledger, created: "2026-07-11T12:05:00Z" });
  assert.equal(written.length, 0, "the only changed path was deleted");
  assert.ok(notes.some((n) => /skipped gone\.txt/.test(n)));
  rmSync(dir, { recursive: true, force: true });
});

test("attestCommit: the written records round-trip through loadLedger", () => {
  const { dir, git } = initRepo();
  write(dir, "a.txt", "x");
  write(dir, "b.txt", "y");
  git("add", "-A");
  git("commit", "-q", "-m", "two files");
  const ledger = join(dir, "ledger.jsonl");
  const { written } = attestCommit({ cwd: dir, agent: "a", ledger, created: CREATED });
  const { attestations } = loadLedger(ledger);
  assert.equal(attestations.length, written.length);
  assert.deepEqual(new Set(attestations.map((a) => a.id)), new Set(written.map((w) => w.id)));
  rmSync(dir, { recursive: true, force: true });
});

// --- renderHookBlock / hookPath --------------------------------------------

test("renderHookBlock: delegates to `provenant hook run`, guarded by command -v, marker-delimited", () => {
  const block = renderHookBlock();
  assert.match(block, /# >>> provenant >>>/);
  assert.match(block, /# <<< provenant <<</);
  assert.match(block, /command -v provenant/);
  assert.match(block, /provenant hook run/);
});

test("hookPath: resolves the post-commit hook inside a repo, null outside", () => {
  const { dir } = initRepo();
  const p = hookPath(dir);
  assert.ok(p && p.endsWith(join("hooks", "post-commit")));
  rmSync(dir, { recursive: true, force: true });

  const nogit = mkdtempSync(join(tmpdir(), "provenant-nogit2-"));
  assert.equal(hookPath(nogit), null);
  rmSync(nogit, { recursive: true, force: true });
});

// --- installHook -----------------------------------------------------------

test("installHook: creates an executable post-commit hook when none exists", () => {
  const { dir } = initRepo();
  const res = installHook({ cwd: dir });
  assert.equal(res.action, "created");
  assert.equal(existsSync(res.path), true);
  const body = readFileSync(res.path, "utf8");
  assert.match(body, /^#!\/bin\/sh/);
  assert.match(body, /provenant hook run/);
  assert.ok(statSync(res.path).mode & 0o100, "owner-executable bit set");
  rmSync(dir, { recursive: true, force: true });
});

test("installHook: idempotent — re-install updates the one managed block, no dupes", () => {
  const { dir } = initRepo();
  installHook({ cwd: dir });
  const res = installHook({ cwd: dir });
  assert.equal(res.action, "updated");
  const body = readFileSync(res.path, "utf8");
  assert.equal(body.match(/# >>> provenant >>>/g).length, 1);
  assert.equal(body.match(/# <<< provenant <<</g).length, 1);
  rmSync(dir, { recursive: true, force: true });
});

test("installHook: preserves an existing hand-written hook by appending the block", () => {
  const { dir } = initRepo();
  const hookFile = join(dir, ".git", "hooks", "post-commit");
  mkdirSync(dirname(hookFile), { recursive: true });
  writeFileSync(hookFile, "#!/bin/sh\necho custom\n");
  const res = installHook({ cwd: dir });
  assert.equal(res.action, "appended");
  const body = readFileSync(res.path, "utf8");
  assert.match(body, /echo custom/); // preserved
  assert.match(body, /provenant hook run/); // added
  rmSync(dir, { recursive: true, force: true });
});

test("installHook: outside a git repo → throws", () => {
  const dir = mkdtempSync(join(tmpdir(), "provenant-nogit3-"));
  assert.throws(() => installHook({ cwd: dir }), /not a git repository/);
  rmSync(dir, { recursive: true, force: true });
});
