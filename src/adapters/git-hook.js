// provenant — git post-commit hook adapter (the dogfood surface).
//
// This is what makes provenant actually build a provenance trail in a live
// agent workflow: a *post-commit* hook that, after each commit lands, writes an
// attestation for every file the commit changed — recording which agent
// produced that content, why (the commit subject), and what it derived from (the
// previous attestation of the same path). The git plumbing lives here; the
// record construction is delegated to the pure `attest` core and the store's
// `appendRecord`, so this adapter adds a new *surface*, not a second notion of
// "attestation".
//
// Post-commit (not pre-commit) is deliberate: provenance records what *did*
// happen. The hook runs after the commit is created, reads the committed tree,
// and never blocks or alters the commit — it only appends to the ledger.
//
// Zero runtime dependencies: `git` is invoked via `child_process`, everything
// else reuses this package's own modules.

import { spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  mkdirSync,
} from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { attest } from "../attest.js";
import { appendRecord, loadLedger, defaultLedgerPath } from "../registry.js";

// Markers delimiting provenant's managed region inside `.git/hooks/post-commit`.
// Install rewrites only the text *between* (and including) these lines, so any
// pre-existing hook body a user or another tool wrote is preserved verbatim.
const START = "# >>> provenant >>>";
const END = "# <<< provenant <<<";

// --- git plumbing ----------------------------------------------------------

// changedPaths({ cwd }) → the repo-relative paths changed by the HEAD commit.
//
// Uses `git diff-tree` against HEAD, which lists a root commit's files too (it
// diffs against the empty tree), so the very first commit is attested as well.
// Any git failure (not a repo, no commits) yields [] so the hook is a no-op
// rather than an error — provenance is additive, never disruptive.
export function changedPaths(opts = {}) {
  const { cwd = process.cwd() } = opts;
  const r = spawnSync(
    "git",
    ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "HEAD"],
    { cwd, encoding: "utf8" }
  );
  if (r.status !== 0 || typeof r.stdout !== "string") return [];
  return r.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

// The HEAD commit's subject line — used as each attestation's `intent`.
function commitSubject(cwd) {
  const r = spawnSync("git", ["log", "-1", "--pretty=%s"], { cwd, encoding: "utf8" });
  if (r.status !== 0 || typeof r.stdout !== "string") return null;
  return r.stdout.trim() || null;
}

// The HEAD commit's full sha — recorded in each attestation's `meta.commit`.
function headSha(cwd) {
  const r = spawnSync("git", ["rev-parse", "HEAD"], { cwd, encoding: "utf8" });
  if (r.status !== 0 || typeof r.stdout !== "string") return null;
  return r.stdout.trim() || null;
}

// --- attestCommit (what the hook runs) -------------------------------------

// attestCommit({ cwd, agent, ledger, now, created, intent }) →
//   { written, notes, ledger }
//
// Attests every file changed in the HEAD commit:
//   - `agent`   — from the option, else env `PROVENANT_AGENT`, else "unknown".
//   - `intent`  — from the option, else the commit subject, else "commit".
//   - `artifact`— the sha256 of the committed file's current content.
//   - `parents` — the previous live attestation of the SAME path (found by
//     `meta.path` in the existing ledger), so each new version derives from its
//     predecessor and `chainOf` walks a file's history. No prior version → [].
//   - `meta`    — { harness: "git", commit: <sha>, path: <rel> }.
//
// A file that can't be read (e.g. deleted by the commit) is skipped with a note
// rather than failing the whole run. Pure of the clock only via the injected
// `now`/`created`; everything else is real git + real I/O, since this is the
// adapter that dogfoods the format.
export function attestCommit(opts = {}) {
  const {
    cwd = process.cwd(),
    agent = process.env.PROVENANT_AGENT || "unknown",
    ledger = null,
    now = Date.now(),
    created = null,
    intent = null,
  } = opts;

  const path = ledger || defaultLedgerPath(cwd);
  const paths = changedPaths({ cwd });
  const subject = intent || commitSubject(cwd) || "commit";
  const commit = headSha(cwd);
  const createdIso = created || new Date(Math.floor(now / 1000) * 1000).toISOString();

  // Index the latest attestation id per path so a new version can point at its
  // predecessor. Attestations come back sorted by `created` ascending, so the
  // last write for a path wins.
  const { attestations } = loadLedger(path, { now });
  const latestByPath = new Map();
  for (const a of attestations) {
    const p = a.meta && a.meta.path;
    if (typeof p === "string") latestByPath.set(p, a.id);
  }

  const written = [];
  const notes = [];
  for (const rel of paths) {
    const abs = isAbsolute(rel) ? rel : join(cwd, rel);
    let content;
    try {
      content = readFileSync(abs);
    } catch {
      notes.push(`skipped ${rel}: unreadable (deleted in this commit?)`);
      continue;
    }
    const parentId = latestByPath.get(rel);
    const record = attest(content, {
      agent,
      intent: subject,
      parents: parentId ? [parentId] : [],
      created: createdIso,
      meta: { harness: "git", commit, path: rel },
    });
    appendRecord(path, record);
    latestByPath.set(rel, record.id);
    written.push(record);
  }

  return { written, notes, ledger: path };
}

// --- hook install ----------------------------------------------------------

// gitPath(cwd, rel) → the absolute path of a file inside the git dir, or null if
// cwd is not a git repo. Uses `git rev-parse --git-path` so it resolves
// correctly for worktrees (where hooks live in the shared common dir).
function gitPath(cwd, rel) {
  const r = spawnSync("git", ["rev-parse", "--git-path", rel], {
    cwd,
    encoding: "utf8",
  });
  if (r.status !== 0 || typeof r.stdout !== "string") return null;
  const p = r.stdout.trim();
  if (!p) return null;
  return isAbsolute(p) ? p : join(cwd, p);
}

// hookPath(cwd) → absolute path of this repo's post-commit hook, or null if cwd
// is not a git repository.
export function hookPath(cwd = process.cwd()) {
  return gitPath(cwd, "hooks/post-commit");
}

// renderHookBlock() → the marker-delimited shell block install writes.
//
// The block delegates to `provenant hook run`, guarded by `command -v` so a
// clone where `provenant` isn't on PATH degrades gracefully (no hook error). The
// hook only ever appends to the ledger, so there is no strict/blocking mode —
// provenance is recorded, never enforced.
export function renderHookBlock() {
  return [
    START,
    "# Managed by `provenant hook install` — attests each file changed in the commit.",
    "if command -v provenant >/dev/null 2>&1; then",
    "  provenant hook run",
    "fi",
    END,
  ].join("\n");
}

// installHook({ cwd }) → { path, action }
//
// Idempotent, existing-hook-preserving install:
//   - no post-commit hook yet    → create one (shebang + block)  ["created"]
//   - a hook with our markers     → replace only the marked block ["updated"]
//   - a hook without our markers  → append the block after it     ["appended"]
// Re-running install therefore converges to a single managed block and never
// duplicates it or clobbers a hand-written hook. The file is chmod +x so git
// will execute it.
export function installHook(opts = {}) {
  const { cwd = process.cwd() } = opts;
  const path = hookPath(cwd);
  if (!path) {
    throw new Error("not a git repository (run `git init` first)");
  }

  const block = renderHookBlock();
  let content;
  let action;

  if (!existsSync(path)) {
    content = `#!/bin/sh\n${block}\n`;
    action = "created";
  } else {
    const existing = readFileSync(path, "utf8");
    const s = existing.indexOf(START);
    const e = existing.indexOf(END);
    if (s !== -1 && e !== -1 && e > s) {
      content = existing.slice(0, s) + block + existing.slice(e + END.length);
      action = "updated";
    } else {
      const sep = existing.endsWith("\n") ? "" : "\n";
      content = `${existing}${sep}\n${block}\n`;
      action = "appended";
    }
  }

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  chmodSync(path, 0o755);
  return { path, action };
}
