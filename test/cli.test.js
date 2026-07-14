import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  writeFileSync,
  readFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  appendFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { computeHash } from "../src/hash.js";
import { validateAttestation } from "../src/schema.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "bin", "provenant.js");

// Run the CLI as a child process. Returns { status, stdout, stderr }.
function run(args, env = {}) {
  const r = spawnSync("node", [CLI, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

let dir;
test.before(() => {
  dir = mkdtempSync(join(tmpdir(), "provenant-cli-"));
});
test.after(() => {
  rmSync(dir, { recursive: true, force: true });
});

// Write a content file, return its absolute path.
function file(name, content) {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
}

function readLedger(p) {
  return readFileSync(p, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

// --- attest ----------------------------------------------------------------

test("attest: hashes a file, appends one valid record, exit 0", () => {
  const ledger = join(dir, "attest1.jsonl");
  const f = file("art1.txt", "hello world");
  const r = run(["attest", f, "--intent", "greet", "--agent", "claude", "--ledger", ledger]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /attested/);

  const records = readLedger(ledger);
  assert.equal(records.length, 1);
  const rec = records[0];
  assert.equal(validateAttestation(rec).valid, true);
  assert.equal(rec.agent, "claude");
  assert.equal(rec.intent, "greet");
  assert.equal(rec.artifact, computeHash("hello world"));
});

test("attest --json prints the record, matching the written line", () => {
  const ledger = join(dir, "attest-json.jsonl");
  const f = file("art2.txt", "content");
  const r = run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]);
  assert.equal(r.status, 0);
  const printed = JSON.parse(r.stdout);
  assert.deepEqual(printed, readLedger(ledger)[0]);
});

test("attest resolves the agent from PROVENANT_AGENT env", () => {
  const ledger = join(dir, "attest-env.jsonl");
  const f = file("art3.txt", "x");
  const r = run(["attest", f, "--intent", "w", "--ledger", ledger, "--json"], {
    PROVENANT_AGENT: "env-agent",
  });
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).agent, "env-agent");
});

test("attest records parents from --parents (comma-separated)", () => {
  const ledger = join(dir, "attest-parents.jsonl");
  const p1 = "a".repeat(64);
  const p2 = "b".repeat(64);
  const f = file("art4.txt", "x");
  const r = run([
    "attest", f, "--intent", "w", "--agent", "a1",
    "--parents", `${p1},${p2}`, "--ledger", ledger, "--json",
  ]);
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout).parents, [p1, p2]);
});

test("attest missing --intent → error, exit 1, nothing written", () => {
  const ledger = join(dir, "attest-no-intent.jsonl");
  const f = file("art5.txt", "x");
  const r = run(["attest", f, "--agent", "a1", "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /intent/);
  assert.equal(existsSync(ledger), false);
});

test("attest missing agent (no flag, no env) → error, exit 1", () => {
  const ledger = join(dir, "attest-no-agent.jsonl");
  const f = file("art6.txt", "x");
  const r = run(["attest", f, "--intent", "w", "--ledger", ledger], { PROVENANT_AGENT: "" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /agent/);
});

test("attest an unreadable file → error, exit 1", () => {
  const ledger = join(dir, "attest-missing-file.jsonl");
  const r = run(["attest", join(dir, "does-not-exist"), "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /cannot read file/);
});

test("attest missing <file> argument → error, exit 1", () => {
  const r = run(["attest", "--intent", "w", "--agent", "a1"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires a <file>/);
});

// --- verify ----------------------------------------------------------------

test("verify: an attested file → exit 0; --json emits { attested, record, revoked }", () => {
  const ledger = join(dir, "verify.jsonl");
  const f = file("v1.txt", "verified content");
  run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger]);

  const human = run(["verify", f, "--ledger", ledger]);
  assert.equal(human.status, 0);
  assert.match(human.stdout, /attested/);

  const j = run(["verify", f, "--ledger", ledger, "--json"]);
  assert.equal(j.status, 0);
  const out = JSON.parse(j.stdout);
  assert.equal(out.attested, true);
  assert.equal(out.revoked, false);
  assert.equal(out.record.agent, "a1");
});

test("verify: accepts a raw sha256 digest argument", () => {
  const ledger = join(dir, "verify-hash.jsonl");
  const f = file("v2.txt", "by hash");
  run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  const hash = computeHash("by hash");
  const r = run(["verify", hash, "--ledger", ledger, "--json"]);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).attested, true);
});

test("verify: an unattested file → exit 1", () => {
  const ledger = join(dir, "verify-miss.jsonl");
  const f = file("v3.txt", "never attested");
  const r = run(["verify", f, "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /unattested/);
});

test("verify: a revoked artifact → exit 1, revoked message", () => {
  const ledger = join(dir, "verify-revoked.jsonl");
  const f = file("v4.txt", "to be revoked");
  const att = JSON.parse(
    run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  run(["revoke", att.id, "--reason", "bad", "--agent", "a1", "--ledger", ledger]);
  const r = run(["verify", f, "--ledger", ledger, "--json"]);
  assert.equal(r.status, 1);
  const out = JSON.parse(r.stdout);
  assert.equal(out.attested, false);
  assert.equal(out.revoked, true);
});

// --- revoke ----------------------------------------------------------------

test("revoke: appends a revocation (append-only); the artifact stops verifying", () => {
  const ledger = join(dir, "revoke.jsonl");
  const f = file("r1.txt", "content");
  const att = JSON.parse(
    run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  const before = readLedger(ledger).length;

  const r = run(["revoke", att.id, "--reason", "superseded", "--agent", "a1", "--ledger", ledger, "--json"]);
  assert.equal(r.status, 0);
  const rev = JSON.parse(r.stdout);
  assert.equal(rev.type, "revocation");
  assert.equal(rev.attestation_id, att.id);
  assert.equal(readLedger(ledger).length, before + 1);
  assert.equal(run(["verify", f, "--ledger", ledger]).status, 1);
});

test("revoke: by unambiguous id prefix works", () => {
  const ledger = join(dir, "revoke-prefix.jsonl");
  const f = file("r2.txt", "x");
  const att = JSON.parse(
    run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  const r = run(["revoke", att.id.slice(0, 8), "--reason", "r", "--agent", "a1", "--ledger", ledger]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /revoked/);
});

test("revoke: an already-revoked attestation → no-op note, no new line, exit 0", () => {
  const ledger = join(dir, "revoke-twice.jsonl");
  const f = file("r3.txt", "x");
  const att = JSON.parse(
    run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  run(["revoke", att.id, "--reason", "r", "--agent", "a1", "--ledger", ledger]);
  const lines = readLedger(ledger).length;
  const r = run(["revoke", att.id, "--reason", "r", "--agent", "a1", "--ledger", ledger]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /already revoked/);
  assert.equal(readLedger(ledger).length, lines);
});

test("revoke: an unknown id → error, exit 1", () => {
  const ledger = join(dir, "revoke-unknown.jsonl");
  const f = file("r4.txt", "x");
  run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  const r = run(["revoke", "deadbeefdeadbeef", "--reason", "r", "--agent", "a1", "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no attestation/);
});

test("revoke: missing --reason → error, exit 1", () => {
  const ledger = join(dir, "revoke-no-reason.jsonl");
  const f = file("r5.txt", "x");
  const att = JSON.parse(
    run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  const r = run(["revoke", att.id, "--agent", "a1", "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /reason/);
});

// --- coverage --------------------------------------------------------------

test("coverage: all files attested → score 1.00, exit 0, --json math", () => {
  const ledger = join(dir, "cov-full.jsonl");
  const a = file("c1.txt", "aaa");
  const b = file("c2.txt", "bbb");
  run(["attest", a, "--intent", "w", "--agent", "x", "--ledger", ledger]);
  run(["attest", b, "--intent", "w", "--agent", "x", "--ledger", ledger]);

  const human = run(["coverage", a, b, "--ledger", ledger]);
  assert.equal(human.status, 0);
  assert.match(human.stdout, /coverage 1\.00/);

  const j = run(["coverage", a, b, "--ledger", ledger, "--json"]);
  assert.equal(j.status, 0);
  const out = JSON.parse(j.stdout);
  assert.equal(out.total, 2);
  assert.equal(out.attested, 2);
  assert.equal(out.score, 1);
});

test("coverage: a partly-attested set → exit 1, unattested listed", () => {
  const ledger = join(dir, "cov-partial.jsonl");
  const a = file("c3.txt", "aaa");
  const b = file("c4.txt", "never");
  run(["attest", a, "--intent", "w", "--agent", "x", "--ledger", ledger]);
  const j = run(["coverage", a, b, "--ledger", ledger, "--json"]);
  assert.equal(j.status, 1);
  const out = JSON.parse(j.stdout);
  assert.equal(out.attested, 1);
  assert.equal(out.total, 2);
  assert.equal(out.score, 0.5);
  assert.equal(out.unattested.length, 1);
});

test("coverage: an unreadable file → error, exit 1", () => {
  const ledger = join(dir, "cov-missing.jsonl");
  const r = run(["coverage", join(dir, "nope.txt"), "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /cannot read file/);
});

// --- log -------------------------------------------------------------------

test("log: an empty/missing ledger → 'no attestations', exit 0; --json → []", () => {
  const ledger = join(dir, "log-empty.jsonl");
  const human = run(["log", "--ledger", ledger]);
  assert.equal(human.status, 0);
  assert.match(human.stdout, /no attestations/);
  const j = run(["log", "--ledger", ledger, "--json"]);
  assert.deepEqual(JSON.parse(j.stdout), []);
});

test("log: lists live attestations; --json returns the resolved array", () => {
  const ledger = join(dir, "log-list.jsonl");
  const a = file("l1.txt", "one");
  const b = file("l2.txt", "two");
  run(["attest", a, "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  run(["attest", b, "--intent", "w", "--agent", "a2", "--ledger", ledger]);
  const j = run(["log", "--ledger", ledger, "--json"]);
  assert.equal(j.status, 0);
  assert.equal(JSON.parse(j.stdout).length, 2);
});

test("log: --agent filters to one producer", () => {
  const ledger = join(dir, "log-agent.jsonl");
  const a = file("l3.txt", "one");
  const b = file("l4.txt", "two");
  run(["attest", a, "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  run(["attest", b, "--intent", "w", "--agent", "a2", "--ledger", ledger]);
  const j = run(["log", "--ledger", ledger, "--agent", "a2", "--json"]);
  const rows = JSON.parse(j.stdout);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].agent, "a2");
});

test("log: default hides revoked; --all shows it labeled", () => {
  const ledger = join(dir, "log-all.jsonl");
  const a = file("l5.txt", "x");
  const att = JSON.parse(
    run(["attest", a, "--intent", "w", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  run(["revoke", att.id, "--reason", "r", "--agent", "a1", "--ledger", ledger]);
  assert.match(run(["log", "--ledger", ledger]).stdout, /no attestations/);
  const all = run(["log", "--ledger", ledger, "--all"]);
  assert.equal(all.status, 0);
  assert.match(all.stdout, /revoked/);
});

test("log: --all warns to stderr about a skipped unparseable line", () => {
  const ledger = join(dir, "log-warn.jsonl");
  const a = file("l6.txt", "x");
  run(["attest", a, "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  appendFileSync(ledger, "not json\n");
  const r = run(["log", "--ledger", ledger, "--all"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /warning:.*skipped/i);
});

// --- chain -----------------------------------------------------------------

test("chain: prints a provenance chain; --json returns the ordered records", () => {
  const ledger = join(dir, "chain.jsonl");
  const a = file("ch1.txt", "v0");
  const parent = JSON.parse(
    run(["attest", a, "--intent", "v0", "--agent", "a1", "--ledger", ledger, "--json"]).stdout
  );
  const b = file("ch2.txt", "v1");
  const child = JSON.parse(
    run(["attest", b, "--intent", "v1", "--agent", "a1", "--parents", parent.id, "--ledger", ledger, "--json"]).stdout
  );
  const j = run(["chain", child.id, "--ledger", ledger, "--json"]);
  assert.equal(j.status, 0);
  const chain = JSON.parse(j.stdout);
  assert.deepEqual(chain.map((r) => r.id), [child.id, parent.id]);
});

test("chain: an unknown id → error, exit 1", () => {
  const ledger = join(dir, "chain-unknown.jsonl");
  const a = file("ch3.txt", "x");
  run(["attest", a, "--intent", "w", "--agent", "a1", "--ledger", ledger]);
  const r = run(["chain", "deadbeef", "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no attestation/);
});

// --- router / argument handling --------------------------------------------

test("unknown subcommand → usage on stderr, exit 1", () => {
  const r = run(["frobnicate"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Usage/);
});

test("no subcommand → usage on stderr, exit 1", () => {
  const r = run([]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Usage/);
});

test("an unknown flag → error, exit 1", () => {
  const ledger = join(dir, "unknown-flag.jsonl");
  const f = file("uf.txt", "x");
  const r = run(["attest", f, "--intent", "w", "--agent", "a1", "--bogus", "--ledger", ledger]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unknown flag/);
});

test("PROVENANT_LEDGER env selects the ledger when --ledger is omitted", () => {
  const ledger = join(dir, "env-ledger.jsonl");
  const f = file("envart.txt", "x");
  const r = run(["attest", f, "--intent", "w", "--agent", "a1"], { PROVENANT_LEDGER: ledger });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(existsSync(ledger), true);
  assert.equal(run(["verify", f], { PROVENANT_LEDGER: ledger }).status, 0);
});

// --- hook (CLI) ------------------------------------------------------------

test("hook without a subcommand → usage, exit 1", () => {
  const r = run(["hook"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires a subcommand/);
});

test("hook with an unknown subcommand → error, exit 1", () => {
  const r = run(["hook", "frobnicate"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unknown hook subcommand/);
});

// --- otel (CLI) ------------------------------------------------------------

test("otel: emits one flat provenant.* attribute object per attestation", () => {
  const ledger = join(dir, "otel-attrs.jsonl");
  const f = file("otel1.txt", "hello otel");
  assert.equal(
    run(["attest", f, "--intent", "ship", "--agent", "claude", "--ledger", ledger]).status,
    0
  );

  const r = run(["otel", ledger]);
  assert.equal(r.status, 0, r.stderr);
  const rows = JSON.parse(r.stdout);
  assert.equal(Array.isArray(rows), true);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]["provenant.agent"], "claude");
  assert.equal(rows[0]["provenant.intent"], "ship");
  assert.equal(rows[0]["provenant.artifact"], computeHash("hello otel"));
  assert.equal(rows[0]["provenant.revoked"], false);
  // Flat + scalar values only.
  for (const v of Object.values(rows[0])) {
    assert.ok(["string", "number", "boolean"].includes(typeof v));
  }
});

test("otel: an empty/missing ledger emits an empty array, exit 0", () => {
  const r = run(["otel", join(dir, "otel-missing.jsonl")]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), []);
});

test("otel --coverage: emits the flat provenant.coverage.* attribute object", () => {
  const ledger = join(dir, "otel-cov.jsonl");
  const f = file("otelcov.txt", "covered");
  assert.equal(
    run(["attest", f, "--intent", "w", "--agent", "a1", "--ledger", ledger]).status,
    0
  );
  const missing = file("otelmissing.txt", "not attested");

  const r = run(["otel", ledger, "--coverage", f, missing]);
  assert.equal(r.status, 0, r.stderr);
  const attrs = JSON.parse(r.stdout);
  assert.equal(attrs["provenant.coverage.total"], 2);
  assert.equal(attrs["provenant.coverage.attested"], 1);
  assert.equal(attrs["provenant.coverage.unattested"], 1);
  assert.equal(attrs["provenant.coverage.score"], 0.5);
});

test("otel without a ledger argument → error, exit 1", () => {
  const r = run(["otel"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires a <ledger-file>/);
});
