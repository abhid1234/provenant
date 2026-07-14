#!/usr/bin/env node
// provenant CLI.
//
// Dispatches to subcommands:
//  - `attest <file>`: hash a file's content and append an attestation.
//  - `verify <file-or-hash>`: is this artifact attested? (exit 0 = yes).
//  - `chain <attestation-id>`: print an attestation's provenance chain.
//  - `coverage <path...>`: what fraction of the given files is attested?
//  - `log`: list the ledger's attestations (who produced what, why).
//  - `revoke <attestation-id> --reason`: supersede an attestation.
//  - `hook install|run`: git post-commit adapter — auto-attest changed files.
//  - `otel <ledger>`: emit OpenTelemetry span attributes for the ledger.

import { readFileSync } from "node:fs";
import { attest, revoke } from "../src/attest.js";
import { computeHash } from "../src/hash.js";
import { validateAttestation, isSha256Hex } from "../src/schema.js";
import { verify, chainOf, coverage } from "../src/verify.js";
import { attestationToSpanAttributes, coverageToSpanAttributes } from "../src/otel.js";
import { attestCommit, installHook } from "../src/adapters/git-hook.js";
import {
  loadLedger,
  appendRecord,
  defaultLedgerPath,
  listAttestations,
  shortId,
} from "../src/registry.js";

const USAGE = `provenant — the open provenance format for AI-agent work

Usage:
  provenant attest <file> --intent "<why>" [--agent <id>] [--parents <ids>]
                          [--ledger <path>] [--json]
      Hash the file's content and append a signed-off attestation to the ledger:
      which agent produced this content, why, and what it derives from. Exit 0.
  provenant verify <file-or-hash> [--ledger <path>] [--json]
      Is the artifact (a file, hashed here, or a raw sha256 digest) attested?
      Exit 0 if a live attestation exists, 1 otherwise (or if revoked).
  provenant chain <attestation-id> [--ledger <path>] [--json]
      Print the provenance chain of an attestation: the record and every
      ancestor it derives from via \`parents\`. Exit 1 if the id is unknown.
  provenant coverage <path...> [--ledger <path>] [--json]
      Audit what fraction of the given files carry a live attestation. Exit 0
      when all are attested, 1 when any is unattested or revoked.
  provenant log [--all] [--agent <id>] [--ledger <path>] [--json]
      List the ledger's live attestations (who produced what, why, from what).
      --all also shows revoked attestations, labeled.
  provenant revoke <attestation-id> --reason "<why>" [--agent <id>]
                   [--ledger <path>] [--json]
      Supersede an attestation (full id or unambiguous prefix) by appending a
      revocation record. No-op with a note if it is already revoked.
  provenant hook install [--ledger <path>]
      Install a git post-commit hook that attests every file a commit changed.
      Idempotent; preserves an existing hook.
  provenant hook run [--agent <id>] [--ledger <path>] [--json]
      What the hook runs: attest each file changed in the HEAD commit.
  provenant otel <ledger-file> [--coverage <path...>]
      Emit OpenTelemetry-style span attributes (JSON) for the ledger: one flat
      \`provenant.*\` attribute object per attestation. With --coverage, instead
      emit the single \`provenant.coverage.*\` attribute object for those files.

Flags:
  --intent <str>   why the artifact was produced (required for \`attest\`)
  --agent <id>     the producing agent (env PROVENANT_AGENT)
  --parents <ids>  comma-separated attestation ids this work derives from
  --reason <str>   why an attestation is being revoked (required for \`revoke\`)
  --all            include revoked attestations (log)
  --ledger <path>  ledger file (default: env PROVENANT_LEDGER or
                   .provenant/ledger.jsonl)
  --json           emit machine-readable output for the active command`;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

// Surface loadLedger/resolveRecords `notes` (skipped/tampered lines) to stderr.
// A dropped line is a corrupt/tampered record; the warning is the mitigation so
// a missing attestation is visible rather than silently absent.
function warnNotes(notes) {
  for (const note of notes) process.stderr.write(`warning: ${note}\n`);
}

// An ISO-8601-UTC timestamp for "now", truncated to whole seconds so the clock
// is read in exactly one place and records stay tidy.
function nowIso() {
  return new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
}

// --- attest ----------------------------------------------------------------

function parseAttestArgs(args) {
  let file = null;
  let intent = null;
  let agent = process.env.PROVENANT_AGENT || null;
  let parents = [];
  let ledger = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      json = true;
    } else if (a === "--intent") {
      intent = args[++i];
      if (intent == null) fail("error: --intent requires a value\n\n" + USAGE);
    } else if (a === "--agent") {
      agent = args[++i];
      if (agent == null) fail("error: --agent requires a value\n\n" + USAGE);
    } else if (a === "--parents") {
      const v = args[++i];
      if (v == null) fail("error: --parents requires a value\n\n" + USAGE);
      parents = v.split(",").map((s) => s.trim()).filter(Boolean);
    } else if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (file == null) {
      file = a;
    } else {
      fail(`error: \`attest\` takes a single <file> (extra: ${a})\n\n` + USAGE);
    }
  }
  return { file, intent, agent, parents, ledger, json };
}

function runAttest(args) {
  const { file, intent, agent, parents, ledger, json } = parseAttestArgs(args);

  if (file == null) {
    fail("error: `attest` requires a <file> argument\n\n" + USAGE);
    return;
  }
  if (intent == null || intent.trim().length === 0) {
    fail("error: `attest` requires a non-empty --intent\n\n" + USAGE);
    return;
  }
  if (agent == null || agent.trim().length === 0) {
    fail("error: `attest` requires --agent (or the PROVENANT_AGENT env var)\n\n" + USAGE);
    return;
  }

  let content;
  try {
    content = readFileSync(file);
  } catch {
    fail(`error: cannot read file: ${file}`);
    return;
  }

  // The clock is read only here; attest stays pure over the injected `created`.
  let record;
  try {
    record = attest(content, { agent, intent, parents, created: nowIso() });
  } catch (e) {
    fail(`error: ${e.message}`);
    return;
  }

  // Validate the finished record; gate the write on it so a malformed record is
  // rejected rather than appended.
  const result = validateAttestation(record);
  if (!result.valid) {
    process.stdout.write(
      `✗ cannot attest (${result.errors.length} error${result.errors.length === 1 ? "" : "s"}):\n`
    );
    for (const e of result.errors) {
      const at = e.path === "" ? "<root>" : e.path;
      process.stdout.write(`  ${at}: ${e.message} [${e.code}]\n`);
    }
    process.exit(1);
    return;
  }

  const path = ledger || defaultLedgerPath();
  appendRecord(path, record);

  if (json) {
    process.stdout.write(JSON.stringify(record) + "\n");
  } else {
    process.stdout.write(
      `attested ${record.id} — ${record.agent} produced ${shortId(record.artifact)} — ` +
        `"${record.intent}"\n`
    );
  }
  process.exit(0);
}

// --- verify ----------------------------------------------------------------

function parseSingleArgWithLedger(args, name) {
  let value = null;
  let ledger = null;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      json = true;
    } else if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (value == null) {
      value = a;
    } else {
      fail(`error: \`${name}\` takes a single argument (extra: ${a})\n\n` + USAGE);
    }
  }
  return { value, ledger, json };
}

function runVerify(args) {
  const { value, ledger, json } = parseSingleArgWithLedger(args, "verify");

  if (value == null) {
    fail("error: `verify` requires a <file-or-hash> argument\n\n" + USAGE);
    return;
  }

  // A 64-hex argument is taken as a digest verbatim; anything else is a file
  // path whose content is hashed here.
  let hash;
  if (isSha256Hex(value)) {
    hash = value;
  } else {
    let content;
    try {
      content = readFileSync(value);
    } catch {
      fail(`error: not a sha256 digest and cannot read as a file: ${value}`);
      return;
    }
    hash = computeHash(content);
  }

  const path = ledger || defaultLedgerPath();
  const { attestations, notes } = loadLedger(path);
  warnNotes(notes);

  const result = verify(hash, attestations);

  if (json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  } else if (result.attested) {
    const r = result.record;
    process.stdout.write(
      `attested ✓ — ${shortId(hash)} by ${r.agent} — "${r.intent}" (${r.created}) [${shortId(r.id)}]\n`
    );
  } else if (result.revoked) {
    process.stdout.write(`revoked ✗ — ${shortId(hash)} had an attestation but it was revoked\n`);
  } else {
    process.stdout.write(`unattested ✗ — no attestation for ${shortId(hash)}\n`);
  }

  process.exit(result.attested ? 0 : 1);
}

// --- chain -----------------------------------------------------------------

function runChain(args) {
  const { value, ledger, json } = parseSingleArgWithLedger(args, "chain");

  if (value == null) {
    fail("error: `chain` requires an <attestation-id> argument\n\n" + USAGE);
    return;
  }

  const path = ledger || defaultLedgerPath();
  const { attestations, notes } = loadLedger(path);
  warnNotes(notes);

  // Resolve the target id: exact match first, else a unique id prefix.
  let target = attestations.find((a) => a.id === value);
  if (!target) {
    const matches = attestations.filter((a) => a.id.startsWith(value));
    if (matches.length > 1) {
      fail(`error: ambiguous id prefix "${value}" matches ${matches.length} attestations`);
      return;
    }
    target = matches[0];
  }
  if (!target) {
    fail(`error: no attestation with id "${value}"`);
    return;
  }

  const chain = chainOf(target.id, attestations);

  if (json) {
    process.stdout.write(JSON.stringify(chain) + "\n");
    process.exit(0);
  }

  process.stdout.write(
    `provenance chain for ${shortId(target.id)} (${chain.length} record${chain.length === 1 ? "" : "s"}):\n`
  );
  chain.forEach((r, i) => {
    const arrow = i === 0 ? "•" : "↳";
    process.stdout.write(
      `  ${arrow} ${shortId(r.id)}  ${r.agent}  ${shortId(r.artifact)}  "${r.intent}"\n`
    );
  });
  process.exit(0);
}

// --- coverage --------------------------------------------------------------

function parseCoverageArgs(args) {
  const files = [];
  let ledger = null;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      json = true;
    } else if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      files.push(a);
    }
  }
  return { files, ledger, json };
}

function runCoverage(args) {
  const { files, ledger, json } = parseCoverageArgs(args);

  if (files.length === 0) {
    fail("error: `coverage` requires one or more file paths\n\n" + USAGE);
    return;
  }

  // Hash each file's content; an unreadable file is a clear error (the audit
  // asks about concrete files, so a missing one is a mistake to surface).
  const hashes = [];
  for (const f of files) {
    let content;
    try {
      content = readFileSync(f);
    } catch {
      fail(`error: cannot read file: ${f}`);
      return;
    }
    hashes.push(computeHash(content));
  }

  const path = ledger || defaultLedgerPath();
  const { attestations, notes } = loadLedger(path);
  warnNotes(notes);

  const result = coverage(hashes, attestations);
  const clean = result.unattested.length === 0 && result.revoked.length === 0;

  if (json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  } else {
    process.stdout.write(
      `coverage ${result.score.toFixed(2)} — ${result.attested}/${result.total} ` +
        `artifact${result.total === 1 ? "" : "s"} attested\n`
    );
    if (result.revoked.length) {
      process.stdout.write(`  ${result.revoked.length} revoked\n`);
    }
    if (result.unattested.length) {
      process.stdout.write(`  ${result.unattested.length} unattested\n`);
    }
  }

  process.exit(clean ? 0 : 1);
}

// --- log -------------------------------------------------------------------

function parseLogArgs(args) {
  let all = false;
  let agent = null;
  let ledger = null;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      json = true;
    } else if (a === "--all") {
      all = true;
    } else if (a === "--agent") {
      agent = args[++i];
      if (agent == null) fail("error: --agent requires a value\n\n" + USAGE);
    } else if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: \`log\` takes no positional arguments (got: ${a})\n\n` + USAGE);
    }
  }
  return { all, agent, ledger, json };
}

function runLog(args) {
  const { all, agent, ledger, json } = parseLogArgs(args);

  const path = ledger || defaultLedgerPath();
  const { attestations, notes } = loadLedger(path);
  if (all) warnNotes(notes);

  let rows = all ? attestations : listAttestations(attestations);
  if (agent != null) rows = rows.filter((a) => a.agent === agent);

  if (json) {
    process.stdout.write(JSON.stringify(rows) + "\n");
    process.exit(0);
  }

  if (rows.length === 0) {
    process.stdout.write("no attestations\n");
    process.exit(0);
  }

  for (const a of rows) {
    const label = a.revoked ? "  (revoked)" : "";
    process.stdout.write(
      `${shortId(a.id)}  ${a.agent}  ${shortId(a.artifact)}  "${a.intent}"  ${a.created}${label}\n`
    );
  }
  process.exit(0);
}

// --- revoke ----------------------------------------------------------------

function parseRevokeArgs(args) {
  let id = null;
  let reason = null;
  let agent = process.env.PROVENANT_AGENT || null;
  let ledger = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      json = true;
    } else if (a === "--reason") {
      reason = args[++i];
      if (reason == null) fail("error: --reason requires a value\n\n" + USAGE);
    } else if (a === "--agent") {
      agent = args[++i];
      if (agent == null) fail("error: --agent requires a value\n\n" + USAGE);
    } else if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (id == null) {
      id = a;
    } else {
      fail(`error: \`revoke\` takes a single <attestation-id> (extra: ${a})\n\n` + USAGE);
    }
  }
  return { id, reason, agent, ledger, json };
}

function runRevoke(args) {
  const { id, reason, agent, ledger, json } = parseRevokeArgs(args);

  if (id == null || id.trim().length === 0) {
    fail("error: `revoke` requires an attestation <id>\n\n" + USAGE);
    return;
  }
  if (reason == null || reason.trim().length === 0) {
    fail("error: `revoke` requires a non-empty --reason\n\n" + USAGE);
    return;
  }
  if (agent == null || agent.trim().length === 0) {
    fail("error: `revoke` requires --agent (or the PROVENANT_AGENT env var)\n\n" + USAGE);
    return;
  }

  const path = ledger || defaultLedgerPath();
  const { attestations } = loadLedger(path);

  // Resolve the target: exact id first, else a unique id prefix.
  let target = attestations.find((a) => a.id === id);
  if (!target) {
    const matches = attestations.filter((a) => a.id.startsWith(id));
    if (matches.length > 1) {
      fail(`error: ambiguous id prefix "${id}" matches ${matches.length} attestations`);
      return;
    }
    target = matches[0];
  }
  if (!target) {
    fail(`error: no attestation with id "${id}"`);
    return;
  }

  // Already revoked → the desired end state already holds; note and stop.
  if (target.revoked) {
    process.stdout.write(`already revoked — nothing to do (${shortId(target.id)})\n`);
    process.exit(0);
  }

  let record;
  try {
    record = revoke(target.id, { agent, reason, at: nowIso() });
  } catch (e) {
    fail(`error: ${e.message}`);
    return;
  }
  appendRecord(path, record);

  if (json) {
    process.stdout.write(JSON.stringify(record) + "\n");
  } else {
    process.stdout.write(
      `revoked ${shortId(target.id)} (attested by ${target.agent}) — "${reason}"\n`
    );
  }
  process.exit(0);
}

// --- hook ------------------------------------------------------------------

function runHookInstall(args) {
  let ledger = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: unexpected argument: ${a}\n\n` + USAGE);
    }
  }

  let result;
  try {
    result = installHook({});
  } catch (e) {
    fail(`error: ${e.message}`);
    return;
  }

  process.stdout.write(
    `${result.action} post-commit hook at ${result.path} — attests changed files\n`
  );
  if (ledger) {
    process.stdout.write(
      `note: set PROVENANT_LEDGER=${ledger} in the hook's environment to record to that ledger\n`
    );
  }
  process.exit(0);
}

function runHookRun(args) {
  let agent = process.env.PROVENANT_AGENT || undefined;
  let ledger = null;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") {
      json = true;
    } else if (a === "--agent") {
      agent = args[++i];
      if (agent == null) fail("error: --agent requires a value\n\n" + USAGE);
    } else if (a === "--ledger") {
      ledger = args[++i];
      if (ledger == null) fail("error: --ledger requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: unexpected argument: ${a}\n\n` + USAGE);
    }
  }

  const { written, notes } = attestCommit({ agent, ledger });
  warnNotes(notes);

  if (json) {
    process.stdout.write(JSON.stringify({ written }) + "\n");
  } else if (written.length === 0) {
    process.stdout.write("no files attested (empty or non-git commit)\n");
  } else {
    process.stdout.write(
      `attested ${written.length} file${written.length === 1 ? "" : "s"} from the commit:\n`
    );
    for (const r of written) {
      const p = (r.meta && r.meta.path) || shortId(r.artifact);
      process.stdout.write(`  ${shortId(r.id)}  ${p}  ${r.agent}\n`);
    }
  }
  process.exit(0);
}

function runHook(args) {
  const sub = args[0];
  if (sub === "install") {
    runHookInstall(args.slice(1));
    return;
  }
  if (sub === "run") {
    runHookRun(args.slice(1));
    return;
  }
  if (sub == null) {
    fail("error: `hook` requires a subcommand: install | run\n\n" + USAGE);
    return;
  }
  fail(`error: unknown hook subcommand: ${sub} (expected install | run)\n\n` + USAGE);
}

// --- otel ------------------------------------------------------------------

function parseOtelArgs(args) {
  let ledger = null;
  const coverageFiles = [];
  let coverageMode = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--coverage") {
      coverageMode = true;
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (coverageMode) {
      // Once --coverage is seen, remaining positionals are the files to audit.
      coverageFiles.push(a);
    } else if (ledger == null) {
      ledger = a;
    } else {
      fail(`error: \`otel\` takes a single <ledger-file> (extra: ${a})\n\n` + USAGE);
    }
  }
  return { ledger, coverageFiles, coverageMode };
}

function runOtel(args) {
  const { ledger, coverageFiles, coverageMode } = parseOtelArgs(args);

  if (ledger == null) {
    fail("error: `otel` requires a <ledger-file> argument\n\n" + USAGE);
    return;
  }

  const { attestations, notes } = loadLedger(ledger);
  warnNotes(notes);

  // --coverage: audit the given files against the ledger and emit the single
  // `provenant.coverage.*` attribute object.
  if (coverageMode) {
    if (coverageFiles.length === 0) {
      fail("error: `otel --coverage` requires one or more file paths\n\n" + USAGE);
      return;
    }
    const hashes = [];
    for (const f of coverageFiles) {
      let content;
      try {
        content = readFileSync(f);
      } catch {
        fail(`error: cannot read file: ${f}`);
        return;
      }
      hashes.push(computeHash(content));
    }
    const report = coverage(hashes, attestations);
    process.stdout.write(JSON.stringify(coverageToSpanAttributes(report)) + "\n");
    process.exit(0);
  }

  // Default: one flat `provenant.*` attribute object per attestation, as a JSON
  // array (empty ledger → `[]`).
  const rows = attestations.map((a) => attestationToSpanAttributes(a));
  process.stdout.write(JSON.stringify(rows) + "\n");
  process.exit(0);
}

// --- main router -----------------------------------------------------------

function main(argv) {
  const args = argv.slice(2);
  const command = args[0];

  if (command === "attest") return runAttest(args.slice(1));
  if (command === "verify") return runVerify(args.slice(1));
  if (command === "chain") return runChain(args.slice(1));
  if (command === "coverage") return runCoverage(args.slice(1));
  if (command === "log") return runLog(args.slice(1));
  if (command === "revoke") return runRevoke(args.slice(1));
  if (command === "hook") return runHook(args.slice(1));
  if (command === "otel") return runOtel(args.slice(1));

  // Unknown / missing subcommand → usage on stderr, exit 1.
  fail(USAGE);
}

main(process.argv);
