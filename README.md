# provenant

**The open provenance format for AI-agent work.** When an agent produces something — a file, a patch, a generated asset — it writes an *attestation*: a small, verifiable record of *which agent* produced *which artifact*, *why*, and *derived from what*. The records form an append-only, content-addressed ledger anyone can verify offline. So a repo full of agent-written work finally has a portable, tamper-evident authorship trail. Zero dependencies.

> Working name — see [`vision.md`](vision.md). Grounded in the mid-2026 state of agent-authored codebases.

Coding agents now write a large and growing share of the code, docs, and assets in a repo — Claude Code, Codex, Cursor, and Google Antigravity all commit on their own — but the work lands with **no verifiable record of where it came from**. `git blame` shows the human who ran the agent, not the model, the harness, the intent, or the upstream artifacts it derived from. Reviewers can't tell agent output from human output; security teams can't audit which artifacts a misconfigured agent touched; and every harness that gestures at "signed agent commits" does it in its own private, non-portable way. provenant is the missing layer: an open format for *authorship and derivation*, not another platform.

```bash
npx @avee1234/provenant attest src/auth.js --intent "add OAuth"   # record what I produced
npx @avee1234/provenant verify src/auth.js                        # is this attested, and by whom?
npx @avee1234/provenant chain <id>                                # what did it derive from?
npx @avee1234/provenant coverage src/**/*.js                      # what fraction of the repo is attested?
npx @avee1234/provenant revoke <id> --reason "superseded"         # supersede an attestation
npx @avee1234/provenant hook install                              # auto-attest every file a commit changes
```

**Why it's different:** content-addressed, so verification is *trustless* — an attestation names an artifact by the sha256 of its bytes, so anyone can re-hash the file and check the record offline, with no appeal to the tool that wrote it. The ledger is append-only JSONL with content-hash IDs, so many agents writing attestations at once can't corrupt it or merge-conflict it with itself. Harness-neutral: Claude Code, Codex, Cursor, Google Antigravity, or a factory worker — anything that can run a CLI or import a function.

Same open-format-and-conformance playbook as [opentrajectory](https://github.com/abhid1234/opentrajectory) (traces) and [worklease](https://github.com/abhid1234/worklease) (coordination) — the provenance standard for the one thing an agent fleet can't currently prove: *which agent produced which artifact, why, and from what.*

## The attestation format

An attestation is one JSON object. `id` is the sha256 content hash of the record itself (its own `id` excluded), so a record's identity *is* its content — a tampered line no longer matches its id and is dropped on read. `artifact` is the sha256 of the artifact's bytes, so verification never needs the bytes stored in the ledger.

```json
{
  "id": "325be403c7480ede4648a3aac500437b545b6a41c0323daf08d2793ed9595e9a",
  "type": "attestation",
  "agent": "claude-opus-4-8/claude-code",
  "artifact": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "intent": "add OAuth login flow",
  "parents": ["a1b2c3…"],
  "created": "2026-07-11T12:00:00Z",
  "meta": { "harness": "git", "commit": "deadbeef…", "path": "src/auth.js" },
  "signature": "f0e1d2…"
}
```

- `agent` — **who** produced the artifact (model / harness identity).
- `artifact` — **what**, as the sha256 hex of its content.
- `intent` — **why** it was produced (non-empty).
- `parents` — **from what** — the attestation ids this work derives from (`chain` walks these back to origins).
- `created` — an ISO-8601-**UTC** timestamp (`…Z`; offsets and impossible calendar dates are rejected).
- `meta` *(optional)* — free-form context (harness / model / session / path).
- `signature` *(optional)* — a digest proving *who wrote the record*, not just what it says: HMAC-sha256 (shared secret) or an ed25519 signature (cross-org, no shared secret).

A **revocation** supersedes an attestation: `{ id, type: "revocation", attestation_id, agent, reason, at }`. Revocations are appended, never deletions — the ledger stays append-only, and `verify` folds them in at read time.

## Library API

Zero-dependency ESM. `import { … } from "@avee1234/provenant"`. Every function is pure and clock-injected (no I/O except the ledger store), so the whole core is deterministic and unit-testable.

**Schema & validation** — never throw; each returns `{ valid, errors }` collecting *every* violation.
- `validateAttestation(obj)` / `validateRevocation(obj)` / `validateLedger(arr)`
- `isSha256Hex(s)`, `isIso8601Utc(s)` — the two format primitives
- `ATTESTATION_FIELDS`, `REVOCATION_FIELDS`, `RECORD_TYPES`, `ERROR_CODES`

**Hash & construct** — pure record constructors (throw on bad input rather than emit a malformed record).
- `computeHash(content)` → the sha256 hex of a string/Buffer (the artifact fingerprint)
- `attest(content, { agent, intent, parents, created, meta })` → an attestation record. `content` is a string/Buffer (hashed here) or `{ hash }` (a pre-computed digest).
- `revoke(attestationId, { agent, reason, at })` → a revocation record
- `computeRecordId(record)` / `canonicalize(record)` — the content-hash id primitives

**Ledger store** — the append-only JSONL layer.
- `loadLedger(path)` → `{ attestations, notes }` (missing file → empty, no throw; folds revocations, drops tampered/unparseable lines with a note)
- `appendRecord(path, record)` — append exactly one line (`O_APPEND`); existing lines are never rewritten
- `resolveRecords(records)` → fold a raw log into the current attestation array
- `defaultLedgerPath(cwd)` — `PROVENANT_LEDGER`, else `.provenant/ledger.jsonl`
- `listAttestations`, `shortId`

**Verify & query** — pure, offline, over a resolved array.
- `verify(artifactHash, attestations)` → `{ attested, record, revoked }`
- `chainOf(attestationId, attestations)` → the ordered provenance chain (record + ancestors via `parents`, deduped and cycle-safe)
- `coverage(artifactHashes, attestations)` → `{ score, total, attested, unattested, revoked }`

**Sign** *(optional HMAC tamper-evidence — shared secret)*
- `sign(record, secret)` → HMAC-sha256 hex over the record's canonical pre-image
- `verifySignature(record, secret)` → constant-time boolean

**Sign (ed25519)** *(optional asymmetric tamper-evidence — cross-org, no shared secret)*
- `generateKeypair()` → `{ publicKey, privateKey }` PEM strings (SPKI / PKCS#8)
- `signAsym(record, privateKeyPem)` → a detached ed25519 signature (hex) over the same canonical pre-image
- `verifyAsym(record, publicKeyPem, signatureHex?)` → boolean; pass `signatureHex` (detached) or omit it to verify the record's own `signature` (embedded). Never throws — a bad key/signature is `false`.

**OpenTelemetry** *(pure record → span-attribute bridge)*
- `attestationToSpanAttributes(record)` → a FLAT `provenant.*` attribute object (scalars only; `parents` joined to a comma string, plus `parent_count`, `revoked`, `signed`)
- `coverageToSpanAttributes(report)` → a FLAT `provenant.coverage.*` attribute object from a `coverage()` result

**Git adapter** *(the dogfood surface)*
- `attestCommit({ cwd, agent, ledger, created, intent })`, `changedPaths`, `installHook`, `hookPath`, `renderHookBlock`

## CLI

```bash
provenant attest <file> --intent "<why>" [--agent <id>] [--parents <ids>] [--ledger <path>] [--json]
provenant verify <file-or-hash> [--ledger <path>] [--json]
provenant chain <attestation-id> [--ledger <path>] [--json]
provenant coverage <path...> [--ledger <path>] [--json]
provenant log [--all] [--agent <id>] [--ledger <path>] [--json]
provenant revoke <attestation-id> --reason "<why>" [--agent <id>] [--ledger <path>] [--json]
provenant hook install [--ledger <path>]
provenant hook run [--agent <id>] [--ledger <path>] [--json]
provenant otel <ledger-file> [--coverage <path...>]
```

- **`attest <file>`** — hash the file's content and append an attestation: which agent produced it, why, and what it derives from. The record is validated before it's written. Exit `0` on write.
- **`verify <file-or-hash>`** — is the artifact (a file, hashed here, or a raw sha256 digest) attested? Exit `0` if a live attestation exists, `1` if unattested or revoked.
- **`chain <id>`** — print the provenance chain of an attestation (the record and every ancestor via `parents`). Accepts a full id or an unambiguous prefix. Exit `1` if the id is unknown.
- **`coverage <path...>`** — audit what fraction of the given files carry a live attestation. Exit `0` when all are attested, `1` when any is unattested or revoked.
- **`log`** — list the ledger's live attestations (who produced what, why, from what). `--all` also shows revoked ones, labeled; `--agent` filters to one producer.
- **`revoke <id> --reason`** — supersede an attestation by appending a revocation. A no-op with a note if it is already revoked (still exit `0`).
- **`hook install` / `hook run`** — install a **git post-commit hook** that attests every file a commit changed, chaining each new version to the previous attestation of the same path. Post-commit (not pre-commit) is deliberate: provenance records what *did* happen, and the hook only ever appends — it never blocks or alters a commit. Install is idempotent and preserves any existing hook (it manages only a marked block).
- **`otel <ledger-file>`** — emit OpenTelemetry-style span attributes (JSON) for the ledger: one flat `provenant.*` attribute object per attestation. With `--coverage <path...>`, instead emit the single `provenant.coverage.*` attribute object auditing those files against the ledger.

Common flags: `--agent <id>` (or `PROVENANT_AGENT`), `--ledger <path>` (or `PROVENANT_LEDGER`, default `.provenant/ledger.jsonl`), `--json` for machine-readable output.

## The ledger

The store is an **append-only JSONL file** (default `.provenant/ledger.jsonl`), meant to be **committed** so the provenance trail travels with the repo across worktrees and harnesses. New records are appended as whole lines; existing lines are never rewritten. Every record's `id` is a content hash of its own content, so a duplicated append is idempotent on read and two agents appending at once union-merge cleanly instead of conflicting. A line that fails its integrity check (its `id` no longer matches its content — i.e. it was tampered) or won't parse is skipped with a note surfaced to stderr — one bad line never discards the rest of the ledger.

## OpenTelemetry

provenant projects records onto **span attributes** so provenance rides along with the traces an agent fleet already emits. `attestationToSpanAttributes(record)` returns a **flat** `provenant.*` object — `provenant.agent`, `provenant.artifact`, `provenant.intent`, `provenant.parents` (the ids joined to a comma string) with `provenant.parent_count`, `provenant.created`, and the `provenant.revoked` / `provenant.signed` booleans — values are only strings, numbers, and booleans, so any exporter accepts them with no nesting. `coverageToSpanAttributes(coverage(…))` does the same for a repo audit under `provenant.coverage.*`. Both are pure and deterministic; `provenant otel <ledger>` prints them as JSON. Same bridge convention as the rest of the family (constraintguard's `cg otel`).

## ed25519 signatures

The HMAC layer proves authorship to anyone holding the shared secret — which is everyone who can verify, so it can't prove authorship *across* an org boundary. The optional **ed25519** layer closes that: the author signs with a private key nobody else holds, and anyone verifies with the matching public key — cross-org tamper-evidence with no shared secret. `generateKeypair()` mints a keypair (SPKI / PKCS#8 PEM), `signAsym(record, privateKeyPem)` signs the *same* canonical pre-image the ledger already hashes, and `verifyAsym(record, publicKeyPem, signatureHex?)` verifies the detached signature or the record's own embedded `signature`. Node's built-in `crypto` only — zero external dependency. Layered on top like HMAC; never required to attest or verify.

## Install

```bash
npm install @avee1234/provenant      # library
npx @avee1234/provenant attest …     # CLI, no install
```

Requires Node ≥ 18. Run the test suite with `node --test`.

Status: **v0.2** — see [`roadmap.md`](roadmap.md). MIT · zero dependencies · harness-neutral.
