# provenant — roadmap

Built the same way as constraintguard / worklease / memport / selfpatch: each feature is one GitHub issue → triaged → specced → implemented → adversarially reviewed → shipped, with a human at the gates. Zero dependencies; harness-neutral; git-backed.

## Design principles
1. **Verifiable offline.** An attestation names an artifact by the sha256 of its content, so anyone can re-hash the file and check the record with only the ledger — no server, no appeal to the tool that wrote it.
2. **The ledger never conflicts with itself.** Append-only JSONL with content-hash IDs, so many agents writing attestations at once can't corrupt or merge-conflict the ledger.
3. **Provenance is first-class.** A record carries *who* (agent), *what* (artifact hash), *why* (intent), and *from what* (parents) — enough to walk a chain back to origins.
4. **Zero-dep, harness-neutral.** Works for Claude Code, Codex, Cursor, or Google Antigravity — anything that can run a CLI or import a function.

## Core (v0.1)

1. **schema** — `validateAttestation` / `validateRevocation` / `validateLedger`. The open shape of an attestation: `{ id, agent, artifact, intent, parents[], created, meta?, signature? }` and a revocation. Foundation. *(mirrors the other repos' #1)*

2. **hash + attest** — `computeHash` fingerprints an artifact's content; `attest(artifact, meta)` builds a validated attestation with a content-hash id; `revoke` supersedes one. Deterministic; pure core with the clock injected.

3. **registry** — `provenant log` / the append-only JSONL ledger store with content-hash integrity and revocation folding. Many agents appending at once must never corrupt it or lose a record.

4. **verify** — `provenant verify <file-or-hash>`. The heart: is this artifact attested, and by whom? Plus `chain` (walk `parents` back to origins, cycle-safe) and `coverage` (what fraction of a repo is attested?). Pure, well-tested, zero-dep.

5. **sign** — optional `sign` / `verifySignature` HMAC-sha256 tamper-evidence, so a record proves *who wrote it*, not just *what it says*. Layered on top; never required.

## Adapters & ecosystem (v0.2)

6. **git-hook adapter (dogfood)** — a post-commit hook that attests every file a commit changed, chaining each new version to the previous attestation of that path. Dogfood on the author's own parallel-agent factory.
7. **Claude Code / Codex / Cursor / Google Antigravity adapters** — surface `attest` to each harness (a hook or an MCP tool) so an agent records provenance as it produces work.
8. **`provenant audit`** — a repo-wide coverage report: which tracked files carry a live attestation, which don't, and which were revoked.
9. **OpenTelemetry bridge** — emit attest/verify/revoke events as span attributes (reuse the family pattern).
10. **asymmetric signatures** — an optional ed25519 layer above HMAC, for cross-org verification without a shared secret.

## The playground (community hook — priority)
A browser page running the **real** library: an agent "produces" a file, provenant attests it, and you watch the ledger grow. Tamper with a byte of the artifact → `verify` goes red offline. Walk the provenance chain of a derived artifact back to its sources. Revoke an attestation and watch coverage drop. Same house style as constraintguard.vercel.app — the visceral "provenance you can check yourself" demo.

## Launch (v0.1 public)
Public repo + green CI + MIT + npm (`@avee1234/provenant`) + the playground + a research-grounded README (the "agent work has no verifiable authorship trail" framing). Then the video/posts kit. Narrative: *agents write more of the repo every week; git blame names the human, not the model, the intent, or the sources; here's the open, zero-dep, offline-verifiable layer that records which agent produced which artifact, why, and from what.*

## Open design questions (for the human gate)
- **artifact granularity** — whole-file content hash only, or also sub-file / symbol-level artifacts? Leaning: file-content hashes for v0.1, finer grains later.
- **tamper-evidence** — HMAC (shared secret, simple) vs asymmetric signatures (cross-org, heavier)? Leaning: optional HMAC for v0.1, ed25519 as a v0.2 layer.
- **ledger location** — a tracked git file (survives, shareable) vs an ignored local file vs a broker? Leaning: a git-tracked append-only JSONL for v0.1 (conflict-free by construction).
- **parents semantics** — should `chain` follow only explicit `parents`, or also infer derivation from same-path history? Leaning: explicit `parents` are authoritative; the git adapter *populates* them from path history.
- **first dogfood surface** — a git post-commit hook (broad) vs a Claude Code hook (closest to home). Leaning: the post-commit hook, since it captures every harness that commits.
