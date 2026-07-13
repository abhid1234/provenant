# provenant — vision

*(working name; alts: attestly, agentproof. Renameable — everything is scoped `@avee1234/provenant`.)*

## The one-liner
**The open provenance format for AI-agent work.** When an agent produces something — a file, a patch, a generated asset — it writes an *attestation*: a small, verifiable record of *which agent* produced *which artifact*, *why*, and *derived from what*. The records form an append-only, content-addressed ledger anyone can verify offline. So a repo full of agent-written work finally has a portable, tamper-evident authorship trail.

## The problem (mid-2026)
Coding agents now write a large and growing share of the code, docs, and assets in a repo — Claude Code, Codex, Cursor, and Google Antigravity all commit on their own. But the work lands with **no verifiable record of where it came from.** `git blame` shows the human who ran the agent, not the model, the harness, the prompt intent, or the upstream artifacts it was derived from. Once a change is merged, that context is gone.

That gap is getting expensive:

> "As more of the codebase is authored by agents, teams can't answer basic questions — *which model wrote this, under what intent, and what did it build on?* — and there's no neutral, portable way to record or check it."

Reviewers can't tell agent output from human output. Security teams can't audit which artifacts a compromised or misconfigured agent touched. Compliance regimes that will soon *require* AI-provenance disclosure have nothing standard to point at. And every harness that gestures at "signed agent commits" does it in its own private, non-portable way.

## The wedge — a provenance format, not a platform
provenant is **not** a CI system, **not** a signing service, and **not** a policy engine. It's the thin open layer *underneath* those:

- an open JSON schema for an **attestation** — `{ id, agent, artifact, intent, parents[], created, meta?, signature? }`
- a **conflict-free, append-only ledger** (JSONL with content-hash IDs, so the ledger itself never merge-conflicts and every record self-verifies)
- the verbs any harness can call: **`attest`** (record what you produced), **`verify`** (is this artifact attested, and by whom?), **`chain`** (what did it derive from?), **`coverage`** (what fraction of a repo is attested?)
- optional **HMAC tamper-evidence** for *who wrote the record*, not just *what it says*
- offline and portable by construction — verification needs only the ledger and the artifact, no server. Zero dependencies, harness-neutral.

This is the exact playbook behind [opentrajectory](https://github.com/abhid1234/opentrajectory) (traces), [constraintguard](https://github.com/abhid1234/constraintguard) (constraints), worklease (coordination), memport (memory), and selfpatch (self-modification): **own the open interoperability standard, not the runtime.** provenant is that standard for the one thing agent work currently lacks — a verifiable authorship trail.

## Why it's defensible
- **Neutral by construction** — no single agent vendor will build the format that certifies a *rival's* agent output; a third party is the natural home for the standard.
- **Content-addressed, so verification is trustless** — an attestation names an artifact by the sha256 of its bytes, so anyone can re-hash the file and check the record offline, with no appeal to the tool that wrote it.
- **Small, verifiable surface** — a schema + an append-only ledger + a verifier. The same shape the factory builds and adversarially reviews well.

## The unfair advantage
The author runs a parallel-agent software factory where dozens of agent-authored artifacts land daily and *nobody can currently prove which agent produced which*. provenant's first user, testbed, and demo is the author's own fleet.

## What "done for v0.1" looks like
A `provenant` CLI + zero-dep library that lets an agent attest an artifact it produced (with intent and parents), verify offline whether any artifact is attested and by whom, walk an artifact's provenance chain back to what it derived from, audit a repo's attestation coverage, and optionally HMAC-sign records for tamper-evidence — all backed by a ledger that never conflicts with itself.

## Non-goals
- Not a CI or a build system (it records provenance; it doesn't run the work).
- Not a PKI / certificate authority (HMAC tamper-evidence for v0.1; asymmetric signing is a later, optional layer).
- Not access control or policy enforcement (it produces the verifiable record a policy engine can act on — it isn't the engine).
