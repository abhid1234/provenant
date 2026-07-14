// provenant — `attest` + `revoke` core (pure record constructors).
//
// `attest` builds a valid attestation record with a deterministic content-hash
// id, with NO I/O and NO clock — `created` is injected, so the result is fully
// determined by its inputs and unit-testable. The CLI (`bin/provenant.js`) is
// the only part that reads the clock and appends to the ledger.
//
// Unlike the schema validators (which never throw), these constructors *do*
// throw a clear Error on invalid input: a record is meaningless without an
// agent, an intent, a valid artifact digest, and a real timestamp, so building
// one from bad inputs is a programming error, not a data-validation result.

import { computeRecordId } from "./registry.js";
import { computeHash } from "./hash.js";
import { isSha256Hex, isIso8601Utc, validateEvaluation } from "./schema.js";

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Resolve the `artifact` field: either an already-computed digest passed as
// `{ hash }`, or raw content (string/Buffer) hashed here via `computeHash`.
function resolveArtifact(artifact) {
  if (Buffer.isBuffer(artifact) || typeof artifact === "string") {
    return computeHash(artifact);
  }
  if (isPlainObject(artifact) && "hash" in artifact) {
    if (!isSha256Hex(artifact.hash)) {
      throw new Error("attest: artifact.hash must be a sha256 hex digest (64 hex chars)");
    }
    return artifact.hash;
  }
  throw new Error(
    "attest: artifact must be a string, a Buffer, or an object { hash } with a sha256 digest"
  );
}

// attest(artifact, meta) → an attestation record matching ATTESTATION_FIELDS order.
//
//   artifact    — the artifact's content (string/Buffer, hashed here) OR an
//                 object `{ hash }` carrying an already-computed sha256 digest.
//   meta.agent  — who produced the artifact (e.g. "claude-opus-4-8/claude-code")
//   meta.intent — why it was produced (non-empty)
//   meta.parents — attestation ids this work derives from (default [])
//   meta.created — ISO-8601-UTC timestamp the artifact was attested at
//   meta.meta   — optional free-form object (harness/model/session, …)
//   meta.evaluation — optional attested CLAIM about the artifact's quality:
//                 `{ score (0..1), method, checks?, evaluator? }`. Part of the
//                 canonical content, so the content-hash id (and any signature)
//                 cover it — the score can't be silently edited. When absent,
//                 the record is byte-for-byte identical to a no-eval attestation.
//
// `id` is the ledger's shared content hash of the whole record (its `id`
// excluded), so an attestation's id IS its content hash and it resolves cleanly
// through the store — one hasher across every record type. Throws on any invalid
// input rather than emitting a malformed record.
export function attest(artifact, meta = {}) {
  const { agent, intent, parents = [], created, meta: metaObj, evaluation } = meta;

  const artifactHash = resolveArtifact(artifact);

  if (!isNonEmptyString(agent)) {
    throw new Error("attest: agent must be a non-empty string");
  }
  if (!isNonEmptyString(intent)) {
    throw new Error("attest: intent must be a non-empty string");
  }
  if (!isIso8601Utc(created)) {
    throw new Error("attest: created must be an ISO-8601 UTC timestamp (…Z)");
  }
  if (!Array.isArray(parents)) {
    throw new Error("attest: parents must be an array of attestation ids");
  }
  for (const p of parents) {
    if (!isSha256Hex(p)) {
      throw new Error("attest: every parent must be an attestation id (sha256 hex digest)");
    }
  }
  if (metaObj !== undefined && !isPlainObject(metaObj)) {
    throw new Error("attest: meta must be an object");
  }
  // An evaluation, when given, must be a well-formed claim: validate it up front
  // (non-throwing validator) and throw a clear error rather than hashing a
  // malformed score into the record.
  if (evaluation !== undefined) {
    const res = validateEvaluation(evaluation);
    if (!res.valid) {
      const detail = res.errors
        .map((e) => `${e.path === "" ? "<root>" : e.path}: ${e.message}`)
        .join("; ");
      throw new Error(`attest: evaluation is invalid: ${detail}`);
    }
  }

  // Build the record in canonical field order (id excluded — it is derived).
  // `evaluation` sits with the other content, so it is covered by the content
  // hash and any signature; omitted entirely when absent (backward-compatible).
  const record = {
    type: "attestation",
    agent,
    artifact: artifactHash,
    intent,
    parents: [...parents],
    created,
    ...(metaObj !== undefined ? { meta: metaObj } : {}),
    ...(evaluation !== undefined ? { evaluation } : {}),
  };
  return { id: computeRecordId(record), ...record };
}

// revoke(attestationId, meta) → a revocation record that supersedes an
// attestation. Pure and deterministic (like `attest`): `at` is injected. Throws
// on invalid input.
//
//   attestationId — the sha256 id of the attestation being revoked
//   meta.agent    — who is revoking
//   meta.reason   — why (non-empty)
//   meta.at       — ISO-8601-UTC timestamp of the revocation
export function revoke(attestationId, meta = {}) {
  const { agent, reason, at } = meta;

  if (!isSha256Hex(attestationId)) {
    throw new Error("revoke: attestationId must be an attestation id (sha256 hex digest)");
  }
  if (!isNonEmptyString(agent)) {
    throw new Error("revoke: agent must be a non-empty string");
  }
  if (!isNonEmptyString(reason)) {
    throw new Error("revoke: reason must be a non-empty string");
  }
  if (!isIso8601Utc(at)) {
    throw new Error("revoke: at must be an ISO-8601 UTC timestamp (…Z)");
  }

  const record = {
    type: "revocation",
    attestation_id: attestationId,
    agent,
    reason,
    at,
  };
  return { id: computeRecordId(record), ...record };
}
