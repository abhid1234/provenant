// provenant — browser-safe content-hash + record layer for the playground.
//
// `verify.js` and `schema.js` are pure and copied VERBATIM from src/. This file
// is the browser shim for the two things src/ does with node:crypto — content
// hashing (hash.js) and content-hash record ids (registry.js). The PURE fold /
// canonicalization / constructor logic is copied verbatim from the real source;
// only the sha256 primitive is swapped from Node's `createHash` to the browser's
// async `crypto.subtle.digest('SHA-256', …)`. The DECISIONS (what a record looks
// like, how the log folds, what an id is) are the real library's, unchanged.

// --- the one browser primitive (replaces node:crypto createHash) -------------

// sha256Hex(str) → lowercase 64-char hex digest of a UTF-8 string, via SubtleCrypto.
export async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// --- pure core, VERBATIM from src/registry.js (id excluded from the digest) --

// canonicalize(record) → deterministic JSON string with sorted keys, over the
// record EXCLUDING its own `id`. (verbatim from registry.js)
export function canonicalize(record) {
  const { id: _id, ...rest } = record;
  return stableStringify(rest);
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

// shortId(id) → first 8 hex chars. (verbatim from registry.js)
export function shortId(id) {
  return typeof id === "string" ? id.slice(0, 8) : String(id);
}

// listAttestations(attestations) → the still-live subset. (verbatim)
export function listAttestations(attestations) {
  return attestations.filter((a) => !a.revoked);
}

// --- browser-async swaps for the two node:crypto callers ---------------------

// computeHash(content) → sha256 hex of the artifact's bytes (async). The browser
// analog of src/hash.js computeHash (string content, hashed as UTF-8).
export async function computeHash(content) {
  return sha256Hex(content);
}

// computeRecordId(record) → sha256 content hash of the record, id excluded
// (async). The browser analog of src/registry.js computeRecordId.
export async function computeRecordId(record) {
  return sha256Hex(canonicalize(record));
}

// --- pure record constructors, ported from src/attest.js (throw on bad input) -

import { validateEvaluation } from "./schema.js";

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}
function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// A lowercase sha256 hex digest (64 hex chars) — same gate as schema.js.
const SHA256_HEX = /^[0-9a-f]{64}$/;
function isSha256Hex(s) {
  return typeof s === "string" && SHA256_HEX.test(s);
}
// Strict ISO-8601 UTC — same gate as schema.js isIso8601Utc.
const ISO8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
function isIso8601Utc(s) {
  if (typeof s !== "string" || !ISO8601_UTC.test(s)) return false;
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) return false;
  return new Date(ms).toISOString().slice(0, 10) === s.slice(0, 10);
}

async function resolveArtifact(artifact) {
  if (typeof artifact === "string") return computeHash(artifact);
  if (isPlainObject(artifact) && "hash" in artifact) {
    if (!isSha256Hex(artifact.hash)) {
      throw new Error("attest: artifact.hash must be a sha256 hex digest (64 hex chars)");
    }
    return artifact.hash;
  }
  throw new Error("attest: artifact must be a string or an object { hash } with a sha256 digest");
}

// attest(content, meta) → an attestation record with a real content-hash id.
// Ported from src/attest.js: same validation, same canonical field order, same
// computeRecordId — only async because the digest is async in the browser.
export async function attest(artifact, meta = {}) {
  const { agent, intent, parents = [], created, meta: metaObj, evaluation } = meta;

  const artifactHash = await resolveArtifact(artifact);

  if (!isNonEmptyString(agent)) throw new Error("attest: agent must be a non-empty string");
  if (!isNonEmptyString(intent)) throw new Error("attest: intent must be a non-empty string");
  if (!isIso8601Utc(created)) {
    throw new Error("attest: created must be an ISO-8601 UTC timestamp (…Z)");
  }
  if (!Array.isArray(parents)) throw new Error("attest: parents must be an array of attestation ids");
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
  return { id: await computeRecordId(record), ...record };
}

// revoke(attestationId, meta) → a revocation record. Ported from src/attest.js.
export async function revoke(attestationId, meta = {}) {
  const { agent, reason, at } = meta;

  if (!isSha256Hex(attestationId)) {
    throw new Error("revoke: attestationId must be an attestation id (sha256 hex digest)");
  }
  if (!isNonEmptyString(agent)) throw new Error("revoke: agent must be a non-empty string");
  if (!isNonEmptyString(reason)) throw new Error("revoke: reason must be a non-empty string");
  if (!isIso8601Utc(at)) throw new Error("revoke: at must be an ISO-8601 UTC timestamp (…Z)");

  const record = {
    type: "revocation",
    attestation_id: attestationId,
    agent,
    reason,
    at,
  };
  return { id: await computeRecordId(record), ...record };
}

// --- resolveRecords, ported VERBATIM from src/registry.js (async id check) ----
//
// Folds a parsed append log into the current attestation array: (1) integrity
// filter — drop any record whose id ≠ its own content hash; (2) fold latest
// attestation per id; (3) apply revocations. Only computeRecordId is awaited;
// every decision is the real library's.
export async function resolveRecords(records, opts = {}) {
  const { now = Date.now() } = opts;
  void now; // reserved: attestations have no wall-clock decay
  const notes = [];

  // 1. Integrity filter (also drops non-objects, which can't self-hash).
  const valid = [];
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r === null || typeof r !== "object" || Array.isArray(r)) {
      notes.push(`skipped record ${i}: not an object`);
      continue;
    }
    if (r.id !== (await computeRecordId(r))) {
      notes.push(`skipped record ${i}: id/content mismatch`);
      continue;
    }
    valid.push(r);
  }

  // 2. Fold attestations / collect revocations.
  const attestations = new Map();
  const revocations = [];
  for (const r of valid) {
    const type = r.type == null ? "attestation" : r.type;
    if (type === "attestation") {
      attestations.set(r.id, { ...r });
    } else if (type === "revocation") {
      revocations.push(r);
    } else {
      notes.push(`skipped record ${shortId(r.id)}: unknown type "${r.type}"`);
    }
  }

  // 3. Apply revocations.
  for (const rev of revocations) {
    const att = attestations.get(rev.attestation_id);
    if (!att) {
      notes.push(`revocation for unknown attestation_id ${shortId(rev.attestation_id)} ignored`);
      continue;
    }
    att.revoked = true;
    att.revoked_by = rev.agent;
    att.revoked_at = rev.at;
    att.revoked_reason = rev.reason;
    if (rev.agent !== att.agent) {
      notes.push(`attestation ${shortId(att.id)} revoked by ${rev.agent}, attested by ${att.agent}`);
    }
  }

  const resolved = [...attestations.values()].sort(byCreated);
  return { attestations: resolved, notes };
}

// Sort by `created` ascending; unparseable/absent timestamps sort last, stably.
function byCreated(a, b) {
  const ca = Date.parse(a.created);
  const cb = Date.parse(b.created);
  const na = Number.isNaN(ca);
  const nb = Number.isNaN(cb);
  if (na && nb) return 0;
  if (na) return 1;
  if (nb) return -1;
  return ca - cb;
}
