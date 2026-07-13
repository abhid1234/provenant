// provenant — the append-only ledger store.
//
// A ledger is an append-only JSONL file (one JSON record per line). This module
// is the single home for the store: a small set of *pure* functions (canonical
// serialization, content-hash ids, log resolution) plus a thin I/O layer
// (`appendRecord`, `loadLedger`) that keeps every filesystem access in one
// place. The design is deliberately lock-free — writes are single-line `O_APPEND`
// writes, reads fold the whole log into the current attestation array, and every
// record self-identifies by a content hash, so concurrent or duplicated appends
// resolve cleanly instead of conflicting. Node's built-in `crypto` is the only
// "dependency"; there are zero runtime packages.

import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

// --- pure core -------------------------------------------------------------

// canonicalize(record) → deterministic JSON string with sorted keys and no
// incidental whitespace, over the record EXCLUDING its own `id`. Recurses so
// key ordering can never perturb the digest at any depth. Used as the hash
// pre-image (and, in `sign`, the HMAC pre-image), so it does not need to
// round-trip to a value.
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

// computeRecordId(record) → the sha256 content hash of the record (its `id`
// excluded). Deterministic and content-addressed: identical content ⇒ identical
// id, so a duplicated append is idempotent on read and a tampered line no longer
// matches its own id. Both `attest` and `revoke` use this same helper so a
// record's `id` IS its content hash — one shared implementation across every
// record type.
export function computeRecordId(record) {
  return createHash("sha256").update(canonicalize(record)).digest("hex");
}

// shortId(id) → first 8 hex chars, the compact id `log` shows and `revoke`
// accepts as a prefix.
export function shortId(id) {
  return typeof id === "string" ? id.slice(0, 8) : String(id);
}

// listAttestations(attestations) → the subset that is still live (not revoked).
// Pure selector kept here for direct unit testing.
export function listAttestations(attestations) {
  return attestations.filter((a) => !a.revoked);
}

// resolveRecords(records, { now }) → { attestations, notes }
//
// Folds an already-parsed append log (order = append order) into the current
// attestation array. Pure and total: `now` (epoch ms) is accepted for signature
// parity with the rest of the store (attestations don't decay, so it is
// reserved), and no bad field value throws. Nothing is written back — every
// derived flag is computed here at read time.
//
//   1. Integrity filter — drop any record whose `id` doesn't equal its own
//      content hash (tamper/corruption), with a note. One bad line never
//      discards the rest of the ledger.
//   2. Fold attestations — latest attestation record per `id` wins
//      (content-addressed, so normally identical; tolerant of a re-append →
//      idempotent).
//   3. Apply revocations — a `revocation` record marks its `attestation_id`
//      `revoked: true` (with revoked_by / revoked_at / revoked_reason); an
//      unknown `attestation_id` is noted and ignored.
//
// Returns the attestations sorted by `created` ascending plus the collected
// notes.
export function resolveRecords(records, opts = {}) {
  const { now = Date.now() } = opts;
  void now; // reserved: attestations have no wall-clock decay
  const notes = [];

  // 1. Integrity filter (also drops non-objects, which can't self-hash).
  const valid = [];
  records.forEach((r, i) => {
    if (r === null || typeof r !== "object" || Array.isArray(r)) {
      notes.push(`skipped record ${i}: not an object`);
      return;
    }
    if (r.id !== computeRecordId(r)) {
      notes.push(`skipped record ${i}: id/content mismatch`);
      return;
    }
    valid.push(r);
  });

  // 2. Fold attestations / collect revocations (a record is a revocation iff
  //    type === "revocation"; an attestation iff no type or type ===
  //    "attestation"; anything else is forward-compat noise, skipped).
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
      notes.push(
        `revocation for unknown attestation_id ${shortId(rev.attestation_id)} ignored`
      );
      continue;
    }
    att.revoked = true;
    att.revoked_by = rev.agent;
    att.revoked_at = rev.at;
    att.revoked_reason = rev.reason;
    if (rev.agent !== att.agent) {
      notes.push(
        `attestation ${shortId(att.id)} revoked by ${rev.agent}, attested by ${att.agent}`
      );
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

// --- I/O layer -------------------------------------------------------------

// defaultLedgerPath(cwd) → the ONE place the default ledger location is defined;
// `attest`, `verify`, `log`, and `revoke` all call it. `PROVENANT_LEDGER`
// overrides, else a git-tracked `.provenant/ledger.jsonl` at the repo root.
export function defaultLedgerPath(cwd = process.cwd()) {
  return process.env.PROVENANT_LEDGER || join(cwd, ".provenant", "ledger.jsonl");
}

// appendRecord(path, record) → the stored record (with its content-hash `id`).
// Assigns `id` if absent, creates the parent directory, then appends exactly one
// JSON line terminated by "\n" with the `"a"` flag (O_APPEND). Existing lines are
// never rewritten — this is the whole safety story. Used by `attest` and
// `revoke`.
export function appendRecord(path, record) {
  const stored = record.id ? record : { ...record, id: computeRecordId(record) };
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(stored) + "\n");
  return stored;
}

// loadLedger(path, { now }) → { attestations, notes }
//
// Reads the JSONL file (missing file → empty ledger, no throw), parses each
// non-blank line tolerantly (a line that won't parse is dropped with a note,
// never aborting the load), and returns the resolved current ledger via
// `resolveRecords`.
export function loadLedger(path, opts = {}) {
  const { now = Date.now() } = opts;

  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    if (e && e.code === "ENOENT") return { attestations: [], notes: [] };
    throw e;
  }

  const parsed = [];
  const parseNotes = [];
  raw.split("\n").forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      parsed.push(JSON.parse(trimmed));
    } catch {
      parseNotes.push(`skipped unparseable line ${i + 1}`);
    }
  });

  const resolved = resolveRecords(parsed, { now });
  return { attestations: resolved.attestations, notes: [...parseNotes, ...resolved.notes] };
}
