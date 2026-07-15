// provenant — `sign` core (optional HMAC tamper-evidence layer).
//
// Content-hash ids already make the ledger *tamper-evident against corruption*:
// change a byte and the record no longer matches its own id, so `resolveRecords`
// drops it. But anyone can recompute a content hash, so a content hash alone
// doesn't prove *who* wrote the record. An optional HMAC-sha256 `signature`,
// keyed by a shared secret, closes that gap: only a holder of the secret can
// produce a signature that `verifySignature` accepts, so a signed attestation is
// evidence it was written by a party that held the key — not forged or replayed
// by one that didn't. Pure and zero-dependency: Node's `crypto` only.

import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalize } from "./registry.js";

// The HMAC pre-image: the record's canonical form with BOTH its `id` (excluded
// by `canonicalize`) and its `signature` (stripped here) removed, so a record
// can be signed and then have the signature attached without the signature
// perturbing its own pre-image.
function preimage(record) {
  const { signature: _sig, ...rest } = record;
  return canonicalize(rest);
}

// sign(record, secret) → the HMAC-sha256 hex digest over the record's canonical
// pre-image (id and signature excluded), keyed by `secret`. Deterministic:
// identical record + secret ⇒ identical signature.
export function sign(record, secret) {
  return createHmac("sha256", secret).update(preimage(record)).digest("hex");
}

// verifySignature(record, secret) → true iff `record.signature` is present and
// equals the HMAC recomputed under `secret`. A missing/non-string signature, a
// wrong secret, or any tampered field returns false. The comparison is
// constant-time (via `timingSafeEqual`) so it doesn't leak the signature through
// timing.
export function verifySignature(record, secret) {
  if (!record || typeof record.signature !== "string") return false;
  // Require EXACTLY 64 lowercase hex chars first. Buffer.from(str, "hex") decodes
  // permissively — it stops at the first invalid char — so "…<valid 64>garbage"
  // would otherwise decode to the same 32 bytes and verify. An HMAC-sha256 hex
  // digest is exactly 64 chars.
  if (!/^[0-9a-f]{64}$/.test(record.signature)) return false;
  const expected = sign(record, secret);
  const a = Buffer.from(record.signature, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
