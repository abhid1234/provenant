// provenant — content hashing (the artifact fingerprint primitive).
//
// `computeHash` is the one place an artifact's *content* becomes a stable,
// portable identity: the sha256 hex digest of its bytes. An attestation records
// this digest (not the bytes), so a ledger says which *content* an agent
// produced without ever storing the content itself — the record is portable and
// the artifact is verifiable by re-hashing it offline. Pure and zero-dependency:
// Node's built-in `crypto` is the only "dependency".

import { createHash } from "node:crypto";

// computeHash(content) → the sha256 hex digest of `content`. Accepts a string
// (hashed as UTF-8) or a Buffer (hashed as raw bytes). Deterministic and
// content-addressed: identical content ⇒ identical digest, so re-hashing an
// artifact offline reproduces the exact `artifact` field an attestation carries.
export function computeHash(content) {
  return createHash("sha256").update(content).digest("hex");
}
