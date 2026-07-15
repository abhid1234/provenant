// provenant — `sign-asym` core (optional ed25519 asymmetric-signature layer).
//
// The HMAC layer in `sign.js` proves *who wrote a record* to anyone who holds
// the shared secret — which is everyone who can verify, so it can't prove
// authorship *across* an org boundary. ed25519 closes that gap: the author signs
// with a private key nobody else has, and anyone can verify with the matching
// public key. So a record signed this way is cross-org tamper-evidence — a
// reader in another org can confirm which key produced the record without ever
// sharing a secret with the author. The pre-image is the record's canonical form
// (the SAME `canonicalize` the ledger's content-hash id and the HMAC layer use),
// with `id` (excluded by `canonicalize`) and `signature` removed, so a record
// can be signed and then carry its own signature without perturbing the payload.
//
// Optional and layered, exactly like `sign.js` — never required to attest or
// verify. Zero-dependency: Node's built-in `crypto` ed25519 only.

import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { canonicalize } from "./registry.js";

// The signature pre-image: the record's canonical form with `id` (dropped by
// `canonicalize`) and `signature` removed, so signing then attaching the
// signature does not change what was signed. Shared by `signAsym` and both forms
// of `verifyAsym`.
function preimage(record) {
  const { signature: _sig, ...rest } = record;
  return Buffer.from(canonicalize(rest));
}

// generateKeypair() → { publicKey, privateKey } as PEM strings (SPKI public /
// PKCS#8 private). A fresh ed25519 keypair; keep the private key secret, publish
// or distribute the public key so others can verify what this key signs.
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// signAsym(record, privateKeyPem) → a detached ed25519 signature (hex) over the
// record's canonical pre-image (id and signature excluded), produced with the
// PKCS#8 private key PEM. Deterministic: ed25519 signatures are deterministic, so
// identical record + key ⇒ identical signature. Throws on a missing/invalid key,
// like the other constructors — signing with a bad key is a programming error.
export function signAsym(record, privateKeyPem) {
  if (typeof privateKeyPem !== "string" || privateKeyPem.length === 0) {
    throw new Error("signAsym: privateKeyPem must be a PKCS#8 private-key PEM string");
  }
  // `null` algorithm ⇒ ed25519's built-in hashing (sign the message directly).
  return cryptoSign(null, preimage(record), privateKeyPem).toString("hex");
}

// verifyAsym(record, publicKeyPem, signatureHex?) → boolean.
//
// Two forms, mirroring how a signature can travel:
//   - detached — pass `signatureHex` explicitly (the `signAsym` return value).
//   - embedded — omit `signatureHex`; the record's own `signature` field is used
//     (a record signed and then re-attached, exactly like the HMAC layer).
//
// True iff the ed25519 signature verifies against the record's canonical
// pre-image under `publicKeyPem`. A missing/non-string signature, a tampered
// field, the wrong key, or a malformed signature returns false rather than
// throwing — a verifier is a `{valid}`-style predicate, never a crash.
export function verifyAsym(record, publicKeyPem, signatureHex) {
  const sig = signatureHex === undefined ? (record && record.signature) : signatureHex;
  if (typeof sig !== "string" || sig.length === 0) return false;
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) return false;

  // Require EXACTLY 128 lowercase hex chars (a 64-byte ed25519 signature) before
  // decoding: Buffer.from(str, "hex") stops at the first invalid char, so a valid
  // 128-char signature followed by garbage would otherwise decode to the same 64
  // bytes and verify.
  if (!/^[0-9a-f]{128}$/.test(sig)) return false;

  let sigBytes;
  try {
    sigBytes = Buffer.from(sig, "hex");
  } catch {
    return false;
  }
  if (sigBytes.length !== 64) return false;

  try {
    return cryptoVerify(null, preimage(record), publicKeyPem, sigBytes);
  } catch {
    // A malformed signature or key surfaces as `false`, not an exception.
    return false;
  }
}
