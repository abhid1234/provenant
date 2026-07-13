// provenant — public entry point (package `main`).
// Re-exports the pure schema/validator API.
// Re-exports the `computeHash` content-fingerprint primitive.
// Re-exports the pure `attest` / `revoke` record-constructor API.
// Re-exports the append-only ledger store (`loadLedger`, `appendRecord`, …).
// Re-exports the pure `verify` / `chainOf` / `coverage` provenance-query API.
// Re-exports the optional `sign` / `verifySignature` HMAC tamper-evidence layer.
// Re-exports the git post-commit adapter (`attestCommit`, `installHook`, …).

export {
  validateAttestation,
  validateRevocation,
  validateLedger,
  isIso8601Utc,
  isSha256Hex,
  ATTESTATION_FIELDS,
  REVOCATION_FIELDS,
  RECORD_TYPES,
  ERROR_CODES,
} from "./schema.js";
export { computeHash } from "./hash.js";
export { attest, revoke } from "./attest.js";
export {
  canonicalize,
  computeRecordId,
  resolveRecords,
  loadLedger,
  appendRecord,
  defaultLedgerPath,
  listAttestations,
  shortId,
} from "./registry.js";
export { verify, chainOf, coverage } from "./verify.js";
export { sign, verifySignature } from "./sign.js";
export {
  changedPaths,
  attestCommit,
  hookPath,
  renderHookBlock,
  installHook,
} from "./adapters/git-hook.js";
