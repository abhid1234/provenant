import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateAttestation,
  validateRevocation,
  validateLedger,
  isIso8601Utc,
  isSha256Hex,
  ATTESTATION_FIELDS,
  REVOCATION_FIELDS,
  RECORD_TYPES,
  ERROR_CODES,
} from "../src/schema.js";

// A 64-hex sha256-shaped string, and a canonical fully-valid attestation.
const HEX = "a".repeat(64);
const HEX2 = "b".repeat(64);

function validAttestation(overrides = {}) {
  return {
    id: "some-record-id",
    type: "attestation",
    agent: "claude-opus-4-8/claude-code",
    artifact: HEX,
    intent: "add OAuth",
    parents: [],
    created: "2026-07-11T12:00:00Z",
    ...overrides,
  };
}

function validRevocation(overrides = {}) {
  return {
    id: "some-revocation-id",
    type: "revocation",
    attestation_id: HEX,
    agent: "claude",
    reason: "superseded",
    at: "2026-07-11T12:30:00Z",
    ...overrides,
  };
}

function codes(result) {
  return result.errors.map((e) => e.code);
}
function codeAt(result, path) {
  return result.errors.filter((e) => e.path === path).map((e) => e.code);
}

// --- exported constants ----------------------------------------------------

test("RECORD_TYPES lists attestation and revocation", () => {
  assert.deepEqual(RECORD_TYPES, ["attestation", "revocation"]);
});

test("ATTESTATION_FIELDS + REVOCATION_FIELDS are the canonical field sets", () => {
  assert.deepEqual(ATTESTATION_FIELDS, [
    "id",
    "type",
    "agent",
    "artifact",
    "intent",
    "parents",
    "created",
    "meta",
    "evaluation",
    "signature",
  ]);
  assert.deepEqual(REVOCATION_FIELDS, [
    "id",
    "type",
    "attestation_id",
    "agent",
    "reason",
    "at",
  ]);
});

test("ERROR_CODES exposes every stable code", () => {
  for (const code of [
    "MISSING_FIELD",
    "UNKNOWN_FIELD",
    "WRONG_TYPE",
    "NOT_OBJECT",
    "NOT_ARRAY",
    "EMPTY_STRING",
    "INVALID_ENUM",
    "INVALID_ISO8601",
    "INVALID_SHA256",
    "INVALID_SIGNATURE",
    "DUPLICATE_ID",
    "OUT_OF_RANGE",
  ]) {
    assert.equal(ERROR_CODES[code], code, `ERROR_CODES.${code}`);
  }
});

// --- isIso8601Utc ----------------------------------------------------------

test("isIso8601Utc accepts UTC …Z with and without sub-seconds", () => {
  assert.equal(isIso8601Utc("2026-07-11T12:00:00Z"), true);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00.123Z"), true);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00.000001Z"), true);
});

test("isIso8601Utc rejects offsets and local times", () => {
  assert.equal(isIso8601Utc("2026-07-11T12:00:00+00:00"), false);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00-05:00"), false);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00"), false);
  assert.equal(isIso8601Utc("2026-07-11 12:00:00Z"), false);
  assert.equal(isIso8601Utc("2026-07-11"), false);
});

test("isIso8601Utc rejects impossible calendar dates (regex-shaped but unreal)", () => {
  // Out-of-range month/day that Date.parse rejects outright.
  assert.equal(isIso8601Utc("2026-13-40T00:00:00Z"), false);
  // Roll-over dates Date.parse silently normalizes — the round-trip catches them.
  assert.equal(isIso8601Utc("2026-02-30T00:00:00Z"), false);
  assert.equal(isIso8601Utc("2026-04-31T00:00:00Z"), false);
});

test("isIso8601Utc rejects non-strings", () => {
  assert.equal(isIso8601Utc(42), false);
  assert.equal(isIso8601Utc(null), false);
  assert.equal(isIso8601Utc(undefined), false);
  assert.equal(isIso8601Utc({}), false);
});

// --- isSha256Hex -----------------------------------------------------------

test("isSha256Hex accepts exactly 64 lowercase hex chars", () => {
  assert.equal(isSha256Hex(HEX), true);
  assert.equal(isSha256Hex("0123456789abcdef".repeat(4)), true);
});

test("isSha256Hex rejects wrong length, uppercase, non-hex, non-string", () => {
  assert.equal(isSha256Hex("a".repeat(63)), false);
  assert.equal(isSha256Hex("a".repeat(65)), false);
  assert.equal(isSha256Hex("A".repeat(64)), false); // uppercase
  assert.equal(isSha256Hex("g".repeat(64)), false); // non-hex
  assert.equal(isSha256Hex(""), false);
  assert.equal(isSha256Hex(42), false);
  assert.equal(isSha256Hex(null), false);
});

// --- validateAttestation ---------------------------------------------------

test("fully-valid attestation → valid, no errors", () => {
  assert.deepEqual(validateAttestation(validAttestation()), { valid: true, errors: [] });
});

test("attestation with optional meta + signature (valid) → valid", () => {
  const a = validAttestation({ meta: { harness: "git" }, signature: HEX2 });
  assert.deepEqual(validateAttestation(a), { valid: true, errors: [] });
});

test("each required attestation field missing → one MISSING_FIELD at that path", () => {
  for (const field of ["id", "type", "agent", "artifact", "intent", "parents", "created"]) {
    const a = validAttestation();
    delete a[field];
    const result = validateAttestation(a);
    assert.equal(result.valid, false, `${field} missing → invalid`);
    assert.deepEqual(codeAt(result, field), ["MISSING_FIELD"], `${field}`);
  }
});

test("meta and signature are optional (absence is valid)", () => {
  const a = validAttestation();
  assert.ok(!("meta" in a));
  assert.ok(!("signature" in a));
  assert.equal(validateAttestation(a).valid, true);
});

test("attestation wrong types per field", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ id: 42 })), "id"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ agent: 1 })), "agent"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ intent: {} })), "intent"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ artifact: 5 })), "artifact"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ parents: "x" })), "parents"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ meta: [] })), "meta"), ["WRONG_TYPE"]);
});

test("attestation empty strings → EMPTY_STRING", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ id: "" })), "id"), ["EMPTY_STRING"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ agent: "  " })), "agent"), ["EMPTY_STRING"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ intent: "" })), "intent"), ["EMPTY_STRING"]);
});

test("attestation artifact must be sha256 hex → INVALID_SHA256", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ artifact: "nope" })), "artifact"), ["INVALID_SHA256"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ artifact: "A".repeat(64) })), "artifact"), ["INVALID_SHA256"]);
});

test("attestation type must be exactly 'attestation' → INVALID_ENUM", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ type: "revocation" })), "type"), ["INVALID_ENUM"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ type: "x" })), "type"), ["INVALID_ENUM"]);
});

test("attestation parents: each entry must be a sha256-hex id", () => {
  assert.equal(validateAttestation(validAttestation({ parents: [HEX, HEX2] })).valid, true);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ parents: [42] })), "parents[0]"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ parents: ["short"] })), "parents[0]"), ["INVALID_SHA256"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ parents: [HEX, "bad"] })), "parents[1]"), ["INVALID_SHA256"]);
});

test("attestation created must be ISO-8601 UTC → INVALID_ISO8601", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ created: "not-a-date" })), "created"), ["INVALID_ISO8601"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ created: "2026-07-11T12:00:00+00:00" })), "created"), ["INVALID_ISO8601"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ created: "2026-02-30T00:00:00Z" })), "created"), ["INVALID_ISO8601"]);
});

test("attestation signature must be an HMAC-sha256 hex digest → INVALID_SIGNATURE", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ signature: "nope" })), "signature"), ["INVALID_SIGNATURE"]);
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ signature: 5 })), "signature"), ["INVALID_SIGNATURE"]);
  assert.equal(validateAttestation(validAttestation({ signature: HEX2 })).valid, true);
});

test("attestation unknown top-level field → UNKNOWN_FIELD", () => {
  assert.deepEqual(codeAt(validateAttestation(validAttestation({ foo: 1 })), "foo"), ["UNKNOWN_FIELD"]);
});

test("attestation non-object input → single NOT_OBJECT at ''", () => {
  for (const bad of [null, [], 42, "x", undefined]) {
    const result = validateAttestation(bad);
    assert.deepEqual(codes(result), ["NOT_OBJECT"]);
    assert.equal(result.errors[0].path, "");
  }
});

test("attestation collects every violation without short-circuiting", () => {
  const result = validateAttestation({
    id: "",
    type: "bogus",
    agent: "",
    artifact: "nope",
    intent: "",
    parents: "x",
    created: "bad",
    extra: 1,
  });
  const c = codes(result);
  assert.ok(c.includes("EMPTY_STRING"));
  assert.ok(c.includes("INVALID_ENUM"));
  assert.ok(c.includes("INVALID_SHA256"));
  assert.ok(c.includes("WRONG_TYPE"));
  assert.ok(c.includes("INVALID_ISO8601"));
  assert.ok(c.includes("UNKNOWN_FIELD"));
  assert.ok(result.errors.length >= 6);
});

// --- validateRevocation ----------------------------------------------------

test("fully-valid revocation → valid, no errors", () => {
  assert.deepEqual(validateRevocation(validRevocation()), { valid: true, errors: [] });
});

test("each required revocation field missing → one MISSING_FIELD (no optionals)", () => {
  for (const field of REVOCATION_FIELDS) {
    const r = validRevocation();
    delete r[field];
    const result = validateRevocation(r);
    assert.equal(result.valid, false, `${field}`);
    assert.deepEqual(codeAt(result, field), ["MISSING_FIELD"], `${field}`);
  }
});

test("revocation attestation_id must be sha256 hex", () => {
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ attestation_id: "x" })), "attestation_id"), ["INVALID_SHA256"]);
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ attestation_id: 5 })), "attestation_id"), ["WRONG_TYPE"]);
});

test("revocation type must be 'revocation', at must be ISO UTC, reason non-empty", () => {
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ type: "attestation" })), "type"), ["INVALID_ENUM"]);
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ at: "nope" })), "at"), ["INVALID_ISO8601"]);
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ reason: "" })), "reason"), ["EMPTY_STRING"]);
});

test("revocation unknown field → UNKNOWN_FIELD; non-object → NOT_OBJECT", () => {
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ meta: {} })), "meta"), ["UNKNOWN_FIELD"]);
  assert.deepEqual(codes(validateRevocation(null)), ["NOT_OBJECT"]);
});

// --- validateLedger --------------------------------------------------------

test("valid array of unique-id records → valid", () => {
  const ledger = [validAttestation({ id: "one" }), validRevocation({ id: "two" })];
  assert.deepEqual(validateLedger(ledger), { valid: true, errors: [] });
});

test("empty array is a valid ledger", () => {
  assert.deepEqual(validateLedger([]), { valid: true, errors: [] });
});

test("non-array input → single NOT_ARRAY", () => {
  for (const bad of [null, {}, 42, "x"]) {
    assert.deepEqual(codes(validateLedger(bad)), ["NOT_ARRAY"]);
  }
});

test("ledger dispatches revocation vs attestation by type; element paths prefixed [i]", () => {
  const ledger = [validAttestation({ id: "one" }), validRevocation({ id: "two", at: "nope" })];
  const result = validateLedger(ledger);
  assert.deepEqual(codeAt(result, "[1].at"), ["INVALID_ISO8601"]);
});

test("ledger whole-element NOT_OBJECT path is [i]", () => {
  const result = validateLedger([validAttestation(), 42]);
  assert.deepEqual(codeAt(result, "[1]"), ["NOT_OBJECT"]);
});

test("ledger duplicate id → DUPLICATE_ID at the later occurrence only", () => {
  const ledger = [validAttestation({ id: "dup" }), validAttestation({ id: "dup" })];
  const result = validateLedger(ledger);
  assert.deepEqual(codeAt(result, "[1].id"), ["DUPLICATE_ID"]);
  assert.equal(codeAt(result, "[0].id").length, 0);
});
