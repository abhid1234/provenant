import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateEvaluation,
  validateAttestation,
  EVALUATION_FIELDS,
  EVAL_METHODS,
  ERROR_CODES,
} from "../src/schema.js";
import { attest, revoke } from "../src/attest.js";
import { evalOf, evalCoverage } from "../src/evaluation.js";
import { computeRecordId, resolveRecords } from "../src/registry.js";
import { computeHash } from "../src/hash.js";
import { sign, verifySignature } from "../src/sign.js";
import { attestationToSpanAttributes } from "../src/otel.js";

const T0 = "2026-07-11T12:00:00Z";
const T1 = "2026-07-11T12:05:00Z";
const T2 = "2026-07-11T12:10:00Z";
const SECRET = "correct horse battery staple";

// Resolve raw records the way loadLedger would (revocations folded).
function resolve(records) {
  return resolveRecords(records).attestations;
}

function codes(result) {
  return result.errors.map((e) => e.code);
}
function codeAt(result, path) {
  return result.errors.filter((e) => e.path === path).map((e) => e.code);
}

// A minimal valid evaluation, with overridable fields.
function validEval(overrides = {}) {
  return { score: 0.9, method: "test", ...overrides };
}

// --- exported constants ----------------------------------------------------

test("EVALUATION_FIELDS is the canonical evaluation field set", () => {
  assert.deepEqual(EVALUATION_FIELDS, ["score", "method", "checks", "evaluator"]);
});

test("EVAL_METHODS lists the well-known methods (a hint, not a constraint)", () => {
  assert.deepEqual(EVAL_METHODS, ["self", "test", "judge", "human"]);
});

// --- validateEvaluation: valid ---------------------------------------------

test("validateEvaluation: a minimal { score, method } is valid", () => {
  assert.deepEqual(validateEvaluation({ score: 0.9, method: "test" }), {
    valid: true,
    errors: [],
  });
});

test("validateEvaluation: score boundaries 0 and 1 are valid", () => {
  assert.equal(validateEvaluation({ score: 0, method: "self" }).valid, true);
  assert.equal(validateEvaluation({ score: 1, method: "human" }).valid, true);
});

test("validateEvaluation: any non-empty method string is accepted (bespoke evaluators)", () => {
  for (const m of [...EVAL_METHODS, "my-custom-rubric-v2"]) {
    assert.equal(validateEvaluation({ score: 0.5, method: m }).valid, true, m);
  }
});

test("validateEvaluation: checks + evaluator are valid when well-formed", () => {
  const e = validEval({
    checks: [
      { name: "unit-tests", passed: true },
      { name: "typecheck", passed: false, note: "2 errors" },
    ],
    evaluator: "vitest@2",
  });
  assert.deepEqual(validateEvaluation(e), { valid: true, errors: [] });
});

test("validateEvaluation: an empty checks array is valid", () => {
  assert.equal(validateEvaluation(validEval({ checks: [] })).valid, true);
});

// --- validateEvaluation: invalid -------------------------------------------

test("validateEvaluation: a non-object is NOT_OBJECT", () => {
  for (const bad of [null, undefined, 42, "x", [], true]) {
    const r = validateEvaluation(bad);
    assert.equal(r.valid, false);
    assert.deepEqual(codes(r), [ERROR_CODES.NOT_OBJECT]);
  }
});

test("validateEvaluation: a missing score is MISSING_FIELD", () => {
  const r = validateEvaluation({ method: "test" });
  assert.equal(r.valid, false);
  assert.deepEqual(codeAt(r, "score"), [ERROR_CODES.MISSING_FIELD]);
});

test("validateEvaluation: a missing method is MISSING_FIELD", () => {
  const r = validateEvaluation({ score: 0.5 });
  assert.equal(r.valid, false);
  assert.deepEqual(codeAt(r, "method"), [ERROR_CODES.MISSING_FIELD]);
});

test("validateEvaluation: a non-number score is WRONG_TYPE", () => {
  assert.deepEqual(codeAt(validateEvaluation({ score: "0.9", method: "t" }), "score"), [
    ERROR_CODES.WRONG_TYPE,
  ]);
});

test("validateEvaluation: a NaN score is WRONG_TYPE", () => {
  assert.deepEqual(codeAt(validateEvaluation({ score: NaN, method: "t" }), "score"), [
    ERROR_CODES.WRONG_TYPE,
  ]);
});

test("validateEvaluation: a score outside [0,1] is OUT_OF_RANGE (both ends)", () => {
  assert.deepEqual(codeAt(validateEvaluation({ score: -0.01, method: "t" }), "score"), [
    ERROR_CODES.OUT_OF_RANGE,
  ]);
  assert.deepEqual(codeAt(validateEvaluation({ score: 1.5, method: "t" }), "score"), [
    ERROR_CODES.OUT_OF_RANGE,
  ]);
});

test("validateEvaluation: an empty method is EMPTY_STRING", () => {
  assert.deepEqual(codeAt(validateEvaluation({ score: 0.5, method: "   " }), "method"), [
    ERROR_CODES.EMPTY_STRING,
  ]);
});

test("validateEvaluation: a non-string method is WRONG_TYPE", () => {
  assert.deepEqual(codeAt(validateEvaluation({ score: 0.5, method: 7 }), "method"), [
    ERROR_CODES.WRONG_TYPE,
  ]);
});

test("validateEvaluation: an unknown field is UNKNOWN_FIELD", () => {
  assert.deepEqual(codeAt(validateEvaluation(validEval({ bogus: 1 })), "bogus"), [
    ERROR_CODES.UNKNOWN_FIELD,
  ]);
});

test("validateEvaluation: a non-array checks is NOT_ARRAY", () => {
  assert.deepEqual(codeAt(validateEvaluation(validEval({ checks: {} })), "checks"), [
    ERROR_CODES.NOT_ARRAY,
  ]);
});

test("validateEvaluation: a non-object check entry is NOT_OBJECT", () => {
  assert.deepEqual(codeAt(validateEvaluation(validEval({ checks: ["x"] })), "checks[0]"), [
    ERROR_CODES.NOT_OBJECT,
  ]);
});

test("validateEvaluation: a check missing name is MISSING_FIELD", () => {
  const r = validateEvaluation(validEval({ checks: [{ passed: true }] }));
  assert.deepEqual(codeAt(r, "checks[0].name"), [ERROR_CODES.MISSING_FIELD]);
});

test("validateEvaluation: a check with an empty name is EMPTY_STRING", () => {
  const r = validateEvaluation(validEval({ checks: [{ name: "  ", passed: true }] }));
  assert.deepEqual(codeAt(r, "checks[0].name"), [ERROR_CODES.EMPTY_STRING]);
});

test("validateEvaluation: a check with a non-string name is WRONG_TYPE", () => {
  const r = validateEvaluation(validEval({ checks: [{ name: 1, passed: true }] }));
  assert.deepEqual(codeAt(r, "checks[0].name"), [ERROR_CODES.WRONG_TYPE]);
});

test("validateEvaluation: a check missing passed is MISSING_FIELD", () => {
  const r = validateEvaluation(validEval({ checks: [{ name: "x" }] }));
  assert.deepEqual(codeAt(r, "checks[0].passed"), [ERROR_CODES.MISSING_FIELD]);
});

test("validateEvaluation: a check with a non-boolean passed is WRONG_TYPE", () => {
  const r = validateEvaluation(validEval({ checks: [{ name: "x", passed: "yes" }] }));
  assert.deepEqual(codeAt(r, "checks[0].passed"), [ERROR_CODES.WRONG_TYPE]);
});

test("validateEvaluation: a check with a non-string note is WRONG_TYPE", () => {
  const r = validateEvaluation(validEval({ checks: [{ name: "x", passed: true, note: 1 }] }));
  assert.deepEqual(codeAt(r, "checks[0].note"), [ERROR_CODES.WRONG_TYPE]);
});

test("validateEvaluation: a check with an unknown field is UNKNOWN_FIELD", () => {
  const r = validateEvaluation(validEval({ checks: [{ name: "x", passed: true, weight: 1 }] }));
  assert.deepEqual(codeAt(r, "checks[0].weight"), [ERROR_CODES.UNKNOWN_FIELD]);
});

test("validateEvaluation: a non-string evaluator is WRONG_TYPE; empty is EMPTY_STRING", () => {
  assert.deepEqual(codeAt(validateEvaluation(validEval({ evaluator: 5 })), "evaluator"), [
    ERROR_CODES.WRONG_TYPE,
  ]);
  assert.deepEqual(codeAt(validateEvaluation(validEval({ evaluator: "" })), "evaluator"), [
    ERROR_CODES.EMPTY_STRING,
  ]);
});

test("validateEvaluation: collects EVERY violation in one pass (no short-circuit)", () => {
  const r = validateEvaluation({ score: 2, method: "", bogus: 1, checks: [{ note: 9 }] });
  assert.equal(r.valid, false);
  const paths = r.errors.map((e) => e.path);
  assert.ok(paths.includes("score"));
  assert.ok(paths.includes("method"));
  assert.ok(paths.includes("bogus"));
  assert.ok(paths.includes("checks[0].name"));
  assert.ok(paths.includes("checks[0].passed"));
  assert.ok(paths.includes("checks[0].note"));
});

// --- attest carries + hashes the evaluation --------------------------------

test("attest: carries an optional evaluation and the record validates", () => {
  const e = validEval({ checks: [{ name: "tests", passed: true }], evaluator: "vitest" });
  const r = attest("x", { agent: "a", intent: "i", created: T0, evaluation: e });
  assert.deepEqual(r.evaluation, e);
  assert.equal(validateAttestation(r).valid, true);
});

test("attest: omits evaluation entirely when not given (backward-compatible)", () => {
  const r = attest("x", { agent: "a", intent: "i", created: T0 });
  assert.ok(!("evaluation" in r));
  // Identical to the pre-evaluation record: same id as before this feature.
  const same = attest("x", { agent: "a", intent: "i", created: T0 });
  assert.equal(r.id, same.id);
});

test("attest: the evaluation is part of the content hash (id covers the score)", () => {
  const base = { agent: "a", intent: "i", created: T0 };
  const a = attest("x", { ...base, evaluation: { score: 0.9, method: "test" } });
  const b = attest("x", { ...base, evaluation: { score: 0.1, method: "test" } });
  // A different score ⇒ a different content-hash id.
  assert.notEqual(a.id, b.id);
  // …and the id is the true content hash of the whole record.
  assert.equal(a.id, computeRecordId(a));
});

test("attest: throws on an invalid evaluation rather than hashing a bad score", () => {
  assert.throws(
    () => attest("x", { agent: "a", intent: "i", created: T0, evaluation: { score: 2, method: "t" } }),
    /evaluation is invalid/
  );
  assert.throws(
    () => attest("x", { agent: "a", intent: "i", created: T0, evaluation: { method: "t" } }),
    /evaluation is invalid/
  );
});

// --- tamper: a rewritten score breaks the id and signature -----------------

test("tampering the score breaks the content-hash id → resolveRecords drops it", () => {
  const r = attest("x", { agent: "a", intent: "i", created: T0, evaluation: { score: 0.9, method: "test" } });
  const tampered = { ...r, evaluation: { score: 0.1, method: "test" } };
  // Its stored id no longer matches its content.
  assert.notEqual(tampered.id, computeRecordId(tampered));
  const { attestations, notes } = resolveRecords([tampered]);
  assert.equal(attestations.length, 0, "the tampered record is dropped");
  assert.ok(notes.some((n) => /id\/content mismatch/.test(n)));
});

test("tampering the score breaks an HMAC signature over the record", () => {
  const r = attest("x", { agent: "a", intent: "i", created: T0, evaluation: { score: 0.9, method: "test" } });
  const signed = { ...r, signature: sign(r, SECRET) };
  assert.equal(verifySignature(signed, SECRET), true);
  const tampered = { ...signed, evaluation: { score: 0.1, method: "test" } };
  assert.equal(verifySignature(tampered, SECRET), false, "the signature covers the evaluation");
});

// --- evalOf ----------------------------------------------------------------

test("evalOf: returns the live evaluation claim with the attesting agent", () => {
  const e = validEval({ checks: [{ name: "t", passed: true }], evaluator: "vitest" });
  const a = attest("x", { agent: "claude", intent: "i", created: T0, evaluation: e });
  const claim = evalOf(a.artifact, resolve([a]));
  assert.deepEqual(claim, {
    score: 0.9,
    method: "test",
    checks: [{ name: "t", passed: true }],
    evaluator: "vitest",
    agent: "claude",
  });
});

test("evalOf: normalizes missing checks to [] and missing evaluator to null", () => {
  const a = attest("x", { agent: "a", intent: "i", created: T0, evaluation: { score: 0.5, method: "self" } });
  const claim = evalOf(a.artifact, resolve([a]));
  assert.deepEqual(claim.checks, []);
  assert.equal(claim.evaluator, null);
});

test("evalOf: an artifact with no evaluation → null", () => {
  const a = attest("x", { agent: "a", intent: "i", created: T0 });
  assert.equal(evalOf(a.artifact, resolve([a])), null);
});

test("evalOf: an unknown artifact → null", () => {
  assert.equal(evalOf(computeHash("nothing"), []), null);
});

test("evalOf: ignores a revoked attestation's claim", () => {
  const a = attest("x", { agent: "a", intent: "i", created: T0, evaluation: { score: 0.9, method: "test" } });
  const rev = revoke(a.id, { agent: "a", reason: "superseded", at: T1 });
  assert.equal(evalOf(a.artifact, resolve([a, rev])), null);
});

test("evalOf: returns the most recent live claim for the artifact", () => {
  const early = attest("x", { agent: "a1", intent: "early", created: T0, evaluation: { score: 0.5, method: "self" } });
  const late = attest("x", { agent: "a2", intent: "late", created: T2, evaluation: { score: 0.95, method: "judge" } });
  const claim = evalOf(early.artifact, resolve([early, late]));
  assert.equal(claim.score, 0.95);
  assert.equal(claim.method, "judge");
  assert.equal(claim.agent, "a2");
});

test("evalOf: a live re-evaluation supersedes a revoked one", () => {
  const a1 = attest("x", { agent: "a", intent: "first", created: T0, evaluation: { score: 0.4, method: "self" } });
  const rev = revoke(a1.id, { agent: "a", reason: "r", at: T1 });
  const a2 = attest("x", { agent: "a", intent: "redo", created: T2, evaluation: { score: 0.9, method: "test" } });
  const claim = evalOf(a1.artifact, resolve([a1, rev, a2]));
  assert.equal(claim.score, 0.9);
});

// --- evalCoverage ----------------------------------------------------------

test("evalCoverage: counts evaluated, lists unevaluated, computes mean + min", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.8, method: "test" } });
  const b = attest("b", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.6, method: "judge" } });
  const c = attest("c", { agent: "x", intent: "w", created: T0 }); // no eval
  const attestations = resolve([a, b, c]);
  const missing = computeHash("missing");
  const rep = evalCoverage([a.artifact, b.artifact, c.artifact, missing], attestations);
  assert.equal(rep.evaluated, 2);
  assert.deepEqual(new Set(rep.unevaluated), new Set([c.artifact, missing]));
  assert.ok(Math.abs(rep.mean_score - 0.7) < 1e-9);
  assert.equal(rep.min_score, 0.6);
  assert.deepEqual(rep.below, []);
});

test("evalCoverage: an empty / all-unevaluated audit → null mean and min", () => {
  const empty = evalCoverage([], []);
  assert.deepEqual(empty, { evaluated: 0, unevaluated: [], mean_score: null, min_score: null, below: [] });

  const a = attest("a", { agent: "x", intent: "w", created: T0 });
  const rep = evalCoverage([a.artifact], resolve([a]));
  assert.equal(rep.evaluated, 0);
  assert.deepEqual(rep.unevaluated, [a.artifact]);
  assert.equal(rep.mean_score, null);
  assert.equal(rep.min_score, null);
});

test("evalCoverage: --threshold flags the below-threshold artifacts", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.95, method: "test" } });
  const b = attest("b", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.5, method: "self" } });
  const attestations = resolve([a, b]);
  const rep = evalCoverage([a.artifact, b.artifact], attestations, { threshold: 0.8 });
  assert.equal(rep.evaluated, 2);
  assert.deepEqual(rep.below, [{ artifact: b.artifact, score: 0.5 }]);
});

test("evalCoverage: no threshold → below is always empty even for low scores", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.1, method: "self" } });
  const rep = evalCoverage([a.artifact], resolve([a]));
  assert.deepEqual(rep.below, []);
});

test("evalCoverage: de-duplicates the requested digests", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.9, method: "test" } });
  const rep = evalCoverage([a.artifact, a.artifact, a.artifact], resolve([a]));
  assert.equal(rep.evaluated, 1);
});

test("evalCoverage: a revoked-only artifact counts as unevaluated", () => {
  const a = attest("a", { agent: "x", intent: "w", created: T0, evaluation: { score: 0.9, method: "test" } });
  const rev = revoke(a.id, { agent: "x", reason: "r", at: T1 });
  const rep = evalCoverage([a.artifact], resolve([a, rev]));
  assert.equal(rep.evaluated, 0);
  assert.deepEqual(rep.unevaluated, [a.artifact]);
});

// --- otel bridge emits eval attrs ------------------------------------------

test("otel: emits provenant.eval.* when an evaluation is present", () => {
  const a = attest("content", {
    agent: "claude",
    intent: "ship",
    created: T0,
    evaluation: {
      score: 0.9,
      method: "test",
      checks: [
        { name: "unit", passed: true },
        { name: "lint", passed: false },
      ],
      evaluator: "vitest@2",
    },
  });
  const attrs = attestationToSpanAttributes(a);
  assert.equal(attrs["provenant.eval.score"], 0.9);
  assert.equal(attrs["provenant.eval.method"], "test");
  assert.equal(attrs["provenant.eval.checks_passed"], 1);
  assert.equal(attrs["provenant.eval.evaluator"], "vitest@2");
  // Still flat + scalar.
  for (const v of Object.values(attrs)) {
    assert.ok(["string", "number", "boolean"].includes(typeof v));
  }
});

test("otel: omits provenant.eval.* entirely on a record with no evaluation", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0 });
  const attrs = attestationToSpanAttributes(a);
  assert.equal("provenant.eval.score" in attrs, false);
  assert.equal("provenant.eval.method" in attrs, false);
  assert.equal("provenant.eval.checks_passed" in attrs, false);
});

test("otel: checks_passed is 0 when a claim carries no checks; evaluator omitted", () => {
  const a = attest("content", { agent: "a1", intent: "w", created: T0, evaluation: { score: 0.7, method: "self" } });
  const attrs = attestationToSpanAttributes(a);
  assert.equal(attrs["provenant.eval.checks_passed"], 0);
  assert.equal("provenant.eval.evaluator" in attrs, false);
});
