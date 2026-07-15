// provenant — evaluation queries (pure, offline confidence audit).
//
// provenant already records WHO produced an artifact, WHY, and FROM WHAT. An
// attestation can also carry an `evaluation`: a portable, content-addressed
// CLAIM about the artifact's quality/confidence and how it was judged — "this
// agent asserts this artifact scores 0.9 by method=test, and here are the
// checks". Because the evaluation is part of the canonical record content, the
// content-hash id (and any signature) cover it, so the claim is as tamper-
// evident as the rest of the attestation.
//
// This module answers the two questions that claim makes auditable across a
// repo, with no filesystem and no clock — pure over a resolved attestation
// array (the fold of a ledger via `resolveRecords` / `loadLedger`):
//   - `evalOf`       — what is the LIVE evaluation claim for this artifact?
//   - `evalCoverage` — which outputs are low-confidence or unevaluated?
//
// Distinct from runtime outcome verification (a sibling concern): this is an
// *attested, content-addressed claim* recorded alongside provenance, auditable
// like coverage — not a re-execution of the artifact.

// Pick the most recently `created` record from a non-empty list. Ties leave the
// earlier-folded record in place (stable), matching verify.js so the two agree
// on "the live record" for a given ledger.
function latest(records) {
  return records.reduce((best, r) =>
    Date.parse(r.created) >= Date.parse(best.created) ? r : best
  );
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// evalOf(artifactHash, attestations) → the live evaluation claim for an
// artifact, or `null` when none exists.
//
//   attestations — a resolved array (live + revoked) from `resolveRecords`.
//
// The claim is drawn from the most recently `created`, NON-revoked attestation
// for the digest that carries an `evaluation`. A revoked attestation's claim is
// ignored (its whole record is superseded), and an attestation with no
// evaluation contributes nothing. Returns a flat view of the claim plus the
// attesting `agent`:
//
//   { score, method, checks, evaluator, agent }
//
// `checks` is always an array (`[]` when the claim carried none) and `evaluator`
// is `null` when absent, so a caller never has to probe for optional fields.
export function evalOf(artifactHash, attestations) {
  const matches = (attestations || []).filter(
    (a) => a.artifact === artifactHash && !a.revoked && isPlainObject(a.evaluation)
  );
  if (matches.length === 0) return null;

  const record = latest(matches);
  const e = record.evaluation;
  return {
    score: e.score,
    method: e.method,
    checks: Array.isArray(e.checks) ? e.checks : [],
    evaluator: e.evaluator === undefined ? null : e.evaluator,
    agent: record.agent,
  };
}

// evalCoverage(artifactHashes, attestations, opts) → the confidence report:
//
//   { evaluated, unevaluated, mean_score, min_score, below }
//
// The "which outputs are low-confidence / unevaluated?" audit, over a set of
// artifact digests (de-duplicated first, so an artifact asked about twice counts
// once). Each digest's live claim is resolved via `evalOf`:
//
//   - evaluated   — count of distinct digests carrying a live evaluation.
//   - unevaluated — digests with no live evaluation at all (array) — the ones an
//                   auditor should chase down.
//   - mean_score  — mean of the evaluated digests' scores, or `null` when none
//                   are evaluated (an empty mean is undefined, not zero).
//   - min_score   — the lowest evaluated score, or `null` when none.
//   - below       — with `opts.threshold` set, the evaluated digests scoring
//                   *below* it as `[{ artifact, score }]` (the low-confidence
//                   list); `[]` when no threshold is given.
export function evalCoverage(artifactHashes, attestations, opts = {}) {
  const { threshold } = opts;
  const hasThreshold = typeof threshold === "number" && !Number.isNaN(threshold);
  const hashes = [...new Set(artifactHashes || [])];

  const scores = [];
  const unevaluated = [];
  const below = [];
  let evaluated = 0;

  for (const h of hashes) {
    const claim = evalOf(h, attestations);
    if (claim === null) {
      unevaluated.push(h);
      continue;
    }
    evaluated += 1;
    scores.push(claim.score);
    if (hasThreshold && claim.score < threshold) {
      below.push({ artifact: h, score: claim.score });
    }
  }

  const mean_score =
    scores.length === 0 ? null : scores.reduce((a, b) => a + b, 0) / scores.length;
  const min_score = scores.length === 0 ? null : Math.min(...scores);

  return { evaluated, unevaluated, mean_score, min_score, below };
}
