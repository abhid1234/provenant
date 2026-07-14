// provenant — `verify` core (pure offline verification + provenance queries).
//
// Given a resolved attestation array (the fold of a ledger via
// `resolveRecords`), answer the three questions provenance exists to answer,
// with no filesystem and no clock:
//   - `verify`   — is *this* artifact digest attested (and by which record)?
//   - `chainOf`  — what did an attestation derive FROM (the ordered ancestry)?
//   - `coverage` — what fraction of a set of artifacts is attested (a repo audit)?
//
// All three operate purely over the resolved array, so a caller loads the ledger
// once (`loadLedger`) and queries it offline — the whole point of a portable,
// content-addressed provenance record.

// Pick the most recently `created` record from a non-empty list. Ties are broken
// by leaving the earlier-folded record in place (stable), so the result is
// deterministic for a given ledger.
function latest(records) {
  return records.reduce((best, r) =>
    Date.parse(r.created) >= Date.parse(best.created) ? r : best
  );
}

// verify(artifactHash, attestations, opts) → { attested, record, revoked }
//
//   attestations — a resolved array (live + revoked) from `resolveRecords`.
//
// Resolution:
//   - a live (non-revoked) attestation for the digest exists → attested: true,
//     `record` is the most recent such attestation, revoked: false.
//   - only revoked attestations for the digest exist → attested: false,
//     `record` is the most recent (revoked) one, revoked: true.
//   - no attestation for the digest at all → attested: false, record: null,
//     revoked: false.
export function verify(artifactHash, attestations, opts = {}) {
  void opts; // reserved
  const matches = (attestations || []).filter((a) => a.artifact === artifactHash);
  if (matches.length === 0) {
    return { attested: false, record: null, revoked: false };
  }
  const live = matches.filter((a) => !a.revoked);
  if (live.length > 0) {
    return { attested: true, record: latest(live), revoked: false };
  }
  return { attested: false, record: latest(matches), revoked: true };
}

// chainOf(attestationId, attestations) → the ordered provenance chain: the named
// attestation followed by all of its ancestors reachable through `parents`,
// depth-first, **deduped** and **cycle-safe**. A parent id with no matching
// record in the array is skipped (a chain is best-effort over what's present).
// An unknown starting id yields an empty array.
export function chainOf(attestationId, attestations) {
  const byId = new Map((attestations || []).map((a) => [a.id, a]));
  const chain = [];
  const seen = new Set();

  const visit = (id) => {
    if (seen.has(id)) return; // cycle / diamond guard
    seen.add(id);
    const record = byId.get(id);
    if (!record) return; // missing ancestor — skip, don't invent
    chain.push(record);
    for (const parent of record.parents || []) visit(parent);
  };

  visit(attestationId);
  return chain;
}

// coverage(artifactHashes, attestations) → { score, total, attested, unattested, revoked }
//
// The repo audit: of a set of artifact digests, what fraction carries a live
// attestation? Input digests are de-duplicated first, so `total` is the number
// of *distinct* artifacts asked about.
//
//   - attested   — count of distinct digests with at least one live attestation.
//   - unattested — digests with no attestation at all (array).
//   - revoked    — digests whose only attestations are revoked (array).
//   - score      — attested / total, a float in [0, 1] (1 when total is 0).
export function coverage(artifactHashes, attestations) {
  const hashes = [...new Set(artifactHashes || [])];

  const liveArtifacts = new Set();
  const revokedArtifacts = new Set();
  for (const a of attestations || []) {
    if (a.revoked) revokedArtifacts.add(a.artifact);
    else liveArtifacts.add(a.artifact);
  }

  let attested = 0;
  const unattested = [];
  const revoked = [];
  for (const h of hashes) {
    if (liveArtifacts.has(h)) attested += 1;
    else if (revokedArtifacts.has(h)) revoked.push(h);
    else unattested.push(h);
  }

  const total = hashes.length;
  const score = total === 0 ? 1 : attested / total;
  return { score, total, attested, unattested, revoked };
}
