// provenant — OpenTelemetry bridge (pure record → span-attribute mappers).
//
// A provenance record is a nested JSON object; an OpenTelemetry span attribute
// set is a FLAT map whose values are only strings, numbers, or booleans (arrays
// of those are allowed by OTel, but we join them to comma strings so the output
// survives any exporter and stays trivially serializable). These two pure
// functions project a provenant record and a `coverage()` report onto that flat
// shape, under a `provenant.*` / `provenant.coverage.*` key namespace — the same
// bridge convention the family uses (constraintguard's `cg otel`), so an agent
// can decorate the span it's already emitting with "which agent produced which
// artifact, why, and is it still attested" without any nesting or I/O.
//
// Deterministic and zero-dependency: no clock, no crypto, no filesystem — a
// record in, a flat attribute object out.

// Join an array of values to a comma-separated string (OTel-safe scalar). An
// absent/empty array becomes "" so the key is always present and a downstream
// span never sees `undefined`.
function joinAttr(values) {
  return Array.isArray(values) ? values.join(",") : "";
}

// attestationToSpanAttributes(record) → a FLAT object of `provenant.*` span
// attributes (string / number / bool values only). Mirrors the record's core
// provenance fields plus two derived booleans a span consumer wants at a glance:
//
//   - provenant.id            — the record's content-hash id
//   - provenant.agent         — who produced the artifact
//   - provenant.artifact      — the artifact's sha256 digest
//   - provenant.intent        — why it was produced
//   - provenant.parents       — the parent ids, joined to a comma string
//   - provenant.parent_count  — how many parents (number)
//   - provenant.created       — the ISO-8601-UTC timestamp
//   - provenant.revoked       — is this attestation revoked? (bool)
//   - provenant.signed        — does it carry a `signature`? (bool)
//
// When the record is revoked, the revocation context (`revoked_by` / `_at` /
// `_reason`, folded in by `resolveRecords`) is added as flat scalars too; those
// keys are omitted entirely on a live record so the shape stays honest. Any
// scalar `meta.*` value is flattened under `provenant.meta.<key>` — nested or
// array meta values are skipped, keeping every emitted value a bare scalar.
export function attestationToSpanAttributes(record) {
  const r = record || {};
  const parents = Array.isArray(r.parents) ? r.parents : [];

  const attrs = {
    "provenant.id": r.id,
    "provenant.agent": r.agent,
    "provenant.artifact": r.artifact,
    "provenant.intent": r.intent,
    "provenant.parents": joinAttr(parents),
    "provenant.parent_count": parents.length,
    "provenant.created": r.created,
    "provenant.revoked": r.revoked === true,
    "provenant.signed": typeof r.signature === "string" && r.signature.length > 0,
  };

  if (r.revoked === true) {
    if (r.revoked_by !== undefined) attrs["provenant.revoked_by"] = r.revoked_by;
    if (r.revoked_at !== undefined) attrs["provenant.revoked_at"] = r.revoked_at;
    if (r.revoked_reason !== undefined) attrs["provenant.revoked_reason"] = r.revoked_reason;
  }

  if (r.meta !== null && typeof r.meta === "object" && !Array.isArray(r.meta)) {
    for (const [k, v] of Object.entries(r.meta)) {
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
        attrs[`provenant.meta.${k}`] = v;
      }
    }
  }

  return attrs;
}

// coverageToSpanAttributes(report) → a FLAT object of `provenant.coverage.*`
// span attributes from a `coverage()` result. `coverage()` returns `unattested`
// and `revoked` as ARRAYS of digests; a span wants their counts, so those are
// projected to numbers here (the arrays themselves never leave the flat map):
//
//   - provenant.coverage.score       — attested / total, a float in [0, 1]
//   - provenant.coverage.total       — distinct artifacts audited
//   - provenant.coverage.attested    — count with a live attestation
//   - provenant.coverage.unattested  — count with no attestation at all
//   - provenant.coverage.revoked     — count whose only attestations are revoked
export function coverageToSpanAttributes(report) {
  const r = report || {};
  return {
    "provenant.coverage.score": r.score,
    "provenant.coverage.total": r.total,
    "provenant.coverage.attested": r.attested,
    "provenant.coverage.unattested": Array.isArray(r.unattested) ? r.unattested.length : 0,
    "provenant.coverage.revoked": Array.isArray(r.revoked) ? r.revoked.length : 0,
  };
}
