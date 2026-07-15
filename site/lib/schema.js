// provenant — attestation + revocation schema and validators.
//
// Pure, zero-dependency validators for the open `attestation` and `revocation`
// record shapes and a ledger (array of records). None of these functions throw
// on bad input; each returns `{ valid, errors }` and collects *every* violation
// (no short-circuit) so a harness or human can fix everything in one pass.
//
// Error = { path: string, code: string, message: string }
//   path — dot/bracket path to the offending value ("parents[0]", "[2].artifact",
//          or "" for the whole object).
//   code — a stable machine-readable code from ERROR_CODES.
//   message — one-line human explanation.

export const RECORD_TYPES = ["attestation", "revocation"];

// The exact set of allowed top-level attestation fields, in canonical order.
// `meta`, `evaluation`, and `signature` are optional; every other field is
// required.
export const ATTESTATION_FIELDS = [
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
];

// The required subset of ATTESTATION_FIELDS (everything but the two optionals).
const ATTESTATION_REQUIRED = [
  "id",
  "type",
  "agent",
  "artifact",
  "intent",
  "parents",
  "created",
];

// The exact set of allowed top-level revocation fields, in canonical order.
export const REVOCATION_FIELDS = [
  "id",
  "type",
  "attestation_id",
  "agent",
  "reason",
  "at",
];

// The exact set of allowed fields of an `evaluation` sub-object, in canonical
// order. `score` and `method` are required; `checks` and `evaluator` optional.
export const EVALUATION_FIELDS = ["score", "method", "checks", "evaluator"];
const EVALUATION_REQUIRED = ["score", "method"];

// The exact set of allowed fields of a single `checks[]` entry.
const CHECK_FIELDS = ["name", "passed", "note"];

// Well-known `evaluation.method` values. This is a *hint*, not a constraint —
// `method` may be any non-empty string (a bespoke evaluator names its own
// method) — so validation never rejects an unknown method; the list is exported
// for consumers (and the CLI) that want to surface the common ones.
export const EVAL_METHODS = ["self", "test", "judge", "human"];

export const ERROR_CODES = {
  MISSING_FIELD: "MISSING_FIELD",
  UNKNOWN_FIELD: "UNKNOWN_FIELD",
  WRONG_TYPE: "WRONG_TYPE",
  NOT_OBJECT: "NOT_OBJECT",
  NOT_ARRAY: "NOT_ARRAY",
  EMPTY_STRING: "EMPTY_STRING",
  INVALID_ENUM: "INVALID_ENUM",
  INVALID_ISO8601: "INVALID_ISO8601",
  INVALID_SHA256: "INVALID_SHA256",
  INVALID_SIGNATURE: "INVALID_SIGNATURE",
  DUPLICATE_ID: "DUPLICATE_ID",
  OUT_OF_RANGE: "OUT_OF_RANGE",
};

// Strict ISO-8601 UTC: YYYY-MM-DDTHH:MM:SS(.sss)?Z. The regex gates the format
// (UTC `Z` only, no offsets); Date.parse gates real-calendar validity so
// impossible dates like 2026-13-40T00:00:00Z are rejected.
const ISO8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// A lowercase sha256 (or HMAC-sha256) digest: exactly 64 hex characters. Every
// content hash and record id in provenant is one of these, so the same check
// gates `artifact`, `parents[]`, `attestation_id`, and the `signature` shape.
const SHA256_HEX = /^[0-9a-f]{64}$/;

export function isIso8601Utc(s) {
  if (typeof s !== "string" || !ISO8601_UTC.test(s)) return false;
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) return false;
  // Date.parse silently rolls over impossible calendar dates (e.g.
  // 2026-02-30 → Mar 2, 2026-04-31 → May 1) instead of returning NaN, so a
  // format-valid but nonexistent date would slip through. Round-trip the
  // parsed value and require the calendar portion to match the input.
  return new Date(ms).toISOString().slice(0, 10) === s.slice(0, 10);
}

export function isSha256Hex(s) {
  return typeof s === "string" && SHA256_HEX.test(s);
}

function err(path, code, message) {
  return { path, code, message };
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

// Validate a single string field: present-ness is checked by the caller; here
// we type/emptiness-check a value that exists.
function checkStringField(errors, obj, field) {
  const v = obj[field];
  if (typeof v !== "string") {
    errors.push(err(field, ERROR_CODES.WRONG_TYPE, `${field} must be a string`));
  } else if (v.trim().length === 0) {
    errors.push(err(field, ERROR_CODES.EMPTY_STRING, `${field} must not be empty`));
  }
}

// Validate a single sha256-hex field (a content hash or record id): a string of
// exactly 64 lowercase hex characters.
function checkSha256Field(errors, obj, field) {
  const v = obj[field];
  if (typeof v !== "string") {
    errors.push(err(field, ERROR_CODES.WRONG_TYPE, `${field} must be a string`));
  } else if (!SHA256_HEX.test(v)) {
    errors.push(
      err(field, ERROR_CODES.INVALID_SHA256, `${field} must be a sha256 hex digest (64 hex chars)`)
    );
  }
}

export function validateAttestation(obj) {
  // 1. Must be a non-null plain object.
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "attestation must be a JSON object")],
    };
  }

  const errors = [];

  // 2. Required fields present (meta + signature are optional).
  for (const field of ATTESTATION_REQUIRED) {
    if (!(field in obj)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }

  // 3. Unknown top-level fields.
  for (const key of Object.keys(obj)) {
    if (!ATTESTATION_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  // 4. Per-field type/shape (only for fields that are present).
  if ("id" in obj) checkStringField(errors, obj, "id");
  if ("agent" in obj) checkStringField(errors, obj, "agent");
  if ("intent" in obj) checkStringField(errors, obj, "intent");
  if ("artifact" in obj) checkSha256Field(errors, obj, "artifact");

  if ("type" in obj && obj.type !== "attestation") {
    errors.push(
      err("type", ERROR_CODES.INVALID_ENUM, 'type must be "attestation"')
    );
  }

  if ("parents" in obj) {
    const parents = obj.parents;
    if (!Array.isArray(parents)) {
      errors.push(err("parents", ERROR_CODES.WRONG_TYPE, "parents must be an array"));
    } else {
      parents.forEach((p, i) => {
        if (typeof p !== "string") {
          errors.push(err(`parents[${i}]`, ERROR_CODES.WRONG_TYPE, "parent must be a string"));
        } else if (!SHA256_HEX.test(p)) {
          errors.push(
            err(
              `parents[${i}]`,
              ERROR_CODES.INVALID_SHA256,
              "parent must be an attestation id (sha256 hex digest)"
            )
          );
        }
      });
    }
  }

  if ("created" in obj && !isIso8601Utc(obj.created)) {
    errors.push(err("created", ERROR_CODES.INVALID_ISO8601, "created must be ISO 8601 UTC (…Z)"));
  }

  if ("meta" in obj && !isPlainObject(obj.meta)) {
    errors.push(err("meta", ERROR_CODES.WRONG_TYPE, "meta must be an object"));
  }

  // The optional `evaluation` sub-object is validated by validateEvaluation and
  // its error paths re-prefixed under `evaluation.` so the whole attestation
  // still reports every violation in one pass.
  if ("evaluation" in obj) {
    for (const e of validateEvaluation(obj.evaluation).errors) {
      const path = e.path === "" ? "evaluation" : `evaluation.${e.path}`;
      errors.push(err(path, e.code, e.message));
    }
  }

  if ("signature" in obj && !isSha256Hex(obj.signature)) {
    errors.push(
      err(
        "signature",
        ERROR_CODES.INVALID_SIGNATURE,
        "signature must be an HMAC-sha256 hex digest (64 hex chars)"
      )
    );
  }

  return { valid: errors.length === 0, errors };
}

// validateEvaluation(evaluation) → { valid, errors }
//
// The open shape of an attestation's optional `evaluation` — a portable,
// content-addressed CLAIM about the attested artifact's quality/confidence and
// how it was judged: `{ score, method, checks?, evaluator? }`. Like every other
// validator here it never throws and collects *every* violation:
//
//   - score     — required; a number in [0, 1] (WRONG_TYPE if not a number,
//                 OUT_OF_RANGE if outside the unit interval or NaN).
//   - method    — required; a non-empty string (how it was judged — `self` /
//                 `test` / `judge` / `human` or any bespoke evaluator name).
//   - checks    — optional; an array of `{ name, passed, note? }` entries, each
//                 a named boolean sub-check (name non-empty, passed a boolean,
//                 note an optional string).
//   - evaluator — optional; a non-empty string naming who/what evaluated.
export function validateEvaluation(evaluation) {
  if (!isPlainObject(evaluation)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "evaluation must be a JSON object")],
    };
  }

  const errors = [];

  // 1. Required fields present (checks + evaluator are optional).
  for (const field of EVALUATION_REQUIRED) {
    if (!(field in evaluation)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }

  // 2. Unknown fields.
  for (const key of Object.keys(evaluation)) {
    if (!EVALUATION_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  // 3. score — a number in the closed unit interval [0, 1].
  if ("score" in evaluation) {
    const s = evaluation.score;
    if (typeof s !== "number" || Number.isNaN(s)) {
      errors.push(err("score", ERROR_CODES.WRONG_TYPE, "score must be a number"));
    } else if (s < 0 || s > 1) {
      errors.push(err("score", ERROR_CODES.OUT_OF_RANGE, "score must be in [0, 1]"));
    }
  }

  // 4. method / evaluator — non-empty strings (evaluator only when present).
  if ("method" in evaluation) checkStringField(errors, evaluation, "method");
  if ("evaluator" in evaluation) checkStringField(errors, evaluation, "evaluator");

  // 5. checks — an array of well-formed `{ name, passed, note? }` entries.
  if ("checks" in evaluation) {
    const checks = evaluation.checks;
    if (!Array.isArray(checks)) {
      errors.push(err("checks", ERROR_CODES.NOT_ARRAY, "checks must be an array"));
    } else {
      checks.forEach((c, i) => {
        if (!isPlainObject(c)) {
          errors.push(err(`checks[${i}]`, ERROR_CODES.NOT_OBJECT, "check must be an object"));
          return;
        }
        if (!("name" in c)) {
          errors.push(err(`checks[${i}].name`, ERROR_CODES.MISSING_FIELD, "name is required"));
        } else if (typeof c.name !== "string") {
          errors.push(err(`checks[${i}].name`, ERROR_CODES.WRONG_TYPE, "name must be a string"));
        } else if (c.name.trim().length === 0) {
          errors.push(err(`checks[${i}].name`, ERROR_CODES.EMPTY_STRING, "name must not be empty"));
        }
        if (!("passed" in c)) {
          errors.push(err(`checks[${i}].passed`, ERROR_CODES.MISSING_FIELD, "passed is required"));
        } else if (typeof c.passed !== "boolean") {
          errors.push(
            err(`checks[${i}].passed`, ERROR_CODES.WRONG_TYPE, "passed must be a boolean")
          );
        }
        if ("note" in c && typeof c.note !== "string") {
          errors.push(err(`checks[${i}].note`, ERROR_CODES.WRONG_TYPE, "note must be a string"));
        }
        for (const key of Object.keys(c)) {
          if (!CHECK_FIELDS.includes(key)) {
            errors.push(
              err(`checks[${i}].${key}`, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`)
            );
          }
        }
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

export function validateRevocation(obj) {
  // 1. Must be a non-null plain object.
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "revocation must be a JSON object")],
    };
  }

  const errors = [];

  // 2. Required fields present (revocation has no optional fields).
  for (const field of REVOCATION_FIELDS) {
    if (!(field in obj)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }

  // 3. Unknown top-level fields.
  for (const key of Object.keys(obj)) {
    if (!REVOCATION_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  // 4. Per-field type/shape (only for fields that are present).
  if ("id" in obj) checkStringField(errors, obj, "id");
  if ("agent" in obj) checkStringField(errors, obj, "agent");
  if ("reason" in obj) checkStringField(errors, obj, "reason");
  if ("attestation_id" in obj) checkSha256Field(errors, obj, "attestation_id");

  if ("type" in obj && obj.type !== "revocation") {
    errors.push(err("type", ERROR_CODES.INVALID_ENUM, 'type must be "revocation"'));
  }

  if ("at" in obj && !isIso8601Utc(obj.at)) {
    errors.push(err("at", ERROR_CODES.INVALID_ISO8601, "at must be ISO 8601 UTC (…Z)"));
  }

  return { valid: errors.length === 0, errors };
}

export function validateLedger(arr) {
  // 1. Must be an array.
  if (!Array.isArray(arr)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_ARRAY, "ledger must be a JSON array")],
    };
  }

  const errors = [];

  // 2. Per-element validation, dispatched by `type` (a record with
  // type === "revocation" is a revocation; anything else is validated as an
  // attestation). Each error path is re-prefixed with [i].
  arr.forEach((record, i) => {
    const isRevocation = isPlainObject(record) && record.type === "revocation";
    const result = isRevocation ? validateRevocation(record) : validateAttestation(record);
    for (const e of result.errors) {
      const path = e.path === "" ? `[${i}]` : `[${i}].${e.path}`;
      errors.push(err(path, e.code, e.message));
    }
  });

  // 3. Duplicate id detection among structurally-valid records. A duplicate id
  // signals corruption or a double-append; flag every occurrence after the
  // first at [i].id.
  const seen = new Set();
  arr.forEach((record, i) => {
    if (isPlainObject(record) && isNonEmptyString(record.id)) {
      if (seen.has(record.id)) {
        errors.push(
          err(`[${i}].id`, ERROR_CODES.DUPLICATE_ID, `duplicate id: ${record.id}`)
        );
      } else {
        seen.add(record.id);
      }
    }
  });

  return { valid: errors.length === 0, errors };
}
