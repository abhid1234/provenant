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
// `meta` and `signature` are optional; every other field is required.
export const ATTESTATION_FIELDS = [
  "id",
  "type",
  "agent",
  "artifact",
  "intent",
  "parents",
  "created",
  "meta",
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
