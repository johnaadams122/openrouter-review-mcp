import { createHash } from 'node:crypto';

const REQUIRED_FINDING_FIELDS = ['severity', 'section', 'root_cause', 'affected_behavior', 'consequence', 'evidence'];
const REVIEW_ROOT_FIELDS = ['verdict', 'findings'];
const SEVERITY_ENUM = ['blocker', 'major', 'minor'];
const VERDICT_ENUM = ['pass', 'block'];

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export const RESPONSE_FORMAT = deepFreeze({
  type: 'json_schema',
  json_schema: {
    name: 'openrouter_advisory_review_v1',
    strict: true,
    schema: {
      type: 'object',
      additionalProperties: false,
      required: ['verdict', 'findings'],
      properties: {
        verdict: { type: 'string', enum: ['pass', 'block'] },
        findings: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['severity', 'section', 'root_cause', 'affected_behavior', 'consequence', 'evidence'],
            properties: {
              severity: { type: 'string', enum: ['blocker', 'major', 'minor'] },
              section: { type: 'string', minLength: 1 },
              root_cause: { type: 'string', minLength: 1 },
              affected_behavior: { type: 'string', minLength: 1 },
              consequence: { type: 'string', minLength: 1 },
              evidence: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 } },
            },
          },
        },
      },
    },
  },
});

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const SCHEMA_SHA256 = createHash('sha256').update(canonicalJson(RESPONSE_FORMAT), 'utf8').digest('hex');

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function invalid(reason, verdict = null) {
  return { ok: false, reason, verdict, findingCount: null };
}

function findUnexpectedProperty(value, allowedFields) {
  return Object.keys(value).find((key) => !allowedFields.includes(key));
}

// These `reason` strings are schema-validation diagnostics, not caught Error objects, so they sit
// outside safeErrorDetail()'s redaction convention (review-engine.mjs) -- a deliberately different
// case, evaluated on its own merits rather than reusing that helper's all-or-nothing redaction.
// The interpolated value here is REVIEWER-generated (a malformed property name or enum value from
// the reviewer's own completion), never the caller's submitted document, and this string is never
// persisted to the ledger or logged -- leaseStore.reconcile() only ever stores the short, fixed
// `code` constant (e.g. 'STRICT_OUTPUT_INVALID') as haltReason, capped separately at 128 chars by
// requireHaltReason() -- so it reaches nothing but the one MCP caller who dispatched this exact
// review, in this one synchronous response. That caller already possesses the raw document and
// already expects to see the reviewer's own (here, malformed) output, so this is not a
// confidentiality boundary crossing. The cap below exists only for basic response-size hygiene: an
// untrusted-tier ("prompted_json") reviewer has no OpenRouter-enforced schema/length backstop and
// could in principle emit a pathologically long property name or enum value (up to its full
// completion-token budget), which would otherwise inflate this one diagnostic string unbounded.
const MAX_INTERPOLATED_VALUE_LENGTH = 100;

function describeInvalidValue(value) {
  let text;
  if (typeof value === 'string') {
    text = value;
  } else {
    try {
      text = JSON.stringify(value);
    } catch {
      text = undefined;
    }
    if (typeof text !== 'string') text = String(value);
  }
  // slice() cuts by UTF-16 code unit, so a truncation boundary landing inside an astral
  // character's surrogate pair can leave a lone surrogate in the tail. JSON.stringify() (used to
  // build the eventual reason string, and again by formatToolResult() downstream) escapes a lone
  // surrogate rather than throwing, so this is a cosmetic display artifact only, never a crash or
  // wire-format corruption -- not worth a codepoint-aware slice for a diagnostic string this size.
  return text.length > MAX_INTERPOLATED_VALUE_LENGTH
    ? `${text.slice(0, MAX_INTERPOLATED_VALUE_LENGTH)}... (truncated, ${text.length} chars total)`
    : text;
}

function validateFinding(finding, index) {
  if (!isPlainObject(finding)) return `findings[${index}] is not an object`;
  const unexpected = findUnexpectedProperty(finding, REQUIRED_FINDING_FIELDS);
  if (unexpected) return `findings[${index}] has an unexpected property "${describeInvalidValue(unexpected)}"`;
  for (const field of REQUIRED_FINDING_FIELDS) {
    if (!(field in finding)) return `findings[${index}] is missing required field "${field}"`;
  }
  if (!SEVERITY_ENUM.includes(finding.severity)) return `findings[${index}].severity "${describeInvalidValue(finding.severity)}" is outside the enum`;
  for (const field of ['section', 'root_cause', 'affected_behavior', 'consequence']) {
    if (typeof finding[field] !== 'string' || finding[field].length === 0) return `findings[${index}].${field} must be a non-empty string`;
  }
  if (!Array.isArray(finding.evidence) || finding.evidence.length === 0) return `findings[${index}].evidence must be a non-empty array`;
  if (!finding.evidence.every((item) => typeof item === 'string' && item.length > 0)) return `findings[${index}].evidence items must be non-empty strings`;
  return null;
}

export function validateAdvisoryContent(contentText) {
  let review;
  try {
    review = JSON.parse(contentText);
  } catch {
    return invalid('failed to parse choices[0].message.content as JSON');
  }

  if (!isPlainObject(review)) return invalid('review content is not an object');
  const unexpectedRootProperty = findUnexpectedProperty(review, REVIEW_ROOT_FIELDS);
  if (unexpectedRootProperty) return invalid(`review content has an unexpected property "${describeInvalidValue(unexpectedRootProperty)}"`);
  if (!VERDICT_ENUM.includes(review.verdict)) return invalid(`verdict "${describeInvalidValue(review.verdict)}" is outside the enum`);
  if (!Array.isArray(review.findings)) return invalid('findings is not an array', review.verdict);
  for (let index = 0; index < review.findings.length; index += 1) {
    const error = validateFinding(review.findings[index], index);
    if (error) return invalid(error, review.verdict);
  }
  return { ok: true, reason: null, verdict: review.verdict, findingCount: review.findings.length };
}

// Mechanical (not semantic) cleanup for prompted_json-mode reviewer responses, which routinely
// come back wrapped in a markdown code fence even when the prompt asks for raw JSON. This does
// not interpret or validate content -- it only strips known wrapping so validateAdvisoryContent's
// strict parser gets a fair shot at the real content underneath.
const FENCED_JSON_PATTERN = /^```(?:json)?\s*\n([\s\S]*?)\n```$/;

export function stripJsonFraming(text) {
  if (typeof text !== 'string') throw new TypeError('text must be a string');
  const trimmed = text.trim();
  const fenceMatch = trimmed.match(FENCED_JSON_PATTERN);
  return fenceMatch ? fenceMatch[1].trim() : trimmed;
}

export function extractFiniteNonnegativeCost(envelope) {
  if (!isPlainObject(envelope) || !isPlainObject(envelope.usage)) return null;
  const cost = envelope.usage.cost;
  if (typeof cost !== 'number' || !Number.isFinite(cost) || cost < 0) return null;
  return cost;
}
