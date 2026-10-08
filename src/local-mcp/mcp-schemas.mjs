import { z } from 'zod';
import { PROFILES } from '../review-core/reviewer-registry.mjs';
import { sharedError } from './shared/contracts.mjs';

/**
 * Strict Zod input/output schemas for the four openrouter_review_* MCP tools,
 * plus the shared text/structured result formatter. This module owns shape
 * only -- it never calls the review engine and never reimplements any of its
 * validation. Enumerated values (profile IDs, change kinds) are derived
 * directly from `../review-core/reviewer-registry.mjs` so this file cannot
 * silently drift from the fixed reviewer policy it is describing.
 */

const PROFILE_IDS = Object.freeze(Object.keys(PROFILES));
const CHANGE_KINDS = Object.freeze(Object.keys(PROFILES.final_verification_v1.reviewerIdsForChangeKinds));

// Exactly the five ReviewEngineError codes review-engine.mjs's haltAndClose() can attach to
// a single reviewer's entry. finalizeReviewOutcome may also project one at the top level. A
// halt from a rejected guard clause (SOURCE_INVALID, CONTRACT_CHANGED, LEASE_*, APPROVAL_*) is
// thrown before any structured result exists, so it never reaches this shape -- it surfaces as an
// MCP tool error instead (see tools/openrouter-review-mcp-server.mjs).
//
// Batch-wide expiry and duplicate refusal use the separate top-level list below; they are
// valid structured HALTED outcomes but never per-reviewer error codes.
const REVIEW_HALT_ERROR_CODES = Object.freeze([
  'PROVIDER_MISMATCH',
  'STRICT_OUTPUT_INVALID',
  'UNKNOWN_COST',
  'TRANSPORT_FAILURE',
  'DISPATCH_UNKNOWN',
]);

const REVIEW_TOP_LEVEL_ERROR_CODES = Object.freeze([
  ...REVIEW_HALT_ERROR_CODES,
  'LEASE_EXPIRED',
  'DUPLICATE_DISPATCH_IN_PROGRESS',
]);

const SHA256_HEX = z.string().regex(/^[a-f0-9]{64}$/, 'must be a lowercase SHA-256 digest');
const OPAQUE_ID = z.string().min(1).max(256);
const UPPERCASE_STATE = z.string().regex(/^[A-Z_]+$/, 'must be an uppercase state');
const USD = z.number().finite().nonnegative();
const POSITIVE_INT = z.number().int().positive();
const ISO_TIMESTAMP = z.string().min(1).refine((value) => Number.isFinite(Date.parse(value)), {
  message: 'must be a parseable ISO timestamp',
});

/**
 * `source_text` and `source_path` mirror loadReviewSource()'s own hard
 * requirement in source-contract.mjs (`hasText === hasPath` throws) --
 * enforcing it here gives callers a precise MCP-level validation error
 * instead of a generic SOURCE_INVALID engine error for the same mistake.
 * Byte limits, UTF-8 validity, and allowed-root containment are intentionally
 * left to the engine: this schema does not duplicate that policy.
 */
function requireExactlyOneSource(shape) {
  return shape.refine(
    (value) => (value.source_text !== undefined) !== (value.source_path !== undefined),
    { message: 'exactly one of source_text or source_path is required', path: ['source_text'] },
  );
}

export const TOOL_NAMES = Object.freeze({
  PREFLIGHT: 'openrouter_review_preflight',
  AUTHORIZE_WORKFLOW: 'openrouter_review_authorize_workflow',
  REVIEW: 'openrouter_review_document',
  STATUS: 'openrouter_review_status',
  RESULT: 'openrouter_review_result',
  SUBMIT: 'openrouter_review_submit',
  REQUEST_RESULT: 'openrouter_review_request_result',
  CANCEL: 'openrouter_review_cancel',
});

// ---------------------------------------------------------------------------
// openrouter_review_preflight
// ---------------------------------------------------------------------------

export const PREFLIGHT_INPUT_SCHEMA = requireExactlyOneSource(z.object({
  source_text: z.string().optional(),
  source_path: z.string().optional(),
  profile: z.enum(PROFILE_IDS),
  changeKinds: z.array(z.enum(CHANGE_KINDS)).optional(),
  reviewContext: z.string().optional(),
}).strict());

const ITEM_MAXIMUM_SCHEMA = z.object({
  itemId: OPAQUE_ID,
  maxUsd: USD,
}).strict();

const REVIEWER_SUMMARY_SCHEMA = z.object({
  reviewerId: z.string().min(1),
  model: z.string().min(1),
  route: z.string().min(1),
  maxUsd: USD,
}).strict();

export const PREFLIGHT_OUTPUT_SCHEMA = z.object({
  preflightId: OPAQUE_ID,
  state: UPPERCASE_STATE,
  reviewContractSha256: SHA256_HEX,
  sourceSha256: SHA256_HEX,
  profile: z.enum(PROFILE_IDS),
  profileVersion: z.string().min(1),
  itemMaxima: z.array(ITEM_MAXIMUM_SCHEMA).min(1),
  requestedUsd: USD,
  expiresAt: ISO_TIMESTAMP,
  reviewers: z.array(REVIEWER_SUMMARY_SCHEMA).min(1),
}).strict();

// ---------------------------------------------------------------------------
// openrouter_review_authorize_workflow
// ---------------------------------------------------------------------------

// Required only for a SECOND (or later) authorize_workflow call against the same preflightId
// while autonomous authorization is on -- see review-engine.mjs's authorizeWorkflow docstring.
// Ignored (never required, never consulted) for a first-use call or whenever autonomy is off.
const JUSTIFICATION = z.object({
  source: z.enum(['human', 'llm']),
  reason: z.string().min(1).max(2000),
}).strict();

export const AUTHORIZE_WORKFLOW_INPUT_SCHEMA = z.object({
  preflightId: OPAQUE_ID,
  maxJobs: POSITIVE_INT,
  expiresAt: ISO_TIMESTAMP.optional(),
  justification: JUSTIFICATION.optional(),
}).strict();

export const AUTHORIZE_WORKFLOW_OUTPUT_SCHEMA = z.object({
  leaseId: OPAQUE_ID,
  preflightId: OPAQUE_ID,
  state: UPPERCASE_STATE,
  requestedUsd: USD,
  maxJobs: POSITIVE_INT,
  expiresAt: ISO_TIMESTAMP,
}).strict();

// ---------------------------------------------------------------------------
// openrouter_review_document (review())
// ---------------------------------------------------------------------------

export const REVIEW_INPUT_SCHEMA = requireExactlyOneSource(z.object({
  leaseId: OPAQUE_ID,
  preflightId: OPAQUE_ID,
  source_text: z.string().optional(),
  source_path: z.string().optional(),
  reviewContext: z.string().optional(),
}).strict());

const FINDING_SCHEMA = z.object({
  severity: z.enum(['blocker', 'major', 'minor']),
  section: z.string().min(1),
  root_cause: z.string().min(1),
  affected_behavior: z.string().min(1),
  consequence: z.string().min(1),
  evidence: z.array(z.string().min(1)).min(1),
}).strict();

const ADVISORY_SCHEMA = z.object({
  verdict: z.enum(['pass', 'block']),
  findings: z.array(FINDING_SCHEMA),
}).strict();

// Field presence intentionally varies with how a reviewer entry was produced
// in review-engine.mjs: `provider` is only ever attached on a clean pass or a
// PROVIDER_MISMATCH halt; `model`/`advisory` only ever accompany a clean pass
// (recovered from advisoryCache or freshly reconciled). All three stay
// optional rather than required-or-absent per costKind so this schema does
// not have to re-encode that branching as a discriminated union.
const REVIEWER_RESULT_ENTRY_SCHEMA = z.object({
  reviewerId: z.string().min(1),
  jobId: OPAQUE_ID,
  state: UPPERCASE_STATE,
  costUsd: USD,
  costKind: z.enum([
    'KNOWN', 'UNKNOWN_WORST_CASE_CHARGED', 'RECOVERED_STATUS_ONLY',
    // ZERO_ON_TRANSPORT_FAILURE and REUSED_FROM_PRIOR_LEASE come from review-engine.mjs's
    // processDispatchOutcome/findReusableAdvisory. They are listed here even though this schema
    // module is not currently wired into any live validation path (outputSchema is deliberately
    // not passed to registerTool()), so it does not silently drift from the real set of values a
    // REVIEWER_RESULT_ENTRY_SCHEMA-shaped object can actually carry.
    'ZERO_ON_TRANSPORT_FAILURE', 'REUSED_FROM_PRIOR_LEASE',
    // ZERO_ON_PROVIDER_REJECTION, listed for the same reason: a response WAS received and it was
    // the provider refusing to run the request before any inference (a 4xx pre-inference reject).
    // Distinct from ZERO_ON_TRANSPORT_FAILURE, which means no response arrived at all.
    'ZERO_ON_PROVIDER_REJECTION',
  ]),
  provider: z.string().min(1).optional(),
  model: z.string().min(1).optional(),
  advisory: ADVISORY_SCHEMA.optional(),
  // Present only on a halted reviewer (review-engine.mjs's haltAndClose). Reviewers dispatch
  // concurrently, so several can halt for genuinely different reasons in one batch, and the single
  // top-level `error` can only report one of them. Same { code, message } shape as REVIEW_ERROR_SCHEMA below, declared inline rather than
  // reusing that constant because it is defined after this one in this file.
  error: z.object({
    code: z.enum(REVIEW_HALT_ERROR_CODES),
    message: z.string().min(1),
  }).strict().optional(),
}).strict();

const REVIEWERS_RESULT_MAP_SCHEMA = z.record(z.string().min(1), REVIEWER_RESULT_ENTRY_SCHEMA);

const REVIEW_ERROR_SCHEMA = z.object({
  code: z.enum(REVIEW_TOP_LEVEL_ERROR_CODES),
  message: z.string().min(1),
}).strict();

// A single flat object (rather than a discriminatedUnion) so the MCP SDK's
// object-schema normalization -- used for both tools/list JSON-schema
// generation and per-call output validation -- can recognize and validate it
// directly; a top-level z.discriminatedUnion is not an object schema and both
// paths silently skip or crash on one, which a smoke check against the
// installed SDK build (1.30.0) confirmed.
export const REVIEW_OUTPUT_SCHEMA = z.object({
  state: z.enum(['PASSED', 'HALTED']),
  leaseId: OPAQUE_ID,
  preflightId: OPAQUE_ID,
  reviewContractSha256: SHA256_HEX,
  reviewers: REVIEWERS_RESULT_MAP_SCHEMA,
  error: REVIEW_ERROR_SCHEMA.optional(),
}).strict().refine(
  (value) => (value.state === 'HALTED') === (value.error !== undefined),
  { message: 'error must be present if and only if state is HALTED', path: ['error'] },
);

// ---------------------------------------------------------------------------
// openrouter_review_status
// ---------------------------------------------------------------------------

export const STATUS_INPUT_SCHEMA = z.object({
  leaseId: OPAQUE_ID,
}).strict();

export const STATUS_OUTPUT_SCHEMA = z.object({
  leaseId: OPAQUE_ID,
  state: UPPERCASE_STATE,
  requestedUsd: USD,
  reservedUsd: USD,
  spentUsd: USD,
  jobsConsumed: z.number().int().nonnegative(),
  maxJobs: POSITIVE_INT,
  expiresAt: ISO_TIMESTAMP,
}).strict();

// ---------------------------------------------------------------------------
// openrouter_review_result
// ---------------------------------------------------------------------------

export const RESULT_INPUT_SCHEMA = z.object({
  leaseId: OPAQUE_ID,
}).strict();

// Reuses REVIEWERS_RESULT_MAP_SCHEMA (defined above for openrouter_review_document)
// unchanged: result()'s per-reviewer entries are always either a full
// REVIEWER_RESULT_ENTRY_SCHEMA-shaped recovered advisory or the same
// RECOVERED_STATUS_ONLY-costKind stub review() already produces, so this
// tool cannot silently drift from that shape.
export const RESULT_OUTPUT_SCHEMA = z.object({
  leaseId: OPAQUE_ID,
  state: UPPERCASE_STATE,
  reviewers: REVIEWERS_RESULT_MAP_SCHEMA,
}).strict();

// Shared execution adds receipt lifecycle without changing the original review
// or per-reviewer schemas. These tools are registered only by a shared bridge.
const SHARED_UUID = z.string().regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i);
const IDEMPOTENCY_KEY = z.string().regex(/^[A-Za-z0-9_-]{16,128}$/);
const CANONICAL_TIME = z.string().refine(value => {
  try { return new Date(value).toISOString() === value; } catch { return false; }
});
const TERMINAL_KIND = z.enum(['REVIEW_RETURNED','REVIEW_ERROR','EXPIRED','CANCELLED','CONTENT_LOST']);
export const SUBMIT_INPUT_SCHEMA = requireExactlyOneSource(z.object({
  leaseId: SHARED_UUID, preflightId: SHARED_UUID,
  source_text: z.string().optional(), source_path: z.string().optional(),
  reviewContext: z.string().optional(), idempotencyKey: IDEMPOTENCY_KEY,
}).strict());
export const REQUEST_RESULT_INPUT_SCHEMA = z.union([
  z.object({receiptId:SHARED_UUID}).strict(),
  z.object({leaseId:SHARED_UUID,idempotencyKey:IDEMPOTENCY_KEY}).strict(),
]);
export const CANCEL_INPUT_SCHEMA = z.object({receiptId:SHARED_UUID}).strict();
export const PUBLIC_RECEIPT_SCHEMA = z.object({
  receiptId:SHARED_UUID,leaseId:SHARED_UUID,preflightId:SHARED_UUID,
  state:z.enum(['QUEUED','WAITING','EXECUTING','RECOVERY_PENDING','TERMINAL']),
  acceptedAt:CANONICAL_TIME,effectiveDeadline:CANONICAL_TIME,
  snapshotSourceId:SHA256_HEX,reviewContractSha256:SHA256_HEX,
  startedAt:CANONICAL_TIME.optional(),cancellationRequested:z.literal(true).optional(),
  terminalKind:TERMINAL_KIND.optional(),
}).strict().refine(value=>(value.state==='TERMINAL')===(value.terminalKind!==undefined));
const SHARED_TERMINAL_ERROR = z.object({
  code:z.enum(['REQUEST_FAILED','PROTECTED_CONTENT_TOO_LARGE']),message:z.string(),
}).strict().refine(value=>value.message===sharedError(value.code).message);
export const PUBLIC_TERMINAL_SCHEMA = z.union([
  z.object({kind:z.literal('REVIEW_RETURNED'),review:REVIEW_OUTPUT_SCHEMA}).strict(),
  z.object({kind:z.literal('REVIEW_ERROR'),error:SHARED_TERMINAL_ERROR}).strict(),
  z.object({kind:z.enum(['EXPIRED','CANCELLED','CONTENT_LOST']),reviewers:REVIEWERS_RESULT_MAP_SCHEMA}).strict(),
]);
export const SUBMIT_OUTPUT_SCHEMA = z.object({accepted:z.literal(true),receipt:PUBLIC_RECEIPT_SCHEMA}).strict();
export const REQUEST_RESULT_OUTPUT_SCHEMA = z.union([
  z.object({receipt:PUBLIC_RECEIPT_SCHEMA,pending:z.literal(true)}).strict().refine(value=>value.receipt.state!=='TERMINAL'),
  z.object({receipt:PUBLIC_RECEIPT_SCHEMA,pending:z.literal(false),outcome:PUBLIC_TERMINAL_SCHEMA}).strict()
    .refine(value=>value.receipt.state==='TERMINAL'&&value.receipt.terminalKind===value.outcome.kind),
]);
export const CANCEL_OUTPUT_SCHEMA = z.object({receipt:PUBLIC_RECEIPT_SCHEMA,cancelled:z.boolean()}).strict();

// ---------------------------------------------------------------------------
// Shared text/structured result formatter
// ---------------------------------------------------------------------------

/**
 * Every tool in tools/openrouter-review-mcp-server.mjs returns
 * `structuredContent` plus an identical serialized text JSON block.
 * Centralized here so the two representations can never
 * drift apart from each other.
 */
export function formatToolResult(structuredContent) {
  return {
    structuredContent,
    content: [{ type: 'text', text: JSON.stringify(structuredContent) }],
  };
}
