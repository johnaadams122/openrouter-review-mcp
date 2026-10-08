import { createHash, randomUUID } from 'node:crypto';
import { SCHEMA_SHA256, extractFiniteNonnegativeCost, stripJsonFraming, validateAdvisoryContent } from '../review-core/advisory-schema.mjs';
import { PROMPT_VERSION, REGISTRY_SHA256, buildReviewContract, getReviewer } from '../review-core/reviewer-registry.mjs';
import { LEDGER_DATA_ROOT_LOCKED_CODE } from './lease-store.mjs';
import { createOwnershipCoordinator, DEFAULT_ARM_LOCK_RETRY_MS, DEFAULT_ARM_TIMEOUT_MS } from './ownership-coordinator.mjs';
import { buildReviewRequest, loadReviewSource, preflightReview } from './source-contract.mjs';
import {
  canonicalJson,
  executionFingerprint,
  sharedError,
  validatePreparedEnvelope,
} from './shared/contracts.mjs';
import { isAllowedReviewerSet, maximumPreflightEncryptedBytes, resolveBoundProjectPolicy, resolveCallerPolicy } from './shared/policy.mjs';

// Real Node.js error codes are drawn from a small, fixed vocabulary; this list exists only to
// pick a recognizable label in the generic marker below (e.g. "ENOENT" rather than "Error").
// safeErrorDetail() gates on MEMBERSHIP in this fixed set, never on shape -- see its own
// docstring for why a shape-only gate is forgeable.
const KNOWN_NODE_ERROR_CODES = new Set([
  'ENOENT', 'EACCES', 'EPERM', 'ENOSPC', 'EBUSY', 'ENOTEMPTY', 'EEXIST', 'EISDIR', 'ENOTDIR',
  'EMFILE', 'ENFILE', 'EROFS', 'EXDEV', 'ELOOP', 'ENAMETOOLONG',
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'ENETUNREACH', 'EHOSTUNREACH', 'EADDRINUSE',
  // Not a Node code: the lease store's own data-root lock timeout, by its exported constant, so a
  // busy ledger is named as such. Still an exact-match constant.
  LEDGER_DATA_ROOT_LOCKED_CODE,
]);
// The standard built-in JS error names, plus this module's own ReviewEngineError -- a fixed,
// closed set for the exact same reason KNOWN_NODE_ERROR_CODES is one: safeErrorDetail() only
// ever prints a `.name` value that is byte-for-byte a member of this set, never one merely
// shaped like a plausible name.
const KNOWN_ERROR_NAMES = new Set([
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError', 'EvalError', 'URIError',
  'AggregateError', 'ReviewEngineError',
]);

/**
 * Returns a log-safe description of a caught error: a recognizable label plus a fixed marker,
 * never the error's own message. A caught error's `.message` can carry a fragment of the document
 * under review or of a reviewer's output, so it is never interpolated into a stderr line or a
 * returned result. The label is a `.code` that is exactly a member of KNOWN_NODE_ERROR_CODES or
 * ERROR_CODES, else a `.name` that is exactly a member of KNOWN_ERROR_NAMES, else 'Error'. Both
 * properties are freely settable, so a shape test ("looks like an upper-case enum") is forgeable --
 * an access-key-shaped string passes it -- while exact membership in a fixed set is not.
 */
export function safeErrorDetail(error) {
  if (error === null || typeof error !== 'object') return 'non-Error rejection (detail redacted)';
  // Read each property EXACTLY ONCE, and never let a misbehaving accessor make this function
  // itself throw: reading `.code`/`.name` twice each (once for a `typeof` check, once again to use
  // the value) is unsafe against a getter with side effects -- a value that is safe on the
  // first read could differ, or throw, on the second. This function exists specifically to be
  // callable from any catch block without extra care, so it must degrade to the generic label
  // rather than propagate a second exception of its own.
  let code = null;
  try { ({ code } = error); } catch { /* leaves code null, same as not having one */ }
  let name = null;
  try { ({ name } = error); } catch { /* leaves name null, same as not having one */ }
  const rawCode = typeof code === 'string' ? code : null;
  const rawName = typeof name === 'string' ? name : null;
  const label = rawCode !== null && (KNOWN_NODE_ERROR_CODES.has(rawCode) || ERROR_CODES.includes(rawCode))
    ? rawCode
    : (rawName !== null && KNOWN_ERROR_NAMES.has(rawName) ? rawName : 'Error');
  return `${label} (detail redacted)`;
}

// Kill alert: the only codes an
// alert about a failed managed dispatch may name. A fixed, closed set matched by exact equality on `.code`, for the same reason
// safeErrorDetail() above never trusts a shape. A test in the shared-service suite (not part of this release) pins it against
// the codes thrown by the managed dispatch and store modules, so a newly thrown code cannot be added without this list.
export const MANAGED_DISPATCH_FAULT_CODES = Object.freeze([
  'MANAGED_WORKER_TIMEOUT',
  'MANAGED_WORKER_FAILED',
  'MANAGED_WORKER_PROTOCOL',
  'MANAGED_INTENT_STALE',
  'MANAGED_CAPTURE_PENDING',
  'MANAGED_CAPTURE_READ_DENIED',
]);

const FAULT_REVIEWER_ID = /^[a-z0-9_]{1,64}$/;
const FIVE_DIGIT_RUN = /\d{5,}/;
// Four digits at most, so a reason never holds a run the alert store refuses (five or more digits).
const FAULT_ELAPSED_CAP_SECONDS = 9999;

/**
 * The reason line of the warning alert written when a managed dispatch throws: `<CODE> after <n>s reviewer <id>`. Pure, and it
 * never throws, whatever it is given: no argument, null, a primitive or an object with a hostile getter reads as missing fields,
 * and each field is read on its own, so one hostile field does not erase the others. The code comes first so it survives any
 * truncation downstream.
 *
 * - CODE is the error's `.code`, read exactly once and inside a try (a hostile getter reads as no code), and only when it is
 *   byte-for-byte one of MANAGED_DISPATCH_FAULT_CODES; anything else, a thrown non-object included, is the literal OTHER. The
 *   message, the name and every other property are never read, so no content can reach the alert (the rule safeErrorDetail()
 *   documents).
 * - n is whole elapsed seconds, floored and clamped to 0 through 9999, counted from just before the dispatch call starts. The
 *   engine cannot see when the worker was spawned, so the figure includes the adapter's own checks before the spawn (intent
 *   verification, the dispatching marker, the request check). A small figure, 0s included, says only that the call ended quickly,
 *   which usually means a refusal before or at worker start; it is not proof that no worker ran. A reading that is not a finite
 *   number renders the literal unknown (with no s), so a broken clock cannot write a nonsense figure.
 * - id is the reviewer's registry id, used only when it is a plain lower-case token with no run of five digits (the alert store
 *   refuses such a reason); otherwise the literal unknown.
 */
export function describeManagedDispatchFault(input) {
  const read = (key) => {
    try { return input[key]; } catch { return undefined; }
  };
  const error = read('error');
  const elapsedMs = read('elapsedMs');
  const reviewerId = read('reviewerId');
  let rawCode = null;
  if (error !== null && typeof error === 'object') {
    try { ({ code: rawCode } = error); } catch { rawCode = null; }
  }
  const code = typeof rawCode === 'string' && MANAGED_DISPATCH_FAULT_CODES.includes(rawCode) ? rawCode : 'OTHER';
  const elapsed = typeof elapsedMs === 'number' && Number.isFinite(elapsedMs)
    ? `${Math.min(FAULT_ELAPSED_CAP_SECONDS, Math.max(0, Math.floor(elapsedMs / 1000)))}s`
    : 'unknown';
  const reviewer = typeof reviewerId === 'string' && FAULT_REVIEWER_ID.test(reviewerId) && !FIVE_DIGIT_RUN.test(reviewerId)
    ? reviewerId
    : 'unknown';
  return `${code} after ${elapsed} reviewer ${reviewer}`;
}

function reviewersFromItemMaxima(itemMaxima) {
  return itemMaxima.map((item) => {
    const reviewerId = item.itemId.replace(/^item-/, '');
    const reviewer = getReviewer(reviewerId);
    return { reviewerId: reviewer.id, model: reviewer.model, route: reviewer.route, maxUsd: item.maxUsd };
  });
}

/**
 * Resolves the reviewer registry entry for a stale RESERVED job even when its own ledger record
 * has no reviewerId. reviewerId on a job record is optional (lease-store.mjs's consume(),
 * "backward compatible with every existing direct caller") -- reserveReviewers() (the live
 * reservation path) always supplies it, but the ledger is a long-lived, append-only store that can
 * hold jobs left stuck RESERVED by earlier code versions written before consume() recorded
 * reviewerId at all. Without this fallback, such a job's captured outcome would be unreachable by
 * the pre-pass -- getReviewer(undefined) throws, and recovery falls back to the conservative
 * worst-case charge for a job whose real, cheaper cost was actually determinable.
 *
 * itemId derives reviewerId the same way reviewersFromItemMaxima() above already does;
 * deriveJobId() is the SAME deterministic formula every job's own id is minted from -- trying each
 * candidate and keeping only the one whose derived id matches this job's real id is the one way to
 * recover the identity without trusting anything the caller supplies. Returns null (never throws)
 * when nothing matches, so callers can fall through to their own error handling uniformly.
 */
async function resolveStaleJobReviewer({ staleJob, staleLease, leaseStore }) {
  if (staleJob.reviewerId !== undefined) {
    try {
      return getReviewer(staleJob.reviewerId);
    } catch {
      // Falls through to the itemMaxima-derived reverse lookup below.
    }
  }
  const [preflightId] = staleLease.preflightIds;
  if (preflightId === undefined) return null;
  const preflightRecord = await leaseStore.getPreflight(preflightId);
  if (!preflightRecord) return null;
  for (const item of preflightRecord.itemMaxima) {
    const candidateReviewerId = item.itemId.replace(/^item-/, '');
    if (deriveJobId(staleJob.leaseId, candidateReviewerId, staleLease.reviewContractSha256) !== staleJob.jobId) continue;
    try {
      return getReviewer(candidateReviewerId);
    } catch {
      return null;
    }
  }
  return null;
}

const ERROR_CODES = Object.freeze([
  'SOURCE_INVALID',
  'CONTENT_BLOCKED',
  'CONTRACT_CHANGED',
  'LEASE_MISSING',
  'LEASE_EXPIRED',
  'LEASE_CLOSED',
  'LEASE_CAP_EXCEEDED',
  'DAILY_ALLOWANCE_EXCEEDED',
  'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION',
  'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
  'APPROVAL_DENIED',
  'APPROVAL_TIMEOUT',
  'PROVIDER_MISMATCH',
  'STRICT_OUTPUT_INVALID',
  'UNKNOWN_COST',
  'TRANSPORT_FAILURE',
  'DISPATCH_UNKNOWN',
  // A lease-store write (createLease/consume/reconcile/close/sweepOrphanedLeases) rejected this
  // call because its ownerLock.acquisitionId no longer matches the ledger's live processOwner
  // record -- a SEPARATE, genuinely different failure category from a stale lease or a mismatched
  // review contract: it means a SECOND server instance has since raced/superseded this one (an
  // unclean-shutdown reclaim, or an operator starting a second process against the same data
  // root), not that anything about the lease/contract itself is wrong. Deliberately its own code
  // rather than reusing LEASE_MISSING/CONTRACT_CHANGED -- conflating them would hide a real
  // operational problem (this process has been superseded) behind misleading diagnostics that
  // point an operator at the wrong thing to investigate.
  'PROCESS_OWNERSHIP_LOST',
  // Graceful shutdown draining: beginShutdown() has been called, so this engine refuses
  // to START new owner-sensitive work (authorizeWorkflow/review) while it drains whatever is
  // already in flight and the composition root prepares to release process ownership. Thrown only
  // by refuseIfShuttingDown() at the export boundary below -- never from inside a call that already
  // began, which is always allowed to finish or halt on its own terms.
  'SHUTTING_DOWN',
  // On-demand ownership arming: an owner-sensitive call's on-demand ARM exhausted its budget
  // against another holder. `details.reason` says which of LIVE_OWNER / NOT_YET_STALE /
  // DATA_ROOT_LOCKED; nothing was attempted, preflight/status/result keep working, and retrying the
  // same call later is safe.
  'PROCESS_OWNERSHIP_UNAVAILABLE',
  // Operation-scoped release: a prior owner-sensitive operation completed, but handing process
  // ownership back failed. The completed operation keeps its original value/error; the coordinator
  // latches this code for every later owner-sensitive call so a caller cannot accidentally
  // redispatch completed work. Read-oriented tools remain callable.
  'PROCESS_OWNERSHIP_RELEASE_FAILED',
  // An ordinary, NON-arming store call lost the data-root lock for its whole short lock budget, so it
  // committed nothing: a read, an unfenced write, or an owner-fenced write such as consume(),
  // createLease() or a close(). Deliberately distinct from the arm failure above: the ledger was
  // only momentarily busy, and retrying the same call is safe. It carries no `reason`: the raw lock
  // error has none, and the code itself already says the ledger was busy. See
  // withLedgerBusyTranslation() below.
  'LEDGER_BUSY',
  // An arm was refused because a still-live server armed this data root with different spend caps.
  // Terminal for that arm: waiting cannot change a configuration disagreement.
  'OWNERSHIP_CAP_MISMATCH',
]);

// The one message every LEDGER_BUSY carries, so the tool surface's { code, message } is stable.
const LEDGER_BUSY_MESSAGE = 'the review ledger is busy (another session is using it); retrying the same call is safe';

// Bounded retries for a managed compare-and-set that loses to a sibling reviewer's ledger write. A retry
// happens only after a real sibling write, and each sibling bumps the shared revisions at most about four
// times (reservation, intent, reconcile, halt); 64 covers the policy's maximum of 15 reviewers per request.
const SIBLING_REVISION_ATTEMPTS = 64;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Every structured failure this engine reports. `details` is an OPTIONAL, ADVISORY payload: a plain object, copied and frozen at
 * construction, that the MCP server serializes next to `{ code, message }`. Callers must never
 * require it -- `{ code, message }` is the whole contract -- and when none is supplied the error has
 * no `details` property at all.
 */
export class ReviewEngineError extends Error {
  constructor(code, message, details) {
    if (!ERROR_CODES.includes(code)) throw new TypeError(`unknown review engine error code: ${code}`);
    if (details !== undefined && !isPlainObject(details)) {
      throw new TypeError('ReviewEngineError details must be a plain object when supplied');
    }
    super(message);
    this.name = 'ReviewEngineError';
    this.code = code;
    if (details !== undefined) this.details = Object.freeze({ ...details });
  }
}

/**
 * True for lease-store.mjs's data-root lock timeout, recognized by its exported code constant and
 * never by message text. Several connected server processes can share one data root, so this is
 * ordinary, transient contention rather than a rare fault.
 */
function isLedgerBusyError(error) {
  return error?.code === LEDGER_DATA_ROOT_LOCKED_CODE;
}

/**
 * A reconcile that records a real dispatch outcome and loses only the data-root lock is retried
 * until its next sleep would pass this budget, and each sleep between attempts is an equal-jitter
 * draw from [BASE / 2, BASE). See reconcileRetryingLedgerBusy() inside createReviewEngine. Exported
 * so the retry tests import them.
 */
export const LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS = 10_000;
export const LEDGER_BUSY_RECONCILE_RETRY_BASE_MS = 500;

// The engine's default `sleep` option for the reconcile retry: a plain timer. Tests pass a fake one.
function defaultSleep(milliseconds) {
  return new Promise((resolve) => { setTimeout(resolve, milliseconds); });
}

function ledgerBusyError() {
  return new ReviewEngineError('LEDGER_BUSY', LEDGER_BUSY_MESSAGE);
}

/**
 * The per-site translation for LEDGER_DATA_ROOT_LOCKED escaping an ordinary, NON-arming store call
 * Applied at exactly these sites: status()'s and result()'s opening
 * getLease, preflight()'s createPreflight, getCachedPreflight()'s getPreflight fallback, and --
 * inline, in the same shape -- translateConsumeError() and grantLeaseFromOutcome()'s catch. Every
 * other store call is covered by withLedgerBusyBoundary() below. An ARM that exhausts its budget is
 * a different failure (PROCESS_OWNERSHIP_UNAVAILABLE), translated where the arm happens. Every other
 * error passes through unchanged.
 */
async function withLedgerBusyTranslation(work) {
  try {
    return await work();
  } catch (error) {
    if (isLedgerBusyError(error)) throw ledgerBusyError();
    throw error;
  }
}

/**
 * The boundary translation. EVERY non-arming store call reachable from a tool must surface as
 * LEDGER_BUSY, and the
 * per-site translations above cannot name every call on every path. So each engine export that can
 * reach the lease store is wrapped in this, at the export object: a rejection whose code is STILL
 * the raw LEDGER_DATA_ROOT_LOCKED when it escapes becomes LEDGER_BUSY, with the original message
 * kept as advisory details; anything else, every ReviewEngineError included, is rethrown
 * unchanged. Retrying the same call is safe, review() included: its markDispatching claim and the
 * existing-job recovery make a re-entry resume rather than redo. The per-site translations still
 * matter: translateConsumeError() and grantLeaseFromOutcome() would otherwise relabel the error
 * LEASE_MISSING or CONTRACT_CHANGED before it ever reached this boundary.
 */
function withLedgerBusyBoundary(operation) {
  return async (...args) => {
    try {
      return await operation(...args);
    } catch (error) {
      if (isLedgerBusyError(error)) {
        throw new ReviewEngineError('LEDGER_BUSY', LEDGER_BUSY_MESSAGE, { originalMessage: String(error.message) });
      }
      throw error;
    }
  };
}

function requirePlainObject(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${field} must be an object`);
  return value;
}

function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${field} must be a non-empty string`);
  return value;
}

function requireFunction(value, field) {
  if (typeof value !== 'function') throw new TypeError(`${field} must be a function`);
  return value;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function validateManagedExecutionBundle(managedExecution) {
  if (managedExecution === undefined) return null;
  requirePlainObject(managedExecution, 'managedExecution');
  const requiredKeys = [
    'managedLedger', 'protectedStore', 'identityDigest', 'mappingPins', 'resultPersistence',
    'executionPermits', 'managedDispatchAdapter', 'dispatchOutcomeStore', 'terminalStore', 'getInstallationConfig',
  ];
  for (const key of requiredKeys) {
    if (!Object.hasOwn(managedExecution, key)) throw new TypeError(`managedExecution.${key} is required`);
  }
  const {
    managedLedger, protectedStore, identityDigest, mappingPins, resultPersistence,
    executionPermits, managedDispatchAdapter, dispatchOutcomeStore, terminalStore, getInstallationConfig,
  } = managedExecution;
  requirePlainObject(managedLedger, 'managedExecution.managedLedger');
  for (const method of [
    'lookupManagedIdentity', 'reserveManagedPreflightCapacity', 'commitManagedPreflight',
    'releaseManagedPreflightReservation', 'createManagedLease', 'getStagingPermit',
    'getManagedPreflightForPreparation',
    'recoverManagedReceipt', 'getReceipt', 'findReceiptForManagedLease', 'consumeManaged', 'transitionIntentPending',
    'releaseCancellableReservation', 'reconcileManaged', 'findManagedReusableJobs',
    'markManagedRecoveryPending',
    'beginTerminalPublication', 'terminalizeReceipt', 'terminalizeTerminalPublicationAsContentLost',
    'closeManagedLease', 'claimManagedHealthEffect',
    'recordManagedHealthEffect',
  ]) requireFunction(managedLedger[method], `managedExecution.managedLedger.${method}`);
  requirePlainObject(protectedStore, 'managedExecution.protectedStore');
  for (const method of ['put', 'get', 'verify', 'inspectDispatchCapture']) requireFunction(protectedStore[method], `managedExecution.protectedStore.${method}`);
  requireFunction(identityDigest, 'managedExecution.identityDigest');
  requirePlainObject(mappingPins, 'managedExecution.mappingPins');
  requireFunction(mappingPins.mayDelete, 'managedExecution.mappingPins.mayDelete');
  requirePlainObject(resultPersistence, 'managedExecution.resultPersistence');
  requireFunction(resultPersistence.persistManagedAdvisory, 'managedExecution.resultPersistence.persistManagedAdvisory');
  requireFunction(resultPersistence.persistManagedTerminal, 'managedExecution.resultPersistence.persistManagedTerminal');
  requirePlainObject(executionPermits, 'managedExecution.executionPermits');
  requireFunction(executionPermits.assertLive, 'managedExecution.executionPermits.assertLive');
  requirePlainObject(executionPermits.allocationGate, 'managedExecution.executionPermits.allocationGate');
  requireFunction(executionPermits.allocationGate.runReservationPhase, 'managedExecution.executionPermits.allocationGate.runReservationPhase');
  requirePlainObject(managedDispatchAdapter, 'managedExecution.managedDispatchAdapter');
  for (const method of ['prepareDispatchResources', 'releaseDispatchResources', 'dispatchPrepared']) {
    requireFunction(managedDispatchAdapter[method], `managedExecution.managedDispatchAdapter.${method}`);
  }
  requirePlainObject(dispatchOutcomeStore, 'managedExecution.dispatchOutcomeStore');
  for (const method of ['recoverCapture', 'recall']) {
    requireFunction(dispatchOutcomeStore[method], `managedExecution.dispatchOutcomeStore.${method}`);
  }
  requirePlainObject(terminalStore, 'managedExecution.terminalStore');
  for (const method of ['recordPublication', 'recallPublication', 'recallCommitted']) {
    requireFunction(terminalStore[method], `managedExecution.terminalStore.${method}`);
  }
  requireFunction(getInstallationConfig, 'managedExecution.getInstallationConfig');
  return managedExecution;
}

function requireAuthenticatedBinding(authenticatedBinding, errorCode = 'REQUEST_NOT_FOUND') {
  if (!isPlainObject(authenticatedBinding)) throw sharedError(errorCode);
  const descriptors = Object.getOwnPropertyDescriptors(authenticatedBinding);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')
      || Object.keys(descriptors).some((key) => !['bindingId', 'credentialVersion', 'credentialDigest'].includes(key))
      || !['bindingId', 'credentialVersion', 'credentialDigest'].every((key) => Object.hasOwn(descriptors, key)
        && descriptors[key].enumerable && Object.hasOwn(descriptors[key], 'value'))) {
    throw sharedError(errorCode);
  }
  const value = Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  if (typeof value.bindingId !== 'string' || value.bindingId.length === 0
      || typeof value.credentialVersion !== 'string' || value.credentialVersion.length === 0
      || typeof value.credentialDigest !== 'string' || !/^[a-f0-9]{64}$/.test(value.credentialDigest)) {
    throw sharedError(errorCode);
  }
  return Object.freeze(value);
}

/**
 * An owner-sensitive call carries an explicit, frozen
 * `{ acquisitionId }` snapshot taken once, right after its arm, and every fenced write in that call
 * uses it. Refuses anything but a FROZEN object whose OWN acquisitionId is a DATA property holding a
 * non-empty string, so a missing or unarmed snapshot fails loudly before any I/O instead of reaching
 * the ledger's fence. The live ownership handle is refused too: it is frozen, and its acquisitionId
 * is a string while armed, but that property is a getter, so a write handed the handle would read the
 * live id at write time, which is exactly the late read the snapshot exists to prevent.
 */
function requireOwnerToken(ownerToken) {
  const acquisitionId = ownerToken !== null && typeof ownerToken === 'object' && Object.isFrozen(ownerToken)
    ? Object.getOwnPropertyDescriptor(ownerToken, 'acquisitionId')?.value
    : undefined;
  if (typeof acquisitionId !== 'string' || acquisitionId.length === 0) {
    throw new TypeError('ownerToken must be a frozen { acquisitionId } snapshot');
  }
  return ownerToken;
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Operational alerts: a proactive warning when spend nears the account's monthly limit, and a
// failure-rate/pipeline-health critical alert, independent of spend. Both reuse alertStore.mjs --
// no second notification mechanism.
// ---------------------------------------------------------------------------

// Fraction of the account's monthly spend limit (as reported by the key-status probe's `limit`
// field) at which review() raises a warning alert, once per billing period. No limit is hardcoded
// here: the fraction is always computed against whatever `limit` the live probe reports, so the
// alert tracks the account's real cap even if it changes.
export const DEFAULT_SPEND_ALERT_THRESHOLD_FRACTION = 0.75;

// How many CONSECUTIVE dispatch failures (any haltAndClose reason -- transport failure, a bad or
// unverifiable cost, a provider mismatch, invalid structured output, or an unknown dispatch
// outcome) must occur in a row before review() raises a critical pipeline-health alert,
// independent of spend. Exported as a configurable engine option (see createReviewEngine's own
// `consecutiveDispatchFailureAlertThreshold` parameter below), not a literal used only here, so an
// operator can retune it without a code change.
//
// Chosen default: 3. Justification:
//   - Failures of this pipeline tend to come in STREAKS -- one environmental root cause (for
//     example, the host repeatedly tearing down the dispatch worker) recurring call after call --
//     rather than as occasional flukes interleaved with successes. A consecutive-run threshold
//     matches that failure shape directly.
//   - 1 is too sensitive: a single TRANSPORT_FAILURE/DISPATCH_UNKNOWN halt is unremarkable on its
//     own (individual dispatch hiccups happen even when the pipeline as a whole is healthy -- e.g.
//     one reviewer flaking while the pipeline mechanism itself is fine) and would make the alert
//     noisy enough to be tuned out, defeating its purpose.
//   - 3 catches a genuinely broken pipeline within three document() calls -- fast enough that
//     failed jobs do not silently accumulate before an operator finds out -- while still
//     tolerating one or two isolated blips without paging anyone.
//   - A "3 of the last 5" sliding-window alternative was rejected: it needs to durably persist a
//     WINDOW of past outcomes (not just one integer) to survive a process restart -- and
//     restart-survival is the entire reason this state is durable at all (see
//     dispatch-health-store.mjs's own docstring) -- which is additional state machinery for a
//     marginal precision gain when failures cluster in unbroken runs. Revisit toward a windowed
//     design if the failure pattern changes shape.
export const DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD = 3;

// Upper bound for consecutiveDispatchFailureAlertThreshold -- see the constructor validation
// below for why this exists (the value is interpolated into the alert's own reason text, which
// alert-store.mjs refuses if it contains a run of 5+ digits). 9999 is already far beyond any
// realistic tuning of this threshold in practice; the bound exists to fail a misconfiguration
// loudly at construction, not to constrain legitimate use.
export const MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD = 9999;

// 'YYYY-MM' from an ISO-8601 UTC timestamp -- mirrors lease-store.mjs's own utcDayKey() slicing
// convention (see that file) for the daily paid-job allowance's reset boundary, at month
// granularity instead of day granularity.
function utcMonthKey(isoTimestamp) {
  return isoTimestamp.slice(0, 7);
}

const SPEND_ALERT_REASON_PREFIX = 'openrouter monthly spend crossed';

/**
 * In-process-only stand-in for createDispatchHealthStore (dispatch-health-store.mjs), used as
 * createReviewEngine's default `dispatchHealthStore` so a caller that does not care about the
 * failure-rate alert (nearly every existing test in this codebase) is unaffected. Same
 * `recordOutcome({ succeeded, alertThreshold }) -> { consecutiveFailures, shouldAlert }` contract
 * as the real store; NOT restart-surviving, which is exactly why production wiring
 * (tools/openrouter-review-mcp-server.mjs) always passes the real durable one instead -- see that
 * store's own docstring for why an in-memory-only counter would defeat this alert's purpose
 * against the specific failure mode (host-process churn) it exists to catch.
 */
function createVolatileDispatchHealthStore() {
  let state = { consecutiveFailures: 0, alertedForCurrentStreak: false };
  return Object.freeze({
    // Mirrors the real store's own retry-on-failed-alert contract exactly (see
    // dispatch-health-store.mjs's recordOutcome/markAlerted docstrings): the alerted flag is
    // committed only by markAlerted(), never inline here, so a caller whose alert write fails
    // still gets `shouldAlert: true` again on the next consecutive failure.
    async recordOutcome({ succeeded, alertThreshold }) {
      if (succeeded) {
        state = { consecutiveFailures: 0, alertedForCurrentStreak: false };
        return { consecutiveFailures: 0, shouldAlert: false };
      }
      const consecutiveFailures = state.consecutiveFailures + 1;
      const shouldAlert = !state.alertedForCurrentStreak && consecutiveFailures >= alertThreshold;
      state = { ...state, consecutiveFailures };
      return { consecutiveFailures, shouldAlert };
    },
    async markAlerted() {
      state = { ...state, alertedForCurrentStreak: true };
    },
  });
}

/**
 * In-process-only stand-in for createPendingHealthVerdictStore (pending-health-verdict-store.mjs),
 * used as createReviewEngine's default `pendingHealthVerdictStore` so a caller that never triggers
 * ambiguousDispatching (nearly every existing test in this codebase) is unaffected. Same
 * `record`/`recall`/`remove`/`list`/`claim`/`recallClaim`/`releaseClaim` contract as the real
 * store (the claim methods mirror its exclusive per-job claim with an in-memory map: the first claim
 * for a jobId wins until it is released, a claim keeps an optional gradeAsOfMs exactly as given, and
 * recallClaim reports 'absent' or 'held', never 'unreadable', because nothing here can be
 * half-written); NOT restart-surviving, matching createVolatileDispatchHealthStore's own posture
 * above -- production wiring (tools/openrouter-review-mcp-server.mjs) always passes the real durable
 * one instead. Exported only so its claim contract can be tested directly; production code
 * reaches it only as createReviewEngine's default.
 */
export function createVolatilePendingHealthVerdictStore() {
  const records = new Map();
  const claims = new Map();
  function requireClaimJobId(jobId) {
    if (typeof jobId !== 'string' || !/^[a-f0-9]{64}$/.test(jobId)) {
      throw new TypeError('jobId must be a 64-character lowercase SHA-256 hex string');
    }
  }
  return Object.freeze({
    async record(entry) { records.set(entry.jobId, { ...entry }); },
    async recall({ jobId }) { return records.get(jobId) ?? null; },
    async remove({ jobId }) { records.delete(jobId); },
    async list() { return [...records.values()]; },
    async claim({ jobId, nowMs, gradeAsOfMs } = {}) {
      requireClaimJobId(jobId);
      if (!Number.isSafeInteger(nowMs)) throw new TypeError('nowMs must be a safe integer');
      if (gradeAsOfMs !== undefined && !Number.isSafeInteger(gradeAsOfMs)) {
        throw new TypeError('gradeAsOfMs, when given, must be a safe integer');
      }
      if (claims.has(jobId)) return { claimed: false };
      const claimId = randomUUID();
      const held = { jobId, claimId, pid: process.pid, claimedAtMs: nowMs };
      if (gradeAsOfMs !== undefined) held.gradeAsOfMs = gradeAsOfMs;
      claims.set(jobId, held);
      return { claimed: true, claimId };
    },
    async recallClaim({ jobId } = {}) {
      requireClaimJobId(jobId);
      const held = claims.get(jobId);
      return held === undefined ? { status: 'absent' } : { status: 'held', claim: { ...held } };
    },
    async releaseClaim({ jobId, claimId } = {}) {
      requireClaimJobId(jobId);
      if (claimId !== null && (typeof claimId !== 'string' || claimId.length === 0)) {
        throw new TypeError('claimId must be a non-empty string, or null to force-drop the claim');
      }
      const held = claims.get(jobId);
      if (held !== undefined && (claimId === null || held.claimId === claimId)) claims.delete(jobId);
    },
  });
}

/**
 * Deterministic per-(lease, reviewer, contract) job identity. Reusing this
 * exact ID for the exact same lease/reviewer/contract triple is what makes
 * `review()` idempotent: a repeated call finds the job the ledger already
 * knows about (via lease-store's own duplicate-ID rejection surfaced as a
 * lookup) instead of ever placing a second paid dispatch.
 */
function deriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return sha256(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`);
}

/**
 * Classifies a document's most recent lease (found by raw-source hash) for the repeat-authorization
 * ledger cross-check: 'SUCCEEDED' when every expected reviewer reconciled with recorded advisory
 * content and no halt, 'FAILED' when every expected reviewer reconciled without usable content, and
 * 'AMBIGUOUS' for anything else -- no lease, a missing preflight, a reviewer never dispatched, a job
 * still RESERVED, a genuine mix of success and failure, or any read error.
 *
 * A never-dispatched reviewer is AMBIGUOUS unconditionally, even after the lease expired: reading it
 * as FAILED would let a caller authorize, never dispatch, wait for expiry and repeat, collecting
 * unlimited free unsupervised grants. A genuine mix is AMBIGUOUS too: with one reviewer that
 * reliably succeeds and another that reliably halts, "not every reviewer succeeded" would make every
 * repeat an automatic grant, so FAILED requires every expected reviewer to have failed.
 */
export async function resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 } = {}) {
  try {
    const lease = await leaseStore.getMostRecentLeaseForRawSource(rawSourceSha256);
    if (lease === null) return 'AMBIGUOUS';

    const preflight = await leaseStore.getPreflight(lease.preflightIds[0]);
    if (!preflight) return 'AMBIGUOUS';

    let expectedReviewers;
    try {
      expectedReviewers = reviewersFromItemMaxima(preflight.itemMaxima);
    } catch {
      return 'AMBIGUOUS';
    }

    let anySucceeded = false;
    let anyFailed = false;
    for (const reviewer of expectedReviewers) {
      const jobId = deriveJobId(lease.id, reviewer.reviewerId, lease.reviewContractSha256);
      const job = await leaseStore.getJob(jobId);

      if (job === null) return 'AMBIGUOUS'; // never dispatched -- never evidence of anything, see docstring
      if (job.state === 'RESERVED') return 'AMBIGUOUS'; // may genuinely still be in flight

      const succeeded = job.haltReason === undefined && (await resultStore.recall({ jobId })) !== null;
      if (succeeded) anySucceeded = true; else anyFailed = true;
    }
    if (anySucceeded && anyFailed) return 'AMBIGUOUS'; // a genuine mix is not proof the review failed -- see docstring
    return anySucceeded ? 'SUCCEEDED' : 'FAILED';
  } catch {
    return 'AMBIGUOUS';
  }
}

/**
 * Shared classifier for review()'s own in-loop existingJob fallback and result()'s ledger-only
 * fallback -- kept as one function so a fix to one can never drift from the other. Surfaces the
 * ledger job's OWN persisted costKind (KNOWN, UNKNOWN_WORST_CASE_CHARGED, or
 * ZERO_ON_TRANSPORT_FAILURE -- see lease-store.mjs's reconcile()) when one exists;
 * RECOVERED_STATUS_ONLY only when there is genuinely no cost information to report (no job at all,
 * or a job still RESERVED and never reconciled).
 *
 * Without this, a worst-case (or proven-zero) charge recovered from nothing but the bare ledger (a
 * fresh process, or review()/result() re-entered after this same process lost its in-memory
 * advisoryCache/resultStore write) would be relabeled RECOVERED_STATUS_ONLY -- indistinguishable
 * from "we have no idea," even though the ledger job itself already records which kind of figure
 * it is.
 */
export function costKindFromLedgerJob(job) {
  return job && job.costKind ? job.costKind : 'RECOVERED_STATUS_ONLY';
}

/**
 * Single choke point for recognizing lease-store.mjs's assertCurrentlyOwnsProcess() failure
 * ("caller does not currently hold process ownership of this data root") -- the one piece of
 * string/regex matching every PROCESS_OWNERSHIP_LOST classification site needs. It is used at three
 * call sites (translateConsumeError, finalizeReviewOutcome's close-error handler,
 * grantLeaseFromOutcome's createLease catch); inlining the regex at each would invite a new error
 * type being silently misclassified the next time one copy is edited without the other two.
 * Centralized here so a future change to the exact wording (or to what counts as this failure) only
 * ever needs one edit.
 *
 * Tolerant of a missing/malformed error the same way every other predicate in this file is: `null`,
 * a non-Error, or an Error with a non-string `.message` all safely read as `false`, never throw.
 */
function isProcessOwnershipLostError(error) {
  return typeof error?.message === 'string' && /does not currently hold process ownership/i.test(error.message);
}

function translateConsumeError(error) {
  const message = error?.message ?? 'lease reservation failed';
  // Checked FIRST, ahead of every other branch: lease-store.mjs's assertCurrentlyOwnsProcess()
  // throws this exact message ("caller does not currently hold process ownership of this data
  // root") when consume()'s own inline ownership fence rejects a stale acquisitionId. It does not
  // actually collide with any pattern below (no "cap"/"closed"/"expired"/"contract"/"missing"
  // substring), so without this branch it would silently fall through to the generic LEASE_MISSING
  // catch-all -- a materially false diagnosis, since this failure has nothing to do with the lease
  // itself: it means a second process has since raced/superseded this one as the ledger's owner.
  // See PROCESS_OWNERSHIP_LOST's own comment in ERROR_CODES above for why this must stay distinct.
  if (isProcessOwnershipLostError(error)) return new ReviewEngineError('PROCESS_OWNERSHIP_LOST', message);
  // A data-root lock timeout during reservation is transient contention, not a missing lease -- without this it fell through to the LEASE_MISSING catch-all below.
  if (isLedgerBusyError(error)) return ledgerBusyError();
  // Checked before /cap/i below (though the two patterns don't actually collide -- "daily
  // dispatch allowance exhausted" contains no substring "cap", verified directly -- without
  // this check the message would instead fall through to the generic LEASE_MISSING catch-all).
  // This condition is distinct from a lease cap (it is an installation-wide daily rate limit, not
  // this lease running out of budget) and a caller needs to tell them apart -- one clears at
  // the next UTC midnight, the other never does.
  if (/daily dispatch allowance/i.test(message)) return new ReviewEngineError('DAILY_ALLOWANCE_EXCEEDED', message);
  if (/cap/i.test(message)) return new ReviewEngineError('LEASE_CAP_EXCEEDED', message);
  if (/closed/i.test(message)) return new ReviewEngineError('LEASE_CLOSED', message);
  if (/expired/i.test(message)) return new ReviewEngineError('LEASE_EXPIRED', message);
  if (/contract/i.test(message)) return new ReviewEngineError('CONTRACT_CHANGED', message);
  if (/missing/i.test(message)) return new ReviewEngineError('LEASE_MISSING', message);
  return new ReviewEngineError('LEASE_MISSING', message);
}

function decodeEnvelopeBody(dispatchOutcome) {
  const envelope = JSON.parse(dispatchOutcome.envelopeJsonText);
  const bodyText = Buffer.from(envelope.bodyBase64, 'base64').toString('utf8');
  return JSON.parse(bodyText);
}

/**
 * The envelope's own HTTP status, or null if it cannot be read. Separate from decodeEnvelopeBody()
 * above, which decodes only the body and discards the status -- that was fine while every status
 * was treated identically, and stopped being fine once a 4xx needed distinguishing from a 5xx.
 * Never throws: a caller in a cost-classification path must be able to fall through to the
 * conservative worst-case charge rather than take a second exception.
 */
function decodeEnvelopeHttpStatus(dispatchOutcome) {
  try {
    const { httpStatus } = JSON.parse(dispatchOutcome.envelopeJsonText);
    return Number.isSafeInteger(httpStatus) ? httpStatus : null;
  } catch {
    return null;
  }
}

/**
 * HTTP statuses on which the provider provably refused the request BEFORE running any inference,
 * so real spend is zero. Such a response (for example a 402 for an exhausted prepaid balance, with
 * no routed provider and zero tokens) is a RECEIVED response, so it never reaches the FailureKind
 * zero-cost list and would otherwise be charged the full reservation as UNKNOWN_WORST_CASE_CHARGED.
 *
 * Deliberately EXCLUDES 5xx, 408, and anything else where inference may already have started and
 * been billed -- assuming zero cost there would UNDER-record real spend, which is the more dangerous
 * direction (the same reason RESPONSE_READ_FAILED stays worst-case-charged below). 400 is also
 * excluded: unlike the six below it is not unambiguously pre-inference.
 */
const ZERO_COST_HTTP_REJECTION_STATUSES = new Set([401, 402, 403, 404, 422, 429]);

/**
 * True only for a response that is provably a pre-inference refusal. The status alone is NOT
 * sufficient: a provider that bills before
 * returning a 4xx would otherwise have its real spend silently written off, so a body showing any
 * evidence of generation -- a routed provider, or any non-zero token count -- disqualifies it and
 * falls back to the conservative worst-case charge.
 */
function isProvablyZeroCostRejection(dispatchOutcome, parsedBody) {
  const httpStatus = decodeEnvelopeHttpStatus(dispatchOutcome);
  if (httpStatus === null || !ZERO_COST_HTTP_REJECTION_STATUSES.has(httpStatus)) return false;
  if (!parsedBody || typeof parsedBody !== 'object') return false;
  if (parsedBody.provider) return false;
  const usage = parsedBody.usage;
  if (usage && typeof usage === 'object') {
    for (const key of ['completion_tokens', 'prompt_tokens', 'total_tokens', 'reasoning_tokens']) {
      const value = usage[key];
      if (typeof value === 'number' && value > 0) return false;
    }
  }
  return true;
}

// Every openrouter-review-dispatch.ps1 FailureKind that provably occurs either before any network
// I/O at all (INVALID_DEADLINE, DEADLINE_EXCEEDED, REQUEST_FILE_INVALID, CREDENTIAL_MISSING,
// CREDENTIAL_DECRYPT_FAILED), or before OpenRouter's HTTP response was ever received (NETWORK_ERROR
// covers a failed request-body write and a failed GetResponse() call; TIMEOUT is GetResponse()
// itself timing out) -- so real cost is provably zero for every one of these, not merely assumed.
// Deliberately EXCLUDES two FailureKinds that must stay worst-case-charged, so not every `kind:
// 'FAILURE'` outcome is zero-cost: (1) RESPONSE_READ_FAILED -- by the time this fires,
// $webResponse.GetResponse() has ALREADY succeeded (status/headers received), and since every
// reviewer request sets `stream: false` (reviewer-registry.mjs), a successful GetResponse() on a
// non-streaming completions call means the full generation was very likely already produced --
// and, per standard non-streaming-API billing practice, probably already billed -- server-side
// before this LOCAL body-read failure ever happened; folding it into the same zero-cost bucket as a
// response that was never received at all would risk silently under-recording real spend, the
// more dangerous direction. (2) INTERNAL_ERROR -- a generic
// top-level catch-all that could in principle fire at any point in the dispatch flow, including
// after a successful response; its timing cannot be proven safe the way every kind above can.
const ZERO_COST_TRANSPORT_FAILURE_KINDS = new Set([
  'INVALID_DEADLINE', 'DEADLINE_EXCEEDED', 'REQUEST_FILE_INVALID',
  'CREDENTIAL_MISSING', 'CREDENTIAL_DECRYPT_FAILED', 'NETWORK_ERROR', 'TIMEOUT',
]);

// Tolerant of a missing/malformed envelope (returns null rather than throwing) -- an
// unrecognized or absent failureKind falls through to the worst-case-charged default below, the
// same fail-closed direction every other unrecognized/ambiguous case in this module already takes.
function decodeFailureKind(dispatchOutcome) {
  try {
    return JSON.parse(dispatchOutcome.envelopeJsonText)?.failureKind ?? null;
  } catch {
    return null;
  }
}

/**
 * Returns the text to validate as a reviewer's advisory JSON. A 'prompted_json' reviewer (one
 * without provider-enforced strict-schema output) may wrap its JSON in markdown fences or leading
 * prose, so its text goes through stripJsonFraming(); the strict-schema path is returned unchanged.
 * A non-string value passes through untouched so the validator reports it.
 */
export function selectContentTextForValidation(contentText, reviewer) {
  if (typeof contentText !== 'string') return contentText;
  return reviewer.outputMode === 'prompted_json' ? stripJsonFraming(contentText) : contentText;
}

// OpenRouter's normalized completion field controls acceptance; native provider metadata does not.
export function isAcceptedReviewCompletion(body) {
  return body?.choices?.[0]?.finish_reason === 'stop';
}

/**
 * Reserves each candidate reviewer on the lease, in order, stopping at the first condition that
 * prevents a safe reservation: the lease has expired, the same reviewer already has an in-flight
 * (RESERVED) job for this exact review contract under another lease, or a store call failed. Never
 * rejects for those conditions: it returns the reviewers reserved so far plus the stop reason, so the
 * caller never loses track of reservations already made.
 */
export async function reserveReviewers({
  leaseStore, clock, leaseId, leaseExpiresAtMs, reviewContractSha256, candidates, ownerToken,
} = {}) {
  // Validated before the loop and before any store call: a token that is not a real
  // snapshot is a programming error, never an ORDINARY_FAILURE for the loop's own catch to absorb.
  requireOwnerToken(ownerToken);
  const reservedReviewerIds = [];
  for (const candidate of candidates) {
    if (leaseExpiresAtMs <= Number(clock())) {
      return {
        reservedReviewerIds,
        stopReason: 'LEASE_EXPIRED',
        ordinaryFailureError: null,
        stopDetail: { reviewerId: candidate.reviewerId, jobId: null },
      };
    }

    // Checks 2 (this re-check) and 3 (consume(), below) are both real, lock-serialized store I/O
    // (lease-store.mjs) that can throw under I/O error or lock contention -- both share this one
    // try/catch so either failure routes through the same ORDINARY_FAILURE stop rather than
    // rejecting reserveReviewers() itself and losing everything already in reservedReviewerIds.
    try {
      // eslint-disable-next-line no-await-in-loop
      const priorJobs = await leaseStore.findJobsForReviewerContract(reviewContractSha256, candidate.reviewerId);
      const priorReserved = priorJobs.find((priorJob) => priorJob.state === 'RESERVED');
      if (priorReserved) {
        return {
          reservedReviewerIds,
          stopReason: 'DUPLICATE_IN_PROGRESS',
          ordinaryFailureError: null,
          stopDetail: { reviewerId: candidate.reviewerId, jobId: priorReserved.id },
        };
      }

      // eslint-disable-next-line no-await-in-loop
      await leaseStore.consume(leaseId, reviewContractSha256, {
        reservationUsd: candidate.reservationUsd,
        jobId: candidate.jobId,
        countsTowardDailyAllowance: candidate.countsTowardDailyAllowance,
        reviewerId: candidate.reviewerId,
        acquisitionId: ownerToken.acquisitionId,
      });
    } catch (error) {
      return {
        reservedReviewerIds,
        stopReason: 'ORDINARY_FAILURE',
        ordinaryFailureError: error,
        stopDetail: { reviewerId: candidate.reviewerId, jobId: candidate.jobId },
      };
    }

    reservedReviewerIds.push(candidate.reviewerId);
  }

  return { reservedReviewerIds, stopReason: null, ordinaryFailureError: null, stopDetail: null };
}

/**
 * The pure decision half of Step 5, kept separate from the I/O half below so the close-guard in
 * finalizeReviewOutcome has something well-defined to guard AGAINST: every branch decision happens
 * here, before any ledger write, and a throw in here can never skip the close.
 *
 * Priority order is load-bearing. `stopReason` is
 * checked FIRST, unconditionally, before any "did every dispatched reviewer pass" evaluation --
 * otherwise a Step-2 stop that fired before reserving anyone (so Step 3 dispatched nothing, or only
 * already-resolved reviewers that happened to pass) would vacuously read as PASSED and silently
 * drop the real stop condition.
 *
 * Not exported: finalizeReviewOutcome is the tested surface, and every branch here is reachable
 * through it.
 */
function decideFinalReviewOutcome({ stopReason, stopDetail, reviewers, orderedReviewerIds }) {
  // MONEY SAFETY, checked FIRST and applied to every branch below, not just one: never close the
  // lease while any reviewer's own last-known ledger state is still RESERVED. Guarding only the
  // branch below that fires for stopReason null/'ORDINARY_FAILURE' is not enough: if the
  // LEASE_EXPIRED and DUPLICATE_IN_PROGRESS branches returned their own fixed closeCode
  // unconditionally, the same orphaning bug would be reachable through a different stopReason,
  // because Step 1/Step 2 can queue an EARLIER reviewer onto
  // needsRedispatch/ambiguousDispatching (a real pre-existing RESERVED job) before a LATER reviewer
  // in the same pass trips LEASE_EXPIRED or DUPLICATE_IN_PROGRESS; Step 3 still dispatches the
  // earlier reviewer regardless (by design, see Step 1's own batchStop-handling comment); if that
  // dispatch then rejects and its own recovery also can't prove resolution, it stays genuinely
  // RESERVED while stopReason names the LATER, unrelated reviewer's own stop condition -- decoupled
  // from which specific reviewer is actually still reserved. Computing this once, up front, and
  // applying it uniformly closes that seam structurally instead of needing a matching guard added
  // to every branch by hand. Closing anyway would make that reservation permanently unrecoverable:
  // sweepOrphanedLeases() only ever touches ACTIVE leases (lease-store.mjs:420) and review() refuses
  // to re-enter a non-ACTIVE lease at all -- exactly the orphaned-reservation failure class this
  // whole design exists to eliminate. Leaving the lease ACTIVE keeps it eligible for both of those
  // existing recovery paths; the caller still gets a real HALTED result either way, just without a
  // false "this is closed and done" signal.
  const anyStillReserved = orderedReviewerIds.some(
    (reviewerId) => reviewers[reviewerId] !== undefined && reviewers[reviewerId].state === 'RESERVED',
  );

  if (stopReason === 'LEASE_EXPIRED') {
    return {
      state: 'HALTED',
      closeCode: anyStillReserved ? null : 'LEASE_EXPIRED',
      error: {
        code: 'LEASE_EXPIRED',
        message: stopDetail && stopDetail.reviewerId
          ? `the lease expired before reviewer ${stopDetail.reviewerId} could be reserved`
          : 'the lease expired before every reviewer could be reserved',
      },
    };
  }

  if (stopReason === 'DUPLICATE_IN_PROGRESS') {
    return {
      state: 'HALTED',
      closeCode: anyStillReserved ? null : 'DUPLICATE_DISPATCH_IN_PROGRESS',
      error: {
        code: 'DUPLICATE_DISPATCH_IN_PROGRESS',
        message: stopDetail && stopDetail.reviewerId
          ? `reviewer ${stopDetail.reviewerId} already has an in-flight dispatch (job ${stopDetail.jobId}) under a different lease for this exact document; refusing to create a duplicate paid dispatch`
          : 'a reviewer already has an in-flight dispatch under a different lease for this exact document; refusing to create a duplicate paid dispatch',
      },
    };
  }

  // stopReason is null or 'ORDINARY_FAILURE': both evaluate the dispatched set the ordinary way.
  // 'ORDINARY_FAILURE' additionally throws afterwards, in finalizeReviewOutcome -- side effects
  // first, then the throw, matching today's contract for a mid-loop consume() failure.
  //
  // "First halted reviewer" is computed by scanning the profile's own fixed order, never by
  // Promise.allSettled's settle order, so the reported top-level reason cannot depend on timing.
  const firstHaltedReviewerId = orderedReviewerIds.find(
    (reviewerId) => reviewers[reviewerId] !== undefined && reviewers[reviewerId].error !== undefined,
  );
  if (firstHaltedReviewerId === undefined) return { state: 'PASSED', closeCode: null, error: null };

  const failure = reviewers[firstHaltedReviewerId].error;
  return {
    state: 'HALTED',
    closeCode: anyStillReserved ? null : failure.code,
    error: { code: failure.code, message: failure.message },
  };
}

/**
 * Applies decideFinalReviewOutcome()'s decision: closes the lease with the decided close code (when
 * there is one), always runs the spend check, and then returns the PASSED/HALTED result -- or throws,
 * after those side effects, for an ownership loss on close, a decision error, or an ORDINARY_FAILURE
 * stop.
 */
export async function finalizeReviewOutcome({
  leaseStore, checkSpendAndMaybeAlert, leaseId, preflightId, reviewContractSha256,
  reviewers, orderedReviewerIds, ownerToken, stopReason = null, stopDetail = null, ordinaryFailureError = null,
} = {}) {
  // Validated first, before the decision, the close and the spend check: a token that is
  // not a real snapshot is a programming error, and nothing below may run under it.
  requireOwnerToken(ownerToken);
  let decision;
  let decisionError = null;
  try {
    decision = decideFinalReviewOutcome({ stopReason, stopDetail, reviewers, orderedReviewerIds });
  } catch (error) {
    decisionError = error;
    decision = { state: 'HALTED', closeCode: 'DISPATCH_UNKNOWN', error: null };
  }

  // A close() on a business-logic-verified-ACTIVE lease can still fail:
  // lease-store.mjs's assertCurrentlyOwnsProcess() rejects this call outright if
  // ownerToken.acquisitionId no longer matches the ledger's live owner (a second server instance
  // has since raced/superseded this one). Left unhandled, that would escape as a
  // raw, non-ReviewEngineError Error -- toolErrorFromEngineError (openrouter-review-mcp-server.mjs)
  // explicitly rethrows anything that isn't a ReviewEngineError rather than formatting a clean tool
  // response, so an MCP caller would see an opaque crash instead of a diagnosable code. Caught here
  // and reclassified specifically for the ownership case; any OTHER close() failure (e.g. a genuine
  // race closing an already-non-ACTIVE lease) keeps escaping unchanged --
  // that is an existing, separately-accepted residual (see recoverStaleLease()'s own "lease is
  // closed" handling), not something this handler covers.
  let closeError = null;
  try {
    if (decision.closeCode !== null) await leaseStore.close(leaseId, decision.closeCode, { acquisitionId: ownerToken.acquisitionId });
  } catch (error) {
    closeError = error;
  } finally {
    await checkSpendAndMaybeAlert();
  }

  if (closeError !== null) {
    if (isProcessOwnershipLostError(closeError)) {
      throw new ReviewEngineError('PROCESS_OWNERSHIP_LOST', closeError.message);
    }
    throw closeError;
  }

  if (decisionError !== null) throw decisionError;
  if (stopReason === 'ORDINARY_FAILURE') throw translateConsumeError(ordinaryFailureError);

  return decision.state === 'PASSED'
    ? { state: 'PASSED', leaseId, preflightId, reviewContractSha256, reviewers }
    : { state: 'HALTED', leaseId, preflightId, reviewContractSha256, reviewers, error: decision.error };
}

/**
 * Creates the ordered-dispatch, fail-closed review engine.
 *
 * `leaseStore` is the ledger (createLeaseStore); `approvalAdapter`
 * exposes `authorize(request, { leaseExpiresAt }) -> { outcome, nonce }`;
 * `dispatchAdapter` exposes `dispatch({ requestBytes, jobId, reviewerId }) ->
 * { kind: 'RESPONSE' | 'FAILURE', envelopeJsonText }`. Tests must supply fake
 * adapters for all three -- this module never shells out to PowerShell
 * itself and never reads a credential.
 *
 * Preflight identity is verified against a redacted, expiring in-process
 * cache populated by `preflight()` -- never against raw source or request
 * bodies, and never against anything the caller could forge, because the
 * ledger independently re-validates the bound contract at `consume()` time.
 *
 * Losing this cache to a process restart is NOT safe by construction.
 * Running preflight() again only helps a caller who can mint a *new*
 * preflightId and knows to do so; a caller that already ran
 * authorizeWorkflow() successfully is durably bound to the *original*
 * preflightId's reviewContractSha256 via the lease the ledger already
 * created, and authorizeWorkflow()'s own human-approval step is unavoidably
 * slow (a person reading and typing an exact phrase) -- long enough for the
 * host to restart the local stdio MCP server process before the next
 * `document()` call arrives. `getCachedPreflight()` below therefore falls back to the durable
 * `leaseStore.getPreflight()` record (reconstructing the `reviewers` list
 * from its `itemMaxima` via the fixed reviewer registry) plus the durable
 * `preflightContextStore` for the one field the ledger's own redaction rules
 * keep out of it (`reviewContext`, free-form text, never a hash) -- so the
 * ORIGINAL preflightId keeps working across a restart, not just a fresh one.
 *
 * `review()` recomputes the review contract from fresh inputs every call:
 * `source_text`/`source_path` are always re-supplied and re-hashed, and
 * `reviewContext` may optionally be re-supplied the same way -- passing the
 * current context lets drift since `preflight()` be detected as
 * CONTRACT_CHANGED, symmetrically with source drift; omitting it falls back
 * to the cached (already-trusted) context from `preflight()`.
 *
 * A RESERVED-but-never-reconciled job is not necessarily of unknowable
 * outcome, so it is not simply charged its worst-case cost with no content:
 * `dispatchAdapter`'s real implementation shells out to a PowerShell script
 * that can itself complete a real OpenRouter call and still lose the
 * response, if the Node process that was going to read its stdout gets
 * replaced first. `dispatchOutcomeStore`
 * (see dispatch-outcome-store.mjs) is the read side of a durable capture that
 * script writes the instant it has ANY outcome, before ever returning it
 * on stdout; `review()`'s existingJob recovery consults it before giving up,
 * running a recovered outcome through the exact same validation pipeline
 * (`processDispatchOutcome`) a live one always used.
 */
export function createReviewEngine({
  leaseStore,
  ownerLock,
  approvalAdapter,
  dispatchAdapter,
  resultStore,
  preflightContextStore,
  dispatchOutcomeStore,
  scrubEngine,
  scrubMappingStore,
  clock = () => Date.now(),
  sourcePolicy,
  preflightPolicy,
  preflightTtlMs = 15 * 60 * 1000,
  // Grace window applied before review()'s expired-lease recovery path (see
  // its own comment below) or recoverOrphanedLeases() ever treats a stale
  // RESERVED job as safe to force-close. Must clear the dispatch adapter's
  // own execFile backstop (which can fire up to ~30s past a lease's
  // expiresAt in the worst case -- see createDispatchAdapter's
  // effectiveTimeoutMs comment in tools/openrouter-review-mcp-server.mjs)
  // with real margin, so recovery never races a dispatch that is still
  // legitimately about to reconcile on its own. 2 minutes is 4x that 30s
  // worst case.
  orphanSweepGraceMs = 2 * 60 * 1000,
  installationHardMaximumUsd,
  autonomousAuthorization = false,
  alertStore = { async record() {}, async list() { return []; } },
  repeatAuthorizationJudge,
  // Best-effort, read-only probe of OpenRouter's own live spend-cap status. Defaults to
  // always-unknown so a caller that does not care about the 75%-cap alert
  // (nearly every existing test in this codebase) never needs to supply one -- an unknown status
  // simply skips the alert, exactly as a real probe failure would (see checkSpendAndMaybeAlert
  // below). Production wiring passes a real adapter shelling out to
  // tools/openrouter-review-key-status.ps1 (see createKeyStatusProbeAdapter in
  // tools/openrouter-review-mcp-server.mjs).
  keyStatusProbe = { async check() { return { limit: null, limitRemaining: null, limitReset: null }; } },
  spendAlertThresholdFraction = DEFAULT_SPEND_ALERT_THRESHOLD_FRACTION,
  // Durable consecutive-dispatch-failure counter. Defaults to a
  // volatile in-process implementation with the SAME contract as the real
  // createDispatchHealthStore (see dispatch-health-store.mjs) -- matching alertStore's own
  // soft-default posture above -- so a caller that does not care about this alert is unaffected.
  // Production wiring passes a real, restart-surviving createDispatchHealthStore({ dataRoot }).
  dispatchHealthStore = createVolatileDispatchHealthStore(),
  consecutiveDispatchFailureAlertThreshold = DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD,
  // Durable, per-job store for a dispatch-health verdict DEFERRED by ambiguousDispatching until the
  // real (often delayed) dispatch outcome can be checked, instead of recording a failure at once.
  // Defaults to a volatile in-process implementation with the same contract as the real
  // createPendingHealthVerdictStore -- matching dispatchHealthStore's own soft-default posture
  // above -- so a caller that never triggers ambiguousDispatching is unaffected.
  pendingHealthVerdictStore = createVolatilePendingHealthVerdictStore(),
  // Grace window before resolvePendingHealthVerdicts() will resolve a pending record -- default 6
  // minutes, above the few-minute delay with which a real dispatch outcome can still land after
  // the dispatching call has given up.
  healthVerdictGraceMs = 6 * 60 * 1000,
  // Backstop: a pending record whose notBeforeMs is more than this far in the past is resolved as
  // succeeded:false WITHOUT checking dispatchOutcomeStore at all, so a systemically broken sweep can
  // never suppress the failure signal forever.
  healthVerdictBackstopMs = 60 * 60 * 1000,
  // On-demand ownership arming: the budget and the base poll interval for
  // the on-demand arm the ownership coordinator performs the first time an owner-sensitive call
  // runs. The defaults are the coordinator's own exported constants, never re-typed numbers.
  armTimeoutMs = DEFAULT_ARM_TIMEOUT_MS,
  armLockRetryMs = DEFAULT_ARM_LOCK_RETRY_MS,
  // Injected sleep and monotonic time for the bounded reconcile retry.
  // Tests can advance monotonic time without waiting; wall-clock changes cannot extend the budget.
  sleep = defaultSleep,
  monotonicNow = () => performance.now(),
  retainOwnershipUntilShutdown = false,
  managedExecution,
} = {}) {
  const validatedManagedExecution = validateManagedExecutionBundle(managedExecution);
  if (retainOwnershipUntilShutdown === true && validatedManagedExecution === null) {
    throw new TypeError('retainOwnershipUntilShutdown requires managedExecution');
  }
  requirePlainObject(leaseStore, 'leaseStore');
  // A hard constructor dependency, validated the same way leaseStore/resultStore/etc already are.
  // An acquisitionId (not a bare isOwner() flag alone) is what every owner-sensitive lease-store
  // write below re-verifies against the ledger's own live state. The dependency is on the handle
  // OBJECT only: it may arrive unarmed (see the note on the acquisitionId check just below), and
  // each fenced write re-verifies the frozen ownerToken snapshot taken right after the arm
  // (snapshotOwnerToken), never a live ownerLock read, so a later supersession still fails the
  // ledger fence closed.
  requirePlainObject(ownerLock, 'ownerLock');
  requireFunction(ownerLock.isOwner, 'ownerLock.isOwner');
  // Ownership is released after each completed operation, so every engine handle must be reusable even
  // when it happens to arrive already armed. Accepting a pre-armed handle without arm() would let
  // the first call succeed and leave every later owner-sensitive call unable to re-acquire.
  requireFunction(ownerLock.arm, 'ownerLock.arm');
  requireFunction(ownerLock.release, 'ownerLock.release');
  // Production hands this engine an UNARMED handle, whose acquisitionId reads null until the
  // ownership coordinator arms it on the first owner-sensitive call. null is therefore accepted; ''
  // and undefined still throw, so a malformed handle still fails here. arm() is required above even
  // for a handle that arrives armed, because its first completed operation releases non-finally and
  // a later operation must re-acquire through it.
  if (ownerLock.acquisitionId !== null) requireNonEmptyString(ownerLock.acquisitionId, 'ownerLock.acquisitionId');
  requirePlainObject(approvalAdapter, 'approvalAdapter');
  requireFunction(approvalAdapter.authorize, 'approvalAdapter.authorize');
  requirePlainObject(dispatchAdapter, 'dispatchAdapter');
  requireFunction(dispatchAdapter.dispatch, 'dispatchAdapter.dispatch');
  requirePlainObject(resultStore, 'resultStore');
  requireFunction(resultStore.record, 'resultStore.record');
  requireFunction(resultStore.recall, 'resultStore.recall');
  if (validatedManagedExecution !== null) requireFunction(resultStore.recallManaged, 'resultStore.recallManaged');
  requirePlainObject(preflightContextStore, 'preflightContextStore');
  requireFunction(preflightContextStore.record, 'preflightContextStore.record');
  requireFunction(preflightContextStore.recall, 'preflightContextStore.recall');
  requirePlainObject(dispatchOutcomeStore, 'dispatchOutcomeStore');
  requireFunction(dispatchOutcomeStore.recall, 'dispatchOutcomeStore.recall');
  requirePlainObject(scrubEngine, 'scrubEngine');
  requireFunction(scrubEngine.scrub, 'scrubEngine.scrub');
  requireFunction(scrubEngine.desubstitute, 'scrubEngine.desubstitute');
  requirePlainObject(scrubMappingStore, 'scrubMappingStore');
  requireFunction(scrubMappingStore.record, 'scrubMappingStore.record');
  requireFunction(scrubMappingStore.recall, 'scrubMappingStore.recall');
  requireFunction(scrubMappingStore.deleteMapping, 'scrubMappingStore.deleteMapping');
  requireFunction(clock, 'clock');
  requireFunction(sleep, 'sleep');
  requireFunction(monotonicNow, 'monotonicNow');
  requirePlainObject(sourcePolicy, 'sourcePolicy');
  requirePlainObject(preflightPolicy, 'preflightPolicy');
  if (!Number.isSafeInteger(preflightTtlMs) || preflightTtlMs <= 0) throw new TypeError('preflightTtlMs must be a positive safe integer');
  if (!Number.isSafeInteger(orphanSweepGraceMs) || orphanSweepGraceMs < 0) throw new TypeError('orphanSweepGraceMs must be a non-negative safe integer');
  if (!Number.isSafeInteger(armTimeoutMs) || armTimeoutMs <= 0) throw new TypeError('armTimeoutMs must be a positive safe integer');
  if (!Number.isSafeInteger(armLockRetryMs) || armLockRetryMs <= 0) throw new TypeError('armLockRetryMs must be a positive safe integer');
  if (typeof installationHardMaximumUsd !== 'number' || !Number.isFinite(installationHardMaximumUsd) || installationHardMaximumUsd < 0) {
    throw new TypeError('installationHardMaximumUsd must be a finite non-negative USD amount');
  }
  // Required and strictly validated like leaseStore/approvalAdapter/dispatchAdapter above -- not
  // given a soft no-op default the way alertStore was, because this collaborator gates an actual
  // spending decision (whether to allow a repeat autonomous authorization), not a best-effort
  // audit record. See authorizeWorkflow's repeat-authorization branch below.
  requirePlainObject(repeatAuthorizationJudge, 'repeatAuthorizationJudge');
  requireFunction(repeatAuthorizationJudge.judge, 'repeatAuthorizationJudge.judge');
  requirePlainObject(keyStatusProbe, 'keyStatusProbe');
  requireFunction(keyStatusProbe.check, 'keyStatusProbe.check');
  if (
    typeof spendAlertThresholdFraction !== 'number' || !Number.isFinite(spendAlertThresholdFraction)
    || spendAlertThresholdFraction <= 0 || spendAlertThresholdFraction > 1
  ) {
    throw new TypeError('spendAlertThresholdFraction must be a finite number in (0, 1]');
  }
  requirePlainObject(dispatchHealthStore, 'dispatchHealthStore');
  requireFunction(dispatchHealthStore.recordOutcome, 'dispatchHealthStore.recordOutcome');
  requireFunction(dispatchHealthStore.markAlerted, 'dispatchHealthStore.markAlerted');
  // Validated the same way dispatchHealthStore is above: healthVerdictGraceMs and
  // healthVerdictBackstopMs feed real arithmetic, so a bad value must fail loudly here rather than
  // silently miscompute later.
  requirePlainObject(pendingHealthVerdictStore, 'pendingHealthVerdictStore');
  requireFunction(pendingHealthVerdictStore.record, 'pendingHealthVerdictStore.record');
  requireFunction(pendingHealthVerdictStore.recall, 'pendingHealthVerdictStore.recall');
  requireFunction(pendingHealthVerdictStore.remove, 'pendingHealthVerdictStore.remove');
  requireFunction(pendingHealthVerdictStore.list, 'pendingHealthVerdictStore.list');
  // The pending-health sweep's per-job claim. Required rather than optional, so a
  // store without it fails loudly here instead of silently reopening the cross-process double count.
  requireFunction(pendingHealthVerdictStore.claim, 'pendingHealthVerdictStore.claim');
  requireFunction(pendingHealthVerdictStore.recallClaim, 'pendingHealthVerdictStore.recallClaim');
  requireFunction(pendingHealthVerdictStore.releaseClaim, 'pendingHealthVerdictStore.releaseClaim');
  if (!Number.isSafeInteger(healthVerdictGraceMs) || healthVerdictGraceMs <= 0) {
    throw new TypeError('healthVerdictGraceMs must be a positive safe integer');
  }
  if (!Number.isSafeInteger(healthVerdictBackstopMs) || healthVerdictBackstopMs <= 0) {
    throw new TypeError('healthVerdictBackstopMs must be a positive safe integer');
  }
  // Upper-bounded at 4 digits (not just "positive"), matching MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD
  // above: the threshold is interpolated directly
  // into the critical alert's own reason text (see recordDispatchHealthOutcome), and
  // alert-store.mjs's own downstream-safety guard refuses any reason containing a run of 5+
  // digits. An operator typo producing a 5+ digit threshold would therefore make the alert write
  // fail EVERY time, deterministically -- this bound makes that class of misconfiguration fail
  // loudly at construction instead, well before it could ever reach a real alert attempt.
  if (
    !Number.isSafeInteger(consecutiveDispatchFailureAlertThreshold)
    || consecutiveDispatchFailureAlertThreshold <= 0
    || consecutiveDispatchFailureAlertThreshold > MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD
  ) {
    throw new TypeError(`consecutiveDispatchFailureAlertThreshold must be a positive safe integer no greater than ${MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD}`);
  }

  /**
   * Best-effort, once-per-billing-period proactive spend alert. Wired into exactly ONE place:
   * finalizeReviewOutcome()'s own finally block, which every terminal outcome of a review() call
   * that got as far as the reserve/dispatch phases funnels through -- PASSED, HALTED, the
   * ORDINARY_FAILURE throw, a rethrown decision bug, and a failing close() alike. So a
   * multi-reviewer batch checks the live probe exactly ONCE per document()/review() call however
   * many of its reviewers halted. It is deliberately NOT called from haltAndClose: reviewers
   * dispatch concurrently and several can halt independently, so a per-halt call would fire once
   * per halted reviewer -- N+1 probe processes for a batch of N.
   *
   * review() still has exits this function is intentionally NOT wired into (the pre-dispatch
   * orphan-recovery return, and every guard-clause thrown ReviewEngineError) -- none of those
   * represent a NEW dispatch attempt that could have moved the live spend figure. Contrast with
   * recordDispatchHealthOutcome below, which IS also wired into the orphan-recovery paths, because
   * those genuinely are the failure signal that alert cares about even though they involve no new
   * dispatch.
   *
   * Step 1's batch-wide stop (batchStop) is DIFFERENT from those two: it routes through
   * finalizeReviewOutcome() like every other terminal path (see the batchStop-handling comment
   * above Step 2), so it DOES reach this call too -- correctly, since Step 1's own
   * existingJob recovery (processDispatchOutcome, run before batchStop can even be evaluated) can
   * reconcile a real prior charge on the very call that goes on to hit a batchStop.
   *
   * "Billing period" is approximated as the UTC calendar month: the key-status probe's own
   * `limitReset` field is a bare cadence string ("monthly"), never an actual reset date, so there
   * is no authoritative period boundary to key off directly. UTC calendar month reuses the same
   * UTC-boundary convention lease-store.mjs's own daily paid-job allowance already established
   * for ITS reset boundary (see utcDayKey there) -- consistent with, not a new convention
   * alongside, this codebase's existing choice.
   *
   * Dedup reuses alertStore's own durable log via list() (never a second store): exact-matches
   * this call's reason string against every WARNING alert already on record for this component,
   * so a process restart never loses the "already alerted this period" fact and this feature adds
   * no new persisted state beyond the one file it is asked to reuse.
   *
   * Never throws: a probe or alert-store failure here must not turn an otherwise-decided review()
   * outcome (PASSED or HALTED) into something newly failing for an unrelated reason.
   */
  async function checkSpendAndMaybeAlert() {
    try {
      const status = await keyStatusProbe.check();
      const limit = status?.limit;
      const limitRemaining = status?.limitRemaining;
      if (typeof limit !== 'number' || !Number.isFinite(limit) || limit <= 0) return;
      if (typeof limitRemaining !== 'number' || !Number.isFinite(limitRemaining)) return;
      const usedFraction = (limit - limitRemaining) / limit;
      if (usedFraction < spendAlertThresholdFraction) return;
      const periodKey = utcMonthKey(new Date(Number(clock())).toISOString());
      const thresholdPercent = Math.round(spendAlertThresholdFraction * 100);
      const reason = `${SPEND_ALERT_REASON_PREFIX} ${thresholdPercent} percent of cap for period ${periodKey}`;
      const existing = await alertStore.list();
      const alreadyAlerted = existing.some((entry) => entry.component === 'openrouter-review' && entry.reason === reason);
      if (alreadyAlerted) return;
      await alertStore.record({ severity: 'warning', reason, component: 'openrouter-review' });
    } catch (error) {
      process.stderr.write(`openrouter-review-alert: spend-check-failed error=${safeErrorDetail(error)}\n`);
    }
  }

  /**
   * Best-effort, per-dispatch pipeline-health tracking. Called from the two single choke points
   * every real dispatch outcome funnels through: haltAndClose (`succeeded: false` -- covers every
   * halt reason, since failures tend to cluster as unbroken streaks of ANY dispatch-level halt, not
   * just the narrower transport-failure codes) and processDispatchOutcome's clean-pass branch
   * (`succeeded: true`). Deliberately per-DISPATCH, not per-batch (unlike the spend check above):
   * the alert counts N consecutive failed dispatches. A halt does not cancel its siblings, so a
   * batch in which two reviewers halt correctly records TWO consecutive failures, and a PASSED
   * batch's multiple successful reviewers each still correctly reset the streak.
   *
   * Never throws, for the same reason checkSpendAndMaybeAlert never does.
   *
   * The whole body runs through serializedDispatchHealthAccess (below): dispatchHealthStore is
   * ONE record per installation (not per-document like leaseStore's jobs), and its own
   * recordOutcome()/markAlerted() do an unlocked read-modify-write with real async gaps --
   * dispatch-health-store.mjs's own docstring accepts a lost update between two SAME-outcome-type
   * callers (a slightly stale streak count, never worse), but a SUCCESS and a FAILURE racing in
   * the same Step 3 batch (reviewers dispatch concurrently) can durably corrupt
   * alertedForCurrentStreak itself -- a fresh streak of 0 gets permanently
   * pre-marked "already alerted", silently suppressing the critical alert for the entire NEXT real
   * failure streak, not just miscounting one. Serializing every call makes that interleaving
   * structurally impossible.
   */
  /**
   * One critical alert per job reconciled at a KNOWN cost above its reservation. The ledger already
   * holds the real cost; this is the loud signal that a reviewer's
   * worst-case bound did not hold and needs re-checking. Best effort, like every alert here: a failed
   * alert write never undoes or fails an already-committed reconcile.
   */
  async function recordAboveReservationAlert(reviewerId) {
    process.stderr.write(`openrouter-review-engine: cost-above-reservation reviewer=${reviewerId}\n`);
    try {
      await alertStore.record({
        severity: 'critical',
        reason: `reviewer ${reviewerId} was billed above its reserved worst case; the ledger records the real cost`,
        component: 'openrouter-review',
      });
    } catch (error) {
      process.stderr.write(`openrouter-review-alert: above-reservation-alert-failed error=${safeErrorDetail(error)}\n`);
    }
  }

  // Kill alert. Reads the engine's injected monotonic clock, never the wall clock, and never throws: a clock that
  // throws or returns something that is not a finite number reads as null, which the reason renders as an unknown elapsed time.
  function readMonotonicMsOrNull() {
    try {
      const reading = Number(monotonicNow());
      return Number.isFinite(reading) ? reading : null;
    } catch {
      return null;
    }
  }

  function logManagedDispatchFaultAlertFailure(alertError) {
    try {
      process.stderr.write(`openrouter-review-alert: managed-dispatch-fault-alert-failed error=${safeErrorDetail(alertError)}\n`);
    } catch {
      // A log line must never be able to fail the booking it describes.
    }
  }

  /**
   * STARTS, and deliberately never awaits, one best-effort warning alert for a managed dispatch that threw. The booking
   * that follows must not wait on a file system that could hang, so a record() that never settles just leaves a pending promise.
   * A record() that throws, a promise that rejects and a clock that throws are all caught here and leave one redacted stderr line
   * in the style of recordAboveReservationAlert() above; none can reach the caller, so the worst-case booking is unchanged.
   */
  function startManagedDispatchFaultAlert({ error, startedAtMs, reviewerId }) {
    try {
      const endedAtMs = readMonotonicMsOrNull();
      const elapsedMs = startedAtMs === null || endedAtMs === null ? Number.NaN : endedAtMs - startedAtMs;
      const reason = describeManagedDispatchFault({ error, elapsedMs, reviewerId });
      Promise.resolve(alertStore.record({ severity: 'warning', reason, component: 'openrouter-review' }))
        .catch(logManagedDispatchFaultAlertFailure);
    } catch (alertError) {
      logManagedDispatchFaultAlertFailure(alertError);
    }
  }

  async function recordDispatchHealthOutcome({ succeeded }) {
    await serializedDispatchHealthAccess(async () => {
      try {
        const { shouldAlert } = await dispatchHealthStore.recordOutcome({
          succeeded, alertThreshold: consecutiveDispatchFailureAlertThreshold,
        });
        if (shouldAlert) {
          await alertStore.record({
            severity: 'critical',
            reason: `openrouter review pipeline had ${consecutiveDispatchFailureAlertThreshold} consecutive dispatch failures`,
            component: 'openrouter-review',
          });
          // Only durably marks the streak alerted AFTER the alert write above has actually
          // succeeded: committing this flag unconditionally would mean a transient or
          // deterministic alertStore.record() failure at the crossing moment permanently silenced
          // the alert for the rest of that streak, since every later consecutive failure would see
          // the flag already true and never retry. If THIS line never runs (the record() call above threw,
          // caught below), the next consecutive failure recomputes shouldAlert: true and tries
          // again -- see dispatch-health-store.mjs's own markAlerted() docstring for the full
          // reasoning and the accepted trade-off (a rare duplicate alert, never a silently lost
          // one).
          await dispatchHealthStore.markAlerted();
        }
      } catch (error) {
        process.stderr.write(`openrouter-review-alert: dispatch-health-check-failed error=${safeErrorDetail(error)}\n`);
      }
    });
  }

  // IN-PROCESS ONLY serialization for dispatchHealthStore access -- see
  // recordDispatchHealthOutcome's own docstring above for why. Same chaining shape as
  // serializedByRawSource below (chain after the tail SETTLES, regardless of whether the previous
  // call succeeded or threw, so one call's failure can never wedge every later call), but keyless:
  // unlike the per-document repeat-authorization queue, dispatchHealthStore is a single shared
  // record, so every call -- even from two entirely different documents' own review() calls --
  // must serialize against every other one.
  let dispatchHealthQueueTail = Promise.resolve();
  function serializedDispatchHealthAccess(work) {
    const settledTail = dispatchHealthQueueTail.then(() => {}, () => {});
    const next = settledTail.then(work);
    dispatchHealthQueueTail = next.then(() => {}, () => {});
    return next;
  }

  // Per-document (rawSourceSha256), IN-PROCESS ONLY serialization for the autonomous
  // repeat-authorization sequence in authorizeWorkflow below (count check -> justify -> create
  // lease). Without it, two authorizeWorkflow calls for the same document, issued without waiting
  // for each other (ordinary, legal MCP client behavior -- the SDK dispatches incoming requests
  // without serializing them), could both read the same prior-lease count and both independently
  // pass justification, granting more repeats than the one justification event should have
  // allowed. A real local-LLM judge call or human approval click-through is slow, so that race
  // window is wide.
  //
  // Deliberately NOT the ledger's own cross-process lock (leaseStore's acquireDataRootLock):
  // holding THAT lock for as long as an LLM judge call or a human popup takes (up to
  // OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS, 5 minutes by default, or however long a human takes
  // to click through) would freeze every OTHER ledger operation on this server -- every other
  // authorizeWorkflow, preflight, dispatch reconcile -- for that entire window, and risks the
  // lock's own lockStaleMs staleness-reclaim heuristic misfiring on a holder that is slow but
  // still alive. This lock only serializes calls for the SAME document against each other; calls
  // for different documents remain fully concurrent, so it does not reintroduce that problem.
  //
  // In-process only, matching this server's already-documented realistic threat model (a
  // Windows-local stdio MCP server realistically run by one operator on one machine -- see
  // lease-store.mjs's own residual-risk comment) -- does not protect against two SEPARATE server
  // instances racing, the same residual risk already accepted for the ledger lock itself.
  //
  // No cleanup of old entries: bounded by the number of DISTINCT documents ever
  // repeat-authorized in this process's lifetime, realistically small for this kind of tool --
  // same YAGNI posture already used elsewhere in this codebase for low-cardinality unbounded
  // state (alert-store.mjs's own "grows without bound... revisit only if it becomes a real
  // problem").
  const repeatAuthorizationQueues = new Map();
  function serializedByRawSource(rawSourceSha256, work) {
    const tail = repeatAuthorizationQueues.get(rawSourceSha256) ?? Promise.resolve();
    // Chain after the tail SETTLES, regardless of whether the previous call in the queue
    // succeeded or threw -- one call's failure must never permanently wedge every later call for
    // the same document.
    const settledTail = tail.then(() => {}, () => {});
    const next = settledTail.then(work);
    // The stored value for future chaining is always-resolving (same reasoning as settledTail
    // above); the caller of THIS call gets `next` directly, which carries the real outcome.
    repeatAuthorizationQueues.set(rawSourceSha256, next.then(() => {}, () => {}));
    return next;
  }

  // Redacted, in-process only: reviewContractSha256 / sourceSha256 / itemMaxima
  // / requestedUsd / expiresAt / the reviewContext string used to build the
  // exact request bytes again at review() time. Never the source text itself.
  const preflightCache = new Map();
  // Advisory content the ledger deliberately never persists (it never stores
  // raw response bodies). Populated only on a clean, freshly reconciled pass
  // so a same-process repeated review() call can still return full content
  // instead of a bare status; a cross-process repeat still recovers state
  // safely, just without content, and never re-dispatches either way.
  const advisoryCache = new Map();
  // A managed advisory ref is obtained only from the owner-fenced persistence adapter. It is
  // intentionally process-local: recovery must first recall an exact frozen terminal candidate,
  // never rediscover arbitrary advisory catalog entries.
  const managedAdvisoryRefs = new Map();
  // Exact-fingerprint follower reuse has no target-lease job. Retain the selected source for the
  // live completion; cold recovery independently re-resolves the same bounded source set below.
  const managedReuseSources = new Map();

  // Graceful-shutdown state. Both the refusal and the
  // in-flight tracking are applied at the EXPORT boundary (see the returned frozen object at the
  // bottom of this function), never inside authorizeWorkflow/review themselves -- those two are
  // large bodies with many early returns and halt paths, and wrapping them from
  // outside puts the refusal in exactly one place and the tracking in exactly one place instead of
  // threading a flag through every branch of both.
  let shuttingDown = false;
  const inFlightOperations = new Set();

  /**
   * Registers `promise` as outstanding until it settles, and returns it UNCHANGED so the caller
   * still receives -- and still must handle -- the original.
   *
   * The `.finally()` below creates a DERIVED promise that belongs to this engine alone; no caller
   * ever holds it. If `promise` rejects (LEASE_EXPIRED, APPROVAL_DENIED, CONTENT_BLOCKED, or the
   * SHUTTING_DOWN refusal -- all routine outcomes on this surface), that
   * derived promise rejects too with nothing attached to handle it, and Node's default since v15
   * (--unhandled-rejections=throw) would take the whole MCP server process down on an ordinary
   * refusal. The trailing .catch() silences only OUR derived promise; the caller's own copy is
   * untouched, so a genuinely unhandled caller-side rejection still reports exactly as before.
   */
  function trackInFlight(promise) {
    inFlightOperations.add(promise);
    promise.finally(() => inFlightOperations.delete(promise)).catch(() => {});
    return promise;
  }

  function refuseIfShuttingDown() {
    if (shuttingDown) {
      throw new ReviewEngineError('SHUTTING_DOWN', 'the server is shutting down and refuses new owner-sensitive work');
    }
  }

  /**
   * The work the ownership coordinator runs ONCE per arm it performs itself -- never for a handle
   * that arrived already armed -- and that every concurrent caller joining that arm waits for. Two
   * steps, each caught on its own so one failing never skips the other, and neither ever fails the
   * call that triggered the arm:
   *   1. orphan recovery through the INTERNAL recoverStaleLease(), never the wrapped
   *      recoverOrphanedLeases export -- that export arms through this same coordinator, so calling
   *      it from inside the arm cycle would join the very cycle it runs in and never settle;
   *   2. the pending dispatch-health verdict sweep. dispatch-health.json has no cross-process lock,
   *      so only the armed owner may write it.
   * Log lines carry counts and codes only -- never a currency figure, never a raw error message.
   */
  async function runCycleWork({ ownerToken }) {
    try {
      const recovered = await recoverStaleLease({ leaseId: undefined, staleAfterMs: orphanSweepGraceMs, ownerToken });
      if (recovered.length > 0) {
        const jobCount = recovered.reduce((total, entry) => total + entry.reconciledJobs.length, 0);
        process.stderr.write(`openrouter-review-engine: arm-cycle-recovery-closed leases=${recovered.length} jobs=${jobCount}\n`);
      }
    } catch (error) {
      try {
        process.stderr.write(`openrouter-review-engine: arm-cycle-recovery-failed error=${safeErrorDetail(error)}\n`);
      } catch {
        // A logging failure itself must never fail the call that triggered the arm.
      }
    }
    try {
      await resolvePendingHealthVerdicts();
    } catch (error) {
      try {
        process.stderr.write(`openrouter-review-engine: arm-cycle-health-sweep-failed error=${safeErrorDetail(error)}\n`);
      } catch {
        // A logging failure itself must never fail the call that triggered the arm.
      }
    }
  }

  // Layer 2 (src/local-mcp/ownership-coordinator.mjs): single-flight arming, the shutdown checks
  // around it, the once-per-arm cycle work above, and translation of store failures into this
  // engine's own error vocabulary. resolvedCaps carries this engine's own enforced cap, so the store
  // can stamp it and refuse a live sibling configured differently.
  const coordinator = createOwnershipCoordinator({
    ownerLock,
    armTimeoutMs,
    armLockRetryMs,
    resolvedCaps: Object.freeze({ installationHardMaximumUsd }),
    isShuttingDown: () => shuttingDown,
    runCycleWork,
    engineError: (code, message, details) => new ReviewEngineError(code, message, details),
    retainOwnershipUntilShutdown,
  });

  const managedModeEnabled = validatedManagedExecution !== null && retainOwnershipUntilShutdown === true;

  async function runManagedOperation({ runCycleRecovery } = {}, operation) {
    if (!managedModeEnabled) throw new TypeError('managed operation requires retained managed execution');
    requireFunction(operation, 'operation');
    refuseIfShuttingDown();
    return trackInFlight(coordinator.runOperation({ runCycleRecovery }, operation));
  }

  async function resolveManagedPolicyContext(selector, authenticatedBinding) {
    if (!managedModeEnabled) throw new TypeError('managed policy resolution requires retained managed execution');
    const binding = requireAuthenticatedBinding(authenticatedBinding);
    let identity;
    let config;
    try {
      identity = await validatedManagedExecution.managedLedger.lookupManagedIdentity({
        selector,
        bindingId: binding.bindingId,
      });
      if (identity === null) throw sharedError('REQUEST_NOT_FOUND');
      config = await validatedManagedExecution.getInstallationConfig();
      const currentBinding = Array.isArray(config?.bindings)
        ? config.bindings.find((candidate) => candidate?.bindingId === binding.bindingId)
        : null;
      if (!currentBinding || currentBinding.credentialVersion !== binding.credentialVersion) {
        throw sharedError('REQUEST_NOT_FOUND');
      }
      const policy = await resolveBoundProjectPolicy({
        config,
        bindingId: binding.bindingId,
        credentialDigest: binding.credentialDigest,
        storedProjectId: identity.projectId,
        identityDigest: validatedManagedExecution.identityDigest,
      });
      if (policy.projectId !== identity.projectId
          || policy.policyEpoch !== identity.policyEpoch
          || policy.scopeDigest !== identity.scopeDigest) throw sharedError('REQUEST_NOT_FOUND');
      return { binding, config, policy };
    } catch {
      throw sharedError('REQUEST_NOT_FOUND');
    }
  }

  async function resolveManagedPolicy(selector, authenticatedBinding) {
    return (await resolveManagedPolicyContext(selector, authenticatedBinding)).policy;
  }

  async function resolveManagedSourcePolicy(input, authenticatedBinding) {
    const binding = requireAuthenticatedBinding(authenticatedBinding, 'PROJECT_SCOPE_DENIED');
    const config = await validatedManagedExecution.getInstallationConfig();
    const currentBinding = Array.isArray(config?.bindings)
      ? config.bindings.find((candidate) => candidate?.bindingId === binding.bindingId)
      : null;
    if (!currentBinding || currentBinding.credentialVersion !== binding.credentialVersion) {
      throw sharedError('PROJECT_SCOPE_DENIED');
    }
    const hasText = typeof input?.source_text === 'string';
    const hasPath = typeof input?.source_path === 'string';
    if (hasText === hasPath) throw sharedError('PROJECT_SCOPE_DENIED');
    const policy = await resolveCallerPolicy({
      config,
      bindingId: binding.bindingId,
      credentialDigest: binding.credentialDigest,
      sourceKind: hasText ? 'inline' : 'path',
      ...(hasPath ? { sourcePath: input.source_path } : {}),
      identityDigest: validatedManagedExecution.identityDigest,
    });
    return { binding, config, policy };
  }

  async function statusForPolicy({ leaseId } = {}, authenticatedBinding) {
    if (!managedModeEnabled) throw new TypeError('managed status requires retained managed execution');
    const policy = await resolveManagedPolicy({ leaseId }, authenticatedBinding);
    const lease = await leaseStore.getLease(leaseId);
    if (!lease || lease.version !== 1 || !lease.managedBinding
        || lease.managedBinding.bindingId !== policy.bindingId
        || lease.managedBinding.scopeDigest !== policy.scopeDigest
        || lease.managedBinding.projectId !== policy.projectId
        || lease.managedBinding.policyEpoch !== policy.policyEpoch) {
      throw sharedError('REQUEST_NOT_FOUND');
    }
    return {
      leaseId: lease.id,
      state: lease.state,
      requestedUsd: lease.requestedUsd,
      reservedUsd: lease.reservedUsd,
      spentUsd: lease.spentUsd,
      jobsConsumed: lease.jobsConsumed,
      maxJobs: lease.maxJobs,
      expiresAt: lease.expiresAt,
    };
  }

  function managedStatus(lease) {
    return {
      leaseId: lease.id, state: lease.state, requestedUsd: lease.requestedUsd,
      reservedUsd: lease.reservedUsd, spentUsd: lease.spentUsd,
      jobsConsumed: lease.jobsConsumed, maxJobs: lease.maxJobs, expiresAt: lease.expiresAt,
    };
  }

  async function metadataOnlyManagedReviewers(receipt, lease) {
    const reviewers = {};
    for (const reviewerId of receipt.reviewerIds) {
      const jobId = deriveJobId(receipt.leaseId, reviewerId, receipt.reviewContractSha256);
      // This is an authorized terminal projection, not settlement authority: no protected object,
      // capture, mapping, or source is read here.
      // eslint-disable-next-line no-await-in-loop
      const job = await leaseStore.getJob(jobId);
      if (job === null || job.id !== jobId || job.receiptId !== receipt.receiptId || job.leaseId !== receipt.leaseId
          || job.reviewContractSha256 !== receipt.reviewContractSha256
          || job.reviewerId !== reviewerId || job.executionFingerprint !== receipt.executionFingerprint
          || job.scopeDigest !== receipt.scopeDigest || !['RECONCILED', 'CANCELLED_ZERO_DISPATCH'].includes(job.state)) continue;
      if (job.state === 'CANCELLED_ZERO_DISPATCH') {
        reviewers[reviewerId] = { reviewerId, jobId, state: job.state, costUsd: 0, costKind: 'RECOVERED_STATUS_ONLY' };
      } else {
        let error;
        if (job.haltReason !== undefined) {
          try { error = { code: job.haltReason, message: sharedError(job.haltReason).message }; } catch { error = { code: job.haltReason, message: 'managed reviewer failed' }; }
        }
        reviewers[reviewerId] = {
          reviewerId, jobId, state: job.state, costUsd: job.costUsd,
          costKind: job.costKind,
          ...(error === undefined ? {} : { error }),
        };
      }
    }
    return reviewers;
  }

  async function requestManagedResult({ receiptId } = {}, authenticatedBinding) {
    const policy = await resolveManagedPolicy({ receiptId }, authenticatedBinding);
    const receipt = await validatedManagedExecution.managedLedger.getReceipt({
      receiptId, bindingId: policy.bindingId, scopeDigest: policy.scopeDigest,
    });
    if (receipt === null || receipt.state !== 'TERMINAL') throw sharedError('REQUEST_NOT_FOUND');
    if (receipt.terminal?.kind === 'CANCELLED' || receipt.terminal?.kind === 'EXPIRED' || receipt.terminal?.kind === 'CONTENT_LOST') {
      const lease = await leaseStore.getLease(receipt.leaseId);
      if (lease === null || lease.id !== receipt.leaseId || lease.managedBinding?.receiptId !== receipt.receiptId) throw sharedError('REQUEST_NOT_FOUND');
      return deepFreeze({ kind: receipt.terminal.kind, reviewers: await metadataOnlyManagedReviewers(receipt, lease) });
    }
    const committed = await validatedManagedExecution.terminalStore.recallCommitted({ receiptId });
    if (committed === null) throw sharedError('REQUEST_NOT_FOUND');
    if (committed.terminal.outcome.kind === 'REVIEW_RETURNED') return deepFreeze({ kind: 'REVIEW_RETURNED', review: committed.terminal.projection.value });
    return deepFreeze({ kind: 'REVIEW_ERROR', error: committed.terminal.outcome.error });
  }

  // `result` keeps its legacy { leaseId, state, reviewers } contract, with the lease state as `state`
  // (the terminal contract's own legacy view). A request that is still running is reported as such,
  // with no reviewer entries yet, rather than as not found.
  async function resultForPolicy({ leaseId } = {}, authenticatedBinding) {
    const policy = await resolveManagedPolicy({ leaseId }, authenticatedBinding);
    const receipt = await validatedManagedExecution.managedLedger.findReceiptForManagedLease({
      leaseId, bindingId: policy.bindingId, scopeDigest: policy.scopeDigest,
    });
    if (receipt === null) throw sharedError('REQUEST_NOT_FOUND');
    const lease = await leaseStore.getLease(leaseId);
    if (lease === null || lease.id !== leaseId || lease.managedBinding?.receiptId !== receipt.receiptId) throw sharedError('REQUEST_NOT_FOUND');
    if (receipt.state !== 'TERMINAL') return deepFreeze({ leaseId, state: lease.state, reviewers: {} });
    const managed = await requestManagedResult({ receiptId: receipt.receiptId }, authenticatedBinding);
    if (managed.kind === 'REVIEW_ERROR') {
      throw sharedError(managed.error?.code === 'PROTECTED_CONTENT_TOO_LARGE' ? 'PROTECTED_CONTENT_TOO_LARGE' : 'REQUEST_FAILED');
    }
    return deepFreeze({ leaseId, state: lease.state, reviewers: managed.kind === 'REVIEW_RETURNED' ? managed.review.reviewers : managed.reviewers });
  }

  async function preflightForPolicy(input, authenticatedBinding) {
    if (!managedModeEnabled) throw new TypeError('managed preflight requires retained managed execution');
    const { binding, config, policy } = await resolveManagedSourcePolicy(input, authenticatedBinding);
    const reservationId = randomUUID();
    const generation = 1;
    const preflightId = randomUUID();
    const expiresAt = new Date(Number(clock()) + config.engine.preflightTtlMs).toISOString();
    const ownerContext = await runManagedOperation({ runCycleRecovery: true }, async ({ ownerToken }) => {
      const reservation = await validatedManagedExecution.managedLedger.reserveManagedPreflightCapacity({
        reservationId,
        generation,
        bindingId: binding.bindingId,
        projectId: policy.projectId,
        policyEpoch: policy.policyEpoch,
        scopeDigest: policy.scopeDigest,
        maxEncryptedBytes: maximumPreflightEncryptedBytes({
          maxSinglePreflightPlaintextBytes: config.storage.maxSinglePreflightPlaintextBytes,
        }),
        expiresAt,
        acquisitionId: ownerToken.acquisitionId,
      });
      try {
        const rawReviewContext = input?.reviewContext ?? '';
        if (typeof rawReviewContext !== 'string') throw new ReviewEngineError('SOURCE_INVALID', 'reviewContext must be a string');
        let source;
        try {
          source = await loadAndScrubSource({
            source_text: input?.source_text,
            source_path: input?.source_path,
            sourcePolicy: { ...sourcePolicy, allowedRoots: policy.allowedRoots, maxSourceBytes: config.engine.maxSourceBytes },
            preflightId,
          });
        } catch (error) {
          if (error instanceof ReviewEngineError) throw error;
          throw new ReviewEngineError('SOURCE_INVALID', error.message);
        }
        const contextScrub = await scrubEngine.scrub({ text: rawReviewContext, preflightId });
        if (contextScrub.blocked) {
          throw new ReviewEngineError('CONTENT_BLOCKED', `reviewContext blocked before send: ${contextScrub.blockedCategories.join(', ')}`);
        }
        const reviewContext = contextScrub.scrubbedText;
        const accumulatedMapping = contextScrub.mapping ?? {};
        let computed;
        try {
          computed = preflightReview({
            source,
            profile: input?.profile,
            reviewContext,
            policy: { ...preflightPolicy, maxRequestBytes: config.engine.maxRequestBytes },
            // Same default the per-session review path applies: final verification without changeKinds means none.
            changeKinds: input?.profile === 'final_verification_v1' ? (input?.changeKinds ?? []) : input?.changeKinds,
          });
        } catch (error) {
          throw new ReviewEngineError('SOURCE_INVALID', error.message);
        }
        const reviewContextSha256 = sha256(reviewContext);
        const reviewContractSha256 = buildReviewContract({
          sourceSha256: computed.sourceSha256,
          reviewContextSha256,
          profile: computed.profile,
          profileVersion: computed.profileVersion,
        });
        const itemMaxima = computed.reviewers.map((reviewer) => ({ itemId: `item-${reviewer.reviewerId}`, maxUsd: reviewer.maxUsd }));
        const requestedUsd = computed.totalMaxUsd;
        const mappingBytes = Buffer.byteLength(canonicalJson(accumulatedMapping), 'utf8');
        const contextBytes = Buffer.byteLength(reviewContext, 'utf8');
        if (mappingBytes + contextBytes > config.storage.maxSinglePreflightPlaintextBytes) {
          throw sharedError('REQUEST_TOO_LARGE');
        }
        const publication = Object.freeze({
          kind: 'preflight',
          target: Object.freeze({ reservationId, generation }),
          creationBarrierId: reservation.replayBarrierId,
          createdAt: reservation.createdAt,
        });
        const contextRef = await validatedManagedExecution.protectedStore.put({
          kind: 'preflight-context',
          objectId: randomUUID(),
          value: reviewContext,
          publication,
          association: { preflightId },
        });
        const mappingRef = await validatedManagedExecution.protectedStore.put({
          kind: 'scrub-mapping',
          objectId: randomUUID(),
          value: accumulatedMapping,
          publication,
          association: { preflightId },
        });
        const snapshotSourceId = validatedManagedExecution.identityDigest(
          'shared-source-v1', Buffer.from(source.rawText, 'utf8'),
        );
        const snapshotContextId = validatedManagedExecution.identityDigest(
          'shared-context-v1', Buffer.from(rawReviewContext, 'utf8'),
        );
        const mappingIdentity = validatedManagedExecution.identityDigest(
          'shared-mapping-v1', Buffer.from(canonicalJson(accumulatedMapping), 'utf8'),
        );
        const preflight = {
          id: preflightId,
          state: 'PREFLIGHTED',
          reviewContractSha256,
          sourceSha256: computed.sourceSha256,
          rawSourceSha256: source.rawSourceSha256,
          profile: computed.profile,
          profileVersion: computed.profileVersion,
          schemaSha256: config.review.advisorySchemaSha256,
          registrySha256: config.review.registrySha256,
          itemMaxima,
          requestedUsd,
          expiresAt,
        };
        const managedIdentity = {
          bindingId: binding.bindingId,
          scopeDigest: policy.scopeDigest,
          projectId: policy.projectId,
          policyEpoch: policy.policyEpoch,
          snapshotSourceId,
          snapshotContextId,
          mappingIdentity,
          contextRef,
          mappingRef,
          identityKeyVersion: config.protectedReferences.identityKeyVersion,
        };
        const record = await validatedManagedExecution.managedLedger.commitManagedPreflight({
          reservationId,
          generation,
          preflight,
          managedIdentity,
          contextRef,
          mappingRef,
          exactEncryptedBytes: contextRef.encryptedBytes + mappingRef.encryptedBytes,
          acquisitionId: ownerToken.acquisitionId,
        });
        return {
          preflightId: record.id,
          state: record.state,
          reviewContractSha256,
          sourceSha256: computed.sourceSha256,
          profile: computed.profile,
          profileVersion: computed.profileVersion,
          itemMaxima,
          requestedUsd,
          expiresAt: record.expiresAt,
          reviewers: computed.reviewers.map((reviewer) => ({
            reviewerId: reviewer.reviewerId,
            model: reviewer.model,
            route: reviewer.route,
            maxUsd: reviewer.maxUsd,
          })),
        };
      } catch (error) {
        await validatedManagedExecution.managedLedger.releaseManagedPreflightReservation({
          reservationId,
          generation,
          reason: 'PREPARE_FAILED',
          acquisitionId: ownerToken.acquisitionId,
        });
        throw error;
      }
    });
    return ownerContext;
  }

  async function authorizeForPolicy({ preflightId, maxJobs, expiresAt, justification } = {}, authenticatedBinding, ownerToken) {
    if (!managedModeEnabled) throw new TypeError('managed authorization requires retained managed execution');
    requireOwnerToken(ownerToken);
    const policy = await resolveManagedPolicy({ preflightId }, authenticatedBinding);
    const preflightRecord = await leaseStore.getPreflight(preflightId);
    if (!preflightRecord || preflightRecord.state !== 'PREFLIGHTED') throw sharedError('REQUEST_NOT_FOUND');
    if (preflightRecord.requestedUsd > installationHardMaximumUsd) {
      throw new ReviewEngineError('LEASE_CAP_EXCEEDED', 'requested amount exceeds the installation hard maximum');
    }
    const boundExpiresAt = expiresAt ?? preflightRecord.expiresAt;
    if (typeof boundExpiresAt !== 'string' || !Number.isFinite(Date.parse(boundExpiresAt))
        || Date.parse(boundExpiresAt) > Date.parse(preflightRecord.expiresAt)) {
      throw new ReviewEngineError('CONTRACT_CHANGED', 'requested lease expiry exceeds the bound preflight expiry');
    }
    if (!Number.isSafeInteger(maxJobs) || maxJobs <= 0) {
      throw new ReviewEngineError('CONTRACT_CHANGED', 'maxJobs must be a positive safe integer');
    }
    const reviewerCount = preflightRecord.itemMaxima.length;
    if (maxJobs < reviewerCount) {
      throw new ReviewEngineError(
        'LEASE_CAP_EXCEEDED',
        `maxJobs (${maxJobs}) must be at least the preflight reviewer count (${reviewerCount})`,
        { maxJobs, reviewerCount },
      );
    }
    const approvalRequest = {
      preflightHashes: [preflightRecord.reviewContractSha256],
      profiles: [preflightRecord.profile],
      itemMaxima: preflightRecord.itemMaxima,
      requestedUsd: preflightRecord.requestedUsd,
      maxJobs,
      expiresAt: boundExpiresAt,
    };
    function hasValidJustification(value) {
      return value !== null && typeof value === 'object'
        && (value.source === 'human' || value.source === 'llm')
        && typeof value.reason === 'string' && value.reason.length > 0;
    }
    async function grantManagedLease(outcome) {
      if (outcome.outcome === 'DENIED') throw new ReviewEngineError('APPROVAL_DENIED', 'the approval worker denied this workflow');
      if (outcome.outcome === 'TIMED_OUT') throw new ReviewEngineError('APPROVAL_TIMEOUT', 'the approval request timed out before confirmation');
      if (outcome.outcome !== 'APPROVED') throw new ReviewEngineError('APPROVAL_DENIED', `unrecognized approval outcome: ${outcome.outcome}`);
      const lease = await validatedManagedExecution.managedLedger.createManagedLease({
        preflightId,
        bindingId: policy.bindingId,
        scopeDigest: policy.scopeDigest,
        projectId: policy.projectId,
        policyEpoch: policy.policyEpoch,
        requestedUsd: preflightRecord.requestedUsd,
        maxJobs,
        expiresAt: boundExpiresAt,
        acquisitionId: ownerToken.acquisitionId,
      });
      return {
        leaseId: lease.id,
        preflightId,
        state: lease.state,
        requestedUsd: lease.requestedUsd,
        maxJobs: lease.maxJobs,
        expiresAt: lease.expiresAt,
      };
    }

    if (!autonomousAuthorization) {
      const outcome = await approvalAdapter.authorize(approvalRequest, { leaseExpiresAt: preflightRecord.expiresAt });
      return grantManagedLease(outcome);
    }

    return serializedByRawSource(preflightRecord.rawSourceSha256, async () => {
      const priorLeaseCount = await leaseStore.countLeasesForRawSource(preflightRecord.rawSourceSha256);
      const documentOutcome = priorLeaseCount === 0
        ? null
        : await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256: preflightRecord.rawSourceSha256 });
      let outcome;
      let repeatJustifiedVia = null;
      if (priorLeaseCount === 0) {
        outcome = { outcome: 'APPROVED', nonce: randomUUID(), autonomous: true };
      } else if (documentOutcome === 'SUCCEEDED' && (!hasValidJustification(justification) || justification.source === 'llm')) {
        throw new ReviewEngineError(
          'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
          `this document's most recent prior lease already completed successfully; a repeat claiming it failed is contradicted by this server's own ledger (preflight ${preflightId})`,
        );
      } else if (documentOutcome === 'FAILED' && hasValidJustification(justification)) {
        outcome = { outcome: 'APPROVED', nonce: randomUUID(), autonomous: true };
        repeatJustifiedVia = 'ledger';
      } else if (!hasValidJustification(justification)) {
        throw new ReviewEngineError(
          'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION',
          `this document already has ${priorLeaseCount} prior lease(s) (preflight ${preflightId}); a repeat authorization under autonomy requires justification: { source: 'human' | 'llm', reason }`,
        );
      } else if (justification.source === 'human') {
        try {
          await alertStore.record({
            severity: 'info',
            reason: `human justification requested for a repeat authorization of profile ${preflightRecord.profile}`,
            component: 'openrouter-review',
          });
        } catch (error) {
          process.stderr.write(`openrouter-review-alert: ${safeErrorDetail(error)}\n`);
        }
        outcome = await approvalAdapter.authorize(approvalRequest, { leaseExpiresAt: preflightRecord.expiresAt });
        repeatJustifiedVia = 'human';
      } else {
        const verdict = await repeatAuthorizationJudge.judge({
          reason: justification.reason,
          profile: preflightRecord.profile,
          priorLeaseCount,
        });
        if (verdict.ok !== true || verdict.justified !== true) {
          throw new ReviewEngineError(
            'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
            verdict.ok === true
              ? `the repeat-authorization judge declined: ${verdict.reasoning}`
              : 'the repeat-authorization judge could not be reached; treating as not justified',
          );
        }
        outcome = { outcome: 'APPROVED', nonce: randomUUID(), autonomous: true };
        repeatJustifiedVia = 'llm';
      }
      const response = await grantManagedLease(outcome);
      try {
        await alertStore.record({
          severity: 'info',
          reason: repeatJustifiedVia === null
            ? `autonomous authorization granted for profile ${preflightRecord.profile}`
            : `autonomous repeat authorization justified via ${repeatJustifiedVia} for profile ${preflightRecord.profile}`,
          component: 'openrouter-review',
        });
      } catch (error) {
        process.stderr.write(`openrouter-review-alert: ${safeErrorDetail(error)}\n`);
      }
      return response;
    });
  }

  function requirePreparationContext(value) {
    if (!isPlainObject(value) || !Object.isFrozen(value)) throw new TypeError('preparationContext must be frozen');
    const keys = Object.keys(value).sort();
    if (keys.length !== 2 || keys[0] !== 'generation' || keys[1] !== 'stagingId'
        || typeof value.stagingId !== 'string' || value.stagingId.length === 0
        || !Number.isSafeInteger(value.generation) || value.generation <= 0) {
      throw new TypeError('preparationContext must be exactly { stagingId, generation }');
    }
    return value;
  }

  function reviewerFingerprintEntry(reviewer, requestBodyDigest) {
    return {
      reviewerId: reviewer.id,
      model: reviewer.model,
      route: reviewer.route,
      expectedProvider: reviewer.expectedProvider,
      outputMode: reviewer.outputMode ?? 'strict_json',
      requestControls: {
        reasoning: reviewer.request.reasoning,
        ...(reviewer.request.temperature === undefined ? {} : { temperature: reviewer.request.temperature }),
        maxTokens: reviewer.request.maxTokens,
        stream: reviewer.request.stream,
        provider: {
          zdr: reviewer.request.provider.zdr,
          dataCollection: reviewer.request.provider.dataCollection,
          requireParameters: reviewer.request.provider.requireParameters,
          allowFallbacks: reviewer.request.provider.allowFallbacks,
        },
        priceCeiling: reviewer.priceCeiling,
      },
      requestBodyDigest,
    };
  }

  async function prepareReview(input = {}, authenticatedBinding, preparationContext) {
    const {
      leaseId, preflightId, source_text, source_path, reviewContext, changeKinds,
    } = input;
    const hasReviewContext = Object.hasOwn(input, 'reviewContext');
    if (!managedModeEnabled) throw new TypeError('managed preparation requires retained managed execution');
    const context = requirePreparationContext(preparationContext);
    const { binding, config, policy } = await resolveManagedPolicyContext({ preflightId }, authenticatedBinding);
    if (typeof leaseId !== 'string' || leaseId.length === 0 || typeof preflightId !== 'string' || preflightId.length === 0) {
      throw sharedError('REQUEST_NOT_FOUND');
    }
    if (hasReviewContext && typeof reviewContext !== 'string') {
      throw new ReviewEngineError('SOURCE_INVALID', 'reviewContext must be a string');
    }

    return runManagedOperation({ runCycleRecovery: false }, async ({ ownerToken }) => {
      const staging = await validatedManagedExecution.managedLedger.getStagingPermit({
        stagingId: context.stagingId,
        generation: context.generation,
        acquisitionId: ownerToken.acquisitionId,
      });
      if (!staging || staging.state !== 'RESERVED' || staging.stagingId !== context.stagingId
          || staging.generation !== context.generation || staging.bindingId !== binding.bindingId
          || staging.scopeDigest !== policy.scopeDigest || staging.leaseId !== leaseId
          || typeof staging.keyDigest !== 'string' || !/^[a-f0-9]{64}$/.test(staging.keyDigest)
          || typeof staging.inputDigest !== 'string' || !/^[a-f0-9]{64}$/.test(staging.inputDigest)
          || typeof staging.createdAt !== 'string' || !Number.isFinite(Date.parse(staging.createdAt))
          || typeof staging.replayBarrierId !== 'string' || staging.replayBarrierId.length === 0
          || typeof staging.effectiveDeadline !== 'string' || Date.parse(staging.effectiveDeadline) <= Number(clock())) {
        throw sharedError('REQUEST_NOT_FOUND');
      }

      const preparation = await validatedManagedExecution.managedLedger.getManagedPreflightForPreparation({
        preflightId,
        leaseId,
        acquisitionId: ownerToken.acquisitionId,
      });
      const preflight = preparation?.preflight;
      const managedIdentity = preparation?.managedIdentity;
      const lease = preparation?.lease;
      if (!preflight || !managedIdentity || !lease || preflight.id !== preflightId
          || preflight.state !== 'PREFLIGHTED' || lease.id !== leaseId || lease.state !== 'MANAGED_ACTIVE'
          || managedIdentity.bindingId !== binding.bindingId
          || managedIdentity.scopeDigest !== policy.scopeDigest
          || managedIdentity.projectId !== policy.projectId
          || managedIdentity.policyEpoch !== policy.policyEpoch
          || lease.managedBinding?.bindingId !== binding.bindingId
          || lease.managedBinding?.scopeDigest !== policy.scopeDigest
          || lease.managedBinding?.projectId !== policy.projectId
          || lease.managedBinding?.policyEpoch !== policy.policyEpoch
          || !Array.isArray(lease.preflightIds) || lease.preflightIds.length !== 1
          || lease.preflightIds[0] !== preflightId
          || lease.reviewContractSha256 !== preflight.reviewContractSha256
          || lease.sourceSha256 !== preflight.sourceSha256
          || lease.profile !== preflight.profile || lease.profileVersion !== preflight.profileVersion
          || lease.schemaSha256 !== preflight.schemaSha256 || lease.registrySha256 !== preflight.registrySha256
          || Date.parse(staging.effectiveDeadline) > Date.parse(lease.expiresAt)
          || Date.parse(lease.expiresAt) > Date.parse(preflight.expiresAt)) {
        throw sharedError('REQUEST_NOT_FOUND');
      }

      let source;
      try {
        source = await loadAndScrubSource({
          source_text,
          source_path,
          sourcePolicy: { ...sourcePolicy, allowedRoots: policy.allowedRoots, maxSourceBytes: config.engine.maxSourceBytes },
          preflightId,
        });
      } catch (error) {
        if (error instanceof ReviewEngineError) throw error;
        throw new ReviewEngineError('SOURCE_INVALID', error.message);
      }
      const snapshotSourceId = validatedManagedExecution.identityDigest(
        'shared-source-v1', Buffer.from(source.rawText, 'utf8'),
      );
      if (snapshotSourceId !== managedIdentity.snapshotSourceId) {
        throw new ReviewEngineError('CONTRACT_CHANGED', 'prepared source or context differs from the managed preflight');
      }

      let scrubbedContext;
      let mapping;
      let snapshotContextId;
      if (hasReviewContext) {
        const contextScrub = await scrubEngine.scrub({ text: reviewContext, preflightId });
        if (contextScrub.blocked) {
          throw new ReviewEngineError('CONTENT_BLOCKED', `reviewContext blocked before send: ${contextScrub.blockedCategories.join(', ')}`);
        }
        scrubbedContext = contextScrub.scrubbedText;
        mapping = contextScrub.mapping ?? {};
        snapshotContextId = validatedManagedExecution.identityDigest(
          'shared-context-v1', Buffer.from(reviewContext, 'utf8'),
        );
        const providedMappingIdentity = validatedManagedExecution.identityDigest(
          'shared-mapping-v1', Buffer.from(canonicalJson(mapping), 'utf8'),
        );
        if (snapshotContextId !== managedIdentity.snapshotContextId
            || providedMappingIdentity !== managedIdentity.mappingIdentity) {
          throw new ReviewEngineError('CONTRACT_CHANGED', 'prepared source or context differs from the managed preflight');
        }
      }

      const [storedContext, storedMapping] = await Promise.all([
        validatedManagedExecution.protectedStore.get(managedIdentity.contextRef),
        validatedManagedExecution.protectedStore.get(managedIdentity.mappingRef),
      ]);
      if (typeof storedContext !== 'string' || storedMapping === null || typeof storedMapping !== 'object'
          || Array.isArray(storedMapping)) {
        throw sharedError('PROTECTED_CONTENT_INVALID');
      }
      if (hasReviewContext) {
        if (storedContext !== scrubbedContext || canonicalJson(storedMapping) !== canonicalJson(mapping)) {
          throw new ReviewEngineError('CONTRACT_CHANGED', 'prepared source or context differs from the managed preflight');
        }
      } else {
        // Absence is semantic: accepted work inherits the already-scrubbed protected preflight
        // context. Re-scrubbing that value would treat placeholders as fresh raw input and hashing
        // it would replace the immutable identity of the caller's original raw context.
        scrubbedContext = storedContext;
        mapping = storedMapping;
        snapshotContextId = managedIdentity.snapshotContextId;
      }
      const mappingIdentity = validatedManagedExecution.identityDigest(
        'shared-mapping-v1', Buffer.from(canonicalJson(mapping), 'utf8'),
      );
      if (mappingIdentity !== managedIdentity.mappingIdentity) {
        throw sharedError('PROTECTED_CONTENT_INVALID');
      }

      const effectiveChangeKinds = preflight.profile === 'final_verification_v1' ? (changeKinds ?? []) : changeKinds;
      let computed;
      try {
        computed = preflightReview({
          source,
          profile: preflight.profile,
          reviewContext: scrubbedContext,
          policy: { ...preflightPolicy, maxRequestBytes: config.engine.maxRequestBytes },
          changeKinds: effectiveChangeKinds,
        });
      } catch (error) {
        throw new ReviewEngineError('SOURCE_INVALID', error.message);
      }
      const recomputedContract = buildReviewContract({
        sourceSha256: computed.sourceSha256,
        reviewContextSha256: sha256(scrubbedContext),
        profile: computed.profile,
        profileVersion: computed.profileVersion,
      });
      const configuredProfile = config.review.allowedProfiles.find((entry) => (
        entry.profileId === computed.profile && entry.profileVersion === computed.profileVersion
      ));
      if (!configuredProfile
          || !isAllowedReviewerSet(configuredProfile, computed.reviewers.map((entry) => entry.reviewerId))
          || preflight.sourceSha256 !== computed.sourceSha256
          || preflight.rawSourceSha256 !== source.rawSourceSha256
          || preflight.reviewContractSha256 !== recomputedContract
          || preflight.profile !== computed.profile || preflight.profileVersion !== computed.profileVersion
          || preflight.schemaSha256 !== config.review.advisorySchemaSha256
          || preflight.registrySha256 !== config.review.registrySha256
          || preflight.requestedUsd !== computed.totalMaxUsd
          || canonicalJson(preflight.itemMaxima) !== canonicalJson(computed.reviewers.map((entry) => ({
            itemId: `item-${entry.reviewerId}`, maxUsd: entry.maxUsd,
          })))) {
        throw new ReviewEngineError('CONTRACT_CHANGED', 'managed preflight contract changed before preparation');
      }

      const publication = deepFreeze({
        kind: 'prepared',
        target: { stagingId: context.stagingId, generation: context.generation },
        creationBarrierId: staging.replayBarrierId,
        createdAt: staging.createdAt,
      });
      const envelopeRequestRefs = [];
      const bareRequestRefs = [];
      const fingerprintReviewers = [];
      for (const summary of computed.reviewers) {
        const reviewer = getReviewer(summary.reviewerId);
        const requestBytes = Buffer.from(JSON.stringify(summary.requestBody), 'utf8');
        if (requestBytes.byteLength > config.engine.maxRequestBytes) throw sharedError('REQUEST_TOO_LARGE');
        const requestBodyDigest = validatedManagedExecution.identityDigest('shared-body-v1', requestBytes);
        // eslint-disable-next-line no-await-in-loop
        const requestRef = await validatedManagedExecution.protectedStore.put({
          kind: 'dispatch-request',
          objectId: randomUUID(),
          value: requestBytes,
          publication,
        });
        envelopeRequestRefs.push({ reviewerId: reviewer.id, requestRef, requestBodyDigest });
        bareRequestRefs.push(requestRef);
        fingerprintReviewers.push(reviewerFingerprintEntry(reviewer, requestBodyDigest));
      }
      const fingerprintFields = {
        protocolVersion: config.protocolVersion,
        storageVersion: config.storageVersion,
        buildManifestSha256: config.buildManifestSha256,
        reviewContractSha256: preflight.reviewContractSha256,
        registrySha256: config.review.registrySha256,
        advisorySchemaSha256: config.review.advisorySchemaSha256,
        promptVersion: config.review.promptVersion ?? PROMPT_VERSION,
        profile: {
          profileId: computed.profile,
          profileVersion: computed.profileVersion,
          orderedReviewerIds: computed.reviewers.map((entry) => entry.reviewerId),
        },
        reviewers: fingerprintReviewers,
        snapshotSourceId,
        snapshotContextId,
        mappingIdentity,
        classifierContractDigest: config.engine.classifierContractDigest,
        identityListDigest: config.engine.identityListDigest,
        policy: { scopeDigest: policy.scopeDigest, policyEpoch: policy.policyEpoch, projectId: policy.projectId },
      };
      const fingerprint = executionFingerprint(fingerprintFields);
      const mappingPin = { preflightId, mappingIdentity };
      const acceptedBindingCredentialIdentity = validatedManagedExecution.identityDigest(
        'shared-binding-credential-v1', Buffer.from(canonicalJson(binding), 'utf8'),
      );
      const envelope = validatePreparedEnvelope({
        version: 'shared-review-prepared-v1',
        leaseId,
        preflightId,
        scopeDigest: policy.scopeDigest,
        policyEpoch: policy.policyEpoch,
        projectId: policy.projectId,
        executionFingerprint: fingerprint,
        acceptedBindingCredentialIdentity,
        fingerprintFields,
        requestRefs: envelopeRequestRefs,
        mappingPin,
        effectiveDeadline: staging.effectiveDeadline,
      });
      const envelopeRef = await validatedManagedExecution.protectedStore.put({
        kind: 'prepared-envelope',
        objectId: randomUUID(),
        value: envelope,
        publication,
      });
      const preparedPayload = { envelopeRef, requestRefs: bareRequestRefs };
      const exactEncryptedBytes = envelopeRef.encryptedBytes
        + bareRequestRefs.reduce((total, ref) => total + ref.encryptedBytes, 0);
      if (!Number.isSafeInteger(exactEncryptedBytes) || exactEncryptedBytes > staging.maxEncryptedBytes) {
        throw sharedError('REQUEST_BYTES_FULL');
      }
      return deepFreeze({
        preparedPayload,
        exactEncryptedBytes,
        receiptSeed: {
          leaseId,
          preflightId,
          bindingId: binding.bindingId,
          projectId: policy.projectId,
          policyEpoch: policy.policyEpoch,
          scopeDigest: policy.scopeDigest,
          executionFingerprint: fingerprint,
          snapshotSourceId,
          snapshotContextId,
          reviewContractSha256: preflight.reviewContractSha256,
          mappingPins: [mappingPin],
          reviewerIds: computed.reviewers.map((entry) => entry.reviewerId),
          effectiveDeadline: staging.effectiveDeadline,
        },
      });
    });
  }

  function requireClaimExecution(value, receiptId) {
    if (!isPlainObject(value) || !Object.isFrozen(value)) throw new TypeError('claimExecution must be frozen');
    const expectedKeys = ['claimId', 'executionGroupId', 'ownerGeneration', 'ownerToken', 'permitToken', 'receiptId'];
    if (canonicalJson(Object.keys(value).sort()) !== canonicalJson(expectedKeys)
        || value.receiptId !== receiptId
        || typeof value.executionGroupId !== 'string' || value.executionGroupId.length === 0
        || typeof value.claimId !== 'string' || value.claimId.length === 0
        || !Number.isSafeInteger(value.ownerGeneration) || value.ownerGeneration <= 0) {
      throw new TypeError('claimExecution has an invalid shape');
    }
    requireOwnerToken(value.ownerToken);
    if (value.permitToken === null || (typeof value.permitToken !== 'object' && typeof value.permitToken !== 'string')) {
      throw new TypeError('claimExecution.permitToken is invalid');
    }
    return value;
  }

  function validateClaimedManagedView(view, claimExecution) {
    const receipt = view?.receipt;
    const executionGroup = view?.executionGroup;
    const lease = view?.lease;
    const preflight = view?.preflight;
    if (!receipt || !executionGroup || !lease || !preflight || !Array.isArray(view.jobs)
        || receipt.receiptId !== claimExecution.receiptId
        || receipt.executionGroupId !== claimExecution.executionGroupId
        || receipt.claimId !== claimExecution.claimId
        || executionGroup.executionGroupId !== claimExecution.executionGroupId
        || executionGroup.claimId !== claimExecution.claimId
        || executionGroup.leaderReceiptId !== receipt.receiptId
        || !['CLAIMED', 'RECOVERY_PENDING'].includes(executionGroup.state)
        || !['EXECUTING', 'RECOVERY_PENDING'].includes(receipt.state)
        || lease.id !== receipt.leaseId || lease.state !== 'MANAGED_ACTIVE'
        || lease.managedBinding?.receiptId !== receipt.receiptId
        || lease.managedBinding?.bindingId !== receipt.bindingId
        || lease.managedBinding?.scopeDigest !== receipt.scopeDigest
        || lease.managedBinding?.projectId !== receipt.projectId
        || lease.managedBinding?.policyEpoch !== receipt.policyEpoch
        || lease.managedBinding?.executionFingerprint !== receipt.executionFingerprint
        || preflight.id !== receipt.preflightId
        || preflight.reviewContractSha256 !== receipt.reviewContractSha256
        || preflight.profile !== lease.profile || preflight.profileVersion !== lease.profileVersion
        || preflight.schemaSha256 !== lease.schemaSha256 || preflight.registrySha256 !== lease.registrySha256
        || executionGroup.executionFingerprint !== receipt.executionFingerprint
        || executionGroup.scopeDigest !== receipt.scopeDigest
        || canonicalJson(executionGroup.reviewerIds) !== canonicalJson(receipt.reviewerIds)) {
      throw sharedError('REQUEST_NOT_FOUND');
    }
    const descriptor = validatedManagedExecution.executionPermits.assertLive({
      receiptId: receipt.receiptId,
      claimId: claimExecution.claimId,
      token: claimExecution.permitToken,
      reviewerIds: receipt.reviewerIds,
      ownerGeneration: claimExecution.ownerGeneration,
    });
    if (executionGroup.permit?.permitTokenDigest !== descriptor.permitTokenDigest
        || executionGroup.permit?.permitSetRevision !== descriptor.permitSetRevision
        || executionGroup.permit?.activeBatchUnits !== 1
        || canonicalJson(executionGroup.permit?.reviewerIds) !== canonicalJson(descriptor.reviewerIds)) {
      throw sharedError('REQUEST_NOT_FOUND');
    }
    for (const job of view.jobs) {
      if (job.receiptId !== receipt.receiptId || job.claimId !== claimExecution.claimId
          || job.executionFingerprint !== receipt.executionFingerprint || job.scopeDigest !== receipt.scopeDigest
          || !receipt.reviewerIds.includes(job.reviewerId)) throw sharedError('PROTECTED_CONTENT_INVALID');
    }
    const mapping = view.mapping;
    if (mapping !== null && (mapping?.preflightId !== receipt.preflightId
        || mapping.mappingIdentity !== receipt.mappingPins?.[0]?.mappingIdentity
        || typeof mapping.identityKeyVersion !== 'string' || !mapping.mappingRef)) {
      throw sharedError('PROTECTED_CONTENT_INVALID');
    }
    return { receipt, executionGroup, lease, preflight, mapping, jobs: view.jobs };
  }

  async function recoverClaimedManagedView(claimExecution) {
    const view = await validatedManagedExecution.managedLedger.recoverManagedReceipt({
      receiptId: claimExecution.receiptId,
      acquisitionId: claimExecution.ownerToken.acquisitionId,
    });
    return validateClaimedManagedView(view, claimExecution);
  }

  async function resolveAcceptedBackgroundAuthority(receipt) {
    let config;
    let currentBinding;
    let policy;
    try {
      config = await validatedManagedExecution.getInstallationConfig();
      currentBinding = Array.isArray(config?.bindings)
        ? config.bindings.find((candidate) => candidate?.bindingId === receipt.bindingId)
        : null;
      if (!currentBinding?.enabled) throw sharedError('REQUEST_NOT_FOUND');
      policy = await resolveBoundProjectPolicy({
        config,
        bindingId: receipt.bindingId,
        credentialDigest: currentBinding.credentialDigest,
        storedProjectId: receipt.projectId,
        identityDigest: validatedManagedExecution.identityDigest,
      });
      if (policy.projectId !== receipt.projectId || policy.policyEpoch !== receipt.policyEpoch
          || policy.scopeDigest !== receipt.scopeDigest) throw sharedError('REQUEST_NOT_FOUND');
    } catch {
      throw sharedError('REQUEST_NOT_FOUND');
    }
    const acceptedBindingCredentialIdentity = validatedManagedExecution.identityDigest(
      'shared-binding-credential-v1',
      Buffer.from(canonicalJson({
        bindingId: currentBinding.bindingId,
        credentialVersion: currentBinding.credentialVersion,
        credentialDigest: currentBinding.credentialDigest,
      }), 'utf8'),
    );
    return { config, policy, acceptedBindingCredentialIdentity };
  }

  function assertPreparedEnvelopeMatchesReceipt(envelope, receipt, config, acceptedCredentialIdentity) {
    const fields = envelope.fingerprintFields;
    if (envelope.leaseId !== receipt.leaseId || envelope.preflightId !== receipt.preflightId
        || envelope.scopeDigest !== receipt.scopeDigest || envelope.policyEpoch !== receipt.policyEpoch
        || envelope.projectId !== receipt.projectId
        || envelope.executionFingerprint !== receipt.executionFingerprint
        || envelope.acceptedBindingCredentialIdentity !== acceptedCredentialIdentity
        || envelope.effectiveDeadline !== receipt.effectiveDeadline
        || envelope.mappingPin.preflightId !== receipt.preflightId
        || canonicalJson(receipt.mappingPins) !== canonicalJson([envelope.mappingPin])
        || fields.snapshotSourceId !== receipt.snapshotSourceId
        || fields.snapshotContextId !== receipt.snapshotContextId
        || fields.reviewContractSha256 !== receipt.reviewContractSha256
        || fields.protocolVersion !== config.protocolVersion || fields.storageVersion !== config.storageVersion
        || fields.buildManifestSha256 !== config.buildManifestSha256
        || fields.registrySha256 !== config.review.registrySha256
        || fields.advisorySchemaSha256 !== config.review.advisorySchemaSha256
        || fields.promptVersion !== (config.review.promptVersion ?? PROMPT_VERSION)
        || fields.classifierContractDigest !== config.engine.classifierContractDigest
        || fields.identityListDigest !== config.engine.identityListDigest
        || fields.profile.orderedReviewerIds.length !== receipt.reviewerIds.length
        || canonicalJson(fields.profile.orderedReviewerIds) !== canonicalJson(receipt.reviewerIds)
        || canonicalJson(envelope.requestRefs.map((entry) => entry.requestRef))
          !== canonicalJson(receipt.preparedPayload?.requestRefs)) {
      throw sharedError('PROTECTED_CONTENT_INVALID');
    }
    const configuredProfile = config.review.allowedProfiles.find((entry) => (
      entry.profileId === fields.profile.profileId && entry.profileVersion === fields.profile.profileVersion
    ));
    if (!configuredProfile
        || !isAllowedReviewerSet(configuredProfile, receipt.reviewerIds)) {
      throw sharedError('PROTECTED_CONTENT_INVALID');
    }
    for (const entry of fields.reviewers) {
      let reviewer;
      try { reviewer = getReviewer(entry.reviewerId); } catch { throw sharedError('PROTECTED_CONTENT_INVALID'); }
      if (canonicalJson(entry) !== canonicalJson(reviewerFingerprintEntry(reviewer, entry.requestBodyDigest))) {
        throw sharedError('PROTECTED_CONTENT_INVALID');
      }
    }
  }

  async function readValidatedPreparedExecution(receipt, authority) {
    const payload = receipt.preparedPayload;
    if (!payload || !payload.envelopeRef || !Array.isArray(payload.requestRefs)) {
      throw sharedError('PROTECTED_CONTENT_INVALID');
    }
    await validatedManagedExecution.protectedStore.verify(payload.envelopeRef, { kind: 'prepared-envelope' });
    const envelope = validatePreparedEnvelope(await validatedManagedExecution.protectedStore.get(payload.envelopeRef));
    assertPreparedEnvelopeMatchesReceipt(
      envelope, receipt, authority.config, authority.acceptedBindingCredentialIdentity,
    );
    const requests = [];
    let exactEncryptedBytes = payload.envelopeRef.encryptedBytes;
    for (const [index, entry] of envelope.requestRefs.entries()) {
      const requestRef = payload.requestRefs[index];
      // eslint-disable-next-line no-await-in-loop
      await validatedManagedExecution.protectedStore.verify(requestRef, { kind: 'dispatch-request' });
      // eslint-disable-next-line no-await-in-loop
      const value = await validatedManagedExecution.protectedStore.get(requestRef);
      if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw sharedError('PROTECTED_CONTENT_INVALID');
      const requestBytes = Buffer.from(value);
      const requestBodyDigest = validatedManagedExecution.identityDigest('shared-body-v1', requestBytes);
      if (requestBodyDigest !== entry.requestBodyDigest) throw sharedError('PROTECTED_CONTENT_INVALID');
      let parsed;
      try { parsed = JSON.parse(requestBytes.toString('utf8')); } catch { throw sharedError('PROTECTED_CONTENT_INVALID'); }
      if (Buffer.from(JSON.stringify(parsed), 'utf8').compare(requestBytes) !== 0) throw sharedError('PROTECTED_CONTENT_INVALID');
      exactEncryptedBytes += requestRef.encryptedBytes;
      if (!Number.isSafeInteger(exactEncryptedBytes)) throw sharedError('PROTECTED_CONTENT_INVALID');
      requests.push({ reviewerId: entry.reviewerId, reviewer: getReviewer(entry.reviewerId), requestRef });
    }
    return { envelope, requests, exactEncryptedBytes };
  }

  function reviewerMaximum(preflight, reviewerId) {
    const matches = preflight.itemMaxima?.filter((entry) => entry.itemId === `item-${reviewerId}`) ?? [];
    if (matches.length !== 1 || !Number.isFinite(matches[0].maxUsd) || matches[0].maxUsd < 0) {
      throw sharedError('PROTECTED_CONTENT_INVALID');
    }
    return matches[0].maxUsd;
  }

  // Sibling reviewers of one receipt run in parallel and each of their ledger steps bumps the shared
  // receipt and group revisions, so a compare-and-set built from a fresh view can lose to a sibling.
  // `operation` must re-read its view on every call; siblings interleave only a bounded number of writes.
  async function retryOnSiblingRevision(operation) {
    for (let attempt = 1; ; attempt += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop
        return await operation();
      } catch (error) {
        if (attempt >= SIBLING_REVISION_ATTEMPTS || error?.code !== 'REQUEST_REVISION_CONFLICT') throw error;
      }
    }
  }

  // Jobs a managed reconcile returned WITHOUT writing, because the ledger already held that exact
  // reconcile (a recovery replay). The above-reservation alert fires only for the call that actually
  // recorded the overrun, so a replay never raises it a second time.
  const idempotentReconcileReplays = new WeakSet();

  function createManagedOutcomeOperations({ claimExecution, reviewerId, jobId, mapping }) {
    async function freshJob(requiredStates) {
      const view = await recoverClaimedManagedView(claimExecution);
      const job = view.jobs.find((candidate) => candidate.id === jobId && candidate.reviewerId === reviewerId);
      if (!job || !requiredStates.includes(job.state)) throw sharedError('REQUEST_NOT_FOUND');
      return { view, job };
    }
    return Object.freeze({
      async recallMapping() {
        if (mapping === null) throw sharedError('REQUEST_CONTENT_LOST');
        await validatedManagedExecution.protectedStore.verify(mapping.mappingRef, { kind: 'scrub-mapping' });
        return validatedManagedExecution.protectedStore.get(mapping.mappingRef);
      },
      async reconcile({ costUsd, costKind, haltReason, aboveReservation }) {
        return retryOnSiblingRevision(async () => {
          const { view, job } = await freshJob(['INTENT_PENDING', 'RESERVED', 'RECONCILED']);
          if (job.state === 'RECONCILED') {
            if (job.costUsd !== costUsd || job.costKind !== costKind
                || job.haltReason !== haltReason
                || (job.aboveReservation === true) !== (aboveReservation === true)) throw sharedError('PROTECTED_CONTENT_INVALID');
            idempotentReconcileReplays.add(job);
            return job;
          }
          return (await validatedManagedExecution.managedLedger.reconcileManaged(jobId, {
            receiptId: view.receipt.receiptId,
            expectedReceiptRevision: view.receipt.revision,
            executionGroupId: view.executionGroup.executionGroupId,
            expectedGroupRevision: view.executionGroup.revision,
            expectedJobRevision: job.revision,
            claimId: claimExecution.claimId,
            costUsd,
            costKind,
            ...(haltReason === undefined ? {} : { haltReason }),
            ...(aboveReservation === true ? { aboveReservation: true } : {}),
            acquisitionId: claimExecution.ownerToken.acquisitionId,
          })).job;
        });
      },
      async persistAdvisory(advisoryEntry) {
        const advisoryRef = await validatedManagedExecution.resultPersistence.persistManagedAdvisory({
          receiptId: claimExecution.receiptId,
          jobId,
          advisoryEntry,
          preflightId: mapping.preflightId,
          mappingPin: { preflightId: mapping.preflightId, mappingIdentity: mapping.mappingIdentity },
          ownerToken: claimExecution.ownerToken,
        });
        managedAdvisoryRefs.set(`${claimExecution.receiptId}:${jobId}`, advisoryRef);
        return advisoryRef;
      },
      async recordHealthOutcome({ succeeded }) {
        const { job } = await freshJob(['RECONCILED']);
        const prior = job.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME;
        if (prior !== undefined) return;
        const effectId = randomUUID();
        const claimed = await validatedManagedExecution.managedLedger.claimManagedHealthEffect({
          jobId,
          expectedJobRevision: job.revision,
          effectKind: 'DISPATCH_HEALTH_OUTCOME',
          effectId,
          claimId: claimExecution.claimId,
          acquisitionId: claimExecution.ownerToken.acquisitionId,
        });
        await recordDispatchHealthOutcome({ succeeded });
        await validatedManagedExecution.managedLedger.recordManagedHealthEffect({
          jobId,
          expectedJobRevision: claimed.revision,
          effectKind: 'DISPATCH_HEALTH_OUTCOME',
          effectId,
          claimId: claimExecution.claimId,
          acquisitionId: claimExecution.ownerToken.acquisitionId,
        });
      },
    });
  }

  async function executePreparedJobs({ receiptId }, claimExecution) {
    const claim = requireClaimExecution(claimExecution, receiptId);
    const initial = await recoverClaimedManagedView(claim);
    const authority = await resolveAcceptedBackgroundAuthority(initial.receipt);
    const prepared = await readValidatedPreparedExecution(initial.receipt, authority);
    if (initial.mapping === null) throw sharedError('REQUEST_CONTENT_LOST');
    await validatedManagedExecution.protectedStore.verify(initial.mapping.mappingRef, { kind: 'scrub-mapping' });

    const reviewers = {};
    const tasks = prepared.requests.map(({ reviewerId, reviewer, requestRef }) => async () => {
      const jobId = deriveJobId(initial.receipt.leaseId, reviewerId, initial.receipt.reviewContractSha256);
      const reservationUsd = reviewerMaximum(initial.preflight, reviewerId);
      let view = await recoverClaimedManagedView(claim);
      let job = view.jobs.find((candidate) => candidate.id === jobId);
      if (job === undefined) {
        const reusable = await validatedManagedExecution.managedLedger.findManagedReusableJobs({
          executionFingerprint: initial.receipt.executionFingerprint,
          scopeDigest: initial.receipt.scopeDigest,
          reviewerId,
        });
        if (reusable.length > 0) {
          managedReuseSources.set(`${receiptId}:${reviewerId}`, reusable[0]);
          return { reviewerId, reusedJob: reusable[0] };
        }
        const reserved = await validatedManagedExecution.executionPermits.allocationGate.runReservationPhase({
          receiptId,
          claimId: claim.claimId,
          token: claim.permitToken,
        }, () => retryOnSiblingRevision(async () => {
          const current = await recoverClaimedManagedView(claim);
          const existing = current.jobs.find((candidate) => candidate.id === jobId);
          if (existing !== undefined) return { ...current, job: existing };
          return validatedManagedExecution.managedLedger.consumeManaged(
            current.lease.id,
            current.receipt.reviewContractSha256,
            {
              receiptId,
              expectedReceiptRevision: current.receipt.revision,
              executionGroupId: current.executionGroup.executionGroupId,
              expectedGroupRevision: current.executionGroup.revision,
              claimId: claim.claimId,
              jobId,
              reviewerId,
              reservationUsd,
              countsTowardDailyAllowance: reviewer.trustTier === undefined,
              acquisitionId: claim.ownerToken.acquisitionId,
            },
          );
        }));
        job = reserved.job;
      }
      if (job.state === 'RECONCILED') return { reviewerId, settledJob: job };
      if (job.state !== 'RESERVED' || job.intentState !== 'NONE') {
        return { reviewerId, recoveryRequired: true, job };
      }

      const notAfterMs = Date.parse(view.lease.expiresAt);
      const resources = await validatedManagedExecution.managedDispatchAdapter.prepareDispatchResources({
        requestRef,
        notAfterMs,
      });
      let intentCommitted = false;
      try {
        let transitioned;
        for (let attempt = 0; attempt < SIBLING_REVISION_ATTEMPTS; attempt += 1) {
          // eslint-disable-next-line no-await-in-loop
          view = await recoverClaimedManagedView(claim);
          const currentJob = view.jobs.find((candidate) => candidate.id === jobId);
          if (!currentJob || currentJob.state !== 'RESERVED' || currentJob.intentState !== 'NONE') {
            throw sharedError('REQUEST_NOT_FOUND');
          }
          // Recheck after the potentially slow resource wait and after every stale-CAS refresh.
          // eslint-disable-next-line no-await-in-loop
          const currentAuthority = await resolveAcceptedBackgroundAuthority(view.receipt);
          if (currentAuthority.acceptedBindingCredentialIdentity !== prepared.envelope.acceptedBindingCredentialIdentity) {
            throw sharedError('REQUEST_NOT_FOUND');
          }
          try {
            // eslint-disable-next-line no-await-in-loop
            transitioned = await validatedManagedExecution.managedLedger.transitionIntentPending({
              receiptId,
              expectedReceiptRevision: view.receipt.revision,
              executionGroupId: view.executionGroup.executionGroupId,
              expectedGroupRevision: view.executionGroup.revision,
              jobId,
              expectedJobRevision: currentJob.revision,
              claimId: claim.claimId,
              token: claim.permitToken,
              ownerToken: claim.ownerToken,
              acquisitionId: claim.ownerToken.acquisitionId,
            });
            break;
          } catch (error) {
            if (attempt === SIBLING_REVISION_ATTEMPTS - 1 || error?.code !== 'REQUEST_REVISION_CONFLICT') throw error;
          }
        }
        if (transitioned === undefined) throw sharedError('REQUEST_NOT_FOUND');
        const intent = Object.freeze({
          version: 1,
          receiptId,
          claimId: claim.claimId,
          jobId,
          leaseId: view.lease.id,
          reviewerId,
          executionFingerprint: view.receipt.executionFingerprint,
          scopeDigest: view.receipt.scopeDigest,
          intentState: 'INTENT_PENDING',
        });
        intentCommitted = true;
        let dispatchOutcome;
        const dispatchStartedAtMs = readMonotonicMsOrNull();
        try {
          dispatchOutcome = await validatedManagedExecution.managedDispatchAdapter.dispatchPrepared({
            requestRef,
            jobId,
            reviewerId,
            notAfterMs,
            intent,
            claimExecution: claim,
            dispatchResources: resources,
          });
        } catch (error) {
          // Kill alert: start, and do not await, one warning alert naming the fixed code and the elapsed
          // seconds. It cannot throw and cannot delay the booking below, which stays exactly as it was.
          startManagedDispatchFaultAlert({ error, startedAtMs: dispatchStartedAtMs, reviewerId });
          return haltAndClose({
            leaseId: view.lease.id,
            jobId,
            reviewerId,
            costUsd: reservationUsd,
            costKind: 'UNKNOWN_WORST_CASE_CHARGED',
            code: 'DISPATCH_UNKNOWN',
            message: `dispatch threw for reviewer ${reviewerId}: ${safeErrorDetail(error)}`,
            reviewers,
            preflightId: view.receipt.preflightId,
            reviewContractSha256: view.receipt.reviewContractSha256,
            ownerToken: claim.ownerToken,
            outcomeOperations: createManagedOutcomeOperations({
              claimExecution: claim, reviewerId, jobId, mapping: view.mapping,
            }),
          });
        }
        const result = await processDispatchOutcome({
          dispatchOutcome,
          leaseId: transitioned.lease.id,
          jobId,
          reviewer,
          reviewerSummary: { reviewerId, maxUsd: reservationUsd },
          reviewers,
          preflightId: transitioned.receipt.preflightId,
          reviewContractSha256: transitioned.receipt.reviewContractSha256,
          ownerToken: claim.ownerToken,
          outcomeOperations: createManagedOutcomeOperations({
            claimExecution: claim, reviewerId, jobId, mapping: view.mapping,
          }),
        });
        return { reviewerId, result };
      } finally {
        if (!intentCommitted) await validatedManagedExecution.managedDispatchAdapter.releaseDispatchResources(resources);
      }
    });

    const settled = await Promise.allSettled(tasks.map((run) => run()));
    if (settled.some((outcome) => outcome.status === 'rejected')) {
      // A reviewer that failed before its dispatch intent (daily allowance, cancellation, expiry, a
      // ledger error) spent nothing. Release any reservation it left so the receipt settles as a
      // terminal outcome instead of staying EXECUTING; dispatched siblings keep their reconciled cost.
      const current = await recoverClaimedManagedView(claim);
      await releaseManagedReservedJobs(claim, current.receipt.cancellationRequested === true ? 'CANCELLED' : 'CLAIM_RETIRED');
    }
    return { receipt: initial.receipt, reviewers, settled };
  }

  function managedIntentFor(receipt, job) {
    return {
      version: 1,
      receiptId: receipt.receiptId,
      claimId: job.claimId,
      jobId: job.id,
      leaseId: job.leaseId,
      reviewerId: job.reviewerId,
      executionFingerprint: job.executionFingerprint,
      scopeDigest: job.scopeDigest,
      intentState: 'INTENT_PENDING',
    };
  }

  async function recallManagedDispatchOutcome(receipt, job) {
    const intent = managedIntentFor(receipt, job);
    const intentDigest = sha256(canonicalJson(intent));
    const association = { jobId: job.id, reviewerId: job.reviewerId, intentDigest };
    let row = validatedManagedExecution.protectedStore.inspectDispatchCapture({ association });
    if (row === null) return null;
    if (row.state !== 'CAPTURE_PUBLISHED') {
      row = await validatedManagedExecution.dispatchOutcomeStore.recoverCapture({
        ...association,
        expectedRevision: row.revision,
      });
    }
    if (row?.state !== 'CAPTURE_PUBLISHED') return null;
    return validatedManagedExecution.dispatchOutcomeStore.recall({
      ...association,
      expectedRef: row.outcomeRef,
    });
  }

  async function recoverPreparedJobs({ receiptId }, claimExecution) {
    const claim = requireClaimExecution(claimExecution, receiptId);
    const initial = await recoverClaimedManagedView(claim);
    const reviewers = {};
    for (const job of initial.jobs) {
      if (!['INTENT_PENDING', 'RECONCILED'].includes(job.state)) continue;
      // eslint-disable-next-line no-await-in-loop
      const captured = await recallManagedDispatchOutcome(initial.receipt, job);
      const reviewer = getReviewer(job.reviewerId);
      const maxUsd = reviewerMaximum(initial.preflight, job.reviewerId);
      const outcomeOperations = createManagedOutcomeOperations({
        claimExecution: claim,
        reviewerId: job.reviewerId,
        jobId: job.id,
        mapping: initial.mapping,
      });
      if (job.state === 'RECONCILED' && job.costKind === 'KNOWN' && job.haltReason === undefined) {
        // eslint-disable-next-line no-await-in-loop
        const persisted = await resultStore.recallManaged({
          receiptId: initial.receipt.receiptId, sourceReceiptId: initial.receipt.receiptId, jobId: job.id, ownerToken: claim.ownerToken,
        });
        if (persisted !== null) {
          // Settled and persisted before a stop: processing its capture again would persist the same
          // advisory twice, which the protected catalog refuses. Only its first health decision may be
          // missing; the terminal candidate recalls the advisory itself.
          // eslint-disable-next-line no-await-in-loop
          await outcomeOperations.recordHealthOutcome({ succeeded: true });
          continue;
        }
      }
      if (captured === null || captured.kind === 'DISPATCHING') {
        if (job.state === 'RECONCILED') {
          // Reconcile may have committed before the first health claim. The durable job is enough
          // to make that first decision; an already-CLAIMED effect is deliberately never retried.
          // eslint-disable-next-line no-await-in-loop
          await outcomeOperations.recordHealthOutcome({
            succeeded: job.costKind === 'KNOWN' && job.haltReason === undefined,
          });
          continue;
        }
        // eslint-disable-next-line no-await-in-loop
        await haltAndClose({
          leaseId: initial.lease.id,
          jobId: job.id,
          reviewerId: job.reviewerId,
          costUsd: maxUsd,
          costKind: 'UNKNOWN_WORST_CASE_CHARGED',
          code: 'DISPATCH_UNKNOWN',
          message: `a prior managed dispatch for reviewer ${job.reviewerId} has no usable capture; refusing to redispatch`,
          reviewers,
          preflightId: initial.receipt.preflightId,
          reviewContractSha256: initial.receipt.reviewContractSha256,
          ownerToken: claim.ownerToken,
          outcomeOperations,
        });
        continue;
      }
      // eslint-disable-next-line no-await-in-loop
      await processDispatchOutcome({
        dispatchOutcome: captured,
        leaseId: initial.lease.id,
        jobId: job.id,
        reviewer,
        reviewerSummary: { reviewerId: job.reviewerId, maxUsd },
        reviewers,
        preflightId: initial.receipt.preflightId,
        reviewContractSha256: initial.receipt.reviewContractSha256,
        ownerToken: claim.ownerToken,
        outcomeOperations,
      });
    }
    return { receipt: initial.receipt, reviewers };
  }

  async function releaseManagedReservedJobs(claimExecution, reason) {
    while (true) {
      const view = await recoverClaimedManagedView(claimExecution);
      const job = view.jobs.find((candidate) => candidate.state === 'RESERVED' && candidate.intentState === 'NONE');
      if (!job) return view;
      try {
        await validatedManagedExecution.managedLedger.releaseCancellableReservation({
          receiptId: view.receipt.receiptId,
          expectedReceiptRevision: view.receipt.revision,
          executionGroupId: view.executionGroup.executionGroupId,
          expectedGroupRevision: view.executionGroup.revision,
          jobId: job.id,
          expectedJobRevision: job.revision,
          claimId: claimExecution.claimId,
          reason,
          acquisitionId: claimExecution.ownerToken.acquisitionId,
        });
      } catch (error) {
        if (error?.code !== 'REQUEST_REVISION_CONFLICT') throw error;
      }
    }
  }

  function terminalReviewerEntry(job, reviewerId) {
    if (job.state === 'CANCELLED_ZERO_DISPATCH') {
      return { reviewerId, jobId: job.id, state: job.state, costUsd: 0, costKind: 'RECOVERED_STATUS_ONLY' };
    }
    const entry = advisoryCache.get(job.id);
    if (entry?.reviewerId === reviewerId && entry?.jobId === job.id) return entry;
    const code = job.haltReason
      ?? (job.costKind === 'UNKNOWN_WORST_CASE_CHARGED' ? 'DISPATCH_UNKNOWN'
        : job.costKind === 'ZERO_ON_TRANSPORT_FAILURE' || job.costKind === 'ZERO_ON_PROVIDER_REJECTION' ? 'TRANSPORT_FAILURE'
          : undefined);
    let error;
    if (code !== undefined) {
      try { error = { code, message: sharedError(code).message }; } catch { error = { code, message: 'managed reviewer failed' }; }
    }
    return {
      reviewerId, jobId: job.id, state: job.state, costUsd: job.costUsd, costKind: job.costKind,
      ...(error === undefined ? {} : { error }),
    };
  }

  function overflowTerminalCandidate(candidate) {
    const { terminal } = candidate;
    const reviewers = Object.fromEntries(Object.entries(terminal.projection.value.reviewers).map(([reviewerId, entry]) => {
      const { advisory: _advisory, ...status } = entry;
      return [reviewerId, status];
    }));
    const advisoryAssociations = terminal.advisoryAssociations.map(({ advisoryRef: _ref, ...association }) => ({
      ...association, contentAvailable: false,
    }));
    const error = sharedError('PROTECTED_CONTENT_TOO_LARGE');
    return {
      outcomeKind: 'REVIEW_ERROR', outcomeErrorCode: error.code, leaseDisposition: candidate.leaseDisposition,
      settledStatus: candidate.settledStatus, advisoryAssociations,
      terminal: {
        ...terminal,
        outcome: { kind: 'REVIEW_ERROR', error: { code: error.code, message: error.message } },
        projection: { schema: 'RESULT_OUTPUT_V1', value: { leaseId: terminal.leaseId, state: 'MANAGED_ACTIVE', reviewers } },
        advisoryAssociations,
      },
    };
  }

  async function verifiedReusableTerminalSource(job, receipt, targetLease, reviewerId) {
    // A follower carries no native target job; even a target-native candidate is re-resolved by
    // its deterministic job id so a ledger view cannot manufacture terminal metadata.
    const sourceLease = job.receiptId === receipt.receiptId ? targetLease : await leaseStore.getLease(job.leaseId);
    if (sourceLease === null || sourceLease.id !== job.leaseId
        || sourceLease.reviewContractSha256 !== receipt.reviewContractSha256
        || sourceLease.profile !== targetLease.profile || sourceLease.profileVersion !== targetLease.profileVersion
        || sourceLease.schemaSha256 !== targetLease.schemaSha256 || sourceLease.registrySha256 !== targetLease.registrySha256
        || sourceLease.managedBinding?.receiptId !== job.receiptId
        || sourceLease.managedBinding?.scopeDigest !== receipt.scopeDigest
        || sourceLease.managedBinding?.executionFingerprint !== receipt.executionFingerprint) return null;
    const jobId = deriveJobId(sourceLease.id, reviewerId, sourceLease.reviewContractSha256);
    const sourceJob = await leaseStore.getJob(jobId);
    if (sourceJob === null || sourceJob.id !== jobId || sourceJob.receiptId !== job.receiptId
        || sourceJob.leaseId !== sourceLease.id || sourceJob.reviewerId !== reviewerId
        || sourceJob.reviewContractSha256 !== sourceLease.reviewContractSha256
        || sourceJob.executionFingerprint !== receipt.executionFingerprint || sourceJob.scopeDigest !== receipt.scopeDigest
        || !['RECONCILED', 'CANCELLED_ZERO_DISPATCH'].includes(sourceJob.state)) return null;
    return sourceJob;
  }

  async function terminalCandidateForView(view, ownerToken) {
    const { receipt, lease } = view;
    const jobs = new Map(view.jobs.map((job) => [job.reviewerId, job]));
    const reviewers = {};
    const associations = [];
    let returned = true;
    for (const reviewerId of receipt.reviewerIds) {
      let job = jobs.get(reviewerId);
      if (job === undefined) {
        job = managedReuseSources.get(`${receipt.receiptId}:${reviewerId}`);
        if (job === undefined) {
          // A cold follower has no target-lease job. This lookup returns only exact persisted
          // fingerprint/scope matches; source content still requires recallManaged below.
          // eslint-disable-next-line no-await-in-loop
          const reusable = await validatedManagedExecution.managedLedger.findManagedReusableJobs({
            executionFingerprint: receipt.executionFingerprint, scopeDigest: receipt.scopeDigest, reviewerId,
          });
          if (reusable.length === 1) job = reusable[0];
        }
        if (job !== undefined) managedReuseSources.set(`${receipt.receiptId}:${reviewerId}`, job);
      }
      if (job === undefined) {
        // Settlement runs only after execution, so a reviewer with neither a job nor a reusable source
        // was never reserved and never dispatched (a refused consume, a cancellation, an expiry). The
        // terminal contract records it as a job-less association that the projection omits.
        associations.push({ reviewerId, contentAvailable: false });
        returned = false;
        continue;
      }
      if (!['RECONCILED', 'CANCELLED_ZERO_DISPATCH'].includes(job.state)) return null;
      // eslint-disable-next-line no-await-in-loop
      job = await verifiedReusableTerminalSource(job, receipt, lease, reviewerId);
      if (job === null) return null;
      const sourceReceiptId = job.receiptId;
      let entry = terminalReviewerEntry(job, reviewerId);
      if (sourceReceiptId !== receipt.receiptId) entry = { ...entry, costKind: 'REUSED_FROM_PRIOR_LEASE' };
      reviewers[reviewerId] = entry;
      let advisoryRef = managedAdvisoryRefs.get(`${sourceReceiptId}:${job.id}`);
      if (advisoryRef === undefined && job.state === 'RECONCILED' && job.costKind === 'KNOWN' && job.haltReason === undefined) {
        // Before the immutable publication exists, this is the only recovery read allowed: the
        // constructor-wired store verifies the exact current claim/job association and returns its
        // associated ref together with the advisory. It is never a catalog capability.
        // eslint-disable-next-line no-await-in-loop
        const recovered = await resultStore.recallManaged({
          receiptId: receipt.receiptId, sourceReceiptId, jobId: job.id, ownerToken,
        });
        if (recovered !== null) {
          advisoryRef = recovered.advisoryRef;
          entry = sourceReceiptId === receipt.receiptId
            ? recovered.advisoryEntry
            : { ...recovered.advisoryEntry, costKind: 'REUSED_FROM_PRIOR_LEASE' };
          reviewers[reviewerId] = entry;
          managedAdvisoryRefs.set(`${sourceReceiptId}:${job.id}`, advisoryRef);
          advisoryCache.set(job.id, entry);
        }
      }
      const available = job.state === 'RECONCILED' && job.costKind === 'KNOWN' && job.haltReason === undefined
        && entry.advisory !== undefined && advisoryRef !== undefined;
      if (!available) returned = false;
      associations.push({ reviewerId, contentAvailable: available,
        sourceReceiptId, jobId: job.id, ...(available ? { advisoryRef } : {}) });
    }
    const settledStatus = { ...managedStatus(lease), reservedUsd: 0 };
    // The ledger accepts a CANCELLED publication for a cancelled receipt, and only for one.
    const cancelled = receipt.cancellationRequested === true;
    // A partial result keeps the advisories that did come back, as a HALTED review (the terminal contract
    // allows HALTED with unavailable reviewers); only a result with no usable advisory is an error.
    const partial = !returned && associations.some((association) => association.contentAvailable);
    if ((returned || partial) && !cancelled) {
      const projected = returned ? reviewers : Object.fromEntries(Object.entries(reviewers).map(([reviewerId, entry]) => {
        if (associations.find((association) => association.reviewerId === reviewerId)?.contentAvailable) return [reviewerId, entry];
        const { advisory: _advisory, ...status } = entry;
        return [reviewerId, status];
      }));
      const haltError = partial
        ? (Object.values(projected).find((entry) => entry.advisory === undefined && entry.error !== undefined)?.error
          ?? { code: 'DISPATCH_UNKNOWN', message: 'A reviewer did not return a review.' })
        : undefined;
      const candidate = {
        outcomeKind: 'REVIEW_RETURNED', leaseDisposition: 'CLOSED', settledStatus, advisoryAssociations: associations,
        terminal: {
          version: 'shared-review-terminal-v1', receiptId: receipt.receiptId, leaseId: receipt.leaseId,
          preflightId: receipt.preflightId, snapshotSourceId: receipt.snapshotSourceId,
          snapshotContextId: receipt.snapshotContextId, reviewContractSha256: receipt.reviewContractSha256,
          completedAt: new Date(Number(clock())).toISOString(), outcome: { kind: 'REVIEW_RETURNED' }, settledStatus,
          projection: { schema: 'REVIEW_OUTPUT_V1', value: { state: partial ? 'HALTED' : 'PASSED', leaseId: receipt.leaseId,
            preflightId: receipt.preflightId, reviewContractSha256: receipt.reviewContractSha256, reviewers: projected,
            ...(partial ? { error: haltError } : {}) } }, advisoryAssociations: associations,
        },
      };
      return Buffer.byteLength(canonicalJson(candidate.terminal), 'utf8') > 134_217_728
        ? overflowTerminalCandidate(candidate)
        : candidate;
    }
    const stripped = Object.fromEntries(Object.entries(reviewers).map(([reviewerId, entry]) => {
      const { advisory: _advisory, ...status } = entry;
      return [reviewerId, status];
    }));
    const unavailable = associations.map(({ advisoryRef: _ref, ...association }) => ({ ...association, contentAvailable: false }));
    const kind = cancelled ? 'CANCELLED' : 'REVIEW_ERROR';
    const error = sharedError(cancelled ? 'REQUEST_CANCELLED' : 'REQUEST_FAILED');
    return {
      outcomeKind: kind, outcomeErrorCode: error.code, leaseDisposition: cancelled ? 'CANCELLED' : 'CLOSED', settledStatus,
      advisoryAssociations: unavailable,
      terminal: {
        version: 'shared-review-terminal-v1', receiptId: receipt.receiptId, leaseId: receipt.leaseId,
        preflightId: receipt.preflightId, snapshotSourceId: receipt.snapshotSourceId,
        snapshotContextId: receipt.snapshotContextId, reviewContractSha256: receipt.reviewContractSha256,
        completedAt: new Date(Number(clock())).toISOString(), outcome: { kind, error: { code: error.code, message: error.message } },
        settledStatus, projection: { schema: 'RESULT_OUTPUT_V1', value: { leaseId: receipt.leaseId, state: 'MANAGED_ACTIVE', reviewers: stripped } },
        advisoryAssociations: unavailable,
      },
    };
  }

  function transientTerminalPersistenceFailure(error) {
    // Terminal record/replay errors leave the candidate and receipt recoverable.  The
    // terminal contract calls out ordinary filesystem/DPAPI pressure as retryable;
    // coded policy, claim, and record-shape failures remain visible to the caller.
    return error?.code === undefined || [
      'REQUEST_REVISION_CONFLICT',
      'SERVICE_UNAVAILABLE',
      'LEDGER_BUSY',
      'EXECUTOR_PERSISTENCE_UNAVAILABLE',
      'EIO',
      'EACCES',
      'EPERM',
      'EBUSY',
      'ENOSPC',
      'EMFILE',
      'ENFILE',
      'ETIMEDOUT',
      'ABORT_ERR',
    ].includes(error.code);
  }

  async function finalizeManagedTerminal(claimExecution, attempt = 1) {
    let view = await recoverClaimedManagedView(claimExecution);
    // Every null return leaves the receipt RECOVERY_PENDING, so the durable state always agrees with the
    // caller's result and recovery (the scheduler's retry, or a restart) settles it later. The view is
    // re-read on each attempt: a caller cancel or a follower joining the group moves the revisions.
    async function pending() {
      return retryOnSiblingRevision(async () => {
        const current = await recoverClaimedManagedView(claimExecution);
        if (current.receipt.state === 'RECOVERY_PENDING') return current;
        const marked = await validatedManagedExecution.managedLedger.markManagedRecoveryPending({
          receiptId: current.receipt.receiptId, expectedRevision: current.receipt.revision,
          executionGroupId: current.executionGroup.executionGroupId, expectedGroupRevision: current.executionGroup.revision,
          claimId: claimExecution.claimId, acquisitionId: claimExecution.ownerToken.acquisitionId,
        });
        return { ...current, receipt: marked.receipt, executionGroup: marked.executionGroup };
      });
    }
    if (view.receipt.terminalPublication === undefined) {
      const candidate = await terminalCandidateForView(view, claimExecution.ownerToken);
      if (candidate === null) {
        await pending();
        return null;
      }
      const publicationId = randomUUID();
      const completedAt = candidate.terminal.completedAt;
      let begun;
      try {
        begun = await validatedManagedExecution.managedLedger.beginTerminalPublication({
          receiptId: view.receipt.receiptId, expectedReceiptRevision: view.receipt.revision,
          executionGroupId: view.executionGroup.executionGroupId, expectedGroupRevision: view.executionGroup.revision,
          claimId: claimExecution.claimId, publicationId, completedAt, outcomeKind: candidate.outcomeKind,
          ...(candidate.outcomeErrorCode === undefined ? {} : { outcomeErrorCode: candidate.outcomeErrorCode }),
          leaseDisposition: candidate.leaseDisposition, settledStatus: candidate.settledStatus,
          advisoryAssociations: candidate.advisoryAssociations, acquisitionId: claimExecution.ownerToken.acquisitionId,
        });
      } catch (error) {
        // A concurrent cancel or admission moved the revisions after this view was read: rebuild the
        // candidate from a fresh view (a cancel changes its outcome kind) rather than fail the claim.
        if (error?.code !== 'REQUEST_REVISION_CONFLICT' || attempt >= SIBLING_REVISION_ATTEMPTS) throw error;
        return finalizeManagedTerminal(claimExecution, attempt + 1);
      }
      view = { ...view, receipt: begun.receipt, executionGroup: begun.executionGroup };
      try {
        await validatedManagedExecution.resultPersistence.persistManagedTerminal({
          receiptId: view.receipt.receiptId, publicationId, terminal: candidate.terminal, ownerToken: claimExecution.ownerToken,
        });
      } catch (error) {
        if (error?.code === 'PROTECTED_CONTENT_INVALID') throw error;
        await pending();
        return null;
      }
    }
    const publication = view.receipt.terminalPublication;
    let recalled;
    try {
      recalled = await validatedManagedExecution.terminalStore.recallPublication({
        receiptId: view.receipt.receiptId, publicationId: publication.publicationId, ownerToken: claimExecution.ownerToken,
      });
    } catch (error) {
      if (error?.code !== 'PROTECTED_CONTENT_INVALID') {
        if (!transientTerminalPersistenceFailure(error)) throw error;
        await pending();
        return null;
      }
      try {
        return await validatedManagedExecution.managedLedger.terminalizeTerminalPublicationAsContentLost({
          receiptId: view.receipt.receiptId, expectedRevision: view.receipt.revision,
          executionGroupId: view.executionGroup.executionGroupId, expectedGroupRevision: view.executionGroup.revision,
          claimId: claimExecution.claimId, publicationId: publication.publicationId,
          acquisitionId: claimExecution.ownerToken.acquisitionId,
        });
      } catch (lossError) {
        if (!transientTerminalPersistenceFailure(lossError)) throw lossError;
        await pending();
        return null;
      }
    }
    if (recalled === null) {
      await pending();
      return null;
    }
    try {
      return await validatedManagedExecution.managedLedger.terminalizeReceipt({
        receiptId: view.receipt.receiptId, expectedRevision: view.receipt.revision,
        executionGroupId: view.executionGroup.executionGroupId, expectedGroupRevision: view.executionGroup.revision,
        claimId: claimExecution.claimId, publicationId: publication.publicationId,
        acquisitionId: claimExecution.ownerToken.acquisitionId,
      });
    } catch (error) {
      if (!transientTerminalPersistenceFailure(error)) throw error;
      await pending();
      return null;
    }
  }

  async function executePreparedReview(selector, claimExecution) {
    const execution = await executePreparedJobs(selector ?? {}, claimExecution);
    const terminal = await finalizeManagedTerminal(requireClaimExecution(claimExecution, execution.receipt.receiptId));
    return deepFreeze({ receiptId: execution.receipt.receiptId, state: terminal === null ? 'RECOVERY_PENDING' : 'TERMINAL' });
  }

  async function recoverManagedReceipt(selector, claimExecution) {
    const claim = requireClaimExecution(claimExecution, selector?.receiptId);
    const opening = await recoverClaimedManagedView(claim);
    if (opening.receipt.terminalPublication !== undefined) {
      const terminal = await finalizeManagedTerminal(claim);
      return deepFreeze({ receiptId: opening.receipt.receiptId, state: terminal === null ? 'RECOVERY_PENDING' : 'TERMINAL' });
    }
    await recoverPreparedJobs(selector ?? {}, claim);
    let view = await recoverClaimedManagedView(claim);
    const reserved = view.jobs.some((job) => job.state === 'RESERVED' && job.intentState === 'NONE');
    if (reserved) {
      let canCreateIntent = true;
      try { await resolveAcceptedBackgroundAuthority(view.receipt); } catch { canCreateIntent = false; }
      if (view.receipt.cancellationRequested === true) {
        view = await releaseManagedReservedJobs(claim, 'CANCELLED');
      } else if (!canCreateIntent) {
        view = await releaseManagedReservedJobs(claim, 'CLAIM_RETIRED');
      } else if (view.receipt.startedAt === undefined && Date.parse(view.receipt.effectiveDeadline) <= Number(clock())) {
        view = await releaseManagedReservedJobs(claim, 'EXPIRED');
      } else {
        await executePreparedJobs(selector ?? {}, claim);
        view = await recoverClaimedManagedView(claim);
      }
    }
    const terminal = await finalizeManagedTerminal(claim);
    return deepFreeze({ receiptId: view.receipt.receiptId, state: terminal === null ? 'RECOVERY_PENDING' : 'TERMINAL' });
  }

  // Mapping cleanup accepts durable content only when its identity, settled metadata and schema
  // match the ledger job. A parseable result file alone does not make a mapping disposable.
  function hasDurableAdvisory(entry, job, reviewerId) {
    if (!entry || !job || job.state !== 'RECONCILED' || job.costKind !== 'KNOWN'
        || job.haltReason !== undefined || entry.error !== undefined
        || entry.jobId !== job.id || entry.reviewerId !== reviewerId
        || entry.state !== 'RECONCILED' || entry.costKind !== 'KNOWN'
        || entry.costUsd !== job.costUsd) return false;
    try { return validateAdvisoryContent(JSON.stringify(entry.advisory)).ok; } catch { return false; }
  }

  function mappingNoLongerNeeded(job, durable, reviewerId, expectedJobId) {
    if (!job || job.id !== expectedJobId || job.state !== 'RECONCILED'
        || (job.reviewerId !== undefined && job.reviewerId !== reviewerId)) return false;
    if (typeof job.haltReason === 'string' && job.haltReason.length > 0) return true;
    if (['UNKNOWN_WORST_CASE_CHARGED', 'ZERO_ON_TRANSPORT_FAILURE', 'ZERO_ON_PROVIDER_REJECTION'].includes(job.costKind)) return true;
    return hasDurableAdvisory(durable, job, reviewerId);
  }

  // Content recovery for an already-reconciled job is deliberately separate from processDispatchOutcome. This job's
  // money has already settled; even an invalid capture must never reconcile or close it again.
  async function recoverReconciledAdvisory(job) {
    if (job.state !== 'RECONCILED' || job.costKind !== 'KNOWN' || job.haltReason !== undefined) return null;
    // Keep ledger reads outside content-refusal catches: LEDGER_BUSY must remain observable.
    const lease = await leaseStore.getLease(job.leaseId);
    if (!lease || lease.id !== job.leaseId || lease.reviewContractSha256 !== job.reviewContractSha256) return null;
    const preflightId = lease.preflightIds?.[0];
    if (typeof preflightId !== 'string') return null;
    const preflight = await leaseStore.getPreflight(preflightId);
    if (!preflight || preflight.id !== preflightId || preflight.reviewContractSha256 !== job.reviewContractSha256
        || preflight.schemaSha256 !== SCHEMA_SHA256 || preflight.registrySha256 !== REGISTRY_SHA256
        || !Array.isArray(preflight.itemMaxima)) return null;
    const item = preflight.itemMaxima.find((candidate) => typeof candidate.itemId === 'string'
      && deriveJobId(job.leaseId, candidate.itemId.replace(/^item-/, ''), job.reviewContractSha256) === job.id);
    if (!item) return null;
    const reviewerId = item.itemId.replace(/^item-/, '');
    if (job.reviewerId !== undefined && job.reviewerId !== reviewerId) return null;
    try {
      const reviewer = getReviewer(reviewerId);
      const seedMapping = await scrubMappingStore.recall({ preflightId });
      // A concurrent owner may have saved content and deleted the mapping after our first
      // miss. Snapshot the mapping first, then prefer that newly durable restored content.
      const durable = await resultStore.recall({ jobId: job.id });
      if (hasDurableAdvisory(durable, job, reviewerId)) return durable;
      const captured = await dispatchOutcomeStore.recall({ jobId: job.id });
      if (captured?.kind !== 'RESPONSE') return null;
      const body = decodeEnvelopeBody(captured);
      const cost = extractFiniteNonnegativeCost(body);
      // A job flagged aboveReservation was reconciled at a KNOWN cost above
      // its reservation on purpose; only an unflagged job's cost must sit within its bound.
      const withinBound = job.aboveReservation === true || (cost <= job.reservationUsd && cost <= item.maxUsd);
      if (cost === null || cost !== job.costUsd || !Number.isFinite(job.reservationUsd)
          || !Number.isFinite(item.maxUsd) || !withinBound
          || body.provider !== reviewer.expectedProvider) return null;
      if (!isAcceptedReviewCompletion(body)) return null;
      const content = selectContentTextForValidation(body?.choices?.[0]?.message?.content, reviewer);
      const checked = typeof content === 'string' ? validateAdvisoryContent(content) : { ok: false };
      if (!checked.ok) return null;
      const findings = await Promise.all(JSON.parse(content).findings.map(
        (finding) => desubstituteFinding(finding, { preflightId, seedMapping: seedMapping ?? undefined }),
      ));
      return {
        reviewerId, jobId: job.id, state: 'RECONCILED', costUsd: job.costUsd, costKind: 'KNOWN',
        provider: body.provider, model: reviewer.model, advisory: { verdict: checked.verdict, findings },
      };
    } catch {
      // Capture/mapping/content failures leave the settled status intact, without exposing data.
      return null;
    }
  }

  async function rememberRecoveredAdvisory(entry, ownerToken) {
    requireOwnerToken(ownerToken);
    if (!ownerLock.isOwner() || ownerLock.acquisitionId !== ownerToken.acquisitionId) return;
    try {
      await resultStore.record({ jobId: entry.jobId, advisory: entry });
      advisoryCache.set(entry.jobId, entry);
    } catch (error) {
      try {
        process.stderr.write(`openrouter-review-engine: resultStore-record-failed jobId=${entry.jobId} error=${safeErrorDetail(error)}\n`);
      } catch { /* Logging cannot invalidate already-paid-for content. */ }
    }
  }

  async function recallAdvisory(job, ownerToken) {
    const durable = await resultStore.recall({ jobId: job.id });
    const entry = advisoryCache.get(job.id) ?? durable ?? await recoverReconciledAdvisory(job);
    // Always inspect durability, even on a live cache hit whose original write failed.
    if (entry?.advisory && !durable && ownerToken !== undefined) {
      await rememberRecoveredAdvisory(entry, ownerToken);
    }
    return entry;
  }

  // Shared by review and result: choose the first usable reconciled advisory in ledger order.
  // A valid capture can fill a content gap; only a caller with an explicit token may persist it.
  async function findReusableAdvisory(priorJobs, ownerToken) {
    for (const priorJob of priorJobs) {
      if (priorJob.state !== 'RECONCILED' || priorJob.haltReason !== undefined) continue;
      // eslint-disable-next-line no-await-in-loop
      const content = await recallAdvisory(priorJob, ownerToken);
      if (content && content.advisory) return content;
    }
    return null;
  }

  /**
   * In-process fast path first (unchanged); on a miss, falls back to the
   * durable ledger preflight record plus the durable reviewContext store,
   * reconstructing the exact same shape the in-memory cache would have held
   * -- so a caller retrying with the ORIGINAL preflightId after a real
   * process restart still recovers, not just a caller able to mint a fresh
   * one. A recovered entry is re-populated into the in-memory Map so a
   * SAME-process repeat hits the fast path without another two reads.
   * `reviewContext` can legitimately recover as `undefined` if its own
   * durable write never landed (best-effort, see `preflight()` below) --
   * that degrades a caller who omits reviewContext at review()-time to a
   * SOURCE_INVALID, but never silently accepts wrong content, and
   * never affects a caller (like authorizeWorkflow()) that never needed
   * reviewContext in the first place.
   */
  async function getCachedPreflight(preflightId) {
    // Same opaque-ID shape lease-store.mjs's own requireId() enforces (never
    // reached via the real MCP tool schema, which caps this the same way --
    // this guard is defense-in-depth for a direct engine caller, so an
    // oversized ID degrades to the same "unknown" null a genuinely missing
    // one already returns, rather than an inconsistent raw TypeError leaking
    // out of leaseStore.getPreflight() on the durable-fallback path below.
    if (typeof preflightId !== 'string' || preflightId.length === 0 || preflightId.length > 256) return null;
    const cached = preflightCache.get(preflightId);
    if (cached) {
      if (Date.parse(cached.expiresAt) <= Number(clock())) {
        preflightCache.delete(preflightId);
        return null;
      }
      return cached;
    }

    const record = await withLedgerBusyTranslation(() => leaseStore.getPreflight(preflightId));
    if (!record) return null;
    if (Date.parse(record.expiresAt) <= Number(clock())) return null;

    const reviewContext = await preflightContextStore.recall({ preflightId });
    const recovered = {
      reviewContractSha256: record.reviewContractSha256,
      sourceSha256: record.sourceSha256,
      rawSourceSha256: record.rawSourceSha256,
      profile: record.profile,
      profileVersion: record.profileVersion,
      reviewContext: reviewContext ?? undefined,
      itemMaxima: record.itemMaxima,
      requestedUsd: record.requestedUsd,
      expiresAt: record.expiresAt,
      reviewers: reviewersFromItemMaxima(record.itemMaxima),
    };
    preflightCache.set(preflightId, recovered);
    return recovered;
  }

  /**
   * The single choke point every caller of loadReviewSource() goes through --
   * both preflight() and review() call THIS, never loadReviewSource()
   * directly -- so scrubbing cannot be bypassed by construction, not by
   * convention. Recomputes sourceSha256 from the SCRUBBED text before
   * returning: scrubbing source.text without also updating
   * source.sourceSha256 would make preflightReview()'s own independent
   * re-hash-and-compare check (source-contract.mjs's `source.sourceSha256
   * !== sha256(source.text)` guard) throw on the very first real
   * substitution. Throws CONTENT_BLOCKED (never SOURCE_INVALID) when the scrub
   * engine hard-blocks, so callers can distinguish "this content is unsafe
   * to send" from "this content was malformed."
   */
  async function loadAndScrubSource({ source_text, source_path, sourcePolicy: policy, preflightId }) {
    const source = await loadReviewSource({ source_text, source_path }, policy);
    // Captured BEFORE scrubbing overwrites source.sourceSha256 below: source-contract.mjs's
    // sourceFromText/sourceFromPath already hash the raw text at this point, and that raw hash is
    // the one thing that stays identical across repeated preflight() calls for the same document
    // -- unlike the scrubbed hash computed below, which embeds preflightId-keyed placeholder
    // substitution and therefore differs on every call. See lease-store.mjs's
    // countLeasesForRawSource for why this matters (the repeat-authorization justification gate).
    const rawSourceSha256 = source.sourceSha256;
    const scrubResult = await scrubEngine.scrub({ text: source.text, preflightId });
    if (scrubResult.blocked) {
      throw new ReviewEngineError(
        'CONTENT_BLOCKED',
        `content blocked before send: ${scrubResult.blockedCategories.join(', ')}`,
      );
    }
    return { ...source, rawText: source.text, text: scrubResult.scrubbedText, sourceSha256: sha256(scrubResult.scrubbedText), rawSourceSha256 };
  }

  /**
   * Reverse-substitution over one value from a reviewer's finding object.
   * Findings carry both plain strings (root_cause, section, ...) and a
   * REQUIRED, non-empty array of strings (`evidence` -- see
   * advisory-schema.mjs's REQUIRED_FINDING_FIELDS/RESPONSE_FORMAT). evidence
   * is exactly where a reviewer is most likely to quote a scrubbed span
   * verbatim ("evidence: ['line 42: account ACCOUNT_a1b2c3d4 is malformed']"),
   * so a version of this helper that only handled `typeof value === 'string'`
   * would leave literal placeholder tokens sitting in every finding's
   * evidence array, un-reversed -- not a PII leak, but a broken, confusing
   * result for every real finding (evidence is non-empty by schema, so this
   * is not a rare edge case). Recurses one level into arrays of strings to
   * close that; any other type (a nested object, a number) is returned
   * unchanged, since the schema never allows one.
   */
  async function desubstituteValue(value, { preflightId, seedMapping }) {
    if (typeof value === 'string') return scrubEngine.desubstitute({ text: value, preflightId, seedMapping });
    if (Array.isArray(value)) return Promise.all(value.map((item) => desubstituteValue(item, { preflightId, seedMapping })));
    return value;
  }

  async function desubstituteFinding(finding, { preflightId, seedMapping }) {
    const restored = {};
    for (const [key, value] of Object.entries(finding)) {
      // eslint-disable-next-line no-await-in-loop
      restored[key] = await desubstituteValue(value, { preflightId, seedMapping });
    }
    return restored;
  }

  async function preflight({ source_text, source_path, profile, changeKinds, reviewContext = '' } = {}) {
    if (typeof reviewContext !== 'string') throw new ReviewEngineError('SOURCE_INVALID', 'reviewContext must be a string');
    // Minted up front, not left to leaseStore.createPreflight()'s own default
    // (input.id === undefined ? randomUUID() : ...), so both the source scrub
    // below and the reviewContext scrub use the SAME preflightId the caller
    // ultimately receives. This is load-bearing, not cosmetic: scrub-engine.
    // mjs derives every placeholder token via an HMAC keyed on preflightId,
    // so review()'s later re-scrub of the identical source_text/reviewContext
    // (see review() below) must land on the exact same placeholder tokens
    // this call embeds into the bound reviewContractSha256 -- otherwise a
    // legitimate, byte-identical resubmit of substitution-eligible content
    // would spuriously CONTRACT_CHANGED (a throwaway
    // scratch ID here, re-keyed into the durable mapping store only AFTER
    // createPreflight() returns its own separately-generated ID, would leave
    // the scrubbedText itself computed under a DIFFERENT HMAC key than
    // review() re-derives later, changing sourceSha256 on every single
    // review() call that contains any substitution-eligible content).
    // leaseStore.createPreflight() already accepts an explicit `id`, so this
    // reuses that existing hook rather than inventing new machinery.
    const preflightId = randomUUID();
    let source;
    try {
      source = await loadAndScrubSource({ source_text, source_path, sourcePolicy, preflightId });
    } catch (error) {
      if (error instanceof ReviewEngineError) throw error;
      throw new ReviewEngineError('SOURCE_INVALID', error.message);
    }

    const contextScrub = await scrubEngine.scrub({ text: reviewContext, preflightId });
    if (contextScrub.blocked) {
      throw new ReviewEngineError('CONTENT_BLOCKED', `reviewContext blocked before send: ${contextScrub.blockedCategories.join(', ')}`);
    }
    reviewContext = contextScrub.scrubbedText;
    // scrub-engine.mjs's mappingCache accumulates per preflightId: this SECOND scrub() call
    // under the same preflightId already returns the mapping merged from
    // BOTH the source scrub above and this reviewContext scrub, so capturing
    // it here means the durable-store write below never needs a third,
    // wasteful dummy scrub() call (which would also fire two more
    // unnecessary Ollama requests).
    const accumulatedMapping = contextScrub.mapping;

    let computed;
    try {
      computed = preflightReview({ source, profile, reviewContext, policy: preflightPolicy, changeKinds });
    } catch (error) {
      throw new ReviewEngineError('SOURCE_INVALID', error.message);
    }

    const reviewContextSha256 = sha256(reviewContext);
    const reviewContractSha256 = buildReviewContract({
      sourceSha256: computed.sourceSha256,
      reviewContextSha256,
      profile: computed.profile,
      profileVersion: computed.profileVersion,
    });

    const expiresAt = new Date(Number(clock()) + preflightTtlMs).toISOString();
    const itemMaxima = computed.reviewers.map((reviewer) => ({ itemId: `item-${reviewer.reviewerId}`, maxUsd: reviewer.maxUsd }));
    const requestedUsd = computed.totalMaxUsd;

    const record = await withLedgerBusyTranslation(() => leaseStore.createPreflight({
      id: preflightId,
      reviewContractSha256,
      sourceSha256: computed.sourceSha256,
      rawSourceSha256: source.rawSourceSha256,
      profile: computed.profile,
      profileVersion: computed.profileVersion,
      schemaSha256: SCHEMA_SHA256,
      registrySha256: REGISTRY_SHA256,
      itemMaxima,
      requestedUsd,
      expiresAt,
    }));

    const reviewers = computed.reviewers.map((reviewer) => ({
      reviewerId: reviewer.reviewerId,
      model: reviewer.model,
      route: reviewer.route,
      maxUsd: reviewer.maxUsd,
    }));

    preflightCache.set(record.id, {
      reviewContractSha256,
      sourceSha256: computed.sourceSha256,
      rawSourceSha256: source.rawSourceSha256,
      profile: computed.profile,
      profileVersion: computed.profileVersion,
      reviewContext,
      itemMaxima,
      requestedUsd,
      expiresAt: record.expiresAt,
      reviewers,
    });

    // Best-effort durability only, matching resultStore.record()'s own
    // established convention below: a local disk failure here must not turn
    // an already-computed, valid preflight response into a reported failure
    // -- the in-memory cache above already has this process covered; a local
    // write failure only narrows (never breaks) cross-process recovery,
    // specifically the reviewContext-omitted case in review().
    try {
      await preflightContextStore.record({ preflightId: record.id, reviewContext });
    } catch (error) {
      try {
        process.stderr.write(
          `openrouter-review-engine: preflightContextStore-record-failed preflightId=${record.id} error=${safeErrorDetail(error)}\n`,
        );
      } catch {
        // A logging failure itself must never abort a successful preflight.
      }
    }

    // Best-effort durability, matching preflightContextStore.record()'s own
    // established convention immediately above: a local disk failure here
    // must not turn an already-computed, valid preflight response into a
    // reported failure -- the in-process scrubEngine mappingCache already has
    // THIS process covered (see loadAndScrubSource/scrub() above), so a
    // same-process desubstitute() call still works even if this write fails.
    // Stated plainly, not softened: if this write fails AND a later
    // reverse-substitution (processDispatchOutcome() below, or result())
    // ever runs in a DIFFERENT process -- e.g. after a restart, where
    // scrubEngine's own mappingCache is empty and seedMapping is the only
    // remaining source -- the real values are PERMANENTLY unrecoverable
    // through any path this code offers; desubstitute() has nothing to fall
    // back on and returns the raw placeholder text unchanged. Still safe (it
    // fails toward over-redaction, a placeholder staying visible forever,
    // never toward a leak of the real value) but this is a genuine
    // degradation, not merely a "narrowing" of recovery -- mirrors how
    // getCachedPreflight()'s own docstring states its analogous
    // reviewContext-recovery degradation plainly rather than downplaying it.
    try {
      await scrubMappingStore.record({ preflightId: record.id, mapping: accumulatedMapping ?? {} });
    } catch (error) {
      try {
        process.stderr.write(
          `openrouter-review-engine: scrubMappingStore-record-failed preflightId=${record.id} error=${safeErrorDetail(error)}\n`,
        );
      } catch {
        // A logging failure itself must never abort a successful preflight.
      }
    }

    return {
      preflightId: record.id,
      state: record.state,
      reviewContractSha256,
      sourceSha256: computed.sourceSha256,
      profile: computed.profile,
      profileVersion: computed.profileVersion,
      itemMaxima,
      requestedUsd,
      expiresAt: record.expiresAt,
      reviewers,
    };
  }

  /**
   * Creates a lease bound to a cached preflight once the workflow is approved. Without autonomy,
   * every call opens the human approval prompt. With autonomousAuthorization on, the first lease for
   * a document (by raw-source hash, not preflightId) is granted without a prompt and recorded as an
   * info alert; a repeat for the same document needs a justification ({ source: 'human' | 'llm',
   * reason }), is granted directly when the ledger proves the prior attempt failed, and is refused
   * for the LLM path when the ledger proves it succeeded (a human can still override). The
   * installation hard maximum and the maxJobs-versus-reviewer-count check apply in both modes.
   */
  async function authorizeWorkflow({ preflightId, maxJobs, expiresAt, justification } = {}, ownerToken) {
    // Reached only through the wrapper at the bottom of
    // createReviewEngine, after the arm, carrying that call's frozen ownerToken snapshot.
    requireOwnerToken(ownerToken);
    const cached = await getCachedPreflight(preflightId);
    if (!cached) throw new ReviewEngineError('CONTRACT_CHANGED', 'preflight identity could not be verified (missing or expired)');

    if (cached.requestedUsd > installationHardMaximumUsd) {
      throw new ReviewEngineError('LEASE_CAP_EXCEEDED', 'requested amount exceeds the installation hard maximum');
    }

    const boundExpiresAt = expiresAt ?? cached.expiresAt;
    if (typeof boundExpiresAt !== 'string' || !Number.isFinite(Date.parse(boundExpiresAt))) {
      throw new ReviewEngineError('CONTRACT_CHANGED', 'expiresAt must be an ISO timestamp');
    }
    if (Date.parse(boundExpiresAt) > Date.parse(cached.expiresAt)) {
      throw new ReviewEngineError('CONTRACT_CHANGED', 'requested lease expiry exceeds the bound preflight expiry');
    }

    if (!Number.isSafeInteger(maxJobs) || maxJobs <= 0) {
      throw new ReviewEngineError('CONTRACT_CHANGED', 'maxJobs must be a positive safe integer');
    }
    const reviewerCount = cached.reviewers.length;
    if (maxJobs < reviewerCount) {
      throw new ReviewEngineError(
        'LEASE_CAP_EXCEEDED',
        `maxJobs (${maxJobs}) must be at least the preflight reviewer count (${reviewerCount})`,
        { maxJobs, reviewerCount },
      );
    }

    const approvalRequest = {
      preflightHashes: [cached.reviewContractSha256],
      profiles: [cached.profile],
      itemMaxima: cached.itemMaxima,
      requestedUsd: cached.requestedUsd,
      maxJobs,
      expiresAt: boundExpiresAt,
    };

    function hasValidJustification(value) {
      return value !== null && typeof value === 'object'
        && (value.source === 'human' || value.source === 'llm')
        && typeof value.reason === 'string' && value.reason.length > 0;
    }

    // Shared by both branches below: validate the approval outcome and create the lease. Kept as
    // one function so the two branches (autonomous, serialized per document below; non-autonomous,
    // unserialized -- every call there already requires its own human popup, so there is no
    // count-based gate to race) cannot drift apart on this logic.
    async function grantLeaseFromOutcome(outcome) {
      if (outcome.outcome === 'DENIED') throw new ReviewEngineError('APPROVAL_DENIED', 'the approval worker denied this workflow');
      if (outcome.outcome === 'TIMED_OUT') throw new ReviewEngineError('APPROVAL_TIMEOUT', 'the approval request timed out before confirmation');
      if (outcome.outcome !== 'APPROVED') throw new ReviewEngineError('APPROVAL_DENIED', `unrecognized approval outcome: ${outcome.outcome}`);
      try {
        return await leaseStore.createLease({
          preflightIds: [preflightId],
          requestedUsd: cached.requestedUsd,
          maxJobs,
          expiresAt: boundExpiresAt,
          acquisitionId: ownerToken.acquisitionId,
        });
      } catch (error) {
        // Distinguish a lost-ownership failure (this process has since been superseded as the
        // ledger's owner -- see PROCESS_OWNERSHIP_LOST's own comment in ERROR_CODES) from a genuine
        // contract-changed failure, rather than relabeling ANY createLease() failure as
        // CONTRACT_CHANGED, which would be a materially false diagnosis.
        if (isProcessOwnershipLostError(error)) {
          throw new ReviewEngineError('PROCESS_OWNERSHIP_LOST', error.message);
        }
        // A data-root lock timeout is contention, not a changed contract.
        if (isLedgerBusyError(error)) throw ledgerBusyError();
        throw new ReviewEngineError('CONTRACT_CHANGED', error.message);
      }
    }

    function buildAuthorizeResponse(lease) {
      return {
        leaseId: lease.id,
        preflightId,
        state: lease.state,
        requestedUsd: lease.requestedUsd,
        maxJobs: lease.maxJobs,
        expiresAt: lease.expiresAt,
      };
    }

    if (autonomousAuthorization) {
      // Autonomous mode replaces the LIVE human gate with structural guardrails: OpenRouter's own
      // server-side monthly limit (which returns 402 regardless of any bug here), the per-UTC-day
      // paid dispatch allowance in lease-store, and the per-workflow installationHardMaximumUsd
      // ceiling already checked above, PLUS the repeat-authorization justification below for any
      // call past the first.
      //
      // The ENTIRE sequence -- count check, justification, and lease creation -- runs inside
      // serializedByRawSource so concurrent calls for the SAME document cannot each read a stale
      // prior-lease count and each independently pass justification (see that helper's own
      // comment for the race this closes). Calls for DIFFERENT documents are
      // unaffected and remain fully concurrent.
      return serializedByRawSource(cached.rawSourceSha256, async () => {
        const priorLeaseCount = await leaseStore.countLeasesForRawSource(cached.rawSourceSha256);
        // Only computed on a genuine repeat -- cross-checks the ledger's own real prior-attempt
        // outcome so a claim of failure/success can be verified rather than trusted on an LLM's
        // plausibility judgment alone. See resolveDocumentOutcome's own docstring.
        const documentOutcome = priorLeaseCount === 0
          ? null
          : await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256: cached.rawSourceSha256 });
        let outcome;
        let repeatJustifiedVia = null;
        if (priorLeaseCount === 0) {
          // First use of this document (by raw content hash, not preflightId -- see the docstring
          // above): granted exactly as before, no popup, no justification.
          outcome = { outcome: 'APPROVED', nonce: randomUUID(), autonomous: true };
        } else if (documentOutcome === 'SUCCEEDED' && (!hasValidJustification(justification) || justification.source === 'llm')) {
          // The ledger proves the most recent prior lease for this document already completed
          // successfully -- a claim that it failed is objectively false. No LLM call (asking it to
          // override a ledger-proven-false premise is pointless), no popup, no alert (matches this
          // function's existing convention that a denial produces no alert). A human can still
          // override via justification.source === 'human' below -- only the LLM is foreclosed here.
          throw new ReviewEngineError(
            'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
            `this document's most recent prior lease already completed successfully; a repeat claiming it failed is contradicted by this server's own ledger (preflight ${preflightId})`
          );
        } else if (documentOutcome === 'FAILED' && hasValidJustification(justification)) {
          // The ledger proves the most recent prior lease for this document genuinely did not
          // succeed (a real dispatch was attempted and halted, or reconciled with no recorded
          // content) -- this already meets the gate's own bar for a legitimate retry. Granted
          // directly: no LLM call, no popup. `justification` is still required above (any source, a
          // non-empty `reason`) purely so the resulting alert has a human-readable line -- its
          // content is not evaluated.
          outcome = { outcome: 'APPROVED', nonce: randomUUID(), autonomous: true };
          repeatJustifiedVia = 'ledger';
        } else if (!hasValidJustification(justification)) {
          throw new ReviewEngineError(
            'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION',
            `this document already has ${priorLeaseCount} prior lease(s) (preflight ${preflightId}); a repeat authorization under autonomy requires justification: { source: 'human' | 'llm', reason }`
          );
        } else if (justification.source === 'human') {
          // Best-effort, matching alertStore's own failure posture elsewhere in this function: a
          // lost audit line for WHY a human is being asked must never itself block asking them.
          try {
            await alertStore.record({
              severity: 'info',
              reason: `human justification requested for a repeat authorization of profile ${cached.profile}`,
              component: 'openrouter-review',
            });
          } catch (error) {
            process.stderr.write(`openrouter-review-alert: ${safeErrorDetail(error)}\n`);
          }
          outcome = await approvalAdapter.authorize(approvalRequest, { leaseExpiresAt: cached.expiresAt });
          repeatJustifiedVia = 'human';
        } else {
          const verdict = await repeatAuthorizationJudge.judge({
            reason: justification.reason,
            profile: cached.profile,
            priorLeaseCount,
          });
          if (verdict.ok !== true || verdict.justified !== true) {
            throw new ReviewEngineError(
              'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
              verdict.ok === true
                ? `the repeat-authorization judge declined: ${verdict.reasoning}`
                : 'the repeat-authorization judge could not be reached; treating as not justified'
            );
          }
          outcome = { outcome: 'APPROVED', nonce: randomUUID(), autonomous: true };
          repeatJustifiedVia = 'llm';
        }

        // NOTE what a FIRST-USE autonomous grant skips: the sealed approval-request file is
        // written inside createApprovalAdapter.authorize (adapters.mjs:161-206), so it produces no
        // such artifact -- deliberate, since no human approved anything and minting a "sealed
        // approval" record would misrepresent what happened. The alert line below is the audit
        // trail for those. A human-justified REPEAT is different: it genuinely calls
        // approvalAdapter.authorize above and does produce a real sealed record, because a human
        // really did approve that specific call.
        const lease = await grantLeaseFromOutcome(outcome);

        // Best-effort, exactly like resultStore.record's own failure posture: the lease is
        // already validly granted, and losing an audit line must never turn a good authorization
        // into a failure. Note the reason text carries no dollar sign and no long digit run --
        // see alert-store.mjs for why that would be silently blanked downstream.
        try {
          await alertStore.record({
            severity: 'info',
            reason: repeatJustifiedVia === null
              ? `autonomous authorization granted for profile ${cached.profile}`
              : `autonomous authorization granted for profile ${cached.profile} as a justified repeat via ${repeatJustifiedVia}`,
            component: 'openrouter-review',
          });
        } catch (error) {
          process.stderr.write(`openrouter-review-alert: ${safeErrorDetail(error)}\n`);
        }

        return buildAuthorizeResponse(lease);
      });
    }

    // Non-autonomous: every call, first or repeat, already requires its own fresh human-typed
    // approval, and is not serialized, since there is no count-based gate here for concurrent calls
    // to race.
    const outcome = await approvalAdapter.authorize(approvalRequest, { leaseExpiresAt: cached.expiresAt });
    const lease = await grantLeaseFromOutcome(outcome);
    return buildAuthorizeResponse(lease);
  }

  async function status({ leaseId } = {}) {
    if (typeof leaseId !== 'string' || leaseId.length === 0) throw new ReviewEngineError('LEASE_MISSING', 'leaseId is required');
    const lease = await withLedgerBusyTranslation(() => leaseStore.getLease(leaseId));
    if (!lease) throw new ReviewEngineError('LEASE_MISSING', 'lease is missing');
    return {
      leaseId: lease.id,
      state: lease.state,
      requestedUsd: lease.requestedUsd,
      reservedUsd: lease.reservedUsd,
      spentUsd: lease.spentUsd,
      jobsConsumed: lease.jobsConsumed,
      maxJobs: lease.maxJobs,
      expiresAt: lease.expiresAt,
    };
  }

  /**
   * leaseStore.reconcile() for a reconcile that records a real dispatch outcome, retried when, and
   * only when, it rejects with
   * the store's data-root lock timeout (isLedgerBusyError). The retry is the SAME call: the same jobId
   * and the same options object, so the same ownerToken's acquisitionId. After each lock timeout it
   * sleeps an equal-jitter draw and tries again, until the next sleep would pass
   * LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS; then it rethrows that last lock error, so the caller's own
   * lock-timeout path runs unchanged. Any other rejection, PROCESS_OWNERSHIP_LOST included, is rethrown
   * at once and never retried.
   *
   * A retry cannot record twice. lease-store.mjs throws LEDGER_DATA_ROOT_LOCKED only from
   * acquireDataRootLock(), which mutate() awaits before its replay and before the reconcile callback
   * runs, so an attempt that timed out on the lock appended nothing. And reconcile() is a compare-and-set
   * on the job's state: inside the lock it refuses a job that is no longer RESERVED.
   *
   * Elapsed time includes lock-attempt waits through a monotonic clock. The requested-sleep floor also
   * bounds injected no-wait test sleeps; wall-clock changes cannot stretch the budget. Shutdown does not cut the retry short: it
   * always runs inside an operation awaitDrain tracks (a review(), authorizeWorkflow() or
   * recoverOrphanedLeases call, directly or through the arm it awaits), and finishing that write is what
   * the shutdown drain waits for. One retry (one budget plus one last attempt's own lock wait) fits
   * inside the default 30 s drain; a call whose reconciles run one after another (review()'s Step 1
   * recovery, the recoverStaleLease() pre-pass) can spend one budget per busy reconcile. A drain that
   * times out while this helper is between attempts leaves the job RESERVED for a later recovery, since
   * no timed-out attempt wrote anything.
   */
  async function reconcileRetryingLedgerBusy(jobId, options) {
    const startedAtMs = Number(monotonicNow());
    let sleptMs = 0;
    for (;;) {
      try {
        // eslint-disable-next-line no-await-in-loop
        return await leaseStore.reconcile(jobId, options);
      } catch (error) {
        if (!isLedgerBusyError(error)) throw error;
        const clockElapsedMs = Number(monotonicNow()) - startedAtMs;
        const elapsedMs = Number.isFinite(clockElapsedMs) ? Math.max(clockElapsedMs, sleptMs) : sleptMs;
        const delayMs = Math.floor(
          LEDGER_BUSY_RECONCILE_RETRY_BASE_MS / 2 + Math.random() * (LEDGER_BUSY_RECONCILE_RETRY_BASE_MS / 2),
        );
        if (elapsedMs + delayMs > LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS) throw error;
        // eslint-disable-next-line no-await-in-loop
        await sleep(delayMs);
        sleptMs += delayMs;
      }
    }
  }

  /**
   * The single fail-closed exit for a reviewer whose dispatch outcome cannot be accepted: reconciles
   * the job at the given cost and costKind (setting haltReason only for a KNOWN cost), records the
   * reviewer's error entry, records a dispatch-health failure unless the caller defers it, and
   * returns a HALTED result. It does not close the lease itself; finalizeReviewOutcome() decides
   * that once per batch.
   */
  async function haltAndClose({ leaseId, jobId, reviewerId, costUsd, costKind, code, message, extra, reviewers, preflightId, reviewContractSha256, ownerToken, recordHealthOutcome = true, outcomeOperations, aboveReservation = false }) {
    // haltReason marks a halt as SAFE to retry, gated on costKind === 'KNOWN' -- NOT on which
    // `code` fired. costKind:'KNOWN' (PROVIDER_MISMATCH, STRICT_OUTPUT_INVALID) means a real
    // response was actually received and fully inspected: we KNOW no usable content resulted, so a
    // retry is unambiguously a fresh, distinct dispatch, never colliding with hidden already-billed
    // content. Every other costKind this function ever reconciles at
    // (UNKNOWN_WORST_CASE_CHARGED -- UNKNOWN_COST, DISPATCH_UNKNOWN, and TRANSPORT_FAILURE's two
    // non-zero-cost FailureKinds RESPONSE_READ_FAILED/INTERNAL_ERROR; see
    // ZERO_COST_TRANSPORT_FAILURE_KINDS's own docstring above) means the true outcome could NOT be
    // fully verified -- a real request may genuinely have gone out and been billed, its content just
    // never confirmed. Marking any of those "safe" would let a later cross-lease retry silently
    // redispatch and risk a real duplicate paid call -- exactly the landmine this whole mechanism
    // exists to block. Deliberately keyed on costKind rather than enumerating specific codes: a new
    // halt code added later automatically gets the conservative (no haltReason) treatment unless it
    // is deliberately given costKind:'KNOWN', instead of silently inheriting "safe" by omission.
    // costKind:'ZERO_ON_TRANSPORT_FAILURE' also gets no haltReason under this rule, harmlessly --
    // its costUsd is always 0, already excluded from every landmine check by their own costUsd>0
    // filter. Tracing every leaseStore.reconcile() call site by costKind (not by code) shows that
    // RESPONSE_READ_FAILED and INTERNAL_ERROR share DISPATCH_UNKNOWN's ambiguity, which a purely
    // code-name-based check would miss. See lease-store.mjs's reconcile() docstring for the full
    // contract.
    // A halt that records a real dispatch outcome (every halt processDispatchOutcome makes) retries a
    // lock-busy reconcile within its budget, as the clean pass does. A DISPATCH_UNKNOWN halt records
    // none (the dispatch threw, or only a DISPATCHING marker exists), so it keeps a single attempt: its lock timeout still reaches the rejection loop,
    // whose recovery reconcile charges the reservation or, if the lock is still busy, leaves the job
    // RESERVED for a later recovery that may yet find a real captured outcome.
    const reconcileOptions = {
      costUsd, costKind, haltReason: costKind === 'KNOWN' ? code : undefined, acquisitionId: ownerToken.acquisitionId,
      ...(aboveReservation ? { aboveReservation: true } : {}),
    };
    const reconciled = outcomeOperations
      ? await outcomeOperations.reconcile(reconcileOptions)
      : (code === 'DISPATCH_UNKNOWN'
        ? await leaseStore.reconcile(jobId, reconcileOptions)
        : await reconcileRetryingLedgerBusy(jobId, reconcileOptions));
    if (aboveReservation && !idempotentReconcileReplays.has(reconciled)) await recordAboveReservationAlert(reviewerId);
    // `error` is spread LAST so a future `extra` field can never silently shadow this reviewer's
    // own failure detail -- the one field finalizeReviewOutcome scans for when picking the batch's
    // top-level halt reason.
    reviewers[reviewerId] = {
      reviewerId, jobId, state: 'RECONCILED', costUsd: reconciled.costUsd, costKind, ...extra,
      error: { code, message },
    };
    // Step 3 alerts: this is the ONE fail-closed exit every post-intent halt funnels through (see
    // this function's own docstring above), so it is the correct single place to record a
    // dispatch-health FAILURE -- that tracker is per-dispatch by design, and this function is
    // called once per halted REVIEWER. The per-BATCH spend check deliberately does NOT run here:
    // with several reviewers able to halt in one batch it would fire up to N+1 times per call
    // (once per halt, plus once from finalization), spawning a key-status probe process each time.
    // finalizeReviewOutcome()'s own finally block is the single per-batch checkpoint, and it covers
    // every terminal path. Best-effort and never throws.
    // recordHealthOutcome: false is used by exactly one caller -- ambiguousDispatching's own
    // haltAndClose() call in the reviewer-dispatch loop below -- which defers this decision to
    // resolvePendingHealthVerdicts() instead of recording an immediate failure for a job whose real
    // outcome is often still in flight. See resolvePendingHealthVerdicts() below.
    if (recordHealthOutcome) {
      await (outcomeOperations
        ? outcomeOperations.recordHealthOutcome({ succeeded: false })
        : recordDispatchHealthOutcome({ succeeded: false }));
    }
    return { state: 'HALTED', leaseId, preflightId, reviewContractSha256, reviewers, error: { code, message } };
  }

  /**
   * Best-effort durable write for an ambiguousDispatching force-close's deferred verdict. On
   * failure (disk error, etc.), the caller falls back to recording the failure immediately -- the
   * one path in this design where that still happens for an ambiguous job, deliberately, as a
   * fail-safe.
   */
  async function writePendingHealthVerdict({ jobId, reviewerId, reservationUsd }) {
    try {
      const now = clock();
      await pendingHealthVerdictStore.record({
        jobId, reviewerId, reservationUsd,
        notBeforeMs: now + healthVerdictGraceMs,
        recordedAtMs: now,
      });
      return true;
    } catch (error) {
      process.stderr.write(`openrouter-review-engine: pending-health-verdict-write-failed jobId=${jobId} error=${safeErrorDetail(error)}\n`);
      return false;
    }
  }

  /**
   * Validates a dispatch outcome (provider/schema/cost/content) and either
   * reconciles it as a clean pass or halts the lease -- the single pipeline
   * both a just-dispatched RESPONSE and a durably-recovered one (see
   * dispatch-outcome-store.mjs) go through identically, so a recovered
   * outcome gets exactly the same scrutiny a live one always did, never a
   * shortcut. Returns the HALTED result object if this reviewer failed
   * validation (the caller must return it immediately); returns `null` on a
   * clean pass, having already set `reviewers[reviewer.id]` and
   * `advisoryCache` itself, in which case the caller continues its loop.
   *
   * Never calls leaseStore.consume(): both call sites (a fresh dispatch, and
   * a recovered RESERVED job) already reserved `jobId` before reaching here,
   * exactly once, by construction -- this function only ever validates and
   * reconciles.
   */
  async function processDispatchOutcome({ dispatchOutcome, leaseId, jobId, reviewer, reviewerSummary, reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations }) {
    if (dispatchOutcome.kind !== 'RESPONSE') {
      // Reconciles at zero cost for a PROVEN-zero-cost FailureKind, never the reserved worst-case
      // ceiling: a failure that provably happened before any response was received cannot have
      // produced a billed generation. This is NOT safe to apply uniformly to every `kind:
      // 'FAILURE'` outcome -- see ZERO_COST_TRANSPORT_FAILURE_KINDS's own docstring above for
      // exactly which FailureKinds are provably zero-cost and which two must stay
      // worst-case-charged. This is deliberately narrower than DISPATCH_UNKNOWN (an ambiguous "we
      // don't even know whether a dispatch was attempted" case -- a stale DISPATCHING marker, or
      // the dispatch adapter itself throwing before ever reaching the worker), which keeps the
      // conservative worst-case charge unconditionally: there the worker never had a chance to
      // report anything either way, so there is no positive signal (unlike a definite FAILURE) to
      // conclude anything from.
      const failureKind = decodeFailureKind(dispatchOutcome);
      const isZeroCost = failureKind !== null && ZERO_COST_TRANSPORT_FAILURE_KINDS.has(failureKind);
      return await haltAndClose({
        leaseId, jobId, reviewerId: reviewer.id,
        costUsd: isZeroCost ? 0 : reviewerSummary.maxUsd,
        costKind: isZeroCost ? 'ZERO_ON_TRANSPORT_FAILURE' : 'UNKNOWN_WORST_CASE_CHARGED',
        code: 'TRANSPORT_FAILURE',
        message: `the dispatch worker reported a transport failure for reviewer ${reviewer.id}${failureKind ? ` (${failureKind})` : ''}`,
        reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations,
      });
    }

    let parsedBody = null;
    try {
      parsedBody = decodeEnvelopeBody(dispatchOutcome);
    } catch {
      parsedBody = null;
    }

    const cost = parsedBody ? extractFiniteNonnegativeCost(parsedBody) : null;
    if (cost === null) {
      // A provider that REFUSED the request before running it has no cost to report, so it lands
      // here looking identical to a response whose cost merely could not be parsed -- and used to
      // be charged the full reservation on that basis. Checked before the worst-case fallback, and
      // only for the narrow provably-pre-inference case; everything else still falls through
      // unchanged. See isProvablyZeroCostRejection() for why the status alone is not enough.
      if (isProvablyZeroCostRejection(dispatchOutcome, parsedBody)) {
        return await haltAndClose({
          leaseId, jobId, reviewerId: reviewer.id, costUsd: 0,
          costKind: 'ZERO_ON_PROVIDER_REJECTION', code: 'TRANSPORT_FAILURE',
          message: `reviewer ${reviewer.id} was refused by the provider before any inference ran (HTTP ${decodeEnvelopeHttpStatus(dispatchOutcome)})`,
          reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations,
        });
      }
      return await haltAndClose({
        leaseId, jobId, reviewerId: reviewer.id, costUsd: reviewerSummary.maxUsd,
        costKind: 'UNKNOWN_WORST_CASE_CHARGED', code: 'UNKNOWN_COST',
        message: `reviewer ${reviewer.id} returned no verifiable finite non-negative cost`,
        reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations,
      });
    }
    // A finite reported cost above the reservation is REAL spend, not an untrustworthy report (a
    // reasoning model can bill hidden reasoning beyond its max_tokens bound). Booking it at the
    // reservation as UNKNOWN_COST with the review discarded would under-record real spend, so it is
    // recorded at its real value, flagged aboveReservation, the content kept on a clean pass, and
    // one critical alert raised. Recording more than was reserved only fails closed.
    const aboveReservation = cost > reviewerSummary.maxUsd;

    if (parsedBody.provider !== reviewer.expectedProvider) {
      return await haltAndClose({
        leaseId, jobId, reviewerId: reviewer.id, costUsd: cost, costKind: 'KNOWN', code: 'PROVIDER_MISMATCH',
        message: `reviewer ${reviewer.id} returned provider "${parsedBody.provider}", expected "${reviewer.expectedProvider}"`,
        extra: { provider: parsedBody.provider },
        reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations, aboveReservation,
      });
    }

    if (!isAcceptedReviewCompletion(parsedBody)) {
      return await haltAndClose({
        leaseId, jobId, reviewerId: reviewer.id, costUsd: cost, costKind: 'KNOWN',
        code: 'STRICT_OUTPUT_INVALID',
        message: `reviewer ${reviewer.id} output failed strict validation: completion finish_reason must be stop`,
        reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations, aboveReservation,
      });
    }

    const contentText = parsedBody?.choices?.[0]?.message?.content;
    const cleanedContentText = selectContentTextForValidation(contentText, reviewer);
    const contentResult = typeof cleanedContentText === 'string' ? validateAdvisoryContent(cleanedContentText) : { ok: false, reason: 'message content missing' };
    if (!contentResult.ok) {
      return await haltAndClose({
        leaseId, jobId, reviewerId: reviewer.id, costUsd: cost, costKind: 'KNOWN', code: 'STRICT_OUTPUT_INVALID',
        message: `reviewer ${reviewer.id} output failed strict validation: ${contentResult.reason}`,
        reviewers, preflightId, reviewContractSha256, ownerToken, outcomeOperations, aboveReservation,
      });
    }

    // Reverse-substitution on the way back, before this ever becomes visible
    // to a caller or gets persisted to resultStore: recall the durable
    // mapping (a fresh process -- e.g. review() recovering after a restart,
    // see createReviewEngine's own docstring -- has an empty in-process
    // scrubEngine.mappingCache for this preflightId, so seedMapping is what
    // makes desubstitute() work even then; a same-process call already
    // populated that cache moments earlier via this same review() call's own
    // loadAndScrubSource()/reviewContext scrub, so seedMapping is
    // defense-in-depth there, not the only path).
    //
    // Read BEFORE the reconcile below. The moment that
    // reconcile commits, a concurrent result() can see every reviewer RECONCILED and delete this
    // mapping (its bounded-lifetime cleanup), so a read placed after it could find nothing and
    // publish raw placeholder tokens. A read FAILURE is captured rather than thrown here, the
    // reconcile runs exactly as before, and the captured failure is rethrown straight after it. So a
    // mapping-read failure still lands AFTER a successful reconcile at KNOWN cost, which is the money
    // behaviour three tests pin (parallel-dispatch's "a rejection AFTER a successful reconcile" and
    // its getJob read-back sibling, and engine.test's post-reconcile pre-pass failure test).
    let seedMapping = null;
    let seedMappingReadFailed = false;
    let seedMappingReadError;
    try {
      seedMapping = outcomeOperations
        ? await outcomeOperations.recallMapping()
        : await scrubMappingStore.recall({ preflightId });
    } catch (error) {
      seedMappingReadFailed = true;
      seedMappingReadError = error;
    }
    // A lock timeout here is retried within its budget first, so contention alone does not turn this
    // completed dispatch into the rejection loop's worst-case charge. Past the budget the lock error
    // is rethrown and that path runs unchanged.
    const aboveReservationOption = aboveReservation ? { aboveReservation: true } : {};
    const reconciled = outcomeOperations
      ? await outcomeOperations.reconcile({ costUsd: cost, costKind: 'KNOWN', acquisitionId: ownerToken.acquisitionId, ...aboveReservationOption })
      : await reconcileRetryingLedgerBusy(jobId, { costUsd: cost, costKind: 'KNOWN', acquisitionId: ownerToken.acquisitionId, ...aboveReservationOption });
    if (aboveReservation && !idempotentReconcileReplays.has(reconciled)) await recordAboveReservationAlert(reviewer.id);
    if (seedMappingReadFailed) throw seedMappingReadError;
    // Deliberately re-parses cleanedContentText, NOT the raw contentText above
    // -- do not revert this. validateAdvisoryContent(cleanedContentText) (see
    // contentResult above) already ran JSON.parse on this exact string and
    // only returned ok:true because that parse succeeded, so this second
    // parse of the SAME string is guaranteed to succeed too. Raw contentText
    // still has its markdown code fence for a prompted_json reviewer (see
    // selectContentTextForValidation above), and re-parsing THAT here would
    // throw a SyntaxError past the STRICT_OUTPUT_INVALID guard this whole
    // pipeline exists to fail closed through.
    const rawFindings = JSON.parse(cleanedContentText).findings;
    const findings = await Promise.all(rawFindings.map(
      (finding) => desubstituteFinding(finding, { preflightId, seedMapping: seedMapping ?? undefined }),
    ));
    const entry = {
      reviewerId: reviewer.id,
      jobId,
      state: 'RECONCILED',
      costUsd: reconciled.costUsd,
      costKind: 'KNOWN',
      provider: parsedBody.provider,
      model: reviewer.model,
      advisory: { verdict: contentResult.verdict, findings },
    };
    reviewers[reviewer.id] = entry;
    advisoryCache.set(jobId, entry);
    // Scope boundary: unlike the ledger writes above
    // (leaseStore.reconcile(), fully fenced by acquisitionId inside its own atomic mutate()
    // transaction), resultStore gets only a lighter, SYNCHRONOUS, best-effort ownerLock.isOwner()
    // check before writing -- matching its own already-established "best effort, never blocks an
    // already-paid-for success" posture, not the full ledger guarantee. The real money-safety
    // guarantee already happened in the leaseStore.reconcile() call just above, which IS
    // ledger-fenced; a stale/superseded process simply skips this write entirely rather than
    // racing a successor to publish content for a job it no longer owns.
    //
    // Every path that reaches here is armed. review() arms before
    // it starts; recoverStaleLease() -> processDispatchOutcome() runs only after an arm, either inside
    // the ownership coordinator's own arm cycle (runCycleWork) or from the recoverOrphanedLeases
    // export, which arms first. So in production a false isOwner() here still means this handle has
    // begun releasing (shutdown), never that it was not yet armed. (One engine test fakes a false
    // isOwner() on an armed handle on purpose, to pin that this gate skips only the record: the
    // reconcile above is fenced by acquisitionId alone and still succeeds.)
    if (outcomeOperations) {
      await outcomeOperations.persistAdvisory(entry);
    } else if (ownerLock.isOwner()) {
      try {
        await resultStore.record({ jobId, advisory: entry });
      } catch (error) {
        // Best-effort durability only: this write is a safety net for a
        // connection that may ALREADY be gone by the time this line runs,
        // never a precondition for the normal case where it's still alive.
        // A local disk failure here must not turn a real, already-paid-for
        // success into a reported failure -- `entry` above is already
        // assigned and `reviewers[reviewer.id]` already set, so the PASSED
        // result the caller returns is unaffected either way.
        //
        // The failure is still logged: a silent durable-write failure is
        // invisible and hard to diagnose later, so it must stay VISIBLE even though it
        // can't be allowed to change the result. Matches the
        // `openrouter-review-dispatch:` stderr convention in
        // tools/openrouter-review-mcp-server.mjs (prefix: event key=value...).
        try {
          process.stderr.write(
            `openrouter-review-engine: resultStore-record-failed jobId=${jobId} error=${safeErrorDetail(error)}\n`,
          );
        } catch {
          // A logging failure itself must never abort a successful review.
        }
      }
    }
    // Step 3 dispatch-health tracking: a clean pass through THIS branch is the "succeeded"
    // signal recordDispatchHealthOutcome resets the consecutive-failure streak on. Deliberately
    // NOT paired with checkSpendAndMaybeAlert here -- unlike the health streak (per-dispatch by
    // design), the spend check is per-BATCH, so it belongs only at the batch's terminal checkpoint
    // (finalizeReviewOutcome()), not once per successful reviewer within a still-in-progress
    // multi-reviewer batch.
    await (outcomeOperations
      ? outcomeOperations.recordHealthOutcome({ succeeded: true })
      : recordDispatchHealthOutcome({ succeeded: true }));
    return null;
  }

  /**
   * Shared tail of every real (or redispatched) OpenRouter call: dispatch,
   * translate a thrown rejection into the same DISPATCH_UNKNOWN halt shape
   * `haltAndClose` already produces for other post-intent failures, then run
   * whatever came back through `processDispatchOutcome`. Both `review()`
   * call sites already reserved `jobId` before reaching here -- a fresh
   * reservation just above (leaseStore.consume()), or a pre-existing one
   * recovered from the ledger -- so `worstCaseCostUsd` is passed explicitly
   * by the caller rather than re-derived here, and `notAfterMs` is always
   * the lease's own fixed absolute expiry, per the no-relative-duration
   * fix documented on `dispatchAdapter.dispatch()`'s call sites above.
   * Returns the HALTED result object on failure (the caller must return it
   * immediately); returns `null` on a clean pass (the caller continues its
   * loop), matching `processDispatchOutcome`'s own contract.
   */
  async function dispatchAndReconcile({ requestBytes, notAfterMs, worstCaseCostUsd, leaseId, jobId, reviewer, reviewerSummary, reviewers, preflightId, reviewContractSha256, ownerToken }) {
    let dispatchOutcome;
    try {
      dispatchOutcome = await dispatchAdapter.dispatch({ requestBytes, jobId, reviewerId: reviewer.id, notAfterMs });
    } catch (error) {
      // e.g. dispatchAdapter.dispatch() itself never got far enough to
      // produce a FAILURE-kind outcome (a durable capture, if the
      // underlying script DID get that far before this rejection surfaced,
      // is still recoverable on a later retry via the existingJob path
      // above; nothing here needs to check it, since haltAndClose's own
      // reconcile(jobId, ...) below already closes this specific attempt at
      // the worst case either way).
      //
      // Uses safeErrorDetail(), not error.message, for the same reason every
      // process.stderr.write(...) site in this file already does:
      // this message flows into the HALTED result review()/document() returns to
      // the MCP caller -- a more exposed channel than a local stderr log, not a
      // less exposed one -- and dispatchAdapter is a caller-supplied collaborator
      // whose real implementation shells out and reads back an on-disk envelope
      // that can contain the reviewer's own generated content, so nothing here
      // can prove a thrown error is always content-free.
      return await haltAndClose({
        leaseId, jobId, reviewerId: reviewer.id, costUsd: worstCaseCostUsd,
        costKind: 'UNKNOWN_WORST_CASE_CHARGED', code: 'DISPATCH_UNKNOWN',
        message: `dispatch threw for reviewer ${reviewer.id}: ${safeErrorDetail(error)}`,
        reviewers, preflightId, reviewContractSha256, ownerToken,
      });
    }
    return await processDispatchOutcome({ dispatchOutcome, leaseId, jobId, reviewer, reviewerSummary, reviewers, preflightId, reviewContractSha256, ownerToken });
  }

  async function validateBoundReviewInputs({ leaseId, preflightId, source_text, source_path, reviewContext } = {}, ownerToken) {
    // Reached only through the wrapper at the bottom of
    // createReviewEngine, after the arm, carrying that call's frozen ownerToken snapshot.
    requireOwnerToken(ownerToken);
    if (typeof leaseId !== 'string' || leaseId.length === 0) throw new ReviewEngineError('LEASE_MISSING', 'leaseId is required');
    if (typeof preflightId !== 'string' || preflightId.length === 0) throw new ReviewEngineError('CONTRACT_CHANGED', 'preflightId is required');

    const lease = await leaseStore.getLease(leaseId);
    if (!lease) throw new ReviewEngineError('LEASE_MISSING', 'lease is missing');
    if (lease.state !== 'ACTIVE') throw new ReviewEngineError('LEASE_CLOSED', `lease is ${lease.state}`);
    // Fixed for the remainder of this call -- lease is never reassigned
    // below -- so every reviewer's dispatch bound derives from the SAME
    // absolute instant, not a value re-derived per iteration (see the
    // dispatch-loop comment below for why that fixedness matters).
    const leaseExpiresAtMs = Date.parse(lease.expiresAt);
    if (leaseExpiresAtMs <= Number(clock())) {
      // Recovery path for a lease left ACTIVE with a stale RESERVED job by
      // an earlier call whose process was replaced (crash, host reconnect)
      // before it could ever reconcile. This is
      // reached BEFORE getCachedPreflight() below on purpose: that is an
      // in-memory cache a process restart always empties, so recovery must
      // not depend on it -- a caller can re-enter review() with the same
      // leaseId/preflightId after a real restart and still reach this.
      // recoverStaleLease() (which wraps leaseStore.sweepOrphanedLeases()) is a no-op unless at
      // least orphanSweepGraceMs has passed since expiresAt, so a lease with nothing to recover (or
      // one whose dispatch may still be legitimately finishing) falls through to the plain
      // throw below.
      // eslint-disable-next-line no-await-in-loop
      const swept = await recoverStaleLease({ leaseId, staleAfterMs: orphanSweepGraceMs, ownerToken });
      const recovered = swept.find((entry) => entry.leaseId === leaseId);
      if (recovered && recovered.reconciledJobs.length > 0) {
        // recoverStaleLease() already runs every recovered job through recordDispatchHealthOutcome
        // itself (a real success/failure signal for a job resolved at its real cost via
        // processDispatchOutcome, a failure for one the conservative worst-case fallback closed) --
        // recording it again here, unconditionally as a failure, would double-count and could
        // misreport a genuinely successful recovery as a failure.
        return { earlyResult: {
          state: 'HALTED', leaseId, preflightId,
          error: {
            code: 'LEASE_EXPIRED',
            // Deliberately does not claim "at worst-case cost" -- a previously-
            // reserved job recovered here may have been reconciled at its real, determinable cost
            // instead (see each entry's own costKind in recoveredJobs).
            message: `the lease had already expired; ${recovered.reconciledJobs.length} previously-reserved job(s) were resolved during recovery (see each job's own costKind for whether it reflects a real known cost or a conservative worst-case charge)`,
          },
          recoveredJobs: recovered.reconciledJobs,
        } };
      }
      throw new ReviewEngineError('LEASE_EXPIRED', 'lease is expired');
    }

    const cached = await getCachedPreflight(preflightId);
    if (!cached) throw new ReviewEngineError('CONTRACT_CHANGED', 'preflight identity could not be verified (missing or expired)');

    let source;
    try {
      source = await loadAndScrubSource({ source_text, source_path, sourcePolicy, preflightId });
    } catch (error) {
      if (error instanceof ReviewEngineError) throw error;
      throw new ReviewEngineError('SOURCE_INVALID', error.message);
    }

    // reviewContext is optional here: omitting it re-confirms the cached
    // (already-trusted, already-scrubbed at preflight() time) context,
    // which is what most callers rely on.
    // Supplying it lets a caller present the *current* review context at
    // review() time -- mirroring how source_text / source_path are
    // re-supplied fresh -- so drift in the context since preflight is
    // actually detectable here, not just re-derivable from a value this
    // function already trusted. Without this, reviewContextSha256 could only
    // ever be recomputed from cached.reviewContext, which can never disagree
    // with itself. A freshly-supplied reviewContext is scrubbed here, under
    // the SAME preflightId, before it is hashed or ever bound into a
    // dispatched request -- the omitted-context path is not re-scrubbed
    // again (harmless by determinism, but wasteful: it was already scrubbed
    // once, in preflight()).
    let effectiveReviewContext = reviewContext === undefined ? cached.reviewContext : reviewContext;
    if (typeof effectiveReviewContext !== 'string') throw new ReviewEngineError('SOURCE_INVALID', 'reviewContext must be a string');
    if (reviewContext !== undefined) {
      const contextScrub = await scrubEngine.scrub({ text: reviewContext, preflightId });
      if (contextScrub.blocked) {
        throw new ReviewEngineError('CONTENT_BLOCKED', `reviewContext blocked before send: ${contextScrub.blockedCategories.join(', ')}`);
      }
      effectiveReviewContext = contextScrub.scrubbedText;
    }

    const reviewContextSha256 = sha256(effectiveReviewContext);
    const reviewContractSha256 = buildReviewContract({
      sourceSha256: source.sourceSha256,
      reviewContextSha256,
      profile: cached.profile,
      profileVersion: cached.profileVersion,
    });
    if (reviewContractSha256 !== lease.reviewContractSha256 || reviewContractSha256 !== cached.reviewContractSha256) {
      throw new ReviewEngineError('CONTRACT_CHANGED', 'recomputed review contract does not match the bound lease');
    }

    return {
      leaseId,
      preflightId,
      leaseExpiresAtMs,
      cached,
      source,
      effectiveReviewContext,
      reviewContractSha256,
    };
  }

  async function executeValidatedReview({
    leaseId,
    preflightId,
    leaseExpiresAtMs,
    cached,
    source,
    effectiveReviewContext,
    reviewContractSha256,
  }, ownerToken) {
    requireOwnerToken(ownerToken);

    const reviewers = {};
    // Profile/registry order, fixed for this whole call. Step 3 builds its concurrent task list in
    // THIS order (so a test observing dispatch order still sees the profile's order) and Step 5
    // picks the batch's top-level halt reason by scanning it -- neither depends on
    // Promise.allSettled's settle order, which is not guaranteed to match dispatch order.
    const orderedReviewerIds = cached.reviewers.map((reviewerSummary) => reviewerSummary.reviewerId);

    // -----------------------------------------------------------------------
    // Step 1 -- check phase. Sequential, fast, local and mostly read-only
    // (parallelizing this too would add complexity for no measurable saving).
    // It resolves recovery and cross-lease reuse and sorts everything else
    // into the three lists Step 3 will act on. NOTHING is reserved and
    // NOTHING is dispatched here, which is what lets every reviewer's abort
    // conditions be checked before ANY reviewer is reserved -- so no earlier
    // reviewer is ever dispatched (and possibly already spent) before a later
    // reviewer's abort condition has been checked.
    // -----------------------------------------------------------------------
    const needsRedispatch = [];
    const needsFreshReservation = [];
    const ambiguousDispatching = [];
    let batchStop = null;

    for (const reviewerSummary of cached.reviewers) {
      const reviewer = getReviewer(reviewerSummary.reviewerId);
      const jobId = deriveJobId(leaseId, reviewer.id, reviewContractSha256);

      // This whole per-reviewer body is real, lock-serialized store I/O (leaseStore.getJob(),
      // findJobsForReviewerContract(), and processDispatchOutcome()'s own reconcile() calls, each
      // wrapped in mutate()) that can throw under I/O error or lock contention -- exactly the same
      // failure class reserveReviewers() below already guards its own copy of
      // findJobsForReviewerContract()/consume() against, routing through the established
      // ORDINARY_FAILURE stopReason rather than rejecting review() itself. Without this guard, a
      // raw, uncaught EPERM/"ledger data root is locked" error under concurrent lock pressure would
      // escape review() directly, abandoning any reviewer already queued onto
      // needsRedispatch/ambiguousDispatching earlier in THIS SAME pass -- the exact
      // orphaned-reservation failure class this whole design exists to eliminate (see
      // reserveReviewers()'s own docstring, a few lines below). Reusing batchStop for this, rather
      // than inventing a second mechanism, means Step 3 still dispatches/reconciles everything
      // already classified before the throw, exactly as the two other batchStop conditions
      // (DUPLICATE_DISPATCH_IN_PROGRESS, LEASE_EXPIRED) already do.
      try {
        // No-retry recovery: a job ID this engine has already seen for this
        // exact lease/reviewer/contract triple is never dispatched again.
        // eslint-disable-next-line no-await-in-loop
        const existingJob = await leaseStore.getJob(jobId);
        if (existingJob) {
          // eslint-disable-next-line no-await-in-loop
          const recovered = await recallAdvisory(existingJob, ownerToken);
          // MONEY-SAFETY VISIBILITY: processDispatchOutcome durably reconciles a job's real cost in
          // the ledger (leaseStore.reconcile()) BEFORE it builds and records that job's own advisory
          // content (reviewers[reviewer.id]=entry, resultStore.record()) -- if anything throws in
          // that narrow window (most realistically the whole Node process dying), the job is left
          // durably RECONCILED at
          // a real, known cost with no recoverable content anywhere: not in advisoryCache, not in
          // resultStore. Without this guard, `recovered` would be null and this reviewer's entry
          // would silently look like a clean, contentless success -- no .error, no .advisory --
          // letting the whole batch report PASSED (or an unrelated HALTED) while this reviewer's
          // real, paid-for findings are permanently lost.
          //
          // A LEGITIMATE halt (haltAndClose, e.g. PROVIDER_MISMATCH) also reconciles at a real known
          // cost and also never writes to resultStore/advisoryCache -- so by ledger state alone it
          // would be indistinguishable from a genuine content-loss landmine (both are
          // state:RECONCILED, costKind:KNOWN, costUsd>0, nothing recoverable). haltReason
          // (lease-store.mjs's reconcile(), persisted by haltAndClose and the dispatch-rejection
          // recovery path) is the durable marker that tells them apart: present only for a genuine
          // halt, absent (never a bare empty string) for a genuine clean-pass reconcile whose
          // content-write never landed. Normally this branch is never reached for a same-lease halt
          // retry, because a halt with nothing else genuinely RESERVED closes the lease (review()
          // then refuses re-entry) -- but the anyStillReserved guard (decideFinalReviewOutcome) can leave a
          // lease ACTIVE alongside a halted reviewer when a DIFFERENT reviewer in the same batch is
          // genuinely still RESERVED, and a caller's retry of that still-open lease reaches this
          // branch for the already-halted one. This does NOT affect findReusableAdvisory's
          // cross-lease reuse decision below by construction: reaching a cross-lease job by
          // definition means THIS lease's own existingJob check above was never reached for it --
          // see the separate haltReason check alongside that call instead.
          const isUnexplainedContentLoss = existingJob.state === 'RECONCILED'
            && (existingJob.costKind === 'KNOWN' || existingJob.costUsd > 0) && !existingJob.haltReason;
          reviewers[reviewer.id] = recovered ?? {
            reviewerId: reviewer.id,
            jobId,
            state: existingJob.state,
            costUsd: existingJob.costUsd,
            costKind: costKindFromLedgerJob(existingJob),
            ...(isUnexplainedContentLoss ? {
              error: {
                code: 'CONTENT_LOST',
                message: `reviewer ${reviewer.id}'s job ${jobId} is ${existingJob.state} in the ledger at a real known cost, but no advisory content could be recovered from any store`,
              },
            } : existingJob.haltReason ? {
              error: {
                code: existingJob.haltReason,
                message: `reviewer ${reviewer.id}'s job ${jobId} previously halted with code ${existingJob.haltReason} on this same lease; no advisory content was ever produced`,
              },
            } : {}),
          };
          if (existingJob.state !== 'RESERVED') continue;

          // A RESERVED-but-never-reconciled job means a previous attempt was
          // interrupted between reservation and reconciliation. Before treating
          // that outcome as truly unknowable, check whether the dispatch script
          // itself durably captured its outcome before its caller was replaced
          // (see dispatch-outcome-store.mjs and the matching write in
          // openrouter-review-dispatch.ps1).
          // eslint-disable-next-line no-await-in-loop
          const capturedOutcome = await dispatchOutcomeStore.recall({ jobId });
          if (capturedOutcome && capturedOutcome.kind !== 'DISPATCHING') {
            // Runs the recovered outcome through the exact same
            // validation/reconcile pipeline a live dispatch would have. Its
            // return value is deliberately ignored: a halt here sets this
            // reviewer's own `error` entry, and Step 5 reports it -- a halt does
            // not stop the batch, so there is nothing
            // to return early with.
            // eslint-disable-next-line no-await-in-loop
            await processDispatchOutcome({
              dispatchOutcome: capturedOutcome, leaseId, jobId, reviewer, reviewerSummary,
              reviewers, preflightId, reviewContractSha256, ownerToken,
            });
            continue;
          }
          if (capturedOutcome && capturedOutcome.kind === 'DISPATCHING') {
            // A dispatch WAS attempted for this jobId and its outcome is
            // genuinely unknown: it may still be in flight, or may have
            // completed without a chance to durably record a RESPONSE/FAILURE.
            // Redispatching risks a real duplicate OpenRouter call, so this
            // stays the original conservative behavior -- close it out at the
            // worst case, never dispatch again. Resolved in Step 3 alongside the
            // reviewers that ARE dispatched; it needs no separate phase.
            ambiguousDispatching.push({ reviewer, reviewerSummary, jobId, reservationUsd: existingJob.reservationUsd });
            continue;
          }
          // No capture of ANY kind -- not even a DISPATCHING marker. Because
          // markDispatching() is an EXCLUSIVE, atomic claim written before
          // dispatchAdapter.dispatch()'s own execute() call can ever run, its
          // total absence is conclusive proof no OpenRouter request was ever
          // sent for this jobId, so redispatch is safe. It reuses the EXISTING
          // reservation and must NEVER be handed to Step 2's consume(), which
          // would throw on an already-RESERVED jobId.
          needsRedispatch.push({ reviewer, reviewerSummary, jobId, worstCaseCostUsd: existingJob.reservationUsd });
          continue;
        }

        // Cross-lease dedup: only reached for a reviewer THIS lease has never
        // itself touched. findJobsForReviewerContract scans EVERY job ever
        // created (any lease, any state) for this exact (contract, reviewer)
        // pair; findReusableAdvisory decides which of those, if any, is safe to
        // reuse for free.
        // eslint-disable-next-line no-await-in-loop
        const priorJobs = await leaseStore.findJobsForReviewerContract(reviewContractSha256, reviewer.id);
        // eslint-disable-next-line no-await-in-loop
        const reusable = await findReusableAdvisory(priorJobs, ownerToken);
        if (reusable) {
          reviewers[reviewer.id] = { ...reusable, costKind: 'REUSED_FROM_PRIOR_LEASE' };
          continue;
        }

        // MONEY SAFETY: a prior job under a DIFFERENT lease that RECONCILED at a real known cost,
        // with no recoverable content AND no haltReason, is an unexplained content-loss landmine
        // (real money was spent; the response may genuinely exist somewhere, it just never got
        // durably recorded before its process died -- see lease-store.mjs's reconcile() docstring).
        // Unlike a genuine halt (haltReason present, e.g. PROVIDER_MISMATCH -- nothing was ever
        // produced, so a fresh redispatch is provably safe and must proceed, see the sibling test
        // below), redispatching here risks a real duplicate paid call for content that may already
        // exist. This is the cross-lease counterpart of the same-lease isUnexplainedContentLoss
        // check above. Reported the same way a
        // same-lease landmine already is -- HALTED, never a silent fresh dispatch -- but does not
        // set batchStop: one reviewer's landmine must not block a sibling reviewer this lease
        // genuinely still needs.
        const unexplainedCrossLeaseLoss = priorJobs.find(
          (priorJob) => priorJob.state === 'RECONCILED'
            && (priorJob.costKind === 'KNOWN' || priorJob.costUsd > 0) && !priorJob.haltReason,
        );
        if (unexplainedCrossLeaseLoss) {
          reviewers[reviewer.id] = {
            reviewerId: reviewer.id,
            jobId: unexplainedCrossLeaseLoss.id,
            state: unexplainedCrossLeaseLoss.state,
            costUsd: unexplainedCrossLeaseLoss.costUsd,
            costKind: costKindFromLedgerJob(unexplainedCrossLeaseLoss),
            error: {
              code: 'CONTENT_LOST',
              message: `reviewer ${reviewer.id}'s prior job ${unexplainedCrossLeaseLoss.id} (a different lease, ${unexplainedCrossLeaseLoss.leaseId}) is RECONCILED at a real known cost with no recoverable advisory content and no recorded halt reason -- refusing to redispatch to avoid a possible duplicate paid call`,
            },
          };
          continue;
        }

        // The two conditions that stop reservation of anything NEW for the whole
        // batch: if either trips for any reviewer, nothing on needsFreshReservation
        // is ever reserved, for ANY reviewer, including ones already found clean
        // earlier in this same pass. This does NOT mean nothing is dispatched
        // (see the batchStop-handling comment below Step 1's own loop): a
        // reviewer already queued onto needsRedispatch or ambiguousDispatching
        // earlier in this pass (a real pre-existing RESERVED job from an
        // interrupted earlier attempt) still reaches Step 3 and Step 5 even when
        // a LATER reviewer trips one of these two conditions -- abandoning it
        // here would orphan a real reservation. Step 2 independently re-checks the
        // duplicate condition immediately before each reservation, because a
        // duplicate can appear in the gap between this early pass and that
        // reservation; this check is the cheap early rejection that avoids doing
        // any further work reserving fresh candidates in an already-doomed batch.
        const priorReserved = priorJobs.find((priorJob) => priorJob.state === 'RESERVED');
        if (priorReserved) {
          batchStop = {
            code: 'DUPLICATE_DISPATCH_IN_PROGRESS',
            stopDetail: { reviewerId: reviewer.id, jobId: priorReserved.id },
          };
          break;
        }
        if (leaseExpiresAtMs <= Number(clock())) {
          batchStop = {
            code: 'LEASE_EXPIRED',
            stopDetail: { reviewerId: reviewer.id, jobId: null },
          };
          break;
        }

        needsFreshReservation.push({ reviewer, reviewerSummary, jobId });
      } catch (error) {
        // Mirrors reserveReviewers()'s own ORDINARY_FAILURE shape exactly (stopDetail carries
        // {reviewerId, jobId}; ordinaryFailureError is translated and re-thrown by
        // finalizeReviewOutcome AFTER the already-classified subset's own dispatch/reconcile/close
        // has run) -- see the reservation-construction ternary directly below Step 1 for where
        // batchStop.ordinaryFailureError is threaded through.
        batchStop = {
          code: 'ORDINARY_FAILURE',
          stopDetail: { reviewerId: reviewer.id, jobId },
          ordinaryFailureError: error,
        };
        break;
      }
    }

    // -----------------------------------------------------------------------
    // Step 2 -- reserve phase. Fresh reservations only; a "needs redispatch"
    // reviewer already holds one and must never be consume()'d again.
    //
    // A batchStop from Step 1 (batchStop !== null) is deliberately NOT an
    // immediate return: an EARLIER reviewer in this exact pass can already be
    // sitting in needsRedispatch or ambiguousDispatching with a real
    // pre-existing RESERVED job from an interrupted earlier review() call (i.e.
    // real money already reserved). Closing the lease and returning here,
    // without ever routing that earlier reviewer's entry through Step 3
    // (dispatch) or Step 5 (finalization), would strand it: once the lease is
    // closed, sweepOrphanedLeases() can never recover it (it only ever recovers
    // a job under an ACTIVE lease) and review() refuses to re-enter a
    // non-ACTIVE lease at all -- so that job would stay RESERVED forever, and
    // every FUTURE review() call for the same document would immediately re-hit
    // the same DUPLICATE_DISPATCH_IN_PROGRESS condition (it matches on the
    // job's own `state === 'RESERVED'` regardless of which lease owns it),
    // permanently blocking that document from ever completing review through
    // this pipeline again.
    //
    // Instead this reuses the exact machinery Step 2's OWN stop condition already
    // uses, rather than inventing a second code path: a batchStop skips this
    // reserveReviewers() call (nothing on needsFreshReservation is touched --
    // the batch-wide condition means don't reserve anything new) but synthesizes
    // the SAME { reservedReviewerIds, stopReason, stopDetail,
    // ordinaryFailureError } shape reserveReviewers() itself returns, with
    // reservedReviewerIds: [] (nothing fresh was reserved) and stopReason
    // translated from batchStop.code ('DUPLICATE_DISPATCH_IN_PROGRESS' here vs.
    // 'DUPLICATE_IN_PROGRESS' in decideFinalReviewOutcome's vocabulary;
    // 'LEASE_EXPIRED' is spelled the same in both). Step 3 below already handles
    // needsRedispatch/ambiguousDispatching independently of reservedReviewerIds
    // (see its own loop), so it still dispatches and reconciles whatever is
    // already queued there even when reservedReviewerIds is empty. Step 5's
    // finalizeReviewOutcome is the ONLY place that closes the lease for this
    // path too, exactly like Step 2's own stop already works -- so
    // checkSpendAndMaybeAlert() (in finalizeReviewOutcome's own finally block)
    // also runs on this exit: a batchStop CAN follow a Step 1 recovery that
    // reconciled a real prior charge (via processDispatchOutcome), so "no new
    // spend could have happened" would not be a sound reason to skip it.
    // -----------------------------------------------------------------------
    const reservation = batchStop
      ? {
        reservedReviewerIds: [],
        stopReason: batchStop.code === 'DUPLICATE_DISPATCH_IN_PROGRESS' ? 'DUPLICATE_IN_PROGRESS' : batchStop.code,
        stopDetail: batchStop.stopDetail,
        // Only Step 1's own ORDINARY_FAILURE batchStop (see the try/catch around Step 1's loop
        // above) ever populates this; the other two batchStop codes never do.
        ordinaryFailureError: batchStop.ordinaryFailureError ?? null,
      }
      : await reserveReviewers({
        leaseStore,
        clock,
        leaseId,
        leaseExpiresAtMs,
        reviewContractSha256,
        ownerToken,
        candidates: needsFreshReservation.map(({ reviewer, reviewerSummary, jobId }) => ({
          reviewerId: reviewer.id,
          jobId,
          reservationUsd: reviewerSummary.maxUsd,
          // "Paid" is the ABSENCE of a trustTier -- gemini and grok carry none, every free reviewer
          // carries trustTier: 'untrusted' (reviewer-registry.mjs).
          countsTowardDailyAllowance: reviewer.trustTier === undefined,
        })),
      });
    const reservedReviewerIds = new Set(reservation.reservedReviewerIds);

    // -----------------------------------------------------------------------
    // Step 3 -- dispatch phase, the actual parallelization. Built in profile
    // order so dispatch ORDER stays deterministic; every task then runs
    // concurrently and each reviewer resolves fully independently of the
    // others' outcomes.
    //
    // Every task carries its own `reservationUsd` because the rejection
    // handler below needs it to reconcile a job whose task blew up before
    // reconciling itself -- see that handler for why leaving one RESERVED is
    // permanently unrecoverable.
    //
    // Every `run` is an ASYNC arrow, and buildReviewRequest() is called INSIDE
    // it rather than out here in the builder loop. Both are deliberate: this
    // loop runs AFTER Step 2 has already reserved real money, so anything that
    // throws between here and Promise.allSettled would escape review() with
    // reservations held and the lease never closed. A synchronous throw inside
    // a NON-async arrow would surface during `.map()`, before allSettled ever
    // sees it, and skip the rejection handler entirely; inside an async arrow
    // the same throw becomes a rejected promise the handler below reconciles
    // and reports. buildReviewRequest is a pure function of an already-loaded
    // source and a fixed registry entry -- preflight() built the byte-identical
    // body for every reviewer in this profile, and the contract-hash check
    // above already proved the inputs match -- so it is not expected to throw
    // here at all; this just removes the possibility of an unguarded one, at no
    // cost. Invocation ORDER is unaffected: an async function body still runs
    // synchronously up to its first await, so each task still reaches
    // dispatchAdapter.dispatch() synchronously, in array order.
    // -----------------------------------------------------------------------
    const concurrentTasks = [];
    for (const reviewerId of orderedReviewerIds) {
      const ambiguous = ambiguousDispatching.find((entry) => entry.reviewer.id === reviewerId);
      if (ambiguous) {
        concurrentTasks.push({
          reviewerId,
          jobId: ambiguous.jobId,
          reservationUsd: ambiguous.reservationUsd,
          run: async () => {
            const deferred = await writePendingHealthVerdict({
              jobId: ambiguous.jobId, reviewerId: ambiguous.reviewer.id, reservationUsd: ambiguous.reservationUsd,
            });
            return haltAndClose({
              leaseId, jobId: ambiguous.jobId, reviewerId: ambiguous.reviewer.id,
              costUsd: ambiguous.reservationUsd, costKind: 'UNKNOWN_WORST_CASE_CHARGED',
              code: 'DISPATCH_UNKNOWN',
              message: `a prior dispatch for reviewer ${ambiguous.reviewer.id} has an unknown outcome; refusing to redispatch`,
              reviewers, preflightId, reviewContractSha256, ownerToken,
              recordHealthOutcome: !deferred,
            });
          },
        });
        continue;
      }

      const redispatch = needsRedispatch.find((entry) => entry.reviewer.id === reviewerId);
      if (redispatch) {
        concurrentTasks.push({
          reviewerId,
          jobId: redispatch.jobId,
          reservationUsd: redispatch.worstCaseCostUsd,
          run: async () => {
            const redispatchRequestBody = buildReviewRequest({
              reviewer: redispatch.reviewer, sourceText: source.text, reviewContext: effectiveReviewContext,
            });
            const redispatchRequestBytes = Buffer.from(JSON.stringify(redispatchRequestBody), 'utf8');
            return dispatchAndReconcile({
              requestBytes: redispatchRequestBytes, notAfterMs: leaseExpiresAtMs,
              worstCaseCostUsd: redispatch.worstCaseCostUsd, leaseId, jobId: redispatch.jobId,
              reviewer: redispatch.reviewer, reviewerSummary: redispatch.reviewerSummary,
              reviewers, preflightId, reviewContractSha256, ownerToken,
            });
          },
        });
        continue;
      }

      if (!reservedReviewerIds.has(reviewerId)) continue;
      const fresh = needsFreshReservation.find((entry) => entry.reviewer.id === reviewerId);
      concurrentTasks.push({
        reviewerId,
        jobId: fresh.jobId,
        reservationUsd: fresh.reviewerSummary.maxUsd,
        run: async () => {
          const requestBody = buildReviewRequest({
            reviewer: fresh.reviewer, sourceText: source.text, reviewContext: effectiveReviewContext,
          });
          const requestBytes = Buffer.from(JSON.stringify(requestBody), 'utf8');
          return dispatchAndReconcile({
            requestBytes, notAfterMs: leaseExpiresAtMs, worstCaseCostUsd: fresh.reviewerSummary.maxUsd,
            leaseId, jobId: fresh.jobId, reviewer: fresh.reviewer, reviewerSummary: fresh.reviewerSummary,
            reviewers, preflightId, reviewContractSha256, ownerToken,
          });
        },
      });
    }

    // Promise.allSettled, never Promise.all: a single reviewer's rejection must not be allowed to
    // reject the whole call and lose visibility into the others. dispatchAndReconcile already
    // converts a thrown dispatch error into a haltAndClose-shaped return value, so a rejection here
    // should not normally occur -- this is defense-in-depth against an unexpected throw, and the
    // rejected entries are handled explicitly below rather than silently dropped from the result.
    // An empty list is legitimate (everyone resolved in Step 1, or Step 2's very first check
    // tripped) and resolves immediately to [].
    const settled = await Promise.allSettled(concurrentTasks.map((task) => task.run()));
    // A plain for-loop, NOT settled.forEach: the rejection handling below has to await a real
    // ledger write, and forEach would fire-and-forget an async callback -- finalization would then
    // close the lease while the reconcile was still in flight.
    for (const [index, outcome] of settled.entries()) {
      if (outcome.status !== 'rejected') continue;
      const task = concurrentTasks[index];
      // Kept as the raw rejection value (never pre-extracted to .message) so both uses below go
      // through safeErrorDetail(), the same as dispatchAndReconcile()'s catch block: this rejection
      // can originate inside processDispatchOutcome's own scrubMappingStore.recall()/
      // desubstituteFinding() calls (see the comment block below), which process real
      // reviewer-generated content, so nothing here can prove outcome.reason.message is always
      // content-free. Pre-extracting `.message` would make the stderr write below over-redact
      // (safeErrorDetail() sees a bare string, not an Error, and returns the generic non-Error
      // marker) while the returned-result copy would embed that raw string unredacted -- passing
      // the raw value through lets safeErrorDetail() actually inspect it.
      const rejectionReason = outcome.reason;

      // MONEY SAFETY, not bookkeeping. A rejected task may have blown up ANYWHERE inside
      // dispatchAndReconcile -- including after this job was already RESERVED but before anything
      // reconciled it (processDispatchOutcome has no try/catch of its own around
      // leaseStore.reconcile(), scrubMappingStore.recall(), desubstituteFinding(), or its
      // JSON.parse). If this job is left RESERVED, finalization below closes the lease, and from
      // that moment the reservation is PERMANENTLY unrecoverable: sweepOrphanedLeases() skips any
      // lease that is not ACTIVE (lease-store.mjs:420) and review() refuses to re-enter a
      // non-ACTIVE lease at all (review-engine.mjs:1359), so nothing left in the system can ever
      // reconcile it or release its reservedUsd. That is precisely the orphaned-reservation failure
      // class this whole design exists to eliminate, so it must not be reintroduced through the
      // rejection path. Reconciling at the reviewer's full reserved worst case is exactly what
      // haltAndClose's own DISPATCH_UNKNOWN path already does for an outcome nobody can verify.
      //
      // Guarded, and deliberately unconditional rather than gated on a getJob() state read up front:
      // the rejection may also have happened AFTER a successful reconcile (e.g. a throw from
      // scrubMappingStore.recall() or desubstituteFinding(), neither wrapped in a try/catch inside
      // processDispatchOutcome), in which case this recovery call throws `job is not reserved` --
      // correctly, since there is genuinely nothing left to reconcile. The REPORTED entry must not
      // then fall back to the bare RESERVED/zero-cost/RECOVERED_STATUS_ONLY stub -- that would misreport a
      // reviewer that the ledger already knows is really RECONCILED at a real, known cost. The catch
      // block reads the real job back and, when it is no longer RESERVED, reports FROM it -- same
      // convention as Step 1's own existingJob recovery (review-engine.mjs:~1710-1721,
      // costKindFromLedgerJob). Either way the failure is logged and the loop still builds this
      // reviewer's entry and still reaches finalization -- a reconcile or logging failure must never
      // crash the batch or leave finalization unreached.
      let reconciledEntry = null;
      try {
        // No haltReason: this recovery reconcile fires for a task whose true outcome is genuinely
        // unverifiable (the same "an outcome nobody can verify" shape haltAndClose's own
        // DISPATCH_UNKNOWN path is -- see that function's own comment), so it must NOT be marked
        // safe to retry. A real request may have gone out and been billed; leaving haltReason unset
        // correctly routes a later cross-lease retry into the content-loss-landmine guard instead of
        // a silent redispatch.
        // eslint-disable-next-line no-await-in-loop
        const reconciled = await leaseStore.reconcile(task.jobId, {
          costUsd: task.reservationUsd, costKind: 'UNKNOWN_WORST_CASE_CHARGED', acquisitionId: ownerToken.acquisitionId,
        });
        reconciledEntry = {
          reviewerId: task.reviewerId, jobId: task.jobId, state: 'RECONCILED',
          costUsd: reconciled.costUsd, costKind: 'UNKNOWN_WORST_CASE_CHARGED',
        };
      } catch (reconcileError) {
        try {
          process.stderr.write(
            `openrouter-review-engine: dispatch-task-rejected-reconcile-failed reviewerId=${task.reviewerId} jobId=${task.jobId} error=${safeErrorDetail(reconcileError)}\n`,
          );
        } catch {
          // A logging failure must never drop this reviewer's outcome from the result.
        }
        // The recovery reconcile() above throws whenever the job is no longer RESERVED -- most
        // commonly because processDispatchOutcome's OWN reconcile() already succeeded (real money,
        // real costKind, already durably committed) before a LATER step in that same function threw.
        // Read the real job back before ever falling to the bare stub below: if it exists and is no
        // longer RESERVED, the ledger's own record is the ground truth for this reviewer's status,
        // not an unknown. Guarded like the process.stderr.write() above: getJob() is a real fallible
        // operation (leaseStore's mutate() -- a cross-process file lock plus a full ledger replay
        // from disk -- can throw on I/O error or a corrupted ledger record), and this whole block's
        // own invariant is that a failure here must never crash the batch or leave finalization
        // unreached. A getJob() failure just means the read-back could not happen; reconciledEntry
        // stays null and execution falls through to the bare RESERVED/zero-cost/RECOVERED_STATUS_ONLY stub
        // below, exactly as when the job doesn't exist or is still genuinely RESERVED -- this must
        // be indistinguishable from "couldn't determine the real state," not a new special case.
        let ledgerJob = null;
        try {
          // eslint-disable-next-line no-await-in-loop
          ledgerJob = await leaseStore.getJob(task.jobId);
        } catch {
          // Falls through to the bare stub below, same as ledgerJob === null.
        }
        if (ledgerJob && ledgerJob.state !== 'RESERVED') {
          reconciledEntry = {
            reviewerId: task.reviewerId, jobId: task.jobId, state: ledgerJob.state,
            costUsd: ledgerJob.costUsd, costKind: costKindFromLedgerJob(ledgerJob),
          };
        }
      }

      try {
        // Loud on purpose: this is a genuinely unexpected code path, and a silent failure here would
        // be invisible and hard to diagnose. Same
        // `<prefix>: <event> key=value...` shape as the other stderr lines in this file.
        process.stderr.write(
          `openrouter-review-engine: dispatch-task-rejected reviewerId=${task.reviewerId} jobId=${task.jobId} error=${safeErrorDetail(rejectionReason)}\n`,
        );
      } catch {
        // A logging failure must never drop this reviewer's outcome from the result.
      }
      // Spread into a NEW object rather than mutating in place: an entry recovered from
      // advisoryCache or resultStore is a shared reference, and mutating it would corrupt the
      // cache. An entry the failed task already managed to set is preserved as-is (it carries real
      // cost detail); otherwise `reconciledEntry` is used -- either the recovery reconcile's own
      // fresh entry, or the real ledger job read back in the catch block above
      // when the recovery reconcile found the job already resolved -- so the result can never claim
      // RESERVED for a job the ledger now records as RECONCILED. Only when the job genuinely does
      // not exist, or is genuinely still RESERVED with no recoverable outcome, does this fall back
      // to the bare RESERVED/zero-cost/RECOVERED_STATUS_ONLY stub. jobId is always a real string (never
      // null) in all three cases, so the entry still satisfies REVIEWER_RESULT_ENTRY_SCHEMA's
      // OPAQUE_ID.
      reviewers[task.reviewerId] = {
        ...(reviewers[task.reviewerId] ?? reconciledEntry ?? {
          reviewerId: task.reviewerId, jobId: task.jobId, state: 'RESERVED',
          costUsd: 0, costKind: 'RECOVERED_STATUS_ONLY',
        }),
        // Ownership loss is classified at the three owner-fenced sites that have their own
        // translator, and every leaseStore.reconcile() rejection converges here. Stamping it with
        // the generic DISPATCH_UNKNOWN would lose the distinction at the single worst place, since
        // those reconcile sites are the ONLY ones that can fire after real money has been spent: an
        // operator whose server had been superseded by a second instance would be told "we cannot
        // verify what happened to this dispatch" instead of "another process took the ledger". See
        // PROCESS_OWNERSHIP_LOST's own comment in ERROR_CODES -- it exists precisely because
        // conflating this failure with a generic one "would hide a real operational problem behind
        // misleading diagnostics that point an operator at the wrong thing to investigate."
        //
        // Nothing else changes: the job's money state is untouched (it stays RESERVED on an ACTIVE
        // lease, still recoverable), this is purely the reported classification. The
        // ownership message is fixed text rather than safeErrorDetail(rejectionReason), because the
        // predicate has already established what the failure IS -- there is nothing left to redact.
        error: isProcessOwnershipLostError(rejectionReason)
          ? {
            code: 'PROCESS_OWNERSHIP_LOST',
            message: `dispatch task for reviewer ${task.reviewerId} could not be reconciled: this process no longer holds ledger ownership of the data root`,
          }
          : {
            code: 'DISPATCH_UNKNOWN',
            message: `dispatch task for reviewer ${task.reviewerId} rejected unexpectedly: ${safeErrorDetail(rejectionReason)}`,
          },
      };
      // Dispatch-health alert: a rejected dispatch task is a real dispatch failure
      // just like any haltAndClose() halt, and must count toward the same consecutive-failure
      // streak or the alert can never fire for this failure class. Same single choke point's
      // convention as haltAndClose (review-engine.mjs:1400) and processDispatchOutcome's clean-pass
      // branch below -- best-effort, never throws.
      //
      // EXCEPT a lost-ownership rejection. That is not a
      // dispatch failure -- this process was superseded as the ledger's owner -- and counting it
      // would let a superseded server raise the consecutive-dispatch-failure alert about a healthy
      // pipeline. It is still reported, as PROCESS_OWNERSHIP_LOST, in this reviewer's entry above.
      //
      // Nor a data-root lock timeout: with several server processes sharing the data root,
      // contention for the ledger's write lock is ordinary and says nothing about the dispatch
      // pipeline. Money is unchanged either way: the recovery reconcile above still charged worst
      // case (or, if it timed out on the lock too, left the job RESERVED for a later recovery at
      // its captured cost),
      // and the entry above still reports DISPATCH_UNKNOWN.
      if (!isProcessOwnershipLostError(rejectionReason) && !isLedgerBusyError(rejectionReason)) {
        // eslint-disable-next-line no-await-in-loop
        await recordDispatchHealthOutcome({ succeeded: false });
      }
    }

    // -----------------------------------------------------------------------
    // Step 5 -- finalization. The single place that closes the lease, and the
    // single place that decides PASSED vs HALTED vs throw.
    // -----------------------------------------------------------------------
    return await finalizeReviewOutcome({
      leaseStore,
      checkSpendAndMaybeAlert,
      leaseId,
      preflightId,
      reviewContractSha256,
      reviewers,
      orderedReviewerIds,
      ownerToken,
      stopReason: reservation.stopReason,
      stopDetail: reservation.stopDetail,
      ordinaryFailureError: reservation.ordinaryFailureError,
    });
  }

  async function review(input = {}, ownerToken) {
    const validated = await validateBoundReviewInputs(input, ownerToken);
    if (validated.earlyResult !== undefined) return validated.earlyResult;
    return executeValidatedReview(validated, ownerToken);
  }

  /**
   * Recovers a completed (or in-progress) lease's advisory content using
   * nothing but `leaseId` -- independent of the short-lived, in-process
   * `preflightCache`/`advisoryCache`, both of which a lost connection or a
   * process restart always empties. This is the durable counterpart to
   * `review()`'s own in-loop recovery: `review()` requires a caller to
   * still hold a verifiable `preflightId` (and re-supply source_text), which
   * a caller who lost its connection before ever seeing the response may
   * not have retained; `result()` requires only the `leaseId` the original
   * `authorizeWorkflow()` call returned.
   *
   * Each reviewer's deterministic `jobId` is re-derived from the lease's own
   * durable `reviewContractSha256` plus its first bound preflight's durable
   * `itemMaxima` -- not from re-deriving the reviewer set some other way,
   * since that set could in principle vary independently of what this lease
   * record actually reserved jobs against. For each reviewer: a durable
   * `resultStore` hit returns the full advisory content; otherwise a known
   * ledger job under THIS lease's own jobId falls back to bare state/cost,
   * with `costKind` taken from the job's own persisted value via
   * `costKindFromLedgerJob` (mirroring review()'s own existingJob fallback) --
   * `RECOVERED_STATUS_ONLY` only when the ledger genuinely has no cost
   * classification for it (e.g. still RESERVED); a reviewer with NO ledger
   * job at all under this lease is checked against the cross-lease reuse
   * lookup (`findJobsForReviewerContract`/`findReusableAdvisory`, same as
   * review()'s own dispatch loop) before finally falling back to a
   * `NOT_DISPATCHED` stub -- a reviewer served for free via cross-lease reuse
   * never reserves a job under its own lease's jobId, so this is what makes
   * its real content recoverable here too, not only from review()'s own live
   * return value.
   *
   * Read-only: never calls dispatchAdapter.dispatch, never reserves or
   * reconciles a job, never mutates the lease -- safe to call repeatedly,
   * from any process, at any time after authorizeWorkflow() has run.
   */
  async function result({ leaseId } = {}) {
    if (typeof leaseId !== 'string' || leaseId.length === 0) throw new ReviewEngineError('LEASE_MISSING', 'leaseId is required');
    // result()'s own busy-ledger site translation. Every later store call in this
    // recovery read is covered by withLedgerBusyBoundary() at the export object.
    const lease = await withLedgerBusyTranslation(() => leaseStore.getLease(leaseId));
    if (!lease) throw new ReviewEngineError('LEASE_MISSING', 'lease is missing');

    const [firstPreflightId] = lease.preflightIds;
    const preflightRecord = firstPreflightId ? await leaseStore.getPreflight(firstPreflightId) : null;
    const itemMaxima = preflightRecord ? preflightRecord.itemMaxima : [];
    // Recalled ONCE before the loop, not per reviewer. Entries already
    // reverse-substituted by processDispatchOutcome() (the live path above)
    // are stored ALREADY restored in resultStore -- this recovery path's own
    // desubstitute() calls below are therefore only load-bearing for content
    // whose live reverse-substitution was lost before it could run (e.g. a
    // crash between processDispatchOutcome reconciling and its result being
    // durably stored), never a double-substitution risk: desubstitute() only
    // replaces placeholder tokens it actually finds in the text (see
    // scrub-engine.mjs), so re-running it on already-restored content that
    // contains no remaining placeholders is a no-op.
    let seedMapping = null;
    try {
      seedMapping = firstPreflightId ? await scrubMappingStore.recall({ preflightId: firstPreflightId }) : null;
    } catch { /* Captured recovery will refuse content if the mapping remains unreadable. */ }

    const reviewers = {};
    let allDurablyResolved = itemMaxima.length > 0 && preflightRecord.id === firstPreflightId
      && preflightRecord.reviewContractSha256 === lease.reviewContractSha256;
    for (const item of itemMaxima) {
      const reviewerId = item.itemId.replace(/^item-/, '');
      const jobId = deriveJobId(leaseId, reviewerId, lease.reviewContractSha256);
      // eslint-disable-next-line no-await-in-loop
      const recovered = await resultStore.recall({ jobId });
      // eslint-disable-next-line no-await-in-loop
      const existingJob = await leaseStore.getJob(jobId);
      const jobBoundToLease = existingJob?.leaseId === leaseId
        && existingJob.reviewContractSha256 === lease.reviewContractSha256;
      if (existingJob) allDurablyResolved &&= jobBoundToLease
        && mappingNoLongerNeeded(existingJob, recovered, reviewerId, jobId);
      if (recovered) {
        if (!existingJob) allDurablyResolved = false;
        if (recovered.advisory && Array.isArray(recovered.advisory.findings)) {
          // eslint-disable-next-line no-await-in-loop
          const restoredFindings = await Promise.all((recovered.advisory.findings ?? []).map(
            (finding) => desubstituteFinding(finding, { preflightId: firstPreflightId, seedMapping: seedMapping ?? undefined }),
          ));
          reviewers[reviewerId] = { ...recovered, advisory: { ...recovered.advisory, findings: restoredFindings } };
        } else {
          reviewers[reviewerId] = recovered;
        }
        continue;
      }
      if (existingJob) {
        // No token: this path stays ownerless and reconstructs on demand without persisting.
        // eslint-disable-next-line no-await-in-loop
        const captured = jobBoundToLease ? await recoverReconciledAdvisory(existingJob) : null;
        reviewers[reviewerId] = captured ?? { reviewerId, jobId, state: existingJob.state, costUsd: existingJob.costUsd, costKind: costKindFromLedgerJob(existingJob) };
        continue;
      }
      // No job was EVER created on THIS lease for this reviewer under its own per-lease jobId.
      // This can legitimately mean "never dispatched" (an earlier reviewer halted the lease
      // first) -- OR it can mean this reviewer was served for free via review()'s own cross-lease
      // reuse path (REUSED_FROM_PRIOR_LEASE): a reused reviewer never calls leaseStore.consume()
      // on THIS lease at all, so no job -- and no per-lease jobId -- ever exists for it here.
      // Checking the SAME cross-lease lookup review() itself uses (via the shared
      // findReusableAdvisory helper, see its own docstring) before concluding NOT_DISPATCHED is
      // what makes this durable: result()'s entire reason for existing is recovering a caller
      // that lost its connection before ever seeing review()'s own live response, which is a
      // common case for this pipeline, not an edge case -- so a reused reviewer's real content
      // must be recoverable here too, not
      // only from the live review() return value.
      // eslint-disable-next-line no-await-in-loop
      const priorJobs = await leaseStore.findJobsForReviewerContract(lease.reviewContractSha256, reviewerId);
      // eslint-disable-next-line no-await-in-loop
      const reused = await findReusableAdvisory(priorJobs);
      const sourceJob = reused ? priorJobs.find((job) => job.id === reused.jobId) : null;
      // Transient reuse is not proof that either mapping can safely be discarded.
      // eslint-disable-next-line no-await-in-loop
      const sourceDurable = sourceJob ? await resultStore.recall({ jobId: sourceJob.id }) : null;
      allDurablyResolved &&= !!sourceJob
        && sourceJob.reviewContractSha256 === lease.reviewContractSha256
        && mappingNoLongerNeeded(sourceJob, sourceDurable, reviewerId,
          deriveJobId(sourceJob.leaseId, reviewerId, lease.reviewContractSha256));
      reviewers[reviewerId] = reused
        ? { ...reused, costKind: 'REUSED_FROM_PRIOR_LEASE' }
        : { reviewerId, jobId, state: 'NOT_DISPATCHED', costUsd: 0, costKind: 'RECOVERED_STATUS_ONLY' };
    }

    // A settled charge alone is not durable content. Keep the mapping through the
    // reconcile/content-write gap, including successful but ownerless reconstruction.
    if (allDurablyResolved && firstPreflightId) {
      await scrubMappingStore.deleteMapping({ preflightId: firstPreflightId });
    }

    return { leaseId, state: lease.state, reviewers };
  }

  /**
   * Recovers every stale RESERVED job on an eligible lease (or every eligible lease in the store,
   * when `leaseId` is omitted) at its REAL, determinable cost where possible, instead of
   * unconditionally charging the conservative worst-case reservation. leaseStore.sweepOrphanedLeases()
   * on its own only knows how to worst-case-charge a bare ledger job; it has no access to
   * dispatchOutcomeStore (the durable per-job RESPONSE/FAILURE capture -- see
   * dispatch-outcome-store.mjs) or to the validation/content-persistence pipeline
   * (processDispatchOutcome) that a live review() call always uses. Without this pre-pass, a real,
   * already-completed OpenRouter dispatch (real content generated, real tokens billed) whose caller
   * died would be reconciled at its full worst-case reservation, overcharging it, and the real
   * advisory content it produced would never be persisted anywhere recoverable.
   *
   * Pre-pass: for every stale RESERVED job leaseStore.findStaleReservedJobs() reports, check
   * dispatchOutcomeStore for a durably captured outcome. A real RESPONSE/FAILURE (kind !==
   * 'DISPATCHING') runs through processDispatchOutcome() -- the EXACT SAME validation/reconcile/
   * content-persistence pipeline a live dispatch always used, so a recovered outcome gets identical
   * scrutiny, never a shortcut -- reconciling it at its real cost and (for a clean pass) durably
   * recording its real advisory content via resultStore, recoverable afterward through
   * openrouter_review_result exactly like a live PASSED reviewer's content already is.
   *
   * Deliberately narrower scope: a DISPATCHING marker (a dispatch was attempted and its outcome is
   * genuinely unknown -- may still be in flight) or no capture at all falls through to the fallback
   * below, worst-case-charged. The "no capture at all" case is provably safe to REDISPATCH inside a
   * live review() call (see the existingJob loop above), but this function has no live caller and
   * no source text to redispatch with. Treating it as zero cost here instead (the same
   * exclusive-claim reasoning markDispatching() already establishes) is a plausible further
   * tightening that is deliberately not made here.
   *
   * Fallback: leaseStore.sweepOrphanedLeases() reconciles + closes whatever the pre-pass left
   * genuinely RESERVED -- it also still closes any lease this
   * pre-pass only PARTIALLY resolved. A lease the pre-pass resolved EVERY stale job for has nothing
   * left RESERVED, so sweepOrphanedLeases() silently skips it (see its own docstring); this
   * function closes such a lease explicitly afterward, only once a fresh read confirms none of its
   * stale jobs are still RESERVED.
   *
   * Returns the same shape leaseStore.sweepOrphanedLeases() already returns --
   * `[{ leaseId, lease, reconciledJobs }]` -- built fresh per touched lease from the ledger AFTER
   * both passes, so a lease the pre-pass and the fallback each partially resolved is reported as
   * ONE entry covering every job that got resolved, not split across two.
   */
  async function recoverStaleLease({ leaseId, staleAfterMs, ownerToken }) {
    requireOwnerToken(ownerToken);
    const staleJobs = await leaseStore.findStaleReservedJobs({ leaseId, staleAfterMs });
    if (staleJobs.length === 0) return [];

    const staleJobIdsByLease = new Map();
    for (const staleJob of staleJobs) {
      const jobIds = staleJobIdsByLease.get(staleJob.leaseId) ?? new Set();
      jobIds.add(staleJob.jobId);
      staleJobIdsByLease.set(staleJob.leaseId, jobIds);
    }

    for (const staleJob of staleJobs) {
      let capturedOutcome;
      try {
        // eslint-disable-next-line no-await-in-loop
        capturedOutcome = await dispatchOutcomeStore.recall({ jobId: staleJob.jobId });
      } catch {
        capturedOutcome = null;
      }
      if (!capturedOutcome || capturedOutcome.kind === 'DISPATCHING') continue;

      try {
        // eslint-disable-next-line no-await-in-loop
        const staleLease = await leaseStore.getLease(staleJob.leaseId);
        if (!staleLease || staleLease.state !== 'ACTIVE') continue;
        // eslint-disable-next-line no-await-in-loop
        const reviewer = await resolveStaleJobReviewer({ staleJob, staleLease, leaseStore });
        if (!reviewer) continue;
        const [preflightId] = staleLease.preflightIds;
        // eslint-disable-next-line no-await-in-loop
        await processDispatchOutcome({
          dispatchOutcome: capturedOutcome,
          leaseId: staleJob.leaseId,
          jobId: staleJob.jobId,
          reviewer,
          reviewerSummary: { maxUsd: staleJob.reservationUsd },
          reviewers: {},
          preflightId,
          reviewContractSha256: staleLease.reviewContractSha256,
          ownerToken,
        });
      } catch (error) {
        // Real store I/O can throw on a genuine race (e.g. a live review() call resolving the same
        // job concurrently), and an unexpected reviewerId throws inside getReviewer() -- never let
        // one job's recovery abort the whole sweep. Anything still RESERVED after this falls
        // through to the fallback below, exactly as if the pre-pass had not run for it.
        //
        // processDispatchOutcome() has no try/catch of its own around leaseStore.reconcile(),
        // scrubMappingStore.recall(), or desubstituteFinding() (see the identical, already-accepted
        // comment on review()'s own live Step 3 rejection handler a few hundred lines above) -- a
        // throw AFTER the reconcile() inside it already durably committed a real cost can leave this
        // job RECONCILED at real money with its advisory content never persisted. This is a
        // characteristic of the shared processDispatchOutcome() pipeline (the live rejection handler
        // has the identical limitation, and reports no more than the bare ledger record too). Logged
        // loudly here for the same reason every other durable-write failure in this module is: it
        // must stay visible, even though a full CONTENT_LOST-style detection here would be new
        // machinery not attempted here. The job's real ledger state (cost, costKind) is still
        // correctly recovered a few lines below via a fresh leaseStore.getJob() read either way.
        //
        // The log goes through safeErrorDetail(), never the raw error.message: this catch wraps
        // processing of real reviewer-generated content, so a raw message could carry
        // content-derived text into an unredacted stderr log. Every stderr.write(...) diagnostic in
        // this file goes through that single helper rather than auditing each site's
        // error-producing code path individually to prove which ones are safe.
        try {
          process.stderr.write(`openrouter-review-engine: recoverStaleLease-pre-pass-failed jobId=${staleJob.jobId} error=${safeErrorDetail(error)}\n`);
        } catch {
          // A logging failure itself must never abort recovery.
        }
        // Callers rely on recoverStaleLease() running every recovered job through
        // recordDispatchHealthOutcome itself (see review()'s re-entry branch). That holds for a
        // clean pass or an ordinary haltAndClose()-driven halt (both go through
        // processDispatchOutcome's own internal calls), but NOT for this exact catch: a throw here
        // means processDispatchOutcome never reached either of its own calls, so without this line
        // the job's outcome -- succeeded or failed -- would be invisible to the
        // consecutive-dispatch-failure health tracker. Matches review()'s own live Step 3 rejection handler
        // (review-engine.mjs, dispatch-task-rejected), which calls this UNCONDITIONALLY for every
        // rejected task regardless of whether its own recovery reconcile found the job already
        // resolved -- a rejection is itself the failure signal being tracked, independent of whatever
        // partial ledger state a best-effort read-back happens to find.
        //
        // Except a lost-ownership failure, which is not a dispatch failure at all (this process was
        // superseded as the ledger's owner). It stays logged loudly above; it just never advances
        // the consecutive-dispatch-failure streak. Nor does a data-root lock timeout. Money is
        // unchanged: whatever this
        // pre-pass left RESERVED, the fallback sweep below still charges at worst case and counts.
        if (!isProcessOwnershipLostError(error) && !isLedgerBusyError(error)) {
          // eslint-disable-next-line no-await-in-loop
          await recordDispatchHealthOutcome({ succeeded: false });
        }
      }
    }

    // Fallback: reconciles + closes at worst-case whatever the pre-pass above left genuinely
    // RESERVED -- and still what closes any lease the pre-pass only partially resolved.
    //
    // Guarded: this call, like every leaseStore operation, can throw under real cross-process lock
    // contention (lease-store.mjs's own fail-closed mutate() design), for example under several
    // concurrent recoverOrphanedLeases() calls. Since this ONE call can cover every stale lease in the store-wide case,
    // an uncaught throw here would abort recovery for every lease in this batch, not just one, and
    // -- because this function is also called from review()'s own re-entry branch (:2042) --
    // could crash a live caller's review() call outright instead of returning its normal
    // LEASE_EXPIRED result. Nothing here is money-unsafe to skip: a lease left untouched by a
    // failed sweep is exactly as safe as it was before this call ran, and a future recovery attempt
    // (the next process's arm-cycle sweep, or the next caller's own re-entry) picks it back up regardless.
    let swept = [];
    try {
      swept = await leaseStore.sweepOrphanedLeases({ leaseId, staleAfterMs, acquisitionId: ownerToken.acquisitionId });
    } catch (error) {
      try {
        process.stderr.write(`openrouter-review-engine: recoverStaleLease-fallback-sweep-failed error=${safeErrorDetail(error)}\n`);
      } catch {
        // A logging failure itself must never abort recovery.
      }
    }
    for (const entry of swept) {
      for (const _recoveredJob of entry.reconciledJobs) {
        // eslint-disable-next-line no-await-in-loop
        await recordDispatchHealthOutcome({ succeeded: false });
      }
    }

    // A lease every one of whose stale jobs the pre-pass resolved on its own has nothing left
    // RESERVED, so sweepOrphanedLeases() above silently skipped it (see its own
    // "reservedJobs.length === 0" guard) -- close it explicitly here instead, only once a fresh
    // read confirms nothing on it is still genuinely RESERVED. The whole per-lease body is wrapped
    // in its own try/catch (like the pre-pass's own per-job loop above) so a lock-timeout or other
    // unexpected failure reading ONE lease's jobs can never abort this loop for every OTHER lease in
    // a store-wide sweep -- for the same lock-contention reason the sweepOrphanedLeases() fallback
    // call above is guarded.
    for (const [candidateLeaseId, jobIds] of staleJobIdsByLease) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const freshJobs = await Promise.all([...jobIds].map((jobId) => leaseStore.getJob(jobId)));
        if (freshJobs.some((job) => !job || job.state === 'RESERVED')) continue;
        // One immediate retry: every job on this lease is ALREADY reconciled at real, durably
        // committed cost (no money or content at risk either way), so the only thing a close()
        // failure here can cost is this lease's own record staying ACTIVE instead of
        // ORPHANED_ON_RECOVERY -- a low-stakes label, but a cheap retry meaningfully reduces how often
        // a genuinely transient I/O hiccup (the realistic cause) leaves it that way.
        let closeError = null;
        for (let attempt = 0; attempt < 2; attempt += 1) {
          try {
            // eslint-disable-next-line no-await-in-loop
            await leaseStore.close(candidateLeaseId, 'ORPHANED_ON_RECOVERY', { acquisitionId: ownerToken.acquisitionId });
            closeError = null;
            break;
          } catch (error) {
            closeError = error;
            // "lease is closed" (close()'s own message for a non-ACTIVE lease) means someone else --
            // sweepOrphanedLeases() above, or a genuine race with a live review()/recoverOrphanedLeases()
            // call finishing this same lease normally -- already closed it; retrying can never help and
            // every job here is already reconciled at real money, so this is expected and harmless.
            if (/lease is closed/i.test(error?.message ?? '')) break;
          }
        }
        if (closeError !== null && !/lease is closed/i.test(closeError?.message ?? '')) {
          // Anything else (a disk I/O failure, a lock timeout) surviving both attempts would otherwise
          // leave every job on this lease already RECONCILED at real cost -- no money or content at
          // risk -- but the lease record itself stuck ACTIVE, with no future retry ever finding a
          // stale job left to recover from it (sweepOrphanedLeases() itself only ever touches a lease
          // it still finds >=1 RESERVED job on). Loud but non-fatal, matching this codebase's
          // established convention (see processDispatchOutcome's own resultStore.record() failure
          // handling) that a durable-write failure here must stay visible rather than being silently
          // swallowed, even though it can't be allowed to abort the recovery itself.
          //
          // ACCEPTED RESIDUAL: if BOTH attempts fail, nothing further makes this structurally
          // impossible without materially more machinery -- a durable "pending close" mechanism that
          // some FUTURE sweep, not gated on sweepOrphanedLeases()'s own reservedJobs>0 filter, could
          // retry indefinitely, which is a larger change than orphan recovery itself needs
          // (reconciling at real cost and preserving content, not a general lease lifecycle
          // redesign). Judged disproportionate given the actual stakes: this is a
          // lease-record STATE LABEL only -- every job on the lease is already durably RECONCILED at its real cost
          // with content already persisted to resultStore BEFORE this close() call ever runs, and
          // openrouter_review_result reads the ledger/resultStore directly, never gated on
          // lease.state -- so a permanently-ACTIVE label here costs nothing in money or content, only
          // a slightly confusing status() read. Requires two consecutive close() failures to reach at
          // all. This is the same category of already-accepted structural residual this codebase
          // documents elsewhere (e.g. lease-store.mjs's own N-way concurrent-writer lock race) --
          // logged loudly so a human can investigate if it ever actually happens, not silently
          // tolerated.
          try {
            process.stderr.write(`openrouter-review-engine: recoverStaleLease-close-failed leaseId=${candidateLeaseId} error=${safeErrorDetail(closeError)}\n`);
          } catch {
            // A logging failure itself must never abort recovery.
          }
        }
      } catch (error) {
        // A failure reading this lease's own jobs (e.g. the same lock-timeout class guarded above)
        // -- log and move on to the next lease rather than losing the whole batch.
        try {
          process.stderr.write(`openrouter-review-engine: recoverStaleLease-close-loop-failed leaseId=${candidateLeaseId} error=${safeErrorDetail(error)}\n`);
        } catch {
          // A logging failure itself must never abort recovery.
        }
      }
    }

    // Build ONE combined, fresh-read result per touched lease -- a caller reading
    // .reconciledJobs must see EVERY job resolved during this recovery, whether the pre-pass's
    // real-cost path or the worst-case fallback resolved it, not just whichever mechanism happened
    // to run last.
    //
    // Checking merely `!== 'ACTIVE'` here would be too permissive. A genuinely still-alive, slow
    // live review() call for this SAME lease can be independently finishing throughout this whole
    // function's run (a multi-minute delay is possible, which orphanSweepGraceMs's own grace window
    // narrows but cannot fully eliminate) -- and if IT reaches
    // finalizeReviewOutcome() and halts with its own, more specific close code (e.g.
    // PROVIDER_MISMATCH) in the gap between this function's pre-pass/fallback and this final read,
    // that lease is `!== 'ACTIVE'` for a reason that has NOTHING to do with this recovery. Reporting
    // it here anyway would misrepresent an unrelated, genuinely-live completion as something THIS
    // recovery resolved. 'ORPHANED_ON_RECOVERY' is the one close code exclusively produced by
    // sweepOrphanedLeases() and this function's own explicit close-loop above, never by the normal
    // live review() path (a genuine PASS never calls close() at all -- closeCode is null -- and every
    // HALT closes under its OWN specific failure code) -- checking for it precisely is what makes
    // "resolved BY THIS recovery" and "closed for some unrelated reason" distinguishable.
    // Wrapped the same way as the close-loop above: a failure reading ONE lease's final state must
    // not drop every OTHER already-recovered lease from this batch's own return value.
    const results = [];
    for (const [candidateLeaseId, jobIds] of staleJobIdsByLease) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const finalLease = await leaseStore.getLease(candidateLeaseId);
        if (!finalLease || finalLease.state !== 'ORPHANED_ON_RECOVERY') continue;
        // eslint-disable-next-line no-await-in-loop
        const reconciledJobs = await Promise.all([...jobIds].map((jobId) => leaseStore.getJob(jobId)));
        results.push({ leaseId: candidateLeaseId, lease: finalLease, reconciledJobs });
      } catch (error) {
        try {
          process.stderr.write(`openrouter-review-engine: recoverStaleLease-final-read-failed leaseId=${candidateLeaseId} error=${safeErrorDetail(error)}\n`);
        } catch {
          // A logging failure itself must never abort recovery.
        }
      }
    }
    return results;
  }

  /**
   * Pure verdict logic for one due pending-verdict record: replays the same read-only validation
   * steps processDispatchOutcome()'s RESPONSE branch uses (decode envelope, extract cost, check
   * provider, completion, validate content), minus its ledger-writing tail (no leaseStore.reconcile(), no
   * resultStore.record(), no desubstituteFinding()) -- see this file's own processDispatchOutcome()
   * for the branch this mirrors. The job's real billing outcome is already final (closed at
   * force-close time by ambiguousDispatching); this function's only job is answering "would this
   * have validated as a real success," never re-deciding or re-charging anything. Never calls
   * leaseStore, resultStore, or scrubMappingStore -- both values it needs (reviewerId,
   * reservationUsd) come from the pending record itself, not the ledger, keeping the "this sweep
   * never touches the ledger" property literally true.
   */
  async function resolveOneHealthVerdict(record) {
    const dispatchOutcome = await dispatchOutcomeStore.recall({ jobId: record.jobId });
    if (!dispatchOutcome || dispatchOutcome.kind === 'DISPATCHING') return false;
    if (dispatchOutcome.kind === 'FAILURE') return false;

    const reviewer = getReviewer(record.reviewerId);
    const reviewerSummary = { maxUsd: record.reservationUsd };

    let parsedBody = null;
    try {
      parsedBody = decodeEnvelopeBody(dispatchOutcome);
    } catch {
      parsedBody = null;
    }

    const cost = parsedBody ? extractFiniteNonnegativeCost(parsedBody) : null;
    // A known cost above the reservation is still a completed dispatch;
    // the overrun is reported by its own alert when the job is reconciled, not as a health failure.
    if (cost === null) return false;
    if (parsedBody.provider !== reviewer.expectedProvider) return false;
    if (!isAcceptedReviewCompletion(parsedBody)) return false;

    const contentText = parsedBody?.choices?.[0]?.message?.content;
    const cleanedContentText = selectContentTextForValidation(contentText, reviewer);
    const contentResult = typeof cleanedContentText === 'string' ? validateAdvisoryContent(cleanedContentText) : { ok: false };
    return contentResult.ok === true;
  }

  /**
   * Resolves every due pending dispatch-health verdict (a record written when ambiguousDispatching
   * force-closed a job whose real outcome was still unknown). A record that resolves as a real
   * failure, or that is past the backstop, records one dispatch-health failure; a record that
   * resolves as a genuine success is silently removed and never recorded. A deferred success must
   * never call recordDispatchHealthOutcome({ succeeded: true }): dispatch-health-store.mjs's success
   * unconditionally resets the streak to 0 with no per-job memory, so a deferred success resolving
   * AFTER an unrelated, later, real failure would silently erase that real failure's count.
   */
  async function resolvePendingHealthVerdicts() {
    const now = clock();
    const pending = await pendingHealthVerdictStore.list();
    for (const record of pending) {
      if (now < record.notBeforeMs) continue;
      // Production runs this sweep only from the ownership coordinator's arm cycle (startup takes
      // no ownership), and the per-job claim below is the defense-in-depth that still resolves each
      // verdict at most once if two processes ever do sweep one data root at the same time. Per
      // record, in this order:
      //   1. claim -- an exclusive create. On a loss, the existing claim is read back:
      //      'absent' (its holder released it after our create lost) gets one more claim; a claim
      //      whose holder crashed or hung -- readable and older than healthVerdictBackstopMs, or
      //      unreadable (truncated mid-write) with a file older than healthVerdictGraceMs -- is taken
      //      over: force-released, then claimed once more, and the record resolved below, with its
      //      backstop measured at the crashed claimer's time rather than now (backstopAsOfMs). The
      //      taker's own claim carries that instant as gradeAsOfMs, so if the taker dies too, the
      //      next takeover still grades from it.
      //      Anything else, and a retry or takeover that loses again, is a clean skip. A record is
      //      never dropped uncounted, so each verdict is still counted exactly once.
      //   2. re-read the record under the claim -- load-bearing on every path, the first-try win, the
      //      retry and the takeover alike: a process that listed early and claims after the holder
      //      finished would otherwise resolve the same job a second time.
      //   3-5. verdict, remove, record a failure -- unchanged, including delete-then-record.
      //   6. release the claim in the finally, and only after a successful claim, so the record is
      //      always removed BEFORE its claim is released, and a throw frees the claim for a retry.
      let claimId = null;
      // The instant the record backstop is measured at: now, except after a takeover (step 1).
      let backstopAsOfMs = now;
      try {
        // eslint-disable-next-line no-await-in-loop
        let claim = await pendingHealthVerdictStore.claim({ jobId: record.jobId, nowMs: now });
        if (claim.claimed !== true) {
          // eslint-disable-next-line no-await-in-loop
          const held = await pendingHealthVerdictStore.recallClaim({ jobId: record.jobId });
          if (held.status === 'absent') {
            // eslint-disable-next-line no-await-in-loop
            claim = await pendingHealthVerdictStore.claim({ jobId: record.jobId, nowMs: now });
          } else if ((held.status === 'held' && now - held.claim.claimedAtMs > healthVerdictBackstopMs)
            || (held.status === 'unreadable' && now - held.mtimeMs > healthVerdictGraceMs)) {
            // No live sweep holds a claim for the whole backstop, and a claim file still being
            // written is milliseconds old, so its holder is gone: take the claim over.
            // Grade the record as of the moment the crashed claimer took it (its claimedAtMs, or an
            // unreadable file's mtimeMs), not now. A sweep claims a record only once it is due, so
            // every claim old enough to take over is itself past the record backstop measured from
            // now: measured from now, every takeover would be forced to a failure and a real success
            // whose sweep crashed would never be graded. A claim that was itself a
            // takeover carries the instant it inherited (gradeAsOfMs), and the new claim below
            // carries it on. It survives a crashed taker, not a throw: a throw below releases the
            // claim in the finally, so the next sweep measures from now and a record whose
            // resolution throws every time is still counted, never retried forever.
            // A real file's mtimeMs has a fractional part, and gradeAsOfMs must be a safe integer
            // like claimedAtMs, so the mtime is floored to a whole ms here, the way Date.now() floors
            // wall time. The grace test above keeps the exact mtimeMs.
            backstopAsOfMs = held.status === 'held' ? (held.claim.gradeAsOfMs ?? held.claim.claimedAtMs) : Math.floor(held.mtimeMs);
            // eslint-disable-next-line no-await-in-loop
            await pendingHealthVerdictStore.releaseClaim({ jobId: record.jobId, claimId: null });
            // eslint-disable-next-line no-await-in-loop
            claim = await pendingHealthVerdictStore.claim({ jobId: record.jobId, nowMs: now, gradeAsOfMs: backstopAsOfMs });
            try {
              process.stderr.write(`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${record.jobId} found=${held.status} won=${claim.claimed === true}\n`);
            } catch {
              // A logging failure itself must never abort the sweep.
            }
          }
          if (claim.claimed !== true) continue;
        }
        claimId = claim.claimId;
        // eslint-disable-next-line no-await-in-loop
        const fresh = await pendingHealthVerdictStore.recall({ jobId: record.jobId });
        if (fresh === null) continue;
        // Backstop: a record this stale skips the real outcome check entirely and resolves
        // succeeded:false unconditionally, regardless of what dispatchOutcomeStore holds -- a
        // record surviving this long past its deadline implies the sweep mechanism itself hasn't
        // run in a very long time, itself a symptom worth surfacing as a failure rather than a case
        // still worth the normal, more careful check. Measured at
        // backstopAsOfMs: now, or after a takeover the crashed claimer's own claim time.
        let succeeded;
        if (backstopAsOfMs - fresh.notBeforeMs > healthVerdictBackstopMs) {
          succeeded = false;
        } else {
          // eslint-disable-next-line no-await-in-loop
          succeeded = await resolveOneHealthVerdict(fresh);
        }
        // eslint-disable-next-line no-await-in-loop
        await pendingHealthVerdictStore.remove({ jobId: record.jobId });
        // A resolved success is silently dropped here -- see this function's own docstring above for
        // why recordDispatchHealthOutcome must never be called with succeeded:true from this sweep.
        if (!succeeded) {
          // eslint-disable-next-line no-await-in-loop
          await recordDispatchHealthOutcome({ succeeded: false });
        }
      } catch (error) {
        try {
          process.stderr.write(`openrouter-review-engine: resolve-pending-health-verdict-failed jobId=${record.jobId} error=${safeErrorDetail(error)}\n`);
        } catch {
          // A logging failure itself must never abort the sweep.
        }
      } finally {
        if (claimId !== null) {
          try {
            // eslint-disable-next-line no-await-in-loop
            await pendingHealthVerdictStore.releaseClaim({ jobId: record.jobId, claimId });
          } catch (releaseError) {
            try {
              process.stderr.write(`openrouter-review-engine: pending-health-verdict-claim-release-failed jobId=${record.jobId} error=${safeErrorDetail(releaseError)}\n`);
            } catch {
              // A logging failure itself must never abort the sweep.
            }
          }
        }
      }
    }
  }

  /**
   * Sweeps every eligible expired lease in the store (not just one the
   * caller already knows about) and, per recoverStaleLease() above, reconciles each stale RESERVED
   * job at its real cost where a durable dispatch-outcome capture makes that determinable, falling
   * back to the conservative worst-case charge otherwise. Production does not call
   * this export: the coordinator's arm cycle runs the same
   * store-wide recoverStaleLease() sweep internally, once per cycle in which it arms, so a lease
   * orphaned by a PRIOR process instance's crash is still recovered by the next process to arm,
   * even if nobody ever calls review() again for it -- review()'s own recovery
   * path (see above) only fires when a caller happens to retry with the
   * exact leaseId/preflightId. Same orphanSweepGraceMs grace window either
   * way, so a dispatch that may still be legitimately finishing is never
   * raced. Safe to call with nothing to recover (returns an empty array).
   */
  async function recoverOrphanedLeases(ownerToken) {
    requireOwnerToken(ownerToken);
    // A store-wide sweep is just recoverStaleLease() with no specific lease in mind -- dispatch
    // health is already recorded inside it for every job the worst-case fallback resolves, so
    // there is nothing left for this wrapper to do beyond passing leaseId through as undefined.
    return recoverStaleLease({ leaseId: undefined, staleAfterMs: orphanSweepGraceMs, ownerToken });
  }

  // The busy-ledger boundary translation: every export below that can reach the
  // lease store -- preflight, authorizeWorkflow, status, review, result and recoverOrphanedLeases --
  // is wrapped in withLedgerBusyBoundary(), so a raw data-root lock timeout escaping any of them
  // becomes LEDGER_BUSY. The boundary wraps each export from the OUTSIDE, around
  // refuseIfShuttingDown() and trackInFlight() too, so what awaitDrain tracks is still the
  // operation's own promise. "Bare" in the comments below means no shutdown refusal and no
  // trackInFlight; it never means outside this boundary.
  return Object.freeze({
    preflight: withLedgerBusyBoundary(preflight),
    // authorizeWorkflow, review and recoverOrphanedLeases are the three owner-sensitive entry
    // points -- each one reaches an owner-fenced leaseStore mutation -- so those three, and only
    // those three, are wrapped here: for shutdown (trackInFlight) and for arming
    // (coordinator.runOperation, awaited inside the tracked promise). Each fenced write carries the
    // frozen ownerToken snapshot captured by that complete-operation bracket, never a live ownerLock
    // read. The other exports on this object (preflight, status,
    // result, isAutonomousAuthorizationEnabled) reach no owner-fenced write and are left bare.
    //
    // recoverOrphanedLeases must be wrapped too, even though it is easy to overlook: exported
    // unwrapped while performing owner-fenced writes, a drain could report itself complete and
    // release process ownership with those writes still in flight. The export has no production
    // caller: startup does not sweep, and the arm cycle uses the internal recoverStaleLease() path
    // (the comment on the recoverOrphanedLeases wrapper below says why it must).
    //
    // Deliberately `async`, not a bare arrow: refuseIfShuttingDown() throws SYNCHRONOUSLY, and from
    // a non-async arrow that throw escapes during the CALLER's own expression evaluation, before
    // any promise exists for a handler to attach to. Every caller on this surface (the MCP tool
    // layer, every test) treats a failure here as a rejection, so `async` is what makes the refusal
    // reach them the same way every other failure already does.
    //
    // What gets registered as outstanding is trackInFlight's argument. That is ONE promise covering the on-demand arm AND the real call together, so a
    // drain can never report itself complete -- and the composition root release ownership -- while
    // an arm is still acquiring or a call it admitted is still running. The whole body sits inside
    // trackInFlight's argument for exactly that reason: an arm awaited outside it would be invisible
    // to awaitDrain. The extra promise `async` wraps around it settles a couple of microtasks later
    // and is not what awaitDrain counts, which is why outstandingCount reflects real work and not
    // wrapper bookkeeping.
    //
    // Each wrapper runs through the ownership coordinator's admission census, arm/recovery cycle,
    // callback and last-operation release. The coordinator captures the frozen ownerToken the call's
    // fenced writes use. authorizeWorkflow and review ask for the once-per-arm cycle recovery;
    // recoverOrphanedLeases does not, because it performs that same sweep itself right after -- asking
    // for both would sweep twice. Its own cycle is the ORPHAN sweep only; after the operation's
    // completion release, a later authorizeWorkflow or review re-arms and runs the pending-health
    // sweep in its fresh cycle. Production does not call this export, but its explicit behavior
    // remains covered independently.
    //
    // Each of the three stays inside withLedgerBusyBoundary() (the boundary translation), which
    // wraps it from the OUTSIDE and awaits its promise. trackInFlight's argument is therefore still
    // the operation's own promise (the arm plus the call): the boundary can turn a raw lock timeout
    // into LEDGER_BUSY for the caller, but it never becomes what awaitDrain waits on.
    authorizeWorkflow: withLedgerBusyBoundary(async (...args) => {
      refuseIfShuttingDown();
      return trackInFlight(coordinator.runOperation(
        { runCycleRecovery: true },
        ({ ownerToken }) => authorizeWorkflow(args[0], ownerToken),
      ));
    }),
    status: withLedgerBusyBoundary(status),
    review: withLedgerBusyBoundary(async (...args) => {
      refuseIfShuttingDown();
      return trackInFlight(coordinator.runOperation(
        { runCycleRecovery: true },
        ({ ownerToken }) => review(args[0], ownerToken),
      ));
    }),
    result: withLedgerBusyBoundary(result),
    // Wrapped for the same two reasons authorizeWorkflow and review are, and `async` for the same
    // third: recoverStaleLease() reconciles and closes leases under the ownerToken this wrapper
    // snapshots after arming, so this must both refuse to START once shutdown begins and be
    // counted by awaitDrain while it runs.
    //
    // Wrapping the EXPORT does not touch the internal path, and that asymmetry is deliberate rather
    // than an oversight. review() reaches stale-lease recovery by calling recoverStaleLease()
    // directly, never this export, so a review admitted before shutdown still completes its own
    // recovery during the drain -- correct, since awaitDrain is already waiting on that review's
    // own promise. The ownership coordinator's arm cycle (runCycleWork above) uses the internal path
    // too, and must: this export arms through that same coordinator, so calling it from inside the
    // arm cycle would join the very cycle it runs in and never settle. Only a fresh,
    // externally-initiated sweep is refused.
    recoverOrphanedLeases: withLedgerBusyBoundary(async () => {
      refuseIfShuttingDown();
      return trackInFlight(coordinator.runOperation(
        { runCycleRecovery: false },
        ({ ownerToken }) => recoverOrphanedLeases(ownerToken),
      ));
    }),
    // Deliberately left BARE, unlike the three
    // above -- per this object's own comment at the top, only an export reaching an owner-fenced
    // leaseStore mutation (one carrying the caller's ownerToken) gets refuseIfShuttingDown()/
    // trackInFlight(). resolvePendingHealthVerdicts() never calls leaseStore at all (see its own
    // docstring) -- it only touches pendingHealthVerdictStore and dispatchHealthStore, neither of
    // which is owner-fenced -- so it belongs with status/result/isAutonomousAuthorizationEnabled
    // below, not with this trio. Production never calls this export: the arm cycle (runCycleWork) calls the inner function right after
    // orphan recovery, so only the armed owner ever writes dispatch-health.json. The export stays
    // bare for tests and direct callers.
    resolvePendingHealthVerdicts,
    ...(managedModeEnabled ? {
      runManagedOperation: withLedgerBusyBoundary(runManagedOperation),
      resolveManagedPolicy: withLedgerBusyBoundary(resolveManagedPolicy),
      statusForPolicy: withLedgerBusyBoundary(statusForPolicy),
      resultForPolicy: withLedgerBusyBoundary(resultForPolicy),
      requestManagedResult: withLedgerBusyBoundary(requestManagedResult),
      preflightForPolicy: withLedgerBusyBoundary(preflightForPolicy),
      authorizeForPolicy: withLedgerBusyBoundary(authorizeForPolicy),
      prepareReview: withLedgerBusyBoundary(prepareReview),
      executePreparedReview: withLedgerBusyBoundary(executePreparedReview),
      recoverManagedReceipt: withLedgerBusyBoundary(recoverManagedReceipt),
    } : {}),
    isAutonomousAuthorizationEnabled() {
      return autonomousAuthorization === true;
    },
    /**
     * Refuses every SUBSEQUENT authorizeWorkflow/review call with SHUTTING_DOWN. Idempotent, and
     * deliberately leaves anything already in flight alone -- draining those is awaitDrain's job,
     * and nothing here ever cancels paid work that may already be running. One-way: an engine that
     * has begun shutting down never resumes.
     */
    beginShutdown() {
      shuttingDown = true;
    },
    /**
     * Waits up to `timeoutMs` for every currently-tracked operation to settle. Reports
     * `{ drained: true, outstandingCount: 0 }` when they all did, or `{ drained: false,
     * outstandingCount }` naming how many were still outstanding when the timeout won, so the
     * composition root can choose between releasing process ownership cleanly and exiting with work
     * still running. Purely observational: it never cancels, halts, or refuses anything.
     */
    async awaitDrain({ timeoutMs } = {}) {
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
        throw new TypeError('timeoutMs must be a non-negative safe integer');
      }
      const tracked = [...inFlightOperations];
      if (tracked.length === 0) return { drained: true, outstandingCount: 0 };
      const TIMEOUT_SENTINEL = Symbol('awaitDrain-timeout');
      // The handle is captured so the settled path can clear it below. An uncleared pending timer
      // keeps Node's event loop alive for the remainder of timeoutMs, which for a helper whose
      // whole purpose is letting the process exit promptly would delay the exact shutdown it was
      // called to enable -- by however long the caller's own drain budget happens to be.
      let timeoutHandle;
      const timeoutPromise = new Promise((resolve) => {
        timeoutHandle = setTimeout(() => resolve(TIMEOUT_SENTINEL), timeoutMs);
      });
      try {
        const settleAll = Promise.allSettled(tracked).then(() => 'drained');
        const outcome = await Promise.race([settleAll, timeoutPromise]);
        return outcome === TIMEOUT_SENTINEL
          ? { drained: false, outstandingCount: inFlightOperations.size }
          : { drained: true, outstandingCount: 0 };
      } finally {
        clearTimeout(timeoutHandle);
      }
    },
  });
}
