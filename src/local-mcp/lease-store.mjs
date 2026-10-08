import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { promisify } from 'node:util';
import { canonicalJson } from './shared/contracts.mjs';
import { createSharedLedgerState } from './shared/ledger-state.mjs';
import { configurationFingerprint, largestAllowedReviewerCount, maximumPreflightEncryptedBytes, maximumPreparedEncryptedBytes, validateInstallationConfig } from './shared/policy.mjs';

const execFileAsync = promisify(execFile);

const FORBIDDEN_FIELD = /^(?:source_?text|request_?body|response_?body|api_?key)$/i;
const HASH = /^[a-f0-9]{64}$/;
// Whether a reconciled cost is a real, validated figure ('KNOWN'), a proven-zero cost for a
// transport failure that provably preceded any received response ('ZERO_ON_TRANSPORT_FAILURE' --
// see review-engine.mjs's ZERO_COST_TRANSPORT_FAILURE_KINDS), or a conservative worst-case
// placeholder charged because the true outcome could not be determined
// ('UNKNOWN_WORST_CASE_CHARGED'). Without this field, a worst-case charge reconciled
// at TRANSPORT_FAILURE/UNKNOWN_COST/DISPATCH_UNKNOWN time is, once persisted, indistinguishable
// from a genuine confirmed cost -- the ledger would record only costUsd, never which kind of figure
// it was. review-engine.mjs already computes this distinction in-process; this just makes it durable
// so a LATER caller (a fresh process, openrouter_review_result, a human auditing spend) can still
// tell them apart instead of the ledger silently forgetting. Deliberately excludes
// 'RECOVERED_STATUS_ONLY' (review-engine's own "no ledger job to classify at all" sentinel) and
// 'REUSED_FROM_PRIOR_LEASE' (never persisted here -- a reused reviewer never calls consume()/
// reconcile() on its own lease at all, by design) -- neither is a real reconcile() outcome this
// store should accept.
// 'ZERO_ON_PROVIDER_REJECTION' is deliberately DISTINCT from
// 'ZERO_ON_TRANSPORT_FAILURE' rather than folded into it: that one means no response was ever
// received, while this one means a response WAS received and it was the provider refusing to run
// the request at all (a 4xx pre-inference reject -- no provider routed to, no tokens generated).
// Reusing the transport kind would have made its own docstring false, and this ledger is
// append-only, so a mislabelled record can never be corrected in place. Additive by construction:
// haltAndClose keys retry-safety on `costKind === 'KNOWN'`, so a new zero-cost kind inherits the
// conservative not-retry-safe default automatically, exactly as ZERO_ON_TRANSPORT_FAILURE does.
const COST_KIND = new Set(['KNOWN', 'UNKNOWN_WORST_CASE_CHARGED', 'ZERO_ON_TRANSPORT_FAILURE', 'ZERO_ON_PROVIDER_REJECTION']);

function clone(value) { return structuredClone(value); }
function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}
function deriveReviewerJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256')
    .update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8')
    .digest('hex');
}
function requireObject(value, name) { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`); return value; }
function requireId(value, name) { if (typeof value !== 'string' || value.length === 0 || value.length > 256) throw new TypeError(`${name} must be a non-empty opaque ID`); return value; }
function requireHash(value, name) { if (typeof value !== 'string' || !HASH.test(value)) throw new TypeError(`${name} must be a lowercase SHA-256 digest`); return value; }
function requireUsd(value, name) { if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new TypeError(`${name} must be a finite non-negative USD amount`); return value; }
function requireCostKind(value) { if (!COST_KIND.has(value)) throw new TypeError('costKind must be one of KNOWN, UNKNOWN_WORST_CASE_CHARGED, ZERO_ON_TRANSPORT_FAILURE, ZERO_ON_PROVIDER_REJECTION'); return value; }
// Optional, minimal durable marker distinguishing a genuine halt (haltAndClose, e.g.
// PROVIDER_MISMATCH, or the dispatch-rejection recovery path's own DISPATCH_UNKNOWN) from a
// genuine clean-pass success whose content-recording step never completed -- see reconcile()'s own
// docstring for why this ambiguity matters. Deliberately just the halt's short code, never the full
// free-form message (review-engine.mjs already reports that transiently; persisting it here would
// widen this store's forbidden-field surface for no safety benefit).
function requireHaltReason(value) { if (typeof value !== 'string' || value.length === 0 || value.length > 128) throw new TypeError('haltReason must be a non-empty short string'); return value; }
// A reconciled cost may exceed the job's reservation only when the caller says so explicitly and
// truthfully: a provider-reported KNOWN cost above the reservation is real spend (some models bill
// hidden reasoning past max_tokens), and booking the reservation instead would under-record it.
// Recording more than was reserved can only fail closed. Without the flag the old
// refusal stands, so an ordinary reconcile can never overshoot by accident. The flag is stored as
// `aboveReservation: true` on the job and is otherwise absent.
function checkedReconcileCost({ costUsd, costKind, aboveReservation, reservationUsd }) {
  const cost = requireUsd(costUsd, 'costUsd');
  if (aboveReservation === undefined) {
    if (cost > reservationUsd) throw new RangeError('known cost exceeds reservation');
    return { cost, aboveReservationField: {} };
  }
  if (aboveReservation !== true || costKind !== 'KNOWN' || !(cost > reservationUsd)) {
    throw new RangeError('aboveReservation is only valid for a KNOWN cost above the reservation');
  }
  return { cost, aboveReservationField: { aboveReservation: true } };
}
function requirePositiveInteger(value, name) { if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`); return value; }
function requireFutureTimestamp(value, name) { if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new TypeError(`${name} must be an ISO timestamp`); return value; }
function assertTimestampNotExpired(expiresAt, nowMs, kind) { if (Date.parse(expiresAt) <= nowMs) throw new Error(`${kind} is expired`); }
function maxItemUsd(items) { return items.reduce((total, item) => total + item.maxUsd, 0); }
// Reserved USD is a running float sum, so adding and releasing reservations in different orders leaves
// residue of about 1e-17 (for example -5.55e-17, which the shared ledger refuses as negative money).
// Snap anything under a billionth of a dollar to zero when a reservation is released. The admission cap
// check stays strict: it must never admit a reservation above the authorized amount.
const USD_RESIDUE = 1e-9;
function releaseReservedUsd(reservedUsd, releasedUsd) { const remaining = reservedUsd - releasedUsd; return Math.abs(remaining) < USD_RESIDUE ? 0 : remaining; }
// An object literal (or a null-prototype object): not an array, not a class instance, not an
// object that inherits fields a caller never meant to pass.
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function requireExactObject(value, required, optional = [], name = 'input') {
  canonicalJson(value);
  if (!isPlainObject(value)) throw new TypeError(`${name} must be a plain object`);
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !Object.hasOwn(value, key)) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw new TypeError(`${name} has an invalid shape`);
  }
  return value;
}
// -0 and 0 are the same cap, but Object.is(-0, 0) is false, so a cap is normalized before it is
// stamped or compared.
function normalizeNegativeZero(value) { return Object.is(value, -0) ? 0 : value; }
// Replay-side validation of an ACQUIRED record's `caps`. Absent, or undefined or
// null per member, means "not recorded", which is bootstrap-compatible. A present member that is not
// a finite number >= 0 fails replay closed, like every other malformed processOwner field. Members
// this code does not know are ignored, as replay already ignores unknown top-level fields. Returns
// only the members that are present.
function normalizeRecordedCaps(value) {
  if (value === undefined || value === null) return {};
  if (!isPlainObject(value)) throw new Error('processOwner ACQUIRED record has invalid caps');
  const recorded = {};
  for (const member of CAP_MEMBERS) {
    const cap = value[member];
    if (cap === undefined || cap === null) continue;
    if (typeof cap !== 'number' || !Number.isFinite(cap) || cap < 0) {
      throw new Error(`processOwner ACQUIRED record has invalid caps.${member}`);
    }
    recorded[member] = normalizeNegativeZero(cap);
  }
  return recorded;
}

function assertNoForbiddenFields(value) {
  if (Array.isArray(value)) return value.forEach(assertNoForbiddenFields);
  if (value !== null && typeof value === 'object') for (const [key, nested] of Object.entries(value)) {
    if (FORBIDDEN_FIELD.test(key)) throw new TypeError(`forbidden field: ${key}`);
    assertNoForbiddenFields(nested);
  }
}

function normalizeItemMaxima(value) {
  if (!Array.isArray(value) || value.length === 0) throw new TypeError('itemMaxima must be a non-empty array');
  return value.map((item, index) => {
    requireObject(item, `itemMaxima[${index}]`);
    return { itemId: requireId(item.itemId, `itemMaxima[${index}].itemId`), maxUsd: requireUsd(item.maxUsd, `itemMaxima[${index}].maxUsd`) };
  });
}

function defaultIsProcessAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error?.code !== 'ESRCH'; }
}

// How much later than its own ACQUIRED record a process may claim to have started before we stop
// believing it is that record's owner. A genuine owner ALWAYS starts before it writes its record,
// so any positive gap is already anomalous -- this margin exists only to absorb a backward clock
// step (an NTP correction) between the two readings. It is deliberately generous: a recycled PID
// typically appears hours or days after the original owner exited, so nothing realistic is lost by
// refusing to act on a gap of minutes, while a too-small margin risks the one outcome this whole
// mechanism exists to prevent -- two live processes both believing they own the ledger.
const OWNER_START_TIME_SKEW_MARGIN_MS = 300_000;

// Identity of one ownership CLAIM, not of a pid. All three parts matter: a later generation is a
// different owner even on the same pid, and acquisitionId is what every owner-fenced write
// already checks (`assertCurrentlyOwnsProcess`).
function ownerKey(owner) {
  return `${owner.acquisitionId}:${owner.generation}:${owner.pid}`;
}

// Epoch-ms creation time of a live process, or null when it cannot be determined.
//
// `defaultIsProcessAlive` above answers only "does something hold this PID", which Windows
// answers YES for a recycled PID (the PID may now belong to an unrelated process) and, because it
// treats every non-ESRCH error as alive, also for a protected process the caller may not signal
// (for example, pid 4 returns EPERM -> "alive").
// A creation time is what distinguishes "this PID exists" from "this PID is still the process
// that wrote the ownership record".
//
// PowerShell is used because the alternatives do not work: on current Windows `wmic` may be absent
// (spawnSync ENOENT), `tasklist` reports an image name but no start time, and an exclusive file
// handle is not a usable liveness primitive (a second opener succeeds). The arithmetic is done
// IN PowerShell so an epoch integer crosses the boundary -- never a formatted date, which renders
// in local time and would make a process compare unequal to itself.
//
// Returns null rather than throwing on every failure, and is null on non-Windows: a null is
// "no proof of death", which leaves today's behaviour exactly unchanged.
async function defaultProcessStartTimeMs(pid) {
  if (process.platform !== 'win32') return null;
  const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
  if (typeof systemRoot !== 'string' || !isAbsolute(systemRoot)) return null;
  // `pid` is interpolated into a PowerShell -Command string below, so it must be a number and not
  // a string that could carry a statement separator. Passing the script as one execFile argument
  // stops a SHELL from splitting it, but PowerShell itself would still parse an injected `;`.
  //
  // Unreachable as things stand -- every pid reaching here came from a processOwner record, and
  // applyProcessOwnerRecord runs requirePositiveInteger on it during replay, so a malformed pid
  // throws long before this function is called. This guard exists because processStartTimeMs is an
  // injectable seam: it makes the function safe on its own terms rather than on its caller's.
  // Deliberately not covered by a test -- the state it defends against cannot be constructed
  // through the store, and exporting this function purely to reach it would widen the API to
  // create the very reachability the guard is asserting does not exist.
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  const script = `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; `
    + 'if ($p) { [long]($p.StartTime.ToUniversalTime() - [datetime]\'1970-01-01\').TotalMilliseconds }';
  try {
    const { stdout } = await execFileAsync(
      join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 10_000, windowsHide: true },
    );
    const parsed = Number.parseInt(String(stdout).trim(), 10);
    return Number.isSafeInteger(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function utcDayKey(isoTimestamp) {
  return isoTimestamp.slice(0, 10);
}

const OWNER_ACQUISITION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function requireOwnerAcquisitionId(value) {
  if (typeof value !== 'string' || !OWNER_ACQUISITION_ID.test(value)) {
    throw new TypeError('acquisitionId must be a UUID string');
  }
  return value;
}

/**
 * Every "the data root's global write lock is held by someone else right now" failure carries this
 * code. It is a TRANSIENT, self-healing condition: the holder finishes, or -- once its lock has
 * aged past `lockStaleMs` AND its owning pid is confirmed dead -- the next caller reclaims it.
 * Age alone is NEVER sufficient; reclaim is the conjunction enforced at the `isProcessAlive`
 * call sites below. Two
 * readers: the ownership attempt loop below (runOwnershipAttempts), which must tell this apart
 * from a structural failure (a corrupt record, a bad argument) that has to abort immediately
 * rather than be retried for the whole acquire budget; and, through the exported
 * LEDGER_DATA_ROOT_LOCKED_CODE, the review engine, which reports it to a tool caller as a busy
 * ledger.
 *
 * Deliberately a plain property on the existing Error, not a new error TYPE. As the comment on
 * RELEASE_RENAME_RETRY_ATTEMPTS below explains, threading a new exception through `mutate()`'s many
 * call sites breaks the "if this throws, nothing happened" assumption every one of them is written
 * against. Adding a
 * property is purely additive: the message each existing caller already sees is unchanged.
 */
export const LEDGER_DATA_ROOT_LOCKED_CODE = 'LEDGER_DATA_ROOT_LOCKED';
// This file's own short alias for the export above; every existing reference below uses it.
const DATA_ROOT_LOCKED_CODE = LEDGER_DATA_ROOT_LOCKED_CODE;

/**
 * An ownership attempt loop spent its whole budget without acquiring. Thrown by
 * acquireProcessOwnership() and by a handle's arm(), which share the loop, as a plain Error. For
 * acquireProcessOwnership() the message text is exactly what it has always thrown; arm()'s reads
 * the same with "arm" in place of the method name. The properties are purely additive: `reason`
 * ('LIVE_OWNER' | 'NOT_YET_STALE' | 'DATA_ROOT_LOCKED') and, for the first two only, `owner`
 * ({ pid, generation, timestamp }) and `ownerAgeMs`. `owner` is the process whose ownership or cap
 * record blocked arming; during the bounded cap-probe fallback its ACQUIRED record may since have
 * been cleanly released, but that live process can still re-arm under the recorded caps.
 * DATA_ROOT_LOCKED concerns the data-root write lock, not a processOwner record, so it names no
 * holder.
 */
export const PROCESS_OWNERSHIP_UNAVAILABLE_CODE = 'PROCESS_OWNERSHIP_UNAVAILABLE';
// arm() re-entered while an arm is already in flight on the same handle. Joining concurrent callers
// is the ownership coordinator's job; the handle makes a re-entry loud instead of racing it.
export const ARM_IN_PROGRESS_CODE = 'ARM_IN_PROGRESS';
// arm() on a handle whose final release has landed. The store knows nothing about shutdown, so this
// is its own code; the ownership coordinator translates it to the engine's SHUTTING_DOWN.
export const OWNER_HANDLE_RELEASED_CODE = 'OWNER_HANDLE_RELEASED';
export const OWNER_RELEASE_PENDING_CODE = 'OWNER_RELEASE_PENDING';
// arm()'s caller-supplied shouldAbort() read true, or threw, before an attempt started. A
// throw is a stop request too, carried as the error's `cause`. This arm wrote no ACQUIRED record.
export const ARM_ABORTED_CODE = 'ARM_ABORTED';
// The arming backoff's base is this many times the last attempt's duration, so an attempt
// of d ms is always followed by a sleep of at least 2d.
export const ARM_BACKOFF_MULTIPLIER = 4;
// arm() refused because the caps it would stamp disagree with the caps recorded by a live, probed
// predecessor. Terminal: waiting cannot change a configuration
// disagreement. Carries `recorded` and `resolved`, each { installationHardMaximumUsd?,
// dailyPaidJobAllowance? }.
export const OWNERSHIP_CAP_MISMATCH_CODE = 'OWNERSHIP_CAP_MISMATCH';
// The caps stamped on an ACQUIRED record, in the order messages name them.
const CAP_MEMBERS = Object.freeze(['installationHardMaximumUsd', 'dailyPaidJobAllowance']);
// How often an arm's backoff sleep polls its caller's shouldAbort(). The sleep can be long
// (ARM_BACKOFF_MULTIPLIER times one attempt's cost, and that cost grows with the ledger), so a stop
// request is noticed within this interval instead of when the sleep ends.
const ARM_ABORT_POLL_MS = 100;
// How long a preflight seal may wait in the protected store's queue before its caller gives up:
// the reclaim helper holds the ledger lock while it waits, and a failed preview waits for its answer.
const PREFLIGHT_SEAL_TIMEOUT_MS = 2_000;

function dataRootLockedError(message) {
  const error = new Error(message);
  error.code = DATA_ROOT_LOCKED_CODE;
  return error;
}

export function createLeaseStore({
  dataRoot,
  clock = () => Date.now(),
  lockTimeoutMs = 2_000,
  lockRetryMs = 10,
  lockStaleMs = 60_000,
  isProcessAlive = defaultIsProcessAlive,
  processStartTimeMs = defaultProcessStartTimeMs,
  // An optional { signal } ends the sleep early, clearing its timer, when the signal aborts. Only the
  // arming loop passes one, so it can stop mid-sleep without leaving a timer pending.
  sleep = (milliseconds, { signal } = {}) => new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
  }),
  // Distinct from `clock` above: `clock` stamps LEDGER RECORDS with wall-clock time (and can
  // run ahead of real time under append()'s own monotonic clamp). acquireProcessOwnership()'s
  // acquireTimeoutMs needs a genuinely monotonic elapsed-time source that can never run
  // backward -- performance.now() in production, injectable here so a test can control it
  // without needing a real wall-clock wait.
  monotonicNow = () => performance.now(),
  beforeAtomicRename,
  beforeStaleReclaim,
  beforeRelease,
  dailyPaidJobAllowance = 20,
  // Test-only seam (mirrors clock/isProcessAlive/sleep above): lets a test simulate a
  // rename() that fails for longer than real transient Windows contention ever has been
  // observed to, without needing node:fs/promises module mocking. Production code never
  // overrides this.
  renameImpl = rename,
  // The arming backoff's only source of randomness (its jitter). Injectable so a test
  // can pin every draw. acquireProcessOwnership() never uses it.
  random = Math.random,
  // Test-only seam: awaited with { generation, acquisitionId } after a successful ownership
  // attempt's mutate() has returned -- the ACQUIRED record is durable and the data-root lock is
  // released -- and before arm() or acquireProcessOwnership() resolves. It must not throw: a throw
  // reaches the acquirer AFTER its ACQUIRED record is already on disk. Production never passes it.
  afterOwnerAcquired,
  // The bound on each preflight seal (PREFLIGHT_SEAL_TIMEOUT_MS); injectable so a test need not wait two seconds.
  preflightSealTimeoutMs = PREFLIGHT_SEAL_TIMEOUT_MS,
  managedExecution,
} = {}) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  if (typeof processStartTimeMs !== 'function') {
    throw new TypeError('processStartTimeMs must be a function');
  }
  if (typeof clock !== 'function' || typeof isProcessAlive !== 'function' || typeof sleep !== 'function' || typeof renameImpl !== 'function' || typeof monotonicNow !== 'function' || typeof random !== 'function') {
    throw new TypeError('clock, isProcessAlive, sleep, renameImpl, monotonicNow, and random must be functions');
  }
  if (afterOwnerAcquired !== undefined && typeof afterOwnerAcquired !== 'function') throw new TypeError('afterOwnerAcquired must be a function');
  if (!Number.isSafeInteger(lockTimeoutMs) || lockTimeoutMs < 0 || !Number.isSafeInteger(lockRetryMs) || lockRetryMs < 0 || !Number.isSafeInteger(lockStaleMs) || lockStaleMs < 0) throw new TypeError('lock timing values must be non-negative safe integers');
  if (beforeAtomicRename !== undefined && typeof beforeAtomicRename !== 'function') throw new TypeError('beforeAtomicRename must be a function');
  if (beforeStaleReclaim !== undefined && typeof beforeStaleReclaim !== 'function') throw new TypeError('beforeStaleReclaim must be a function');
  if (beforeRelease !== undefined && typeof beforeRelease !== 'function') throw new TypeError('beforeRelease must be a function');
  if (!Number.isSafeInteger(dailyPaidJobAllowance) || dailyPaidJobAllowance <= 0) {
    throw new TypeError('dailyPaidJobAllowance must be a positive safe integer');
  }
  if (!Number.isSafeInteger(preflightSealTimeoutMs) || preflightSealTimeoutMs <= 0) {
    throw new TypeError('preflightSealTimeoutMs must be a positive safe integer');
  }

  let managed = null;
  if (managedExecution !== undefined) {
    if (!isPlainObject(managedExecution)) throw new TypeError('managedExecution must be a plain object');
    const required = ['installationConfig', 'buildManifest', 'storageProofs', 'executionPermits'];
    if (Object.keys(managedExecution).length !== required.length || required.some((name) => !Object.hasOwn(managedExecution, name))) {
      throw new TypeError('managedExecution has an invalid shape');
    }
    const installationConfig = validateInstallationConfig(managedExecution.installationConfig);
    const configFingerprint = configurationFingerprint(installationConfig, managedExecution.buildManifest);
    if (installationConfig.dataRoot !== dataRoot) throw new TypeError('managed installation dataRoot must match lease store dataRoot');
    const storageProofs = managedExecution.storageProofs;
    const executionPermits = managedExecution.executionPermits;
    if (!isPlainObject(storageProofs) || !isPlainObject(executionPermits)) throw new TypeError('managed adapters must be plain objects');
    for (const name of ['verifyPublished', 'inspectTarget', 'deleteRetired', 'listManifestTargets', 'verifyAdvisoryPublication', 'proveTerminalPublication', 'provePermanentTerminalPublicationLoss']) {
      if (typeof storageProofs[name] !== 'function') throw new TypeError(`storageProofs.${name} must be a function`);
    }
    if (typeof executionPermits.assertLive !== 'function') throw new TypeError('executionPermits.assertLive must be a function');
    managed = Object.freeze({
      installationConfig,
      buildManifest: structuredClone(managedExecution.buildManifest),
      configFingerprint,
      buildManifestFingerprint: installationConfig.buildManifestSha256,
      storageProofs,
      executionPermits,
    });
  }

  const ledgerRoot = join(dataRoot, 'ledger');
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  const preflights = new Map();
  const leases = new Map();
  const jobs = new Map();
  let sharedState = createSharedLedgerState();
  // Paid job creations per UTC day, derived from the ledger -- never separately persisted.
  // A job is created exactly once (the state:'RESERVED' transition), so counting those is exact.
  // UTC, not local time: append() stamps every record with an ISO-8601 UTC timestamp, so a UTC
  // day key is the only boundary that agrees with the data. Other tools may use a local-time day
  // key; this store deliberately matches its own UTC-stamped records.
  const paidJobsByUtcDay = new Map();
  let lastRecordTime = 0;

  // processOwner is a SINGLETON, not a Map -- "who owns it right now" is always just the
  // latest processOwner record replay() produces. currentOwner is null before any
  // processOwner record has ever been written; otherwise it holds the latest applied
  // record's own {state, pid, generation, acquisitionId, timestamp}.
  let currentOwner = null;
  // The most recent ACQUIRED record. Tracked separately because currentOwner is
  // overwritten by a later RELEASED record, and RELEASED records carry no caps; the cap check
  // compares against this one whether or not it has since been released. Reset by replay().
  let latestAcquiredOwner = null;
  let highestOwnerGeneration = 0;
  // Every acquisitionId ever seen in an ACQUIRED record, across this ledger's whole
  // history -- closes the reused-acquisitionId gap (a stale handle from an earlier
  // generation could otherwise pass the guarded-write predicate against a later one).
  const seenAcquisitionIds = new Set();

  // Known, deliberately accepted v1 residual risk: the
  // stale-reclaim and release restore paths below can, in principle, fail to
  // fully preserve mutual exclusion if THREE OR FOUR writers race for this
  // lock at the same instant during crash recovery (e.g. process B captures
  // process C's live lock by mistake while reclaiming a dead process's lock,
  // then a fourth process D acquires the now-empty lockRoot before B's
  // best-effort restore of C's lock lands). Token-gating already closes the
  // much more common and more dangerous two/three-writer case (a release
  // deleting a lock it does not own outright). Closing the residual N-way case
  // completely would require real distributed-lock machinery (fencing tokens
  // or periodic lease renewal), which is disproportionate for a Windows-local
  // stdio MCP server realistically run by one operator on one machine.
  //
  // This residual is accepted even though several server instances may now be connected to
  // the same data root at once: every one of them takes this lock for every ledger operation,
  // reads included, because mutate() wraps them all. The adaptive, jittered backoff on the
  // arming path (runOwnershipAttempts) lowers lock SATURATION; it does not make the
  // three-or-four-writer crash-recovery race impossible. Fencing tokens or lease renewal remain
  // deferred: any evidence of a mutual-exclusion failure would make closing this residual
  // mandatory.
  const RENAME_RETRYABLE_CODES = new Set(['EPERM', 'EBUSY', 'ENOTEMPTY']);
  const RENAME_RETRY_DELAY_MS = 25;
  const RENAME_RETRY_ATTEMPTS = 16;
  // Release gets a larger dedicated retry budget. The shared 400ms budget
  // above (16 x 25ms) is sized for the ACQUIRE path's stale-reclaim rename, where failing
  // and retrying the whole outer acquire loop is cheap -- one caller waits a bit longer,
  // nothing is lost. The RELEASE rename (below) is not symmetric: failing to release
  // leaves lockRoot genuinely still occupied, which deadlocks every OTHER acquirer (they
  // see a live owner, never a reclaimable stale one) until this exact process exits -- and,
  // just as seriously, deadlocks every LATER call this SAME process makes too (its own lock
  // can never look "stale" to itself while it is still alive). That asymmetric cost justifies
  // a much larger, still-bounded budget here specifically, rather than raising the shared
  // constant for every call site. 120 x 25ms = 3000ms gives real sustained AV/indexer
  // contention (the same class of transient Windows handle-hold this file's own acquire-path
  // comment already documents) about 7.5x the headroom, while staying fast in the ordinary
  // case: a successful rename never waits out the budget, only genuine contention does.
  //
  // What happens if this budget is STILL exhausted (an exceedingly rare residual, not the
  // realistic case this budget targets) is constrained by two failure modes to avoid:
  //   * Silently swallowing the failure hides a stuck lock: the lock is left exactly as stuck
  //     either way, and staying quiet about it only hides an operational problem an operator
  //     could otherwise notice.
  //   * Throwing a new error type after a committed effect breaks callers. Every one of
  //     mutate()'s callers assumes "if this throws, nothing happened"; a brand-new exception
  //     that escapes mutate() AFTER its real effect already committed could be mislabelled by
  //     review-engine.mjs's error translation (for example as CONTRACT_CHANGED), or could make
  //     consume()-failure handling drop a genuinely-reserved, paid job out of its batch --
  //     permanently orphaning it, per the sweepOrphanedLeases()/non-ACTIVE-lease-refusal
  //     invariants. Auditing every mutate() call site for a new post-effect failure mode is a
  //     much larger change than this budget warrants.
  // The resulting design: generic release returns an internal receipt instead of throwing after
  // a committed effect. The completed work result/error therefore remains primary. A
  // store-local exact-token capability retries before the next transaction, bounded by
  // that caller's acquisition deadline; if it still cannot finish, that next caller
  // receives the established pre-effect LEDGER_DATA_ROOT_LOCKED refusal. Process-owner
  // release consumes the same receipt to report its own cleanup failure upstream.
  const RELEASE_RENAME_RETRY_ATTEMPTS = 120;
  // A winning writer makes lockRoot visible just before its tiny owner.json
  // write completes. Five consecutive reads (the initial read plus four retries)
  // give that write 40ms at the default polling interval, while the caller's
  // lock deadline remains an additional cap. Exhaustion still fails closed;
  // unreadable metadata is never treated as evidence that an owner is dead.
  const OWNER_READ_MAX_ATTEMPTS = 5;

  // Windows can transiently refuse to rename a directory while something else
  // (a concurrent owner.json read from a contending acquirer's poll loop, or an
  // unrelated antivirus/indexer touch on a freshly created directory) briefly
  // holds it open, even with no real ownership conflict. This retry delay is
  // deliberately independent of the configurable lockRetryMs -- a fast test
  // polling interval is not evidence of how long real contention lasts -- and
  // bounded (16 x 25ms = 400ms worst case) rather than open-ended. It weakens
  // no safety property: every caller here only proceeds past a successful
  // rename after separately verifying, via the token, that what it captured is
  // really its own.
  async function renameRetrying(from, to, { attempts = RENAME_RETRY_ATTEMPTS, deadline } = {}) {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await renameImpl(from, to);
      } catch (error) {
        const outOfAttempts = attempt >= attempts;
        // A caller's configured lockTimeoutMs governs how long acquireDataRootLock
        // as a whole may take; a stale-reclaim rename retry must not silently spend
        // past it on the caller's behalf.
        const pastCallerDeadline = deadline !== undefined && Date.now() >= deadline;
        if (!RENAME_RETRYABLE_CODES.has(error?.code) || outOfAttempts || pastCallerDeadline) throw error;
        await new Promise((resolve) => setTimeout(resolve, RENAME_RETRY_DELAY_MS));
      }
    }
  }

  // Mirrors the ownerIsSupersededPid() check below that the processOwner ledger record's own
  // staleness gate uses -- this applies the same check to the LOWER-level data-root mkdir lock.
  // A bare isProcessAlive(pid) answers "does
  // something hold this PID", which Windows answers YES for a pid the dead lock-holder's
  // process happened to leave behind and something else has since reused. Because staleness and
  // liveness are a conjunction, a falsely-alive pid never resolves on its own: the lock stays
  // stuck for as long as the recycled pid (or whatever reuses it next) stays alive, no matter
  // how long a caller waits -- there is no timeout escape, the same shape the processOwner check
  // closes one layer up. ownerIsSupersededPid() itself is generic over any {pid, timestamp} record, so
  // it is reused as-is; only the caching layer here is new, because this lock's owner turns over
  // on every single mutate() call (unlike a processOwner record, which lives from an arm to its
  // release, so minutes to hours) and a real caller polls every lockRetryMs, so an unbounded,
  // per-poll probe would
  // itself turn the acquire budget into the lock-starvation outage the probe's placement comment
  // in runOwnershipAttempts() warns about.
  //
  // Cached per lockToken (never per pid alone -- many different lock-holders can reuse the same
  // pid over a store's lifetime, and a later lock is a different owner even on the same pid).
  // Every lock this codebase writes always carries a lockToken (see the write below); a
  // lockToken-less record can only be hand-written test/legacy state, and is probed uncached
  // (still correct, just not memoized).
  const supersededLockTokens = new Set();
  const confirmedLiveLockTokens = new Set();
  async function isDataRootLockReclaimable(owner, recordAgeMs) {
    if (!isProcessAlive(owner.pid)) return true;
    if (typeof owner.lockToken !== 'string') return ownerIsSupersededPid(owner, recordAgeMs);
    if (supersededLockTokens.has(owner.lockToken)) return true;
    if (confirmedLiveLockTokens.has(owner.lockToken)) return false;
    const superseded = await ownerIsSupersededPid(owner, recordAgeMs);
    (superseded ? supersededLockTokens : confirmedLiveLockTokens).add(owner.lockToken);
    return superseded;
  }

  // Builds owner.json in a private, uniquely-named staging directory (uncontended by
  // construction -- nobody else ever looks at this name) and only then publishes it to the
  // well-known lockRoot path via a single atomic rename. A simpler design that did
  // `mkdir(lockRoot)` and `writeFile(lockRoot/owner.json)` as two
  // separate steps would let a process killed between them leave lockRoot existing but permanently
  // empty -- every contender's owner-read fails forever (there is nothing to parse), which
  // never reaches the staleness check below, so no amount of waiting ever reclaims it. Staging
  // first removes that window entirely: lockRoot can now only ever be observed either absent,
  // or already carrying a valid owner.json, because both are written by the one filesystem
  // operation (rename) that makes lockRoot exist at all. A process dying before the publish
  // rename leaves only an orphaned, uniquely-named staging directory -- harmless clutter, the
  // same accepted-residual shape this file already leaves behind for `.release-<uuid>` and
  // `.stale-<uuid>` directories elsewhere, never a blocking state.
  async function createAndPublishLockRoot() {
    const stagingRoot = `${lockRoot}.creating-${randomUUID()}`;
    await mkdir(stagingRoot);
    const owner = { pid: process.pid, timestamp: new Date(Number(clock())).toISOString(), lockToken: randomUUID() };
    try {
      await writeFile(join(stagingRoot, 'owner.json'), `${JSON.stringify(owner)}\n`, { encoding: 'utf8', flag: 'wx' });
    } catch (writeError) {
      // Do not leave a permanently unowned, unverifiable lock directory behind
      // just because owner.json could not be written (e.g. a transient I/O
      // failure) -- that would fail every future acquirer closed forever. Safe
      // here without any of the caller-visibility concerns lockRoot's own
      // cleanup failures raise elsewhere in this file: stagingRoot is private,
      // so a failed rm here only leaks one small orphaned directory, never a
      // lock anything else contends on.
      await rm(stagingRoot, { recursive: true, force: true }).catch(() => {});
      throw writeError;
    }
    try {
      await renameImpl(stagingRoot, lockRoot);
    } catch (publishError) {
      await rm(stagingRoot, { recursive: true, force: true }).catch(() => {});
      if (!RENAME_RETRYABLE_CODES.has(publishError?.code)) throw publishError;
      // lockRoot is occupied -- by a live lock, a stale one, or a racing acquirer's own
      // just-won publish. Report it exactly like the original direct mkdir(lockRoot) EEXIST
      // case so the unmodified contention/staleness-reclaim logic below runs unchanged.
      //
      // Deliberately UNCONDITIONAL, not gated on first confirming lockRoot actually exists.
      // Two alternatives are rejected:
      // 1. A bespoke small retry budget (a handful of ms) before this mapping, to absorb a
      //    momentary Windows rename hiccup unrelated to real occupancy. Any budget large
      //    enough to help starves the OUTER, already-injectable-sleep contention loop of the
      //    ~50ms window it needs to be entered in, so a second live store instance no longer
      //    waits correctly for the first to release the lock.
      // 2. Confirming occupancy with a single stat(lockRoot) read before relabeling (so a
      //    genuine non-occupancy I/O error on stagingRoot's own parent is not misdiagnosed as
      //    contention). Under concurrent load this is worse: by the time the read runs, a
      //    transient occupancy-related failure may have already resolved, so the read can see
      //    "not occupied" for a failure that WAS occupancy-related -- and the resulting raw,
      //    non-EEXIST-coded error then escapes uncaught past acquireProcessOwnership()'s own
      //    retry loop (which only recognizes LEDGER_DATA_ROOT_LOCKED as retryable), breaking
      //    its documented "exactly one caller wins per round" guarantee.
      // The tradeoff accepted here: a genuine, rare non-occupancy publish failure (e.g. a
      // permissions problem on stagingRoot's own parent) is diagnosed as the same
      // "ledger data root is locked (owner cannot be verified)" message every other
      // unverifiable-owner case already produces (once the owner-read retry below exhausts
      // against a lockRoot that was never actually created), rather than surfacing its own
      // distinct error -- misleading, but safe, matching the ALREADY-accepted precedent
      // immediately below this function (release()'s own exhausted-retry-budget case takes
      // the identical "safe over informative" tradeoff, for the identical reason: a bespoke
      // new failure shape that can escape uncaught into code that never expected it is a
      // worse outcome than a merely-imprecise diagnosis).
      throw Object.assign(new Error('lockRoot already occupied'), { code: 'EEXIST' });
    }
    return owner;
  }

  let pendingDataRootLockCleanup = null;

  function emitReleaseDiagnostic(kind, suppressDiagnostics) {
    if (suppressDiagnostics) return;
    try {
      process.stderr.write(`openrouter-review-lease-store: ${kind} (detail redacted)${kind === 'release-rename-failed' ? '; exact local cleanup remains pending' : ''}\n`);
    } catch {
      // Diagnostics are observational; a broken stderr sink cannot replace a committed effect or
      // the original logical error that release runs alongside in mutate()'s finally.
    }
  }

  // Releases only the exact lock owner that acquired this transaction. Its receipt is internal:
  // ordinary callers retain their work outcome even when a shared cleanup remains pending.
  async function releaseDataRootLock(owner, { deadline, retry = false, suppressDiagnostics = false } = {}) {
    if (!retry && beforeRelease) await beforeRelease({ lockToken: owner.lockToken });
    const releaseStaging = `${lockRoot}.release-${randomUUID()}`;
    try {
      await renameRetrying(lockRoot, releaseStaging, { attempts: RELEASE_RENAME_RETRY_ATTEMPTS, deadline });
    } catch (renameError) {
      if (renameError?.code === 'ENOENT') return { state: 'complete' };
      emitReleaseDiagnostic('release-rename-failed', suppressDiagnostics);
      return { state: 'pending', owner };
    }
    let captured;
    try { captured = JSON.parse(await readFile(join(releaseStaging, 'owner.json'), 'utf8')); } catch { captured = null; }
    if (captured?.lockToken === owner.lockToken) {
      try {
        await rm(releaseStaging, { recursive: true, force: true });
      } catch {
        // This is private staging, not the shared lock. It is a bounded storage leak only.
        emitReleaseDiagnostic('release-cleanup-failed', suppressDiagnostics);
      }
      return { state: 'complete' };
    }
    // A replacement won the read/rename race. Restore the unverified isolated copy; this owner no
    // longer occupies the shared path, so its exact cleanup capability is safely retired.
    await renameRetrying(releaseStaging, lockRoot, { deadline }).catch(() => {});
    return { state: 'complete' };
  }

  async function settlePendingDataRootLockCleanup({ deadline } = {}) {
    const pending = pendingDataRootLockCleanup;
    if (pending === null) return;
    if (pending.promise !== null) return pending.promise;
    pending.promise = (async () => {
      let observed;
      try {
        observed = JSON.parse(await readFile(join(lockRoot, 'owner.json'), 'utf8'));
      } catch (error) {
        if (error?.code === 'ENOENT') {
          // `owner.json` missing is unreadable metadata while lockRoot still exists, not proof
          // that this exact lock vanished. Check the directory separately before retiring it.
          try {
            await readdir(lockRoot);
          } catch (rootError) {
            if (rootError?.code === 'ENOENT') {
              if (pendingDataRootLockCleanup === pending) pendingDataRootLockCleanup = null;
              return;
            }
          }
        }
        throw dataRootLockedError('ledger data root is locked (pending local cleanup could not complete)');
      }
      if (typeof observed?.lockToken !== 'string') {
        throw dataRootLockedError('ledger data root is locked (pending local cleanup could not complete)');
      }
      if (observed.lockToken !== pending.owner.lockToken) {
        // Verified replacement: this capability cannot touch the foreign lock and must never be
        // revived after a later transaction creates a new lock at this path.
        if (pendingDataRootLockCleanup === pending) pendingDataRootLockCleanup = null;
        return;
      }
      const receipt = await releaseDataRootLock(pending.owner, {
        deadline,
        retry: true,
        suppressDiagnostics: true,
      });
      if (receipt.state === 'pending') {
        throw dataRootLockedError('ledger data root is locked (pending local cleanup could not complete)');
      }
      if (pendingDataRootLockCleanup === pending) pendingDataRootLockCleanup = null;
    })();
    try {
      return await pending.promise;
    } finally {
      if (pendingDataRootLockCleanup === pending) pending.promise = null;
    }
  }

  async function acquireDataRootLock({ suppressReleaseDiagnostics = false } = {}) {
    const deadline = Date.now() + lockTimeoutMs;
    // A retained capability belongs to this store instance and is settled before any new effect.
    // It shares the caller's pre-effect budget and never grants a same-PID store a general bypass.
    await settlePendingDataRootLockCleanup({ deadline });
    await mkdir(dataRoot, { recursive: true });
    let ownerReadAttempts = 0;
    for (;;) {
      try {
        const owner = await createAndPublishLockRoot();
        return async () => {
          const receipt = await releaseDataRootLock(owner, { suppressDiagnostics: suppressReleaseDiagnostics });
          if (receipt.state === 'pending' && pendingDataRootLockCleanup === null) {
            pendingDataRootLockCleanup = { owner: receipt.owner, promise: null };
          }
          return receipt;
        };
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
        let owner;
        try {
          owner = JSON.parse(await readFile(join(lockRoot, 'owner.json'), 'utf8'));
        } catch {
          ownerReadAttempts += 1;
          if (ownerReadAttempts >= OWNER_READ_MAX_ATTEMPTS || Date.now() >= deadline) {
            throw dataRootLockedError('ledger data root is locked (owner cannot be verified)');
          }
          await sleep(lockRetryMs);
          if (Date.now() >= deadline) throw dataRootLockedError('ledger data root is locked (owner cannot be verified)');
          continue;
        }
        const ownerTime = Date.parse(owner?.timestamp);
        if (!Number.isSafeInteger(owner?.pid) || !Number.isFinite(ownerTime)) throw dataRootLockedError('ledger data root is locked (owner cannot be verified)');
        ownerReadAttempts = 0;
        const recordAgeMs = Number(clock()) - ownerTime;
        if (recordAgeMs >= lockStaleMs && (await isDataRootLockReclaimable(owner, recordAgeMs))) {
          const staleRoot = `${lockRoot}.stale-${randomUUID()}`;
          if (beforeStaleReclaim) await beforeStaleReclaim({ pid: owner.pid, timestamp: owner.timestamp });
          try {
            await renameRetrying(lockRoot, staleRoot, { deadline });
          } catch (renameError) {
            if (renameError?.code === 'ENOENT') continue;
            // renameRetrying gives up after RENAME_RETRY_ATTEMPTS (16) or the LOCK deadline
            // (lockTimeoutMs), both far shorter than acquireProcessOwnership's own budget -- so
            // exhausting it is NOT evidence the condition is permanent. A code renameRetrying
            // itself classes as transient is the same self-healing shape as lock contention (an
            // antivirus or indexer briefly holding a handle on the lock directory), so tag it and
            // let the caller's declared budget apply. Without this, the acquire-retry fix above
            // covered only the timeout/verification escapes and this one still abandoned the whole
            // ~90s budget -- in the RECOVERY path, the one that exists to clear an orphaned lock.
            //
            // Deliberately narrow. Anything renameRetrying does NOT class as transient is
            // structural and must still fail fast carrying its own message, or an accurate
            // immediate diagnosis is replaced by a misleading timeout an entire budget later.
            if (!RENAME_RETRYABLE_CODES.has(renameError?.code)) throw renameError;
            throw dataRootLockedError(
              `ledger data root is locked (stale lock reclaim rename failed: ${renameError.message})`,
            );
          }
          // rename() is atomic, so staleRoot now holds exactly whatever sat at
          // lockRoot the instant we moved it -- but a competing process could
          // have reclaimed and re-acquired the lock in the gap between our
          // owner.json read above and this rename (classic TOCTOU). Re-check
          // identity against what we captured before treating it as safe to
          // delete: never destroy a lock we did not confirm is the same dead
          // owner we decided was stale.
          let captured;
          try { captured = JSON.parse(await readFile(join(staleRoot, 'owner.json'), 'utf8')); } catch { captured = null; }
          const capturedIsSameDeadOwner = captured && owner.lockToken !== undefined
            ? captured.lockToken === owner.lockToken
            : captured && captured.pid === owner.pid && captured.timestamp === owner.timestamp;
          if (!capturedIsSameDeadOwner) {
            // We caught someone else's lock (possibly a brand-new, live one)
            // instead of the stale one we verified. Put it back rather than
            // deleting it, then retry from the top of the loop.
            try { await renameRetrying(staleRoot, lockRoot, { deadline }); } catch { /* lockRoot was re-occupied by a third writer; leave staleRoot orphaned rather than delete an unverified lock */ }
            continue;
          }
          await rm(staleRoot, { recursive: true, force: true });
          continue;
        }
        if (Date.now() >= deadline) throw dataRootLockedError('ledger data root is locked');
        await sleep(lockRetryMs);
      }
    }
  }

  function applyRecord(record) {
    if (record.recordType === 'shared/service-mode' || record.recordType === 'shared/transition') {
      sharedState.apply(record);
      if (record.preflight !== undefined) preflights.set(record.preflight.id, record.preflight);
      if (record.lease !== undefined) leases.set(record.lease.id, record.lease);
      if (record.job !== undefined) {
        jobs.set(record.job.id, record.job);
        if (record.kind === 'MANAGED_CONSUMED' && record.job.paid === true) {
          const key = utcDayKey(record.timestamp);
          paidJobsByUtcDay.set(key, (paidJobsByUtcDay.get(key) ?? 0) + 1);
        }
      }
    } else if (record.recordType === 'preflight') preflights.set(record.id, record);
    else if (record.recordType === 'lease') leases.set(record.id, record);
    else if (record.recordType === 'job') jobs.set(record.id, record);
    else if (record.recordType === 'transition') {
      if (!record.lease || !record.job) throw new Error('ledger transition is incomplete');
      leases.set(record.lease.id, record.lease);
      jobs.set(record.job.id, record.job);
      if (record.state === 'RESERVED' && record.job.paid === true) {
        const key = utcDayKey(record.timestamp);
        paidJobsByUtcDay.set(key, (paidJobsByUtcDay.get(key) ?? 0) + 1);
      }
    } else if (record.recordType === 'processOwner') {
      applyProcessOwnerRecord(record);
    }
  }

  // Explicit transition table. Every reader replaying
  // the ledger enforces this identically -- not just the code path that originally wrote the
  // record -- so a corrupted or hand-edited record is caught on the next replay regardless of
  // who or what produced it.
  function applyProcessOwnerRecord(record) {
    requirePositiveInteger(record.pid, 'processOwner.pid');
    requireOwnerAcquisitionId(record.acquisitionId);
    if (record.state !== 'ACQUIRED' && record.state !== 'RELEASED') {
      throw new Error(`processOwner record has an invalid state: ${record.state}`);
    }
    if (!Number.isSafeInteger(record.generation) || record.generation <= 0) {
      throw new Error('processOwner record has an invalid generation');
    }
    if (!Number.isFinite(Date.parse(record.timestamp))) {
      throw new Error('processOwner record has an unparseable timestamp');
    }
    if (record.state === 'ACQUIRED') {
      const expectedGeneration = highestOwnerGeneration + 1;
      if (record.generation !== expectedGeneration) {
        throw new Error(`processOwner ACQUIRED record has generation ${record.generation}, expected ${expectedGeneration}`);
      }
      if (seenAcquisitionIds.has(record.acquisitionId)) {
        throw new Error('processOwner ACQUIRED record reuses a previously-seen acquisitionId');
      }
      // Validated before any state changes, so a malformed caps fails replay with nothing half-applied.
      const caps = normalizeRecordedCaps(record.caps);
      highestOwnerGeneration = expectedGeneration;
      seenAcquisitionIds.add(record.acquisitionId);
      currentOwner = {
        state: 'ACQUIRED', pid: record.pid, generation: record.generation,
        acquisitionId: record.acquisitionId, timestamp: record.timestamp, caps,
      };
      latestAcquiredOwner = currentOwner;
    } else {
      if (
        currentOwner === null
        || currentOwner.state !== 'ACQUIRED'
        || currentOwner.acquisitionId !== record.acquisitionId
      ) {
        throw new Error('processOwner RELEASED record does not match the currently tracked ACQUIRED record');
      }
      if (currentOwner.generation !== record.generation || currentOwner.pid !== record.pid) {
        throw new Error('processOwner RELEASED record generation/pid does not match the tracked ACQUIRED record');
      }
      currentOwner = {
        state: 'RELEASED', pid: record.pid, generation: record.generation,
        acquisitionId: record.acquisitionId, timestamp: record.timestamp,
      };
    }
  }

  async function replay() {
    await mkdir(ledgerRoot, { recursive: true });
    preflights.clear(); leases.clear(); jobs.clear(); paidJobsByUtcDay.clear(); lastRecordTime = 0;
    sharedState = createSharedLedgerState();
    currentOwner = null; latestAcquiredOwner = null; highestOwnerGeneration = 0; seenAcquisitionIds.clear();
    const names = (await readdir(ledgerRoot)).filter((name) => name.endsWith('.json')).sort();
    for (const name of names) {
      let record;
      try {
        record = JSON.parse(await readFile(join(ledgerRoot, name), 'utf8'));
      } catch (error) {
        // Same fail-closed OUTCOME as before -- this deliberately still throws. Skipping an
        // unreadable record in an append-only MONEY ledger could drop a spend record, so replay()
        // must never become tolerant. The only thing that changes is that the operator is told
        // WHICH file to look at: JSON.parse throws before the structural check below, so malformed
        // JSON (the likely real-world corruption shape -- a truncated or empty file) previously
        // surfaced as a bare SyntaxError naming nothing, while a structurally-wrong-but-parseable
        // record named its file.
        //
        // The warning is load-bearing, not boilerplate. Naming a file invites deleting it, and for
        // a processOwner record that is the WORST available action: ACQUIRED records form a strict
        // +1 generation chain (applyProcessOwnerRecord below), so removing one from the middle
        // bricks every operation permanently -- and the resulting error then names the NEXT record,
        // walking an operator forward through the chain until the whole audit trail after the gap
        // is gone. Filenames are timestamp+uuid only, so nothing on the outside distinguishes a
        // processOwner record from any other kind.
        throw new Error(
          `unreadable ledger record: ${name}: ${error && error.message ? error.message : String(error)}`
          + ' -- do not delete this file; identify its recordType first (deleting a processOwner'
          + ' record breaks the ownership generation chain and cannot be undone)',
        );
      }
      if (!record || typeof record !== 'object' || typeof record.timestamp !== 'string') throw new Error(`invalid ledger record: ${name}`);
      applyRecord(record);
      lastRecordTime = Math.max(lastRecordTime, Date.parse(record.timestamp) || 0);
    }
  }

  async function append(record) {
    const now = Math.max(Number(clock()), lastRecordTime + 1);
    if (!Number.isFinite(now)) throw new TypeError('clock must return a finite timestamp');
    const complete = { ...record, timestamp: new Date(now).toISOString() };
    assertNoForbiddenFields(complete);
    if (complete.recordType === 'shared/service-mode' || complete.recordType === 'shared/transition') sharedState.validate(complete);
    const target = join(ledgerRoot, `${complete.timestamp.replace(/[:.]/g, '-')}-${randomUUID()}.json`);
    const temporary = `${target}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(complete)}\n`, { encoding: 'utf8', flag: 'wx' });
    if (beforeAtomicRename) await beforeAtomicRename(clone(complete));
    await rename(temporary, target);
    lastRecordTime = now;
    applyRecord(complete);
    return complete;
  }

  // Deliberately a plain try/finally. Surfacing a release failure as a distinguishable thrown
  // error would break callers -- see RELEASE_RENAME_RETRY_ATTEMPTS's own comment above. Because
  // release() (above) never throws, work()'s own success or failure propagates through this
  // try/finally completely unaffected by release(), for every one of this function's many
  // callers throughout review-engine.mjs.
  /**
   * Runs `work` under the data root's exclusive write lock, against freshly replayed state.
   *
   * What this DOES guarantee: mutual exclusion (no other process is between this replay() and the
   * final release), and that every record `work` appends is individually complete and durable
   * before the next one starts.
   *
   * What it does NOT guarantee, stated plainly because several comments in this file lean on the
   * shorthand "if this throws, nothing happened": there is no rollback. `mutate` is three lines
   * and has no undo log. For the many callers that append at most ONE record the shorthand is
   * exactly true -- the single append either happened or it did not. It is NOT true of a caller
   * that appends several, where a throw partway leaves the earlier records committed.
   *
   * `sweepOrphanedLeases()` is the one such caller today (one transition per reserved job, then
   * the lease close). That is survivable rather than corrupting: each record it writes is a
   * complete, consistent snapshot, `reconcile()` independently refuses to re-apply a job that is
   * no longer RESERVED, and the sweep's own eligibility filter skips jobs it has already done --
   * so a retry RESUMES rather than double-applies, and no cost can be counted twice.
   *
   * Its one non-resuming window -- a throw between the last transition and the lease close, which
   * leaves the lease ACTIVE with nothing reserved -- needs no repair, for a reason worth
   * recording so it is not "fixed" again: that is the SAME state a
   * completely successful review leaves behind. `finalizeReviewOutcome` returns
   * `{ state: 'PASSED', closeCode: null }` and only closes the lease when closeCode is non-null,
   * so "ACTIVE, expired, nothing reserved" is the ordinary resting state of every review that
   * passed. Nothing in the ledger distinguishes the two, and a query that swept them up would
   * relabel every successful lease `ORPHANED_ON_RECOVERY` -- destroying the meaning of the one
   * close code produced exclusively by the recovery path. A regression test in
   * tests/openrouter-review-engine.test.mjs pins that a passed lease is left alone.
   *
   * So: do not read the shorthand as atomicity. Before adding a second multi-append caller, check
   * what its partial state is indistinguishable FROM before deciding it needs recovering.
   */
  // The shared executor has concurrent callers in one store. Queue those calls before the
  // cross-process lock so they cannot repeatedly overtake one another or exhaust its timeout
  // while waiting on this very instance. Other stores/processes still use the same disk fence.
  let managedMutationTail = Promise.resolve();
  function mutate(work, options) {
    if (managed === null) return mutateUnderLock(work, options);
    const operation = managedMutationTail.then(() => mutateUnderLock(work, options));
    managedMutationTail = operation.catch(() => {});
    return operation;
  }

  async function mutateUnderLock(work, { onPhysicalRelease, suppressReleaseDiagnostics = false } = {}) {
    const release = await acquireDataRootLock({ suppressReleaseDiagnostics });
    try {
      await replay();
      return await work();
    } finally {
      const receipt = await release();
      // A receipt observer is intentionally observational. It must never mask a committed result
      // or the original logical error from work().
      try { onPhysicalRelease?.(receipt); } catch { /* observer failures are not transaction failures */ }
    }
  }

  // Age of the currently-tracked ownership record. Derived from the SAME monotonic value append()
  // would actually stamp a new record with (Math.max(Number(clock()), lastRecordTime + 1)), not a
  // raw clock() read -- matching this file's own established fix for the identical class of bug in
  // consume()'s daily-allowance day-key check (see that call site's own comment). A fixed or
  // slow-moving clock() can otherwise sit BEHIND a ledger timestamp that append()'s monotonic
  // clamp already pushed forward (e.g. several ACQUIRED records landing within one clock() tick),
  // making the age go negative and a genuinely dead, long-abandoned owner read as perpetually
  // "not yet stale." Only meaningful with a tracked owner, i.e. inside mutate().
  function ownerAgeMs() {
    return Math.max(Number(clock()), lastRecordTime + 1) - Date.parse(currentOwner.timestamp);
  }

  // The same age for any processOwner record, not only the tracked current owner.
  function recordAgeMs(record) {
    return Math.max(Number(clock()), lastRecordTime + 1) - Date.parse(record.timestamp);
  }

  // The transactional cap check. It runs at the
  // TOP of every arm attempt's mutate() callback, so it is re-evaluated inside the locked
  // transaction on every attempt. It is also reached when the latest holder is alive and unreleased:
  // placed just before acquireFreshOwnership() it never would be, because the LIVE_OWNER branch
  // returns first.
  //
  // It compares the caps this arm would stamp with the most recent ACQUIRED record's, member by
  // member. A member the record does not carry is compatible (bootstrap). A difference matters only
  // while the recording process could still be enforcing its own caps: its pid is alive per the
  // cheap, synchronous isProcessAlive, and this call has not already proven that pid recycled.
  //
  // Returns null to proceed. A first dangerous mismatch returns a CAP_MISMATCH_UNPROBED refusal, so
  // the loop can probe the pid's start time OUTSIDE the lock. A pid Windows recycled for an unrelated
  // process must heal, not brick every later arm. Only a mismatch against an owner this call
  // has already probed and found genuine throws the terminal OWNERSHIP_CAP_MISMATCH.
  function checkCaps(resolved, { supersededOwners, capProbedOwners }) {
    if (latestAcquiredOwner === null) return null;
    const recorded = latestAcquiredOwner.caps;
    const differing = CAP_MEMBERS.filter((member) => recorded[member] !== undefined && !Object.is(recorded[member], resolved[member]));
    if (differing.length === 0) return null;
    const key = ownerKey(latestAcquiredOwner);
    if (!isProcessAlive(latestAcquiredOwner.pid) || supersededOwners.has(key)) return null;
    if (!capProbedOwners.has(key)) {
      return {
        ok: false,
        reason: 'CAP_MISMATCH_UNPROBED',
        owner: clone(latestAcquiredOwner),
        ownerAgeMs: recordAgeMs(latestAcquiredOwner),
      };
    }
    const named = differing.map((member) => `${member} recorded ${recorded[member]}, resolved ${resolved[member]}`).join('; ');
    const error = new Error(
      `ownership caps disagree with the live owner that recorded them (pid ${latestAcquiredOwner.pid}, `
      + `generation ${latestAcquiredOwner.generation}): ${named}`,
    );
    error.code = OWNERSHIP_CAP_MISMATCH_CODE;
    error.recorded = { ...recorded };
    error.resolved = { ...resolved };
    throw error;
  }

  // Positive proof that the process now holding `owner.pid` is NOT the one that wrote that record,
  // because it started after the record already existed. Returns false for everything else --
  // an unreadable start time, an unavailable probe, a non-Windows host, a gap inside the skew
  // margin -- so every uncertain path lands on today's behaviour: keep refusing.
  //
  // The direction here is the whole safety argument. A false TRUE hands ownership to a second
  // live process; a false FALSE merely leaves a stuck server stuck, which is where it already is.
  // Two comparisons must agree:
  //
  //   * as INSTANTS -- did the process start after the record was written? This is the direct
  //     question, but it compares a start time the OS reports on the REAL wall clock against a
  //     record timestamp written by this store's INJECTED clock(). When those disagree (every
  //     test here that pins a fictional date, and any future caller that injects a clock) it
  //     answers nonsense, in the unsafe direction -- a live owner reads as recycled.
  //
  //   * as DURATIONS -- is the process YOUNGER than the record is OLD? Both sides are elapsed
  //     times rather than points on a timeline, so a clock OFFSET cancels out. `Date.now()` is
  //     deliberately used rather than clock(): the process age must be measured on the same real
  //     clock that produced startedMs, or this comparison inherits the problem it exists to remove.
  //
  // Be precise about what that second comparison buys: the two are NOT independent. When clock()
  // IS the real wall clock -- i.e. in
  // production -- they are algebraically the SAME test: substituting recordAgeMs = Date.now() -
  // recordTs into the duration form reduces it to startedMs > recordTs + MARGIN, the instant form
  // exactly. The duration check earns its place only when the two clocks differ, which is where
  // the instant check silently produces the unsafe answer.
  //
  // KNOWN RESIDUAL, deliberately not closed here. Because the two
  // collapse into one in production, a single wall-clock event can defeat both: a BACKWARD step
  // that lands in the window between the owner process starting and it writing its record, and
  // is larger than that whole window plus the margin, backdates the record below the process's
  // own start time and both forms read "recycled" for a genuinely live owner. The record is
  // written at the process's first arm, so the window can be minutes or hours, and the step must
  // exceed that WHOLE window plus the five-minute margin (the record only lands before the start
  // time if the clock went back further than the time that had passed since the start): a longer
  // window raises the bar rather than lowering it. The consequence is still the one this mechanism
  // exists to prevent. Closing it properly needs an identity that no clock can move -- storing the
  // owner's own start time in the record and comparing for EQUALITY rather than order -- which
  // would add a new field to an append-only money ledger.
  async function ownerIsSupersededPid(owner, recordAgeMs, knownStartTimeMs) {
    let startedMs = knownStartTimeMs;
    try {
      if (startedMs === undefined) startedMs = await processStartTimeMs(owner.pid);
    } catch {
      return false;
    }
    if (!Number.isFinite(startedMs) || !Number.isFinite(recordAgeMs)) return false;
    const startedAfterRecordWasWritten = startedMs > Date.parse(owner.timestamp) + OWNER_START_TIME_SKEW_MARGIN_MS;
    const processIsYoungerThanRecord = (Date.now() - startedMs) + OWNER_START_TIME_SKEW_MARGIN_MS < recordAgeMs;
    return startedAfterRecordWasWritten && processIsYoungerThanRecord;
  }

  async function appendOwnerRecord(fields) {
    return append({ recordType: 'processOwner', ...fields });
  }

  // Sleep between two refused ARM attempts. The base grows with what one
  // attempt really costs on this ledger -- ARM_BACKOFF_MULTIPLIER times the last attempt's
  // duration, floored at the arm's own lockRetryMs -- so every attempt of d ms is followed by a
  // sleep of at least 2d, and the arming loop holds the global write lock at most about one third
  // of the time, whatever the ledger size. Equal jitter over that base, never full jitter, so a
  // sleep cannot collapse toward zero and re-create the hot loop; the draw is clamped into
  // [half, base] in case `random` misbehaves. The sleep never runs past the arm's own deadline.
  // acquireProcessOwnership() keeps its fixed lockRetryMs sleep and never calls this.
  function armBackoffMs({ armLockRetryMs, lastAttemptMs, remainingMs }) {
    const base = Math.max(armLockRetryMs, ARM_BACKOFF_MULTIPLIER * Math.ceil(lastAttemptMs));
    const half = Math.floor(base / 2);
    const drawn = half + Math.floor(Number(random()) * (base - half + 1));
    const sleepMs = Number.isFinite(drawn) ? Math.min(Math.max(drawn, half), base) : base;
    return Math.min(sleepMs, remainingMs);
  }

  // One process-ownership handle. The object is frozen and its identity never
  // changes; what changes is the closure state behind it. `generation`, `acquisitionId` and
  // `state` are ACCESSORS, so the object stays frozen while every read sees the current values.
  // A spread `{ ...handle }` therefore snapshots them: wrap a handle, never spread it. Every method
  // is a closure that never uses `this`, so a delegating wrapper holding a copied method reference
  // still acts on the real handle.
  //
  // States: unarmed -> arming -> armed -> releasing -> released, plus arming -> unarmed when an arm
  // fails and releasing -> unarmed for release({ final: false }). `released` is terminal.
  // isOwner() is exactly `state === 'armed'`, so it reads false from the moment a release begins,
  // and both id getters read null in every state but `armed`.
  //
  // This handle is the lowest ownership layer: it knows nothing about shutdown,
  // recovery, configuration or where caps come from. Joining concurrent arm() callers is the
  // ownership coordinator's job; the handle only makes a concurrent re-entry loud.
  function buildOwnerHandle({ armed } = {}) {
    let state = armed ? 'armed' : 'unarmed';
    let generation = armed ? armed.generation : null;
    let acquisitionId = armed ? armed.acquisitionId : null;
    let everArmed = Boolean(armed);
    // The in-flight arm. Private: arm() re-entered while it runs throws rather than joining it, but
    // release() awaits it -- releasing "nothing" mid-arm would leave a fresh ACQUIRED record with no
    // matching RELEASED, the squat this design exists to end.
    let armPromise = null;
    // The in-flight release, joined by every concurrent release() call so they share ONE mutate()
    // cycle. It is reset together with `state`, synchronously, when it settles, so a later release()
    // can never be handed an earlier cycle's already-settled promise.
    let releasePromise = null;
    // Finality of the in-flight release. A joiner may raise it and nothing lowers it, so a
    // shutdown can never resolve into a re-armable handle.
    let releaseFinal = false;

    function codedError(code, message) {
      const error = new Error(message);
      error.code = code;
      return error;
    }

    async function arm({ acquireTimeoutMs, lockRetryMs, caps, shouldAbort } = {}) {
      // Validation runs first, before any I/O and whatever the state, so a malformed call is
      // refused the same way whether or not the handle happens to be armed already.
      if (!Number.isSafeInteger(acquireTimeoutMs) || acquireTimeoutMs <= 0) {
        throw new TypeError('arm() acquireTimeoutMs must be a positive safe integer');
      }
      if (!Number.isSafeInteger(lockRetryMs) || lockRetryMs <= 0) {
        throw new TypeError('arm() lockRetryMs must be a positive safe integer');
      }
      if (!isPlainObject(caps)) throw new TypeError('arm() caps must be a plain object');
      const { installationHardMaximumUsd } = caps;
      if (typeof installationHardMaximumUsd !== 'number' || !Number.isFinite(installationHardMaximumUsd) || installationHardMaximumUsd < 0) {
        throw new TypeError('arm() caps.installationHardMaximumUsd must be a finite number >= 0');
      }
      // A bare cancellation token: the store only asks it "stop now?" and knows
      // nothing about why. The ownership coordinator passes its shutdown flag here.
      if (shouldAbort !== undefined && typeof shouldAbort !== 'function') {
        throw new TypeError('arm() shouldAbort must be a function when given');
      }
      if (state === 'arming') {
        throw codedError(ARM_IN_PROGRESS_CODE, 'arm() re-entered while an arm is already in flight on this handle; concurrent callers must share one arm (the ownership coordinator does this)');
      }
      if (state === 'armed') return;
      if (state === 'released') {
        throw codedError(OWNER_HANDLE_RELEASED_CODE, 'arm() on a released ownership handle; release({ final: true }) is terminal');
      }
      if (state === 'release-pending') {
        throw codedError(OWNER_RELEASE_PENDING_CODE, 'arm() while prior owner release cleanup is pending; retry release() instead');
      }
      if (state === 'releasing') {
        // Wait for the release to land, then answer from wherever it landed: unarmed (arm now),
        // released (refuse), or armed again because the release failed (resolve).
        try { await releasePromise; } catch { /* the release's own caller sees its failure */ }
        return arm({ acquireTimeoutMs, lockRetryMs, caps, shouldAbort });
      }
      // unarmed: a real acquisition, through the same loop acquireProcessOwnership() uses.
      state = 'arming';
      armPromise = (async () => {
        try {
          const acquired = await runOwnershipAttempts({
            label: 'arm',
            acquireTimeoutMs,
            nextSleepMs: ({ lastAttemptMs, remainingMs }) => armBackoffMs({ armLockRetryMs: lockRetryMs, lastAttemptMs, remainingMs }),
            shouldAbort,
            // Each cap is stamped by the layer that enforces it: the caller's own enforced
            // installationHardMaximumUsd, and THIS store's own dailyPaidJobAllowance, the value
            // consume() actually enforces. -0 becomes 0 first, because Object.is(-0, 0) is false.
            // dailyPaidJobAllowance needs no normalizing: createLeaseStore refuses any value <= 0,
            // and -0 <= 0, so it is always a positive integer here.
            caps: {
              installationHardMaximumUsd: normalizeNegativeZero(installationHardMaximumUsd),
              dailyPaidJobAllowance,
            },
          });
          generation = acquired.generation;
          acquisitionId = acquired.acquisitionId;
          everArmed = true;
          state = 'armed';
        } catch (error) {
          // Back to unarmed so a later arm() genuinely retries; the loop's error (a timeout, a cap
          // mismatch, or ARM_ABORTED) is rethrown as is.
          state = 'unarmed';
          throw error;
        } finally {
          armPromise = null;
        }
      })();
      return armPromise;
    }

    async function release({ final = true } = {}) {
      if (state === 'unarmed') {
        // Nothing is held: a clean no-op that writes nothing and attempts no I/O, so an ownerless
        // shutdown, or a startup failure before any arm, can never fail on it.
        if (final) state = 'released';
        return;
      }
      if (state === 'released') return;
      if (state === 'arming') {
        // Await the in-flight arm, then release what it produced. An arm that failed has left the
        // handle unarmed, so a final release still lands `released` -- without rethrowing the arm's
        // error, which is already surfacing to the arm's own caller.
        try { await armPromise; } catch { /* surfaced to the arm's caller */ }
        return release({ final });
      }
      if (state === 'releasing') {
        if (final) releaseFinal = true;
        return releasePromise;
      }
      if (state === 'release-pending') {
        if (final) releaseFinal = true;
        if (releasePromise !== null) return releasePromise;
        releasePromise = (async () => {
          try {
            await settlePendingDataRootLockCleanup({ deadline: Date.now() + lockTimeoutMs });
          } catch {
            releasePromise = null;
            throw codedError(OWNER_RELEASE_PENDING_CODE, 'process ownership release cleanup remains pending');
          }
          state = releaseFinal ? 'released' : 'unarmed';
          generation = null;
          acquisitionId = null;
          releasePromise = null;
          releaseFinal = false;
        })();
        return releasePromise;
      }
      // armed: the conditional compare-and-set RELEASED append, exactly as before.
      state = 'releasing';
      releaseFinal = final;
      const releasingAcquisitionId = acquisitionId;
      releasePromise = (async () => {
        let physicalReceipt = null;
        try {
          await mutate(async () => {
            if (
              currentOwner !== null
              && currentOwner.state === 'ACQUIRED'
              && currentOwner.acquisitionId === releasingAcquisitionId
            ) {
              if (beforeRelease) await beforeRelease(clone(currentOwner));
              await appendOwnerRecord({
                state: 'RELEASED', pid: currentOwner.pid,
                generation: currentOwner.generation, acquisitionId: currentOwner.acquisitionId,
              });
            }
            // else: a successor already superseded this handle -- nothing to release.
          }, {
            suppressReleaseDiagnostics: true,
            onPhysicalRelease(receipt) { physicalReceipt = receipt; },
          });
        } catch (error) {
          // A failed handover must never be reported as a clean one: back to armed, so a later
          // release() genuinely retries. The state is the gate (the armed branch always starts a
          // fresh release), so clearing the memo below is tidiness, not what makes the retry real.
          state = 'armed';
          releasePromise = null;
          releaseFinal = false;
          throw error;
        }
        if (physicalReceipt?.state === 'pending') {
          // The conditional logical operation completed (either append or deliberate superseded
          // no-op), so ownership is gone even while the exact shared-lock cleanup remains pending.
          state = 'release-pending';
          releasePromise = null;
          throw codedError(OWNER_RELEASE_PENDING_CODE, 'process ownership release cleanup remains pending');
        }
        state = releaseFinal ? 'released' : 'unarmed';
        generation = null;
        acquisitionId = null;
        releasePromise = null;
        releaseFinal = false;
      })();
      return releasePromise;
    }

    return Object.freeze({
      dataRoot,
      get generation() { return state === 'armed' ? generation : null; },
      get acquisitionId() { return state === 'armed' ? acquisitionId : null; },
      get everArmed() { return everArmed; },
      get state() { return state; },
      isOwner: () => state === 'armed',
      arm,
      release,
    });
  }

  // Inline ownership fencing. Each owner-sensitive
  // write below calls this as the FIRST statement inside its own existing mutate() transaction --
  // deliberately never a separate, composable verifyOwnership() call made before the write, which
  // would reopen a check-then-act race between the check and the write it is meant to guard. Since
  // mutate() always replays the ledger fresh before running its callback, this re-checks the
  // caller's acquisitionId against the ledger's live currentOwner every single time, never relying
  // on an in-memory isOwner() flag that could be stale during a pending release() elsewhere.
  function assertCurrentlyOwnsProcess(acquisitionId) {
    requireId(acquisitionId, 'acquisitionId');
    if (
      currentOwner === null
      || currentOwner.state !== 'ACQUIRED'
      || currentOwner.acquisitionId !== acquisitionId
    ) {
      throw new Error('caller does not currently hold process ownership of this data root');
    }
  }

  // The structured contention error, built from the loop's last refused attempt.
  // For acquireProcessOwnership() the message text is exactly what it has always thrown, so every
  // existing exact-message assertion still matches; arm() passes its own label, so an arm's message
  // starts "arm timed out". `owner` is rebuilt from three
  // named fields rather than cloned, so the internal fence token (acquisitionId) never leaves the
  // store. The loop always performs its initial attempt, even if scheduling consumed a tiny
  // budget before it could start, so every timeout describes an observed refusal.
  function ownershipUnavailableError({ label, acquireTimeoutMs, lastAttempt }) {
    const reason = lastAttempt?.reason;
    const error = new Error(`${label} timed out after ${acquireTimeoutMs}ms${reason ? ` (${reason})` : ''}`);
    error.code = PROCESS_OWNERSHIP_UNAVAILABLE_CODE;
    error.reason = reason;
    if (lastAttempt?.owner) {
      const { pid, generation, timestamp } = lastAttempt.owner;
      error.owner = { pid, generation, timestamp };
      error.ownerAgeMs = lastAttempt.ownerAgeMs;
    }
    return error;
  }

  // The one ownership attempt loop (acquireProcessOwnership() and the handle's arm()
  // share one internal attempt loop, so the two paths can never drift apart). `label` names the
  // caller in the timeout message. `nextSleepMs({ lastAttemptMs, remainingMs })` is the caller's
  // backoff between refused attempts: `lastAttemptMs` is what the refused attempt's mutate() just
  // cost, and `remainingMs` is what is left of the budget. `shouldAbort()` is an optional
  // caller-supplied stop check, read at the top of every iteration -- before every attempt
  // and right after every sleep -- and polled while a sleep runs; never once an attempt has
  // committed ACQUIRED. Only arm() passes it.
  // Resolves { generation, acquisitionId } of the ACQUIRED record this call appended; rejects with
  // the structured PROCESS_OWNERSHIP_UNAVAILABLE error once the budget is spent, with ARM_ABORTED
  // once shouldAbort() reads true, and rethrows any other failure at once, unchanged (including a
  // terminal OWNERSHIP_CAP_MISMATCH). `caps` is set only on the arm() path: the caps checkCaps()
  // compares and the ACQUIRED record carries. acquireProcessOwnership() passes undefined, so it
  // neither checks nor stamps.
  async function runOwnershipAttempts({ label, acquireTimeoutMs, nextSleepMs, shouldAbort, caps }) {
    // A stop check that throws is a stop request, never an error of its own. The first
    // throw is kept, whether the check at the top of the loop or a sleep's poll met it, and becomes
    // the ARM_ABORTED error's `cause`. Once one is kept the loop is stopping: a check that throws
    // only once is never lost to a later read that returns false. This never throws, so a poll's
    // timer callback can call it.
    let stopThrown;
    const stopRequested = () => {
      if (stopThrown !== undefined) return true;
      if (shouldAbort === undefined) return false;
      try {
        return shouldAbort();
      } catch (error) {
        stopThrown = { cause: error };
        return true;
      }
    };
    const deadline = Number(monotonicNow()) + acquireTimeoutMs;
    // The most recent REFUSED attempt, loop-scoped so every one of the three timeout throws below
    // reports what it last saw -- including the pre-attempt deadline check, which could only ever
    // report a bare reason string while `attempt` was block-scoped inside the loop body.
    let lastAttempt = null;
    const timedOut = () => ownershipUnavailableError({ label, acquireTimeoutMs, lastAttempt });
    // The sleep between refused attempts. When the caller can stop this loop (an arm), the
    // sleep is raced against a poll of its shouldAbort() every ARM_ABORT_POLL_MS and handed an abort
    // signal, so a stop request ends it early and leaves no timer behind: the sleep can be
    // ARM_BACKOFF_MULTIPLIER times a slow attempt, and a shutdown must not wait it out. The poll only
    // ends the sleep; the stop itself is still the check at the top of the loop.
    const backoff = async (lastAttemptMs) => {
      const milliseconds = nextSleepMs({ lastAttemptMs, remainingMs: deadline - Number(monotonicNow()) });
      if (shouldAbort === undefined) {
        await sleep(milliseconds);
        return;
      }
      const stop = new AbortController();
      // stopRequested(), never shouldAbort() itself: a stop check that throws is kept as a stop
      // request there (see stopThrown), so nothing escapes this timer callback, where it would be an
      // uncaught exception that crashes the process, and the throw is not lost when the check at the
      // top of the loop reads the predicate next.
      const poll = setInterval(() => {
        if (stopRequested()) stop.abort();
      }, ARM_ABORT_POLL_MS);
      const stopped = new Promise((resolve) => { stop.signal.addEventListener('abort', resolve, { once: true }); });
      try {
        await Promise.race([sleep(milliseconds, { signal: stop.signal }), stopped]);
      } finally {
        clearInterval(poll);
      }
    };
    // Owners this call has PROVEN cannot be the process named in their own record, keyed on the
    // full {acquisitionId, generation, pid} triple rather than the pid alone -- a later
    // generation is a different owner and must be judged on its own evidence, never inherit a
    // verdict reached about its predecessor. Scoped to this one call: nothing is persisted, and
    // a fresh acquire re-proves it from scratch.
    const supersededOwners = new Set();
    const probedOwners = new Set();
    // Owners whose cap mismatch this call has already probed and found to be the genuine, live
    // recording process. A second mismatch against one of them is terminal.
    const capProbedOwners = new Set();
    // Set right after a cap probe. The next attempt is the one that acts on the probe's
    // verdict, so it runs even if the ~470 ms probe itself crossed the deadline: the terminal
    // mismatch for a genuine owner, or an ordinary attempt once a recycled pid counts as dead.
    // Without it, that timeout would carry no reason at all (a cap refusal is never recorded as
    // lastAttempt), and the caller would learn nothing about the holder the probe just found.
    let actingOnCapProbe = false;
    // At most one attempt may START past the deadline to act on a cap probe. Owner churn can replace
    // the record while the probe is outside the lock; without this one-call bound, every replacement
    // could earn another probe and another deadline-exempt attempt indefinitely.
    let postDeadlineCapFollowupUsed = false;
    for (;;) {
      // Gate STARTING a new attempt on the deadline -- checked here, immediately before
      // calling mutate(), not just after a failed attempt. Without this, a sleep() call that
      // itself crossed the deadline still let the NEXT loop iteration start one more mutate()
      // attempt unconditionally: with attempts starting at
      // monotonic 0/10/20ms and a 25ms deadline, sleep() landing at 30ms still let a 4th
      // attempt start -- and if ownership happened to become acquirable in that attempt, the
      // method would succeed past its own admission deadline instead of timing out. An
      // attempt already awaiting mutate() when this check runs is unaffected -- mutate() is
      // never aborted mid-flight, so it always runs to completion -- so "an attempt already
      // in progress is allowed to finish" still holds; only the decision to start a NEW one is
      // gated. The existing post-attempt check below is kept too, so a failed attempt that
      // itself crosses the deadline throws immediately rather than sleeping once more first.
      //
      // The caller's stop check comes first, so a caller that is shutting down never waits out one
      // more attempt. Every sleep in this loop is followed by this point. A kept throw
      // from the stop check rides along as the abort's `cause`.
      if (stopRequested()) {
        const aborted = new Error(`${label} aborted by its caller before acquiring`, stopThrown);
        aborted.code = ARM_ABORTED_CODE;
        throw aborted;
      }
      // The first attempt always runs even if scheduling consumed a tiny positive budget before
      // this check, so every timeout reports an observed refusal. The loop also permits exactly one
      // attempt to start past the deadline when it is the immediate follow-up to a cap probe. Every later
      // ordinary attempt remains gated by the deadline.
      if (Number(monotonicNow()) >= deadline) {
        if (actingOnCapProbe && !postDeadlineCapFollowupUsed) {
          postDeadlineCapFollowupUsed = true;
        } else if (lastAttempt !== null || actingOnCapProbe) {
          throw timedOut();
        }
      }
      actingOnCapProbe = false;
      // A contended data-root lock is a REASON TO KEEP POLLING, not a reason to abandon the
      // budget. Without this catch, one `lockTimeoutMs` (2s) expiry aborted the whole
      // `acquireTimeoutMs` (90s) window -- and because `lockStaleMs` (60s) is the age an
      // orphaned lock must reach before ANY caller may reclaim it, a lock left behind by a
      // blocked acquirer that was killed mid-mutate() hard-failed every server start for the
      // next 60 seconds. (Age is the binding constraint in THAT scenario only because the
      // killed acquirer is genuinely dead, so the liveness half of the reclaim conjunction
      // passes at once. Reclaim is never decided by lock age alone -- see the comment on
      // LEDGER_DATA_ROOT_LOCKED_CODE.)
      // Retrying keeps the caller inside its own declared budget, which
      // outlasts that window, so the self-healing the lock design already provides is actually
      // reachable. Only this one code is swallowed: anything else (a corrupt record, a bad
      // argument) is a structural failure that retrying cannot fix, and is rethrown at once.
      let attempt;
      // Measured around the mutate() so an adaptive backoff can size itself to what one attempt
      // really costs on this ledger.
      const attemptStartedAt = Number(monotonicNow());
      try {
        attempt = await mutate(async () => {
          if (caps !== undefined) {
            const capRefusal = checkCaps(caps, { supersededOwners, capProbedOwners });
            if (capRefusal !== null) return capRefusal;
          }
          if (currentOwner === null || currentOwner.state === 'RELEASED') {
            return acquireFreshOwnership();
          }
          if (isProcessAlive(currentOwner.pid) && !supersededOwners.has(ownerKey(currentOwner))) {
            // `ageMs` is reported so the caller can decide, OUTSIDE this lock, whether the
            // record is already stale enough to be worth a start-time probe. Nothing is
            // decided here -- an owner reported alive is still refused, exactly as before.
            return {
              ok: false,
              reason: 'LIVE_OWNER',
              owner: clone(currentOwner),
              ownerAgeMs: ownerAgeMs(),
            };
          }
          // See ownerAgeMs() for why the age is derived from append()'s own monotonic value
          // rather than a raw clock() read.
          if (!(ownerAgeMs() >= lockStaleMs)) {
            // Carries the holder exactly as LIVE_OWNER does, for the structured timeout error.
            // Both values are already in scope here, so this adds no I/O.
            return {
              ok: false,
              reason: 'NOT_YET_STALE',
              owner: clone(currentOwner),
              ownerAgeMs: ownerAgeMs(),
            };
          }
          if (beforeStaleReclaim) await beforeStaleReclaim(clone(currentOwner));
          return acquireFreshOwnership();
        });
      } catch (error) {
        if (error?.code !== DATA_ROOT_LOCKED_CODE) throw error;
        // Same shape as a failed attempt below: record the reason, re-check the deadline, back
        // off, poll again. Reported as its own reason code so a real arm-failure diagnostic still
        // distinguishes lock contention from LIVE_OWNER or NOT_YET_STALE.
        // It REPLACES any earlier refusal rather than keeping its holder: DATA_ROOT_LOCKED concerns
        // the data-root write lock, not a processOwner record, so it has no holder to report.
        lastAttempt = { ok: false, reason: 'DATA_ROOT_LOCKED' };
        if (Number(monotonicNow()) >= deadline) throw timedOut();
        // This attempt's cost was time spent waiting on a busy ledger: itself a reason to back off.
        await backoff(Number(monotonicNow()) - attemptStartedAt);
        continue;
      }
      const lastAttemptMs = Number(monotonicNow()) - attemptStartedAt;
      if (attempt.ok) {
        // The ACQUIRED record is durable and the data-root lock released by now. shouldAbort() is
        // deliberately not read again: a committed acquisition is never aborted; a
        // caller that must undo it releases it.
        if (afterOwnerAcquired) await afterOwnerAcquired({ generation: attempt.generation, acquisitionId: attempt.acquisitionId });
        return { generation: attempt.generation, acquisitionId: attempt.acquisitionId };
      }
      if (attempt.reason === 'CAP_MISMATCH_UNPROBED') {
        // Outside the lock: is the live-looking recording pid really that process, or a pid Windows
        // recycled? Superseded means treat it as dead; genuine means the next attempt's
        // mismatch is terminal. Either way retry AT ONCE, with no sleep, and without recording this
        // as the last refusal: it is not a contention reason. The retry runs even past the
        // deadline (actingOnCapProbe) and turns the verdict into an in-lock answer, unless it loses
        // the data-root write lock; then the timeout reports DATA_ROOT_LOCKED instead.
        // A deadline-exempt follow-up is the only extra attempt a cap probe earns. If owner churn made that
        // attempt observe a different cap recorder, stop retryably on the live record it actually
        // observed instead of starting an unbounded probe/follow-up chain. This is deliberately not
        // terminal OWNERSHIP_CAP_MISMATCH: the successor's pid was never start-time-probed.
        if (postDeadlineCapFollowupUsed && Number(monotonicNow()) >= deadline) {
          lastAttempt = {
            ok: false,
            reason: 'LIVE_OWNER',
            owner: attempt.owner,
            ownerAgeMs: attempt.ownerAgeMs,
          };
          throw timedOut();
        }
        const key = ownerKey(attempt.owner);
        if (await ownerIsSupersededPid(attempt.owner, attempt.ownerAgeMs)) supersededOwners.add(key);
        else capProbedOwners.add(key);
        actingOnCapProbe = true;
        continue;
      }
      lastAttempt = attempt;
      // A live-looking owner on an ALREADY-STALE record is the one case a bare pid check can
      // never resolve on its own: it is indistinguishable from a recycled pid, and because
      // liveness is tested before staleness, no amount of waiting changes the answer. Probe the
      // owner's start time ONCE and let the next poll act on the verdict.
      //
      // Two properties of this placement are load-bearing, not incidental:
      //   * it is OUTSIDE mutate(), so the ~470ms child-process spawn never happens while the
      //     ledger's global write lock is held -- a poll loop that probed while holding that lock
      //     would turn its own budget into a minute-long outage for every other caller;
      //   * it is gated on the record ALREADY being stale, so the probe can only ever unblock a
      //     takeover the staleness rule already permits, never make one happen sooner. On a
      //     healthy start (no owner, or a RELEASED one) it never runs at all.
      if (attempt.reason === 'LIVE_OWNER' && attempt.ownerAgeMs >= lockStaleMs) {
        const key = ownerKey(attempt.owner);
        if (!probedOwners.has(key)) {
          probedOwners.add(key);
          if (await ownerIsSupersededPid(attempt.owner, attempt.ownerAgeMs)) supersededOwners.add(key);
        }
      }
      if (Number(monotonicNow()) >= deadline) throw timedOut();
      await backoff(lastAttemptMs);
    }

    async function acquireFreshOwnership() {
      const acquisitionId = randomUUID();
      const generation = highestOwnerGeneration + 1;
      // Stamped on the arm() path only; the legacy path writes no caps field.
      const appended = await appendOwnerRecord({
        state: 'ACQUIRED', pid: process.pid, generation, acquisitionId,
        ...(caps === undefined ? {} : { caps }),
      });
      return { ok: true, generation: appended.generation, acquisitionId: appended.acquisitionId };
    }
  }

  function managedError(code, message = code) {
    const error = new Error(message);
    Object.defineProperty(error, 'code', { value: code, enumerable: true });
    return error;
  }

  function requireManagedExecution() {
    if (managed === null) throw managedError('SERVICE_MODE_REQUIRED', 'managed review service is not configured');
    return managed;
  }

  function requireActiveServiceMode() {
    const context = requireManagedExecution();
    const mode = sharedState.serviceMode;
    if (mode === null || mode.state !== 'ACTIVE') throw managedError('SERVICE_MODE_REQUIRED');
    if (mode.configFingerprint !== context.configFingerprint || mode.buildManifestFingerprint !== context.buildManifestFingerprint) throw managedError('SERVICE_MODE_MISMATCH');
    return mode;
  }

  function requireConfiguredManagedScope(bindingId, projectId, policyEpoch) {
    const context = requireManagedExecution();
    const binding = context.installationConfig.bindings.find((entry) => entry.bindingId === bindingId && entry.enabled === true);
    const project = context.installationConfig.projects.find((entry) => entry.projectId === projectId);
    const domain = binding?.domains.find((entry) => entry.projectId === projectId);
    if (binding === undefined || project === undefined || domain === undefined || project.policyEpoch !== policyEpoch) throw managedError('SERVICE_MODE_MISMATCH');
  }

  function requireExpectedRevision(value, expected, code = 'REQUEST_REVISION_CONFLICT') {
    if (!Number.isSafeInteger(expected) || expected <= 0 || value.revision !== expected) throw managedError(code);
  }

  function strictDeadline(value) {
    requireFutureTimestamp(value, 'deadline');
    if (Date.parse(value) <= Math.max(Number(clock()), lastRecordTime + 1)) throw managedError('REQUEST_EXPIRED');
    return value;
  }

  async function appendShared(kind, fields) {
    return append({ recordType: 'shared/transition', version: 1, kind, ...fields });
  }

  function requireReceiptAccess(receiptId, bindingId, scopeDigest) {
    if (typeof receiptId !== 'string' || !OWNER_ACQUISITION_ID.test(receiptId)
      || typeof bindingId !== 'string' || bindingId.length === 0
      || typeof scopeDigest !== 'string' || !HASH.test(scopeDigest)) return null;
    const receipt = sharedState.getReceipt(receiptId);
    if (receipt === null || receipt.bindingId !== bindingId || receipt.scopeDigest !== scopeDigest) return null;
    return receipt;
  }

  function requireManagedLease(leaseId) {
    const lease = leases.get(requireId(leaseId, 'leaseId'));
    if (lease === undefined || lease.version !== 1 || lease.state !== 'MANAGED_ACTIVE') throw managedError('MANAGED_LEASE_REQUIRED');
    return lease;
  }

  function completeManagedResult(receipt, executionGroup, job, lease) {
    return clone({ receipt, executionGroup, job, lease });
  }

  function requireTerminalClaim(receipt, executionGroup, claimId) {
    if (receipt === null || executionGroup === null
      || receipt.executionGroupId !== executionGroup.executionGroupId
      || executionGroup.leaderReceiptId !== receipt.receiptId
      || receipt.claimId !== claimId || executionGroup.claimId !== claimId
      || executionGroup.state !== 'CLAIMED'
      || !['EXECUTING', 'RECOVERY_PENDING'].includes(receipt.state)) throw managedError('CLAIM_NOT_OWNER');
    const lease = requireManagedLease(receipt.leaseId);
    if (lease.managedBinding.receiptId !== receipt.receiptId
      || lease.managedBinding.executionFingerprint !== receipt.executionFingerprint) throw managedError('MANAGED_LEASE_REQUIRED');
    if ([...jobs.values()].some((job) => job.version === 1 && job.receiptId === receipt.receiptId
      && ['RESERVED', 'INTENT_PENDING'].includes(job.state))) throw managedError('RESERVATION_NOT_CANCELLABLE');
    return lease;
  }

  function terminalAssociatedJobs(receipt, executionGroup, publication) {
    const associatedJobs = [];
    for (const association of publication.advisoryAssociations) {
      if (association.jobId === undefined) {
        if ([...jobs.values()].some((job) => job.version === 1 && job.receiptId === receipt.receiptId
          && job.reviewerId === association.reviewerId)) throw managedError('PROTECTED_CONTENT_INVALID');
        continue;
      }
      const sourceReceipt = sharedState.getReceipt(association.sourceReceiptId);
      const job = jobs.get(association.jobId);
      const native = association.sourceReceiptId === receipt.receiptId;
      if (sourceReceipt === null || job?.version !== 1
        || !executionGroup.orderedReceiptIds.includes(sourceReceipt.receiptId)
        || sourceReceipt.executionGroupId !== executionGroup.executionGroupId
        || sourceReceipt.executionFingerprint !== receipt.executionFingerprint || sourceReceipt.scopeDigest !== receipt.scopeDigest
        || job.receiptId !== sourceReceipt.receiptId || job.leaseId !== sourceReceipt.leaseId
        || job.reviewerId !== association.reviewerId || job.executionFingerprint !== receipt.executionFingerprint
        || job.scopeDigest !== receipt.scopeDigest
        || !(native ? ['RECONCILED', 'CANCELLED_ZERO_DISPATCH'].includes(job.state) : job.state === 'RECONCILED')) throw managedError('PROTECTED_CONTENT_INVALID');
      associatedJobs.push({ sourceReceiptId: sourceReceipt.receiptId, job });
    }
    return associatedJobs;
  }

  async function finalizeTerminalPublication(input, contentLost) {
    requireExactObject(input, ['receiptId', 'expectedRevision', 'executionGroupId', 'expectedGroupRevision', 'claimId', 'publicationId', 'acquisitionId']);
    return mutate(async () => {
      assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
      const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
      const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
      const claimId = requireOwnerAcquisitionId(input.claimId);
      const publicationId = requireOwnerAcquisitionId(input.publicationId);
      if (receiptCurrent === null || groupCurrent === null || receiptCurrent.executionGroupId !== groupCurrent.executionGroupId) throw managedError('RECEIPT_NOT_FOUND');
      // The durable terminal is immutable, including after normal claim retirement.
      if (receiptCurrent.state === 'TERMINAL') return clone(receiptCurrent);
      requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
      const leaseCurrent = requireTerminalClaim(receiptCurrent, groupCurrent, claimId);
      const publication = receiptCurrent.terminalPublication;
      if (publication === undefined || publication.publicationId !== publicationId || publication.claimId !== claimId) throw managedError('CLAIM_CONFLICT');
      let terminal;
      if (contentLost) {
        const proof = await managed.storageProofs.provePermanentTerminalPublicationLoss({
          receiptId: receiptCurrent.receiptId, publicationId,
          frozenAdvisoryAssociations: clone(publication.advisoryAssociations.filter((entry) => entry.contentAvailable)),
        });
        requireExactObject(proof, ['reason'], [], 'permanent terminal loss proof');
        if (!['TERMINAL_CANDIDATE_INVALID', 'SOURCE_ADVISORY_INVALID'].includes(proof.reason)) throw managedError('PROTECTED_CONTENT_INVALID');
        terminal = { kind: 'CONTENT_LOST', errorCode: 'REQUEST_CONTENT_LOST', completedAt: publication.completedAt };
      } else {
        const proof = await managed.storageProofs.proveTerminalPublication({ receiptId: receiptCurrent.receiptId, publicationId });
        requireExactObject(proof, ['terminalRef', 'terminalDigest'], [], 'terminal publication proof');
        if (!validProtectedRefs([proof.terminalRef])) throw managedError('PROTECTED_CONTENT_INVALID');
        requireHash(proof.terminalDigest, 'terminalDigest');
        terminal = {
          kind: publication.outcomeKind,
          ...(publication.outcomeErrorCode === undefined ? {} : { errorCode: publication.outcomeErrorCode }),
          completedAt: publication.completedAt, terminalRef: clone(proof.terminalRef), terminalDigest: proof.terminalDigest,
        };
      }
      const { terminalPublication: _publication, ...receiptBase } = receiptCurrent;
      const receipt = { ...receiptBase, revision: receiptCurrent.revision + 1, state: 'TERMINAL', terminal };
      const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
      const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1, state: publication.leaseDisposition };
      await appendShared('RECEIPT_TERMINALIZED', { receipt, executionGroup, lease });
      return clone(receipt);
    });
  }

  function validProtectedRefs(refs) {
    try { canonicalJson(refs); } catch { return false; }
    return Array.isArray(refs) && refs.every((ref) => isPlainObject(ref)
      && Object.keys(ref).length === 3
      && Object.hasOwn(ref, 'objectId') && OWNER_ACQUISITION_ID.test(ref.objectId)
      && Object.hasOwn(ref, 'sha256') && HASH.test(ref.sha256)
      && Object.hasOwn(ref, 'encryptedBytes') && Number.isSafeInteger(ref.encryptedBytes) && ref.encryptedBytes >= 0);
  }

  function inspectionMatches(inspected, refs, { absent = false } = {}) {
    try { canonicalJson(inspected); } catch { return false; }
    return isPlainObject(inspected) && inspected.complete === true && Array.isArray(inspected.objects)
      && inspected.objects.length === refs.length
      && inspected.objects.every((entry) => isPlainObject(entry) && typeof entry.present === 'boolean' && (!absent || entry.present === false))
      && canonicalJson(inspected.objects.map((entry) => entry.ref)) === canonicalJson(refs);
  }

  function referencedProtectedObjectIds(snapshot) {
    const ids = new Set();
    const add = (ref) => { if (isPlainObject(ref) && typeof ref.objectId === 'string') ids.add(ref.objectId); };
    for (const [, identity] of snapshot.managedIdentities) { add(identity.contextRef); add(identity.mappingRef); }
    for (const receipt of snapshot.receipts) {
      if (receipt.preparedPayload !== undefined) {
        add(receipt.preparedPayload.envelopeRef);
        receipt.preparedPayload.requestRefs.forEach(add);
      }
      if (receipt.retiredPreparedPayloadAudit !== undefined) {
        add(receipt.retiredPreparedPayloadAudit.envelopeRef);
        receipt.retiredPreparedPayloadAudit.requestRefs.forEach(add);
      }
      add(receipt.terminal?.terminalRef);
    }
    for (const tombstone of snapshot.preflightTombstones) { add(tombstone.retiredContextAuditRef); add(tombstone.retiredMappingAuditRef); }
    for (const tombstone of snapshot.payloadTombstones) {
      add(tombstone.retiredPreparedPayloadAudit.envelopeRef);
      tombstone.retiredPreparedPayloadAudit.requestRefs.forEach(add);
    }
    return ids;
  }

  // ---- Preflight capacity maintenance (reclaim on pressure and sealing of released reservations) ----
  //
  // The four *InTransaction bodies are the transactions of disposeUnadmittedManagedLease, retireManagedPreflight,
  // ackManagedPreflightPayloadDeletion and ackReleasedPreflightReservationPayloadDeletion, moved out of those public methods
  // unchanged. Each runs INSIDE a transaction its caller already holds: the caller has replayed the ledger, checked ownership
  // and read the active service mode. The public methods wrap them in their own mutate(); the reclaim helper below calls them
  // from inside reserveManagedPreflightCapacity's mutate(). Never call a PUBLIC method from inside another mutate(): the
  // managed mutation queue would put it behind the running transaction, which is waiting for it, so it would deadlock.

  // The one place a reservation's deletion-ack target is built. Its key order is load-bearing: capacity recognises an ack
  // only by JSON.stringify of exactly { reservationId, generation } (ledger-state.mjs snapshot), while the ack validator
  // accepts either order, so a target built any other way would validate, delete, and still leave the bytes charged.
  function preflightReservationTarget({ reservationId, generation }) {
    return { reservationId, generation };
  }

  async function disposeUnadmittedManagedLeaseInTransaction({ leaseId, expectedRevision, reason }) {
    const current = requireManagedLease(leaseId);
    requireExpectedRevision(current, expectedRevision);
    if (!['PREPARATION_FAILED', 'EXPIRED'].includes(reason)) throw new TypeError('invalid unadmitted lease disposal reason');
    const state = sharedState.snapshot();
    const hasReceipt = state.receipts.some((receipt) => receipt.leaseId === current.id);
    const hasJob = state.managedJobs.some((job) => job.leaseId === current.id);
    const hasLiveStage = state.staging.some((entry) => entry.leaseId === current.id && ['RESERVED', 'COMMITTED'].includes(entry.state));
    if (Object.hasOwn(current.managedBinding, 'receiptId') || Object.hasOwn(current.managedBinding, 'executionFingerprint')
      || hasReceipt || hasJob || hasLiveStage) throw managedError('REQUEST_NOT_ELIGIBLE');
    const lease = {
      ...current,
      revision: current.revision + 1,
      state: reason === 'EXPIRED' ? 'EXPIRED' : 'CANCELLED',
    };
    await appendShared('UNADMITTED_LEASE_DISPOSED', { lease });
    return clone(lease);
  }

  async function retireManagedPreflightInTransaction({ preflightId, expectedRevision, reason }) {
    requireId(reason, 'reason');
    const current = sharedState.getManagedPreflight(requireOwnerAcquisitionId(preflightId));
    const identity = sharedState.getManagedIdentity(preflightId);
    if (current === null || identity === null) throw managedError('FRESH_PREFLIGHT_REQUIRED');
    if (sharedState.snapshot().preflightTombstones.some((entry) => entry.preflightId === preflightId)) throw managedError('REQUEST_REVISION_CONFLICT');
    requireExpectedRevision(current, expectedRevision);
    const dependentLeaseIds = new Set(sharedState.snapshot().managedLeases.filter((lease) => lease.preflightIds.includes(preflightId) && lease.state === 'MANAGED_ACTIVE').map((lease) => lease.id));
    if (dependentLeaseIds.size > 0 || sharedState.snapshot().receipts.some((receipt) => receipt.preflightId === preflightId && receipt.state !== 'TERMINAL')) throw managedError('SERVICE_ROLLBACK_BLOCKED');
    const retiredAt = new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString();
    const mappingDeleteNoLaterThan = new Date(Date.parse(retiredAt) + (24 * 60 * 60 * 1000)).toISOString();
    const preflight = { ...current, revision: current.revision + 1 };
    const managedIdentity = clone(identity);
    const preflightTombstone = {
      version: 1, preflightId, revision: preflight.revision,
      retiredContextAuditRef: { ...identity.contextRef, retiredAt },
      retiredMappingAuditRef: { ...identity.mappingRef, retiredAt, mappingDeleteNoLaterThan },
    };
    await appendShared('MANAGED_PREFLIGHT_RETIRED', { preflight, managedIdentity, preflightTombstone });
    return clone({ preflight, tombstone: preflightTombstone });
  }

  async function ackManagedPreflightPayloadDeletionInTransaction({ preflightId, expectedRevision, acquisitionId, mode }) {
    const current = sharedState.getManagedPreflight(requireOwnerAcquisitionId(preflightId));
    requireExpectedRevision(current, expectedRevision);
    const tombstone = sharedState.snapshot().preflightTombstones.find((entry) => entry.preflightId === preflightId);
    if (tombstone === undefined || tombstone.revision !== current.revision) throw managedError('REQUEST_NOT_ELIGIBLE');
    const origin = sharedState.getPreflightOrigin(preflightId);
    if (origin === null) throw managedError('PROTECTED_CONTENT_INVALID');
    const target = { preflightId };
    if (sharedState.snapshot().deletionAcks.some((entry) => canonicalJson(entry.target) === canonicalJson(target))) throw managedError('REQUEST_REVISION_CONFLICT', 'deletion already acknowledged');
    const refs = [
      { objectId: tombstone.retiredContextAuditRef.objectId, sha256: tombstone.retiredContextAuditRef.sha256, encryptedBytes: tombstone.retiredContextAuditRef.encryptedBytes },
      { objectId: tombstone.retiredMappingAuditRef.objectId, sha256: tombstone.retiredMappingAuditRef.sha256, encryptedBytes: tombstone.retiredMappingAuditRef.encryptedBytes },
    ];
    const before = managed.storageProofs.inspectTarget({ kind: 'preflight', target: origin });
    if (!isPlainObject(before) || before.complete !== true || !Array.isArray(before.objects)
      || canonicalJson(before.objects.map((entry) => entry.ref)) !== canonicalJson(refs)) throw managedError('PROTECTED_CONTENT_INVALID', 'deletion manifest does not match the tombstone');
    const descriptor = { version: 1, kind: 'preflight', target: origin, refs, tombstoneRevision: tombstone.revision, acquisitionId, replayBarrierId: mode.replayBarrierId };
    managed.storageProofs.deleteRetired({ descriptor });
    const inspected = managed.storageProofs.inspectTarget({ kind: 'preflight', target: origin });
    if (!isPlainObject(inspected) || inspected.complete !== true || !Array.isArray(inspected.objects)
      || canonicalJson(inspected.objects.map((entry) => entry.ref)) !== canonicalJson(refs)
      || inspected.objects.some((entry) => entry.present !== false)) throw managedError('PROTECTED_CONTENT_INVALID', 'deletion proof is incomplete or content remains present');
    const preflightDeletionAck = { version: 1, target, context: { objectId: refs[0].objectId, sha256: refs[0].sha256 }, mapping: { objectId: refs[1].objectId, sha256: refs[1].sha256 }, deletionProvedAt: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString() };
    await appendShared('MANAGED_PREFLIGHT_PAYLOAD_DELETION_ACKED', { preflightDeletionAck });
    return clone(preflightDeletionAck);
  }

  // Accepts any RELEASED reservation whatever its releaseReason, exactly as the public method always did (deliberately
  // unchanged). The reclaim helper and the release's own refund call it only for PREPARE_FAILED and RESTART releases.
  async function ackReleasedPreflightReservationPayloadDeletionInTransaction({ reservationId, generation, acquisitionId, mode }) {
    const current = sharedState.getPreflightReservation(requireOwnerAcquisitionId(reservationId));
    if (current === null || current.generation !== generation || current.state !== 'RELEASED') throw managedError('STAGING_STALE');
    const target = preflightReservationTarget({ reservationId, generation });
    if (sharedState.snapshot().deletionAcks.some((entry) => canonicalJson(entry.target) === canonicalJson(target))) throw managedError('REQUEST_REVISION_CONFLICT', 'deletion already acknowledged');
    const before = managed.storageProofs.inspectTarget({ kind: 'preflight', target });
    if (!isPlainObject(before) || before.complete !== true || !Array.isArray(before.objects)) throw managedError('PROTECTED_CONTENT_INVALID', 'deletion manifest is incomplete');
    const refs = before.objects.map((entry) => entry.ref);
    canonicalJson(refs);
    const descriptor = { version: 1, kind: 'preflight', target, refs, tombstoneRevision: current.revision, acquisitionId, replayBarrierId: mode.replayBarrierId };
    managed.storageProofs.deleteRetired({ descriptor });
    const inspected = managed.storageProofs.inspectTarget({ kind: 'preflight', target });
    if (!isPlainObject(inspected) || inspected.complete !== true || !Array.isArray(inspected.objects)
      || canonicalJson(inspected.objects.map((entry) => entry.ref)) !== canonicalJson(refs)
      || inspected.objects.some((entry) => entry.present !== false)) throw managedError('PROTECTED_CONTENT_INVALID', 'deletion proof is incomplete or content remains present');
    const preflightDeletionAck = {
      version: 1, target,
      ...(refs[0] === undefined ? {} : { context: { objectId: refs[0].objectId, sha256: refs[0].sha256 } }),
      ...(refs[1] === undefined ? {} : { mapping: { objectId: refs[1].objectId, sha256: refs[1].sha256 } }),
      deletionProvedAt: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString(),
    };
    await appendShared('MANAGED_PREFLIGHT_PAYLOAD_DELETION_ACKED', { preflightDeletionAck });
    return clone(preflightDeletionAck);
  }

  // Counts-only log lines in the redacted style of emitReleaseDiagnostic: fixed words and numbers, never an id, a message,
  // an amount or a path. A code is included only when it is a plain upper-case word.
  function emitPreflightMaintenanceLine(text) {
    try {
      process.stderr.write(`openrouter-review-lease-store: ${text}\n`);
    } catch {
      // Observational only: a broken stderr sink must never change a ledger outcome.
    }
  }

  function redactedErrorCode(error) {
    let code;
    try { code = error?.code; } catch { code = undefined; }
    return typeof code === 'string' && /^[A-Z][A-Z0-9_]{2,63}$/.test(code) ? code : 'ERROR';
  }

  // Seals a preflight target, bounded by preflightSealTimeoutMs. The protected store's lifecycle queue has no time
  // limit of its own (nor has its native storage helper), so one stuck put would otherwise stall this call for good: inside
  // the reserve transaction that would hold the ledger lock and every other ledger call behind it, and on the release path
  // it would hold back a failed preview's answer. A seal that times out is a failure (code SEAL_TIMEOUT) and is never
  // followed by an acknowledgement; if the abandoned seal finishes later, that is harmless (sealing is idempotent).
  async function sealPreflightTargetWithinBound(target) {
    let timer;
    const sealing = Promise.resolve().then(() => managed.storageProofs.sealTarget({ kind: 'preflight', target }));
    // An abandoned seal that fails after the bound must not surface as an unhandled rejection.
    sealing.catch(() => {});
    const bound = new Promise((_, reject) => {
      timer = setTimeout(() => reject(managedError('SEAL_TIMEOUT', 'the protected-store seal did not finish in time')),
        preflightSealTimeoutMs);
    });
    try {
      return await Promise.race([sealing, bound]);
    } finally {
      clearTimeout(timer);
    }
  }

  // Seal-on-release: after a PREPARE_FAILED or RESTART release (and only after its own transaction has ended), seal the target so a
  // reservation that never stored anything has an empty manifest row, then acknowledge the deletion in a second short
  // transaction; the charge then drops through the ordinary capacity rule. Every failure, a timed-out seal included, is
  // logged and swallowed: the release already happened, and the reservation simply stays charged until the owed-deletion
  // phase of the reclaim helper retries it under bytes pressure. A store without sealTarget (older fakes) skips the refund
  // and keeps the charge.
  async function refundReleasedPreflightReservation({ reservationId, generation, acquisitionId }) {
    try {
      if (typeof managed.storageProofs.sealTarget !== 'function') return;
      await sealPreflightTargetWithinBound(preflightReservationTarget({ reservationId, generation }));
      await mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const target = preflightReservationTarget({ reservationId, generation });
        // Already acknowledged in between (for example by a reclaim under pressure): nothing is owed.
        if (sharedState.snapshot().deletionAcks.some((entry) => canonicalJson(entry.target) === canonicalJson(target))) return null;
        return ackReleasedPreflightReservationPayloadDeletionInTransaction({ reservationId, generation, acquisitionId, mode });
      });
    } catch (error) {
      emitPreflightMaintenanceLine(`preflight-release-refund-failed code=${redactedErrorCode(error)} (detail redacted)`);
    }
  }

  // Reclaim on pressure. Called only from reserveManagedPreflightCapacity's transaction, after its input checks, and only
  // when its count check or its bytes check would refuse. It never throws and never calls a public method (see above). Every
  // row it appends is an existing kind with ordinary values, and each is durable at once, so any prefix of its work is a
  // valid, replayable ledger that the next pressure call continues from. It plans, filters, checks feasibility, then acts,
  // all against one snapshot of this transaction (the only writer while it runs).
  const PREFLIGHT_RECLAIM_MAX_APPENDS = 12;
  const PREFLIGHT_RECLAIM_TIME_BUDGET_MS = 750;
  const PREFLIGHT_RECLAIM_MAX_CONSECUTIVE_FAILURES = 2;
  const PREFLIGHT_RECLAIM_POISON_FAILURES = 3;
  const PREFLIGHT_RECLAIM_POISON_EXPIRY_MS = 5 * 60 * 1000;
  // The only released reservations the helper ever seals or acknowledges: their preparer has finished (a failed
  // preparation) or is dead (a restart). An EXPIRED or ABANDONED release may still have a live preparer, and sealing a
  // target that already has a manifest row is no fence against that preparer's later put, so the helper never seals or
  // acknowledges such a release and leaves its charge in place. The public ackReleasedPreflightReservationPayloadDeletion
  // still accepts any RELEASED reservation whatever its reason, as it always did; it is deliberately unchanged.
  const PREFLIGHT_RECLAIM_RELEASE_REASONS = new Set(['PREPARE_FAILED', 'RESTART']);
  // Failed attempts per candidate (keyed by reservationId or preflightId) in this store instance, as { count, lastFailureAt }
  // on the monotonic clock. A success clears the entry and it lapses five minutes after the last failure, so a transient
  // fault never takes a candidate out of reach until a restart.
  const preflightReclaimFailures = new Map();

  // What a Phase 2 victim costs in appends when a bytes need relies on it: its disposals not yet done, its retire, and the
  // acknowledgement that frees its bytes (the retire alone frees none).
  function preflightVictimAppends(candidate, disposedLeaseIds) {
    return candidate.disposals.filter((lease) => !disposedLeaseIds.has(lease.id)).length + 2;
  }

  function preflightCapacityNeed(capacity, maxEncryptedBytes) {
    const storage = managed.installationConfig.storage;
    return {
      needCount: Math.max(0, capacity.livePreflightCount - storage.maxLivePreflights + 1),
      needBytes: Math.max(0, capacity.preflightEncryptedBytes + maxEncryptedBytes - storage.maxPreflightEncryptedBytes),
    };
  }

  function preflightReclaimPoisoned(key) {
    const entry = preflightReclaimFailures.get(key);
    if (entry === undefined) return false;
    if (Number(monotonicNow()) - entry.lastFailureAt >= PREFLIGHT_RECLAIM_POISON_EXPIRY_MS) {
      preflightReclaimFailures.delete(key);
      return false;
    }
    return entry.count >= PREFLIGHT_RECLAIM_POISON_FAILURES;
  }

  function notePreflightReclaimFailure(key) {
    const now = Number(monotonicNow());
    const entry = preflightReclaimFailures.get(key);
    const lapsed = entry === undefined || now - entry.lastFailureAt >= PREFLIGHT_RECLAIM_POISON_EXPIRY_MS;
    preflightReclaimFailures.set(key, { count: lapsed ? 1 : entry.count + 1, lastFailureAt: now });
  }

  // Pure planning over one snapshot. Anything that would be a no-op (already acknowledged, nothing charged, nothing the store
  // can prove, poisoned) is dropped here, before any budget is spent.
  function planPreflightReclaim({ snapshot, now, acquisitionId, mode, needBytes }) {
    const ackedTargets = new Set(snapshot.deletionAcks.map((entry) => JSON.stringify(entry.target)));
    const tombstoned = new Set(snapshot.preflightTombstones.map((entry) => entry.preflightId));
    const identities = new Map(snapshot.managedIdentities);
    const preflightById = new Map(snapshot.managedPreflights.map((preflight) => [preflight.id, preflight]));
    const groups = new Map(snapshot.executionGroups.map((group) => [group.executionGroupId, group]));
    const leaseById = new Map(snapshot.managedLeases.map((lease) => [lease.id, lease]));
    const reservationById = new Map(snapshot.preflightReservations.map((reservation) => [reservation.reservationId, reservation]));
    const reservationOrdinal = new Map(snapshot.preflightReservations.map((reservation, index) => [reservation.reservationId, index]));
    const originByPreflight = new Map();
    for (const preflight of snapshot.managedPreflights) {
      const origin = sharedState.getPreflightOrigin(preflight.id);
      if (origin !== null) originByPreflight.set(preflight.id, origin);
    }
    // The capacity rule of ledger-state.mjs, restated per reservation: charged until an ack names its own target. The rule's
    // other case (a committed reservation whose preflight is acknowledged) cannot arise where this is used: a committed
    // reservation is priced only for a Phase 2 candidate (no tombstone, so no acknowledgement) or for an owed tombstone that
    // is not acknowledged yet.
    const charge = (reservation) => {
      if (ackedTargets.has(JSON.stringify(preflightReservationTarget(reservation)))) return 0;
      return reservation.state === 'COMMITTED' ? reservation.exactEncryptedBytes ?? 0 : reservation.retainedEncryptedBytes;
    };
    const inspect = (target) => {
      try {
        const inspected = managed.storageProofs.inspectTarget({ kind: 'preflight', target });
        return isPlainObject(inspected) && Array.isArray(inspected.objects) ? inspected : null;
      } catch {
        return null;
      }
    };
    const canSeal = typeof managed.storageProofs.sealTarget === 'function';

    // Phase 0: reservations left RESERVED by a dead owner (another acquisition or replay barrier). They can never commit
    // (commitManagedPreflight refuses them). A same-owner reservation is never a candidate, even past its expiry: its
    // operation may be mid-store.
    const staleReserved = [];
    for (const reservation of snapshot.preflightReservations) {
      if (reservation.state !== 'RESERVED') continue;
      if (reservation.ownerAcquisitionId === acquisitionId && reservation.replayBarrierId === mode.replayBarrierId) continue;
      if (preflightReclaimPoisoned(reservation.reservationId)) continue;
      const inspected = inspect(preflightReservationTarget(reservation));
      const ackable = inspected !== null && (inspected.complete === true || canSeal);
      staleReserved.push({ reservation, bytesRelief: ackable ? charge(reservation) : 0 });
    }

    // Phase 1 (bytes pressure only): deletions already owed, for retired preflights and for PREPARE_FAILED and RESTART
    // releases only (see PREFLIGHT_RECLAIM_RELEASE_REASONS). A retire frees only its own small committed bytes, so a bytes
    // need is met mainly by these acks. Largest relief first, then ledger order.
    const owed = [];
    if (needBytes > 0) {
      for (const reservation of snapshot.preflightReservations) {
        if (reservation.state !== 'RELEASED' || !PREFLIGHT_RECLAIM_RELEASE_REASONS.has(reservation.releaseReason)) continue;
        if (preflightReclaimPoisoned(reservation.reservationId)) continue;
        const relief = charge(reservation);
        if (relief <= 0) continue;
        const inspected = inspect(preflightReservationTarget(reservation));
        if (inspected === null || (inspected.complete !== true && !canSeal)) continue;
        owed.push({ kind: 'RELEASED', reservation, relief, ordinal: reservationOrdinal.get(reservation.reservationId) });
      }
      for (const tombstone of snapshot.preflightTombstones) {
        if (preflightReclaimPoisoned(tombstone.preflightId) || ackedTargets.has(JSON.stringify({ preflightId: tombstone.preflightId }))) continue;
        const preflight = preflightById.get(tombstone.preflightId);
        const origin = originByPreflight.get(tombstone.preflightId);
        const reservation = origin === undefined ? undefined : reservationById.get(origin.reservationId);
        if (preflight === undefined || reservation === undefined || tombstone.revision !== preflight.revision) continue;
        const relief = charge(reservation);
        const refs = [tombstone.retiredContextAuditRef, tombstone.retiredMappingAuditRef]
          .map(({ objectId, sha256, encryptedBytes }) => ({ objectId, sha256, encryptedBytes }));
        const inspected = inspect(origin);
        if (relief <= 0 || inspected?.complete !== true
          || canonicalJson(inspected.objects.map((entry) => entry.ref)) !== canonicalJson(refs)) continue;
        owed.push({ kind: 'RETIRED', preflight, relief, ordinal: reservationOrdinal.get(origin.reservationId) });
      }
      owed.sort((left, right) => right.relief - left.relief || left.ordinal - right.ordinal);
    }

    // Phase 2: retire candidates, each with no remaining dependents (clauses C0 to C5 below).
    const receiptsByPreflight = new Map();
    const leasesByPreflight = new Map();
    const push = (map, key, value) => { const list = map.get(key); if (list === undefined) map.set(key, [value]); else list.push(value); };
    for (const receipt of snapshot.receipts) {
      for (const preflightId of new Set([receipt.preflightId, ...receipt.mappingPins.map((pin) => pin.preflightId)])) push(receiptsByPreflight, preflightId, receipt);
    }
    for (const lease of snapshot.managedLeases) for (const preflightId of lease.preflightIds) push(leasesByPreflight, preflightId, lease);
    const leaseWithReceipt = new Set(snapshot.receipts.map((receipt) => receipt.leaseId));
    const leaseWithJob = new Set(snapshot.managedJobs.map((job) => job.leaseId));
    const leaseWithLiveStage = new Set(snapshot.staging.filter((entry) => ['RESERVED', 'COMMITTED'].includes(entry.state)).map((entry) => entry.leaseId));
    const candidates = [];
    snapshot.managedPreflights.forEach((preflight, ordinal) => {
      // C0: committed, with an identity and an origin, no tombstone yet, and not poisoned in this store instance.
      if (tombstoned.has(preflight.id) || !identities.has(preflight.id) || !originByPreflight.has(preflight.id) || preflightReclaimPoisoned(preflight.id)) return;
      const receipts = receiptsByPreflight.get(preflight.id) ?? [];
      // C2: every receipt for it, by preflight id or by mapping pin, is TERMINAL.
      if (receipts.some((receipt) => receipt.state !== 'TERMINAL')) return;
      // C3: no such receipt's execution group is still CLAIMED or RECOVERY_PENDING (the claim window between
      // RECEIPT_TERMINALIZED and CLAIM_RETIRED still pins the mapping; the public retire does not check this).
      if (receipts.some((receipt) => ['CLAIMED', 'RECOVERY_PENDING'].includes(groups.get(receipt.executionGroupId)?.state))) return;
      // C4: no such receipt's lease is still MANAGED_ACTIVE (the rest of the listPinnedMappings pin rule).
      if (receipts.some((receipt) => leaseById.get(receipt.leaseId)?.state === 'MANAGED_ACTIVE')) return;
      // C5: expired, or spent with every receipt REVIEW_RETURNED. An unexpired unspent preflight is still authorizable, and
      // a spent one whose review failed, was cancelled or expired waits for its own expiry (a cheap retry stays possible).
      const expired = Date.parse(preflight.expiresAt) <= now;
      const returned = receipts.length > 0 && receipts.every((receipt) => receipt.terminal?.kind === 'REVIEW_RETURNED');
      if (!expired && !returned) return;
      // C1: no MANAGED_ACTIVE lease depends on it, except one that is expired and was never admitted (no receipt, no job,
      // no live staging, no receipt binding), which is disposed first. The ledger's dispose transition has no expiry check,
      // so this one is the helper's own.
      const disposals = [];
      for (const lease of leasesByPreflight.get(preflight.id) ?? []) {
        if (lease.state !== 'MANAGED_ACTIVE') continue;
        if (Date.parse(lease.expiresAt) > now || leaseWithReceipt.has(lease.id) || leaseWithJob.has(lease.id) || leaseWithLiveStage.has(lease.id)
          || Object.hasOwn(lease.managedBinding, 'receiptId') || Object.hasOwn(lease.managedBinding, 'executionFingerprint')) return;
        disposals.push(lease);
      }
      const origin = originByPreflight.get(preflight.id);
      const reservation = reservationById.get(origin.reservationId);
      candidates.push({
        preflight, disposals, ordinal,
        rank: expired ? 0 : 1,
        at: expired ? Date.parse(preflight.expiresAt) : Math.max(...receipts.map((receipt) => Date.parse(receipt.terminal.completedAt))),
        bytesRelief: reservation === undefined ? 0 : charge(reservation),
      });
    });
    // Expired first by expiresAt; then spent-and-returned by the latest receipt's terminal.completedAt; ties by the ledger
    // ordinal of the commit (replay applies rows in sorted file order, so every process picks the same victims).
    candidates.sort((left, right) => left.rank - right.rank || left.at - right.at || left.ordinal - right.ordinal);

    return { staleReserved, owed, candidates, canSeal };
  }

  // Feasibility for the count need and the bytes need together, simulated on the plan as if every attempt succeeded and in
  // the order the phases act: Phase 0 as it runs, Phase 1 while bytes are still needed, then exactly the ordered Phase 2
  // victims that the remaining count need would retire, each relieving only its own small committed bytes through its ack.
  // Appends count where they decide the outcome: a victim that a still-open bytes need relies on frees those bytes only
  // through the acknowledgement that follows its retire in the same call, so its disposals, its retire and that
  // acknowledgement must fit in one call's append budget, and a victim that cannot stops the simulation as it stops the act
  // phase. This check uses the whole budget, not what Phase 0 and Phase 1 leave: their work destroys no finished preflight
  // and is durable, so when it crowds a victim out the act phase stops before the victim and the next call, with that work
  // done, finishes it. A count-only victim needs no such check: a count need met partly in one call is met by the rest in
  // the next.
  function preflightReclaimFeasible(plan, needCount, needBytes) {
    let count = needCount;
    let bytes = needBytes;
    for (const item of plan.staleReserved) {
      if (count <= 0 && (bytes <= 0 || item.bytesRelief <= 0)) continue;
      count -= 1;
      bytes -= item.bytesRelief;
    }
    for (const item of plan.owed) {
      if (bytes <= 0) break;
      bytes -= item.relief;
    }
    const disposed = new Set();
    for (const candidate of plan.candidates) {
      if (count <= 0) break;
      if (bytes > 0 && preflightVictimAppends(candidate, disposed) > PREFLIGHT_RECLAIM_MAX_APPENDS) break;
      for (const lease of candidate.disposals) disposed.add(lease.id);
      count -= 1;
      bytes -= candidate.bytesRelief;
    }
    return count <= 0 && bytes <= 0;
  }

  async function reclaimPreflightCapacityUnderPressure({ acquisitionId, mode, capacity, maxEncryptedBytes }) {
    const counts = { released: 0, sealed: 0, disposed: 0, retired: 0, acked: 0, failed: 0 };
    try {
      const started = Number(monotonicNow());
      let { needCount, needBytes } = preflightCapacityNeed(capacity, maxEncryptedBytes);
      const now = Math.max(Number(clock()), lastRecordTime + 1);
      const plan = planPreflightReclaim({ snapshot: sharedState.snapshot(), now, acquisitionId, mode, needBytes });
      // Feasibility before any append: if the candidates cannot cover the need, append nothing and let the original refusal
      // surface (a partial reclaim would destroy retained preflights for a reserve that still fails).
      if (!preflightReclaimFeasible(plan, needCount, needBytes)) return;
      // One shared budget for every phase: appends (every dispose, release, retire and ack is one, failed or not), elapsed
      // time on the injectable monotonic clock checked between appends, and consecutive failures.
      let appends = 0;
      let consecutiveFailures = 0;
      const canAppend = () => appends < PREFLIGHT_RECLAIM_MAX_APPENDS
        && consecutiveFailures < PREFLIGHT_RECLAIM_MAX_CONSECUTIVE_FAILURES
        && Number(monotonicNow()) - started < PREFLIGHT_RECLAIM_TIME_BUDGET_MS;
      const attempt = async (key, work) => {
        appends += 1;
        try {
          const value = await work();
          consecutiveFailures = 0;
          preflightReclaimFailures.delete(key);
          return { ok: true, value };
        } catch {
          counts.failed += 1;
          consecutiveFailures += 1;
          notePreflightReclaimFailure(key);
          return { ok: false };
        }
      };
      // The seal also drains every put already queued for the target, so an in-flight write is either finished (and
      // deleted by the ack) or refused; on a target that already has a row it changes nothing. It is bounded: a seal that
      // times out is a failed attempt and its ack is never tried.
      const sealThenAckReleased = async (reservation) => {
        if (plan.canSeal) {
          const sealed = await sealPreflightTargetWithinBound(preflightReservationTarget(reservation));
          if (sealed?.sealed === true) counts.sealed += 1;
        }
        return ackReleasedPreflightReservationPayloadDeletionInTransaction({
          reservationId: reservation.reservationId, generation: reservation.generation, acquisitionId, mode,
        });
      };

      phases: {
        for (const item of plan.staleReserved) {
          if (needCount <= 0 && (needBytes <= 0 || item.bytesRelief <= 0)) continue;
          if (!canAppend()) break phases;
          const key = item.reservation.reservationId;
          const released = await attempt(key, () => appendShared('MANAGED_PREFLIGHT_RESERVATION_RELEASED', {
            preflightReservation: { ...item.reservation, state: 'RELEASED', revision: item.reservation.revision + 1, releaseReason: 'RESTART' },
          }));
          if (!released.ok) continue;
          counts.released += 1;
          needCount -= 1;
          if (item.bytesRelief <= 0) continue;
          if (!canAppend()) break phases;
          const acked = await attempt(key, () => sealThenAckReleased(item.reservation));
          if (acked.ok) { counts.acked += 1; needBytes -= item.bytesRelief; }
        }
        for (const item of plan.owed) {
          if (needBytes <= 0) break;
          if (!canAppend()) break phases;
          const acked = item.kind === 'RELEASED'
            ? await attempt(item.reservation.reservationId, () => sealThenAckReleased(item.reservation))
            : await attempt(item.preflight.id, () => ackManagedPreflightPayloadDeletionInTransaction({
              preflightId: item.preflight.id, expectedRevision: item.preflight.revision, acquisitionId, mode,
            }));
          if (acked.ok) { counts.acked += 1; needBytes -= item.relief; }
        }
        const disposedLeaseIds = new Set();
        candidates: for (let index = 0; index < plan.candidates.length; index += 1) {
          if (needCount <= 0) break;
          // Before destroying anything: the victims this count need would still retire must be able to free the open
          // bytes need by their own charge; otherwise the reserve is refused anyway, so stop here.
          const victims = plan.candidates.slice(index, index + needCount);
          if (victims.length < needCount || needBytes > victims.reduce((sum, entry) => sum + entry.bytesRelief, 0)) break;
          const candidate = plan.candidates[index];
          const key = candidate.preflight.id;
          // While a bytes need is open, touch this victim only if the budget still holds all of its disposals, its retire and
          // the acknowledgement that frees its bytes; otherwise stop before any of it is done. A retire whose acknowledgement
          // cannot follow in this call would destroy a finished preflight for a reserve that is refused anyway.
          if (needBytes > 0 && appends + preflightVictimAppends(candidate, disposedLeaseIds) > PREFLIGHT_RECLAIM_MAX_APPENDS) break;
          for (const lease of candidate.disposals) {
            if (disposedLeaseIds.has(lease.id)) continue;
            if (!canAppend()) break phases;
            const disposed = await attempt(key, () => disposeUnadmittedManagedLeaseInTransaction({ leaseId: lease.id, expectedRevision: lease.revision, reason: 'EXPIRED' }));
            if (!disposed.ok) continue candidates;
            disposedLeaseIds.add(lease.id);
            counts.disposed += 1;
          }
          if (!canAppend()) break phases;
          const retired = await attempt(key, () => retireManagedPreflightInTransaction({ preflightId: key, expectedRevision: candidate.preflight.revision, reason: 'CAPACITY_RECLAIM' }));
          if (!retired.ok) continue;
          counts.retired += 1;
          needCount -= 1;
          // Tombstone first, then its deletion ack straight away (the audit order the retire test states). If that ack fails,
          // or the time budget stops it, the retire stays: an accepted partial reclaim (the tombstone is durable, and Phase 1
          // of a later bytes-pressure call acknowledges it). The append budget can stop it only when no bytes need is open.
          if (!canAppend()) break phases;
          const acked = await attempt(key, () => ackManagedPreflightPayloadDeletionInTransaction({
            preflightId: key, expectedRevision: retired.value.preflight.revision, acquisitionId, mode,
          }));
          if (acked.ok) { counts.acked += 1; needBytes -= candidate.bytesRelief; }
        }
      }
    } catch {
      counts.failed += 1;
    } finally {
      if (Object.values(counts).some((value) => value > 0)) {
        emitPreflightMaintenanceLine(`preflight-reclaim released=${counts.released} sealed=${counts.sealed} disposed=${counts.disposed} retired=${counts.retired} acked=${counts.acked} failed=${counts.failed} (counts only)`);
      }
    }
  }

  return Object.freeze({
    async inspectProcessOwner() {
      const snapshot = await mutate(async () => currentOwner === null || currentOwner.state === 'RELEASED'
        ? null : { owner: clone(currentOwner), ageMs: ownerAgeMs() });
      if (snapshot === null) return { state: 'NONE' };
      const alive = isProcessAlive(snapshot.owner.pid);
      let startedMs;
      if (alive) {
        try { startedMs = await processStartTimeMs(snapshot.owner.pid); } catch { startedMs = null; }
        if (!Number.isFinite(startedMs) || startedMs <= 0) {
          throw ownershipUnavailableError({ label: 'owner inspection', acquireTimeoutMs: 0,
            lastAttempt: { reason: 'LIVE_OWNER', owner: snapshot.owner, ownerAgeMs: snapshot.ageMs } });
        }
      }
      const superseded = alive && await ownerIsSupersededPid(snapshot.owner, snapshot.ageMs, startedMs);
      return mutate(async () => {
        if (currentOwner === null || currentOwner.state !== 'ACQUIRED'
          || ownerKey(currentOwner) !== ownerKey(snapshot.owner)) {
          throw ownershipUnavailableError({ label: 'owner inspection', acquireTimeoutMs: 0,
            lastAttempt: { reason: 'OWNER_CHANGED' } });
        }
        if (!alive || superseded || !isProcessAlive(currentOwner.pid)) return { state: 'NONE' };
        const shared = sharedState.serviceMode?.state === 'ACTIVE'
          && sharedState.serviceMode.activationAcquisitionId === currentOwner.acquisitionId;
        return { state: shared ? 'SHARED_LIVE' : 'LEGACY_LIVE', pid: currentOwner.pid };
      });
    },
    async activateServiceMode({ configFingerprint, buildManifestFingerprint, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId);
        const context = requireManagedExecution();
        requireHash(configFingerprint, 'configFingerprint');
        requireHash(buildManifestFingerprint, 'buildManifestFingerprint');
        if (configFingerprint !== context.configFingerprint || buildManifestFingerprint !== context.buildManifestFingerprint) throw managedError('SERVICE_MODE_MISMATCH');
        const existing = sharedState.serviceMode;
        if (existing?.state === 'ACTIVE') {
          if (existing.configFingerprint === configFingerprint && existing.buildManifestFingerprint === buildManifestFingerprint) return existing;
          throw managedError('SERVICE_MODE_ACTIVE');
        }
        const serviceMode = {
          recordType: 'shared/service-mode', version: 1, state: 'ACTIVE', revision: existing === null ? 1 : existing.revision + 1,
          configFingerprint, buildManifestFingerprint, activationAcquisitionId: acquisitionId,
          replayBarrierId: randomUUID(), replayBarrierCompletedAt: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString(),
        };
        await appendShared('MODE_ACTIVATED', { serviceMode });
        return clone(serviceMode);
      });
    },
    async getServiceMode() {
      return mutate(async () => sharedState.serviceMode);
    },
    async beginManagedReplay({ expectedModeRevision, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId);
        const current = requireActiveServiceMode();
        requireExpectedRevision(current, expectedModeRevision);
        const serviceMode = {
          ...current, revision: current.revision + 1, activationAcquisitionId: acquisitionId,
          replayBarrierId: randomUUID(), replayBarrierCompletedAt: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString(),
        };
        await appendShared('MODE_REPLAY_BARRIER_ADVANCED', { serviceMode });
        return clone(serviceMode);
      });
    },
    async clearServiceMode({ expectedRevision, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId);
        const current = requireActiveServiceMode();
        requireExpectedRevision(current, expectedRevision);
        const state = sharedState.snapshot();
        const blocked = state.staging.some((entry) => entry.state === 'RESERVED')
          || state.receipts.some((entry) => entry.state !== 'TERMINAL')
          || state.executionGroups.some((entry) => ['CLAIMED', 'RECOVERY_PENDING'].includes(entry.state))
          || state.managedLeases.some((entry) => entry.state === 'MANAGED_ACTIVE');
        if (blocked) throw managedError('SERVICE_ROLLBACK_BLOCKED');
        const serviceMode = { ...current, state: 'CLEARED', revision: current.revision + 1 };
        await appendShared('MODE_CLEARED', { serviceMode });
        return clone(serviceMode);
      });
    },
    async reserveManagedPreflightCapacity(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId);
        const mode = requireActiveServiceMode();
        const config = managed.installationConfig;
        const reservationId = requireOwnerAcquisitionId(input.reservationId);
        const generation = requirePositiveInteger(input.generation, 'generation');
        requireId(input.bindingId, 'bindingId'); requireId(input.projectId, 'projectId'); requirePositiveInteger(input.policyEpoch, 'policyEpoch'); requireHash(input.scopeDigest, 'scopeDigest');
        requireConfiguredManagedScope(input.bindingId, input.projectId, input.policyEpoch);
        const maxEncryptedBytes = Number(input.maxEncryptedBytes);
        const requiredReservation = maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: config.storage.maxSinglePreflightPlaintextBytes });
        if (maxEncryptedBytes !== requiredReservation) throw managedError('REQUEST_BYTES_FULL');
        const expiresAt = strictDeadline(input.expiresAt);
        const prior = sharedState.getPreflightReservation(reservationId);
        if (prior !== null) throw managedError('STAGING_STALE');
        let capacity = sharedState.snapshot().capacity;
        const pressure = preflightCapacityNeed(capacity, maxEncryptedBytes);
        if (pressure.needCount > 0 || pressure.needBytes > 0) {
          // Only when one of the two checks below would refuse. The helper never throws; the original refusals then run in
          // their original order on a fresh reading.
          await reclaimPreflightCapacityUnderPressure({ acquisitionId: input.acquisitionId, mode, capacity, maxEncryptedBytes });
          capacity = sharedState.snapshot().capacity;
        }
        if (capacity.livePreflightCount >= config.storage.maxLivePreflights) throw managedError('REQUEST_CAPACITY_FULL');
        if (capacity.preflightEncryptedBytes + maxEncryptedBytes > config.storage.maxPreflightEncryptedBytes) throw managedError('REQUEST_BYTES_FULL');
        const preflightReservation = {
          recordType: 'shared/preflight-reservation', version: 1, reservationId, generation, revision: 1,
          state: 'RESERVED', bindingId: input.bindingId, projectId: input.projectId, policyEpoch: input.policyEpoch,
          scopeDigest: input.scopeDigest, maxEncryptedBytes, retainedEncryptedBytes: maxEncryptedBytes, expiresAt,
          createdAt: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString(),
          ownerAcquisitionId: input.acquisitionId, replayBarrierId: mode.replayBarrierId,
        };
        await appendShared('MANAGED_PREFLIGHT_RESERVED', { preflightReservation });
        return clone(preflightReservation);
      });
    },
    async commitManagedPreflight(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId);
        const mode = requireActiveServiceMode();
        const reservation = sharedState.getPreflightReservation(requireOwnerAcquisitionId(input.reservationId));
        if (reservation === null || reservation.state !== 'RESERVED' || reservation.generation !== input.generation
          || reservation.ownerAcquisitionId !== input.acquisitionId || reservation.replayBarrierId !== mode.replayBarrierId) throw managedError('STAGING_STALE');
        strictDeadline(reservation.expiresAt);
        requireObject(input.preflight, 'preflight'); requireObject(input.managedIdentity, 'managedIdentity');
        canonicalJson(input.preflight); canonicalJson(input.managedIdentity); canonicalJson(input.contextRef); canonicalJson(input.mappingRef);
        const contextRef = clone(input.contextRef); const mappingRef = clone(input.mappingRef);
        if (canonicalJson(contextRef) !== canonicalJson(input.managedIdentity.contextRef)
          || canonicalJson(mappingRef) !== canonicalJson(input.managedIdentity.mappingRef)) throw managedError('PROTECTED_CONTENT_INVALID');
        const exactEncryptedBytes = Number(input.exactEncryptedBytes);
        if (!Number.isSafeInteger(exactEncryptedBytes) || exactEncryptedBytes < 0 || exactEncryptedBytes > reservation.maxEncryptedBytes
          || exactEncryptedBytes !== contextRef.encryptedBytes + mappingRef.encryptedBytes) throw managedError('REQUEST_BYTES_FULL');
        if (input.managedIdentity.bindingId !== reservation.bindingId || input.managedIdentity.projectId !== reservation.projectId
          || input.managedIdentity.policyEpoch !== reservation.policyEpoch || input.managedIdentity.scopeDigest !== reservation.scopeDigest) throw managedError('SERVICE_MODE_MISMATCH');
        managed.storageProofs.verifyPublished({ kind: 'preflight', target: { reservationId: reservation.reservationId, generation: reservation.generation }, refs: [contextRef, mappingRef] });
        const preflight = {
          recordType: 'preflight', version: 1, revision: 1,
          id: requireOwnerAcquisitionId(input.preflight.id), state: 'PREFLIGHTED',
          reviewContractSha256: requireHash(input.preflight.reviewContractSha256, 'reviewContractSha256'),
          sourceSha256: requireHash(input.preflight.sourceSha256, 'sourceSha256'), rawSourceSha256: requireHash(input.preflight.rawSourceSha256, 'rawSourceSha256'),
          profile: requireId(input.preflight.profile, 'profile'), profileVersion: requireId(input.preflight.profileVersion, 'profileVersion'),
          schemaSha256: requireHash(input.preflight.schemaSha256, 'schemaSha256'), registrySha256: requireHash(input.preflight.registrySha256, 'registrySha256'),
          itemMaxima: normalizeItemMaxima(input.preflight.itemMaxima), requestedUsd: requireUsd(input.preflight.requestedUsd, 'requestedUsd'),
          expiresAt: strictDeadline(input.preflight.expiresAt),
        };
        const managedIdentity = clone(input.managedIdentity);
        requireHash(managedIdentity.snapshotSourceId, 'snapshotSourceId'); requireHash(managedIdentity.snapshotContextId, 'snapshotContextId'); requireHash(managedIdentity.mappingIdentity, 'mappingIdentity'); requireId(managedIdentity.identityKeyVersion, 'identityKeyVersion');
        if (managedIdentity.identityKeyVersion !== managed.installationConfig.protectedReferences.identityKeyVersion
          || preflight.registrySha256 !== managed.installationConfig.review.registrySha256
          || preflight.schemaSha256 !== managed.installationConfig.review.advisorySchemaSha256
          || !managed.installationConfig.review.allowedProfiles.some((entry) => entry.profileId === preflight.profile && entry.profileVersion === preflight.profileVersion)
          || Date.parse(preflight.expiresAt) > Date.parse(reservation.expiresAt)
          || preflight.requestedUsd > maxItemUsd(preflight.itemMaxima)) throw managedError('SERVICE_MODE_MISMATCH');
        const preflightReservation = { ...reservation, revision: reservation.revision + 1, state: 'COMMITTED', exactEncryptedBytes, retainedEncryptedBytes: exactEncryptedBytes };
        await appendShared('MANAGED_PREFLIGHT_COMMITTED', { preflightReservation, preflight, managedIdentity });
        return clone(preflight);
      });
    },
    async releaseManagedPreflightReservation({ reservationId, generation, reason, acquisitionId } = {}) {
      const released = await mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const current = sharedState.getPreflightReservation(requireOwnerAcquisitionId(reservationId));
        if (current === null || current.state !== 'RESERVED' || current.generation !== generation
          || current.ownerAcquisitionId !== acquisitionId || current.replayBarrierId !== mode.replayBarrierId) throw managedError('STAGING_STALE');
        if (!['PREPARE_FAILED', 'EXPIRED', 'RESTART', 'ABANDONED'].includes(reason)) throw new TypeError('invalid release reason');
        const preflightReservation = { ...current, state: 'RELEASED', revision: current.revision + 1, releaseReason: reason };
        await appendShared('MANAGED_PREFLIGHT_RESERVATION_RELEASED', { preflightReservation });
        return clone(preflightReservation);
      });
      // Seal and acknowledge only after the release's own transaction has ended, and only for these two reasons: the
      // refund never seals or acknowledges an EXPIRED or ABANDONED release, which keeps its charge. Never throws: a failure
      // leaves the reservation charged.
      if (reason === 'PREPARE_FAILED' || reason === 'RESTART') await refundReleasedPreflightReservation({ reservationId, generation, acquisitionId });
      return released;
    },
    async createManagedLease(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const preflight = sharedState.getManagedPreflight(requireOwnerAcquisitionId(input.preflightId));
        const identity = sharedState.getManagedIdentity(input.preflightId);
        if (preflight === null || identity === null || sharedState.snapshot().preflightTombstones.some((entry) => entry.preflightId === input.preflightId)) throw managedError('FRESH_PREFLIGHT_REQUIRED');
        requireConfiguredManagedScope(input.bindingId, input.projectId, input.policyEpoch);
        if (identity.bindingId !== input.bindingId || identity.scopeDigest !== input.scopeDigest || identity.projectId !== input.projectId || identity.policyEpoch !== input.policyEpoch) throw managedError('SERVICE_MODE_MISMATCH');
        const expiresAt = strictDeadline(input.expiresAt);
        if (Date.parse(expiresAt) > Date.parse(preflight.expiresAt)) throw new RangeError('lease expiry exceeds preflight expiry');
        const requestedUsd = requireUsd(input.requestedUsd, 'requestedUsd');
        if (requestedUsd > preflight.requestedUsd) throw new RangeError('requestedUsd exceeds preflight cap');
        const lease = {
          recordType: 'lease', version: 1, revision: 1, id: randomUUID(), state: 'MANAGED_ACTIVE', preflightIds: [preflight.id],
          reviewContractSha256: preflight.reviewContractSha256, sourceSha256: preflight.sourceSha256, profile: preflight.profile,
          profileVersion: preflight.profileVersion, schemaSha256: preflight.schemaSha256, registrySha256: preflight.registrySha256,
          requestedUsd, maxJobs: requirePositiveInteger(input.maxJobs, 'maxJobs'), jobsConsumed: 0, reservedUsd: 0, spentUsd: 0, expiresAt,
          managedBinding: { bindingId: input.bindingId, scopeDigest: input.scopeDigest, projectId: input.projectId, policyEpoch: input.policyEpoch },
        };
        await appendShared('MANAGED_LEASE_CREATED', { lease });
        return clone(lease);
      });
    },
    async disposeUnadmittedManagedLease({ leaseId, expectedRevision, reason, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); requireActiveServiceMode();
        return disposeUnadmittedManagedLeaseInTransaction({ leaseId, expectedRevision, reason });
      });
    },
    async reserveStagingPermit(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId);
        const mode = requireActiveServiceMode();
        const lease = requireManagedLease(input.leaseId);
        if (lease.managedBinding.bindingId !== input.bindingId || lease.managedBinding.scopeDigest !== input.scopeDigest) throw managedError('LEASE_REQUEST_CONFLICT');
        const stagingId = requireOwnerAcquisitionId(input.stagingId);
        const generation = requirePositiveInteger(input.generation, 'generation');
        const keyDigest = requireHash(input.keyDigest, 'keyDigest');
        const inputDigest = requireHash(input.inputDigest, 'inputDigest');
        const effectiveDeadline = strictDeadline(input.effectiveDeadline);
        if (Date.parse(effectiveDeadline) > Date.parse(lease.expiresAt)) throw managedError('REQUEST_EXPIRED');
        const existingAssociation = sharedState.getKeyAssociation({ bindingId: input.bindingId, scopeDigest: input.scopeDigest, leaseId: lease.id, keyDigest });
        if (existingAssociation !== null) {
          if (existingAssociation.inputDigest !== inputDigest) throw managedError('IDEMPOTENCY_CONFLICT');
          const existingStaging = sharedState.snapshot().staging.findLast((entry) => entry.leaseId === lease.id && entry.inputDigest === inputDigest);
          if (existingStaging?.state === 'COMMITTED') return clone(existingStaging);
          if (existingStaging?.state === 'RESERVED') {
            if (existingStaging.ownerAcquisitionId === input.acquisitionId && existingStaging.replayBarrierId === mode.replayBarrierId
              && Date.parse(existingStaging.effectiveDeadline) > Math.max(Number(clock()), lastRecordTime + 1)) return clone(existingStaging);
            throw managedError('STAGING_STALE');
          }
        }
        const leaseAssociations = sharedState.snapshot().keyAssociations.filter((entry) => entry.leaseId === lease.id);
        if (leaseAssociations.length > 0 && leaseAssociations.some((entry) => entry.inputDigest !== inputDigest)) throw managedError('LEASE_REQUEST_CONFLICT');
        if (leaseAssociations.length >= managed.installationConfig.queue.maxIdempotencyKeysPerLease) throw managedError('LEASE_REQUEST_CONFLICT');
        if (sharedState.getStaging(stagingId) !== null) throw managedError('STAGING_STALE');
        const maxEncryptedBytes = Number(input.maxEncryptedBytes);
        const profile = managed.installationConfig.review.allowedProfiles.find((entry) => entry.profileId === lease.profile && entry.profileVersion === lease.profileVersion);
        if (profile === undefined) throw managedError('SERVICE_MODE_MISMATCH');
        const requiredReservation = maximumPreparedEncryptedBytes({
          reviewerCount: largestAllowedReviewerCount(profile),
          maxRequestBytes: managed.installationConfig.engine.maxRequestBytes,
        });
        if (!Number.isSafeInteger(maxEncryptedBytes) || maxEncryptedBytes !== requiredReservation) throw managedError('REQUEST_BYTES_FULL');
        const capacity = sharedState.snapshot().capacity;
        if (capacity.unfinishedCount >= managed.installationConfig.queue.maxUnfinishedCount) throw managedError('REQUEST_CAPACITY_FULL');
        if (capacity.unfinishedEncryptedBytes + maxEncryptedBytes > managed.installationConfig.queue.maxUnfinishedEncryptedBytes) throw managedError('REQUEST_BYTES_FULL');
        const staging = {
          recordType: 'shared/staging', version: 1, stagingId, generation, state: 'RESERVED', revision: 1,
          bindingId: input.bindingId, scopeDigest: input.scopeDigest, leaseId: lease.id, keyDigest, inputDigest,
          maxEncryptedBytes, effectiveDeadline, createdAt: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString(), ownerAcquisitionId: input.acquisitionId, replayBarrierId: mode.replayBarrierId,
        };
        const keyAssociation = existingAssociation ?? {
          recordType: 'shared/idempotency-key', version: 1, revision: 1, bindingId: input.bindingId,
          scopeDigest: input.scopeDigest, leaseId: lease.id, keyDigest, inputDigest, target: { leaseId: lease.id, inputDigest },
        };
        await appendShared('STAGING_RESERVED', { staging, keyAssociation });
        return clone(staging);
      });
    },
    async associateManagedIdempotencyKey(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const lease = requireManagedLease(input.leaseId);
        if (lease.managedBinding.bindingId !== input.bindingId || lease.managedBinding.scopeDigest !== input.scopeDigest) throw managedError('LEASE_REQUEST_CONFLICT');
        const keyDigest = requireHash(input.keyDigest, 'keyDigest'); const inputDigest = requireHash(input.inputDigest, 'inputDigest');
        const existing = sharedState.getKeyAssociation({ bindingId: input.bindingId, scopeDigest: input.scopeDigest, leaseId: lease.id, keyDigest });
        if (existing !== null) {
          if (existing.inputDigest !== inputDigest) throw managedError('LEASE_REQUEST_CONFLICT');
          const receipt = sharedState.getReceiptByLease(lease.id);
          return clone({ target: existing.target, ...(receipt === null ? {} : { receiptId: receipt.receiptId }), created: false });
        }
        const associations = sharedState.snapshot().keyAssociations.filter((entry) => entry.leaseId === lease.id);
        if (associations.length === 0 || associations.some((entry) => entry.inputDigest !== inputDigest)
          || associations.length >= managed.installationConfig.queue.maxIdempotencyKeysPerLease) throw managedError('LEASE_REQUEST_CONFLICT');
        const keyAssociation = { recordType: 'shared/idempotency-key', version: 1, revision: 1, bindingId: input.bindingId, scopeDigest: input.scopeDigest, leaseId: lease.id, keyDigest, inputDigest, target: { leaseId: lease.id, inputDigest } };
        await appendShared('IDEMPOTENCY_KEY_ASSOCIATED', { keyAssociation });
        const receipt = sharedState.getReceiptByLease(lease.id);
        return clone({ target: keyAssociation.target, ...(receipt === null ? {} : { receiptId: receipt.receiptId }), created: true });
      });
    },
    async commitStagedReceipt(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId);
        const mode = requireActiveServiceMode();
        const current = sharedState.getStaging(requireOwnerAcquisitionId(input.stagingId));
        if (current?.state === 'COMMITTED') {
          const existing = sharedState.getReceiptByLease(current.leaseId);
          if (existing !== null && existing.receiptId === input.receipt?.receiptId && canonicalJson(existing.preparedPayload) === canonicalJson(input.preparedPayload)) return clone(existing);
        }
        if (current === null || current.state !== 'RESERVED' || current.generation !== input.generation
          || current.ownerAcquisitionId !== input.acquisitionId || current.replayBarrierId !== mode.replayBarrierId) throw managedError('STAGING_STALE');
        strictDeadline(current.effectiveDeadline);
        requireObject(input.receipt, 'receipt'); requireObject(input.executionGroup, 'executionGroup');
        canonicalJson(input.receipt); canonicalJson(input.executionGroup); canonicalJson(input.mappingPins);
        if (['executionGroupId', 'claimId', 'startedAt', 'cancellationRequested', 'terminal', 'retiredPreparedPayloadAudit', 'payloadRetired'].some((name) => Object.hasOwn(input.receipt, name))) throw managedError('LEASE_REQUEST_CONFLICT');
        if (canonicalJson(input.preparedPayload) !== canonicalJson(input.receipt.preparedPayload)) throw managedError('PROTECTED_CONTENT_INVALID');
        const exactEncryptedBytes = Number(input.exactEncryptedBytes);
        if (!Number.isSafeInteger(exactEncryptedBytes) || exactEncryptedBytes < 0 || exactEncryptedBytes > current.maxEncryptedBytes) throw managedError('REQUEST_BYTES_FULL');
        // Request objects must be published before the envelope can bind their refs.
        const refs = [...input.preparedPayload.requestRefs, input.preparedPayload.envelopeRef];
        if (refs.reduce((sum, ref) => sum + ref.encryptedBytes, 0) !== exactEncryptedBytes) throw managedError('REQUEST_BYTES_FULL');
        managed.storageProofs.verifyPublished({ kind: 'prepared', target: { stagingId: current.stagingId, generation: current.generation }, refs });
        const leaseCurrent = requireManagedLease(current.leaseId);
        const identity = sharedState.getManagedIdentity(input.receipt.preflightId);
        if (identity === null || !Array.isArray(input.mappingPins) || input.mappingPins.length === 0
          || input.mappingPins.some((pin) => pin.preflightId !== input.receipt.preflightId || pin.mappingIdentity !== identity.mappingIdentity)) throw managedError('MAPPING_PIN_MISSING');
        if (input.receipt.leaseId !== current.leaseId || input.receipt.bindingId !== current.bindingId || input.receipt.scopeDigest !== current.scopeDigest
          || input.receipt.keyDigest !== current.keyDigest || input.receipt.inputDigest !== current.inputDigest) throw managedError('LEASE_REQUEST_CONFLICT');
        if (canonicalJson(input.mappingPins) !== canonicalJson(input.receipt.mappingPins)) throw managedError('MAPPING_PIN_MISSING');
        if (input.executionGroup.executionFingerprint !== input.receipt.executionFingerprint
          || input.executionGroup.scopeDigest !== input.receipt.scopeDigest
          || canonicalJson(input.executionGroup.reviewerIds) !== canonicalJson(input.receipt.reviewerIds)) throw managedError('LEASE_REQUEST_CONFLICT');
        const matchingGroup = sharedState.snapshot().executionGroups.find((candidate) => candidate.state !== 'TERMINAL'
          && candidate.executionFingerprint === input.receipt.executionFingerprint
          && candidate.scopeDigest === input.receipt.scopeDigest
          && canonicalJson(candidate.reviewerIds) === canonicalJson(input.receipt.reviewerIds)
          && candidate.orderedReceiptIds.length < managed.installationConfig.queue.maxUnfinishedCount);
        const receipt = {
          ...clone(input.receipt),
          state: matchingGroup === undefined ? 'QUEUED' : 'WAITING',
          executionGroupId: matchingGroup?.executionGroupId ?? input.executionGroup.executionGroupId,
        };
        const executionGroup = matchingGroup === undefined
          ? {
            ...clone(input.executionGroup),
            revision: 1,
            state: 'OPEN',
            orderedReceiptIds: [receipt.receiptId],
          }
          : {
            ...matchingGroup,
            revision: matchingGroup.revision + 1,
            orderedReceiptIds: [...matchingGroup.orderedReceiptIds, receipt.receiptId],
          };
        const staging = { ...current, state: 'COMMITTED', revision: current.revision + 1 };
        const lease = {
          ...leaseCurrent, revision: leaseCurrent.revision + 1,
          managedBinding: { ...leaseCurrent.managedBinding, receiptId: receipt.receiptId, executionFingerprint: receipt.executionFingerprint },
        };
        await appendShared('RECEIPT_ADMITTED', { staging, receipt, executionGroup, lease, mappingPins: clone(input.mappingPins) });
        return clone(receipt);
      });
    },
    async releaseStagingPermit({ stagingId, generation, reason, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const current = sharedState.getStaging(requireOwnerAcquisitionId(stagingId));
        if (current === null || current.state !== 'RESERVED' || current.generation !== generation
          || current.ownerAcquisitionId !== acquisitionId || current.replayBarrierId !== mode.replayBarrierId) throw managedError('STAGING_STALE');
        if (!['PREPARE_FAILED', 'EXPIRED', 'RESTART'].includes(reason)) throw new TypeError('invalid staging release reason');
        const staging = { ...current, state: 'RELEASED', revision: current.revision + 1, releaseReason: reason };
        await appendShared('STAGING_RELEASED', { staging });
        return clone(staging);
      });
    },
    async getStagingPermit({ stagingId, generation, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const current = sharedState.getStaging(requireOwnerAcquisitionId(stagingId));
        if (current === null || current.state !== 'RESERVED' || current.generation !== generation
          || current.ownerAcquisitionId !== acquisitionId || current.replayBarrierId !== mode.replayBarrierId) throw managedError('STAGING_STALE');
        strictDeadline(current.effectiveDeadline);
        return clone(current);
      });
    },
    async recoverStagingPermits({ acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const releasedStagingIds = [];
        for (const current of sharedState.snapshot().staging) {
          if (current.state !== 'RESERVED') continue;
          if (current.ownerAcquisitionId === acquisitionId && current.replayBarrierId === mode.replayBarrierId && Date.parse(current.effectiveDeadline) > Math.max(Number(clock()), lastRecordTime + 1)) continue;
          const staging = { ...current, state: 'RELEASED', revision: current.revision + 1, releaseReason: current.ownerAcquisitionId === acquisitionId ? 'EXPIRED' : 'RESTART' };
          await appendShared('STAGING_RELEASED', { staging });
          releasedStagingIds.push(staging.stagingId);
        }
        return { releasedStagingIds };
      });
    },
    async getReceipt({ receiptId, bindingId, scopeDigest } = {}) {
      return mutate(async () => {
        const receipt = requireReceiptAccess(receiptId, bindingId, scopeDigest);
        return receipt === null ? null : clone(receipt);
      });
    },
    async findReceiptByIdempotency({ bindingId, scopeDigest, leaseId, keyDigest } = {}) {
      return mutate(async () => {
        if (typeof bindingId !== 'string' || bindingId.length === 0 || typeof scopeDigest !== 'string' || !HASH.test(scopeDigest)
          || typeof leaseId !== 'string' || !OWNER_ACQUISITION_ID.test(leaseId) || typeof keyDigest !== 'string' || !HASH.test(keyDigest)) return null;
        const association = sharedState.getKeyAssociation({ bindingId, scopeDigest, leaseId, keyDigest });
        if (association === null) return null;
        const receipt = requireReceiptAccess(sharedState.getReceiptByLease(leaseId)?.receiptId, bindingId, scopeDigest);
        return receipt === null || receipt.inputDigest !== association.inputDigest ? null : clone(receipt);
      });
    },
    async assertReceiptInputDigest({ receiptId, inputDigest } = {}) {
      return mutate(async () => {
        const receipt = sharedState.getReceipt(requireOwnerAcquisitionId(receiptId));
        if (receipt === null) throw managedError('RECEIPT_NOT_FOUND');
        if (receipt.inputDigest !== requireHash(inputDigest, 'inputDigest')) throw managedError('IDEMPOTENCY_CONFLICT');
      });
    },
    async findReceiptForManagedLease({ leaseId, bindingId, scopeDigest } = {}) {
      return mutate(async () => {
        if (typeof leaseId !== 'string' || !OWNER_ACQUISITION_ID.test(leaseId)) return null;
        const receipt = sharedState.getReceiptByLease(leaseId);
        return receipt === null || receipt.bindingId !== bindingId || receipt.scopeDigest !== scopeDigest ? null : clone(receipt);
      });
    },
    async listManagedReceipts() { return mutate(async () => clone(sharedState.snapshot().receipts)); },
    async claimEligibleReceipt(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId);
        requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null) throw managedError('REQUEST_NOT_ELIGIBLE');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        const now = Math.max(Number(clock()), lastRecordTime + 1);
        const oldestEligibleReceiptId = groupCurrent.orderedReceiptIds.find((candidateId) => {
          const candidate = sharedState.getReceipt(candidateId);
          const lease = candidate === null ? undefined : leases.get(candidate.leaseId);
          return candidate !== null && ['QUEUED', 'WAITING'].includes(candidate.state)
            && Date.parse(candidate.effectiveDeadline) > now && lease?.state === 'MANAGED_ACTIVE';
        });
        if (!['QUEUED', 'WAITING'].includes(receiptCurrent.state) || groupCurrent.state !== 'OPEN' || oldestEligibleReceiptId !== receiptCurrent.receiptId) throw managedError('REQUEST_NOT_ELIGIBLE');
        strictDeadline(receiptCurrent.effectiveDeadline);
        const claimId = requireOwnerAcquisitionId(input.claimId);
        requireObject(input.permit, 'permit');
        const descriptor = managed.executionPermits.assertLive({
          receiptId: receiptCurrent.receiptId, claimId, token: input.permit.token,
          reviewerIds: receiptCurrent.reviewerIds, ownerGeneration: currentOwner.generation,
        });
        if (descriptor.permitTokenDigest !== input.permit.permitTokenDigest || descriptor.permitSetRevision !== input.permit.permitSetRevision
          || descriptor.activeBatchUnits !== 1 || canonicalJson(descriptor.reviewerIds) !== canonicalJson(input.permit.reviewerIds)) throw managedError('CLAIM_CONFLICT');
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, state: 'EXECUTING', executionGroupId: groupCurrent.executionGroupId, claimId };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1, state: 'CLAIMED', leaderReceiptId: receipt.receiptId, claimId, claimRevision: 1, permit: clone(descriptor) };
        await appendShared('RECEIPT_CLAIMED', { receipt, executionGroup });
        return clone({ receipt, executionGroup });
      });
    },
    async consumeManaged(leaseId, reviewContractSha256, input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const leaseCurrent = requireManagedLease(leaseId);
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId
          || receiptCurrent.leaseId !== leaseCurrent.id || receiptCurrent.executionFingerprint !== leaseCurrent.managedBinding.executionFingerprint
          || receiptCurrent.scopeDigest !== leaseCurrent.managedBinding.scopeDigest) throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedReceiptRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (receiptCurrent.cancellationRequested === true) throw managedError('REQUEST_CANCELLED');
        if (receiptCurrent.startedAt === undefined) strictDeadline(receiptCurrent.effectiveDeadline);
        assertTimestampNotExpired(leaseCurrent.expiresAt, Math.max(Number(clock()), lastRecordTime + 1), 'lease');
        const contractHash = requireHash(reviewContractSha256, 'reviewContractSha256');
        if (leaseCurrent.reviewContractSha256 !== contractHash) throw new Error('lease contract does not match');
        if (typeof input.countsTowardDailyAllowance !== 'boolean') throw new TypeError('countsTowardDailyAllowance must be boolean');
        const reviewerId = requireId(input.reviewerId, 'reviewerId');
        if (!receiptCurrent.reviewerIds.includes(reviewerId)
          || [...jobs.values()].some((job) => job.version === 1 && job.receiptId === receiptCurrent.receiptId && job.reviewerId === reviewerId)) throw managedError('REQUEST_NOT_ELIGIBLE');
        const reservationUsd = requireUsd(input.reservationUsd, 'reservationUsd');
        if (leaseCurrent.jobsConsumed >= leaseCurrent.maxJobs) throw new RangeError('lease job cap exceeded');
        if (leaseCurrent.reservedUsd + leaseCurrent.spentUsd + reservationUsd > leaseCurrent.requestedUsd) throw new RangeError('lease cap exceeded');
        if (input.countsTowardDailyAllowance) {
          const today = utcDayKey(new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString());
          if ((paidJobsByUtcDay.get(today) ?? 0) >= managed.installationConfig.engine.dailyPaidJobAllowance) throw new RangeError(`daily dispatch allowance exhausted for ${today}`);
        }
        const id = requireHash(input.jobId, 'jobId');
        if (jobs.has(id)) throw new Error('job ID already exists');
        const job = {
          recordType: 'job', version: 1, revision: 1, id, leaseId: leaseCurrent.id, state: 'RESERVED', reservationUsd,
          costUsd: 0, paid: input.countsTowardDailyAllowance, reviewContractSha256: contractHash,
          reviewerId, receiptId: receiptCurrent.receiptId, claimId: input.claimId,
          executionFingerprint: receiptCurrent.executionFingerprint, scopeDigest: receiptCurrent.scopeDigest, intentState: 'NONE',
        };
        const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1, jobsConsumed: leaseCurrent.jobsConsumed + 1, reservedUsd: leaseCurrent.reservedUsd + reservationUsd };
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1 };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        await appendShared('MANAGED_CONSUMED', { receipt, executionGroup, job, lease });
        return completeManagedResult(receipt, executionGroup, job, lease);
      });
    },
    async transitionIntentPending(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        if (!isPlainObject(input.ownerToken) || input.ownerToken.acquisitionId !== input.acquisitionId || Object.keys(input.ownerToken).length !== 1) throw managedError('CLAIM_NOT_OWNER');
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        const jobCurrent = jobs.get(requireHash(input.jobId, 'jobId'));
        if (receiptCurrent === null || groupCurrent === null || jobCurrent === undefined || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId || jobCurrent.claimId !== input.claimId) throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedReceiptRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision); requireExpectedRevision(jobCurrent, input.expectedJobRevision);
        if (jobCurrent.state !== 'RESERVED' || jobCurrent.intentState !== 'NONE') throw managedError('INTENT_ALREADY_COMMITTED');
        if (receiptCurrent.cancellationRequested === true) throw managedError('REQUEST_CANCELLED');
        if (receiptCurrent.startedAt === undefined) strictDeadline(receiptCurrent.effectiveDeadline);
        const leaseCurrent = requireManagedLease(jobCurrent.leaseId);
        assertTimestampNotExpired(leaseCurrent.expiresAt, Math.max(Number(clock()), lastRecordTime + 1), 'lease');
        const descriptor = managed.executionPermits.assertLive({ receiptId: receiptCurrent.receiptId, claimId: input.claimId, token: input.token, reviewerIds: receiptCurrent.reviewerIds, ownerGeneration: currentOwner.generation });
        if (groupCurrent.permit?.permitTokenDigest !== descriptor.permitTokenDigest || groupCurrent.permit?.permitSetRevision !== descriptor.permitSetRevision) throw managedError('CLAIM_CONFLICT');
        const startedAt = receiptCurrent.startedAt ?? new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString();
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, startedAt };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1, startedAt: groupCurrent.startedAt ?? startedAt };
        const job = { ...jobCurrent, revision: jobCurrent.revision + 1, state: 'INTENT_PENDING', intentState: 'INTENT_PENDING' };
        const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1 };
        await appendShared('MANAGED_INTENT_PENDING', { receipt, executionGroup, job, lease });
        return completeManagedResult(receipt, executionGroup, job, lease);
      });
    },
    async verifyManagedDispatchIntent(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        canonicalJson(input);
        if (!isPlainObject(input.ownerToken) || input.ownerToken.acquisitionId !== input.acquisitionId || Object.keys(input.ownerToken).length !== 1) throw managedError('CLAIM_NOT_OWNER');
        const receipt = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const executionGroup = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        const job = jobs.get(requireHash(input.jobId, 'jobId'));
        const reviewerId = requireId(input.reviewerId, 'reviewerId');
        const claimId = requireOwnerAcquisitionId(input.claimId);
        if (receipt === null || executionGroup === null || job?.version !== 1
          || receipt.claimId !== claimId || executionGroup.claimId !== claimId || job.claimId !== claimId
          || !['CLAIMED', 'RECOVERY_PENDING'].includes(executionGroup.state)
          || executionGroup.leaderReceiptId !== receipt.receiptId || job.receiptId !== receipt.receiptId
          || receipt.executionGroupId !== executionGroup.executionGroupId
          || receipt.executionFingerprint !== executionGroup.executionFingerprint || receipt.scopeDigest !== executionGroup.scopeDigest
          || canonicalJson(receipt.reviewerIds) !== canonicalJson(executionGroup.reviewerIds)
          || job.state !== 'INTENT_PENDING' || job.intentState !== 'INTENT_PENDING' || job.reviewerId !== reviewerId) throw managedError('CLAIM_NOT_OWNER');
        const lease = leases.get(job.leaseId);
        if (lease?.version !== 1 || lease.state !== 'MANAGED_ACTIVE'
          || receipt.leaseId !== job.leaseId
          || job.executionFingerprint !== receipt.executionFingerprint || job.scopeDigest !== receipt.scopeDigest
          || lease.managedBinding.receiptId !== receipt.receiptId
          || lease.managedBinding.executionFingerprint !== receipt.executionFingerprint
          || lease.managedBinding.bindingId !== receipt.bindingId || lease.managedBinding.scopeDigest !== receipt.scopeDigest
          || lease.managedBinding.projectId !== receipt.projectId || lease.managedBinding.policyEpoch !== receipt.policyEpoch) throw managedError('MANAGED_LEASE_REQUIRED');
        const notAfterMs = input.notAfterMs;
        if (typeof notAfterMs !== 'number' || !Number.isSafeInteger(notAfterMs) || notAfterMs !== Date.parse(lease.expiresAt)
          || Math.max(Number(clock()), lastRecordTime + 1) >= notAfterMs) throw managedError('REQUEST_EXPIRED');
        canonicalJson(input.requestRef);
        const requestIndex = receipt.reviewerIds.indexOf(reviewerId);
        if (requestIndex < 0 || receipt.preparedPayload === undefined
          || canonicalJson(receipt.preparedPayload.requestRefs[requestIndex]) !== canonicalJson(input.requestRef)) throw managedError('PROTECTED_CONTENT_INVALID');
        if (!isPlainObject(input.intent)) throw new TypeError('intent must be a plain object');
        const intentKeys = ['version', 'receiptId', 'claimId', 'jobId', 'leaseId', 'reviewerId', 'executionFingerprint', 'scopeDigest', 'intentState'];
        if (Object.keys(input.intent).length !== intentKeys.length || intentKeys.some((key) => !Object.hasOwn(input.intent, key))) throw new TypeError('intent has an invalid shape');
        const expectedIntent = {
          version: 1,
          receiptId: receipt.receiptId,
          claimId,
          jobId: job.id,
          leaseId: lease.id,
          reviewerId,
          executionFingerprint: receipt.executionFingerprint,
          scopeDigest: receipt.scopeDigest,
          intentState: 'INTENT_PENDING',
        };
        if (canonicalJson(input.intent) !== canonicalJson(expectedIntent)) throw managedError('CLAIM_CONFLICT');
        const descriptor = managed.executionPermits.assertLive({
          receiptId: receipt.receiptId,
          claimId,
          token: input.token,
          reviewerIds: receipt.reviewerIds,
          ownerGeneration: currentOwner.generation,
        });
        if (executionGroup.permit?.permitTokenDigest !== descriptor.permitTokenDigest
          || executionGroup.permit?.permitSetRevision !== descriptor.permitSetRevision
          || executionGroup.permit?.activeBatchUnits !== descriptor.activeBatchUnits
          || canonicalJson(executionGroup.permit?.reviewerIds) !== canonicalJson(descriptor.reviewerIds)) throw managedError('CLAIM_CONFLICT');
        return Object.freeze({
          intentDigest: createHash('sha256').update(canonicalJson(expectedIntent), 'utf8').digest('hex'),
          notAfterMs,
        });
      });
    },
    async releaseCancellableReservation(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        const jobCurrent = jobs.get(requireHash(input.jobId, 'jobId'));
        if (receiptCurrent === null || groupCurrent === null || jobCurrent === undefined || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId || jobCurrent.claimId !== input.claimId) throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedReceiptRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision); requireExpectedRevision(jobCurrent, input.expectedJobRevision);
        if (jobCurrent.state !== 'RESERVED' || jobCurrent.intentState !== 'NONE') throw managedError('RESERVATION_NOT_CANCELLABLE');
        if (!['CANCELLED', 'EXPIRED', 'CLAIM_RETIRED'].includes(input.reason)) throw new TypeError('invalid cancellation reason');
        const leaseCurrent = leases.get(jobCurrent.leaseId);
        const { costUsd: _costUsd, costKind: _costKind, haltReason: _haltReason, managedHealthEffects: _effects, ...jobBase } = jobCurrent;
        const job = { ...jobBase, revision: jobCurrent.revision + 1, state: 'CANCELLED_ZERO_DISPATCH', cancellationReason: input.reason };
        const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1, reservedUsd: releaseReservedUsd(leaseCurrent.reservedUsd, jobCurrent.reservationUsd) };
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1 };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        await appendShared('MANAGED_RESERVATION_CANCELLED', { receipt, executionGroup, job, lease });
        return completeManagedResult(receipt, executionGroup, job, lease);
      });
    },
    async reconcileManaged(jobId, input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const jobCurrent = jobs.get(requireHash(jobId, 'jobId'));
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (jobCurrent === undefined || receiptCurrent === null || groupCurrent === null || jobCurrent.claimId !== input.claimId || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId) throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(jobCurrent, input.expectedJobRevision); requireExpectedRevision(receiptCurrent, input.expectedReceiptRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (!['RESERVED', 'INTENT_PENDING'].includes(jobCurrent.state)) throw new Error('job is not reconcilable');
        const { cost: costUsd, aboveReservationField } = checkedReconcileCost({ costUsd: input.costUsd, costKind: input.costKind, aboveReservation: input.aboveReservation, reservationUsd: jobCurrent.reservationUsd });
        const leaseCurrent = leases.get(jobCurrent.leaseId);
        const job = { ...jobCurrent, revision: jobCurrent.revision + 1, state: 'RECONCILED', intentState: jobCurrent.intentState, costUsd, costKind: requireCostKind(input.costKind), ...(input.haltReason === undefined ? {} : { haltReason: requireHaltReason(input.haltReason) }), ...aboveReservationField };
        const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1, reservedUsd: releaseReservedUsd(leaseCurrent.reservedUsd, jobCurrent.reservationUsd), spentUsd: leaseCurrent.spentUsd + costUsd };
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1 };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        await appendShared('MANAGED_RECONCILED', { receipt, executionGroup, job, lease });
        return completeManagedResult(receipt, executionGroup, job, lease);
      });
    },
    async ackReleasedPreflightReservationPayloadDeletion({ reservationId, generation, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        return ackReleasedPreflightReservationPayloadDeletionInTransaction({ reservationId, generation, acquisitionId, mode });
      });
    },
    async recoverManagedPreflightReservations({ acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const releasedReservationIds = [];
        for (const current of sharedState.snapshot().preflightReservations) {
          if (current.state !== 'RESERVED') continue;
          if (current.ownerAcquisitionId === acquisitionId && current.replayBarrierId === mode.replayBarrierId && Date.parse(current.expiresAt) > Math.max(Number(clock()), lastRecordTime + 1)) continue;
          const preflightReservation = { ...current, state: 'RELEASED', revision: current.revision + 1, releaseReason: current.ownerAcquisitionId === acquisitionId ? 'EXPIRED' : 'RESTART' };
          await appendShared('MANAGED_PREFLIGHT_RESERVATION_RELEASED', { preflightReservation });
          releasedReservationIds.push(preflightReservation.reservationId);
        }
        return { releasedReservationIds };
      });
    },
    async retireManagedPreflight({ preflightId, expectedRevision, reason, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); requireActiveServiceMode();
        return retireManagedPreflightInTransaction({ preflightId, expectedRevision, reason });
      });
    },
    async ackManagedPreflightPayloadDeletion({ preflightId, expectedRevision, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        return ackManagedPreflightPayloadDeletionInTransaction({ preflightId, expectedRevision, acquisitionId, mode });
      });
    },
    async getManagedPreflightForPreparation(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId);
        requireActiveServiceMode();
        const preflightId = requireOwnerAcquisitionId(input.preflightId);
        const preflight = sharedState.getManagedPreflight(preflightId);
        const managedIdentity = sharedState.getManagedIdentity(preflightId);
        const retired = sharedState.snapshot().preflightTombstones.some((entry) => entry.preflightId === preflightId);
        if (preflight === null || preflight.state !== 'PREFLIGHTED' || managedIdentity === null || retired) {
          throw managedError('FRESH_PREFLIGHT_REQUIRED');
        }
        const lease = requireManagedLease(requireOwnerAcquisitionId(input.leaseId));
        if (lease.preflightIds.length !== 1 || lease.preflightIds[0] !== preflightId
          || lease.managedBinding.bindingId !== managedIdentity.bindingId
          || lease.managedBinding.projectId !== managedIdentity.projectId
          || lease.managedBinding.policyEpoch !== managedIdentity.policyEpoch
          || lease.managedBinding.scopeDigest !== managedIdentity.scopeDigest) {
          throw managedError('LEASE_REQUEST_CONFLICT');
        }
        const now = Number(clock());
        if (Date.parse(preflight.expiresAt) <= now || Date.parse(lease.expiresAt) <= now) {
          throw managedError('REQUEST_EXPIRED');
        }
        return clone({ preflight, managedIdentity, lease });
      });
    },
    async lookupManagedIdentity({ selector, bindingId } = {}) {
      return mutate(async () => {
        if (typeof bindingId !== 'string' || bindingId.length === 0 || !isPlainObject(selector)) return null;
        try { canonicalJson(selector); } catch { return null; }
        if (Object.keys(selector).length === 0 || Object.keys(selector).length > 2) return null;
        let preflightId;
        let receipt = null;
        let lease = null;
        let association = null;
        let selectorKind;
        if (Object.hasOwn(selector, 'preflightId') && Object.keys(selector).length === 1 && OWNER_ACQUISITION_ID.test(selector.preflightId)) {
          selectorKind = 'preflight';
          preflightId = selector.preflightId;
        } else if (Object.hasOwn(selector, 'receiptId') && Object.keys(selector).length === 1 && OWNER_ACQUISITION_ID.test(selector.receiptId)) {
          selectorKind = 'receipt';
          receipt = sharedState.getReceipt(selector.receiptId);
          preflightId = receipt?.preflightId;
        }
        else if (Object.hasOwn(selector, 'leaseId')) {
          if (!OWNER_ACQUISITION_ID.test(selector.leaseId)) return null;
          selectorKind = 'lease';
          lease = leases.get(selector.leaseId);
          if (lease?.version !== 1 || (Object.keys(selector).length === 2 && !Object.hasOwn(selector, 'keyDigest'))) return null;
          if (Object.hasOwn(selector, 'keyDigest')) {
            if (typeof selector.keyDigest !== 'string' || !HASH.test(selector.keyDigest)) return null;
            association = sharedState.getKeyAssociation({ bindingId, scopeDigest: lease.managedBinding.scopeDigest, leaseId: lease.id, keyDigest: selector.keyDigest });
            if (association === null) return null;
          }
          [preflightId] = lease.preflightIds;
        } else return null;
        const identity = sharedState.getManagedIdentity(preflightId);
        if (identity === null || identity.bindingId !== bindingId) return null;
        const retired = sharedState.snapshot().preflightTombstones.some((entry) => entry.preflightId === preflightId);
        if (retired) {
          if (selectorKind === 'preflight') return null;
          lease ??= receipt === null ? null : leases.get(receipt.leaseId);
          receipt ??= lease === null || lease === undefined ? null : sharedState.getReceiptByLease(lease.id);
          const preflight = sharedState.getManagedPreflight(preflightId);
          if (preflight === null || preflight.state !== 'PREFLIGHTED'
            || lease?.version !== 1 || lease.state === 'MANAGED_ACTIVE'
            || receipt === null || receipt.state !== 'TERMINAL'
            || lease.preflightIds.length !== 1 || lease.preflightIds[0] !== preflightId
            || receipt.preflightId !== preflightId || receipt.leaseId !== lease.id
            || lease.managedBinding.receiptId !== receipt.receiptId
            || lease.managedBinding.executionFingerprint !== receipt.executionFingerprint
            || lease.reviewContractSha256 !== preflight.reviewContractSha256
            || lease.sourceSha256 !== preflight.sourceSha256
            || lease.profile !== preflight.profile || lease.profileVersion !== preflight.profileVersion
            || lease.schemaSha256 !== preflight.schemaSha256 || lease.registrySha256 !== preflight.registrySha256
            || receipt.reviewContractSha256 !== preflight.reviewContractSha256
            || receipt.bindingId !== identity.bindingId || receipt.projectId !== identity.projectId
            || receipt.policyEpoch !== identity.policyEpoch || receipt.scopeDigest !== identity.scopeDigest
            || receipt.snapshotSourceId !== identity.snapshotSourceId || receipt.snapshotContextId !== identity.snapshotContextId
            || lease.managedBinding.bindingId !== identity.bindingId || lease.managedBinding.projectId !== identity.projectId
            || lease.managedBinding.policyEpoch !== identity.policyEpoch || lease.managedBinding.scopeDigest !== identity.scopeDigest
            || !receipt.mappingPins.some((pin) => pin.preflightId === preflightId && pin.mappingIdentity === identity.mappingIdentity)) return null;
          const associationMatchesReceipt = (candidate, keyDigest) => candidate !== null
            && candidate.bindingId === identity.bindingId && candidate.scopeDigest === identity.scopeDigest
            && candidate.leaseId === lease.id && candidate.keyDigest === keyDigest
            && candidate.inputDigest === receipt.inputDigest
            && candidate.target.leaseId === lease.id && candidate.target.inputDigest === receipt.inputDigest;
          const primaryAssociation = sharedState.getKeyAssociation({
            bindingId: identity.bindingId,
            scopeDigest: identity.scopeDigest,
            leaseId: lease.id,
            keyDigest: receipt.keyDigest,
          });
          if (!associationMatchesReceipt(primaryAssociation, receipt.keyDigest)
            || (association !== null && !associationMatchesReceipt(association, selector.keyDigest))) return null;
        }
        return clone({ projectId: identity.projectId, policyEpoch: identity.policyEpoch, scopeDigest: identity.scopeDigest });
      });
    },
    async rebindManagedExecutionPermit(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId || groupCurrent.state !== 'CLAIMED') throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedReceiptRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        const descriptor = managed.executionPermits.assertLive({ receiptId: receiptCurrent.receiptId, claimId: input.claimId, token: input.permit?.token, reviewerIds: groupCurrent.reviewerIds, ownerGeneration: currentOwner.generation });
        if (canonicalJson(descriptor.reviewerIds) !== canonicalJson(groupCurrent.reviewerIds)
          || descriptor.permitTokenDigest !== input.permit.permitTokenDigest || descriptor.permitSetRevision !== input.permit.permitSetRevision) throw managedError('CLAIM_CONFLICT');
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1 };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1, permit: clone(descriptor) };
        await appendShared('MANAGED_EXECUTION_PERMIT_REBOUND', { receipt, executionGroup });
        return clone(executionGroup);
      });
    },
    async requestManagedCancellation(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        const claimId = requireOwnerAcquisitionId(input.claimId);
        if (receiptCurrent === null || groupCurrent === null
          || receiptCurrent.executionGroupId !== groupCurrent.executionGroupId
          || groupCurrent.leaderReceiptId !== receiptCurrent.receiptId
          || receiptCurrent.claimId !== claimId || groupCurrent.claimId !== claimId
          || groupCurrent.state !== 'CLAIMED') throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (receiptCurrent.terminalPublication !== undefined) throw managedError('REQUEST_NOT_ELIGIBLE');
        if (receiptCurrent.state === 'TERMINAL') return clone(receiptCurrent);
        if (!['EXECUTING', 'RECOVERY_PENDING'].includes(receiptCurrent.state)) throw managedError('REQUEST_NOT_ELIGIBLE');
        if (receiptCurrent.cancellationRequested === true) return clone(receiptCurrent);
        const leaseCurrent = leases.get(receiptCurrent.leaseId);
        if (leaseCurrent?.version !== 1 || leaseCurrent.state !== 'MANAGED_ACTIVE'
          || leaseCurrent.managedBinding.receiptId !== receiptCurrent.receiptId
          || leaseCurrent.managedBinding.executionFingerprint !== receiptCurrent.executionFingerprint) throw managedError('MANAGED_LEASE_REQUIRED');
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, cancellationRequested: true };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1 };
        await appendShared('MANAGED_CANCEL_REQUESTED', { receipt, executionGroup, lease });
        return clone(receipt);
      });
    },
    async markManagedRecoveryPending(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        const claimId = requireOwnerAcquisitionId(input.claimId);
        if (receiptCurrent === null || groupCurrent === null
          || receiptCurrent.executionGroupId !== groupCurrent.executionGroupId
          || groupCurrent.leaderReceiptId !== receiptCurrent.receiptId
          || receiptCurrent.claimId !== claimId || groupCurrent.claimId !== claimId
          || groupCurrent.state !== 'CLAIMED') throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (receiptCurrent.state === 'RECOVERY_PENDING') return clone({ receipt: receiptCurrent, executionGroup: groupCurrent });
        if (receiptCurrent.state !== 'EXECUTING') throw managedError('REQUEST_NOT_ELIGIBLE');
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, state: 'RECOVERY_PENDING' };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        await appendShared('MANAGED_RECOVERY_PENDING', { receipt, executionGroup });
        return clone({ receipt, executionGroup });
      });
    },
    async beginTerminalPublication(input = {}) {
      requireExactObject(input, ['receiptId', 'expectedReceiptRevision', 'executionGroupId', 'expectedGroupRevision', 'claimId', 'publicationId', 'completedAt', 'outcomeKind', 'leaseDisposition', 'settledStatus', 'advisoryAssociations', 'acquisitionId'], ['outcomeErrorCode']);
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        const claimId = requireOwnerAcquisitionId(input.claimId);
        const leaseCurrent = requireTerminalClaim(receiptCurrent, groupCurrent, claimId);
        const terminalPublication = clone({
          version: 1, publicationId: requireOwnerAcquisitionId(input.publicationId), claimId,
          completedAt: input.completedAt, outcomeKind: input.outcomeKind,
          ...(input.outcomeErrorCode === undefined ? {} : { outcomeErrorCode: input.outcomeErrorCode }),
          leaseDisposition: input.leaseDisposition, settledStatus: input.settledStatus, advisoryAssociations: input.advisoryAssociations,
        });
        if (receiptCurrent.terminalPublication !== undefined) {
          if (canonicalJson(receiptCurrent.terminalPublication) !== canonicalJson(terminalPublication)
            || receiptCurrent.revision !== input.expectedReceiptRevision + 1 || groupCurrent.revision !== input.expectedGroupRevision + 1) throw managedError('REQUEST_REVISION_CONFLICT');
          return clone({ receipt: receiptCurrent, executionGroup: groupCurrent, terminalPublication });
        }
        requireExpectedRevision(receiptCurrent, input.expectedReceiptRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, terminalPublication };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1 };
        sharedState.validate({ recordType: 'shared/transition', version: 1, kind: 'TERMINAL_PUBLICATION_BEGUN', receipt, executionGroup, lease,
          timestamp: new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString() });
        terminalAssociatedJobs(receiptCurrent, groupCurrent, terminalPublication);
        for (const association of terminalPublication.advisoryAssociations) {
          if (association.contentAvailable && await managed.storageProofs.verifyAdvisoryPublication({
            receiptId: association.sourceReceiptId, jobId: association.jobId, advisoryRef: clone(association.advisoryRef),
          }) !== true) throw managedError('PROTECTED_CONTENT_INVALID');
        }
        await appendShared('TERMINAL_PUBLICATION_BEGUN', { receipt, executionGroup, lease });
        return clone({ receipt, executionGroup, terminalPublication });
      });
    },
    async getTerminalPublicationForAccess(input = {}) {
      requireExactObject(input, ['receiptId', 'publicationId', 'acquisitionId']);
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receipt = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const publicationId = requireOwnerAcquisitionId(input.publicationId);
        const executionGroup = receipt === null ? null : sharedState.getExecutionGroup(receipt.executionGroupId);
        const terminalPublication = receipt?.terminalPublication;
        if (terminalPublication === undefined || terminalPublication.publicationId !== publicationId) throw managedError('CLAIM_NOT_OWNER');
        const lease = requireTerminalClaim(receipt, executionGroup, terminalPublication.claimId);
        const associatedJobs = terminalAssociatedJobs(receipt, executionGroup, terminalPublication);
        return deepFreeze(clone({ claimId: terminalPublication.claimId, terminalPublication, receipt, lease, associatedJobs }));
      });
    },
    async terminalizeTerminalPublicationAsContentLost(input = {}) {
      return finalizeTerminalPublication(input, true);
    },
    async requestPostIntentCancellation(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId) throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (receiptCurrent.terminalPublication !== undefined) throw managedError('REQUEST_NOT_ELIGIBLE');
        const jobsForReceipt = [...jobs.values()].filter((job) => job.version === 1 && job.receiptId === receiptCurrent.receiptId);
        if (!jobsForReceipt.some((job) => job.state === 'INTENT_PENDING' || job.state === 'RECONCILED')) throw managedError('RESERVATION_NOT_CANCELLABLE');
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, cancellationRequested: true };
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1 };
        const lease = { ...leases.get(receipt.leaseId), revision: leases.get(receipt.leaseId).revision + 1 };
        await appendShared('POST_INTENT_CANCEL_REQUESTED', { receipt, executionGroup, lease });
        return clone(receipt);
      });
    },
    async cancelQueuedReceipt(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null || receiptCurrent.state === 'TERMINAL') throw managedError('RECEIPT_NOT_FOUND');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (!['QUEUED', 'WAITING'].includes(receiptCurrent.state) || [...jobs.values()].some((job) => job.version === 1 && job.receiptId === receiptCurrent.receiptId && ['RESERVED', 'INTENT_PENDING'].includes(job.state))) throw managedError('RESERVATION_NOT_CANCELLABLE');
        const completedAt = new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString();
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, state: 'TERMINAL', terminal: { kind: 'CANCELLED', errorCode: 'REQUEST_CANCELLED', completedAt } };
        const allOthersTerminal = groupCurrent.orderedReceiptIds.filter((id) => id !== receipt.receiptId).every((id) => sharedState.getReceipt(id)?.state === 'TERMINAL');
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1, ...(allOthersTerminal ? { state: 'TERMINAL', terminalAt: completedAt } : {}) };
        const leaseCurrent = leases.get(receipt.leaseId); const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1, state: 'CANCELLED' };
        await appendShared('RECEIPT_TERMINALIZED', { receipt, executionGroup, lease });
        return clone(receipt);
      });
    },
    async expireUnstartedReceipt(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null || !['QUEUED', 'WAITING'].includes(receiptCurrent.state)) throw managedError('RECEIPT_NOT_FOUND');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (receiptCurrent.startedAt !== undefined || [...jobs.values()].some((job) => job.version === 1 && job.receiptId === receiptCurrent.receiptId && ['RESERVED', 'INTENT_PENDING'].includes(job.state))) throw managedError('REQUEST_NOT_ELIGIBLE');
        const completedAt = new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString();
        const receipt = { ...receiptCurrent, revision: receiptCurrent.revision + 1, state: 'TERMINAL', terminal: { kind: 'EXPIRED', errorCode: 'REQUEST_EXPIRED', completedAt } };
        const allOthersTerminal = groupCurrent.orderedReceiptIds.filter((id) => id !== receipt.receiptId).every((id) => sharedState.getReceipt(id)?.state === 'TERMINAL');
        const executionGroup = { ...groupCurrent, revision: groupCurrent.revision + 1, ...(allOthersTerminal ? { state: 'TERMINAL', terminalAt: completedAt } : {}) };
        const leaseCurrent = leases.get(receipt.leaseId); const lease = { ...leaseCurrent, revision: leaseCurrent.revision + 1, state: 'EXPIRED' };
        await appendShared('RECEIPT_TERMINALIZED', { receipt, executionGroup, lease });
        return clone(receipt);
      });
    },
    async terminalizeReceipt(input = {}) {
      return finalizeTerminalPublication(input, false);
    },
    async retireManagedClaim(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const receiptCurrent = sharedState.getReceipt(requireOwnerAcquisitionId(input.receiptId));
        const groupCurrent = sharedState.getExecutionGroup(requireOwnerAcquisitionId(input.executionGroupId));
        if (receiptCurrent === null || groupCurrent === null || receiptCurrent.claimId !== input.claimId || groupCurrent.claimId !== input.claimId) throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(receiptCurrent, input.expectedRevision); requireExpectedRevision(groupCurrent, input.expectedGroupRevision);
        if (receiptCurrent.terminalPublication !== undefined) throw managedError('REQUEST_NOT_ELIGIBLE');
        const receiptJobs = [...jobs.values()].filter((job) => job.version === 1 && job.receiptId === receiptCurrent.receiptId);
        if (receiptJobs.some((job) => ['RESERVED', 'INTENT_PENDING'].includes(job.state))) throw managedError('RESERVATION_NOT_CANCELLABLE');
        if (receiptJobs.some((job) => job.state === 'RECONCILED' && !['CLAIMED', 'RECORDED'].includes(job.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME?.state))) throw managedError('REQUEST_NOT_ELIGIBLE');
        if (!['TERMINALIZED', 'NO_INTENT_RETRY'].includes(input.reason)) throw new TypeError('invalid claim retirement reason');
        if (input.reason === 'TERMINALIZED') {
          const lease = leases.get(receiptCurrent.leaseId);
          if (receiptCurrent.state !== 'TERMINAL' || lease?.state === 'MANAGED_ACTIVE') throw managedError('REQUEST_NOT_ELIGIBLE');
        } else {
          const lease = leases.get(receiptCurrent.leaseId);
          if (receiptCurrent.state === 'TERMINAL' || receiptCurrent.startedAt !== undefined || receiptCurrent.cancellationRequested === true
            || lease?.state !== 'MANAGED_ACTIVE' || receiptJobs.some((job) => job.intentState === 'INTENT_PENDING')) throw managedError('REQUEST_NOT_ELIGIBLE');
          strictDeadline(receiptCurrent.effectiveDeadline);
        }
        const { claimId: _receiptClaim, ...receiptBase } = receiptCurrent;
        const receipt = { ...receiptBase, revision: receiptCurrent.revision + 1, state: input.reason === 'TERMINALIZED' ? 'TERMINAL' : 'WAITING' };
        const { claimId: _groupClaim, leaderReceiptId: _leader, permit: _permit, claimRevision: _claimRevision, ...groupBase } = groupCurrent;
        const allTerminal = groupCurrent.orderedReceiptIds.every((id) => id === receipt.receiptId || sharedState.getReceipt(id)?.state === 'TERMINAL');
        const completedAt = receipt.terminal?.completedAt ?? new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString();
        const { terminalAt: _oldTerminalAt, ...openableGroup } = groupBase;
        const executionGroup = {
          ...openableGroup,
          revision: groupCurrent.revision + 1,
          state: allTerminal ? 'TERMINAL' : 'OPEN',
          ...(allTerminal ? { terminalAt: completedAt } : {}),
        };
        await appendShared('CLAIM_RETIRED', { receipt, executionGroup });
        return clone(receipt);
      });
    },
    async closeManagedLease({ leaseId, receiptId, expectedRevision, state, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); requireActiveServiceMode();
        const current = requireManagedLease(leaseId);
        requireExpectedRevision(current, expectedRevision);
        const receipt = sharedState.getReceipt(requireOwnerAcquisitionId(receiptId));
        if (receipt === null || receipt.leaseId !== current.id) throw managedError('RECEIPT_NOT_FOUND');
        if ([...jobs.values()].some((job) => job.version === 1 && job.leaseId === current.id && ['RESERVED', 'INTENT_PENDING'].includes(job.state))) throw managedError('RESERVATION_NOT_CANCELLABLE');
        if (!['CANCELLED', 'EXPIRED', 'CLOSED', 'LEASE_EXPIRED', 'DUPLICATE_DISPATCH_IN_PROGRESS', 'PROVIDER_MISMATCH', 'STRICT_OUTPUT_INVALID', 'UNKNOWN_COST', 'TRANSPORT_FAILURE', 'DISPATCH_UNKNOWN', 'ORPHANED_ON_RECOVERY'].includes(state)) throw new TypeError('invalid managed lease disposition');
        const lease = { ...current, revision: current.revision + 1, state };
        await appendShared('MANAGED_LEASE_DISPOSED', { lease });
        return clone(lease);
      });
    },
    async claimManagedHealthEffect(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const current = jobs.get(requireHash(input.jobId, 'jobId'));
        if (current?.version !== 1 || current.claimId !== input.claimId || current.state !== 'RECONCILED') throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(current, input.expectedJobRevision);
        if (input.effectKind !== 'DISPATCH_HEALTH_OUTCOME') throw new TypeError('invalid managed health effect');
        if (current.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME !== undefined) throw managedError('CLAIM_CONFLICT');
        const job = { ...current, revision: current.revision + 1, managedHealthEffects: { DISPATCH_HEALTH_OUTCOME: { effectId: requireOwnerAcquisitionId(input.effectId), state: 'CLAIMED', claimId: input.claimId } } };
        await appendShared('HEALTH_EFFECT_CLAIMED', { job });
        return clone(job);
      });
    },
    async recordManagedHealthEffect(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input.acquisitionId); requireActiveServiceMode();
        const current = jobs.get(requireHash(input.jobId, 'jobId'));
        if (current?.version !== 1 || current.claimId !== input.claimId || input.effectKind !== 'DISPATCH_HEALTH_OUTCOME') throw managedError('CLAIM_NOT_OWNER');
        requireExpectedRevision(current, input.expectedJobRevision);
        const effect = current.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME;
        if (effect?.state !== 'CLAIMED' || effect.effectId !== input.effectId || effect.claimId !== input.claimId) throw managedError('CLAIM_CONFLICT');
        const job = { ...current, revision: current.revision + 1, managedHealthEffects: { DISPATCH_HEALTH_OUTCOME: { ...effect, state: 'RECORDED' } } };
        await appendShared('HEALTH_EFFECT_RECORDED', { job });
        return clone(job);
      });
    },
    async findManagedReusableJobs({ executionFingerprint, scopeDigest, reviewerId } = {}) {
      return mutate(async () => clone([...jobs.values()].filter((job) => job.version === 1 && job.state === 'RECONCILED'
        && job.executionFingerprint === requireHash(executionFingerprint, 'executionFingerprint')
        && job.scopeDigest === requireHash(scopeDigest, 'scopeDigest') && job.reviewerId === requireId(reviewerId, 'reviewerId'))));
    },
    async listPinnedMappings() {
      return mutate(async () => {
        const grouped = new Map();
        const snapshot = sharedState.snapshot();
        const retiredPreflightIds = new Set(snapshot.preflightTombstones.map((entry) => entry.preflightId));
        for (const [preflightId, identity] of snapshot.managedIdentities) {
          if (!retiredPreflightIds.has(preflightId)) grouped.set(`${preflightId}:${identity.mappingIdentity}`, { preflightId, mappingIdentity: identity.mappingIdentity, receiptIds: [] });
        }
        for (const receipt of snapshot.receipts) {
          const group = receipt.executionGroupId === undefined ? null : sharedState.getExecutionGroup(receipt.executionGroupId);
          const lease = leases.get(receipt.leaseId);
          if (receipt.state === 'TERMINAL' && !['CLAIMED', 'RECOVERY_PENDING'].includes(group?.state) && lease?.state !== 'MANAGED_ACTIVE') continue;
          for (const pin of receipt.mappingPins) {
            const key = `${pin.preflightId}:${pin.mappingIdentity}`;
            const entry = grouped.get(key) ?? { preflightId: pin.preflightId, mappingIdentity: pin.mappingIdentity, receiptIds: [] };
            entry.receiptIds.push(receipt.receiptId); grouped.set(key, entry);
          }
        }
        return clone([...grouped.values()]);
      });
    },
    async recoverManagedReceipt({ receiptId, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); requireActiveServiceMode();
        const receipt = sharedState.getReceipt(requireOwnerAcquisitionId(receiptId));
        if (receipt === null) throw managedError('RECEIPT_NOT_FOUND');
        const executionGroup = receipt.executionGroupId === undefined ? null : sharedState.getExecutionGroup(receipt.executionGroupId);
        const lease = leases.get(receipt.leaseId);
        const managedJobs = [...jobs.values()].filter((job) => job.version === 1 && job.receiptId === receipt.receiptId);
        const preflight = sharedState.getManagedPreflight(receipt.preflightId);
        const identity = sharedState.getManagedIdentity(receipt.preflightId);
        if (preflight === null || identity === null || lease?.version !== 1
          || lease.preflightIds.length !== 1 || lease.preflightIds[0] !== receipt.preflightId
          || lease.managedBinding.receiptId !== receipt.receiptId
          || lease.reviewContractSha256 !== receipt.reviewContractSha256
          || preflight.reviewContractSha256 !== receipt.reviewContractSha256
          || identity.bindingId !== receipt.bindingId || identity.projectId !== receipt.projectId
          || identity.policyEpoch !== receipt.policyEpoch || identity.scopeDigest !== receipt.scopeDigest) {
          throw managedError('PROTECTED_CONTENT_INVALID');
        }
        const retired = sharedState.snapshot().preflightTombstones.some((entry) => entry.preflightId === receipt.preflightId);
        const pinned = receipt.mappingPins.some((pin) => pin.preflightId === receipt.preflightId
          && pin.mappingIdentity === identity.mappingIdentity);
        const mapping = retired || !pinned ? null : {
          preflightId: receipt.preflightId, mappingIdentity: identity.mappingIdentity,
          mappingRef: identity.mappingRef, identityKeyVersion: identity.identityKeyVersion,
        };
        return clone({ receipt, executionGroup, jobs: managedJobs, lease, preflight, mapping });
      });
    },
    async retireManagedPayload({ receiptId, expectedRevision, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); requireActiveServiceMode();
        const current = sharedState.getReceipt(requireOwnerAcquisitionId(receiptId));
        if (current === null || current.state !== 'TERMINAL' || current.preparedPayload === undefined) throw managedError('REQUEST_NOT_ELIGIBLE');
        requireExpectedRevision(current, expectedRevision);
        const group = current.executionGroupId === undefined ? null : sharedState.getExecutionGroup(current.executionGroupId);
        if (group !== null && ['CLAIMED', 'RECOVERY_PENDING'].includes(group.state)) throw managedError('REQUEST_NOT_ELIGIBLE');
        const retiredAt = new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString();
        const retiredPreparedPayloadAudit = { ...clone(current.preparedPayload), retiredAt };
        const { preparedPayload: _prepared, ...base } = current;
        const receipt = { ...base, revision: current.revision + 1, retiredPreparedPayloadAudit, payloadRetired: true };
        const tombstone = { version: 1, receiptId: current.receiptId, retiredPreparedPayloadAudit, revision: receipt.revision };
        await appendShared('PAYLOAD_RETIRED', { receipt, tombstone });
        return clone({ receipt, tombstone });
      });
    },
    async sweepRetiredManagedPayloads({ acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        const deletedReceiptIds = [];
        for (const receipt of sharedState.snapshot().receipts) {
          if (receipt.state !== 'TERMINAL' || receipt.payloadRetired !== true || receipt.retiredPreparedPayloadAudit === undefined) continue;
          const origin = sharedState.getReceiptOrigin(receipt.receiptId); if (origin === null) continue;
          const refs = [...receipt.retiredPreparedPayloadAudit.requestRefs, receipt.retiredPreparedPayloadAudit.envelopeRef];
          if (!validProtectedRefs(refs)) throw managedError('PROTECTED_CONTENT_INVALID');
          const before = managed.storageProofs.inspectTarget({ kind: 'prepared', target: origin });
          if (!inspectionMatches(before, refs)) throw managedError('PROTECTED_CONTENT_INVALID');
          const descriptor = { version: 1, kind: 'prepared', target: origin, refs, tombstoneRevision: receipt.revision, acquisitionId, replayBarrierId: mode.replayBarrierId };
          managed.storageProofs.deleteRetired({ descriptor });
          const inspected = managed.storageProofs.inspectTarget({ kind: 'prepared', target: origin });
          if (!inspectionMatches(inspected, refs, { absent: true })) throw managedError('PROTECTED_CONTENT_INVALID');
          deletedReceiptIds.push(receipt.receiptId);
        }
        return { deletedReceiptIds };
      });
    },
    async purgeUnadmittedManagedPayloads({ completedReplayBarrierId, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId); const mode = requireActiveServiceMode();
        if (mode.replayBarrierId !== completedReplayBarrierId) throw managedError('SERVICE_MODE_MISMATCH');
        const deletedObjectIds = [];
        const snapshot = sharedState.snapshot();
        const admittedOrigins = new Set(snapshot.receipts.map((receipt) => canonicalJson(sharedState.getReceiptOrigin(receipt.receiptId))).filter((value) => value !== 'null'));
        const referencedObjectIds = referencedProtectedObjectIds(snapshot);
        const barrierCompletedAtMs = Date.parse(mode.replayBarrierCompletedAt);
        const manifestTargets = managed.storageProofs.listManifestTargets({ beforeReplayBarrierId: completedReplayBarrierId });
        if (!Array.isArray(manifestTargets)) throw managedError('PROTECTED_CONTENT_INVALID');
        for (const target of manifestTargets) {
          try { canonicalJson(target); } catch { continue; }
          if (!isPlainObject(target) || target.kind !== 'prepared' || target.featureFormatVersion !== 1
            || !isPlainObject(target.target) || Object.keys(target.target).length !== 2
            || !Object.hasOwn(target.target, 'stagingId') || !OWNER_ACQUISITION_ID.test(target.target.stagingId)
            || !Object.hasOwn(target.target, 'generation') || !Number.isSafeInteger(target.target.generation) || target.target.generation <= 0
            || typeof target.creationBarrierId !== 'string' || !OWNER_ACQUISITION_ID.test(target.creationBarrierId)
            || typeof target.createdAt !== 'string' || !Number.isFinite(Date.parse(target.createdAt)) || new Date(target.createdAt).toISOString() !== target.createdAt
            || Date.parse(target.createdAt) >= barrierCompletedAtMs || target.creationBarrierId === completedReplayBarrierId
            || !validProtectedRefs(target.refs) || admittedOrigins.has(canonicalJson(target.target))
            || target.refs.some((ref) => referencedObjectIds.has(ref.objectId))) continue;
          const staging = sharedState.getStaging(target.target.stagingId);
          if (staging === null || staging.state !== 'RELEASED' || staging.generation !== target.target.generation
            || staging.replayBarrierId !== target.creationBarrierId || target.createdAt !== staging.createdAt) continue;
          const before = managed.storageProofs.inspectTarget({ kind: 'prepared', target: target.target });
          if (!inspectionMatches(before, target.refs)) throw managedError('PROTECTED_CONTENT_INVALID');
          const descriptor = { version: 1, kind: target.kind, target: target.target, refs: target.refs, tombstoneRevision: staging.revision, acquisitionId, replayBarrierId: mode.replayBarrierId };
          managed.storageProofs.deleteRetired({ descriptor });
          const inspected = managed.storageProofs.inspectTarget({ kind: 'prepared', target: target.target });
          if (!inspectionMatches(inspected, target.refs, { absent: true })) throw managedError('PROTECTED_CONTENT_INVALID');
          deletedObjectIds.push(...target.refs.map((ref) => ref.objectId));
        }
        return { deletedObjectIds };
      });
    },
    async createPreflight(input = {}) {
      return mutate(async () => {
        assertNoForbiddenFields(input); requireObject(input, 'preflight');
        const expiresAt = requireFutureTimestamp(input.expiresAt, 'expiresAt'); assertTimestampNotExpired(expiresAt, Number(clock()), 'preflight');
        const itemMaxima = normalizeItemMaxima(input.itemMaxima); const requestedUsd = requireUsd(input.requestedUsd, 'requestedUsd');
        if (requestedUsd > maxItemUsd(itemMaxima)) throw new RangeError('requestedUsd exceeds preflight cap');
        const id = input.id === undefined ? randomUUID() : requireId(input.id, 'preflight.id'); if (preflights.has(id)) throw new Error('preflight ID already exists');
        // rawSourceSha256 is the hash of the document's RAW content, computed before any scrub
        // substitution ever touches it (source-contract.mjs's sourceFromText/sourceFromPath) --
        // deliberately distinct from sourceSha256 above, which is hashed AFTER scrubbing and
        // therefore differs on every single preflight() call for byte-identical content (scrub
        // placeholders are HMAC-keyed on the fresh preflightId each call mints). This is the one
        // stable "same document" signal the repeat-authorization justification gate can key on --
        // see countLeasesForRawSource below and review-engine.mjs's authorizeWorkflow docstring.
        return clone(await append({ recordType: 'preflight', id, state: 'PREFLIGHTED', reviewContractSha256: requireHash(input.reviewContractSha256, 'reviewContractSha256'), sourceSha256: requireHash(input.sourceSha256, 'sourceSha256'), rawSourceSha256: requireHash(input.rawSourceSha256, 'rawSourceSha256'), profile: requireId(input.profile, 'profile'), profileVersion: requireId(input.profileVersion, 'profileVersion'), schemaSha256: requireHash(input.schemaSha256, 'schemaSha256'), registrySha256: requireHash(input.registrySha256, 'registrySha256'), itemMaxima, requestedUsd, expiresAt }));
      });
    },
    /* Acquires process ownership immediately and returns an already-armed handle. The
       arm-on-demand path is createUnarmedOwnerHandle() below. */
    async acquireProcessOwnership({ acquireTimeoutMs } = {}) {
      if (!Number.isSafeInteger(acquireTimeoutMs) || acquireTimeoutMs <= 0) {
        throw new TypeError('acquireTimeoutMs must be a positive safe integer');
      }
      // The loop itself lives in runOwnershipAttempts(). This caller keeps its fixed lockRetryMs
      // backoff between refused attempts, exactly as before.
      const acquired = await runOwnershipAttempts({
        label: 'acquireProcessOwnership',
        acquireTimeoutMs,
        nextSleepMs: () => lockRetryMs,
        // The legacy path neither checks nor stamps caps.
        caps: undefined,
      });
      return buildOwnerHandle({ armed: acquired });
    },
    // Mints the ownership handle WITHOUT acquiring: state 'unarmed', no I/O and no
    // ledger record. The handle arms on demand, when its first owner-sensitive caller calls arm().
    createUnarmedOwnerHandle() {
      return buildOwnerHandle();
    },
    async createLease(input = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(input?.acquisitionId);
        assertNoForbiddenFields(input); requireObject(input, 'lease');
        if (!Array.isArray(input.preflightIds) || input.preflightIds.length === 0) throw new TypeError('preflightIds must be a non-empty array');
        if (new Set(input.preflightIds).size !== input.preflightIds.length) throw new Error('duplicate preflight IDs are not allowed');
        const selected = input.preflightIds.map((id) => { const preflight = preflights.get(requireId(id, 'preflightIds entry')); if (!preflight) throw new Error(`preflight is missing: ${id}`); assertTimestampNotExpired(preflight.expiresAt, Number(clock()), 'preflight'); return preflight; });
        const first = selected[0]; for (const preflight of selected.slice(1)) if (preflight.reviewContractSha256 !== first.reviewContractSha256 || preflight.sourceSha256 !== first.sourceSha256) throw new Error('preflights do not share a contract and source');
        const expiresAt = requireFutureTimestamp(input.expiresAt, 'expiresAt'); assertTimestampNotExpired(expiresAt, Number(clock()), 'lease');
        if (Date.parse(expiresAt) > Math.min(...selected.map((preflight) => Date.parse(preflight.expiresAt)))) throw new RangeError('lease expiry exceeds preflight expiry');
        const requestedUsd = requireUsd(input.requestedUsd, 'requestedUsd'); if (requestedUsd > selected.reduce((total, preflight) => total + preflight.requestedUsd, 0)) throw new RangeError('requestedUsd exceeds preflight cap');
        const id = input.id === undefined ? randomUUID() : requireId(input.id, 'lease.id'); if (leases.has(id)) throw new Error('lease ID already exists');
        return clone(await append({ recordType: 'lease', id, state: 'ACTIVE', preflightIds: selected.map((preflight) => preflight.id), reviewContractSha256: first.reviewContractSha256, sourceSha256: first.sourceSha256, profile: first.profile, profileVersion: first.profileVersion, schemaSha256: first.schemaSha256, registrySha256: first.registrySha256, requestedUsd, maxJobs: requirePositiveInteger(input.maxJobs, 'maxJobs'), jobsConsumed: 0, reservedUsd: 0, spentUsd: 0, expiresAt }));
      });
    },
    async consume(leaseId, reviewContractSha256, { reservationUsd, jobId = randomUUID(), countsTowardDailyAllowance = false, reviewerId, acquisitionId } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId);
        const current = leases.get(requireId(leaseId, 'leaseId')); if (!current) throw new Error('lease is missing'); if (current.state !== 'ACTIVE') throw new Error('lease is closed'); assertTimestampNotExpired(current.expiresAt, Number(clock()), 'lease');
        const contractHash = requireHash(reviewContractSha256, 'reviewContractSha256');
        if (current.reviewContractSha256 !== contractHash) throw new Error('lease contract does not match');
        const reservation = requireUsd(reservationUsd, 'reservationUsd'); if (current.jobsConsumed >= current.maxJobs) throw new RangeError('lease job cap exceeded'); if (current.reservedUsd + current.spentUsd + reservation > current.requestedUsd) throw new RangeError('lease cap exceeded');
        const paid = countsTowardDailyAllowance === true;
        if (paid) {
          // Deliberately worded WITHOUT the substring "cap": translateConsumeError
          // (review-engine.mjs:70) checks for this message first, ahead of /cap/i,
          // so it isn't swallowed by the generic LEASE_MISSING fallback -- a
          // distinct, differently-actionable condition from a lease cap.
          //
          // The day key MUST be derived from the same monotonic value append()
          // will actually stamp the record with (Math.max(Number(clock()),
          // lastRecordTime + 1)), NOT from a fresh raw clock() read here. A bare
          // clock() read let the guardrail be bypassed entirely: a burst of
          // mutate() calls landing within one clock() tick near UTC midnight lets
          // append()'s monotonic bump roll the PERSISTED (and counted) timestamp
          // into the next day while this check kept reading the old day's
          // now-frozen, sub-limit count -- every call after the first then passed
          // the gate, because paidJobsByUtcDay for the old day never incremented
          // (e.g. 15 of 15 consume() calls admitted against an allowance of 5 when
          // clock() is frozen 5ms before midnight).
          const today = utcDayKey(new Date(Math.max(Number(clock()), lastRecordTime + 1)).toISOString());
          if ((paidJobsByUtcDay.get(today) ?? 0) >= dailyPaidJobAllowance) {
            throw new RangeError(`daily dispatch allowance exhausted for ${today}`);
          }
        }
        const id = requireId(jobId, 'jobId'); if (jobs.has(id)) throw new Error('job ID already exists');
        // reviewContractSha256 and reviewerId (when supplied) are stored on the job record so
        // findJobsForReviewerContract below can look up every job ever created for one exact
        // (contract, reviewer) pair across ALL leases, not just this one -- see that method's own
        // docstring for the cross-lease re-dispatch/re-charge bug this backs the fix for.
        // reviewerId is optional (unlike reviewContractSha256, already a hard-required param above)
        // purely for backward compatibility with existing direct callers of consume() that have no
        // reason to supply it; JSON.stringify drops an `undefined`-valued key automatically, so an
        // omitted reviewerId is simply absent from the persisted ledger record, not a stored null.
        const job = {
          recordType: 'job', id, leaseId: current.id, state: 'RESERVED', reservationUsd: reservation, costUsd: 0, paid,
          reviewContractSha256: contractHash,
          reviewerId: reviewerId === undefined ? undefined : requireId(reviewerId, 'reviewerId'),
        };
        const lease = { ...current, jobsConsumed: current.jobsConsumed + 1, reservedUsd: current.reservedUsd + reservation };
        await append({ recordType: 'transition', state: 'RESERVED', lease, job }); return clone(job);
      });
    },
    // haltReason is optional and, like reviewerId on consume(), omitted (never a stored null) when
    // not supplied -- JSON.stringify drops the undefined key automatically. Present only when this
    // call comes from a genuine halt (haltAndClose, or the dispatch-rejection recovery path);
    // absent for a genuine clean-pass reconcile, whether or not its own later resultStore.record()
    // call actually completes. This is the durable signal review-engine.mjs's cross-lease dedup and
    // same-lease retry recovery both need to tell a real halt (safe to retry) apart from an
    // unexplained content-loss landmine (real money already spent on content that may still exist
    // somewhere and must not be silently re-purchased); see
    // review-engine.mjs's own findReusableAdvisory and existingJob-recovery docstrings.
    async reconcile(jobId, { costUsd, costKind, haltReason, acquisitionId, aboveReservation } = {}) {
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId);
        const currentJob = jobs.get(requireId(jobId, 'jobId')); if (!currentJob) throw new Error('job is missing'); if (currentJob.state !== 'RESERVED') throw new Error('job is not reserved');
        const { cost, aboveReservationField } = checkedReconcileCost({ costUsd, costKind, aboveReservation, reservationUsd: currentJob.reservationUsd }); const currentLease = leases.get(currentJob.leaseId);
        const job = {
          ...currentJob, state: 'RECONCILED', costUsd: cost, costKind: requireCostKind(costKind),
          haltReason: haltReason === undefined ? undefined : requireHaltReason(haltReason),
          ...aboveReservationField,
        };
        const lease = { ...currentLease, reservedUsd: releaseReservedUsd(currentLease.reservedUsd, currentJob.reservationUsd), spentUsd: currentLease.spentUsd + cost };
        await append({ recordType: 'transition', state: 'RECONCILED', lease, job }); return clone(job);
      });
    },
    async close(leaseId, state = 'CLOSED', { acquisitionId } = {}) { return mutate(async () => { assertCurrentlyOwnsProcess(acquisitionId); const current = leases.get(requireId(leaseId, 'leaseId')); if (!current) throw new Error('lease is missing'); if (current.state !== 'ACTIVE') throw new Error('lease is closed'); if (typeof state !== 'string' || !/^[A-Z_]+$/.test(state)) throw new TypeError('state must be an uppercase state'); return clone(await append({ ...current, state })); }); },
    /**
     * Read-only enumeration of every RESERVED job on a stale, still-ACTIVE lease -- the exact same
     * eligibility filter sweepOrphanedLeases() below uses (ACTIVE lease, expired for at least
     * staleAfterMs), but without reconciling or closing anything. Added so a caller
     * (review-engine.mjs) can inspect each job's own durable dispatch-outcome capture BEFORE
     * deciding how to reconcile it, instead of sweepOrphanedLeases()'s own unconditional worst-case
     * charge -- see that function's own docstring for the money-safety bug this exists to let a
     * caller fix (a real, already-completed dispatch being charged its worst-case reservation
     * instead of the real cost OpenRouter actually billed; see review-engine.mjs's
     * recoverStaleLease()). Pass `leaseId` to scope to one lease; omit it to scan the whole store.
     */
    async findStaleReservedJobs({ leaseId, staleAfterMs } = {}) {
      if (!Number.isSafeInteger(staleAfterMs) || staleAfterMs < 0) throw new TypeError('staleAfterMs must be a non-negative safe integer');
      return mutate(async () => {
        const now = Number(clock());
        const candidates = leaseId === undefined
          ? [...leases.values()]
          : [leases.get(requireId(leaseId, 'leaseId'))].filter(Boolean);
        const results = [];
        for (const candidate of candidates) {
          if (candidate.state !== 'ACTIVE') continue;
          if (Date.parse(candidate.expiresAt) + staleAfterMs > now) continue;
          for (const job of jobs.values()) {
            if (job.leaseId === candidate.id && job.state === 'RESERVED') {
              results.push({
                leaseId: candidate.id, jobId: job.id, reviewerId: job.reviewerId, reservationUsd: job.reservationUsd,
              });
            }
          }
        }
        return results;
      });
    },
    /**
     * Recovers a RESERVED job whose real dispatch outcome will never be
     * known -- e.g. the process that reserved it was replaced (crash, host
     * reconnect) before it could ever call reconcile(). consume() re-checks
     * lease expiry, but without this sweep nothing would re-visit a
     * RESERVED job once its owning process was gone -- review()'s own
     * in-loop existingJob check (src/local-mcp/review-engine.mjs) depends
     * on an in-memory preflight cache that a process restart always
     * empties, so a lease could be left permanently ACTIVE with money
     * reserved and no code path left that could ever close it.
     *
     * Reconciles every RESERVED job on an eligible lease at its full
     * `reservationUsd` (the same conservative worst-case charge
     * haltAndClose() already uses for every other unknown-outcome halt in
     * review-engine.mjs) and closes the lease as `ORPHANED_ON_RECOVERY`.
     * A lease is eligible only once it has been expired for at least
     * `staleAfterMs` -- required, no default, so a caller must make a
     * deliberate choice about how much grace to give a dispatch that may
     * still be legitimately finishing (the dispatch adapter's own
     * execFile backstop can fire up to ~30s past a lease's expiresAt in
     * the worst case; the grace window must clear that with real margin
     * to avoid racing a dispatch that is about to reconcile normally).
     * A lease with zero RESERVED jobs is left untouched (nothing to
     * recover), matching review()'s own existing plain-throw behavior for
     * that case. Pass `leaseId` to target one specific lease (used when
     * review() is re-entered for an already-expired lease); omit it to
     * sweep every eligible lease in the store (used by the engine's arm-cycle
     * recovery).
     *
     * Money-safety note: this function's own unconditional
     * worst-case charge is now only the FALLBACK for a job whose real outcome genuinely can't be
     * determined. Neither review-engine.mjs call site invokes this directly any more -- both go
     * through recoverStaleLease() there, which first checks findStaleReservedJobs() above against
     * dispatch-outcome-store.mjs's durable capture and reconciles a real, already-completed
     * dispatch at its ACTUAL OpenRouter cost (via the same processDispatchOutcome() pipeline a
     * live dispatch uses), before ever falling back to calling this function for whatever it
     * couldn't resolve that way. Called directly (as every existing test in this file still does),
     * this function's own worst-case-always behavior is unchanged.
     */
    async sweepOrphanedLeases({ leaseId, staleAfterMs, acquisitionId } = {}) {
      if (!Number.isSafeInteger(staleAfterMs) || staleAfterMs < 0) throw new TypeError('staleAfterMs must be a non-negative safe integer');
      return mutate(async () => {
        assertCurrentlyOwnsProcess(acquisitionId);
        const now = Number(clock());
        const candidates = leaseId === undefined
          ? [...leases.values()]
          : [leases.get(requireId(leaseId, 'leaseId'))].filter(Boolean);
        const results = [];
        for (const candidate of candidates) {
          if (candidate.state !== 'ACTIVE') continue;
          if (Date.parse(candidate.expiresAt) + staleAfterMs > now) continue;
          const reservedJobs = [...jobs.values()].filter((job) => job.leaseId === candidate.id && job.state === 'RESERVED');
          if (reservedJobs.length === 0) continue;
          let lease = candidate;
          const reconciledJobs = [];
          for (const reservedJob of reservedJobs) {
            const cost = reservedJob.reservationUsd;
            const job = { ...reservedJob, state: 'RECONCILED', costUsd: cost, costKind: 'UNKNOWN_WORST_CASE_CHARGED' };
            lease = { ...lease, reservedUsd: releaseReservedUsd(lease.reservedUsd, reservedJob.reservationUsd), spentUsd: lease.spentUsd + cost };
            await append({ recordType: 'transition', state: 'RECONCILED', lease, job });
            reconciledJobs.push(clone(job));
          }
          const closedLease = await append({ ...lease, state: 'ORPHANED_ON_RECOVERY' });
          results.push({ leaseId: candidate.id, lease: clone(closedLease), reconciledJobs });
        }
        return results;
      });
    },
    async renew(leaseId) { await mutate(async () => { const current = leases.get(requireId(leaseId, 'leaseId')); if (!current || current.state !== 'ACTIVE') throw new Error('closed lease cannot be renewed'); throw new Error('leases are non-renewable'); }); },
    async getLease(leaseId) { return mutate(async () => { const current = leases.get(requireId(leaseId, 'leaseId')); return current ? clone(current) : null; }); },
    async getJob(jobId) { return mutate(async () => { const current = jobs.get(requireId(jobId, 'jobId')); return current ? clone(current) : null; }); },
    async getPreflight(preflightId) { return mutate(async () => { const current = preflights.get(requireId(preflightId, 'preflightId')); return current ? clone(current) : null; }); },
    // Backs review-engine.mjs's repeat-authorization justification gate: authorizeWorkflow needs
    // to know, before granting a lease, whether this DOCUMENT (not this one preflight attempt) has
    // already produced a lease. Deliberately keyed on rawSourceSha256, not preflightId: a fresh
    // preflightId is minted on every single preflight() call, even for byte-identical content, so
    // keying on preflightId alone would let a caller trivially reset the count to zero just by
    // re-preflighting the same document (calling preflight() again with the same source_text would
    // get an unjustified lease every time, defeating the entire point of this gate). Finds every
    // preflight ever created that shares this
    // raw-content hash, then counts every lease ever bound to ANY of them, regardless of current
    // lease state (ACTIVE, closed, orphaned) -- the point is bounding how many times authorization
    // was ever granted for this one document, not how many leases happen to still be open, and not
    // how many distinct preflight ATTEMPTS happened to be made for it.
    async countLeasesForRawSource(rawSourceSha256) {
      return mutate(async () => {
        requireHash(rawSourceSha256, 'rawSourceSha256');
        const matchingPreflightIds = new Set();
        for (const preflight of preflights.values()) {
          if (preflight.rawSourceSha256 === rawSourceSha256) matchingPreflightIds.add(preflight.id);
        }
        let count = 0;
        for (const lease of leases.values()) {
          if (lease.preflightIds.some((id) => matchingPreflightIds.has(id))) count += 1;
        }
        return count;
      });
    },
    // Backs the repeat-authorization ledger cross-check (review-engine.mjs's resolveDocumentOutcome).
    // Once authorizeWorkflow knows a document has prior leases (countLeasesForRawSource above), it needs
    // the MOST RECENT one's own outcome, not just the count. Mirrors countLeasesForRawSource's own
    // two-step approach (every preflight sharing this raw hash, then every lease bound to any of
    // them) but returns the lease object itself, only the LAST match. `leases`/`preflights` are
    // Maps populated by replaying the ledger's own append-only JSONL in insertion order and updated
    // in place via .set() on an existing key (consume/reconcile/close all read-modify-write the same
    // lease.id, never .delete()) -- Map iteration order therefore equals ledger append order AND
    // stays stable across later mutations, so the last matching entry in iteration order is, by
    // construction, the most recently CREATED lease, not just the most recently touched one.
    async getMostRecentLeaseForRawSource(rawSourceSha256) {
      return mutate(async () => {
        requireHash(rawSourceSha256, 'rawSourceSha256');
        const matchingPreflightIds = new Set();
        for (const preflight of preflights.values()) {
          if (preflight.rawSourceSha256 === rawSourceSha256) matchingPreflightIds.add(preflight.id);
        }
        let mostRecent = null;
        for (const lease of leases.values()) {
          if (lease.preflightIds.some((id) => matchingPreflightIds.has(id))) mostRecent = lease;
        }
        return mostRecent === null ? null : clone(mostRecent);
      });
    },
    // Backs review-engine.mjs's cross-lease dispatch dedup:
    // re-running authorize_workflow against the same preflightId (e.g. to correct a maxJobs
    // mistake, the exact documented recovery step for a LEASE_CAP_EXCEEDED halt) mints a genuinely
    // NEW lease. review()'s own per-lease jobId (deriveJobId(leaseId, reviewerId,
    // reviewContractSha256)) is scoped to ONE lease by construction, so the existing existingJob
    // check never sees a reviewer already RECONCILED under a DIFFERENT lease for the exact same
    // document -- without this query, that reviewer could be dispatched and charged again. Returns EVERY
    // job ever created (any lease, any state) matching this exact (reviewContractSha256,
    // reviewerId) pair, in ledger/chronological order; the caller decides what a match means (a
    // RECONCILED job carrying real advisory content is safe to reuse for free, a RESERVED one is
    // ambiguous and must not be raced against with a fresh dispatch, and anything else imposes no
    // obstruction) -- this method itself makes no judgment call, matching countLeasesForRawSource's
    // own "the method finds, the caller decides" split immediately above. Modern records carry an
    // explicit reviewerId. Older records legitimately omit it, so they may be included only when
    // their immutable job id proves this exact reviewer under their OWN still-bound lease and first
    // selected preflight. This query stays read-only: it never repairs an old record or guesses from
    // a reviewer-like field on a malformed ledger entry.
    async findJobsForReviewerContract(reviewContractSha256, reviewerId) {
      return mutate(async () => {
        const contractHash = requireHash(reviewContractSha256, 'reviewContractSha256');
        const id = requireId(reviewerId, 'reviewerId');
        const matches = [];
        for (const job of jobs.values()) {
          if (job.reviewContractSha256 !== contractHash) continue;
          // Existing persisted reviewer IDs remain the authority. In particular, do not override a
          // conflicting explicit value merely because a hand-built job id happens to derive to the
          // requested reviewer; that would silently change legacy query semantics.
          if (job.reviewerId === id) {
            matches.push(job);
            continue;
          }
          if (job.reviewerId !== undefined) continue;

          // A reviewerless historical job can only be recovered if its own lease and first selected
          // preflight still prove the binding. Every condition is deliberately fail-closed: a missing
          // lease/preflight, a mismatched contract, malformed itemMaxima, or a synthetic id remains
          // invisible to cross-lease reuse rather than becoming grounds to suppress a later dispatch.
          const lease = leases.get(job.leaseId);
          if (
            !lease
            || lease.reviewContractSha256 !== contractHash
            || !Array.isArray(lease.preflightIds)
            || typeof lease.preflightIds[0] !== 'string'
            || deriveReviewerJobId(lease.id, id, contractHash) !== job.id
          ) continue;
          const preflight = preflights.get(lease.preflightIds[0]);
          if (
            !preflight
            || preflight.reviewContractSha256 !== contractHash
            || !Array.isArray(preflight.itemMaxima)
            || !preflight.itemMaxima.some((item) => item && item.itemId === `item-${id}`)
          ) continue;
          matches.push(job);
        }
        return clone(matches);
      });
    },
  });
}
