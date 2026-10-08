import {
  ARM_ABORTED_CODE,
  OWNER_HANDLE_RELEASED_CODE,
  OWNERSHIP_CAP_MISMATCH_CODE,
  PROCESS_OWNERSHIP_UNAVAILABLE_CODE,
} from './lease-store.mjs';

/*
 * Coordinates on-demand process ownership of the review ledger: one single-flight arm per cycle,
 * the post-arm recovery work, and release when the last admitted owner-sensitive operation ends.
 */

// Default budget for one on-demand arm. It must exceed lease-store.mjs's lockStaleMs (60 s)
// plus real I/O margin so that a DEAD predecessor's ownership record can go stale and be reclaimed
// inside one arm. A LIVE holder is not a condition that waiting resolves, so running out of this
// budget correctly fails the call instead of waiting longer.
export const DEFAULT_ARM_TIMEOUT_MS = 90_000;

// Base poll interval for the arming loop only (the store's own data-root lock loop keeps its 10 ms).
// The store stretches it with the measured cost of each attempt and jitters it, so
// several servers arming at once cannot keep the ledger's global write lock saturated.
export const DEFAULT_ARM_LOCK_RETRY_MS = 250;

const SHUTTING_DOWN_MESSAGE = 'the server is shutting down and refuses new owner-sensitive work';
const STILL_AVAILABLE = 'preflight, status and result still work, and retrying this same call later is safe';
const PROCESS_OWNERSHIP_RELEASE_FAILED_MESSAGE = 'process ownership could not be released after an earlier operation; this server refuses new owner-sensitive work; preflight, status and result remain callable';

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requirePositiveSafeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${field} must be a positive safe integer`);
}

function requireFunction(value, field) {
  if (typeof value !== 'function') throw new TypeError(`${field} must be a function`);
}

// Same member rule the store's transactional cap check applies: an absent or null member
// is "absent", and -0 is normalized to 0 so a '0' vs '-0' configuration is never a difference.
function capValue(value) {
  if (value === undefined || value === null) return undefined;
  return Object.is(value, -0) ? 0 : value;
}

function describeCapDifferences(recorded, resolved) {
  const names = [...new Set([...Object.keys(recorded), ...Object.keys(resolved)])].sort();
  const differences = [];
  for (const name of names) {
    const recordedValue = capValue(recorded[name]);
    const resolvedValue = capValue(resolved[name]);
    if (recordedValue === undefined || resolvedValue === undefined) continue;
    if (Object.is(recordedValue, resolvedValue)) continue;
    differences.push(`${name} recorded ${recordedValue} vs this server ${resolvedValue}`);
  }
  return differences;
}

/**
 * The translation table (applied to a failed arm() only). A holder is named ONLY for LIVE_OWNER and
 * NOT_YET_STALE, and only from its pid/generation/timestamp -- never its acquisitionId, an internal
 * fence token. DATA_ROOT_LOCKED concerns a different lock and has no process owner at all, so its
 * message never names a pid, whatever stray fields the error carries. Anything unrecognized --
 * including ARM_IN_PROGRESS, which would mean a bug in this module's own single-flight -- is
 * rethrown unchanged.
 */
function translateArmError(error, { armTimeoutMs, engineError }) {
  const code = error !== null && typeof error === 'object' ? error.code : undefined;

  if (code === PROCESS_OWNERSHIP_UNAVAILABLE_CODE) {
    const { reason, owner, ownerAgeMs } = error;
    const namesAHolder = (reason === 'LIVE_OWNER' || reason === 'NOT_YET_STALE')
      && owner !== null && typeof owner === 'object' && Number.isSafeInteger(owner.pid)
      && typeof ownerAgeMs === 'number' && Number.isFinite(ownerAgeMs);
    if (namesAHolder) {
      const holder = { pid: owner.pid, generation: owner.generation, timestamp: owner.timestamp };
      const ageSeconds = Math.max(0, Math.floor(ownerAgeMs / 1000));
      const situation = reason === 'LIVE_OWNER'
        ? `is held by another live server process (pid ${holder.pid}, owner for ${ageSeconds}s)`
        : `was last taken by pid ${holder.pid}, whose ownership record (${ageSeconds}s old) is not yet stale enough to reclaim`;
      return engineError(
        'PROCESS_OWNERSHIP_UNAVAILABLE',
        `process ownership of the review ledger ${situation}; ${STILL_AVAILABLE}`,
        { reason, owner: holder, ownerAgeMs },
      );
    }
    return engineError(
      'PROCESS_OWNERSHIP_UNAVAILABLE',
      `the review ledger stayed busy for this call's whole ${armTimeoutMs}ms ownership budget and no holder could be identified; ${STILL_AVAILABLE}`,
      { reason: typeof reason === 'string' ? reason : 'DATA_ROOT_LOCKED' },
    );
  }

  if (code === OWNERSHIP_CAP_MISMATCH_CODE) {
    const recorded = isPlainObject(error.recorded) ? { ...error.recorded } : {};
    const resolved = isPlainObject(error.resolved) ? { ...error.resolved } : {};
    const differences = describeCapDifferences(recorded, resolved);
    const detail = differences.length > 0 ? differences.join('; ') : 'no member-by-member difference was reported';
    return engineError(
      'OWNERSHIP_CAP_MISMATCH',
      `another live server armed this review ledger with different spend caps (${detail}); give every session the same cap settings, or wait for that server to exit, then retry`,
      { recorded, resolved },
    );
  }

  // The store knows nothing about shutdown. A released handle only ever means this
  // process is ending its ownership for good, and ARM_ABORTED means the arm stopped because the
  // shouldAbort token this coordinator handed it (isShuttingDown) turned true. Both are shutdown,
  // reported in the engine's own vocabulary.
  if (code === OWNER_HANDLE_RELEASED_CODE || code === ARM_ABORTED_CODE) return engineError('SHUTTING_DOWN', SHUTTING_DOWN_MESSAGE);

  return error;
}

export function createOwnershipCoordinator({
  ownerLock,
  armTimeoutMs,
  armLockRetryMs,
  resolvedCaps,
  isShuttingDown,
  runCycleWork,
  engineError,
  retainOwnershipUntilShutdown = false,
  log = (line) => process.stderr.write(`${line}\n`),
} = {}) {
  if (ownerLock === null || typeof ownerLock !== 'object') throw new TypeError('ownerLock must be an object');
  requireFunction(ownerLock.isOwner, 'ownerLock.isOwner');
  // The compensating shutdown release in runCycle calls it, so check it now, not then.
  requireFunction(ownerLock.release, 'ownerLock.release');
  requirePositiveSafeInteger(armTimeoutMs, 'armTimeoutMs');
  requirePositiveSafeInteger(armLockRetryMs, 'armLockRetryMs');
  if (!isPlainObject(resolvedCaps)) throw new TypeError('resolvedCaps must be a plain object');
  requireFunction(isShuttingDown, 'isShuttingDown');
  requireFunction(runCycleWork, 'runCycleWork');
  requireFunction(engineError, 'engineError');
  requireFunction(log, 'log');
  if (typeof retainOwnershipUntilShutdown !== 'boolean') throw new TypeError('retainOwnershipUntilShutdown must be a boolean');

  // The one in-flight cycle: { runCycleRecovery, promise }, or null. It covers the WHOLE cycle -- the
  // arm and its post-arm recovery together -- so a joiner can never proceed before that recovery.
  let cycle = null;

  // Admitted operations share the current arm, and only the last one releases it. A caller
  // that sees this barrier waits OUTSIDE activeOperations, then loops before admission; it can never
  // observe a retiring acquisition as usable. The object identity prevents a finished older release
  // from clearing a newer barrier.
  let activeOperations = 0;
  let releaseBarrier = null;
  let releaseFaultLatched = false;

  function writeLog(line) {
    try {
      log(line);
    } catch {
      // A logging failure must never change the outcome it was reporting on.
    }
  }

  function refuseIfReleaseFaulted() {
    if (releaseFaultLatched) {
      throw engineError('PROCESS_OWNERSHIP_RELEASE_FAILED', PROCESS_OWNERSHIP_RELEASE_FAILED_MESSAGE);
    }
  }

  function snapshotOwnerToken() {
    const acquisitionId = ownerLock.acquisitionId;
    if (typeof acquisitionId !== 'string' || acquisitionId.length === 0) {
      throw new Error('owner token unavailable: the ownership handle is not armed');
    }
    return Object.freeze({ acquisitionId });
  }

  function createReleaseBarrier() {
    let resolve;
    const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
    return { promise, resolve };
  }

  /**
   * Completes one admitted operation. A normal completion release is deliberately absorbed here:
   * a finished review must keep its original value (or original error) even if physical ownership
   * handoff then fails. The fixed diagnostic and sticky latch make that failure observable and stop
   * every later owner-sensitive operation without tempting a caller to redispatch completed work.
   */
  async function completeOperation() {
    activeOperations -= 1;
    if (activeOperations !== 0 || ownerLock.isOwner() !== true) return;
    if (retainOwnershipUntilShutdown) return;

    // This publication and the zero transition are synchronous. In particular, a reentrant handle
    // callback invoked by release() sees the barrier already installed and cannot enter this cycle.
    const barrier = createReleaseBarrier();
    releaseBarrier = barrier;
    try {
      await ownerLock.release({ final: isShuttingDown() });
    } catch {
      releaseFaultLatched = true;
      writeLog('openrouter-review-ownership: completion-release-failed; ownership release could not complete and new owner-sensitive work is refused');
    } finally {
      if (releaseBarrier === barrier) releaseBarrier = null;
      // Wake after the failure latch is set and the matching barrier is no longer current. Every
      // waiter loops, so a newer barrier or shutdown that landed while it slept still wins.
      barrier.resolve();
    }
  }

  async function runCycle(state) {
    try {
      try {
        // shouldAbort is the live shutdown predicate itself, never a snapshot: the store polls it
        // before every attempt and after every sleep, so a shutdown that begins while this arm waits
        // on a live holder stops the wait promptly instead of stalling the drain for the whole
        // budget. The store stays policy-free: it only sees a cancellation token.
        await ownerLock.arm({ acquireTimeoutMs: armTimeoutMs, lockRetryMs: armLockRetryMs, caps: resolvedCaps, shouldAbort: isShuttingDown });
      } catch (error) {
        throw translateArmError(error, { armTimeoutMs, engineError });
      }

      // Checked synchronously in the arm's own continuation, with no await between the check and the
      // decision: an arm admitted before shutdown can never keep ownership acquired after it.
      // This still matters with an abortable arm: an attempt that already COMMITTED its ACQUIRED
      // record is never aborted, so the compensating release below is what keeps every ACQUIRED
      // matched by a RELEASED.
      if (isShuttingDown()) {
        try {
          await ownerLock.release({ final: true });
        } catch {
          // The SHUTTING_DOWN rejection below still wins. A failed release leaves
          // the handle armed, so the shutdown sequence's own release retries it, and the existing
          // ambiguous-drain rule still decides the exit code.
          writeLog('openrouter-review-ownership: compensating-release-failed; shutdown began while this call was arming, its acquisition could not be released here, and release remains unfinished for the shutdown sequence to retry');
        }
        throw engineError('SHUTTING_DOWN', SHUTTING_DOWN_MESSAGE);
      }

      // The recovery decision point, made once and synchronously. Without a recovery request the cycle
      // is cleared right here: a caller arriving after this point finds no cycle and an armed handle,
      // resolves at once, and -- having never joined -- was never promised this cycle's recovery.
      // Skipping it skips the WHOLE of runCycleWork, every step the engine put in it, and for as long
      // as the handle stays armed nothing here runs that work later: a later call finds it armed.
      if (!state.runCycleRecovery) {
        if (cycle === state) cycle = null;
        return;
      }
      const ownerToken = Object.freeze({ acquisitionId: ownerLock.acquisitionId });
      try {
        await runCycleWork({ ownerToken });
      } catch {
        // Recovery is best effort and must never fail the paid call that triggered the arm. The
        // engine's cycle work logs its own redacted detail; this is only a backstop.
        writeLog('openrouter-review-ownership: arm-cycle-work-failed (detail redacted); the call that triggered the arm continues');
      }
    } finally {
      if (cycle === state) cycle = null;
    }
  }

  /**
   * The single entry point. Order, per the interface contract: refuse during shutdown; join an
   * in-flight cycle (raising its recovery flag when this caller needs recovery, so the cycle runs
   * recovery if any joiner asked for it); treat a handle that already owns as armed (no arm, no
   * cycle work); otherwise start the one cycle every concurrent caller will join.
   */
  async function ensureArmed({ runCycleRecovery } = {}) {
    if (typeof runCycleRecovery !== 'boolean') throw new TypeError('runCycleRecovery must be a boolean');
    if (isShuttingDown()) throw engineError('SHUTTING_DOWN', SHUTTING_DOWN_MESSAGE);
    if (cycle !== null) {
      if (runCycleRecovery) cycle.runCycleRecovery = true;
      return cycle.promise;
    }
    if (ownerLock.isOwner() === true) return undefined;
    if (typeof ownerLock.arm !== 'function') throw new TypeError('ownerLock.arm must be a function');
    const state = { runCycleRecovery, promise: null };
    cycle = state;
    state.promise = runCycle(state);
    return state.promise;
  }

  /**
   * Runs one complete owner-sensitive operation. The synchronous admission census covers arm wait,
   * cycle recovery, callback work and completion release. Waiters behind a retiring acquisition are
   * intentionally not counted until they loop through a fresh admission after that release settles.
   */
  async function runOperation({ runCycleRecovery } = {}, operation) {
    if (typeof runCycleRecovery !== 'boolean') throw new TypeError('runCycleRecovery must be a boolean');
    requireFunction(operation, 'operation');

    for (;;) {
      // Shutdown deliberately wins over a release-failure latch, matching ensureArmed's existing
      // refusal contract and letting the composition root retain final-release authority.
      if (isShuttingDown()) throw engineError('SHUTTING_DOWN', SHUTTING_DOWN_MESSAGE);
      refuseIfReleaseFaulted();
      const barrier = releaseBarrier;
      if (barrier !== null) {
        await barrier.promise;
        continue;
      }
      // No await occurs between the barrier check and this increment. A caller admitted here owns a
      // slot in the current cycle even if the arm itself has not yet reached the ledger.
      activeOperations += 1;
      break;
    }

    try {
      await ensureArmed({ runCycleRecovery });
      const ownerToken = snapshotOwnerToken();
      if (retainOwnershipUntilShutdown) {
        // Capture both proofs in this synchronous continuation; legacy handles need no generation.
        const ownerGeneration = ownerLock.generation;
        requirePositiveSafeInteger(ownerGeneration, 'ownerLock.generation');
        return await operation({ ownerToken, ownerGeneration });
      }
      return await operation({ ownerToken });
    } finally {
      await completeOperation();
    }
  }

  return Object.freeze({ ensureArmed, runOperation });
}
