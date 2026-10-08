import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ARM_ABORTED_CODE,
  ARM_IN_PROGRESS_CODE,
  OWNER_HANDLE_RELEASED_CODE,
  OWNERSHIP_CAP_MISMATCH_CODE,
  PROCESS_OWNERSHIP_UNAVAILABLE_CODE,
} from '../src/local-mcp/lease-store.mjs';
import {
  createOwnershipCoordinator,
  DEFAULT_ARM_LOCK_RETRY_MS,
  DEFAULT_ARM_TIMEOUT_MS,
} from '../src/local-mcp/ownership-coordinator.mjs';
import { ReviewEngineError } from '../src/local-mcp/review-engine.mjs';

// Unit tests for the ownership coordinator (always-connect ownership arming).
// Every test drives a fake ownership handle whose arm() is held open by a deferred promise, so each
// interleaving (a joiner arriving mid-arm, shutdown beginning mid-arm, a failed arm) is placed
// exactly rather than hoped for with timers. The fake enforces the owner handle's loud precondition -- a
// re-entrant arm() while arming throws ARM_IN_PROGRESS -- exactly as the real handle does.

// The engine injects this same factory (review-engine.mjs imports the coordinator, so the coordinator
// cannot import ReviewEngineError back without a circular ESM import).
const engineError = (code, message, details) => new ReviewEngineError(code, message, details);
const RESOLVED_CAPS = Object.freeze({ installationHardMaximumUsd: 10 });

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolveFn, rejectFn) => { resolve = resolveFn; reject = rejectFn; });
  return { promise, resolve, reject };
}

// One macrotask turn: every pending microtask (a resumed arm, the coordinator's continuation) has run.
function flush() {
  return new Promise((resolve) => { setImmediate(resolve); });
}

function storeError(code, fields = {}) {
  return Object.assign(new Error(`store failure ${code}`), { code, ...fields });
}

/**
 * A controllable stand-in for the lease-store owner handle: same members, same state names, closures that never
 * use `this`. arm() parks on a deferred the test settles with completeArm()/failArm(); release() can
 * be made to fail once with failNextRelease(), which (like a real release I/O failure) leaves the
 * handle armed.
 */
function createFakeHandle({ armed = false } = {}) {
  let state = armed ? 'armed' : 'unarmed';
  let generation = armed ? 1 : 0;
  let nextReleaseError = null;
  const armCalls = [];
  const releaseCalls = [];
  const pendingArms = [];
  const handle = Object.freeze({
    dataRoot: 'fake-data-root',
    get generation() { return state === 'armed' ? generation : null; },
    get acquisitionId() { return state === 'armed' ? `fake-acquisition-${generation}` : null; },
    get state() { return state; },
    isOwner: () => state === 'armed',
    arm: async (options) => {
      armCalls.push(options);
      if (state === 'arming') throw storeError(ARM_IN_PROGRESS_CODE);
      if (state === 'released') throw storeError(OWNER_HANDLE_RELEASED_CODE);
      if (state === 'armed') return;
      state = 'arming';
      const gate = createDeferred();
      pendingArms.push(gate);
      try {
        await gate.promise;
      } catch (error) {
        state = 'unarmed';
        throw error;
      }
      generation += 1;
      state = 'armed';
    },
    release: async ({ final = true } = {}) => {
      releaseCalls.push({ final, stateAtCall: state });
      if (nextReleaseError !== null) {
        const error = nextReleaseError;
        nextReleaseError = null;
        throw error;
      }
      state = final ? 'released' : 'unarmed';
    },
  });
  return {
    handle,
    armCalls,
    releaseCalls,
    completeArm() { pendingArms.at(-1).resolve(); },
    failArm(error) { pendingArms.at(-1).reject(error); },
    failNextRelease(error) { nextReleaseError = error; },
  };
}

function buildCoordinator({ handle, shutdown = { value: false }, runCycleWork = async () => {}, logLines = [], ...overrides } = {}) {
  return createOwnershipCoordinator({
    ownerLock: handle,
    armTimeoutMs: 1_000,
    armLockRetryMs: 250,
    resolvedCaps: RESOLVED_CAPS,
    isShuttingDown: () => shutdown.value,
    runCycleWork,
    engineError,
    log: (line) => { logLines.push(line); },
    ...overrides,
  });
}

function recordingCycleWork() {
  const calls = [];
  return { calls, runCycleWork: async ({ ownerToken }) => { calls.push(ownerToken); } };
}

// Arms a fresh coordinator, fails that arm with `error`, and returns what ensureArmed() rejected with.
async function armFailure(error) {
  const fake = createFakeHandle();
  const coordinator = buildCoordinator({ handle: fake.handle });
  const arming = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  fake.failArm(error);
  return arming.then(() => assert.fail('the arm was expected to fail'), (rejection) => rejection);
}

test('the arm defaults are a 90 s budget and a 250 ms base interval', () => {
  assert.equal(DEFAULT_ARM_TIMEOUT_MS, 90_000);
  assert.equal(DEFAULT_ARM_LOCK_RETRY_MS, 250);
});

test('coordinator contract: construction validates every option, and log has a default', () => {
  const fake = createFakeHandle();
  const valid = {
    ownerLock: fake.handle, armTimeoutMs: 1_000, armLockRetryMs: 250, resolvedCaps: RESOLVED_CAPS,
    isShuttingDown: () => false, runCycleWork: async () => {}, engineError, log: () => {},
  };
  assert.doesNotThrow(() => createOwnershipCoordinator(valid));
  assert.doesNotThrow(() => createOwnershipCoordinator({ ...valid, log: undefined }), 'log defaults to a stderr writer');
  for (const [name, bad] of [
    ['ownerLock', null], ['ownerLock', { acquisitionId: null }],
    ['armTimeoutMs', 0], ['armTimeoutMs', -1], ['armTimeoutMs', 1.5], ['armTimeoutMs', '90000'],
    ['armLockRetryMs', 0], ['armLockRetryMs', Number.NaN],
    ['resolvedCaps', null], ['resolvedCaps', []], ['resolvedCaps', 'caps'],
    ['isShuttingDown', true], ['runCycleWork', undefined], ['engineError', {}], ['log', 'stderr'],
  ]) {
    assert.throws(() => createOwnershipCoordinator({ ...valid, [name]: bad }), TypeError, `${name}=${String(bad)} must be refused`);
  }
  // The compensating shutdown release (rule 4) calls ownerLock.release(), so a handle that cannot
  // release is refused here, at construction, not at the first shutdown that needs it.
  for (const release of [undefined, 'release']) {
    assert.throws(
      () => createOwnershipCoordinator({ ...valid, ownerLock: { acquisitionId: null, isOwner: () => false, release } }),
      (error) => error instanceof TypeError && error.message === 'ownerLock.release must be a function',
      `a handle whose release is ${String(release)} must be refused`,
    );
  }
  assert.throws(
    () => createOwnershipCoordinator({
      ...valid,
      ownerLock: { acquisitionId: null, isOwner: 'not-a-function', async release() {} },
    }),
    (error) => error instanceof TypeError && error.message === 'ownerLock.isOwner must be a function',
    'isOwner is validated independently when release is otherwise valid',
  );
});

test('coordinator contract: ensureArmed() requires a boolean runCycleRecovery', async () => {
  const coordinator = buildCoordinator({ handle: createFakeHandle().handle });
  await assert.rejects(coordinator.ensureArmed(), TypeError);
  await assert.rejects(coordinator.ensureArmed({}), TypeError);
  await assert.rejects(coordinator.ensureArmed({ runCycleRecovery: 'yes' }), TypeError);
});

test('two concurrent ensureArmed() calls share ONE arm, and neither is refused by the handle\'s own ARM_IN_PROGRESS guard', async () => {
  const fake = createFakeHandle();
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, runCycleWork: work.runCycleWork });
  const first = coordinator.ensureArmed({ runCycleRecovery: true });
  const second = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  fake.completeArm();
  const outcomes = await Promise.allSettled([first, second]);
  assert.deepEqual(
    outcomes.map((outcome) => outcome.status),
    ['fulfilled', 'fulfilled'],
    `a concurrent caller must join the in-flight cycle, never race its own arm; rejected with: ${outcomes.filter((outcome) => outcome.status === 'rejected').map((outcome) => outcome.reason?.code).join(', ')}`,
  );
  assert.equal(fake.armCalls.length, 1);
  const { shouldAbort, ...armOptions } = fake.armCalls[0];
  assert.deepEqual(armOptions, { acquireTimeoutMs: 1_000, lockRetryMs: 250, caps: { installationHardMaximumUsd: 10 } });
  assert.equal(typeof shouldAbort, 'function', 'every arm is handed the shutdown predicate as its abort token');
  assert.equal(fake.handle.isOwner(), true);
  assert.equal(work.calls.length, 1, 'the joined cycle runs its work once');
  assert.deepEqual(work.calls[0], { acquisitionId: 'fake-acquisition-1' });
  assert.equal(Object.isFrozen(work.calls[0]), true, 'the cycle work gets a frozen ownerToken snapshot');
});

test('a failed arm rejects every joiner with the same translated error and clears the cycle, so the next call genuinely arms again', async () => {
  const fake = createFakeHandle();
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, runCycleWork: work.runCycleWork });
  const first = coordinator.ensureArmed({ runCycleRecovery: true });
  const joiner = coordinator.ensureArmed({ runCycleRecovery: false });
  await flush();
  fake.failArm(storeError(PROCESS_OWNERSHIP_UNAVAILABLE_CODE, { reason: 'DATA_ROOT_LOCKED' }));
  const [firstFailure, joinerFailure] = await Promise.all([
    first.then(() => null, (error) => error),
    joiner.then(() => null, (error) => error),
  ]);
  assert.ok(firstFailure instanceof ReviewEngineError);
  assert.equal(firstFailure.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
  assert.equal(joinerFailure, firstFailure, 'a joiner sees exactly the failure the cycle produced');
  assert.equal(fake.handle.state, 'unarmed');

  const retry = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  assert.equal(fake.armCalls.length, 2, 'a later call genuinely arms again rather than joining a dead cycle');
  fake.completeArm();
  await retry;
  assert.equal(fake.handle.isOwner(), true);
  assert.equal(work.calls.length, 1, 'only the successful arm runs cycle work');
});

test('shutdown that begins while the arm is in flight releases what the arm acquired (final) and rejects SHUTTING_DOWN, running no cycle work', async () => {
  const fake = createFakeHandle();
  const shutdown = { value: false };
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, shutdown, runCycleWork: work.runCycleWork });
  const arming = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  shutdown.value = true; // shutdown begins while the acquisition is still committing
  fake.completeArm();
  await assert.rejects(arming, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
  assert.deepEqual(fake.releaseCalls, [{ final: true, stateAtCall: 'armed' }], 'the arm\'s own acquisition is released, finally');
  assert.equal(fake.handle.state, 'released');
  assert.equal(work.calls.length, 0, 'no cycle work runs for an arm that shutdown is compensating');
});

test('a failing compensating release still rejects SHUTTING_DOWN, is logged loudly, and leaves the handle armed for the shutdown sequence to retry', async () => {
  const fake = createFakeHandle();
  const shutdown = { value: false };
  const logLines = [];
  const coordinator = buildCoordinator({ handle: fake.handle, shutdown, logLines });
  fake.failNextRelease(new Error('simulated release I/O failure with private detail'));
  const arming = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  shutdown.value = true;
  fake.completeArm();
  await assert.rejects(arming, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
  assert.equal(fake.releaseCalls.length, 1);
  assert.equal(fake.handle.state, 'armed', 'a failed release leaves the handle armed for the shutdown sequence\'s own release');
  assert.equal(logLines.length, 1);
  assert.match(logLines[0], /compensating-release-failed/);
  assert.doesNotMatch(logLines[0], /private detail/);
});

test('once shutdown has begun, a new caller is refused at once and neither starts nor joins an arm', async () => {
  const fake = createFakeHandle();
  const shutdown = { value: false };
  const coordinator = buildCoordinator({ handle: fake.handle, shutdown });
  const arming = coordinator.ensureArmed({ runCycleRecovery: false });
  await flush();
  shutdown.value = true;
  const refused = coordinator.ensureArmed({ runCycleRecovery: true }).then(() => 'resolved', (error) => error.code);
  const verdict = await Promise.race([
    refused,
    new Promise((resolve) => { setTimeout(() => resolve('still pending: it joined the in-flight cycle'), 200); }),
  ]);
  assert.equal(verdict, 'SHUTTING_DOWN');
  assert.equal(fake.armCalls.length, 1, 'the refused caller did not start an arm of its own');
  fake.completeArm();
  await assert.rejects(arming, (error) => error.code === 'SHUTTING_DOWN');

  const idle = createFakeHandle();
  const idleCoordinator = buildCoordinator({ handle: idle.handle, shutdown: { value: true } });
  await assert.rejects(idleCoordinator.ensureArmed({ runCycleRecovery: true }), (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
  assert.equal(idle.armCalls.length, 0);
});

// Contract steps 1 and 3 in their exact order: the shutdown refusal comes BEFORE the already-armed fast
// path. A handle that owns must never wave owner-sensitive work through once shutdown has begun.
test('shutdown takes precedence over the already-armed fast path: an owning handle is refused SHUTTING_DOWN once shutdown has begun, with no arm, no release and no cycle work', async () => {
  const fake = createFakeHandle({ armed: true });
  const shutdown = { value: false };
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, shutdown, runCycleWork: work.runCycleWork });
  await coordinator.ensureArmed({ runCycleRecovery: true });
  assert.equal(fake.armCalls.length, 0, 'precondition: before shutdown, the owning handle takes the fast path');

  shutdown.value = true;
  for (const runCycleRecovery of [true, false]) {
    await assert.rejects(
      coordinator.ensureArmed({ runCycleRecovery }),
      (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN',
      `runCycleRecovery ${runCycleRecovery}: the shutdown check (contract step 1) must run before the already-armed fast path (step 3)`,
    );
  }
  assert.equal(fake.handle.isOwner(), true, 'the handle still owns, so only the shutdown check can have refused');
  assert.equal(fake.armCalls.length, 0);
  assert.deepEqual(fake.releaseCalls, [], 'a refusal releases nothing: the shutdown sequence owns that release');
  assert.equal(work.calls.length, 0);
});

test('the arm is handed a shouldAbort that reads isShuttingDown(); an arm that aborts on it rejects SHUTTING_DOWN with no compensating release and runs no cycle work', async () => {
  const fake = createFakeHandle();
  const shutdown = { value: false };
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, shutdown, runCycleWork: work.runCycleWork });
  const arming = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  const { shouldAbort } = fake.armCalls[0];
  assert.equal(typeof shouldAbort, 'function');
  assert.equal(shouldAbort(), false, 'no shutdown yet: a waiting arm keeps polling');
  shutdown.value = true;
  assert.equal(shouldAbort(), true, 'the abort token is the live shutdown flag, read on every poll, never a snapshot');
  // What the real handle does when its poll sees the token set: back to unarmed, reject ARM_ABORTED.
  fake.failArm(storeError(ARM_ABORTED_CODE));
  await assert.rejects(arming, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
  assert.equal(fake.handle.state, 'unarmed');
  assert.deepEqual(fake.releaseCalls, [], 'an aborted arm acquired nothing, so there is nothing to compensate');
  assert.equal(work.calls.length, 0);
});

test('a runCycleRecovery:false cycle joined by a runCycleRecovery:true caller runs the cycle work exactly once (union rule)', async () => {
  const fake = createFakeHandle();
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, runCycleWork: work.runCycleWork });
  const creator = coordinator.ensureArmed({ runCycleRecovery: false });
  const joiner = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  fake.completeArm();
  await Promise.all([creator, joiner]);
  assert.equal(fake.armCalls.length, 1);
  assert.equal(work.calls.length, 1, 'any joiner that needs recovery makes the whole cycle run it (rule 1)');
});

test('a runCycleRecovery:false joiner of a recovery cycle resolves only after the cycle work finishes', async () => {
  const fake = createFakeHandle();
  const workGate = createDeferred();
  let workCalls = 0;
  const coordinator = buildCoordinator({
    handle: fake.handle,
    runCycleWork: async () => { workCalls += 1; await workGate.promise; },
  });
  const creator = coordinator.ensureArmed({ runCycleRecovery: true });
  let joinerSettled = false;
  const joiner = coordinator.ensureArmed({ runCycleRecovery: false }).then(() => { joinerSettled = true; });
  await flush();
  fake.completeArm();
  await flush();
  assert.equal(workCalls, 1, 'precondition: the cycle work has started');
  assert.equal(joinerSettled, false, 'a joiner must not proceed before the cycle\'s recovery finishes (rule 1)');
  workGate.resolve();
  await Promise.all([creator, joiner]);
  assert.equal(joinerSettled, true);
  assert.equal(workCalls, 1);
});

test('two runCycleRecovery:false callers arm once and run no cycle work', async () => {
  const fake = createFakeHandle();
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, runCycleWork: work.runCycleWork });
  const first = coordinator.ensureArmed({ runCycleRecovery: false });
  const second = coordinator.ensureArmed({ runCycleRecovery: false });
  await flush();
  fake.completeArm();
  await Promise.all([first, second]);
  assert.equal(fake.armCalls.length, 1);
  assert.equal(work.calls.length, 0);
});

test('the recovery decision is made once, right after the arm -- a runCycleRecovery:true caller arriving later finds an armed handle and runs no cycle work', async () => {
  const fake = createFakeHandle();
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, runCycleWork: work.runCycleWork });
  const creator = coordinator.ensureArmed({ runCycleRecovery: false });
  await flush();
  fake.completeArm();
  await creator;
  await coordinator.ensureArmed({ runCycleRecovery: true });
  assert.equal(fake.armCalls.length, 1);
  assert.equal(work.calls.length, 0, 'a caller that never joined the cycle gets none of its cycle work, whatever that work contains: a runCycleRecovery:false arm runs none of it, now or later');
});

test('a handle that already owns is treated as armed -- no arm() call, no cycle work, and no arm method required', async () => {
  const fake = createFakeHandle({ armed: true });
  const work = recordingCycleWork();
  const coordinator = buildCoordinator({ handle: fake.handle, runCycleWork: work.runCycleWork });
  await coordinator.ensureArmed({ runCycleRecovery: true });
  await coordinator.ensureArmed({ runCycleRecovery: false });
  assert.equal(fake.armCalls.length, 0);
  assert.equal(work.calls.length, 0);

  // The shape of a legacy hand-built fixture: always owning, and no arm method at all.
  const literal = { dataRoot: '/fake', generation: 1, acquisitionId: 'fixture-acquisition', isOwner: () => true, async release() {} };
  const literalCoordinator = buildCoordinator({ handle: literal, runCycleWork: work.runCycleWork });
  await literalCoordinator.ensureArmed({ runCycleRecovery: true });
  assert.equal(work.calls.length, 0);
});

test('an unarmed handle without an arm method is refused with a TypeError when it has to arm', async () => {
  const literal = { acquisitionId: null, isOwner: () => false, async release() {} };
  const coordinator = buildCoordinator({ handle: literal });
  await assert.rejects(
    coordinator.ensureArmed({ runCycleRecovery: true }),
    (error) => error instanceof TypeError && error.message === 'ownerLock.arm must be a function',
  );
});

test('a rejecting runCycleWork is logged as one redacted line and never fails the triggering call', async () => {
  const fake = createFakeHandle();
  const logLines = [];
  const coordinator = buildCoordinator({
    handle: fake.handle,
    logLines,
    runCycleWork: async () => { throw new Error('recovery failed with private detail'); },
  });
  const arming = coordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  fake.completeArm();
  await arming;
  assert.equal(fake.handle.isOwner(), true);
  assert.equal(logLines.length, 1);
  assert.match(logLines[0], /arm-cycle-work-failed/);
  assert.doesNotMatch(logLines[0], /private detail/);
});

test('a throwing log callback never replaces the compensating-release or best-effort cycle-work outcome', async () => {
  const shutdownFake = createFakeHandle();
  const shutdown = { value: false };
  shutdownFake.failNextRelease(new Error('simulated compensating release failure'));
  const shutdownCoordinator = buildCoordinator({
    handle: shutdownFake.handle,
    shutdown,
    log: () => { throw new Error('simulated logger failure'); },
  });
  const arming = shutdownCoordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  shutdown.value = true;
  shutdownFake.completeArm();
  await assert.rejects(
    arming,
    (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN',
    'a throwing logger cannot replace the required shutdown outcome',
  );

  const recoveryFake = createFakeHandle();
  const recoveryCoordinator = buildCoordinator({
    handle: recoveryFake.handle,
    runCycleWork: async () => { throw new Error('simulated cycle-work failure'); },
    log: () => { throw new Error('simulated logger failure'); },
  });
  const recovery = recoveryCoordinator.ensureArmed({ runCycleRecovery: true });
  await flush();
  recoveryFake.completeArm();
  await assert.doesNotReject(recovery, 'best-effort cycle-work failure still resolves when logging also fails');
  assert.equal(recoveryFake.handle.isOwner(), true);
});

test('LIVE_OWNER becomes PROCESS_OWNERSHIP_UNAVAILABLE naming the holder pid and age in whole seconds, with frozen details that never carry acquisitionId', async () => {
  const failure = await armFailure(storeError(PROCESS_OWNERSHIP_UNAVAILABLE_CODE, {
    reason: 'LIVE_OWNER',
    owner: { pid: 4321, generation: 7, timestamp: '2026-09-18T11:59:47.655Z', acquisitionId: 'never-leaves-the-store' },
    ownerAgeMs: 12_345,
  }));
  assert.ok(failure instanceof ReviewEngineError);
  assert.equal(failure.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
  assert.match(failure.message, /pid 4321/);
  assert.match(failure.message, /\b12s\b/);
  assert.match(failure.message, /preflight, status and result still work/);
  assert.match(failure.message, /retrying this same call later is safe/);
  assert.deepEqual(failure.details, {
    reason: 'LIVE_OWNER',
    owner: { pid: 4321, generation: 7, timestamp: '2026-09-18T11:59:47.655Z' },
    ownerAgeMs: 12_345,
  });
  assert.equal(Object.isFrozen(failure.details), true);
  assert.equal(Object.hasOwn(failure.details.owner, 'acquisitionId'), false);
});

test('NOT_YET_STALE becomes PROCESS_OWNERSHIP_UNAVAILABLE naming the holder pid and record age', async () => {
  const failure = await armFailure(storeError(PROCESS_OWNERSHIP_UNAVAILABLE_CODE, {
    reason: 'NOT_YET_STALE',
    owner: { pid: 4321, generation: 7, timestamp: '2026-09-18T11:59:56.001Z' },
    ownerAgeMs: 3_999,
  }));
  assert.equal(failure.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
  assert.match(failure.message, /pid 4321/);
  assert.match(failure.message, /\b3s\b/);
  assert.match(failure.message, /not yet stale/);
  assert.match(failure.message, /retrying this same call later is safe/);
  assert.equal(failure.details.reason, 'NOT_YET_STALE');
  assert.equal(failure.details.owner.pid, 4321);
});

test('DATA_ROOT_LOCKED becomes PROCESS_OWNERSHIP_UNAVAILABLE that never names a pid, even when handed one', async () => {
  const failure = await armFailure(storeError(PROCESS_OWNERSHIP_UNAVAILABLE_CODE, {
    reason: 'DATA_ROOT_LOCKED',
    // Malformed on purpose: the store never names a holder for DATA_ROOT_LOCKED, and the coordinator
    // must not invent one from stray fields either.
    owner: { pid: 4242, generation: 2, timestamp: '2026-09-18T12:00:00.000Z' },
    ownerAgeMs: 9_000,
  }));
  assert.equal(failure.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
  assert.doesNotMatch(failure.message, /pid/i);
  assert.equal(failure.message.includes('4242'), false);
  assert.match(failure.message, /no holder could be identified/);
  assert.match(failure.message, /retrying this same call later is safe/);
  assert.deepEqual(failure.details, { reason: 'DATA_ROOT_LOCKED' });
});

test('OWNERSHIP_CAP_MISMATCH names each differing member recorded vs resolved, never an equal one, and never a dollar sign', async () => {
  const recorded = { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 };
  const resolved = { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 };
  const failure = await armFailure(storeError(OWNERSHIP_CAP_MISMATCH_CODE, { recorded, resolved }));
  assert.ok(failure instanceof ReviewEngineError);
  assert.equal(failure.code, 'OWNERSHIP_CAP_MISMATCH');
  assert.match(failure.message, /installationHardMaximumUsd recorded 5 vs this server 10/);
  assert.doesNotMatch(failure.message, /dailyPaidJobAllowance/, 'an equal member is not named as a difference');
  assert.equal(failure.message.includes('$'), false);
  assert.deepEqual(failure.details, { recorded, resolved });

  const bothRecorded = { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 };
  const bothResolved = { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 30 };
  const bothFailure = await armFailure(storeError(OWNERSHIP_CAP_MISMATCH_CODE, {
    recorded: bothRecorded,
    resolved: bothResolved,
  }));
  assert.match(bothFailure.message, /installationHardMaximumUsd recorded 5 vs this server 10/);
  assert.match(bothFailure.message, /dailyPaidJobAllowance recorded 20 vs this server 30/);
  assert.deepEqual(bothFailure.details, { recorded: bothRecorded, resolved: bothResolved });
});

test('a released handle\'s OWNER_HANDLE_RELEASED becomes SHUTTING_DOWN', async () => {
  const failure = await armFailure(storeError(OWNER_HANDLE_RELEASED_CODE));
  assert.ok(failure instanceof ReviewEngineError);
  assert.equal(failure.code, 'SHUTTING_DOWN');
  assert.equal(Object.hasOwn(failure, 'details'), false);
});

test('an arm aborted by its shouldAbort token (ARM_ABORTED) becomes SHUTTING_DOWN', async () => {
  const failure = await armFailure(storeError(ARM_ABORTED_CODE));
  assert.ok(failure instanceof ReviewEngineError);
  assert.equal(failure.code, 'SHUTTING_DOWN');
  assert.equal(Object.hasOwn(failure, 'details'), false);
});

test('ARM_IN_PROGRESS and any unrecognized error are rethrown unchanged', async () => {
  const armInProgress = storeError(ARM_IN_PROGRESS_CODE);
  assert.equal(await armFailure(armInProgress), armInProgress);
  const unexpected = new RangeError('something structural');
  assert.equal(await armFailure(unexpected), unexpected);
});
