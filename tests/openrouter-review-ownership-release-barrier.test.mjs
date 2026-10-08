import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createOwnershipCoordinator,
} from '../src/local-mcp/ownership-coordinator.mjs';

const CAPS = Object.freeze({ installationHardMaximumUsd: 10 });

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function flush() {
  return new Promise((resolve) => { setImmediate(resolve); });
}

function createHandle({ armSteps = [], releaseSteps = [], malformedToken = false } = {}) {
  let state = 'unarmed';
  let generation = 0;
  let armIndex = 0;
  let releaseIndex = 0;
  const armCalls = [];
  const releaseCalls = [];

  const handle = Object.freeze({
    dataRoot: 'coordinator-test-root',
    get acquisitionId() {
      if (state !== 'armed') return null;
      return malformedToken ? null : `acquisition-${generation}`;
    },
    get generation() { return state === 'armed' ? generation : null; },
    get state() { return state; },
    isOwner: () => state === 'armed',
    arm(options) {
      armCalls.push(options);
      if (state === 'armed') return;
      if (state !== 'unarmed') throw new Error(`unexpected arm in ${state}`);
      const step = armSteps[armIndex++] ?? {};
      state = 'arming';
      const settle = step.gate === undefined ? Promise.resolve() : step.gate.promise;
      return settle.then(
        () => {
          if (step.error !== undefined) throw step.error;
          generation += 1;
          state = 'armed';
        },
        (error) => {
          state = 'unarmed';
          throw error;
        },
      ).catch((error) => {
        state = 'unarmed';
        throw error;
      });
    },
    release({ final = true } = {}) {
      const step = releaseSteps[releaseIndex++] ?? {};
      releaseCalls.push({ final, generation, stateAtCall: state });
      if (typeof step.onStart === 'function') step.onStart();
      state = 'releasing';
      const settle = step.gate === undefined ? Promise.resolve() : step.gate.promise;
      return settle.then(
        () => { state = final ? 'released' : 'unarmed'; },
        (error) => { state = step.failureState ?? 'armed'; throw error; },
      );
    },
  });

  return { handle, armCalls, releaseCalls };
}

function buildCoordinator({ handle, shutdown = { value: false }, cycleCalls = [], runCycleWork, logLines = [], log } = {}) {
  return createOwnershipCoordinator({
    ownerLock: handle,
    armTimeoutMs: 1_000,
    armLockRetryMs: 25,
    resolvedCaps: CAPS,
    isShuttingDown: () => shutdown.value,
    runCycleWork: runCycleWork ?? (async ({ ownerToken }) => { cycleCalls.push(ownerToken); }),
    engineError: (code, message, details) => Object.assign(new Error(message), { code, details }),
    log: log ?? ((line) => { logLines.push(line); }),
  });
}

test('the last completed operation waits for its non-final release before returning its exact value', async () => {
  const releaseGate = deferred();
  const operationGate = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: releaseGate }] });
  const coordinator = buildCoordinator({ handle: fake.handle });
  const value = Object.freeze({ completed: true });
  let receivedToken;
  let settled = false;

  const operation = coordinator.runOperation(
    { runCycleRecovery: true },
    async ({ ownerToken }) => {
      receivedToken = ownerToken;
      await operationGate.promise;
      return value;
    },
  ).then((result) => { settled = true; return result; });

  await flush();
  assert.deepEqual(receivedToken, { acquisitionId: 'acquisition-1' });
  assert.equal(Object.isFrozen(receivedToken), true);
  operationGate.resolve();
  await flush();
  assert.deepEqual(fake.releaseCalls, [{ final: false, generation: 1, stateAtCall: 'armed' }]);
  assert.equal(settled, false, 'the complete lifecycle includes the completion release');

  releaseGate.resolve();
  assert.equal(await operation, value, 'cleanup does not clone or replace the callback value');
  assert.equal(fake.handle.state, 'unarmed');
});

test('overlapping operations share one acquisition and only the last completion starts release', async () => {
  const releaseGate = deferred();
  const firstGate = deferred();
  const secondGate = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: releaseGate }] });
  const cycleCalls = [];
  const coordinator = buildCoordinator({ handle: fake.handle, cycleCalls });
  const tokens = [];

  const first = coordinator.runOperation({ runCycleRecovery: true }, async ({ ownerToken }) => {
    tokens.push(ownerToken);
    await firstGate.promise;
    return 'first';
  });
  const second = coordinator.runOperation({ runCycleRecovery: true }, async ({ ownerToken }) => {
    tokens.push(ownerToken);
    await secondGate.promise;
    return 'second';
  });

  await flush();
  assert.equal(fake.armCalls.length, 1);
  assert.equal(cycleCalls.length, 1, 'one shared arm runs its recovery once');
  assert.equal(tokens.length, 2);
  assert.equal(tokens[0].acquisitionId, tokens[1].acquisitionId);

  firstGate.resolve();
  assert.equal(await first, 'first');
  assert.deepEqual(fake.releaseCalls, [], 'a peer remains admitted, so the first completion cannot release');

  secondGate.resolve();
  await flush();
  assert.equal(fake.releaseCalls.length, 1);
  releaseGate.resolve();
  assert.equal(await second, 'second');
});

test('arrivals reentrant from release wait behind its barrier and run only under a fresh acquisition', async () => {
  const firstRelease = deferred();
  const secondRelease = deferred();
  let arrivalToken = null;
  let arrival;
  let coordinator;
  // The handle invokes onStart synchronously. A barrier published after release() starts would let
  // this reentrant call observe the old acquisition and make the assertion below fail.
  const fake = createHandle({
    releaseSteps: [{
      gate: firstRelease,
      onStart: () => {
        arrival = coordinator.runOperation({ runCycleRecovery: false }, async ({ ownerToken }) => {
          arrivalToken = ownerToken;
          return 'arrival';
        });
      },
    }, { gate: secondRelease }],
  });
  coordinator = buildCoordinator({ handle: fake.handle });

  const first = coordinator.runOperation({ runCycleRecovery: true }, async ({ ownerToken }) => {
    assert.equal(ownerToken.acquisitionId, 'acquisition-1');
    return 'first';
  });
  await flush();
  assert.notEqual(arrival, undefined, 'the arrival is invoked from release(), after the zero transition');
  await flush();
  assert.equal(arrivalToken, null, 'the arrival must not run through the retiring acquisition');
  assert.equal(fake.armCalls.length, 1);

  firstRelease.resolve();
  await flush();
  assert.equal(arrivalToken?.acquisitionId, 'acquisition-2');
  assert.equal(fake.armCalls.length, 2);
  assert.equal(await first, 'first');
  await flush();
  assert.equal(fake.releaseCalls.length, 2);
  secondRelease.resolve();
  assert.equal(await arrival, 'arrival');
});

test('a completion release failure preserves a successful result, logs no private detail, and latches later admissions', async () => {
  const privateFailure = new Error('private filesystem path C:/secret and 99.99 USD');
  const failedRelease = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: failedRelease }] });
  const logLines = [];
  const coordinator = buildCoordinator({ handle: fake.handle, logLines });
  const value = { done: true };

  const completed = coordinator.runOperation({ runCycleRecovery: false }, async () => value);
  await flush();
  failedRelease.reject(privateFailure);
  assert.equal(await completed, value, 'the completed operation result survives a later physical release failure');
  assert.equal(fake.handle.state, 'armed', 'the coordinator must not forge a successful handoff');
  assert.deepEqual(logLines.length, 1);
  assert.match(logLines[0], /completion-release-failed/);
  assert.doesNotMatch(logLines[0], /private filesystem path|99\.99|C:\/secret/);

  let callbackRan = false;
  await assert.rejects(
    coordinator.runOperation({ runCycleRecovery: true }, async () => { callbackRan = true; }),
    (error) => error?.code === 'PROCESS_OWNERSHIP_RELEASE_FAILED',
  );
  assert.equal(callbackRan, false);
  assert.equal(fake.armCalls.length, 1, 'the release-fault latch stops work before a fresh arm');
});

test('a completion release failure preserves the callback rejection identity', async () => {
  const failedRelease = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: failedRelease }] });
  const coordinator = buildCoordinator({ handle: fake.handle });
  const callbackFailure = new Error('callback outcome');

  const completed = coordinator.runOperation({ runCycleRecovery: false }, async () => { throw callbackFailure; });
  await flush();
  failedRelease.reject(new Error('release failure'));
  await assert.rejects(completed, (error) => error === callbackFailure);
});

test('a caller waiting behind a failed release receives the latched public error, never the raw release rejection', async () => {
  const failedRelease = deferred();
  let coordinator;
  let waiter;
  let waiterRan = false;
  const fake = createHandle({
    releaseSteps: [{
      gate: failedRelease,
      onStart: () => {
        waiter = coordinator.runOperation({ runCycleRecovery: false }, async () => { waiterRan = true; });
      },
    }],
  });
  coordinator = buildCoordinator({ handle: fake.handle });

  const completed = coordinator.runOperation({ runCycleRecovery: false }, async () => 'finished');
  await flush();
  const privateReleaseFailure = new Error('raw store error must not reach waiter');
  failedRelease.reject(privateReleaseFailure);

  assert.equal(await completed, 'finished');
  await assert.rejects(
    waiter,
    (error) => error?.code === 'PROCESS_OWNERSHIP_RELEASE_FAILED'
      && error.message === 'process ownership could not be released after an earlier operation; this server refuses new owner-sensitive work; preflight, status and result remain callable',
  );
  assert.equal(waiterRan, false);
});

test('a release-pending failure latches later work without claiming the handle remains armed', async () => {
  const failedRelease = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: failedRelease, failureState: 'release-pending' }] });
  const logLines = [];
  const coordinator = buildCoordinator({ handle: fake.handle, logLines });

  const completed = coordinator.runOperation({ runCycleRecovery: false }, async () => 'finished');
  await flush();
  failedRelease.reject(new Error('physical lock cleanup detail'));
  assert.equal(await completed, 'finished');
  assert.equal(fake.handle.isOwner(), false, 'release-pending has no active ownership to describe as armed');
  assert.equal(logLines.length, 1);
  assert.match(logLines[0], /completion-release-failed/);
  assert.doesNotMatch(logLines[0], /remains armed|physical lock cleanup detail/);
  await assert.rejects(
    coordinator.runOperation({ runCycleRecovery: false }, async () => assert.fail('latched operation ran')),
    (error) => error?.code === 'PROCESS_OWNERSHIP_RELEASE_FAILED',
  );
});

test('shutdown wins over a waiting release-barrier arrival', async () => {
  const releaseGate = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: releaseGate }] });
  const shutdown = { value: false };
  const coordinator = buildCoordinator({ handle: fake.handle, shutdown });

  const completed = coordinator.runOperation({ runCycleRecovery: false }, async () => 'done');
  await flush();
  let callbackRan = false;
  const waiter = coordinator.runOperation({ runCycleRecovery: false }, async () => { callbackRan = true; });
  shutdown.value = true;
  releaseGate.resolve();

  assert.equal(await completed, 'done');
  await assert.rejects(waiter, (error) => error?.code === 'SHUTTING_DOWN');
  assert.equal(callbackRan, false);
});

test('a failed arm unwinds without a release fault and a later operation retries normally', async () => {
  const armFailure = Object.assign(new Error('first arm failed'), { code: 'UNEXPECTED_ARM_FAILURE' });
  const fake = createHandle({ armSteps: [{ error: armFailure }, {}] });
  const coordinator = buildCoordinator({ handle: fake.handle });
  let failedCallbackRan = false;

  await assert.rejects(
    coordinator.runOperation({ runCycleRecovery: false }, async () => { failedCallbackRan = true; }),
    (error) => error === armFailure,
  );
  assert.equal(failedCallbackRan, false);
  assert.deepEqual(fake.releaseCalls, [], 'a failed arm acquired nothing to release');

  assert.equal(
    await coordinator.runOperation({ runCycleRecovery: false }, async ({ ownerToken }) => ownerToken.acquisitionId),
    'acquisition-1',
  );
  assert.equal(fake.armCalls.length, 2, 'the next operation must retry rather than inheriting an arm failure');
});

test('an overlapping recovery requester upgrades the shared cycle and the next serial cycle recovers again', async () => {
  const armGate = deferred();
  const firstRecovery = deferred();
  const recoveryTokens = [];
  const fake = createHandle({ armSteps: [{ gate: armGate }, {}] });
  const coordinator = buildCoordinator({
    handle: fake.handle,
    runCycleWork: async ({ ownerToken }) => {
      recoveryTokens.push(ownerToken);
      if (recoveryTokens.length === 1) await firstRecovery.promise;
    },
  });
  const first = coordinator.runOperation({ runCycleRecovery: false }, async ({ ownerToken }) => ownerToken.acquisitionId);
  const joiner = coordinator.runOperation({ runCycleRecovery: true }, async ({ ownerToken }) => ownerToken.acquisitionId);

  armGate.resolve();
  await flush();
  assert.equal(recoveryTokens.length, 1, 'the recovery requester upgrades the one shared arming cycle');
  firstRecovery.resolve();
  assert.deepEqual(await Promise.all([first, joiner]), ['acquisition-1', 'acquisition-1']);

  assert.equal(
    await coordinator.runOperation({ runCycleRecovery: true }, async ({ ownerToken }) => ownerToken.acquisitionId),
    'acquisition-2',
  );
  assert.deepEqual(
    recoveryTokens.map((token) => token.acquisitionId),
    ['acquisition-1', 'acquisition-2'],
    'a serial operation arms a fresh cycle and runs its requested recovery once',
  );
});

test('multiple barrier waiters cannot use the retiring token and share the fresh arm', async () => {
  const firstRelease = deferred();
  const secondRelease = deferred();
  const secondOperation = deferred();
  const thirdOperation = deferred();
  const tokens = [];
  let coordinator;
  let second;
  let third;
  const fake = createHandle({
    releaseSteps: [{
      gate: firstRelease,
      onStart: () => {
        second = coordinator.runOperation({ runCycleRecovery: false }, async ({ ownerToken }) => {
          tokens.push(['second', ownerToken.acquisitionId]);
          await secondOperation.promise;
        });
        third = coordinator.runOperation({ runCycleRecovery: false }, async ({ ownerToken }) => {
          tokens.push(['third', ownerToken.acquisitionId]);
          await thirdOperation.promise;
        });
      },
    }, { gate: secondRelease }],
  });
  coordinator = buildCoordinator({ handle: fake.handle });

  const first = coordinator.runOperation({ runCycleRecovery: false }, async ({ ownerToken }) => {
    tokens.push(['first', ownerToken.acquisitionId]);
    return 'first';
  });
  await flush();
  assert.equal(fake.releaseCalls.length, 1, 'the first operation creates the retirement barrier');
  assert.deepEqual(tokens, [['first', 'acquisition-1']], 'barrier waiters are not admitted into cycle one');
  assert.notEqual(second, undefined);
  assert.notEqual(third, undefined);
  firstRelease.resolve();
  await flush();
  assert.deepEqual(tokens.slice(1).map(([, token]) => token), ['acquisition-2', 'acquisition-2']);
  assert.equal(fake.armCalls.length, 2, 'both waiters join the fresh arm rather than racing it');

  secondOperation.resolve();
  await flush();
  assert.equal(fake.releaseCalls.length, 1, 'the first fresh-cycle completion cannot release while another waiter is active');
  thirdOperation.resolve();
  await flush();
  assert.equal(fake.releaseCalls.length, 2, 'the final waiter starts the next barrier');
  secondRelease.resolve();
  await Promise.all([first, second, third]);
});

test('a synchronous callback throw still releases and preserves its exact error', async () => {
  const fake = createHandle();
  const coordinator = buildCoordinator({ handle: fake.handle });
  const callbackFailure = new Error('synchronous callback failure');

  await assert.rejects(
    coordinator.runOperation({ runCycleRecovery: false }, () => { throw callbackFailure; }),
    (error) => error === callbackFailure,
  );
  assert.deepEqual(fake.releaseCalls, [{ final: false, generation: 1, stateAtCall: 'armed' }]);
  assert.equal(fake.handle.state, 'unarmed');
});

test('a missing acquired token fails closed before the callback and releases the acquisition', async () => {
  const fake = createHandle({ malformedToken: true });
  const coordinator = buildCoordinator({ handle: fake.handle });
  let callbackRan = false;

  await assert.rejects(
    coordinator.runOperation({ runCycleRecovery: false }, async () => { callbackRan = true; }),
    /owner token unavailable/,
  );
  assert.equal(callbackRan, false);
  assert.deepEqual(fake.releaseCalls, [{ final: false, generation: 1, stateAtCall: 'armed' }]);
});

test('a throwing release-fault logger cannot replace the completed result or fault latch', async () => {
  const failedRelease = deferred();
  const fake = createHandle({ releaseSteps: [{ gate: failedRelease }] });
  const coordinator = buildCoordinator({
    handle: fake.handle,
    log: () => { throw new Error('logger failure'); },
  });

  const completed = coordinator.runOperation({ runCycleRecovery: false }, async () => 'completed');
  await flush();
  failedRelease.reject(new Error('release failure'));
  assert.equal(await completed, 'completed');
  await assert.rejects(
    coordinator.runOperation({ runCycleRecovery: false }, async () => assert.fail('latched operation ran')),
    (error) => error?.code === 'PROCESS_OWNERSHIP_RELEASE_FAILED',
  );
});
