import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchOutcomeStore } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine, ReviewEngineError } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

// The shutdown lifecycle at createReviewEngine's
// EXPORT boundary -- beginShutdown() flips a closure flag that makes every subsequent
// authorizeWorkflow/review call refuse with SHUTTING_DOWN, and awaitDrain() races the still-tracked
// in-flight set against a caller-supplied timeout so the composition root can decide whether to
// release process ownership cleanly or exit while work is still outstanding.
//
// Every test here constructs the engine directly from buildMinimalEngineOptions() below rather than
// through a driving harness: the whole surface under test lives in the returned frozen object, and
// none of these tests ever needs a real preflight/lease/dispatch to exist.

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const START = Date.parse('2026-08-18T12:00:00.000Z');

// Always-clean local-LLM stand-in, matching tests/openrouter-review-engine.test.mjs's own
// passingOllama(): nothing in this file exercises scrub-engine.mjs's hard-block/smell-test logic
// (that module has its own dedicated suite), and a scrub engine that never blocks keeps these
// tests about the shutdown surface only.
function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

// The "not used in this test" convention already established in
// tests/openrouter-review-engine.test.mjs for collaborators outside a given test's scope: no test
// in this file ever reaches a real approval prompt, a real dispatch, or the repeat-authorization
// judge, so each one throws loudly rather than silently pretending to work if a future edit ever
// does reach it.
const notUsedApprovalAdapter = { async authorize() { throw new Error('not used in this test'); } };
const notUsedDispatchAdapter = { async dispatch() { throw new Error('not used in this test'); } };
const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };

/**
 * Adapted from tests/openrouter-review-engine.test.mjs's own buildMinimalEngineOptions() (which is
 * not exported -- importing that file here would re-register its entire suite inside this one).
 * Same shape and the same real collaborators where they matter: a real createLeaseStore() against a
 * fresh temp dataRoot, and a REAL ownerLock acquired against it via acquireProcessOwnership(), so
 * the engine under test is constructed exactly the way production constructs it. The adapters this
 * file never reaches are the loud "not used in this test" stubs above instead of working fakes.
 *
 * CALLER OWNS CLEANUP, exactly as in the original: `await options.ownerLock.release()` and
 * `rm(options.dataRoot, { recursive: true, force: true })` in a finally block, or the temp dir
 * leaks and the ledger's process-ownership record stays held across tests.
 */
async function buildMinimalEngineOptions() {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-shutdown-'));
  const now = START;
  const clock = () => now;
  const leaseStore = createLeaseStore({ dataRoot, clock });
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  return {
    dataRoot,
    leaseStore,
    ownerLock,
    approvalAdapter: notUsedApprovalAdapter,
    dispatchAdapter: notUsedDispatchAdapter,
    resultStore: createResultStore({ dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
    scrubMappingStore: createScrubMappingStore({ dataRoot }),
    clock,
    sourcePolicy,
    preflightPolicy,
    preflightTtlMs: 10 * 60 * 1000,
    installationHardMaximumUsd: 10,
    repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
  };
}

async function releaseOptions(options) {
  await options.ownerLock.release();
  await rm(options.dataRoot, { recursive: true, force: true });
}

/**
 * Replaces leaseStore.getLease with `getLease` on a COPY of the real store. createLeaseStore()
 * returns a frozen object, so assigning the method in place throws in this module's strict-mode
 * context; the spread copy still delegates every other method to the same closure-held ledger
 * state, so the ownerLock acquired against the original stays valid against the copy.
 */
function withGetLease(options, getLease) {
  return { ...options, leaseStore: { ...options.leaseStore, getLease } };
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolveFn, rejectFn) => { resolve = resolveFn; reject = rejectFn; });
  return { promise, resolve, reject };
}

test('awaitDrain: an idle engine (nothing tracked) drains immediately', async () => {
  const options = await buildMinimalEngineOptions();
  try {
    const engine = createReviewEngine(options);
    const result = await engine.awaitDrain({ timeoutMs: 1000 });
    assert.deepEqual(result, { drained: true, outstandingCount: 0 });
  } finally {
    await releaseOptions(options);
  }
});

test('beginShutdown: after shutdown begins, a NEW authorizeWorkflow/review call is refused with SHUTTING_DOWN, cleanly', async () => {
  const options = await buildMinimalEngineOptions();
  try {
    const engine = createReviewEngine(options);
    engine.beginShutdown();
    // Refused as a REJECTION, never a synchronous throw: a synchronous throw from the wrapper would
    // escape during argument evaluation, before any caller (including assert.rejects) ever holds a
    // promise to attach a handler to.
    await assert.rejects(
      engine.authorizeWorkflow({ preflightId: 'whatever', maxJobs: 1 }),
      (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN',
    );
    await assert.rejects(
      engine.review({ leaseId: 'whatever', preflightId: 'whatever' }),
      (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN',
    );
  } finally {
    await releaseOptions(options);
  }
});

test('awaitDrain: a slow tracked operation held open past the timeout reports drained:false with the correct outstandingCount', async () => {
  let releaseSlowCall;
  const slow = new Promise((resolve) => { releaseSlowCall = resolve; });
  const base = await buildMinimalEngineOptions();
  const options = withGetLease(base, async () => { await slow; return null; });
  try {
    const engine = createReviewEngine(options);
    const pending = engine.review({ leaseId: 'x', preflightId: 'y' }).catch(() => {});
    await new Promise((resolve) => setTimeout(resolve, 10));
    const result = await engine.awaitDrain({ timeoutMs: 50 });
    assert.equal(result.drained, false);
    assert.equal(result.outstandingCount, 1);
    releaseSlowCall();
    await pending;
  } finally {
    releaseSlowCall();
    await releaseOptions(base);
  }
});

test('a public-export waiter behind completion release is tracked with the original operation, and shutdown refuses it before its body runs', async () => {
  const base = await buildMinimalEngineOptions();
  const releaseStarted = createDeferred();
  const allowRelease = createDeferred();
  let finalReleaseCalls = 0;
  let getLeaseCalls = 0;
  const realOwnerLock = base.ownerLock;
  const gatedOwnerLock = Object.freeze({
    get dataRoot() { return realOwnerLock.dataRoot; },
    get generation() { return realOwnerLock.generation; },
    get acquisitionId() { return realOwnerLock.acquisitionId; },
    get state() { return realOwnerLock.state; },
    get everArmed() { return realOwnerLock.everArmed; },
    isOwner: () => realOwnerLock.isOwner(),
    arm: (options) => realOwnerLock.arm(options),
    async release(options) {
      if (options?.final === true) {
        finalReleaseCalls += 1;
        return realOwnerLock.release(options);
      }
      releaseStarted.resolve();
      await allowRelease.promise;
      return realOwnerLock.release(options);
    },
  });
  const options = {
    ...withGetLease(base, async () => { getLeaseCalls += 1; return null; }),
    ownerLock: gatedOwnerLock,
  };
  try {
    const engine = createReviewEngine(options);
    const first = engine.review({ leaseId: 'first-missing', preflightId: 'p' });
    await releaseStarted.promise;
    const waiter = engine.review({ leaseId: 'waiter-must-not-run', preflightId: 'p' });

    engine.beginShutdown();
    assert.deepEqual(
      await engine.awaitDrain({ timeoutMs: 50 }),
      { drained: false, outstandingCount: 2 },
      'the callback-complete operation and its barrier waiter both remain tracked',
    );
    assert.equal(finalReleaseCalls, 0, 'a drain timeout does not initiate a separate final release');
    assert.equal(getLeaseCalls, 1, 'the waiter has not entered its body');

    allowRelease.resolve();
    await assert.rejects(first, (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING');
    await assert.rejects(waiter, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
    assert.equal(getLeaseCalls, 1, 'the waiter is refused after the barrier without running its body');
    assert.deepEqual(await engine.awaitDrain({ timeoutMs: 1_000 }), { drained: true, outstandingCount: 0 });

    await gatedOwnerLock.release({ final: true });
    assert.equal(finalReleaseCalls, 1, 'the composition-root finalizer remains the one final-release authority');
  } finally {
    allowRelease.resolve();
    await releaseOptions(base);
  }
});

test('awaitDrain: once the slow operation completes, a later awaitDrain reports drained:true', async () => {
  let resolveGetLease;
  const base = await buildMinimalEngineOptions();
  const options = withGetLease(base, async () => new Promise((resolve) => { resolveGetLease = resolve; }));
  try {
    const engine = createReviewEngine(options);
    const pending = engine.review({ leaseId: 'x', preflightId: 'y' }).catch(() => {});
    await new Promise((resolve) => setTimeout(resolve, 10));
    resolveGetLease(null);
    await pending;
    const result = await engine.awaitDrain({ timeoutMs: 1000 });
    assert.deepEqual(result, { drained: true, outstandingCount: 0 });
  } finally {
    await releaseOptions(base);
  }
});

test('awaitDrain: requires a non-negative safe integer timeoutMs', async () => {
  const options = await buildMinimalEngineOptions();
  try {
    const engine = createReviewEngine(options);
    await assert.rejects(engine.awaitDrain({ timeoutMs: -1 }), TypeError);
    await assert.rejects(engine.awaitDrain({}), TypeError);
  } finally {
    await releaseOptions(options);
  }
});

// Production-crash guard, not a style point. trackInFlight() registers its bookkeeping on a DERIVED
// promise (`promise.finally(...)`), and that derived promise is the engine's own -- no caller ever
// holds it. If the tracked operation rejects (LEASE_EXPIRED, APPROVAL_DENIED, CONTENT_BLOCKED, or
// the SHUTTING_DOWN path itself -- all routine), the derived promise rejects with
// nothing attached to handle it, and Node's default since v15 (--unhandled-rejections=throw) would
// take down the whole MCP server on an ordinary refusal. The caller still receives, and must still
// handle, the original promise; only the engine's private derived promise is silenced here.
test('trackInFlight: a tracked operation that rejects never surfaces as an unhandledRejection', async () => {
  const options = await buildMinimalEngineOptions();
  const unhandled = [];
  const onUnhandledRejection = (reason) => { unhandled.push(reason); };
  // Registering a listener also suppresses the default throw-and-crash behavior for the duration of
  // this test, so a regression is captured and asserted on rather than killing the test process.
  process.on('unhandledRejection', onUnhandledRejection);
  try {
    const engine = createReviewEngine(options);
    // An entirely ordinary production rejection: no lease with this id exists.
    await assert.rejects(
      engine.review({ leaseId: 'no-such-lease', preflightId: 'whatever' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING',
    );
    // Node reports an unhandled rejection on a later turn of the event loop, not at the same
    // microtask checkpoint -- give it real turns to fire before asserting that it did not.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(unhandled, [], 'a rejecting tracked operation must not produce an unhandledRejection');
  } finally {
    process.removeListener('unhandledRejection', onUnhandledRejection);
    await releaseOptions(options);
  }
});

// Counts only pending TIMERS, so a test can assert awaitDrain() left none of its own behind.
// process.getActiveResourcesInfo() (Node >= 17) reports one 'Timeout' entry per live setTimeout
// handle, which makes the "did clearTimeout actually run" question directly observable instead of
// something only a wall-clock process-exit measurement can see.
function countPendingTimeouts() {
  return process.getActiveResourcesInfo().filter((resource) => resource === 'Timeout').length;
}

// The NON-VACUOUS drain test. Its neighbour above ("once the slow operation completes, a later
// awaitDrain reports drained:true") awaits the operation BEFORE calling awaitDrain, so by then the
// tracked set is already empty and awaitDrain returns on its `tracked.length === 0` early return
// without ever racing anything -- measured directly: that test still passes with the delete-on-settle
// bookkeeping removed entirely, so it cannot witness the drain path at all. This one calls awaitDrain
// while the operation is genuinely still in flight, so the set is non-empty, the timeout timer really
// is created, and Promise.allSettled really does have to wait.
//
// It doubles as the only coverage of the clearTimeout in awaitDrain's finally block: a drained
// awaitDrain that leaves its own timer pending keeps Node's event loop alive for the remainder of the
// caller's budget, which for a helper whose entire purpose is letting the process exit promptly
// defeats the point. Removing that clearTimeout leaves every other test in this file green.
test('awaitDrain: an operation still in flight AT CALL TIME drains, and the timeout timer is not left pending', async () => {
  let resolveGetLease;
  const base = await buildMinimalEngineOptions();
  const options = withGetLease(base, async () => new Promise((resolve) => { resolveGetLease = resolve; }));
  try {
    const engine = createReviewEngine(options);
    const pending = engine.review({ leaseId: 'x', preflightId: 'y' }).catch(() => {});
    // Let review() reach the hanging getLease so the operation is genuinely registered as in flight.
    await new Promise((resolve) => setTimeout(resolve, 10));

    // Sampled immediately either side of the awaitDrain call, with no setTimeout of this test's own in
    // between, so the only timer that can account for a difference is awaitDrain's own.
    const timeoutsBefore = countPendingTimeouts();
    const draining = engine.awaitDrain({ timeoutMs: 30_000 });
    resolveGetLease(null);
    const result = await draining;
    const timeoutsAfter = countPendingTimeouts();

    assert.deepEqual(result, { drained: true, outstandingCount: 0 });
    assert.equal(
      timeoutsAfter,
      timeoutsBefore,
      'a drained awaitDrain must clear its own timeout timer, not leave it pending for the full budget',
    );
    await pending;
  } finally {
    if (resolveGetLease) resolveGetLease(null);
    await releaseOptions(base);
  }
});

// Proves the delete-on-settle bookkeeping in trackInFlight() actually runs. Nothing else does:
// awaitDrain's drained path reports { drained: true, outstandingCount: 0 } whether or not settled
// operations were ever removed from the set, because Promise.allSettled() over an already-settled
// promise resolves immediately regardless of whether that promise is still a member. The TIMEOUT path
// is the one place the set's real contents are read back out (`outstandingCount:
// inFlightOperations.size`), so it is the only place a stale entry can be caught.
//
// The consequence this guards is not cosmetic: the server's shutdown sequence branches on
// outstandingCount to choose between releasing process ownership cleanly and exiting with work still
// running, and an ever-growing set of settled promises also never releases their memory in a
// long-lived server process.
test('awaitDrain: outstandingCount counts only genuinely-outstanding work, not operations that already settled', async () => {
  const secondGetLeaseEntered = createDeferred();
  const secondGetLeaseResult = createDeferred();
  let stillRunning;
  let getLeaseCalls = 0;
  const base = await buildMinimalEngineOptions();
  const options = withGetLease(base, async () => {
    getLeaseCalls += 1;
    // First operation settles immediately (a null lease rejects as LEASE_MISSING); the second hangs
    // until this test releases it, so exactly one operation is genuinely outstanding.
    if (getLeaseCalls === 1) return null;
    secondGetLeaseEntered.resolve();
    return secondGetLeaseResult.promise;
  });
  try {
    const engine = createReviewEngine(options);
    await engine.review({ leaseId: 'settled', preflightId: 'y' }).catch(() => {});
    stillRunning = engine.review({ leaseId: 'slow', preflightId: 'y' }).catch(() => {});
    // Ownership is released after each operation and re-armed before the second callback. Observe
    // entry instead of assuming filesystem acquisition and replay fit within an arbitrary scheduling
    // delay under full-suite load.
    await secondGetLeaseEntered.promise;

    const result = await engine.awaitDrain({ timeoutMs: 50 });

    assert.equal(result.drained, false);
    assert.equal(
      result.outstandingCount,
      1,
      'the already-settled first operation must have been removed from the tracked set',
    );
    secondGetLeaseResult.resolve(null);
    await stillRunning;
  } finally {
    secondGetLeaseResult.resolve(null);
    await stillRunning;
    await releaseOptions(base);
  }
});

/** Same spread-copy trick as withGetLease, for the first await inside recoverStaleLease(). */
function withFindStaleReservedJobs(options, findStaleReservedJobs) {
  return { ...options, leaseStore: { ...options.leaseStore, findStaleReservedJobs } };
}

// recoverOrphanedLeases is the THIRD owner-sensitive entry point, so it is wrapped like the other two.
// It is not a read: recoverStaleLease() reconciles and closes leases with ownerLock.acquisitionId,
// so an unwrapped export would let a drain report itself complete -- and the composition root then release
// process ownership -- while those owner-fenced writes were still in flight.
//
// Both halves are asserted here because they fail independently: trackInFlight alone would let a
// fresh sweep start during shutdown, and refuseIfShuttingDown alone would leave an already-running
// sweep uncounted by the drain.
test('recoverOrphanedLeases: counted by awaitDrain while in flight, and refused once shutdown begins', async () => {
  let releaseSweep;
  const base = await buildMinimalEngineOptions();
  const options = withFindStaleReservedJobs(base, async () => {
    await new Promise((resolve) => { releaseSweep = resolve; });
    return [];
  });
  try {
    const engine = createReviewEngine(options);
    const sweeping = engine.recoverOrphanedLeases();
    // Let the sweep reach the hanging findStaleReservedJobs so it is genuinely in flight.
    await new Promise((resolve) => setTimeout(resolve, 10));

    const timedOut = await engine.awaitDrain({ timeoutMs: 50 });
    assert.equal(timedOut.drained, false);
    assert.equal(
      timedOut.outstandingCount,
      1,
      'an in-flight store-wide sweep performs owner-fenced writes and must be counted by the drain',
    );

    releaseSweep();
    await sweeping;

    engine.beginShutdown();
    // A rejection, not a synchronous throw, for the same reason the other two wrappers are async.
    await assert.rejects(
      engine.recoverOrphanedLeases(),
      (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN',
    );
  } finally {
    if (releaseSweep) releaseSweep();
    await releaseOptions(base);
  }
});
