import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore, LEDGER_DATA_ROOT_LOCKED_CODE } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import {
  createReviewEngine, LEDGER_BUSY_RECONCILE_RETRY_BASE_MS, LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS, ReviewEngineError,
} from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { USD } from './helpers/scanner-safe-fixtures.mjs';

// End-to-end coverage for parallel reviewer dispatch. Each edge case, failure mode and success
// criterion of that design is covered either here or in the two unit files
// (openrouter-review-reserve-phase.test.mjs, openrouter-review-finalize.test.mjs).
//
// This file carries its own withEngine harness rather than importing one, matching the convention
// every other engine test file in this directory already follows. Fully offline: fake dispatch
// adapter, fake approval adapter, no OpenRouter request, no credential.

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const START = Date.parse('2026-08-31T12:00:00.000Z');

const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

function geminiPassBody(findings = []) {
  return { provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.01 } };
}

function grokPassBody(findings = []) {
  return { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.02 } };
}

function providerMismatchBody() {
  return { provider: 'NotGoogle', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.01 } };
}

function responseEnvelope(body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

function failureEnvelope(failureKind, message) {
  return Object.freeze({ kind: 'FAILURE', envelopeJsonText: JSON.stringify({ failureKind, message }) });
}

function passBodyFor(reviewerId) {
  return reviewerId === 'gemini' ? geminiPassBody() : grokPassBody();
}

/**
 * Mirrors review-engine.mjs's own private deriveJobId() (not exported), matching the same
 * deliberate re-derivation-not-import convention tests/openrouter-review-engine.test.mjs already
 * uses: drift in that formula makes these tests fail loudly via an unexpected real dispatch rather
 * than silently passing.
 */
function testDeriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8').digest('hex');
}

/** A promise a test can resolve from the outside, to pin down settle order deterministically. */
function createDeferred() {
  let resolveFn;
  const promise = new Promise((resolve) => { resolveFn = resolve; });
  return { promise, resolve: () => resolveFn() };
}

/**
 * Polls a real-time condition with a hard deadline. Used to observe intermediate ledger state
 * WHILE a review() call is still in flight -- e.g. "gemini has already reconciled but the lease is
 * still ACTIVE". Bounded so a regression fails with a readable message instead of hanging the
 * whole suite forever.
 *
 * `condition()` itself is allowed to throw transiently: a condition that reads the ledger (e.g.
 * `leaseStore.getJob()`) shares the SAME exclusive cross-process data-root lock a concurrently
 * running review() dispatch is also holding, and can legitimately throw "ledger data root is
 * locked" after exhausting its own internal lock-wait budget while this loop's outer polling
 * budget still has time left. That is contention, not a real failure, so it is swallowed and
 * retried like an ordinary false-returning check. If `condition()` keeps throwing all the way to
 * the deadline -- which would also happen for a genuine bug in the code under test, not just lock
 * contention -- the final timeout error carries the LAST caught error's message rather than a bare
 * "timed out", so that failure stays diagnosable instead of looking like an unexplained hang.
 */
async function waitFor(condition, description, { timeoutMs = 5_000, intervalMs = 5 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    try {
      if (await condition()) return;
      lastError = undefined;
    } catch (error) {
      lastError = error;
    }
    if (Date.now() > deadline) {
      const detail = lastError ? ` (last error from condition(): ${lastError.message})` : '';
      throw new Error(`timed out waiting for: ${description}${detail}`);
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => { setTimeout(resolve, intervalMs); });
  }
}

function createFakeKeyStatusProbe() {
  const state = { calls: 0 };
  return Object.freeze({
    state,
    async check() {
      state.calls += 1;
      return { limit: null, limitRemaining: null, limitReset: null };
    },
  });
}

/**
 * Wraps a real lease store, recording every close() and consume() call so a test can assert the
 * lease was closed EXACTLY once, or that a particular reviewer's job was never re-reserved. Can
 * also inject behavior into consume() and findJobsForReviewerContract(), which is what makes the
 * mid-Step-2 stop scenarios (a lease expiring between two reservations, a duplicate appearing
 * between Step 1 and Step 2) reachable without any real timing.
 *
 * The two consume hooks are deliberately distinct and NOT interchangeable. `onConsume` runs BEFORE
 * the real reservation, so it is the one that can make a reservation fail. `afterConsume` runs only
 * after a reservation has genuinely succeeded, which is the only correct place to advance the clock
 * past the lease's expiry: advancing it beforehand would make lease-store's own expiry check inside
 * consume() reject THIS reviewer's reservation, which is a different scenario entirely.
 */
function wrapLeaseStore(inner, {
  onConsume, afterConsume, onFindJobs, onGetJob,
} = {}) {
  const closes = [];
  const consumes = [];
  const findJobsCalls = [];
  return {
    closes,
    consumes,
    findJobsCalls,
    ...inner,
    async close(leaseId, state, options) {
      closes.push({ leaseId, state });
      // Forwards `options` (carrying { acquisitionId }) through: acquisitionId is a required
      // argument of the real close(), so a wrapper that passed only the first two positional args
      // would silently break every real close() call.
      return inner.close(leaseId, state, options);
    },
    async consume(leaseId, reviewContractSha256, options) {
      consumes.push({ reviewerId: options.reviewerId, jobId: options.jobId });
      if (onConsume) {
        const override = await onConsume(options);
        if (override !== undefined) return override;
      }
      const job = await inner.consume(leaseId, reviewContractSha256, options);
      if (afterConsume) await afterConsume(options);
      return job;
    },
    async findJobsForReviewerContract(reviewContractSha256, reviewerId) {
      const callIndexForReviewer = findJobsCalls.filter((entry) => entry.reviewerId === reviewerId).length;
      findJobsCalls.push({ reviewerId, callIndexForReviewer });
      if (onFindJobs) {
        const override = await onFindJobs({ reviewerId, callIndexForReviewer });
        if (override !== undefined) return override;
      }
      return inner.findJobsForReviewerContract(reviewContractSha256, reviewerId);
    },
    async getJob(jobId) {
      if (onGetJob) {
        const override = await onGetJob({ jobId });
        if (override !== undefined) return override;
      }
      return inner.getJob(jobId);
    },
  };
}

async function withEngine(run, {
  dispatch, wrapStore, keyStatusProbe, wrapScrubMappingStore, dispatchHealthStore, sleep, monotonicNow,
} = {}) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-parallel-'));
  let now = START;
  const clock = () => now;
  const advance = (ms) => { now += ms; };
  const baseLeaseStore = createLeaseStore({ dataRoot, clock });
  // A REAL ownerLock, since this leaseStore is real.
  // Acquired against the BASE (unwrapped) store, before any test-specific wrapStore() wrapping --
  // wrapLeaseStore() above spreads `...inner` for every non-overridden method, so the acquisitionId
  // this returns stays valid against `leaseStore` regardless of wrapping.
  const ownerLock = await baseLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const leaseStore = wrapStore ? wrapStore(baseLeaseStore, { advance }) : baseLeaseStore;
  const fakeKeyStatusProbe = keyStatusProbe ?? createFakeKeyStatusProbe();
  const baseScrubMappingStore = createScrubMappingStore({ dataRoot });
  const scrubMappingStore = wrapScrubMappingStore ? wrapScrubMappingStore(baseScrubMappingStore) : baseScrubMappingStore;
  // Defaults to the REAL durable store (mirrors openrouter-review-engine-alerts.test.mjs's own
  // withAlertEngine convention) so a test can read its state file directly after review() returns,
  // without every existing test in this file needing to know or care that it exists.
  const healthStore = dispatchHealthStore ?? createDispatchHealthStore({ dataRoot });
  const engine = createReviewEngine({
    leaseStore,
    ownerLock,
    approvalAdapter: { async authorize() { return { outcome: 'APPROVED', nonce: 'fake-nonce' }; } },
    dispatchAdapter: dispatch,
    resultStore: createResultStore({ dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
    scrubMappingStore,
    clock,
    sourcePolicy,
    preflightPolicy,
    preflightTtlMs: 10 * 60 * 1000,
    installationHardMaximumUsd: 10,
    repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    keyStatusProbe: fakeKeyStatusProbe,
    dispatchHealthStore: healthStore,
    // A test that passes `sleep` receives the engine's retry sleeps, together with
    // this harness's `advance`, so a fake sleep can spend each delay on the fake clock. Without one,
    // the engine keeps its default real-timer sleep.
    ...(sleep ? { sleep: (ms) => sleep(ms, { advance }) } : {}),
    ...(monotonicNow === undefined ? {} : { monotonicNow }),
  });
  try {
    await run({
      engine, leaseStore, ownerLock, dataRoot, advance, keyStatusProbe: fakeKeyStatusProbe, dispatchHealthStore: healthStore,
    });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function preflightAndAuthorize(engine, {
  source_text = 'x', profile = 'consequential_spec_v1', changeKinds, maxJobs = 2,
  reviewContext = 'parallel dispatch test scope',
} = {}) {
  const preflight = await engine.preflight({ source_text, profile, changeKinds, reviewContext });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs });
  return { preflight, leaseId: authorization.leaseId, preflightId: preflight.preflightId };
}

// ---------------------------------------------------------------------------
// Step 4: haltAndClose() no longer closes the lease.
// ---------------------------------------------------------------------------

// Documents the concrete hazard the Step-4 change exists to remove, at the store level, so the
// engine-level assertion below is not resting on an assumed property of leaseStore.
test('the lease store itself rejects a second close, which is exactly why only one place may close a lease', async () => {
  const dispatch = { async dispatch() { return responseEnvelope(geminiPassBody()); } };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { leaseId } = await preflightAndAuthorize(engine);
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    await leaseStore.close(leaseId, 'TRANSPORT_FAILURE', { acquisitionId: ownerLock.acquisitionId });
    await assert.rejects(
      () => leaseStore.close(leaseId, 'TRANSPORT_FAILURE', { acquisitionId: ownerLock.acquisitionId }),
      (error) => error.message === 'lease is closed',
    );
  }, { dispatch });
});

test('a halted review() closes its lease exactly once, so a halting reviewer never leaves a second close for a sibling to trip over', async () => {
  const dispatch = { async dispatch() { return failureEnvelope('TIMEOUT', 'the request did not complete before the deadline'); } };
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'TRANSPORT_FAILURE' }]);
    assert.equal((await leaseStore.getLease(leaseId)).state, 'TRANSPORT_FAILURE');
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// ---------------------------------------------------------------------------
// Step 3: one reviewer's halt no longer prevents its siblings.
// ---------------------------------------------------------------------------

// The central behavior of parallel dispatch (Step 3): one reviewer's ordinary halt must not stop
// the reviewers after it in profile order from being attempted. A sequential loop that stopped on
// the first halt would be an artifact of its structure rather than a cost-saving feature -- every
// other part of this codebase already tracks cost and results per reviewer independently.
test('a first reviewer halting no longer prevents a later reviewer from dispatching and passing', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      if (request.reviewerId === 'gemini') return failureEnvelope('TIMEOUT', 'gemini timed out');
      return responseEnvelope(grokPassBody());
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
    assert.equal(result.reviewers.gemini.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
    assert.equal(Object.hasOwn(result.reviewers.grok, 'error'), false);
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'TRANSPORT_FAILURE' }]);
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// ---------------------------------------------------------------------------
// Regressions: Step 1's batchStop handling must not orphan reserved money, and the Step 3
// rejection handler must report a reviewer's real reconciled status.
// ---------------------------------------------------------------------------

// Regression: Step 1's batch-wide stop (a LATER reviewer tripping the cross-lease
// duplicate-in-progress check, or the lease-expiry check) must not close the lease and return
// immediately -- that would abandon an EARLIER reviewer in that exact same pass that was already
// queued onto needsRedispatch or ambiguousDispatching with a real pre-existing RESERVED job from an
// interrupted earlier review() call. Once the lease closed, that job would be permanently
// unrecoverable (sweepOrphanedLeases() only ever recovers a job under an ACTIVE lease, and review()
// refuses to re-enter a non-ACTIVE lease at all) -- and every FUTURE review() call for the same
// document would immediately re-hit the same batch-wide stop on that same still-RESERVED job (the
// duplicate check matches on `state === 'RESERVED'` regardless of which lease owns it), permanently
// blocking the document from ever completing review through this pipeline again.
test('a later reviewer tripping the cross-lease duplicate-in-progress batch stop does not abandon an earlier reviewer already queued for redispatch on THIS lease', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(geminiPassBody());
    },
  };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const { reviewContractSha256 } = preflight;
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;

    // Simulate gemini already holding a RESERVED job under THIS SAME lease, from an earlier
    // review() call that was interrupted before it could ever dispatch or reconcile (the "no
    // capture of ANY kind" case review()'s own existingJob recovery routes onto needsRedispatch).
    // Money is reserved for this job the instant this call succeeds.
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', reviewContractSha256);
    await leaseStore.consume(leaseId, reviewContractSha256, {
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
    });
    assert.equal((await leaseStore.getJob(geminiJobId)).state, 'RESERVED', 'sanity: gemini genuinely has a pending reservation before review() ever runs');

    // grok (later in profile order) trips the batch-wide DUPLICATE_DISPATCH_IN_PROGRESS stop --
    // simulating a genuinely in-flight RESERVED job for grok under some OTHER lease.
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');
    assert.equal(result.error.message.includes('grok'), true, 'the batch-wide stop must still name the LATER reviewer that actually tripped it, not gemini');

    // gemini's pending reservation must reach Step 3 and genuinely redispatch and
    // reconcile, exactly as if the batch-wide stop had never fired for grok. grok itself must never
    // dispatch -- it never got fresh-reserved, and nothing recovers it here.
    assert.deepEqual(dispatch.calls, [{ reviewerId: 'gemini' }]);
    assert.equal(result.reviewers.gemini.state, 'RECONCILED', 'gemini must reach a real terminal state, not stay stuck RESERVED forever');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.gemini.costUsd, 0.01);
    assert.equal(Object.hasOwn(result.reviewers, 'grok'), false);

    const geminiJobAfter = await leaseStore.getJob(geminiJobId);
    assert.equal(geminiJobAfter.state, 'RECONCILED', 'the ledger itself must show gemini reconciled, never permanently stuck RESERVED under a now-closed lease');

    const leaseAfter = await leaseStore.getLease(leaseId);
    assert.equal(leaseAfter.state, 'DUPLICATE_DISPATCH_IN_PROGRESS');
  }, {
    dispatch,
    wrapStore: (inner) => wrapLeaseStore(inner, {
      onFindJobs: async ({ reviewerId }) => {
        if (reviewerId === 'grok') return [{ id: 'other-lease-grok-job', state: 'RESERVED' }];
        return undefined;
      },
    }),
  });
});

// Same regression, the OTHER batch-wide stop condition (lease expiry instead of cross-lease
// duplicate) -- exercises the stopReason mapping's other branch (batchStop.code 'LEASE_EXPIRED'
// passes straight through, unlike 'DUPLICATE_DISPATCH_IN_PROGRESS' which is renamed to
// 'DUPLICATE_IN_PROGRESS' for decideFinalReviewOutcome).
test('a later reviewer tripping the batch-wide lease-expiry stop does not abandon an earlier reviewer already queued for redispatch on THIS lease', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(geminiPassBody());
    },
  };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const { reviewContractSha256 } = preflight;
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;

    const geminiJobId = testDeriveJobId(leaseId, 'gemini', reviewContractSha256);
    await leaseStore.consume(leaseId, reviewContractSha256, {
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
    });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'LEASE_EXPIRED');
    assert.deepEqual(dispatch.calls, [{ reviewerId: 'gemini' }]);
    assert.equal(result.reviewers.gemini.state, 'RECONCILED', 'gemini must reach a real terminal state, not stay stuck RESERVED forever');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');

    const geminiJobAfter = await leaseStore.getJob(geminiJobId);
    assert.equal(geminiJobAfter.state, 'RECONCILED');
    assert.equal((await leaseStore.getLease(leaseId)).state, 'LEASE_EXPIRED');
  }, {
    dispatch,
    // preflightTtlMs (and so the lease's own expiresAt) is 10 minutes past START in this file's
    // withEngine harness; advancing 11 minutes during grok's own findJobsForReviewerContract check
    // (called AFTER the top-of-review() expiry check already passed, using the same fixed
    // leaseExpiresAtMs) makes Step 1's per-reviewer expiry check trip for grok specifically,
    // without the initial guard clause ever seeing it.
    wrapStore: (inner, { advance }) => wrapLeaseStore(inner, {
      onFindJobs: async ({ reviewerId }) => {
        if (reviewerId === 'grok') {
          advance(11 * 60 * 1000);
          return [];
        }
        return undefined;
      },
    }),
  });
});

// Regression: the Step 3 rejection handler's own recovery reconcile() call throws `job is not
// reserved` whenever a rejected task's job is no longer RESERVED -- most commonly because
// processDispatchOutcome's OWN reconcile() already succeeded for real (known cost, known costKind)
// before a LATER step in that same function threw (scrubMappingStore.recall(), the JSON.parse of
// the advisory body, or desubstituteFinding() -- none wrapped in a try/catch). Falling straight
// through to the bare RESERVED/zero-cost/RECOVERED_STATUS_ONLY stub in exactly that case would misreport
// a reviewer's status even though the ledger already knows its real, final outcome.
test(`a rejection AFTER a successful reconcile reports the reviewer's real reconciled state and cost, not a bare RESERVED/${USD}0 stub`, async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  const recallError = new Error('simulated scrubMappingStore.recall failure after a successful reconcile');
  await withEngine(async ({ engine, leaseStore }) => {
    // final_verification_v1 with an empty changeKinds dispatches grok alone (no changeKind maps to
    // an extra reviewer), isolating this scenario to exactly one reviewer's rejection.
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.grok.error.code, 'DISPATCH_UNKNOWN');
    // safeErrorDetail() redacts the raw rejection text; the returned result must carry only the
    // safe marker, here the generic 'Error' label (recallError is a plain Error with no recognized
    // .code).
    assert.equal(result.reviewers.grok.error.message.includes(recallError.message), false, 'the raw rejection text must never reach the returned result');
    assert.ok(result.reviewers.grok.error.message.includes('Error (detail redacted)'));
    // Report the reviewer's REAL reconciled state/cost/costKind from the ledger, not the
    // bare stub -- the ledger already knows the truth even though the advisory content itself was
    // lost to the post-reconcile throw.
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok.costUsd, 0.02);

    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const ledgerJob = await leaseStore.getJob(grokJobId);
    assert.equal(ledgerJob.state, 'RECONCILED');
    assert.equal(ledgerJob.costUsd, 0.02, 'sanity: the reported entry must come from this exact real ledger record, not be fabricated');
  }, {
    dispatch,
    wrapScrubMappingStore: (inner) => ({
      ...inner,
      async recall() { throw recallError; },
    }),
  });
});

// Regression: the read-back covered directly above calls leaseStore.getJob(task.jobId) inside the
// recovery reconcile's own catch block. getJob() is a real fallible operation -- it goes through
// leaseStore's mutate(), a cross-process file lock plus a full ledger replay from disk -- and can
// throw on I/O error or a corrupted ledger record. An unguarded getJob() throw there would escape
// the whole rejection-handling loop and review() itself, skipping finalizeReviewOutcome() entirely
// -- contradicting that code block's own stated invariant that a failure there "must never crash
// the batch or leave finalization unreached".
test(`a getJob() failure during the rejection handler's recovery read-back does not crash review(), and falls back to the bare RESERVED/${USD}0 stub`, async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  const recallError = new Error('simulated scrubMappingStore.recall failure after a successful reconcile');
  const getJobError = new Error('simulated leaseStore.getJob failure (I/O error reading the ledger)');
  await withEngine(async ({ engine, leaseStore }) => {
    // final_verification_v1 with an empty changeKinds dispatches grok alone (no changeKind maps to
    // an extra reviewer), isolating this scenario to exactly one reviewer's rejection -- same setup
    // as the sibling test above, so the only extra variable is the getJob() failure itself.
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });

    // review() itself must resolve, not reject, even though the recovery read-back's own getJob()
    // call throws.
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.grok.error.code, 'DISPATCH_UNKNOWN');
    // safeErrorDetail() redacts the raw rejection text; the returned result must carry only the
    // safe marker, here the generic 'Error' label (recallError is a plain Error with no recognized
    // .code), the same marker the stderr log for this site carries.
    assert.equal(result.reviewers.grok.error.message.includes(recallError.message), false, 'the raw rejection text must never reach the returned result');
    assert.ok(result.reviewers.grok.error.message.includes('Error (detail redacted)'));
    // A failed read-back falls through to the SAME bare stub used when the job genuinely doesn't exist or is
    // still RESERVED -- a getJob() failure must be indistinguishable from "couldn't determine the
    // real state," not a new special case.
    assert.equal(result.reviewers.grok.state, 'RESERVED');
    assert.equal(result.reviewers.grok.costUsd, 0);
    assert.equal(result.reviewers.grok.costKind, 'RECOVERED_STATUS_ONLY');

    // Sanity: the real ledger job is genuinely RECONCILED underneath (processDispatchOutcome's own
    // reconcile() really did succeed before the recall() throw) -- the stub above is a reporting
    // fallback caused by the read-back itself failing, not a reflection of real ledger state. This
    // is the THIRD getJob() call overall, so it does not trip the injected failure (which only fires
    // on the second) and passes through to the real store.
    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const ledgerJobAfter = await leaseStore.getJob(grokJobId);
    assert.equal(ledgerJobAfter.state, 'RECONCILED');
  }, {
    dispatch,
    wrapScrubMappingStore: (inner) => ({
      ...inner,
      async recall() { throw recallError; },
    }),
    // Fails only the SECOND getJob() call. The first is Step 1's own existingJob check (one call
    // per reviewer, and this profile dispatches grok alone); the second is the rejection handler's
    // recovery read-back under test. A plain call counter is deterministic here specifically because
    // this scenario is scoped to a single reviewer -- it is not a general-purpose stand-in for "the
    // Nth getJob call across any profile".
    wrapStore: (inner) => {
      let getJobCalls = 0;
      return {
        ...inner,
        async getJob(jobId) {
          getJobCalls += 1;
          if (getJobCalls === 2) throw getJobError;
          return inner.getJob(jobId);
        },
      };
    },
  });
});

// ---------------------------------------------------------------------------
// Success criteria: dispatch is genuinely concurrent, and the lease closes once, at the end.
// ---------------------------------------------------------------------------

/**
 * Holds every dispatch inside the adapter until `expected` of them are simultaneously in flight,
 * then releases them all -- and records the high-water mark. Under genuinely concurrent dispatch
 * that mark reaches `expected` immediately. Under sequential dispatch it can never exceed 1, and
 * the bounded release timer keeps the run from hanging so the failure reports a readable
 * `maxInFlight` of 1 instead of stalling the suite.
 */
function createConcurrencyProbingDispatch({ expected, releaseAfterMs = 2_000 }) {
  const calls = [];
  const state = { inFlight: 0, maxInFlight: 0 };
  let releaseAll;
  const allEntered = new Promise((resolve) => { releaseAll = resolve; });
  return {
    calls,
    state,
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId });
      state.inFlight += 1;
      state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
      if (state.inFlight >= expected) releaseAll();
      const timer = setTimeout(releaseAll, releaseAfterMs);
      try {
        await allEntered;
      } finally {
        clearTimeout(timer);
        state.inFlight -= 1;
      }
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
}

test('every reviewer that needs dispatching is in flight at the same time, not one after another', async () => {
  const dispatch = createConcurrencyProbingDispatch({ expected: 2 });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.equal(dispatch.state.maxInFlight, 2, 'both reviewers must be in flight simultaneously; a max of 1 means dispatch is still sequential');
    // Dispatch ORDER stays deterministic and matches profile order even though the calls overlap --
    // Promise.allSettled invokes each task synchronously in array order, and Step 3 builds that
    // array in profile order.
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
  }, { dispatch });
});

test('the lease stays open while a sibling is still in flight and closes only after every reviewer has settled', async () => {
  const grokGate = createDeferred();
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      if (request.reviewerId === 'gemini') return failureEnvelope('TIMEOUT', 'gemini timed out');
      await grokGate.promise;
      return responseEnvelope(grokPassBody());
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine);
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);

    const reviewPromise = engine.review({ leaseId, preflightId, source_text: 'x' });
    await waitFor(
      async () => (await leaseStore.getJob(geminiJobId))?.state === 'RECONCILED',
      'gemini to finish its own halt bookkeeping while grok is still gated',
    );
    // The whole point of moving the close out of haltAndClose: at this instant gemini has fully
    // halted and reconciled, yet grok is still in flight and the lease must still be open.
    assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE');
    assert.deepEqual(leaseStore.closes, []);

    grokGate.resolve();
    const result = await reviewPromise;

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'TRANSPORT_FAILURE' }]);
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// A central capability of parallel dispatch: two reviewers halting for genuinely DIFFERENT reasons
// in the same batch. It proves three separate requirements at once -- per-reviewer failure detail is correct
// for each; the lease closes exactly once (not twice, and not with an uncaught error from the
// second halt); and the top-level reason is the profile-order-first halt, NOT whichever settled
// first. grok is forced to settle completely -- ledger write and all -- before gemini's dispatch is
// even released, so a settle-order-based implementation would report grok's TRANSPORT_FAILURE here.
test('two reviewers halting for different reasons each keep their own detail, close the lease exactly once, and report the profile-order-first reason regardless of settle order', async () => {
  const geminiGate = createDeferred();
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      if (request.reviewerId === 'grok') return failureEnvelope('TIMEOUT', 'grok timed out');
      await geminiGate.promise;
      return responseEnvelope(providerMismatchBody());
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine);
    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);

    const reviewPromise = engine.review({ leaseId, preflightId, source_text: 'x' });
    await waitFor(
      async () => (await leaseStore.getJob(grokJobId))?.state === 'RECONCILED',
      'grok (the SECOND reviewer in profile order) to settle first',
    );
    geminiGate.resolve();
    const result = await reviewPromise;

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'PROVIDER_MISMATCH', 'the top-level reason must be gemini\'s -- first in profile order -- even though grok settled first');
    assert.equal(result.reviewers.gemini.error.code, 'PROVIDER_MISMATCH');
    assert.equal(result.reviewers.grok.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.provider, 'NotGoogle');
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'PROVIDER_MISMATCH' }], 'exactly one close, under the profile-order-first halt');
    assert.equal((await leaseStore.getLease(leaseId)).state, 'PROVIDER_MISMATCH');
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// Edge case: a reviewer on Step 1's "needs redispatch" list already holds a reservation and
// must NEVER be handed to Step 2's consume() -- a second consume() for an already-RESERVED jobId
// would throw, and a reservation counted twice is a money-accounting bug. Asserted mechanistically
// against the observed consume() call log, not merely inferred from the review() outcome.
test('a redispatch-flagged reviewer reuses its existing reservation and is never consume()d again', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    // Stands in for "a previous review() call reserved this and vanished before dispatch() was ever
    // invoked". Deliberately no dispatch-outcome capture of any kind, not even a DISPATCHING
    // marker: that absence is what makes a redispatch provably safe.
    await leaseStore.consume(leaseId, preflight.reviewContractSha256, {
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
    });
    const consumesBeforeReview = leaseStore.consumes.length;

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
    const consumesDuringReview = leaseStore.consumes.slice(consumesBeforeReview);
    assert.deepEqual(
      consumesDuringReview.map((entry) => entry.reviewerId),
      ['grok'],
      'only grok needed a fresh reservation; gemini must reuse the one it already holds',
    );
    assert.equal(
      consumesDuringReview.filter((entry) => entry.jobId === geminiJobId).length,
      0,
      'gemini\'s existing jobId must never be re-reserved',
    );
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// Edge case: a dispatch task that REJECTS rather than returning cleanly. dispatchAndReconcile
// already converts a thrown dispatchAdapter error into a halt-shaped return value, so reaching a
// rejected allSettled entry takes something further in -- here, reconcile() itself failing for one
// reviewer (for example, a genuine concurrent double-call on the same RESERVED job throws a raw
// Error).
//
// TWO requirements, and the SECOND is the one with money attached. (1) The reviewer is not silently
// dropped from the result: it gets an explicit DISPATCH_UNKNOWN-shaped entry and a loud stderr
// line. (2) Its RESERVED job is reconciled before finalization closes the lease -- because once the
// lease is closed, sweepOrphanedLeases() skips it (lease-store.mjs:420, ACTIVE only) and review()
// refuses to re-enter it (review-engine.mjs:1359), so a job still RESERVED at that moment is
// orphaned FOREVER. The `reservedUsd` and job-state assertions below are what make this test bite
// on requirement 2; a version that only checked `leaseStore.closes` passed happily while the money
// was being orphaned.
//
// Mutation check: deleting the recovery reconcile from review()'s rejection handler should redden
// the two ledger assertions below (gemini's job state, and the lease's reservedUsd) while
// everything else in this test stays green.
test('a dispatch task that rejects outright reconciles its orphaned reservation, is surfaced as an explicit DISPATCH_UNKNOWN for that reviewer, and is logged loudly', async () => {
  const dispatch = {
    async dispatch(request) { return responseEnvelope(passBodyFor(request.reviewerId)); },
  };
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    await withEngine(async ({ engine, leaseStore }) => {
      const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine);
      const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
      const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      assert.equal(result.state, 'HALTED');
      assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
      assert.equal(result.reviewers.gemini.error.code, 'DISPATCH_UNKNOWN');
      assert.match(result.reviewers.gemini.error.message, /rejected unexpectedly/);
      assert.equal(result.reviewers.gemini.jobId, geminiJobId, 'the fallback entry must still carry a real jobId, never null');
      // The reported entry must agree with the ledger rather than claiming RESERVED for a job the
      // recovery reconcile has already closed out.
      assert.equal(result.reviewers.gemini.state, 'RECONCILED');
      assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
      assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
      // grok is untouched by its sibling's unexpected rejection.
      assert.equal(result.reviewers.grok.state, 'RECONCILED');
      assert.equal(result.reviewers.grok.costKind, 'KNOWN');
      assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'DISPATCH_UNKNOWN' }]);

      // Requirement 2, asserted against the durable ledger rather than review()'s return value.
      const geminiJob = await leaseStore.getJob(geminiJobId);
      assert.equal(geminiJob.state, 'RECONCILED', 'a rejected task must never leave its job RESERVED under a lease finalization is about to close forever');
      assert.equal(geminiJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
      assert.equal(geminiJob.haltReason, undefined, 'DISPATCH_UNKNOWN means the true outcome is unverifiable -- a real request may have gone out and been billed -- so this must NOT be marked safe to retry; a later cross-lease attempt must treat it as a content-loss landmine, not a genuine halt');
      const lease = await leaseStore.getLease(leaseId);
      // A tolerance, not exact equality, and NOT a hedge -- do not "tidy" this into
      // assert.equal(..., 0), it would be flaky. Measured against this exact fixture: gemini and
      // grok are both reserved before either reconciles, so reservedUsd runs 0 -> g -> g+k -> -g ->
      // -k and lands on +/-5.55e-17, never exactly 0. (An exact assert.equal(reservedUsd, 0) is
      // correct only for a test where each reservation is released before the next is taken,
      // making every step an exact x - x.) Every reservation is rounded up to a whole
      // microdollar, so a genuinely orphaned one is >= 1e-6 while the noise here is ~1e-16: 1e-9
      // sits in that gap, failing loudly on a real leak and never on representation noise.
      assert.ok(Math.abs(lease.reservedUsd) < 1e-9, `every reservation must be released before the lease closes; reservedUsd was ${lease.reservedUsd}`);

      const combined = written.join('');
      assert.match(combined, /openrouter-review-engine: dispatch-task-rejected/);
      assert.ok(combined.includes(geminiJobId), 'expected the failing jobId in the stderr warning');
      // safeErrorDetail() redacts the raw message (this catch wraps a real dispatch reconcile
      // failure) -- assert the safe marker, not the original text. The raw rejection value itself
      // (`rejectionReason`) is passed to safeErrorDetail(), not an already-extracted message string,
      // so a plain Error with no recognized .code reports the 'Error' label rather than the
      // non-Error-rejection marker, and the returned result's own `message` field is redacted the
      // same way.
      assert.ok(combined.includes('Error (detail redacted)'), 'expected the redacted-error marker in the stderr warning');
      assert.ok(!combined.includes('simulated reconcile failure'), 'the raw underlying message must never appear in the stderr warning');
      assert.doesNotMatch(combined, /dispatch-task-rejected-reconcile-failed/, 'the recovery reconcile itself must have succeeded here');
      // The returned result must be redacted the identical way: the caller-visible message field,
      // not just the stderr log.
      assert.ok(!result.reviewers.gemini.error.message.includes('simulated reconcile failure'), 'the raw rejection text must never reach the returned result either');
      assert.ok(result.reviewers.gemini.error.message.includes('Error (detail redacted)'), 'the returned message must carry the same safe marker as the stderr log');
    }, {
      dispatch,
      // Reaching a REJECTED allSettled entry takes a failure deeper than the dispatch adapter, so
      // this makes gemini's FIRST reconcile() throw. Exactly once, deliberately: a fake that failed
      // EVERY gemini reconcile would also break the rejection handler's own recovery reconcile,
      // making requirement 2 untestable and hiding whether the recovery works. One transient failure is
      // also the more realistic shape (a lock contention, a concurrent double-call) than a
      // permanently broken store. The jobId is learned from the consume() call Step 2 makes for
      // gemini, since it cannot be derived before the lease exists. Spreading `wrapped` copies its
      // `closes`/`consumes` array references, so the assertions above still observe the same logs.
      wrapStore: (inner) => {
        const wrapped = wrapLeaseStore(inner);
        const geminiJobIds = new Set();
        let geminiReconcileFailuresRemaining = 1;
        return {
          ...wrapped,
          async consume(leaseId, reviewContractSha256, options) {
            if (options.reviewerId === 'gemini') geminiJobIds.add(options.jobId);
            return wrapped.consume(leaseId, reviewContractSha256, options);
          },
          async reconcile(jobId, costs) {
            if (geminiJobIds.has(jobId) && geminiReconcileFailuresRemaining > 0) {
              geminiReconcileFailuresRemaining -= 1;
              throw new Error('simulated reconcile failure');
            }
            return inner.reconcile(jobId, costs);
          },
        };
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// Edge case, one layer deeper than the test above: the rejection handler's OWN recovery
// reconcile() -- and the getJob() read-back it falls back to when that fails -- can BOTH fail to
// prove the job resolved (e.g. the exact same lock contention that caused the original rejection
// is still active a moment later). When that happens the job is genuinely still RESERVED in the
// ledger, and decideFinalReviewOutcome must not close the lease over it, or the reservation is
// orphaned forever (sweepOrphanedLeases only ever touches ACTIVE leases; review() refuses to
// re-enter a non-ACTIVE lease at all).
//
// Mutation check: removing decideFinalReviewOutcome's anyStillReserved guard (i.e. setting
// `closeCode: failure.code` unconditionally) should redden the two ledger assertions below
// (leaseStore.closes, lease.state) while everything else in this test stays green.
test('a dispatch task whose rejection AND its own recovery reconcile both fail leaves the lease ACTIVE and the job genuinely RESERVED, never falsely closed', async () => {
  const dispatch = {
    async dispatch(request) { return responseEnvelope(passBodyFor(request.reviewerId)); },
  };
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    await withEngine(async ({ engine, leaseStore }) => {
      const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine);
      const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      assert.equal(result.state, 'HALTED');
      assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
      assert.equal(result.reviewers.gemini.error.code, 'DISPATCH_UNKNOWN');
      // The reported entry must agree with the ledger: reconcile genuinely never succeeded for
      // this job, so it must never be reported as anything but still RESERVED.
      assert.equal(result.reviewers.gemini.state, 'RESERVED');
      // grok is untouched by its sibling's unexpected, unrecoverable rejection.
      assert.equal(result.reviewers.grok.state, 'RECONCILED');
      assert.equal(result.reviewers.grok.costKind, 'KNOWN');

      // The money-safety requirement: never close a lease while a reviewer job is genuinely still
      // RESERVED. Asserted against the durable ledger, not just review()'s return value.
      assert.deepEqual(leaseStore.closes, [], 'must never close a lease while a reviewer job is genuinely still RESERVED');
      const geminiJob = await leaseStore.getJob(geminiJobId);
      assert.equal(geminiJob.state, 'RESERVED');
      assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE', 'the lease must stay ACTIVE so the still-reserved job remains recoverable via sweepOrphanedLeases or a future retry');

      const combined = written.join('');
      assert.match(combined, /openrouter-review-engine: dispatch-task-rejected/);
      assert.match(combined, /openrouter-review-engine: dispatch-task-rejected-reconcile-failed/, 'the recovery reconcile itself must have failed here, distinct from the sibling test where it succeeds');
    }, {
      dispatch,
      // Unlike the sibling test above, gemini's reconcile() fails on EVERY call -- both the
      // original dispatch's reconcile (triggering the rejection) and the rejection handler's own
      // recovery reconcile -- so the job is genuinely never reconciled anywhere. getJob() itself is
      // left untouched, so it correctly reads back the real (still-RESERVED) ledger state, matching
      // this test's premise: the failure is in reconcile() specifically, not in reading the ledger.
      wrapStore: (inner) => {
        const wrapped = wrapLeaseStore(inner);
        const geminiJobIds = new Set();
        return {
          ...wrapped,
          async consume(leaseId, reviewContractSha256, options) {
            if (options.reviewerId === 'gemini') geminiJobIds.add(options.jobId);
            return wrapped.consume(leaseId, reviewContractSha256, options);
          },
          async reconcile(jobId, costs) {
            if (geminiJobIds.has(jobId)) throw new Error('simulated persistent reconcile failure');
            return inner.reconcile(jobId, costs);
          },
        };
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// A dispatch task that rejects (Step 3's Promise.allSettled rejection path) must count toward the
// consecutive-dispatch-failure health tracker exactly like any other real dispatch failure
// (haltAndClose's own FAILURE-response halts already do). Otherwise the docstring's claim that "a
// batch in which two reviewers halt now correctly records TWO consecutive failures" would be false
// for any halt that arrives via rejection instead of a normal haltAndClose() call -- silently
// degrading the alert that exists to surface a run of consecutive failed reviews.
//
// Mutation check: removing the recordDispatchHealthOutcome({succeeded:false}) call from the Step 3
// rejection handler should redden the assertion below (consecutiveFailures stays 0) while the
// sibling "reconciles its orphaned reservation..." test above stays green.
test('a rejected dispatch task counts toward the consecutive-dispatch-failure health tracker, like any other real dispatch failure', async () => {
  const dispatch = {
    async dispatch(request) { return responseEnvelope(passBodyFor(request.reviewerId)); },
  };
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    await withEngine(async ({ engine, dispatchHealthStore }) => {
      const { leaseId, preflightId } = await preflightAndAuthorize(engine);
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      assert.equal(result.state, 'HALTED');
      assert.equal(result.error.code, 'DISPATCH_UNKNOWN');

      const stateText = await readFile(dispatchHealthStore.statePath, 'utf8');
      const state = JSON.parse(stateText);
      assert.equal(state.consecutiveFailures, 1, 'a rejected dispatch task must be recorded as a real dispatch failure, not silently uncounted');
    }, {
      dispatch,
      // Same "gemini's reconcile() fails exactly once" shape as the sibling rejection test above --
      // reaching a REJECTED allSettled entry, with the recovery reconcile succeeding afterward.
      wrapStore: (inner) => {
        const wrapped = wrapLeaseStore(inner);
        const geminiJobIds = new Set();
        let geminiReconcileFailuresRemaining = 1;
        return {
          ...wrapped,
          async consume(leaseId, reviewContractSha256, options) {
            if (options.reviewerId === 'gemini') geminiJobIds.add(options.jobId);
            return wrapped.consume(leaseId, reviewContractSha256, options);
          },
          async reconcile(jobId, costs) {
            if (geminiJobIds.has(jobId) && geminiReconcileFailuresRemaining > 0) {
              geminiReconcileFailuresRemaining -= 1;
              throw new Error('simulated reconcile failure');
            }
            return inner.reconcile(jobId, costs);
          },
        };
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

/**
 * A dispatchHealthStore fake that inserts a REAL async gap (setImmediate, twice) inside every
 * recordOutcome()/markAlerted() call -- unlike the real production store, which is lock-free but
 * usually fast enough that two calls rarely interleave in a real filesystem. `maxObservedActive`
 * tracks how many calls were simultaneously inside the store at once, across its whole lifetime;
 * proving it never exceeds 1 is what makes a concurrency fix verifiable rather than merely
 * plausible -- a race that depends on real disk timing can pass a thousand test runs and still be
 * real, but a race that is made structurally impossible cannot, regardless of how slow the
 * underlying store gets.
 */
function createConcurrencyGuardedDispatchHealthStore() {
  let consecutiveFailures = 0;
  let alertedForCurrentStreak = false;
  let active = 0;
  let maxObservedActive = 0;
  async function guarded(fn) {
    active += 1;
    maxObservedActive = Math.max(maxObservedActive, active);
    try {
      // A real, wall-clock delay (not setImmediate/microtask) -- wide enough that the sibling
      // call's own path through real lease-store file I/O (reconcile()'s own mkdir/write/rename,
      // itself serialized behind the ledger's cross-process lock) has ample time to also reach
      // this store and be observed overlapping, if nothing prevents it.
      await new Promise((resolveFn) => { setTimeout(resolveFn, 30); });
      const result = fn();
      await new Promise((resolveFn) => { setTimeout(resolveFn, 30); });
      return result;
    } finally {
      active -= 1;
    }
  }
  return {
    get maxObservedActive() { return maxObservedActive; },
    async recordOutcome({ succeeded, alertThreshold }) {
      return guarded(() => {
        let shouldAlert = false;
        if (succeeded) {
          consecutiveFailures = 0;
          alertedForCurrentStreak = false;
        } else {
          consecutiveFailures += 1;
          shouldAlert = !alertedForCurrentStreak && consecutiveFailures >= alertThreshold;
        }
        return { consecutiveFailures, shouldAlert };
      });
    },
    async markAlerted() {
      return guarded(() => { alertedForCurrentStreak = true; });
    },
  };
}

// Regression: a SUCCESS and a FAILURE landing in the same Step 3 batch (possible only because
// dispatch is parallel) could both enter dispatchHealthStore's own unlocked read-modify-write at
// once, and under the right interleaving durably corrupt alertedForCurrentStreak itself: a fresh
// streak of 0 gets permanently pre-marked "already alerted", silently suppressing the critical
// alert for the entire NEXT real failure streak. serializedDispatchHealthAccess
// (review-engine.mjs), an in-process queue around every recordDispatchHealthOutcome call, prevents
// that.
//
// Mutation check: removing the serializedDispatchHealthAccess wrapper from
// recordDispatchHealthOutcome should redden the assertion below (maxObservedActive reaches 2)
// while every other test in this file stays green.
test('a success and a failure landing in the same batch never enter dispatchHealthStore concurrently', async () => {
  const dispatch = {
    async dispatch(request) {
      if (request.reviewerId === 'gemini') return failureEnvelope('TIMEOUT', 'gemini timed out');
      return responseEnvelope(grokPassBody());
    },
  };
  const healthStore = createConcurrencyGuardedDispatchHealthStore();
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.gemini.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.equal(healthStore.maxObservedActive, 1, 'recordDispatchHealthOutcome must serialize every call into dispatchHealthStore -- a success and a failure racing in the same batch must never overlap');
  }, { dispatch, dispatchHealthStore: healthStore });
});

// Regression: decideFinalReviewOutcome's anyStillReserved guard must cover the
// LEASE_EXPIRED/DUPLICATE_IN_PROGRESS early-return branches too, not only the fallback/'ordinary'
// branch -- otherwise the same orphaning bug is reachable through a DIFFERENT stopReason. This
// combines the two ingredients: an earlier
// reviewer (gemini) already queued onto needsRedispatch with a real pre-existing RESERVED job (same
// setup as "a later reviewer tripping the cross-lease duplicate-in-progress batch stop..." above),
// PLUS gemini's own redispatch failing with a persistent reconcile() error (same setup as "a
// dispatch task whose rejection AND its own recovery reconcile both fail..." above) -- so gemini is
// STILL genuinely RESERVED when grok (later in profile order) trips DUPLICATE_DISPATCH_IN_PROGRESS.
//
// Mutation check: making decideFinalReviewOutcome guard only the fallback branch (moving
// anyStillReserved inside the null/ORDINARY_FAILURE branch only) should redden the two ledger
// assertions below while every other test in this file stays green.
test('a later reviewer tripping a batch-wide stop does not close the lease over an earlier reviewer that is genuinely still RESERVED after its own redispatch and recovery both fail', async () => {
  const dispatch = {
    // The response itself is a normal pass -- the failure this test cares about is at the
    // reconcile() step below, not the dispatch/transport step.
    async dispatch(request) { return responseEnvelope(passBodyFor(request.reviewerId)); },
  };
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    await withEngine(async ({ engine, leaseStore, ownerLock }) => {
      const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
      // Authorization releases ownership when it completes; acquire the real handle for direct
      // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
      await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
      const { reviewContractSha256 } = preflight;
      const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;

      // gemini already holds a RESERVED job under THIS lease (an interrupted earlier attempt).
      const geminiJobId = testDeriveJobId(leaseId, 'gemini', reviewContractSha256);
      await leaseStore.consume(leaseId, reviewContractSha256, {
        reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
      });

      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      // grok's own batch-wide stop still names grok.
      assert.equal(result.state, 'HALTED');
      assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');

      // The money-safety requirement: gemini's redispatch was attempted (Step 3 still dispatches it
      // regardless of grok's later stop), failed, and its recovery reconcile also failed -- so
      // gemini is genuinely still RESERVED, and the lease must NOT close over it.
      assert.equal(result.reviewers.gemini.state, 'RESERVED');
      assert.deepEqual(leaseStore.closes, [], 'must never close a lease while a reviewer job is genuinely still RESERVED, regardless of which stopReason triggered finalization');
      const geminiJob = await leaseStore.getJob(geminiJobId);
      assert.equal(geminiJob.state, 'RESERVED');
      assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE', 'the lease must stay ACTIVE so the still-reserved job remains recoverable');
    }, {
      dispatch,
      wrapStore: (inner) => {
        const wrapped = wrapLeaseStore(inner, {
          onFindJobs: async ({ reviewerId }) => {
            if (reviewerId === 'grok') return [{ id: 'other-lease-grok-job', state: 'RESERVED' }];
            return undefined;
          },
        });
        return {
          ...wrapped,
          // grok never reaches reconcile() in this scenario (it stops at the batch-wide check
          // before any fresh reservation), so this only ever affects gemini's own redispatch --
          // simulating the same persistent lock-contention failure as the sibling "both fail" test
          // above, both for the original redispatch attempt and the rejection handler's own
          // recovery reconcile.
          async reconcile(jobId, costs) {
            throw new Error('simulated persistent reconcile failure');
          },
        };
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// processDispatchOutcome durably reconciles a job's real cost BEFORE it records that job's own
// advisory content anywhere. A throw in that narrow window (most realistically the whole process
// dying) leaves a job durably RECONCILED at a real cost with no recoverable content anywhere. This
// test seeds that exact ledger state directly (rather than trying to time a real throw inside
// processDispatchOutcome) and proves Step 1's own recovery stub reports it loudly instead of
// silently looking like a clean, contentless pass.
//
// Mutation check: removing the isUnexplainedContentLoss guard (a stub with no .error) should
// redden the assertions below while every other test in this file stays green.
test('a job the ledger shows RECONCILED at a real cost, with no recoverable advisory content anywhere, is reported loudly (CONTENT_LOST) rather than silently as a clean pass', async () => {
  const dispatch = {
    async dispatch(request) { return responseEnvelope(passBodyFor(request.reviewerId)); },
  };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const { reviewContractSha256 } = preflight;
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', reviewContractSha256);

    // The exact landmine: reconcile() succeeded (real known cost, durably committed) but nothing
    // ever recorded the advisory content anywhere -- gemini never gets dispatched at all here
    // (dispatch() would throw if it did), simulating a PRIOR review() call that reconciled this
    // job for real and then had its content-recording steps interrupted.
    await leaseStore.consume(leaseId, reviewContractSha256, { reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(geminiJobId, { costUsd: geminiMaxUsd, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'CONTENT_LOST');
    assert.equal(result.reviewers.gemini.error.code, 'CONTENT_LOST');
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
    assert.equal(Object.hasOwn(result.reviewers.gemini, 'advisory'), false, 'no advisory content exists to report -- that is exactly the gap this test proves is now loud, not silent');
    // grok is untouched by gemini's own pre-existing landmine and dispatches/reconciles normally.
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'CONTENT_LOST' }]);
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// Symmetric regression guard, same seeding technique as the test directly above: a job reconciled
// via a GENUINE haltAndClose() halt (e.g. PROVIDER_MISMATCH) would be, by the ledger's cost fields
// alone, indistinguishable from the true content-loss landmine the test above seeds. Without
// haltReason, retrying a still-ACTIVE lease after a genuine halt would report the SAME generic
// CONTENT_LOST as an unexplained landmine -- imprecise (the real, more specific halt code is
// available), though never unsafe on its own (a same-lease retry never redispatches either way).
// This seeds the halt WITH its real code (haltReason: 'PROVIDER_MISMATCH', exactly as
// haltAndClose() itself persists) and proves the retry reports THAT code, not CONTENT_LOST.
//
// Mutation check: making isUnexplainedContentLoss ignore haltReason must turn this test's
// `error.code` assertion red while the sibling test above (seeded with no haltReason at all) stays
// green -- that is what proves the two are actually distinguished, not just relabeled.
test('a job the ledger shows RECONCILED via a genuine halt (haltReason recorded) reports that halt\'s real code on retry, not a generic CONTENT_LOST', async () => {
  const dispatch = {
    async dispatch(request) { return responseEnvelope(passBodyFor(request.reviewerId)); },
  };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const { reviewContractSha256 } = preflight;
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', reviewContractSha256);

    // Same ledger shape as the sibling landmine test (RECONCILED, real KNOWN cost, no advisory
    // content anywhere) -- but this time with haltReason recorded, exactly as haltAndClose() now
    // persists for a genuine halt. gemini is never dispatched here, matching a real
    // PROVIDER_MISMATCH halt's own real-world shape (a response WAS received and paid for, but
    // haltAndClose never calls resultStore.record()).
    await leaseStore.consume(leaseId, reviewContractSha256, { reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(geminiJobId, { costUsd: geminiMaxUsd, costKind: 'KNOWN', haltReason: 'PROVIDER_MISMATCH', acquisitionId: ownerLock.acquisitionId });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.gemini.error.code, 'PROVIDER_MISMATCH', 'the real recorded halt code, not a generic CONTENT_LOST');
    assert.notEqual(result.reviewers.gemini.error.code, 'CONTENT_LOST');
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
    assert.equal(Object.hasOwn(result.reviewers.gemini, 'advisory'), false);
    // grok is untouched by gemini's own pre-existing halt and dispatches/reconciles normally.
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// ---------------------------------------------------------------------------
// Step 2's own stop conditions, reached end to end.
// ---------------------------------------------------------------------------

/**
 * Returns a wrapStore that makes ONE reviewer's SECOND findJobsForReviewerContract call report an
 * in-flight duplicate. Step 1 queries each reviewer once and Step 2 queries each fresh-reservation
 * candidate once more, so "the second call for reviewer X" is precisely the Step 2 re-check --
 * simulating a duplicate that appeared in the gap between the two passes, with no real timing
 * involved.
 */
function duplicateAppearsBeforeReservationFor(reviewerId, priorJobId) {
  return (inner) => wrapLeaseStore(inner, {
    onFindJobs({ reviewerId: queried, callIndexForReviewer }) {
      if (queried !== reviewerId || callIndexForReviewer !== 1) return undefined;
      return [{ id: priorJobId, state: 'RESERVED', reviewerId, leaseId: 'some-other-lease', reservationUsd: 0.2, costUsd: 0 }];
    },
  });
}

test('a duplicate that appears between Step 1 and a later reviewer\'s reservation stops the reserve pass, and the reviewers already reserved still dispatch at real cost', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  const keyStatusProbe = createFakeKeyStatusProbe();
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    // A structured HALTED, exactly as Step 1 already reports the identical real-world condition --
    // never a thrown error.
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');
    assert.match(result.error.message, /reviewer grok already has an in-flight dispatch \(job in-flight-grok-job\)/);
    // gemini was reserved before the stop and is never abandoned: it dispatches and reconciles for
    // real, so its reservation is not orphaned.
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini']);
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok, undefined);
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'DUPLICATE_DISPATCH_IN_PROGRESS' }]);
    assert.equal(keyStatusProbe.state.calls, 1, 'money may have been spent on the reserved subset, so the spend probe must run on this branch too');
  }, { dispatch, keyStatusProbe, wrapStore: duplicateAppearsBeforeReservationFor('grok', 'in-flight-grok-job') });
});

test('Step 2 stopping before it reserves ANYONE still reports the real stop reason, never a vacuous PASSED', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  const keyStatusProbe = createFakeKeyStatusProbe();
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    // Nothing was reserved and nothing was dispatched: Promise.allSettled ran over an empty array.
    // Reading "zero reviewers, nothing failed" as PASSED would be a vacuous PASS, and Step 5's
    // priority order is what makes it structurally impossible.
    assert.deepEqual(dispatch.calls, []);
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');
    assert.deepEqual(result.reviewers, {});
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'DUPLICATE_DISPATCH_IN_PROGRESS' }]);
    assert.equal(keyStatusProbe.state.calls, 1);
  }, { dispatch, keyStatusProbe, wrapStore: duplicateAppearsBeforeReservationFor('gemini', 'in-flight-gemini-job') });
});

test('a mid-reserve consume() failure still dispatches and reconciles everything already reserved, then surfaces the failure by throwing', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine);
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);

    // The contract for this specific error class is a throw out of review(), with no structured
    // result -- preserved deliberately (Step 5, branch 3), but only AFTER the
    // already-reserved subset's own finalization has completed.
    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_CAP_EXCEEDED',
    );

    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini']);
    const geminiJob = await leaseStore.getJob(geminiJobId);
    assert.equal(geminiJob.state, 'RECONCILED', 'a reviewer reserved before the failure must not be left RESERVED');
    assert.equal(geminiJob.costKind, 'KNOWN', 'and must be charged its REAL cost, not a worst case for work it actually completed');
    assert.equal(geminiJob.costUsd, 0.01);
    // gemini passed cleanly, so finalization took the PASSED branch and deliberately did not close
    // the lease -- matching the clean-path behavior -- before throwing.
    assert.deepEqual(leaseStore.closes, []);
    assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE');
  }, {
    dispatch,
    wrapStore: (inner) => wrapLeaseStore(inner, {
      onConsume(options) {
        if (options.reviewerId === 'grok') throw new RangeError('lease cap exceeded');
      },
    }),
  });
});

// Step 1's OWN sequential check phase (before Step 2 or Step 3 ever runs) makes real,
// lock-serialized leaseStore calls, just like reserveReviewers()'s copy of this exact
// findJobsForReviewerContract() call a few lines below, which the ORDINARY_FAILURE test above
// already covers. Under concurrent lock pressure, a raw, uncaught EPERM/"ledger data root is
// locked" escaping review() directly from this loop would abandon gemini's real pre-existing
// reservation instead of dispatching it.
//
// Mutation check: removing the try/catch around Step 1's loop body should redden this test's
// dispatch.calls/geminiJob assertions (gemini's reservation is abandoned, dispatch.calls stays
// empty) while assert.rejects alone would still pass either way -- the throw itself is not what
// this guards, its SAFETY is.
test('an infrastructure failure during Step 1\'s own check phase still dispatches and reconciles a reviewer already queued for redispatch earlier in the same pass, then surfaces the failure by throwing', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  const keyStatusProbe = createFakeKeyStatusProbe();
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    // Stands in for "a previous review() call reserved gemini and vanished before dispatch() was
    // ever invoked" -- gemini is classified into needsRedispatch during Step 1, in profile order,
    // BEFORE grok's own Step-1 check (later in profile order) throws.
    await leaseStore.consume(leaseId, preflight.reviewContractSha256, {
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
    });

    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING' && /ledger data root is locked/.test(error.message),
    );

    // The money-safety assertion: gemini's pre-existing reservation is dispatched and reconciled for
    // real, exactly as if grok's own check had never thrown -- never abandoned RESERVED forever.
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini']);
    const geminiJob = await leaseStore.getJob(geminiJobId);
    assert.equal(geminiJob.state, 'RECONCILED', 'a reviewer already queued for redispatch before the failure must not be left RESERVED');
    assert.equal(geminiJob.costKind, 'KNOWN');
    // grok never reached Step 2 or Step 3 at all: nothing was ever reserved or dispatched for it.
    assert.equal(dispatch.calls.some((call) => call.reviewerId === 'grok'), false);
    // Finalization ran (matching reserveReviewers()'s own ORDINARY_FAILURE contract): the spend
    // probe fires, and since gemini passed cleanly the lease stays ACTIVE rather than being closed
    // -- the failure is an infrastructure hiccup, not a verdict on the document.
    assert.equal(keyStatusProbe.state.calls, 1);
    assert.deepEqual(leaseStore.closes, []);
    assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE');
  }, {
    dispatch,
    keyStatusProbe,
    wrapStore: (inner) => wrapLeaseStore(inner, {
      onFindJobs({ reviewerId }) {
        if (reviewerId === 'grok') throw new Error('ledger data root is locked');
      },
    }),
  });
});

// Same money-safety property as the test above, but for the FIRST of Step 1's three fallible
// leaseStore call sites (leaseStore.getJob() itself, reached before findJobsForReviewerContract
// is ever called); the test above covers the third.
test('an infrastructure failure at Step 1\'s OWN first leaseStore call (getJob) also still dispatches and reconciles a reviewer already queued for redispatch earlier in the same pass', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  const keyStatusProbe = createFakeKeyStatusProbe();
  // getJob() takes only a bare jobId (unlike findJobsForReviewerContract, which takes reviewerId
  // directly), so there is no reviewerId to match on here -- and jobId itself is only known INSIDE
  // withEngine's callback, after the store (and this wrapStore closure) already had to be built.
  // A call-order counter is the only signal available at wrap time; Step 1 processes reviewers in
  // fixed profile order (gemini, then grok), so the SECOND getJob() call is deterministically
  // grok's own -- confirmed below by assert.deepEqual(dispatch.calls, ['gemini']).
  let getJobCalls = 0;
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    // Authorization releases ownership when it completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await leaseStore.consume(leaseId, preflight.reviewContractSha256, {
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
    });

    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING' && /ledger data root is locked/.test(error.message),
    );

    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini']);
    const geminiJob = await leaseStore.getJob(geminiJobId);
    assert.equal(geminiJob.state, 'RECONCILED', 'a reviewer already queued for redispatch before the failure must not be left RESERVED');
    assert.equal(geminiJob.costKind, 'KNOWN');
    assert.equal(keyStatusProbe.state.calls, 1);
    assert.deepEqual(leaseStore.closes, []);
    assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE');
  }, {
    dispatch,
    keyStatusProbe,
    wrapStore: (inner) => wrapLeaseStore(inner, {
      onGetJob() {
        getJobCalls += 1;
        if (getJobCalls === 2) throw new Error('ledger data root is locked');
      },
    }),
  });
});

test('a lease that expires between two reservations halts with LEASE_EXPIRED even though every reviewer that did dispatch passed', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  const keyStatusProbe = createFakeKeyStatusProbe();
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    // Unconditionally HALTED: the stopReason is checked before any "did everyone pass" evaluation,
    // so a coincidentally-clean dispatch set can never override it (Step 5, branch 1).
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'LEASE_EXPIRED');
    assert.match(result.error.message, /before reviewer grok could be reserved/);
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini']);
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok, undefined);
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'LEASE_EXPIRED' }]);
    assert.equal(keyStatusProbe.state.calls, 1, 'the reserved subset really dispatched, so the spend probe must run on this branch too');
  }, {
    dispatch,
    keyStatusProbe,
    wrapStore: (inner, { advance }) => wrapLeaseStore(inner, {
      // Stands in for a reservation round-trip that took long enough to cross the lease's own
      // expiry -- real elapsed time a lease near its expiry can genuinely cross now that Step 1
      // runs to completion for every reviewer before Step 2 reserves anyone. afterConsume, NOT
      // onConsume: the clock must move only once gemini's own reservation has genuinely succeeded,
      // otherwise lease-store's expiry check inside consume() would reject gemini instead, which is
      // a different scenario (and would make this test prove nothing about Step 2's own check).
      afterConsume(options) {
        if (options.reviewerId === 'gemini') advance(11 * 60 * 1000);
      },
    }),
  });
});

// ---------------------------------------------------------------------------
// Batch-size boundaries.
// ---------------------------------------------------------------------------

// final_verification_v1 with an empty changeKinds list resolves to reviewerIds ['grok'] alone
// (reviewer-registry.mjs), so this is a genuine one-element Promise.allSettled -- the boundary
// between "sequential" and "concurrent" in practice, covered explicitly even though it needs no
// special-casing in the code.
test('a single-reviewer batch behaves identically to a single dispatch', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(grokPassBody());
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, {
      profile: 'final_verification_v1', changeKinds: [],
    });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['grok']);
    assert.equal(Object.hasOwn(result.reviewers, 'gemini'), false);
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
    assert.deepEqual(leaseStore.closes, [], 'a fully-clean batch still never closes its lease');
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// Promise.allSettled([]) resolves immediately to [], and finalization must proceed straight to its
// PASSED branch rather than throwing or hanging. Already a real path in production (a fully
// recovered retry), so this confirms the empty case rather than introducing it.
test('a batch with nothing left to dispatch resolves cleanly instead of throwing or hanging', async () => {
  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      return responseEnvelope(passBodyFor(request.reviewerId));
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const first = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(first.state, 'PASSED');

    const second = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(second.state, 'PASSED');
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok'], 'the repeat call must dispatch nothing at all');
    assert.deepEqual(second.reviewers.gemini.advisory, first.reviewers.gemini.advisory);
    assert.deepEqual(second.reviewers.grok.advisory, first.reviewers.grok.advisory);
    assert.deepEqual(leaseStore.closes, []);
  }, { dispatch, wrapStore: (inner) => wrapLeaseStore(inner) });
});

// ---------------------------------------------------------------------------
// Process-ownership shutdown safety: the ORDINARY launcher-give-up case.
// ---------------------------------------------------------------------------

/**
 * The common-path half of a pair; its exceptional-path sibling is "a dispatch task whose rejection
 * AND its own recovery reconcile both fail ..." above. The claim asserted here is deliberately
 * narrow.
 *
 * Do NOT assert the stronger claim, here or in this test's name:
 * "reconciliation always completes before drain". It does not, in general. haltAndClose()'s own
 * reconcile can reject, the rejection handler's retry can reject too, and the tracked promise then
 * settles with the job still RESERVED -- exactly what the sibling test above pins down. The
 * invariant that survives that case is narrower: releasing process ownership once awaitDrain()
 * reports drained is safe because no Node-side owner-sensitive OPERATION is still active, NOT
 * because the ledger is guaranteed settled.
 *
 * The only claim asserted here: on the ORDINARY launcher-give-up path -- reconcile
 * succeeds, the common case -- the ledger job really is already reconciled at its worst-case cost
 * before drain could ever consider that operation finished. That is what keeps the ordinary case
 * free of any cost beyond the already-accepted, already-documented stranded-outcome gap.
 *
 * WHAT IS MODELLED, AND WHAT IS NOT. createDispatchAdapter() spawns the Scheduled-Task LAUNCHER,
 * never the worker directly (tools/openrouter-review-mcp-server.mjs:310 -> :229), under a hard-kill
 * `timeout` (:428), and RETHROWS when that timeout fires (:447). The worker itself runs under the
 * Windows Scheduled Task the launcher registers, and that is why it outlives the launcher's give-up
 * -- deliberately NOT attributed to `detached: true` (:421), which that same file's own :215-227
 * comment records as NOT surviving process teardown on Windows. So "the launcher gave up
 * on a slow Scheduled Task" reaches the engine as dispatch() THROWING, and the throw is the ONLY
 * thing modelled below. The still-running worker is not modelled at all and this test makes no
 * claim about it: nothing here observes, waits on, or asserts anything about a process that
 * outlives the launcher.
 *
 * HOW THE ORDERING IS MADE OBSERVABLE, and why the naive version of this test proves nothing.
 * dispatchAndReconcile's catch (review-engine.mjs:2006) calls haltAndClose(), which awaits
 * leaseStore.reconcile() (:1780). If the fixture merely TIMESTAMPED that write, the obvious
 * mutation -- make the catch fire-and-forget haltAndClose() while returning the same HALTED shape
 * -- would still pass: the reconcile is entered synchronously either way and takes the data-root
 * lock (lease-store.mjs mutate()) strictly before finalization's own close() can, so it would
 * commit first by accident and both ordering assertions would stay green. The fixture therefore
 * HOLDS the write open on `reconcileHold`, a gate this test alone releases. Under the real, awaited
 * code the whole review is parked behind that gate; under a fire-and-forget mutation it is not.
 *
 * The second ordering assertion (reconcile before the promise the tool handler holds) is a
 * redundant cross-check kept for message quality, NOT an independently mutation-proven guard: every
 * mutation tried removes gemini's reconcile from the timeline entirely, so both ordering assertions
 * redden together and assert.ok aborts on the drain one first.
 *
 * Not a replica of production: beginShutdown() and awaitDrain() below are the REAL engine exports
 * the shipped server's runShutdownSequence() calls, driving the real in-flight registry
 * (review-engine.mjs trackInFlight) -- the stdio harness makes the same choice, because a replica
 * can stay green with the production machinery deleted.
 * beginShutdown() is called here to make the sequence realistic; nothing below depends on its own
 * refusal behaviour, which is covered by tests/openrouter-review-engine-shutdown.test.mjs:113.
 *
 * NO STDERR ASSERTION, deliberately: nothing on this path writes a diagnostic (dispatchAndReconcile's
 * catch returns haltAndClose's value and logs nothing). The success-path stderr line
 * lives in runShutdownSequence() in tools/openrouter-review-mcp-server.mjs and is covered
 * by the matched pair of arms in tests/openrouter-review-mcp-stdio.test.mjs, not here.
 *
 * withEngine() acquires a real process-ownership handle and never releases it -- its finally block
 * deletes the whole temp data root instead. That weakens nothing asserted here: awaitDrain observes
 * the engine's in-flight registry only and never consults the ownership record. The dedicated
 * shutdown suite does release, if a future test in this file ever needs that.
 *
 * Mutation check: making dispatchAndReconcile's catch (review-engine.mjs) fire-and-forget its
 * haltAndClose() call -- the call left in place but un-awaited, the same HALTED shape returned and
 * the same `reviewers` entry set inline -- should redden this test, on the mid-flight check ("the
 * drain must still be waiting while the worst-case reconcile is unfinished"), while the other tests
 * in this file stay green. If it does not redden, the fixture is broken, not the production code.
 */
test('the ordinary launcher-give-up path reconciles its job at worst-case before drain can ever call that operation finished', { timeout: 30_000 }, async () => {
  const timeline = [];
  const launcherGivesUp = createDeferred();
  // Held by the fixture's own reconcile wrapper, released only by this test. See "HOW THE ORDERING
  // IS MADE OBSERVABLE" above -- without it, the mutation this test exists to catch cannot lose.
  const reconcileHold = createDeferred();

  const dispatch = {
    calls: [],
    async dispatch(request) {
      this.calls.push({ reviewerId: request.reviewerId });
      if (request.reviewerId !== 'gemini') return responseEnvelope(grokPassBody());
      await launcherGivesUp.promise;
      timeline.push('launcher-gave-up');
      throw new Error('the dispatch launcher stopped waiting before the worker reported');
    },
  };

  await withEngine(async ({ engine, leaseStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine);
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    assert.ok(geminiMaxUsd > 0, 'a zero worst-case maximum would make both cost assertions below vacuous');
    const geminiReconcileAttempt = `reconcile-attempt:${geminiJobId}`;
    const geminiReconciled = `ledger-reconciled:${geminiJobId}`;

    const reviewPromise = engine.review({ leaseId, preflightId, source_text: 'x' });
    // Attached before anything else observes this promise, so 'review-settled' is recorded at the
    // earliest instant the MCP tool handler itself could have seen it settle.
    let reviewSettled = false;
    const observedReview = reviewPromise.then(
      (value) => { reviewSettled = true; timeline.push('review-settled'); return value; },
      (error) => { reviewSettled = true; timeline.push('review-settled'); throw error; },
    );

    // Bounded, unlike a bare `await someDeferred.promise`: a regression that halts before gemini is
    // ever dispatched fails with this message instead of wedging the whole `node --test` run.
    await waitFor(
      () => dispatch.calls.some((call) => call.reviewerId === 'gemini'),
      'gemini\'s dispatch to be entered',
    );

    // Non-vacuity, measured rather than inferred. awaitDrain() over an EMPTY registry returns
    // { drained: true, outstandingCount: 0 } unconditionally, so every drain assertion below would
    // be worthless if review() were not actually tracked. This probes the registry directly:
    // awaitDrain snapshots it synchronously, races a 0ms timer, cancels nothing, and reports the
    // real outstanding count on the timeout branch.
    assert.deepEqual(
      await engine.awaitDrain({ timeoutMs: 0 }),
      { drained: false, outstandingCount: 1 },
      'the in-flight registry must genuinely hold this review; an empty one makes drained:true prove nothing',
    );

    engine.beginShutdown();
    let drainSettled = false;
    const drainPromise = engine.awaitDrain({ timeoutMs: 10_000 });
    const observedDrain = drainPromise.then((outcome) => {
      drainSettled = true;
      timeline.push('drained');
      return outcome;
    });

    launcherGivesUp.resolve();

    // The halt path has now entered its worst-case reconcile and is parked on the gate.
    await waitFor(
      () => timeline.includes(geminiReconcileAttempt),
      'the launcher-give-up halt to reach its worst-case reconcile',
    );
    // A generous settle window. Under a fire-and-forget haltAndClose the review would race ahead to
    // finalization here -- close the lease, settle, and let the drain report drained -- all of which
    // is ordinary in-process work that completes in well under this budget.
    await new Promise((resolve) => { setTimeout(resolve, 200); });

    // --- THE PROPERTY UNDER TEST, checked while the ledger write is provably still unfinished.
    //     This is the assertion the mutation reddens, so it is stated first and stated plainly. ---
    assert.equal(
      drainSettled, false,
      'the drain must still be waiting while the worst-case reconcile is unfinished -- a drained verdict here would release process ownership over an unsettled owner-fenced write',
    );
    assert.equal(
      reviewSettled, false,
      'the promise the tool handler holds must not settle while the worst-case reconcile is unfinished',
    );
    assert.deepEqual(
      leaseStore.closes, [],
      'finalization must not have run yet -- a closed lease here means the halt was not awaited',
    );

    reconcileHold.resolve();
    const result = await observedReview;
    const drainOutcome = await observedDrain;

    // --- The same property restated as an ordering, for a legible failure message. A missing entry
    //     sorts AFTER everything instead of reporting -1, so a halt that never reconciles at all
    //     still reddens the ordering assertion it actually violated. ---
    const orderOf = (entry) => {
      const index = timeline.indexOf(entry);
      return index === -1 ? Number.POSITIVE_INFINITY : index;
    };
    assert.ok(
      orderOf(geminiReconciled) < orderOf('drained'),
      `the worst-case reconcile must land before awaitDrain reports drained; timeline was ${JSON.stringify(timeline)}`,
    );
    assert.ok(
      orderOf(geminiReconciled) < orderOf('review-settled'),
      `the worst-case reconcile must land before the promise the tool handler holds settles; timeline was ${JSON.stringify(timeline)}`,
    );
    // Exactly one ATTEMPT, not merely one success: the wrapper records the attempt BEFORE calling
    // through, so this bites even on a second reconcile that throws and is swallowed. That is the
    // realistic regression -- Step 3's rejection handler running its own recovery reconcile over an
    // already-reconciled job would throw 'job is not reserved' (lease-store.mjs:706) into the catch
    // the sibling test at :859 covers, leaving a success-only count at 1 and this test green.
    assert.equal(
      timeline.filter((entry) => entry === geminiReconcileAttempt).length, 1,
      'the ordinary launcher-give-up path must reconcile once, inside dispatchAndReconcile\'s own catch -- Step 3\'s rejection handler must never be involved',
    );
    assert.equal(
      timeline.filter((entry) => entry === geminiReconciled).length, 1,
      'and that single attempt must be the one that committed',
    );

    assert.equal(drainOutcome.drained, true);
    // Pins the returned SHAPE, not a measured count: review-engine.mjs's drained branch returns a
    // hardcoded 0, so this cannot fail once `drained` is true. Do not cite it as proof the registry
    // emptied -- the mid-flight probe above is what establishes that.
    assert.equal(drainOutcome.outstandingCount, 0);

    // --- It really was a launcher give-up, not some other halt that happens to reconcile. ---
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
    assert.match(result.reviewers.gemini.error.message, /dispatch threw for reviewer gemini/);
    // Same redaction contract every other outward-facing message in this engine carries
    // (safeErrorDetail()). This is dispatchAndReconcile's own safeErrorDetail() call site, a different
    // one from the Step 3 rejection handler the tests above cover.
    assert.ok(
      !result.reviewers.gemini.error.message.includes('stopped waiting before the worker reported'),
      'the raw thrown text must never reach the caller-visible message',
    );
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
    assert.equal(result.reviewers.grok.state, 'RECONCILED', 'the sibling reviewer is untouched by its neighbour\'s abandoned launcher');

    // --- The durable ledger, read after the fact. ---
    const geminiJob = await leaseStore.getJob(geminiJobId);
    assert.equal(geminiJob.state, 'RECONCILED');
    assert.equal(geminiJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(geminiJob.costUsd, geminiMaxUsd);
    // Asserts ABSENCE of the field, and nothing more: lease-store.mjs:710 omits the key entirely
    // when the value is undefined, so "correctly withheld" and "never persisted at all" look the
    // same from here. hasOwn rather than `=== undefined` so a future rename that persists the same
    // meaning under a new key still reddens. The positive control that makes the pair meaningful is
    // the sibling test at :1193, which proves a KNOWN-cost halt DOES record a haltReason.
    assert.equal(
      Object.hasOwn(geminiJob, 'haltReason'), false,
      'a launcher give-up leaves the true outcome unverifiable -- the worker may still bill -- so it must never be marked safe to retry',
    );
    assert.deepEqual(leaseStore.closes, [{ leaseId, state: 'DISPATCH_UNKNOWN' }]);
  }, {
    dispatch,
    // Records the reconcile ATTEMPT before calling through and the durable write only after it
    // resolves, and -- for gemini alone -- holds the write open on a gate this test releases. The
    // gate is what makes the ordering assertions discriminating rather than incidental; see the
    // docstring's "HOW THE ORDERING IS MADE OBSERVABLE".
    wrapStore: (inner) => {
      const wrapped = wrapLeaseStore(inner);
      // gemini's jobId cannot be derived before the lease exists, so it is learned from the
      // consume() call Step 2 makes -- the same technique the two rejection tests above use.
      const geminiJobIds = new Set();
      return {
        ...wrapped,
        async consume(leaseId, reviewContractSha256, options) {
          if (options.reviewerId === 'gemini') geminiJobIds.add(options.jobId);
          return wrapped.consume(leaseId, reviewContractSha256, options);
        },
        async reconcile(jobId, costs) {
          timeline.push(`reconcile-attempt:${jobId}`);
          if (geminiJobIds.has(jobId)) await reconcileHold.promise;
          const reconciled = await inner.reconcile(jobId, costs);
          timeline.push(`ledger-reconciled:${jobId}`);
          return reconciled;
        },
      };
    },
  });
});

// Ownership loss must be classified at the three leaseStore.reconcile() sites too -- the only
// owner-fenced writes that can fire AFTER money has been spent -- not only at the other
// owner-fenced write sites. If the rejection handler stamped the generic DISPATCH_UNKNOWN, an
// operator whose server has been superseded by a second instance would be told "we cannot verify
// what happened to this dispatch" instead of "another process took the ledger". PROCESS_OWNERSHIP_LOST's own comment in
// ERROR_CODES says exactly why that matters: conflating it with a generic failure "would hide a
// real operational problem behind misleading diagnostics that point an operator at the wrong
// thing to investigate."
test('ownership lost at reconcile() is reported as PROCESS_OWNERSHIP_LOST, not a generic DISPATCH_UNKNOWN, and records no dispatch-health failure', async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  // Losing process ownership is not a dispatch failure --
  // this process was superseded as the ledger's owner -- so it must not advance the
  // consecutive-dispatch-failure streak, or a superseded server would raise that alert about a
  // pipeline that is healthy.
  const healthOutcomes = [];
  // The exact message lease-store.mjs's assertCurrentlyOwnsProcess() throws -- the same string
  // isProcessOwnershipLostError() already matches at the three sites that DO classify it.
  const ownershipLost = new Error('caller does not currently hold process ownership of this data root');
  await withEngine(async ({ engine }) => {
    // final_verification_v1 with an empty changeKinds dispatches grok alone, isolating this to
    // exactly one reviewer's rejection.
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(
      result.reviewers.grok.error.code,
      'PROCESS_OWNERSHIP_LOST',
      'a superseded owner must be named as such, not hidden behind DISPATCH_UNKNOWN',
    );
    assert.deepEqual(healthOutcomes, [], 'an ownership loss must not be recorded as a dispatch-health failure');
  }, {
    dispatch,
    wrapStore: (inner) => ({
      ...inner,
      async reconcile() { throw ownershipLost; },
    }),
    dispatchHealthStore: {
      async recordOutcome({ succeeded }) { healthOutcomes.push(succeeded); return { shouldAlert: false }; },
      async markAlerted() {},
    },
  });
});

// A RESPONSE envelope with a caller-chosen HTTP status. The shared responseEnvelope() helper above
// hardcodes 200, which is right for every test that models a real completion; these model the
// provider REJECTING the request outright, which still arrives as kind:'RESPONSE'.
function responseEnvelopeWithStatus(httpStatus, body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({
      httpStatus,
      bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64'),
    }),
  });
}

// A representative OpenRouter 402 insufficient-credits error body (shape per OpenRouter's public
// error documentation): the request was refused before any provider was chosen.
function insufficientCreditBody() {
  return {
    error: {
      message: 'This request requires more credits, or fewer max_tokens.',
      code: 402,
      metadata: { limit_source: 'openrouter_credits', provider_name: null },
    },
  };
}

// An HTTP 402 (insufficient credit balance) is rejected by OpenRouter before the request is routed
// to any provider -- provider_name null, zero tokens generated, real spend provably zero. But a
// 402 is a RECEIVED response, so it never reaches the FAILURE branch's zero-cost list; without
// special handling it would fall through to the "no verifiable cost" worst-case halt and be charged
// the FULL reservation as UNKNOWN_WORST_CASE_CHARGED. A pre-inference 4xx rejection has zero spend
// and must not be charged the reservation.
test('an HTTP 402 pre-inference rejection is charged nothing, not the full reservation', async () => {
  const dispatch = { async dispatch() { return responseEnvelopeWithStatus(402, insufficientCreditBody()); } };
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.grok.costUsd, 0, 'a request the provider never ran must cost nothing');
    assert.equal(result.reviewers.grok.costKind, 'ZERO_ON_PROVIDER_REJECTION');
  }, { dispatch });
});

// The safety half, and the reason the zero-cost rule must stay narrow: treating a 4xx
// pre-inference reject as zero-cost is safe, but a 5xx (or 408, or a mid-stream disconnect) is
// NOT -- inference may already have started and been billed, so assuming zero there would
// UNDER-record real spend, the more dangerous direction. The same reasoning keeps
// RESPONSE_READ_FAILED worst-case-charged.
test('an HTTP 502 is NOT treated as zero-cost -- inference may already have been billed', async () => {
  const dispatch = { async dispatch() { return responseEnvelopeWithStatus(502, { error: { message: 'bad gateway' } }); } };
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.grok.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.ok(result.reviewers.grok.costUsd > 0, 'a server-side failure must stay conservatively charged');
  }, { dispatch });
});

// The status code alone is not sufficient: the safe case is a completed 4xx
// with a null provider AND zero tokens generated. A body that shows real generation must stay
// worst-case-charged even under a 4xx status, or a provider that bills before returning a 4xx
// would have its real spend silently written off.
test('a 4xx whose body shows generated tokens is NOT treated as zero-cost', async () => {
  const dispatch = {
    async dispatch() {
      return responseEnvelopeWithStatus(429, {
        error: { message: 'rate limited after partial generation' },
        usage: { completion_tokens: 128 },
      });
    },
  };
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.grok.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  }, { dispatch });
});

// A data-root lock timeout is not a dispatch failure either. With several server instances
// connected, contention for the ledger's write lock is ordinary, so a reconcile that times out on
// it must not advance the consecutive-dispatch-failure streak, or routine contention would raise
// that alert about a healthy pipeline. The money outcome is deliberately UNCHANGED: the rejection
// loop still reconciles the job at its full reservation and still reports it DISPATCH_UNKNOWN,
// exactly as the plain-error test above pins.
test('a clean-pass reconcile rejected LEDGER_DATA_ROOT_LOCKED records no dispatch-health failure, and its money outcome is unchanged: charged the full reservation, reported DISPATCH_UNKNOWN', async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  const healthOutcomes = [];
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    await withEngine(async ({ engine, leaseStore }) => {
      // final_verification_v1 with an empty changeKinds dispatches grok alone.
      const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
      const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
      const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      assert.deepEqual(healthOutcomes, [], 'a data-root lock timeout must not be recorded as a dispatch-health failure');
      assert.equal(result.state, 'HALTED');
      assert.equal(result.reviewers.grok.error.code, 'DISPATCH_UNKNOWN', 'the reported classification is unchanged');
      assert.match(result.reviewers.grok.error.message, /LEDGER_DATA_ROOT_LOCKED \(detail redacted/, 'the redacted detail names the busy ledger');
      const grokJob = await leaseStore.getJob(grokJobId);
      assert.equal(grokJob.state, 'RECONCILED');
      assert.equal(grokJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED', 'money unchanged: the recovery reconcile still charges worst case');
      assert.equal(grokJob.costUsd, grokMaxUsd);
    }, {
      dispatch,
      // The store's own lock-timeout shape (lease-store.mjs dataRootLockedError), on EVERY clean-pass
      // (KNOWN) reconcile. The engine retries that reconcile within a bounded budget (see the
      // bounded-retry tests below), so
      // the lock must outlast the budget for the rejection loop to be reached at all; this no-wait
      // sleep spends the budget on the fake clock. The loop's worst-case recovery reconcile, which is
      // never retried, then succeeds.
      sleep: async (ms, { advance }) => { advance(ms); },
      wrapStore: (inner) => ({
        ...inner,
        async reconcile(jobId, costs) {
          if (costs.costKind === 'KNOWN') {
            throw Object.assign(new Error('ledger data root is locked'), { code: LEDGER_DATA_ROOT_LOCKED_CODE });
          }
          return inner.reconcile(jobId, costs);
        },
      }),
      dispatchHealthStore: {
        async recordOutcome({ succeeded }) { healthOutcomes.push(succeeded); return { shouldAlert: false }; },
        async markAlerted() {},
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// ---------------------------------------------------------------------------
// Bounded retry of a reconcile that lost only the ledger lock: a reconcile that records a real
// dispatch outcome and loses only the ledger lock is retried within a bounded budget, same call and
// same ownerToken, before the standard fallback path runs. Nothing else is retried.
// ---------------------------------------------------------------------------

// The store's own lock-timeout shape (lease-store.mjs dataRootLockedError), by its exported code.
function ledgerLockTimeoutError() {
  return Object.assign(new Error('ledger data root is locked'), { code: LEDGER_DATA_ROOT_LOCKED_CODE });
}

// A fake for the engine's `sleep` option, through withEngine's `sleep`: it records each delay the
// retry asks for and moves the harness's fake clock forward by it, so no real time passes.
function recordingFakeSleep() {
  const sleeps = [];
  return { sleeps, async sleep(ms, { advance }) { sleeps.push(ms); advance(ms); } };
}

function recordingHealthStore(healthOutcomes) {
  return {
    async recordOutcome({ succeeded }) { healthOutcomes.push(succeeded); return { shouldAlert: false }; },
    async markAlerted() {},
  };
}

function isEqualJitterDraw(ms) {
  return ms >= LEDGER_BUSY_RECONCILE_RETRY_BASE_MS / 2 && ms < LEDGER_BUSY_RECONCILE_RETRY_BASE_MS;
}

test('a clean-pass reconcile that loses the ledger lock once is retried and books the real cost: RECONCILED at KNOWN, the review content returned, one dispatch-health success, one reconcile committed', async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  const healthOutcomes = [];
  const committed = [];
  let lockTimeoutsThrown = 0;
  const { sleeps, sleep } = recordingFakeSleep();
  await withEngine(async ({ engine, leaseStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(lockTimeoutsThrown, 1, 'precondition: the clean-pass reconcile lost the lock once');
    assert.equal(result.state, 'PASSED', 'the retried reconcile succeeded, so the review passed');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok.costUsd, 0.02);
    assert.equal(result.reviewers.grok.advisory.verdict, 'pass', 'the review content is returned');
    assert.deepEqual(healthOutcomes, [true], 'one dispatch-health success, and no failure');
    assert.deepEqual(committed, ['KNOWN'], 'exactly one reconcile was committed');
    assert.equal(sleeps.length, 1, 'one jittered sleep, before the one retry');
    assert.ok(isEqualJitterDraw(sleeps[0]), `the sleep is an equal-jitter draw: ${sleeps[0]}`);
    const grokJob = await leaseStore.getJob(grokJobId);
    assert.equal(grokJob.state, 'RECONCILED');
    assert.equal(grokJob.costKind, 'KNOWN');
    assert.equal(grokJob.costUsd, 0.02, 'charged its real cost, never the reservation');
  }, {
    dispatch,
    sleep,
    wrapStore: (inner) => ({
      ...inner,
      async reconcile(jobId, costs) {
        if (lockTimeoutsThrown === 0) {
          lockTimeoutsThrown += 1;
          throw ledgerLockTimeoutError();
        }
        const reconciled = await inner.reconcile(jobId, costs);
        committed.push(costs.costKind);
        return reconciled;
      },
    }),
    dispatchHealthStore: recordingHealthStore(healthOutcomes),
  });
});

test('a lock timeout that outlasts the retry budget, spent on the fake clock, falls through to the standard path: charged the full reservation, reported DISPATCH_UNKNOWN, no dispatch-health failure', async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  // Far more lock timeouts than the budget allows attempts. Were the budget ignored, the retry would
  // outlast them and book the real cost, so this test reddens instead of hanging.
  const lockTimeouts = 1000;
  const healthOutcomes = [];
  let knownAttempts = 0;
  const { sleeps, sleep } = recordingFakeSleep();
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    await withEngine(async ({ engine, leaseStore }) => {
      const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
      const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
      const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      assert.ok(sleeps.length > 0, 'the lock timeout was retried');
      const slept = sleeps.reduce((total, ms) => total + ms, 0);
      assert.ok(slept <= LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS, `the sleeps stay inside the budget: ${slept} ms`);
      assert.ok(slept > LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS - LEDGER_BUSY_RECONCILE_RETRY_BASE_MS, `the retry stopped only when its next sleep would pass the budget: ${slept} ms`);
      assert.ok(sleeps.every(isEqualJitterDraw), `every sleep is an equal-jitter draw: ${sleeps.join(', ')}`);
      assert.ok(new Set(sleeps).size > 1, 'the sleeps are jittered, not one fixed interval');
      assert.equal(knownAttempts, sleeps.length + 1, 'one attempt before the first sleep, and one after each');
      assert.deepEqual(healthOutcomes, [], 'a lock timeout is still not a dispatch-health failure');
      assert.equal(result.state, 'HALTED');
      assert.equal(result.reviewers.grok.error.code, 'DISPATCH_UNKNOWN', 'the classification is unchanged');
      const grokJob = await leaseStore.getJob(grokJobId);
      assert.equal(grokJob.state, 'RECONCILED');
      assert.equal(grokJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED', 'the worst-case recovery reconcile is unchanged');
      assert.equal(grokJob.costUsd, grokMaxUsd);
    }, {
      dispatch,
      sleep,
      wrapStore: (inner) => ({
        ...inner,
        async reconcile(jobId, costs) {
          if (costs.costKind === 'KNOWN' && knownAttempts < lockTimeouts) {
            knownAttempts += 1;
            throw ledgerLockTimeoutError();
          }
          return inner.reconcile(jobId, costs);
        },
      }),
      dispatchHealthStore: recordingHealthStore(healthOutcomes),
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

test('a reconcile rejection that is not the lock code is never retried, whether a plain error or a lost ownership: one attempt, no sleep, then the standard path', async () => {
  const dispatch = { async dispatch() { return responseEnvelope(grokPassBody()); } };
  const cases = [
    { name: 'a plain error', makeError: () => new Error('simulated reconcile failure'), code: 'DISPATCH_UNKNOWN', health: [false] },
    // The exact message lease-store.mjs's assertCurrentlyOwnsProcess() throws.
    { name: 'a lost ownership', makeError: () => new Error('caller does not currently hold process ownership of this data root'), code: 'PROCESS_OWNERSHIP_LOST', health: [] },
  ];
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    for (const { name, makeError, code, health } of cases) {
      const healthOutcomes = [];
      let knownAttempts = 0;
      const { sleeps, sleep } = recordingFakeSleep();
      // eslint-disable-next-line no-await-in-loop
      await withEngine(async ({ engine, leaseStore }) => {
        const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
        const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
        const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

        assert.equal(knownAttempts, 1, `${name}: exactly one reconcile attempt, never retried`);
        assert.deepEqual(sleeps, [], `${name}: no retry sleep`);
        assert.equal(result.reviewers.grok.error.code, code, `${name}: the classification is unchanged`);
        assert.deepEqual(healthOutcomes, health, `${name}: the dispatch-health outcome is unchanged`);
        const grokJob = await leaseStore.getJob(grokJobId);
        if (code === 'PROCESS_OWNERSHIP_LOST') {
          assert.equal(grokJob.state, 'RESERVED', 'a stale owner cannot commit the fallback either');
          assert.equal(grokJob.costKind, undefined, 'no reconcile under a stale token can book a charge');
        } else {
          assert.equal(grokJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED', `${name}: the worst-case recovery reconcile is unchanged`);
        }
      }, {
        dispatch,
        sleep,
        wrapStore: (inner) => ({
          ...inner,
          async reconcile(jobId, costs) {
            if (costs.costKind === 'KNOWN') {
              knownAttempts += 1;
              throw makeError();
            }
            if (code === 'PROCESS_OWNERSHIP_LOST') throw makeError();
            return inner.reconcile(jobId, costs);
          },
        }),
        dispatchHealthStore: recordingHealthStore(healthOutcomes),
      });
    }
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

test('a halt that records a real dispatch outcome gets the same recovery: haltAndClose\'s reconcile, losing the lock once, is retried and books the halt at its known cost', async () => {
  // Grok answers, but from the wrong provider: a real outcome, halted PROVIDER_MISMATCH at a known cost.
  const dispatch = { async dispatch() { return responseEnvelope({ ...grokPassBody(), provider: 'NotXai' }); } };
  const healthOutcomes = [];
  const committed = [];
  let lockTimeoutsThrown = 0;
  const { sleeps, sleep } = recordingFakeSleep();
  await withEngine(async ({ engine, leaseStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(lockTimeoutsThrown, 1, 'precondition: the halt\'s reconcile lost the lock once');
    assert.equal(result.reviewers.grok.error.code, 'PROVIDER_MISMATCH', 'the real halt is reported, not DISPATCH_UNKNOWN');
    assert.equal(result.state, 'HALTED');
    assert.deepEqual(committed, ['KNOWN'], 'exactly one reconcile was committed: the halt\'s own');
    assert.equal(sleeps.length, 1, 'one jittered sleep, before the one retry');
    assert.deepEqual(healthOutcomes, [false], 'a real halt still records its one dispatch-health failure');
    const grokJob = await leaseStore.getJob(grokJobId);
    assert.equal(grokJob.costKind, 'KNOWN');
    assert.equal(grokJob.costUsd, 0.02, 'charged its known cost, never the reservation');
    assert.equal(grokJob.haltReason, 'PROVIDER_MISMATCH', 'recorded as a known-cost halt');
  }, {
    dispatch,
    sleep,
    wrapStore: (inner) => ({
      ...inner,
      async reconcile(jobId, costs) {
        if (lockTimeoutsThrown === 0) {
          lockTimeoutsThrown += 1;
          throw ledgerLockTimeoutError();
        }
        const reconciled = await inner.reconcile(jobId, costs);
        committed.push(costs.costKind);
        return reconciled;
      },
    }),
    dispatchHealthStore: recordingHealthStore(healthOutcomes),
  });
});

test('a DISPATCH_UNKNOWN halt records no real outcome, so its reconcile keeps a single attempt: its lock timeout reaches the rejection loop unretried', async () => {
  const dispatch = { async dispatch() { throw new Error('simulated dispatch adapter failure'); } };
  const healthOutcomes = [];
  const committed = [];
  let lockTimeoutsThrown = 0;
  const { sleeps, sleep } = recordingFakeSleep();
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    await withEngine(async ({ engine }) => {
      const { leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

      assert.deepEqual(sleeps, [], 'the DISPATCH_UNKNOWN halt\'s reconcile is never retried');
      assert.equal(lockTimeoutsThrown, 1, 'precondition: that reconcile lost the lock');
      assert.match(result.reviewers.grok.error.message, /rejected unexpectedly: LEDGER_DATA_ROOT_LOCKED \(detail redacted/, 'the halt\'s lock timeout reached the rejection loop');
      assert.equal(result.reviewers.grok.error.code, 'DISPATCH_UNKNOWN');
      assert.deepEqual(committed, ['UNKNOWN_WORST_CASE_CHARGED'], 'only the rejection loop\'s recovery reconcile committed');
      assert.deepEqual(healthOutcomes, [], 'a lock timeout is not a dispatch-health failure');
    }, {
      dispatch,
      sleep,
      wrapStore: (inner) => ({
        ...inner,
        async reconcile(jobId, costs) {
          if (lockTimeoutsThrown === 0) {
            lockTimeoutsThrown += 1;
            throw ledgerLockTimeoutError();
          }
          const reconciled = await inner.reconcile(jobId, costs);
          committed.push(costs.costKind);
          return reconciled;
        },
      }),
      dispatchHealthStore: recordingHealthStore(healthOutcomes),
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

for (const wallClock of ['frozen', 'backward']) {
  for (const realHalt of [false, true]) {
    test(`reconcile retry budget regression: slow lock attempts count with a ${wallClock} wall clock, real halt=${realHalt}`, async () => {
      const lockWaitMs = 2_000;
      let elapsed = 0;
      let attempts = 0;
      let dispatches = 0;
      const sleeps = [];
      const healthOutcomes = [];
      const originalStderrWrite = process.stderr.write;
      process.stderr.write = () => true;
      try {
        await withEngine(async ({ engine, leaseStore }) => {
          const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
          const jobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
          const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
          assert.ok(attempts > 1, 'the completed response was retried');
          assert.ok(elapsed <= LEDGER_BUSY_RECONCILE_RETRY_BUDGET_MS + lockWaitMs,
            `attempt waits and sleeps must fit the budget plus one final lock wait; elapsed=${elapsed}`);
          assert.equal(dispatches, 1, 'reconciliation retries never redispatch');
          assert.equal(result.state, 'HALTED');
          assert.equal(result.reviewers.grok.error.code, 'DISPATCH_UNKNOWN', 'the approved exhausted-budget fallback is unchanged');
          assert.deepEqual(healthOutcomes, [], 'local lock contention is not a dispatch-health failure, including after a real provider halt');
          const job = await leaseStore.getJob(jobId);
          assert.equal(job.state, 'RECONCILED');
          assert.equal(job.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
          assert.equal(job.costUsd, preflight.itemMaxima.find(item => item.itemId === 'item-grok').maxUsd);
          assert.ok(sleeps.every(isEqualJitterDraw));
        }, {
          monotonicNow: () => elapsed,
          sleep: async ms => { sleeps.push(ms); elapsed += ms; },
          dispatch: { async dispatch() {
            dispatches += 1;
            return responseEnvelope(realHalt ? { ...grokPassBody(), provider: 'NotXai' } : grokPassBody());
          } },
          wrapStore: (inner, { advance }) => ({
            ...inner,
            async reconcile(jobId, costs) {
              if (costs.costKind === 'KNOWN' && attempts < 100) {
                attempts += 1;
                elapsed += lockWaitMs;
                if (wallClock === 'backward') advance(-lockWaitMs);
                throw ledgerLockTimeoutError();
              }
              return inner.reconcile(jobId, costs);
            },
          }),
          dispatchHealthStore: recordingHealthStore(healthOutcomes),
        });
      } finally {
        process.stderr.write = originalStderrWrite;
      }
    });
  }
}
