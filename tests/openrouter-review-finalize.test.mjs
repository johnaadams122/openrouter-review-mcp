import assert from 'node:assert/strict';
import test from 'node:test';
import { finalizeReviewOutcome, ReviewEngineError } from '../src/local-mcp/review-engine.mjs';

// Unit tests for finalizeReviewOutcome, the finalization step of review(). Driven directly against
// fake collaborators so all five priority-ordered branches -- including the vacuous zero-reviewer
// cases -- can be exercised without contriving each one through a full review() call. Fully
// offline.

const LEASE_ID = 'lease-1';
const PREFLIGHT_ID = 'preflight-1';
const CONTRACT = 'b'.repeat(64);

function createFakeLeaseStore({ closeError = null } = {}) {
  const closes = [];
  return {
    closes,
    async close(leaseId, state) {
      closes.push({ leaseId, state });
      if (closeError) throw closeError;
      return { id: leaseId, state };
    },
  };
}

function createSpendProbe() {
  const state = { calls: 0 };
  return { state, async check() { state.calls += 1; } };
}

// A minimal, always-owning stand-in matching the real shape leaseStore.acquireProcessOwnership()
// returns. Safe here because this file's own createFakeLeaseStore() above is a fully hand-built
// fake (its close() doesn't even inspect its third `{acquisitionId}` argument) --
// finalizeReviewOutcome() itself only ever reads ownerToken.acquisitionId (a frozen snapshot of
// this fake's id) to pass through to close(), so a merely shape-valid fake is sufficient.
function createFakeOwnerLock({ acquisitionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } = {}) {
  return { dataRoot: '/fake', generation: 1, acquisitionId, isOwner: () => true, async release() {} };
}

function passedEntry(reviewerId) {
  return {
    reviewerId, jobId: `job-${reviewerId}`, state: 'RECONCILED', costUsd: 0.01, costKind: 'KNOWN',
    advisory: { verdict: 'pass', findings: [] },
  };
}

function haltedEntry(reviewerId, code, message) {
  return {
    reviewerId, jobId: `job-${reviewerId}`, state: 'RECONCILED', costUsd: 0.02,
    costKind: 'UNKNOWN_WORST_CASE_CHARGED', error: { code, message },
  };
}

function finalize({ leaseStore, spendProbe, reviewers = {}, orderedReviewerIds = [], stopReason = null, stopDetail = null, ordinaryFailureError = null }) {
  return finalizeReviewOutcome({
    leaseStore,
    checkSpendAndMaybeAlert: () => spendProbe.check(),
    leaseId: LEASE_ID,
    preflightId: PREFLIGHT_ID,
    reviewContractSha256: CONTRACT,
    reviewers,
    orderedReviewerIds,
    ownerToken: Object.freeze({ acquisitionId: createFakeOwnerLock().acquisitionId }),
    stopReason,
    stopDetail,
    ordinaryFailureError,
  });
}

// --- Branch 4: everyone passed ---------------------------------------------------------------

test('branch 4: every reviewer passed returns PASSED, runs the spend check, and never closes the lease', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: passedEntry('gemini'), grok: passedEntry('grok') };

  const result = await finalize({ leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'] });

  assert.equal(result.state, 'PASSED');
  assert.equal(result.leaseId, LEASE_ID);
  assert.equal(result.preflightId, PREFLIGHT_ID);
  assert.equal(result.reviewContractSha256, CONTRACT);
  assert.equal(result.reviewers, reviewers);
  assert.equal(Object.hasOwn(result, 'error'), false);
  assert.deepEqual(leaseStore.closes, [], 'a fully-clean batch must never close its lease, matching the pre-existing behavior');
  assert.equal(spendProbe.state.calls, 1);
});

test('branch 4 vacuously: zero reviewers with a genuinely null stopReason is PASSED, not a crash', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();

  const result = await finalize({ leaseStore, spendProbe });

  assert.equal(result.state, 'PASSED');
  assert.deepEqual(leaseStore.closes, []);
  assert.equal(spendProbe.state.calls, 1);
});

// --- Branch 5: some reviewer halted ------------------------------------------------------------

test('branch 5: a halted reviewer closes the lease under its own code exactly once and returns HALTED', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: passedEntry('gemini'), grok: haltedEntry('grok', 'TRANSPORT_FAILURE', 'grok transport failed') };

  const result = await finalize({ leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'] });

  assert.equal(result.state, 'HALTED');
  assert.deepEqual(result.error, { code: 'TRANSPORT_FAILURE', message: 'grok transport failed' });
  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'TRANSPORT_FAILURE' }]);
  assert.equal(spendProbe.state.calls, 1);
});

test('branch 5: the top-level reason is the FIRST halt in profile order, not whichever entry happens to enumerate first', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  // `grok` is inserted into the map FIRST on purpose: Object key order would pick it, profile order
  // must pick gemini. This is the deterministic-ordering rule Promise.allSettled cannot give us.
  const reviewers = {
    grok: haltedEntry('grok', 'TRANSPORT_FAILURE', 'grok transport failed'),
    gemini: haltedEntry('gemini', 'PROVIDER_MISMATCH', 'gemini returned the wrong provider'),
  };

  const result = await finalize({ leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'] });

  assert.deepEqual(result.error, { code: 'PROVIDER_MISMATCH', message: 'gemini returned the wrong provider' });
  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'PROVIDER_MISMATCH' }]);
  assert.equal(result.reviewers.gemini.error.code, 'PROVIDER_MISMATCH');
  assert.equal(result.reviewers.grok.error.code, 'TRANSPORT_FAILURE');
});

// --- Branch 1: LEASE_EXPIRED -------------------------------------------------------------------

test('branch 1: a LEASE_EXPIRED stopReason wins even when every dispatched reviewer passed', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: passedEntry('gemini') };

  const result = await finalize({
    leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'],
    stopReason: 'LEASE_EXPIRED', stopDetail: { reviewerId: 'grok', jobId: null },
  });

  assert.equal(result.state, 'HALTED');
  assert.equal(result.error.code, 'LEASE_EXPIRED');
  assert.match(result.error.message, /before reviewer grok could be reserved/);
  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'LEASE_EXPIRED' }]);
  assert.equal(spendProbe.state.calls, 1, 'real dispatches to the reserved subset may have spent real money, so the spend probe must run here too');
});

test('branch 1 vacuously: LEASE_EXPIRED with zero reviewers and nothing dispatched still reports LEASE_EXPIRED, never PASSED', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();

  const result = await finalize({
    leaseStore, spendProbe, stopReason: 'LEASE_EXPIRED', stopDetail: { reviewerId: 'gemini', jobId: null },
  });

  assert.equal(result.state, 'HALTED');
  assert.equal(result.error.code, 'LEASE_EXPIRED');
  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'LEASE_EXPIRED' }]);
  assert.equal(spendProbe.state.calls, 1);
});

// --- Branch 2: DUPLICATE_IN_PROGRESS -----------------------------------------------------------

test('branch 2: a DUPLICATE_IN_PROGRESS stopReason returns a structured HALTED, never a throw, even when every dispatched reviewer passed', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: passedEntry('gemini') };

  const result = await finalize({
    leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'],
    stopReason: 'DUPLICATE_IN_PROGRESS', stopDetail: { reviewerId: 'grok', jobId: 'in-flight-grok-job' },
  });

  assert.equal(result.state, 'HALTED');
  assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');
  assert.match(result.error.message, /reviewer grok already has an in-flight dispatch \(job in-flight-grok-job\)/);
  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'DUPLICATE_DISPATCH_IN_PROGRESS' }]);
  assert.equal(spendProbe.state.calls, 1);
});

test('branch 2 vacuously: DUPLICATE_IN_PROGRESS with zero reviewers still reports the duplicate, never PASSED', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();

  const result = await finalize({
    leaseStore, spendProbe, stopReason: 'DUPLICATE_IN_PROGRESS', stopDetail: { reviewerId: 'gemini', jobId: 'in-flight-gemini-job' },
  });

  assert.equal(result.state, 'HALTED');
  assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');
  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'DUPLICATE_DISPATCH_IN_PROGRESS' }]);
});

// --- Branch 3: ORDINARY_FAILURE ----------------------------------------------------------------

test('branch 3: an ORDINARY_FAILURE finalizes the dispatched subset first, then throws the translated consume() error', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: passedEntry('gemini') };

  await assert.rejects(
    () => finalize({
      leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'],
      stopReason: 'ORDINARY_FAILURE', ordinaryFailureError: new RangeError('lease cap exceeded'),
      stopDetail: { reviewerId: 'grok', jobId: 'job-grok' },
    }),
    (error) => error instanceof ReviewEngineError && error.code === 'LEASE_CAP_EXCEEDED',
  );

  // Branch 4 ran first (gemini passed cleanly), so the lease is deliberately left open and the
  // spend check still fired -- the side effects happen, then the throw is what the caller receives.
  assert.deepEqual(leaseStore.closes, []);
  assert.equal(spendProbe.state.calls, 1);
});

test('branch 3 with a halted dispatched reviewer closes the lease under that halt before throwing', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: haltedEntry('gemini', 'UNKNOWN_COST', 'gemini reported no verifiable cost') };

  await assert.rejects(
    () => finalize({
      leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini', 'grok'],
      stopReason: 'ORDINARY_FAILURE', ordinaryFailureError: new Error('daily dispatch allowance exhausted for 2026-08-31'),
      stopDetail: { reviewerId: 'grok', jobId: 'job-grok' },
    }),
    (error) => error instanceof ReviewEngineError && error.code === 'DAILY_ALLOWANCE_EXCEEDED',
  );

  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'UNKNOWN_COST' }]);
  assert.equal(spendProbe.state.calls, 1);
});

// --- The close guard ---------------------------------------------------------------------------

test('a bug while building the outcome still closes the lease fail-closed and still runs the spend check, then rethrows the real bug', async () => {
  const leaseStore = createFakeLeaseStore();
  const spendProbe = createSpendProbe();
  // orderedReviewerIds is deliberately not an array: `.find` on it throws inside the decision
  // step. This stands in for "a bug elsewhere in this same finalization step throws first" -- an
  // invariant this design must uphold explicitly, since an inline-per-halt close() would have had
  // nothing after it that could fail.
  await assert.rejects(
    () => finalize({ leaseStore, spendProbe, reviewers: {}, orderedReviewerIds: 'not-an-array' }),
    (error) => error instanceof TypeError,
  );

  assert.deepEqual(leaseStore.closes, [{ leaseId: LEASE_ID, state: 'DISPATCH_UNKNOWN' }], 'the lease must never be left ACTIVE with money reserved because the result builder threw');
  assert.equal(spendProbe.state.calls, 1);
});

test('a leaseStore.close() failure still runs the spend check before propagating', async () => {
  const leaseStore = createFakeLeaseStore({ closeError: new Error('lease is closed') });
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: haltedEntry('gemini', 'TRANSPORT_FAILURE', 'gemini transport failed') };

  await assert.rejects(
    () => finalize({ leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini'] }),
    (error) => error.message === 'lease is closed',
  );
  assert.equal(spendProbe.state.calls, 1);
});

// A close() on a business-logic-verified-ACTIVE lease can still throw: lease-store.mjs's
// assertCurrentlyOwnsProcess() rejects a stale/superseded acquisitionId. This proves that failure
// is caught and reclassified as a clean ReviewEngineError instead of escaping as a raw Error --
// toolErrorFromEngineError (openrouter-review-mcp-server.mjs) explicitly rethrows anything that
// isn't a ReviewEngineError rather than formatting a clean tool response, so an unclassified escape
// here would surface to an MCP caller as an opaque crash instead of a diagnosable code.
test('a leaseStore.close() failure caused by a lost process ownership is reclassified as PROCESS_OWNERSHIP_LOST, not a raw Error', async () => {
  const leaseStore = createFakeLeaseStore({ closeError: new Error('caller does not currently hold process ownership of this data root') });
  const spendProbe = createSpendProbe();
  const reviewers = { gemini: haltedEntry('gemini', 'TRANSPORT_FAILURE', 'gemini transport failed') };

  await assert.rejects(
    () => finalize({ leaseStore, spendProbe, reviewers, orderedReviewerIds: ['gemini'] }),
    (error) => error instanceof ReviewEngineError && error.code === 'PROCESS_OWNERSHIP_LOST',
  );
  assert.equal(spendProbe.state.calls, 1, 'the spend check must still run even when close() fails this way');
});
