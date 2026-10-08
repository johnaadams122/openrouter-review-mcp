import assert from 'node:assert/strict';
import test from 'node:test';
import { reserveReviewers } from '../src/local-mcp/review-engine.mjs';

// Unit tests for reserveReviewers(), the reservation step of review(), driven against a
// hand-built fake leaseStore rather than the real one, so every one of the four stop-reason cases
// and the three-check ordering rule can be driven directly instead of contrived through a full
// review() call. Fully offline: no dispatch adapter, no credential, no network.

const CONTRACT = 'a'.repeat(64);
const LEASE_ID = 'lease-1';
const EXPIRES_AT_MS = 1_000_000;

function candidate(reviewerId, { reservationUsd = 0.2, countsTowardDailyAllowance = true } = {}) {
  return { reviewerId, jobId: `job-${reviewerId}`, reservationUsd, countsTowardDailyAllowance };
}

/**
 * Records every call in one ordered log so a test can assert not just WHAT was called but in what
 * ORDER, and prove that a check which should have short-circuited really did prevent the later
 * ones from running at all.
 */
function createFakeLeaseStore({ priorJobsByReviewer = {}, consumeBehavior, findJobsBehavior } = {}) {
  const calls = [];
  return {
    calls,
    async findJobsForReviewerContract(reviewContractSha256, reviewerId) {
      calls.push({ method: 'findJobsForReviewerContract', reviewerId, reviewContractSha256 });
      if (findJobsBehavior) await findJobsBehavior({ reviewerId });
      const entry = priorJobsByReviewer[reviewerId];
      return entry === undefined ? [] : entry;
    },
    async consume(leaseId, reviewContractSha256, options) {
      calls.push({
        method: 'consume',
        leaseId,
        reviewContractSha256,
        reviewerId: options.reviewerId,
        jobId: options.jobId,
        reservationUsd: options.reservationUsd,
        countsTowardDailyAllowance: options.countsTowardDailyAllowance,
      });
      if (consumeBehavior) await consumeBehavior(options);
      return { id: options.jobId, state: 'RESERVED' };
    },
  };
}

// A minimal, always-owning stand-in matching the real shape leaseStore.acquireProcessOwnership()
// returns. Safe here because this file's own createFakeLeaseStore() above is a fully hand-built
// fake with no real ownership concept of its own -- reserveReviewers() itself never inspects its
// ownerToken (a frozen snapshot of this fake's id) beyond reading .acquisitionId to pass through
// to consume(), so a merely shape-valid fake is sufficient.
function createFakeOwnerLock({ acquisitionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } = {}) {
  return { dataRoot: '/fake', generation: 1, acquisitionId, isOwner: () => true, async release() {} };
}

function reserve(leaseStore, { candidates, nowMs = 0 }) {
  return reserveReviewers({
    leaseStore,
    clock: () => nowMs,
    leaseId: LEASE_ID,
    leaseExpiresAtMs: EXPIRES_AT_MS,
    reviewContractSha256: CONTRACT,
    candidates,
    ownerToken: Object.freeze({ acquisitionId: createFakeOwnerLock().acquisitionId }),
  });
}

test('reserving every candidate cleanly returns them all with a null stopReason', async () => {
  const leaseStore = createFakeLeaseStore();
  const result = await reserve(leaseStore, { candidates: [candidate('gemini'), candidate('grok')] });

  assert.deepEqual(result.reservedReviewerIds, ['gemini', 'grok']);
  assert.equal(result.stopReason, null);
  assert.equal(result.ordinaryFailureError, null);
  assert.equal(result.stopDetail, null);
  assert.deepEqual(
    leaseStore.calls.map((call) => `${call.method}:${call.reviewerId}`),
    ['findJobsForReviewerContract:gemini', 'consume:gemini', 'findJobsForReviewerContract:grok', 'consume:grok'],
  );
});

test('consume() receives the reservation amount, jobId, reviewerId and daily-allowance flag each candidate carries', async () => {
  const leaseStore = createFakeLeaseStore();
  await reserve(leaseStore, {
    candidates: [candidate('gemini', { reservationUsd: 0.3, countsTowardDailyAllowance: true }),
      candidate('nemotron_super', { reservationUsd: 0, countsTowardDailyAllowance: false })],
  });

  const consumes = leaseStore.calls.filter((call) => call.method === 'consume');
  assert.deepEqual(consumes[0], {
    method: 'consume', leaseId: LEASE_ID, reviewContractSha256: CONTRACT, reviewerId: 'gemini',
    jobId: 'job-gemini', reservationUsd: 0.3, countsTowardDailyAllowance: true,
  });
  assert.deepEqual(consumes[1], {
    method: 'consume', leaseId: LEASE_ID, reviewContractSha256: CONTRACT, reviewerId: 'nemotron_super',
    jobId: 'job-nemotron_super', reservationUsd: 0, countsTowardDailyAllowance: false,
  });
});

test('an expired lease stops with LEASE_EXPIRED and never reaches the duplicate check or consume()', async () => {
  // The duplicate would ALSO fire and consume() would ALSO succeed if either were reached -- so a
  // LEASE_EXPIRED result here can only mean the expiry check genuinely ran first.
  const leaseStore = createFakeLeaseStore({
    priorJobsByReviewer: { gemini: [{ id: 'other-job', state: 'RESERVED' }] },
  });
  const result = await reserve(leaseStore, {
    candidates: [candidate('gemini'), candidate('grok')],
    nowMs: EXPIRES_AT_MS,
  });

  assert.deepEqual(result.reservedReviewerIds, []);
  assert.equal(result.stopReason, 'LEASE_EXPIRED');
  assert.equal(result.ordinaryFailureError, null);
  assert.deepEqual(result.stopDetail, { reviewerId: 'gemini', jobId: null });
  assert.deepEqual(leaseStore.calls, [], 'neither the duplicate re-check nor consume() may run once the lease has expired');
});

test('a cross-lease duplicate found by the re-check stops with DUPLICATE_IN_PROGRESS and never calls consume()', async () => {
  const leaseStore = createFakeLeaseStore({
    priorJobsByReviewer: { grok: [{ id: 'in-flight-grok-job', state: 'RESERVED' }] },
  });
  const result = await reserve(leaseStore, { candidates: [candidate('gemini'), candidate('grok')] });

  assert.deepEqual(result.reservedReviewerIds, ['gemini'], 'gemini reserved before the stop and must still be reported');
  assert.equal(result.stopReason, 'DUPLICATE_IN_PROGRESS');
  assert.equal(result.ordinaryFailureError, null);
  assert.deepEqual(result.stopDetail, { reviewerId: 'grok', jobId: 'in-flight-grok-job' });
  assert.equal(leaseStore.calls.filter((call) => call.method === 'consume' && call.reviewerId === 'grok').length, 0);
});

test('a prior job that is not RESERVED (already reconciled elsewhere) is not a duplicate and does not stop the pass', async () => {
  const leaseStore = createFakeLeaseStore({
    priorJobsByReviewer: { grok: [{ id: 'done-grok-job', state: 'RECONCILED' }] },
  });
  const result = await reserve(leaseStore, { candidates: [candidate('gemini'), candidate('grok')] });

  assert.deepEqual(result.reservedReviewerIds, ['gemini', 'grok']);
  assert.equal(result.stopReason, null);
});

test('a consume() throw for any other reason stops with ORDINARY_FAILURE and carries the original error', async () => {
  const capExceeded = new RangeError('lease cap exceeded');
  const leaseStore = createFakeLeaseStore({
    async consumeBehavior(options) { if (options.reviewerId === 'grok') throw capExceeded; },
  });
  const result = await reserve(leaseStore, { candidates: [candidate('gemini'), candidate('grok')] });

  assert.deepEqual(result.reservedReviewerIds, ['gemini'], 'an already-reserved reviewer is never abandoned by a later failure');
  assert.equal(result.stopReason, 'ORDINARY_FAILURE');
  assert.equal(result.ordinaryFailureError, capExceeded);
  assert.deepEqual(result.stopDetail, { reviewerId: 'grok', jobId: 'job-grok' });
});

test('a findJobsForReviewerContract() throw for any other reason also stops with ORDINARY_FAILURE, never an uncaught rejection', async () => {
  // Mirrors the consume()-throw test above, but injects the throw into check 2 (the cross-lease
  // duplicate re-check) instead of check 3 (consume()). Both calls are real, lock-serialized store
  // I/O (lease-store.mjs) that can fail the same way -- this proves the pre-fix code caught only
  // consume()'s throw and left this one to reject reserveReviewers() itself, orphaning
  // reservedReviewerIds and the ACTIVE lease with no stopReason at all.
  const lockContention = new Error('lease store locked by another process');
  const leaseStore = createFakeLeaseStore({
    async findJobsBehavior({ reviewerId }) { if (reviewerId === 'grok') throw lockContention; },
  });
  const result = await reserve(leaseStore, { candidates: [candidate('gemini'), candidate('grok')] });

  assert.deepEqual(result.reservedReviewerIds, ['gemini'], 'an already-reserved reviewer is never abandoned by a later failure');
  assert.equal(result.stopReason, 'ORDINARY_FAILURE');
  assert.equal(result.ordinaryFailureError, lockContention);
  assert.deepEqual(result.stopDetail, { reviewerId: 'grok', jobId: 'job-grok' });
  assert.equal(leaseStore.calls.filter((call) => call.method === 'consume' && call.reviewerId === 'grok').length, 0);
});

test('an empty candidate list is a clean no-op, never a stop', async () => {
  const leaseStore = createFakeLeaseStore();
  const result = await reserve(leaseStore, { candidates: [] });

  assert.deepEqual(result.reservedReviewerIds, []);
  assert.equal(result.stopReason, null);
  assert.deepEqual(leaseStore.calls, []);
});

test('a stop on the very first candidate still returns an empty reservedReviewerIds, never undefined', async () => {
  const leaseStore = createFakeLeaseStore({
    priorJobsByReviewer: { gemini: [{ id: 'in-flight-gemini-job', state: 'RESERVED' }] },
  });
  const result = await reserve(leaseStore, { candidates: [candidate('gemini'), candidate('grok')] });

  assert.deepEqual(result.reservedReviewerIds, []);
  assert.equal(result.stopReason, 'DUPLICATE_IN_PROGRESS');
  assert.equal(leaseStore.calls.filter((call) => call.method === 'consume').length, 0);
});
