import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { resolveDocumentOutcome } from '../src/local-mcp/review-engine.mjs';

const HASH = 'a'.repeat(64);

// Mirrors review-engine.mjs's own private deriveJobId() formula exactly (src/local-mcp/review-engine.mjs,
// "Deterministic per-(lease, reviewer, contract) job identity") -- deliberately not exported, matching
// this project's own established convention of keeping it private (see e.g. the cross-lease-dedup
// tests' own comment on this), so a test that needs to seed a specific job replicates the formula
// here. If this formula ever changes, every test in this file that computes a jobId must change too.
function deriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8').digest('hex');
}

async function withStores(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-ledger-check-'));
  let now = Date.parse('2026-09-01T10:00:00.000Z');
  const leaseStore = createLeaseStore({ dataRoot, clock: () => now });
  // createLease()/consume()/reconcile() are all
  // owner-sensitive -- a REAL acquireProcessOwnership() call is required here, not a fake
  // acquisitionId, since this is a real leaseStore fixture, not a fake collaborator.
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const resultStore = createResultStore({ dataRoot });
  try {
    await run({ leaseStore, ownerLock, resultStore, advance: (ms) => { now += ms; } });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 = 'e'.repeat(64), itemMaxima = [{ itemId: 'item-gemini', maxUsd: 0.20 }] } = {}) {
  return leaseStore.createPreflight({
    reviewContractSha256: HASH,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256,
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'c'.repeat(64),
    registrySha256: 'd'.repeat(64),
    itemMaxima,
    requestedUsd: itemMaxima.reduce((total, item) => total + item.maxUsd, 0),
    expiresAt,
  });
}

test('resolveDocumentOutcome: SUCCEEDED when the only expected reviewer is RECONCILED with real recorded content', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId });
    const jobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(jobId, { costUsd: 0.10, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });
    await resultStore.record({ jobId, advisory: { verdict: 'pass', findings: [] } });

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'SUCCEEDED');
  });
});

test('resolveDocumentOutcome: SUCCEEDED requires ALL expected reviewers to succeed (positive multi-reviewer case)', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const itemMaxima = [{ itemId: 'item-gemini', maxUsd: 0.20 }, { itemId: 'item-grok', maxUsd: 0.20 }];
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256, itemMaxima });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.40, maxJobs: 2, expiresAt, acquisitionId: ownerLock.acquisitionId });

    for (const reviewerId of ['gemini', 'grok']) {
      const jobId = deriveJobId(lease.id, reviewerId, lease.reviewContractSha256);
      await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId, reviewerId, acquisitionId: ownerLock.acquisitionId });
      await leaseStore.reconcile(jobId, { costUsd: 0.10, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });
      await resultStore.record({ jobId, advisory: { verdict: 'pass', findings: [] } });
    }

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'SUCCEEDED');
  });
});

test('resolveDocumentOutcome: AMBIGUOUS (not FAILED) when reviewers are MIXED -- one succeeded, one halted -- a mix is not proof the review failed', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const itemMaxima = [{ itemId: 'item-gemini', maxUsd: 0.20 }, { itemId: 'item-grok', maxUsd: 0.20 }];
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256, itemMaxima });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.40, maxJobs: 2, expiresAt, acquisitionId: ownerLock.acquisitionId });

    const geminiJobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(geminiJobId, { costUsd: 0.10, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });
    await resultStore.record({ jobId: geminiJobId, advisory: { verdict: 'pass', findings: [] } });

    const grokJobId = deriveJobId(lease.id, 'grok', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId: grokJobId, reviewerId: 'grok', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(grokJobId, { costUsd: 0.10, costKind: 'KNOWN', haltReason: 'PROVIDER_MISMATCH', acquisitionId: ownerLock.acquisitionId });

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'AMBIGUOUS');
  });
});

test('resolveDocumentOutcome: FAILED requires ALL expected reviewers to genuinely fail, not just one (positive multi-reviewer case)', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const itemMaxima = [{ itemId: 'item-gemini', maxUsd: 0.20 }, { itemId: 'item-grok', maxUsd: 0.20 }];
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256, itemMaxima });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.40, maxJobs: 2, expiresAt, acquisitionId: ownerLock.acquisitionId });

    const geminiJobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(geminiJobId, { costUsd: 0.10, costKind: 'KNOWN', haltReason: 'PROVIDER_MISMATCH', acquisitionId: ownerLock.acquisitionId });

    const grokJobId = deriveJobId(lease.id, 'grok', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId: grokJobId, reviewerId: 'grok', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(grokJobId, { costUsd: 0.10, costKind: 'KNOWN', haltReason: 'STRICT_OUTPUT_INVALID', acquisitionId: ownerLock.acquisitionId });

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'FAILED');
  });
});

test('resolveDocumentOutcome: FAILED when a reviewer RECONCILED with a haltReason (e.g. PROVIDER_MISMATCH)', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId });
    const jobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(jobId, { costUsd: 0.10, costKind: 'KNOWN', haltReason: 'PROVIDER_MISMATCH', acquisitionId: ownerLock.acquisitionId });

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'FAILED');
  });
});

test('resolveDocumentOutcome: FAILED when a reviewer RECONCILED with no recorded content (e.g. an orphan-recovery worst-case charge)', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId });
    const jobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    // Mirrors sweepOrphanedLeases()'s own reconcile shape: no haltReason, no resultStore content.
    await leaseStore.reconcile(jobId, { costUsd: 0.20, costKind: 'UNKNOWN_WORST_CASE_CHARGED', acquisitionId: ownerLock.acquisitionId });

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'FAILED');
  });
});

test('resolveDocumentOutcome: AMBIGUOUS when the expected reviewer was never dispatched at all, lease NOT yet expired', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    await leaseStore.createLease({
      preflightIds: [(await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 })).id],
      requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId,
    });
    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'AMBIGUOUS');
  });
});

test('resolveDocumentOutcome: a reviewer never dispatched at all on an ALREADY expired lease is still AMBIGUOUS, not FAILED', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore, advance }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    await leaseStore.createLease({
      preflightIds: [(await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 })).id],
      requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId,
    });
    advance(11 * 60 * 1000); // past expiresAt -- a manufactured "prior failure" must NOT read as FAILED
    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'AMBIGUOUS');
  });
});

test('resolveDocumentOutcome: AMBIGUOUS when a reviewer job is still RESERVED (possibly in flight)', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId });
    const jobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    // Deliberately never reconciled -- a genuinely in-flight (or not-yet-swept orphaned) dispatch.

    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256 }), 'AMBIGUOUS');
  });
});

test('resolveDocumentOutcome: AMBIGUOUS when no lease has ever been created for this document', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    assert.equal(await resolveDocumentOutcome({ leaseStore, resultStore, rawSourceSha256: 'f'.repeat(64) }), 'AMBIGUOUS');
  });
});

test('resolveDocumentOutcome: AMBIGUOUS when an unexpected error is thrown, never propagated', async () => {
  await withStores(async ({ leaseStore, ownerLock }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 });
    const lease = await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId });
    const jobId = deriveJobId(lease.id, 'gemini', lease.reviewContractSha256);
    await leaseStore.consume(lease.id, HASH, { reservationUsd: 0.20, jobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId });
    await leaseStore.reconcile(jobId, { costUsd: 0.10, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });
    const throwingResultStore = { async recall() { throw new Error('disk read failure'); } };

    const outcome = await resolveDocumentOutcome({ leaseStore, resultStore: throwingResultStore, rawSourceSha256 });
    assert.equal(outcome, 'AMBIGUOUS');
  });
});

test('resolveDocumentOutcome: never calls any leaseStore mutation (structural money-safety proof)', async () => {
  await withStores(async ({ leaseStore, ownerLock, resultStore }) => {
    const expiresAt = '2026-09-01T10:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(leaseStore, expiresAt, { rawSourceSha256 });
    await leaseStore.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId: ownerLock.acquisitionId });

    const calledMutations = [];
    const trackCall = (name) => async (...args) => { calledMutations.push(name); return leaseStore[name](...args); };
    const guardedLeaseStore = {
      getMostRecentLeaseForRawSource: leaseStore.getMostRecentLeaseForRawSource,
      getPreflight: leaseStore.getPreflight,
      getJob: leaseStore.getJob,
      consume: trackCall('consume'),
      reconcile: trackCall('reconcile'),
      createLease: trackCall('createLease'),
      createPreflight: trackCall('createPreflight'),
      close: trackCall('close'),
    };

    await resolveDocumentOutcome({ leaseStore: guardedLeaseStore, resultStore, rawSourceSha256 });
    assert.deepEqual(calledMutations, [], 'resolveDocumentOutcome must never call a leaseStore mutation method');
  });
});

test('resolveDocumentOutcome: AMBIGUOUS even when called with no arguments at all, never a rejected promise', async () => {
  const outcome = await resolveDocumentOutcome();
  assert.equal(outcome, 'AMBIGUOUS');
});
