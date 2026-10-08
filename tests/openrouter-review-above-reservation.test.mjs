import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';

// A provider can report a cost above the job's reservation (e.g. reasoning tokens billed past
// max_tokens); such a cost is recorded at its real value and flagged `aboveReservation`, instead
// of being booked at the reservation, which would under-record real spend. Recording MORE than was
// reserved can only fail closed (the lease has less room left); the flag has to be explicit so an
// ordinary reconcile can never exceed its reservation by accident.

const HASH = 'a'.repeat(64);
const JOB_ID = 'f'.repeat(64);
const EXPIRES_AT = '2026-09-29T12:10:00.000Z';

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-above-reservation-'));
  const clock = () => Date.parse('2026-09-29T12:00:00.000Z');
  const store = createLeaseStore({ dataRoot, clock });
  try {
    await run({ store, dataRoot, clock });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function reserveOneJob(store, { reservationUsd = 0.20, requestedUsd = 0.40 } = {}) {
  const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
  const preflight = await store.createPreflight({
    reviewContractSha256: HASH,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256: 'e'.repeat(64),
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'c'.repeat(64),
    registrySha256: 'd'.repeat(64),
    itemMaxima: [{ itemId: 'item-grok', maxUsd: reservationUsd }, { itemId: 'item-gemini', maxUsd: requestedUsd - reservationUsd }],
    requestedUsd,
    expiresAt: EXPIRES_AT,
  });
  const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd, maxJobs: 2, expiresAt: EXPIRES_AT, acquisitionId });
  await store.consume(lease.id, HASH, { reservationUsd, jobId: JOB_ID, reviewerId: 'grok', acquisitionId });
  return { acquisitionId, lease };
}

test('a known cost above the reservation is still refused without the explicit flag', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await reserveOneJob(store);
    await assert.rejects(
      () => store.reconcile(JOB_ID, { costUsd: 0.25, costKind: 'KNOWN', acquisitionId }),
      /known cost exceeds reservation/,
    );
  });
});

test('a flagged known cost above the reservation is recorded at its real value and marked', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId, lease } = await reserveOneJob(store);
    const job = await store.reconcile(JOB_ID, { costUsd: 0.25, costKind: 'KNOWN', aboveReservation: true, acquisitionId });
    assert.deepEqual(
      { state: job.state, costUsd: job.costUsd, costKind: job.costKind, aboveReservation: job.aboveReservation, reservationUsd: job.reservationUsd },
      { state: 'RECONCILED', costUsd: 0.25, costKind: 'KNOWN', aboveReservation: true, reservationUsd: 0.20 },
    );
    const updated = await store.getLease(lease.id);
    assert.equal(updated.reservedUsd, 0);
    assert.equal(updated.spentUsd, 0.25);
  });
});

test('an ordinary reconcile carries no aboveReservation field at all', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await reserveOneJob(store);
    const job = await store.reconcile(JOB_ID, { costUsd: 0.10, costKind: 'KNOWN', acquisitionId });
    assert.equal(Object.hasOwn(job, 'aboveReservation'), false);
  });
});

test('the flag must be truthful: it is refused for a cost within the reservation or a non-KNOWN cost', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await reserveOneJob(store);
    await assert.rejects(
      () => store.reconcile(JOB_ID, { costUsd: 0.20, costKind: 'KNOWN', aboveReservation: true, acquisitionId }),
      /aboveReservation/,
    );
    await assert.rejects(
      () => store.reconcile(JOB_ID, { costUsd: 0.25, costKind: 'UNKNOWN_WORST_CASE_CHARGED', aboveReservation: true, acquisitionId }),
      /aboveReservation/,
    );
    await assert.rejects(
      () => store.reconcile(JOB_ID, { costUsd: 0.25, costKind: 'KNOWN', aboveReservation: 'yes', acquisitionId }),
      /aboveReservation/,
    );
    const stillReserved = await store.getJob(JOB_ID);
    assert.equal(stillReserved.state, 'RESERVED');
  });
});

test('after an above-reservation reconcile the lease refuses any reservation it can no longer afford', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId, lease } = await reserveOneJob(store, { reservationUsd: 0.20, requestedUsd: 0.40 });
    await store.reconcile(JOB_ID, { costUsd: 0.30, costKind: 'KNOWN', aboveReservation: true, acquisitionId });
    // 0.30 spent of 0.40 requested: the second reviewer's 0.20 reservation no longer fits.
    await assert.rejects(
      () => store.consume(lease.id, HASH, { reservationUsd: 0.20, jobId: 'e'.repeat(64), reviewerId: 'gemini', acquisitionId }),
      /cap/i,
    );
  });
});

test('a fresh store replaying the ledger sees the real cost and the flag', async () => {
  await withStore(async ({ store, dataRoot, clock }) => {
    const { acquisitionId, lease } = await reserveOneJob(store);
    await store.reconcile(JOB_ID, { costUsd: 0.25, costKind: 'KNOWN', aboveReservation: true, acquisitionId });
    const replayed = createLeaseStore({ dataRoot, clock });
    const job = await replayed.getJob(JOB_ID);
    const replayedLease = await replayed.getLease(lease.id);
    assert.deepEqual(
      { costUsd: job.costUsd, costKind: job.costKind, aboveReservation: job.aboveReservation, spentUsd: replayedLease.spentUsd },
      { costUsd: 0.25, costKind: 'KNOWN', aboveReservation: true, spentUsd: 0.25 },
    );
  });
});
