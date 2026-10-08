import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';

const CONTRACT = 'a'.repeat(64);
const ARM = Object.freeze({
  acquireTimeoutMs: 1_000,
  lockRetryMs: 25,
  caps: Object.freeze({ installationHardMaximumUsd: 5 }),
});

function futureExpiry() {
  return new Date(Date.now() + 10 * 60 * 1000).toISOString();
}

async function withDataRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-ledger-accounting-'));
  try {
    return await run(dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

function physicalReleaseSwitch(dataRoot) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  let blocked = false;
  return {
    setBlocked(value) { blocked = value; },
    async renameImpl(from, to) {
      if (from === lockRoot && blocked) {
        throw Object.assign(new Error('controlled physical cleanup failure'), { code: 'EACCES' });
      }
      return rename(from, to);
    },
  };
}

async function ledgerRecords(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const names = (await readdir(ledgerRoot)).filter((name) => name.endsWith('.json')).sort();
  return Promise.all(names.map(async (name) => JSON.parse(await readFile(join(ledgerRoot, name), 'utf8'))));
}

async function createPreflight(store, id, requestedUsd = 0.30) {
  return store.createPreflight({
    id,
    reviewContractSha256: CONTRACT,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256: 'c'.repeat(64),
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'd'.repeat(64),
    registrySha256: 'e'.repeat(64),
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: requestedUsd }],
    requestedUsd,
    expiresAt: futureExpiry(),
  });
}

async function createActiveLease(store, handle, { preflightId = 'preflight', leaseId = 'lease', requestedUsd = 0.30, maxJobs = 3 } = {}) {
  const preflight = await createPreflight(store, preflightId, requestedUsd);
  await handle.arm(ARM);
  const lease = await store.createLease({
    id: leaseId,
    preflightIds: [preflight.id],
    requestedUsd,
    maxJobs,
    expiresAt: preflight.expiresAt,
    acquisitionId: handle.acquisitionId,
  });
  return { preflight, lease };
}

test('ledger accounting: a committed createLease survives physical cleanup failure and appears once after same-store recovery', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const preflight = await createPreflight(store, 'create-lease-preflight', 0.20);
    const handle = store.createUnarmedOwnerHandle();
    await handle.arm(ARM);
    physical.setBlocked(true);

    const created = await store.createLease({
      id: 'committed-create-lease', preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1,
      expiresAt: preflight.expiresAt, acquisitionId: handle.acquisitionId,
    });
    assert.equal(created.id, 'committed-create-lease');
    assert.equal(created.state, 'ACTIVE');

    physical.setBlocked(false);
    const recovered = await store.getLease(created.id);
    assert.deepEqual(recovered, created);
    const records = await ledgerRecords(dataRoot);
    assert.equal(records.filter((record) => record.id === created.id && record.state === 'ACTIVE').length, 1);
  });
});

test('ledger accounting: a committed paid consume preserves one reservation and allowance-relevant job after physical cleanup failure', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl, dailyPaidJobAllowance: 2 });
    const handle = store.createUnarmedOwnerHandle();
    const { lease } = await createActiveLease(store, handle, { preflightId: 'consume-preflight', leaseId: 'consume-lease' });
    physical.setBlocked(true);

    const job = await store.consume(lease.id, CONTRACT, {
      jobId: 'paid-consume-job', reviewerId: 'gemini', reservationUsd: 0.10,
      countsTowardDailyAllowance: true, acquisitionId: handle.acquisitionId,
    });
    assert.deepEqual(
      { id: job.id, state: job.state, paid: job.paid, reservationUsd: job.reservationUsd, costUsd: job.costUsd },
      { id: 'paid-consume-job', state: 'RESERVED', paid: true, reservationUsd: 0.10, costUsd: 0 },
    );

    physical.setBlocked(false);
    const recoveredJob = await store.getJob(job.id);
    const recoveredLease = await store.getLease(lease.id);
    assert.equal(recoveredJob.state, 'RESERVED');
    assert.equal(recoveredJob.paid, true);
    assert.deepEqual(
      { jobsConsumed: recoveredLease.jobsConsumed, reservedUsd: recoveredLease.reservedUsd, spentUsd: recoveredLease.spentUsd },
      { jobsConsumed: 1, reservedUsd: 0.10, spentUsd: 0 },
    );
    const records = await ledgerRecords(dataRoot);
    assert.equal(records.filter((record) => record.job?.id === job.id && record.state === 'RESERVED').length, 1);
  });
});

test('ledger accounting: a committed known-cost reconcile preserves its cost kind and lease totals after physical cleanup failure', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const handle = store.createUnarmedOwnerHandle();
    const { lease } = await createActiveLease(store, handle, { preflightId: 'reconcile-preflight', leaseId: 'reconcile-lease' });
    const reserved = await store.consume(lease.id, CONTRACT, {
      jobId: 'reconcile-job', reviewerId: 'gemini', reservationUsd: 0.10,
      countsTowardDailyAllowance: true, acquisitionId: handle.acquisitionId,
    });
    physical.setBlocked(true);

    const reconciled = await store.reconcile(reserved.id, {
      costUsd: 0.04, costKind: 'KNOWN', acquisitionId: handle.acquisitionId,
    });
    assert.deepEqual(
      { state: reconciled.state, costUsd: reconciled.costUsd, costKind: reconciled.costKind },
      { state: 'RECONCILED', costUsd: 0.04, costKind: 'KNOWN' },
    );

    physical.setBlocked(false);
    const recoveredJob = await store.getJob(reserved.id);
    const recoveredLease = await store.getLease(lease.id);
    assert.deepEqual(
      { state: recoveredJob.state, costUsd: recoveredJob.costUsd, costKind: recoveredJob.costKind },
      { state: 'RECONCILED', costUsd: 0.04, costKind: 'KNOWN' },
    );
    assert.deepEqual(
      { jobsConsumed: recoveredLease.jobsConsumed, reservedUsd: recoveredLease.reservedUsd, spentUsd: recoveredLease.spentUsd },
      { jobsConsumed: 1, reservedUsd: 0, spentUsd: 0.04 },
    );
    const records = await ledgerRecords(dataRoot);
    assert.equal(records.filter((record) => record.job?.id === reserved.id && record.state === 'RECONCILED').length, 1);
  });
});

test('ledger accounting: a committed close preserves the closed lease exactly once after physical cleanup failure', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const handle = store.createUnarmedOwnerHandle();
    const { lease } = await createActiveLease(store, handle, { preflightId: 'close-preflight', leaseId: 'close-lease' });
    physical.setBlocked(true);

    const closed = await store.close(lease.id, 'CLOSED', { acquisitionId: handle.acquisitionId });
    assert.deepEqual({ id: closed.id, state: closed.state }, { id: lease.id, state: 'CLOSED' });

    physical.setBlocked(false);
    const recovered = await store.getLease(lease.id);
    assert.deepEqual({ id: recovered.id, state: recovered.state }, { id: lease.id, state: 'CLOSED' });
    const records = await ledgerRecords(dataRoot);
    assert.equal(records.filter((record) => record.id === lease.id && record.state === 'CLOSED').length, 1);
  });
});

test('ledger accounting: a pre-commit createLease rejection remains the exact original error when physical cleanup also fails', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const originalError = Object.assign(new Error('original createLease append failure'), { code: 'EPERM' });
    let failLeaseAppend = false;
    const store = createLeaseStore({
      dataRoot,
      lockTimeoutMs: 30,
      lockRetryMs: 5,
      renameImpl: physical.renameImpl,
      beforeAtomicRename: async (record) => {
        if (failLeaseAppend && record.id === 'rejected-create-lease') throw originalError;
      },
    });
    const preflight = await createPreflight(store, 'rejected-create-preflight', 0.20);
    const handle = store.createUnarmedOwnerHandle();
    await handle.arm(ARM);
    failLeaseAppend = true;
    physical.setBlocked(true);

    await assert.rejects(
      store.createLease({
        id: 'rejected-create-lease', preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1,
        expiresAt: preflight.expiresAt, acquisitionId: handle.acquisitionId,
      }),
      (error) => error === originalError,
    );

    physical.setBlocked(false);
    await store.getPreflight(preflight.id);
    const records = await ledgerRecords(dataRoot);
    assert.equal(records.some((record) => record.id === 'rejected-create-lease'), false);
  });
});

test('ledger accounting: the paid allowance survives serial ownership handoff, while a free reservation remains available', async () => {
  await withDataRoot(async (dataRoot) => {
    const firstStore = createLeaseStore({ dataRoot, dailyPaidJobAllowance: 1 });
    const firstHandle = firstStore.createUnarmedOwnerHandle();
    const { lease } = await createActiveLease(firstStore, firstHandle, {
      preflightId: 'allowance-preflight', leaseId: 'allowance-lease', requestedUsd: 0.30, maxJobs: 3,
    });
    const paid = await firstStore.consume(lease.id, CONTRACT, {
      jobId: 'allowance-paid-job', reviewerId: 'gemini', reservationUsd: 0.10,
      countsTowardDailyAllowance: true, acquisitionId: firstHandle.acquisitionId,
    });
    await firstStore.reconcile(paid.id, { costUsd: 0.04, costKind: 'KNOWN', acquisitionId: firstHandle.acquisitionId });
    await firstHandle.release({ final: false });

    const siblingStore = createLeaseStore({ dataRoot, dailyPaidJobAllowance: 1 });
    const siblingHandle = siblingStore.createUnarmedOwnerHandle();
    await siblingHandle.arm(ARM);
    await assert.rejects(
      siblingStore.consume(lease.id, CONTRACT, {
        jobId: 'allowance-second-paid', reviewerId: 'grok', reservationUsd: 0.10,
        countsTowardDailyAllowance: true, acquisitionId: siblingHandle.acquisitionId,
      }),
      /daily dispatch allowance exhausted/,
    );

    const free = await siblingStore.consume(lease.id, CONTRACT, {
      jobId: 'allowance-free-job', reviewerId: 'free', reservationUsd: 0.10,
      countsTowardDailyAllowance: false, acquisitionId: siblingHandle.acquisitionId,
    });
    const leaseAfterFree = await siblingStore.getLease(lease.id);
    assert.deepEqual(
      { id: free.id, state: free.state, paid: free.paid, reservationUsd: free.reservationUsd },
      { id: 'allowance-free-job', state: 'RESERVED', paid: false, reservationUsd: 0.10 },
    );
    assert.deepEqual(
      { jobsConsumed: leaseAfterFree.jobsConsumed, reservedUsd: leaseAfterFree.reservedUsd, spentUsd: leaseAfterFree.spentUsd },
      { jobsConsumed: 2, reservedUsd: 0.10, spentUsd: 0.04 },
    );
    await siblingHandle.release({ final: false });
  });
});
