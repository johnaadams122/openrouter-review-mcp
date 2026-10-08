// Reclaim on pressure and the maintenance bodies it shares with the public ledger methods.
//
// reserveManagedPreflightCapacity runs a private helper only when its count check or its bytes check would refuse. The
// helper plans on one snapshot, drops no-ops, checks feasibility for the count need and the bytes need together, then acts
// under one budget (12 appends, about 750 ms on the injectable monotonic clock, stop after 2 consecutive failures, a
// candidate skipped after 3 failures within five minutes of that clock, each seal inside the transaction bounded by its own
// timer). While a bytes need is open, a retire victim is touched only if its disposals, its retire and its acknowledgement
// all fit in what is left of the append budget, and feasibility counts that cost too. Its owed phase touches only
// PREPARE_FAILED and RESTART releases and retired preflights (the helper never seals or acknowledges an EXPIRED or
// ABANDONED release, although the public acknowledgement accepts one). Capacity is asserted by
// replaying the ledger files through the validator, never only by behaviour, and the rows the helper writes are replayed
// through a frozen copy of the main-12dccfd validator (old-build compatibility).
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { canonicalJson } from '../src/local-mcp/shared/contracts.mjs';
import { createSharedLedgerState } from '../src/local-mcp/shared/ledger-state.mjs';
import { maximumPreflightEncryptedBytes } from '../src/local-mcp/shared/policy.mjs';
import { buildInstallationConfig, DIGESTS } from './helpers/shared-policy-fixture.mjs';
import {
  INPUT_DIGEST,
  KEY_DIGEST,
  LATER,
  NOW,
  PROJECT_ID,
  acquireOwner,
  activateManagedMode,
  admitManagedReceipt,
  appendRawRecord,
  claimManagedReceipt,
  createFakeStorageProofs,
  createManagedLease,
  createManagedPreflight,
  managedExecutionFor,
  preflightReservationBytes,
  preparedReservationBytes,
  readLedgerRecords,
  spendManagedPreflight,
  withManagedDataRoot,
} from './helpers/shared-ledger-fixture.mjs';

const EARLY = '2026-09-19T17:30:00.000Z';
const AFTER_EARLY = '2026-09-19T17:45:00.000Z';
const AFTER_FUTURE = '2026-09-19T18:05:00.000Z';
const LATEST = '2026-09-19T20:00:00.000Z';
const MIB = 1024 * 1024;
// createManagedPreflight commits context 2,048 plus mapping 1,024 encrypted bytes (fixture protectedRefs).
const COMMITTED_BYTES = 3_072;
const RESERVED = 'MANAGED_PREFLIGHT_RESERVED';
const RETIRED = 'MANAGED_PREFLIGHT_RETIRED';
const ACKED = 'MANAGED_PREFLIGHT_PAYLOAD_DELETION_ACKED';
const RELEASED = 'MANAGED_PREFLIGHT_RESERVATION_RELEASED';
const DISPOSED = 'UNADMITTED_LEASE_DISPOSED';
const RECLAIM_LINE = /^openrouter-review-lease-store: preflight-reclaim released=\d+ sealed=\d+ disposed=\d+ retired=\d+ acked=\d+ failed=\d+ \(counts only\)\n$/u;
// The LF-normalized sha256 of the frozen copy of src/local-mcp/shared/ledger-state.mjs as of main 12dccfd (the code is byte-identical; one explanatory comment was reworded).
const FROZEN_VALIDATOR_SHA256 = 'ba328dff1f82f547d05f3b2fce19589119f7ea743d0d8b3559520d81dfdf2855';

const code = (expected) => (error) => error?.code === expected;
const at = (iso) => Date.parse(iso);
const kindsSince = (records, count) => records.slice(count).map((record) => record.kind ?? record.recordType);
const targetOf = ({ reservationId, generation }) => ({ reservationId, generation });
const turn = () => new Promise((resolve) => setImmediate(resolve));
const POISON_EXPIRY_MS = 5 * 60 * 1000;

function storageLimits({ live = 30, reservations = 12, extraBytes = 0, plaintext = MIB } = {}) {
  const reservation = maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: plaintext });
  return { maxLivePreflights: live, maxPreflightEncryptedBytes: (reservations * reservation) + extraBytes, maxSinglePreflightPlaintextBytes: plaintext };
}

// Rejects instead of hanging when a promise does not settle in time, so a missing bound fails fast and by name.
async function settleWithin(promise, milliseconds, label) {
  let timer;
  const late = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} did not settle within ${milliseconds} ms`)), milliseconds); });
  try {
    return await Promise.race([promise, late]);
  } finally {
    clearTimeout(timer);
  }
}

// The helper's time budget and its poison expiry run on the injected monotonic clock. It is frozen by default, so no test
// depends on the host's speed; the time-bound and poison-expiry tests move it by hand.
async function openHarness(dataRoot, {
  limits = storageLimits(), storageProofs, managedExecution, beforeAtomicRename, monotonic = { now: 0 }, time = { now: NOW }, sealTimeoutMs,
} = {}) {
  const execution = managedExecution ?? managedExecutionFor(dataRoot, {
    installationConfig: buildInstallationConfig({ dataRoot, storage: limits }),
    ...(storageProofs === undefined ? {} : { storageProofs }),
  });
  // faults.failNextAck makes the next deletion-ack append fail once (a full disk), whoever writes it.
  const faults = { failNextAck: false };
  const hook = (record) => {
    if (faults.failNextAck && record.kind === ACKED) { faults.failNextAck = false; throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); }
    return beforeAtomicRename?.(record);
  };
  const open = () => createLeaseStore({
    dataRoot, clock: () => time.now, managedExecution: execution, monotonicNow: () => monotonic.now, beforeAtomicRename: hook,
    ...(sealTimeoutMs === undefined ? {} : { preflightSealTimeoutMs: sealTimeoutMs }),
  });
  const store = open();
  const { owner, acquisitionId } = await acquireOwner(store);
  const mode = await activateManagedMode(store, execution, acquisitionId);
  const h = { dataRoot, time, monotonic, faults, managedExecution: execution, store, owner, acquisitionId, mode, open };
  h.setClock = (iso) => { time.now = at(iso); };
  h.reservationBytes = () => preflightReservationBytes(execution);
  h.reserveInput = (overrides = {}) => ({
    reservationId: randomUUID(), generation: 1, bindingId: 'binding-a', projectId: PROJECT_ID, policyEpoch: 1,
    scopeDigest: DIGESTS.scope, maxEncryptedBytes: h.reservationBytes(), expiresAt: LATEST, acquisitionId, ...overrides,
  });
  h.reserve = (overrides) => h.store.reserveManagedPreflightCapacity(h.reserveInput(overrides));
  h.preflight = (overrides = {}) => createManagedPreflight(h.store, execution, acquisitionId, overrides);
  h.spend = (created, options = {}) => spendManagedPreflight(h.store, execution, acquisitionId, {
    preflightId: created.preflightId, ownerGeneration: owner.generation, ...options,
  });
  h.records = () => readLedgerRecords(dataRoot);
  return h;
}

// Replays the ledger files into a fresh validator: the capacity a restarted process (or an older build) derives.
async function replayShared(dataRoot, createState = createSharedLedgerState) {
  const state = createState();
  for (const record of await readLedgerRecords(dataRoot)) {
    if (record.recordType === 'shared/service-mode' || record.recordType === 'shared/transition') state.apply(record);
  }
  return state;
}
const capacityOf = async (dataRoot) => (await replayShared(dataRoot)).snapshot().capacity;
const tombstonedIds = async (dataRoot) => (await replayShared(dataRoot)).snapshot().preflightTombstones.map((entry) => entry.preflightId);

// The lease store's maintenance lines, captured; every other stderr write passes through.
async function captureStoreLines(work) {
  const lines = [];
  const original = process.stderr.write;
  process.stderr.write = function write(chunk, ...rest) {
    const text = String(chunk);
    if (text.startsWith('openrouter-review-lease-store: preflight-')) { lines.push(text); return true; }
    return original.call(this, chunk, ...rest);
  };
  try {
    return { value: await work(), lines };
  } catch (error) {
    return { error, lines };
  } finally {
    process.stderr.write = original;
  }
}

async function loadFrozenValidator() {
  const url = new URL('./fixtures/shared/ledger-state.12dccfd.frozen.mjs', import.meta.url);
  const text = await readFile(url, 'utf8');
  assert.equal(createHash('sha256').update(text.replace(/\r\n/gu, '\n')).digest('hex'), FROZEN_VALIDATOR_SHA256,
    'the frozen copy must stay identical (line endings aside) to ledger-state.mjs at main 12dccfd');
  const contracts = new URL('../src/local-mcp/shared/contracts.mjs', import.meta.url).href;
  const source = text.replace("from './contracts.mjs'", `from ${JSON.stringify(contracts)}`);
  assert.notEqual(source, text, 'the frozen copy imports ./contracts.mjs');
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}

// Several live preflights plus the ids a test inspects afterwards.
async function fillLive(h, count, overrides = {}) {
  const created = [];
  for (let index = 0; index < count; index += 1) created.push(await h.preflight(overrides));
  return created;
}

// Releases a reservation whose own refund then fails once on a full disk, so it stays owed: released, still charged,
// and acknowledgeable only by the helper's owed phase under bytes pressure. A store without sealTarget skips the refund.
async function releaseOwed(h, reservation, reason = 'PREPARE_FAILED') {
  h.faults.failNextAck = true;
  const { error } = await captureStoreLines(() => h.store.releaseManagedPreflightReservation({
    reservationId: reservation.reservationId, generation: reservation.generation, reason, acquisitionId: h.acquisitionId,
  }));
  h.faults.failNextAck = false;
  assert.equal(error, undefined, `the ${reason} release itself succeeds`);
}

// A lease store opened on the same data root by an earlier owner that left reservations RESERVED and then gave up
// ownership; the returned harness is the later owner, for which those reservations belong to a dead owner.
async function afterDeadOwner(dataRoot, { limits, storageProofs, reserve = 1, beforeAtomicRename, sealTimeoutMs, monotonic } = {}) {
  const time = { now: NOW };
  const execution = managedExecutionFor(dataRoot, {
    installationConfig: buildInstallationConfig({ dataRoot, storage: limits }),
    ...(storageProofs === undefined ? {} : { storageProofs }),
  });
  const first = await openHarness(dataRoot, { managedExecution: execution, time });
  const dead = [];
  for (let index = 0; index < reserve; index += 1) dead.push(await first.reserve());
  await first.owner.release({ final: true });
  const h = await openHarness(dataRoot, { managedExecution: execution, time, beforeAtomicRename, sealTimeoutMs, monotonic });
  assert.notEqual(h.acquisitionId, first.acquisitionId);
  return { h, dead };
}

test('the thirty-first reserve succeeds after an expired preflight, then after a spent one; each is retired and acked exactly once', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30 }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent, { completedAt: '2026-09-19T17:05:00.000Z' });
    const expired = await h.preflight({ expiresAt: EARLY });
    await fillLive(h, 28, { expiresAt: LATER });
    assert.equal((await capacityOf(dataRoot)).livePreflightCount, 30);
    h.setClock(AFTER_EARLY);

    let before = (await h.records()).length;
    await h.reserve();
    let records = await h.records();
    assert.deepEqual(kindsSince(records, before), [RETIRED, ACKED, RESERVED]);
    assert.equal(records.at(-3).preflight.id, expired.preflightId, 'the expired preflight goes first');
    assert.deepEqual(records.at(-2).preflightDeletionAck.target, { preflightId: expired.preflightId });
    assert.equal((await capacityOf(dataRoot)).livePreflightCount, 30);

    before = records.length;
    await h.reserve();
    records = await h.records();
    assert.deepEqual(kindsSince(records, before), [RETIRED, ACKED, RESERVED]);
    assert.equal(records.at(-3).preflight.id, spent.preflightId, 'then the spent one');

    before = records.length;
    await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'));
    assert.equal((await h.records()).length, before, 'nothing else is reclaimable, so nothing is appended');
    assert.deepEqual((await tombstonedIds(dataRoot)).sort(), [expired.preflightId, spent.preflightId].sort());
    assert.deepEqual(
      h.managedExecution.storageProofs.deletionCalls().map((call) => canonicalJson(call.target)).sort(),
      [expired, spent].map((entry) => canonicalJson(targetOf(entry))).sort(),
      'deletion was proved for exactly the two retired preflights',
    );
  });
});

test('no reclaim without pressure: with count and bytes not full a reserve appends exactly one row and no tombstone or ack', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 3 }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.preflight({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    const { lines } = await captureStoreLines(() => h.reserve());
    assert.deepEqual(kindsSince(await h.records(), before), [RESERVED], 'two reclaimable preflights exist, but the reserve fits');
    assert.deepEqual(lines, []);
    assert.deepEqual(await tombstonedIds(dataRoot), []);
    // Control: the next reserve is under count pressure and reclaims exactly one.
    const next = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), next), [RETIRED, ACKED, RESERVED]);
  });
});

test('count-only pressure frees a count slot by retiring, and touches no owed released reservation', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 12 }) });
    const owed = await h.store.reserveManagedPreflightCapacity(h.reserveInput());
    h.managedExecution.storageProofs.publish({ kind: 'preflight', target: targetOf(owed), refs: [] });
    await releaseOwed(h, owed);
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.preflight({ expiresAt: LATER });
    const beforeCapacity = await capacityOf(dataRoot);
    assert.equal(beforeCapacity.livePreflightCount, 2);
    const before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED]);
    const after = await capacityOf(dataRoot);
    assert.equal(after.livePreflightCount, 2);
    assert.equal(after.preflightEncryptedBytes, beforeCapacity.preflightEncryptedBytes - COMMITTED_BYTES + h.reservationBytes(),
      'only the retired preflight\'s own bytes were freed; the charged released reservation is still charged');
  });
});

test('bytes-only pressure frees bytes by acknowledging an owed released reservation, and retires nothing', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30, reservations: 2, extraBytes: 2 * COMMITTED_BYTES }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.preflight({ expiresAt: EARLY });
    const owed = await h.reserve();
    const refs = [{ objectId: randomUUID(), sha256: DIGESTS.context, encryptedBytes: 2_048 }];
    h.managedExecution.storageProofs.publish({ kind: 'preflight', target: targetOf(owed), refs });
    await releaseOwed(h, owed);
    await h.reserve();
    h.setClock(AFTER_EARLY);
    const beforeCapacity = await capacityOf(dataRoot);
    const before = (await h.records()).length;
    await h.reserve();
    const records = await h.records();
    assert.deepEqual(kindsSince(records, before), [ACKED, RESERVED], 'an expired and a spent preflight exist, but count is not short');
    assert.deepEqual(records.at(-2).preflightDeletionAck.target, targetOf(owed));
    assert.deepEqual(records.at(-2).preflightDeletionAck.context, { objectId: refs[0].objectId, sha256: refs[0].sha256 });
    const after = await capacityOf(dataRoot);
    assert.equal(after.preflightEncryptedBytes, beforeCapacity.preflightEncryptedBytes, 'one reservation freed, one reserved');
    assert.equal(after.livePreflightCount, beforeCapacity.livePreflightCount + 1);
    assert.deepEqual(await tombstonedIds(dataRoot), []);
  });
});

test('mixed classes: expired by expiresAt (ties by commit order) before spent by latest completedAt; one victim per unit of need', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 6 }) });
    const tieFirst = await h.preflight({ expiresAt: '2026-09-19T17:20:00.000Z' });
    const tieSecond = await h.preflight({ expiresAt: '2026-09-19T17:20:00.000Z' });
    const earliest = await h.preflight({ expiresAt: '2026-09-19T17:10:00.000Z' });
    const spentLate = await h.preflight({ expiresAt: LATER });
    await h.spend(spentLate, { completedAt: '2026-09-19T17:05:00.000Z' });
    const spentEarly = await h.preflight({ expiresAt: LATER });
    await h.spend(spentEarly, { completedAt: '2026-09-19T17:02:00.000Z' });
    const unspent = await h.preflight({ expiresAt: LATER });
    h.setClock(AFTER_EARLY);
    const victims = [];
    for (let call = 0; call < 5; call += 1) {
      const before = (await h.records()).length;
      await h.reserve();
      const added = (await h.records()).slice(before);
      assert.deepEqual(added.map((record) => record.kind), [RETIRED, ACKED, RESERVED], `call ${call + 1} reclaims exactly one`);
      victims.push(added[0].preflight.id);
    }
    assert.deepEqual(victims, [earliest, tieFirst, tieSecond, spentEarly, spentLate].map((entry) => entry.preflightId));
    const before = (await h.records()).length;
    await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'));
    assert.equal((await h.records()).length, before);
    assert.equal((await tombstonedIds(dataRoot)).includes(unspent.preflightId), false, 'the unexpired unspent preflight is never reclaimed');
  });
});

test('bad scope, size, reservation or deadline at full capacity gives the same error and appends zero records', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    const before = (await h.records()).length;
    const existing = (await h.records()).find((record) => record.kind === RESERVED).preflightReservation.reservationId;
    const cases = [
      [{ maxEncryptedBytes: h.reservationBytes() - 1 }, 'REQUEST_BYTES_FULL'],
      [{ projectId: 'unknown-project' }, 'SERVICE_MODE_MISMATCH'],
      [{ reservationId: existing }, 'STAGING_STALE'],
      [{ expiresAt: new Date(NOW - 1_000).toISOString() }, 'REQUEST_EXPIRED'],
    ];
    for (const [overrides, expected] of cases) {
      await assert.rejects(h.reserve(overrides), code(expected), expected);
      assert.equal((await h.records()).length, before, `${expected}: no record appended`);
    }
    await assert.rejects(h.reserve({ scopeDigest: 'not-a-digest' }), TypeError);
    assert.equal((await h.records()).length, before);
    // Control: the same store at the same capacity reclaims for a valid reserve.
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED]);
  });
});

test('an expired, never-admitted lease on the victim is disposed as EXPIRED first, then the preflight is retired and acked', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const expired = await h.preflight({ expiresAt: EARLY });
    const lease = await createManagedLease(h.store, expired.preflightId, h.acquisitionId, { expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [DISPOSED, RETIRED, ACKED, RESERVED]);
    assert.equal(added[0].lease.id, lease.id);
    assert.equal(added[0].lease.state, 'EXPIRED');
    assert.equal((await h.store.getLease(lease.id)).state, 'EXPIRED');
  });
});

// ---- never reclaimed: each case alone at capacity 1 (or 2), so the refusal is exactly REQUEST_CAPACITY_FULL with nothing
// appended and no log line (no attempt was even made); a control then removes the one blocking cause.

async function assertNothingReclaimed(h, label) {
  const before = (await h.records()).length;
  const { error, lines } = await captureStoreLines(() => h.reserve());
  assert.ok(code('REQUEST_CAPACITY_FULL')(error), `${label}: the refusal is unchanged (got ${error?.code ?? 'success'})`);
  assert.equal((await h.records()).length, before, `${label}: nothing appended`);
  assert.deepEqual(lines, [], `${label}: no attempt was made, so nothing is logged`);
}

test('never reclaimed: an unexpired unspent preflight (still authorizable)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    await h.preflight({ expiresAt: LATER });
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'unexpired unspent');
  });
});

test('never reclaimed: a running review (receipt EXECUTING), even after the preflight expired', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight();
    const lease = await createManagedLease(h.store, created.preflightId, h.acquisitionId);
    const admitted = await admitManagedReceipt(h.store, h.managedExecution, h.acquisitionId, { lease, preflightId: created.preflightId });
    await claimManagedReceipt(h.store, h.managedExecution, h.acquisitionId, h.owner.generation, admitted);
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'running');
  });
});

test('never reclaimed: a finished review whose claim is still open (group CLAIMED); reclaimed once the claim is retired', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight({ expiresAt: LATER });
    const spent = await h.spend(created, { retireClaim: false });
    assert.equal(spent.receipt.state, 'TERMINAL');
    assert.deepEqual((await h.store.listPinnedMappings()).find((entry) => entry.preflightId === created.preflightId).receiptIds,
      [spent.receipt.receiptId], 'the claim window still pins the mapping');
    await assertNothingReclaimed(h, 'claim window');
    const view = await h.store.recoverManagedReceipt({ receiptId: spent.receipt.receiptId, acquisitionId: h.acquisitionId });
    await h.store.retireManagedClaim({
      receiptId: spent.receipt.receiptId, expectedRevision: spent.receipt.revision,
      executionGroupId: view.executionGroup.executionGroupId, expectedGroupRevision: view.executionGroup.revision,
      claimId: spent.claimId, reason: 'TERMINALIZED', acquisitionId: h.acquisitionId,
    });
    const before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED]);
  });
});

test('never reclaimed: a recovery-pending review, even after the preflight expired', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight();
    const lease = await createManagedLease(h.store, created.preflightId, h.acquisitionId);
    const admitted = await admitManagedReceipt(h.store, h.managedExecution, h.acquisitionId, { lease, preflightId: created.preflightId });
    const claimed = await claimManagedReceipt(h.store, h.managedExecution, h.acquisitionId, h.owner.generation, admitted);
    await h.store.markManagedRecoveryPending({
      receiptId: claimed.receipt.receiptId, expectedRevision: claimed.receipt.revision,
      executionGroupId: claimed.executionGroup.executionGroupId, expectedGroupRevision: claimed.executionGroup.revision,
      claimId: claimed.claimId, acquisitionId: h.acquisitionId,
    });
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'recovery pending');
  });
});

test('never reclaimed: a pinned mapping (queued receipt), even after the preflight expired', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight();
    const lease = await createManagedLease(h.store, created.preflightId, h.acquisitionId);
    const admitted = await admitManagedReceipt(h.store, h.managedExecution, h.acquisitionId, { lease, preflightId: created.preflightId });
    assert.deepEqual((await h.store.listPinnedMappings()).find((entry) => entry.preflightId === created.preflightId).receiptIds, [admitted.receipt.receiptId]);
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'pinned by a queued receipt');
  });
});

// Only the terminal-receipt rule can block this one: the receipt's lease was closed, so no active lease and no open claim
// remain (closeManagedLease has no production caller, but the ledger allows it).
test('never reclaimed: a queued receipt whose lease was already closed (the receipt-terminal rule alone)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight();
    const lease = await createManagedLease(h.store, created.preflightId, h.acquisitionId);
    const admitted = await admitManagedReceipt(h.store, h.managedExecution, h.acquisitionId, { lease, preflightId: created.preflightId });
    const current = await h.store.getLease(lease.id);
    await h.store.closeManagedLease({ leaseId: lease.id, receiptId: admitted.receipt.receiptId, expectedRevision: current.revision, state: 'CLOSED', acquisitionId: h.acquisitionId });
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'queued receipt, closed lease');
  });
});

test('never reclaimed: a failed or cancelled review before the preflight expires; reclaimed after its expiry', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2 }) });
    const failed = await h.preflight({ expiresAt: LATER });
    await h.spend(failed, { kind: 'REVIEW_ERROR' });
    const cancelled = await h.preflight({ expiresAt: LATER });
    const lease = await createManagedLease(h.store, cancelled.preflightId, h.acquisitionId);
    const admitted = await admitManagedReceipt(h.store, h.managedExecution, h.acquisitionId, { lease, preflightId: cancelled.preflightId, reviewerIds: ['gemini'] });
    await h.store.cancelQueuedReceipt({
      receiptId: admitted.receipt.receiptId, expectedRevision: admitted.receipt.revision,
      executionGroupId: admitted.executionGroup.executionGroupId, expectedGroupRevision: admitted.executionGroup.revision, acquisitionId: h.acquisitionId,
    });
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'failed and cancelled, unexpired');
    h.time.now = at(LATER) + 60_000;
    const before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED], 'once expired, the earlier one is reclaimed');
  });
});

// Guards the "every receipt must be REVIEW_RETURNED" rule: one returned review does not make a preflight spent while another
// review of the same preflight failed, because the failed one may still be retried until the preflight expires.
test('never reclaimed: a preflight with one returned review and one failed review before it expires (every receipt must be REVIEW_RETURNED); reclaimed after its expiry', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight({ expiresAt: LATER });
    await h.spend(created);
    await h.spend(created, { kind: 'REVIEW_ERROR' });
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'one returned and one failed review, unexpired');
    h.time.now = at(LATER) + 60_000;
    const before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED], 'once expired, it is reclaimed');
  });
});

test('never reclaimed: a spent preflight that still has a usable (unexpired) second lease; reclaimed once that lease expires', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const created = await h.preflight({ expiresAt: LATER });
    await h.spend(created);
    const second = await createManagedLease(h.store, created.preflightId, h.acquisitionId, { expiresAt: '2026-09-19T18:30:00.000Z' });
    h.setClock(AFTER_FUTURE);
    await assertNothingReclaimed(h, 'usable second lease');
    h.setClock('2026-09-19T18:31:00.000Z');
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [DISPOSED, RETIRED, ACKED, RESERVED]);
    assert.equal(added[0].lease.id, second.id);
  });
});

test('never reclaimed: a same-owner RESERVED reservation, even past its expiry (its operation may be mid-store)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const mine = await h.reserve({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    await assertNothingReclaimed(h, 'same-owner reserved');
    const state = await replayShared(dataRoot);
    assert.equal(state.getPreflightReservation(mine.reservationId).state, 'RESERVED');
  });
});

test('refusal codes and their order are unchanged when nothing is reclaimable: count first, then bytes, nothing appended', async () => {
  const scenarios = [
    ['count only', storageLimits({ live: 1 }), 'REQUEST_CAPACITY_FULL'],
    ['bytes only', storageLimits({ live: 30, reservations: 1, extraBytes: COMMITTED_BYTES }), 'REQUEST_BYTES_FULL'],
    ['count and bytes', storageLimits({ live: 1, reservations: 1 }), 'REQUEST_CAPACITY_FULL'],
  ];
  for (const [label, limits, expected] of scenarios) {
    await withManagedDataRoot(async (dataRoot) => {
      const h = await openHarness(dataRoot, { limits });
      if (label === 'bytes only') await h.reserve();
      else await h.preflight({ expiresAt: LATER });
      if (label === 'count and bytes') {
        const capacity = await capacityOf(dataRoot);
        assert.ok(capacity.preflightEncryptedBytes + h.reservationBytes() > limits.maxPreflightEncryptedBytes, 'fixture: bytes are full too');
      }
      const before = (await h.records()).length;
      const { error, lines } = await captureStoreLines(() => h.reserve());
      assert.ok(code(expected)(error), `${label}: expected ${expected}, got ${error?.code ?? 'success'}`);
      assert.equal((await h.records()).length, before, `${label}: nothing appended`);
      assert.deepEqual(lines, [], `${label}: nothing logged`);
    });
  }
});

test('an unsatisfiable bytes need with spent and expired candidates present appends nothing and keeps the bytes refusal', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30, reservations: 1, extraBytes: 2 * COMMITTED_BYTES }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.preflight({ expiresAt: EARLY });
    await h.reserve();
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_BYTES_FULL')(error), `got ${error?.code ?? 'success'}`);
    assert.equal((await h.records()).length, before, 'a retire frees only a few KiB, so it is never done for a bytes need');
    assert.deepEqual(lines, []);
    assert.deepEqual(await tombstonedIds(dataRoot), []);
  });
});

test('feasibility first: with count short and an unsatisfiable bytes need, nothing is retired and the count refusal stands', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 1, extraBytes: 2 * COMMITTED_BYTES }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.reserve();
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_CAPACITY_FULL')(error), `got ${error?.code ?? 'success'}`);
    assert.equal((await h.records()).length, before, 'a retire would free the slot but the reserve would still fail on bytes');
    assert.deepEqual(lines, []);
    assert.deepEqual(await tombstonedIds(dataRoot), []);
  });
});

test('feasibility first: an owed acknowledgement too small for the bytes need is not done either; nothing is appended', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30, reservations: 1, extraBytes: COMMITTED_BYTES }) });
    const retired = await h.preflight({ expiresAt: LATER });
    await h.store.retireManagedPreflight({ preflightId: retired.preflightId, expectedRevision: retired.preflight.revision, reason: 'EXPLICIT', acquisitionId: h.acquisitionId });
    await h.reserve();
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_BYTES_FULL')(error), `got ${error?.code ?? 'success'}`);
    assert.equal((await h.records()).length, before, 'the owed tombstone frees only its own bytes, and the reserve would still fail');
    assert.deepEqual(lines, []);
    assert.deepEqual(h.managedExecution.storageProofs.deletionCalls(), []);
  });
});

test('joint pressure: a count need and a bytes need that one retire and its acknowledgement cover together are met; one byte more appends nothing', async () => {
  for (const [label, shortfall] of [['covered exactly', 0], ['one byte short', 1]]) {
    await withManagedDataRoot(async (dataRoot) => {
      // Count is full (a spent preflight and a same-owner RESERVED reservation) and the bytes need is the spent preflight's
      // own committed charge plus `shortfall`: only the retire's own acknowledgement can relieve those bytes.
      const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 2, extraBytes: -shortfall }) });
      const spent = await h.preflight({ expiresAt: LATER });
      await h.spend(spent);
      await h.reserve();
      const capacity = await capacityOf(dataRoot);
      assert.equal(capacity.livePreflightCount, 2, `${label}: fixture: count is full`);
      assert.equal(capacity.preflightEncryptedBytes + h.reservationBytes() - ((2 * h.reservationBytes()) - shortfall), COMMITTED_BYTES + shortfall, `${label}: fixture: the bytes need`);
      const before = (await h.records()).length;
      const { error, lines } = await captureStoreLines(() => h.reserve());
      if (shortfall === 0) {
        assert.equal(error, undefined, `${label}: the reserve succeeds (got ${error?.code})`);
        assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED]);
        assert.deepEqual(await tombstonedIds(dataRoot), [spent.preflightId]);
        assert.match(lines[0], /retired=1 acked=1 failed=0/u);
      } else {
        assert.ok(code('REQUEST_CAPACITY_FULL')(error), `${label}: the count refusal stands (got ${error?.code ?? 'success'})`);
        assert.equal((await h.records()).length, before, `${label}: nothing is appended, so no preflight is destroyed for a reserve that fails`);
        assert.deepEqual(lines, []);
        assert.deepEqual(await tombstonedIds(dataRoot), []);
      }
    });
  }
});

test('joint pressure: once the open bytes need exceeds what the retire victims could free, nothing is retired', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const proofs = createFakeStorageProofs();
    let owedTarget = null;
    let deletionWorks = false;
    const storageProofs = {
      ...proofs,
      deleteRetired(args) {
        if (!deletionWorks && owedTarget !== null && canonicalJson(args.descriptor.target) === canonicalJson(owedTarget)) throw Object.assign(new Error('unlink busy'), { code: 'EBUSY' });
        return proofs.deleteRetired(args);
      },
    };
    // Count is full (a spent preflight and a RESERVED reservation) and the bytes need is one byte above the spent
    // preflight's own charge: the plan is feasible only through the owed reservation's acknowledgement.
    const h = await openHarness(dataRoot, { storageProofs, limits: storageLimits({ live: 2, reservations: 3, extraBytes: -1 }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    const owed = await h.reserve();
    owedTarget = targetOf(owed);
    const refund = await captureStoreLines(() => h.store.releaseManagedPreflightReservation({ reservationId: owed.reservationId, generation: 1, reason: 'PREPARE_FAILED', acquisitionId: h.acquisitionId }));
    assert.match(refund.lines[0], /preflight-release-refund-failed code=EBUSY/u, 'fixture: the refund failed, so the reservation is owed');
    await h.reserve();
    const capacity = await capacityOf(dataRoot);
    assert.equal(capacity.livePreflightCount, 2, 'fixture: count is full');
    assert.equal(capacity.preflightEncryptedBytes + h.reservationBytes() - ((3 * h.reservationBytes()) - 1), COMMITTED_BYTES + 1, 'fixture: the bytes need');
    const before = (await h.records()).length;
    const blocked = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_CAPACITY_FULL')(blocked.error), `the count refusal stands (got ${blocked.error?.code ?? 'success'})`);
    assert.equal((await h.records()).length, before, 'the owed acknowledgement failed, so the spent preflight is not destroyed for nothing');
    assert.deepEqual(await tombstonedIds(dataRoot), []);
    assert.match(blocked.lines[0], /released=0 sealed=0 disposed=0 retired=0 acked=0 failed=1/u);
    // Control: once the deletion works, the next call acknowledges the owed reservation and then retires for the count.
    deletionWorks = true;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [ACKED, RETIRED, ACKED, RESERVED]);
  });
});

test('joint pressure: a victim whose disposals, retire and acknowledgement need more than twelve appends is not touched (eleven leases); ten leases fit', async () => {
  for (const [label, leases] of [['eleven leases', 11], ['ten leases', 10]]) {
    await withManagedDataRoot(async (dataRoot) => {
      // Count is full (the expired victim and a same-owner RESERVED reservation) and the bytes need is the victim's own
      // committed charge, so only the acknowledgement that follows its retire can meet it.
      const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 2 }) });
      const victim = await h.preflight({ expiresAt: EARLY });
      for (let index = 0; index < leases; index += 1) await createManagedLease(h.store, victim.preflightId, h.acquisitionId, { expiresAt: EARLY });
      await h.reserve();
      h.setClock(AFTER_EARLY);
      const capacity = await capacityOf(dataRoot);
      assert.equal(capacity.livePreflightCount, 2, `${label}: fixture: count is full`);
      assert.equal(capacity.preflightEncryptedBytes + h.reservationBytes() - (2 * h.reservationBytes()), COMMITTED_BYTES, `${label}: fixture: the bytes need is the victim's own charge`);
      const before = (await h.records()).length;
      const { error, lines } = await captureStoreLines(() => h.reserve());
      if (leases === 10) {
        assert.equal(error, undefined, `${label}: the reserve succeeds (got ${error?.code})`);
        assert.deepEqual(kindsSince(await h.records(), before), [...Array(10).fill(DISPOSED), RETIRED, ACKED, RESERVED], `${label}: ten disposals, the retire and its acknowledgement are exactly twelve appends`);
        assert.match(lines[0], /disposed=10 retired=1 acked=1 failed=0/u);
      } else {
        assert.ok(code('REQUEST_CAPACITY_FULL')(error), `${label}: the count refusal stands (got ${error?.code ?? 'success'})`);
        assert.equal((await h.records()).length, before, `${label}: no disposal and no retire, because the acknowledgement could not follow in the same call`);
        assert.deepEqual(lines, [], `${label}: nothing was attempted`);
        assert.deepEqual(await tombstonedIds(dataRoot), []);
      }
    });
  }
});

test('joint pressure: feasibility counts appends, so an owed acknowledgement is not done either when the victim it needs cannot finish in one call', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    // The bytes need is an owed tombstone's charge plus the victim's own, and the victim (eleven expired leases) would need
    // thirteen appends for its disposals, its retire and its acknowledgement: no call can meet this need.
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 2 }) });
    const owed = await h.preflight({ expiresAt: LATER });
    await h.store.retireManagedPreflight({ preflightId: owed.preflightId, expectedRevision: owed.preflight.revision, reason: 'EXPLICIT', acquisitionId: h.acquisitionId });
    const victim = await h.preflight({ expiresAt: EARLY });
    for (let index = 0; index < 11; index += 1) await createManagedLease(h.store, victim.preflightId, h.acquisitionId, { expiresAt: EARLY });
    await h.reserve();
    h.setClock(AFTER_EARLY);
    const capacity = await capacityOf(dataRoot);
    assert.equal(capacity.livePreflightCount, 2, 'fixture: count is full');
    assert.equal(capacity.preflightEncryptedBytes + h.reservationBytes() - (2 * h.reservationBytes()), 2 * COMMITTED_BYTES, 'fixture: the bytes need');
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_CAPACITY_FULL')(error), `the count refusal stands (got ${error?.code ?? 'success'})`);
    assert.equal((await h.records()).length, before, 'nothing is appended, not even the owed acknowledgement');
    assert.deepEqual(lines, []);
    assert.deepEqual(h.managedExecution.storageProofs.deletionCalls(), [], 'no deletion was tried');
    assert.deepEqual(await tombstonedIds(dataRoot), [owed.preflightId]);
  });
});

test('joint pressure: when owed acknowledgements leave too few appends for the victim, it is left whole and the next call finishes it', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    // Five owed tombstones and an expired victim with six expired leases: the bytes need is all six charges, so Phase 1
    // spends five appends and the victim's six disposals, retire and acknowledgement (eight more) do not fit in this call.
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 2 }) });
    const owed = [];
    for (let index = 0; index < 5; index += 1) {
      const created = await h.preflight({ expiresAt: LATER });
      await h.store.retireManagedPreflight({ preflightId: created.preflightId, expectedRevision: created.preflight.revision, reason: 'EXPLICIT', acquisitionId: h.acquisitionId });
      owed.push(created.preflightId);
    }
    const victim = await h.preflight({ expiresAt: EARLY });
    for (let index = 0; index < 6; index += 1) await createManagedLease(h.store, victim.preflightId, h.acquisitionId, { expiresAt: EARLY });
    await h.reserve();
    h.setClock(AFTER_EARLY);
    const capacity = await capacityOf(dataRoot);
    assert.equal(capacity.livePreflightCount, 2, 'fixture: count is full');
    assert.equal(capacity.preflightEncryptedBytes + h.reservationBytes() - (2 * h.reservationBytes()), 6 * COMMITTED_BYTES, 'fixture: the bytes need');
    let before = (await h.records()).length;
    const first = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_CAPACITY_FULL')(first.error), `the count refusal stands (got ${first.error?.code ?? 'success'})`);
    assert.deepEqual(kindsSince(await h.records(), before), Array(5).fill(ACKED), 'the owed acknowledgements are kept; the victim is not touched');
    assert.match(first.lines[0], /released=0 sealed=0 disposed=0 retired=0 acked=5 failed=0/u);
    assert.deepEqual((await tombstonedIds(dataRoot)).sort(), [...owed].sort(), 'the victim has no tombstone');
    before = (await h.records()).length;
    const second = await captureStoreLines(() => h.reserve());
    assert.equal(second.error, undefined, `the next call finishes (got ${second.error?.code})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [...Array(6).fill(DISPOSED), RETIRED, ACKED, RESERVED]);
    assert.equal(added[6].preflight.id, victim.preflightId);
  });
});

test('joint pressure: an acknowledgement that fails after its retire is an accepted partial reclaim; the tombstone stays, the bytes refusal stands, and the next call acknowledges it', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2, reservations: 2 }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.reserve();
    const capacity = await capacityOf(dataRoot);
    assert.equal(capacity.livePreflightCount, 2, 'fixture: count is full');
    assert.equal(capacity.preflightEncryptedBytes + h.reservationBytes() - (2 * h.reservationBytes()), COMMITTED_BYTES, 'fixture: the bytes need is the victim\'s own charge');
    h.faults.failNextAck = true;
    let before = (await h.records()).length;
    const first = await captureStoreLines(() => h.reserve());
    h.faults.failNextAck = false;
    assert.ok(code('REQUEST_BYTES_FULL')(first.error), `the count need was met and the bytes need was not (got ${first.error?.code ?? 'success'})`);
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED], 'the retire is durable; its failed acknowledgement is not retried in this call');
    assert.match(first.lines[0], /retired=1 acked=0 failed=1/u);
    assert.deepEqual(await tombstonedIds(dataRoot), [spent.preflightId], 'a fresh replay sees the tombstone');
    const owedCapacity = await capacityOf(dataRoot);
    assert.equal(owedCapacity.livePreflightCount, 1);
    assert.equal(owedCapacity.preflightEncryptedBytes, COMMITTED_BYTES + h.reservationBytes(), 'the retired preflight is still charged');
    before = (await h.records()).length;
    const second = await captureStoreLines(() => h.reserve());
    assert.equal(second.error, undefined, `the next call succeeds (got ${second.error?.code})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RESERVED], 'Phase 1 acknowledges the owed tombstone');
    assert.deepEqual(added[0].preflightDeletionAck.target, { preflightId: spent.preflightId });
  });
});

test('an owed EXPIRED or ABANDONED release is never sealed or acknowledged by the helper (its preparer may still be running)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30, reservations: 3 }) });
    const proofs = h.managedExecution.storageProofs;
    const expired = await h.reserve();
    await h.store.releaseManagedPreflightReservation({ reservationId: expired.reservationId, generation: 1, reason: 'EXPIRED', acquisitionId: h.acquisitionId });
    const abandoned = await h.reserve();
    proofs.publish({ kind: 'preflight', target: targetOf(abandoned), refs: [{ objectId: randomUUID(), sha256: DIGESTS.context, encryptedBytes: 2_048 }] });
    await h.store.releaseManagedPreflightReservation({ reservationId: abandoned.reservationId, generation: 1, reason: 'ABANDONED', acquisitionId: h.acquisitionId });
    const failed = await h.reserve();
    await releaseOwed(h, failed);
    assert.equal((await capacityOf(dataRoot)).preflightEncryptedBytes, 3 * h.reservationBytes(), 'fixture: three released reservations are charged, the cap is full');
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.equal(error, undefined, `the PREPARE_FAILED one carries the reserve (got ${error?.code})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RESERVED]);
    assert.deepEqual(added[0].preflightDeletionAck.target, targetOf(failed), 'the older EXPIRED and ABANDONED ones are skipped, not ranked first');
    assert.match(lines[0], /released=0 sealed=0 disposed=0 retired=0 acked=1 failed=0/u);
    for (const untouched of [expired, abandoned]) {
      const same = (call) => canonicalJson(call.target) === canonicalJson(targetOf(untouched));
      assert.equal(proofs.sealCalls().some(same), false, 'never sealed');
      assert.equal(proofs.deletionCalls().some(same), false, 'never deleted');
    }
    assert.deepEqual(proofs.inspectTarget({ kind: 'preflight', target: targetOf(abandoned) }).objects.map((entry) => entry.present), [true], 'the ABANDONED object is still there');
    assert.equal((await capacityOf(dataRoot)).preflightEncryptedBytes, 3 * h.reservationBytes(), 'those two stay charged: one was freed and one reserved');
    // With only those two left, bytes pressure appends nothing and keeps the bytes refusal.
    const idle = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_BYTES_FULL')(idle.error), `got ${idle.error?.code ?? 'success'}`);
    assert.equal((await h.records()).length, before + 2);
    assert.deepEqual(idle.lines, []);
  });
});

test('more zero-charge and unprovable released records than the budget cannot starve a real owed acknowledgement', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    // No sealTarget: a released reservation with no manifest row can then never be acknowledged.
    const { sealTarget: _unused, ...withoutSeal } = createFakeStorageProofs();
    const limits = storageLimits({ live: 30, reservations: 14 });
    const h = await openHarness(dataRoot, { limits, storageProofs: withoutSeal });
    const release = (reservation) => h.store.releaseManagedPreflightReservation({ reservationId: reservation.reservationId, generation: 1, reason: 'PREPARE_FAILED', acquisitionId: h.acquisitionId });
    for (let index = 0; index < 13; index += 1) {
      const unprovable = await h.reserve();
      await release(unprovable);
      const settled = await h.reserve();
      withoutSeal.publish({ kind: 'preflight', target: targetOf(settled), refs: [] });
      await release(settled);
      await h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: settled.reservationId, generation: 1, acquisitionId: h.acquisitionId });
    }
    const real = await h.reserve();
    withoutSeal.publish({ kind: 'preflight', target: targetOf(real), refs: [{ objectId: randomUUID(), sha256: DIGESTS.context, encryptedBytes: 2_048 }] });
    await release(real);
    const capacity = await capacityOf(dataRoot);
    assert.equal(capacity.preflightEncryptedBytes, 14 * h.reservationBytes(), 'fixture: 13 unprovable and 1 real reservation are charged');
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.equal(error, undefined, `the reserve must succeed (got ${error?.code})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RESERVED]);
    assert.deepEqual(added[0].preflightDeletionAck.target, targetOf(real));
    assert.equal(lines.length, 1);
    assert.match(lines[0], /released=0 sealed=0 disposed=0 retired=0 acked=1 failed=0/u);
  });
});

test('owed acknowledgements go largest relief first: thirteen small tombstones ahead of one large reservation cannot use up the budget', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    // The bytes need is one byte more than twelve small acknowledgements can free; the large owed reservation alone covers it.
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30, reservations: 2, extraBytes: COMMITTED_BYTES - 1 }) });
    for (let index = 0; index < 13; index += 1) {
      const created = await h.preflight({ expiresAt: LATER });
      await h.store.retireManagedPreflight({ preflightId: created.preflightId, expectedRevision: created.preflight.revision, reason: 'EXPLICIT', acquisitionId: h.acquisitionId });
    }
    const large = await h.reserve();
    await releaseOwed(h, large);
    const limit = (2 * h.reservationBytes()) + COMMITTED_BYTES - 1;
    assert.equal((await capacityOf(dataRoot)).preflightEncryptedBytes + h.reservationBytes() - limit, (12 * COMMITTED_BYTES) + 1, 'fixture: the bytes need');
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.equal(error, undefined, `the large acknowledgement carries the reserve (got ${error?.code})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RESERVED]);
    assert.deepEqual(added[0].preflightDeletionAck.target, targetOf(large));
    assert.match(lines[0], /acked=1 failed=0/u);
  });
});

test('act only while a need remains: one owed acknowledgement meets the need and the next is left; a dead reservation beyond the need is not released', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 30, reservations: 2 }) });
    const first = await h.reserve();
    await releaseOwed(h, first);
    const second = await h.reserve();
    await releaseOwed(h, second);
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RESERVED], 'one reservation of need, one acknowledgement');
    assert.deepEqual(added[0].preflightDeletionAck.target, targetOf(first), 'equal relief goes in ledger order');
  });
  await withManagedDataRoot(async (dataRoot) => {
    const { h, dead } = await afterDeadOwner(dataRoot, { limits: storageLimits({ live: 30, reservations: 2 }), reserve: 2 });
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [RELEASED, ACKED, RESERVED]);
    assert.equal(added[0].preflightReservation.reservationId, dead[0].reservationId);
    assert.equal((await replayShared(dataRoot)).getPreflightReservation(dead[1].reservationId).state, 'RESERVED', 'the second dead reservation is left for a later need');
  });
});

test('append bound (count-only pressure): when the twelfth append is a retire, its acknowledgement waits for a later bytes-pressure call', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    // No bytes need is open, so the retire alone meets the need; under joint pressure the same victim is not touched (see
    // the joint-pressure append tests above).
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const expired = await h.preflight({ expiresAt: EARLY });
    for (let index = 0; index < 11; index += 1) await createManagedLease(h.store, expired.preflightId, h.acquisitionId, { expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.equal(error, undefined, `the retire alone frees the count slot (got ${error?.code})`);
    assert.deepEqual(kindsSince(await h.records(), before), [...Array(11).fill(DISPOSED), RETIRED, RESERVED], 'eleven disposals and the retire make twelve; the acknowledgement would be a thirteenth');
    assert.match(lines[0], /disposed=11 retired=1 acked=0 failed=0/u);
    assert.deepEqual(await tombstonedIds(dataRoot), [expired.preflightId]);
  });
});

test('append bound: twelve appends per call; a partial reclaim then refuses with the same code, replays, and the next call finishes', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const expired = await h.preflight({ expiresAt: EARLY });
    const leases = [];
    for (let index = 0; index < 13; index += 1) leases.push(await createManagedLease(h.store, expired.preflightId, h.acquisitionId, { expiresAt: EARLY }));
    h.setClock(AFTER_EARLY);
    let before = (await h.records()).length;
    const first = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_CAPACITY_FULL')(first.error), `partial reclaim keeps the original refusal (got ${first.error?.code ?? 'success'})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), Array(12).fill(DISPOSED), 'exactly twelve appends, then the budget stops it');
    assert.match(first.lines.join(''), /disposed=12 retired=0 acked=0 failed=0/u);
    // Every prefix is a valid ledger: a fresh store and the frozen old-build validator both replay it.
    const { createSharedLedgerState: createFrozenState } = await loadFrozenValidator();
    assert.deepEqual((await replayShared(dataRoot, createFrozenState)).snapshot().capacity, (await capacityOf(dataRoot)));
    const fresh = h.open();
    assert.equal((await fresh.getLease(leases[11].id)).state, 'EXPIRED');
    before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [DISPOSED, RETIRED, ACKED, RESERVED], 'the next pressure call continues where it stopped');
  });
});

test('time bound: slow appends stop the helper at about 750 ms on the injected monotonic clock', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const monotonic = { now: 0 };
    let slow = false;
    const h = await openHarness(dataRoot, {
      limits: storageLimits({ live: 1 }), monotonic,
      beforeAtomicRename: () => { if (slow) monotonic.now += 300; },
    });
    const expired = await h.preflight({ expiresAt: EARLY });
    for (let index = 0; index < 5; index += 1) await createManagedLease(h.store, expired.preflightId, h.acquisitionId, { expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    slow = true;
    const before = (await h.records()).length;
    const { error } = await captureStoreLines(() => h.reserve());
    slow = false;
    assert.ok(code('REQUEST_CAPACITY_FULL')(error));
    assert.deepEqual(kindsSince(await h.records(), before), [DISPOSED, DISPOSED, DISPOSED], 'three 300 ms appends pass 750 ms');
  });
});

test('stop rule: after two consecutive failed attempts the helper stops; nothing is appended and the refusal stands', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const attempts = [];
    let blocked = false;
    const h = await openHarness(dataRoot, {
      limits: storageLimits({ live: 3 }),
      beforeAtomicRename: (record) => {
        if (blocked && record.kind === RETIRED) { attempts.push(record.preflight.id); throw Object.assign(new Error('blocked disk'), { code: 'EBUSY' }); }
      },
    });
    const victims = await fillLive(h, 3, { expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    blocked = true;
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    blocked = false;
    assert.ok(code('REQUEST_CAPACITY_FULL')(error));
    assert.deepEqual(attempts, [victims[0].preflightId, victims[1].preflightId], 'the third candidate is never tried');
    assert.equal((await h.records()).length, before);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /retired=0 acked=0 failed=2/u);
  });
});

test('stop rule: a success resets the consecutive failures, so fail, succeed, fail in one pass goes on to the next candidate', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const failing = new Set();
    const h = await openHarness(dataRoot, {
      limits: storageLimits({ live: 3 }),
      beforeAtomicRename: (record) => {
        if (record.kind === RETIRED && failing.has(record.preflight.id)) throw Object.assign(new Error('blocked disk'), { code: 'EBUSY' });
      },
    });
    const first = await h.preflight({ expiresAt: '2026-09-19T17:10:00.000Z' });
    const second = await h.preflight({ expiresAt: '2026-09-19T17:20:00.000Z' });
    const lease = await createManagedLease(h.store, second.preflightId, h.acquisitionId, { expiresAt: '2026-09-19T17:20:00.000Z' });
    const third = await h.preflight({ expiresAt: EARLY });
    failing.add(first.preflightId);
    failing.add(second.preflightId);
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    assert.equal(error, undefined, `the third candidate carries the reserve (got ${error?.code})`);
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [DISPOSED, RETIRED, ACKED, RESERVED], 'failed retire, disposal, failed retire, then retire and ack');
    assert.equal(added[0].lease.id, lease.id);
    assert.equal(added[1].preflight.id, third.preflightId);
    assert.match(lines[0], /disposed=1 retired=1 acked=1 failed=2/u);
  });
});

test('poison count: a candidate that always fails is attempted three times per store instance, then skipped', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const attempts = [];
    let poisonId;
    const h = await openHarness(dataRoot, {
      limits: storageLimits({ live: 5 }),
      beforeAtomicRename: (record) => {
        if (record.kind === RETIRED && record.preflight.id === poisonId) { attempts.push(record.preflight.id); throw Object.assign(new Error('blocked'), { code: 'EBUSY' }); }
      },
    });
    const poisoned = await h.preflight({ expiresAt: '2026-09-19T17:10:00.000Z' });
    poisonId = poisoned.preflightId;
    await fillLive(h, 4, { expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    for (let call = 1; call <= 4; call += 1) {
      const before = (await h.records()).length;
      await h.reserve();
      assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED], `call ${call}: another candidate carries the reserve`);
      assert.equal(attempts.length, Math.min(call, 3), `call ${call}: attempts on the poisoned candidate`);
    }
    await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'), 'only the poisoned candidate is left, and it is skipped');
    assert.equal(attempts.length, 3);
    // The count lives in this store instance only: a fresh instance tries again.
    h.store = h.open();
    await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'));
    assert.equal(attempts.length, 4);
  });
});

test('poison count: a success clears a candidate\'s failures, so two failed releases and then a failed acknowledgement do not poison it', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const proofs = createFakeStorageProofs();
    const faults = { releases: 0, deletions: 0, target: null };
    const storageProofs = {
      ...proofs,
      deleteRetired(args) {
        if (faults.deletions > 0 && canonicalJson(args.descriptor.target) === canonicalJson(faults.target)) { faults.deletions -= 1; throw Object.assign(new Error('unlink busy'), { code: 'EBUSY' }); }
        return proofs.deleteRetired(args);
      },
    };
    const { h, dead: [dead] } = await afterDeadOwner(dataRoot, {
      limits: storageLimits({ live: 1, reservations: 1 }), storageProofs,
      beforeAtomicRename: (record) => {
        if (faults.releases > 0 && record.kind === RELEASED) { faults.releases -= 1; throw Object.assign(new Error('blocked disk'), { code: 'EBUSY' }); }
      },
    });
    faults.target = targetOf(dead);
    faults.releases = 2;
    for (let call = 1; call <= 2; call += 1) await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'), `call ${call}: the release fails`);
    // Third call: the release succeeds, which clears the two failures, and its acknowledgement then fails once.
    faults.deletions = 1;
    let before = (await h.records()).length;
    await assert.rejects(h.reserve(), code('REQUEST_BYTES_FULL'));
    assert.deepEqual(kindsSince(await h.records(), before), [RELEASED]);
    // One failure since the success: the owed acknowledgement is still tried, and now works.
    before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RESERVED]);
    assert.deepEqual(added[0].preflightDeletionAck.target, targetOf(dead));
  });
});

test('poison expiry: a poisoned candidate is tried again once its last failure is five minutes old on the monotonic clock', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const monotonic = { now: 0 };
    let blocked = true;
    const attempts = [];
    const h = await openHarness(dataRoot, {
      limits: storageLimits({ live: 1 }), monotonic,
      beforeAtomicRename: (record) => {
        if (record.kind === RETIRED) { attempts.push(record.preflight.id); if (blocked) throw Object.assign(new Error('blocked disk'), { code: 'EBUSY' }); }
      },
    });
    const victim = await h.preflight({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    for (let call = 1; call <= 4; call += 1) {
      await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'));
      assert.equal(attempts.length, Math.min(call, 3), `call ${call}: attempts`);
    }
    blocked = false;
    monotonic.now = POISON_EXPIRY_MS - 1;
    await assert.rejects(h.reserve(), code('REQUEST_CAPACITY_FULL'), 'one millisecond early: still skipped');
    assert.equal(attempts.length, 3);
    monotonic.now = POISON_EXPIRY_MS;
    const before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED], 'the fault has cleared and the next pressure call succeeds');
    assert.deepEqual(attempts, [victim.preflightId, victim.preflightId, victim.preflightId, victim.preflightId]);
  });
});

test('concurrent reserves with one reclaimable candidate: one succeeds, one refuses, one retirement is recorded', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2 }) });
    const spent = await h.preflight({ expiresAt: LATER });
    await h.spend(spent);
    await h.preflight({ expiresAt: LATER });
    const before = (await h.records()).length;
    const outcomes = await Promise.allSettled([h.reserve(), h.reserve()]);
    assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
    assert.equal(outcomes.find((outcome) => outcome.status === 'rejected').reason?.code, 'REQUEST_CAPACITY_FULL');
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, ACKED, RESERVED]);
    assert.deepEqual(await tombstonedIds(dataRoot), [spent.preflightId]);
  });
});

test('an in-transaction seal is bounded: one that never settles is abandoned at the bound, the reserve and an unrelated read settle, and no acknowledgement follows', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const proofs = createFakeStorageProofs();
    const stuck = [];
    let stall = false;
    const storageProofs = {
      ...proofs,
      sealTarget(args) {
        if (!stall) return proofs.sealTarget(args);
        return new Promise((resolve) => { stuck.push(() => resolve(proofs.sealTarget(args))); });
      },
    };
    const bound = 300;
    const { h, dead: [dead] } = await afterDeadOwner(dataRoot, { limits: storageLimits({ live: 1 }), storageProofs, sealTimeoutMs: bound });
    // The target has a manifest row, so an acknowledgement would succeed if one were tried after the timed-out seal.
    proofs.publish({ kind: 'preflight', target: targetOf(dead), refs: [] });
    stall = true;
    const before = (await h.records()).length;
    const started = performance.now();
    const reserving = captureStoreLines(() => h.reserve());
    const reading = h.store.getServiceMode();
    const [{ error, lines }, mode] = await settleWithin(Promise.all([reserving, reading]), 10_000, 'the reserve and the queued read');
    const elapsed = performance.now() - started;
    assert.equal(error, undefined, `the release alone frees the count slot (got ${error?.code})`);
    assert.equal(mode.state, 'ACTIVE', 'an unrelated read queued behind the reserve settles too');
    assert.ok(elapsed >= bound - 50 && elapsed < bound + 5_000, `the reserve settles at the bound (took ${Math.round(elapsed)} ms)`);
    assert.equal(stuck.length, 1, 'exactly one seal was started');
    assert.deepEqual(kindsSince(await h.records(), before), [RELEASED, RESERVED], 'released, but never acknowledged after a timed-out seal');
    assert.match(lines[0], /released=1 sealed=0 disposed=0 retired=0 acked=0 failed=1/u);
    // The abandoned seal finishing later adds nothing to the ledger; the charge stays owed.
    stuck[0]();
    for (let index = 0; index < 20; index += 1) await turn();
    assert.deepEqual(kindsSince(await h.records(), before), [RELEASED, RESERVED]);
    assert.equal((await capacityOf(dataRoot)).preflightEncryptedBytes, 2 * h.reservationBytes(), 'the dead reservation stays charged until an owed acknowledgement');
  });
});

test('the helper never throws: a failing monotonic clock leaves the original refusal, appends nothing and logs one counts-only line', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    let broken = false;
    const monotonic = { get now() { if (broken) throw Object.assign(new Error('clock failed'), { code: 'CLOCK_BROKEN' }); return 0; } };
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }), monotonic });
    await h.preflight({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    broken = true;
    const { error, lines } = await captureStoreLines(() => h.reserve());
    broken = false;
    assert.ok(code('REQUEST_CAPACITY_FULL')(error), `the original refusal, never the clock's error (got ${error?.code ?? 'success'})`);
    assert.equal((await h.records()).length, before);
    assert.deepEqual(lines, ['openrouter-review-lease-store: preflight-reclaim released=0 sealed=0 disposed=0 retired=0 acked=0 failed=1 (counts only)\n']);
  });
});

test('spent victims rank by their latest receipt completedAt, not their earliest', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2 }) });
    const twice = await h.preflight({ expiresAt: LATER });
    await h.spend(twice, { completedAt: '2026-09-19T17:01:00.000Z' });
    await h.spend(twice, { completedAt: '2026-09-19T17:09:00.000Z' });
    const once = await h.preflight({ expiresAt: LATER });
    await h.spend(once, { completedAt: '2026-09-19T17:05:00.000Z' });
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [RETIRED, ACKED, RESERVED]);
    assert.equal(added[0].preflight.id, once.preflightId, 'latest 17:05 goes before latest 17:09, although the other was first returned at 17:01');
  });
});

test('a reservation of this same acquisition from an older replay barrier is a dead owner\'s: released as RESTART, sealed and acknowledged', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const older = await h.reserve();
    const advanced = await h.store.beginManagedReplay({ expectedModeRevision: h.mode.revision, acquisitionId: h.acquisitionId });
    assert.notEqual(advanced.replayBarrierId, older.replayBarrierId);
    assert.equal(older.ownerAcquisitionId, h.acquisitionId, 'fixture: the same acquisition');
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [RELEASED, ACKED, RESERVED]);
    assert.equal(added[0].preflightReservation.reservationId, older.reservationId);
    assert.equal(added[0].preflightReservation.releaseReason, 'RESTART');
  });
});

test('the helper uses the ledger\'s own expiry rule: expiresAt equal to now is expired, and now never runs behind the last row', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const victim = await h.preflight({ expiresAt: EARLY });
    const lease = await createManagedLease(h.store, victim.preflightId, h.acquisitionId, { expiresAt: EARLY });
    h.setClock(EARLY);
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [DISPOSED, RETIRED, ACKED, RESERVED], 'the preflight and its lease are expired at exactly their expiresAt');
    assert.equal(added[0].lease.id, lease.id);
  });
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2 }) });
    const victim = await h.preflight({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    await h.preflight({ expiresAt: LATER });
    // The wall clock steps back behind the last row; the ledger's now does not.
    h.time.now = NOW;
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [RETIRED, ACKED, RESERVED]);
    assert.equal(added[0].preflight.id, victim.preflightId);
  });
});

test('never reclaimed: a preflight whose expired lease still has a live staging permit (its disposal would be refused, so nothing is tried)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const victim = await h.preflight({ expiresAt: EARLY });
    const lease = await createManagedLease(h.store, victim.preflightId, h.acquisitionId, { expiresAt: EARLY });
    const stagingId = randomUUID();
    await h.store.reserveStagingPermit({
      stagingId, generation: 1, bindingId: 'binding-a', scopeDigest: DIGESTS.scope, leaseId: lease.id, keyDigest: KEY_DIGEST,
      inputDigest: INPUT_DIGEST, maxEncryptedBytes: preparedReservationBytes(h.managedExecution), effectiveDeadline: EARLY, acquisitionId: h.acquisitionId,
    });
    h.setClock(AFTER_EARLY);
    await assertNothingReclaimed(h, 'live staging');
    // Control: once the permit is released, the lease is disposed and the preflight reclaimed.
    await h.store.releaseStagingPermit({ stagingId, generation: 1, reason: 'EXPIRED', acquisitionId: h.acquisitionId });
    const before = (await h.records()).length;
    await h.reserve();
    assert.deepEqual(kindsSince(await h.records(), before), [DISPOSED, RETIRED, ACKED, RESERVED]);
  });
});

test('never reclaimed: a preflight whose expired lease carries a receipt binding with no receipt row (the ledger accepts one; its disposal would be refused)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const victim = await h.preflight({ expiresAt: EARLY });
    const plain = await createManagedLease(h.store, victim.preflightId, h.acquisitionId, { expiresAt: EARLY });
    // A second lease on the same preflight, created by a hand-written row whose binding names a receipt that does not exist.
    const { timestamp: _unused, ...row } = structuredClone((await h.records()).find((entry) => entry.kind === 'MANAGED_LEASE_CREATED'));
    row.lease.id = randomUUID();
    row.lease.managedBinding = { ...row.lease.managedBinding, receiptId: randomUUID(), executionFingerprint: 'c3'.repeat(32) };
    await appendRawRecord(dataRoot, { ...row, timestamp: new Date(NOW + 60_000).toISOString() });
    assert.equal((await h.store.getLease(row.lease.id)).managedBinding.receiptId, row.lease.managedBinding.receiptId, 'fixture: the ledger replays it');
    h.setClock(AFTER_EARLY);
    await assertNothingReclaimed(h, 'bound lease');
    assert.equal((await h.store.getLease(plain.id)).state, 'MANAGED_ACTIVE', 'not even the other, disposable lease is touched');
  });
});

test('the log line is one counts-only line per invocation that did work, and absent otherwise', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 2 }) });
    const expired = await h.preflight({ expiresAt: EARLY });
    await createManagedLease(h.store, expired.preflightId, h.acquisitionId, { expiresAt: EARLY });
    await h.preflight({ expiresAt: LATER });
    h.setClock(AFTER_EARLY);
    const worked = await captureStoreLines(() => h.reserve());
    assert.equal(worked.error, undefined);
    assert.equal(worked.lines.length, 1);
    assert.match(worked.lines[0], RECLAIM_LINE);
    assert.match(worked.lines[0], /released=0 sealed=0 disposed=1 retired=1 acked=1 failed=0/u);
    assert.doesNotMatch(worked.lines[0], /[0-9a-f]{8}-[0-9a-f]{4}|preflightId|reservationId|leaseId|\$|[\\/]/u, 'no id, amount or path');
    const idle = await captureStoreLines(() => h.reserve());
    assert.ok(code('REQUEST_CAPACITY_FULL')(idle.error));
    assert.deepEqual(idle.lines, [], 'pressure with nothing reclaimable logs nothing');
  });
});

test('dead-owner reservations are released as RESTART, sealed and acknowledged; the same owner\'s are untouched', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const time = { now: NOW };
    const execution = managedExecutionFor(dataRoot, { installationConfig: buildInstallationConfig({ dataRoot, storage: storageLimits({ live: 2, reservations: 12 }) }) });
    const first = await openHarness(dataRoot, { managedExecution: execution, time });
    const dead = await first.reserve();
    await first.owner.release({ final: true });
    const h = await openHarness(dataRoot, { managedExecution: execution, time });
    assert.notEqual(h.acquisitionId, first.acquisitionId);
    const mine = await h.reserve({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    const before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [RELEASED, ACKED, RESERVED]);
    assert.equal(added[0].preflightReservation.reservationId, dead.reservationId);
    assert.equal(added[0].preflightReservation.releaseReason, 'RESTART');
    assert.deepEqual(added[1].preflightDeletionAck.target, targetOf(dead));
    assert.deepEqual(execution.storageProofs.sealCalls(), [{ target: targetOf(dead), sealed: true }]);
    const state = await replayShared(dataRoot);
    assert.equal(state.getPreflightReservation(mine.reservationId).state, 'RESERVED', 'the same owner\'s expired reservation is untouched');
    assert.equal((await capacityOf(dataRoot)).preflightEncryptedBytes, 2 * h.reservationBytes(), 'the dead reservation\'s charge is gone');
  });
});

test('an ack failure leaves a durable tombstone; a later bytes-pressure call completes the owed acknowledgement', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const proofs = createFakeStorageProofs();
    let failDeletion = false;
    const storageProofs = { ...proofs, deleteRetired(args) { if (failDeletion) { failDeletion = false; throw Object.assign(new Error('unlink busy'), { code: 'EBUSY' }); } return proofs.deleteRetired(args); } };
    const reservation = maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: MIB });
    const h = await openHarness(dataRoot, { storageProofs, limits: storageLimits({ live: 2, reservations: 2, extraBytes: COMMITTED_BYTES }) });
    const first = await h.preflight({ expiresAt: EARLY });
    const second = await h.preflight({ expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    failDeletion = true;
    let before = (await h.records()).length;
    const call1 = await captureStoreLines(() => h.reserve());
    assert.equal(call1.error, undefined, 'the retire alone frees the count slot');
    assert.deepEqual(kindsSince(await h.records(), before), [RETIRED, RESERVED], 'the tombstone is durable, the ack failed');
    assert.match(call1.lines[0], /retired=1 acked=0 failed=1/u);
    const owedCapacity = await capacityOf(dataRoot);
    assert.equal(owedCapacity.preflightEncryptedBytes, (2 * COMMITTED_BYTES) + reservation, 'the retired preflight is still charged');
    // A fresh store replays the partial state too.
    assert.deepEqual((await replayShared(dataRoot)).snapshot().preflightTombstones.map((entry) => entry.preflightId), [first.preflightId]);
    before = (await h.records()).length;
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [ACKED, RETIRED, ACKED, RESERVED], 'bytes pressure finishes the owed ack first');
    assert.deepEqual(added[0].preflightDeletionAck.target, { preflightId: first.preflightId });
    assert.equal(added[1].preflight.id, second.preflightId);
  });
});

test('the records the helper writes replay identically in a fresh store and under the frozen main-12dccfd validator', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const time = { now: NOW };
    const reservation = maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: MIB });
    const execution = managedExecutionFor(dataRoot, {
      installationConfig: buildInstallationConfig({ dataRoot, storage: storageLimits({ live: 4, reservations: 2, extraBytes: 3 * COMMITTED_BYTES }) }),
    });
    // The first owner does all the setup and leaves one reservation RESERVED, then gives up ownership; the second owner
    // then sees that reservation as dead.
    const first = await openHarness(dataRoot, { managedExecution: execution, time });
    const spent = await first.preflight();
    const spentReview = await first.spend(spent);
    const extraLease = await createManagedLease(first.store, spent.preflightId, first.acquisitionId, { expiresAt: '2026-09-19T17:50:00.000Z' });
    await first.preflight({ expiresAt: LATEST });
    await first.preflight({ expiresAt: LATEST });
    const failedPreview = await first.reserve();
    await first.store.releaseManagedPreflightReservation({ reservationId: failedPreview.reservationId, generation: 1, reason: 'PREPARE_FAILED', acquisitionId: first.acquisitionId });
    const owed = await first.reserve();
    execution.storageProofs.publish({ kind: 'preflight', target: targetOf(owed), refs: [{ objectId: randomUUID(), sha256: DIGESTS.context, encryptedBytes: 2_048 }] });
    await releaseOwed(first, owed);
    const dead = await first.reserve();
    await first.owner.release({ final: true });
    const h = await openHarness(dataRoot, { managedExecution: execution, time });
    assert.equal((await capacityOf(dataRoot)).preflightEncryptedBytes, (2 * reservation) + (3 * COMMITTED_BYTES), 'fixture: the dead and the owed reservation are charged');
    assert.equal((await capacityOf(dataRoot)).livePreflightCount, 4, 'fixture: count is full');
    h.setClock(AFTER_FUTURE);
    const before = (await h.records()).length;
    await h.reserve();
    await h.reserve();
    const added = (await h.records()).slice(before);
    assert.deepEqual(added.map((record) => record.kind), [RELEASED, ACKED, RESERVED, ACKED, DISPOSED, RETIRED, ACKED, RESERVED]);

    const records = await h.records();
    const { createSharedLedgerState: createFrozenState } = await loadFrozenValidator();
    const current = await replayShared(dataRoot);
    const frozen = await replayShared(dataRoot, createFrozenState);
    assert.deepEqual(frozen.snapshot(), current.snapshot(), 'the old validator accepts every record and derives the same state');
    for (const record of records.filter((entry) => entry.recordType === 'shared/transition')) {
      for (const [id, read] of [
        [record.preflightReservation?.reservationId, 'getPreflightReservation'], [record.preflight?.id, 'getManagedPreflight'],
        [record.preflight?.id, 'getManagedIdentity'], [record.preflight?.id, 'getPreflightOrigin'],
        [record.receipt?.receiptId, 'getReceipt'], [record.lease?.id, 'getManagedLease'],
      ]) {
        if (id !== undefined) assert.deepEqual(frozen[read](id), current[read](id), `${read} agrees`);
      }
    }

    const fresh = h.open();
    assert.deepEqual(await fresh.listPinnedMappings(), await h.store.listPinnedMappings());
    assert.equal(await fresh.countLeasesForRawSource(DIGESTS.file), await h.store.countLeasesForRawSource(DIGESTS.file));
    assert.deepEqual(await fresh.getMostRecentLeaseForRawSource(DIGESTS.file), await h.store.getMostRecentLeaseForRawSource(DIGESTS.file));
    for (const store of [h.store, fresh]) {
      assert.equal(await store.lookupManagedIdentity({ selector: { preflightId: spent.preflightId }, bindingId: 'binding-a' }), null, 'a retired preflight cannot be authorized again');
      for (const selector of [{ leaseId: spentReview.lease.id }, { receiptId: spentReview.receipt.receiptId }, { leaseId: spentReview.lease.id, keyDigest: KEY_DIGEST }]) {
        assert.deepEqual(await store.lookupManagedIdentity({ selector, bindingId: 'binding-a' }), { projectId: PROJECT_ID, policyEpoch: 1, scopeDigest: DIGESTS.scope });
      }
      assert.equal((await store.recoverManagedReceipt({ receiptId: spentReview.receipt.receiptId, acquisitionId: h.acquisitionId })).receipt.state, 'TERMINAL');
      assert.equal((await store.getLease(extraLease.id)).state, 'EXPIRED');
    }
    const capacity = current.snapshot().capacity;
    assert.equal(capacity.preflightEncryptedBytes, (2 * reservation) + (2 * COMMITTED_BYTES));
    assert.equal(capacity.livePreflightCount, 4);
    assert.deepEqual(current.getPreflightReservation(dead.reservationId).state, 'RELEASED');
  });
});

test('the public retire still allows the claim window, so the helper\'s stricter pin rule is deliberate', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot);
    const created = await h.preflight({ expiresAt: LATER });
    const spent = await h.spend(created, { retireClaim: false });
    assert.equal((await h.store.recoverManagedReceipt({ receiptId: spent.receipt.receiptId, acquisitionId: h.acquisitionId })).executionGroup.state, 'CLAIMED');
    const retired = await h.store.retireManagedPreflight({ preflightId: created.preflightId, expectedRevision: created.preflight.revision, reason: 'EXPLICIT', acquisitionId: h.acquisitionId });
    assert.equal(retired.tombstone.preflightId, created.preflightId);
  });
});

test('no re-entry: the helper calls no public method (a nested mutate would deadlock) and its source names none', async () => {
  const source = (await readFile(new URL('../src/local-mcp/lease-store.mjs', import.meta.url), 'utf8')).replace(/\r\n/gu, '\n');
  const start = source.indexOf('  // Reclaim on pressure.');
  const end = source.indexOf('\n  return Object.freeze({', start);
  assert.ok(start > 0 && end > start, 'the helper region is found');
  const region = source.slice(start, end);
  assert.doesNotMatch(region, /\bmutate(?:UnderLock)?\(/u, 'the helper must not open a transaction');
  assert.doesNotMatch(region, /\.(?:retireManagedPreflight|ackManagedPreflightPayloadDeletion|ackReleasedPreflightReservationPayloadDeletion|disposeUnadmittedManagedLease|releaseManagedPreflightReservation|reserveManagedPreflightCapacity)\(/u);
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot, { limits: storageLimits({ live: 1 }) });
    const expired = await h.preflight({ expiresAt: EARLY });
    await createManagedLease(h.store, expired.preflightId, h.acquisitionId, { expiresAt: EARLY });
    h.setClock(AFTER_EARLY);
    let timer;
    const outcome = await Promise.race([
      h.reserve().then(() => 'done'),
      new Promise((resolve) => { timer = setTimeout(() => resolve('deadlock'), 20_000); }),
    ]);
    clearTimeout(timer);
    assert.equal(outcome, 'done', 'a reserve under pressure completes (no nested transaction)');
  });
});

test('the extracted bodies behave as the public methods did: results and error codes', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot);
    const a = h.acquisitionId;
    // dispose
    const created = await h.preflight({ expiresAt: LATER });
    const lease = await createManagedLease(h.store, created.preflightId, a);
    await assert.rejects(h.store.disposeUnadmittedManagedLease({ leaseId: lease.id, expectedRevision: 2, reason: 'EXPIRED', acquisitionId: a }), code('REQUEST_REVISION_CONFLICT'));
    await assert.rejects(h.store.disposeUnadmittedManagedLease({ leaseId: lease.id, expectedRevision: 1, reason: 'OTHER', acquisitionId: a }), TypeError);
    await assert.rejects(h.store.disposeUnadmittedManagedLease({ leaseId: randomUUID(), expectedRevision: 1, reason: 'EXPIRED', acquisitionId: a }), code('MANAGED_LEASE_REQUIRED'));
    const disposed = await h.store.disposeUnadmittedManagedLease({ leaseId: lease.id, expectedRevision: 1, reason: 'PREPARATION_FAILED', acquisitionId: a });
    assert.deepEqual([disposed.state, disposed.revision], ['CANCELLED', 2]);
    const admittedLease = await createManagedLease(h.store, created.preflightId, a);
    await admitManagedReceipt(h.store, h.managedExecution, a, { lease: admittedLease, preflightId: created.preflightId });
    const admittedCurrent = await h.store.getLease(admittedLease.id);
    await assert.rejects(h.store.disposeUnadmittedManagedLease({ leaseId: admittedLease.id, expectedRevision: admittedCurrent.revision, reason: 'EXPIRED', acquisitionId: a }), code('REQUEST_NOT_ELIGIBLE'));
    // retire
    await assert.rejects(h.store.retireManagedPreflight({ preflightId: randomUUID(), expectedRevision: 1, reason: 'X', acquisitionId: a }), code('FRESH_PREFLIGHT_REQUIRED'));
    await assert.rejects(h.store.retireManagedPreflight({ preflightId: created.preflightId, expectedRevision: 1, reason: 'X', acquisitionId: a }), code('SERVICE_ROLLBACK_BLOCKED'));
    const other = await h.preflight({ expiresAt: LATER });
    await assert.rejects(h.store.retireManagedPreflight({ preflightId: other.preflightId, expectedRevision: 1, reason: '', acquisitionId: a }), TypeError);
    await assert.rejects(h.store.retireManagedPreflight({ preflightId: other.preflightId, expectedRevision: 2, reason: 'X', acquisitionId: a }), code('REQUEST_REVISION_CONFLICT'));
    await assert.rejects(h.store.ackManagedPreflightPayloadDeletion({ preflightId: other.preflightId, expectedRevision: 1, acquisitionId: a }), code('REQUEST_NOT_ELIGIBLE'));
    const retired = await h.store.retireManagedPreflight({ preflightId: other.preflightId, expectedRevision: 1, reason: 'X', acquisitionId: a });
    assert.equal(retired.preflight.revision, 2);
    const audit = retired.tombstone.retiredMappingAuditRef;
    assert.equal(Date.parse(audit.mappingDeleteNoLaterThan) - Date.parse(audit.retiredAt), 24 * 60 * 60 * 1000, 'the 24-hour deletion target is unchanged');
    await assert.rejects(h.store.retireManagedPreflight({ preflightId: other.preflightId, expectedRevision: 2, reason: 'X', acquisitionId: a }), code('REQUEST_REVISION_CONFLICT'));
    const ack = await h.store.ackManagedPreflightPayloadDeletion({ preflightId: other.preflightId, expectedRevision: 2, acquisitionId: a });
    assert.deepEqual(Object.keys(ack).sort(), ['context', 'deletionProvedAt', 'mapping', 'target', 'version']);
    await assert.rejects(h.store.ackManagedPreflightPayloadDeletion({ preflightId: other.preflightId, expectedRevision: 2, acquisitionId: a }), code('REQUEST_REVISION_CONFLICT'));
    // released ack
    const reserved = await h.reserve();
    await assert.rejects(h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: reserved.reservationId, generation: 1, acquisitionId: a }), code('STAGING_STALE'));
    h.managedExecution.storageProofs.publish({ kind: 'preflight', target: targetOf(reserved), refs: [] });
    await h.store.releaseManagedPreflightReservation({ reservationId: reserved.reservationId, generation: 1, reason: 'EXPIRED', acquisitionId: a });
    await assert.rejects(h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: reserved.reservationId, generation: 2, acquisitionId: a }), code('STAGING_STALE'));
    // The public method accepts any RELEASED reservation whatever its reason (here EXPIRED), as it always did, and is
    // deliberately left unchanged; only the reclaim helper and the release's own refund restrict themselves to
    // PREPARE_FAILED and RESTART.
    const releasedAck = await h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: reserved.reservationId, generation: 1, acquisitionId: a });
    assert.deepEqual(Object.keys(releasedAck.target), ['reservationId', 'generation'], 'the ack target keeps the key order capacity looks up');
    assert.equal(releasedAck.context, undefined);
    await assert.rejects(h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: reserved.reservationId, generation: 1, acquisitionId: a }), code('REQUEST_REVISION_CONFLICT'));
    const unproved = await h.reserve();
    await h.store.releaseManagedPreflightReservation({ reservationId: unproved.reservationId, generation: 1, reason: 'ABANDONED', acquisitionId: a });
    await assert.rejects(h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: unproved.reservationId, generation: 1, acquisitionId: a }), code('PROTECTED_CONTENT_INVALID'));
    // A foreign acquisition is refused before any body runs.
    for (const call of [
      () => h.store.retireManagedPreflight({ preflightId: created.preflightId, expectedRevision: 1, reason: 'X', acquisitionId: randomUUID() }),
      () => h.store.ackManagedPreflightPayloadDeletion({ preflightId: other.preflightId, expectedRevision: 2, acquisitionId: randomUUID() }),
      () => h.store.ackReleasedPreflightReservationPayloadDeletion({ reservationId: unproved.reservationId, generation: 1, acquisitionId: randomUUID() }),
      () => h.store.disposeUnadmittedManagedLease({ leaseId: admittedLease.id, expectedRevision: 1, reason: 'EXPIRED', acquisitionId: randomUUID() }),
    ]) await assert.rejects(call(), /does not currently hold process ownership/u);
  });
});

test('spendManagedPreflight leaves a REVIEW_RETURNED receipt with its claim retired (terminalizeManagedFixture needs no change)', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const h = await openHarness(dataRoot);
    const created = await h.preflight({ expiresAt: LATER });
    const spent = await h.spend(created, { completedAt: '2026-09-19T17:04:00.000Z' });
    assert.equal(spent.receipt.state, 'TERMINAL');
    assert.equal(spent.receipt.terminal.kind, 'REVIEW_RETURNED');
    assert.equal(spent.receipt.terminal.completedAt, '2026-09-19T17:04:00.000Z');
    const view = await h.store.recoverManagedReceipt({ receiptId: spent.receipt.receiptId, acquisitionId: h.acquisitionId });
    assert.equal(view.executionGroup.state, 'TERMINAL');
    assert.equal(view.lease.state, 'CLOSED');
    assert.deepEqual((await h.store.listPinnedMappings()).find((entry) => entry.preflightId === created.preflightId).receiptIds, [], 'no receipt pins it any more');
  });
});
