import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
// A NAMESPACE import, deliberately. A named import of an export that does not exist yet is an ESM
// link error, which fails this whole file before any test runs. Through the namespace, a missing
// export reads `undefined`, so each test fails on an assertion that names what is missing.
import * as leaseStoreModule from '../src/local-mcp/lease-store.mjs';

const { createLeaseStore } = leaseStoreModule;

// Store-level coverage for on-demand ownership arming: the contention error, the unarmed handle and
// its arm()/release() state machine, the arming backoff and cap stamping. Every test runs against a
// REAL createLeaseStore() on a fresh temp data root. Time is faked through clock/monotonicNow/sleep wherever a test needs to control
// it, the same idiom as tests/openrouter-review-lease.test.mjs.

// A fixed wall-clock origin, built with Date.UTC so no long digit literal appears in source.
const T0 = Date.UTC(2026, 8, 18, 0, 0, 0);
// A holder pid that is not this process. Every test that uses it injects isProcessAlive, so no real
// process is ever signalled.
const FOREIGN_PID = 4242;

const realSleep = (milliseconds) => new Promise((resolve) => { setTimeout(resolve, milliseconds); });

async function withDataRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-owner-handle-'));
  try {
    return await run(dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// Writes a processOwner record straight into the ledger, bypassing the store: the same idiom as
// seedAcquiredOwnerRecord in tests/openrouter-review-lease-process-liveness.test.mjs. `extra` adds
// fields such as `caps`; `rawJson` replaces the serialized text outright, for values JSON.stringify
// cannot produce (a literal -0 or 1e999). Give a later record a later timestampMs: replay() orders
// the ledger by file name, which starts with the timestamp.
async function seedOwnerRecord(dataRoot, {
  state = 'ACQUIRED', pid = FOREIGN_PID, generation = 1, acquisitionId = randomUUID(),
  timestampMs = T0, extra = {}, rawJson,
} = {}) {
  const ledgerRoot = join(dataRoot, 'ledger');
  await mkdir(ledgerRoot, { recursive: true });
  const timestamp = new Date(timestampMs).toISOString();
  const record = { recordType: 'processOwner', state, pid, generation, acquisitionId, timestamp, ...extra };
  const text = rawJson === undefined ? JSON.stringify(record) : rawJson(record);
  await writeFile(join(ledgerRoot, `${timestamp.replace(/[:.]/g, '-')}-seed-${randomUUID()}.json`), `${text}\n`, 'utf8');
  return record;
}

// Every processOwner record on disk, in ledger (file-name) order.
async function readOwnerRecords(dataRoot) {
  let names;
  try {
    names = (await readdir(join(dataRoot, 'ledger'))).filter((name) => name.endsWith('.json')).sort();
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const records = [];
  for (const name of names) {
    const record = JSON.parse(await readFile(join(dataRoot, 'ledger', name), 'utf8'));
    if (record.recordType === 'processOwner') records.push(record);
  }
  return records;
}

// Plants the raw data-root write lock in the shape a writer killed mid-mutate() leaves behind:
// tests/openrouter-review-lease.test.mjs's plantOrphanedDataRootLock idiom.
async function plantDataRootLock(dataRoot, { lockedAtMs, pid = FOREIGN_PID }) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  await mkdir(lockRoot, { recursive: true });
  const owner = { pid, timestamp: new Date(lockedAtMs).toISOString(), lockToken: randomUUID() };
  await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(owner)}\n`, 'utf8');
}

// Awaits a promise that must reject and returns the rejection, for property-level assertions.
async function rejectionOf(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return assert.fail('expected the promise to reject');
}

// One valid arm() argument set. Tests spread over it to vary a single field.
const ARM = Object.freeze({
  acquireTimeoutMs: 1_000,
  lockRetryMs: 250,
  caps: Object.freeze({ installationHardMaximumUsd: 5 }),
});

// The unarmed handle, with a named failure while the entry point does not exist yet.
function unarmedHandleOf(store) {
  assert.equal(typeof store.createUnarmedOwnerHandle, 'function', 'store.createUnarmedOwnerHandle() does not exist yet');
  return store.createUnarmedOwnerHandle();
}

async function pathExists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

test('a deadline crossed before the first attempt still reports the observed holder', async () => {
  await withDataRoot(async (dataRoot) => {
    const holder = await seedOwnerRecord(dataRoot);
    let reads = 0;
    const store = createLeaseStore({
      dataRoot, clock: () => T0 + 5_000,
      monotonicNow: () => reads++ === 0 ? 0 : 2,
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      sleep: async () => assert.fail('no sleep after the budget expired'),
    });
    const error = await rejectionOf(store.acquireProcessOwnership({ acquireTimeoutMs: 1 }));
    assert.equal(error.reason, 'LIVE_OWNER');
    assert.deepEqual(error.owner, { pid: FOREIGN_PID, generation: 1, timestamp: holder.timestamp });
    assert.equal((await readOwnerRecords(dataRoot)).length, 1);
  });
});

test('a deadline crossed before the first attempt still permits an empty-root acquisition to commit', async () => {
  await withDataRoot(async (dataRoot) => {
    let reads = 0;
    let transactions = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      monotonicNow: () => reads++ === 0 ? 0 : 2,
      beforeRelease: async (released) => {
        if (Object.hasOwn(released, 'lockToken')) transactions += 1;
      },
      sleep: async () => assert.fail('a successful first attempt never sleeps'),
    });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1 });
    assert.equal(handle.isOwner(), true);
    assert.equal(transactions, 1, 'the first ownership transaction must run despite the crossed deadline');
    const records = await readOwnerRecords(dataRoot);
    assert.equal(records.length, 1);
    assert.equal(records[0].state, 'ACQUIRED');
    await handle.release();
  });
});

test('the lock and contention codes are exported with their literal values, and a real lock timeout carries the exported code', async () => {
  assert.equal(leaseStoreModule.LEDGER_DATA_ROOT_LOCKED_CODE, 'LEDGER_DATA_ROOT_LOCKED');
  assert.equal(leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE, 'PROCESS_OWNERSHIP_UNAVAILABLE');
  await withDataRoot(async (dataRoot) => {
    // A busy data-root lock that never ages (the clock is fixed), held by a "live" pid.
    await plantDataRootLock(dataRoot, { lockedAtMs: T0 });
    const store = createLeaseStore({ dataRoot, clock: () => T0, lockTimeoutMs: 30, lockRetryMs: 5, isProcessAlive: () => true });
    const error = await rejectionOf(store.getLease('any-lease-id'));
    assert.equal(error.code, leaseStoreModule.LEDGER_DATA_ROOT_LOCKED_CODE, 'the export must be the value the store really throws');
  });
});

test('a LIVE_OWNER timeout keeps its exact message and names the holder, even from the pre-attempt deadline check', async () => {
  await withDataRoot(async (dataRoot) => {
    const holder = await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let monotonic = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      lockRetryMs: 10,
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      monotonicNow: () => monotonic,
      sleep: async (milliseconds) => { monotonic += milliseconds; },
    });
    // Attempts start at monotonic 0, 10 and 20; the sleep after the third lands on 30, past the
    // 25 ms budget, so this throw comes from the PRE-attempt check.
    const error = await rejectionOf(store.acquireProcessOwnership({ acquireTimeoutMs: 25 }));
    assert.equal(String(error), 'Error: acquireProcessOwnership timed out after 25ms (LIVE_OWNER)');
    assert.equal(error.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
    assert.equal(error.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE);
    assert.equal(error.reason, 'LIVE_OWNER');
    assert.deepEqual(error.owner, { pid: FOREIGN_PID, generation: 1, timestamp: holder.timestamp });
    assert.equal(Object.hasOwn(error.owner, 'acquisitionId'), false, 'the fence token must never leave the store');
    assert.equal(error.ownerAgeMs, 5_000);
    assert.equal((await readOwnerRecords(dataRoot)).length, 1, 'a refused acquire appends nothing');
  });
});

test('an attempt that itself crosses the deadline throws from the post-attempt check with the same holder', async () => {
  await withDataRoot(async (dataRoot) => {
    const holder = await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let monotonic = 0;
    let sleeps = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      monotonicNow: () => monotonic,
      sleep: async () => { sleeps += 1; },
      // beforeRelease also fires on every data-root lock release, with { lockToken }. Charging
      // 100 ms of fake time there makes each attempt cost 100 ms, so the first attempt ends past
      // the 50 ms budget.
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) monotonic += 100; },
    });
    const error = await rejectionOf(store.acquireProcessOwnership({ acquireTimeoutMs: 50 }));
    assert.equal(sleeps, 0, 'the first attempt ends past the deadline, so no retry sleep may happen');
    assert.equal(error.message, 'acquireProcessOwnership timed out after 50ms (LIVE_OWNER)');
    assert.equal(error.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
    assert.equal(error.reason, 'LIVE_OWNER');
    assert.deepEqual(error.owner, { pid: FOREIGN_PID, generation: 1, timestamp: holder.timestamp });
    assert.equal(error.ownerAgeMs, 5_000);
  });
});

test('a NOT_YET_STALE timeout now names the holder too', async () => {
  await withDataRoot(async (dataRoot) => {
    const holder = await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let monotonic = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      lockRetryMs: 10,
      lockStaleMs: 60_000,
      isProcessAlive: () => false,
      monotonicNow: () => monotonic,
      sleep: async (milliseconds) => { monotonic += milliseconds; },
    });
    const error = await rejectionOf(store.acquireProcessOwnership({ acquireTimeoutMs: 25 }));
    assert.equal(error.message, 'acquireProcessOwnership timed out after 25ms (NOT_YET_STALE)');
    assert.equal(error.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
    assert.equal(error.reason, 'NOT_YET_STALE');
    assert.deepEqual(error.owner, { pid: FOREIGN_PID, generation: 1, timestamp: holder.timestamp });
    assert.equal(error.ownerAgeMs, 5_000);
  });
});

test('a DATA_ROOT_LOCKED timeout names no holder, even when an earlier attempt saw one', async () => {
  // Case 1: every attempt loses the data-root lock.
  await withDataRoot(async (dataRoot) => {
    await plantDataRootLock(dataRoot, { lockedAtMs: T0 });
    const store = createLeaseStore({
      dataRoot, clock: () => T0, lockTimeoutMs: 30, lockRetryMs: 5, isProcessAlive: () => true, sleep: realSleep,
    });
    const error = await rejectionOf(store.acquireProcessOwnership({ acquireTimeoutMs: 200 }));
    assert.equal(error.message, 'acquireProcessOwnership timed out after 200ms (DATA_ROOT_LOCKED)');
    assert.equal(error.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
    assert.equal(error.reason, 'DATA_ROOT_LOCKED');
    assert.equal(Object.hasOwn(error, 'owner'), false);
    assert.equal(Object.hasOwn(error, 'ownerAgeMs'), false);
  });
  // Case 2: the first attempt sees a LIVE_OWNER; the first retry sleep then plants a busy lock
  // that outlasts the budget. The error reports the LAST reason and must not drag the earlier
  // holder along with it.
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let planted = false;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      lockTimeoutMs: 30,
      lockRetryMs: 5,
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      sleep: async (milliseconds) => {
        if (!planted) {
          planted = true;
          await plantDataRootLock(dataRoot, { lockedAtMs: T0 + 5_000 });
        }
        await realSleep(milliseconds);
      },
    });
    // 400 ms, not 200: the first attempt must finish inside the budget on a loaded host, or the
    // lock is never planted (the same budget as tests/openrouter-review-lease.test.mjs:1889).
    const error = await rejectionOf(store.acquireProcessOwnership({ acquireTimeoutMs: 400 }));
    assert.equal(planted, true, 'the first attempt must have reached the retry sleep');
    assert.equal(error.message, 'acquireProcessOwnership timed out after 400ms (DATA_ROOT_LOCKED)');
    assert.equal(error.reason, 'DATA_ROOT_LOCKED');
    assert.equal(Object.hasOwn(error, 'owner'), false, 'a DATA_ROOT_LOCKED error never carries a stale holder');
  });
});

test('the handle codes and the arming backoff multiplier are exported with their literal values', () => {
  assert.equal(leaseStoreModule.ARM_IN_PROGRESS_CODE, 'ARM_IN_PROGRESS');
  assert.equal(leaseStoreModule.OWNER_HANDLE_RELEASED_CODE, 'OWNER_HANDLE_RELEASED');
  assert.equal(leaseStoreModule.ARM_ABORTED_CODE, 'ARM_ABORTED');
  assert.equal(leaseStoreModule.ARM_BACKOFF_MULTIPLIER, 4);
});

test('createLeaseStore refuses a non-function random or afterOwnerAcquired', () => {
  // No I/O happens at construction, so a placeholder dataRoot is safe here.
  assert.throws(() => createLeaseStore({ dataRoot: 'unused', random: 0.5 }), TypeError);
  assert.throws(() => createLeaseStore({ dataRoot: 'unused', afterOwnerAcquired: 'later' }), TypeError);
  assert.doesNotThrow(() => createLeaseStore({ dataRoot: 'unused', random: () => 0.5, afterOwnerAcquired: async () => {} }));
});

test('createUnarmedOwnerHandle() mints a frozen, unarmed handle and touches no file at all', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    assert.equal(Object.isFrozen(handle), true);
    assert.equal(handle.state, 'unarmed');
    assert.equal(handle.isOwner(), false);
    assert.equal(handle.acquisitionId, null);
    assert.equal(handle.generation, null);
    assert.equal(handle.dataRoot, dataRoot);
    assert.deepEqual(await readdir(dataRoot), [], 'no ledger directory, no lock directory, no record');
  });
});

test('the id getters are live accessors on the frozen object, methods work detached, and a spread snapshots', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    for (const name of ['generation', 'acquisitionId', 'state']) {
      assert.equal(typeof Object.getOwnPropertyDescriptor(handle, name).get, 'function', `${name} must be an accessor`);
    }
    assert.throws(() => { handle.acquisitionId = 'forged'; }, TypeError);
    const snapshot = { ...handle };
    // Detached references, exactly as a delegating wrapper holds them: nothing may rely on `this`.
    const { arm, isOwner, release } = handle;
    await arm(ARM);
    assert.equal(isOwner(), true);
    assert.equal(handle.state, 'armed');
    assert.equal(handle.generation, 1);
    assert.equal(typeof handle.acquisitionId, 'string');
    assert.equal(snapshot.acquisitionId, null, 'a spread copies the value at spread time: wrap a handle, never spread it');
    await release();
    assert.equal(handle.state, 'released');
    assert.equal(handle.acquisitionId, null);
    assert.equal(handle.generation, null);
  });
});

test('arm() on an unarmed handle appends exactly one ACQUIRED record for this process, and the getters track it', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    const records = await readOwnerRecords(dataRoot);
    assert.equal(records.length, 1);
    assert.equal(records[0].state, 'ACQUIRED');
    assert.equal(records[0].pid, process.pid);
    assert.equal(records[0].generation, handle.generation);
    assert.equal(records[0].acquisitionId, handle.acquisitionId);
    assert.equal(handle.isOwner(), true);
  });
});

test('acquireProcessOwnership() returns the same state-machine handle, already armed, and arm() on it does no I/O', async () => {
  await withDataRoot(async (dataRoot) => {
    let renames = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      // renameImpl runs twice in every mutate() cycle (the lock's atomic publish and its release),
      // so a count of zero proves no ledger transaction ran (tests/openrouter-review-lease.test.mjs:1554).
      renameImpl: async (from, to) => { renames += 1; return rename(from, to); },
    });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000 });
    assert.equal(handle.state, 'armed');
    assert.equal(typeof handle.arm, 'function', 'the acquired handle must carry the same arm()');
    const before = await readOwnerRecords(dataRoot);
    renames = 0;
    await handle.arm(ARM);
    assert.equal(renames, 0, 'arm() on an armed handle must not open a ledger transaction');
    assert.deepEqual(await readOwnerRecords(dataRoot), before);
    assert.equal(handle.isOwner(), true);
  });
});

test('arm() refuses a malformed argument with TypeError before any I/O, armed or not', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    const malformed = [
      undefined,
      { ...ARM, acquireTimeoutMs: 0 },
      { ...ARM, acquireTimeoutMs: 1.5 },
      { ...ARM, acquireTimeoutMs: '1000' },
      { ...ARM, lockRetryMs: 0 },
      { ...ARM, lockRetryMs: -1 },
      { ...ARM, caps: undefined },
      { ...ARM, caps: null },
      { ...ARM, caps: [] },
      { ...ARM, caps: Object.assign(Object.create({ inherited: true }), { installationHardMaximumUsd: 5 }) },
      { ...ARM, caps: {} },
      { ...ARM, caps: { installationHardMaximumUsd: -1 } },
      { ...ARM, caps: { installationHardMaximumUsd: Number.NaN } },
      { ...ARM, caps: { installationHardMaximumUsd: Number.POSITIVE_INFINITY } },
      { ...ARM, caps: { installationHardMaximumUsd: '5' } },
      { ...ARM, shouldAbort: 'yes' },
      { ...ARM, shouldAbort: null },
    ];
    for (const options of malformed) {
      await assert.rejects(handle.arm(options), TypeError);
      assert.equal(handle.state, 'unarmed');
    }
    assert.deepEqual(await readdir(dataRoot), [], 'a refused arm() must touch no file');
    await handle.arm(ARM);
    await assert.rejects(handle.arm({ ...ARM, lockRetryMs: 0 }), TypeError, 'an armed handle validates too');
    assert.equal(handle.state, 'armed');
  });
});

test('re-entering arm() while an arm is in flight throws ARM_IN_PROGRESS and starts no second acquisition', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    const first = handle.arm(ARM);
    assert.equal(handle.state, 'arming', 'the state flips synchronously, before any I/O completes');
    assert.equal(handle.isOwner(), false, 'isOwner() is exactly state === armed, so an arm in flight does not own yet');
    assert.equal(handle.acquisitionId, null);
    const error = await rejectionOf(handle.arm(ARM));
    assert.equal(error.code, leaseStoreModule.ARM_IN_PROGRESS_CODE);
    assert.equal(error.code, 'ARM_IN_PROGRESS');
    assert.equal(error.name, 'Error');
    await first;
    assert.equal(handle.state, 'armed');
    const acquired = (await readOwnerRecords(dataRoot)).filter((record) => record.state === 'ACQUIRED');
    assert.equal(acquired.length, 1, 'exactly one acquisition, never a second one racing it');
  });
});

test('a failed arm() returns the handle to unarmed with the loop error unchanged, and a later arm() genuinely retries', async () => {
  await withDataRoot(async (dataRoot) => {
    const holder = await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = T0 + 5_000;
    let holderAlive = true;
    const store = createLeaseStore({
      dataRoot,
      clock: () => now,
      monotonicNow: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
      isProcessAlive: (pid) => (pid === FOREIGN_PID ? holderAlive : true),
      processStartTimeMs: async () => null,
    });
    const handle = unarmedHandleOf(store);
    const error = await rejectionOf(handle.arm(ARM));
    assert.equal(error.message, 'arm timed out after 1000ms (LIVE_OWNER)');
    assert.equal(error.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE);
    assert.deepEqual(error.owner, { pid: FOREIGN_PID, generation: 1, timestamp: holder.timestamp });
    assert.equal(handle.state, 'unarmed');
    assert.equal(handle.acquisitionId, null);
    // The holder then releases cleanly. The SAME handle arms at the next generation.
    await seedOwnerRecord(dataRoot, { state: 'RELEASED', acquisitionId: holder.acquisitionId, timestampMs: T0 + 1 });
    holderAlive = false;
    await handle.arm(ARM);
    assert.equal(handle.state, 'armed');
    assert.equal(handle.generation, 2);
  });
});

test('arm() during an in-flight release waits for it, re-arms after a non-final release, and refuses after a final one', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    const releasing = handle.release({ final: false });
    const rearming = handle.arm(ARM);
    await releasing;
    await rearming;
    assert.equal(handle.state, 'armed');
    assert.equal(handle.generation, 2);
    const finalRelease = handle.release({ final: true });
    const refused = rejectionOf(handle.arm(ARM));
    await finalRelease;
    assert.equal((await refused).code, leaseStoreModule.OWNER_HANDLE_RELEASED_CODE);
    assert.equal(handle.state, 'released');
  });
});

// The release in the in-flight-release test above always succeeds. This is the other branch the contract names: the
// release an arm is waiting on FAILS, which leaves the handle armed, so the arm must resolve on it
// and must not start a second acquisition or inherit the release's error.
test('arm() during an in-flight release that FAILS waits for it, then resolves on the handle the failure left armed, starting no second acquisition', async () => {
  await withDataRoot(async (dataRoot) => {
    let failNextRelease = false;
    let acquisitions = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      // Counts ACQUIRED appends, and fails the next RELEASED append (the same failed-release idiom as the release tests below).
      beforeAtomicRename: async (record) => {
        if (record.recordType !== 'processOwner') return;
        if (record.state === 'ACQUIRED') acquisitions += 1;
        if (failNextRelease && record.state === 'RELEASED') {
          failNextRelease = false;
          throw Object.assign(new Error('simulated append failure'), { code: 'EPERM' });
        }
      },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    const { acquisitionId, generation } = handle;
    failNextRelease = true;
    const releasing = rejectionOf(handle.release({ final: false }));
    const rearming = handle.arm(ARM);
    assert.equal(handle.state, 'releasing', 'the arm arrived while the release was in flight');
    assert.match((await releasing).message, /simulated append failure/, 'the release caller sees its own failure');
    await rearming; // resolves: the arm caller does not inherit the release's failure
    assert.equal(handle.state, 'armed');
    assert.equal(handle.acquisitionId, acquisitionId, 'still the same acquisition');
    assert.equal(handle.generation, generation);
    assert.equal(acquisitions, 1, 'no second acquisition was started');
    assert.deepEqual((await readOwnerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED']);
  });
});

test('release() on a never-armed handle is a clean no-op that touches no file, and a final one is terminal', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed', 'a non-final release of nothing leaves the handle re-armable');
    await handle.release();
    assert.equal(handle.state, 'released', 'a bare release() is final');
    await handle.release();
    assert.equal(handle.state, 'released');
    assert.deepEqual(await readdir(dataRoot), [], 'no ledger directory, no lock directory, no record');
    const error = await rejectionOf(handle.arm(ARM));
    assert.equal(error.code, leaseStoreModule.OWNER_HANDLE_RELEASED_CODE);
    assert.deepEqual(await readdir(dataRoot), [], 'the refused arm() touched nothing either');
  });
});

test('release({ final: false }) lands unarmed and re-arms at a new generation; release({ final: true }) is terminal', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    const firstAcquisitionId = handle.acquisitionId;
    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed');
    assert.equal(handle.acquisitionId, null);
    await handle.arm(ARM);
    assert.equal(handle.state, 'armed');
    assert.equal(handle.generation, 2);
    assert.notEqual(handle.acquisitionId, firstAcquisitionId);
    await handle.release({ final: true });
    assert.equal(handle.state, 'released');
    const error = await rejectionOf(handle.arm(ARM));
    assert.equal(error.code, leaseStoreModule.OWNER_HANDLE_RELEASED_CODE);
    assert.deepEqual(
      (await readOwnerRecords(dataRoot)).map((record) => `${record.state}:${record.generation}`),
      ['ACQUIRED:1', 'RELEASED:1', 'ACQUIRED:2', 'RELEASED:2'],
    );
  });
});

test('finality is monotonic -- a final release joining a non-final one lands released, never unarmed', async () => {
  await withDataRoot(async (dataRoot) => {
    let renames = 0;
    const store = createLeaseStore({
      dataRoot, clock: () => T0, renameImpl: async (from, to) => { renames += 1; return rename(from, to); },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    renames = 0;
    const nonFinalRelease = handle.release({ final: false });
    const finalRelease = handle.release({ final: true });
    assert.equal(handle.state, 'releasing');
    await Promise.all([nonFinalRelease, finalRelease]);
    assert.equal(handle.state, 'released', 'the joiner raised finality, and nothing lowers it');
    assert.equal(renames, 2, 'the joiner shared the one mutate() cycle (two renames) instead of starting its own');
  });
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    await Promise.all([handle.release({ final: true }), handle.release({ final: false })]);
    assert.equal(handle.state, 'released', 'a non-final joiner cannot lower a final release');
  });
});

// The handle's state is what gates a release: a failed release lands `armed`, and the armed branch
// always starts a fresh release. So "the memo is cleared" is tidiness no test could observe; what is
// pinned here is the behaviour it serves, a retry that really retries.
test('a failed release returns the handle to armed, so a retry genuinely retries', async () => {
  await withDataRoot(async (dataRoot) => {
    let failNextRelease = false;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      // Fires just before append()'s rename of each record, so failing it for the RELEASED record
      // makes the release's own append throw (tests/openrouter-review-lease.test.mjs:1687 idiom).
      beforeAtomicRename: async (record) => {
        if (failNextRelease && record.recordType === 'processOwner' && record.state === 'RELEASED') {
          failNextRelease = false;
          throw Object.assign(new Error('simulated append failure'), { code: 'EPERM' });
        }
      },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    const { acquisitionId, generation } = handle;
    failNextRelease = true;
    await assert.rejects(handle.release(), /simulated append failure/);
    assert.equal(handle.state, 'armed', 'a failed handover must never be reported as a clean one');
    assert.equal(handle.isOwner(), true);
    assert.equal(handle.acquisitionId, acquisitionId);
    assert.equal(handle.generation, generation);
    await handle.release();
    assert.equal(handle.state, 'released');
    assert.deepEqual((await readOwnerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
  });
});

test('isOwner() reads false, and both id getters null, from the moment a release begins', async () => {
  await withDataRoot(async (dataRoot) => {
    let handle;
    let observed = null;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      // Called with the tracked owner inside the release's own transaction, just before the
      // RELEASED append. Data-root lock releases also call it, with { lockToken }; skip those.
      beforeRelease: async (argument) => {
        if (Object.hasOwn(argument, 'acquisitionId')) {
          observed = { state: handle.state, isOwner: handle.isOwner(), acquisitionId: handle.acquisitionId, generation: handle.generation };
        }
      },
    });
    handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    const pending = handle.release();
    assert.equal(handle.isOwner(), false, 'false synchronously, before any release I/O');
    assert.equal(handle.state, 'releasing');
    await pending;
    assert.deepEqual(observed, { state: 'releasing', isOwner: false, acquisitionId: null, generation: null });
  });
});

test('release() during an in-flight arm waits for it and releases what it produced', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    const arming = handle.arm(ARM);
    const releasing = handle.release({ final: true });
    await arming;
    await releasing;
    assert.equal(handle.state, 'released');
    assert.deepEqual(
      (await readOwnerRecords(dataRoot)).map((record) => record.state),
      ['ACQUIRED', 'RELEASED'],
      'an ACQUIRED record is never left without its RELEASED',
    );
  });
});

test('a final release() during an arm that fails lands released and does not rethrow the arm error', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = T0 + 5_000;
    const store = createLeaseStore({
      dataRoot,
      clock: () => now,
      monotonicNow: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
    });
    const handle = unarmedHandleOf(store);
    const arming = handle.arm(ARM);
    const releasing = handle.release({ final: true });
    const armError = await rejectionOf(arming);
    assert.equal(armError.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE, 'the arm error reaches the arm caller');
    await releasing; // resolves: the release caller does not inherit the arm's failure
    assert.equal(handle.state, 'released');
    assert.deepEqual((await readOwnerRecords(dataRoot)).map((record) => record.pid), [FOREIGN_PID], 'this process never recorded ownership');
  });
});

// The two tests above pass final: true. These pass final: false (the per-operation release shape), which
// must neither make the handle terminal nor leave the arm's ACQUIRED record without its RELEASED.
test('release({ final: false }) during an arm that succeeds releases the ACQUIRED it produced, lands unarmed, and a later arm() acquires a new generation', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => T0 });
    const handle = unarmedHandleOf(store);
    const arming = handle.arm(ARM);
    let releaseSettled = false;
    const releasing = handle.release({ final: false }).finally(() => { releaseSettled = true; });
    assert.equal(handle.state, 'arming', 'release() changed no state while the arm is in flight');
    await arming;
    // The release is still writing its RELEASED record when the arm settles. A release that returned
    // early, without waiting for the arm, would already have settled here.
    assert.equal(releaseSettled, false, 'the release waits for the arm; it does not return early');
    await releasing;
    assert.equal(handle.state, 'unarmed', 'a non-final release lands unarmed, never released');
    assert.equal(handle.isOwner(), false);
    assert.equal(handle.acquisitionId, null);
    const records = await readOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => `${record.state}:${record.generation}`), ['ACQUIRED:1', 'RELEASED:1']);
    assert.equal(records[1].acquisitionId, records[0].acquisitionId, 'the RELEASED record matches the ACQUIRED record the arm wrote');
    assert.equal(records[1].pid, process.pid);
    await handle.arm(ARM);
    assert.equal(handle.state, 'armed');
    assert.equal(handle.generation, 2);
    assert.notEqual(handle.acquisitionId, records[0].acquisitionId);
  });
});

test('release({ final: false }) during an arm that fails lands unarmed, writes nothing, and does not rethrow the arm error', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = T0 + 5_000;
    const store = createLeaseStore({
      dataRoot,
      clock: () => now,
      monotonicNow: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
    });
    const handle = unarmedHandleOf(store);
    const before = await readOwnerRecords(dataRoot);
    const arming = handle.arm(ARM);
    const releasing = handle.release({ final: false });
    const armError = await rejectionOf(arming);
    assert.equal(armError.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE, 'the arm error reaches the arm caller');
    await releasing; // resolves: the release caller does not inherit the arm's failure
    assert.equal(handle.state, 'unarmed', 'a non-final release after a failed arm leaves the handle re-armable, not released');
    assert.deepEqual(await readOwnerRecords(dataRoot), before, 'nothing written: no ACQUIRED and no RELEASED record');
  });
});

test('afterOwnerAcquired runs once the ACQUIRED record is durable and the data-root lock is released, before the acquirer resolves', async () => {
  await withDataRoot(async (dataRoot) => {
    let handle;
    let armSettled = false;
    const seen = [];
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      afterOwnerAcquired: async ({ generation, acquisitionId }) => {
        const onDisk = (await readOwnerRecords(dataRoot)).find((record) => record.acquisitionId === acquisitionId);
        seen.push({
          generation,
          durable: onDisk?.state === 'ACQUIRED' && onDisk.generation === generation,
          lockReleased: !(await pathExists(join(dataRoot, '.ledger-write.lock'))),
          handleState: handle.state,
          isOwner: handle.isOwner(),
          armSettled,
        });
      },
    });
    handle = unarmedHandleOf(store);
    await handle.arm(ARM).then(() => { armSettled = true; });
    assert.deepEqual(seen, [{ generation: 1, durable: true, lockReleased: true, handleState: 'arming', isOwner: false, armSettled: false }]);
    // The legacy acquire path runs the same seam.
    await handle.release();
    const legacy = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000 });
    assert.equal(seen.length, 2);
    assert.equal(seen[1].generation, legacy.generation);
    assert.equal(seen[1].durable, true);
    assert.equal(seen[1].lockReleased, true);
  });
});

test('an arm polling against a live holder aborts at the next check once shouldAbort flips, and writes no ACQUIRED', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = 0;
    let attempts = 0;
    let sleeps = 0;
    let abort = false;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      monotonicNow: () => now,
      sleep: async (milliseconds) => {
        sleeps += 1;
        now += milliseconds;
        if (sleeps === 2) abort = true; // shutdown begins during the second backoff sleep
      },
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      // One data-root lock release per mutate() cycle, so this counts ownership attempts.
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) attempts += 1; },
    });
    const handle = unarmedHandleOf(store);
    const error = await rejectionOf(handle.arm({ ...ARM, acquireTimeoutMs: 5_000, shouldAbort: () => abort }));
    assert.equal(error.code, leaseStoreModule.ARM_ABORTED_CODE);
    assert.equal(error.code, 'ARM_ABORTED');
    assert.equal(attempts, 2, 'no attempt may start once shouldAbort reads true');
    assert.ok(now < 5_000, 'aborted long before the budget ran out');
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual((await readOwnerRecords(dataRoot)).map((record) => record.pid), [FOREIGN_PID], 'no ACQUIRED record for this process');
    // It is checked before the FIRST attempt too, and the in-flight arm promise was cleared: a new
    // arm() is not ARM_IN_PROGRESS, and it aborts without opening a single ledger transaction.
    const again = await rejectionOf(handle.arm({ ...ARM, shouldAbort: () => true }));
    assert.equal(again.code, leaseStoreModule.ARM_ABORTED_CODE);
    assert.equal(attempts, 2);
  });
});

// The other half of the abort rule: an attempt that has already committed ACQUIRED is never aborted. If it were, the
// handle would go back to unarmed with its ACQUIRED record on disk, the coordinator would skip its
// compensating release (it releases only after arm() resolves), and nothing would ever write the
// matching RELEASED: the stuck-ownership state this design exists to prevent.
test('shouldAbort turning true while the ACQUIRED record is being committed does not abort the arm; the handle ends armed, owning the one ACQUIRED it wrote', async () => {
  await withDataRoot(async (dataRoot) => {
    let abort = false;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      // Fires inside the committing mutate(), just before the ACQUIRED record's rename: shutdown
      // begins while this attempt is already committing, so every later read of shouldAbort is true.
      beforeAtomicRename: async (record) => {
        if (record.recordType === 'processOwner' && record.state === 'ACQUIRED') abort = true;
      },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm({ ...ARM, shouldAbort: () => abort });
    assert.equal(abort, true, 'precondition: shouldAbort read true before arm() resolved');
    assert.equal(handle.state, 'armed', 'a committed acquisition is never aborted: its caller releases it');
    assert.equal(handle.isOwner(), true);
    const records = await readOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => `${record.state}:${record.pid}`), [`ACQUIRED:${process.pid}`]);
    assert.equal(records[0].acquisitionId, handle.acquisitionId, 'the handle owns the record it committed, so a release can match it');
  });
});

// This test uses the store's REAL default sleep, because the property is that production's own sleep is cut
// short. One attempt costs 8000 ms of fake monotonic time: more than a quarter of the server's 30 s
// shutdown drain, a cost a large ledger can reach (replay time grows with the number of ledger
// files). With random() = 0 the backoff then asks for a real 16 000 ms sleep.
// shouldAbort turns true 50 ms into the arm, while that sleep runs. Case (b) then gives the same arm a
// shouldAbort that starts throwing while that sleep runs.
test('a stop request during a long arming sleep ends the arm within one abort poll, and leaves no sleep timer behind; a stop check that throws there rejects the arm instead of escaping the poll', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = 0;
    let attempts = 0;
    let abort = false;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      monotonicNow: () => now,
      random: () => 0,
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      beforeRelease: async (released) => {
        if (Object.hasOwn(released, 'lockToken')) { attempts += 1; now += 8_000; }
      },
    });
    const handle = unarmedHandleOf(store);
    const timersBefore = process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    const started = Date.now();
    setTimeout(() => { abort = true; }, 50);
    const error = await rejectionOf(handle.arm({ ...ARM, acquireTimeoutMs: 90_000, shouldAbort: () => abort }));
    const elapsedMs = Date.now() - started;
    assert.equal(error.code, leaseStoreModule.ARM_ABORTED_CODE);
    assert.equal(attempts, 1, 'the stop arrived during the first backoff sleep');
    assert.ok(elapsedMs < 1_000, `the arm must stop near the 100 ms abort poll, not wait out its 16 000 ms sleep; took ${elapsedMs} ms`);
    assert.equal(handle.state, 'unarmed');
    // A sleep cut short must clear its timer. A pending one would hold the server's event loop open
    // after a clean shutdown, until exitAfterShutdown()'s fallback process.exit() fires.
    const timersAfter = process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    assert.ok(timersAfter <= timersBefore, `a sleep timer was left pending (${timersBefore} before, ${timersAfter} after)`);

    // Case (b): the stop check reads false before the attempt, then throws on every later read, the
    // first of them while the backoff sleep runs. The loop keeps that throw as a stop request, so the
    // sleep ends and the arm rejects ARM_ABORTED with the throw as its cause (the next test pins a check that
    // throws only once). Thrown from the poll's timer callback instead, it would be an uncaught
    // exception: a crash.
    const broken = new Error('the stop check itself failed');
    let reads = 0;
    const startedB = Date.now();
    const brokenError = await rejectionOf(handle.arm({
      ...ARM,
      acquireTimeoutMs: 90_000,
      shouldAbort: () => { reads += 1; if (reads > 1) throw broken; return false; },
    }));
    const elapsedB = Date.now() - startedB;
    assert.equal(brokenError.code, leaseStoreModule.ARM_ABORTED_CODE, 'a stop check that throws is a stop request');
    assert.equal(brokenError.cause, broken, 'the abort carries the error the stop check threw as its cause');
    assert.equal(attempts, 2, 'one more attempt, then the throw arrived during its backoff sleep');
    assert.ok(elapsedB < 3_000, `a throwing stop check must end the sleep, not wait it out; took ${elapsedB} ms`);
    assert.equal(handle.state, 'unarmed');
    const timersAfterB = process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    assert.ok(timersAfterB <= timersBefore, `case (b) left a timer pending (${timersBefore} before, ${timersAfterB} after)`);
  });
});

// A stop check that throws ONCE is still a stop request. The loop keeps the first throw, so
// the arm rejects ARM_ABORTED with that throw as its cause even when every later read of the check
// returns false. Case (a): the throw comes at the check before the first attempt. Case (b): it comes
// in a backoff sleep's poll, where a throw the loop did not keep would be lost: the check at the top
// of the loop would read false again and the arm would carry on. At the moment of that throw the
// holder dies and its record is already stale, so an arm that lost the throw would reclaim on its
// very next attempt.
test('a stop check that throws only once is kept as a stop request -- the arm rejects ARM_ABORTED with that throw as its cause, before an attempt and during a sleep, although every later read returns false', async () => {
  // (a) The throw comes at the check before the first attempt.
  await withDataRoot(async (dataRoot) => {
    let attempts = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0,
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) attempts += 1; },
    });
    const handle = unarmedHandleOf(store);
    const once = new Error('the stop check failed once, before the first attempt');
    let reads = 0;
    const error = await rejectionOf(handle.arm({
      ...ARM,
      shouldAbort: () => { reads += 1; if (reads === 1) throw once; return false; },
    }));
    assert.equal(error.code, leaseStoreModule.ARM_ABORTED_CODE, 'a stop check that throws is a stop request');
    assert.equal(error.cause, once, 'the abort carries the throw as its cause');
    assert.equal(attempts, 0, 'no attempt started');
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual(await readOwnerRecords(dataRoot), [], 'nothing written');
  });

  // (b) The throw comes in the first poll of a real backoff sleep (one attempt costs 8000 ms of fake
  // monotonic time; with random() = 0 the sleep is 16 000 ms), and every later read returns false.
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = 0;
    let wallClockMs = T0 + 5_000;
    let holderAlive = true;
    let attempts = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => wallClockMs,
      monotonicNow: () => now,
      random: () => 0,
      isProcessAlive: (pid) => (pid === FOREIGN_PID ? holderAlive : true),
      processStartTimeMs: async () => null,
      beforeRelease: async (released) => {
        if (Object.hasOwn(released, 'lockToken')) { attempts += 1; now += 8_000; }
      },
    });
    const handle = unarmedHandleOf(store);
    const once = new Error('the stop check failed once, during a sleep');
    let reads = 0;
    const started = Date.now();
    const error = await rejectionOf(handle.arm({
      ...ARM,
      acquireTimeoutMs: 90_000,
      shouldAbort: () => {
        reads += 1;
        if (reads !== 2) return false;
        // Read 1 is the check before the first attempt; read 2 is the sleep's first poll. The holder
        // dies here, past the 60 s stale age, so the next attempt, if any, would reclaim.
        holderAlive = false;
        wallClockMs = T0 + 120_000;
        throw once;
      },
    }));
    const elapsedMs = Date.now() - started;
    assert.equal(error.code, leaseStoreModule.ARM_ABORTED_CODE, 'the one throw must stop the arm, not be lost to the next read');
    assert.equal(error.cause, once, 'the abort carries the throw as its cause');
    assert.equal(attempts, 1, 'no attempt after the throw');
    assert.equal(reads, 2, 'a kept throw is not read again: the arm is already stopping');
    assert.ok(elapsedMs < 3_000, `the throw must end the sleep, not wait it out; took ${elapsedMs} ms`);
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual((await readOwnerRecords(dataRoot)).map((record) => record.pid), [FOREIGN_PID], 'no ACQUIRED record for this process');
  });
});

// Shared by the lock-share and jitter tests below: a live foreign holder that never goes away, so every arm
// attempt is refused (LIVE_OWNER) until the budget ends, in fake time where each attempt costs
// exactly `attemptCostMs`. The cost is charged in beforeRelease's data-root-lock call
// ({ lockToken }), which runs inside every mutate() cycle, so it is time the global write lock is
// really held.
async function armAgainstLiveHolder(dataRoot, { attemptCostMs, budgetMs, random }) {
  await seedOwnerRecord(dataRoot, { timestampMs: T0 });
  const timeline = { now: 0, lockHeldMs: 0, sleeps: [] };
  const store = createLeaseStore({
    dataRoot,
    clock: () => T0 + 5_000,
    monotonicNow: () => timeline.now,
    sleep: async (milliseconds) => { timeline.sleeps.push(milliseconds); timeline.now += milliseconds; },
    isProcessAlive: () => true,
    processStartTimeMs: async () => null,
    random,
    beforeRelease: async (released) => {
      if (Object.hasOwn(released, 'lockToken')) {
        timeline.now += attemptCostMs;
        timeline.lockHeldMs += attemptCostMs;
      }
    },
  });
  const handle = unarmedHandleOf(store);
  const error = await rejectionOf(handle.arm({ ...ARM, acquireTimeoutMs: budgetMs }));
  assert.equal(error.reason, 'LIVE_OWNER');
  return timeline;
}

test('the arming loop holds the global write lock for at most about one third of its budget, whatever one attempt costs', async () => {
  // random() = 0 draws the SHORTEST possible sleep: the worst case for lock share.
  for (const attemptCostMs of [10, 100, 700]) {
    await withDataRoot(async (dataRoot) => {
      const timeline = await armAgainstLiveHolder(dataRoot, { attemptCostMs, budgetMs: 30_000, random: () => 0 });
      // Every sleep but the last (the deadline may cut that one short) is at least twice the
      // attempt before it, so each attempt-plus-sleep cycle holds the lock at most a third of its time.
      for (const milliseconds of timeline.sleeps.slice(0, -1)) {
        assert.ok(milliseconds >= 2 * attemptCostMs, `a ${attemptCostMs} ms attempt was followed by only a ${milliseconds} ms sleep`);
      }
      // Over the whole budget the same bound holds, up to the one final attempt that has no sleep
      // after it (n attempts, n - 1 sleeps).
      assert.ok(
        timeline.lockHeldMs * 3 <= timeline.now + 2 * attemptCostMs,
        `attempts of ${attemptCostMs} ms: the loop held the lock ${timeline.lockHeldMs} ms of ${timeline.now} ms`,
      );
    });
  }
});

// The lock-contention backoff test's harness: every arm attempt loses the data-root write lock, so every refusal takes the
// LEDGER_DATA_ROOT_LOCKED catch path instead of a LIVE_OWNER refusal. The lock is planted as held by
// THIS process with a timestamp that never ages (the clock is fixed), so it is never reclaimable, and
// lockTimeoutMs: 0 makes each mutate() give up after one publish try. That try is charged the next
// entry of `attemptCostsMs` in fake time, inside renameImpl's publish onto the lock path: the one
// call every attempt makes. shouldAbort() records how many sleeps had happened each time it was
// read, and reads true once `abortAtSleep` sleeps are done.
async function armAgainstBusyLedger(dataRoot, { attemptCostsMs, budgetMs, abortAtSleep = Number.POSITIVE_INFINITY }) {
  await plantDataRootLock(dataRoot, { lockedAtMs: T0, pid: process.pid });
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  const timeline = { now: 0, attempts: 0, sleeps: [], abortChecksAtSleep: [] };
  const store = createLeaseStore({
    dataRoot,
    clock: () => T0,
    lockTimeoutMs: 0,
    monotonicNow: () => timeline.now,
    sleep: async (milliseconds) => { timeline.sleeps.push(milliseconds); timeline.now += milliseconds; },
    // 0 draws the shortest sleep, half the base, so every expected sleep below is exact.
    random: () => 0,
    renameImpl: async (from, to) => {
      if (to === lockRoot) {
        timeline.now += attemptCostsMs[timeline.attempts % attemptCostsMs.length];
        timeline.attempts += 1;
      }
      return rename(from, to);
    },
  });
  const handle = unarmedHandleOf(store);
  const shouldAbort = () => {
    timeline.abortChecksAtSleep.push(timeline.sleeps.length);
    return timeline.sleeps.length >= abortAtSleep;
  };
  const error = await rejectionOf(handle.arm({ ...ARM, acquireTimeoutMs: budgetMs, shouldAbort }));
  return { timeline, error, handle };
}

test('the adaptive backoff also governs the LEDGER_DATA_ROOT_LOCKED catch path -- sized from each failed attempt, clipped to the deadline, abortable after every sleep, timing out as DATA_ROOT_LOCKED', async () => {
  // No abort: attempts cost 100, 300, 50 and 100 ms. With lockRetryMs 250 and random() = 0 each
  // sleep is half of max(250, 4 x cost): 200, then 600, then 125 (the lockRetryMs floor wins), then
  // 200 cut to the 25 ms left of the 1500 ms budget. Attempts end at 100, 600, 1250 and 1475.
  await withDataRoot(async (dataRoot) => {
    const { timeline, error, handle } = await armAgainstBusyLedger(dataRoot, { attemptCostsMs: [100, 300, 50, 100], budgetMs: 1_500 });
    assert.equal(error.message, 'arm timed out after 1500ms (DATA_ROOT_LOCKED)');
    assert.deepEqual(timeline.sleeps, [200, 600, 125, 25], 'each sleep is sized from the attempt before it, and the last is clipped to the deadline');
    assert.equal(timeline.attempts, 4);
    assert.equal(timeline.now, 1_500, 'the timeout arrives exactly at the budget, never past it');
    assert.equal(error.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE);
    assert.equal(error.reason, 'DATA_ROOT_LOCKED');
    assert.equal(Object.hasOwn(error, 'owner'), false, 'a DATA_ROOT_LOCKED error names no holder');
    assert.deepEqual(timeline.abortChecksAtSleep, [0, 1, 2, 3, 4], 'shouldAbort is read before the first attempt and after every sleep');
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual(await readOwnerRecords(dataRoot), [], 'nothing written');
  });
  // Abort: shouldAbort reads true once the second lock-contention sleep is done, so no third attempt starts.
  await withDataRoot(async (dataRoot) => {
    const { timeline, error, handle } = await armAgainstBusyLedger(dataRoot, { attemptCostsMs: [100, 300], budgetMs: 30_000, abortAtSleep: 2 });
    assert.equal(error.code, leaseStoreModule.ARM_ABORTED_CODE);
    assert.deepEqual(timeline.sleeps, [200, 600], 'both sleeps sized from the attempt before them');
    assert.equal(timeline.attempts, 2, 'no attempt starts once shouldAbort reads true after a lock-contention sleep');
    assert.deepEqual(timeline.abortChecksAtSleep, [0, 1, 2]);
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual(await readOwnerRecords(dataRoot), [], 'nothing written');
  });
});

test('every arming sleep is an equal-jittered draw in [floor(base/2), base], and different draws give different sleeps', async () => {
  await withDataRoot(async (dataRoot) => {
    const draws = [0, 0.5, 1, 0.25];
    let drawIndex = 0;
    // Each attempt costs 100 ms, so base = max(250, 4 x 100) = 400 and half = 200. Attempts end at
    // 100, 400, 800 and 1300; the fourth sleep lands exactly on the 1550 ms deadline, so none of the
    // four sleeps is cut short and every draw shows through.
    const timeline = await armAgainstLiveHolder(dataRoot, {
      attemptCostMs: 100,
      budgetMs: 1_550,
      random: () => draws[drawIndex++ % draws.length],
    });
    // 0 gives half; 0.5 gives 200 + floor(0.5 x 201) = 300; 1 is out of range and clamps to base;
    // 0.25 gives 200 + floor(0.25 x 201) = 250.
    assert.deepEqual(timeline.sleeps, [200, 300, 400, 250]);
    for (const milliseconds of timeline.sleeps) assert.ok(milliseconds >= 200 && milliseconds <= 400);
    assert.equal(new Set(timeline.sleeps).size, 4, 'different draws must give different sleeps');
  });
});

test('acquireProcessOwnership() keeps its fixed lockRetryMs sleep and never draws from random', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedOwnerRecord(dataRoot, { timestampMs: T0 });
    let now = 0;
    const sleeps = [];
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      lockRetryMs: 10,
      monotonicNow: () => now,
      sleep: async (milliseconds) => { sleeps.push(milliseconds); now += milliseconds; },
      isProcessAlive: () => true,
      processStartTimeMs: async () => null,
      random: () => assert.fail('acquireProcessOwnership() must never draw from random'),
      // Attempts costing 100 ms would widen an ADAPTIVE sleep; the legacy path must not adapt.
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) now += 100; },
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 500 }), /\(LIVE_OWNER\)$/);
    assert.ok(sleeps.length > 0);
    assert.deepEqual([...new Set(sleeps)], [10], 'always exactly lockRetryMs, however long an attempt took');
  });
});

// A predecessor processOwner record with caps, optionally followed by its own clean RELEASED record.
async function seedCapsHolder(dataRoot, { caps, released = false, timestampMs = T0, pid = FOREIGN_PID }) {
  const holder = await seedOwnerRecord(dataRoot, { pid, timestampMs, extra: caps === undefined ? {} : { caps } });
  if (released) {
    await seedOwnerRecord(dataRoot, { state: 'RELEASED', pid, acquisitionId: holder.acquisitionId, timestampMs: timestampMs + 1 });
  }
  return holder;
}

// The most recent processOwner record on disk: the one an arm just appended, when it succeeded.
async function lastOwnerRecord(dataRoot) {
  return (await readOwnerRecords(dataRoot)).at(-1);
}

test('OWNERSHIP_CAP_MISMATCH_CODE is exported with its literal value', () => {
  assert.equal(leaseStoreModule.OWNERSHIP_CAP_MISMATCH_CODE, 'OWNERSHIP_CAP_MISMATCH');
});

test('a latest ACQUIRED record with no caps is bootstrap-compatible, even from a live process; the arm stamps both caps, the allowance from the store itself', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: undefined, released: true });
    let probes = 0;
    let transactions = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      dailyPaidJobAllowance: 7,
      isProcessAlive: () => true,
      processStartTimeMs: async () => { probes += 1; return T0 - 60_000; },
      // One data-root lock release per mutate() transaction.
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) transactions += 1; },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm(ARM);
    assert.equal(handle.generation, 2);
    const stamped = await lastOwnerRecord(dataRoot);
    assert.equal(stamped.state, 'ACQUIRED');
    // installationHardMaximumUsd is the caller's; dailyPaidJobAllowance is THIS store's own option.
    assert.deepEqual(stamped.caps, { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 7 });
    assert.equal(probes, 0, 'a compatible record never needs the start-time probe');
    // The structural half of "transactional": a check in a mutate() of its own, before the
    // acquiring one, would make this 2, and would reopen check-then-acquire between the two.
    assert.equal(transactions, 1, 'the cap check and the ACQUIRED append share ONE mutate() transaction');
  });
});

test('a recorded null member is absent, not a mismatch, while a present member still counts', async () => {
  // Compatible: installationHardMaximumUsd is null (absent) and dailyPaidJobAllowance matches.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: null, dailyPaidJobAllowance: 7 }, released: true });
    const store = createLeaseStore({
      dataRoot, clock: () => T0 + 5_000, dailyPaidJobAllowance: 7,
      isProcessAlive: () => true, processStartTimeMs: async () => T0 - 60_000,
    });
    const handle = unarmedHandleOf(store);
    await handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 } });
    assert.deepEqual((await lastOwnerRecord(dataRoot)).caps, { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 7 });
  });
  // Refused on the one member present on both sides; the absent member is not reported as recorded.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: null, dailyPaidJobAllowance: 30 }, released: true });
    const store = createLeaseStore({
      dataRoot, clock: () => T0 + 5_000, dailyPaidJobAllowance: 7,
      isProcessAlive: () => true, processStartTimeMs: async () => T0 - 60_000,
    });
    const handle = unarmedHandleOf(store);
    const error = await rejectionOf(handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 } }));
    assert.equal(error.code, leaseStoreModule.OWNERSHIP_CAP_MISMATCH_CODE);
    assert.deepEqual(error.recorded, { dailyPaidJobAllowance: 30 });
    assert.deepEqual(error.resolved, { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 7 });
  });
});

test('a malformed caps member on an ACQUIRED record fails replay closed; absent and null stay valid', async () => {
  const malformed = [
    (record) => JSON.stringify({ ...record, caps: { installationHardMaximumUsd: 'five' } }),
    (record) => JSON.stringify({ ...record, caps: { installationHardMaximumUsd: -1 } }),
    (record) => JSON.stringify({ ...record, caps: { dailyPaidJobAllowance: true } }),
    (record) => JSON.stringify({ ...record, caps: 'five' }),
    (record) => JSON.stringify({ ...record, caps: [5, 20] }),
    // JSON.stringify cannot write Infinity, but a literal 1e999 in the raw text parses to it.
    (record) => JSON.stringify({ ...record, caps: { installationHardMaximumUsd: 0 } })
      .replace('"installationHardMaximumUsd":0', '"installationHardMaximumUsd":1e999'),
  ];
  for (const rawJson of malformed) {
    await withDataRoot(async (dataRoot) => {
      await seedOwnerRecord(dataRoot, { rawJson });
      const store = createLeaseStore({ dataRoot, clock: () => T0 + 5_000 });
      await assert.rejects(store.getLease('force-a-replay'), /processOwner ACQUIRED record has invalid caps/);
    });
  }
  for (const extra of [{}, { caps: null }, { caps: { installationHardMaximumUsd: null, dailyPaidJobAllowance: null } }]) {
    await withDataRoot(async (dataRoot) => {
      await seedOwnerRecord(dataRoot, { extra });
      const store = createLeaseStore({ dataRoot, clock: () => T0 + 5_000 });
      assert.equal(await store.getLease('force-a-replay'), null);
    });
  }
});

test('a resolved -0 compares equal to a recorded 0, and a recorded -0 to a resolved 0; the store\'s own allowance can never be -0', async () => {
  // A live predecessor that released cleanly recorded 0; this arm resolves -0.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: 0, dailyPaidJobAllowance: 20 }, released: true });
    const store = createLeaseStore({
      dataRoot, clock: () => T0 + 5_000, isProcessAlive: () => true, processStartTimeMs: async () => T0 - 60_000,
    });
    const handle = unarmedHandleOf(store);
    await handle.arm({ ...ARM, caps: { installationHardMaximumUsd: -0 } });
    // generation 2 is the pin: the comparison accepted -0 against the recorded 0. The stamped value
    // cannot show a -0 either way, because JSON.stringify writes -0 as 0.
    assert.equal(handle.generation, 2);
    const stamped = await lastOwnerRecord(dataRoot);
    assert.equal(typeof stamped.caps, 'object', 'the arm must stamp caps');
    assert.deepEqual(stamped.caps, { installationHardMaximumUsd: 0, dailyPaidJobAllowance: 20 });
  });
  // The mirror image: a hand-edited ledger carrying a literal -0, which JSON.parse keeps as -0.
  await withDataRoot(async (dataRoot) => {
    const holder = await seedOwnerRecord(dataRoot, {
      extra: { caps: { installationHardMaximumUsd: 0, dailyPaidJobAllowance: 20 } },
      rawJson: (record) => JSON.stringify(record).replace('"installationHardMaximumUsd":0', '"installationHardMaximumUsd":-0'),
    });
    await seedOwnerRecord(dataRoot, { state: 'RELEASED', acquisitionId: holder.acquisitionId, timestampMs: T0 + 1 });
    const store = createLeaseStore({
      dataRoot, clock: () => T0 + 5_000, isProcessAlive: () => true, processStartTimeMs: async () => T0 - 60_000,
    });
    const handle = unarmedHandleOf(store);
    await handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 0 } });
    assert.equal(handle.generation, 2);
    assert.equal(typeof (await lastOwnerRecord(dataRoot)).caps, 'object', 'the arm must stamp caps');
  });
  // The other stamped member is the store's own dailyPaidJobAllowance. It needs no -0 normalizing,
  // because the store refuses -0 at construction (-0 <= 0), so the resolved side can never be -0.
  assert.throws(
    () => createLeaseStore({ dataRoot: 'unused', dailyPaidJobAllowance: -0 }),
    /dailyPaidJobAllowance must be a positive safe integer/,
  );
});

test('a live sibling with different caps refuses the arm at once -- one attempt, one probe, one attempt -- even after it released', async () => {
  const cases = [
    { name: 'unreleased sibling, installation cap differs', released: false, storeAllowance: 20, armCap: 10,
      recorded: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, resolved: { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 },
      named: 'installationHardMaximumUsd recorded 5, resolved 10' },
    { name: 'sibling that released cleanly: the comparison still targets its ACQUIRED record', released: true, storeAllowance: 20, armCap: 10,
      recorded: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, resolved: { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 },
      named: 'installationHardMaximumUsd recorded 5, resolved 10' },
    { name: 'the daily allowance differs: it is this store\'s own option', released: false, storeAllowance: 30, armCap: 5,
      recorded: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, resolved: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 30 },
      named: 'dailyPaidJobAllowance recorded 20, resolved 30' },
  ];
  for (const scenario of cases) {
    await withDataRoot(async (dataRoot) => {
      await seedCapsHolder(dataRoot, { caps: scenario.recorded, released: scenario.released });
      const before = await readOwnerRecords(dataRoot);
      let now = T0 + 5_000;
      let attempts = 0;
      let probes = 0;
      const sleeps = [];
      const store = createLeaseStore({
        dataRoot,
        clock: () => now,
        monotonicNow: () => now,
        sleep: async (milliseconds) => { sleeps.push(milliseconds); now += milliseconds; },
        dailyPaidJobAllowance: scenario.storeAllowance,
        isProcessAlive: () => true,
        // Started a minute before its own record: a genuine owner, so the probe proves nothing.
        processStartTimeMs: async () => { probes += 1; return T0 - 60_000; },
        beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) attempts += 1; },
      });
      const handle = unarmedHandleOf(store);
      const error = await rejectionOf(handle.arm({ ...ARM, caps: { installationHardMaximumUsd: scenario.armCap } }));
      assert.equal(error.code, leaseStoreModule.OWNERSHIP_CAP_MISMATCH_CODE, scenario.name);
      assert.deepEqual(error.recorded, scenario.recorded, scenario.name);
      assert.deepEqual(error.resolved, scenario.resolved, scenario.name);
      assert.ok(error.message.includes(scenario.named), `${scenario.name}: ${error.message}`);
      assert.ok(error.message.includes(`pid ${FOREIGN_PID}`), scenario.name);
      assert.equal(error.message.includes('$'), false, 'no currency sign in the message');
      assert.equal(attempts, 2, `${scenario.name}: one attempt, the probe, one attempt -- never a poll`);
      assert.equal(probes, 1, scenario.name);
      assert.deepEqual(sleeps, [], `${scenario.name}: no backoff sleep at all`);
      assert.equal(handle.state, 'unarmed');
      assert.deepEqual(await readOwnerRecords(dataRoot), before, `${scenario.name}: nothing appended`);
    });
  }
});

test('a recorded pid that Windows recycled heals through the start-time probe, and the arm stamps its own caps; inside the skew margin it cannot be told apart and is refused', async () => {
  await withDataRoot(async (dataRoot) => {
    // Real-clock timestamps: ownerIsSupersededPid() compares durations on the real clock, so a
    // recycled pid is provable only against a record that is really two hours old.
    const recordedAt = Date.now() - (2 * 3_600_000);
    await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, timestampMs: recordedAt });
    let probes = 0;
    let transactions = 0;
    const sleeps = [];
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      sleep: async (milliseconds) => { sleeps.push(milliseconds); },
      isProcessAlive: () => true,
      // The process now holding that pid started ten minutes ago, long after the record was written.
      processStartTimeMs: async () => { probes += 1; return Date.now() - (10 * 60_000); },
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) transactions += 1; },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 } });
    assert.equal(handle.generation, 2);
    assert.deepEqual((await lastOwnerRecord(dataRoot)).caps, { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 });
    assert.equal(probes, 1, 'exactly one probe, run outside the lock');
    assert.equal(transactions, 2, 'the refusal, then the re-check and the ACQUIRED append together in ONE mutate()');
    assert.deepEqual(sleeps, [], 'a superseded verdict is retried at once, with no backoff sleep');
  });
  // A known limit of the start-time probe. The probe proves a pid recycled only when its process started more than
  // OWNER_START_TIME_SKEW_MARGIN_MS (five minutes) after the record, because a genuine owner's record
  // can lag its start by clock skew. Here the record is three minutes old and the pid's new process
  // started one minute ago, two minutes after it: the probe cannot tell that apart from the genuine
  // owner, so the arm is refused, and keeps being refused for as long as that process lives (the gap
  // between start and record never changes). It fails closed; aligning the caps is the way out.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, {
      caps: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, released: true, timestampMs: Date.now() - (3 * 60_000),
    });
    let probes = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      isProcessAlive: () => true,
      processStartTimeMs: async () => { probes += 1; return Date.now() - 60_000; },
    });
    const handle = unarmedHandleOf(store);
    const error = await rejectionOf(handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 } }));
    assert.equal(error.code, leaseStoreModule.OWNERSHIP_CAP_MISMATCH_CODE);
    assert.ok(error.message.includes(`pid ${FOREIGN_PID}`), error.message);
    assert.equal(probes, 1);
  });
});

// The start-time probe is a real PowerShell spawn (hundreds of milliseconds, longer under load) that
// runs outside the lock, so it can cross the arm's deadline. The attempt that acts on its verdict still
// runs (the follow-up attempt), so the arm ends on an in-lock answer. Each case gives a 1000 ms budget and a
// probe that costs 2000 ms of fake time. Without the follow-up rule every case times out with no
// reason and no holder, which the coordinator would report as a busy ledger.
test('a cap probe that crosses the arm deadline still gets its follow-up attempt, so the arm never times out without a real reason', async () => {
  const armWithASlowProbe = async (dataRoot, { alive, startedMs, clock, onProbe = () => {} }) => {
    const timeline = { monotonic: 0, attempts: 0, probes: 0, sleeps: [] };
    const store = createLeaseStore({
      dataRoot,
      clock,
      monotonicNow: () => timeline.monotonic,
      sleep: async (milliseconds) => { timeline.sleeps.push(milliseconds); timeline.monotonic += milliseconds; },
      isProcessAlive: (pid) => (pid === FOREIGN_PID ? alive() : true),
      processStartTimeMs: async () => { timeline.probes += 1; timeline.monotonic += 2_000; onProbe(); return startedMs(); },
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) timeline.attempts += 1; },
    });
    const handle = unarmedHandleOf(store);
    const outcome = await handle.arm({ ...ARM, acquireTimeoutMs: 1_000, caps: { installationHardMaximumUsd: 10 } })
      .then(() => 'armed', (error) => error);
    return { outcome, handle, timeline };
  };
  const probeCrossedTheDeadline = (timeline) => {
    assert.ok(timeline.monotonic > 1_000, 'precondition: the probe really did cross the deadline');
    assert.equal(timeline.probes, 1);
    assert.equal(timeline.attempts, 2, 'one attempt, the probe, and the follow-up attempt');
    assert.deepEqual(timeline.sleeps, [], 'no backoff sleep anywhere');
  };
  const recorded = { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 };

  // (a) A genuine live sibling: the follow-up throws the terminal mismatch it would have thrown in time.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: recorded });
    const { outcome, handle, timeline } = await armWithASlowProbe(dataRoot, {
      alive: () => true, startedMs: () => T0 - 60_000, clock: () => T0 + 5_000,
    });
    assert.equal(outcome.code, leaseStoreModule.OWNERSHIP_CAP_MISMATCH_CODE, `expected the probe's verdict, got: ${outcome.message} (reason ${outcome.reason})`);
    assert.ok(outcome.message.includes(`pid ${FOREIGN_PID}`));
    assert.equal(handle.state, 'unarmed');
    probeCrossedTheDeadline(timeline);
  });

  // (b) The sibling exits during the probe: the follow-up is refused NOT_YET_STALE, and the timeout
  // carries that real reason and holder, never an undefined reason or 'CAP_MISMATCH_UNPROBED'.
  await withDataRoot(async (dataRoot) => {
    const holder = await seedCapsHolder(dataRoot, { caps: recorded });
    let holderAlive = true;
    const { outcome, timeline } = await armWithASlowProbe(dataRoot, {
      alive: () => holderAlive, startedMs: () => T0 - 60_000, clock: () => T0 + 5_000, onProbe: () => { holderAlive = false; },
    });
    assert.equal(outcome.message, 'arm timed out after 1000ms (NOT_YET_STALE)');
    assert.equal(outcome.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE);
    assert.equal(outcome.reason, 'NOT_YET_STALE');
    assert.deepEqual(outcome.owner, { pid: FOREIGN_PID, generation: 1, timestamp: holder.timestamp });
    probeCrossedTheDeadline(timeline);
  });

  // (c) A recycled pid (real-clock timestamps, as in the recycled-pid test above): the follow-up acquires and stamps, past
  // the budget. An arm may therefore resolve up to one probe plus one attempt after its deadline.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: recorded, released: true, timestampMs: Date.now() - (2 * 3_600_000) });
    const { outcome, handle, timeline } = await armWithASlowProbe(dataRoot, {
      alive: () => true, startedMs: () => Date.now() - (10 * 60_000), clock: () => Date.now(),
    });
    assert.equal(outcome, 'armed', `expected the follow-up to acquire, got: ${outcome.message}`);
    assert.equal(handle.generation, 2);
    assert.deepEqual((await lastOwnerRecord(dataRoot)).caps, { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 });
    probeCrossedTheDeadline(timeline);
  });
});

test('a deadline-crossing cap probe whose follow-up loses the data-root lock times out as DATA_ROOT_LOCKED with no stale holder', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, {
      caps: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 },
    });
    let monotonic = 0;
    let probes = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      monotonicNow: () => monotonic,
      lockTimeoutMs: 30,
      lockRetryMs: 5,
      sleep: async (milliseconds) => {
        monotonic += milliseconds;
        await realSleep(Math.min(milliseconds, 1));
      },
      isProcessAlive: () => true,
      processStartTimeMs: async () => {
        probes += 1;
        monotonic += 2_000;
        await plantDataRootLock(dataRoot, { lockedAtMs: T0 + 5_000 });
        return T0 - 60_000;
      },
    });
    const handle = unarmedHandleOf(store);
    const error = await rejectionOf(handle.arm({
      ...ARM,
      acquireTimeoutMs: 1_000,
      caps: { installationHardMaximumUsd: 10 },
    }));
    assert.equal(probes, 1);
    assert.equal(error.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE);
    assert.equal(error.reason, 'DATA_ROOT_LOCKED');
    assert.equal(Object.hasOwn(error, 'owner'), false);
    assert.equal(Object.hasOwn(error, 'ownerAgeMs'), false);
    assert.equal(handle.state, 'unarmed');
  });
});

test('owner churn after one post-deadline cap probe returns retryable LIVE_OWNER without probing the successor', async () => {
  await withDataRoot(async (dataRoot) => {
    const recorded = { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 };
    const first = await seedCapsHolder(dataRoot, { caps: recorded });
    const successorPid = FOREIGN_PID + 1;
    let successor;
    let monotonic = 0;
    let probes = 0;
    let attempts = 0;
    const sleeps = [];
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      monotonicNow: () => monotonic,
      sleep: async (milliseconds) => { sleeps.push(milliseconds); monotonic += milliseconds; },
      isProcessAlive: () => true,
      processStartTimeMs: async () => {
        probes += 1;
        if (probes > 1) throw new Error('a second post-deadline cap probe is forbidden');
        monotonic += 2_000;
        await seedOwnerRecord(dataRoot, {
          state: 'RELEASED', pid: first.pid, generation: first.generation,
          acquisitionId: first.acquisitionId, timestampMs: T0 + 1,
        });
        successor = await seedOwnerRecord(dataRoot, {
          pid: successorPid, generation: 2, timestampMs: T0 + 2, extra: { caps: recorded },
        });
        return T0 - 60_000;
      },
      beforeRelease: async (released) => {
        if (Object.hasOwn(released, 'lockToken')) attempts += 1;
      },
    });
    const handle = unarmedHandleOf(store);
    const error = await rejectionOf(handle.arm({
      ...ARM,
      acquireTimeoutMs: 1_000,
      caps: { installationHardMaximumUsd: 10 },
    }));
    assert.equal(error.code, leaseStoreModule.PROCESS_OWNERSHIP_UNAVAILABLE_CODE);
    assert.equal(error.reason, 'LIVE_OWNER');
    assert.ok(successor, 'the first cap probe must install the successor used by the follow-up');
    assert.deepEqual(error.owner, {
      pid: successorPid,
      generation: 2,
      timestamp: successor.timestamp,
    });
    assert.equal(Object.hasOwn(error.owner, 'acquisitionId'), false);
    assert.equal(attempts, 2, 'one cap refusal, one post-probe follow-up, then stop');
    assert.equal(probes, 1, 'the successor is reported retryably without another post-deadline probe');
    assert.deepEqual(sleeps, []);
    assert.equal(handle.state, 'unarmed');
    assert.equal((await readOwnerRecords(dataRoot)).length, 3, 'the caller appended no ownership record');
  });
});

test('a cap change after a dead predecessor is an ordinary operator change: the arm reclaims and stamps the new caps', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 } });
    let probes = 0;
    let transactions = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 120_000, // past the 60 s lockStaleMs, so the dead holder is reclaimable
      isProcessAlive: () => false,
      processStartTimeMs: async () => { probes += 1; return null; },
      beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) transactions += 1; },
    });
    const handle = unarmedHandleOf(store);
    await handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 } });
    assert.equal(handle.generation, 2);
    assert.deepEqual((await lastOwnerRecord(dataRoot)).caps, { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 });
    assert.equal(probes, 0, 'a dead predecessor never needs the probe');
    assert.equal(transactions, 1, 'the cap check, the stale reclaim and the ACQUIRED append share ONE mutate() transaction');
  });
});

// This test is the behavioral half of "transactional": the check re-runs on every attempt. The structural
// half, that it shares the acquiring mutate(), is the transaction count in the bootstrap, recycled-pid and
// dead-predecessor tests above: this test's interleave happens during a backoff sleep, so it cannot see a check split into its own mutate().
test('the cap check re-validates on every attempt -- a waiter checks again against a record written while it waited', async () => {
  await withDataRoot(async (dataRoot) => {
    // P: a live foreign predecessor with no caps, so any arm validates against it as compatible.
    await seedCapsHolder(dataRoot, { caps: undefined });
    let now = T0 + 1_000;
    let predecessorAlive = true;
    let interleaved = false;
    let probes = 0;
    const shared = {
      dataRoot,
      clock: () => now,
      monotonicNow: () => now,
      isProcessAlive: (pid) => (pid === FOREIGN_PID ? predecessorAlive : true),
      processStartTimeMs: async () => { probes += 1; return null; },
    };
    const storeA = createLeaseStore({ ...shared, sleep: async (milliseconds) => { now += milliseconds; } });
    const handleA = unarmedHandleOf(storeA);
    const storeB = createLeaseStore({
      ...shared,
      sleep: async (milliseconds) => {
        if (!interleaved) {
          interleaved = true;
          // While B waits out P, P dies and goes stale, and A -- a DIFFERENT cap configuration in
          // this same live process -- reclaims, stamps its caps and releases cleanly.
          predecessorAlive = false;
          now += 120_000;
          await handleA.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 } });
          await handleA.release();
        }
        now += milliseconds;
      },
    });
    const handleB = unarmedHandleOf(storeB);
    const error = await rejectionOf(handleB.arm({ ...ARM, acquireTimeoutMs: 600_000, caps: { installationHardMaximumUsd: 5 } }));
    assert.equal(interleaved, true, 'B must have validated against P first, then waited');
    assert.equal(error.code, leaseStoreModule.OWNERSHIP_CAP_MISMATCH_CODE);
    assert.deepEqual(error.recorded, { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 });
    assert.deepEqual(error.resolved, { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 });
    assert.equal(probes, 1, 'the live recording pid (this process) was probed once and found genuine');
    assert.deepEqual(
      (await readOwnerRecords(dataRoot)).map((record) => `${record.state}:${record.generation}`),
      ['ACQUIRED:1', 'ACQUIRED:2', 'RELEASED:2'],
      'B never acquired on its stale validation',
    );
  });
});

test('acquireProcessOwnership() neither checks nor stamps caps', async () => {
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, released: true });
    let probes = 0;
    // A live sibling with different caps: arm() would refuse here; the legacy path must not.
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      dailyPaidJobAllowance: 30,
      isProcessAlive: () => true,
      processStartTimeMs: async () => { probes += 1; return T0 - 60_000; },
    });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000 });
    assert.equal(handle.generation, 2);
    const written = await lastOwnerRecord(dataRoot);
    assert.equal(written.state, 'ACQUIRED');
    assert.equal(Object.hasOwn(written, 'caps'), false, 'the legacy path stamps nothing');
    assert.equal(probes, 0);
  });
});

// Adversarial: arm() validates only caps.installationHardMaximumUsd, and nothing else the
// caller puts in `caps` reaches the ledger or the comparison. A caller that also hands in a
// dailyPaidJobAllowance, or any other member, changes nothing: the arm stamps and compares THIS
// store's own allowance, the value consume() enforces. The caller's allowance is chosen to disagree
// with the store's in every case, in the direction that would flip the outcome if it were used.
test('arm() ignores a caller-supplied dailyPaidJobAllowance and any extra caps member -- it stamps and compares the store\'s own allowance', async () => {
  const callerCaps = { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 99, extraMember: 3 };
  const recorded = { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 };
  const armWith = async (dataRoot, { storeAllowance, caps }) => {
    let probes = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => T0 + 5_000,
      dailyPaidJobAllowance: storeAllowance,
      isProcessAlive: () => true,
      // Started a minute before its own record: a genuine owner, so a probe proves nothing.
      processStartTimeMs: async () => { probes += 1; return T0 - 60_000; },
    });
    const handle = unarmedHandleOf(store);
    const outcome = await handle.arm({ ...ARM, caps }).then(() => 'armed', (error) => error.code);
    return { outcome, probes, last: await lastOwnerRecord(dataRoot) };
  };
  const observed = {};
  // (a) Bootstrap, nothing recorded: exactly the two cap members are stamped, the allowance the store's.
  await withDataRoot(async (dataRoot) => {
    observed.stamped = (await armWith(dataRoot, { storeAllowance: 7, caps: callerCaps })).last.caps;
  });
  // (b) A live predecessor that released cleanly recorded { 5, 20 }, and the store's own allowance is
  // 20: compatible, although the caller's allowance (30) differs from the record.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: recorded, released: true });
    const { outcome, probes } = await armWith(dataRoot, { storeAllowance: 20, caps: { ...callerCaps, dailyPaidJobAllowance: 30 } });
    observed.onlyCallerDiffers = { outcome, probes };
  });
  // (c) The mirror image: the caller's allowance (20) matches the record, the store's own (30) does not.
  await withDataRoot(async (dataRoot) => {
    await seedCapsHolder(dataRoot, { caps: recorded, released: true });
    const { outcome, probes } = await armWith(dataRoot, { storeAllowance: 30, caps: { ...callerCaps, dailyPaidJobAllowance: 20 } });
    observed.onlyStoreDiffers = { outcome, probes };
  });
  assert.deepEqual(observed, {
    stamped: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 7 },
    onlyCallerDiffers: { outcome: 'armed', probes: 0 },
    onlyStoreDiffers: { outcome: 'OWNERSHIP_CAP_MISMATCH', probes: 1 },
  });
});

// Shutdown can begin while a cap probe runs, outside the lock, after the
// refusal's transaction. The follow-up attempt is exempt from the deadline gate, never from the stop
// check, so the arm must end ARM_ABORTED after that one transaction, whatever the probe found: a
// genuine sibling, whose follow-up would throw the terminal mismatch, and a recycled pid (real-clock
// timestamps, as in the recycled-pid test above), whose follow-up would append an ACQUIRED record during shutdown.
test('a stop that arrives during the cap probe aborts the arm before the follow-up attempt, whether the probe finds a genuine sibling or a recycled pid', async () => {
  const cases = {
    genuineSibling: { recordedAt: () => T0, clock: () => T0 + 5_000, startedMs: () => T0 - 60_000 },
    recycledPid: { recordedAt: () => Date.now() - (2 * 3_600_000), clock: () => Date.now(), startedMs: () => Date.now() - (10 * 60_000) },
  };
  const observed = {};
  for (const [name, scenario] of Object.entries(cases)) {
    await withDataRoot(async (dataRoot) => {
      await seedCapsHolder(dataRoot, { caps: { installationHardMaximumUsd: 5, dailyPaidJobAllowance: 20 }, timestampMs: scenario.recordedAt() });
      const before = (await readOwnerRecords(dataRoot)).length;
      let now = 0;
      let abort = false;
      const seen = { probes: 0, transactions: 0, sleeps: [] };
      const store = createLeaseStore({
        dataRoot,
        clock: scenario.clock,
        monotonicNow: () => now,
        sleep: async (milliseconds) => { seen.sleeps.push(milliseconds); now += milliseconds; },
        isProcessAlive: () => true,
        // Shutdown begins while the probe runs.
        processStartTimeMs: async () => { seen.probes += 1; abort = true; return scenario.startedMs(); },
        beforeRelease: async (released) => { if (Object.hasOwn(released, 'lockToken')) seen.transactions += 1; },
      });
      const handle = unarmedHandleOf(store);
      const outcome = await handle.arm({ ...ARM, caps: { installationHardMaximumUsd: 10 }, shouldAbort: () => abort })
        .then(() => 'armed', (error) => error.code);
      observed[name] = { outcome, ...seen, state: handle.state, appended: (await readOwnerRecords(dataRoot)).length - before };
    });
  }
  const aborted = { outcome: 'ARM_ABORTED', probes: 1, transactions: 1, sleeps: [], state: 'unarmed', appended: 0 };
  assert.deepEqual(observed, { genuineSibling: aborted, recycledPid: aborted }, 'the stop wins over the follow-up attempt: one transaction, nothing appended');
});
