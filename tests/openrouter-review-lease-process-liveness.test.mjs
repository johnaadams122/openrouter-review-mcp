import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';

// Every sibling lease-store test file injects a fake isProcessAlive to keep tests fast and
// deterministic -- correct for proving the DECISION logic (stale vs. live, generation bump), but
// a fake cannot prove the genuine OS-level property underneath it: a real PID that is actually alive, and a real PID that is actually dead. This file proves
// exactly that, using the store's real, un-faked defaultIsProcessAlive (`process.kill(pid, 0)`)
// against a real spawned, and a real SIGKILL'd, child process.

async function spawnLongLivedChild() {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { stdio: 'ignore' });
  await new Promise((resolve) => setTimeout(resolve, 200)); // let it actually start
  return child;
}

// Seeds the ledger directly with a processOwner ACQUIRED record, bypassing
// acquireProcessOwnership() entirely -- these tests need to name a specific real PID (a live
// child's, or one already confirmed dead), not whatever PID the current test process happens to
// have.
async function seedAcquiredOwnerRecord(dataRoot, { pid, generation, timestamp }) {
  const ledgerRoot = join(dataRoot, 'ledger');
  await mkdir(ledgerRoot, { recursive: true });
  const record = {
    recordType: 'processOwner', state: 'ACQUIRED', pid, generation,
    acquisitionId: randomUUID(), timestamp,
  };
  await writeFile(join(ledgerRoot, `${timestamp.replace(/[:.]/g, '-')}-seed.json`), `${JSON.stringify(record)}\n`, 'utf8');
  return record;
}

// Seeds the RAW `.ledger-write.lock` mkdir mutex directly -- the lower-level lock
// acquireDataRootLock() itself owns, distinct from the processOwner ledger record above. A real
// crash mid-mutate() leaves exactly this shape behind: a lock directory naming whatever pid was
// running the call, with no ledger record necessarily written at all yet.
async function seedDataRootLock(dataRoot, { pid, timestamp, lockToken = randomUUID() }) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  await mkdir(lockRoot, { recursive: true });
  const owner = { pid, timestamp, lockToken };
  await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(owner)}\n`, 'utf8');
  return owner;
}

// ---------------------------------------------------------------------------
// The data-root mkdir lock's own stale-reclaim check needs the same PID-recycling guard as the
// processOwner record's check (see the section further below): a bare isProcessAlive(pid) has no
// protection against the SAME pid being recycled to an unrelated live process during the lock's
// own stale window. Since this raw lock turns over on every single mutate() call (not once per
// server lifetime like a processOwner record), that is a real, if narrower, exposure to the same
// unrecoverable-hang shape: staleness and liveness are a conjunction, so a falsely-alive pid
// never resolves no matter how long a caller waits.
// ---------------------------------------------------------------------------

test('a recycled pid holding the raw data-root lock does not block a fresh writer forever', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  // A real, genuinely-alive process that this lock record cannot possibly belong to: the lock
  // is dated ten minutes before this child existed. Nothing is faked -- real pid, real liveness
  // check, real start-time probe.
  const child = await spawnLongLivedChild();
  try {
    const recordedAt = Date.now() - (10 * 60_000);
    await seedDataRootLock(dataRoot, { pid: child.pid, timestamp: new Date(recordedAt).toISOString() });

    const store = createLeaseStore({ dataRoot, clock: () => Date.now(), lockStaleMs: 60_000, lockRetryMs: 5 });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 20_000 });
    assert.equal(handle.generation, 1, 'the empty ledger behind the reclaimed lock has no prior owner');
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a genuinely live process holding the raw data-root lock is never reclaimed, no matter how stale the record looks', async () => {
  // The fail direction that matters, mirroring the processOwner-level test of the same name
  // above: this check can only ever turn "alive" into "reclaimable", which permits a takeover --
  // so a false positive here means two processes both believe they hold the ledger's write lock
  // at once. A real owner's start time always precedes its own lock record.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  try {
    const recordedAt = Date.now();
    await seedDataRootLock(dataRoot, { pid: child.pid, timestamp: new Date(recordedAt).toISOString() });

    // A full day past lockStaleMs: staleness alone must never be enough to reclaim a genuinely
    // live lock.
    const store = createLeaseStore({
      dataRoot, clock: () => Date.now() + (24 * 3600_000), lockStaleMs: 60_000, lockRetryMs: 5, lockTimeoutMs: 50,
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 300 }), /timed out.*\(DATA_ROOT_LOCKED\)/);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the raw data-root lock\'s pid-recycling probe runs once per stuck lock, not once per poll', async () => {
  // The probe costs a real child-process spawn (hundreds of milliseconds). This raw lock is read
  // on every mutate() retry (every lockRetryMs), so an unbounded per-poll probe would turn the
  // acquire budget into a lock-starvation outage, the same hazard the processOwner probe's
  // placement avoids one layer up.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  let probeCalls = 0;
  try {
    const recordedAt = Date.now() - (10 * 60_000);
    await seedDataRootLock(dataRoot, { pid: child.pid, timestamp: new Date(recordedAt).toISOString() });

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      lockStaleMs: 60_000,
      lockRetryMs: 5,
      lockTimeoutMs: 300,
      // Reports a genuine owner, so the loop keeps polling to its deadline rather than acquiring.
      processStartTimeMs: async () => { probeCalls += 1; return recordedAt - 1000; },
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 300 }), /timed out/);
    assert.equal(probeCalls, 1);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the raw data-root lock\'s pid-recycling probe is never consulted before the record is already stale', async () => {
  // The probe can only ever unblock a reclaim the staleness rule already permits -- it must
  // never make one happen SOONER than the unfixed code would have allowed.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  let probeCalls = 0;
  try {
    const recordedAt = Date.now();
    await seedDataRootLock(dataRoot, { pid: child.pid, timestamp: new Date(recordedAt).toISOString() });

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      lockStaleMs: 3600_000, // an hour: the lock is nowhere near stale
      lockRetryMs: 5,
      lockTimeoutMs: 200,
      processStartTimeMs: async () => { probeCalls += 1; return recordedAt + (10 * 60_000); },
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 300 }), /timed out.*\(DATA_ROOT_LOCKED\)/);
    assert.equal(probeCalls, 0);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('real process liveness: acquiring against a genuinely live, separate process refuses, using the real default isProcessAlive', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  try {
    const now = Date.parse('2026-09-03T00:00:00.000Z');
    // Directly seed the ledger with an ACQUIRED record naming the REAL child's pid, so the
    // production default isProcessAlive (real process.kill(pid, 0)) is exercised, not a fake.
    await seedAcquiredOwnerRecord(dataRoot, { pid: child.pid, generation: 1, timestamp: new Date(now).toISOString() });

    const contender = createLeaseStore({ dataRoot, clock: () => now, lockRetryMs: 5 });
    // Asserting only /timed out/ would also pass if isProcessAlive were broken and always
    // reported the owner dead: with the default lockStaleMs (60s) and a fixed clock, the record
    // would then read as NOT_YET_STALE instead, which times out with the same generic message.
    // Pinning the LIVE_OWNER reason specifically proves the real, un-faked isProcessAlive check
    // actually ran and actually reported this genuinely-live child process as alive -- verified by
    // sabotaging defaultIsProcessAlive to always return false and confirming this exact assertion
    // (not just "it timed out") is what catches it.
    await assert.rejects(contender.acquireProcessOwnership({ acquireTimeoutMs: 50 }), /timed out.*\(LIVE_OWNER\)/);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('real process liveness: a genuine hard process exit with no release() call is correctly detected as dead once stale', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  const deadPid = child.pid;
  child.kill('SIGKILL');
  await new Promise((resolve) => setTimeout(resolve, 300)); // let the OS actually reap it
  try {
    let now = Date.parse('2026-09-03T00:00:00.000Z');
    await seedAcquiredOwnerRecord(dataRoot, { pid: deadPid, generation: 1, timestamp: new Date(now).toISOString() });

    const store = createLeaseStore({ dataRoot, clock: () => now, lockStaleMs: 100, lockRetryMs: 5 });
    now += 200; // past lockStaleMs
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 5000 });
    assert.equal(handle.generation, 2);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Ownership identity is more than a bare PID.
//
// `defaultIsProcessAlive` is `process.kill(pid, 0)`, and liveness is checked BEFORE staleness,
// so a wrong "alive" answer has no timeout escape -- the server is not hung, it is permanently
// unstartable. A recycled PID can belong to an unrelated live process, and process.kill(pid, 0)
// still reports it as alive.
//
// The discriminator needs no new stored field: a process cannot have acquired ownership before it
// existed, so a start time LATER than the record's own timestamp proves the pid was recycled.
// ---------------------------------------------------------------------------

test('a recycled pid whose process started AFTER the ownership record does not hold ownership forever', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  // A real, genuinely-alive process that this record cannot possibly belong to: the record is
  // dated ten minutes before this child existed. Nothing is faked here -- real pid, real
  // liveness check, real start-time probe.
  const child = await spawnLongLivedChild();
  try {
    const recordedAt = Date.now() - (10 * 60_000);
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(recordedAt).toISOString(),
    });

    const store = createLeaseStore({ dataRoot, clock: () => Date.now(), lockStaleMs: 60_000, lockRetryMs: 5 });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 20_000 });
    assert.equal(handle.generation, 2);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a genuinely live owner that started BEFORE its own record keeps ownership no matter how stale the record is', async () => {
  // The fail direction that matters. This check can only ever turn "alive" into "dead", which
  // PERMITS a takeover -- so a false positive here means two live servers, exactly what mutual
  // exclusion exists to prevent. A real owner's start time always precedes its own record.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  try {
    const recordedAt = Date.now();
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(recordedAt).toISOString(),
    });

    // A full day past lockStaleMs: staleness alone must never be enough to evict a live owner.
    const store = createLeaseStore({
      dataRoot, clock: () => Date.now() + (24 * 3600_000), lockStaleMs: 60_000, lockRetryMs: 5,
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 3000 }), /timed out.*\(LIVE_OWNER\)/);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('an unreadable start time keeps the owner, rather than assuming the pid was recycled', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  try {
    const recordedAt = Date.now() - (10 * 60_000);
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(recordedAt).toISOString(),
    });

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      lockStaleMs: 60_000,
      lockRetryMs: 5,
      processStartTimeMs: async () => { throw new Error('probe unavailable on this host'); },
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 2000 }), /timed out.*\(LIVE_OWNER\)/);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a start time barely later than the record is treated as clock skew, not a recycled pid', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  try {
    const recordedAt = Date.now() - (10 * 60_000);
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(recordedAt).toISOString(),
    });

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      lockStaleMs: 60_000,
      lockRetryMs: 5,
      // One second after the record -- a backward clock step, not a pid that outlived its owner.
      processStartTimeMs: async () => recordedAt + 1000,
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 2000 }), /timed out.*\(LIVE_OWNER\)/);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the start-time probe runs once per candidate owner, not once per poll', async () => {
  // The probe costs a real child-process spawn (hundreds of milliseconds). The acquire loop
  // polls every lockRetryMs (5ms here), so a per-poll probe would turn the acquire budget into
  // a lock-starvation outage.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  let probeCalls = 0;
  try {
    const recordedAt = Date.now() - (10 * 60_000);
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(recordedAt).toISOString(),
    });

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      lockStaleMs: 60_000,
      lockRetryMs: 5,
      // Reports a genuine owner, so the loop keeps polling to its deadline rather than acquiring.
      processStartTimeMs: async () => { probeCalls += 1; return recordedAt - 1000; },
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 300 }), /timed out/);
    assert.equal(probeCalls, 1);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the start-time probe is never consulted before the record is already stale', async () => {
  // The probe can only ever unblock a takeover that the staleness rule already permits. It must
  // never be able to make one happen SOONER than the unfixed code would have allowed.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  let probeCalls = 0;
  try {
    const recordedAt = Date.now();
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(recordedAt).toISOString(),
    });

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.now(),
      lockStaleMs: 3600_000, // an hour: the record is nowhere near stale
      lockRetryMs: 5,
      processStartTimeMs: async () => { probeCalls += 1; return recordedAt + (10 * 60_000); },
    });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 200 }), /timed out.*\(LIVE_OWNER\)/);
    assert.equal(probeCalls, 0);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a store clock that is not the real wall clock cannot make a live owner look recycled', async () => {
  // The probe reads a start time from the OS (real wall clock); the record carries a timestamp
  // written by the store's INJECTED clock. When those two disagree -- every test in this repo
  // that pins a fictional date, and any future caller that injects a clock -- comparing them as
  // instants is meaningless, and it fails in the UNSAFE direction: a genuine, live owner looks
  // like a recycled pid, which is how a second process ends up owning the ledger.
  //
  // So the verdict also requires a clock-domain-independent check: the process must be YOUNGER
  // than the record is OLD. Here the record is backdated years while the child is seconds old,
  // so the instant comparison says "recycled" and the duration comparison says "not", and the
  // conjunction correctly refuses.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-real-'));
  const child = await spawnLongLivedChild();
  try {
    const fictional = Date.parse('2026-09-03T00:00:00.000Z');
    await seedAcquiredOwnerRecord(dataRoot, {
      pid: child.pid, generation: 1, timestamp: new Date(fictional).toISOString(),
    });

    // Fixed clock pinned at the record's own instant: the record is ~0ms old in the store's own
    // domain, while the real child started days after that fictional date.
    const store = createLeaseStore({ dataRoot, clock: () => fictional, lockStaleMs: 0, lockRetryMs: 5 });
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 2000 }), /timed out.*\(LIVE_OWNER\)/);
  } finally {
    child.kill();
    await rm(dataRoot, { recursive: true, force: true });
  }
});
