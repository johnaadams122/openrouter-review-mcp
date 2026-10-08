import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { UUID_ONES } from './helpers/scanner-safe-fixtures.mjs';

const HASH = 'a'.repeat(64);

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  let now = Date.parse('2026-08-17T12:00:00.000Z');
  const store = createLeaseStore({ dataRoot, clock: () => now });
  try {
    await run({ store, dataRoot, advance: (milliseconds) => { now += milliseconds; } });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function createBoundPreflight(store, expiresAt, { rawSourceSha256 = 'e'.repeat(64) } = {}) {
  return store.createPreflight({
    reviewContractSha256: HASH,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256,
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'c'.repeat(64),
    registrySha256: 'd'.repeat(64),
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }],
    requestedUsd: 0.20,
    expiresAt,
  });
}

function deriveReviewJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256')
    .update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8')
    .digest('hex');
}

async function createTwoReviewerPreflight(store, expiresAt) {
  return store.createPreflight({
    reviewContractSha256: HASH,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256: 'e'.repeat(64),
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'c'.repeat(64),
    registrySha256: 'd'.repeat(64),
    itemMaxima: [
      { itemId: 'item-gemini', maxUsd: 0.20 },
      { itemId: 'item-grok', maxUsd: 0.20 },
    ],
    requestedUsd: 0.40,
    expiresAt,
  });
}

test('a lease is source-bound, cap-bounded, and cannot be widened or renewed', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({
      preflightIds: [preflight.id],
      requestedUsd: 0.20,
      maxJobs: 1,
      expiresAt,
      acquisitionId,
    });

    await assert.rejects(
      () => store.createLease({ preflightIds: [preflight.id, preflight.id], requestedUsd: 0.40, maxJobs: 1, expiresAt, acquisitionId }),
      /duplicate preflight/i,
    );
    await assert.rejects(() => store.consume(lease.id, 'e'.repeat(64), { reservationUsd: 0.01, acquisitionId }), /contract/i);
    await assert.rejects(() => store.consume(lease.id, HASH, { reservationUsd: 0.21, acquisitionId }), /cap/i);
    await store.close(lease.id, 'UNKNOWN_COST', { acquisitionId });
    await assert.rejects(() => store.renew(lease.id), /closed lease/i);
  });
});

test('getPreflight returns the stored record by ID, or null when unknown', async () => {
  await withStore(async ({ store }) => {
    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');
    const fetched = await store.getPreflight(preflight.id);
    assert.equal(fetched.id, preflight.id);
    assert.deepEqual(fetched.itemMaxima, [{ itemId: 'item-gemini', maxUsd: 0.20 }]);
    assert.equal(await store.getPreflight('missing-preflight-id'), null);
  });
});

test('getPreflight still finds a record after a simulated restart (fresh store instance over the same on-disk ledger)', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');
    const restarted = createLeaseStore({ dataRoot, clock: () => Date.parse('2026-08-17T12:00:00.000Z') });
    const fetched = await restarted.getPreflight(preflight.id);
    assert.equal(fetched.id, preflight.id);
  });
});

test('ledger records are append-only, atomic redacted state transitions', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-one', acquisitionId });
    await store.reconcile(job.id, { costUsd: 0.05, costKind: 'KNOWN', acquisitionId });

    const recordDirectory = join(dataRoot, 'ledger');
    const recordNames = await readdir(recordDirectory);
    assert.equal(recordNames.length >= 4, true);
    assert.equal(recordNames.some((name) => name.endsWith('.tmp')), false);
    const contents = await Promise.all(recordNames.map(async (name) => readFile(join(recordDirectory, name), 'utf8')));
    const combined = contents.join('\n');
    assert.match(combined, /"state":"PREFLIGHTED"/);
    assert.match(combined, /"state":"RESERVED"/);
    assert.doesNotMatch(combined, /sourceText|requestBody|responseBody|apiKey/i);
  });
});

test('a separate store fails closed while another data-root writer lock is fresh', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    await mkdir(lockRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 0 });
    await assert.rejects(
      () => store.createPreflight({ expiresAt: '2026-08-17T12:10:00.000Z' }),
      /locked/i,
    );
  });
});

test('a contender retries transient owner.json read and parse failures before honoring the winning live lock', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    const ownerPath = join(lockRoot, 'owner.json');
    const winningOwner = {
      pid: 888888,
      timestamp: '2026-08-17T11:00:00.000Z',
      lockToken: 'winning-lock-token',
    };
    await mkdir(lockRoot);

    let sleepCalls = 0;
    let liveOwnerChecks = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      lockTimeoutMs: 2_000,
      lockRetryMs: 10,
      isProcessAlive: (pid) => {
        assert.equal(pid, winningOwner.pid);
        liveOwnerChecks += 1;
        return true;
      },
      // A stale-but-alive raw lock is also probed for pid recycling (see
      // isDataRootLockReclaimable in lease-store.mjs) -- pinned unable-to-determine here so this
      // test stays hermetic (no real PowerShell spawn) and keeps its pre-existing behavior: an
      // unresolvable start time is never treated as proof of recycling.
      processStartTimeMs: async () => null,
      sleep: async (milliseconds) => {
        assert.equal(milliseconds, 10);
        sleepCalls += 1;
        if (sleepCalls === 1) {
          await writeFile(ownerPath, '{', 'utf8');
        } else if (sleepCalls === 2) {
          await writeFile(ownerPath, `${JSON.stringify(winningOwner)}\n`, 'utf8');
        } else if (sleepCalls === 3) {
          await rm(lockRoot, { recursive: true, force: true });
        }
      },
    });

    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');

    assert.equal(preflight.state, 'PREFLIGHTED');
    assert.equal(sleepCalls, 3, 'one read retry, one parse retry, and one verified-owner contention wait');
    assert.equal(liveOwnerChecks, 1, 'the recovered owner metadata must be checked before waiting');
  });
});

test('a verified live owner resets the owner-read retry budget before lock ownership turns over', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    const ownerPath = join(lockRoot, 'owner.json');
    const firstOwner = { pid: 777777, timestamp: '2026-08-17T11:00:00.000Z', lockToken: 'first-owner-token' };
    const secondOwner = { pid: 888888, timestamp: '2026-08-17T11:00:00.000Z', lockToken: 'second-owner-token' };
    await mkdir(lockRoot);

    let sleepCalls = 0;
    const liveOwnerChecks = [];
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      lockTimeoutMs: 10_000,
      lockRetryMs: 10,
      isProcessAlive: (pid) => {
        liveOwnerChecks.push(pid);
        return true;
      },
      // See the sibling test above: pinned so the stale-but-alive probe never spawns a real
      // process here, and an unresolvable start time keeps the pre-existing "still refuse" result.
      processStartTimeMs: async () => null,
      sleep: async (milliseconds) => {
        assert.equal(milliseconds, 10);
        sleepCalls += 1;
        if (sleepCalls === 1) {
          await writeFile(ownerPath, '{', 'utf8');
        } else if (sleepCalls === 2) {
          await rm(ownerPath, { force: true });
        } else if (sleepCalls === 3) {
          await writeFile(ownerPath, '{', 'utf8');
        } else if (sleepCalls === 4) {
          await writeFile(ownerPath, `${JSON.stringify(firstOwner)}\n`, 'utf8');
        } else if (sleepCalls === 5) {
          await rm(lockRoot, { recursive: true, force: true });
          await mkdir(lockRoot);
        } else if (sleepCalls === 6) {
          await writeFile(ownerPath, '{', 'utf8');
        } else if (sleepCalls === 7) {
          await writeFile(ownerPath, `${JSON.stringify(secondOwner)}\n`, 'utf8');
        } else if (sleepCalls === 8) {
          await rm(lockRoot, { recursive: true, force: true });
        }
      },
    });

    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');

    assert.equal(preflight.state, 'PREFLIGHTED');
    assert.equal(sleepCalls, 8, 'each verified owner epoch gets its own transient-read retry budget');
    assert.deepEqual(liveOwnerChecks, [firstOwner.pid, secondOwner.pid]);
  });
});

test('an owner-read retry cannot acquire after its injected sleep exhausts the lock deadline', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    await mkdir(lockRoot);

    const originalDateNow = Date.now;
    let wallTimeMs = 1_000;
    let sleepCalls = 0;
    Date.now = () => wallTimeMs;
    try {
      const store = createLeaseStore({
        dataRoot,
        lockTimeoutMs: 1,
        lockRetryMs: 10,
        sleep: async (milliseconds) => {
          assert.equal(milliseconds, 10);
          sleepCalls += 1;
          wallTimeMs += milliseconds;
          await rm(lockRoot, { recursive: true, force: true });
        },
      });

      await assert.rejects(
        () => createBoundPreflight(store, '2026-08-17T12:10:00.000Z'),
        /ledger data root is locked \(owner cannot be verified\)/i,
      );
    } finally {
      Date.now = originalDateNow;
    }

    assert.equal(sleepCalls, 1);
    assert.deepEqual(await readdir(dataRoot), [], 'the expired contender must not acquire or write a ledger record');
  });
});

async function pathExists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

test('lockRoot is never observable without owner.json already inside it -- the acquire publish is one atomic rename, not mkdir-then-write', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    let publishRenameCalls = 0;
    let sawLockRootBeforePublish = false;
    let capturedOwner = null;
    const originalRenameImpl = rename;
    // Spy on the exact moment createAndPublishLockRoot() (lease-store.mjs) publishes: the
    // rename's `to` is lockRoot itself, distinguishing it from the release/stale-reclaim
    // renames, whose `to` is always a `.release-`/`.stale-` staging path instead. The lock is
    // acquired AND released within one mutate() cycle, so lockRoot/owner.json is gone again by
    // the time createPreflight() resolves -- the only place a valid pre-publish owner record
    // can be observed is here, inside the spy, immediately before the real rename runs.
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      renameImpl: async (from, to) => {
        if (to === lockRoot) {
          publishRenameCalls += 1;
          sawLockRootBeforePublish = await pathExists(lockRoot);
          capturedOwner = JSON.parse(await readFile(join(from, 'owner.json'), 'utf8'));
        }
        return originalRenameImpl(from, to);
      },
    });
    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');

    assert.equal(preflight.state, 'PREFLIGHTED');
    assert.equal(publishRenameCalls, 1, 'exactly one publish rename for one uncontended acquire');
    assert.equal(sawLockRootBeforePublish, false, 'lockRoot must not exist before the atomic publish rename runs');
    assert.equal(typeof capturedOwner?.lockToken, 'string', 'owner.json must already be fully written into the staging directory before it is ever renamed to lockRoot');
    const leftoverEntries = (await readdir(dataRoot)).filter((name) => name !== 'ledger');
    assert.deepEqual(leftoverEntries, [], 'the uncontended fast path must leave no orphaned staging directory, and no held lockRoot, behind once released');
  });
});

// Note on what this test does and does not prove: it does NOT reproduce an empty-lockRoot failure
// (that requires an empty *lockRoot itself*, which the sibling test above already proves the
// acquire path can never produce). What it proves instead is that the staged-publish
// mechanism's own failure residue is harmless: a stray
// `.creating-<uuid>` directory (left behind by a process that died between staging mkdir and the
// owner.json write, or between the write and the publish rename -- see createAndPublishLockRoot()'s
// own comment in lease-store.mjs) is inert clutter under a name nothing else ever contends on,
// exactly like this file's pre-existing `.release-<uuid>`/`.stale-<uuid>` orphans -- never a
// second lockRoot-shaped bottleneck.
test('an orphaned staging directory from a hypothetical earlier crash is harmless clutter, never a second blocking lock', async () => {
  await withStore(async ({ dataRoot, store }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    const orphanedStaging = `${lockRoot}.creating-simulated-crash`;
    await mkdir(orphanedStaging);

    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');
    assert.equal(preflight.state, 'PREFLIGHTED', 'an orphaned staging directory under a different name must not block a fresh acquire');

    assert.equal(await pathExists(lockRoot), false, 'the lock is acquired and released within one call -- lockRoot must be gone again, not left stuck');
    assert.equal(await pathExists(join(orphanedStaging, 'owner.json')), false, 'the orphaned staging directory is left exactly as it was -- harmless clutter, not touched');
  });
});

test('a publish-rename failure with NO occupant at lockRoot fails safely closed (a deliberately misleading-but-safe explanation, not an escaping raw error)', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    // A retryable-shaped code (EPERM/EBUSY/ENOTEMPTY) on the publish rename usually means
    // lockRoot is occupied, but the identical codes can also come from an unrelated I/O/
    // permissions problem that has nothing to do with occupancy. Simulate exactly that -- the
    // rename throws while lockRoot genuinely never exists. A point-in-time occupancy check is
    // not used: under real concurrent load it would let a raw, non-EEXIST-coded error escape
    // past acquireProcessOwnership()'s own
    // retry loop (which only recognizes LEDGER_DATA_ROOT_LOCKED), breaking its "exactly one
    // caller wins per round" guarantee -- see createAndPublishLockRoot()'s own comment. This
    // test pins the deliberate, safe alternative: unconditional EEXIST-shaped contention
    // reporting, which always resolves via the existing, well-tested owner-read/staleness
    // path below rather than ever escaping as a bespoke, unexpected error shape.
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      lockTimeoutMs: 200,
      lockRetryMs: 10,
      renameImpl: async (from, to) => {
        if (to === lockRoot) {
          const error = new Error('simulated non-occupancy I/O failure');
          error.code = 'EPERM';
          throw error;
        }
        return rename(from, to);
      },
    });

    await assert.rejects(
      () => createBoundPreflight(store, '2026-08-17T12:10:00.000Z'),
      /ledger data root is locked \(owner cannot be verified\)/i,
    );
    assert.equal(await pathExists(lockRoot), false, 'a failed publish must never leave lockRoot behind either');
  });
});

test('an owner.json that stays unreadable fails closed after a bounded retry grace', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    await mkdir(lockRoot);
    await writeFile(join(lockRoot, 'owner.json'), '{', 'utf8');

    let sleepCalls = 0;
    const store = createLeaseStore({
      dataRoot,
      lockTimeoutMs: 2_000,
      lockRetryMs: 10,
      sleep: async (milliseconds) => {
        assert.equal(milliseconds, 10);
        sleepCalls += 1;
      },
    });

    await assert.rejects(
      () => createBoundPreflight(store, '2026-08-17T12:10:00.000Z'),
      /ledger data root is locked \(owner cannot be verified\)/i,
    );
    assert.equal(sleepCalls, 4, 'one initial read plus four bounded retries');
  });
});

test('a lock abandoned by a dead process past the staleness window is reclaimed by a new writer', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    await mkdir(lockRoot);
    const abandonedOwner = { pid: 999999, timestamp: '2026-08-17T11:00:00.000Z' };
    await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(abandonedOwner)}\n`, 'utf8');

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      isProcessAlive: (pid) => pid !== abandonedOwner.pid,
    });

    const preflight = await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');
    assert.equal(preflight.state, 'PREFLIGHTED');
  });
});

test('a lock whose owner process is still alive is not reclaimed even past the staleness window', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    await mkdir(lockRoot);
    const liveOwner = { pid: 999999, timestamp: '2026-08-17T11:00:00.000Z' };
    await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(liveOwner)}\n`, 'utf8');

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      isProcessAlive: (pid) => pid === liveOwner.pid,
      // liveOwner has no lockToken, so isDataRootLockReclaimable's probe cache never applies and
      // this would otherwise spawn a real PowerShell probe on every 10ms retry across the whole
      // 100ms budget -- pinned unresolvable to stay hermetic and keep refusing, exactly as
      // before this check existed.
      processStartTimeMs: async () => null,
      lockTimeoutMs: 100,
      lockRetryMs: 10,
    });

    await assert.rejects(
      () => createBoundPreflight(store, '2026-08-17T12:10:00.000Z'),
      /locked/i,
    );
  });
});

test('a competing reclaim in the gap between reading a dead owner and renaming its lock is never destroyed (TOCTOU-safe stale reclaim)', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    await mkdir(lockRoot);
    const deadOwner = { pid: 999999, timestamp: '2026-08-17T11:00:00.000Z' };
    await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(deadOwner)}\n`, 'utf8');

    // A second, live owner that "wins" the race by reclaiming and
    // re-acquiring the lock in the window between this process reading
    // owner.json (deciding it is stale) and renaming it away.
    const competitorOwner = { pid: 888888, timestamp: '2026-08-17T11:59:59.500Z' };
    let sabotaged = false;

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      isProcessAlive: (pid) => pid === competitorOwner.pid,
      lockTimeoutMs: 100,
      lockRetryMs: 10,
      beforeStaleReclaim: async () => {
        if (sabotaged) return;
        sabotaged = true;
        await rm(lockRoot, { recursive: true, force: true });
        await mkdir(lockRoot);
        await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(competitorOwner)}\n`, 'utf8');
      },
    });

    await assert.rejects(
      () => createBoundPreflight(store, '2026-08-17T12:10:00.000Z'),
      /locked/i,
    );
    assert.equal(sabotaged, true);

    // The competitor's freshly re-acquired lock must have survived the
    // encounter intact -- never blindly deleted by the losing process's
    // stale-reclaim rename.
    const survivingOwner = JSON.parse(await readFile(join(lockRoot, 'owner.json'), 'utf8'));
    assert.deepEqual(survivingOwner, competitorOwner);
  });
});

test('release() never deletes a lock it no longer owns (token-gated release)', async () => {
  await withStore(async ({ dataRoot }) => {
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    const intruderOwner = { pid: 777777, timestamp: '2026-08-17T12:00:00.500Z', lockToken: 'intruder-token' };

    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      beforeRelease: async () => {
        // Simulate a third-party lock that came to occupy lockRoot after this
        // store's own acquisition -- the same shape of race the TOCTOU stale-reclaim
        // test above covers on the acquire side. Release must not destroy it.
        await rm(lockRoot, { recursive: true, force: true });
        await mkdir(lockRoot);
        await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(intruderOwner)}\n`, 'utf8');
      },
    });

    await createBoundPreflight(store, '2026-08-17T12:10:00.000Z');

    const survivor = JSON.parse(await readFile(join(lockRoot, 'owner.json'), 'utf8'));
    assert.deepEqual(survivor, intruderOwner);
  });
});

test('a second live store instance genuinely waits for the first to release the lock', async () => {
  await withStore(async ({ dataRoot }) => {
    let releaseFirstMutation;
    const blocker = new Promise((resolve) => { releaseFirstMutation = resolve; });
    let markFirstMutationEntered;
    const firstMutationEntered = new Promise((resolve) => { markFirstMutationEntered = resolve; });

    const storeA = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      beforeAtomicRename: async () => {
        markFirstMutationEntered();
        await blocker;
      },
    });
    let sleepCalls = 0;
    let markSecondRetrySleepEntered;
    const secondRetrySleepEntered = new Promise((resolve) => { markSecondRetrySleepEntered = resolve; });
    const storeB = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      lockTimeoutMs: 2_000,
      lockRetryMs: 10,
      // Keep the real timer while exposing the exact point where B has observed A's
      // live lock and entered its first retry sleep.
      sleep: (milliseconds) => {
        sleepCalls += 1;
        if (sleepCalls === 1) markSecondRetrySleepEntered();
        return new Promise((resolve) => setTimeout(resolve, milliseconds));
      },
    });

    let firstCall;
    let secondCall;
    try {
      firstCall = createBoundPreflight(storeA, '2026-08-17T12:10:00.000Z');
      await Promise.race([
        firstMutationEntered,
        firstCall.then(() => assert.fail('storeA completed without entering its blocked mutation')),
      ]);

      secondCall = createBoundPreflight(storeB, '2026-08-17T12:10:01.000Z');
      let secondSettled = false;
      const observedSecondCall = secondCall.then(
        () => { secondSettled = true; },
        () => { secondSettled = true; },
      );
      await Promise.race([
        secondRetrySleepEntered,
        observedSecondCall.then(() => assert.fail('storeB completed before entering its retry sleep')),
      ]);
      assert.equal(sleepCalls, 1, 'storeB must have entered its first retry sleep');
      assert.equal(secondSettled, false, 'storeB must remain pending while storeA holds the lock');

      releaseFirstMutation();
      const [firstPreflight, secondPreflight] = await Promise.all([firstCall, secondCall]);
      assert.equal(firstPreflight.state, 'PREFLIGHTED');
      assert.equal(secondPreflight.state, 'PREFLIGHTED');
    } finally {
      releaseFirstMutation();
      await Promise.allSettled([firstCall, secondCall].filter(Boolean));
    }
  });
});

test('a failed atomic transition is ignored on replay and does not partially reserve a lease', async () => {
  await withStore(async ({ dataRoot }) => {
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const stable = createLeaseStore({ dataRoot, clock: () => Date.parse('2026-08-17T12:00:00.000Z') });
    const { acquisitionId } = await stable.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const preflight = await createBoundPreflight(stable, expiresAt);
    const lease = await stable.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const failing = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-08-17T12:00:00.000Z'),
      beforeAtomicRename: (record) => {
        if (record.recordType === 'transition') throw new Error('simulated crash before rename');
      },
    });
    await assert.rejects(() => failing.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-crash', acquisitionId }), /simulated crash/i);

    const recovered = createLeaseStore({ dataRoot, clock: () => Date.parse('2026-08-17T12:00:00.000Z') });
    assert.equal((await recovered.getLease(lease.id)).reservedUsd, 0);
    const job = await recovered.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-crash', acquisitionId });
    assert.equal(job.state, 'RESERVED');
    assert.equal((await recovered.getLease(lease.id)).reservedUsd, 0.10);
  });
});

test('expired leases and forbidden raw fields fail before a spend reservation', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:00:01.000Z';
    await assert.rejects(
      () => store.createPreflight({ reviewContractSha256: HASH, sourceText: 'never persist this', expiresAt }),
      /forbidden/i,
    );
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    advance(2_000);
    await assert.rejects(() => store.consume(lease.id, HASH, { reservationUsd: 0.01, acquisitionId }), /expired/i);
    assert.equal((await store.getLease(lease.id)).reservedUsd, 0);
    assert.equal((await store.getLease(lease.id)).spentUsd, 0);
  });
});

// sweepOrphanedLeases: recovery for a RESERVED job whose dispatch outcome
// will never be known -- e.g. the process that reserved it was replaced
// (crash, host reconnect) before it could reconcile. Without it such a lease
// stays permanently ACTIVE with a RESERVED job, because the only other
// recovery path (review()'s own in-loop existingJob check) depends on an
// in-memory preflight cache that a process restart always empties.
// staleAfterMs is required (no default) so a caller must make a deliberate,
// explicit choice about the grace window, matching this file's existing
// preference for explicit inputs over implicit ones on money-affecting calls.

test('sweepOrphanedLeases reconciles a stale RESERVED job at its reservation cost and closes the lease as ORPHANED_ON_RECOVERY', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.18, jobId: 'orphan-job', acquisitionId });
    assert.equal(job.state, 'RESERVED');

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 120_000 + 1_000);

    const results = await store.sweepOrphanedLeases({ leaseId: lease.id, staleAfterMs: 120_000, acquisitionId });

    assert.equal(results.length, 1);
    assert.equal(results[0].leaseId, lease.id);
    assert.equal(results[0].reconciledJobs.length, 1);
    assert.equal(results[0].reconciledJobs[0].id, 'orphan-job');
    assert.equal(results[0].reconciledJobs[0].costUsd, 0.18);

    const closedLease = await store.getLease(lease.id);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
    assert.equal(closedLease.reservedUsd, 0);
    assert.equal(closedLease.spentUsd, 0.18);
    const closedJob = await store.getJob('orphan-job');
    assert.equal(closedJob.state, 'RECONCILED');
    assert.equal(closedJob.costUsd, 0.18);
  });
});

test('sweepOrphanedLeases leaves a RESERVED job and its lease untouched while still within the staleness grace window', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.18, jobId: 'still-inflight', acquisitionId });

    // Past expiresAt, but well inside the 120s grace window.
    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 5_000);

    const results = await store.sweepOrphanedLeases({ leaseId: lease.id, staleAfterMs: 120_000, acquisitionId });

    assert.equal(results.length, 0);
    assert.equal((await store.getLease(lease.id)).state, 'ACTIVE');
    assert.equal((await store.getJob('still-inflight')).state, 'RESERVED');
  });
});

test('sweepOrphanedLeases is a no-op for an expired lease with no reserved jobs', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 200_000);

    const results = await store.sweepOrphanedLeases({ leaseId: lease.id, staleAfterMs: 120_000, acquisitionId });

    assert.equal(results.length, 0);
    assert.equal((await store.getLease(lease.id)).state, 'ACTIVE');
  });
});

test('sweepOrphanedLeases with no leaseId sweeps every eligible expired lease and skips a not-yet-stale or already-closed one', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';

    const staleFlight = await createBoundPreflight(store, expiresAt);
    const staleLease = await store.createLease({ preflightIds: [staleFlight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.consume(staleLease.id, HASH, { reservationUsd: 0.15, jobId: 'stale-job', acquisitionId });

    const freshFlight = await createBoundPreflight(store, expiresAt);
    const freshLease = await store.createLease({ preflightIds: [freshFlight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const freshJob = await store.consume(freshLease.id, HASH, { reservationUsd: 0.10, jobId: 'fresh-job', acquisitionId });
    await store.reconcile(freshJob.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });
    await store.close(freshLease.id, 'PASSED', { acquisitionId });

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 200_000);

    const results = await store.sweepOrphanedLeases({ staleAfterMs: 120_000, acquisitionId });

    assert.equal(results.length, 1);
    assert.equal(results[0].leaseId, staleLease.id);
    assert.equal((await store.getLease(staleLease.id)).state, 'ORPHANED_ON_RECOVERY');
    assert.equal((await store.getLease(freshLease.id)).state, 'PASSED', 'an already-closed lease must be left untouched');
  });
});

test('sweepOrphanedLeases rejects a negative staleAfterMs', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(() => store.sweepOrphanedLeases({ staleAfterMs: -1 }), /staleAfterMs/);
  });
});

// findStaleReservedJobs: a read-only enumeration used by review-engine.mjs's recoverStaleLease()
// to inspect each stale job's own durable dispatch-outcome capture BEFORE reconciling it, instead
// of sweepOrphanedLeases()'s unconditional worst-case charge. Same eligibility filter as
// sweepOrphanedLeases (ACTIVE lease, expired for at least staleAfterMs), but touches no state.
test('findStaleReservedJobs reports every RESERVED job on a stale lease without reconciling or closing anything', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.18, jobId: 'stale-job', reviewerId: 'gemini', acquisitionId });

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 120_000 + 1_000);

    const found = await store.findStaleReservedJobs({ leaseId: lease.id, staleAfterMs: 120_000 });

    assert.equal(found.length, 1);
    assert.deepEqual(found[0], { leaseId: lease.id, jobId: 'stale-job', reviewerId: 'gemini', reservationUsd: 0.18 });
    // Read-only: nothing was reconciled or closed.
    assert.equal((await store.getLease(lease.id)).state, 'ACTIVE');
    assert.equal((await store.getJob('stale-job')).state, 'RESERVED');
  });
});

test('findStaleReservedJobs reports nothing for a RESERVED job still within the staleness grace window', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.18, jobId: 'still-inflight', acquisitionId });

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 5_000);

    assert.deepEqual(await store.findStaleReservedJobs({ leaseId: lease.id, staleAfterMs: 120_000 }), []);
  });
});

test('findStaleReservedJobs with no leaseId scans every eligible expired lease and skips a not-yet-stale or already-closed one', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';

    const staleFlight = await createBoundPreflight(store, expiresAt);
    const staleLease = await store.createLease({ preflightIds: [staleFlight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.consume(staleLease.id, HASH, { reservationUsd: 0.15, jobId: 'stale-job', acquisitionId });

    const freshFlight = await createBoundPreflight(store, expiresAt);
    const freshLease = await store.createLease({ preflightIds: [freshFlight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const freshJob = await store.consume(freshLease.id, HASH, { reservationUsd: 0.10, jobId: 'fresh-job', acquisitionId });
    await store.reconcile(freshJob.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });
    await store.close(freshLease.id, 'PASSED', { acquisitionId });

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 200_000);

    const found = await store.findStaleReservedJobs({ staleAfterMs: 120_000 });

    assert.equal(found.length, 1);
    assert.equal(found[0].leaseId, staleLease.id);
    assert.equal(found[0].jobId, 'stale-job');
  });
});

test('findStaleReservedJobs rejects a negative staleAfterMs', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(() => store.findStaleReservedJobs({ staleAfterMs: -1 }), /staleAfterMs/);
  });
});

// Backs the repeat-authorization justification gate in review-engine.mjs: authorizeWorkflow needs
// to know, before granting a lease, whether this DOCUMENT (not just this one preflight attempt)
// has already produced one. Deliberately keyed on rawSourceSha256, not preflightId -- a fresh
// preflightId is minted on every preflight() call even for byte-identical content, so a caller
// could otherwise reset the count to zero just by re-preflighting the same document.
test('countLeasesForRawSource counts every lease ever created from ANY preflight sharing this raw source hash, regardless of lease state', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const firstPreflight = await createBoundPreflight(store, expiresAt, { rawSourceSha256 });

    assert.equal(await store.countLeasesForRawSource(rawSourceSha256), 0, 'a never-authorized document has zero leases');

    const first = await store.createLease({ preflightIds: [firstPreflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    assert.equal(await store.countLeasesForRawSource(rawSourceSha256), 1);

    // Close the first lease -- a closed/orphaned lease still counts. The point is bounding how
    // many times authorization was ever granted for this document, not how many are still open.
    await store.close(first.id, 'PASSED', { acquisitionId });
    assert.equal(await store.countLeasesForRawSource(rawSourceSha256), 1, 'a closed lease still counts');

    // A SECOND preflight() call for the SAME raw document content mints a fresh preflightId (the
    // exact scenario that defeated a preflightId-keyed version of this check) -- its lease must
    // still be attributed to the same document.
    const secondPreflight = await createBoundPreflight(store, expiresAt, { rawSourceSha256 });
    assert.notEqual(secondPreflight.id, firstPreflight.id, 'a fresh preflight() call always mints a new ID');
    await store.createLease({ preflightIds: [secondPreflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    assert.equal(await store.countLeasesForRawSource(rawSourceSha256), 2, 'a lease from a DIFFERENT preflightId for the SAME document must still count');
  });
});

test('countLeasesForRawSource only counts leases for documents sharing this raw source hash, not a different document', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const rawSourceSha256A = 'f'.repeat(64);
    const rawSourceSha256B = 'a1'.repeat(32);
    const preflightA = await createBoundPreflight(store, expiresAt, { rawSourceSha256: rawSourceSha256A });
    await createBoundPreflight(store, expiresAt, { rawSourceSha256: rawSourceSha256B });
    await store.createLease({ preflightIds: [preflightA.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });

    assert.equal(await store.countLeasesForRawSource(rawSourceSha256A), 1);
    assert.equal(await store.countLeasesForRawSource(rawSourceSha256B), 0);
  });
});

test('countLeasesForRawSource rejects a malformed rawSourceSha256', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(() => store.countLeasesForRawSource(''), /rawSourceSha256/);
    await assert.rejects(() => store.countLeasesForRawSource('not-a-hash'), /rawSourceSha256/);
  });
});

test('getMostRecentLeaseForRawSource returns null when no lease has ever been created for this document', async () => {
  await withStore(async ({ store }) => {
    assert.equal(await store.getMostRecentLeaseForRawSource('f'.repeat(64)), null);
  });
});

test('getMostRecentLeaseForRawSource returns the single lease when only one exists', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(store, expiresAt, { rawSourceSha256 });
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });

    const found = await store.getMostRecentLeaseForRawSource(rawSourceSha256);
    assert.equal(found.id, lease.id);
  });
});

test('getMostRecentLeaseForRawSource returns the LAST lease created, across multiple preflights for the same document', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);

    const firstPreflight = await createBoundPreflight(store, expiresAt, { rawSourceSha256 });
    const firstLease = await store.createLease({ preflightIds: [firstPreflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.close(firstLease.id, 'PASSED', { acquisitionId });

    // A second preflight() call for the SAME raw document mints a fresh preflightId -- its lease
    // must still be found, and as the MOST RECENT one, not the first.
    const secondPreflight = await createBoundPreflight(store, expiresAt, { rawSourceSha256 });
    const secondLease = await store.createLease({ preflightIds: [secondPreflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });

    const found = await store.getMostRecentLeaseForRawSource(rawSourceSha256);
    assert.equal(found.id, secondLease.id, 'must return the SECOND (most recent) lease, not the first');
    assert.notEqual(found.id, firstLease.id);
  });
});

test('getMostRecentLeaseForRawSource still finds the most recent lease after it has been mutated since creation', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const rawSourceSha256 = 'f'.repeat(64);
    const preflight = await createBoundPreflight(store, expiresAt, { rawSourceSha256 });
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });

    // Mutate the lease well after creation -- proves Map iteration order (insertion position) is
    // unaffected by later .set() updates to the SAME key, which this method's correctness depends on.
    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'a'.repeat(64), acquisitionId });
    await store.reconcile(job.id, { costUsd: 0.05, costKind: 'KNOWN', acquisitionId });

    const found = await store.getMostRecentLeaseForRawSource(rawSourceSha256);
    assert.equal(found.id, lease.id);
    assert.equal(found.spentUsd, 0.05, 'the returned record must be the freshest state, not a stale snapshot from creation time');
  });
});

test('getMostRecentLeaseForRawSource only finds leases for documents sharing this raw source hash, not a different document', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const rawSourceSha256A = 'f'.repeat(64);
    const rawSourceSha256B = 'a1'.repeat(32);
    const preflightA = await createBoundPreflight(store, expiresAt, { rawSourceSha256: rawSourceSha256A });
    await createBoundPreflight(store, expiresAt, { rawSourceSha256: rawSourceSha256B });
    const leaseA = await store.createLease({ preflightIds: [preflightA.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });

    const found = await store.getMostRecentLeaseForRawSource(rawSourceSha256A);
    assert.equal(found.id, leaseA.id);
    assert.equal(await store.getMostRecentLeaseForRawSource(rawSourceSha256B), null);
  });
});

test('getMostRecentLeaseForRawSource rejects a malformed rawSourceSha256', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(() => store.getMostRecentLeaseForRawSource(''), /rawSourceSha256/);
    await assert.rejects(() => store.getMostRecentLeaseForRawSource('not-a-hash'), /rawSourceSha256/);
  });
});

// findJobsForReviewerContract backs review-engine.mjs's cross-lease dispatch dedup: re-running
// authorize_workflow against the same preflightId (e.g. to correct a maxJobs mistake) mints a
// genuinely NEW lease with its own per-lease deterministic jobIds (deriveJobId(leaseId,
// reviewerId, reviewContractSha256) in review-engine.mjs), so without a cross-lease lookup an
// already-RECONCILED reviewer from a PRIOR lease is invisible to the per-lease existingJob check
// and would be silently re-dispatched (and re-charged) from scratch. This method is the
// cross-lease lookup that closes that gap: it scans every job ever
// created (any lease, any state) for one exact (reviewContractSha256, reviewerId) pair. consume()
// now persists both fields on the job record so they are queryable this way.

test('consume() persists reviewerId and reviewContractSha256 on the job record when reviewerId is supplied', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-with-reviewer', reviewerId: 'gemini', acquisitionId });
    assert.equal(job.reviewerId, 'gemini');
    assert.equal(job.reviewContractSha256, HASH);
    const fetched = await store.getJob('job-with-reviewer');
    assert.equal(fetched.reviewerId, 'gemini');
    assert.equal(fetched.reviewContractSha256, HASH);
  });
});

test('consume() still works with reviewerId omitted (backward compatible with every existing direct caller)', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-no-reviewer', acquisitionId });
    assert.equal(job.reviewerId, undefined);
    assert.equal(job.reviewContractSha256, HASH);
  });
});

test('findJobsForReviewerContract recovers only deterministically bound legacy reviewerless jobs in ledger order', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflightA = await createTwoReviewerPreflight(store, expiresAt);
    const leaseA = await store.createLease({
      preflightIds: [preflightA.id], requestedUsd: 0.40, maxJobs: 3, expiresAt, acquisitionId,
    });
    const legacyGeminiId = deriveReviewJobId(leaseA.id, 'gemini', HASH);
    const legacyGemini = await store.consume(leaseA.id, HASH, {
      reservationUsd: 0.10, jobId: legacyGeminiId, acquisitionId,
    });
    await store.reconcile(legacyGemini.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });
    const legacyGrokId = deriveReviewJobId(leaseA.id, 'grok', HASH);
    const legacyGrok = await store.consume(leaseA.id, HASH, {
      reservationUsd: 0.10, jobId: legacyGrokId, acquisitionId,
    });
    await store.reconcile(legacyGrok.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });

    const preflightB = await createTwoReviewerPreflight(store, expiresAt);
    const leaseB = await store.createLease({
      preflightIds: [preflightB.id], requestedUsd: 0.40, maxJobs: 3, expiresAt, acquisitionId,
    });
    const modernGemini = await store.consume(leaseB.id, HASH, {
      reservationUsd: 0.10, jobId: 'modern-gemini', reviewerId: 'gemini', acquisitionId,
    });
    await store.reconcile(modernGemini.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });
    const explicitConflict = await store.consume(leaseB.id, HASH, {
      reservationUsd: 0.10,
      jobId: deriveReviewJobId(leaseB.id, 'gemini', HASH),
      reviewerId: 'grok',
      acquisitionId,
    });
    await store.reconcile(explicitConflict.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });
    const unselectedLegacy = await store.consume(leaseB.id, HASH, {
      reservationUsd: 0.10,
      jobId: deriveReviewJobId(leaseB.id, 'not-selected-by-preflight', HASH),
      acquisitionId,
    });
    await store.reconcile(unselectedLegacy.id, { costUsd: 0.02, costKind: 'KNOWN', acquisitionId });

    // These impossible-through-the-public-API records model old/corrupt
    // ledger state. A lookup may never turn them into a usable legacy match:
    // it needs the job's actual lease and one selected preflight item too.
    const ledgerRoot = join(dataRoot, 'ledger');
    const missingLeaseId = 'legacy-missing-bound-lease';
    const missingPreflightLeaseId = 'legacy-missing-bound-preflight';
    const malformedLeaseId = 'legacy-malformed-bound-lease';
    const forgedTimestamp = '2026-08-17T12:09:00.000Z';
    await Promise.all([
      writeFile(join(ledgerRoot, '9999-legacy-missing-lease.json'), JSON.stringify({
        recordType: 'job', id: deriveReviewJobId(missingLeaseId, 'gemini', HASH), leaseId: missingLeaseId,
        state: 'RECONCILED', reservationUsd: 0.10, costUsd: 0.02, reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
      writeFile(join(ledgerRoot, '9999-legacy-missing-preflight-lease.json'), JSON.stringify({
        recordType: 'lease', id: missingPreflightLeaseId, state: 'ACTIVE', preflightIds: ['legacy-absent-preflight'],
        reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
      writeFile(join(ledgerRoot, '9999-legacy-missing-preflight-job.json'), JSON.stringify({
        recordType: 'job', id: deriveReviewJobId(missingPreflightLeaseId, 'gemini', HASH), leaseId: missingPreflightLeaseId,
        state: 'RECONCILED', reservationUsd: 0.10, costUsd: 0.02, reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
      writeFile(join(ledgerRoot, '9999-legacy-malformed-lease.json'), JSON.stringify({
        recordType: 'lease', id: malformedLeaseId, state: 'ACTIVE', preflightIds: 'not-an-array',
        reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
      writeFile(join(ledgerRoot, '9999-legacy-malformed-job.json'), JSON.stringify({
        recordType: 'job', id: deriveReviewJobId(malformedLeaseId, 'gemini', HASH), leaseId: malformedLeaseId,
        state: 'RECONCILED', reservationUsd: 0.10, costUsd: 0.02, reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
    ]);

    assert.deepEqual(
      (await store.findJobsForReviewerContract(HASH, 'gemini')).map((job) => job.id),
      [legacyGemini.id, modernGemini.id],
      'legacy deterministic and modern exact matches retain ledger order; explicit/malformed alternatives do not match gemini',
    );
    assert.deepEqual(
      (await store.findJobsForReviewerContract(HASH, 'grok')).map((job) => job.id),
      [legacyGrok.id, explicitConflict.id],
      'a stored reviewerId remains an exact, unchanged match even when its id would derive to another reviewer',
    );
    assert.deepEqual(
      await store.findJobsForReviewerContract(HASH, 'not-selected-by-preflight'),
      [],
      'a reviewerless deterministic id is insufficient when its own preflight never selected that reviewer',
    );
  });
});

test('findJobsForReviewerContract does not recover a reviewerless legacy job selected only by a later preflight', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const firstPreflight = await createBoundPreflight(store, expiresAt);
    const laterPreflight = await store.createPreflight({
      reviewContractSha256: HASH,
      sourceSha256: 'b'.repeat(64),
      rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1',
      profileVersion: '1',
      schemaSha256: 'c'.repeat(64),
      registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-grok', maxUsd: 0.20 }],
      requestedUsd: 0.20,
      expiresAt,
    });

    // Multi-preflight leases are impossible through createLease(), but a legacy/corrupt ledger can
    // contain one. The later preflight selecting grok must not make a reviewerless job look bound:
    // legacy discovery trusts only the first selected preflight.
    const leaseId = 'legacy-later-preflight-lease';
    const forgedTimestamp = '2026-08-17T12:09:00.000Z';
    await Promise.all([
      writeFile(join(dataRoot, 'ledger', '9999-legacy-later-preflight-lease.json'), JSON.stringify({
        recordType: 'lease', id: leaseId, state: 'ACTIVE',
        preflightIds: [firstPreflight.id, laterPreflight.id],
        reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
      writeFile(join(dataRoot, 'ledger', '9999-legacy-later-preflight-job.json'), JSON.stringify({
        recordType: 'job', id: deriveReviewJobId(leaseId, 'grok', HASH), leaseId,
        state: 'RECONCILED', reservationUsd: 0.10, costUsd: 0.02,
        reviewContractSha256: HASH, timestamp: forgedTimestamp,
      }), 'utf8'),
    ]);

    assert.deepEqual(
      await store.findJobsForReviewerContract(HASH, 'grok'),
      [],
      'a later preflight cannot establish a reviewerless legacy binding',
    );
  });
});

test('findJobsForReviewerContract finds a job across a DIFFERENT lease for the same (contract, reviewer) pair', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflightA = await createBoundPreflight(store, expiresAt);
    const leaseA = await store.createLease({ preflightIds: [preflightA.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    const jobA = await store.consume(leaseA.id, HASH, { reservationUsd: 0.10, jobId: 'job-a', reviewerId: 'gemini', acquisitionId });
    await store.reconcile(jobA.id, { costUsd: 0.08, costKind: 'KNOWN', acquisitionId });

    assert.equal(await store.findJobsForReviewerContract(HASH, 'gemini').then((jobs) => jobs.length), 1);
    const [found] = await store.findJobsForReviewerContract(HASH, 'gemini');
    assert.equal(found.id, 'job-a');
    assert.equal(found.leaseId, leaseA.id);
    assert.equal(found.state, 'RECONCILED');
    assert.equal(found.costUsd, 0.08);

    // A SECOND, independent lease for the same document (mirroring a
    // re-authorize-with-a-different-maxJobs recovery) also shows up once it reserves its own job
    // for the same reviewer+contract pair -- the whole point is finding it BEFORE it reconciles,
    // while it's still ambiguous.
    const preflightB = await createBoundPreflight(store, expiresAt);
    const leaseB = await store.createLease({ preflightIds: [preflightB.id], requestedUsd: 0.20, maxJobs: 2, expiresAt, acquisitionId });
    await store.consume(leaseB.id, HASH, { reservationUsd: 0.10, jobId: 'job-b', reviewerId: 'gemini', acquisitionId });

    const both = await store.findJobsForReviewerContract(HASH, 'gemini');
    assert.equal(both.length, 2);
    assert.deepEqual(both.map((job) => job.id).sort(), ['job-a', 'job-b']);
  });
});

test('findJobsForReviewerContract only matches the exact (reviewContractSha256, reviewerId) pair, not a different reviewer or a different contract', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 2, expiresAt, acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-gemini', reviewerId: 'gemini', acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.10, jobId: 'job-grok', reviewerId: 'grok', acquisitionId });

    assert.deepEqual((await store.findJobsForReviewerContract(HASH, 'gemini')).map((job) => job.id), ['job-gemini']);
    assert.deepEqual((await store.findJobsForReviewerContract(HASH, 'grok')).map((job) => job.id), ['job-grok']);

    const otherHash = 'f'.repeat(64);
    assert.deepEqual(await store.findJobsForReviewerContract(otherHash, 'gemini'), []);
  });
});

test('findJobsForReviewerContract returns an empty array when nothing matches', async () => {
  await withStore(async ({ store }) => {
    assert.deepEqual(await store.findJobsForReviewerContract(HASH, 'gemini'), []);
  });
});

test('findJobsForReviewerContract rejects a malformed reviewContractSha256 or reviewerId', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(() => store.findJobsForReviewerContract('not-a-hash', 'gemini'), /reviewContractSha256/);
    await assert.rejects(() => store.findJobsForReviewerContract(HASH, ''), /reviewerId/);
  });
});

// A worst-case charge, once persisted with no way to say WHICH kind of figure it is, is
// indistinguishable from a genuine confirmed cost to anything reading the ledger later. Most
// transport failures reconcile at zero, but UNKNOWN_COST/DISPATCH_UNKNOWN/RESPONSE_READ_FAILED/
// INTERNAL_ERROR are still charged the worst case, so the kind of figure must be durable too.
// costKind is required (never silently defaulted) so every call site must be explicit, matching
// this file's own no-silent-defaults convention (requireUsd, requireHash, etc.).
test('reconcile requires a valid costKind and persists it on the job record', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 3, expiresAt, acquisitionId });

    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.06, jobId: 'known-job', acquisitionId });
    await assert.rejects(() => store.reconcile(job.id, { costUsd: 0.05, acquisitionId }), /costKind/);
    await assert.rejects(() => store.reconcile(job.id, { costUsd: 0.05, costKind: 'GUESS', acquisitionId }), /costKind/);

    const reconciled = await store.reconcile(job.id, { costUsd: 0.05, costKind: 'KNOWN', acquisitionId });
    assert.equal(reconciled.costKind, 'KNOWN');
    assert.equal((await store.getJob(job.id)).costKind, 'KNOWN');

    const worstCaseJob = await store.consume(lease.id, HASH, { reservationUsd: 0.06, jobId: 'worst-case-job', acquisitionId });
    const reconciledWorstCase = await store.reconcile(worstCaseJob.id, { costUsd: 0.06, costKind: 'UNKNOWN_WORST_CASE_CHARGED', acquisitionId });
    assert.equal(reconciledWorstCase.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal((await store.getJob(worstCaseJob.id)).costKind, 'UNKNOWN_WORST_CASE_CHARGED');

    // The zero-cost transport-failure classification (review-engine.mjs's ZERO_COST_TRANSPORT_FAILURE_KINDS)
    // is a distinct, genuinely-known-to-be-zero cost -- not the same as an arbitrary KNOWN cost from
    // a validated response, so it gets its own persisted costKind rather than being folded into KNOWN.
    const zeroJob = await store.consume(lease.id, HASH, { reservationUsd: 0.06, jobId: 'zero-cost-job', acquisitionId });
    const reconciledZero = await store.reconcile(zeroJob.id, { costUsd: 0, costKind: 'ZERO_ON_TRANSPORT_FAILURE', acquisitionId });
    assert.equal(reconciledZero.costKind, 'ZERO_ON_TRANSPORT_FAILURE');
    assert.equal((await store.getJob(zeroJob.id)).costKind, 'ZERO_ON_TRANSPORT_FAILURE');
  });
});

// Closes the "KNOWN IMPRECISION" gap review-engine.mjs's own existingJob recovery docstring
// describes: a job reconciled via a genuine haltAndClose() halt (e.g. PROVIDER_MISMATCH) and a job
// reconciled via processDispatchOutcome's clean-pass branch that then crashed before recording its
// own content are both RECONCILED/KNOWN/costUsd>0 with nothing recoverable -- indistinguishable by
// the ledger's other fields alone. haltReason is the minimal, durable marker that tells them apart:
// present only for a genuine halt, absent (never a bare empty string) for a genuine clean-pass
// reconcile, whether or not its own later content-write actually completed.
test('reconcile accepts and persists an optional haltReason, distinct from costKind', async () => {
  await withStore(async ({ store }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 3, expiresAt, acquisitionId });

    // Omitted entirely -- the genuine clean-pass shape. JSON.stringify drops the undefined key,
    // matching consume()'s own established convention for an omitted reviewerId.
    const cleanJob = await store.consume(lease.id, HASH, { reservationUsd: 0.05, jobId: 'clean-job', acquisitionId });
    const reconciledClean = await store.reconcile(cleanJob.id, { costUsd: 0.05, costKind: 'KNOWN', acquisitionId });
    assert.equal(reconciledClean.haltReason, undefined);
    assert.equal((await store.getJob(cleanJob.id)).haltReason, undefined);

    // A real halt code, persisted and read back exactly -- including through a fresh getJob() call,
    // which replays the whole ledger from disk (mutate()'s own replay() call), so this also proves
    // durability, not just an in-memory echo.
    const haltedJob = await store.consume(lease.id, HASH, { reservationUsd: 0.05, jobId: 'halted-job', acquisitionId });
    const reconciledHalt = await store.reconcile(haltedJob.id, { costUsd: 0.05, costKind: 'KNOWN', haltReason: 'PROVIDER_MISMATCH', acquisitionId });
    assert.equal(reconciledHalt.haltReason, 'PROVIDER_MISMATCH');
    assert.equal((await store.getJob(haltedJob.id)).haltReason, 'PROVIDER_MISMATCH');

    const badJob = await store.consume(lease.id, HASH, { reservationUsd: 0.05, jobId: 'bad-job', acquisitionId });
    await assert.rejects(() => store.reconcile(badJob.id, { costUsd: 0.05, costKind: 'KNOWN', haltReason: '', acquisitionId }), /haltReason/);
    await assert.rejects(() => store.reconcile(badJob.id, { costUsd: 0.05, costKind: 'KNOWN', haltReason: 123, acquisitionId }), /haltReason/);
  });
});

test('sweepOrphanedLeases marks every recovered job UNKNOWN_WORST_CASE_CHARGED, since the true outcome is never known by construction', async () => {
  await withStore(async ({ store, advance }) => {
    const { acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const expiresAt = '2026-08-17T12:10:00.000Z';
    const preflight = await createBoundPreflight(store, expiresAt);
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1, expiresAt, acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.15, jobId: 'orphaned-job', acquisitionId });

    advance(Date.parse(expiresAt) - Date.parse('2026-08-17T12:00:00.000Z') + 200_000);
    const results = await store.sweepOrphanedLeases({ leaseId: lease.id, staleAfterMs: 120_000, acquisitionId });

    assert.equal(results[0].reconciledJobs[0].costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal((await store.getJob('orphaned-job')).costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  });
});

test('processOwner: a fresh ACQUIRED record with generation 1 is accepted and becomes currentOwner', async () => {
  await withStore(async ({ store, dataRoot }) => {
    // currentOwner has no direct public accessor, so
    // assert indirectly via a second replay() over the same ledger succeeding cleanly,
    // proving the record round-trips through applyRecord()/replay() without throwing.
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const record = {
      recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 1,
      acquisitionId: randomUUID(), timestamp: '2026-09-03T00:00:00.000Z',
    };
    await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-seed.json'), `${JSON.stringify(record)}\n`, 'utf8');
    // A subsequent store operation triggers replay() internally; it must not throw.
    await store.createPreflight({
      reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
    });
  });
});

test('processOwner: an ACQUIRED record with a generation that is not exactly highestSeen+1 fails replay() closed', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const record = {
      recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 2,
      acquisitionId: randomUUID(), timestamp: '2026-09-03T00:00:00.000Z',
    };
    await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-seed.json'), `${JSON.stringify(record)}\n`, 'utf8');
    await assert.rejects(
      store.createPreflight({
        reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
        profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
        itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
      }),
      /generation/,
    );
  });
});

test('processOwner: a RELEASED record whose acquisitionId does not match the tracked ACQUIRED record fails replay() closed', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const acquired = {
      recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 1,
      acquisitionId: randomUUID(), timestamp: '2026-09-03T00:00:00.000Z',
    };
    const released = {
      recordType: 'processOwner', state: 'RELEASED', pid: 1234, generation: 1,
      acquisitionId: randomUUID(), timestamp: '2026-09-03T00:00:01.000Z',
    };
    await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-a.json'), `${JSON.stringify(acquired)}\n`, 'utf8');
    await writeFile(join(ledgerRoot, '2026-09-03T00-00-01-000Z-b.json'), `${JSON.stringify(released)}\n`, 'utf8');
    await assert.rejects(
      store.createPreflight({
        reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
        profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
        itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
      }),
      /does not match/,
    );
  });
});

test('processOwner: a clean ACQUIRED -> RELEASED -> ACQUIRED(gen 2) sequence with fresh acquisitionIds each time is accepted', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const idOne = randomUUID();
    const idTwo = randomUUID();
    const records = [
      { recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 1, acquisitionId: idOne, timestamp: '2026-09-03T00:00:00.000Z' },
      { recordType: 'processOwner', state: 'RELEASED', pid: 1234, generation: 1, acquisitionId: idOne, timestamp: '2026-09-03T00:00:01.000Z' },
      { recordType: 'processOwner', state: 'ACQUIRED', pid: 5678, generation: 2, acquisitionId: idTwo, timestamp: '2026-09-03T00:00:02.000Z' },
    ];
    for (const [index, record] of records.entries()) {
      await writeFile(join(ledgerRoot, `2026-09-03T00-00-0${index}-000Z-r.json`), `${JSON.stringify(record)}\n`, 'utf8');
    }
    await store.createPreflight({
      reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
    });
  });
});

test('processOwner: an ACQUIRED record reusing a previously-seen acquisitionId fails replay() closed', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const reused = randomUUID();
    const records = [
      { recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 1, acquisitionId: reused, timestamp: '2026-09-03T00:00:00.000Z' },
      { recordType: 'processOwner', state: 'RELEASED', pid: 1234, generation: 1, acquisitionId: reused, timestamp: '2026-09-03T00:00:01.000Z' },
      { recordType: 'processOwner', state: 'ACQUIRED', pid: 5678, generation: 2, acquisitionId: reused, timestamp: '2026-09-03T00:00:02.000Z' },
    ];
    for (const [index, record] of records.entries()) {
      await writeFile(join(ledgerRoot, `2026-09-03T00-00-0${index}-000Z-r.json`), `${JSON.stringify(record)}\n`, 'utf8');
    }
    await assert.rejects(
      store.createPreflight({
        reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
        profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
        itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
      }),
      /acquisitionId/,
    );
  });
});

test('processOwner: a malformed record (bad pid, bad state, bad generation, bad acquisitionId, bad timestamp) each fail replay() closed', async () => {
  const bad = [
    { pid: -1, state: 'ACQUIRED', generation: 1, acquisitionId: UUID_ONES, timestamp: '2026-09-03T00:00:00.000Z' },
    { pid: 1234, state: 'SOMETHING_ELSE', generation: 1, acquisitionId: UUID_ONES, timestamp: '2026-09-03T00:00:00.000Z' },
    { pid: 1234, state: 'ACQUIRED', generation: 0, acquisitionId: UUID_ONES, timestamp: '2026-09-03T00:00:00.000Z' },
    { pid: 1234, state: 'ACQUIRED', generation: 1, acquisitionId: 'not-a-uuid', timestamp: '2026-09-03T00:00:00.000Z' },
    { pid: 1234, state: 'ACQUIRED', generation: 1, acquisitionId: UUID_ONES, timestamp: 'not-a-real-timestamp' },
  ];
  for (const fields of bad) {
    await withStore(async ({ store, dataRoot }) => {
      const ledgerRoot = join(dataRoot, 'ledger');
      await mkdir(ledgerRoot, { recursive: true });
      const record = { recordType: 'processOwner', ...fields };
      await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-bad.json'), `${JSON.stringify(record)}\n`, 'utf8');
      await assert.rejects(store.createPreflight({
        reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
        profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
        itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
      }));
    });
  }
});

test('processOwner: a RELEASED record whose generation or pid mismatches the tracked ACQUIRED record fails replay() closed (distinct from the acquisitionId-mismatch case above)', async () => {
  const mismatches = [
    { field: 'generation', released: { generation: 2 } },
    { field: 'pid', released: { pid: 9999 } },
  ];
  for (const { released } of mismatches) {
    await withStore(async ({ store, dataRoot }) => {
      const { randomUUID } = await import('node:crypto');
      const ledgerRoot = join(dataRoot, 'ledger');
      await mkdir(ledgerRoot, { recursive: true });
      const acquisitionId = randomUUID();
      const acquired = {
        recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 1,
        acquisitionId, timestamp: '2026-09-03T00:00:00.000Z',
      };
      const releasedRecord = {
        recordType: 'processOwner', state: 'RELEASED', pid: 1234, generation: 1,
        acquisitionId, timestamp: '2026-09-03T00:00:01.000Z', ...released,
      };
      await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-a.json'), `${JSON.stringify(acquired)}\n`, 'utf8');
      await writeFile(join(ledgerRoot, '2026-09-03T00-00-01-000Z-b.json'), `${JSON.stringify(releasedRecord)}\n`, 'utf8');
      await assert.rejects(
        store.createPreflight({
          reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
          profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
          itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
        }),
        /does not match/,
      );
    });
  }
});

test('processOwner: a recordType that is a near-miss typo is silently unrecognized and never affects ownership', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const record = {
      recordType: 'proccessOwner', state: 'ACQUIRED', pid: 1234, generation: 999,
      acquisitionId: randomUUID(), timestamp: '2026-09-03T00:00:00.000Z',
    };
    await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-typo.json'), `${JSON.stringify(record)}\n`, 'utf8');
    // Must not throw -- an unrecognized recordType is inert, exactly like every other record type.
    await store.createPreflight({
      reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
    });
  });
});

test('processOwner: replay() resets currentOwner/generation/seenAcquisitionIds before rebuilding, not retaining stale state', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const { randomUUID } = await import('node:crypto');
    const ledgerRoot = join(dataRoot, 'ledger');
    await mkdir(ledgerRoot, { recursive: true });
    const record = {
      recordType: 'processOwner', state: 'ACQUIRED', pid: 1234, generation: 1,
      acquisitionId: randomUUID(), timestamp: '2026-09-03T00:00:00.000Z',
    };
    await writeFile(join(ledgerRoot, '2026-09-03T00-00-00-000Z-r.json'), `${JSON.stringify(record)}\n`, 'utf8');
    // First operation replays and accepts it.
    await store.createPreflight({
      reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
    });
    // A second operation triggers a second replay() over the SAME ledger (generation 1 record
    // still present) -- if highestOwnerGeneration were not reset, this would still work fine
    // (no new ACQUIRED record is being validated here), so this test instead proves reset
    // indirectly: a second ACQUIRED(gen:1) record would be rejected as a generation collision
    // if state leaked across replays cumulatively rather than resetting -- but since we only
    // ever see ONE gen:1 record here across two replays, the real proof is that this succeeds
    // twice without accumulating a phantom "already at generation 1" state that would reject
    // gen:1 the second time as "not gen 2". This documents the reset contract directly.
    await store.createPreflight({
      reviewContractSha256: HASH, sourceSha256: 'b'.repeat(64), rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1', profileVersion: '1', schemaSha256: 'c'.repeat(64), registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini2', maxUsd: 0.20 }], requestedUsd: 0.20, expiresAt: '2026-09-03T01:00:00.000Z',
    });
  });
});

test('acquireProcessOwnership: a fresh acquire (no prior record) succeeds immediately with generation 1', async () => {
  await withStore(async ({ store }) => {
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    assert.equal(handle.generation, 1);
    assert.equal(typeof handle.acquisitionId, 'string');
    assert.equal(handle.isOwner(), true);
  });
});

test('acquireProcessOwnership: acquiring against a live, non-stale owner refuses and retries until the caller wins', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let now = Date.parse('2026-09-03T00:00:00.000Z');
    let alive = true;
    // lockStaleMs is deliberately small (50ms, not this file's usual 60_000 default) so this
    // test proves the same property -- refuse-while-live, then refuse-a-few-more-times-while-
    // dead-but-not-yet-stale, then eventually reclaim -- without needing ~12,000 real 5ms retry
    // round trips (measured at ~32s wall time against the original 60_000 value) to simulate
    // enough elapsed time for staleness to kick in. 50ms sits comfortably above the 30ms
    // alive-flip threshold below, so several genuine NOT_YET_STALE refusals still happen after
    // `alive` flips false, proving the staleness gate does real work rather than reclaiming on
    // the very next check.
    const store = createLeaseStore({
      dataRoot, clock: () => now, lockRetryMs: 5, lockStaleMs: 50,
      isProcessAlive: () => alive,
      monotonicNow: () => now,
      sleep: async (ms) => { now += ms; if (now > Date.parse('2026-09-03T00:00:00.030Z')) alive = false; },
    });
    const first = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    assert.equal(first.generation, 1);
    // Second store, same data root, same process pid -- simulates the SAME process
    // attempting a second acquisition while the first is still alive; sleep() flips
    // `alive` to false partway through so this proves refuse-then-eventually-reclaim,
    // not "acquire always wins."
    const second = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    assert.equal(second.generation, 2);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('acquireProcessOwnership: a dead-but-not-yet-stale owner still refuses (staleness window respected)', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let now = Date.parse('2026-09-03T00:00:00.000Z');
    const store = createLeaseStore({
      dataRoot, clock: () => now, lockRetryMs: 5, lockStaleMs: 60_000,
      isProcessAlive: () => false,
      monotonicNow: () => now,
      sleep: async (ms) => { now += ms; },
    });
    await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    // Not yet stale (< lockStaleMs elapsed) -- must still refuse until acquireTimeoutMs
    // itself is exhausted, proving staleness (not just liveness) gates reclaim.
    await assert.rejects(
      store.acquireProcessOwnership({ acquireTimeoutMs: 50 }),
      /timed out/,
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('acquireProcessOwnership: a dead+stale owner reclaims with a bumped generation and a fresh acquisitionId', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let now = Date.parse('2026-09-03T00:00:00.000Z');
    const store = createLeaseStore({
      dataRoot, clock: () => now, lockRetryMs: 5, lockStaleMs: 100,
      isProcessAlive: () => false,
      monotonicNow: () => now,
      sleep: async (ms) => { now += ms; },
    });
    const first = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    now += 200; // past lockStaleMs
    const second = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    assert.equal(second.generation, 2);
    assert.notEqual(second.acquisitionId, first.acquisitionId);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('acquireProcessOwnership: called without acquireTimeoutMs throws a validation error, not a silent default', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(store.acquireProcessOwnership({}), TypeError);
    await assert.rejects(store.acquireProcessOwnership(), TypeError);
  });
});

test('acquireProcessOwnership: an attempt already in progress when acquireTimeoutMs elapses is allowed to finish; no new attempt starts after', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let monotonic = 0;
    let attemptCount = 0;
    const store = createLeaseStore({
      dataRoot, clock: () => Date.parse('2026-09-03T00:00:00.000Z'), lockRetryMs: 5, lockStaleMs: 0,
      // Counts every attempt AND controls its outcome: the first three report a LIVE owner
      // (forcing refuse-and-retry) -- attempts starting at monotonic 0, 10, 20, then sleep()
      // pushing monotonic to 30, past this test's 25ms deadline. The FOURTH call would report
      // the owner dead, and lockStaleMs:0 makes a dead owner instantly reclaimable -- so if a 4th
      // attempt were ever STARTED, it would succeed (reclaim) rather than time out. Counting
      // calls proves whether that 4th attempt actually starts.
      isProcessAlive: () => { attemptCount += 1; return attemptCount <= 3; },
      monotonicNow: () => monotonic,
      sleep: async () => { monotonic += 10; },
    });
    // Seed a live owner (via a separate, default-timed store over the same ledger) so every
    // attempt against `store` reaches the isProcessAlive check above, instead of taking the
    // null-owner fresh-acquire branch.
    const seedStore = createLeaseStore({ dataRoot, clock: () => Date.parse('2026-09-03T00:00:00.000Z') });
    await seedStore.acquireProcessOwnership({ acquireTimeoutMs: 1000 });

    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 25 }), /timed out/);
    // PROVES no new attempt starts once the deadline is crossed: exactly 3 attempts (at
    // monotonic 0, 10, 20) must run before sleep() pushes monotonic to 30 and the pre-attempt
    // deadline check stops a 4th from ever starting. Without that check, this exact setup lets a
    // 4th attempt start at monotonic 30, see isProcessAlive() report a dead owner, and
    // successfully reclaim -- resolving instead of rejecting, with attemptCount left at 4.
    assert.equal(attemptCount, 3, 'a 4th mutate() attempt must never start once the deadline has passed');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('acquireProcessOwnership: concurrent attempts against one store -- exactly one wins per round, generations strictly increase with no duplicates', async () => {
  // A real two-process race can't be reproduced in one test process (both callers would
  // genuinely share process.pid, so a naive Promise.all of two acquisitions can only ever
  // produce ONE winner: whoever's mutate() call runs first wins the next generation, and the
  // second caller's own mutate() call then sees a LIVE (same-pid) owner and refuses forever,
  // since nothing ever releases that generation while the second call is still waiting. This
  // test instead proves the property the design actually guarantees under real concurrency --
  // serialized mutate() calls, exactly-one-winner-per-round, strictly increasing generations, no
  // duplicate acquisitionIds -- by having each contender treat the PRIOR round's owner as dead
  // (isProcessAlive: () => false) so every concurrently-issued acquireProcessOwnership call
  // can genuinely succeed in turn as the ledger lock serializes their mutate() calls one after
  // another, rather than the second one blocking forever on a same-pid liveness check that
  // real cross-process concurrency would never hit this way.
  //
  // Configuration rationale: lockStaleMs is a SINGLE constructor knob shared by two unrelated
  // staleness checks -- acquireProcessOwnership()'s own ownership-record staleness gate (what
  // this test wants to control) AND acquireDataRootLock()'s OWN internal check for whether the
  // LEDGER'S mkdir-based mutex itself looks abandoned. Setting it to 0 with a FIXED clock does
  // not just make the former trivially satisfied -- it ALSO makes the latter trivially
  // satisfied, so a contender that loses the very first mkdir() race treats the WINNER'S
  // freshly-created, still-actively-held lock as instantly abandoned and tries to reclaim it out
  // from under the winner, mid operation. That is the three/four-writer crash-recovery residual
  // documented on acquireDataRootLock(), forced to occur on EVERY contention event; it shows up
  // as intermittent `ENOTEMPTY` rmdir races and genuine mutual-exclusion violations (two callers
  // both computing and writing the same next generation).
  //
  // So this test uses a real clock (`Date.now()`, so real elapsed time accrues between rounds)
  // + a small nonzero lockStaleMs (30ms -- comfortably above the sub-10ms a single mutate()
  // cycle takes even under contention on this test's own temp directory, so a genuinely
  // still-active lock is never mistaken for stale) + lockRetryMs (5ms) small enough that real
  // elapsed time crosses that 30ms threshold within a handful of retries. Contention is kept at
  // 2-way per round as a deliberate safety margin: token-gating already closes the
  // "two/three-writer" release-deletion case, but a narrower residual risk specifically for
  // THREE OR FOUR simultaneous crash-recovery reclaims is documented on acquireDataRootLock() as
  // accepted, so this test does not try to prove itself safe against that separate, known
  // limitation. Two sequential rounds still prove the strictly-increasing-generations property
  // across multiple contested rounds.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const store = createLeaseStore({
      dataRoot, clock: () => Date.now(),
      lockRetryMs: 5, lockStaleMs: 30, isProcessAlive: () => false,
    });
    const roundOne = await Promise.all([
      store.acquireProcessOwnership({ acquireTimeoutMs: 5000 }),
      store.acquireProcessOwnership({ acquireTimeoutMs: 5000 }),
    ]);
    const roundTwo = await Promise.all([
      store.acquireProcessOwnership({ acquireTimeoutMs: 5000 }),
      store.acquireProcessOwnership({ acquireTimeoutMs: 5000 }),
    ]);
    const results = [...roundOne, ...roundTwo];
    const generations = results.map((r) => r.generation).sort((a, b) => a - b);
    assert.deepEqual(generations, [1, 2, 3, 4]);
    const acquisitionIds = new Set(results.map((r) => r.acquisitionId));
    assert.equal(acquisitionIds.size, 4);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('release(): isOwner() returns false immediately after release(), with no I/O needed to check it', async () => {
  await withStore(async ({ store }) => {
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    assert.equal(handle.isOwner(), true);
    await handle.release();
    assert.equal(handle.isOwner(), false);
  });
});

test('release(): a clean RELEASED record lets the next acquire skip the stale-wait entirely', async () => {
  await withStore(async ({ store }) => {
    const first = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    await first.release();
    // acquireTimeoutMs deliberately far shorter than any staleness window this test would
    // otherwise need -- if release() didn't actually clear ownership, this would time out.
    const second = await store.acquireProcessOwnership({ acquireTimeoutMs: 50 });
    assert.equal(second.generation, 2);
  });
});

test('release(): two concurrent release() calls join and await the SAME operation; only one RELEASED record is ever appended', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const [a, b] = await Promise.all([handle.release(), handle.release()]);
    assert.equal(a, b);
    const names = (await readdir(join(dataRoot, 'ledger'))).filter((n) => n.endsWith('.json'));
    let releasedCount = 0;
    for (const name of names) {
      const record = JSON.parse(await readFile(join(dataRoot, 'ledger', name), 'utf8'));
      if (record.recordType === 'processOwner' && record.state === 'RELEASED') releasedCount += 1;
    }
    assert.equal(releasedCount, 1);
  });
});

// The "only one RELEASED record is ever appended" assertion above does NOT, on its own, distinguish genuine single-flight promise-joining from two independently
// completed mutate() cycles that merely happen to agree on the ledger content, because the second
// cycle's own compare-and-set check (currentOwner.state is already RELEASED by the time it runs)
// would ALSO produce exactly one RELEASED record even with the memoization removed entirely (see
// the note directly below the test). renameImpl is the seam that tells the two apart: it is called
// by acquireDataRootLock()'s own physical-lock-release rename on EVERY mutate() cycle (success or
// not), and NEVER by append()'s own ledger-record rename (that one imports `rename` directly, with
// no constructor override -- see the "release() call that fails once" test's own comment on this
// exact distinction). So counting renameImpl invocations counts mutate() CYCLES, independent of
// what each cycle decided to write.
test('release(): two concurrent release() calls share exactly ONE mutate() cycle, not two independently-deduped ones', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let lockReleaseRenames = 0;
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-09-04T00:00:00.000Z'),
      renameImpl: async (from, to) => {
        lockReleaseRenames += 1;
        return rename(from, to);
      },
    });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    lockReleaseRenames = 0; // ignore the acquire's own lock-lifecycle rename
    await Promise.all([handle.release(), handle.release()]);
    assert.equal(
      lockReleaseRenames, 2,
      'two concurrent release() calls on the same handle must share exactly one mutate() cycle, which '
      + 'itself performs exactly two renames (the data-root lock\'s own atomic acquire-publish '
      + 'plus the release rename) -- '
      + 'if this were 4, single-flight memoization was bypassed even though the ledger content '
      + 'backstop alone would still have produced only one RELEASED record',
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});
// Disabling buildOwnerHandle()'s `if (!releasePromise)` memoization (every release() call starts a
// fresh mutate() cycle) makes this test fail with `4 !== 2` -- two independent mutate() cycles, two
// renames each -- while the older "only one RELEASED record is ever appended" test stays green,
// which is why that older test alone cannot tell genuine single-flight joining apart from two
// independently-completed cycles that agree via the compare-and-set backstop.

test('release(): against a generation a successor has already superseded is a no-op (compare-and-set refuses the stale write)', async () => {
  await withStore(async ({ store }) => {
    const first = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    await first.release();
    const second = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    // first's handle is stale now -- releasing it must not disturb second's live ownership.
    await first.release();
    assert.equal(second.isOwner(), true);
  });
});

// The test above provides ZERO regression protection for release()'s compare-and-set guard. Its
// second `first.release()` call never re-enters mutate() at all -- buildOwnerHandle()'s own
// single-flight memoization (`releasePromise` already resolved from the FIRST, legitimate
// release() call) short-circuits it before the compare-and-set logic is ever reached again, so it
// stays green even with the whole compare-and-set guard deleted (see the note directly below this
// test). The scenario the safety property is actually
// about -- a handle superseded by a successor's STALE RECLAIM, never released by its own call --
// is exercised here instead: `first` never calls release() before `second` reclaims via the
// existing dead+stale path (same shape as the "acquireProcessOwnership: a dead+stale owner
// reclaims..." test above), so this IS first's first-ever release() call, and it genuinely reaches
// the currentOwner.acquisitionId !== acquisitionId branch. This guard is what makes a conflicting
// RELEASED record bricking replay() structurally unreachable, not just less likely, so it is
// load-bearing for the whole ownership design.
test('release(): a handle superseded by a genuine stale reclaim (never released by its own call) writes NO conflicting record and disturbs nothing', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let now = Date.parse('2026-09-04T00:00:00.000Z');
    const store = createLeaseStore({
      dataRoot, clock: () => now, lockRetryMs: 5, lockStaleMs: 100,
      isProcessAlive: () => false,
      monotonicNow: () => now,
      sleep: async (ms) => { now += ms; },
    });
    const first = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    // Snapshotted here, before first.release() below: a released handle's acquisitionId reads
    // null, and comparing ledger records against null would let the "no RELEASED record for
    // first" check further down pass whatever the ledger held.
    const firstAcquisitionId = first.acquisitionId;
    now += 200; // past lockStaleMs -- first now looks dead+stale to a new acquirer
    const second = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
    assert.equal(second.generation, 2);
    assert.notEqual(second.acquisitionId, first.acquisitionId, 'second reclaimed via staleness, not via first.release()');

    const recordsBefore = (await readdir(join(dataRoot, 'ledger'))).filter((n) => n.endsWith('.json'));

    // THE ACTUAL TRACE: first's own FIRST-EVER release() call, against a handle a successor has
    // already superseded via reclaim (not via first's own release()).
    await first.release();

    const recordsAfter = (await readdir(join(dataRoot, 'ledger'))).filter((n) => n.endsWith('.json'));
    assert.equal(recordsAfter.length, recordsBefore.length, 'releasing a superseded handle must append ZERO new ledger records');
    assert.equal(second.isOwner(), true, 'the live successor must be completely undisturbed');

    // Confirm no RELEASED record was ever written for first's own acquisitionId, and second's own
    // ACQUIRED record is untouched.
    let releasedForFirst = 0;
    let secondsAcquiredIntact = false;
    for (const name of recordsAfter) {
      const record = JSON.parse(await readFile(join(dataRoot, 'ledger', name), 'utf8'));
      if (record.recordType !== 'processOwner') continue;
      if (record.acquisitionId === firstAcquisitionId && record.state === 'RELEASED') releasedForFirst += 1;
      if (record.acquisitionId === second.acquisitionId && record.state === 'ACQUIRED') secondsAcquiredIntact = true;
    }
    assert.equal(releasedForFirst, 0, 'a superseded handle must NEVER write a RELEASED record for its own acquisitionId');
    assert.equal(secondsAcquiredIntact, true);

    // A fresh store replaying the same on-disk ledger must not throw -- proving no conflicting
    // record was written that could violate applyProcessOwnerRecord()'s strict transition table
    // (the "bricked replay" failure mode).
    const fresh = createLeaseStore({ dataRoot, clock: () => now });
    await fresh.getLease('force-a-replay-only');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});
// Making release()'s guard `if (currentOwner !== null && currentOwner.state === 'ACQUIRED' &&
// currentOwner.acquisitionId === acquisitionId)` unconditional (see lease-store.mjs,
// buildOwnerHandle()) fails the test above at its "releasing a superseded handle must append ZERO
// new ledger records" assertion: the stale handle's release() appends a spurious RELEASED record
// stamped with SECOND's own pid/generation/acquisitionId (since currentOwner at that point IS
// second's tracked ACQUIRED record), which applyProcessOwnerRecord() accepts as a valid transition
// FOR SECOND -- silently flipping the ledger's live owner to RELEASED out from under a
// still-active second, whose own in-memory isOwner() flag has no way to know that happened. The
// weaker "against a generation a successor has already superseded" test stays green under the
// same change, which is why this test exists.

test('release(): a release() call that fails once genuinely retries and can succeed on a later call', async () => {
  // renameImpl only affects acquireDataRootLock's own physical lock-directory rename, never
  // append()'s own rename() call (append() imports `rename` directly, with no
  // constructor-level override) -- so a failure injected through renameImpl would never reach
  // release()'s own processOwner append.
  // beforeAtomicRename is the right seam: it fires immediately before append()'s own
  // rename() for every record, so failing it precisely for the RELEASED record (and no
  // other) genuinely makes release()'s append throw.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    let failNextRelease = false;
    const store = createLeaseStore({
      dataRoot,
      clock: () => Date.parse('2026-09-03T00:00:00.000Z'),
      beforeAtomicRename: async (record) => {
        if (failNextRelease && record.recordType === 'processOwner' && record.state === 'RELEASED') {
          failNextRelease = false;
          throw Object.assign(new Error('simulated append failure'), { code: 'EPERM' });
        }
      },
    });
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 }); // ACQUIRED append succeeds normally
    failNextRelease = true;
    await assert.rejects(handle.release(), /simulated append failure/);
    assert.equal(handle.isOwner(), true, 'a failed release() must not report success');
    // The memo was cleared on failure (see release()'s own catch block), so this is a
    // genuine retry, not a cached rejected promise -- and it succeeds now that
    // failNextRelease is false again.
    await handle.release();
    assert.equal(handle.isOwner(), false);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// Inline ownership fencing on the 5 owner-sensitive writes (createLease, consume, reconcile,
// close, sweepOrphanedLeases). Each independently re-verifies the caller's acquisitionId against
// the ledger's live currentOwner as the first statement inside its own existing mutate()
// transaction -- deliberately never a separate, composable verifyOwnership() call made before the
// write, which would leave a gap between the check and the write.

test('inline fence: createLease/consume/reconcile/close/sweepOrphanedLeases each throw when called with no current owner', async () => {
  await withStore(async ({ store }) => {
    const preflight = await createBoundPreflight(store, '2026-09-03T01:00:00.000Z');
    await assert.rejects(store.createLease({
      preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1,
      expiresAt: '2026-09-03T00:30:00.000Z', acquisitionId: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    }), /process owner/);
  });
});

test('inline fence: a guarded write with the correct acquisitionId succeeds; with a WRONG one throws and performs no effect', async () => {
  await withStore(async ({ store }) => {
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const preflight = await createBoundPreflight(store, '2026-09-03T01:00:00.000Z');
    const lease = await store.createLease({
      preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1,
      expiresAt: '2026-09-03T00:30:00.000Z', acquisitionId: handle.acquisitionId,
    });
    assert.equal(lease.state, 'ACTIVE');

    await assert.rejects(store.consume(lease.id, HASH, {
      reservationUsd: 0.10, acquisitionId: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    }), /process owner/);

    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.10, acquisitionId: handle.acquisitionId });
    assert.equal(job.state, 'RESERVED');

    await assert.rejects(store.reconcile(job.id, {
      costUsd: 0.05, costKind: 'KNOWN', acquisitionId: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    }), /process owner/);
    const reconciled = await store.reconcile(job.id, { costUsd: 0.05, costKind: 'KNOWN', acquisitionId: handle.acquisitionId });
    assert.equal(reconciled.state, 'RECONCILED');

    await assert.rejects(store.close(lease.id, 'CLOSED', { acquisitionId: 'ffffffff-ffff-ffff-ffff-ffffffffffff' }), /process owner/);
    const closed = await store.close(lease.id, 'CLOSED', { acquisitionId: handle.acquisitionId });
    assert.equal(closed.state, 'CLOSED');
  });
});

test('inline fence: sweepOrphanedLeases requires the correct acquisitionId too', async () => {
  await withStore(async ({ store }) => {
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    await assert.rejects(
      store.sweepOrphanedLeases({ staleAfterMs: 0, acquisitionId: 'ffffffff-ffff-ffff-ffff-ffffffffffff' }),
      /process owner/,
    );
    const result = await store.sweepOrphanedLeases({ staleAfterMs: 0, acquisitionId: handle.acquisitionId });
    assert.deepEqual(result, []);
  });
});

test('inline fence: a guarded write attempted with the correct acquisitionId but AFTER that generation was cleanly RELEASED is refused', async () => {
  await withStore(async ({ store }) => {
    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    // Snapshotted before release: a released handle's acquisitionId reads null, and a null id
    // fails requireId() with a TypeError long before it reaches the ownership fence this test pins.
    const { acquisitionId } = handle;
    const preflight = await createBoundPreflight(store, '2026-09-03T01:00:00.000Z');
    await handle.release();
    await assert.rejects(store.createLease({
      preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1,
      expiresAt: '2026-09-03T00:30:00.000Z', acquisitionId,
    }), /process owner/);
  });
});

test('inline fence: the realistic same-process cross-root collision -- two stores under the SAME test process, acquisitionId (not generation/pid) closes the gap', async () => {
  const rootA = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-a-'));
  const rootB = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-b-'));
  try {
    const storeA = createLeaseStore({ dataRoot: rootA, clock: () => Date.parse('2026-09-03T00:00:00.000Z') });
    const storeB = createLeaseStore({ dataRoot: rootB, clock: () => Date.parse('2026-09-03T00:00:00.000Z') });
    const handleA = await storeA.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const handleB = await storeB.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    // Both acquired at generation 1, both under the SAME process.pid (genuinely, since this
    // is one Node test process) -- generation and pid both "match" across A and B. Only
    // acquisitionId, which is independently random per store, tells them apart.
    assert.equal(handleA.generation, 1);
    assert.equal(handleB.generation, 1);
    assert.notEqual(handleA.acquisitionId, handleB.acquisitionId);
    const preflight = await createBoundPreflight(storeB, '2026-09-03T01:00:00.000Z');
    await assert.rejects(storeB.createLease({
      preflightIds: [preflight.id], requestedUsd: 0.20, maxJobs: 1,
      expiresAt: '2026-09-03T00:30:00.000Z', acquisitionId: handleA.acquisitionId, // copied verbatim from A
    }), /process owner/);
  } finally {
    await rm(rootA, { recursive: true, force: true });
    await rm(rootB, { recursive: true, force: true });
  }
});

test('inline fence: two independently constructed stores at two DIFFERENT data roots never interact -- independent generation numbering', async () => {
  const rootA = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-a-'));
  const rootB = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-b-'));
  try {
    const storeA = createLeaseStore({ dataRoot: rootA, clock: () => Date.parse('2026-09-03T00:00:00.000Z') });
    const storeB = createLeaseStore({ dataRoot: rootB, clock: () => Date.parse('2026-09-03T00:00:00.000Z') });
    const handleA1 = await storeA.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    await handleA1.release();
    const handleA2 = await storeA.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    const handleB1 = await storeB.acquireProcessOwnership({ acquireTimeoutMs: 1000 });
    assert.equal(handleA2.generation, 2);
    assert.equal(handleB1.generation, 1);
  } finally {
    await rm(rootA, { recursive: true, force: true });
    await rm(rootB, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Lock-timeout handling inside acquireProcessOwnership().
//
// acquireProcessOwnership() polls `mutate()` -- which takes the ledger's global data-root write
// lock and replays every ledger file -- once per `lockRetryMs` for up to `acquireTimeoutMs`. Two
// hazards follow from that:
//
//   1. If a single transient "ledger data root is locked" error from `await mutate(...)` aborted
//      the retry loop, the declared acquire budget would never be used: a start would die ~2s in
//      (`lockTimeoutMs`), which is far SHORTER than `lockStaleMs` (60s), the age an orphaned lock
//      must reach before anyone may reclaim it. A lock orphaned by a blocked acquirer that was
//      killed mid-mutate() would then hard-fail EVERY server start for the next 60 seconds.
//
//   2. A blocked start that polls holds or contends for that lock across most of its acquire
//      window, which is what makes being killed mid-mutate() likely rather than a corner case.
//
// These two tests pin the retry itself. The separate poll cadence (a blocked acquirer does not
// re-lock every `lockRetryMs`) is what shrinks the window in the first place.
// ---------------------------------------------------------------------------

const realSleep = (milliseconds) => new Promise((resolve) => { setTimeout(resolve, milliseconds); });

async function plantOrphanedDataRootLock(dataRoot, lockedAt) {
  await mkdir(join(dataRoot, '.ledger-write.lock'), { recursive: true });
  await writeFile(
    join(dataRoot, '.ledger-write.lock', 'owner.json'),
    JSON.stringify({ pid: 999_999, timestamp: new Date(lockedAt).toISOString(), lockToken: 'orphaned-by-a-killed-acquirer' }),
    'utf8',
  );
}

test('acquireProcessOwnership spends its whole budget on a locked data root instead of aborting at the first lock timeout', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-lockbudget-'));
  try {
    // The clock never advances, so the planted lock never becomes reclaimable: the ONLY way out
    // of this call is exhausting acquireTimeoutMs. That makes the assertion about which deadline
    // was honoured, with no dependence on real-world timing.
    const lockedAt = Date.parse('2026-09-06T00:00:00.000Z');
    await plantOrphanedDataRootLock(dataRoot, lockedAt);
    const store = createLeaseStore({
      dataRoot,
      clock: () => lockedAt,
      lockTimeoutMs: 50,
      lockRetryMs: 5,
      lockStaleMs: 60_000,
      isProcessAlive: () => false,
      sleep: realSleep,
    });

    await assert.rejects(
      store.acquireProcessOwnership({ acquireTimeoutMs: 400 }),
      // Aborting at the first lock timeout would reject with the bare 'ledger data root is
      // locked' at ~50ms -- one eighth of its own budget. The reason code is asserted too, so a lock-contention timeout stays
      // distinguishable from a LIVE_OWNER or NOT_YET_STALE one in a real startup error report.
      /^Error: acquireProcessOwnership timed out after 400ms \(DATA_ROOT_LOCKED\)$/,
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('acquireProcessOwnership acquires once an orphaned data-root lock clears partway through its budget', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-lockclears-'));
  try {
    const lockedAt = Date.parse('2026-09-06T00:00:00.000Z');
    await plantOrphanedDataRootLock(dataRoot, lockedAt);

    // The lock is cleared BY the retrying itself, not by a timer: a run that does not retry can
    // never reach sleep 25 and so can never observe the cleared lock. The first mutate() attempt
    // is bounded by lockTimeoutMs (50ms) at lockRetryMs (5ms) per sleep, so it can spend at most
    // ~10 sleeps -- and a slower host spends FEWER, never more, since real elapsed time is what
    // ends it. 25 is therefore unreachable within one attempt under any host speed.
    let sleeps = 0;
    let clearedAfterSleeps = null;
    const store = createLeaseStore({
      dataRoot,
      clock: () => lockedAt,
      lockTimeoutMs: 50,
      lockRetryMs: 5,
      lockStaleMs: 60_000,
      isProcessAlive: () => false,
      sleep: async (milliseconds) => {
        sleeps += 1;
        if (sleeps === 25) {
          clearedAfterSleeps = sleeps;
          await rm(join(dataRoot, '.ledger-write.lock'), { recursive: true, force: true });
        }
        await realSleep(milliseconds);
      },
    });

    const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 10_000 });
    assert.equal(handle.generation, 1);
    assert.equal(typeof handle.acquisitionId, 'string');
    assert.equal(clearedAfterSleeps, 25, 'the lock must have been cleared by the retry loop itself, not before it started');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('acquireProcessOwnership rethrows a NON-lock failure at once instead of burning its budget on it', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-structural-'));
  try {
    const lockedAt = Date.parse('2026-09-06T00:00:00.000Z');
    // A real prior owner record, so the second store below takes the stale-reclaim branch and
    // reaches beforeStaleReclaim -- the injectable seam that runs INSIDE mutate()'s work function,
    // which is what makes it a faithful stand-in for a structural failure raised from in there.
    const first = createLeaseStore({ dataRoot, clock: () => lockedAt });
    await first.acquireProcessOwnership({ acquireTimeoutMs: 1000 });

    const structural = new Error('a corrupt ledger record, not lock contention');
    const successor = createLeaseStore({
      dataRoot,
      clock: () => lockedAt + 61_000,
      lockStaleMs: 60_000,
      isProcessAlive: () => false,
      sleep: realSleep,
      beforeStaleReclaim: () => { throw structural; },
    });

    // The retry added for a contended lock must NOT widen into "retry everything": a structural
    // failure is not self-healing, so swallowing it would replace an accurate, immediate
    // explanation with a misleading timeout an entire acquire budget later. Deleting the
    // `error?.code !== DATA_ROOT_LOCKED_CODE` rethrow makes this reject with the timeout message
    // instead, which is exactly what this asserts against.
    await assert.rejects(
      successor.acquireProcessOwnership({ acquireTimeoutMs: 10_000 }),
      /^Error: a corrupt ledger record, not lock contention$/,
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// A helper that plants a genuinely ORPHANED data-root lock: a lock directory whose owner process
// is dead. A store that merely acquires and finishes does NOT leave one behind (mutate() releases
// in its finally), so the stale-reclaim branch is only reachable by writing the lock directly --
// which is exactly the production state a hard-killed acquirer leaves.
async function plantOrphanedLock(dataRoot, { timestamp, pid = 999_999 }) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  await mkdir(lockRoot, { recursive: true });
  await writeFile(
    join(lockRoot, 'owner.json'),
    `${JSON.stringify({ pid, timestamp, lockToken: 'orphan-token' })}\n`,
    'utf8',
  );
}

test('a TRANSIENT stale-lock reclaim rename failure is retried against the acquire budget, not thrown away with it', async () => {
  // acquireProcessOwnership retries a contended lock because acquireDataRootLock tags those
  // throws with LEDGER_DATA_ROOT_LOCKED -- but if the stale-reclaim rename escape rethrew RAW, a
  // transient Windows rename failure (an antivirus or indexer holding a handle on the lock
  // directory) would still abandon the whole ~90s budget. That would fire in the RECOVERY path
  // itself: the one that exists to clear an orphaned lock.
  //
  // renameRetrying already knows which codes are transient (RENAME_RETRYABLE_CODES) and gives up
  // after RENAME_RETRY_ATTEMPTS (16) or the LOCK deadline (lockTimeoutMs) -- far shorter than the
  // acquire budget. Exhausting it is therefore not evidence the condition is permanent.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const lockedAt = Date.parse('2026-08-17T12:00:00.000Z');
    await plantOrphanedLock(dataRoot, { timestamp: new Date(lockedAt).toISOString() });

    let staleRenames = 0;
    const successor = createLeaseStore({
      dataRoot,
      clock: () => lockedAt + 61_000,
      lockStaleMs: 60_000,
      isProcessAlive: () => false,
      sleep: realSleep,
      renameImpl: async (from, to) => {
        // Only the stale-reclaim rename is being exercised; it is the one moving the lock root.
        if (String(from).endsWith('.ledger-write.lock')) {
          staleRenames += 1;
          if (staleRenames <= 20) {
            throw Object.assign(new Error('EPERM: operation not permitted, rename'), { code: 'EPERM' });
          }
        }
        return rename(from, to);
      },
    });

    const handle = await successor.acquireProcessOwnership({ acquireTimeoutMs: 20_000 });
    assert.ok(handle.acquisitionId, 'the successor must eventually reclaim the orphaned lock');
    assert.ok(
      staleRenames > 20,
      `the reclaim rename must be retried past renameRetrying's own ceiling (saw ${staleRenames})`,
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a STRUCTURAL stale-lock reclaim rename failure still fails fast, and keeps its own message', async () => {
  // The other half of the same guard, and the reason the fix must stay narrow: a non-retryable
  // rename code is not self-healing, so retrying it for a whole budget would replace an accurate
  // immediate explanation with a misleading timeout 90 seconds later. Only RENAME_RETRYABLE_CODES
  // may be treated as transient.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const lockedAt = Date.parse('2026-08-17T12:00:00.000Z');
    await plantOrphanedLock(dataRoot, { timestamp: new Date(lockedAt).toISOString() });

    const successor = createLeaseStore({
      dataRoot,
      clock: () => lockedAt + 61_000,
      lockStaleMs: 60_000,
      isProcessAlive: () => false,
      sleep: realSleep,
      renameImpl: async (from, to) => {
        if (String(from).endsWith('.ledger-write.lock')) {
          throw Object.assign(new Error('EROFS: read-only file system, rename'), { code: 'EROFS' });
        }
        return rename(from, to);
      },
    });

    await assert.rejects(
      successor.acquireProcessOwnership({ acquireTimeoutMs: 20_000 }),
      /EROFS: read-only file system, rename/,
      'a structural rename failure must surface its own message, not a budget-later timeout',
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('an unreadable ledger record names the file, and says plainly that deleting it is not the remedy', async () => {
  // replay() parses every *.json in the ledger, and mutate() replays before EVERY operation -- so
  // one corrupt file breaks the write path, the read path AND acquireProcessOwnership, i.e. the
  // server cannot even start. Failing closed there is CORRECT for an append-only money ledger
  // (silently skipping a record could drop a spend record), so this does not make replay
  // tolerant. The concern is purely about error reporting: JSON.parse throws BEFORE the `invalid ledger
  // record` check, so without a wrapper malformed JSON -- the likely real-world corruption shape --
  // surfaces as a bare SyntaxError naming nothing, leaving an operator to guess which of hundreds
  // of timestamp+uuid filenames is at fault.
  //
  // The warning is not decoration: deleting a MIDDLE processOwner record
  // breaks the strict +1 generation chain and bricks the ledger permanently, and the resulting
  // error then names the NEXT record -- so an operator who treats a named file as "the one to
  // delete" is walked deeper into destroying the audit trail. Naming the file without saying that
  // would have made this error report actively dangerous.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const store = createLeaseStore({ dataRoot });
    await store.acquireProcessOwnership({ acquireTimeoutMs: 2000 });

    const ledger = join(dataRoot, 'ledger');
    await writeFile(join(ledger, '2026-08-17T12-00-05-000Z-corrupt.json'), '{ this is not json', 'utf8');

    await assert.rejects(
      store.getPreflight('does-not-matter'),
      (error) => {
        assert.match(error.message, /2026-08-17T12-00-05-000Z-corrupt\.json/, 'must name the offending file');
        assert.match(error.message, /do not delete/i, 'must warn against the destructive "remedy" it would otherwise invite');
        return true;
      },
    );

    // Fail-closed is preserved, not traded away for the better message: a later operation still
    // refuses rather than skipping the record it could not read.
    await assert.rejects(store.acquireProcessOwnership({ acquireTimeoutMs: 500 }), /corrupt\.json/);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a stray .tmp file beside the ledger is still ignored, not treated as a corrupt record', async () => {
  // The write path is crash-safe by construction: append() writes `<name>.json.<uuid>.tmp` and
  // atomically renames, and replay() filters on `.endsWith('.json')`, so a partial write is
  // invisible. This pins that, so the error report above can never be
  // "fixed" by widening the filter into something that would fail closed on every interrupted write.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const store = createLeaseStore({ dataRoot });
    await store.acquireProcessOwnership({ acquireTimeoutMs: 2000 });
    await writeFile(join(dataRoot, 'ledger', 'partial.json.abc-123.tmp'), '{ broken', 'utf8');
    assert.equal(await store.getPreflight('unknown-id'), null, 'a .tmp file must not break replay');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('an unknown processOwner state is REFUSED, never silently treated as a release of ownership', async () => {
  // This is not a dead validity check. applyProcessOwnerRecord's state guard is the only thing standing between an unrecognised state
  // and the `else` branch, which treats a record as RELEASED -- so deleting the guard converts an
  // unknown state into a SILENT handback of the data root while another process may still be live,
  // breaking mutual exclusion with nothing to catch it. No other test exercises this guard.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const store = createLeaseStore({ dataRoot });
    const { generation, acquisitionId } = await store.acquireProcessOwnership({ acquireTimeoutMs: 2000 });

    // A record that is well-formed in every other respect -- correct type, plausible pid, real
    // generation and acquisitionId, parseable timestamp -- so the ONLY thing that can reject it is
    // the state guard itself, not some unrelated structural check.
    await writeFile(
      join(dataRoot, 'ledger', '2026-08-17T13-00-00-000Z-bogus-state.json'),
      `${JSON.stringify({
        recordType: 'processOwner', state: 'PROBABLY_RELEASED', pid: process.pid,
        generation: generation + 1, acquisitionId, timestamp: '2026-08-17T13:00:00.000Z',
      })}\n`,
      'utf8',
    );

    await assert.rejects(
      createLeaseStore({ dataRoot }).getPreflight('anything'),
      /processOwner record has an invalid state: PROBABLY_RELEASED/,
      'an unrecognised state must fail closed, not fall through to the RELEASED branch',
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('staleness age is derived from the monotonic stamp append() actually used, not a raw clock read', async () => {
  // No other test exercises this clamp. The clamp exists because append() stamps records with Math.max(clock(), lastRecordTime + 1), so a
  // fixed or slow-moving clock can sit BEHIND a timestamp the ledger already advanced past. A raw
  // clock() read then makes ageMs NEGATIVE, and a genuinely dead, long-abandoned owner reads as
  // perpetually "not yet stale" -- ownership that can never be reclaimed.
  //
  // Constructed so the arithmetic is the only variable: one prior record forces append()'s
  // monotonic bump to stamp the ownership record one tick AHEAD of the frozen clock, and
  // lockStaleMs is 0 so ANY non-negative age qualifies. Raw: age is negative, refuses forever.
  // Clamped: age is positive, reclaims immediately.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-'));
  try {
    const frozen = Date.parse('2026-08-17T12:00:00.000Z');
    const first = createLeaseStore({ dataRoot, clock: () => frozen });
    // Consumes the frozen instant, so the ownership record below is stamped frozen+1.
    await createBoundPreflight(first, '2026-08-17T12:10:00.000Z');
    await first.acquireProcessOwnership({ acquireTimeoutMs: 1000 });

    const successor = createLeaseStore({
      dataRoot,
      clock: () => frozen,
      lockStaleMs: 0,
      isProcessAlive: () => false,
      sleep: realSleep,
    });
    const handle = await successor.acquireProcessOwnership({ acquireTimeoutMs: 2000 });
    assert.ok(
      handle.acquisitionId,
      'a dead owner stamped ahead of a frozen clock must still be reclaimable',
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});
