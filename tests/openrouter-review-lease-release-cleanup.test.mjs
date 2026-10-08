import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import * as leaseStoreModule from '../src/local-mcp/lease-store.mjs';

const { createLeaseStore } = leaseStoreModule;
const HASH = 'a'.repeat(64);
const ARM = Object.freeze({
  acquireTimeoutMs: 1_000,
  lockRetryMs: 250,
  caps: Object.freeze({ installationHardMaximumUsd: 5 }),
});

async function withDataRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-release-cleanup-'));
  try {
    return await run(dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function createPreflight(store, id) {
  return store.createPreflight({
    id,
    reviewContractSha256: HASH,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256: 'c'.repeat(64),
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'd'.repeat(64),
    registrySha256: 'e'.repeat(64),
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }],
    requestedUsd: 0.20,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  });
}

async function ownerRecords(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const { readdir } = await import('node:fs/promises');
  const names = (await readdir(ledgerRoot)).filter((name) => name.endsWith('.json')).sort();
  const records = await Promise.all(names.map(async (name) => JSON.parse(await readFile(join(ledgerRoot, name), 'utf8'))));
  return records.filter((record) => record.recordType === 'processOwner');
}

async function seedSupersedingOwner(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const timestamp = new Date(Date.now() + 60_000).toISOString();
  const record = {
    recordType: 'processOwner',
    state: 'ACQUIRED',
    pid: process.pid,
    generation: 2,
    acquisitionId: randomUUID(),
    timestamp,
  };
  await writeFile(
    join(ledgerRoot, `${timestamp.replace(/[:.]/g, '-')}-successor-${randomUUID()}.json`),
    `${JSON.stringify(record)}\n`,
    'utf8',
  );
  return record;
}

async function rejectionOf(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return assert.fail('expected rejection');
}

function handleOf(store) {
  assert.equal(typeof store.createUnarmedOwnerHandle, 'function');
  return store.createUnarmedOwnerHandle();
}

function physicalReleaseSwitch(dataRoot) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  let blockRelease = false;
  let failureMessage = 'controlled physical release failure';
  let postToggleReleaseMoves = 0;
  let blockedReleaseAttempts = 0;
  return {
    lockRoot,
    setBlocked(value) { blockRelease = value; },
    setFailureMessage(value) { failureMessage = value; },
    resetPostToggleReleaseMoves() { postToggleReleaseMoves = 0; },
    get postToggleReleaseMoves() { return postToggleReleaseMoves; },
    get blockedReleaseAttempts() { return blockedReleaseAttempts; },
    async renameImpl(from, to) {
      if (from === lockRoot) {
        if (blockRelease) {
          blockedReleaseAttempts += 1;
          throw Object.assign(new Error(failureMessage), { code: 'EACCES' });
        }
        postToggleReleaseMoves += 1;
      }
      return rename(from, to);
    },
  };
}

async function captureStderr(run) {
  const writes = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => {
    writes.push(String(chunk));
    return originalWrite.call(process.stderr, chunk, ...rest);
  };
  try {
    return { result: await run(), text: writes.join('') };
  } finally {
    process.stderr.write = originalWrite;
  }
}

// Break caught: deleting the store-local retry of the exact stranded cleanup leaves a committed
// preflight inaccessible to every later operation by this same store.
test('two simultaneous readers join exact pending cleanup, preserve the committed preflight, and then read normally', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 300, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const beforeFailure = await createPreflight(store, 'before-failure');
    physical.setBlocked(true);
    const committed = await createPreflight(store, 'committed-despite-cleanup-failure');
    assert.equal(committed.id, 'committed-despite-cleanup-failure', 'the already-committed mutation must keep its result');

    physical.setBlocked(false);
    physical.resetPostToggleReleaseMoves();
    const [first, second] = await Promise.all([
      store.getPreflight(beforeFailure.id),
      store.getPreflight(committed.id),
    ]);

    assert.equal(first.id, beforeFailure.id);
    assert.equal(second.id, committed.id);
    assert.equal(
      physical.postToggleReleaseMoves,
      3,
      'one exact cleanup retry plus one normal physical release for each reader; two cleanup callbacks would make four',
    );
  });
});

// Break caught: treating a still-live PID as sufficient authority would let a different store in
// that process release a lock whose exact cleanup capability belongs only to the first store.
test('a second store in the same PID cannot spend another store\'s cleanup capability, while the originating store can recover', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const first = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const durable = await createPreflight(first, 'first-store-durable');
    physical.setBlocked(true);
    await createPreflight(first, 'strands-first-store-lock');
    physical.setBlocked(false);

    const second = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5 });
    await assert.rejects(() => second.getPreflight(durable.id), /ledger data root is locked/);

    const recovered = await first.getPreflight(durable.id);
    assert.equal(recovered.id, durable.id);
  });
});

// Break caught: a stale cleanup capability that does not pre-read and compare the exact token can
// rename or delete a newer foreign lock. Unreadable metadata must similarly retain the capability.
test('foreign or unreadable lock metadata is never removed as a pending cleanup, and a restored exact token can still recover', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({
      dataRoot,
      lockTimeoutMs: 300,
      lockRetryMs: 5,
      renameImpl: physical.renameImpl,
      isProcessAlive: () => true,
    });
    const durable = await createPreflight(store, 'durable-before-foreign');
    physical.setBlocked(true);
    await createPreflight(store, 'strands-lock-for-foreign-check');
    const originalOwner = await readFile(join(physical.lockRoot, 'owner.json'), 'utf8');

    await rm(join(physical.lockRoot, 'owner.json'));
    physical.setBlocked(false);
    await assert.rejects(() => store.getPreflight(durable.id), /owner cannot be verified|ledger data root is locked/);

    await writeFile(join(physical.lockRoot, 'owner.json'), originalOwner, 'utf8');
    const recovered = await store.getPreflight(durable.id);
    assert.equal(recovered.id, durable.id, 'unreadable metadata must retain, not discard, the exact cleanup capability');

    physical.setBlocked(true);
    await createPreflight(store, 'strands-lock-for-foreign-replacement');
    const displaced = `${physical.lockRoot}.test-original`;
    await rename(physical.lockRoot, displaced);
    await mkdir(physical.lockRoot);
    const foreignOwner = '{"pid":4242,"timestamp":"2026-09-18T00:00:00.000Z","lockToken":"foreign-token"}\n';
    await writeFile(join(physical.lockRoot, 'owner.json'), foreignOwner, 'utf8');
    physical.setBlocked(false);

    await assert.rejects(() => store.getPreflight(durable.id), /ledger data root is locked/);
    assert.equal(await readFile(join(physical.lockRoot, 'owner.json'), 'utf8'), foreignOwner, 'the foreign lock must remain untouched');

    // A verified replacement retires the old capability. Once the real foreign lock is gone, a
    // later transaction must run only its own release callback, never revive the stale one.
    await rm(physical.lockRoot, { recursive: true, force: true });
    physical.resetPostToggleReleaseMoves();
    const afterReplacement = await store.getPreflight(durable.id);
    assert.equal(afterReplacement.id, durable.id);
    assert.equal(physical.postToggleReleaseMoves, 1, 'the retired callback must not later rename a new lock');
  });
});

// Break caught: generic mutations may keep a completed result when physical cleanup fails, but their
// log and the next pre-effect failure must never disclose the injected filesystem detail.
test('generic cleanup failure is redacted and its later pre-effect refusal carries only the fixed lock error', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const sensitive = "\u0043\u003a\u005c\u0073\u0065\u006e\u0073\u0069\u0074\u0069\u0076\u0065\u005c\u0072\u0065\u006c\u0065\u0061\u0073\u0065\u002d\u0070\u0061\u0074\u0068\u005c\u0072\u0061\u0077\u002d\u0065\u0072\u0072\u006f\u0072";
    physical.setFailureMessage(sensitive);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const durable = await createPreflight(store, 'redaction-durable');
    physical.setBlocked(true);

    const captured = await captureStderr(() => createPreflight(store, 'redaction-committed'));
    assert.equal(captured.result.id, 'redaction-committed');
    assert.match(captured.text, /release-rename-failed \(detail redacted\); exact local cleanup remains pending/);
    assert.doesNotMatch(captured.text, /sensitive|release-path|raw-error/i);

    const failure = await rejectionOf(store.getPreflight(durable.id));
    assert.equal(failure.code, leaseStoreModule.LEDGER_DATA_ROOT_LOCKED_CODE);
    assert.equal(failure.message, 'ledger data root is locked (pending local cleanup could not complete)');
    assert.doesNotMatch(failure.message, /sensitive|release-path|raw-error/i);
  });
});

// Break caught: error output is observational. A synchronous stderr sink failure during the
// post-effect physical-release error report must not turn either a committed value or the original
// logical work error into the sink's exception.
test('a throwing generic cleanup error report preserves both the committed value and original work error', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    let triggerPhysicalFailure = false;
    const store = createLeaseStore({
      dataRoot,
      lockTimeoutMs: 30,
      lockRetryMs: 5,
      renameImpl: physical.renameImpl,
      beforeRelease: async (released) => {
        if (triggerPhysicalFailure && Object.hasOwn(released, 'lockToken')) physical.setBlocked(true);
      },
    });
    const originalWrite = process.stderr.write;
    const sinkError = new Error('simulated throwing stderr sink');
    process.stderr.write = () => { throw sinkError; };
    try {
      triggerPhysicalFailure = true;
      const committed = await createPreflight(store, 'throwing-report-committed');
      assert.equal(committed.id, 'throwing-report-committed');

      // The next acquire first settles the exact old lock. Its own duplicate-id work then fails;
      // its physical cleanup fails too, exercising the same throwing error report in a work-error path.
      physical.setBlocked(false);
      const originalError = await rejectionOf(createPreflight(store, committed.id));
      assert.notStrictEqual(originalError, sinkError);
      assert.match(originalError.message, /preflight ID already exists/);
      assert.equal(physical.blockedReleaseAttempts, 2, 'the duplicate-id work error must also reach the throwing error report seam');
    } finally {
      process.stderr.write = originalWrite;
    }
  });
});

// Break caught: a failed RELEASED append plus physical cleanup failure is not a completed handover.
// The original logical error wins, the handle stays armed, and its later retry first disposes only
// the exact stranded lock before retrying the logical compare-and-set.
test('failed logical RELEASED append plus failed physical cleanup preserves the original error and armed state until a later full retry', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const logicalError = Object.assign(new Error('simulated logical RELEASED append failure'), { code: 'EPERM' });
    let failLogicalRelease = false;
    const store = createLeaseStore({
      dataRoot,
      lockTimeoutMs: 30,
      lockRetryMs: 5,
      renameImpl: physical.renameImpl,
      beforeAtomicRename: async (record) => {
        if (failLogicalRelease && record.recordType === 'processOwner' && record.state === 'RELEASED') {
          failLogicalRelease = false;
          throw logicalError;
        }
      },
    });
    const handle = handleOf(store);
    await handle.arm(ARM);
    const originalAcquisitionId = handle.acquisitionId;
    failLogicalRelease = true;
    physical.setBlocked(true);
    const captured = await captureStderr(() => rejectionOf(handle.release({ final: false })));

    assert.strictEqual(captured.result, logicalError, 'the physical cleanup receipt must not replace the original logical failure');
    assert.equal(handle.state, 'armed');
    assert.equal(handle.isOwner(), true);
    assert.equal(handle.acquisitionId, originalAcquisitionId);
    assert.doesNotMatch(captured.text, /controlled physical release failure|ledger-write\.lock/i);

    physical.setBlocked(false);
    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
  });
});

// Break caught: a read can safely finish store-local cleanup after a committed RELEASED append.
// The handle must remain release-pending until its own cleanup-only release observes that fact.
test('a read can complete exact pending cleanup before the handle retry, which then settles without another RELEASED append', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const preflight = await createPreflight(store, 'read-before-owner-retry');
    const handle = handleOf(store);
    await handle.arm(ARM);
    physical.setBlocked(true);
    const pending = await rejectionOf(handle.release({ final: false }));
    assert.equal(pending.code, leaseStoreModule.OWNER_RELEASE_PENDING_CODE);

    physical.setBlocked(false);
    const readable = await store.getPreflight(preflight.id);
    assert.equal(readable.id, preflight.id);
    assert.equal(handle.state, 'release-pending');
    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
  });
});

// Break caught: absence after a failed shared-lock rename is a verified safe completion. The
// retained capability must clear, so the next transaction creates and releases only its own lock.
test('an already-absent pending lock is safely retired before the next transaction', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const durable = await createPreflight(store, 'absent-pending-durable');
    physical.setBlocked(true);
    await createPreflight(store, 'absent-pending-committed');
    await rm(physical.lockRoot, { recursive: true, force: true });
    physical.setBlocked(false);
    physical.resetPostToggleReleaseMoves();

    const recovered = await store.getPreflight(durable.id);
    assert.equal(recovered.id, durable.id);
    assert.equal(physical.postToggleReleaseMoves, 1, 'only the new transaction lock should move');
  });
});

// Break caught: a conditional no-op does complete the ownership handover. A physical failure after
// that no-op must therefore be cleanup-only release-pending, never the old armed failure path and
// never an invented RELEASED record.
test('superseded-owner no-op plus physical cleanup failure becomes cleanup-only release-pending without a RELEASED append', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const handle = handleOf(store);
    await handle.arm(ARM);
    await seedSupersedingOwner(dataRoot);
    physical.setBlocked(true);

    const pending = await rejectionOf(handle.release({ final: false }));
    assert.equal(pending.code, leaseStoreModule.OWNER_RELEASE_PENDING_CODE);
    assert.equal(handle.state, 'release-pending');
    assert.equal(handle.isOwner(), false);
    assert.equal(handle.acquisitionId, null);
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'ACQUIRED']);

    physical.setBlocked(false);
    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed');
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'ACQUIRED']);
  });
});

// Break caught: a superseded owner must become unarmed after a successful conditional no-op. It must
// not be restored to armed merely because this handle did not append a RELEASED record.
test('superseded-owner no-op with complete physical cleanup becomes unarmed without a RELEASED append', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot });
    const handle = handleOf(store);
    await handle.arm(ARM);
    await seedSupersedingOwner(dataRoot);

    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed');
    assert.equal(handle.isOwner(), false);
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'ACQUIRED']);
  });
});

// Break caught: after RELEASED commits, reporting the handle unarmed lets a new arm claim a lock
// that is physically still retained. The retry must perform cleanup only, never append RELEASED twice.
test('a committed owner release with failed physical cleanup becomes release-pending and retries cleanup without another RELEASED record', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const neverOwned = handleOf(store);
    assert.equal(neverOwned.everArmed, false);

    const handle = handleOf(store);
    await handle.arm(ARM);
    physical.setBlocked(true);
    const pending = await rejectionOf(handle.release({ final: false }));
    assert.equal(typeof leaseStoreModule.OWNER_RELEASE_PENDING_CODE, 'string');
    assert.equal(pending.code, leaseStoreModule.OWNER_RELEASE_PENDING_CODE);
    assert.equal(handle.state, 'release-pending');
    assert.equal(handle.isOwner(), false);
    assert.equal(handle.acquisitionId, null);
    assert.equal(handle.generation, null);
    assert.equal(handle.everArmed, true);
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
    const armError = await rejectionOf(handle.arm(ARM));
    assert.equal(armError.code, leaseStoreModule.OWNER_RELEASE_PENDING_CODE);

    physical.setBlocked(false);
    await handle.release({ final: false });
    assert.equal(handle.state, 'unarmed');
    assert.equal(handle.everArmed, true);
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
  });
});

// Break caught: a final release joining a failed non-final release must not lose finality while its
// physical cleanup is pending; otherwise shutdown can leave a re-armable handle.
test('final intent stays monotonic across release-pending cleanup and still writes only one RELEASED record', async () => {
  await withDataRoot(async (dataRoot) => {
    const physical = physicalReleaseSwitch(dataRoot);
    const store = createLeaseStore({ dataRoot, lockTimeoutMs: 30, lockRetryMs: 5, renameImpl: physical.renameImpl });
    const handle = handleOf(store);
    await handle.arm(ARM);
    physical.setBlocked(true);
    const first = await rejectionOf(handle.release({ final: false }));
    assert.equal(first.code, leaseStoreModule.OWNER_RELEASE_PENDING_CODE);
    const finalAttempt = await rejectionOf(handle.release({ final: true }));
    assert.equal(finalAttempt.code, leaseStoreModule.OWNER_RELEASE_PENDING_CODE);

    physical.setBlocked(false);
    await handle.release({ final: false });
    assert.equal(handle.state, 'released');
    assert.equal(handle.everArmed, true);
    assert.deepEqual((await ownerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
  });
});

// Break caught: accepting an acquisition ID from a previous non-final release would let an old
// operation append a lease after the handle has completed a fresh ownership cycle.
test('a prior cycle token cannot create a lease after a later arm has acquired a new generation', async () => {
  await withDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot });
    const preflight = await createPreflight(store, 'stale-token-preflight');
    const handle = handleOf(store);

    await handle.arm(ARM);
    const priorToken = handle.acquisitionId;
    await handle.release({ final: false });
    await handle.arm(ARM);
    const currentToken = handle.acquisitionId;
    assert.notEqual(currentToken, priorToken);

    await assert.rejects(
      () => store.createLease({
        id: 'stale-token-lease',
        preflightIds: [preflight.id],
        requestedUsd: 0.20,
        maxJobs: 1,
        expiresAt: preflight.expiresAt,
        acquisitionId: priorToken,
      }),
      /does not currently hold process ownership/,
    );

    const lease = await store.createLease({
      id: 'current-token-lease',
      preflightIds: [preflight.id],
      requestedUsd: 0.20,
      maxJobs: 1,
      expiresAt: preflight.expiresAt,
      acquisitionId: currentToken,
    });
    assert.equal(lease.id, 'current-token-lease');
  });
});
