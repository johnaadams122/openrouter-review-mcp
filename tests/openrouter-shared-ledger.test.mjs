import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createSharedLedgerState } from '../src/local-mcp/shared/ledger-state.mjs';
import { buildInstallationConfig, DIGESTS } from './helpers/shared-policy-fixture.mjs';
import {
  FUTURE,
  INPUT_DIGEST,
  KEY_DIGEST,
  LATER,
  NOW,
  acquireOwner,
  admitManagedReceipt,
  activateManagedMode,
  appendRawRecord,
  createManagedLease,
  createManagedPreflight,
  createFakeStorageProofs,
  claimManagedReceipt,
  managedExecutionFor,
  preparedReservationBytes,
  preflightReservationBytes,
  readLedgerRecords,
  receiptFor,
  terminalizeManagedFixture,
  withManagedDataRoot,
} from './helpers/shared-ledger-fixture.mjs';

function storeFor(dataRoot, managedExecution, clock = () => NOW) {
  return createLeaseStore({ dataRoot, clock, managedExecution });
}

// Break caught: validation that mutates one index before discovering a skipped revision leaves a
// process with state that can never be reproduced from the rejected append.
test('pure shared replay rejects malformed/revision-skipped records without changing its snapshot', () => {
  const state = createSharedLedgerState();
  const serviceMode = {
    recordType: 'shared/service-mode',
    version: 1,
    state: 'ACTIVE',
    revision: 1,
    configFingerprint: '1'.repeat(64),
    buildManifestFingerprint: '2'.repeat(64),
    activationAcquisitionId: ['1'.repeat(8),'1111','4111','8111','1'.repeat(12)].join('-'),
    replayBarrierId: ['2'.repeat(8),'2222','4222','8222','2'.repeat(12)].join('-'),
    replayBarrierCompletedAt: new Date(NOW).toISOString(),
  };
  state.apply(serviceMode);
  const before = state.snapshot();

  assert.throws(() => state.apply({ ...serviceMode, revision: 3, state: 'CLEARED' }), /revision/i);
  assert.deepEqual(state.snapshot(), before);
  assert.throws(() => state.apply({ ...serviceMode, revision: 2, unknown: true }), /unknown/i);
  assert.deepEqual(state.snapshot(), before);
  assert.throws(() => state.apply({ ...serviceMode, version: 2, revision: 2 }), /version|mode/i);
  assert.deepEqual(state.snapshot(), before);
});

// Break caught: Object.entries can invoke accessors while validating a hostile in-memory record.
test('pure shared replay rejects accessors before reading their values', () => {
  const state = createSharedLedgerState();
  let reads = 0;
  const record = {
    recordType: 'shared/service-mode', version: 1, state: 'ACTIVE', revision: 1,
    configFingerprint: '1'.repeat(64), buildManifestFingerprint: '2'.repeat(64),
    activationAcquisitionId: ['1'.repeat(8),'1111','4111','8111','1'.repeat(12)].join('-'),
    replayBarrierId: ['2'.repeat(8),'2222','4222','8222','2'.repeat(12)].join('-'),
    replayBarrierCompletedAt: new Date(NOW).toISOString(),
  };
  Object.defineProperty(record, 'unknown', { enumerable: true, get() { reads += 1; return 'secret'; } });
  assert.throws(() => state.apply(record), /data|accessor|enumerable/i);
  assert.equal(reads, 0);
  assert.equal(state.snapshot().serviceMode, null);
});

// Break caught: enabling managed methods without the explicit composition-root bundle lets old
// standalone processes mutate the new shared state with no policy or protected-store authority.
test('managed mutations require the explicit managedExecution composition bundle', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const store = createLeaseStore({ dataRoot, clock: () => NOW });
    const { owner, acquisitionId } = await acquireOwner(store);
    await assert.rejects(
      store.activateServiceMode({
        configFingerprint: 'a'.repeat(64),
        buildManifestFingerprint: 'b'.repeat(64),
        acquisitionId,
      }),
      /managed|service mode|configured/i,
    );
  });
});

// Break caught: broadening ordinary consume to ACTIVE-or-MANAGED_ACTIVE bypasses receipt claims.
test('managed leases are distinct from legacy ACTIVE leases and ordinary consume rejects them', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);

    assert.equal(lease.state, 'MANAGED_ACTIVE');
    await assert.rejects(
      store.consume(lease.id, DIGESTS.reviewContract, {
        reservationUsd: 0.01,
        jobId: randomUUID(),
        acquisitionId,
      }),
      /closed|legacy/i,
    );
  });
});

// Break caught: performing capacity checks outside mutate admits sixteen writers into fifteen slots.
test('sixteen simultaneous staging reservations admit exactly fifteen and replay the same occupancy', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const baseConfig = buildInstallationConfig({ dataRoot });
    const installationConfig = buildInstallationConfig({
      dataRoot,
      review: {
        ...baseConfig.review,
        allowedProfiles: [{
          profileId: 'final_verification_v1',
          profileVersion: '1',
          allowedReviewerSets: [['grok']],
        }],
      },
    });
    const managedExecution = managedExecutionFor(dataRoot, { installationConfig });
    const store = storeFor(dataRoot, managedExecution);
    const { owner, acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const leases = await Promise.all(Array.from({ length: 16 }, () => createManagedLease(store, preflightId, acquisitionId)));

    const outcomes = await Promise.allSettled(leases.map((lease, index) => store.reserveStagingPermit({
      stagingId: randomUUID(),
      generation: 1,
      bindingId: 'binding-a',
      scopeDigest: DIGESTS.scope,
      leaseId: lease.id,
      keyDigest: index.toString(16).padStart(64, '0'),
      inputDigest: index.toString(16).padStart(64, 'f'),
      maxEncryptedBytes: preparedReservationBytes(managedExecution),
      effectiveDeadline: FUTURE,
      acquisitionId,
    })));

    assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 15);
    assert.equal(outcomes.filter((outcome) => outcome.status === 'rejected').length, 1);
    assert.equal(outcomes.find((outcome) => outcome.status === 'rejected').reason?.code, 'REQUEST_CAPACITY_FULL');

    await owner.release({ final: true });
    const restarted = storeFor(dataRoot, managedExecution);
    const receipts = await restarted.listManagedReceipts();
    assert.deepEqual(receipts, [], 'reserved staging does not masquerade as an accepted receipt');
    const records = await readLedgerRecords(dataRoot);
    assert.equal(records.filter((record) => record.kind === 'STAGING_RESERVED').length, 15);
  });
});

// Break caught: staging commit appended as separate release/receipt records exposes an accepted
// receipt without atomically replacing its capacity permit and lease association.
test('staging commit is one compound admission append and exact replay is idempotent', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    const stagingId = randomUUID();
    await store.reserveStagingPermit({
      stagingId,
      generation: 1,
      bindingId: 'binding-a',
      scopeDigest: DIGESTS.scope,
      leaseId: lease.id,
      keyDigest: KEY_DIGEST,
      inputDigest: INPUT_DIGEST,
      maxEncryptedBytes: preparedReservationBytes(managedExecution),
      effectiveDeadline: FUTURE,
      acquisitionId,
    });
    const built = receiptFor({ leaseId: lease.id, preflightId });
    const executionGroup = {
      recordType: 'shared/execution-group',
      version: 1,
      executionGroupId: randomUUID(),
      revision: 1,
      executionFingerprint: built.receipt.executionFingerprint,
      scopeDigest: DIGESTS.scope,
      state: 'OPEN',
      orderedReceiptIds: [built.receipt.receiptId],
      reviewerIds: ['grok'],
    };
    managedExecution.storageProofs.publish({
      kind: 'prepared',
      target: { stagingId, generation: 1 },
      refs: [...built.preparedPayload.requestRefs, built.preparedPayload.envelopeRef],
    });

    const admitted = await store.commitStagedReceipt({
      stagingId,
      generation: 1,
      receipt: built.receipt,
      executionGroup,
      preparedPayload: built.preparedPayload,
      exactEncryptedBytes: built.exactEncryptedBytes,
      mappingPins: built.receipt.mappingPins,
      acquisitionId,
    });
    assert.equal(admitted.receiptId, built.receipt.receiptId);
    const beforeReplay = await readLedgerRecords(dataRoot);
    const replayed = await store.commitStagedReceipt({
      stagingId,
      generation: 1,
      receipt: built.receipt,
      executionGroup,
      preparedPayload: built.preparedPayload,
      exactEncryptedBytes: built.exactEncryptedBytes,
      mappingPins: built.receipt.mappingPins,
      acquisitionId,
    });
    assert.deepEqual(replayed, admitted);
    const afterReplay = await readLedgerRecords(dataRoot);
    assert.equal(afterReplay.length, beforeReplay.length, 'exact admission replay appends nothing');
    const admissions = afterReplay.filter((record) => record.kind === 'RECEIPT_ADMITTED');
    assert.equal(admissions.length, 1);
    assert.equal(admissions[0].staging.state, 'COMMITTED');
    assert.equal(admissions[0].receipt.receiptId, built.receipt.receiptId);
    assert.equal(admissions[0].lease.managedBinding.receiptId, built.receipt.receiptId);
  });
});

// Break caught: equality at a strict deadline can slip through a `< now` comparison.
test('staging reservation and commit reject deadline equality without spending or accepting', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    let now = NOW;
    const store = storeFor(dataRoot, managedExecution, () => now);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    now = Date.parse(FUTURE);
    await assert.rejects(
      store.reserveStagingPermit({
        stagingId: randomUUID(),
        generation: 1,
        bindingId: 'binding-a',
        scopeDigest: DIGESTS.scope,
        leaseId: lease.id,
        keyDigest: KEY_DIGEST,
        inputDigest: INPUT_DIGEST,
        maxEncryptedBytes: preparedReservationBytes(managedExecution),
        effectiveDeadline: FUTURE,
        acquisitionId,
      }),
      (error) => error?.code === 'REQUEST_EXPIRED',
    );
    assert.deepEqual(await store.listManagedReceipts(), []);
  });
});

// Break caught: replay applying shared snapshots incrementally can leave valid legacy maps mutated
// after the final shared snapshot fails structural or revision validation.
test('malformed shared transitions fail replay closed while historical records remain readable', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const seed = storeFor(dataRoot, managedExecution);
    const preflight = await seed.createPreflight({
      id: 'historical-preflight',
      reviewContractSha256: DIGESTS.reviewContract,
      sourceSha256: DIGESTS.source,
      rawSourceSha256: DIGESTS.file,
      profile: 'final_verification_v1',
      profileVersion: '1',
      schemaSha256: DIGESTS.schema,
      registrySha256: DIGESTS.registry,
      itemMaxima: [{ itemId: 'item-grok', maxUsd: 0.20 }],
      requestedUsd: 0.20,
      expiresAt: FUTURE,
    });
    await appendRawRecord(dataRoot, {
      recordType: 'shared/transition',
      version: 99,
      kind: 'MODE_ACTIVATED',
      serviceMode: {},
    });

    const restarted = storeFor(dataRoot, managedExecution);
    await assert.rejects(restarted.getPreflight(preflight.id), /invalid|shared|version|record/i);
  });
});

// Break caught: treating count and encrypted-byte capacity as one heuristic either permits a
// thirty-first tiny preflight or incorrectly claims thirty worst-case reservations fit 200 MiB.
test('managed preflight count and byte saturation are independent durable limits', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);

    for (let index = 0; index < 30; index += 1) {
      await createManagedPreflight(store, managedExecution, acquisitionId);
    }
    await assert.rejects(
      store.reserveManagedPreflightCapacity({
        reservationId: randomUUID(),
        generation: 1,
        bindingId: 'binding-a',
        projectId: 'project-alpha',
        policyEpoch: 1,
        scopeDigest: DIGESTS.scope,
        maxEncryptedBytes: preflightReservationBytes(managedExecution),
        expiresAt: FUTURE,
        acquisitionId,
      }),
      (error) => error?.code === 'REQUEST_CAPACITY_FULL',
    );
  });

  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const reserve = () => store.reserveManagedPreflightCapacity({
      reservationId: randomUUID(),
      generation: 1,
      bindingId: 'binding-a',
      projectId: 'project-alpha',
      policyEpoch: 1,
      scopeDigest: DIGESTS.scope,
      maxEncryptedBytes: preflightReservationBytes(managedExecution),
      expiresAt: FUTURE,
      acquisitionId,
    });
    const outcomes = await Promise.allSettled([reserve(), reserve()]);
    assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
    assert.equal(outcomes.find((outcome) => outcome.status === 'rejected').reason?.code, 'REQUEST_BYTES_FULL');
  });
});

// Break caught: lookup by a global key digest leaks or joins a receipt across a binding, scope, or lease.
test('idempotency lookup is caller-bound and changed input cannot alter its immutable target', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    const admitted = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease, preflightId });

    assert.equal((await store.findReceiptByIdempotency({
      bindingId: 'binding-a', scopeDigest: DIGESTS.scope, leaseId: lease.id, keyDigest: KEY_DIGEST,
    })).receiptId, admitted.receipt.receiptId);
    assert.equal(await store.findReceiptByIdempotency({
      bindingId: 'binding-b', scopeDigest: DIGESTS.scope, leaseId: lease.id, keyDigest: KEY_DIGEST,
    }), null);
    assert.equal(await store.findReceiptByIdempotency({
      bindingId: 'binding-a', scopeDigest: '0'.repeat(64), leaseId: lease.id, keyDigest: KEY_DIGEST,
    }), null);
    await assert.rejects(
      store.assertReceiptInputDigest({ receiptId: admitted.receipt.receiptId, inputDigest: 'f'.repeat(64) }),
      (error) => error?.code === 'IDEMPOTENCY_CONFLICT',
    );
  });
});

// Break caught: keeping aliases only on an in-memory staging object loses a caller's second key
// after an acknowledgement failure and can let a sixty-fifth key bypass the per-lease bound.
test('idempotency aliases are durable, bounded, and resolve the same private receipt', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { owner, acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    const admitted = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease, preflightId });

    const aliasDigests = [];
    for (let index = 1; index < 64; index += 1) {
      const keyDigest = index.toString(16).padStart(64, '0');
      aliasDigests.push(keyDigest);
      const association = await store.associateManagedIdempotencyKey({
        bindingId: 'binding-a', scopeDigest: DIGESTS.scope, leaseId: lease.id,
        keyDigest, inputDigest: INPUT_DIGEST, acquisitionId,
      });
      assert.equal(association.created, true);
      assert.equal(association.receiptId, admitted.receipt.receiptId);
    }
    await assert.rejects(
      store.associateManagedIdempotencyKey({
        bindingId: 'binding-a', scopeDigest: DIGESTS.scope, leaseId: lease.id,
        keyDigest: 'f'.repeat(64), inputDigest: INPUT_DIGEST, acquisitionId,
      }),
      (error) => error?.code === 'LEASE_REQUEST_CONFLICT',
    );

    const privateReceipt = await store.getReceipt({
      receiptId: admitted.receipt.receiptId, bindingId: 'binding-a', scopeDigest: DIGESTS.scope,
    });
    assert.deepEqual(privateReceipt.preparedPayload, admitted.receipt.preparedPayload);
    assert.equal(privateReceipt.keyDigest, KEY_DIGEST);
    assert.equal((await store.lookupManagedIdentity({ selector: { preflightId }, bindingId: 'binding-a' })).projectId, 'project-alpha');
    assert.equal((await store.lookupManagedIdentity({ selector: { leaseId: lease.id }, bindingId: 'binding-a' })).scopeDigest, DIGESTS.scope);
    assert.equal((await store.lookupManagedIdentity({ selector: { receiptId: admitted.receipt.receiptId }, bindingId: 'binding-a' })).policyEpoch, 1);
    assert.equal((await store.lookupManagedIdentity({ selector: { leaseId: lease.id, keyDigest: aliasDigests.at(-1) }, bindingId: 'binding-a' })).projectId, 'project-alpha');
    assert.equal(await store.lookupManagedIdentity({ selector: { receiptId: admitted.receipt.receiptId }, bindingId: 'binding-b' }), null);

    let reads = 0;
    const malformedSelector = {};
    Object.defineProperty(malformedSelector, 'receiptId', { enumerable: true, get() { reads += 1; return admitted.receipt.receiptId; } });
    assert.equal(await store.lookupManagedIdentity({ selector: malformedSelector, bindingId: 'binding-a' }), null);
    assert.equal(reads, 0);

    await owner.release({ final: true });
    const restarted = storeFor(dataRoot, managedExecution);
    const replayed = await restarted.findReceiptByIdempotency({
      bindingId: 'binding-a', scopeDigest: DIGESTS.scope, leaseId: lease.id, keyDigest: aliasDigests.at(-1),
    });
    assert.equal(replayed.receiptId, admitted.receipt.receiptId);
  });
});

// Break caught: reserve-only cancellation refunds jobs/day counters or changes spent money.
test('managed reservation cancellation releases only reserved USD and keeps monotonic counters', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { owner, acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    const admitted = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease, preflightId });
    const claimed = await claimManagedReceipt(store, managedExecution, acquisitionId, owner.generation, admitted);
    const reserved = await store.consumeManaged(lease.id, DIGESTS.reviewContract, {
      receiptId: claimed.receipt.receiptId,
      claimId: claimed.claimId,
      reviewerId: 'grok',
      expectedReceiptRevision: claimed.receipt.revision,
      executionGroupId: claimed.executionGroup.executionGroupId,
      expectedGroupRevision: claimed.executionGroup.revision,
      reservationUsd: 0.10,
      jobId: '9'.repeat(64),
      countsTowardDailyAllowance: true,
      acquisitionId,
    });
    const cancelled = await store.releaseCancellableReservation({
      receiptId: reserved.receipt.receiptId,
      expectedReceiptRevision: reserved.receipt.revision,
      executionGroupId: reserved.executionGroup.executionGroupId,
      expectedGroupRevision: reserved.executionGroup.revision,
      jobId: reserved.job.id,
      expectedJobRevision: reserved.job.revision,
      claimId: claimed.claimId,
      reason: 'CANCELLED',
      acquisitionId,
    });

    assert.equal(cancelled.job.state, 'CANCELLED_ZERO_DISPATCH');
    assert.equal(cancelled.job.costUsd, undefined);
    assert.equal(cancelled.lease.reservedUsd, 0);
    assert.equal(cancelled.lease.spentUsd, 0);
    assert.equal(cancelled.lease.jobsConsumed, 1);
  });
});

// Break caught: replaying a previous process's staging permit leaves a late prepared writer able
// to admit content after the new owner has released that permit.
test('replay barrier recovery releases prior-owner staging and rejects every late commit', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const first = storeFor(dataRoot, managedExecution);
    const { owner: firstOwner, acquisitionId: firstAcquisitionId } = await acquireOwner(first);
    const mode = await activateManagedMode(first, managedExecution, firstAcquisitionId);
    const { preflightId } = await createManagedPreflight(first, managedExecution, firstAcquisitionId);
    const lease = await createManagedLease(first, preflightId, firstAcquisitionId);
    const stagingId = randomUUID();
    await first.reserveStagingPermit({
      stagingId,
      generation: 1,
      bindingId: 'binding-a',
      scopeDigest: DIGESTS.scope,
      leaseId: lease.id,
      keyDigest: KEY_DIGEST,
      inputDigest: INPUT_DIGEST,
      maxEncryptedBytes: preparedReservationBytes(managedExecution),
      effectiveDeadline: FUTURE,
      acquisitionId: firstAcquisitionId,
    });
    const built = receiptFor({ leaseId: lease.id, preflightId });
    managedExecution.storageProofs.publish({
      kind: 'prepared',
      target: { stagingId, generation: 1 },
      refs: [...built.preparedPayload.requestRefs, built.preparedPayload.envelopeRef],
    });
    await firstOwner.release({ final: true });

    const restarted = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(restarted);
    await restarted.beginManagedReplay({ expectedModeRevision: mode.revision, acquisitionId });
    assert.deepEqual(await restarted.recoverStagingPermits({ acquisitionId }), { releasedStagingIds: [stagingId] });
    await assert.rejects(
      restarted.commitStagedReceipt({
        stagingId,
        generation: 1,
        receipt: built.receipt,
        executionGroup: {
          recordType: 'shared/execution-group', version: 1, executionGroupId: randomUUID(), revision: 1,
          executionFingerprint: built.receipt.executionFingerprint, scopeDigest: DIGESTS.scope,
          state: 'OPEN', orderedReceiptIds: [built.receipt.receiptId], reviewerIds: ['grok'],
        },
        preparedPayload: built.preparedPayload,
        exactEncryptedBytes: built.exactEncryptedBytes,
        mappingPins: built.receipt.mappingPins,
        acquisitionId,
      }),
      (error) => error?.code === 'STAGING_STALE',
    );
    assert.deepEqual(await restarted.listManagedReceipts(), []);
  });
});

// Break caught: treating a previous process's scrub reservation as current can admit late
// protected context after the new replay barrier or release the wrong generation's capacity.
test('preflight reservation recovery is generation- and replay-barrier-fenced', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const first = storeFor(dataRoot, managedExecution);
    const { owner: firstOwner, acquisitionId: firstAcquisitionId } = await acquireOwner(first);
    const mode = await activateManagedMode(first, managedExecution, firstAcquisitionId);
    const reservationId = randomUUID();
    await first.reserveManagedPreflightCapacity({
      reservationId,
      generation: 1,
      bindingId: 'binding-a',
      projectId: 'project-alpha',
      policyEpoch: 1,
      scopeDigest: DIGESTS.scope,
      maxEncryptedBytes: preflightReservationBytes(managedExecution),
      expiresAt: FUTURE,
      acquisitionId: firstAcquisitionId,
    });
    await firstOwner.release({ final: true });

    const restarted = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(restarted);
    await restarted.beginManagedReplay({ expectedModeRevision: mode.revision, acquisitionId });
    assert.deepEqual(await restarted.recoverManagedPreflightReservations({ acquisitionId }), {
      releasedReservationIds: [reservationId],
    });
    await assert.rejects(
      restarted.releaseManagedPreflightReservation({
        reservationId,
        generation: 1,
        reason: 'ABANDONED',
        acquisitionId,
      }),
      (error) => error?.code === 'STAGING_STALE',
    );
  });
});

// Break caught: trusting a caller's deletion assertion releases ciphertext capacity while the
// associated protected objects still exist.
test('released preflight bytes remain charged until trusted inspection proves every object absent', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const realStorageProofs = createFakeStorageProofs();
    let deletionEnabled = false;
    const storageProofs = {
      ...realStorageProofs,
      deleteRetired(args) { if (deletionEnabled) realStorageProofs.deleteRetired(args); },
    };
    const managedExecution = managedExecutionFor(dataRoot, { storageProofs });
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const reservationId = randomUUID();
    const target = { reservationId, generation: 1 };
    const refs = [
      { objectId: randomUUID(), sha256: DIGESTS.context, encryptedBytes: 2_048 },
      { objectId: randomUUID(), sha256: DIGESTS.mapping, encryptedBytes: 1_024 },
    ];
    await store.reserveManagedPreflightCapacity({
      reservationId,
      generation: 1,
      bindingId: 'binding-a',
      projectId: 'project-alpha',
      policyEpoch: 1,
      scopeDigest: DIGESTS.scope,
      maxEncryptedBytes: preflightReservationBytes(managedExecution),
      expiresAt: FUTURE,
      acquisitionId,
    });
    managedExecution.storageProofs.publish({ kind: 'preflight', target, refs });
    await store.releaseManagedPreflightReservation({
      reservationId,
      generation: 1,
      reason: 'PREPARE_FAILED',
      acquisitionId,
    });

    await assert.rejects(
      store.ackReleasedPreflightReservationPayloadDeletion({ reservationId, generation: 1, acquisitionId }),
      /present|deletion|proof|manifest/i,
    );
    deletionEnabled = true;
    const ack = await store.ackReleasedPreflightReservationPayloadDeletion({ reservationId, generation: 1, acquisitionId });
    assert.deepEqual(ack.target, target);
    await assert.rejects(
      store.ackReleasedPreflightReservationPayloadDeletion({ reservationId, generation: 1, acquisitionId }),
      /already|stale|revision|deletion/i,
    );
  });
});

// Break caught: deleting context/mapping before a durable retirement tombstone loses the only
// auditable object IDs, while retaining the old pin forever prevents bounded cleanup.
test('preflight retirement writes exact audit refs before trusted deletion and removes its pin', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const created = await createManagedPreflight(store, managedExecution, acquisitionId);

    assert.deepEqual(await store.listPinnedMappings(), [{
      preflightId: created.preflightId,
      mappingIdentity: DIGESTS.mapping,
      receiptIds: [],
    }]);
    const retired = await store.retireManagedPreflight({
      preflightId: created.preflightId,
      expectedRevision: created.preflight.revision,
      reason: 'EXPIRED',
      acquisitionId,
    });
    assert.equal(retired.tombstone.retiredContextAuditRef.objectId, created.refs.contextRef.objectId);
    assert.equal(retired.tombstone.retiredMappingAuditRef.objectId, created.refs.mappingRef.objectId);
    assert.deepEqual(await store.listPinnedMappings(), []);
    const beforeAck = await readLedgerRecords(dataRoot);
    assert.equal(beforeAck.at(-1).kind, 'MANAGED_PREFLIGHT_RETIRED');

    const ack = await store.ackManagedPreflightPayloadDeletion({
      preflightId: created.preflightId,
      expectedRevision: retired.preflight.revision,
      acquisitionId,
    });
    assert.deepEqual(ack.context, { objectId: created.refs.contextRef.objectId, sha256: created.refs.contextRef.sha256 });
    assert.deepEqual(ack.mapping, { objectId: created.refs.mappingRef.objectId, sha256: created.refs.mappingRef.sha256 });
    const inspection = managedExecution.storageProofs.inspectTarget({
      kind: 'preflight', target: { reservationId: created.reservationId, generation: created.generation },
    });
    assert.ok(inspection.objects.every((entry) => entry.present === false));
    await assert.rejects(
      store.ackManagedPreflightPayloadDeletion({
        preflightId: created.preflightId,
        expectedRevision: retired.preflight.revision,
        acquisitionId,
      }),
      /already|revision|deletion/i,
    );
  });
});

// Break caught: removing a terminal prepared payload directly can erase its refs without a
// receipt tombstone, and a terminal audit-only receipt can be mistaken for live mapping work.
test('terminal prepared payload retirement is tombstone-first and sweeps only its exact objects', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    const admitted = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease, preflightId });
    const terminal = await store.cancelQueuedReceipt({
      receiptId: admitted.receipt.receiptId,
      expectedRevision: admitted.receipt.revision,
      executionGroupId: admitted.executionGroup.executionGroupId,
      expectedGroupRevision: admitted.executionGroup.revision,
      acquisitionId,
    });
    const pins = await store.listPinnedMappings();
    assert.deepEqual(pins, [{ preflightId, mappingIdentity: DIGESTS.mapping, receiptIds: [] }]);

    const retired = await store.retireManagedPayload({
      receiptId: terminal.receiptId,
      expectedRevision: terminal.revision,
      acquisitionId,
    });
    assert.equal(retired.receipt.preparedPayload, undefined);
    assert.deepEqual(retired.tombstone.retiredPreparedPayloadAudit, retired.receipt.retiredPreparedPayloadAudit);
    assert.equal((await readLedgerRecords(dataRoot)).at(-1).kind, 'PAYLOAD_RETIRED');
    assert.deepEqual(await store.sweepRetiredManagedPayloads({ acquisitionId }), { deletedReceiptIds: [terminal.receiptId] });
    const inspection = managedExecution.storageProofs.inspectTarget({
      kind: 'prepared', target: { stagingId: admitted.stagingId, generation: 1 },
    });
    assert.ok(inspection.objects.every((entry) => entry.present === false));
  });
});

// Break caught: deleteRetired ran before the trusted manifest was proven complete and
// byte-for-byte identical to the receipt tombstone, so a bad adapter response could delete first.
test('retired payload sweep proves exact manifest refs before deletion and repeats proof after', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const baseStorageProofs = createFakeStorageProofs();
    let inspectionMode = 'exact';
    let inspectionCalls = 0;
    let deleteCalls = 0;
    const storageProofs = {
      ...baseStorageProofs,
      inspectTarget(args) {
        inspectionCalls += 1;
        const inspected = baseStorageProofs.inspectTarget(args);
        if (inspectionMode === 'incomplete') return { complete: false, objects: inspected.objects };
        if (inspectionMode === 'mismatch' && inspected.objects.length > 0) {
          inspected.objects[0].ref.sha256 = '0'.repeat(64);
        }
        if (inspectionMode === 'post-incomplete' && inspectionCalls === 2) {
          return { complete: false, objects: inspected.objects };
        }
        return inspected;
      },
      deleteRetired(args) {
        deleteCalls += 1;
        if (inspectionMode !== 'post-incomplete') baseStorageProofs.deleteRetired(args);
      },
    };
    const managedExecution = managedExecutionFor(dataRoot, { storageProofs });
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const lease = await createManagedLease(store, preflightId, acquisitionId);
    const admitted = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease, preflightId });
    const terminal = await store.cancelQueuedReceipt({
      receiptId: admitted.receipt.receiptId,
      expectedRevision: admitted.receipt.revision,
      executionGroupId: admitted.executionGroup.executionGroupId,
      expectedGroupRevision: admitted.executionGroup.revision,
      acquisitionId,
    });
    await store.retireManagedPayload({ receiptId: terminal.receiptId, expectedRevision: terminal.revision, acquisitionId });

    inspectionMode = 'incomplete';
    await assert.rejects(store.sweepRetiredManagedPayloads({ acquisitionId }), /protected|manifest|content/i);
    assert.equal(deleteCalls, 0);
    inspectionMode = 'mismatch';
    await assert.rejects(store.sweepRetiredManagedPayloads({ acquisitionId }), /protected|manifest|content/i);
    assert.equal(deleteCalls, 0);
    inspectionMode = 'post-incomplete';
    inspectionCalls = 0;
    await assert.rejects(store.sweepRetiredManagedPayloads({ acquisitionId }), /protected|manifest|content/i);
    assert.equal(deleteCalls, 1);
    inspectionMode = 'exact';
    assert.deepEqual(await store.sweepRetiredManagedPayloads({ acquisitionId }), { deletedReceiptIds: [terminal.receiptId] });
    assert.equal(deleteCalls, 2);
  });
});

// Break caught: orphan purge treated every non-RESERVED prepared manifest as deletable,
// including accepted, referenced, foreign-format, wrong-generation, current-barrier and new files.
test('orphan purge deletes only an exact old-barrier released staging generation', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const first = storeFor(dataRoot, managedExecution);
    const { owner: firstOwner, acquisitionId: firstAcquisitionId } = await acquireOwner(first);
    const firstMode = await activateManagedMode(first, managedExecution, firstAcquisitionId);
    const { preflightId } = await createManagedPreflight(first, managedExecution, firstAcquisitionId);

    const acceptedLease = await createManagedLease(first, preflightId, firstAcquisitionId);
    const accepted = await admitManagedReceipt(first, managedExecution, firstAcquisitionId, { lease: acceptedLease, preflightId });
    const targets = {};
    const reserveOld = async (name, refs, manifestOverrides = {}) => {
      const lease = await createManagedLease(first, preflightId, firstAcquisitionId);
      const stagingId = randomUUID();
      const staging = await first.reserveStagingPermit({
        stagingId,
        generation: 1,
        bindingId: 'binding-a',
        scopeDigest: DIGESTS.scope,
        leaseId: lease.id,
        keyDigest: randomUUID().replaceAll('-', '').padEnd(64, '0'),
        inputDigest: randomUUID().replaceAll('-', '').padEnd(64, '1'),
        maxEncryptedBytes: preparedReservationBytes(managedExecution),
        effectiveDeadline: FUTURE,
        acquisitionId: firstAcquisitionId,
      });
      const target = { stagingId, generation: manifestOverrides.generation ?? 1 };
      const manifestCreatedAt = typeof manifestOverrides.createdAt === 'function'
        ? manifestOverrides.createdAt(staging.createdAt)
        : (manifestOverrides.createdAt ?? staging.createdAt);
      managedExecution.storageProofs.publish({
        kind: 'prepared',
        target,
        refs,
        creationBarrierId: firstMode.replayBarrierId,
        createdAt: manifestCreatedAt,
        featureFormatVersion: manifestOverrides.featureFormatVersion ?? 1,
      });
      targets[name] = { target, refs };
    };
    const newRef = () => ({ objectId: randomUUID(), sha256: DIGESTS.file, encryptedBytes: 128 });
    await reserveOld('eligible', [newRef()]);
    await reserveOld('foreignFormat', [newRef()], { featureFormatVersion: 2 });
    await reserveOld('wrongGeneration', [newRef()], { generation: 2 });
    await reserveOld('changedCreationTime', [newRef()], {
      createdAt: (stagingCreatedAt) => new Date(Date.parse(stagingCreatedAt) + 1).toISOString(),
    });
    await reserveOld('tooNew', [newRef()], { createdAt: LATER });
    await reserveOld('referenced', [accepted.receipt.preparedPayload.envelopeRef]);
    await firstOwner.release({ final: true });

    const restarted = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(restarted);
    const replayMode = await restarted.beginManagedReplay({ expectedModeRevision: firstMode.revision, acquisitionId });
    await restarted.recoverStagingPermits({ acquisitionId });
    const currentLease = await createManagedLease(restarted, preflightId, acquisitionId);
    const currentTarget = { stagingId: randomUUID(), generation: 1 };
    const currentStaging = await restarted.reserveStagingPermit({
      ...currentTarget,
      bindingId: 'binding-a',
      scopeDigest: DIGESTS.scope,
      leaseId: currentLease.id,
      keyDigest: '7'.repeat(64),
      inputDigest: '8'.repeat(64),
      maxEncryptedBytes: preparedReservationBytes(managedExecution),
      effectiveDeadline: FUTURE,
      acquisitionId,
    });
    const currentRefs = [newRef()];
    managedExecution.storageProofs.publish({
      kind: 'prepared', target: currentTarget, refs: currentRefs,
      creationBarrierId: replayMode.replayBarrierId, createdAt: currentStaging.createdAt,
    });
    await restarted.releaseStagingPermit({ ...currentTarget, reason: 'PREPARE_FAILED', acquisitionId });

    assert.deepEqual(await restarted.purgeUnadmittedManagedPayloads({
      completedReplayBarrierId: replayMode.replayBarrierId,
      acquisitionId,
    }), { deletedObjectIds: targets.eligible.refs.map((ref) => ref.objectId) });

    const deletedTargets = managedExecution.storageProofs.deletionCalls().map((entry) => JSON.stringify(entry.target));
    assert.deepEqual(deletedTargets, [JSON.stringify(targets.eligible.target)]);
    for (const candidate of [targets.foreignFormat, targets.wrongGeneration, targets.changedCreationTime, targets.tooNew, targets.referenced, { target: currentTarget }]) {
      assert.ok(!deletedTargets.includes(JSON.stringify(candidate.target)));
    }
    assert.ok(!deletedTargets.includes(JSON.stringify({ stagingId: accepted.stagingId, generation: 1 })));
  });
});

// Break caught: clearing service mode while a dispatchable managed lease survives lets a standalone
// process interpret managed authority without its service fence.
test('service mode cannot clear while a managed lease remains dispatchable', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { acquisitionId } = await acquireOwner(store);
    const mode = await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    await createManagedLease(store, preflightId, acquisitionId);
    await assert.rejects(
      store.clearServiceMode({ expectedRevision: mode.revision, acquisitionId }),
      (error) => error?.code === 'SERVICE_ROLLBACK_BLOCKED',
    );
  });
});

// Break caught: admission accepted every equal execution as a new group, so callers could not
// share settled reviewer work and the persisted fifteen-member group bound was never exercised.
test('equal receipts join one bounded group and the sixteenth member starts a fresh group', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { owner, acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);

    const admitted = [];
    for (let index = 0; index < 15; index += 1) {
      const lease = await createManagedLease(store, preflightId, acquisitionId);
      admitted.push(await admitManagedReceipt(store, managedExecution, acquisitionId, {
        lease,
        preflightId,
        keyDigest: index.toString(16).padStart(64, '0'),
      }));
    }

    const firstGroupId = admitted[0].executionGroup.executionGroupId;
    assert.ok(admitted.every((entry) => entry.executionGroup.executionGroupId === firstGroupId));
    assert.equal(admitted[0].receipt.state, 'QUEUED');
    assert.ok(admitted.slice(1).every((entry) => entry.receipt.state === 'WAITING'));
    assert.equal(admitted.at(-1).executionGroup.orderedReceiptIds.length, 15);

    const terminalLeader = await store.cancelQueuedReceipt({
      receiptId: admitted[0].receipt.receiptId,
      expectedRevision: admitted[0].receipt.revision,
      executionGroupId: firstGroupId,
      expectedGroupRevision: admitted.at(-1).executionGroup.revision,
      acquisitionId,
    });
    assert.equal(terminalLeader.state, 'TERMINAL');
    const followerView = await store.recoverManagedReceipt({
      receiptId: admitted[1].receipt.receiptId,
      acquisitionId,
    });
    const followerClaimId = randomUUID();
    const followerPermit = managedExecution.executionPermits.mint({
      receiptId: followerView.receipt.receiptId,
      claimId: followerClaimId,
      reviewerIds: followerView.receipt.reviewerIds,
      ownerGeneration: owner.generation,
    });
    const followerClaim = await store.claimEligibleReceipt({
      receiptId: followerView.receipt.receiptId,
      expectedRevision: followerView.receipt.revision,
      executionGroupId: firstGroupId,
      expectedGroupRevision: followerView.executionGroup.revision,
      claimId: followerClaimId,
      permit: followerPermit,
      acquisitionId,
    });
    assert.equal(followerClaim.receipt.receiptId, admitted[1].receipt.receiptId);
    assert.equal(followerClaim.receipt.state, 'EXECUTING');

    const sixteenthLease = await createManagedLease(store, preflightId, acquisitionId);
    const sixteenth = await admitManagedReceipt(store, managedExecution, acquisitionId, {
      lease: sixteenthLease,
      preflightId,
      keyDigest: 'f'.repeat(64),
    });
    assert.notEqual(sixteenth.executionGroup.executionGroupId, firstGroupId);
    assert.equal(sixteenth.executionGroup.orderedReceiptIds.length, 1);
    assert.equal(sixteenth.receipt.state, 'QUEUED');
  });
});

// Break caught: terminalizing a claimed leader can clear the group claim too early or leave the
// terminal member at the head forever, preventing the oldest waiting follower from succeeding it.
test('terminal claimed leader retires explicitly before the oldest follower can claim', async () => {
  await withManagedDataRoot(async (dataRoot) => {
    const managedExecution = managedExecutionFor(dataRoot);
    const store = storeFor(dataRoot, managedExecution);
    const { owner, acquisitionId } = await acquireOwner(store);
    await activateManagedMode(store, managedExecution, acquisitionId);
    const { preflightId } = await createManagedPreflight(store, managedExecution, acquisitionId);
    const firstLease = await createManagedLease(store, preflightId, acquisitionId);
    const first = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease: firstLease, preflightId });
    const secondLease = await createManagedLease(store, preflightId, acquisitionId);
    const second = await admitManagedReceipt(store, managedExecution, acquisitionId, {
      lease: secondLease,
      preflightId,
      keyDigest: '9'.repeat(64),
    });
    const groupView = await store.recoverManagedReceipt({ receiptId: first.receipt.receiptId, acquisitionId });
    const leader = await claimManagedReceipt(store, managedExecution, acquisitionId, owner.generation, {
      receipt: groupView.receipt,
      executionGroup: groupView.executionGroup,
    });
    await store.requestManagedCancellation({
      receiptId: leader.receipt.receiptId,
      expectedRevision: leader.receipt.revision,
      executionGroupId: leader.executionGroup.executionGroupId,
      expectedGroupRevision: leader.executionGroup.revision,
      claimId: leader.claimId,
      acquisitionId,
    });
    await terminalizeManagedFixture(store, managedExecution, acquisitionId, leader.receipt.receiptId,
      { kind: 'CANCELLED', errorCode: 'REQUEST_CANCELLED', leaseDisposition: 'CANCELLED' });
    const terminalView = await store.recoverManagedReceipt({ receiptId: leader.receipt.receiptId, acquisitionId });
    assert.equal(terminalView.executionGroup.state, 'CLAIMED');
    const retired = await store.retireManagedClaim({
      receiptId: terminalView.receipt.receiptId,
      expectedRevision: terminalView.receipt.revision,
      executionGroupId: terminalView.executionGroup.executionGroupId,
      expectedGroupRevision: terminalView.executionGroup.revision,
      claimId: leader.claimId,
      reason: 'TERMINALIZED',
      acquisitionId,
    });
    assert.equal(retired.state, 'TERMINAL');
    const followerView = await store.recoverManagedReceipt({ receiptId: second.receipt.receiptId, acquisitionId });
    assert.equal(followerView.executionGroup.state, 'OPEN');
    const follower = await claimManagedReceipt(store, managedExecution, acquisitionId, owner.generation, {
      receipt: followerView.receipt,
      executionGroup: followerView.executionGroup,
    });
    assert.equal(follower.receipt.receiptId, second.receipt.receiptId);
    assert.equal(follower.receipt.state, 'EXECUTING');
  });
});
