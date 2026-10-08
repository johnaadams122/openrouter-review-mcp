import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { canonicalJson } from '../../src/local-mcp/shared/contracts.mjs';
import { configurationFingerprint, largestAllowedReviewerCount, maximumPreflightEncryptedBytes, maximumPreparedEncryptedBytes } from '../../src/local-mcp/shared/policy.mjs';
import { buildInstallationConfig, buildManifest, DIGESTS } from './shared-policy-fixture.mjs';

export const NOW = Date.parse('2026-09-19T17:00:00.000Z');
export const FUTURE = '2026-09-19T18:00:00.000Z';
export const LATER = '2026-09-19T19:00:00.000Z';
export const KEY_DIGEST = 'a1'.repeat(32);
export const INPUT_DIGEST = 'b2'.repeat(32);
export const EXECUTION_FINGERPRINT = 'c3'.repeat(32);
export const SNAPSHOT_SOURCE_ID = 'd4'.repeat(32);
export const SNAPSHOT_CONTEXT_ID = 'e5'.repeat(32);
// Managed records must name a project the fixture installation config registers, so read it from there.
export const PROJECT_ID = buildInstallationConfig().projects[0].projectId;

function targetKey(kind, target) {
  return `${kind}:${canonicalJson(target)}`;
}

function sameRef(left, right) {
  return left.objectId === right.objectId
    && left.sha256 === right.sha256
    && left.encryptedBytes === right.encryptedBytes;
}

export function createFakeStorageProofs() {
  const manifests = new Map();
  const advisories = new Map();
  const terminalProofs = new Map();
  const permanentLossProofs = new Map();
  const deletions = [];
  const seals = [];
  const advisoryKey = (receiptId, jobId) => `${receiptId}\0${jobId}`;
  const terminalKey = (receiptId, publicationId) => `${receiptId}\0${publicationId}`;
  return Object.freeze({
    publish({ kind, target, refs, createdAt = new Date(NOW).toISOString(), creationBarrierId = randomUUID(), featureFormatVersion = 1 }) {
      // Like the real store, a sealed target refuses any later put (its private creation barrier never matches).
      if (manifests.get(targetKey(kind, target))?.sealed === true) {
        throw Object.assign(new Error('protected object conflict'), { code: 'PROTECTED_OBJECT_CONFLICT' });
      }
      manifests.set(targetKey(kind, target), {
        kind,
        target: structuredClone(target),
        refs: structuredClone(refs),
        createdAt,
        creationBarrierId,
        featureFormatVersion,
      });
    },
    verifyPublished({ kind, target, refs }) {
      const manifest = manifests.get(targetKey(kind, target));
      if (manifest === undefined
        || manifest.refs.length !== refs.length
        || !manifest.refs.every((ref, index) => sameRef(ref, refs[index]))) {
        throw new Error('trusted storage proof mismatch');
      }
    },
    inspectTarget({ kind, target }) {
      const manifest = manifests.get(targetKey(kind, target));
      if (manifest === undefined) return { complete: false, objects: [] };
      return {
        complete: true,
        objects: manifest.refs.map((entry) => {
          const { present, ...ref } = entry;
          return { ref: structuredClone(ref), present: present !== false };
        }),
      };
    },
    deleteRetired({ descriptor }) {
      const manifest = manifests.get(targetKey(descriptor.kind, descriptor.target));
      if (manifest === undefined) throw new Error('trusted storage target is missing');
      const refs = manifest.refs.map(({ present: _present, ...ref }) => ref);
      if (canonicalJson(refs) !== canonicalJson(descriptor.refs)) throw new Error('trusted storage deletion refs mismatch');
      deletions.push(structuredClone(descriptor));
      manifest.refs = manifest.refs.map((entry) => ({ ...entry, present: false }));
    },
    listManifestTargets() {
      return [...manifests.values()].map((entry) => structuredClone(entry));
    },
    // The real store's optional seal: a preflight target that already has a manifest row is left alone; one without a
    // row gets an empty row, which reads back as a complete manifest with no objects, and later puts are refused.
    async sealTarget({ kind, target }) {
      if (kind !== 'preflight') throw new TypeError('seal kind is invalid');
      const sealed = !manifests.has(targetKey(kind, target));
      if (sealed) {
        manifests.set(targetKey(kind, target), {
          kind, target: structuredClone(target), refs: [], createdAt: new Date(NOW).toISOString(),
          creationBarrierId: randomUUID(), featureFormatVersion: 1, sealed: true,
        });
      }
      seals.push({ target: structuredClone(target), sealed });
      return { sealed };
    },
    sealCalls() { return structuredClone(seals); },
    publishAdvisory({ receiptId, jobId, advisoryRef }) {
      advisories.set(advisoryKey(receiptId, jobId), structuredClone(advisoryRef));
    },
    verifyAdvisoryPublication({ receiptId, jobId, advisoryRef }) {
      const current = advisories.get(advisoryKey(receiptId, jobId));
      if (current === undefined || canonicalJson(current) !== canonicalJson(advisoryRef)) {
        throw new Error('trusted advisory proof mismatch');
      }
      return true;
    },
    publishTerminalProof({ receiptId, publicationId, terminalRef, terminalDigest }) {
      terminalProofs.set(terminalKey(receiptId, publicationId), structuredClone({ terminalRef, terminalDigest }));
    },
    proveTerminalPublication({ receiptId, publicationId }) {
      const proof = terminalProofs.get(terminalKey(receiptId, publicationId));
      if (proof === undefined) throw new Error('trusted terminal proof mismatch');
      return structuredClone(proof);
    },
    publishPermanentTerminalLoss({ receiptId, publicationId, frozenAdvisoryAssociations, reason }) {
      permanentLossProofs.set(terminalKey(receiptId, publicationId), structuredClone({ frozenAdvisoryAssociations, reason }));
    },
    provePermanentTerminalPublicationLoss({ receiptId, publicationId, frozenAdvisoryAssociations }) {
      const proof = permanentLossProofs.get(terminalKey(receiptId, publicationId));
      if (proof === undefined || canonicalJson(proof.frozenAdvisoryAssociations) !== canonicalJson(frozenAdvisoryAssociations)) {
        throw new Error('trusted permanent-loss proof mismatch');
      }
      return { reason: proof.reason };
    },
    markAbsent(kind, target) {
      const manifest = manifests.get(targetKey(kind, target));
      assert.ok(manifest, 'test manifest must exist');
      manifest.refs = manifest.refs.map((entry) => ({ ...entry, present: false }));
    },
    deletionCalls() { return structuredClone(deletions); },
  });
}

export function createFakeExecutionPermits() {
  const live = new Map();
  return Object.freeze({
    mint({ receiptId, claimId, reviewerIds, ownerGeneration = 1 }) {
      const token = Object.freeze({ nonce: randomUUID() });
      const permitTokenDigest = createHash('sha256').update(token.nonce).digest('hex');
      const permit = Object.freeze({
        token,
        permitTokenDigest,
        permitSetRevision: 1,
        activeBatchUnits: 1,
        reviewerIds: Object.freeze([...reviewerIds]),
      });
      live.set(token, { receiptId, claimId, reviewerIds: [...reviewerIds], ownerGeneration, permit });
      return permit;
    },
    assertLive({ receiptId, claimId, token, reviewerIds, ownerGeneration }) {
      const entry = live.get(token);
      if (entry === undefined
        || entry.receiptId !== receiptId
        || entry.claimId !== claimId
        || entry.ownerGeneration !== ownerGeneration
        || canonicalJson(entry.reviewerIds) !== canonicalJson(reviewerIds)) {
        throw new Error('execution permit is stale or foreign');
      }
      const { token: _runtimeToken, ...durable } = entry.permit;
      return Object.freeze(durable);
    },
  });
}

export async function withManagedDataRoot(run) {
  const prefix = 'openrouter-shared-ledger-';
  const resolvedTmpRoot = resolve(tmpdir());
  const dataRoot = resolve(await mkdtemp(join(resolvedTmpRoot, prefix)));
  try {
    return await run(dataRoot);
  } finally {
    if (dirname(dataRoot) !== resolvedTmpRoot
      || !dataRoot.startsWith(`${resolvedTmpRoot}${sep}`)
      || !basename(dataRoot).startsWith(prefix)) {
      throw new Error('refusing to remove a path outside the owned shared-ledger test prefix');
    }
    await rm(dataRoot, { recursive: true, force: true });
  }
}

export function managedExecutionFor(dataRoot, overrides = {}) {
  return {
    installationConfig: buildInstallationConfig({ dataRoot }),
    buildManifest: buildManifest(),
    storageProofs: createFakeStorageProofs(),
    executionPermits: createFakeExecutionPermits(),
    ...overrides,
  };
}

export function preparedReservationBytes(managedExecution, profileId = 'final_verification_v1') {
  const profile = managedExecution.installationConfig.review.allowedProfiles.find((entry) => entry.profileId === profileId);
  assert.ok(profile, `test profile ${profileId} must exist`);
  return maximumPreparedEncryptedBytes({
    reviewerCount: largestAllowedReviewerCount(profile),
    maxRequestBytes: managedExecution.installationConfig.engine.maxRequestBytes,
  });
}

export function preflightReservationBytes(managedExecution) {
  return maximumPreflightEncryptedBytes({
    maxSinglePreflightPlaintextBytes: managedExecution.installationConfig.storage.maxSinglePreflightPlaintextBytes,
  });
}

export async function acquireOwner(store) {
  const owner = await store.acquireProcessOwnership({ acquireTimeoutMs: 1_000 });
  return { owner, acquisitionId: owner.acquisitionId };
}

export async function activateManagedMode(store, managedExecution, acquisitionId) {
  return store.activateServiceMode({
    configFingerprint: configurationFingerprint(managedExecution.installationConfig, managedExecution.buildManifest),
    buildManifestFingerprint: managedExecution.installationConfig.buildManifestSha256,
    acquisitionId,
  });
}

export function protectedRefs() {
  return {
    contextRef: { objectId: randomUUID(), sha256: DIGESTS.context, encryptedBytes: 2_048 },
    mappingRef: { objectId: randomUUID(), sha256: DIGESTS.mapping, encryptedBytes: 1_024 },
  };
}

export async function createManagedPreflight(store, managedExecution, acquisitionId, overrides = {}) {
  const reservationId = randomUUID();
  const generation = 1;
  const preflightId = overrides.preflightId ?? randomUUID();
  const refs = protectedRefs();
  const scopeDigest = overrides.scopeDigest ?? DIGESTS.scope;
  const maxEncryptedBytes = preflightReservationBytes(managedExecution);
  await store.reserveManagedPreflightCapacity({
    reservationId,
    generation,
    bindingId: 'binding-a',
    projectId: PROJECT_ID,
    policyEpoch: 1,
    scopeDigest,
    maxEncryptedBytes,
    expiresAt: overrides.expiresAt ?? FUTURE,
    acquisitionId,
  });
  managedExecution.storageProofs.publish({
    kind: 'preflight',
    target: { reservationId, generation },
    refs: [refs.contextRef, refs.mappingRef],
  });
  const preflight = await store.commitManagedPreflight({
    reservationId,
    generation,
    preflight: {
      id: preflightId,
      state: 'PREFLIGHTED',
      reviewContractSha256: DIGESTS.reviewContract,
      sourceSha256: DIGESTS.source,
      rawSourceSha256: DIGESTS.file,
      profile: 'final_verification_v1',
      profileVersion: '1',
      schemaSha256: DIGESTS.schema,
      registrySha256: DIGESTS.registry,
      itemMaxima: [{ itemId: 'item-grok', maxUsd: 0.20 }],
      requestedUsd: 0.20,
      expiresAt: overrides.expiresAt ?? FUTURE,
    },
    managedIdentity: {
      bindingId: 'binding-a',
      scopeDigest,
      projectId: PROJECT_ID,
      policyEpoch: 1,
      snapshotSourceId: SNAPSHOT_SOURCE_ID,
      snapshotContextId: SNAPSHOT_CONTEXT_ID,
      mappingIdentity: DIGESTS.mapping,
      identityKeyVersion: 'identity-v1',
      contextRef: refs.contextRef,
      mappingRef: refs.mappingRef,
    },
    contextRef: refs.contextRef,
    mappingRef: refs.mappingRef,
    exactEncryptedBytes: refs.contextRef.encryptedBytes + refs.mappingRef.encryptedBytes,
    acquisitionId,
  });
  return { preflight, preflightId, reservationId, generation, refs };
}

export async function createManagedLease(store, preflightId, acquisitionId, overrides = {}) {
  return store.createManagedLease({
    preflightId,
    requestedUsd: 0.20,
    maxJobs: 1,
    expiresAt: FUTURE,
    bindingId: 'binding-a',
    scopeDigest: DIGESTS.scope,
    projectId: PROJECT_ID,
    policyEpoch: 1,
    acquisitionId,
    ...overrides,
  });
}

export function receiptFor({ leaseId, preflightId, receiptId = randomUUID(), reviewerIds = ['grok'], scopeDigest = DIGESTS.scope }) {
  const envelopeRef = { objectId: randomUUID(), sha256: DIGESTS.mapping, encryptedBytes: 2_048 };
  const requestRefs = reviewerIds.map(() => ({ objectId: randomUUID(), sha256: DIGESTS.file, encryptedBytes: 4_096 }));
  return {
    receipt: {
      recordType: 'shared/receipt',
      version: 1,
      receiptId,
      revision: 1,
      leaseId,
      preflightId,
      bindingId: 'binding-a',
      projectId: PROJECT_ID,
      policyEpoch: 1,
      scopeDigest,
      keyDigest: KEY_DIGEST,
      inputDigest: INPUT_DIGEST,
      executionFingerprint: EXECUTION_FINGERPRINT,
      snapshotSourceId: SNAPSHOT_SOURCE_ID,
      snapshotContextId: SNAPSHOT_CONTEXT_ID,
      reviewContractSha256: DIGESTS.reviewContract,
      preparedPayload: { envelopeRef, requestRefs },
      mappingPins: [{ preflightId, mappingIdentity: DIGESTS.mapping }],
      reviewerIds,
      acceptedAt: new Date(NOW).toISOString(),
      effectiveDeadline: FUTURE,
      state: 'QUEUED',
    },
    preparedPayload: { envelopeRef, requestRefs },
    exactEncryptedBytes: envelopeRef.encryptedBytes + requestRefs.reduce((sum, ref) => sum + ref.encryptedBytes, 0),
  };
}

export async function admitManagedReceipt(store, managedExecution, acquisitionId, {
  lease,
  preflightId,
  keyDigest = KEY_DIGEST,
  inputDigest = INPUT_DIGEST,
  reviewerIds = ['grok'],
  scopeDigest = DIGESTS.scope,
} = {}) {
  const stagingId = randomUUID();
  await store.reserveStagingPermit({
    stagingId,
    generation: 1,
    bindingId: 'binding-a',
    scopeDigest,
    leaseId: lease.id,
    keyDigest,
    inputDigest,
    maxEncryptedBytes: preparedReservationBytes(managedExecution),
    effectiveDeadline: FUTURE,
    acquisitionId,
  });
  const built = receiptFor({ leaseId: lease.id, preflightId, reviewerIds, scopeDigest });
  built.receipt.keyDigest = keyDigest;
  built.receipt.inputDigest = inputDigest;
  const executionGroup = {
    recordType: 'shared/execution-group',
    version: 1,
    executionGroupId: randomUUID(),
    revision: 1,
    executionFingerprint: built.receipt.executionFingerprint,
    scopeDigest,
    state: 'OPEN',
    orderedReceiptIds: [built.receipt.receiptId],
    reviewerIds,
  };
  managedExecution.storageProofs.publish({
    kind: 'prepared',
    target: { stagingId, generation: 1 },
    refs: [...built.preparedPayload.requestRefs, built.preparedPayload.envelopeRef],
  });
  const receipt = await store.commitStagedReceipt({
    stagingId,
    generation: 1,
    receipt: built.receipt,
    executionGroup,
    preparedPayload: built.preparedPayload,
    exactEncryptedBytes: built.exactEncryptedBytes,
    mappingPins: built.receipt.mappingPins,
    acquisitionId,
  });
  const recovery = await store.recoverManagedReceipt({ receiptId: receipt.receiptId, acquisitionId });
  return { receipt, executionGroup: recovery.executionGroup, stagingId, built };
}

export async function claimManagedReceipt(store, managedExecution, acquisitionId, ownerGeneration, admitted) {
  const claimId = randomUUID();
  const permit = managedExecution.executionPermits.mint({
    receiptId: admitted.receipt.receiptId,
    claimId,
    reviewerIds: admitted.receipt.reviewerIds,
    ownerGeneration,
  });
  const claimed = await store.claimEligibleReceipt({
    receiptId: admitted.receipt.receiptId,
    expectedRevision: admitted.receipt.revision,
    executionGroupId: admitted.executionGroup.executionGroupId,
    expectedGroupRevision: admitted.executionGroup.revision,
    claimId,
    permit,
    acquisitionId,
  });
  return { ...claimed, claimId, permit };
}

export async function readLedgerRecords(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const names = (await readdir(ledgerRoot)).filter((name) => name.endsWith('.json')).sort();
  return Promise.all(names.map(async (name) => JSON.parse(await readFile(join(ledgerRoot, name), 'utf8'))));
}

// Exercise the publication protocol when a lifecycle test does not need real protected content.
export async function terminalizeManagedFixture(store, managedExecution, acquisitionId, receiptId, {
  kind = 'REVIEW_ERROR', errorCode = 'REQUEST_FAILED', leaseDisposition = 'CLOSED',
  completedAt = new Date(NOW).toISOString(), advisoryAssociations,
} = {}) {
  const view = await store.recoverManagedReceipt({ receiptId, acquisitionId });
  const publicationId = randomUUID();
  const associations = advisoryAssociations ?? view.receipt.reviewerIds.map((reviewerId) => {
    const job = view.jobs.find((entry) => entry.reviewerId === reviewerId);
    return { reviewerId, contentAvailable: false, ...(job === undefined ? {} : { sourceReceiptId: receiptId, jobId: job.id }) };
  });
  const begun = await store.beginTerminalPublication({
    receiptId, expectedReceiptRevision: view.receipt.revision,
    executionGroupId: view.executionGroup.executionGroupId, expectedGroupRevision: view.executionGroup.revision,
    claimId: view.receipt.claimId, publicationId, completedAt, outcomeKind: kind,
    ...(kind === 'REVIEW_RETURNED' ? {} : { outcomeErrorCode: errorCode }), leaseDisposition,
    settledStatus: {
      leaseId: view.lease.id, state: view.lease.state, requestedUsd: view.lease.requestedUsd,
      reservedUsd: view.lease.reservedUsd, spentUsd: view.lease.spentUsd,
      jobsConsumed: view.lease.jobsConsumed, maxJobs: view.lease.maxJobs, expiresAt: view.lease.expiresAt,
    },
    advisoryAssociations: associations, acquisitionId,
  });
  managedExecution.storageProofs.publishTerminalProof({ receiptId, publicationId,
    terminalRef: { objectId: publicationId, sha256: DIGESTS.file, encryptedBytes: 512 }, terminalDigest: DIGESTS.file });
  return store.terminalizeReceipt({ receiptId, expectedRevision: begun.receipt.revision,
    executionGroupId: begun.executionGroup.executionGroupId, expectedGroupRevision: begun.executionGroup.revision,
    claimId: begun.receipt.claimId, publicationId, acquisitionId });
}

// A preflight whose review has finished, in the resting state the reclaim helper may retire: one lease, one admitted
// receipt, claimed, terminalized with `kind` at `completedAt` (terminalizeManagedFixture; REVIEW_RETURNED needs no advisory
// association, the terminal validators accept every reviewer as unavailable), and its claim retired (CLAIM_RETIRED leaves
// the execution group TERMINAL). `retireClaim: false` stops inside the claim window (receipt TERMINAL, group still CLAIMED).
// Receipts that share a fingerprint, scope and reviewer list join a group that is not TERMINAL yet, so spend one preflight
// fully before admitting the next, or pass distinct `reviewerIds`.
export async function spendManagedPreflight(store, managedExecution, acquisitionId, {
  preflightId, ownerGeneration = 1, kind = 'REVIEW_RETURNED', completedAt = new Date(NOW).toISOString(),
  reviewerIds = ['grok'], retireClaim = true, leaseOverrides = {},
} = {}) {
  const lease = await createManagedLease(store, preflightId, acquisitionId, leaseOverrides);
  const admitted = await admitManagedReceipt(store, managedExecution, acquisitionId, { lease, preflightId, reviewerIds });
  const claimed = await claimManagedReceipt(store, managedExecution, acquisitionId, ownerGeneration, admitted);
  const terminal = await terminalizeManagedFixture(store, managedExecution, acquisitionId, admitted.receipt.receiptId, {
    kind, completedAt, ...(kind === 'REVIEW_RETURNED' ? {} : { errorCode: kind === 'REVIEW_ERROR' ? 'REQUEST_FAILED' : `REQUEST_${kind}` }),
  });
  let receipt = terminal;
  if (retireClaim) {
    const view = await store.recoverManagedReceipt({ receiptId: terminal.receiptId, acquisitionId });
    receipt = await store.retireManagedClaim({
      receiptId: terminal.receiptId, expectedRevision: terminal.revision,
      executionGroupId: view.executionGroup.executionGroupId, expectedGroupRevision: view.executionGroup.revision,
      claimId: claimed.claimId, reason: 'TERMINALIZED', acquisitionId,
    });
  }
  return { lease, admitted, claimId: claimed.claimId, receipt };
}

export async function appendRawRecord(dataRoot, record, suffix = randomUUID()) {
  const timestamp = record.timestamp ?? new Date(NOW + 10_000).toISOString();
  const path = join(dataRoot, 'ledger', `${timestamp.replace(/[:.]/g, '-')}-${suffix}.json`);
  await writeFile(path, `${JSON.stringify({ ...record, timestamp })}\n`, 'utf8');
  return path;
}
