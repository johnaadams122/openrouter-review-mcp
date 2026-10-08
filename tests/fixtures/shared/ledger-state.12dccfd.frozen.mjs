import { canonicalJson } from './contracts.mjs';

const DIGEST = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const TRANSITION_FIELDS = Object.freeze({
  MODE_ACTIVATED: ['serviceMode'],
  MODE_REPLAY_BARRIER_ADVANCED: ['serviceMode'],
  MODE_CLEARED: ['serviceMode'],
  MANAGED_LEASE_CREATED: ['lease'],
  MANAGED_LEASE_DISPOSED: ['lease'],
  UNADMITTED_LEASE_DISPOSED: ['lease'],
  MANAGED_PREFLIGHT_RESERVED: ['preflightReservation'],
  MANAGED_PREFLIGHT_COMMITTED: ['preflightReservation', 'preflight', 'managedIdentity'],
  MANAGED_PREFLIGHT_RESERVATION_RELEASED: ['preflightReservation'],
  MANAGED_PREFLIGHT_RETIRED: ['preflight', 'managedIdentity', 'preflightTombstone'],
  MANAGED_PREFLIGHT_PAYLOAD_DELETION_ACKED: ['preflightDeletionAck'],
  STAGING_RESERVED: ['staging', 'keyAssociation'],
  STAGING_RELEASED: ['staging'],
  IDEMPOTENCY_KEY_ASSOCIATED: ['keyAssociation'],
  RECEIPT_ADMITTED: ['staging', 'receipt', 'executionGroup', 'lease', 'mappingPins'],
  RECEIPT_CLAIMED: ['receipt', 'executionGroup'],
  CLAIM_RETIRED: ['receipt', 'executionGroup'],
  RECEIPT_TERMINALIZED: ['receipt', 'executionGroup', 'lease'],
  TERMINAL_PUBLICATION_BEGUN: ['receipt', 'executionGroup', 'lease'],
  POST_INTENT_CANCEL_REQUESTED: ['receipt', 'executionGroup', 'lease'],
  MANAGED_CANCEL_REQUESTED: ['receipt', 'executionGroup', 'lease'],
  MANAGED_CONSUMED: ['receipt', 'executionGroup', 'job', 'lease'],
  MANAGED_INTENT_PENDING: ['receipt', 'executionGroup', 'job', 'lease'],
  MANAGED_RESERVATION_CANCELLED: ['receipt', 'executionGroup', 'job', 'lease'],
  MANAGED_RECONCILED: ['receipt', 'executionGroup', 'job', 'lease'],
  MANAGED_EXECUTION_PERMIT_REBOUND: ['receipt', 'executionGroup'],
  MANAGED_RECOVERY_PENDING: ['receipt', 'executionGroup'],
  HEALTH_EFFECT_CLAIMED: ['job'],
  HEALTH_EFFECT_RECORDED: ['job'],
  PAYLOAD_RETIRED: ['receipt', 'tombstone'],
});

function clone(value) { return structuredClone(value); }

function fail(message) { throw new Error(`invalid shared ledger record: ${message}`); }

function strictData(value, name = 'value') {
  if (value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => strictData(entry, `${name}[${index}]`));
    return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) fail(`${name} must be a plain object`);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail(`${name}.${key} must be enumerable data`);
    if (typeof descriptor.value === 'number' && !Number.isFinite(descriptor.value)) fail(`${name}.${key} must be finite`);
    strictData(descriptor.value, `${name}.${key}`);
  }
}

function exactKeys(value, required, optional = [], name = 'object') {
  strictData(value, name);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name} has unknown key ${key}`);
  for (const key of required) if (!Object.hasOwn(value, key)) fail(`${name} is missing ${key}`);
}

function positive(value, name) { if (!Number.isSafeInteger(value) || value <= 0) fail(`${name} must be positive`); }
function bytes(value, name) { if (!Number.isSafeInteger(value) || value < 0) fail(`${name} must be bytes`); }
function uuid(value, name) { if (typeof value !== 'string' || !UUID.test(value)) fail(`${name} must be UUID`); }
function digest(value, name) { if (typeof value !== 'string' || !DIGEST.test(value)) fail(`${name} must be digest`); }
function time(value, name) { if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail(`${name} must be canonical time`); }
function opaque(value, name) { if (typeof value !== 'string' || value.length === 0) fail(`${name} must be a nonempty string`); }
function usd(value, name) { if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail(`${name} must be USD`); }
function bool(value, name) { if (typeof value !== 'boolean') fail(`${name} must be boolean`); }

function validateProtectedRef(value, name) {
  exactKeys(value, ['objectId', 'sha256', 'encryptedBytes'], [], name);
  uuid(value.objectId, `${name}.objectId`); digest(value.sha256, `${name}.sha256`); bytes(value.encryptedBytes, `${name}.encryptedBytes`);
}

function validateAuditRef(value, name, mapping = false) {
  exactKeys(value, ['objectId', 'sha256', 'encryptedBytes', 'retiredAt', ...(mapping ? ['mappingDeleteNoLaterThan'] : [])], [], name);
  uuid(value.objectId, `${name}.objectId`); digest(value.sha256, `${name}.sha256`); bytes(value.encryptedBytes, `${name}.encryptedBytes`);
  time(value.retiredAt, `${name}.retiredAt`); if (mapping) time(value.mappingDeleteNoLaterThan, `${name}.mappingDeleteNoLaterThan`);
}

function validatePreparedPayload(value, name, retired = false) {
  exactKeys(value, ['envelopeRef', 'requestRefs', ...(retired ? ['retiredAt'] : [])], [], name);
  validateProtectedRef(value.envelopeRef, `${name}.envelopeRef`);
  if (!Array.isArray(value.requestRefs) || value.requestRefs.length < 1 || value.requestRefs.length > 15) fail(`${name}.requestRefs must contain 1..15 refs`);
  value.requestRefs.forEach((entry, index) => validateProtectedRef(entry, `${name}.requestRefs[${index}]`));
  if (retired) time(value.retiredAt, `${name}.retiredAt`);
}

function validateMappingPins(value, name = 'mappingPins') {
  if (!Array.isArray(value) || value.length < 1) fail(`${name} must be a nonempty array`);
  for (const [index, pin] of value.entries()) {
    exactKeys(pin, ['preflightId', 'mappingIdentity'], [], `${name}[${index}]`);
    uuid(pin.preflightId, `${name}[${index}].preflightId`); digest(pin.mappingIdentity, `${name}[${index}].mappingIdentity`);
  }
}

const TERMINAL_ERROR_CODES = Object.freeze({
  REVIEW_ERROR: new Set(['REQUEST_FAILED', 'PROTECTED_CONTENT_TOO_LARGE']),
  EXPIRED: new Set(['REQUEST_EXPIRED']),
  CANCELLED: new Set(['REQUEST_CANCELLED']),
  CONTENT_LOST: new Set(['REQUEST_CONTENT_LOST']),
});

const MANAGED_DISPOSITIONS = new Set([
  'CANCELLED', 'EXPIRED', 'CLOSED', 'LEASE_EXPIRED', 'DUPLICATE_DISPATCH_IN_PROGRESS',
  'PROVIDER_MISMATCH', 'STRICT_OUTPUT_INVALID', 'UNKNOWN_COST', 'TRANSPORT_FAILURE',
  'DISPATCH_UNKNOWN', 'ORPHANED_ON_RECOVERY',
]);

function validateSettledStatus(value, name = 'settledStatus') {
  exactKeys(value, ['leaseId', 'state', 'requestedUsd', 'reservedUsd', 'spentUsd', 'jobsConsumed', 'maxJobs', 'expiresAt'], [], name);
  uuid(value.leaseId, `${name}.leaseId`); opaque(value.state, `${name}.state`);
  usd(value.requestedUsd, `${name}.requestedUsd`); usd(value.reservedUsd, `${name}.reservedUsd`); usd(value.spentUsd, `${name}.spentUsd`);
  bytes(value.jobsConsumed, `${name}.jobsConsumed`); positive(value.maxJobs, `${name}.maxJobs`); time(value.expiresAt, `${name}.expiresAt`);
}

function validateTerminalPublication(value, reviewerIds, claimId) {
  exactKeys(value, ['version', 'publicationId', 'claimId', 'completedAt', 'outcomeKind', 'leaseDisposition', 'settledStatus', 'advisoryAssociations'], ['outcomeErrorCode'], 'terminalPublication');
  if (value.version !== 1) fail('invalid terminal publication version');
  uuid(value.publicationId, 'terminalPublication.publicationId'); uuid(value.claimId, 'terminalPublication.claimId');
  if (value.claimId !== claimId) fail('terminal publication claim mismatch');
  time(value.completedAt, 'terminalPublication.completedAt');
  if (!['REVIEW_RETURNED', 'REVIEW_ERROR', 'EXPIRED', 'CANCELLED', 'CONTENT_LOST'].includes(value.outcomeKind)) fail('invalid terminal publication outcome');
  if (value.outcomeKind === 'REVIEW_RETURNED') {
    if (value.outcomeErrorCode !== undefined) fail('returned publication has error code');
  } else if (!TERMINAL_ERROR_CODES[value.outcomeKind]?.has(value.outcomeErrorCode)) fail('terminal publication error mapping mismatch');
  if (!MANAGED_DISPOSITIONS.has(value.leaseDisposition)) fail('invalid terminal publication lease disposition');
  validateSettledStatus(value.settledStatus);
  if (!Array.isArray(value.advisoryAssociations) || value.advisoryAssociations.length !== reviewerIds.length || value.advisoryAssociations.length > 15) fail('invalid terminal publication associations');
  value.advisoryAssociations.forEach((association, index) => {
    exactKeys(association, ['reviewerId', 'contentAvailable'], ['sourceReceiptId', 'jobId', 'advisoryRef'], `advisoryAssociations[${index}]`);
    opaque(association.reviewerId, `advisoryAssociations[${index}].reviewerId`);
    if (association.reviewerId !== reviewerIds[index] || typeof association.contentAvailable !== 'boolean') fail('terminal publication reviewer mismatch');
    const hasSource = association.sourceReceiptId !== undefined;
    const hasJob = association.jobId !== undefined;
    const hasRef = association.advisoryRef !== undefined;
    if (hasSource !== hasJob) fail('terminal publication job association is incomplete');
    if (hasSource) { uuid(association.sourceReceiptId, `advisoryAssociations[${index}].sourceReceiptId`); opaque(association.jobId, `advisoryAssociations[${index}].jobId`); }
    if (association.contentAvailable) {
      if (!hasJob || !hasRef) fail('available advisory association is incomplete');
      validateProtectedRef(association.advisoryRef, `advisoryAssociations[${index}].advisoryRef`);
    } else if (hasRef) fail('unavailable advisory has a protected ref');
  });
}

function validateRevision(map, key, value, name) {
  positive(value.revision, `${name}.revision`);
  const prior = map.get(key);
  const expected = prior === undefined ? 1 : prior.revision + 1;
  if (value.revision !== expected) fail(`${name} revision ${value.revision}, expected ${expected}`);
}

function validateServiceMode(mode, current) {
  exactKeys(mode, ['recordType', 'version', 'state', 'revision', 'configFingerprint', 'buildManifestFingerprint', 'activationAcquisitionId', 'replayBarrierId', 'replayBarrierCompletedAt'], [], 'serviceMode');
  if (mode.recordType !== 'shared/service-mode' || mode.version !== 1 || !['ACTIVE', 'CLEARED'].includes(mode.state)) fail('invalid service mode');
  positive(mode.revision, 'serviceMode.revision');
  if (mode.revision !== (current === null ? 1 : current.revision + 1)) fail('skipped service mode revision');
  digest(mode.configFingerprint, 'serviceMode.configFingerprint');
  digest(mode.buildManifestFingerprint, 'serviceMode.buildManifestFingerprint');
  uuid(mode.activationAcquisitionId, 'serviceMode.activationAcquisitionId');
  uuid(mode.replayBarrierId, 'serviceMode.replayBarrierId');
  time(mode.replayBarrierCompletedAt, 'serviceMode.replayBarrierCompletedAt');
}

function validateReservation(value, map) {
  exactKeys(value, ['recordType', 'version', 'reservationId', 'generation', 'revision', 'state', 'bindingId', 'projectId', 'policyEpoch', 'scopeDigest', 'maxEncryptedBytes', 'retainedEncryptedBytes', 'expiresAt', 'createdAt', 'ownerAcquisitionId', 'replayBarrierId'], ['exactEncryptedBytes', 'releaseReason'], 'preflightReservation');
  if (value.recordType !== 'shared/preflight-reservation' || value.version !== 1 || !['RESERVED', 'COMMITTED', 'RELEASED', 'RETIRED'].includes(value.state)) fail('invalid preflight reservation');
  uuid(value.reservationId, 'reservationId'); positive(value.generation, 'generation');
  validateRevision(map, value.reservationId, value, 'preflightReservation');
  opaque(value.bindingId, 'bindingId'); opaque(value.projectId, 'projectId'); positive(value.policyEpoch, 'policyEpoch'); digest(value.scopeDigest, 'scopeDigest');
  bytes(value.maxEncryptedBytes, 'maxEncryptedBytes'); bytes(value.retainedEncryptedBytes, 'retainedEncryptedBytes');
  if (value.exactEncryptedBytes !== undefined) bytes(value.exactEncryptedBytes, 'exactEncryptedBytes');
  time(value.expiresAt, 'expiresAt'); time(value.createdAt, 'createdAt'); uuid(value.ownerAcquisitionId, 'ownerAcquisitionId'); uuid(value.replayBarrierId, 'replayBarrierId');
  if (value.state === 'RESERVED' && (value.exactEncryptedBytes !== undefined || value.releaseReason !== undefined || value.retainedEncryptedBytes !== value.maxEncryptedBytes)) fail('invalid reserved preflight capacity');
  if (value.state === 'COMMITTED' && (value.exactEncryptedBytes === undefined || value.releaseReason !== undefined || value.retainedEncryptedBytes !== value.exactEncryptedBytes)) fail('invalid committed preflight capacity');
  if (value.state === 'RELEASED' && !['PREPARE_FAILED', 'EXPIRED', 'RESTART', 'ABANDONED'].includes(value.releaseReason)) fail('invalid preflight release reason');
}

function validateStaging(value, map) {
  exactKeys(value, ['recordType', 'version', 'stagingId', 'generation', 'state', 'revision', 'bindingId', 'scopeDigest', 'leaseId', 'keyDigest', 'inputDigest', 'maxEncryptedBytes', 'effectiveDeadline', 'createdAt', 'ownerAcquisitionId', 'replayBarrierId'], ['releaseReason'], 'staging');
  if (value.recordType !== 'shared/staging' || value.version !== 1 || !['RESERVED', 'RELEASED', 'COMMITTED'].includes(value.state)) fail('invalid staging');
  uuid(value.stagingId, 'stagingId'); positive(value.generation, 'generation'); validateRevision(map, value.stagingId, value, 'staging');
  opaque(value.bindingId, 'bindingId'); digest(value.scopeDigest, 'scopeDigest'); uuid(value.leaseId, 'leaseId'); digest(value.keyDigest, 'keyDigest'); digest(value.inputDigest, 'inputDigest');
  bytes(value.maxEncryptedBytes, 'maxEncryptedBytes'); time(value.effectiveDeadline, 'effectiveDeadline'); time(value.createdAt, 'createdAt'); uuid(value.ownerAcquisitionId, 'ownerAcquisitionId'); uuid(value.replayBarrierId, 'replayBarrierId');
  if (value.state === 'RESERVED' && value.releaseReason !== undefined) fail('reserved staging has release reason');
  if (value.state === 'COMMITTED' && value.releaseReason !== undefined) fail('committed staging has release reason');
  if (value.state === 'RELEASED' && !['PREPARE_FAILED', 'EXPIRED', 'RESTART'].includes(value.releaseReason)) fail('invalid staging release reason');
}

function validateReceipt(value, map) {
  exactKeys(value,
    ['recordType', 'version', 'receiptId', 'revision', 'leaseId', 'preflightId', 'bindingId', 'projectId', 'policyEpoch', 'scopeDigest', 'keyDigest', 'inputDigest', 'executionFingerprint', 'snapshotSourceId', 'snapshotContextId', 'reviewContractSha256', 'mappingPins', 'reviewerIds', 'acceptedAt', 'effectiveDeadline', 'state'],
    ['preparedPayload', 'retiredPreparedPayloadAudit', 'startedAt', 'executionGroupId', 'claimId', 'cancellationRequested', 'terminalPublication', 'terminal', 'payloadRetired'], 'receipt');
  if (value.recordType !== 'shared/receipt' || value.version !== 1) fail('invalid receipt');
  uuid(value.receiptId, 'receiptId'); validateRevision(map, value.receiptId, value, 'receipt');
  uuid(value.leaseId, 'leaseId'); uuid(value.preflightId, 'preflightId'); opaque(value.bindingId, 'bindingId'); opaque(value.projectId, 'projectId'); positive(value.policyEpoch, 'policyEpoch');
  digest(value.scopeDigest, 'scopeDigest'); digest(value.keyDigest, 'keyDigest'); digest(value.inputDigest, 'inputDigest'); digest(value.executionFingerprint, 'executionFingerprint');
  digest(value.snapshotSourceId, 'snapshotSourceId'); digest(value.snapshotContextId, 'snapshotContextId'); digest(value.reviewContractSha256, 'reviewContractSha256');
  validateMappingPins(value.mappingPins); time(value.acceptedAt, 'acceptedAt'); time(value.effectiveDeadline, 'effectiveDeadline');
  if (!Array.isArray(value.reviewerIds) || value.reviewerIds.length < 1 || value.reviewerIds.length > 15 || new Set(value.reviewerIds).size !== value.reviewerIds.length) fail('invalid receipt reviewers');
  value.reviewerIds.forEach((entry, index) => opaque(entry, `reviewerIds[${index}]`));
  if ((value.preparedPayload === undefined) === (value.retiredPreparedPayloadAudit === undefined)) fail('receipt must have exactly one payload form');
  if (value.preparedPayload !== undefined) validatePreparedPayload(value.preparedPayload, 'preparedPayload');
  if (value.retiredPreparedPayloadAudit !== undefined) validatePreparedPayload(value.retiredPreparedPayloadAudit, 'retiredPreparedPayloadAudit', true);
  if (value.startedAt !== undefined) time(value.startedAt, 'startedAt');
  if (value.executionGroupId !== undefined) uuid(value.executionGroupId, 'executionGroupId');
  if (value.claimId !== undefined) uuid(value.claimId, 'claimId');
  if (value.cancellationRequested !== undefined && value.cancellationRequested !== true) fail('cancellationRequested must be true');
  if (value.terminalPublication !== undefined) validateTerminalPublication(value.terminalPublication, value.reviewerIds, value.claimId);
  if (value.payloadRetired !== undefined && value.payloadRetired !== true) fail('payloadRetired must be true');
  if (value.payloadRetired === true && value.retiredPreparedPayloadAudit === undefined) fail('retired receipt is missing audit payload');
  if (!['QUEUED', 'WAITING', 'EXECUTING', 'RECOVERY_PENDING', 'TERMINAL'].includes(value.state)) fail('invalid receipt state');
  if (['QUEUED', 'WAITING'].includes(value.state) && (value.claimId !== undefined || value.startedAt !== undefined || value.cancellationRequested !== undefined || value.terminalPublication !== undefined)) fail('waiting receipt retains execution state');
  if (['EXECUTING', 'RECOVERY_PENDING'].includes(value.state) && value.claimId === undefined) fail('executing receipt is missing claim');
  if (value.state === 'TERMINAL') {
    exactKeys(value.terminal, ['kind', 'completedAt'], ['terminalRef', 'terminalDigest', 'errorCode'], 'terminal');
    if (!['REVIEW_RETURNED', 'REVIEW_ERROR', 'EXPIRED', 'CANCELLED', 'CONTENT_LOST'].includes(value.terminal.kind)) fail('invalid terminal kind');
    time(value.terminal.completedAt, 'terminal.completedAt');
    if (value.terminal.terminalRef !== undefined) validateProtectedRef(value.terminal.terminalRef, 'terminal.terminalRef');
    if ((value.terminal.terminalRef === undefined) !== (value.terminal.terminalDigest === undefined)) fail('terminal ref and digest must be paired');
    if (value.terminal.terminalDigest !== undefined) digest(value.terminal.terminalDigest, 'terminal.terminalDigest');
    if (value.terminal.kind === 'REVIEW_RETURNED' && value.terminal.terminalRef === undefined) fail('returned review requires terminalRef');
    if (value.terminal.errorCode !== undefined) opaque(value.terminal.errorCode, 'terminal.errorCode');
    if (value.terminal.kind === 'REVIEW_RETURNED') {
      if (value.terminal.errorCode !== undefined) fail('returned terminal has error code');
    } else if (!TERMINAL_ERROR_CODES[value.terminal.kind]?.has(value.terminal.errorCode)) fail('terminal error mapping mismatch');
    if (value.terminalPublication !== undefined) fail('terminal receipt retains publication');
  } else if (value.terminal !== undefined) fail('nonterminal receipt cannot have terminal');
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > 16_384) fail('receipt metadata too large');
}

function validateGroup(value, map) {
  exactKeys(value, ['recordType', 'version', 'executionGroupId', 'revision', 'executionFingerprint', 'scopeDigest', 'state', 'orderedReceiptIds', 'reviewerIds'], ['leaderReceiptId', 'claimId', 'claimRevision', 'startedAt', 'terminalAt', 'permit'], 'executionGroup');
  if (value.recordType !== 'shared/execution-group' || value.version !== 1) fail('invalid execution group');
  uuid(value.executionGroupId, 'executionGroupId'); validateRevision(map, value.executionGroupId, value, 'executionGroup');
  digest(value.executionFingerprint, 'executionFingerprint'); digest(value.scopeDigest, 'scopeDigest');
  if (!Array.isArray(value.orderedReceiptIds) || value.orderedReceiptIds.length < 1 || value.orderedReceiptIds.length > 15 || new Set(value.orderedReceiptIds).size !== value.orderedReceiptIds.length) fail('invalid execution group members');
  value.orderedReceiptIds.forEach((entry, index) => uuid(entry, `orderedReceiptIds[${index}]`));
  if (!Array.isArray(value.reviewerIds) || value.reviewerIds.length < 1 || value.reviewerIds.length > 15 || new Set(value.reviewerIds).size !== value.reviewerIds.length) fail('invalid execution group reviewers');
  value.reviewerIds.forEach((entry, index) => opaque(entry, `reviewerIds[${index}]`));
  if (!['OPEN', 'CLAIMED', 'RECOVERY_PENDING', 'TERMINAL'].includes(value.state)) fail('invalid execution group state');
  if (value.leaderReceiptId !== undefined) uuid(value.leaderReceiptId, 'leaderReceiptId');
  if (value.claimId !== undefined) uuid(value.claimId, 'claimId');
  if (value.claimRevision !== undefined) positive(value.claimRevision, 'claimRevision');
  if (value.startedAt !== undefined) time(value.startedAt, 'group.startedAt');
  if (value.terminalAt !== undefined) time(value.terminalAt, 'terminalAt');
  if (value.permit !== undefined) {
    exactKeys(value.permit, ['permitTokenDigest', 'permitSetRevision', 'activeBatchUnits', 'reviewerIds'], [], 'permit');
    digest(value.permit.permitTokenDigest, 'permitTokenDigest'); positive(value.permit.permitSetRevision, 'permitSetRevision');
    if (value.permit.activeBatchUnits !== 1 || canonicalJson(value.permit.reviewerIds) !== canonicalJson(value.reviewerIds)) fail('invalid permit allocation');
  }
  if (['CLAIMED', 'RECOVERY_PENDING'].includes(value.state) && (value.leaderReceiptId === undefined || value.claimId === undefined || value.claimRevision === undefined || value.permit === undefined)) fail('claimed group is incomplete');
  if (value.state === 'OPEN' && [value.leaderReceiptId, value.claimId, value.claimRevision, value.permit].some((entry) => entry !== undefined)) fail('open group retains claim state');
  if (value.state === 'TERMINAL' && value.terminalAt === undefined) fail('terminal group is missing terminalAt');
}

function validateManagedLease(value, map) {
  exactKeys(value, ['recordType', 'version', 'revision', 'id', 'state', 'preflightIds', 'reviewContractSha256', 'sourceSha256', 'profile', 'profileVersion', 'schemaSha256', 'registrySha256', 'requestedUsd', 'maxJobs', 'jobsConsumed', 'reservedUsd', 'spentUsd', 'expiresAt', 'managedBinding'], [], 'lease');
  if (value.recordType !== 'lease' || value.version !== 1) fail('invalid managed lease');
  uuid(value.id, 'lease.id'); validateRevision(map, value.id, value, 'lease');
  if (!['MANAGED_ACTIVE', 'CANCELLED', 'EXPIRED', 'CLOSED', 'LEASE_EXPIRED', 'DUPLICATE_DISPATCH_IN_PROGRESS', 'PROVIDER_MISMATCH', 'STRICT_OUTPUT_INVALID', 'UNKNOWN_COST', 'TRANSPORT_FAILURE', 'DISPATCH_UNKNOWN', 'ORPHANED_ON_RECOVERY'].includes(value.state)) fail('invalid managed lease state');
  if (!Array.isArray(value.preflightIds) || value.preflightIds.length < 1 || new Set(value.preflightIds).size !== value.preflightIds.length) fail('invalid lease preflights');
  value.preflightIds.forEach((entry, index) => uuid(entry, `preflightIds[${index}]`));
  digest(value.reviewContractSha256, 'lease.reviewContractSha256'); digest(value.sourceSha256, 'lease.sourceSha256'); opaque(value.profile, 'lease.profile'); opaque(value.profileVersion, 'lease.profileVersion'); digest(value.schemaSha256, 'lease.schemaSha256'); digest(value.registrySha256, 'lease.registrySha256');
  usd(value.requestedUsd, 'lease.requestedUsd'); positive(value.maxJobs, 'lease.maxJobs'); bytes(value.jobsConsumed, 'lease.jobsConsumed'); usd(value.reservedUsd, 'lease.reservedUsd'); usd(value.spentUsd, 'lease.spentUsd'); time(value.expiresAt, 'lease.expiresAt');
  exactKeys(value.managedBinding, ['bindingId', 'scopeDigest', 'projectId', 'policyEpoch'], ['receiptId', 'executionFingerprint'], 'managedBinding');
  opaque(value.managedBinding.bindingId, 'managedBinding.bindingId'); digest(value.managedBinding.scopeDigest, 'managedBinding.scopeDigest'); opaque(value.managedBinding.projectId, 'managedBinding.projectId'); positive(value.managedBinding.policyEpoch, 'managedBinding.policyEpoch');
  if (value.managedBinding.receiptId !== undefined) uuid(value.managedBinding.receiptId, 'managedBinding.receiptId');
  if (value.managedBinding.executionFingerprint !== undefined) digest(value.managedBinding.executionFingerprint, 'managedBinding.executionFingerprint');
}

function validateManagedJob(value, map) {
  exactKeys(value, ['recordType', 'version', 'revision', 'id', 'leaseId', 'state', 'reservationUsd', 'paid', 'reviewContractSha256', 'reviewerId', 'receiptId', 'claimId', 'executionFingerprint', 'scopeDigest', 'intentState'], ['costUsd', 'costKind', 'haltReason', 'managedHealthEffects', 'cancellationReason', 'aboveReservation'], 'job');
  if (value.recordType !== 'job' || value.version !== 1) fail('invalid managed job');
  digest(value.id, 'job.id'); validateRevision(map, value.id, value, 'job');
  uuid(value.leaseId, 'job.leaseId'); usd(value.reservationUsd, 'job.reservationUsd'); bool(value.paid, 'job.paid'); digest(value.reviewContractSha256, 'job.reviewContractSha256'); opaque(value.reviewerId, 'job.reviewerId'); uuid(value.receiptId, 'job.receiptId'); uuid(value.claimId, 'job.claimId'); digest(value.executionFingerprint, 'job.executionFingerprint'); digest(value.scopeDigest, 'job.scopeDigest');
  if (!['RESERVED', 'INTENT_PENDING', 'CANCELLED_ZERO_DISPATCH', 'RECONCILED'].includes(value.state)) fail('invalid managed job state');
  if (value.state !== 'RECONCILED' && value.aboveReservation !== undefined) fail('invalid above-reservation job');
  if (!['NONE', 'INTENT_PENDING'].includes(value.intentState)) fail('invalid job intent state');
  if (value.state === 'RESERVED' && (value.intentState !== 'NONE' || value.costUsd !== 0 || value.costKind !== undefined || value.haltReason !== undefined || value.cancellationReason !== undefined || value.managedHealthEffects !== undefined)) fail('invalid reserved job');
  if (value.state === 'INTENT_PENDING' && (value.intentState !== 'INTENT_PENDING' || value.costUsd !== 0 || value.costKind !== undefined || value.haltReason !== undefined || value.cancellationReason !== undefined || value.managedHealthEffects !== undefined)) fail('invalid intent job');
  if (value.state === 'CANCELLED_ZERO_DISPATCH' && (value.costUsd !== undefined || value.costKind !== undefined || value.haltReason !== undefined || value.managedHealthEffects !== undefined || !['CANCELLED', 'EXPIRED', 'CLAIM_RETIRED'].includes(value.cancellationReason))) fail('invalid cancelled job');
  if (value.state === 'RECONCILED') {
    usd(value.costUsd, 'job.costUsd');
    if (!['KNOWN', 'UNKNOWN_WORST_CASE_CHARGED', 'ZERO_ON_TRANSPORT_FAILURE', 'ZERO_ON_PROVIDER_REJECTION'].includes(value.costKind) || value.cancellationReason !== undefined) fail('invalid reconciled job');
    if (value.haltReason !== undefined) opaque(value.haltReason, 'job.haltReason');
    // Rule: a KNOWN cost above the reservation is recorded at its real value and flagged.
    // The flag is present exactly when a KNOWN cost exceeds the reservation, so a replayed record can
    // neither hide an overrun nor claim one it does not have.
    const knownOverrun = value.costKind === 'KNOWN' && value.costUsd > value.reservationUsd;
    if ((value.aboveReservation !== undefined && value.aboveReservation !== true)
      || (value.aboveReservation === true) !== knownOverrun) fail('invalid above-reservation job');
    if (value.managedHealthEffects !== undefined) {
      exactKeys(value.managedHealthEffects, [], ['DISPATCH_HEALTH_OUTCOME'], 'managedHealthEffects');
      const effect = value.managedHealthEffects.DISPATCH_HEALTH_OUTCOME;
      if (effect !== undefined) {
        exactKeys(effect, ['effectId', 'state', 'claimId'], [], 'healthEffect');
        uuid(effect.effectId, 'healthEffect.effectId'); uuid(effect.claimId, 'healthEffect.claimId');
        if (!['CLAIMED', 'RECORDED'].includes(effect.state)) fail('invalid health effect state');
      }
    }
  }
}

function validatePreflight(value, map) {
  exactKeys(value, ['recordType', 'version', 'revision', 'id', 'state', 'reviewContractSha256', 'sourceSha256', 'rawSourceSha256', 'profile', 'profileVersion', 'schemaSha256', 'registrySha256', 'itemMaxima', 'requestedUsd', 'expiresAt'], [], 'preflight');
  if (value.recordType !== 'preflight' || value.version !== 1 || value.state !== 'PREFLIGHTED') fail('invalid managed preflight');
  uuid(value.id, 'preflight.id'); validateRevision(map, value.id, value, 'preflight');
  digest(value.reviewContractSha256, 'preflight.reviewContractSha256'); digest(value.sourceSha256, 'preflight.sourceSha256'); digest(value.rawSourceSha256, 'preflight.rawSourceSha256');
  opaque(value.profile, 'preflight.profile'); opaque(value.profileVersion, 'preflight.profileVersion'); digest(value.schemaSha256, 'preflight.schemaSha256'); digest(value.registrySha256, 'preflight.registrySha256');
  if (!Array.isArray(value.itemMaxima) || value.itemMaxima.length < 1 || new Set(value.itemMaxima.map((entry) => entry.itemId)).size !== value.itemMaxima.length) fail('invalid preflight item maxima');
  value.itemMaxima.forEach((entry, index) => {
    exactKeys(entry, ['itemId', 'maxUsd'], [], `itemMaxima[${index}]`); opaque(entry.itemId, `itemMaxima[${index}].itemId`); usd(entry.maxUsd, `itemMaxima[${index}].maxUsd`);
  });
  usd(value.requestedUsd, 'preflight.requestedUsd'); time(value.expiresAt, 'preflight.expiresAt');
}

function validateManagedIdentity(value) {
  exactKeys(value, ['bindingId', 'scopeDigest', 'projectId', 'policyEpoch', 'snapshotSourceId', 'snapshotContextId', 'mappingIdentity', 'identityKeyVersion', 'contextRef', 'mappingRef'], [], 'managedIdentity');
  opaque(value.bindingId, 'managedIdentity.bindingId'); digest(value.scopeDigest, 'managedIdentity.scopeDigest'); opaque(value.projectId, 'managedIdentity.projectId'); positive(value.policyEpoch, 'managedIdentity.policyEpoch');
  digest(value.snapshotSourceId, 'managedIdentity.snapshotSourceId'); digest(value.snapshotContextId, 'managedIdentity.snapshotContextId'); digest(value.mappingIdentity, 'managedIdentity.mappingIdentity'); opaque(value.identityKeyVersion, 'managedIdentity.identityKeyVersion');
  validateProtectedRef(value.contextRef, 'managedIdentity.contextRef'); validateProtectedRef(value.mappingRef, 'managedIdentity.mappingRef');
}

function validateKeyAssociation(value, map) {
  exactKeys(value, ['recordType', 'version', 'revision', 'bindingId', 'scopeDigest', 'leaseId', 'keyDigest', 'inputDigest', 'target'], [], 'keyAssociation');
  if (value.recordType !== 'shared/idempotency-key' || value.version !== 1 || value.revision !== 1) fail('invalid key association');
  opaque(value.bindingId, 'keyAssociation.bindingId'); digest(value.scopeDigest, 'keyAssociation.scopeDigest'); uuid(value.leaseId, 'keyAssociation.leaseId'); digest(value.keyDigest, 'keyAssociation.keyDigest'); digest(value.inputDigest, 'keyAssociation.inputDigest');
  exactKeys(value.target, ['leaseId', 'inputDigest'], [], 'keyAssociation.target'); uuid(value.target.leaseId, 'keyAssociation.target.leaseId'); digest(value.target.inputDigest, 'keyAssociation.target.inputDigest');
  if (value.target.leaseId !== value.leaseId || value.target.inputDigest !== value.inputDigest) fail('key association target mismatch');
  const prior = map.get(associationKey(value));
  if (prior !== undefined && canonicalJson(prior) !== canonicalJson(value)) fail('key association is immutable');
}

function validatePreflightTombstone(value) {
  exactKeys(value, ['version', 'preflightId', 'revision', 'retiredContextAuditRef', 'retiredMappingAuditRef'], [], 'preflightTombstone');
  if (value.version !== 1) fail('invalid preflight tombstone version'); uuid(value.preflightId, 'preflightTombstone.preflightId'); positive(value.revision, 'preflightTombstone.revision');
  validateAuditRef(value.retiredContextAuditRef, 'retiredContextAuditRef'); validateAuditRef(value.retiredMappingAuditRef, 'retiredMappingAuditRef', true);
}

function validatePayloadTombstone(value) {
  exactKeys(value, ['version', 'receiptId', 'retiredPreparedPayloadAudit', 'revision'], [], 'tombstone');
  if (value.version !== 1) fail('invalid payload tombstone version'); uuid(value.receiptId, 'tombstone.receiptId'); positive(value.revision, 'tombstone.revision'); validatePreparedPayload(value.retiredPreparedPayloadAudit, 'tombstone.retiredPreparedPayloadAudit', true);
}

function validatePreflightDeletionAck(value) {
  exactKeys(value, ['version', 'target', 'deletionProvedAt'], ['context', 'mapping'], 'preflightDeletionAck');
  if (value.version !== 1) fail('invalid deletion ack version'); time(value.deletionProvedAt, 'deletionProvedAt');
  const targetKeys = Object.keys(value.target);
  if (targetKeys.length === 1 && targetKeys[0] === 'preflightId') uuid(value.target.preflightId, 'target.preflightId');
  else if (targetKeys.length === 2 && targetKeys.includes('reservationId') && targetKeys.includes('generation')) { uuid(value.target.reservationId, 'target.reservationId'); positive(value.target.generation, 'target.generation'); }
  else fail('invalid deletion ack target');
  for (const name of ['context', 'mapping']) if (value[name] !== undefined) {
    exactKeys(value[name], ['objectId', 'sha256'], [], `preflightDeletionAck.${name}`); uuid(value[name].objectId, `${name}.objectId`); digest(value[name].sha256, `${name}.sha256`);
  }
}

function associationKey(value) { return `${value.bindingId}\0${value.scopeDigest}\0${value.leaseId}\0${value.keyDigest}`; }

export function createSharedLedgerState() {
  const history = [];
  let serviceMode = null;
  const preflightReservations = new Map();
  const managedPreflights = new Map();
  const managedIdentities = new Map();
  const staging = new Map();
  const receipts = new Map();
  const receiptByLease = new Map();
  const keyAssociations = new Map();
  const executionGroups = new Map();
  const managedLeases = new Map();
  const managedJobs = new Map();
  const preflightTombstones = new Map();
  const payloadTombstones = new Map();
  const deletionAcks = new Map();
  const preflightOrigins = new Map();
  const receiptOrigins = new Map();

  function without(value, omitted) {
    return Object.fromEntries(Object.entries(value).filter(([key]) => !omitted.includes(key)));
  }

  function unchanged(next, prior, mutable, name) {
    if (prior !== undefined && canonicalJson(without(next, mutable)) !== canonicalJson(without(prior, mutable))) fail(`${name} changed immutable fields`);
  }

  function validateTransitionConsistency(record) {
    const priorReservation = record.preflightReservation === undefined ? undefined : preflightReservations.get(record.preflightReservation.reservationId);
    const priorStaging = record.staging === undefined ? undefined : staging.get(record.staging.stagingId);
    const priorReceipt = record.receipt === undefined ? undefined : receipts.get(record.receipt.receiptId);
    const priorGroup = record.executionGroup === undefined ? undefined : executionGroups.get(record.executionGroup.executionGroupId);
    const priorLease = record.lease === undefined ? undefined : managedLeases.get(record.lease.id);
    const priorJob = record.job === undefined ? undefined : managedJobs.get(record.job.id);
    const priorPreflight = record.preflight === undefined ? undefined : managedPreflights.get(record.preflight.id);

    if (record.preflightReservation !== undefined) unchanged(record.preflightReservation, priorReservation, ['revision', 'state', 'exactEncryptedBytes', 'retainedEncryptedBytes', 'releaseReason'], 'preflight reservation');
    if (record.staging !== undefined) unchanged(record.staging, priorStaging, ['revision', 'state', 'releaseReason'], 'staging');
    if (record.receipt !== undefined) unchanged(record.receipt, priorReceipt, ['revision', 'state', 'startedAt', 'claimId', 'cancellationRequested', 'terminalPublication', 'terminal', 'preparedPayload', 'retiredPreparedPayloadAudit', 'payloadRetired'], 'receipt');
    if (record.executionGroup !== undefined) unchanged(record.executionGroup, priorGroup, ['revision', 'state', 'orderedReceiptIds', 'leaderReceiptId', 'claimId', 'claimRevision', 'startedAt', 'terminalAt', 'permit'], 'execution group');
    if (record.lease !== undefined) unchanged(record.lease, priorLease, ['revision', 'state', 'jobsConsumed', 'reservedUsd', 'spentUsd', 'managedBinding'], 'managed lease');
    if (record.job !== undefined) unchanged(record.job, priorJob, ['revision', 'state', 'costUsd', 'costKind', 'haltReason', 'intentState', 'managedHealthEffects', 'cancellationReason', 'aboveReservation'], 'managed job');
    if (record.preflight !== undefined) unchanged(record.preflight, priorPreflight, ['revision'], 'managed preflight');

    if (priorReceipt?.terminalPublication !== undefined) {
      if (!['RECEIPT_TERMINALIZED', 'MANAGED_EXECUTION_PERMIT_REBOUND', 'MANAGED_RECOVERY_PENDING'].includes(record.kind)) fail('terminal publication pins its receipt');
      if (record.kind !== 'RECEIPT_TERMINALIZED'
        && canonicalJson(record.receipt.terminalPublication) !== canonicalJson(priorReceipt.terminalPublication)) fail('terminal publication is immutable');
    } else if (record.receipt?.terminalPublication !== undefined && record.kind !== 'TERMINAL_PUBLICATION_BEGUN') fail('terminal publication requires begin transition');
    if (priorGroup !== undefined) {
      const publishing = [...receipts.values()].find((receipt) => receipt.executionGroupId === priorGroup.executionGroupId && receipt.terminalPublication !== undefined);
      if (publishing !== undefined && (record.executionGroup.state !== 'CLAIMED'
        || record.executionGroup.claimId !== publishing.claimId || record.executionGroup.leaderReceiptId !== publishing.receiptId)) fail('terminal publication pins its claim');
    }
    if (priorLease !== undefined && record.kind !== 'RECEIPT_TERMINALIZED'
      && [...receipts.values()].some((receipt) => receipt.leaseId === priorLease.id && receipt.terminalPublication !== undefined)
      && canonicalJson(without(record.lease, ['revision'])) !== canonicalJson(without(priorLease, ['revision']))) fail('terminal publication freezes lease facts');

    if (record.receipt !== undefined && record.executionGroup !== undefined) {
      if (record.receipt.executionGroupId !== record.executionGroup.executionGroupId
        || record.receipt.executionFingerprint !== record.executionGroup.executionFingerprint
        || record.receipt.scopeDigest !== record.executionGroup.scopeDigest
        || canonicalJson(record.receipt.reviewerIds) !== canonicalJson(record.executionGroup.reviewerIds)
        || !record.executionGroup.orderedReceiptIds.includes(record.receipt.receiptId)) fail('receipt/group association mismatch');
    }
    if (record.receipt !== undefined && record.lease !== undefined) {
      if (record.receipt.leaseId !== record.lease.id
        || record.receipt.bindingId !== record.lease.managedBinding.bindingId
        || record.receipt.scopeDigest !== record.lease.managedBinding.scopeDigest
        || record.receipt.projectId !== record.lease.managedBinding.projectId
        || record.receipt.policyEpoch !== record.lease.managedBinding.policyEpoch) fail('receipt/lease association mismatch');
    }
    if (record.job !== undefined && record.receipt !== undefined && record.lease !== undefined) {
      if (record.job.receiptId !== record.receipt.receiptId || record.job.leaseId !== record.lease.id
        || record.job.claimId !== record.receipt.claimId || record.job.executionFingerprint !== record.receipt.executionFingerprint
        || record.job.scopeDigest !== record.receipt.scopeDigest) fail('managed job association mismatch');
    }

    switch (record.kind) {
      case 'MODE_ACTIVATED': if (record.serviceMode.state !== 'ACTIVE') fail('activation must be active'); break;
      case 'MODE_REPLAY_BARRIER_ADVANCED': if (serviceMode?.state !== 'ACTIVE' || record.serviceMode.state !== 'ACTIVE') fail('replay barrier requires active mode'); break;
      case 'MODE_CLEARED': if (serviceMode?.state !== 'ACTIVE' || record.serviceMode.state !== 'CLEARED') fail('mode clear transition mismatch'); break;
      case 'MANAGED_PREFLIGHT_RESERVED': if (priorReservation !== undefined || record.preflightReservation.state !== 'RESERVED') fail('invalid initial preflight reservation'); break;
      case 'MANAGED_PREFLIGHT_COMMITTED':
        if (priorReservation?.state !== 'RESERVED' || record.preflightReservation.state !== 'COMMITTED' || priorPreflight !== undefined
          || record.managedIdentity.bindingId !== record.preflightReservation.bindingId || record.managedIdentity.projectId !== record.preflightReservation.projectId
          || record.managedIdentity.policyEpoch !== record.preflightReservation.policyEpoch || record.managedIdentity.scopeDigest !== record.preflightReservation.scopeDigest) fail('invalid preflight commit');
        break;
      case 'MANAGED_PREFLIGHT_RESERVATION_RELEASED': if (priorReservation?.state !== 'RESERVED' || record.preflightReservation.state !== 'RELEASED') fail('invalid preflight release'); break;
      case 'UNADMITTED_LEASE_DISPOSED': {
        const hasReceipt = [...receipts.values()].some((receipt) => receipt.leaseId === record.lease.id);
        const hasJob = [...managedJobs.values()].some((job) => job.leaseId === record.lease.id);
        const hasLiveStage = [...staging.values()].some((entry) => entry.leaseId === record.lease.id && ['RESERVED', 'COMMITTED'].includes(entry.state));
        if (priorLease?.state !== 'MANAGED_ACTIVE' || !['CANCELLED', 'EXPIRED'].includes(record.lease.state)
          || Object.hasOwn(priorLease.managedBinding, 'receiptId') || Object.hasOwn(priorLease.managedBinding, 'executionFingerprint')
          || hasReceipt || hasJob || hasLiveStage
          || record.lease.jobsConsumed !== priorLease.jobsConsumed
          || record.lease.reservedUsd !== priorLease.reservedUsd
          || record.lease.spentUsd !== priorLease.spentUsd
          || canonicalJson(record.lease.managedBinding) !== canonicalJson(priorLease.managedBinding)) fail('invalid unadmitted lease disposal');
        break;
      }
      case 'MANAGED_PREFLIGHT_RETIRED':
        if (priorPreflight === undefined || canonicalJson(managedIdentities.get(record.preflight.id)) !== canonicalJson(record.managedIdentity)
          || record.preflightTombstone.preflightId !== record.preflight.id || record.preflightTombstone.revision !== record.preflight.revision) fail('invalid preflight retirement');
        break;
      case 'STAGING_RESERVED':
        if (priorStaging !== undefined || record.staging.state !== 'RESERVED' || record.keyAssociation.leaseId !== record.staging.leaseId
          || record.keyAssociation.bindingId !== record.staging.bindingId || record.keyAssociation.scopeDigest !== record.staging.scopeDigest
          || record.keyAssociation.keyDigest !== record.staging.keyDigest || record.keyAssociation.inputDigest !== record.staging.inputDigest) fail('invalid staging reservation');
        break;
      case 'STAGING_RELEASED': if (priorStaging?.state !== 'RESERVED' || record.staging.state !== 'RELEASED') fail('invalid staging release'); break;
      case 'RECEIPT_ADMITTED':
        if (priorStaging?.state !== 'RESERVED' || record.staging.state !== 'COMMITTED' || priorReceipt !== undefined || priorLease?.state !== 'MANAGED_ACTIVE'
          || record.receipt.leaseId !== record.staging.leaseId || record.receipt.keyDigest !== record.staging.keyDigest || record.receipt.inputDigest !== record.staging.inputDigest
          || canonicalJson(record.mappingPins) !== canonicalJson(record.receipt.mappingPins)
          || record.lease.managedBinding.receiptId !== record.receipt.receiptId || record.lease.managedBinding.executionFingerprint !== record.receipt.executionFingerprint) fail('invalid receipt admission');
        break;
      case 'RECEIPT_CLAIMED':
        if (priorReceipt === undefined || priorGroup?.state !== 'OPEN' || record.receipt.state !== 'EXECUTING' || record.executionGroup.state !== 'CLAIMED'
          || record.receipt.claimId !== record.executionGroup.claimId || record.executionGroup.leaderReceiptId !== record.receipt.receiptId) fail('invalid receipt claim');
        break;
      case 'TERMINAL_PUBLICATION_BEGUN': {
        const publication = record.receipt.terminalPublication;
        const expectedStatus = priorLease === undefined ? null : {
          leaseId: priorLease.id,
          state: priorLease.state,
          requestedUsd: priorLease.requestedUsd,
          reservedUsd: priorLease.reservedUsd,
          spentUsd: priorLease.spentUsd,
          jobsConsumed: priorLease.jobsConsumed,
          maxJobs: priorLease.maxJobs,
          expiresAt: priorLease.expiresAt,
        };
        const unsettled = [...managedJobs.values()].some((job) => job.receiptId === record.receipt.receiptId && ['RESERVED', 'INTENT_PENDING'].includes(job.state));
        const associationsValid = publication?.advisoryAssociations.every((association) => {
          if (association.jobId === undefined) return ![...managedJobs.values()].some((job) => job.receiptId === priorReceipt?.receiptId && job.reviewerId === association.reviewerId);
          const sourceReceipt = receipts.get(association.sourceReceiptId);
          const job = managedJobs.get(association.jobId);
          const native = association.sourceReceiptId === priorReceipt?.receiptId;
          return sourceReceipt !== undefined && job !== undefined && priorGroup !== undefined
            && priorGroup.orderedReceiptIds.includes(sourceReceipt.receiptId)
            && sourceReceipt.executionGroupId === priorGroup.executionGroupId
            && sourceReceipt.executionFingerprint === priorReceipt.executionFingerprint
            && sourceReceipt.scopeDigest === priorReceipt.scopeDigest
            && job.receiptId === sourceReceipt.receiptId && job.leaseId === sourceReceipt.leaseId && job.reviewerId === association.reviewerId
            && job.executionFingerprint === priorReceipt.executionFingerprint && job.scopeDigest === priorReceipt.scopeDigest
            && (native ? ['RECONCILED', 'CANCELLED_ZERO_DISPATCH'].includes(job.state) : job.state === 'RECONCILED');
        });
        if (!['EXECUTING', 'RECOVERY_PENDING'].includes(priorReceipt?.state) || priorGroup?.state !== 'CLAIMED' || priorLease?.state !== 'MANAGED_ACTIVE'
          || priorReceipt.terminalPublication !== undefined || publication === undefined || publication.claimId !== priorReceipt.claimId
          || (priorReceipt.cancellationRequested === true
            ? publication.outcomeKind !== 'CANCELLED' || publication.outcomeErrorCode !== 'REQUEST_CANCELLED' || publication.leaseDisposition !== 'CANCELLED'
            : publication.outcomeKind === 'CANCELLED' || publication.leaseDisposition === 'CANCELLED')
          || record.receipt.state !== priorReceipt.state || record.executionGroup.state !== priorGroup.state
          || unsettled || associationsValid !== true || canonicalJson(publication.settledStatus) !== canonicalJson(expectedStatus)
          || canonicalJson(without(record.receipt, ['revision', 'terminalPublication'])) !== canonicalJson(without(priorReceipt, ['revision', 'terminalPublication']))
          || canonicalJson(without(record.executionGroup, ['revision'])) !== canonicalJson(without(priorGroup, ['revision']))
          || canonicalJson(without(record.lease, ['revision'])) !== canonicalJson(without(priorLease, ['revision']))) fail('invalid terminal publication begin');
        break;
      }
      case 'MANAGED_CANCEL_REQUESTED':
        if (!['EXECUTING', 'RECOVERY_PENDING'].includes(priorReceipt?.state)
          || priorGroup?.state !== 'CLAIMED' || priorLease?.state !== 'MANAGED_ACTIVE'
          || priorReceipt.cancellationRequested === true || record.receipt.cancellationRequested !== true
          || record.receipt.state !== priorReceipt.state || record.receipt.claimId !== priorReceipt.claimId
          || record.executionGroup.state !== priorGroup.state || record.executionGroup.claimId !== priorGroup.claimId
          || canonicalJson(without(record.receipt, ['revision', 'cancellationRequested'])) !== canonicalJson(without(priorReceipt, ['revision', 'cancellationRequested']))
          || canonicalJson(without(record.executionGroup, ['revision'])) !== canonicalJson(without(priorGroup, ['revision']))
          || canonicalJson(without(record.lease, ['revision'])) !== canonicalJson(without(priorLease, ['revision']))) fail('invalid managed cancellation request');
        break;
      case 'MANAGED_RECOVERY_PENDING':
        if (priorReceipt?.state !== 'EXECUTING' || priorGroup?.state !== 'CLAIMED'
          || record.receipt.state !== 'RECOVERY_PENDING' || record.executionGroup.state !== 'CLAIMED'
          || record.receipt.claimId !== priorReceipt.claimId || record.executionGroup.claimId !== priorGroup.claimId
          || canonicalJson(without(record.receipt, ['revision', 'state'])) !== canonicalJson(without(priorReceipt, ['revision', 'state']))
          || canonicalJson(without(record.executionGroup, ['revision'])) !== canonicalJson(without(priorGroup, ['revision']))) fail('invalid managed recovery pending');
        break;
      case 'RECEIPT_TERMINALIZED':
        if (priorReceipt?.terminalPublication !== undefined) {
          const publication = priorReceipt.terminalPublication;
          const candidateBacked = record.receipt.terminal?.terminalRef !== undefined;
          const expectedKind = candidateBacked ? publication.outcomeKind : 'CONTENT_LOST';
          const expectedErrorCode = candidateBacked ? publication.outcomeErrorCode : 'REQUEST_CONTENT_LOST';
          const unsettled = [...managedJobs.values()].some((job) => job.receiptId === record.receipt.receiptId && ['RESERVED', 'INTENT_PENDING'].includes(job.state));
          if (!['EXECUTING', 'RECOVERY_PENDING'].includes(priorReceipt.state) || priorGroup?.state !== 'CLAIMED' || priorLease?.state !== 'MANAGED_ACTIVE'
            || record.receipt.state !== 'TERMINAL' || record.receipt.terminalPublication !== undefined
            || record.receipt.terminal?.kind !== expectedKind || record.receipt.terminal?.errorCode !== expectedErrorCode
            || record.receipt.terminal?.completedAt !== publication.completedAt
            || record.lease.state !== publication.leaseDisposition || record.executionGroup.state !== 'CLAIMED'
            || record.executionGroup.claimId !== priorGroup.claimId || unsettled
            || canonicalJson(without(record.receipt, ['revision', 'state', 'terminalPublication', 'terminal'])) !== canonicalJson(without(priorReceipt, ['revision', 'state', 'terminalPublication', 'terminal']))
            || canonicalJson(without(record.executionGroup, ['revision'])) !== canonicalJson(without(priorGroup, ['revision']))
            || record.lease.jobsConsumed !== priorLease.jobsConsumed || record.lease.reservedUsd !== priorLease.reservedUsd
            || record.lease.spentUsd !== priorLease.spentUsd || canonicalJson(record.lease.managedBinding) !== canonicalJson(priorLease.managedBinding)) fail('invalid terminal publication finalization');
        } else if (!['QUEUED', 'WAITING'].includes(priorReceipt?.state) || priorReceipt.claimId !== undefined
          || !['CANCELLED', 'EXPIRED'].includes(record.receipt.terminal?.kind)
          || record.receipt.terminal.terminalRef !== undefined
          || record.lease.state !== record.receipt.terminal.kind) fail('claimed terminalization requires a frozen publication');
        break;
      case 'CLAIM_RETIRED': if (!['CLAIMED', 'RECOVERY_PENDING'].includes(priorGroup?.state) || record.receipt.claimId !== undefined || !['OPEN', 'TERMINAL'].includes(record.executionGroup.state)) fail('invalid claim retirement'); break;
      case 'MANAGED_CONSUMED': if (priorJob !== undefined || record.job.state !== 'RESERVED' || priorLease?.state !== 'MANAGED_ACTIVE') fail('invalid managed reservation'); break;
      case 'MANAGED_INTENT_PENDING': if (priorJob?.state !== 'RESERVED' || record.job.state !== 'INTENT_PENDING') fail('invalid managed intent'); break;
      case 'MANAGED_RESERVATION_CANCELLED': if (priorJob?.state !== 'RESERVED' || record.job.state !== 'CANCELLED_ZERO_DISPATCH') fail('invalid reservation cancellation'); break;
      case 'MANAGED_RECONCILED': if (!['RESERVED', 'INTENT_PENDING'].includes(priorJob?.state) || record.job.state !== 'RECONCILED') fail('invalid managed reconciliation'); break;
      case 'HEALTH_EFFECT_CLAIMED': if (priorJob?.state !== 'RECONCILED' || record.job.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME?.state !== 'CLAIMED') fail('invalid health-effect claim'); break;
      case 'HEALTH_EFFECT_RECORDED': if (priorJob?.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME?.state !== 'CLAIMED' || record.job.managedHealthEffects?.DISPATCH_HEALTH_OUTCOME?.state !== 'RECORDED') fail('invalid health-effect record'); break;
      case 'PAYLOAD_RETIRED': if (priorReceipt?.state !== 'TERMINAL' || record.receipt.payloadRetired !== true || record.tombstone.receiptId !== record.receipt.receiptId || record.tombstone.revision !== record.receipt.revision) fail('invalid payload retirement'); break;
      default: break;
    }
  }

  function apply(record) {
    canonicalJson(record);
    strictData(record, 'record');
    if (record.recordType === 'shared/service-mode') {
      validateServiceMode(record, serviceMode);
      serviceMode = clone(record);
      history.push(clone(record));
      return;
    }
    if (record.recordType !== 'shared/transition') fail(`unknown type ${String(record.recordType)}`);
    if (record.version !== 1 || typeof record.kind !== 'string' || !Object.hasOwn(TRANSITION_FIELDS, record.kind)) fail('unknown transition kind/version');
    const required = TRANSITION_FIELDS[record.kind];
    exactKeys(record, ['recordType', 'version', 'kind', ...required, 'timestamp'], [], 'transition');
    time(record.timestamp, 'transition.timestamp');

    if (record.serviceMode !== undefined) validateServiceMode(record.serviceMode, serviceMode);
    if (record.preflightReservation !== undefined) validateReservation(record.preflightReservation, preflightReservations);
    if (record.staging !== undefined) validateStaging(record.staging, staging);
    if (record.receipt !== undefined) validateReceipt(record.receipt, receipts);
    if (record.executionGroup !== undefined) validateGroup(record.executionGroup, executionGroups);
    if (record.lease !== undefined) validateManagedLease(record.lease, managedLeases);
    if (record.job !== undefined) validateManagedJob(record.job, managedJobs);
    if (record.preflight !== undefined) validatePreflight(record.preflight, managedPreflights);
    if (record.managedIdentity !== undefined) validateManagedIdentity(record.managedIdentity);
    if (record.keyAssociation !== undefined) validateKeyAssociation(record.keyAssociation, keyAssociations);
    if (record.mappingPins !== undefined) validateMappingPins(record.mappingPins);
    if (record.preflightTombstone !== undefined) validatePreflightTombstone(record.preflightTombstone);
    if (record.tombstone !== undefined) validatePayloadTombstone(record.tombstone);
    if (record.preflightDeletionAck !== undefined) validatePreflightDeletionAck(record.preflightDeletionAck);
    validateTransitionConsistency(record);

    if (record.serviceMode !== undefined) serviceMode = clone(record.serviceMode);
    if (record.preflightReservation !== undefined) preflightReservations.set(record.preflightReservation.reservationId, clone(record.preflightReservation));
    if (record.preflight !== undefined) {
      managedPreflights.set(record.preflight.id, clone(record.preflight));
      if (record.kind === 'MANAGED_PREFLIGHT_COMMITTED') preflightOrigins.set(record.preflight.id, { reservationId: record.preflightReservation.reservationId, generation: record.preflightReservation.generation });
    }
    if (record.managedIdentity !== undefined) managedIdentities.set(record.preflight.id, clone(record.managedIdentity));
    if (record.staging !== undefined) staging.set(record.staging.stagingId, clone(record.staging));
    if (record.receipt !== undefined) {
      receipts.set(record.receipt.receiptId, clone(record.receipt));
      receiptByLease.set(record.receipt.leaseId, record.receipt.receiptId);
      if (record.kind === 'RECEIPT_ADMITTED') receiptOrigins.set(record.receipt.receiptId, { stagingId: record.staging.stagingId, generation: record.staging.generation });
    }
    if (record.executionGroup !== undefined) executionGroups.set(record.executionGroup.executionGroupId, clone(record.executionGroup));
    if (record.lease !== undefined) managedLeases.set(record.lease.id, clone(record.lease));
    if (record.job !== undefined) managedJobs.set(record.job.id, clone(record.job));
    if (record.keyAssociation !== undefined) keyAssociations.set(associationKey(record.keyAssociation), clone(record.keyAssociation));
    if (record.preflightTombstone !== undefined) preflightTombstones.set(record.preflightTombstone.preflightId, clone(record.preflightTombstone));
    if (record.tombstone !== undefined) payloadTombstones.set(record.tombstone.receiptId, clone(record.tombstone));
    if (record.preflightDeletionAck !== undefined) deletionAcks.set(JSON.stringify(record.preflightDeletionAck.target), clone(record.preflightDeletionAck));
    history.push(clone(record));
  }

  function validate(record) {
    const candidate = createSharedLedgerState();
    for (const prior of history) candidate.apply(prior);
    candidate.apply(record);
  }

  function snapshot() {
    const unfinishedReceipts = [...receipts.values()].filter((value) => value.state !== 'TERMINAL');
    const reservedStaging = [...staging.values()].filter((value) => value.state === 'RESERVED');
    const retiredPreflightIds = new Set(preflightTombstones.keys());
    const livePreflights = [...preflightReservations.values()].filter((value) => value.state === 'RESERVED'
      || (value.state === 'COMMITTED' && ![...preflightOrigins.entries()].some(([preflightId, target]) => retiredPreflightIds.has(preflightId) && target.reservationId === value.reservationId && target.generation === value.generation)));
    return clone({
      serviceMode,
      preflightReservations: [...preflightReservations.values()],
      managedPreflights: [...managedPreflights.values()],
      managedIdentities: [...managedIdentities.entries()],
      staging: [...staging.values()],
      receipts: [...receipts.values()],
      executionGroups: [...executionGroups.values()],
      managedLeases: [...managedLeases.values()],
      managedJobs: [...managedJobs.values()],
      keyAssociations: [...keyAssociations.values()],
      preflightTombstones: [...preflightTombstones.values()],
      payloadTombstones: [...payloadTombstones.values()],
      deletionAcks: [...deletionAcks.values()],
      capacity: {
        unfinishedCount: reservedStaging.length + unfinishedReceipts.length,
        unfinishedEncryptedBytes: reservedStaging.reduce((sum, item) => sum + item.maxEncryptedBytes, 0)
          + unfinishedReceipts.reduce((sum, item) => sum + (item.preparedPayload?.envelopeRef.encryptedBytes ?? 0) + (item.preparedPayload?.requestRefs ?? []).reduce((subtotal, ref) => subtotal + ref.encryptedBytes, 0), 0),
        livePreflightCount: livePreflights.length,
        preflightEncryptedBytes: preflightReservations.size === 0 ? 0 : [...preflightReservations.values()].reduce((sum, item) => {
          const acknowledged = deletionAcks.has(JSON.stringify({ reservationId: item.reservationId, generation: item.generation }))
            || (item.state === 'COMMITTED' && [...preflightOrigins.entries()].some(([preflightId, target]) => target.reservationId === item.reservationId && deletionAcks.has(JSON.stringify({ preflightId }))));
          return sum + (acknowledged ? 0 : (item.state === 'COMMITTED' ? item.exactEncryptedBytes ?? 0 : item.retainedEncryptedBytes));
        }, 0),
      },
    });
  }

  return Object.freeze({
    apply,
    validate,
    snapshot,
    get serviceMode() { return serviceMode === null ? null : clone(serviceMode); },
    getPreflightReservation: (id) => clone(preflightReservations.get(id) ?? null),
    getManagedPreflight: (id) => clone(managedPreflights.get(id) ?? null),
    getManagedIdentity: (id) => clone(managedIdentities.get(id) ?? null),
    getStaging: (id) => clone(staging.get(id) ?? null),
    getReceipt: (id) => clone(receipts.get(id) ?? null),
    getReceiptByLease: (id) => clone(receipts.get(receiptByLease.get(id)) ?? null),
    getExecutionGroup: (id) => clone(executionGroups.get(id) ?? null),
    getManagedLease: (id) => clone(managedLeases.get(id) ?? null),
    getManagedJob: (id) => clone(managedJobs.get(id) ?? null),
    getKeyAssociation: (value) => clone(keyAssociations.get(associationKey(value)) ?? null),
    getPreflightOrigin: (id) => clone(preflightOrigins.get(id) ?? null),
    getReceiptOrigin: (id) => clone(receiptOrigins.get(id) ?? null),
  });
}
