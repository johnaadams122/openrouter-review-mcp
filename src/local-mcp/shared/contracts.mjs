import { createHash, createHmac } from 'node:crypto';

const DIGEST = /^[a-f0-9]{64}$/;
const OPAQUE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9_-]{16,128}$/;
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
const IDENTITY_DOMAINS = new Set([
  'shared-source-v1', 'shared-context-v1', 'shared-mapping-v1', 'shared-body-v1',
  'shared-idempotency-v1', 'shared-input-v1', 'shared-policy-v1',
  'shared-binding-credential-v1',
]);

const ERROR_MESSAGES = Object.freeze({
  INVALID_IDEMPOTENCY_KEY: 'Invalid idempotency key.',
  INVALID_SHARED_RECORD: 'Invalid shared review record.',
  INVALID_INSTALLATION_CONFIG: 'Invalid shared review configuration.',
  SERVICE_NOT_PROVISIONED: 'Shared review service is not provisioned.',
  SERVICE_MIGRATION_REQUIRED: 'Shared review service requires a quiescent migration.',
  EXECUTOR_PERSISTENCE_UNAVAILABLE: 'Persistent executor launch is unavailable.',
  SERVICE_UNAVAILABLE: 'Shared review service is temporarily unavailable.',
  PROJECT_SCOPE_REQUIRED: 'A configured project scope is required.',
  PROJECT_SCOPE_DENIED: 'Project scope is not permitted.',
  REQUEST_NOT_FOUND: 'Review request was not found.',
  REQUEST_TOO_LARGE: 'Review request exceeds the input limit.',
  IDEMPOTENCY_CONFLICT: 'Idempotency key conflicts with an existing request.',
  LEASE_REQUEST_CONFLICT: 'Lease already identifies another review request.',
  REQUEST_CAPACITY_FULL: 'Review request capacity is full.',
  REQUEST_BYTES_FULL: 'Review storage capacity is full.',
  REQUEST_EXPIRED: 'Review request expired before execution.',
  REQUEST_CANCELLED: 'Review request was cancelled.',
  REQUEST_CONTENT_LOST: 'Review content is unavailable.',
  REQUEST_FAILED: 'Review request failed.',
  FRESH_PREFLIGHT_REQUIRED: 'A fresh review preflight is required.',
  PROTECTED_CONTENT_INVALID: 'Protected review content is invalid.',
  PROTECTED_CONTENT_TOO_LARGE: 'Protected review content exceeds its size limit.',
});

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export const SHARED_LIMITS = deepFreeze({
  maxReviewers: 15,
  maxSourceBytes: 2_000_000,
  maxRequestBytes: 4_194_304,
  maxActiveBatches: 5,
  maxWaitingCallerRequests: 10,
  maxUnfinishedCount: 15,
  maxActiveReviewerDispatches: 15,
  maxUnfinishedEncryptedBytes: 209_715_200,
  maxUnstartedWaitMs: 1_800_000,
  maxReceiptMetadataBytes: 16_384,
  maxIdempotencyKeysPerLease: 64,
  maxLivePreflights: 30,
  maxPreflightEncryptedBytes: 209_715_200,
  maxSinglePreflightPlaintextBytes: 67_108_864,
  helloBytes: 512,
  controlFrameBytes: 4_096,
  metadataFrameBytes: 16_384,
  contentFrameBytes: 1_048_576,
  chunkRawBytes: 524_288,
  maxEncodedRequestBytes: 67_108_864,
  maxConnections: 32,
  maxInflightIngressBytes: 134_217_728,
  maxResultTransfers: 2,
  maxResultBufferBytes: 268_435_456,
  authenticationTimeoutMs: 10_000,
  preparedEnvelopePlaintextBytes: 131_072,
});

function fail(message = 'invalid strict JSON value') {
  throw new TypeError(message);
}

function strictDescriptors(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(`${field} must be a plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== 'string') fail(`${field} cannot contain symbol keys`);
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${field}.${key} must be an enumerable data property`);
  }
  return descriptors;
}

function exactObject(value, required, optional = [], field = 'value') {
  const descriptors = strictDescriptors(value, field);
  const keys = Object.keys(descriptors);
  const allowed = new Set([...required, ...optional]);
  if (keys.some((key) => !allowed.has(key)) || required.some((key) => !Object.hasOwn(descriptors, key))) fail(`${field} has an invalid shape`);
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}

function strictArray(value, field, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail(`${field} must be an array`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== 'string')) fail(`${field} cannot contain symbol keys`);
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || lengthDescriptor.enumerable || !Object.hasOwn(lengthDescriptor, 'value')) fail(`${field} has an invalid length`);
  if (value.length < min || value.length > max) fail(`${field} length is out of range`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${field} must be dense`);
  }
  if (keys.some((key) => key !== 'length' && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))) fail(`${field} cannot contain extra properties`);
  return Array.from({ length: value.length }, (_, index) => descriptors[String(index)].value);
}

function canonicalize(value, stack) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('numbers must be finite');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (typeof value !== 'object') fail();
  if (stack.has(value)) fail('cycles are not supported');
  stack.add(value);
  try {
    if (Array.isArray(value)) return `[${strictArray(value, 'array').map((item) => canonicalize(item, stack)).join(',')}]`;
    const descriptors = strictDescriptors(value, 'object');
    return `{${Object.keys(descriptors).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(descriptors[key].value, stack)}`).join(',')}}`;
  } finally {
    stack.delete(value);
  }
}

export function canonicalJson(value) {
  return canonicalize(value, new Set());
}

function strictClone(value) {
  return JSON.parse(canonicalJson(value));
}

function requireString(value, field) {
  if (typeof value !== 'string' || value.length === 0) fail(`${field} must be a non-empty string`);
  return value;
}

function requireOpaque(value, field) {
  if (typeof value !== 'string' || !OPAQUE_ID.test(value)) fail(`${field} must be an opaque ID`);
  return value;
}

function requireDigest(value, field) {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail(`${field} must be a digest`);
  return value;
}

function requireUuid(value, field) {
  if (typeof value !== 'string' || !UUID.test(value)) fail(`${field} must be a UUID`);
  return value;
}

function requirePositiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${field} must be a positive safe integer`);
  return value;
}

function requireNonnegativeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be a non-negative safe integer`);
  return value;
}

function requireIsoTime(value, field) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail(`${field} must be a canonical UTC timestamp`);
  return value;
}

function protectedRef(value, field) {
  const ref = exactObject(value, ['objectId', 'sha256', 'encryptedBytes'], [], field);
  return { objectId: requireUuid(ref.objectId, `${field}.objectId`), sha256: requireDigest(ref.sha256, `${field}.sha256`), encryptedBytes: requireNonnegativeInteger(ref.encryptedBytes, `${field}.encryptedBytes`) };
}

function validateTerminalPublication(value, reviewerIds, claimId) {
  const publication = exactObject(value,
    ['version', 'publicationId', 'claimId', 'completedAt', 'outcomeKind', 'leaseDisposition', 'settledStatus', 'advisoryAssociations'],
    ['outcomeErrorCode'], 'terminalPublication');
  if (publication.version !== 1 || publication.claimId !== claimId) fail('terminal publication is invalid');
  requireUuid(publication.publicationId, 'terminalPublication.publicationId');
  requireUuid(publication.claimId, 'terminalPublication.claimId');
  requireIsoTime(publication.completedAt, 'terminalPublication.completedAt');
  if (!['REVIEW_RETURNED', 'REVIEW_ERROR', 'EXPIRED', 'CANCELLED', 'CONTENT_LOST'].includes(publication.outcomeKind)) fail('terminal publication outcome is invalid');
  if (publication.outcomeKind === 'REVIEW_RETURNED') {
    if (publication.outcomeErrorCode !== undefined) fail('returned publication has error code');
  } else if (!TERMINAL_ERROR_CODES[publication.outcomeKind]?.has(publication.outcomeErrorCode)) fail('terminal publication error is invalid');
  if (!MANAGED_DISPOSITIONS.has(publication.leaseDisposition)) fail('terminal publication disposition is invalid');
  const settled = exactObject(publication.settledStatus,
    ['leaseId', 'state', 'requestedUsd', 'reservedUsd', 'spentUsd', 'jobsConsumed', 'maxJobs', 'expiresAt'], [], 'terminalPublication.settledStatus');
  requireUuid(settled.leaseId, 'terminalPublication.settledStatus.leaseId');
  requireOpaque(settled.state, 'terminalPublication.settledStatus.state');
  for (const name of ['requestedUsd', 'reservedUsd', 'spentUsd']) {
    if (!Number.isFinite(settled[name]) || settled[name] < 0) fail(`terminalPublication.settledStatus.${name} is invalid`);
  }
  requireNonnegativeInteger(settled.jobsConsumed, 'terminalPublication.settledStatus.jobsConsumed');
  requirePositiveInteger(settled.maxJobs, 'terminalPublication.settledStatus.maxJobs');
  requireIsoTime(settled.expiresAt, 'terminalPublication.settledStatus.expiresAt');
  const associations = strictArray(publication.advisoryAssociations, 'terminalPublication.advisoryAssociations', { min: reviewerIds.length, max: reviewerIds.length });
  associations.forEach((entry, index) => {
    const association = exactObject(entry, ['reviewerId', 'contentAvailable'], ['sourceReceiptId', 'jobId', 'advisoryRef'], `terminalPublication.advisoryAssociations[${index}]`);
    if (association.reviewerId !== reviewerIds[index] || typeof association.contentAvailable !== 'boolean') fail('terminal publication reviewer is invalid');
    requireOpaque(association.reviewerId, `terminalPublication.advisoryAssociations[${index}].reviewerId`);
    const hasSource = association.sourceReceiptId !== undefined;
    const hasJob = association.jobId !== undefined;
    const hasRef = association.advisoryRef !== undefined;
    if (hasSource !== hasJob) fail('terminal publication association is incomplete');
    if (hasSource) {
      requireUuid(association.sourceReceiptId, `terminalPublication.advisoryAssociations[${index}].sourceReceiptId`);
      requireOpaque(association.jobId, `terminalPublication.advisoryAssociations[${index}].jobId`);
    }
    if (association.contentAvailable) {
      if (!hasJob || !hasRef) fail('available terminal advisory is incomplete');
      protectedRef(association.advisoryRef, `terminalPublication.advisoryAssociations[${index}].advisoryRef`);
    } else if (hasRef) fail('unavailable terminal advisory has a reference');
  });
}

export function sharedError(code) {
  if (typeof code !== 'string' || !Object.hasOwn(ERROR_MESSAGES, code)) throw new TypeError('unknown shared error code');
  const error = new Error(ERROR_MESSAGES[code]);
  Object.defineProperty(error, 'code', { value: code, enumerable: true, configurable: false, writable: false });
  return error;
}

export function createIdentityDigest(key) {
  if (!Buffer.isBuffer(key) || key.byteLength !== 32) throw new TypeError('identity key must be a 32-byte Buffer');
  const privateKey = Buffer.from(key);
  return (domain, bytes) => {
    if (!IDENTITY_DOMAINS.has(domain)) throw new TypeError('unknown identity domain');
    if (!Buffer.isBuffer(bytes)) throw new TypeError('identity bytes must be a Buffer');
    const hmac = createHmac('sha256', privateKey);
    hmac.update(domain, 'utf8');
    hmac.update(Buffer.from([0]));
    hmac.update(bytes);
    return hmac.digest('hex');
  };
}

export function digestIdempotencyKey(key, identityDigest) {
  if (typeof key !== 'string' || !IDEMPOTENCY_KEY.test(key) || typeof identityDigest !== 'function') throw sharedError('INVALID_IDEMPOTENCY_KEY');
  try {
    return requireDigest(identityDigest('shared-idempotency-v1', Buffer.from(key, 'utf8')), 'idempotency digest');
  } catch {
    throw sharedError('INVALID_IDEMPOTENCY_KEY');
  }
}

function validateFingerprintFields(value) {
  const fields = exactObject(value, [
    'protocolVersion', 'storageVersion', 'buildManifestSha256', 'reviewContractSha256', 'registrySha256',
    'advisorySchemaSha256', 'promptVersion', 'profile', 'reviewers', 'snapshotSourceId',
    'snapshotContextId', 'mappingIdentity', 'classifierContractDigest', 'identityListDigest', 'policy',
  ], [], 'fingerprintFields');
  for (const name of ['protocolVersion', 'storageVersion', 'promptVersion']) requireOpaque(fields[name], name);
  for (const name of ['buildManifestSha256', 'reviewContractSha256', 'registrySha256', 'advisorySchemaSha256', 'snapshotSourceId', 'snapshotContextId', 'mappingIdentity', 'classifierContractDigest', 'identityListDigest']) requireDigest(fields[name], name);
  const profile = exactObject(fields.profile, ['profileId', 'profileVersion', 'orderedReviewerIds'], [], 'profile');
  requireOpaque(profile.profileId, 'profile.profileId');
  requireOpaque(profile.profileVersion, 'profile.profileVersion');
  const orderedReviewerIds = strictArray(profile.orderedReviewerIds, 'profile.orderedReviewerIds', { min: 1, max: SHARED_LIMITS.maxReviewers });
  orderedReviewerIds.forEach((id, index) => requireOpaque(id, `profile.orderedReviewerIds[${index}]`));
  if (new Set(orderedReviewerIds).size !== orderedReviewerIds.length) fail('reviewer IDs must be unique');
  const reviewers = strictArray(fields.reviewers, 'reviewers', { min: 1, max: SHARED_LIMITS.maxReviewers });
  if (reviewers.length !== orderedReviewerIds.length) fail('reviewer count must match profile');
  reviewers.forEach((value, index) => {
    const reviewer = exactObject(value, ['reviewerId', 'model', 'route', 'expectedProvider', 'outputMode', 'requestControls', 'requestBodyDigest'], [], `reviewers[${index}]`);
    for (const name of ['reviewerId', 'model', 'route', 'expectedProvider', 'outputMode']) requireString(reviewer[name], `reviewers[${index}].${name}`);
    requireDigest(reviewer.requestBodyDigest, `reviewers[${index}].requestBodyDigest`);
    strictDescriptors(reviewer.requestControls, `reviewers[${index}].requestControls`);
    canonicalJson(reviewer.requestControls);
    if (reviewer.reviewerId !== orderedReviewerIds[index]) fail('reviewer order must match profile');
  });
  const policy = exactObject(fields.policy, ['scopeDigest', 'policyEpoch', 'projectId'], [], 'policy');
  requireDigest(policy.scopeDigest, 'policy.scopeDigest');
  requirePositiveInteger(policy.policyEpoch, 'policy.policyEpoch');
  requireOpaque(policy.projectId, 'policy.projectId');
  return strictClone(value);
}

export function executionFingerprint(fields) {
  const validated = validateFingerprintFields(fields);
  return createHash('sha256').update(canonicalJson({ domain: 'shared-review-execution-v1', ...validated }), 'utf8').digest('hex');
}

function invalidRecord() {
  return sharedError('INVALID_SHARED_RECORD');
}

function validateReceiptInner(value) {
  const receipt = exactObject(value, [
    'recordType', 'version', 'receiptId', 'revision', 'leaseId', 'preflightId', 'bindingId', 'projectId',
    'policyEpoch', 'scopeDigest', 'keyDigest', 'inputDigest', 'executionFingerprint', 'snapshotSourceId',
    'snapshotContextId', 'reviewContractSha256', 'mappingPins', 'reviewerIds', 'acceptedAt',
    'effectiveDeadline', 'state',
  ], ['preparedPayload', 'retiredPreparedPayloadAudit', 'startedAt', 'executionGroupId', 'claimId', 'cancellationRequested', 'terminalPublication', 'terminal', 'payloadRetired'], 'receipt');
  if (receipt.recordType !== 'shared/receipt' || receipt.version !== 1) fail('invalid receipt version');
  for (const name of ['receiptId', 'leaseId', 'preflightId']) requireUuid(receipt[name], name);
  requirePositiveInteger(receipt.revision, 'revision');
  requireOpaque(receipt.bindingId, 'bindingId');
  requireOpaque(receipt.projectId, 'projectId');
  requirePositiveInteger(receipt.policyEpoch, 'policyEpoch');
  for (const name of ['scopeDigest', 'keyDigest', 'inputDigest', 'executionFingerprint', 'snapshotSourceId', 'snapshotContextId', 'reviewContractSha256']) requireDigest(receipt[name], name);
  const hasPrepared = receipt.preparedPayload !== undefined;
  const hasRetired = receipt.retiredPreparedPayloadAudit !== undefined;
  if (hasPrepared === hasRetired) fail('receipt must have exactly one payload representation');
  const payload = hasPrepared ? receipt.preparedPayload : receipt.retiredPreparedPayloadAudit;
  const payloadShape = exactObject(payload, ['envelopeRef', 'requestRefs'], hasRetired ? ['retiredAt'] : [], 'payload');
  protectedRef(payloadShape.envelopeRef, 'payload.envelopeRef');
  strictArray(payloadShape.requestRefs, 'payload.requestRefs', { min: 1, max: SHARED_LIMITS.maxReviewers }).forEach((ref, index) => protectedRef(ref, `payload.requestRefs[${index}]`));
  if (hasRetired) requireIsoTime(payloadShape.retiredAt, 'payload.retiredAt');
  strictArray(receipt.mappingPins, 'mappingPins', { min: 1, max: SHARED_LIMITS.maxReviewers }).forEach((pin, index) => {
    const shape = exactObject(pin, ['preflightId', 'mappingIdentity'], [], `mappingPins[${index}]`);
    requireUuid(shape.preflightId, `mappingPins[${index}].preflightId`);
    requireDigest(shape.mappingIdentity, `mappingPins[${index}].mappingIdentity`);
  });
  const reviewerIds = strictArray(receipt.reviewerIds, 'reviewerIds', { min: 1, max: SHARED_LIMITS.maxReviewers });
  reviewerIds.forEach((id, index) => requireOpaque(id, `reviewerIds[${index}]`));
  if (new Set(reviewerIds).size !== reviewerIds.length) fail('reviewer IDs must be unique');
  requireIsoTime(receipt.acceptedAt, 'acceptedAt');
  requireIsoTime(receipt.effectiveDeadline, 'effectiveDeadline');
  if (!['QUEUED', 'WAITING', 'EXECUTING', 'RECOVERY_PENDING', 'TERMINAL'].includes(receipt.state)) fail('invalid receipt state');
  if (receipt.startedAt !== undefined) requireIsoTime(receipt.startedAt, 'startedAt');
  if (receipt.executionGroupId !== undefined) requireUuid(receipt.executionGroupId, 'executionGroupId');
  if (receipt.claimId !== undefined) requireUuid(receipt.claimId, 'claimId');
  if (receipt.cancellationRequested !== undefined && receipt.cancellationRequested !== true) fail('cancellationRequested must be true');
  if (receipt.payloadRetired !== undefined && receipt.payloadRetired !== true) fail('payloadRetired must be true');
  if (receipt.terminalPublication !== undefined) {
    if (receipt.claimId === undefined || receipt.state === 'TERMINAL') fail('terminal publication receipt state is invalid');
    validateTerminalPublication(receipt.terminalPublication, reviewerIds, receipt.claimId);
  }
  if (receipt.terminal !== undefined) {
    const terminal = exactObject(receipt.terminal, ['kind', 'completedAt'], ['terminalRef', 'terminalDigest', 'errorCode'], 'terminal');
    if (!['REVIEW_RETURNED', 'REVIEW_ERROR', 'EXPIRED', 'CANCELLED', 'CONTENT_LOST'].includes(terminal.kind)) fail('invalid terminal kind');
    requireIsoTime(terminal.completedAt, 'terminal.completedAt');
    if (terminal.terminalRef !== undefined) protectedRef(terminal.terminalRef, 'terminal.terminalRef');
    if (terminal.terminalDigest !== undefined) requireDigest(terminal.terminalDigest, 'terminal.terminalDigest');
    if ((terminal.terminalRef === undefined) !== (terminal.terminalDigest === undefined)) fail('terminal ref and digest must be paired');
    if (terminal.errorCode !== undefined) requireOpaque(terminal.errorCode, 'terminal.errorCode');
  }
  if ((receipt.state === 'TERMINAL') !== (receipt.terminal !== undefined)) fail('terminal state must match terminal metadata');
  const cloned = strictClone(value);
  if (Buffer.byteLength(canonicalJson(cloned), 'utf8') > SHARED_LIMITS.maxReceiptMetadataBytes) fail('receipt metadata too large');
  return cloned;
}

export function validateReceipt(value) {
  try { return validateReceiptInner(value); } catch { throw invalidRecord(); }
}

function validatePreparedEnvelopeInner(value) {
  const envelope = exactObject(value, ['version', 'leaseId', 'preflightId', 'scopeDigest', 'policyEpoch', 'projectId', 'executionFingerprint', 'acceptedBindingCredentialIdentity', 'fingerprintFields', 'requestRefs', 'mappingPin', 'effectiveDeadline'], [], 'preparedEnvelope');
  if (envelope.version !== 'shared-review-prepared-v1') fail('invalid prepared envelope version');
  requireUuid(envelope.leaseId, 'leaseId');
  requireUuid(envelope.preflightId, 'preflightId');
  requireDigest(envelope.scopeDigest, 'scopeDigest');
  requirePositiveInteger(envelope.policyEpoch, 'policyEpoch');
  requireOpaque(envelope.projectId, 'projectId');
  requireDigest(envelope.executionFingerprint, 'executionFingerprint');
  requireDigest(envelope.acceptedBindingCredentialIdentity, 'acceptedBindingCredentialIdentity');
  const fingerprintFields = validateFingerprintFields(envelope.fingerprintFields);
  if (executionFingerprint(fingerprintFields) !== envelope.executionFingerprint) fail('execution fingerprint mismatch');
  if (fingerprintFields.policy.scopeDigest !== envelope.scopeDigest || fingerprintFields.policy.policyEpoch !== envelope.policyEpoch || fingerprintFields.policy.projectId !== envelope.projectId) fail('envelope policy mismatch');
  const mappingPin = exactObject(envelope.mappingPin, ['preflightId', 'mappingIdentity'], [], 'mappingPin');
  requireUuid(mappingPin.preflightId, 'mappingPin.preflightId');
  requireDigest(mappingPin.mappingIdentity, 'mappingPin.mappingIdentity');
  if (mappingPin.preflightId !== envelope.preflightId || mappingPin.mappingIdentity !== fingerprintFields.mappingIdentity) fail('mapping pin mismatch');
  const requestRefs = strictArray(envelope.requestRefs, 'requestRefs', { min: 1, max: SHARED_LIMITS.maxReviewers });
  if (requestRefs.length !== fingerprintFields.reviewers.length) fail('request reviewer count mismatch');
  const objectIds = new Set();
  requestRefs.forEach((entry, index) => {
    const shape = exactObject(entry, ['reviewerId', 'requestRef', 'requestBodyDigest'], [], `requestRefs[${index}]`);
    requireOpaque(shape.reviewerId, `requestRefs[${index}].reviewerId`);
    const ref = protectedRef(shape.requestRef, `requestRefs[${index}].requestRef`);
    requireDigest(shape.requestBodyDigest, `requestRefs[${index}].requestBodyDigest`);
    if (objectIds.has(ref.objectId)) fail('duplicate request object ID');
    objectIds.add(ref.objectId);
    const reviewer = fingerprintFields.reviewers[index];
    if (shape.reviewerId !== reviewer.reviewerId || shape.requestBodyDigest !== reviewer.requestBodyDigest) fail('request reviewer identity mismatch');
  });
  requireIsoTime(envelope.effectiveDeadline, 'effectiveDeadline');
  const cloned = strictClone(value);
  if (Buffer.byteLength(canonicalJson(cloned), 'utf8') > SHARED_LIMITS.preparedEnvelopePlaintextBytes) fail('prepared envelope too large');
  return cloned;
}

export function validatePreparedEnvelope(value) {
  try { return validatePreparedEnvelopeInner(value); } catch { throw invalidRecord(); }
}

export function publicReceipt(receipt) {
  const value = validateReceipt(receipt);
  const projection = {
    receiptId: value.receiptId,
    leaseId: value.leaseId,
    preflightId: value.preflightId,
    state: value.state,
    acceptedAt: value.acceptedAt,
    effectiveDeadline: value.effectiveDeadline,
    snapshotSourceId: value.snapshotSourceId,
    reviewContractSha256: value.reviewContractSha256,
    ...(value.startedAt === undefined ? {} : { startedAt: value.startedAt }),
    ...(value.cancellationRequested === undefined ? {} : { cancellationRequested: true }),
    ...(value.terminal === undefined ? {} : { terminalKind: value.terminal.kind }),
  };
  if (Buffer.byteLength(canonicalJson(projection), 'utf8') > SHARED_LIMITS.maxReceiptMetadataBytes) throw invalidRecord();
  return Object.freeze(projection);
}
