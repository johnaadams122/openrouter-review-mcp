import assert from 'node:assert/strict';
import test from 'node:test';
import {
  canonicalJson,
  createIdentityDigest,
  digestIdempotencyKey,
  executionFingerprint,
  publicReceipt,
  sharedError,
  validatePreparedEnvelope,
  validateReceipt,
} from '../src/local-mcp/shared/contracts.mjs';
import {
  maximumPreflightEncryptedBytes,
  maximumPreparedEncryptedBytes,
} from '../src/local-mcp/shared/policy.mjs';
import {
  ACCEPTED_AT,
  DIGESTS,
  EFFECTIVE_DEADLINE,
  EXPECTED_EXECUTION_FINGERPRINT,
  IDS,
  buildFingerprintFields,
  buildPreparedEnvelope,
  buildReceipt,
  clone,
} from './helpers/shared-policy-fixture.mjs';

test('canonicalJson recursively sorts object keys, preserves array order, and normalizes negative zero', () => {
  assert.equal(
    canonicalJson({ b: 2, a: { d: 4, c: 3 }, order: ['z', 'a'], zero: -0 }),
    '{"a":{"c":3,"d":4},"b":2,"order":["z","a"],"zero":0}',
  );
});

test('canonicalJson rejects non-JSON shapes without invoking accessors', () => {
  let reads = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'secret', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error('ACCESSOR-SENTINEL');
    },
  });
  assert.throws(() => canonicalJson(accessor), TypeError);
  assert.equal(reads, 0);

  const nonEnumerable = { visible: true };
  Object.defineProperty(nonEnumerable, 'hidden', { enumerable: false, value: true });
  assert.throws(() => canonicalJson(nonEnumerable), TypeError);
  assert.throws(() => canonicalJson(Object.assign(Object.create(null), { value: 1 })), TypeError);
  assert.throws(() => canonicalJson([, 'sparse']), TypeError);
  assert.throws(() => canonicalJson({ value: Number.POSITIVE_INFINITY }), TypeError);
  assert.throws(() => canonicalJson({ value: undefined }), TypeError);
  assert.throws(() => canonicalJson({ value: 1n }), TypeError);
  assert.throws(() => canonicalJson({ [Symbol('hidden')]: true }), TypeError);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), TypeError);
});

test('canonicalJson rejects numeric-looking array properties beyond length without invoking getters', () => {
  for (const key of [String(2 ** 32 - 1), (2n ** 53n + 1n).toString()]) {
    let reads = 0;
    const values = ['first'];
    Object.defineProperty(values, key, { enumerable: true, get() { reads += 1; return 'discarded'; } });
    assert.throws(() => canonicalJson(values), TypeError);
    assert.equal(reads, 0);
  }
});

test('identity digests use the closed domain-separated HMAC contract', () => {
  const digest = createIdentityDigest(Buffer.alloc(32, 0x11));
  assert.equal(
    digest('shared-source-v1', Buffer.from('abc')),
    'a2ca358d2cc6fd879bb234a7a283b8bc89528833f4392f0bbfa267dbb7a24d6d',
  );
  assert.notEqual(
    digest('shared-source-v1', Buffer.from('abc')),
    digest('shared-context-v1', Buffer.from('abc')),
  );
  assert.throws(() => digest('shared-server-proof-v1', Buffer.from('abc')), TypeError);
  assert.throws(() => createIdentityDigest(Buffer.alloc(31)), TypeError);
  assert.throws(() => createIdentityDigest(new Uint8Array(32)), TypeError);
});

test('idempotency keys are opaque, case-sensitive, and never trimmed or interpreted as receipt IDs', () => {
  const digest = createIdentityDigest(Buffer.alloc(32, 0x22));
  assert.throws(
    () => digestIdempotencyKey(' padded-invalid ', digest),
    { code: 'INVALID_IDEMPOTENCY_KEY', message: 'Invalid idempotency key.' },
  );
  assert.throws(() => digestIdempotencyKey('too-short', digest), { code: 'INVALID_IDEMPOTENCY_KEY' });
  assert.notEqual(
    digestIdempotencyKey('A'.repeat(16), digest),
    digestIdempotencyKey('a'.repeat(16), digest),
  );
  const uuidShapedKey = ['9'.repeat(8),'9999','4999','8999','9'.repeat(12)].join('-');
  assert.match(digestIdempotencyKey(uuidShapedKey, digest), /^[a-f0-9]{64}$/);
  assert.notEqual(digestIdempotencyKey(uuidShapedKey, digest), uuidShapedKey);
});

test('executionFingerprint matches the hand-checked canonical identity and ignores object key insertion order', () => {
  const fields = buildFingerprintFields();
  assert.equal(executionFingerprint(fields), EXPECTED_EXECUTION_FINGERPRINT);
  assert.equal(executionFingerprint(Object.fromEntries(Object.entries(fields).reverse())), EXPECTED_EXECUTION_FINGERPRINT);
});

test('executionFingerprint changes for every material identity family', () => {
  const baseline = buildFingerprintFields();
  const cases = [
    ['source identity', (value) => { value.snapshotSourceId = 'abababababababababababababababababababababababababababababababab'; }],
    ['context identity', (value) => { value.snapshotContextId = 'abababababababababababababababababababababababababababababababab'; }],
    ['mapping identity', (value) => { value.mappingIdentity = 'abababababababababababababababababababababababababababababababab'; }],
    ['policy epoch', (value) => { value.policy.policyEpoch = 2; }],
    ['body identity', (value) => { value.reviewers[0].requestBodyDigest = 'abababababababababababababababababababababababababababababababab'; }],
    ['request controls', (value) => { value.reviewers[0].requestControls.stream = true; }],
    ['build identity', (value) => { value.buildManifestSha256 = 'abababababababababababababababababababababababababababababababab'; }],
    ['classifier identity', (value) => { value.classifierContractDigest = 'abababababababababababababababababababababababababababababababab'; }],
  ];
  for (const [name, mutate] of cases) {
    const changed = clone(baseline);
    mutate(changed);
    assert.notEqual(executionFingerprint(changed), EXPECTED_EXECUTION_FINGERPRINT, name);
  }
});

test('executionFingerprint rejects incomplete, unknown, and reviewer-order-inconsistent fields', () => {
  const missing = buildFingerprintFields();
  delete missing.snapshotContextId;
  assert.throws(() => executionFingerprint(missing), TypeError);

  const extra = buildFingerprintFields({ receiptId: IDS.receipt });
  assert.throws(() => executionFingerprint(extra), TypeError);

  const mismatched = buildFingerprintFields();
  mismatched.profile.orderedReviewerIds = ['gemini'];
  assert.throws(() => executionFingerprint(mismatched), TypeError);

  const missingReviewer = buildFingerprintFields();
  missingReviewer.profile.orderedReviewerIds = ['grok', 'gemini'];
  assert.throws(() => executionFingerprint(missingReviewer), TypeError);
});

test('validateReceipt accepts the complete private schema and publicReceipt exposes only the exact projection', () => {
  const receipt = validateReceipt(buildReceipt({
    startedAt: '2026-09-19T17:05:00.000Z',
    cancellationRequested: true,
    state: 'TERMINAL',
    terminal: {
      kind: 'REVIEW_RETURNED',
      terminalRef: { objectId: IDS.terminal, sha256: DIGESTS.context, encryptedBytes: 8_192 },
      terminalDigest: DIGESTS.request,
      completedAt: '2026-09-19T17:30:00.000Z',
    },
  }));
  assert.deepEqual(publicReceipt(receipt), {
    receiptId: IDS.receipt,
    leaseId: IDS.lease,
    preflightId: IDS.preflight,
    state: 'TERMINAL',
    acceptedAt: ACCEPTED_AT,
    effectiveDeadline: EFFECTIVE_DEADLINE,
    snapshotSourceId: DIGESTS.source,
    reviewContractSha256: DIGESTS.reviewContract,
    startedAt: '2026-09-19T17:05:00.000Z',
    cancellationRequested: true,
    terminalKind: 'REVIEW_RETURNED',
  });
  const missingDigest = clone(receipt);
  delete missingDigest.terminal.terminalDigest;
  assert.throws(() => validateReceipt(missingDigest), { code: 'INVALID_SHARED_RECORD' });
  const missingRef = clone(receipt);
  delete missingRef.terminal.terminalRef;
  assert.throws(() => validateReceipt(missingRef), { code: 'INVALID_SHARED_RECORD' });
});

test('receipt validation rejects accessors, unknown fields, and ambiguous payload lifecycle state', () => {
  let reads = 0;
  const accessor = buildReceipt();
  Object.defineProperty(accessor, 'claimId', {
    enumerable: true,
    get() {
      reads += 1;
      return IDS.terminal;
    },
  });
  assert.throws(() => validateReceipt(accessor), { code: 'INVALID_SHARED_RECORD' });
  assert.equal(reads, 0);

  assert.throws(() => validateReceipt(buildReceipt({ rawSource: 'forbidden' })), { code: 'INVALID_SHARED_RECORD' });
  const bothPayloads = buildReceipt({
    retiredPreparedPayloadAudit: {
      envelopeRef: { objectId: IDS.envelope, sha256: DIGESTS.mapping, encryptedBytes: 2_048 },
      requestRefs: [{ objectId: IDS.request, sha256: DIGESTS.file, encryptedBytes: 4_096 }],
      retiredAt: '2026-09-19T17:45:00.000Z',
    },
  });
  assert.throws(() => validateReceipt(bothPayloads), { code: 'INVALID_SHARED_RECORD' });
});

test('validatePreparedEnvelope enforces the exact cross-linked schema', () => {
  assert.deepEqual(validatePreparedEnvelope(buildPreparedEnvelope()), buildPreparedEnvelope());

  const policyMismatch = buildPreparedEnvelope({ projectId: 'other-project' });
  assert.throws(() => validatePreparedEnvelope(policyMismatch), { code: 'INVALID_SHARED_RECORD' });

  const staleFingerprint = buildPreparedEnvelope();
  staleFingerprint.fingerprintFields.snapshotContextId = 'abababababababababababababababababababababababababababababababab';
  assert.throws(() => validatePreparedEnvelope(staleFingerprint), { code: 'INVALID_SHARED_RECORD' });

  const mismatchedMapping = buildPreparedEnvelope();
  mismatchedMapping.mappingPin.mappingIdentity = 'abababababababababababababababababababababababababababababababab';
  assert.throws(() => validatePreparedEnvelope(mismatchedMapping), { code: 'INVALID_SHARED_RECORD' });

  const mismatchedBody = buildPreparedEnvelope();
  mismatchedBody.requestRefs[0].requestBodyDigest = 'abababababababababababababababababababababababababababababababab';
  assert.throws(() => validatePreparedEnvelope(mismatchedBody), { code: 'INVALID_SHARED_RECORD' });

});

test('prepared credential checkpoints bind accepted execution without changing cross-binding sharing identity', () => {
  const first = buildPreparedEnvelope({ acceptedBindingCredentialIdentity: DIGESTS.credentialA });
  const second = buildPreparedEnvelope({ acceptedBindingCredentialIdentity: DIGESTS.credentialB });
  assert.deepEqual(validatePreparedEnvelope(first), first);
  assert.deepEqual(validatePreparedEnvelope(second), second);
  assert.equal(first.executionFingerprint, second.executionFingerprint);
  assert.notEqual(first.acceptedBindingCredentialIdentity, second.acceptedBindingCredentialIdentity);
});

test('prepared credential checkpoints are mandatory strict digests and never execute accessors', () => {
  const missing = buildPreparedEnvelope();
  delete missing.acceptedBindingCredentialIdentity;
  assert.throws(() => validatePreparedEnvelope(missing), { code: 'INVALID_SHARED_RECORD' });
  for (const invalid of ['', 'a'.repeat(63), 'A'.repeat(64), null, {}, 123]) {
    assert.throws(() => validatePreparedEnvelope(buildPreparedEnvelope({ acceptedBindingCredentialIdentity: invalid })), { code: 'INVALID_SHARED_RECORD' });
  }
  let reads = 0;
  const accessor = buildPreparedEnvelope();
  Object.defineProperty(accessor, 'acceptedBindingCredentialIdentity', { enumerable: true, get() { reads += 1; throw new Error('CHECKPOINT_SENTINEL'); } });
  assert.throws(() => validatePreparedEnvelope(accessor), { code: 'INVALID_SHARED_RECORD' });
  assert.equal(reads, 0);
});

test('validatePreparedEnvelope rejects duplicate protected request object IDs independently of reviewer order', () => {
  const envelope = buildPreparedEnvelope();
  envelope.fingerprintFields.profile = {
    profileId: 'consequential_spec_v1',
    profileVersion: '1',
    orderedReviewerIds: ['grok', 'gemini'],
  };
  envelope.fingerprintFields.reviewers.push({
    reviewerId: 'gemini',
    model: 'google/gemini-3.8-flash',
    route: 'google-vertex/global',
    expectedProvider: 'Google',
    outputMode: 'strict_json',
    requestControls: {
      reasoning: { effort: 'high' },
      maxTokens: 65_536,
      stream: false,
      provider: {
        zdr: true,
        dataCollection: 'deny',
        requireParameters: true,
        allowFallbacks: false,
      },
      priceCeiling: {
        promptUsdPerMillionTokens: 1.5,
        completionUsdPerMillionTokens: 7.5,
      },
    },
    requestBodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });
  envelope.executionFingerprint = '23827b80030fec82f63af2995501c3a25c0d30f0a22befa5bf89736291429f8a';
  envelope.requestRefs.push({
    reviewerId: 'gemini',
    requestRef: {
      objectId: ['7'.repeat(8),'7777','4777','8777','7'.repeat(12)].join('-'),
      sha256: DIGESTS.context,
      encryptedBytes: 8_192,
    },
    requestBodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });
  assert.deepEqual(validatePreparedEnvelope(envelope), envelope);

  const duplicateObject = clone(envelope);
  duplicateObject.requestRefs[1].requestRef.objectId = duplicateObject.requestRefs[0].requestRef.objectId;
  assert.throws(() => validatePreparedEnvelope(duplicateObject), { code: 'INVALID_SHARED_RECORD' });
});

test('sharedError exposes only the exhaustive fixed code/message table', () => {
  const expected = new Map([
    ['INVALID_IDEMPOTENCY_KEY', 'Invalid idempotency key.'],
    ['INVALID_SHARED_RECORD', 'Invalid shared review record.'],
    ['INVALID_INSTALLATION_CONFIG', 'Invalid shared review configuration.'],
    ['SERVICE_NOT_PROVISIONED', 'Shared review service is not provisioned.'],
    ['SERVICE_MIGRATION_REQUIRED', 'Shared review service requires a quiescent migration.'],
    ['EXECUTOR_PERSISTENCE_UNAVAILABLE', 'Persistent executor launch is unavailable.'],
    ['SERVICE_UNAVAILABLE', 'Shared review service is temporarily unavailable.'],
    ['PROJECT_SCOPE_REQUIRED', 'A configured project scope is required.'],
    ['PROJECT_SCOPE_DENIED', 'Project scope is not permitted.'],
    ['REQUEST_NOT_FOUND', 'Review request was not found.'],
    ['REQUEST_TOO_LARGE', 'Review request exceeds the input limit.'],
    ['IDEMPOTENCY_CONFLICT', 'Idempotency key conflicts with an existing request.'],
    ['LEASE_REQUEST_CONFLICT', 'Lease already identifies another review request.'],
    ['REQUEST_CAPACITY_FULL', 'Review request capacity is full.'],
    ['REQUEST_BYTES_FULL', 'Review storage capacity is full.'],
    ['REQUEST_EXPIRED', 'Review request expired before execution.'],
    ['REQUEST_CANCELLED', 'Review request was cancelled.'],
    ['REQUEST_CONTENT_LOST', 'Review content is unavailable.'],
    ['REQUEST_FAILED', 'Review request failed.'],
    ['FRESH_PREFLIGHT_REQUIRED', 'A fresh review preflight is required.'],
    ['PROTECTED_CONTENT_INVALID', 'Protected review content is invalid.'],
    ['PROTECTED_CONTENT_TOO_LARGE', 'Protected review content exceeds its size limit.'],
  ]);
  for (const [code, message] of expected) {
    const error = sharedError(code);
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    assert.doesNotMatch(error.message, /sentinel|path|hash/i);
  }
  assert.throws(() => sharedError('RAW_INTERNAL_SENTINEL'), TypeError);
});

test('prepared and preflight encrypted-byte reservations include fixed overhead and fail before overflow', () => {
  assert.equal(maximumPreparedEncryptedBytes({ reviewerCount: 1, maxRequestBytes: 4_194_304 }), 8_912_896);
  assert.equal(maximumPreparedEncryptedBytes({ reviewerCount: 15, maxRequestBytes: 4_194_304 }), 128_188_416);
  assert.equal(maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: 67_108_864 }), 134_479_872);
  assert.throws(() => maximumPreparedEncryptedBytes({ reviewerCount: 0, maxRequestBytes: 4_194_304 }), TypeError);
  assert.throws(() => maximumPreparedEncryptedBytes({ reviewerCount: 16, maxRequestBytes: 4_194_304 }), TypeError);
  assert.throws(() => maximumPreparedEncryptedBytes({ reviewerCount: 15, maxRequestBytes: Number.MAX_SAFE_INTEGER }), RangeError);
  assert.throws(() => maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: Number.MAX_SAFE_INTEGER }), RangeError);

  let reads = 0;
  const hostile = { maxRequestBytes: 4_194_304 };
  Object.defineProperty(hostile, 'reviewerCount', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error('CAPACITY-ACCESSOR-SENTINEL');
    },
  });
  assert.throws(() => maximumPreparedEncryptedBytes(hostile), TypeError);
  assert.equal(reads, 0);
});
