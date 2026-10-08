import assert from 'node:assert/strict';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createIdentityDigest } from '../src/local-mcp/shared/contracts.mjs';
import * as sharedPolicy from '../src/local-mcp/shared/policy.mjs';
import {
  configurationFingerprint,
  createAuthenticationProof,
  deriveManagedInstallationRoots,
  maximumPreparedEncryptedBytes,
  maximumPreflightEncryptedBytes,
  resolveBoundProjectPolicy,
  resolveCallerPolicy,
  validateInstallationConfig,
} from '../src/local-mcp/shared/policy.mjs';
import {
  DIGESTS,
  authenticationTranscript,
  buildInstallationConfig,
  buildManifest,
  clone,
} from './helpers/shared-policy-fixture.mjs';

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const allowedPath = join(allowedRoot, 'spec.md');
const outsideRoot = resolve('tests/fixtures/openrouter-review/outside');
const outsidePath = join(outsideRoot, 'secret.md');
const identityDigest = createIdentityDigest(Buffer.alloc(32, 0x33));

test('allowed reviewer sets represent both legal final-verification shapes and authorize exact order only', () => {
  const input = buildInstallationConfig();
  input.review.allowedProfiles = [{
    profileId: 'final_verification_v1',
    profileVersion: '1',
    allowedReviewerSets: [['grok'], ['grok', 'gemini']],
  }];
  const validated = validateInstallationConfig(input);
  const profile = validated.review.allowedProfiles[0];
  assert.equal(typeof sharedPolicy.isAllowedReviewerSet, 'function');
  assert.equal(typeof sharedPolicy.largestAllowedReviewerCount, 'function');
  assert.equal(sharedPolicy.isAllowedReviewerSet(profile, ['grok']), true);
  assert.equal(sharedPolicy.isAllowedReviewerSet(profile, ['grok', 'gemini']), true);
  assert.equal(sharedPolicy.isAllowedReviewerSet(profile, ['gemini', 'grok']), false);
  assert.equal(sharedPolicy.largestAllowedReviewerCount(profile), 2);
});

test('allowed reviewer sets reject empty, duplicate, oversized, legacy, and duplicate-profile shapes', () => {
  const cases = [
    ['no sets', (config) => { config.review.allowedProfiles[0].allowedReviewerSets = []; }],
    ['empty set', (config) => { config.review.allowedProfiles[0].allowedReviewerSets = [[]]; }],
    ['duplicate reviewer', (config) => { config.review.allowedProfiles[0].allowedReviewerSets = [['grok', 'grok']]; }],
    ['duplicate set', (config) => { config.review.allowedProfiles[0].allowedReviewerSets = [['grok'], ['grok']]; }],
    ['oversized set', (config) => {
      config.review.allowedProfiles[0].allowedReviewerSets = [Array.from({ length: 16 }, (_, index) => `reviewer-${index}`)];
    }],
    ['legacy field', (config) => {
      config.review.allowedProfiles[0] = {
        profileId: 'final_verification_v1', profileVersion: '1', orderedReviewerIds: ['grok'],
      };
    }],
    ['duplicate profile', (config) => {
      config.review.allowedProfiles.push(clone(config.review.allowedProfiles[0]));
    }],
  ];
  for (const [name, mutate] of cases) {
    const config = buildInstallationConfig();
    mutate(config);
    assert.throws(
      () => validateInstallationConfig(config),
      { code: 'INVALID_INSTALLATION_CONFIG' },
      name,
    );
  }
});

test('preflight capacity covers both protected objects at every allowed plaintext split', () => {
  const combinedPlaintextLimit = 64 * 1024 * 1024;
  const reservation = maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: combinedPlaintextLimit });
  for (const contextBytes of [0, 1, combinedPlaintextLimit / 2, combinedPlaintextLimit - 1, combinedPlaintextLimit]) {
    const mappingBytes = combinedPlaintextLimit - contextBytes;
    const independentObjectBounds = [contextBytes, mappingBytes].map((bytes) => 2 * bytes + 131_072);
    assert.equal(reservation, independentObjectBounds.reduce((sum, bytes) => sum + bytes, 0));
  }
  assert.throws(() => maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: Number.MAX_SAFE_INTEGER }), RangeError);
});

test('prepared capacity includes each request object and the separately protected metadata envelope', () => {
  const bodyLimit = 4 * 1024 * 1024;
  for (const reviewerCount of [1, 2, 3, 15]) {
    const independentlyProtectedPlaintexts = [...Array(reviewerCount).fill(bodyLimit), 131_072];
    const ciphertextTotal = independentlyProtectedPlaintexts.reduce((sum, bytes) => sum + 2 * bytes + 131_072, 0);
    assert.equal(maximumPreparedEncryptedBytes({ reviewerCount, maxRequestBytes: bodyLimit }), ciphertextTotal);
  }
  assert.throws(() => maximumPreparedEncryptedBytes({ reviewerCount: 1, maxRequestBytes: Number.MAX_SAFE_INTEGER }), RangeError);
});

function replaceBinding(config, bindingId, update) {
  const index = config.bindings.findIndex((binding) => binding.bindingId === bindingId);
  config.bindings[index] = { ...config.bindings[index], ...update };
  return config;
}

test('validateInstallationConfig returns a detached deeply frozen canonical config', () => {
  const input = buildInstallationConfig();
  const validated = validateInstallationConfig(input);
  assert.notEqual(validated, input);
  assert.notEqual(validated.engine, input.engine);
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.engine), true);
  assert.equal(Object.isFrozen(validated.bindings[0].domains[0].allowedRoots), true);

  input.engine.dailyPaidJobAllowance = 999;
  input.bindings[0].domains[0].allowedRoots[0] = outsideRoot;
  assert.equal(validated.engine.dailyPaidJobAllowance, 20);
  assert.deepEqual(validated.bindings[0].domains[0].allowedRoots, [allowedRoot]);
  assert.throws(() => { validated.engine.dailyPaidJobAllowance = 999; }, TypeError);
});

test('installation config rejects numeric-looking extra properties on registry arrays', () => {
  const input = buildInstallationConfig();
  Object.defineProperty(input.bindings, String(2 ** 32 - 1), { enumerable: true, value: { hidden: true } });
  assert.throws(() => validateInstallationConfig(input), { code: 'INVALID_INSTALLATION_CONFIG' });
});

test('installation config validation rejects accessors and unknown secret-bearing keys without reading them', () => {
  let reads = 0;
  const config = buildInstallationConfig();
  Object.defineProperty(config.engine, 'apiKey', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error('CREDENTIAL-SENTINEL');
    },
  });
  assert.throws(() => validateInstallationConfig(config), { code: 'INVALID_INSTALLATION_CONFIG' });
  assert.equal(reads, 0);
});

test('installation config permits consistent positive narrowing and rejects v1 maxima or relationship violations', () => {
  const narrowed = buildInstallationConfig();
  narrowed.engine.maxSourceBytes = 1_000_000;
  narrowed.engine.maxRequestBytes = 2_000_000;
  narrowed.queue.maxActiveBatches = 2;
  narrowed.queue.maxWaitingCallerRequests = 3;
  narrowed.queue.maxUnfinishedCount = 5;
  narrowed.queue.maxActiveReviewerDispatches = 6;
  narrowed.queue.maxIdempotencyKeysPerLease = 8;
  narrowed.storage.maxLivePreflights = 10;
  narrowed.storage.maxSinglePreflightPlaintextBytes = 16_000_000;
  narrowed.storage.maxPreflightEncryptedBytes = 40_000_000;
  assert.equal(validateInstallationConfig(narrowed).queue.maxUnfinishedCount, 5);

  const profileTooWide = buildInstallationConfig();
  profileTooWide.queue.maxActiveBatches = 1;
  profileTooWide.queue.maxWaitingCallerRequests = 1;
  profileTooWide.queue.maxUnfinishedCount = 2;
  profileTooWide.queue.maxActiveReviewerDispatches = 1;
  profileTooWide.review.allowedProfiles[0].allowedReviewerSets = [['grok', 'gemini']];
  assert.throws(() => validateInstallationConfig(profileTooWide), { code: 'INVALID_INSTALLATION_CONFIG' });

  const bytesTooNarrow = buildInstallationConfig();
  bytesTooNarrow.queue.maxUnfinishedEncryptedBytes = 1_048_576;
  assert.throws(() => validateInstallationConfig(bytesTooNarrow), { code: 'INVALID_INSTALLATION_CONFIG' });

  const cases = [
    ['source maximum', (value) => { value.engine.maxSourceBytes = 2_000_001; }],
    ['request maximum', (value) => { value.engine.maxRequestBytes = 4_194_305; }],
    ['unfinished relationship', (value) => { value.queue.maxUnfinishedCount = 14; }],
    ['active reviewer relationship', (value) => { value.queue.maxActiveReviewerDispatches = 4; }],
    ['idempotency-key positive bound', (value) => { value.queue.maxIdempotencyKeysPerLease = 0; }],
    ['idempotency-key maximum', (value) => { value.queue.maxIdempotencyKeysPerLease = 65; }],
    ['chunk/frame fit', (value) => { value.transport.contentFrameBytes = 700_000; }],
    ['aggregate ingress', (value) => { value.transport.maxInflightIngressBytes = 60_000_000; }],
    ['preflight reservation/global cap', (value) => { value.storage.maxPreflightEncryptedBytes = 100_000_000; }],
  ];
  for (const [name, mutate] of cases) {
    const invalid = buildInstallationConfig();
    mutate(invalid);
    assert.throws(
      () => validateInstallationConfig(invalid),
      { code: 'INVALID_INSTALLATION_CONFIG' },
      name,
    );
  }
});

test('project registry and bindings cannot widen free eligibility or create ambiguous roots', () => {
  // 'unreviewed-project' is not in the fixture's configured free-tier list, so marking it free-eligible is refused.
  const unknownFree = buildInstallationConfig();
  unknownFree.projects[0].projectId = 'unreviewed-project';
  unknownFree.bindings[0].domains[0].projectId = 'unreviewed-project';
  unknownFree.bindings[0].defaultInlineProjectId = 'unreviewed-project';
  assert.throws(() => validateInstallationConfig(unknownFree), { code: 'INVALID_INSTALLATION_CONFIG' });

  const widened = buildInstallationConfig();
  widened.projects[0].freeEligible = false;
  assert.throws(() => validateInstallationConfig(widened), { code: 'INVALID_INSTALLATION_CONFIG' });

  const wrongDefault = buildInstallationConfig();
  wrongDefault.bindings[0].defaultInlineProjectId = 'project-beta';
  assert.throws(() => validateInstallationConfig(wrongDefault), { code: 'INVALID_INSTALLATION_CONFIG' });

  const emptyUnselectedDomain = buildInstallationConfig();
  emptyUnselectedDomain.bindings[0].domains[0].allowedRoots = [];
  emptyUnselectedDomain.bindings[0].defaultInlineProjectId = null;
  assert.throws(() => validateInstallationConfig(emptyUnselectedDomain), { code: 'INVALID_INSTALLATION_CONFIG' });

  const overlapping = buildInstallationConfig();
  const nested = join(allowedRoot, 'nested-project');
  overlapping.projects.push({ projectId: 'project-beta', policyEpoch: 1, canonicalRoots: [nested], freeEligible: false });
  assert.throws(() => validateInstallationConfig(overlapping), { code: 'INVALID_INSTALLATION_CONFIG' });
});

test('the free-tier project list comes from the installation configuration and must be stated explicitly', () => {
  const missing = buildInstallationConfig();
  delete missing.freeTierProjectIds;
  assert.throws(() => validateInstallationConfig(missing), { code: 'INVALID_INSTALLATION_CONFIG' }, 'a missing list is refused, never defaulted');

  const emptyButFree = buildInstallationConfig({ freeTierProjectIds: [] });
  assert.throws(() => validateInstallationConfig(emptyButFree), { code: 'INVALID_INSTALLATION_CONFIG' }, 'the public default admits no free project');

  const emptyAllPaid = buildInstallationConfig({ freeTierProjectIds: [] });
  emptyAllPaid.projects[0].freeEligible = false;
  for (const binding of emptyAllPaid.bindings) binding.domains[0].freeEligible = false;
  assert.deepEqual(validateInstallationConfig(emptyAllPaid).freeTierProjectIds, []);

  const listedElsewhere = buildInstallationConfig({ freeTierProjectIds: ['project-beta'] });
  assert.throws(() => validateInstallationConfig(listedElsewhere), { code: 'INVALID_INSTALLATION_CONFIG' }, 'only a listed project may be free-eligible');

  const listed = buildInstallationConfig({ freeTierProjectIds: ['project-beta', 'project-alpha'] });
  assert.deepEqual(validateInstallationConfig(listed).freeTierProjectIds, ['project-beta', 'project-alpha']);

  for (const freeTierProjectIds of ['project-alpha', ['project-alpha', 'project-alpha'], ['not an opaque id'], [7], null]) {
    assert.throws(
      () => validateInstallationConfig(buildInstallationConfig({ freeTierProjectIds })),
      { code: 'INVALID_INSTALLATION_CONFIG' },
      JSON.stringify(freeTierProjectIds),
    );
  }
});

test('extra protected terms in the installation configuration are explicit, canonical and fail closed', () => {
  const none = validateInstallationConfig(buildInstallationConfig());
  assert.deepEqual(none.engine.extraProtectedTerms, { sourceSha256: null, markers: [], contextTerms: [] });

  const configuredTerms = { sourceSha256: 'ad'.repeat(32), markers: ['ZQBOARD', 'zq review panel'], contextTerms: ['ZQ'] };
  const configured = buildInstallationConfig();
  configured.engine.extraProtectedTerms = configuredTerms;
  assert.deepEqual(validateInstallationConfig(configured).engine.extraProtectedTerms, configuredTerms);

  const missing = buildInstallationConfig();
  delete missing.engine.extraProtectedTerms;
  assert.throws(() => validateInstallationConfig(missing), { code: 'INVALID_INSTALLATION_CONFIG' }, 'a missing setting is refused, never defaulted');

  const invalid = [
    ['null setting', null],
    ['explicit none still carrying terms', { sourceSha256: null, markers: ['ZQBOARD'], contextTerms: [] }],
    ['a named source with no terms', { sourceSha256: 'ad'.repeat(32), markers: [], contextTerms: [] }],
    ['a source that is not a digest', { sourceSha256: 'not-a-digest', markers: ['ZQBOARD'], contextTerms: [] }],
    ['a term with regex syntax', { sourceSha256: 'ad'.repeat(32), markers: ['ZQ.*'], contextTerms: [] }],
    ['a term that is not canonical', { sourceSha256: 'ad'.repeat(32), markers: ['ZQ   BOARD'], contextTerms: [] }],
    ['a duplicate term', { sourceSha256: 'ad'.repeat(32), markers: ['ZQBOARD', 'zqboard'], contextTerms: [] }],
    ['an unknown key', { sourceSha256: 'ad'.repeat(32), markers: ['ZQBOARD'], contextTerms: [], path: 'x' }],
    ['a missing list', { sourceSha256: 'ad'.repeat(32), markers: ['ZQBOARD'] }],
  ];
  for (const [label, value] of invalid) {
    const config = buildInstallationConfig();
    config.engine.extraProtectedTerms = value;
    assert.throws(() => validateInstallationConfig(config), { code: 'INVALID_INSTALLATION_CONFIG' }, label);
  }
});

test('configurationFingerprint covers the free-tier list and the extra protected terms', () => {
  const manifest = buildManifest();
  const baseline = configurationFingerprint(buildInstallationConfig(), manifest);
  const widenedFreeList = buildInstallationConfig({ freeTierProjectIds: ['project-alpha', 'project-beta'] });
  assert.notEqual(configurationFingerprint(widenedFreeList, manifest), baseline);
  const withTerms = buildInstallationConfig();
  withTerms.engine.extraProtectedTerms = { sourceSha256: 'ad'.repeat(32), markers: ['ZQBOARD'], contextTerms: [] };
  const termsFingerprint = configurationFingerprint(withTerms, manifest);
  assert.notEqual(termsFingerprint, baseline);
  withTerms.engine.extraProtectedTerms.markers = ['ZQPANEL'];
  assert.notEqual(configurationFingerprint(withTerms, manifest), termsFingerprint, 'a changed term changes the fingerprint');
});

test('configurationFingerprint verifies the strict manifest, omits credential digests, and includes credential versions', () => {
  const manifest = buildManifest();
  const base = buildInstallationConfig();
  const baseline = configurationFingerprint(base, manifest);
  assert.match(baseline, /^[a-f0-9]{64}$/);

  const rotatedSecretSameVersion = buildInstallationConfig();
  rotatedSecretSameVersion.bindings[0].credentialDigest = 'abababababababababababababababababababababababababababababababab';
  assert.equal(configurationFingerprint(rotatedSecretSameVersion, manifest), baseline);

  const changedVersion = buildInstallationConfig();
  changedVersion.bindings[0].credentialVersion = 'credential-v9';
  assert.notEqual(configurationFingerprint(changedVersion, manifest), baseline);

  const changedReviewerCatalog = buildInstallationConfig();
  changedReviewerCatalog.review.allowedProfiles[0].allowedReviewerSets = [['grok']];
  assert.notEqual(configurationFingerprint(changedReviewerCatalog, manifest), baseline);

  const changedClassifierIdentity = buildInstallationConfig();
  changedClassifierIdentity.engine.classifierContractDigest = 'ac'.repeat(32);
  assert.notEqual(configurationFingerprint(changedClassifierIdentity, manifest), baseline);

  const wrongDigest = buildInstallationConfig({
    buildManifestSha256: 'abababababababababababababababababababababababababababababababab',
  });
  assert.throws(() => configurationFingerprint(wrongDigest, manifest), { code: 'INVALID_INSTALLATION_CONFIG' });

  const unsortedManifest = buildManifest({
    files: [
      { path: 'z.mjs', sha256: DIGESTS.file, bytes: 1 },
      { path: 'a.mjs', sha256: DIGESTS.node, bytes: 1 },
    ],
  });
  assert.throws(() => configurationFingerprint(base, unsortedManifest), { code: 'INVALID_INSTALLATION_CONFIG' });
});

test('inline caller policy comes only from the authenticated binding and equal authority shares scope', async () => {
  const config = validateInstallationConfig(buildInstallationConfig());
  const policyA = await resolveCallerPolicy({
    config,
    bindingId: 'binding-a',
    credentialDigest: DIGESTS.credentialA,
    sourceKind: 'inline',
    identityDigest,
  });
  const policyB = await resolveCallerPolicy({
    config,
    bindingId: 'binding-b',
    credentialDigest: DIGESTS.credentialB,
    sourceKind: 'inline',
    identityDigest,
  });
  assert.deepEqual(policyA, {
    bindingId: 'binding-a',
    policyEpoch: 1,
    scopeDigest: policyA.scopeDigest,
    projectId: 'project-alpha',
    allowedRoots: [allowedRoot],
    freeEligible: true,
    defaultInlineProjectId: 'project-alpha',
    legacyRecovery: false,
  });
  assert.match(policyA.scopeDigest, /^[a-f0-9]{64}$/);
  assert.equal(policyA.scopeDigest, policyB.scopeDigest);
  assert.notEqual(policyA.bindingId, policyB.bindingId);
  assert.equal(Object.isFrozen(policyA), true);
  assert.equal(Object.isFrozen(policyA.allowedRoots), true);
});

test('caller labels cannot select or widen project authority', async () => {
  const config = validateInstallationConfig(buildInstallationConfig());
  await assert.rejects(
    () => resolveCallerPolicy({
      config,
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialA,
      sourceKind: 'inline',
      projectId: 'project-beta',
      scopeDigest: DIGESTS.scope,
      identityDigest,
    }),
    { code: 'PROJECT_SCOPE_DENIED' },
  );

  const noInline = buildInstallationConfig();
  replaceBinding(noInline, 'binding-a', { defaultInlineProjectId: null });
  await assert.rejects(
    () => resolveCallerPolicy({
      config: validateInstallationConfig(noInline),
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialA,
      sourceKind: 'inline',
      identityDigest,
    }),
    { code: 'PROJECT_SCOPE_REQUIRED' },
  );
});

test('path caller policy selects the canonical containing domain and exposes only that project roots', async () => {
  const input = buildInstallationConfig();
  input.projects.push({ projectId: 'project-beta', policyEpoch: 7, canonicalRoots: [outsideRoot], freeEligible: false });
  for (const binding of input.bindings) {
    binding.domains.push({ projectId: 'project-beta', allowedRoots: [outsideRoot], freeEligible: false });
  }
  const policy = await resolveCallerPolicy({
    config: validateInstallationConfig(input),
    bindingId: 'binding-a',
    credentialDigest: DIGESTS.credentialA,
    sourceKind: 'path',
    sourcePath: outsidePath,
    identityDigest,
  });
  assert.equal(policy.projectId, 'project-beta');
  assert.equal(policy.policyEpoch, 7);
  assert.deepEqual(policy.allowedRoots, [outsideRoot]);
});

test('caller authentication fails closed for bad credentials, disabled bindings, and unknown path domains', async () => {
  const config = validateInstallationConfig(buildInstallationConfig());
  await assert.rejects(
    () => resolveCallerPolicy({
      config,
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialB,
      sourceKind: 'inline',
      identityDigest,
    }),
    { code: 'PROJECT_SCOPE_DENIED' },
  );

  const disabled = buildInstallationConfig();
  replaceBinding(disabled, 'binding-a', { enabled: false });
  await assert.rejects(
    () => resolveCallerPolicy({
      config: validateInstallationConfig(disabled),
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialA,
      sourceKind: 'inline',
      identityDigest,
    }),
    { code: 'PROJECT_SCOPE_DENIED' },
  );

  await assert.rejects(
    () => resolveCallerPolicy({
      config,
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialA,
      sourceKind: 'path',
      sourcePath: outsidePath,
      identityDigest,
    }),
    { code: 'PROJECT_SCOPE_DENIED' },
  );
});

test('path scope resolution projects an allowed oversized source as REQUEST_TOO_LARGE', async () => {
  const input = buildInstallationConfig();
  input.engine.maxSourceBytes = 1;
  await assert.rejects(
    () => resolveCallerPolicy({
      config: validateInstallationConfig(input),
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialA,
      sourceKind: 'path',
      sourcePath: allowedPath,
      identityDigest,
    }),
    { code: 'REQUEST_TOO_LARGE' },
  );
});

test('source-less policy revalidation uses only stored project identity and collapses revocation to REQUEST_NOT_FOUND', async () => {
  const config = validateInstallationConfig(buildInstallationConfig());
  const resolved = await resolveBoundProjectPolicy({
    config,
    bindingId: 'binding-a',
    credentialDigest: DIGESTS.credentialA,
    storedProjectId: 'project-alpha',
    identityDigest,
  });
  assert.equal(resolved.projectId, 'project-alpha');

  for (const overrides of [
    { credentialDigest: DIGESTS.credentialB },
    { storedProjectId: 'project-beta' },
  ]) {
    await assert.rejects(
      () => resolveBoundProjectPolicy({
        config,
        bindingId: 'binding-a',
        credentialDigest: DIGESTS.credentialA,
        storedProjectId: 'project-alpha',
        identityDigest,
        ...overrides,
      }),
      { code: 'REQUEST_NOT_FOUND' },
    );
  }

  await assert.rejects(
    () => resolveBoundProjectPolicy({
      config,
      bindingId: 'binding-a',
      credentialDigest: DIGESTS.credentialA,
      storedProjectId: 'project-alpha',
      projectId: 'project-beta',
      identityDigest,
    }),
    { code: 'REQUEST_NOT_FOUND' },
  );
});

test('deriveManagedInstallationRoots returns only the deterministic frozen managed subtree', () => {
  const dataRoot = resolve('tests/fixtures/shared/root-contract');
  const roots = deriveManagedInstallationRoots(dataRoot);
  const managedRoot = join(dataRoot, 'managed-shared-v1');
  assert.deepEqual(roots, {
    managedRoot,
    objects: join(managedRoot, 'objects'),
    config: join(managedRoot, 'config'),
    credentials: join(managedRoot, 'credentials'),
    builds: join(managedRoot, 'builds'),
  });
  assert.equal(Object.isFrozen(roots), true);
  assert.throws(() => deriveManagedInstallationRoots('relative/data'), { code: 'INVALID_INSTALLATION_CONFIG' });
});

test('authentication proofs use the exact closed transcript and reject accessors before hashing', () => {
  const secret = Buffer.alloc(32, 0x5a);
  assert.equal(
    createAuthenticationProof(secret, 'shared-server-proof-v1', authenticationTranscript()),
    'bd0f39f3f8ae8c2d15bf06d85789a831f5be0d15b4432e5f34e6116e7157b89e',
  );
  assert.notEqual(
    createAuthenticationProof(secret, 'shared-server-proof-v1', authenticationTranscript()),
    createAuthenticationProof(secret, 'shared-binding-proof-v1', authenticationTranscript()),
  );
  assert.notEqual(
    createAuthenticationProof(secret, 'shared-server-proof-v1', authenticationTranscript()),
    createAuthenticationProof(secret, 'shared-server-proof-v1', authenticationTranscript({ nonceS: DIGESTS.source })),
  );
  assert.throws(
    () => createAuthenticationProof(secret, 'shared-source-v1', authenticationTranscript()),
    TypeError,
  );

  let reads = 0;
  const hostile = authenticationTranscript();
  Object.defineProperty(hostile, 'bindingId', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error('AUTH-ACCESSOR-SENTINEL');
    },
  });
  assert.throws(() => createAuthenticationProof(secret, 'shared-server-proof-v1', hostile), TypeError);
  assert.equal(reads, 0);
});

test('free-ineligible policy stays free-ineligible and never gains fallback authority', async () => {
  const input = buildInstallationConfig();
  input.projects[0].freeEligible = false;
  for (const binding of input.bindings) binding.domains[0].freeEligible = false;
  const policy = await resolveCallerPolicy({
    config: validateInstallationConfig(input),
    bindingId: 'binding-a',
    credentialDigest: DIGESTS.credentialA,
    sourceKind: 'path',
    sourcePath: allowedPath,
    identityDigest,
  });
  assert.equal(policy.freeEligible, false);
  assert.equal(policy.projectId, 'project-alpha');
  assert.equal(Object.hasOwn(policy, 'paidFallback'), false);
});
