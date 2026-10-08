import { resolve } from 'node:path';

export const DIGESTS = Object.freeze({
  source: '1111111111111111111111111111111111111111111111111111111111111111',
  context: '2222222222222222222222222222222222222222222222222222222222222222',
  mapping: '3333333333333333333333333333333333333333333333333333333333333333',
  classifier: '4444444444444444444444444444444444444444444444444444444444444444',
  identityList: '5555555555555555555555555555555555555555555555555555555555555555',
  scope: '6666666666666666666666666666666666666666666666666666666666666666',
  credentialA: '7777777777777777777777777777777777777777777777777777777777777777',
  credentialB: '8888888888888888888888888888888888888888888888888888888888888888',
  request: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  reviewContract: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  registry: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  schema: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  file: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  node: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  manifest: 'b4a2f11ea1be24d1d1e01f54f780850f45229e49ef319c5c1a3c37648c4eea27',
});

export const IDS = Object.freeze({
  receipt: ['1'.repeat(8),'1111','4111','8111','1'.repeat(12)].join('-'),
  lease: ['2'.repeat(8),'2222','4222','8222','2'.repeat(12)].join('-'),
  preflight: ['3'.repeat(8),'3333','4333','8333','3'.repeat(12)].join('-'),
  envelope: ['4'.repeat(8),'4444','4444','8444','4'.repeat(12)].join('-'),
  request: ['5'.repeat(8),'5555','4555','8555','5'.repeat(12)].join('-'),
  terminal: ['6'.repeat(8),'6666','4666','8666','6'.repeat(12)].join('-'),
});

export const EFFECTIVE_DEADLINE = '2026-09-19T18:00:00.000Z';
export const ACCEPTED_AT = '2026-09-19T17:00:00.000Z';
export const EXPECTED_EXECUTION_FINGERPRINT = '92e85453f784d1fcfe3fcc036e971a5baee6ae7980708412ffafdc89165b09a2';

export function clone(value) {
  return structuredClone(value);
}

export function buildManifest(overrides = {}) {
  return {
    version: 'shared-review-build-v1',
    protocolVersion: 'shared-review-pipe-v1',
    storageVersion: 'shared-review-storage-v1',
    node: { version: 'v22.0.0', sha256: DIGESTS.node },
    files: [{ path: 'src/main.mjs', sha256: DIGESTS.file, bytes: 123 }],
    ...clone(overrides),
  };
}

export function buildInstallationConfig(overrides = {}) {
  const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
  const base = {
    version: 'shared-review-installation-v1',
    protocolVersion: 'shared-review-pipe-v1',
    storageVersion: 'shared-review-storage-v1',
    dataRoot: resolve('tests/fixtures/shared/data'),
    buildManifestSha256: DIGESTS.manifest,
    engine: {
      installationHardMaximumUsd: 5,
      dailyPaidJobAllowance: 20,
      autonomousAuthorization: false,
      maxSourceBytes: 2_000_000,
      maxRequestBytes: 4_194_304,
      dispatchTimeoutMs: 600_000,
      preflightTtlMs: 1_800_000,
      orphanSweepGraceMs: 120_000,
      healthVerdictGraceMs: 360_000,
      healthVerdictBackstopMs: 3_600_000,
      armTimeoutMs: 90_000,
      armLockRetryMs: 250,
      shutdownDrainTimeoutMs: 30_000,
      ollamaBaseUrl: 'http://localhost:11434',
      ollamaModel: 'qwen2.5:7b',
      ollamaTimeoutMs: 300_000,
      identityListDigest: DIGESTS.identityList,
      classifierContractDigest: DIGESTS.classifier,
      // The explicit "no extra protected terms" setting. Tests that need terms use invented ones.
      extraProtectedTerms: { sourceSha256: null, markers: [], contextTerms: [] },
      spendAlertThresholdFraction: 0.75,
      consecutiveDispatchFailureAlertThreshold: 3,
      keyStatusProbeTimeoutMs: 20_000,
      approvalAdapterVersion: 'local-human-approval-v1',
      dispatchAdapterVersion: 'shared-review-dispatch-v1',
      healthAdapterVersion: 'local-dispatch-health-v1',
      alertAdapterVersion: 'local-alert-store-v1',
      alertAdapterReference: 'alerts-local-v1',
    },
    review: {
      registrySha256: DIGESTS.registry,
      advisorySchemaSha256: DIGESTS.schema,
      promptVersion: 'prompt-v1',
      profileCatalogDigest: '9999999999999999999999999999999999999999999999999999999999999999',
      allowedProfiles: [{
        profileId: 'final_verification_v1',
        profileVersion: '1',
        allowedReviewerSets: [['grok'], ['grok', 'gemini']],
      }],
    },
    queue: {
      maxActiveBatches: 5,
      maxWaitingCallerRequests: 10,
      maxUnfinishedCount: 15,
      maxActiveReviewerDispatches: 15,
      maxUnfinishedEncryptedBytes: 209_715_200,
      maxUnstartedWaitMs: 1_800_000,
      maxReceiptMetadataBytes: 16_384,
      maxIdempotencyKeysPerLease: 64,
    },
    storage: {
      maxLivePreflights: 30,
      maxPreflightEncryptedBytes: 209_715_200,
      maxSinglePreflightPlaintextBytes: 67_108_864,
    },
    transport: {
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
    },
    // Synthetic project IDs only. The free-tier list is installation configuration, never code.
    freeTierProjectIds: ['project-alpha'],
    projects: [{
      projectId: 'project-alpha',
      policyEpoch: 1,
      canonicalRoots: [allowedRoot],
      freeEligible: true,
    }],
    bindings: [
      {
        bindingId: 'binding-a',
        enabled: true,
        credentialVersion: 'credential-v1',
        credentialDigest: DIGESTS.credentialA,
        legacyRecovery: false,
        domains: [{ projectId: 'project-alpha', allowedRoots: [allowedRoot], freeEligible: true }],
        defaultInlineProjectId: 'project-alpha',
      },
      {
        bindingId: 'binding-b',
        enabled: true,
        credentialVersion: 'credential-v2',
        credentialDigest: DIGESTS.credentialB,
        legacyRecovery: false,
        domains: [{ projectId: 'project-alpha', allowedRoots: [allowedRoot], freeEligible: true }],
        defaultInlineProjectId: 'project-alpha',
      },
    ],
    protectedReferences: {
      identityKeyVersion: 'identity-v1',
      identityKeyReference: 'identity-key-local-v1',
      identityListReference: 'identity-list-local-v1',
      installationCredentialReference: 'installation-credential-local-v1',
      bindingCredentialStoreReference: 'binding-credentials-local-v1',
    },
  };
  return Object.assign(base, clone(overrides));
}

export function buildFingerprintFields(overrides = {}) {
  const base = {
    protocolVersion: 'shared-review-pipe-v1',
    storageVersion: 'shared-review-storage-v1',
    buildManifestSha256: DIGESTS.manifest,
    reviewContractSha256: DIGESTS.reviewContract,
    registrySha256: DIGESTS.registry,
    advisorySchemaSha256: DIGESTS.schema,
    promptVersion: 'prompt-v1',
    profile: {
      profileId: 'final_verification_v1',
      profileVersion: '1',
      orderedReviewerIds: ['grok'],
    },
    reviewers: [{
      reviewerId: 'grok',
      model: 'x-ai/grok-4.6',
      route: 'xai/zdr',
      expectedProvider: 'xAI',
      outputMode: 'strict_json',
      requestControls: {
        reasoning: { effort: 'high' },
        temperature: 0,
        maxTokens: 32_768,
        stream: false,
        provider: {
          zdr: true,
          dataCollection: 'deny',
          requireParameters: true,
          allowFallbacks: false,
        },
        priceCeiling: {
          promptUsdPerMillionTokens: 2,
          completionUsdPerMillionTokens: 6,
        },
      },
      requestBodyDigest: DIGESTS.request,
    }],
    snapshotSourceId: DIGESTS.source,
    snapshotContextId: DIGESTS.context,
    mappingIdentity: DIGESTS.mapping,
    classifierContractDigest: DIGESTS.classifier,
    identityListDigest: DIGESTS.identityList,
    policy: { scopeDigest: DIGESTS.scope, policyEpoch: 1, projectId: 'project-alpha' },
  };
  return Object.assign(base, clone(overrides));
}

export function buildPreparedEnvelope(overrides = {}) {
  const base = {
    version: 'shared-review-prepared-v1',
    leaseId: IDS.lease,
    preflightId: IDS.preflight,
    scopeDigest: DIGESTS.scope,
    policyEpoch: 1,
    projectId: 'project-alpha',
    executionFingerprint: EXPECTED_EXECUTION_FINGERPRINT,
    acceptedBindingCredentialIdentity: DIGESTS.credentialA,
    fingerprintFields: buildFingerprintFields(),
    requestRefs: [{
      reviewerId: 'grok',
      requestRef: { objectId: IDS.request, sha256: DIGESTS.file, encryptedBytes: 4_096 },
      requestBodyDigest: DIGESTS.request,
    }],
    mappingPin: { preflightId: IDS.preflight, mappingIdentity: DIGESTS.mapping },
    effectiveDeadline: EFFECTIVE_DEADLINE,
  };
  return Object.assign(base, clone(overrides));
}

export function buildReceipt(overrides = {}) {
  const base = {
    recordType: 'shared/receipt',
    version: 1,
    receiptId: IDS.receipt,
    revision: 1,
    leaseId: IDS.lease,
    preflightId: IDS.preflight,
    bindingId: 'binding-a',
    projectId: 'project-alpha',
    policyEpoch: 1,
    scopeDigest: DIGESTS.scope,
    keyDigest: 'abababababababababababababababababababababababababababababababab',
    inputDigest: 'bc'.repeat(32),
    executionFingerprint: EXPECTED_EXECUTION_FINGERPRINT,
    snapshotSourceId: DIGESTS.source,
    snapshotContextId: DIGESTS.context,
    reviewContractSha256: DIGESTS.reviewContract,
    preparedPayload: {
      envelopeRef: { objectId: IDS.envelope, sha256: DIGESTS.mapping, encryptedBytes: 2_048 },
      requestRefs: [{ objectId: IDS.request, sha256: DIGESTS.file, encryptedBytes: 4_096 }],
    },
    mappingPins: [{ preflightId: IDS.preflight, mappingIdentity: DIGESTS.mapping }],
    reviewerIds: ['grok'],
    acceptedAt: ACCEPTED_AT,
    effectiveDeadline: EFFECTIVE_DEADLINE,
    state: 'QUEUED',
  };
  return Object.assign(base, clone(overrides));
}

export function authenticationTranscript(overrides = {}) {
  return {
    pipeIdentity: 'pipe-1',
    instanceId: IDS.receipt,
    nonceC: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    nonceS: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    protocolVersion: 'shared-review-pipe-v1',
    configFingerprint: DIGESTS.reviewContract,
    buildManifestSha256: DIGESTS.registry,
    bindingId: 'binding-a',
    credentialVersion: 'credential-v1',
    ...clone(overrides),
  };
}
