import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { getReviewer } from '../src/review-core/reviewer-registry.mjs';

const START = Date.parse('2026-09-19T00:00:00.000Z');
const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });

function passBody(provider = 'xAI', findings = [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }], cost = 0.02, content) {
  return { provider, choices: [{ finish_reason: 'stop', message: { content: content ?? JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost } };
}

function response(body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

function nonFiniteCostResponse() {
  // JSON.stringify(Infinity) emits null, so preserve the provider's raw JSON 1e999 token.
  const bodyJson = JSON.stringify(passBody()).replace('"cost":0.02', '"cost":1e999');
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(bodyJson, 'utf8').toString('base64') }),
  });
}

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

function deriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8').digest('hex');
}

async function ledgerBytes(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const names = (await readdir(ledgerRoot)).filter((name) => name.endsWith('.json')).sort();
  return Promise.all(names.map(async (name) => [name, await readFile(join(ledgerRoot, name), 'utf8')]));
}

async function withFixture(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-captured-result-'));
  let now = START;
  const clock = () => now;
  const realLeaseStore = createLeaseStore({ dataRoot, clock });
  const realResultStore = createResultStore({ dataRoot });
  const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
  const preflightContextStore = createPreflightContextStore({ dataRoot });
  const scrubMappingStore = createScrubMappingStore({ dataRoot });
  const ownerHandles = new Set();

  async function writeCapture(jobId, outcome) {
    const path = dispatchOutcomePath({ dataRoot, jobId });
    await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
    await writeFile(path, JSON.stringify(outcome), 'utf8');
  }

  async function makeEngine({ failResultWrites = false, dispatch, wrapLeaseStore, wrapDispatchOutcomeStore, wrapScrubMappingStore, wrapScrubEngine, ownerIsFalse = false } = {}) {
    const ownerLock = realLeaseStore.createUnarmedOwnerHandle();
    ownerHandles.add(ownerLock);
    const mutations = { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 };
    const countedLeaseStore = {
      ...realLeaseStore,
      async consume(...args) { mutations.consume += 1; return realLeaseStore.consume(...args); },
      async reconcile(...args) { mutations.reconcile += 1; return realLeaseStore.reconcile(...args); },
      async close(...args) { mutations.close += 1; return realLeaseStore.close(...args); },
    };
    const leaseStore = wrapLeaseStore ? wrapLeaseStore(countedLeaseStore, mutations) : countedLeaseStore;
    const resultStore = {
      ...realResultStore,
      async record(args) {
        mutations.resultRecord += 1;
        if (typeof failResultWrites === 'function' ? failResultWrites() : failResultWrites) throw new Error('synthetic result persistence failure');
        return realResultStore.record(args);
      },
    };
    const engineOwnerLock = ownerIsFalse ? {
      get acquisitionId() { return ownerLock.acquisitionId; },
      isOwner() { return false; },
      arm(...args) { return ownerLock.arm(...args); },
      release(...args) { return ownerLock.release(...args); },
    } : ownerLock;
    const dispatchAdapter = dispatch ?? {
      async dispatch() { throw new Error('unexpected dispatch'); },
    };
    const engine = createReviewEngine({
      leaseStore,
      ownerLock: engineOwnerLock,
      approvalAdapter: { async authorize() { return { outcome: 'APPROVED', nonce: 'synthetic' }; } },
      dispatchAdapter: { async dispatch(request) { mutations.dispatch += 1; return dispatchAdapter.dispatch(request); } },
      resultStore,
      preflightContextStore,
      dispatchOutcomeStore: wrapDispatchOutcomeStore ? wrapDispatchOutcomeStore(dispatchOutcomeStore) : dispatchOutcomeStore,
      scrubEngine: wrapScrubEngine ? wrapScrubEngine(createScrubEngine({ identityList: [], ollamaClient: passingOllama() })) : createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
      scrubMappingStore: wrapScrubMappingStore ? wrapScrubMappingStore(scrubMappingStore) : scrubMappingStore,
      clock,
      sourcePolicy,
      preflightPolicy,
      preflightTtlMs: 10 * 60 * 1000,
      installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: { async judge() { throw new Error('unexpected repeat authorization'); } },
      dispatchHealthStore: { async recordOutcome() { mutations.health += 1; return { shouldAlert: false }; }, async markAlerted() {} },
      alertStore: { async record() { mutations.alert += 1; }, async list() { return []; } },
    });
    return { engine, ownerLock, mutations, resultStore };
  }

  async function seedReconciled({ sourceText = 'recovery synthetic source', profile = 'final_verification_v1', changeKinds = [], reviewerId, costUsd = 0.02, costKind = 'KNOWN', haltReason, capture, omitReviewerId = false, skipCapture = false } = {}) {
    const seed = await makeEngine();
    const preflight = await seed.engine.preflight({ source_text: sourceText, profile, ...(profile === 'final_verification_v1' ? { changeKinds } : {}), reviewContext: 'recovery fixture' });
    const chosenReviewerId = reviewerId ?? 'grok';
    const authorization = await seed.engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: preflight.reviewers.length });
    await seed.ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const jobId = deriveJobId(authorization.leaseId, chosenReviewerId, preflight.reviewContractSha256);
    const item = preflight.itemMaxima.find((entry) => entry.itemId === `item-${chosenReviewerId}`);
    await realLeaseStore.consume(authorization.leaseId, preflight.reviewContractSha256, {
      reservationUsd: item.maxUsd,
      jobId,
      ...(omitReviewerId ? {} : { reviewerId: chosenReviewerId }),
      acquisitionId: seed.ownerLock.acquisitionId,
    });
    await realLeaseStore.reconcile(jobId, { costUsd, costKind, ...(haltReason === undefined ? {} : { haltReason }), acquisitionId: seed.ownerLock.acquisitionId });
    const expectedProvider = getReviewer(chosenReviewerId).expectedProvider;
    if (!skipCapture) await writeCapture(jobId, capture ?? response(passBody(expectedProvider, undefined, costUsd)));
    await seed.ownerLock.release({ final: false });
    return { leaseId: authorization.leaseId, preflight, jobId, item, reviewerId: chosenReviewerId, seed };
  }

  try {
    await run({ dataRoot, realLeaseStore, realResultStore, dispatchOutcomeStore, scrubMappingStore, makeEngine, seedReconciled, writeCapture, advance: (milliseconds) => { now += milliseconds; } });
  } finally {
    await Promise.all([...ownerHandles].map((handle) => handle.release({ final: true }).catch(() => {})));
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('result reconstructs a valid reconciled capture after a real result write failure without mutating the ledger', async () => {
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, writeCapture }) => {
    let capturedJobId;
    const writer = await makeEngine({
      failResultWrites: true,
      dispatch: {
        async dispatch(request) {
          capturedJobId = request.jobId;
          await writeCapture(request.jobId, response(passBody()));
          return response(passBody());
        },
      },
    });
    const preflight = await writer.engine.preflight({ source_text: 'recovery real write failure', profile: 'final_verification_v1', changeKinds: [], reviewContext: 'recovery fixture' });
    const authorization = await writer.engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 1 });
    const live = await writer.engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: 'recovery real write failure' });
    assert.equal(live.state, 'PASSED');
    assert.equal(await realResultStore.recall({ jobId: capturedJobId }), null, 'precondition: the real persistence write failed');
    const before = await ledgerBytes(dataRoot);

    const reader = await makeEngine();
    assert.equal(reader.ownerLock.state, 'unarmed');
    const recovered = await reader.engine.result({ leaseId: authorization.leaseId });
    const observations = {
      advisory: recovered.reviewers.grok.advisory,
      costUsd: recovered.reviewers.grok.costUsd,
      costKind: recovered.reviewers.grok.costKind,
      ledgerUnchanged: JSON.stringify(await ledgerBytes(dataRoot)) === JSON.stringify(before),
      mutations: reader.mutations,
      persisted: await realResultStore.recall({ jobId: capturedJobId }),
    };
    assert.deepEqual(observations, {
      advisory: { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] },
      costUsd: 0.02,
      costKind: 'KNOWN',
      ledgerUnchanged: true,
      mutations: { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 },
      persisted: null,
    });
  });
});

// A response billed above its reservation is recorded at its real cost and flagged. Its content
// must stay recoverable from the durable capture exactly like any KNOWN job.
test('result reconstructs an above-reservation capture after a real result write failure', async () => {
  await withFixture(async ({ realLeaseStore, realResultStore, makeEngine, writeCapture }) => {
    let capturedJobId;
    const writer = await makeEngine({
      failResultWrites: true,
      dispatch: {
        async dispatch(request) {
          capturedJobId = request.jobId;
          await writeCapture(request.jobId, response(passBody('xAI', undefined, 4.25)));
          return response(passBody('xAI', undefined, 4.25));
        },
      },
    });
    const preflight = await writer.engine.preflight({ source_text: 'recovery above reservation', profile: 'final_verification_v1', changeKinds: [], reviewContext: 'recovery fixture' });
    assert.equal(preflight.itemMaxima[0].maxUsd < 4.25, true, 'precedent: the billed cost is above the reservation');
    const authorization = await writer.engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 1 });
    const live = await writer.engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: 'recovery above reservation' });
    assert.equal(live.state, 'PASSED');
    assert.equal(writer.mutations.alert, 1);
    assert.equal((await realLeaseStore.getJob(capturedJobId)).aboveReservation, true);
    assert.equal(await realResultStore.recall({ jobId: capturedJobId }), null, 'precondition: the real persistence write failed');

    const reader = await makeEngine();
    const recovered = await reader.engine.result({ leaseId: authorization.leaseId });
    assert.deepEqual(
      { costUsd: recovered.reviewers.grok.costUsd, costKind: recovered.reviewers.grok.costKind, verdict: recovered.reviewers.grok.advisory?.verdict },
      { costUsd: 4.25, costKind: 'KNOWN', verdict: 'pass' },
    );
  });
});

test('repeated and concurrent unarmed result readers reconstruct the same reconciled capture without persistence', async () => {
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const before = await ledgerBytes(dataRoot);
    const readerA = await makeEngine();
    const readerB = await makeEngine();
    const [first, second, third] = await Promise.all([
      readerA.engine.result({ leaseId: seeded.leaseId }),
      readerA.engine.result({ leaseId: seeded.leaseId }),
      readerB.engine.result({ leaseId: seeded.leaseId }),
    ]);
    const advisories = [first, second, third].map((value) => value.reviewers.grok.advisory);
    assert.deepEqual(advisories, [advisories[0], advisories[0], advisories[0]]);
    assert.deepEqual(advisories[0], { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(readerA.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
    assert.deepEqual(readerB.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('result reconstructs a valid zero-cost legacy reviewerId-absent capture after restart', async () => {
  await withFixture(async ({ realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled({ costUsd: 0, omitReviewerId: true, capture: response(passBody('xAI', undefined, 0)) });
    const reader = await makeEngine();
    const recovered = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(recovered.reviewers.grok.costUsd, 0);
    assert.equal(recovered.reviewers.grok.costKind, 'KNOWN');
    assert.deepEqual(recovered.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('result refuses malformed, provider-mismatched, and halted reconciled captures without side effects', async () => {
  const cases = [
    ['malformed', { kind: 'RESPONSE', envelopeJsonText: '{not json' }],
    ['wrong provider', response({ ...passBody(), provider: 'Not-xAI' })],
  ];
  for (const [label, capture] of cases) {
    await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
      const seeded = await seedReconciled({ capture });
      const before = await ledgerBytes(dataRoot);
      const reader = await makeEngine();
      const recovered = await reader.engine.result({ leaseId: seeded.leaseId });
      assert.equal(recovered.reviewers.grok.advisory, undefined, `${label} capture must not be promoted to content`);
      assert.equal(recovered.reviewers.grok.costUsd, 0.02);
      assert.equal(recovered.reviewers.grok.costKind, 'KNOWN');
      assert.deepEqual(await ledgerBytes(dataRoot), before);
      assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
      assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
    });
  }
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled({ haltReason: 'PROVIDER_MISMATCH' });
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine();
    const recovered = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(recovered.reviewers.grok.advisory, undefined);
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('same-lease review materializes a reconciled capture once without redispatching or repaying', async () => {
  await withFixture(async ({ realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const worker = await makeEngine();
    const result = await worker.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: 'recovery synthetic source' });
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.equal(worker.mutations.dispatch, 0);
    assert.equal(worker.mutations.consume, 0);
    assert.equal(worker.mutations.reconcile, 0);
    assert.ok(await realResultStore.recall({ jobId: seeded.jobId }));
  });
});

test('refusal nonfinite captured cost encoded as JSON 1e999 leaves the reconciled result status-only', async () => {
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled({ capture: nonFiniteCostResponse() });
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.reviewers.grok.advisory, undefined);
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('refusal captured cost above the job reservation bound leaves the reconciled result status-only', async () => {
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine({ wrapLeaseStore: (real) => ({
      ...real,
      async getJob(jobId) {
        const job = await real.getJob(jobId);
        return job && { ...job, reservationUsd: 0.01 };
      },
    }) });
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.reviewers.grok.advisory, undefined);
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('refusal captured cost above the selected preflight item bound leaves the reconciled result status-only', async () => {
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine({ wrapLeaseStore: (real) => ({
      ...real,
      async getPreflight(preflightId) {
        const preflight = await real.getPreflight(preflightId);
        return preflight && {
          ...preflight,
          itemMaxima: preflight.itemMaxima.map((item) => item.itemId === 'item-grok' ? { ...item, maxUsd: 0.01 } : item),
        };
      },
    }) });
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.reviewers.grok.advisory, undefined);
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

for (const [name, options] of [
  ['absent capture', { skipCapture: true }],
  ['DISPATCHING capture', { capture: { kind: 'DISPATCHING' } }],
  ['FAILURE capture', { capture: { kind: 'FAILURE', envelopeJsonText: JSON.stringify({ failureKind: 'TIMEOUT' }) } }],
  ['malformed outer capture', { capture: '{invalid outer json' }],
  ['malformed envelope', { capture: { kind: 'RESPONSE', envelopeJsonText: '{invalid envelope' } }],
  ['non-json body', { capture: { kind: 'RESPONSE', envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from('not json', 'utf8').toString('base64') }) } }],
  ['missing cost', { capture: response({ ...passBody(), usage: {} }) }],
  ['negative cost', { capture: response(passBody('xAI', undefined, -0.01)) }],
  ['over-bound cost', { capture: response(passBody('xAI', undefined, 1)) }],
  ['mismatched settled cost', { capture: response(passBody('xAI', undefined, 0.01)) }],
  ['strict-invalid content', { capture: response({ ...passBody(), choices: [{ finish_reason: 'stop', message: { content: '{"verdict":"pass","findings":"not-an-array"}' } }] }) }],
  ['non-KNOWN ledger job', { costKind: 'UNKNOWN_WORST_CASE_CHARGED' }],
]) {
  test(`refusal ${name} leaves a reconciled ledger result status-only and side-effect free`, async () => {
    await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
      const seeded = await seedReconciled(options);
      const reader = await makeEngine();
      const before = await ledgerBytes(dataRoot);
      const result = await reader.engine.result({ leaseId: seeded.leaseId });
      assert.equal(result.reviewers.grok.advisory, undefined);
      assert.deepEqual(await ledgerBytes(dataRoot), before);
      assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
      assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
    });
  });
}

test('result reconstructs an expired reconciled capture without ledger mutation', async () => {
  await withFixture(async ({ dataRoot, realLeaseStore, makeEngine, seedReconciled, advance }) => {
    const seeded = await seedReconciled();
    const lease = await realLeaseStore.getLease(seeded.leaseId);
    advance(Date.parse(lease.expiresAt) - START + 1);
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.state, 'ACTIVE');
    assert.equal(result.reviewers.grok.advisory.verdict, 'pass');
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal((await realLeaseStore.getJob(seeded.jobId)).state, 'RECONCILED');
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('prompted_json fenced capture is reconstructed through the selected reviewer contract', async () => {
  await withFixture(async ({ makeEngine, seedReconciled }) => {
    const fenced = '```json\n{"verdict":"pass","findings":[]}\n```';
    const seeded = await seedReconciled({
      profile: 'free_tier_experimental_nemotron_lightning_only_v1',
      reviewerId: 'nemotron_lightning',
      costUsd: 0,
      capture: response(passBody('Nvidia', [], 0, fenced)),
    });
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.deepEqual(result.reviewers.nemotron_lightning.advisory, { verdict: 'pass', findings: [] });
    assert.equal(result.reviewers.nemotron_lightning.model, 'nvidia/nemotron-3.5-lightning:free');
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('cross-lease review reuses a prior captured result without a new job or charge', async () => {
  await withFixture(async ({ realResultStore, makeEngine, seedReconciled }) => {
    const prior = await seedReconciled({ sourceText: 'recovery cross lease source' });
    const worker = await makeEngine();
    const nextPreflight = await worker.engine.preflight({ source_text: 'recovery cross lease source', profile: 'final_verification_v1', changeKinds: [], reviewContext: 'recovery fixture' });
    const nextAuthorization = await worker.engine.authorizeWorkflow({ preflightId: nextPreflight.preflightId, maxJobs: 1 });
    const result = await worker.engine.review({ leaseId: nextAuthorization.leaseId, preflightId: nextPreflight.preflightId, source_text: 'recovery cross lease source' });
    assert.equal(result.reviewers.grok.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.equal(worker.mutations.dispatch, 0);
    assert.equal(worker.mutations.consume, 0);
    assert.equal(worker.mutations.reconcile, 0);
    assert.ok(await realResultStore.recall({ jobId: prior.jobId }));
  });
});

test('cross-lease recovery restores a captured placeholder with the originating preflight mapping', async () => {
  await withFixture(async ({ realResultStore, scrubMappingStore, makeEngine, seedReconciled }) => {
    const sourceText = 'recovery same public source for mapping restoration';
    const placeholder = 'TOKEN_recovery_original';
    const prior = await seedReconciled({
      sourceText,
      capture: response(passBody('xAI', [{ severity: 'minor', section: 'recovery', root_cause: placeholder, affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }])),
    });
    await scrubMappingStore.record({ preflightId: prior.preflight.preflightId, mapping: { [placeholder]: 'original secret value' } });

    const worker = await makeEngine();
    const nextPreflight = await worker.engine.preflight({ source_text: sourceText, profile: 'final_verification_v1', changeKinds: [], reviewContext: 'recovery fixture' });
    await scrubMappingStore.record({ preflightId: nextPreflight.preflightId, mapping: { [placeholder]: 'different target value' } });
    const nextAuthorization = await worker.engine.authorizeWorkflow({ preflightId: nextPreflight.preflightId, maxJobs: 1 });
    const result = await worker.engine.review({ leaseId: nextAuthorization.leaseId, preflightId: nextPreflight.preflightId, source_text: sourceText });
    assert.equal(result.reviewers.grok.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.equal(result.reviewers.grok.advisory.findings[0].root_cause, 'original secret value');
    assert.equal((await realResultStore.recall({ jobId: prior.jobId })).advisory.findings[0].root_cause, 'original secret value');
    assert.equal(worker.mutations.dispatch, 0);
    assert.equal(worker.mutations.consume, 0);
    assert.equal(worker.mutations.reconcile, 0);
  });
});

test('result reconstructs a valid captured advisory from a closed reconciled lease without writes', async () => {
  await withFixture(async ({ dataRoot, realLeaseStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    await seeded.seed.ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    await realLeaseStore.close(seeded.leaseId, 'PROVIDER_MISMATCH', { acquisitionId: seeded.seed.ownerLock.acquisitionId });
    await seeded.seed.ownerLock.release({ final: false });
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.state, 'PROVIDER_MISMATCH');
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('binding valid-control has a real reconciled job, lease, preflight, item, schema, and registry pin', async () => {
  await withFixture(async ({ dataRoot, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const before = await ledgerBytes(dataRoot);
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.deepEqual(await ledgerBytes(dataRoot), before);
  });
});

for (const [name, wrapLeaseStore] of [
  ['missing job', (real) => ({ ...real, async getJob() { return null; }, async findJobsForReviewerContract() { return []; } })],
  ['wrong job id', (real) => ({ ...real, async getJob(id) { const job = await real.getJob(id); return job && { ...job, id: '0'.repeat(64) }; } })],
  ['wrong job reviewerId', (real) => ({ ...real, async getJob(id) { const job = await real.getJob(id); return job && { ...job, reviewerId: 'gemini' }; } })],
  ['wrong job contract hash', (real) => ({ ...real, async getJob(id) { const job = await real.getJob(id); return job && { ...job, reviewContractSha256: '0'.repeat(64) }; } })],
  ['missing originating lease', (() => { let reads = 0; return (real) => ({ ...real, async getLease(id) { reads += 1; return reads === 1 ? real.getLease(id) : null; } }); })()],
  ['missing preflight', (real) => ({ ...real, async getPreflight() { return null; } })],
  ['missing selected item', (real) => ({ ...real, async getPreflight(id) { const preflight = await real.getPreflight(id); return preflight && { ...preflight, itemMaxima: [] }; } })],
  ['schema pin mismatch', (real) => ({ ...real, async getPreflight(id) { const preflight = await real.getPreflight(id); return preflight && { ...preflight, schemaSha256: '0'.repeat(64) }; } })],
  ['registry pin mismatch', (real) => ({ ...real, async getPreflight(id) { const preflight = await real.getPreflight(id); return preflight && { ...preflight, registrySha256: '0'.repeat(64) }; } })],
]) {
  test(`binding refusal ${name} does not promote a captured advisory or mutate state`, async () => {
    await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
      const seeded = await seedReconciled();
      const before = await ledgerBytes(dataRoot);
      const reader = await makeEngine({ wrapLeaseStore });
      const result = await reader.engine.result({ leaseId: seeded.leaseId });
      assert.equal(result.reviewers.grok?.advisory, undefined);
      assert.deepEqual(await ledgerBytes(dataRoot), before);
      assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
      assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
    });
  });
}

for (const [name, options] of [
  ['capture read failure', { wrapDispatchOutcomeStore: (real) => ({ ...real, async recall() { throw new Error('synthetic capture read failure'); } }) }],
  ['mapping read failure', { wrapScrubMappingStore: (real) => ({ ...real, async recall() { throw new Error('synthetic mapping read failure'); } }) }],
]) {
  test(`I/O refusal ${name} returns status-only without billing or persistence`, async () => {
    await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
      const seeded = await seedReconciled();
      const reader = await makeEngine(options);
      const before = await ledgerBytes(dataRoot);
      const result = await reader.engine.result({ leaseId: seeded.leaseId });
      assert.equal(result.reviewers.grok?.advisory, undefined);
      assert.deepEqual(await ledgerBytes(dataRoot), before);
      assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
      assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
    });
  });
}

test('ledger busy during result remains surfaced as LEDGER_BUSY rather than a missing advisory', async () => {
  await withFixture(async ({ makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const reader = await makeEngine({ wrapLeaseStore: (real) => ({ ...real, async getLease() { const error = new Error('LEDGER_DATA_ROOT_LOCKED'); error.code = 'LEDGER_DATA_ROOT_LOCKED'; throw error; } }) });
    await assert.rejects(() => reader.engine.result({ leaseId: seeded.leaseId }), (error) => error.code === 'LEDGER_BUSY');
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('armed recovery retries persistence after a failed write without a second billing mutation', async () => {
  await withFixture(async ({ realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const failing = await makeEngine({ failResultWrites: true });
    const first = await failing.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: 'recovery synthetic source' });
    assert.deepEqual(first.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.equal(failing.mutations.consume, 0);
    assert.equal(failing.mutations.reconcile, 0);
    const retry = await makeEngine();
    const second = await retry.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: 'recovery synthetic source' });
    assert.deepEqual(second.reviewers.grok.advisory, first.reviewers.grok.advisory);
    assert.ok(await realResultStore.recall({ jobId: seeded.jobId }));
    assert.equal(retry.mutations.consume, 0);
    assert.equal(retry.mutations.reconcile, 0);
  });
});

test('loss of live ownership skips result persistence while returning a reconstructed advisory', async () => {
  await withFixture(async ({ realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const worker = await makeEngine({ ownerIsFalse: true });
    const result = await worker.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: 'recovery synthetic source' });
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.equal(worker.mutations.resultRecord, 0);
    assert.equal(worker.mutations.consume, 0);
    assert.equal(worker.mutations.reconcile, 0);
  });
});

test('reverse-substitution failure refuses a captured advisory without billing or persistence', async () => {
  await withFixture(async ({ dataRoot, realResultStore, makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const reader = await makeEngine({ wrapScrubEngine: (real) => ({ ...real, async desubstitute() { throw new Error('synthetic desubstitution failure'); } }) });
    const before = await ledgerBytes(dataRoot);
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.reviewers.grok?.advisory, undefined);
    assert.deepEqual(await ledgerBytes(dataRoot), before);
    assert.equal(await realResultStore.recall({ jobId: seeded.jobId }), null);
    assert.deepEqual(reader.mutations, { dispatch: 0, consume: 0, reconcile: 0, close: 0, resultRecord: 0, health: 0, alert: 0 });
  });
});

test('same live recovery engine retries a previously failed result write instead of trusting its transient cache', async () => {
  await withFixture(async ({ realResultStore, makeEngine, writeCapture }) => {
    const writeFailure = { enabled: true };
    const worker = await makeEngine({ failResultWrites: () => writeFailure.enabled, dispatch: { async dispatch(request) { await writeCapture(request.jobId, response(passBody())); return response(passBody()); } } });
    const preflight = await worker.engine.preflight({ source_text: 'recovery live cache source', profile: 'final_verification_v1', changeKinds: [], reviewContext: 'recovery fixture' });
    const authorization = await worker.engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 1 });
    const jobId = deriveJobId(authorization.leaseId, 'grok', preflight.reviewContractSha256);
    const first = await worker.engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: 'recovery live cache source' });
    assert.deepEqual(first.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.equal(await realResultStore.recall({ jobId }), null);
    const mutationsBeforeRetry = { ...worker.mutations };
    writeFailure.enabled = false;
    const second = await worker.engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: 'recovery live cache source' });
    assert.deepEqual(second.reviewers.grok.advisory, first.reviewers.grok.advisory);
    assert.ok(await realResultStore.recall({ jobId }));
    assert.equal(worker.mutations.dispatch, mutationsBeforeRetry.dispatch);
    assert.equal(worker.mutations.consume, mutationsBeforeRetry.consume);
    assert.equal(worker.mutations.reconcile, mutationsBeforeRetry.reconcile);
    assert.equal(worker.mutations.close, mutationsBeforeRetry.close);
    assert.ok(worker.mutations.resultRecord > mutationsBeforeRetry.resultRecord);
  });
});

test('ownerless transient reconstruction is never cached after its capture disappears', async () => {
  await withFixture(async ({ makeEngine, seedReconciled, writeCapture }) => {
    const seeded = await seedReconciled();
    const reader = await makeEngine();
    const first = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.deepEqual(first.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    await writeCapture(seeded.jobId, { kind: 'DISPATCHING' });
    const second = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(second.reviewers.grok.advisory, undefined);
  });
});

test('simultaneous armed same-lease recovery calls agree without reserving, reconciling, or charging again', async () => {
  await withFixture(async ({ makeEngine, seedReconciled }) => {
    const seeded = await seedReconciled();
    const worker = await makeEngine();
    const [first, second] = await Promise.all([
      worker.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: 'recovery synthetic source' }),
      worker.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: 'recovery synthetic source' }),
    ]);
    assert.deepEqual(first.reviewers.grok.advisory, { verdict: 'pass', findings: [{ severity: 'minor', section: 'recovery', root_cause: 'x', affected_behavior: 'y', consequence: 'z', evidence: ['synthetic'] }] });
    assert.deepEqual(second.reviewers.grok.advisory, first.reviewers.grok.advisory);
    assert.equal(worker.mutations.consume, 0);
    assert.equal(worker.mutations.reconcile, 0);
  });
});
