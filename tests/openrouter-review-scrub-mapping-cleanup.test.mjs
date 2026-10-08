import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
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
const findings = Object.freeze([{ severity: 'minor', section: 'mapping', root_cause: 'synthetic', affected_behavior: 'mapping cleanup', consequence: 'retention boundary', evidence: ['synthetic'] }]);

function deriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8').digest('hex');
}

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

function responseFor(reviewerId, costUsd = 0.02, responseFindings = findings) {
  return {
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({
      httpStatus: 200,
      bodyBase64: Buffer.from(JSON.stringify({
        provider: getReviewer(reviewerId).expectedProvider,
        choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: responseFindings }) } }],
        usage: { cost: costUsd },
      }), 'utf8').toString('base64'),
    }),
  };
}

function durableEntry({ jobId, reviewerId, costUsd = 0.02, ...overrides }) {
  return {
    reviewerId,
    jobId,
    state: 'RECONCILED',
    costUsd,
    costKind: 'KNOWN',
    provider: getReviewer(reviewerId).expectedProvider,
    model: getReviewer(reviewerId).model,
    advisory: { verdict: 'pass', findings },
    ...overrides,
  };
}

async function withFixture(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-scrub-mapping-cleanup-'));
  const realLeaseStore = createLeaseStore({ dataRoot, clock: () => START });
  const realResultStore = createResultStore({ dataRoot });
  const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
  const preflightContextStore = createPreflightContextStore({ dataRoot });
  const scrubMappingStore = createScrubMappingStore({ dataRoot });
  const owners = new Set();

  async function writeCapture(jobId, outcome) {
    await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
    await writeFile(dispatchOutcomePath({ dataRoot, jobId }), JSON.stringify(outcome), 'utf8');
  }

  async function makeEngine({ wrapLeaseStore, wrapResultStore, wrapScrubMappingStore } = {}) {
    const ownerLock = realLeaseStore.createUnarmedOwnerHandle();
    owners.add(ownerLock);
    const resultStore = wrapResultStore ? wrapResultStore(realResultStore) : realResultStore;
    const mappingStore = wrapScrubMappingStore ? wrapScrubMappingStore(scrubMappingStore) : scrubMappingStore;
    const engine = createReviewEngine({
      leaseStore: wrapLeaseStore ? wrapLeaseStore(realLeaseStore) : realLeaseStore,
      ownerLock,
      approvalAdapter: { async authorize() { return { outcome: 'APPROVED', nonce: 'synthetic' }; } },
      dispatchAdapter: { async dispatch() { throw new Error('unexpected dispatch'); } },
      resultStore,
      preflightContextStore,
      dispatchOutcomeStore,
      scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
      scrubMappingStore: mappingStore,
      clock: () => START,
      sourcePolicy,
      preflightPolicy,
      preflightTtlMs: 10 * 60 * 1000,
      installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: { async judge() { throw new Error('unexpected repeat authorization'); } },
      dispatchHealthStore: { async recordOutcome() { throw new Error('unexpected health write'); }, async markAlerted() {} },
      alertStore: { async record() { throw new Error('unexpected alert'); }, async list() { return []; } },
    });
    return { engine, ownerLock };
  }

  async function seedLease({ profile = 'final_verification_v1', sourceText = 'mapping cleanup source', settlementByReviewer = {}, maximumJobs } = {}) {
    const seed = await makeEngine();
    const preflight = await seed.engine.preflight({
      source_text: sourceText,
      profile,
      ...(profile === 'consequential_spec_v1' ? {} : { changeKinds: [] }),
      reviewContext: 'mapping cleanup fixture',
    });
    const authorization = await seed.engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: maximumJobs ?? preflight.reviewers.length });
    await scrubMappingStore.record({ preflightId: preflight.preflightId, mapping: { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' } });
    await seed.ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    try {
      for (const [reviewerId, settlement] of Object.entries(settlementByReviewer)) {
        const item = preflight.itemMaxima.find((candidate) => candidate.itemId === `item-${reviewerId}`);
        assert.ok(item, `fixture reviewer ${reviewerId} is selected by ${profile}`);
        const jobId = deriveJobId(authorization.leaseId, reviewerId, preflight.reviewContractSha256);
        await realLeaseStore.consume(authorization.leaseId, preflight.reviewContractSha256, {
          reservationUsd: item.maxUsd,
          jobId,
          reviewerId,
          acquisitionId: seed.ownerLock.acquisitionId,
        });
        if (settlement.state === 'RESERVED') continue;
        const costUsd = settlement.costUsd ?? 0.02;
        await realLeaseStore.reconcile(jobId, {
          costUsd,
          costKind: settlement.costKind ?? 'KNOWN',
          ...(settlement.haltReason === undefined ? {} : { haltReason: settlement.haltReason }),
          acquisitionId: seed.ownerLock.acquisitionId,
        });
        if (settlement.capture !== false) await writeCapture(jobId, settlement.capture ?? responseFor(reviewerId, costUsd));
        if (settlement.durable) await realResultStore.record({ jobId, advisory: durableEntry({ jobId, reviewerId, costUsd, ...settlement.durable }) });
      }
    } finally {
      await seed.ownerLock.release({ final: false });
    }
    return { leaseId: authorization.leaseId, preflight, reviewerIds: preflight.reviewers.map((reviewer) => reviewer.id) };
  }

  try {
    await run({ dataRoot, realLeaseStore, realResultStore, scrubMappingStore, makeEngine, seedLease });
  } finally {
    await Promise.all([...owners].map((owner) => owner.release({ final: true }).catch(() => {})));
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('mapping cleanup retains a mixed selected review whose clean capture is still transient', async () => {
  await withFixture(async ({ realResultStore, scrubMappingStore, makeEngine, seedLease }) => {
    const seeded = await seedLease({
      profile: 'consequential_spec_v1',
      settlementByReviewer: {
        gemini: { durable: {} },
        grok: {},
      },
    });
    const geminiJobId = deriveJobId(seeded.leaseId, 'gemini', seeded.preflight.reviewContractSha256);
    const grokJobId = deriveJobId(seeded.leaseId, 'grok', seeded.preflight.reviewContractSha256);
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    const observations = {
      durableGemini: await realResultStore.recall({ jobId: geminiJobId }),
      transientGrok: await realResultStore.recall({ jobId: grokJobId }),
      mapping: await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }),
      grokRecovered: result.reviewers.grok.advisory?.verdict,
    };
    assert.equal(observations.durableGemini?.advisory?.verdict, 'pass');
    assert.equal(observations.transientGrok, null);
    assert.deepEqual(observations.mapping, { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' });
    assert.equal(observations.grokRecovered, 'pass');
  });
});

test('mapping cleanup requires a valid durable advisory for every clean KNOWN result', async () => {
  const malformed = [
    ['missing result', undefined],
    ['wrong job binding', { jobId: '0'.repeat(64) }],
    ['wrong reviewer binding', { reviewerId: 'gemini' }],
    ['wrong settled cost', { costUsd: 0.01 }],
    ['wrong cost kind', { costKind: 'ZERO_ON_TRANSPORT_FAILURE' }],
    ['wrong state', { state: 'RESERVED' }],
    ['error-bearing entry', { error: { code: 'STRICT_OUTPUT_INVALID' } }],
    ['malformed advisory schema', { advisory: { verdict: 'pass', findings: 'not-an-array' } }],
  ];
  for (const [label, durable] of malformed) {
    await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
      const seeded = await seedLease({ settlementByReviewer: { grok: { capture: false, ...(durable === undefined ? {} : { durable }) } } });
      const reader = await makeEngine();
      await reader.engine.result({ leaseId: seeded.leaseId });
      assert.deepEqual(await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }), { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' }, label);
    });
  }
  await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
    const seeded = await seedLease({ settlementByReviewer: { grok: { capture: false, durable: {} } } });
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    assert.equal(result.reviewers.grok.advisory.verdict, 'pass');
    assert.equal(await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }), null);
  });
});

test('mapping cleanup retains a mapping for an unrecognized or malformed terminal cost kind', async () => {
  for (const [label, costKind] of [
    ['unrecognized terminal kind', 'UNKNOWN_SYNTHETIC_TERMINAL'],
    ['missing terminal kind', undefined],
  ]) {
    await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
      const seeded = await seedLease({ settlementByReviewer: { grok: { capture: false } } });
      const jobId = deriveJobId(seeded.leaseId, 'grok', seeded.preflight.reviewContractSha256);
      const reader = await makeEngine({
        wrapLeaseStore(real) {
          return {
            ...real,
            async getJob(requestedJobId) {
              const job = await real.getJob(requestedJobId);
              return requestedJobId === jobId ? { ...job, costKind } : job;
            },
          };
        },
      });
      await reader.engine.result({ leaseId: seeded.leaseId });
      assert.deepEqual(await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }), { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' }, label);
    });
  }
});

test('mapping cleanup releases mappings for a recorded halt and a recognized non-KNOWN terminal result', async () => {
  for (const [label, settlement] of [
    ['recorded halt', { haltReason: 'PROVIDER_MISMATCH', capture: false }],
    ['unknown worst-case terminal', { costKind: 'UNKNOWN_WORST_CASE_CHARGED', capture: false }],
    ['proven transport-zero terminal', { costKind: 'ZERO_ON_TRANSPORT_FAILURE', costUsd: 0, capture: false }],
    ['proven provider-rejection-zero terminal', { costKind: 'ZERO_ON_PROVIDER_REJECTION', costUsd: 0, capture: false }],
  ]) {
    await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
      const seeded = await seedLease({ settlementByReviewer: { grok: settlement } });
      const reader = await makeEngine();
      await reader.engine.result({ leaseId: seeded.leaseId });
      assert.equal(await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }), null, label);
    });
  }
});

test('mapping cleanup retains a clean durable result when its preflight identity or contract binding is malformed', async () => {
  for (const [label, corrupt] of [
    ['wrong preflight identity', (preflight) => ({ ...preflight, id: 'wrong-preflight-id' })],
    ['wrong preflight contract', (preflight) => ({ ...preflight, reviewContractSha256: '0'.repeat(64) })],
  ]) {
    await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
      const seeded = await seedLease({ settlementByReviewer: { grok: { capture: false, durable: {} } } });
      const reader = await makeEngine({
        wrapLeaseStore(real) {
          return {
            ...real,
            async getPreflight(preflightId) {
              const preflight = await real.getPreflight(preflightId);
              return preflightId === seeded.preflight.preflightId ? corrupt(preflight) : preflight;
            },
          };
        },
      });
      const result = await reader.engine.result({ leaseId: seeded.leaseId });
      assert.equal(result.reviewers.grok.advisory?.verdict, 'pass', `${label}: valid durable content remains readable`);
      assert.deepEqual(await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }), { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' }, label);
    });
  }
});

test('mapping cleanup retains mappings while a selected job is RESERVED or never dispatched', async () => {
  for (const [label, settlementByReviewer] of [
    ['RESERVED', { grok: { state: 'RESERVED' } }],
    ['NOT_DISPATCHED', {}],
  ]) {
    await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
      const seeded = await seedLease({ settlementByReviewer });
      const reader = await makeEngine();
      await reader.engine.result({ leaseId: seeded.leaseId });
      assert.deepEqual(await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }), { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' }, label);
    });
  }
});

test('result() prefers a concurrently durable restored advisory after its first result-store miss deletes the mapping', async () => {
  await withFixture(async ({ realResultStore, scrubMappingStore, makeEngine, seedLease }) => {
    const capturedPlaceholderFindings = [{ ...findings[0], root_cause: 'captured SYNTHETIC_PLACEHOLDER placeholder' }];
    const seeded = await seedLease({ settlementByReviewer: { grok: { capture: responseFor('grok', 0.02, capturedPlaceholderFindings) } } });
    const jobId = deriveJobId(seeded.leaseId, 'grok', seeded.preflight.reviewContractSha256);
    const writerEntry = durableEntry({
      jobId,
      reviewerId: 'grok',
      advisory: { verdict: 'pass', findings: [{ ...findings[0], root_cause: 'writer durable restored value' }] },
    });
    let firstMissObserved = false;
    let writerRan = false;
    const reader = await makeEngine({
      wrapResultStore(real) {
        return {
          ...real,
          async recall(args) {
            if (args.jobId !== jobId) return real.recall(args);
            if (!firstMissObserved) {
              firstMissObserved = true;
              return null;
            }
            return real.recall(args);
          },
        };
      },
      wrapScrubMappingStore(real) {
        return {
          ...real,
          async recall(args) {
            const snapshot = await real.recall(args);
            if (args.preflightId === seeded.preflight.preflightId && firstMissObserved && !writerRan) {
              writerRan = true;
              await realResultStore.record({ jobId, advisory: writerEntry });
              await real.deleteMapping({ preflightId: seeded.preflight.preflightId });
            }
            return snapshot;
          },
        };
      },
    });
    const result = await reader.engine.result({ leaseId: seeded.leaseId });
    const observations = {
      firstMissObserved,
      writerRan,
      durable: await realResultStore.recall({ jobId }),
      mapping: await scrubMappingStore.recall({ preflightId: seeded.preflight.preflightId }),
      returned: result.reviewers.grok,
    };
    assert.equal(observations.firstMissObserved, true);
    assert.equal(observations.writerRan, true);
    assert.deepEqual(observations.durable, writerEntry);
    assert.equal(observations.mapping, null);
    assert.deepEqual(observations.returned, writerEntry);
  });
});

test('transient cross-lease reuse retains both mappings until the originating result is durable', async () => {
  await withFixture(async ({ scrubMappingStore, makeEngine, seedLease }) => {
    const source = await seedLease({ sourceText: 'cross-lease cleanup source', settlementByReviewer: { grok: {} } });
    const next = await seedLease({ sourceText: 'cross-lease cleanup source', settlementByReviewer: {} });
    const reader = await makeEngine();
    const result = await reader.engine.result({ leaseId: next.leaseId });
    const observations = {
      costKind: result.reviewers.grok.costKind,
      advisory: result.reviewers.grok.advisory?.verdict,
      sourceMapping: await scrubMappingStore.recall({ preflightId: source.preflight.preflightId }),
      nextMapping: await scrubMappingStore.recall({ preflightId: next.preflight.preflightId }),
    };
    assert.equal(observations.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.equal(observations.advisory, 'pass');
    assert.deepEqual(observations.sourceMapping, { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' });
    assert.deepEqual(observations.nextMapping, { SYNTHETIC_PLACEHOLDER: 'restored placeholder value' });
  });
});
