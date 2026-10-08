import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { REVIEW_OUTPUT_SCHEMA, formatToolResult } from '../src/local-mcp/mcp-schemas.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { USD } from './helpers/scanner-safe-fixtures.mjs';

// Re-running authorize_workflow against the same preflightId -- the documented recovery step
// after a LEASE_CAP_EXCEEDED halt from an under-sized maxJobs -- mints a genuinely NEW lease.
// review()'s own per-lease jobId (deriveJobId(leaseId, reviewerId, reviewContractSha256), private
// to review-engine.mjs) is scoped to ONE lease by construction, so a per-lease existingJob check
// never sees a reviewer already RECONCILED under a DIFFERENT lease for the exact same document;
// without a cross-lease lookup, that reviewer would be redispatched and charged again. These
// tests pin down the cross-lease check: review() consults
// leaseStore.findJobsForReviewerContract(reviewContractSha256, reviewerId) for every reviewer this
// LEASE has never itself touched, before ever reserving or dispatching -- reusing a genuinely
// successful prior result for free, and refusing to race a still-ambiguous in-flight one.

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const START = Date.parse('2026-08-29T01:00:00.000Z');

function geminiPassBody(findings = [{
  severity: 'minor', section: 'x', root_cause: 'y', affected_behavior: 'z', consequence: 'w', evidence: ['e'],
}]) {
  return { provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.01 } };
}

function grokPassBody(findings = []) {
  return { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.02 } };
}

function toResponse(body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

function deriveReviewJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256')
    .update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8')
    .digest('hex');
}

async function writeCapturedResponse(dataRoot, jobId, response) {
  const outcomePath = dispatchOutcomePath({ dataRoot, jobId });
  await mkdir(dirname(outcomePath), { recursive: true });
  await writeFile(outcomePath, JSON.stringify(response), 'utf8');
}

function failureEnvelope(failureKind, message) {
  return Object.freeze({ kind: 'FAILURE', envelopeJsonText: JSON.stringify({ failureKind, message }) });
}

function providerMismatchBody() {
  return { provider: 'NotGoogle', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.01 } };
}

/**
 * A dispatch fake that records every call and serves a response by reviewer ID (not queue order,
 * since these tests deliberately call review() more than once against the SAME engine, and a
 * plain FIFO queue would desync across those calls). `responsesByReviewer` maps reviewerId ->
 * either a fixed body or a function(callIndexForThisReviewer) -> body, so a test can vary what a
 * reviewer returns across repeated calls when it needs to (most don't).
 */
function createDispatchFake(responsesByReviewer) {
  const calls = [];
  const callIndexByReviewer = new Map();
  return {
    calls,
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId, jobId: request.jobId });
      const index = callIndexByReviewer.get(request.reviewerId) ?? 0;
      callIndexByReviewer.set(request.reviewerId, index + 1);
      const entry = responsesByReviewer[request.reviewerId];
      const body = typeof entry === 'function' ? entry(index) : entry;
      return toResponse(body);
    },
  };
}

const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

async function withEngine(run, { dispatch } = {}) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-cross-lease-'));
  let now = START;
  const clock = () => now;
  const leaseStore = createLeaseStore({ dataRoot, clock });
  // A REAL ownerLock, since this leaseStore is real.
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const resultStore = createResultStore({ dataRoot });
  const preflightContextStore = createPreflightContextStore({ dataRoot });
  const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
  const scrubEngine = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
  const scrubMappingStore = createScrubMappingStore({ dataRoot });
  const approvalAdapter = { async authorize() { return { outcome: 'APPROVED', nonce: 'fake-nonce' }; } };
  const engine = createReviewEngine({
    leaseStore,
    ownerLock,
    approvalAdapter,
    dispatchAdapter: dispatch,
    resultStore,
    preflightContextStore,
    dispatchOutcomeStore,
    scrubEngine,
    scrubMappingStore,
    clock,
    sourcePolicy,
    preflightPolicy,
    preflightTtlMs: 10 * 60 * 1000,
    installationHardMaximumUsd: 10,
    repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
  });
  try {
    await run({ engine, leaseStore, ownerLock, dataRoot, advance: (ms) => { now += ms; } });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function preflightAndAuthorize(engine, { maxJobs, source_text = 'the same document', reviewContext = 'cross-lease dedup scope' } = {}) {
  const preflight = await engine.preflight({ source_text, profile: 'consequential_spec_v1', reviewContext });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs });
  return { preflight, leaseId: authorization.leaseId, preflightId: preflight.preflightId };
}

/**
 * A real post-reconcile/pre-result-write crash state from an older ledger: its
 * job intentionally has no reviewerId, but its canonical job id still binds it
 * to Gemini. The query fallback and the legacy-capture reconstruction path must both use
 * that binding; no test-side substitute hands reviewer identity to production.
 */
async function seedLegacyCapturedGemini({ engine, leaseStore, ownerLock, dataRoot, costUsd = 0.01, capture = toResponse(geminiPassBody()) }) {
  const leaseA = await preflightAndAuthorize(engine, { maxJobs: 2 });
  await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
  const reservationUsd = leaseA.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
  const jobId = deriveReviewJobId(leaseA.leaseId, 'gemini', leaseA.preflight.reviewContractSha256);
  const job = await leaseStore.consume(leaseA.leaseId, leaseA.preflight.reviewContractSha256, {
    reservationUsd,
    jobId,
    // Deliberately absent: this is the legacy condition the store query must
    // recover from deterministic durable identity rather than a stored field.
    acquisitionId: ownerLock.acquisitionId,
  });
  await leaseStore.reconcile(job.id, { costUsd, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });
  if (capture !== null) await writeCapturedResponse(dataRoot, job.id, capture);
  return { leaseA, job, reservationUsd };
}

test('cross-lease reuse reconstructs a valid reviewerless legacy capture and durably heals it without a second Gemini charge', async () => {
  const dispatched = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
  const capturedBody = geminiPassBody();
  const expectedAdvisory = JSON.parse(capturedBody.choices[0].message.content);
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot }) => {
    const prior = await seedLegacyCapturedGemini({
      engine, leaseStore, ownerLock, dataRoot, capture: toResponse(capturedBody),
    });
    const priorBefore = await leaseStore.getLease(prior.leaseA.leaseId);
    const priorJobBefore = await leaseStore.getJob(prior.job.id);
    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });

    const result = await engine.review({
      leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document',
    });
    const priorAfter = await leaseStore.getLease(prior.leaseA.leaseId);
    const priorJobAfter = await leaseStore.getJob(prior.job.id);
    const leaseBAfter = await leaseStore.getLease(leaseB.leaseId);
    const geminiOnLeaseB = await leaseStore.getJob(
      deriveReviewJobId(leaseB.leaseId, 'gemini', leaseB.preflight.reviewContractSha256),
    );
    const durablePrior = await createResultStore({ dataRoot }).recall({ jobId: prior.job.id });

    // All post-review observations precede assertions so the test reports a
    // duplicate dispatch/charge even if reconstructed content is wrong.
    assert.deepEqual({
      priorBefore: { spentUsd: priorBefore.spentUsd, costUsd: priorJobBefore.costUsd },
      priorAfter: { spentUsd: priorAfter.spentUsd, costUsd: priorJobAfter.costUsd },
      leaseB: { spentUsd: leaseBAfter.spentUsd, reservedUsd: leaseBAfter.reservedUsd },
      dispatched: dispatched.calls.map((call) => call.reviewerId),
      geminiOnLeaseB,
      result: {
        state: result.state,
        gemini: result.reviewers.gemini,
        grok: { state: result.reviewers.grok.state, costKind: result.reviewers.grok.costKind },
      },
      durableAdvisory: durablePrior?.advisory,
    }, {
      priorBefore: { spentUsd: 0.01, costUsd: 0.01 },
      priorAfter: { spentUsd: 0.01, costUsd: 0.01 },
      leaseB: { spentUsd: 0.02, reservedUsd: 0 },
      dispatched: ['grok'],
      geminiOnLeaseB: null,
      result: {
        state: 'PASSED',
        gemini: {
          reviewerId: 'gemini',
          jobId: prior.job.id,
          state: 'RECONCILED',
          costUsd: 0.01,
          costKind: 'REUSED_FROM_PRIOR_LEASE',
          provider: 'Google',
          model: 'google/gemini-3.8-flash',
          advisory: expectedAdvisory,
        },
        grok: { state: 'RECONCILED', costKind: 'KNOWN' },
      },
      durableAdvisory: expectedAdvisory,
    });
  }, { dispatch: dispatched });
});

test('malformed or missing reviewerless legacy captures halt CONTENT_LOST without a replacement Gemini dispatch', async () => {
  const cases = [
    ['missing capture', null],
    ['malformed capture', { kind: 'RESPONSE', envelopeJsonText: '{not-json' }],
  ];
  for (const [label, capture] of cases) {
    const dispatched = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
    // eslint-disable-next-line no-await-in-loop
    await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot }) => {
      const prior = await seedLegacyCapturedGemini({ engine, leaseStore, ownerLock, dataRoot, capture });
      const priorBefore = await leaseStore.getLease(prior.leaseA.leaseId);
      const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
      const result = await engine.review({
        leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document',
      });
      const priorAfter = await leaseStore.getLease(prior.leaseA.leaseId);
      const leaseBAfter = await leaseStore.getLease(leaseB.leaseId);
      const geminiOnLeaseB = await leaseStore.getJob(
        deriveReviewJobId(leaseB.leaseId, 'gemini', leaseB.preflight.reviewContractSha256),
      );
      const durablePrior = await createResultStore({ dataRoot }).recall({ jobId: prior.job.id });

      assert.deepEqual({
        priorBefore: priorBefore.spentUsd,
        priorAfter: priorAfter.spentUsd,
        leaseB: { spentUsd: leaseBAfter.spentUsd, reservedUsd: leaseBAfter.reservedUsd },
        dispatched: dispatched.calls.map((call) => call.reviewerId),
        geminiOnLeaseB,
        result: {
          state: result.state,
          error: result.error?.code,
          gemini: { state: result.reviewers.gemini.state, error: result.reviewers.gemini.error?.code },
          grok: { state: result.reviewers.grok.state, costKind: result.reviewers.grok.costKind },
        },
        durablePrior,
      }, {
        priorBefore: 0.01,
        priorAfter: 0.01,
        leaseB: { spentUsd: 0.02, reservedUsd: 0 },
        dispatched: ['grok'],
        geminiOnLeaseB: null,
        result: {
          state: 'HALTED',
          error: 'CONTENT_LOST',
          gemini: { state: 'RECONCILED', error: 'CONTENT_LOST' },
          grok: { state: 'RECONCILED', costKind: 'KNOWN' },
        },
        durablePrior: null,
      }, label);
    }, { dispatch: dispatched });
  }
});

test('a reviewerless KNOWN zero-cost legacy job without content still blocks a replacement Gemini dispatch', async () => {
  const dispatched = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot }) => {
    const prior = await seedLegacyCapturedGemini({
      engine, leaseStore, ownerLock, dataRoot, costUsd: 0, capture: null,
    });
    const priorBefore = await leaseStore.getLease(prior.leaseA.leaseId);
    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const result = await engine.review({
      leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document',
    });
    const priorAfter = await leaseStore.getLease(prior.leaseA.leaseId);
    const leaseBAfter = await leaseStore.getLease(leaseB.leaseId);
    const geminiOnLeaseB = await leaseStore.getJob(
      deriveReviewJobId(leaseB.leaseId, 'gemini', leaseB.preflight.reviewContractSha256),
    );
    const durablePrior = await createResultStore({ dataRoot }).recall({ jobId: prior.job.id });

    assert.deepEqual({
      priorBefore: priorBefore.spentUsd,
      priorAfter: priorAfter.spentUsd,
      leaseB: { spentUsd: leaseBAfter.spentUsd, reservedUsd: leaseBAfter.reservedUsd },
      dispatched: dispatched.calls.map((call) => call.reviewerId),
      geminiOnLeaseB,
      result: {
        state: result.state,
        error: result.error?.code,
        gemini: { state: result.reviewers.gemini.state, error: result.reviewers.gemini.error?.code },
        grok: { state: result.reviewers.grok.state, costKind: result.reviewers.grok.costKind },
      },
      durablePrior,
    }, {
      priorBefore: 0,
      priorAfter: 0,
      leaseB: { spentUsd: 0.02, reservedUsd: 0 },
      dispatched: ['grok'],
      geminiOnLeaseB: null,
      result: {
        state: 'HALTED',
        error: 'CONTENT_LOST',
        gemini: { state: 'RECONCILED', error: 'CONTENT_LOST' },
        grok: { state: 'RECONCILED', costKind: 'KNOWN' },
      },
      durablePrior: null,
    });
  }, { dispatch: dispatched });
});

test('a re-authorized lease for the same document reuses an already-RECONCILED reviewer for free instead of re-dispatching and re-charging it', async () => {
  const dispatch = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    // Lease A: maxJobs=1 deliberately under-sized (the caller mistake that makes a
    // re-authorization necessary) -- Gemini dispatches and RECONCILEs for real, then Grok's
    // consume() hits the job cap and the whole review() call REJECTS. Gemini's reconciliation is
    // already durably committed to the ledger by that point regardless of the later rejection.
    const preflight = await engine.preflight({ source_text: 'the same document', profile: 'consequential_spec_v1', reviewContext: 'cross-lease dedup scope' });
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const historicalLease = await leaseStore.createLease({
      preflightIds: [preflight.preflightId],
      requestedUsd: preflight.requestedUsd,
      maxJobs: 1,
      expiresAt: preflight.expiresAt,
      acquisitionId: ownerLock.acquisitionId,
    });
    const leaseA = { preflight, preflightId: preflight.preflightId, leaseId: historicalLease.id };
    await assert.rejects(
      () => engine.review({ leaseId: leaseA.leaseId, preflightId: leaseA.preflightId, source_text: 'the same document' }),
      (error) => error.code === 'LEASE_CAP_EXCEEDED',
    );
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini']);
    const leaseAAfter = await leaseStore.getLease(leaseA.leaseId);
    assert.equal(Math.round(leaseAAfter.spentUsd * 100), 1, `gemini genuinely reconciled and spent ${USD}0.01 on lease A`);

    // Lease B: a fresh authorize_workflow against the SAME preflightId, corrected to maxJobs=2 --
    // the documented recovery step. Same source_text/reviewContext/profile, so the SAME
    // reviewContractSha256.
    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    assert.equal(leaseB.preflight.reviewContractSha256, leaseA.preflight.reviewContractSha256, 'both leases must share the identical contract for this test to actually exercise the dedup path');

    const result = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    assert.equal(result.state, 'PASSED');
    // Gemini must NEVER be dispatched a second time -- only grok, the one reviewer lease B
    // genuinely still needs.
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
    assert.equal(result.reviewers.gemini.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.equal(result.reviewers.gemini.costUsd, 0.01, 'the reused entry reports the REAL original cost, not a fabricated zero');
    assert.deepEqual(result.reviewers.gemini.advisory.findings.length, 1, 'reused content must be the genuine prior advisory, not a stub');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');

    // The whole point: lease B's own ledger spend must reflect ONLY grok's real dispatch -- gemini
    // was free.
    const leaseBAfter = await leaseStore.getLease(leaseB.leaseId);
    assert.equal(Math.round(leaseBAfter.spentUsd * 100), 2, `lease B must have spent only on grok (${USD}0.02), not a second gemini charge on top`);
  }, { dispatch });
});

// A reused reviewer never calls leaseStore.consume() on the CURRENT lease, so no job -- and no
// per-lease jobId -- ever exists for it under THAT lease. A result() recovery loop that derives its
// jobId only the same per-lease way review()'s dispatch loop does (deriveJobId(leaseId, reviewerId,
// lease.reviewContractSha256)) would find nothing under it and fall back to a false NOT_DISPATCHED
// stub -- silently discarding real, already-produced advisory content. This matters specifically
// because result()'s entire reason for existing (per its own docstring) is recovering a caller that
// lost its connection before seeing review()'s live response, which is a common case for this
// pipeline, not an edge case.
test('result() recovers a cross-lease-reused reviewer\'s real advisory content, not a false NOT_DISPATCHED', async () => {
  const dispatch = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const preflight = await engine.preflight({ source_text: 'the same document', profile: 'consequential_spec_v1', reviewContext: 'cross-lease dedup scope' });
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const historicalLease = await leaseStore.createLease({
      preflightIds: [preflight.preflightId],
      requestedUsd: preflight.requestedUsd,
      maxJobs: 1,
      expiresAt: preflight.expiresAt,
      acquisitionId: ownerLock.acquisitionId,
    });
    const leaseA = { preflight, preflightId: preflight.preflightId, leaseId: historicalLease.id };
    await assert.rejects(() => engine.review({ leaseId: leaseA.leaseId, preflightId: leaseA.preflightId, source_text: 'the same document' }));

    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const reviewResult = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });
    assert.equal(reviewResult.state, 'PASSED');
    assert.equal(reviewResult.reviewers.gemini.costKind, 'REUSED_FROM_PRIOR_LEASE');

    // result() needs nothing but leaseId -- simulating a caller that lost the connection before
    // ever seeing review()'s own live response above.
    const recovered = await engine.result({ leaseId: leaseB.leaseId });
    assert.equal(recovered.reviewers.gemini.state, 'RECONCILED', 'must recover the real reused result, not a false NOT_DISPATCHED stub');
    assert.equal(recovered.reviewers.gemini.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.deepEqual(recovered.reviewers.gemini.advisory.findings.length, 1, 'the real advisory content, not a stub with no findings');
    assert.equal(recovered.reviewers.grok.state, 'RECONCILED');
  }, { dispatch });
});

test('cross-lease reuse survives a process restart (fresh engine instance over the same on-disk ledger), recovering content via the durable resultStore, not just the in-process cache', async () => {
  const dispatch = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });

  // Built by hand (not the shared withEngine helper) so a SECOND, fully independent engine
  // instance can be constructed over the exact same dataRoot afterward -- withEngine mints its own
  // fresh tmp directory per call, which cannot simulate a restart against the same ledger.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-cross-lease-restart-'));
  try {
    let now = START;
    const clock = () => now;
    // buildEngine() constructs its own fresh leaseStore each call (simulating a genuine
    // restart -- see the comment below), so it must also acquire a REAL ownerLock against that
    // specific instance and return it alongside the engine, so the caller can explicitly release it
    // before the NEXT buildEngine() call acquires its own. Both leaseStore instances run in this
    // same test process, so a second acquireProcessOwnership() would otherwise contend forever
    // against a "live" owner (same real OS pid) if the first were never released.
    const buildEngine = async () => {
      const leaseStore = createLeaseStore({ dataRoot, clock });
      const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
      const engine = createReviewEngine({
        leaseStore,
        ownerLock,
        approvalAdapter: { async authorize() { return { outcome: 'APPROVED', nonce: 'fake-nonce' }; } },
        dispatchAdapter: dispatch,
        resultStore: createResultStore({ dataRoot }),
        preflightContextStore: createPreflightContextStore({ dataRoot }),
        dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
        scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
        scrubMappingStore: createScrubMappingStore({ dataRoot }),
        clock,
        sourcePolicy,
        preflightPolicy,
        preflightTtlMs: 10 * 60 * 1000,
        installationHardMaximumUsd: 10,
        repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
      });
      return { engine, ownerLock, leaseStore };
    };

    const { engine: engineA, ownerLock: ownerLockA, leaseStore: leaseStoreA } = await buildEngine();
    const preflight = await engineA.preflight({ source_text: 'the same document', profile: 'consequential_spec_v1', reviewContext: 'cross-lease dedup scope' });
    await ownerLockA.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const historicalLease = await leaseStoreA.createLease({
      preflightIds: [preflight.preflightId],
      requestedUsd: preflight.requestedUsd,
      maxJobs: 1,
      expiresAt: preflight.expiresAt,
      acquisitionId: ownerLockA.acquisitionId,
    });
    const leaseA = { preflight, preflightId: preflight.preflightId, leaseId: historicalLease.id };
    await assert.rejects(() => engineA.review({ leaseId: leaseA.leaseId, preflightId: leaseA.preflightId, source_text: 'the same document' }));
    await ownerLockA.release();

    // A brand-new engine instance -- its advisoryCache and preflightCache both start empty, so any
    // reuse below can ONLY come from the durable ledger + resultStore, never the in-process Map.
    const { engine: engineB } = await buildEngine();
    const leaseB = await preflightAndAuthorize(engineB, { maxJobs: 2 });
    const result = await engineB.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    assert.equal(result.state, 'PASSED');
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
    assert.equal(result.reviewers.gemini.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.deepEqual(result.reviewers.gemini.advisory.findings.length, 1);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a reviewer still RESERVED (ambiguous, in-flight) under a different lease for the same document blocks a fresh dispatch instead of racing it', async () => {
  const dispatch = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const leaseA = await preflightAndAuthorize(engine, { maxJobs: 2 });
    // Ownership is released once authorization completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    // Simulate lease A's gemini dispatch being genuinely in flight (reserved, not yet reconciled)
    // under a DIFFERENT lease -- e.g. a real, still-running dispatch this exact document's review()
    // call is racing against.
    await leaseStore.consume(leaseA.leaseId, leaseA.preflight.reviewContractSha256, {
      reservationUsd: leaseA.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd,
      jobId: 'in-flight-gemini-job',
      reviewerId: 'gemini',
      acquisitionId: ownerLock.acquisitionId,
    });

    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const result = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DUPLICATE_DISPATCH_IN_PROGRESS');
    const wireResult = formatToolResult(REVIEW_OUTPUT_SCHEMA.parse(result));
    assert.deepEqual(wireResult.structuredContent, result);
    assert.deepEqual(JSON.parse(wireResult.content[0].text), result);
    const invalidReviewerError = structuredClone(result);
    invalidReviewerError.reviewers.gemini = { reviewerId: 'gemini', jobId: 'synthetic-job', state: 'RESERVED', costUsd: 0, costKind: 'UNKNOWN_WORST_CASE_CHARGED' };
    assert.equal(REVIEW_OUTPUT_SCHEMA.safeParse(invalidReviewerError).success, true, 'negative fixture is otherwise valid');
    invalidReviewerError.reviewers.gemini.error = result.error;
    const rejected = REVIEW_OUTPUT_SCHEMA.safeParse(invalidReviewerError);
    assert.equal(rejected.success, false, 'batch-wide duplicate refusal must remain forbidden on an individual reviewer');
    assert.deepEqual(rejected.error.issues.map((issue) => issue.path), [['reviewers', 'gemini', 'error', 'code']]);
    assert.equal(dispatch.calls.length, 0, 'gemini must never be dispatched a second time while the first is still ambiguous, and grok must never be reached either');
    assert.equal(result.reviewers.gemini, undefined);

    const leaseBAfter = await leaseStore.getLease(leaseB.leaseId);
    assert.equal(leaseBAfter.state, 'DUPLICATE_DISPATCH_IN_PROGRESS');
    assert.equal(leaseBAfter.spentUsd, 0);
    assert.equal(leaseBAfter.reservedUsd, 0, 'lease B must never reserve money against an ambiguous dispatch it refused to make');
  }, { dispatch });
});

test('a prior job that reconciled via a HALT (no usable advisory content, e.g. PROVIDER_MISMATCH) does not block a later lease from genuinely retrying that reviewer', async () => {
  const dispatch = createDispatchFake({
    gemini: (callIndex) => (callIndex === 0 ? providerMismatchBody() : geminiPassBody()),
    grok: grokPassBody(),
  });
  await withEngine(async ({ engine, leaseStore }) => {
    const leaseA = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const resultA = await engine.review({ leaseId: leaseA.leaseId, preflightId: leaseA.preflightId, source_text: 'the same document' });
    assert.equal(resultA.state, 'HALTED');
    assert.equal(resultA.error.code, 'PROVIDER_MISMATCH');
    assert.equal((await leaseStore.getLease(leaseA.leaseId)).state, 'PROVIDER_MISMATCH');
    // Reviewers dispatch in parallel, so gemini's PROVIDER_MISMATCH does not cancel grok and
    // lease A dispatches both. grok passes with real content, which lease B then legitimately
    // reuses for free -- leaving gemini as the only reviewer lease B genuinely has to redispatch.
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);

    // A prior job reconciled at a KNOWN cost with real money already spent, but it produced no
    // usable advisory content (haltAndClose never calls resultStore.record()). Reusing it would
    // permanently prevent this reviewer from EVER completing successfully for this document --
    // worse than a duplicate charge. Lease B must genuinely redispatch gemini.
    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const resultB = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    assert.equal(resultB.state, 'PASSED');
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok', 'gemini'], 'gemini must be genuinely redispatched (a real second call) on lease B; grok is reused from lease A for free');
    assert.equal(resultB.reviewers.gemini.costKind, 'KNOWN');
    assert.notEqual(resultB.reviewers.gemini.costKind, 'REUSED_FROM_PRIOR_LEASE');
    assert.equal(resultB.reviewers.grok.costKind, 'REUSED_FROM_PRIOR_LEASE');
  }, { dispatch });
});

// A job that reconciles via processDispatchOutcome's clean-pass branch (leaseStore.reconcile() --
// real money, real KNOWN cost) but crashes before its content-recording step (resultStore.record()) ever runs is
// INDISTINGUISHABLE, by ledger state alone, from a genuine haltAndClose() halt like
// PROVIDER_MISMATCH -- both are RECONCILED/KNOWN/costUsd>0 with nothing recoverable. The
// PROVIDER_MISMATCH test above proves a genuine halt correctly ALLOWS a fresh cross-lease
// redispatch (haltReason now persisted on that job record); this test proves the opposite case --
// an unexplained content-loss landmine, with NO haltReason recorded -- correctly BLOCKS one, so a
// caller can never be silently double-charged for the same reviewer's work on the same document.
test('a prior job that reconciled with a KNOWN cost but NO haltReason and NO recoverable content (an unexplained content-loss landmine) blocks a fresh cross-lease dispatch instead of risking a duplicate paid call', async () => {
  const dispatch = createDispatchFake({ gemini: geminiPassBody(), grok: grokPassBody() });
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const leaseA = await preflightAndAuthorize(engine, { maxJobs: 2 });
    // Ownership is released once authorization completes; acquire the real handle for direct
    // fixture writes. Keep it armed so these tests exercise inline recovery, not an arm sweep.
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const geminiMaxUsd = leaseA.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;

    // Seeds the exact ledger shape a real crash between processDispatchOutcome's reconcile() and its
    // resultStore.record() would leave behind -- real money reconciled, no haltReason (this was
    // never a haltAndClose() halt), no advisory content anywhere. gemini is deliberately never
    // dispatched here (the fake would throw on a call it isn't primed for), simulating a PRIOR
    // review() call whose own dispatch genuinely happened and was genuinely paid for, outside this
    // test's own visibility. A real 64-hex-char jobId (not the default randomUUID()) -- resultStore
    // embeds jobId in a file path and validates its shape, and findReusableAdvisory's content lookup
    // is exactly the path that reaches it for a RECONCILED prior job.
    const geminiJobId = '1'.repeat(64);
    const geminiJob = await leaseStore.consume(leaseA.leaseId, leaseA.preflight.reviewContractSha256, {
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini', acquisitionId: ownerLock.acquisitionId,
    });
    await leaseStore.reconcile(geminiJob.id, { costUsd: geminiMaxUsd, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });

    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const result = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    // The whole point: gemini must NEVER be dispatched a second time for a landmine nothing can
    // prove is safe to retry -- only grok, which this lease genuinely needs, is ever dispatched.
    assert.deepEqual(dispatch.calls.map((call) => call.reviewerId), ['grok'], 'gemini must never be redispatched while its only prior cross-lease outcome is an unexplained content-loss landmine');
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'CONTENT_LOST');
    assert.equal(result.reviewers.gemini.error.code, 'CONTENT_LOST');
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
    assert.equal(Object.hasOwn(result.reviewers.gemini, 'advisory'), false, 'no advisory content exists to report -- that is exactly the ambiguity this test proves is now refused, not silently redispatched');
    // grok is untouched by gemini's own cross-lease landmine and dispatches/reconciles normally --
    // one reviewer's landmine must not block the whole batch.
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');

    // Lease B must never reserve or spend money against gemini -- it was blocked before any
    // consume() call on this lease, not charged and refunded after the fact.
    const leaseBAfter = await leaseStore.getLease(leaseB.leaseId);
    assert.equal(Math.round(leaseBAfter.spentUsd * 100), 2, 'lease B must have spent only on grok, never a second gemini reservation/charge');
  }, { dispatch });
});

// A DISPATCH_UNKNOWN halt (dispatchAdapter.dispatch() itself throwing, or a prior DISPATCHING
// marker's outcome never captured) is fundamentally DIFFERENT from PROVIDER_MISMATCH/
// STRICT_OUTPUT_INVALID/UNKNOWN_COST: those three mean a real response WAS received and inspected
// (safe to retry -- we KNOW no usable content resulted), while DISPATCH_UNKNOWN means the true
// outcome could never be determined AT ALL -- a real request may genuinely have gone out and been
// billed. haltAndClose() must NOT mark a DISPATCH_UNKNOWN halt as safe-to-retry the same way it
// marks the other three, or the cross-lease check would reopen the double-charge risk it exists to
// close, just through a different halt code. This test proves it end to end: a FRESH dispatch that
// throws (the real, most common way DISPATCH_UNKNOWN happens) must still block a later cross-lease
// retry, not silently redispatch and risk a genuine duplicate paid call.
test('a job that halted with an unverifiable DISPATCH_UNKNOWN outcome is treated as a landmine, not a safe-to-retry halt, on a later cross-lease attempt', async () => {
  const dispatch = createDispatchFake({
    gemini: (callIndex) => {
      if (callIndex === 0) throw new Error('simulated: dispatchAdapter.dispatch() itself threw, outcome unknown');
      return geminiPassBody();
    },
    grok: grokPassBody(),
  });
  await withEngine(async ({ engine, leaseStore }) => {
    const leaseA = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const resultA = await engine.review({ leaseId: leaseA.leaseId, preflightId: leaseA.preflightId, source_text: 'the same document' });
    assert.equal(resultA.state, 'HALTED');
    assert.equal(resultA.error.code, 'DISPATCH_UNKNOWN');
    const geminiJobA = await leaseStore.getJob(resultA.reviewers.gemini.jobId);
    assert.equal(geminiJobA.haltReason, undefined, 'DISPATCH_UNKNOWN must never be marked as a safe-to-retry halt -- the true outcome was never verified');

    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const resultB = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    // The whole point: gemini must be dispatched exactly ONCE total (lease A's own attempt) --
    // never a second time on lease B, which would be a real duplicate paid call -- exactly what
    // the cross-lease check exists to prevent.
    assert.equal(dispatch.calls.filter((call) => call.reviewerId === 'gemini').length, 1, 'gemini must never be redispatched while its only prior outcome is an unverifiable DISPATCH_UNKNOWN');
    assert.equal(resultB.reviewers.gemini.error.code, 'CONTENT_LOST');
    assert.equal(resultB.reviewers.grok.state, 'RECONCILED');
  }, { dispatch });
});

// Safety is keyed on `costKind`, not on the specific `code` string ('DISPATCH_UNKNOWN'):
// TRANSPORT_FAILURE's two non-zero-cost FailureKinds
// (RESPONSE_READ_FAILED, INTERNAL_ERROR -- see ZERO_COST_TRANSPORT_FAILURE_KINDS's own docstring in
// review-engine.mjs) share the EXACT same ambiguity as DISPATCH_UNKNOWN under a DIFFERENT top-level
// code. By the time RESPONSE_READ_FAILED fires, OpenRouter's own HTTP response was already received
// (status/headers), and since every reviewer request is non-streaming, the full generation was very
// likely already produced and billed server-side before the local body-read failure happened -- real
// content may exist that this process never captured. This must be treated as a landmine on a later
// cross-lease attempt too, never marked safe to retry, exactly like DISPATCH_UNKNOWN.
test('a TRANSPORT_FAILURE halt with a non-zero-cost FailureKind (RESPONSE_READ_FAILED) is treated as a landmine, not a safe-to-retry halt, on a later cross-lease attempt', async () => {
  const calls = [];
  const geminiCallCount = new Map();
  const dispatch = {
    calls,
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId, jobId: request.jobId });
      if (request.reviewerId === 'gemini') {
        const count = (geminiCallCount.get('gemini') ?? 0) + 1;
        geminiCallCount.set('gemini', count);
        if (count === 1) return failureEnvelope('RESPONSE_READ_FAILED', 'body read failed after a successful GetResponse()');
        return toResponse(geminiPassBody());
      }
      return toResponse(grokPassBody());
    },
  };
  await withEngine(async ({ engine, leaseStore }) => {
    const leaseA = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const resultA = await engine.review({ leaseId: leaseA.leaseId, preflightId: leaseA.preflightId, source_text: 'the same document' });
    assert.equal(resultA.state, 'HALTED');
    assert.equal(resultA.error.code, 'TRANSPORT_FAILURE');
    const geminiJobA = await leaseStore.getJob(resultA.reviewers.gemini.jobId);
    assert.equal(geminiJobA.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.ok(geminiJobA.costUsd > 0, `RESPONSE_READ_FAILED is one of the two FailureKinds that must stay worst-case-charged, never ${USD}0`);
    assert.equal(geminiJobA.haltReason, undefined, 'RESPONSE_READ_FAILED means the response may have already been generated and billed server-side -- it must never be marked safe to retry');

    const leaseB = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const resultB = await engine.review({ leaseId: leaseB.leaseId, preflightId: leaseB.preflightId, source_text: 'the same document' });

    assert.equal(calls.filter((call) => call.reviewerId === 'gemini').length, 1, 'gemini must never be redispatched while its only prior outcome is an unverifiable RESPONSE_READ_FAILED');
    assert.equal(resultB.reviewers.gemini.error.code, 'CONTENT_LOST');
    assert.equal(resultB.reviewers.grok.state, 'RECONCILED');
  }, { dispatch });
});
