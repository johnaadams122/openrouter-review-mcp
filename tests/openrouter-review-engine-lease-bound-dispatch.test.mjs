import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchOutcomeStore } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { REVIEW_OUTPUT_SCHEMA, formatToolResult } from '../src/local-mcp/mcp-schemas.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

// Money-safety property: src/local-mcp/lease-store.mjs's consume() re-checks
// lease expiry at reservation time, but reconcile() never does. So a
// reviewer whose job reserves successfully just before the lease's expiresAt
// could still have its actual paid dispatch run to completion well AFTER the
// lease's authorized window closes, with nothing catching it. These tests
// pin down the guard: review() passes the lease's FIXED absolute expiry
// (`lease.expiresAt`, as an epoch-ms `notAfterMs`) to every reviewer's
// dispatch call -- the same value every iteration, regardless of how much
// wall-clock time a prior reviewer consumed -- and halts cleanly (not a raw
// throw) before even attempting reservation if that deadline has already
// passed. (A pre-subtracted RELATIVE duration could still drift past the
// true deadline across I/O hops -- see the adapter-level tests in
// tests/openrouter-review-dispatch-adapter.test.mjs for that property.)

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const START = Date.parse('2026-08-19T21:00:00.000Z');

function geminiBody() {
  return { provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.01 } };
}

function grokBody() {
  return { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.02 } };
}

function toResponse(body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

/**
 * Setup shared by both tests below, built directly (not via the sibling
 * engine test file's `withEngine` helper) because the dispatch fake here
 * needs closure access to the SAME mutable clock the engine and leaseStore
 * read, so it can advance wall-clock time as a side effect of a call --
 * simulating a real dispatch that took real minutes -- something a fixed
 * dispatch option constructed before the clock exists cannot do.
 */
async function withLeaseBoundEngine(run, { preflightTtlMs = 10 * 60 * 1000, onGeminiDispatch, afterConsume } = {}) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-bound-'));
  let now = START;
  const clock = () => now;
  const leaseStore = createLeaseStore({ dataRoot, clock });
  // A REAL ownerLock, since this leaseStore is real.
  // Acquired against the base (unwrapped) store, before any test-specific wrapping below -- any
  // non-overridden method on wrappedLeaseStore still delegates to this same closure-held ledger
  // state, so the acquisitionId this returns stays valid regardless of wrapping.
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  // Named afterConsume, and invoked only AFTER the real reservation succeeds, on purpose: a clock
  // advance applied BEFORE consume() would trip lease-store's own expiry check inside consume() and
  // fail THIS reviewer's reservation, which is a different scenario from the one under test.
  const baseLeaseStore = leaseStore;
  const wrappedLeaseStore = afterConsume
    ? {
      ...baseLeaseStore,
      async consume(leaseId, reviewContractSha256, options) {
        const job = await baseLeaseStore.consume(leaseId, reviewContractSha256, options);
        await afterConsume(options, (ms) => { now += ms; });
        return job;
      },
    }
    : baseLeaseStore;
  const calls = [];
  const dispatchAdapter = {
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId, jobId: request.jobId, notAfterMs: request.notAfterMs });
      if (request.reviewerId === 'gemini') {
        if (onGeminiDispatch) onGeminiDispatch((ms) => { now += ms; });
        return toResponse(geminiBody());
      }
      return toResponse(grokBody());
    },
  };
  const approvalAdapter = { async authorize() { return { outcome: 'APPROVED', nonce: 'fake-nonce' }; } };
  const resultStore = createResultStore({ dataRoot });
  const preflightContextStore = createPreflightContextStore({ dataRoot });
  const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
  const scrubEngine = createScrubEngine({
    identityList: [],
    ollamaClient: Object.freeze({
      async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
      async checkReidentifiable() { return { ok: true, flagged: false }; },
    }),
  });
  const scrubMappingStore = createScrubMappingStore({ dataRoot });
  const engine = createReviewEngine({
    leaseStore: wrappedLeaseStore,
    ownerLock,
    approvalAdapter,
    dispatchAdapter,
    resultStore,
    preflightContextStore,
    dispatchOutcomeStore,
    scrubEngine,
    scrubMappingStore,
    clock,
    sourcePolicy,
    preflightPolicy,
    preflightTtlMs,
    installationHardMaximumUsd: 10,
    // This file's tests are about lease-bound dispatch, not the repeat-authorization gate.
    repeatAuthorizationJudge: { async judge() { throw new Error('not used in this test'); } },
  });
  try {
    await run({ engine, calls });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function preflightAndAuthorize(engine) {
  const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'lease-bound test' });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  return { leaseId: authorization.leaseId, preflightId: preflight.preflightId };
}

test('review() passes the SAME fixed absolute lease expiry as notAfterMs to every reviewer, unaffected by how much wall-clock time a prior reviewer consumed', async () => {
  await withLeaseBoundEngine(async ({ engine, calls }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const leaseExpiresAtMs = START + 10 * 60 * 1000;
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.equal(calls.length, 2);
    assert.equal(calls[0].reviewerId, 'gemini');
    assert.equal(calls[0].notAfterMs, leaseExpiresAtMs);
    assert.equal(calls[1].reviewerId, 'grok');
    assert.equal(calls[1].notAfterMs, leaseExpiresAtMs, 'must stay the fixed lease expiry, not a duration re-derived after gemini consumed 4 minutes');
  }, { preflightTtlMs: 10 * 60 * 1000, onGeminiDispatch: (advance) => advance(4 * 60 * 1000) });
});

// A lease that runs out mid-batch must halt cleanly with a structured LEASE_EXPIRED result,
// preserving whatever already reconciled, never a raw throw. The clock advances during gemini's
// RESERVATION rather than during its dispatch, because that is the moment the parallel dispatch
// path checks: every reviewer is reserved before any dispatch runs, so an expiry that only appears
// mid-dispatch can no longer stop a later reviewer, while an expiry that appears between two
// reservations still does. The test is also green against a sequential dispatch loop: there,
// gemini's consume() advances the clock and grok's own pre-reservation expiry check trips on the
// next loop iteration.
test('review() halts with LEASE_EXPIRED via a structured result (not a raw throw), preserving the already-reconciled reviewer, when the lease expires between two reservations', async () => {
  await withLeaseBoundEngine(async ({ engine, calls }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'LEASE_EXPIRED');
    const wireResult = formatToolResult(REVIEW_OUTPUT_SCHEMA.parse(result));
    assert.deepEqual(wireResult.structuredContent, result);
    assert.deepEqual(JSON.parse(wireResult.content[0].text), result);
    const invalidReviewerError = structuredClone(result);
    invalidReviewerError.reviewers.gemini.error = result.error;
    const rejected = REVIEW_OUTPUT_SCHEMA.safeParse(invalidReviewerError);
    assert.equal(rejected.success, false, 'batch-wide expiry must remain forbidden on an individual reviewer');
    assert.deepEqual(rejected.error.issues.map((issue) => issue.path), [['reviewers', 'gemini', 'error', 'code']]);
    assert.equal(result.reviewers.gemini.state, 'RECONCILED');
    assert.equal(result.reviewers.grok, undefined);
    assert.equal(calls.filter((call) => call.reviewerId === 'grok').length, 0, 'grok must never be dispatched once the lease has expired');
  }, {
    preflightTtlMs: 10 * 60 * 1000,
    afterConsume: (options, advance) => { if (options.reviewerId === 'gemini') advance(11 * 60 * 1000); },
  });
});
