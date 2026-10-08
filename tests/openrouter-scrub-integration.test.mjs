import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createReviewEngine, ReviewEngineError } from '../src/local-mcp/review-engine.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createDispatchOutcomeStore } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { ACCT_C, USD } from './helpers/scanner-safe-fixtures.mjs';

// End-to-end offline test of the scrub pipeline through createReviewEngine:
// real (non-mocked) scrub-patterns.mjs / scrub-engine.mjs /
// scrub-mapping-store.mjs logic, wired through the real createReviewEngine()
// exactly as tools/openrouter-review-mcp-server.mjs wires it in production.
// Only the Ollama HTTP call (never reachable offline) and the OpenRouter
// dispatch itself (never reachable without spending real money) are faked.
//
// Two fixture notes:
//
// 1. The account-number fixture is a clean digit run: findShapeSpans()'s
//    account_number_shape regex is `(?<!\d\.)\b\d{8,17}\b` (scrub-engine.mjs),
//    and letters embedded in a digit run break its own \b word-boundary, so
//    a letter-interrupted string is never detected as a contiguous 8-17
//    digit run in the first place.
// 2. The passingDispatch() fake uses provider 'xAI' and a real `usage.cost`
//    for the second (grok) reviewer: reviewer-registry.mjs pins grok's
//    expectedProvider to the literal string 'xAI' (no dot), and
//    advisory-schema.mjs's extractFiniteNonnegativeCost() requires a real
//    finite non-negative `usage.cost` field -- an empty `usage: {}` object
//    returns null cost, which review-engine.mjs treats as UNKNOWN_COST and
//    halts rather than passes. This matches what
//    tests/openrouter-review-engine.test.mjs's own geminiPassBody() /
//    grokPassBody() fixtures already use.

function passingDispatch() {
  const responseFor = (body) => ({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ bodyBase64: Buffer.from(JSON.stringify(body)).toString('base64') }),
  });
  const pass = (provider, cost) => ({
    provider,
    choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }],
    usage: { cost },
  });
  let call = 0;
  // consequential_spec_v1's reviewerIds are ['gemini', 'grok'] in that fixed
  // order (reviewer-registry.mjs), and review() dispatches in that order --
  // so the first response here answers gemini, the second answers grok.
  const responses = [responseFor(pass('Google', 0.01)), responseFor(pass('xAI', 0.02))];
  return Object.freeze({
    calls: [],
    async dispatch(args) {
      this.calls.push(args);
      return responses[call++];
    },
  });
}

async function withFullEngine(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-scrub-integration-'));
  const scrubEngine = createScrubEngine({
    identityList: ['jane q. public'],
    ollamaClient: Object.freeze({
      async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
      async checkReidentifiable() { return { ok: true, flagged: false }; },
    }),
  });
  const leaseStore = createLeaseStore({ dataRoot });
  // A REAL ownerLock, since this leaseStore is real
  // (not faked) -- a fake acquisitionId would never match a real store's real currentOwner, causing
  // every guarded write to fail closed.
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const engine = createReviewEngine({
    leaseStore,
    ownerLock,
    approvalAdapter: Object.freeze({ async authorize() { return { outcome: 'APPROVED', nonce: 'n' }; } }),
    dispatchAdapter: passingDispatch(),
    resultStore: createResultStore({ dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine,
    scrubMappingStore: createScrubMappingStore({ dataRoot }),
    sourcePolicy: { allowedRoots: [], maxSourceBytes: 100000 },
    preflightPolicy: { maxRequestBytes: 200000 },
    installationHardMaximumUsd: 10,
    // This file's tests are about scrub-engine integration, not the repeat-authorization gate.
    repeatAuthorizationJudge: { async judge() { throw new Error('not used in this test'); } },
  });
  try {
    await run({ engine });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('end-to-end: hard-block category never reaches preflight completion', async () => {
  await withFullEngine(async ({ engine }) => {
    await assert.rejects(
      () => engine.preflight({ source_text: 'CUI//SP-PRVCY roster', profile: 'consequential_spec_v1' }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTENT_BLOCKED',
    );
  });
});

test('end-to-end: substitution-eligible content round-trips clean through the full preflight -> authorize -> review -> result cycle', async () => {
  await withFullEngine(async ({ engine }) => {
    const sourceText = `Contact Jane Q. Public, account ${ACCT_C}, ${USD}1,200.00 balance.`;
    const preflighted = await engine.preflight({
      source_text: sourceText,
      profile: 'consequential_spec_v1',
    });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    const reviewed = await engine.review({
      leaseId,
      preflightId: preflighted.preflightId,
      source_text: sourceText,
    });
    assert.equal(reviewed.state, 'PASSED');
    const recovered = await engine.result({ leaseId });
    assert.equal(recovered.state, 'ACTIVE');
  });
});

test('end-to-end: clean content with no sensitive shapes at all passes through untouched', async () => {
  await withFullEngine(async ({ engine }) => {
    const preflighted = await engine.preflight({ source_text: 'a plain spec describing a caching layer', profile: 'consequential_spec_v1' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    const reviewed = await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: 'a plain spec describing a caching layer' });
    assert.equal(reviewed.state, 'PASSED');
  });
});
