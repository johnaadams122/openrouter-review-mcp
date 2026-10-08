import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore, LEDGER_DATA_ROOT_LOCKED_CODE } from '../src/local-mcp/lease-store.mjs';
import { REVIEW_OUTPUT_SCHEMA } from '../src/local-mcp/mcp-schemas.mjs';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import {
  costKindFromLedgerJob, createReviewEngine, ReviewEngineError, selectContentTextForValidation,
} from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { validateAdvisoryContent } from '../src/review-core/advisory-schema.mjs';
import { createFakeDispatchWorker } from './fixtures/openrouter-review/fake-dispatch-worker.mjs';
import { ACCT_C, W_MEDICATION } from './helpers/scanner-safe-fixtures.mjs';

// This file's own tests are about lease/dispatch/reconcile behavior, not the repeat-authorization
// justification gate -- that has its own dedicated suite in
// tests/openrouter-review-autonomy.test.mjs. Every createReviewEngine() call here uses this same
// never-exercised fake, matching the "not used in this test" convention already used elsewhere in
// this file for collaborators outside a given test's scope.
const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const START = Date.parse('2026-08-18T12:00:00.000Z');

function geminiPassBody(findings = []) {
  return { provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.01 } };
}

function grokPassBody(findings = []) {
  return { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.02 } };
}

function responseFor(body, httpStatus = 200) {
  return { httpStatus, bodyText: JSON.stringify(body) };
}

/**
 * Wraps the shared offline dispatch fixture so ordered-dispatch tests can
 * observe WHICH reviewer was actually dispatched (the shared fixture's own
 * `calls` log deliberately records only opaque jobId/byte-length, never
 * reviewer identity, per its own secret-minimization contract). This wrapper
 * adds no behavior of its own -- every response still comes from the real
 * fixture -- so `calls` here proves an absence of dispatch, not merely an
 * absence of a field.
 */
function createOrderedFakeDispatch({ responses } = {}) {
  const inner = createFakeDispatchWorker({ responses });
  const calls = [];
  return {
    calls,
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId, jobId: request.jobId, requestByteLength: request.requestBytes.length });
      return inner.dispatch(request);
    },
  };
}

// Always-clean local-LLM stand-in for the default engine-under-test scrub
// engine: this file's own tests are about lease/dispatch/reconcile behavior,
// not scrub-engine.mjs's own hard-block/smell-test logic (that module has
// its own dedicated, exhaustively adversarial suite in
// tests/openrouter-scrub-engine.test.mjs) -- so every test that does not
// explicitly override `scrubEngine` gets a scrub engine that never blocks on
// third-party-PII/reidentifiability grounds, leaving the regex-driven
// account/dollar/identity substitution path (identityList: []) as the only
// thing that can affect source_text/reviewContext content by default.
function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

/**
 * Like createOrderedFakeDispatch, but additionally retains the actual
 * `requestBytes` sent for each call. createOrderedFakeDispatch's own `calls`
 * log deliberately records only `requestByteLength` (see its own comment,
 * mirroring the shared fixture's secret-minimization contract) -- that is
 * exactly what makes it unsuitable for a test that needs to inspect what
 * content was actually bound into the dispatched request body.
 */
function createCapturingDispatch({ responses } = {}) {
  const inner = createFakeDispatchWorker({ responses });
  const calls = [];
  return {
    calls,
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId, jobId: request.jobId, requestBytes: request.requestBytes });
      return inner.dispatch(request);
    },
  };
}

/**
 * A dispatch fake whose response echoes back whatever ACCOUNT_<hex>
 * placeholder token it actually finds in the request it was sent, wrapped
 * inside a finding's root_cause and evidence fields. The exact placeholder
 * digest depends on an HMAC keyed on preflightId (see scrub-engine.mjs's
 * derivePlaceholder), which review-engine.mjs mints internally and never
 * exposes -- so a test cannot know it in advance. Reading it back out of the
 * REAL request bytes this fake actually receives (rather than trying to
 * precompute it) is what lets these tests prove reverse-substitution against
 * the real, live-computed token, not a guessed one.
 */
function createPlaceholderEchoingDispatch() {
  const calls = [];
  return {
    calls,
    async dispatch(request) {
      calls.push({ reviewerId: request.reviewerId, jobId: request.jobId });
      const bodyText = Buffer.from(request.requestBytes).toString('utf8');
      const [placeholder] = bodyText.match(/ACCOUNT_[0-9a-f]{8}/) ?? ['ACCOUNT_00000000'];
      const provider = request.reviewerId === 'gemini' ? 'Google' : 'xAI';
      const cost = request.reviewerId === 'gemini' ? 0.01 : 0.02;
      const body = {
        provider,
        choices: [{
          finish_reason: 'stop',
          message: {
            content: JSON.stringify({
              verdict: 'pass',
              findings: [{
                severity: 'blocker',
                section: 'x',
                root_cause: `account ${placeholder} looks wrong`,
                affected_behavior: 'y',
                consequence: 'z',
                evidence: [`saw ${placeholder} referenced on line 1`],
              }],
            }),
          },
        }],
        usage: { cost },
      };
      return {
        kind: 'RESPONSE',
        envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
      };
    },
  };
}

function createApprovingApproval({ outcome = 'APPROVED' } = {}) {
  const calls = [];
  return {
    calls,
    async authorize(request, options) {
      calls.push({ request, options });
      return { outcome, nonce: 'fake-nonce' };
    },
  };
}

// A minimal, always-owning stand-in matching the real
// shape leaseStore.acquireProcessOwnership() returns ({ dataRoot, generation, acquisitionId,
// isOwner, release }). Safe to use ONLY where the underlying leaseStore in play is itself a fake
// (or the code path under test never reaches a real owner-sensitive lease-store write) -- this
// file's own primary harness (withEngine, below) uses a REAL createLeaseStore() for every test, so
// it acquires a REAL ownerLock instead (see withEngine's own comment); this factory exists for the
// handful of tests that construct createReviewEngine() directly against fully-faked collaborators
// and need a merely shape-valid ownerLock, never one that has to match a real ledger's currentOwner.
function createFakeOwnerLock({ acquisitionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } = {}) {
  let state = 'armed';
  return {
    dataRoot: '/fake',
    get generation() { return state === 'armed' ? 1 : null; },
    get acquisitionId() { return state === 'armed' ? acquisitionId : null; },
    get state() { return state; },
    get everArmed() { return true; },
    isOwner: () => state === 'armed',
    async arm() { if (state !== 'released') state = 'armed'; },
    async release({ final = true } = {}) { state = final ? 'released' : 'unarmed'; },
  };
}

/**
 * Assembles one full, independently-owned set of valid createReviewEngine() options against a
 * fresh temp data root -- mirroring withEngine()'s own collaborator construction below, but
 * returning the raw options object (with `dataRoot` attached as an extra, harmless key
 * createReviewEngine's own destructuring ignores) instead of constructing the engine and driving a
 * callback. Used by the constructor-validation test and the ownerLock.isOwner()/resultStore test
 * below, both of which need to inspect or perturb individual options rather than run inside
 * withEngine's own fixed harness. `leaseStore` is real (createLeaseStore), matching withEngine's own
 * choice, and `ownerLock` is a REAL handle acquired against it (never createFakeOwnerLock()) so a
 * test spreading these options into createReviewEngine() exercises the exact same real
 * acquisitionId-verified ledger writes the production engine does. Caller owns cleanup: release the
 * returned `ownerLock` and rm the returned `dataRoot` when done (see the two tests below for the
 * pattern).
 */
async function buildMinimalEngineOptions() {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-min-'));
  let now = START;
  const clock = () => now;
  const leaseStore = createLeaseStore({ dataRoot, clock });
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  return {
    dataRoot,
    leaseStore,
    ownerLock,
    approvalAdapter: createApprovingApproval(),
    dispatchAdapter: createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] }),
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
  };
}

async function withEngine(run, {
  installationHardMaximumUsd = 10, preflightTtlMs = 10 * 60 * 1000, orphanSweepGraceMs,
  dispatch, approval, resultStore, preflightContextStore, dispatchOutcomeStore, scrubEngine, scrubMappingStore,
  wrapLeaseStore,
  dispatchHealthStore, pendingHealthVerdictStore, wrapPendingHealthVerdictStore, healthVerdictGraceMs, healthVerdictBackstopMs,
  alertStore,
} = {}) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-'));
  let now = START;
  const clock = () => now;
  const realLeaseStore = createLeaseStore({ dataRoot, clock });
  // Optional thin wrap of the REAL store (not a fake replacement) -- lets a test override a single
  // method (e.g. close()) to inject a targeted failure while every other operation still goes
  // through the real, fully-functional ledger, which recoverStaleLease() needs for everything else
  // (findStaleReservedJobs, getLease, getJob, reconcile via processDispatchOutcome, sweepOrphanedLeases).
  const leaseStore = wrapLeaseStore ? wrapLeaseStore(realLeaseStore) : realLeaseStore;
  // This harness's leaseStore is REAL (createLeaseStore above), not a fake -- so
  // createReviewEngine's own required ownerLock must be a REAL handle acquired against that SAME
  // store, not createFakeOwnerLock()'s static stand-in. A fake acquisitionId would never match this
  // store's real currentOwner, and every test in this file that calls authorizeWorkflow()/review()
  // would fail closed with PROCESS_OWNERSHIP_LOST the instant ownership fencing reaches a real
  // leaseStore write. Acquired against realLeaseStore
  // (never the possibly-wrapped `leaseStore`) so a test's own wrapLeaseStore override can never
  // accidentally intercept this call; any non-overridden method on the wrapped object still
  // delegates to the same closure-held ledger state either way, so the acquisitionId this returns
  // is valid against `leaseStore` regardless of wrapping.
  const ownerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const fakeDispatch = dispatch ?? createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
  const fakeApproval = approval ?? createApprovingApproval();
  const fakeResultStore = resultStore ?? createResultStore({ dataRoot });
  const fakePreflightContextStore = preflightContextStore ?? createPreflightContextStore({ dataRoot });
  const fakeDispatchOutcomeStore = dispatchOutcomeStore ?? createDispatchOutcomeStore({ dataRoot });
  const fakeScrubEngine = scrubEngine ?? createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
  const fakeScrubMappingStore = scrubMappingStore ?? createScrubMappingStore({ dataRoot });
  const fakeDispatchHealthStore = dispatchHealthStore ?? createDispatchHealthStore({ dataRoot });
  const realPendingHealthVerdictStore = pendingHealthVerdictStore ?? createPendingHealthVerdictStore({ dataRoot });
  const fakePendingHealthVerdictStore = wrapPendingHealthVerdictStore ? wrapPendingHealthVerdictStore(realPendingHealthVerdictStore) : realPendingHealthVerdictStore;
  const engine = createReviewEngine({
    leaseStore,
    ownerLock,
    approvalAdapter: fakeApproval,
    dispatchAdapter: fakeDispatch,
    resultStore: fakeResultStore,
    preflightContextStore: fakePreflightContextStore,
    dispatchOutcomeStore: fakeDispatchOutcomeStore,
    scrubEngine: fakeScrubEngine,
    scrubMappingStore: fakeScrubMappingStore,
    clock,
    sourcePolicy,
    preflightPolicy,
    preflightTtlMs,
    installationHardMaximumUsd,
    repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    dispatchHealthStore: fakeDispatchHealthStore,
    pendingHealthVerdictStore: fakePendingHealthVerdictStore,
    ...(orphanSweepGraceMs === undefined ? {} : { orphanSweepGraceMs }),
    ...(healthVerdictGraceMs === undefined ? {} : { healthVerdictGraceMs }),
    ...(healthVerdictBackstopMs === undefined ? {} : { healthVerdictBackstopMs }),
    ...(alertStore === undefined ? {} : { alertStore }),
  });
  try {
    await run({
      engine, leaseStore, ownerLock, fakeDispatch, fakeApproval, resultStore: fakeResultStore,
      preflightContextStore: fakePreflightContextStore, dispatchOutcomeStore: fakeDispatchOutcomeStore,
      scrubEngine: fakeScrubEngine, scrubMappingStore: fakeScrubMappingStore,
      dispatchHealthStore: fakeDispatchHealthStore, pendingHealthVerdictStore: fakePendingHealthVerdictStore,
      dataRoot, advance: (ms) => { now += ms; },
    });
  } finally {
    await ownerLock.release({ final: true }).catch(() => {});
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function writeDispatchOutcomeFixture(dataRoot, jobId, outcome) {
  const path = dispatchOutcomePath({ dataRoot, jobId });
  await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
  await writeFile(path, JSON.stringify(outcome), 'utf8');
}

async function preflightAndAuthorize(engine, { source_text = 'x', profile = 'consequential_spec_v1', changeKinds, maxJobs = 2, reviewContext = 'engine test scope' } = {}) {
  const preflight = await engine.preflight({ source_text, profile, changeKinds, reviewContext });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs });
  return { preflight, authorization, leaseId: authorization.leaseId, preflightId: preflight.preflightId };
}

test('selectContentTextForValidation strips markdown JSON framing only for prompted_json reviewers, and passes through everything else unchanged', () => {
  const fenced = '```json\n{"verdict":"pass","findings":[]}\n```';
  assert.equal(selectContentTextForValidation(fenced, { outputMode: 'prompted_json' }), '{"verdict":"pass","findings":[]}');
  assert.equal(selectContentTextForValidation(fenced, { outputMode: undefined }), fenced);
  assert.equal(selectContentTextForValidation(fenced, {}), fenced);
  assert.equal(selectContentTextForValidation(42, { outputMode: 'prompted_json' }), 42);
  assert.equal(selectContentTextForValidation(null, { outputMode: 'prompted_json' }), null);
});

// costKindFromLedgerJob is the single shared classifier both review()'s own in-loop existingJob
// fallback and result()'s ledger-only fallback use, so a fix to one can never drift from the
// other. A worst-case (or proven-zero) charge, once persisted with no way to say WHICH kind of
// figure it is, is indistinguishable from a genuine confirmed cost to anything reading the ledger
// later.
test('costKindFromLedgerJob reports the ledger job\'s own real costKind when present, and RECOVERED_STATUS_ONLY only when there is genuinely no cost information to report', () => {
  assert.equal(costKindFromLedgerJob({ state: 'RECONCILED', costKind: 'KNOWN' }), 'KNOWN');
  assert.equal(costKindFromLedgerJob({ state: 'RECONCILED', costKind: 'UNKNOWN_WORST_CASE_CHARGED' }), 'UNKNOWN_WORST_CASE_CHARGED');
  assert.equal(costKindFromLedgerJob({ state: 'RECONCILED', costKind: 'ZERO_ON_TRANSPORT_FAILURE' }), 'ZERO_ON_TRANSPORT_FAILURE');
  assert.equal(costKindFromLedgerJob({ state: 'RESERVED' }), 'RECOVERED_STATUS_ONLY');
  assert.equal(costKindFromLedgerJob(null), 'RECOVERED_STATUS_ONLY');
});

// NOTE ON SCOPE: this test does NOT call the real (non-exported)
// processDispatchOutcome, and cannot regression-test its shipped
// `JSON.parse(cleanedContentText)` line directly: reverting that line to
// the raw `JSON.parse(contentText)` form still passes every test here,
// this one included. What
// this test DOES prove is the underlying reasoning the fix relies on: the
// same cleaned text that satisfies validateAdvisoryContent is also
// guaranteed parseable by a second, independent JSON.parse call, because
// validateAdvisoryContent already parses that exact string internally (see
// advisory-schema.mjs) before returning ok:true. A true end-to-end
// regression guard would require exporting processDispatchOutcome (or
// building fake-dispatch scaffolding to drive it with a prompted_json
// reviewer); that is outside this test's scope.
test('the same cleaned text that passes validateAdvisoryContent is also guaranteed parseable by JSON.parse (proves the fix\'s underlying reasoning; cannot directly regression-test the shipped line since processDispatchOutcome is not exported and no operational prompted_json reviewer exists yet to drive it end-to-end)', () => {
  const fenced = '```json\n{"verdict":"pass","findings":[]}\n```';
  const reviewer = { outputMode: 'prompted_json' };
  const cleanedContentText = selectContentTextForValidation(fenced, reviewer);
  const contentResult = validateAdvisoryContent(cleanedContentText);
  assert.equal(contentResult.ok, true);
  assert.doesNotThrow(() => JSON.parse(cleanedContentText));
  // The raw fenced text is NOT valid JSON on its own -- this is the exact
  // crash processDispatchOutcome would hit if it re-parsed `contentText`
  // (the raw original) instead of `cleanedContentText` after validation.
  assert.throws(() => JSON.parse(fenced));
});

// ---------------------------------------------------------------------------
// Ordered-dispatch and unknown-cost test.
// ---------------------------------------------------------------------------
test('unknown Gemini cost charges its worst case and closes the lease, while Grok still dispatches independently', async () => {
  const fakeDispatch = createOrderedFakeDispatch({
    responses: [responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: {} })],
  });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'UNKNOWN_COST');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    // A halt does not cancel a sibling. The fake repeats its last queued response, so grok
    // receives the same cost-less body and independently halts the same way.
    assert.equal(fakeDispatch.calls.filter((call) => call.reviewerId === 'grok').length, 1);
    assert.equal(result.reviewers.grok.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  }, { dispatch: fakeDispatch });
});

// ---------------------------------------------------------------------------
// Full state-matrix coverage.
// ---------------------------------------------------------------------------

test('a valid pair dispatches Gemini then Grok in order and returns structured advisory data only', async () => {
  await withEngine(async ({ engine, fakeDispatch, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');
    assert.deepEqual(fakeDispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.deepEqual(result.reviewers.gemini.advisory, { verdict: 'pass', findings: [] });
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
    assert.equal(Object.prototype.hasOwnProperty.call(result.reviewers.gemini, 'requestBody'), false);
    // A clean pass's cost is a real, validated figure -- the ledger itself must durably say so,
    // not just review()'s own in-memory return value for this one call.
    assert.equal((await leaseStore.getJob(result.reviewers.gemini.jobId)).costKind, 'KNOWN');
    assert.equal((await leaseStore.getJob(result.reviewers.grok.jobId)).costKind, 'KNOWN');
  });
});

test('a first-reviewer halt on invalid content closes the lease under its own code while Grok still dispatches', async () => {
  const dispatch = createOrderedFakeDispatch({
    responses: [responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: 'not valid json' } }], usage: { cost: 0.01 } })],
  });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    // The top-level reason is the FIRST halt in profile order (gemini), never whichever settled
    // first -- grok receives the same repeated response and halts on PROVIDER_MISMATCH, since its
    // expectedProvider is 'xAI', not 'Google'.
    assert.equal(result.error.code, 'STRICT_OUTPUT_INVALID');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.gemini.error.code, 'STRICT_OUTPUT_INVALID');
    assert.equal(result.reviewers.grok.error.code, 'PROVIDER_MISMATCH');
    assert.equal(dispatch.calls.filter((call) => call.reviewerId === 'grok').length, 1);
    assert.equal((await leaseStore.getLease(leaseId)).state, 'STRICT_OUTPUT_INVALID');
  }, { dispatch });
});

test('second-reviewer halt on provider mismatch preserves the first reviewer\'s clean result', async () => {
  const dispatch = createOrderedFakeDispatch({
    responses: [responseFor(geminiPassBody()), responseFor({ provider: 'NotXai', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.02 } })],
  });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'PROVIDER_MISMATCH');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.deepEqual(result.reviewers.gemini.advisory, { verdict: 'pass', findings: [] });
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok.provider, 'NotXai');
  }, { dispatch });
});

test('provider mismatch is reported independently of content validity', async () => {
  const dispatch = createOrderedFakeDispatch({
    responses: [responseFor({ provider: 'NotGoogle', choices: [{ finish_reason: 'stop', message: { content: 'garbage, not json at all' } }], usage: { cost: 0.01 } })],
  });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'PROVIDER_MISMATCH');
  }, { dispatch });
});

test('malformed content from an otherwise-correct provider halts as STRICT_OUTPUT_INVALID with a known cost', async () => {
  const dispatch = createOrderedFakeDispatch({
    responses: [responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass' }) } }], usage: { cost: 0.015 } })],
  });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'STRICT_OUTPUT_INVALID');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.gemini.costUsd, 0.015);
  }, { dispatch });
});

for (const [label, usage] of [['missing', {}], ['negative', { cost: -1 }], ['string', { cost: '0.01' }]]) {
  test(`${label} cost is treated as unknown and charged at the reserved worst case`, async () => {
    const dispatch = createOrderedFakeDispatch({
      responses: [responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage })],
    });
    await withEngine(async ({ engine }) => {
      const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
      assert.equal(result.error.code, 'UNKNOWN_COST');
      const geminiMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'gemini').maxUsd;
      assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
    }, { dispatch });
  });
}

// A cost above the reservation is recorded at its real KNOWN value and the review is kept, because
// booking only the reservation (as UNKNOWN_COST, discarding the review) would under-record real spend
// and throw away a finished review. Recording MORE than was reserved can only fail closed; the job is
// flagged aboveReservation and one critical alert is raised.
test('a cost report above the reserved bound is recorded at its real KNOWN cost, keeps its content, and raises one critical alert', async () => {
  const alerts = [];
  const dispatch = createOrderedFakeDispatch({
    responses: [
      responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 999 } }),
      responseFor(grokPassBody()),
    ],
  });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.gemini.costUsd, 999);
    assert.deepEqual(result.reviewers.gemini.advisory, { verdict: 'pass', findings: [] });
    const geminiJob = await leaseStore.getJob(result.reviewers.gemini.jobId);
    assert.equal(geminiJob.aboveReservation, true);
    const grokJob = await leaseStore.getJob(result.reviewers.grok.jobId);
    assert.equal(Object.hasOwn(grokJob, 'aboveReservation'), false);
    const critical = alerts.filter((alert) => alert.severity === 'critical');
    assert.equal(critical.length, 1);
    assert.match(critical[0].reason, /gemini/);
    assert.match(critical[0].reason, /above its reserved worst case/);
  }, { dispatch, alertStore: { async record(alert) { alerts.push(alert); }, async list() { return []; } } });
});

test('a provider mismatch billed above the reserved bound halts with its real cost recorded and flagged', async () => {
  const alerts = [];
  const dispatch = createOrderedFakeDispatch({
    responses: [responseFor({ provider: 'Somebody-Else', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 999 } })],
  });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [], maxJobs: 1 });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'PROVIDER_MISMATCH');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok.costUsd, 999);
    const job = await leaseStore.getJob(result.reviewers.grok.jobId);
    assert.deepEqual({ aboveReservation: job.aboveReservation, haltReason: job.haltReason }, { aboveReservation: true, haltReason: 'PROVIDER_MISMATCH' });
    assert.equal(alerts.filter((alert) => alert.severity === 'critical').length, 1);
  }, { dispatch, alertStore: { async record(alert) { alerts.push(alert); }, async list() { return []; } } });
});

// A transport failure reconciles at zero for a PROVEN-zero-cost FailureKind, never the reserved
// worst-case ceiling: a FailureKind that provably precedes a received response (e.g. a WebException
// with no Response, i.e. no response was ever received) cannot have been billed, and that is exactly
// what ZERO_COST_TRANSPORT_FAILURE_KINDS (review-engine.mjs) covers. It is NOT safe to apply zero
// uniformly to every `kind: 'FAILURE'` outcome: RESPONSE_READ_FAILED and INTERNAL_ERROR are
// deliberately excluded and stay worst-case-charged -- see the tests below this one, and
// ZERO_COST_TRANSPORT_FAILURE_KINDS's own docstring for why. This whole zero-cost path is also
// deliberately narrower than DISPATCH_UNKNOWN (an ambiguous "we don't even know if a dispatch was
// attempted" case, e.g. a stale DISPATCHING marker or the adapter itself throwing before ever
// reaching the worker) -- that case keeps the conservative worst-case charge unconditionally,
// since there really is no signal there one way or the other.
// The fake dispatch worker repeats its last queued response (only one is queued here), so grok
// independently dispatches too and hits the identical TIMEOUT failure gemini did (a halt does not
// cancel a sibling).
test('a transport failure from the dispatch worker reconciles at zero cost (never the worst case) and halts', async () => {
  const dispatch = createOrderedFakeDispatch({ responses: [{ kind: 'FAILURE', failureKind: 'TIMEOUT', message: 'deadline exceeded' }] });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.costKind, 'ZERO_ON_TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.costUsd, 0);
    // Both reviewers now dispatch and both hit the same repeated TIMEOUT outcome, so grok reconciles
    // at the same proven-zero cost gemini did.
    assert.equal(result.reviewers.grok.costKind, 'ZERO_ON_TRANSPORT_FAILURE');
    assert.equal(result.reviewers.grok.costUsd, 0);

    const lease = await leaseStore.getLease(leaseId);
    assert.equal(lease.state, 'TRANSPORT_FAILURE');
    assert.equal(lease.spentUsd, 0, 'a definitively-failed dispatch must never inflate spentUsd for money that never left the account');
    // Not an exact-zero equality: gemini's and grok's reservationUsd are two DIFFERENT floating-point
    // amounts (their own distinct maxUsd figures), reserved via two separate additions and released
    // via two separate subtractions. That round-trip is not guaranteed bit-exact by IEEE 754 the way
    // "reserve X, then subtract that exact same X" always is -- in practice this reconciles to
    // 5.551115123125783e-17, not 0. The noise floor here (1e-9) is many orders of magnitude below a
    // single cent, so this still proves no real money is left reserved.
    assert.ok(Math.abs(lease.reservedUsd) < 1e-9, `expected reservedUsd to be zero within float noise, got ${lease.reservedUsd}`);
    // The ledger's own job record must durably agree this was a proven-zero cost, not just
    // review()'s in-memory return value -- otherwise a later recovery (a fresh process, or this
    // same lease's job recovered with no resultStore hit) would lose the distinction.
    assert.equal((await leaseStore.getJob(result.reviewers.gemini.jobId)).costKind, 'ZERO_ON_TRANSPORT_FAILURE');
    assert.equal((await leaseStore.getJob(result.reviewers.grok.jobId)).costKind, 'ZERO_ON_TRANSPORT_FAILURE');
  }, { dispatch });
});

// RESPONSE_READ_FAILED is deliberately EXCLUDED from the zero-cost set (see
// ZERO_COST_TRANSPORT_FAILURE_KINDS in review-engine.mjs): by the time this FailureKind fires in
// the real dispatch worker, OpenRouter's HTTP response was already successfully received --
// meaning, for this non-streaming request (reviewer-registry.mjs sets stream:false), the
// completion was very likely already fully generated (and probably already billed) server-side
// before the LOCAL body-read failed. Folding this into the same zero-cost bucket as a response that was
// never received at all would risk silently under-recording real spend -- the more dangerous
// direction.
test('a RESPONSE_READ_FAILED transport failure -- a response WAS received, only the local body read failed -- still charges the worst case, not zero', async () => {
  const dispatch = createOrderedFakeDispatch({ responses: [{ kind: 'FAILURE', failureKind: 'RESPONSE_READ_FAILED', message: 'a response was received but its body could not be fully read' }] });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    const geminiMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'gemini').maxUsd;
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);

    const lease = await leaseStore.getLease(leaseId);
    // Both reviewers dispatch and the fake repeats its last queued
    // response, so grok hits the identical RESPONSE_READ_FAILED and is worst-case charged too.
    const grokMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'grok').maxUsd;
    assert.equal(lease.spentUsd, geminiMaxUsd + grokMaxUsd);
    assert.equal((await leaseStore.getJob(result.reviewers.gemini.jobId)).costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  }, { dispatch });
});

// INTERNAL_ERROR is also deliberately excluded: it is a generic top-level catch-all in the real
// dispatch worker that could in principle fire at any point in the dispatch flow, including after
// a successful response -- its timing cannot be proven safe the way every zero-cost kind can.
test('an INTERNAL_ERROR transport failure still charges the worst case, not zero (timing within the dispatch cannot be proven safe)', async () => {
  const dispatch = createOrderedFakeDispatch({ responses: [{ kind: 'FAILURE', failureKind: 'INTERNAL_ERROR', message: 'an unexpected error occurred during dispatch' }] });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    const geminiMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'gemini').maxUsd;
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);

    const lease = await leaseStore.getLease(leaseId);
    // Both reviewers dispatch and the fake repeats its last queued
    // response, so grok hits the identical INTERNAL_ERROR and is worst-case charged too.
    const grokMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'grok').maxUsd;
    assert.equal(lease.spentUsd, geminiMaxUsd + grokMaxUsd);
    // The ledger's own job record must durably say this was a worst-case GUESS, not a confirmed
    // cost -- otherwise a later recovery with no in-memory context would be unable to tell this
    // apart from a genuinely known geminiMaxUsd charge.
    assert.equal((await leaseStore.getJob(result.reviewers.gemini.jobId)).costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  }, { dispatch });
});

// withEngine's own harness constructs and wires a REAL dispatchHealthStore (rather than
// createReviewEngine's internal, test-invisible volatile default), specifically so a test can
// observe this counter from outside. haltAndClose's default recordHealthOutcome:true records every
// post-intent failure (see haltAndClose's own docstring); this test pins that through the harness's
// own dispatchHealthStore.
test('haltAndClose records a dispatch-health failure by default, now externally observable via the harness\'s own dispatchHealthStore', async () => {
  const dispatch = createOrderedFakeDispatch({ responses: [{ kind: 'FAILURE', failureKind: 'INTERNAL_ERROR', message: 'boom' }] });
  await withEngine(async ({ engine, dispatchHealthStore }) => {
    // final_verification_v1 + changeKinds: [] reserves only `grok` (see the narrower-reviewer-set
    // test above), so this lease dispatches exactly ONE reviewer -- keeping this test's assertion
    // (consecutiveFailures === 1) unambiguous, rather than the default two-reviewer profile, which
    // would record two failures (one haltAndClose call per halted reviewer).
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, {
      maxJobs: 1, profile: 'final_verification_v1', changeKinds: [],
    });
    await engine.review({ leaseId, preflightId, source_text: 'x' });
    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 1);
  }, { dispatch });
});

// A missing or unparseable failureKind fails closed to the conservative worst-case charge, the
// same direction every other unrecognized/ambiguous case in this module already takes -- never
// silently defaults to the more dangerous zero charge just because the classifier couldn't read the label.
// Deliberately NOT built via createOrderedFakeDispatch/createFakeDispatchWorker: that shared
// fixture's own buildResultLine() always constructs its OWN envelopeJsonText from
// `outcome.failureKind ?? 'INTERNAL_ERROR'` (see fixtures/openrouter-review/fake-dispatch-worker.mjs)
// rather than passing through a raw envelopeJsonText override -- a real malformed/missing-field
// envelope needs a bespoke fake, the same pattern the "dispatch adapter throwing" test below uses.
test('a FAILURE outcome with no failureKind at all (malformed envelope) fails closed to the worst-case charge, not zero', async () => {
  const dispatch = { async dispatch() { return { kind: 'FAILURE', envelopeJsonText: '{"message":"no failureKind field here"}' }; } };
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    const geminiMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'gemini').maxUsd;
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
  }, { dispatch });
});

test('the dispatch adapter throwing is treated as an unknown outcome, not a crash', async () => {
  const dispatch = { calls: [], async dispatch() { throw new Error('adapter exploded'); } };
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  }, { dispatch });
});

// Same content-leak class safeErrorDetail() already closes for every process.stderr.write(...)
// site in this file (see this module's own header comment), but reached through a DIFFERENT
// channel: dispatchAndReconcile()'s catch block for a thrown dispatchAdapter.dispatch() embeds
// the raw error.message into the `message` field of the HALTED result this function returns --
// which flows all the way back to the MCP caller (review()'s return value), not to a local log.
// A dispatchAdapter is a caller-supplied collaborator (the real implementation in
// tools/openrouter-review-mcp-server.mjs shells out to PowerShell and reads back an on-disk
// envelope potentially containing the reviewer's own generated content), so nothing here can
// prove its thrown errors are always content-free -- the same reasoning safeErrorDetail()'s own
// docstring already rejects for deciding whether a message is "safe" by error shape.
test('a content-bearing error thrown by the dispatch adapter never reaches the halted result verbatim', async () => {
  const leakedFragment = "synthetic-private-error-fragment";
  const dispatch = { async dispatch() { throw new Error(`ENOENT: stray fragment "${leakedFragment}" near byte 42`); } };
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
    assert.ok(
      !result.error.message.includes(leakedFragment),
      `top-level halt message must not embed the raw error text, got: ${result.error.message}`,
    );
    assert.ok(
      !result.reviewers.gemini.error.message.includes(leakedFragment),
      `per-reviewer halt message must not embed the raw error text, got: ${result.reviewers.gemini.error.message}`,
    );
  }, { dispatch });
});

// A second, distinct instance of the exact same leak class: review()'s own
// Promise.allSettled rejection-handling loop (the "MONEY SAFETY, not bookkeeping" block a few
// hundred lines below) extracts `outcome.reason.message` and embeds it directly into
// `reviewers[reviewerId].error.message` on the returned result -- a rejection here can
// originate inside processDispatchOutcome's own scrubMappingStore.recall()/desubstituteFinding()
// calls, which process real reviewer-generated content, so the same reasoning applies: nothing
// proves this rejection's message is always content-free.
test('a content-bearing error thrown by scrubMappingStore.recall() (a post-dispatch rejection, not a dispatch-adapter throw) never reaches the halted result verbatim', async () => {
  const leakedFragment = 'the-actual-real-finding-text-that-must-never-leak';
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.gemini.error.code, 'DISPATCH_UNKNOWN');
    assert.ok(
      !result.reviewers.gemini.error.message.includes(leakedFragment),
      `per-reviewer halt message must not embed the raw rejection text, got: ${result.reviewers.gemini.error.message}`,
    );
  }, {
    scrubMappingStore: {
      async record() {},
      async recall() { throw new Error(`disk read failed near "${leakedFragment}"`); },
      async deleteMapping() {},
    },
  });
});

test('a lease past its expiry is rejected before any reservation is attempted', async () => {
  await withEngine(async ({ engine, advance }) => {
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'scope' });
    const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2, expiresAt: new Date(START + 5_000).toISOString() });
    advance(10_000);
    await assert.rejects(
      () => engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_EXPIRED',
    );
  });
});

test('source drift since preflight is rejected as a contract change, never dispatched', async () => {
  const dispatch = createOrderedFakeDispatch();
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { source_text: 'original text' });
    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'a different source entirely' }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTRACT_CHANGED',
    );
    assert.equal(dispatch.calls.length, 0);
  }, { dispatch });
});

// review() previously had no way to observe a changed reviewContext: it only
// ever re-hashed cached.reviewContext (the same string preflight() cached),
// so the contract recomputation could re-confirm source drift but could
// never actually detect context drift. review() now accepts an optional
// reviewContext so a caller can present the *current* context at review()
// time, exactly as source_text/source_path are already re-supplied fresh.
test('review context drift since preflight is rejected as a contract change, never dispatched', async () => {
  const dispatch = createOrderedFakeDispatch();
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { source_text: 'x', reviewContext: 'original scope' });
    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'x', reviewContext: 'a different scope entirely' }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTRACT_CHANGED',
    );
    assert.equal(dispatch.calls.length, 0);
  }, { dispatch });
});

// Omitting reviewContext at review() time must still behave exactly as
// before this fix: the cached (already-trusted) context is re-confirmed and
// the pair still dispatches and passes.
test('review() without an explicit reviewContext still re-confirms the cached context and passes', async () => {
  await withEngine(async ({ engine, fakeDispatch }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { source_text: 'x', reviewContext: 'engine test scope' });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');
    assert.deepEqual(fakeDispatch.calls.map((call) => call.reviewerId), ['gemini', 'grok']);
  });
});

test('approval denial cancels before any intent is formed: no lease, no dispatch', async () => {
  const dispatch = createOrderedFakeDispatch();
  const approval = createApprovingApproval({ outcome: 'DENIED' });
  await withEngine(async ({ engine }) => {
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'scope' });
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      (error) => error instanceof ReviewEngineError && error.code === 'APPROVAL_DENIED',
    );
    assert.equal(dispatch.calls.length, 0);
  }, { dispatch, approval });
});

test('approval timeout cancels before any intent is formed: no lease, no dispatch', async () => {
  const dispatch = createOrderedFakeDispatch();
  const approval = createApprovingApproval({ outcome: 'TIMED_OUT' });
  await withEngine(async ({ engine, leaseStore }) => {
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'scope' });
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      (error) => error instanceof ReviewEngineError && error.code === 'APPROVAL_TIMEOUT',
    );
    assert.equal(dispatch.calls.length, 0);
    assert.equal(await leaseStore.getLease('anything'), null);
  }, { dispatch, approval });
});

test('the installation hard maximum blocks authorization before the approval adapter is ever called', async () => {
  const approval = createApprovingApproval();
  await withEngine(async ({ engine }) => {
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'scope' });
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_CAP_EXCEEDED',
    );
    assert.equal(approval.calls.length, 0);
  }, { approval, installationHardMaximumUsd: 0.000001 });
});

// Authorization must use the selected (and, after restart, reconstructed) reviewer set.
// Spies delegate to the real store so absence of a lease is an exercised boundary.
async function withLeaseCountingEngine(run, options = {}) {
  let leaseCreates = 0;
  await withEngine((context) => run({ ...context, leaseCreates: () => leaseCreates }), {
    ...options,
    wrapLeaseStore: (store) => ({
      ...store,
      async createLease(input) { leaseCreates += 1; return store.createLease(input); },
    }),
  });
}

function authorizationObservation(outcome, { fakeApproval, fakeDispatch, leaseCreates }) {
  return {
    status: outcome.status,
    engineError: outcome.reason instanceof ReviewEngineError,
    code: outcome.reason?.code,
    message: outcome.reason?.message,
    details: outcome.reason?.details,
    approvals: fakeApproval.calls.length,
    leases: leaseCreates(),
    dispatches: fakeDispatch.calls.length,
  };
}

const profileCapacityCases = [
  { name: 'two reviewers refuse cap one', profile: 'consequential_spec_v1', count: 2, maxJobs: 1, reject: true },
  { name: 'two reviewers accept equality', profile: 'consequential_spec_v1', count: 2, maxJobs: 2 },
  { name: 'two reviewers preserve a greater cap', profile: 'consequential_spec_v1', count: 2, maxJobs: 3 },
  { name: 'final verification selects one reviewer', profile: 'final_verification_v1', changeKinds: [], count: 1, maxJobs: 1 },
  { name: 'final verification spend selects two reviewers', profile: 'final_verification_v1', changeKinds: ['spend'], count: 2, maxJobs: 1, reject: true },
  { name: 'three reviewers refuse cap two', profile: 'spec_review_free_v1', count: 3, maxJobs: 2, reject: true },
  { name: 'three reviewers accept equality', profile: 'spec_review_free_v1', count: 3, maxJobs: 3 },
  { name: 'three reviewers preserve a greater cap', profile: 'spec_review_free_v1', count: 3, maxJobs: 4 },
];
for (const row of profileCapacityCases) {
  test(`authorization capacity: ${row.name}`, async () => {
    await withLeaseCountingEngine(async (context) => {
      const { engine, fakeApproval, leaseStore, leaseCreates } = context;
      const preflight = await engine.preflight({ source_text: 'synthetic capacity document', profile: row.profile, changeKinds: row.changeKinds });
      assert.equal(preflight.reviewers.length, row.count);
      const [outcome] = await Promise.allSettled([engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: row.maxJobs })]);
      if (row.reject) {
        // All observations are collected before asserting, even when old code grants a lease.
        assert.deepEqual(authorizationObservation(outcome, context), {
          status: 'rejected', engineError: true, code: 'LEASE_CAP_EXCEEDED',
          message: `maxJobs (${row.maxJobs}) must be at least the preflight reviewer count (${row.count})`,
          details: { maxJobs: row.maxJobs, reviewerCount: row.count },
          approvals: 0, leases: 0, dispatches: 0,
        });
        const corrected = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: row.count });
        assert.equal(corrected.state, 'ACTIVE');
        assert.equal(corrected.maxJobs, row.count);
        assert.equal(leaseCreates(), 1);
        assert.equal(fakeApproval.calls.length, 1);
      } else {
        assert.equal(outcome.status, 'fulfilled');
        assert.equal(outcome.value.state, 'ACTIVE');
        assert.equal(outcome.value.maxJobs, row.maxJobs);
        assert.equal((await leaseStore.getLease(outcome.value.leaseId)).maxJobs, row.maxJobs);
        assert.equal(fakeApproval.calls.length, 1);
        assert.equal(fakeApproval.calls[0].request.maxJobs, row.maxJobs);
        assert.equal(leaseCreates(), 1);
      }
      assert.equal(context.fakeDispatch.calls.length, 0);
    });
  });
}

for (const [label, input] of [
  ['missing', undefined], ['null', null], ['zero', 0], ['negative', -1], ['fraction', 1.5],
  ['NaN', NaN], ['infinity', Infinity], ['string', '2'], ['unsafe integer', Number.MAX_SAFE_INTEGER + 1],
  ['coercible object', {}],
]) {
  test(`invalid maxJobs ${label} refuses before approval without coercion`, async () => {
    let coercions = 0;
    const maxJobs = label === 'coercible object'
      ? { [Symbol.toPrimitive]() { coercions += 1; throw new Error('must not coerce'); } }
      : input;
    await withLeaseCountingEngine(async (context) => {
      const preflight = await context.engine.preflight({ source_text: 'synthetic malformed cap', profile: 'consequential_spec_v1' });
      const [outcome] = await Promise.allSettled([context.engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs })]);
      assert.deepEqual({ ...authorizationObservation(outcome, context), coercions }, {
        status: 'rejected', engineError: true, code: 'CONTRACT_CHANGED',
        message: 'maxJobs must be a positive safe integer', details: undefined,
        approvals: 0, leases: 0, dispatches: 0, coercions: 0,
      });
    });
  });
}

for (const row of [
  { name: 'missing preflight', code: 'CONTRACT_CHANGED', message: 'preflight identity could not be verified (missing or expired)' },
  { name: 'expired preflight', code: 'CONTRACT_CHANGED', message: 'preflight identity could not be verified (missing or expired)' },
  { name: 'installation maximum', code: 'LEASE_CAP_EXCEEDED', message: 'requested amount exceeds the installation hard maximum' },
  { name: 'invalid requested expiry', code: 'CONTRACT_CHANGED', message: 'expiresAt must be an ISO timestamp' },
  { name: 'later requested expiry', code: 'CONTRACT_CHANGED', message: 'requested lease expiry exceeds the bound preflight expiry' },
]) {
  test(`authorization preserves ${row.name} precedence over malformed capacity`, async () => {
    await withLeaseCountingEngine(async (context) => {
      const preflight = await context.engine.preflight({ source_text: 'synthetic precedence document', profile: 'consequential_spec_v1' });
      const request = { preflightId: preflight.preflightId, maxJobs: 0 };
      if (row.name === 'missing preflight') request.preflightId = 'missing-preflight';
      if (row.name === 'expired preflight') context.advance(Date.parse(preflight.expiresAt) - START + 1);
      if (row.name === 'invalid requested expiry') request.expiresAt = 'invalid-date';
      if (row.name === 'later requested expiry') request.expiresAt = new Date(Date.parse(preflight.expiresAt) + 1_000).toISOString();
      const [outcome] = await Promise.allSettled([context.engine.authorizeWorkflow(request)]);
      assert.deepEqual(authorizationObservation(outcome, context), {
        status: 'rejected', engineError: true, code: row.code, message: row.message,
        details: undefined, approvals: 0, leases: 0, dispatches: 0,
      });
    }, row.name === 'installation maximum' ? { installationHardMaximumUsd: 0.000001 } : {});
  });
}

for (const row of [
  { profile: 'final_verification_v1', changeKinds: [], count: 1 },
  { profile: 'final_verification_v1', changeKinds: ['spend'], count: 2 },
  { profile: 'spec_review_free_v1', count: 3 },
]) {
  test(`restart reconstructs ${row.count} selected reviewers from the original preflight`, async () => {
    await withEngine(async (context) => {
      const { engine, ownerLock, dataRoot, fakeApproval, fakeDispatch } = context;
      const preflight = await engine.preflight({ source_text: 'synthetic restart document', profile: row.profile, changeKinds: row.changeKinds });
      assert.equal(preflight.reviewers.length, row.count);
      await ownerLock.release({ final: true });
      const freshStore = createLeaseStore({ dataRoot, clock: () => START });
      const freshOwner = await freshStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
      let leaseCreates = 0;
      try {
        const restarted = createReviewEngine({
          leaseStore: { ...freshStore, async createLease(input) { leaseCreates += 1; return freshStore.createLease(input); } },
          ownerLock: freshOwner, approvalAdapter: fakeApproval, dispatchAdapter: fakeDispatch,
          resultStore: context.resultStore, preflightContextStore: context.preflightContextStore,
          dispatchOutcomeStore: context.dispatchOutcomeStore, scrubMappingStore: context.scrubMappingStore,
          scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
          dispatchHealthStore: context.dispatchHealthStore, pendingHealthVerdictStore: context.pendingHealthVerdictStore,
          clock: () => START, sourcePolicy, preflightPolicy, installationHardMaximumUsd: 10,
          repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
        });
        if (row.count > 1) {
          const [outcome] = await Promise.allSettled([restarted.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: row.count - 1 })]);
          assert.deepEqual(authorizationObservation(outcome, { fakeApproval, fakeDispatch, leaseCreates: () => leaseCreates }), {
            status: 'rejected', engineError: true, code: 'LEASE_CAP_EXCEEDED',
            message: `maxJobs (${row.count - 1}) must be at least the preflight reviewer count (${row.count})`,
            details: { maxJobs: row.count - 1, reviewerCount: row.count },
            approvals: 0, leases: 0, dispatches: 0,
          });
        }
        const authorization = await restarted.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: row.count });
        assert.equal(authorization.state, 'ACTIVE');
        assert.equal(authorization.maxJobs, row.count);
        assert.equal(authorization.preflightId, preflight.preflightId);
        assert.equal(fakeApproval.calls.length, 1);
        assert.equal(leaseCreates, 1);
        assert.equal(fakeDispatch.calls.length, 0);
      } finally {
        await freshOwner.release({ final: true });
      }
    });
  });
}

test('a repeated review() call for an already-completed lease returns status and never redispatches', async () => {
  await withEngine(async ({ engine, fakeDispatch }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const first = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(first.state, 'PASSED');
    const callsAfterFirst = fakeDispatch.calls.length;

    const second = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(second.state, 'PASSED');
    assert.deepEqual(second.reviewers.gemini.advisory, first.reviewers.gemini.advisory);
    assert.deepEqual(second.reviewers.grok.advisory, first.reviewers.grok.advisory);
    assert.equal(fakeDispatch.calls.length, callsAfterFirst);
  });
});

// A cross-process repeat (fresh engine instance, no in-memory advisoryCache)
// must still recover the FULL advisory, not just state/cost, because the
// durable resultStore (unlike the in-memory advisoryCache) survives losing
// the process. This test drives two separate engine instances -- each with
// its own fresh preflightCache and advisoryCache -- against two separate
// createLeaseStore instances that both read the same on-disk dataRoot AND
// share the same on-disk resultStore, the way a real process restart would:
// the ledger and the result store both persist on disk, only the in-process
// caches are lost.
test('a cross-process repeat (fresh engine instance over the same on-disk ledger) recovers the full advisory and never redispatches', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-xproc-'));
  try {
    let now = START;
    const clock = () => now;
    const approval = createApprovingApproval();
    const resultStore = createResultStore({ dataRoot });
    const preflightContextStore = createPreflightContextStore({ dataRoot });
    const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    // Shared, on-disk, durable stores mirror how the ledger/result store
    // already model a restart -- only leaseStoreN/dispatchN/scrubEngineN are
    // given fresh, per-engine instances below (see the comment on engine2's
    // scrubEngine for why scrubEngine specifically must NOT be shared).
    const scrubMappingStore = createScrubMappingStore({ dataRoot });
    const engineOptions = {
      approvalAdapter: approval,
      resultStore,
      preflightContextStore,
      dispatchOutcomeStore,
      scrubMappingStore,
      clock,
      sourcePolicy,
      preflightPolicy,
      preflightTtlMs: 10 * 60 * 1000,
      installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    };

    const leaseStore1 = createLeaseStore({ dataRoot, clock });
    // A real ownerLock, acquired then explicitly released before leaseStore2 acquires its
    // own -- mirroring a genuine graceful restart (old process releases, new process acquires
    // fresh). Both leaseStore1/leaseStore2 run in this SAME test process, so isProcessAlive() would
    // see leaseStore2's own acquireProcessOwnership() attempt as contending against a "live" owner
    // (same real OS pid) forever if leaseStore1's own lock were never released first.
    const ownerLock1 = await leaseStore1.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const dispatch1 = createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
    const scrubEngine1 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine1 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore1, ownerLock: ownerLock1, dispatchAdapter: dispatch1, scrubEngine: scrubEngine1 });
    const { leaseId, preflightId } = await preflightAndAuthorize(engine1);
    const first = await engine1.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(first.state, 'PASSED');
    await ownerLock1.release();

    // "Restart": a brand-new leaseStore instance (re-reads the same on-disk
    // ledger from scratch) and a brand-new engine instance (empty
    // preflightCache and advisoryCache -- the only state a real restart
    // would actually lose). scrubEngine2 is likewise a FRESH instance, not
    // scrubEngine1 reused: scrub-engine.mjs's own mappingCache is in-process
    // only (see its module docstring), so reusing scrubEngine1 here would
    // silently paper over exactly the cross-process gap scrubMappingStore
    // (shared above, durable) exists to close.
    const leaseStore2 = createLeaseStore({ dataRoot, clock });
    const ownerLock2 = await leaseStore2.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const dispatch2 = createOrderedFakeDispatch();
    const scrubEngine2 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine2 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore2, ownerLock: ownerLock2, dispatchAdapter: dispatch2, scrubEngine: scrubEngine2 });
    // A fresh preflight() call under engine2 re-establishes a verifiable
    // preflight identity for the *same* reviewContractSha256 (the contract
    // depends only on source/context/profile/profileVersion, never on
    // preflightId), without ever redispatching or re-authorizing.
    const preflight2 = await engine2.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'engine test scope' });

    const second = await engine2.review({ leaseId, preflightId: preflight2.preflightId, source_text: 'x' });
    assert.equal(second.state, 'PASSED');
    assert.equal(second.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(second.reviewers.grok.costKind, 'KNOWN');
    assert.deepEqual(second.reviewers.gemini.advisory, { verdict: 'pass', findings: [] });
    assert.deepEqual(second.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
    assert.equal(dispatch2.calls.length, 0);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// A real MCP caller only ever holds the ORIGINAL preflightId returned by
// preflight() -- unlike the xproc test above, it cannot substitute a fresh
// one, because by the time it would notice getCachedPreflight() has gone
// stale (a CONTRACT_CHANGED from document()/review()), the human-approved
// lease is already durably bound to that original preflightId's
// reviewContractSha256. The host can replace its local stdio MCP server
// process in the (unavoidably slow, human-approval-gated) gap between
// authorizeWorkflow() succeeding and the very next document() call.
// These tests reproduce that exact shape -- fresh engine2 (empty
// preflightCache), but the SAME original preflightId, never a re-preflighted
// one -- and prove the durable fallback (leaseStore.getPreflight() +
// preflightContextStore) recovers it instead of throwing CONTRACT_CHANGED.
test('review() recovers using the ORIGINAL preflightId after a process restart, with reviewContext re-supplied', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-xproc-orig-id-'));
  try {
    let now = START;
    const clock = () => now;
    const approval = createApprovingApproval();
    const resultStore = createResultStore({ dataRoot });
    const preflightContextStore = createPreflightContextStore({ dataRoot });
    const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    const scrubMappingStore = createScrubMappingStore({ dataRoot });
    const engineOptions = {
      approvalAdapter: approval, resultStore, preflightContextStore, dispatchOutcomeStore, scrubMappingStore, clock,
      sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    };

    const leaseStore1 = createLeaseStore({ dataRoot, clock });
    // A real ownerLock, released before leaseStore2 acquires its own -- see the sibling xproc
    // test's own comment above for why (both leaseStores run in this same test process, so a second
    // acquireProcessOwnership() would otherwise contend against a "live" owner forever).
    // authorizeWorkflow() below genuinely calls leaseStore.createLease(), so engine1 needs a real,
    // currently-valid acquisitionId, not merely a shape-valid one.
    const ownerLock1 = await leaseStore1.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const dispatch1 = createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
    const scrubEngine1 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine1 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore1, ownerLock: ownerLock1, dispatchAdapter: dispatch1, scrubEngine: scrubEngine1 });
    const { leaseId, preflightId } = await preflightAndAuthorize(engine1, { reviewContext: 'original context text' });
    await ownerLock1.release();

    // "Restart" right after authorizeWorkflow() succeeded, before review() is
    // ever called -- the gap described above. engine2 has
    // never seen this preflightId; leaseStore2 independently re-reads the
    // same on-disk ledger, and scrubEngine2 is a fresh instance (empty
    // in-process mappingCache) for the same reason as the sibling xproc test
    // above. This is engine2's FIRST real review() call for this lease, so it
    // genuinely dispatches and reconciles both reviewers -- needs its own real ownerLock too.
    const leaseStore2 = createLeaseStore({ dataRoot, clock });
    const ownerLock2 = await leaseStore2.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const dispatch2 = createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
    const scrubEngine2 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine2 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore2, ownerLock: ownerLock2, dispatchAdapter: dispatch2, scrubEngine: scrubEngine2 });

    const result = await engine2.review({ leaseId, preflightId, source_text: 'x', reviewContext: 'original context text' });
    assert.equal(result.state, 'PASSED');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// Same restart shape, but reviewContext OMITTED at review()-time -- the
// majority-case usage every other test in this file already relies on
// (preflightAndAuthorize's callers mostly never re-supply it). This is what
// actually exercises the new preflightContextStore fallback specifically:
// without it, cached.reviewContext would be undefined post-restart and
// review() would throw SOURCE_INVALID, not recover.
test('review() recovers using the ORIGINAL preflightId after a process restart, with reviewContext OMITTED (durable context recovery)', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-xproc-orig-id-noctx-'));
  try {
    let now = START;
    const clock = () => now;
    const approval = createApprovingApproval();
    const resultStore = createResultStore({ dataRoot });
    const preflightContextStore = createPreflightContextStore({ dataRoot });
    const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    const scrubMappingStore = createScrubMappingStore({ dataRoot });
    const engineOptions = {
      approvalAdapter: approval, resultStore, preflightContextStore, dispatchOutcomeStore, scrubMappingStore, clock,
      sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    };

    const leaseStore1 = createLeaseStore({ dataRoot, clock });
    // See the sibling "reviewContext re-supplied" test's own comment above for why a real
    // ownerLock (released before leaseStore2 acquires its own) is needed here.
    const ownerLock1 = await leaseStore1.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const dispatch1 = createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
    const scrubEngine1 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine1 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore1, ownerLock: ownerLock1, dispatchAdapter: dispatch1, scrubEngine: scrubEngine1 });
    const { leaseId, preflightId } = await preflightAndAuthorize(engine1, { reviewContext: 'original context text' });
    await ownerLock1.release();

    const leaseStore2 = createLeaseStore({ dataRoot, clock });
    const ownerLock2 = await leaseStore2.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const dispatch2 = createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
    const scrubEngine2 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine2 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore2, ownerLock: ownerLock2, dispatchAdapter: dispatch2, scrubEngine: scrubEngine2 });

    // No reviewContext here -- must fall back to the durably-recovered value.
    const result = await engine2.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// authorizeWorkflow() itself calls getCachedPreflight() first, so a restart
// between preflight() and authorizeWorkflow() (the same code path) must
// recover too, from the durable
// ledger preflight record alone -- authorizeWorkflow() never touches
// reviewContext, so this must work even with an empty preflightContextStore.
test('authorizeWorkflow() recovers a preflight identity after a process restart, using only the durable ledger (no reviewContext needed)', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-xproc-authorize-'));
  try {
    let now = START;
    const clock = () => now;
    const approval = createApprovingApproval();
    const resultStore = createResultStore({ dataRoot });
    const preflightContextStore = createPreflightContextStore({ dataRoot });
    const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    const scrubMappingStore = createScrubMappingStore({ dataRoot });
    const engineOptions = {
      approvalAdapter: approval, resultStore, preflightContextStore, dispatchOutcomeStore, scrubMappingStore, dispatchAdapter: createOrderedFakeDispatch(), clock,
      sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    };

    const leaseStore1 = createLeaseStore({ dataRoot, clock });
    // engine1 only ever calls preflight() below, which is NOT owner-sensitive (see
    // lease-store.mjs's createPreflight() -- no assertCurrentlyOwnsProcess call), so a merely
    // shape-valid fake ownerLock is sufficient here; engine2 genuinely calls authorizeWorkflow()'s
    // createLease(), so it needs a REAL ownerLock acquired against its own leaseStore2 instead (no
    // release/reacquire dance needed since engine1 never acquired real ownership to begin with).
    const scrubEngine1 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine1 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore1, ownerLock: createFakeOwnerLock(), scrubEngine: scrubEngine1 });
    const preflight = await engine1.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'ctx' });

    const leaseStore2 = createLeaseStore({ dataRoot, clock });
    const ownerLock2 = await leaseStore2.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const scrubEngine2 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine2 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore2, ownerLock: ownerLock2, scrubEngine: scrubEngine2 });
    const authorization = await engine2.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    assert.equal(authorization.state, 'ACTIVE');
    assert.equal(authorization.requestedUsd, preflight.requestedUsd);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// An expired preflight must stay unrecoverable through the durable fallback
// too, not just the in-memory one -- otherwise the fix would silently widen
// how long a preflight identity stays usable. Exercised via authorizeWorkflow()
// specifically: no lease exists yet at that point, so getCachedPreflight()'s
// own expiry check is what's actually reached first (a lease can never
// outlive its bound preflight's expiry -- lease-store.mjs's createLease()
// enforces that -- so this scenario can never arise inside review() itself).
test('authorizeWorkflow() still reports CONTRACT_CHANGED for a preflight recovered from the durable ledger but already past its own expiresAt', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-xproc-expired-'));
  try {
    let now = START;
    const clock = () => now;
    const approval = createApprovingApproval();
    const resultStore = createResultStore({ dataRoot });
    const preflightContextStore = createPreflightContextStore({ dataRoot });
    const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    const scrubMappingStore = createScrubMappingStore({ dataRoot });
    const engineOptions = {
      approvalAdapter: approval, resultStore, preflightContextStore, dispatchOutcomeStore, scrubMappingStore, dispatchAdapter: createOrderedFakeDispatch(), clock,
      sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    };

    const leaseStore1 = createLeaseStore({ dataRoot, clock });
    // engine1 only calls preflight() (not owner-sensitive) -- a fake ownerLock suffices.
    // engine2's authorizeWorkflow() call is expected to throw CONTRACT_CHANGED at the expiry check
    // inside getCachedPreflight(), BEFORE ever reaching createLease() -- but it gets a real ownerLock
    // anyway rather than relying on that ordering never changing.
    const scrubEngine1 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine1 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore1, ownerLock: createFakeOwnerLock(), scrubEngine: scrubEngine1 });
    const preflight = await engine1.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'ctx' });

    now += Date.parse(preflight.expiresAt) - START + 1_000;

    const leaseStore2 = createLeaseStore({ dataRoot, clock });
    const ownerLock2 = await leaseStore2.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const scrubEngine2 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine2 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore2, ownerLock: ownerLock2, scrubEngine: scrubEngine2 });
    await assert.rejects(
      () => engine2.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTRACT_CHANGED',
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// An oversized preflightId on the durable
// fallback path would otherwise hit leaseStore.getPreflight()'s own
// requireId() and throw a raw TypeError instead of a clean CONTRACT_CHANGED.
// Never reachable via the real MCP tool schema (which caps this the same
// way), but a direct engine caller must still get a consistent error shape.
test('an oversized preflightId is reported as a contract change, not a raw TypeError, even under a valid lease', async () => {
  await withEngine(async ({ engine, fakeDispatch }) => {
    const { leaseId } = await preflightAndAuthorize(engine);
    await assert.rejects(
      () => engine.review({ leaseId, preflightId: 'x'.repeat(257), source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTRACT_CHANGED',
    );
    assert.equal(fakeDispatch.calls.length, 0);
  });
});

// review()'s own ordering checks leaseId before preflightId (see the two
// guard clauses at the top of review()), so a call with BOTH ids unknown can
// only ever prove the leaseId check -- it can never reach, and therefore
// never proves, the preflightId/CONTRACT_CHANGED branch. This test is
// deliberately scoped to that leaseId-first priority only; the sibling test
// below ("an unknown preflight ID is reported as a contract change even
// under a valid lease") is what actually exercises the preflightId path,
// using a genuinely valid leaseId so the leaseId guard cannot short-circuit
// it.
test('an unknown lease ID is reported as missing even when the preflight ID is also unknown', async () => {
  await withEngine(async ({ engine }) => {
    await assert.rejects(
      () => engine.review({ leaseId: 'no-such-lease', preflightId: 'no-such-preflight', source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING',
    );
    await assert.rejects(
      () => engine.status({ leaseId: 'no-such-lease' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING',
    );
  });
});

test('an unknown preflight ID is reported as a contract change even under a valid lease', async () => {
  await withEngine(async ({ engine, fakeDispatch }) => {
    const { leaseId } = await preflightAndAuthorize(engine);
    await assert.rejects(
      () => engine.review({ leaseId, preflightId: 'no-such-preflight', source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTRACT_CHANGED',
    );
    assert.equal(fakeDispatch.calls.length, 0);
  });
});

test('review() rejects when neither source_text nor source_path is supplied', async () => {
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    await assert.rejects(
      () => engine.review({ leaseId, preflightId }),
      (error) => error instanceof ReviewEngineError && error.code === 'SOURCE_INVALID',
    );
  });
});

test('status() reports the redacted lease ledger view without exposing raw source or bodies', async () => {
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    await engine.review({ leaseId, preflightId, source_text: 'x' });
    const reported = await engine.status({ leaseId });
    assert.equal(reported.leaseId, leaseId);
    assert.equal(reported.state, 'ACTIVE');
    assert.equal(reported.jobsConsumed, 2);
    assert.equal(reported.spentUsd > 0, true);
    assert.doesNotMatch(JSON.stringify(reported), /sourceText|requestBody|responseBody|apiKey/i);
  });
});

// ---------------------------------------------------------------------------
// Orphan recovery. A lease can be left permanently ACTIVE with a RESERVED,
// never-reconciled job when the process that reserved it is replaced (crash
// or host reconnect) before it can call reconcile() -- and the other
// recovery path (the `existingJob` check inside review()'s own loop, below)
// depends on the in-memory preflightCache, which a process restart always
// empties, so review() would never even reach that check again: it would
// throw CONTRACT_CHANGED at the getCachedPreflight() step first. These tests simulate that exact
// scenario without needing a real process restart: they reserve a job
// directly via leaseStore.consume() (standing in for "some earlier call
// reserved this and vanished before reconciling") and never resolve it via
// dispatch, then call review() again.
//
// A real restart would ALSO empty the preflightCache; these tests don't
// reconstruct that separately because review()'s expiry-recovery check
// (see review-engine.mjs) runs strictly before getCachedPreflight() in
// review()'s existing code order -- so it is reached (and must succeed)
// regardless of whether the cache still has this preflightId, which is the
// property that makes recovery work across a real restart.

async function reserveOrphanedJob(engine, leaseStore, ownerLock, { leaseId, preflightId, reviewContractSha256, reservationUsd, jobId, reviewerId }) {
  // authorizeWorkflow() releases process ownership when it completes, so acquire real ownership for
  // this direct setup mutation; retaining it until the next engine call preserves these tests'
  // explicit inline-recovery path.
  await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
  return leaseStore.consume(leaseId, reviewContractSha256, { reservationUsd, jobId, reviewerId, acquisitionId: ownerLock.acquisitionId });
}

// Deliberately re-derives the same jobId formula review-engine.mjs's own
// private deriveJobId() uses, rather than importing it (not exported --
// review-engine.mjs's public surface is preflight/authorizeWorkflow/status/
// review/result/recoverOrphanedLeases only). A future change to that formula
// would make the review() loop fail to find the job these tests reserve
// under this ID, causing an unexpected real dispatch instead of a silent
// false pass -- so drift here fails loudly, not quietly.
function testDeriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Durable dispatch-outcome recovery. Treating every RESERVED-but-never-
// reconciled job as truly unknowable would always charge its worst-case
// cost with no content -- but the dispatch script can itself complete a
// real OpenRouter call and still lose the response if its Node caller gets
// replaced first. These tests simulate that exact shape: reserve
// a job directly (standing in for "a previous review() call got this far and
// vanished before dispatch() ever returned to it"), plant a durable outcome
// fixture at the SAME path the real dispatch script writes to, and call
// review() again on the SAME still-ACTIVE lease (deliberately not expired --
// this exercises the existingJob/RESERVED branch directly, not the separate
// expired-lease/orphan-sweep recovery path the tests above cover).
test('a durably-captured RESPONSE outcome for a RESERVED job recovers full content and never redispatches that reviewer', async () => {
  // Gemini's dispatch is recovered from the durable fixture below, never
  // actually called -- so the fake dispatch queue must hold ONLY grok's
  // response. The shared fixture's default two-item queue (gemini, then
  // grok) would otherwise hand grok gemini's response by FIFO order once
  // gemini's own call never happens, causing a spurious PROVIDER_MISMATCH.
  const dispatch = createOrderedFakeDispatch({ responses: [responseFor(grokPassBody())] });
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, fakeDispatch }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId,
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({
        httpStatus: 200,
        bodyBase64: Buffer.from(JSON.stringify(geminiPassBody([{ severity: 'minor', section: 'x', root_cause: 'y', affected_behavior: 'z', consequence: 'w', evidence: ['e'] }])), 'utf8').toString('base64'),
      }),
    });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.gemini.costUsd, 0.01);
    assert.deepEqual(result.reviewers.gemini.advisory.findings.length, 1);
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    // The dispatch fake's own `calls` log (see createOrderedFakeDispatch)
    // records only reviewers actually sent to dispatchAdapter.dispatch() --
    // gemini must never appear in it, only grok (the one reviewer that
    // genuinely had no prior reservation and needed a real dispatch).
    assert.deepEqual(fakeDispatch.calls.map((call) => call.reviewerId), ['grok']);

    const lease = await leaseStore.getLease(leaseId);
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(Math.round(lease.spentUsd * 1000), Math.round(0.03 * 1000));
  }, { dispatch });
});

test('a durably-captured FAILURE outcome for a RESERVED job halts at zero cost and is never redispatched, while an untouched reviewer still dispatches', async () => {
  const dispatch = createOrderedFakeDispatch({ responses: [responseFor(grokPassBody())] });
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, fakeDispatch }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId,
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'FAILURE',
      envelopeJsonText: JSON.stringify({ failureKind: 'TIMEOUT', message: 'the request did not complete before the deadline' }),
    });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'TRANSPORT_FAILURE');
    // A recovered FAILURE outcome runs through the exact same processDispatchOutcome pipeline a
    // live one always used, so it gets the same zero-cost reconciliation, not a shortcut.
    assert.equal(result.reviewers.gemini.costKind, 'ZERO_ON_TRANSPORT_FAILURE');
    assert.equal(result.reviewers.gemini.costUsd, 0);
    // The invariant that actually matters here is that GEMINI is never redispatched -- grok has no
    // prior reservation of its own and is not cancelled by gemini's halt.
    assert.deepEqual(fakeDispatch.calls.map((call) => call.reviewerId), ['grok']);
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');

    const lease = await leaseStore.getLease(leaseId);
    assert.equal(lease.state, 'TRANSPORT_FAILURE');
    assert.equal(lease.spentUsd, 0.02, 'only grok spent anything; gemini reconciled at a proven zero');
    assert.equal(lease.reservedUsd, 0);
  }, { dispatch });
});

// The Node process can be killed/replaced BEFORE it ever spawns
// tools/openrouter-review-dispatch.ps1, leaving a request file on disk but
// no dispatch-outcomes/ entry at all. That means "no durable capture at all"
// for a RESERVED job is NOT the same ambiguous state as "a dispatch was
// attempted and its outcome is unknown" -- it PROVES
// dispatchAdapter.dispatch() was never invoked for this jobId
// (dispatch-outcome-store.mjs's markDispatching() is written durably,
// before execute() is ever called, specifically so this distinction is
// provable). No marker at all means zero risk of a duplicate OpenRouter
// call, so review() safely redispatches using the EXISTING reservation
// instead of charging worst-case for nothing. The genuinely ambiguous case
// (a DISPATCHING marker present but no resolved outcome) is covered
// separately below and keeps the conservative behavior.
test('a RESERVED job with NO marker at all (dispatch never attempted) safely redispatches using the existing reservation, never re-reserving', async () => {
  // Grok is resolved via an already-durably-captured RESPONSE (the SAME
  // mechanism the "durably-captured RESPONSE" test above uses), so it never
  // needs a fresh dispatch call -- isolating this test to prove exactly one
  // thing: gemini's RESERVED-with-no-marker job safely redispatches. The
  // fake queue holds exactly one response, for that one real call; if grok
  // were ALSO dispatched fresh (a bug), it would consume this same queued
  // gemini-shaped response and fail with PROVIDER_MISMATCH instead.
  const dispatch = createOrderedFakeDispatch({ responses: [responseFor(geminiPassBody())] });
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, fakeDispatch }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId,
    });
    // Deliberately no writeDispatchOutcomeFixture call for gemini at all --
    // not even a DISPATCHING marker -- standing in for "dispatchAdapter.
    // dispatch() was never invoked for this reservation."

    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: grokMaxUsd, jobId: grokJobId,
    });
    await writeDispatchOutcomeFixture(dataRoot, grokJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody()), 'utf8').toString('base64') }),
    });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.equal(result.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(result.reviewers.gemini.costUsd, 0.01);
    assert.equal(result.reviewers.grok.state, 'RECONCILED');
    // Exactly one real dispatch call, for gemini's safe redispatch -- never
    // a second leaseStore.consume() for it either (which would throw on a
    // jobId already RESERVED, so the test passing at all proves that too).
    assert.deepEqual(fakeDispatch.calls.map((call) => call.reviewerId), ['gemini']);

    const lease = await leaseStore.getLease(leaseId);
    assert.equal(lease.state, 'ACTIVE');
  }, { dispatch });
});

test('a RESERVED job with a DISPATCHING marker but no resolved outcome still halts at worst-case cost and is never redispatched, while an untouched reviewer still dispatches -- and defers its dispatch-health verdict instead of recording an immediate failure', async () => {
  const dispatch = createOrderedFakeDispatch({ responses: [responseFor(grokPassBody())] });
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, fakeDispatch, dispatchHealthStore, pendingHealthVerdictStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, { kind: 'DISPATCHING' });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);
    assert.deepEqual(fakeDispatch.calls.map((call) => call.reviewerId), ['grok'], 'a DISPATCHING marker with no resolved outcome must never trigger a redispatch of gemini');
    assert.equal((await leaseStore.getLease(leaseId)).state, 'DISPATCH_UNKNOWN');

    const healthState = await dispatchHealthStore.recall();
    assert.equal(healthState.consecutiveFailures, 0, 'ambiguousDispatching must not record an immediate health failure -- it defers to the sweep');
    const pending = await pendingHealthVerdictStore.recall({ jobId: geminiJobId });
    assert.ok(pending, 'a pending-verdict record must exist for the ambiguously-closed job');
    assert.equal(pending.reviewerId, 'gemini');
    assert.equal(pending.reservationUsd, geminiMaxUsd);
  }, { dispatch });
});

// Deliberately makes BOTH reviewers ambiguous (RESERVED + a DISPATCHING marker, no resolved
// outcome), rather than reusing the mixed gemini-ambiguous/grok-dispatches-fresh shape the two
// tests above use: a fresh, successfully-dispatched reviewer in the SAME concurrent batch calls
// recordDispatchHealthOutcome({succeeded:true}), which -- by the documented, accepted race in
// serializedDispatchHealthAccess's own docstring above (an accepted production trade-off, not a
// bug: a SUCCESS and a FAILURE racing in the same Step 3 batch) -- can reset the very counter this test means to observe, depending on which of the
// two concurrent tasks happens to finish last. With no successful reviewer anywhere in the batch,
// the final consecutiveFailures count is deterministic regardless of task-completion order.
test('when the pending-verdict write itself fails, ambiguousDispatching falls back to recording an immediate health failure', async () => {
  const neverDispatch = { async dispatch() { throw new Error('must never be called -- both reviewers are already ambiguous RESERVED jobs, no fresh dispatch expected'); } };
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, dispatchHealthStore }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, { kind: 'DISPATCHING' });

    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: grokMaxUsd, jobId: grokJobId, reviewerId: 'grok',
    });
    await writeDispatchOutcomeFixture(dataRoot, grokJobId, { kind: 'DISPATCHING' });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(result.reviewers.grok.costKind, 'UNKNOWN_WORST_CASE_CHARGED');

    const healthState = await dispatchHealthStore.recall();
    assert.equal(healthState.consecutiveFailures, 2, 'a pending-write failure must fall back to recording the failure immediately, never silently dropping the signal, for each ambiguous reviewer');
  }, {
    dispatch: neverDispatch,
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async record() { throw new Error('simulated disk failure'); },
    }),
  });
});

test('a redispatch attempt (no marker at all) that itself throws is treated as an unknown outcome, not a crash', async () => {
  const dispatch = { async dispatch() { throw new Error('ECONNRESET'); } };
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId,
    });

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'DISPATCH_UNKNOWN');
    assert.equal(result.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(result.reviewers.gemini.costUsd, geminiMaxUsd);

    const lease = await leaseStore.getLease(leaseId);
    assert.equal(lease.state, 'DISPATCH_UNKNOWN');
  }, { dispatch });
});

test('review() re-entered on an already-expired lease with a stale RESERVED job recovers it instead of throwing', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, advance }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: 0.18, jobId: 'orphan-job',
    });

    advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'LEASE_EXPIRED');
    assert.equal(result.recoveredJobs.length, 1);
    assert.equal(result.recoveredJobs[0].id, 'orphan-job');
    assert.equal(result.recoveredJobs[0].costUsd, 0.18);

    const closedLease = await leaseStore.getLease(leaseId);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
    assert.equal(closedLease.spentUsd, 0.18);
  });
});

test('review() still throws a plain LEASE_EXPIRED (no recovery) for an expired lease with a RESERVED job still inside the grace window', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, advance }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: 0.18, jobId: 'maybe-still-inflight',
    });

    // Past expiresAt, but well inside the default 2-minute grace window.
    advance((Date.parse(lease.expiresAt) - START) + 5_000);

    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_EXPIRED',
    );
    assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE', 'must not be closed while still inside the grace window');
  });
});

test('engine.recoverOrphanedLeases() sweeps every eligible expired lease in the store without needing a specific leaseId', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, advance }) => {
    const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId: orphan.leaseId, preflightId: orphan.preflightId,
      reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: 0.12, jobId: 'sweep-me',
    });
    const orphanLease = await leaseStore.getLease(orphan.leaseId);

    advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.equal(swept.length, 1);
    assert.equal(swept[0].leaseId, orphan.leaseId);
    assert.equal((await leaseStore.getLease(orphan.leaseId)).state, 'ORPHANED_ON_RECOVERY');
  });
});

// ---------------------------------------------------------------------------
// Orphan recovery at REAL cost, not worst-case. A real, already-completed
// OpenRouter dispatch (real content generated, real tokens billed) must not
// be reconciled through a sweepOrphanedLeases()-only recovery path at its
// full worst-case reservation with its real advisory content never persisted
// anywhere recoverable. These tests plant a durably-captured outcome (the
// same dispatch-outcomes/<jobId>.json fixture the "Durable dispatch-outcome
// recovery" tests above use) for a job that is ALSO stale/expired, so
// recovery goes through recoverStaleLease()'s pre-pass instead of -- or
// alongside -- the conservative worst-case fallback every test above this
// point still exercises (none of them ever write a dispatch-outcome fixture
// for their orphaned job).
// ---------------------------------------------------------------------------

test('review() re-entered on an already-expired lease with a durably-captured REAL RESPONSE outcome recovers it at its real cost and real content, not worst-case', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, resultStore, advance }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({
        httpStatus: 200,
        bodyBase64: Buffer.from(JSON.stringify(geminiPassBody([{ severity: 'minor', section: 'x', root_cause: 'y', affected_behavior: 'z', consequence: 'w', evidence: ['e'] }])), 'utf8').toString('base64'),
      }),
    });

    advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'LEASE_EXPIRED');
    assert.equal(result.recoveredJobs.length, 1);
    // The real captured cost from geminiPassBody's usage.cost (0.01), never the reserved
    // worst-case ceiling geminiMaxUsd.
    assert.notEqual(geminiMaxUsd, 0.01, 'the test fixture must actually distinguish real cost from worst-case, or this assertion proves nothing');
    assert.equal(result.recoveredJobs[0].costUsd, 0.01);
    assert.equal(result.recoveredJobs[0].costKind, 'KNOWN');

    const closedLease = await leaseStore.getLease(leaseId);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
    assert.equal(closedLease.spentUsd, 0.01, 'the ledger itself must show the real cost, not the worst-case reservation');

    // The real advisory content -- not just its cost -- must also be recoverable, not lost, both
    // directly through resultStore and through the public result() recovery path.
    const recalled = await resultStore.recall({ jobId: geminiJobId });
    assert.equal(recalled.costKind, 'KNOWN');
    assert.equal(recalled.advisory.findings.length, 1);

    const recoveredResult = await engine.result({ leaseId });
    assert.equal(recoveredResult.reviewers.gemini.costKind, 'KNOWN');
    assert.equal(recoveredResult.reviewers.gemini.advisory.findings.length, 1);
  });
});

test('engine.recoverOrphanedLeases() recovers a durably-captured REAL RESPONSE outcome at its real cost across the whole store, not worst-case', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
    const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
    const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
    const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId: orphan.leaseId, preflightId: orphan.preflightId,
      reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
      jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
    });
    const orphanLease = await leaseStore.getLease(orphan.leaseId);

    advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.equal(swept.length, 1);
    assert.equal(swept[0].leaseId, orphan.leaseId);
    assert.equal(swept[0].reconciledJobs.length, 1);
    assert.equal(swept[0].reconciledJobs[0].costUsd, 0.01);
    assert.equal(swept[0].reconciledJobs[0].costKind, 'KNOWN');
    const closedLease = await leaseStore.getLease(orphan.leaseId);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
    assert.equal(closedLease.spentUsd, 0.01);
  });
});

test('a lease with two stale jobs -- one with a real captured RESPONSE, one with only a DISPATCHING marker -- recovers the real one at its real cost and the ambiguous one at worst-case, reported together in one entry', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);

    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
    });

    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: grokMaxUsd, jobId: grokJobId, reviewerId: 'grok',
    });
    await writeDispatchOutcomeFixture(dataRoot, grokJobId, { kind: 'DISPATCHING' });

    advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.equal(swept.length, 1);
    assert.equal(swept[0].leaseId, leaseId);
    assert.equal(swept[0].reconciledJobs.length, 2, 'both jobs -- the real recovery and the worst-case fallback -- must be reported together, not split across two entries');
    const geminiEntry = swept[0].reconciledJobs.find((job) => job.id === geminiJobId);
    const grokEntry = swept[0].reconciledJobs.find((job) => job.id === grokJobId);
    assert.equal(geminiEntry.costKind, 'KNOWN');
    assert.equal(geminiEntry.costUsd, 0.01);
    assert.equal(grokEntry.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(grokEntry.costUsd, grokMaxUsd);

    const closedLease = await leaseStore.getLease(leaseId);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
    assert.equal(Math.round(closedLease.spentUsd * 1000), Math.round((0.01 + grokMaxUsd) * 1000));
  });
});

test('a durably-captured FAILURE outcome on a stale RESERVED job recovers through orphan-sweep at the exact same zero-cost/worst-case rules review()\'s live existingJob path already applies -- proving the same processDispatchOutcome pipeline, not a special-cased shortcut', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
    const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
    const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
    const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId: orphan.leaseId, preflightId: orphan.preflightId,
      reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
      jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'FAILURE',
      envelopeJsonText: JSON.stringify({ failureKind: 'TIMEOUT', message: 'the request did not complete before the deadline' }),
    });
    const orphanLease = await leaseStore.getLease(orphan.leaseId);

    advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.equal(swept.length, 1);
    // TIMEOUT is a ZERO_COST_TRANSPORT_FAILURE_KINDS entry -- same rule review-engine.mjs's
    // processDispatchOutcome already applies to a live TRANSPORT_FAILURE.
    assert.equal(swept[0].reconciledJobs[0].costUsd, 0);
    assert.equal(swept[0].reconciledJobs[0].costKind, 'ZERO_ON_TRANSPORT_FAILURE');
    assert.equal((await leaseStore.getLease(orphan.leaseId)).state, 'ORPHANED_ON_RECOVERY');
  });
});

// A captured outcome which HALTS (e.g. PROVIDER_MISMATCH) inside the pre-pass must not close the
// whole lease, which would strand any LATER stale job on the same lease permanently RESERVED (both
// the pre-pass's own lease-ACTIVE guard and sweepOrphanedLeases() would then skip it).
// haltAndClose() only reconciles the job -- closing the lease is EXCLUSIVELY
// finalizeReviewOutcome()'s job in a live review() call, and recoverStaleLease() never calls that at
// all, closing leases itself only in its own explicit close-loop once every stale job is resolved.
// This test locks that in as a regression guard.
test('a HALTing captured outcome (e.g. PROVIDER_MISMATCH) processed by the pre-pass does not close the lease early, so a LATER stale job on the same lease still recovers correctly', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);

    // gemini is processed FIRST by the pre-pass (reserved first, and findStaleReservedJobs/Map
    // iteration preserves insertion order) and its captured outcome HALTS on PROVIDER_MISMATCH.
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({
        httpStatus: 200,
        bodyBase64: Buffer.from(JSON.stringify({ provider: 'NotGoogle', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.01 } }), 'utf8').toString('base64'),
      }),
    });

    // grok is processed SECOND, with a captured outcome that PASSES cleanly.
    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: grokMaxUsd, jobId: grokJobId, reviewerId: 'grok',
    });
    await writeDispatchOutcomeFixture(dataRoot, grokJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody()), 'utf8').toString('base64') }),
    });

    advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.equal(swept.length, 1);
    assert.equal(swept[0].reconciledJobs.length, 2, 'grok must not be stranded RESERVED just because gemini, processed earlier in the same pre-pass, halted');
    const geminiEntry = swept[0].reconciledJobs.find((job) => job.id === geminiJobId);
    const grokEntry = swept[0].reconciledJobs.find((job) => job.id === grokJobId);
    assert.equal(geminiEntry.state, 'RECONCILED');
    assert.equal(geminiEntry.costKind, 'KNOWN');
    assert.equal(geminiEntry.costUsd, 0.01);
    // grok must be recovered at its REAL cost from the pre-pass, not the worst-case fallback --
    // proving the pre-pass actually reached it rather than the lease already having been closed.
    assert.equal(grokEntry.state, 'RECONCILED');
    assert.equal(grokEntry.costKind, 'KNOWN');
    assert.equal(grokEntry.costUsd, 0.02);

    const closedLease = await leaseStore.getLease(leaseId);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
  });
});

// A client-side timeout can race a server-side recovery already in progress, so concurrent sweeps
// against the same stale lease are pinned here as a regression test.
test('two concurrent orphan-recovery sweeps against the same stale lease never double-charge a job or corrupt the lease, even when one job has a real captured outcome and another does not', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);

    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
    });

    const grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: grokMaxUsd, jobId: grokJobId, reviewerId: 'grok',
    });
    // Deliberately no dispatch-outcome fixture at all for grok -- exercises the worst-case
    // fallback concurrently with the real-cost pre-pass resolving gemini.

    advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const results = await Promise.all([
      engine.recoverOrphanedLeases(), engine.recoverOrphanedLeases(), engine.recoverOrphanedLeases(),
    ]);
    assert.equal(results.every(Array.isArray), true, 'no concurrent sweep call should throw');

    const closedLease = await leaseStore.getLease(leaseId);
    assert.equal(closedLease.state, 'ORPHANED_ON_RECOVERY');
    // Each job reconciled EXACTLY once, at its correct real/worst-case cost -- never double-charged
    // by two racing sweeps both trying to reconcile the same RESERVED job (reconcile() throws for a
    // job no longer RESERVED, and the pre-pass/fallback both catch that rather than letting a second
    // charge through).
    assert.equal(Math.round(closedLease.spentUsd * 1_000_000), Math.round((0.01 + grokMaxUsd) * 1_000_000));
    const geminiJob = await leaseStore.getJob(geminiJobId);
    const grokJob = await leaseStore.getJob(grokJobId);
    assert.equal(geminiJob.state, 'RECONCILED');
    assert.equal(geminiJob.costUsd, 0.01);
    assert.equal(geminiJob.costKind, 'KNOWN');
    assert.equal(grokJob.state, 'RECONCILED');
    assert.equal(grokJob.costUsd, grokMaxUsd);
    assert.equal(grokJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
  });
});

// The explicit close-loop's catch block must
// tell "already closed" (expected -- someone else already closed this lease) apart from a genuinely
// unexpected close() failure (a disk I/O error, a lock timeout) -- the latter would otherwise leave
// every job on the lease already reconciled at real money with no money or content at risk, but the
// lease record itself stuck ACTIVE forever with nothing left to ever recover it through. Mirrors
// the resultStore.record()-failure test above: a durable-write failure here must stay visible on
// stderr, never silently swallowed, even though it cannot be allowed to abort the recovery itself.
test('a close() failure that PERSISTS across the retry is logged loudly to stderr and leaves the reconciled job recoverable, rather than being silently swallowed', async () => {
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  let closeAttempts = 0;

  try {
    await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
      const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
      const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
      const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
      await reserveOrphanedJob(engine, leaseStore, ownerLock, {
        leaseId: orphan.leaseId, preflightId: orphan.preflightId,
        reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
        jobId: geminiJobId, reviewerId: 'gemini',
      });
      await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
        kind: 'RESPONSE',
        envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
      });
      const orphanLease = await leaseStore.getLease(orphan.leaseId);
      advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

      const swept = await engine.recoverOrphanedLeases();

      assert.equal(closeAttempts, 2, 'both retry attempts must actually run');
      assert.equal(swept.length, 0, 'a lease whose own close() call keeps failing for an unexpected reason is never reported as recovered');
      const geminiJob = await leaseStore.getJob(geminiJobId);
      assert.equal(geminiJob.state, 'RECONCILED', 'the job is still reconciled at its real cost -- the close() failure must not undo that or abort recovery');
      assert.equal(geminiJob.costKind, 'KNOWN');
      assert.equal(geminiJob.costUsd, 0.01);
    }, {
      wrapLeaseStore: (real) => ({
        ...real,
        async close(...args) {
          closeAttempts += 1;
          throw new Error('simulated disk failure');
        },
      }),
    });

    assert.equal(
      // The raw 'simulated disk failure' message is deliberately NOT expected here: every stderr
      // diagnostic in review-engine.mjs routes through safeErrorDetail(), which redacts a plain
      // application-thrown Error (no Node syscall .code) to a generic marker rather than
      // interpolating its message verbatim -- proven directly by tests/openrouter-review-safe-error-detail.test.mjs.
      written.some((line) => line.includes('recoverStaleLease-close-failed') && line.includes('Error (detail redacted)')),
      true,
      'a close() failure that survives the retry must be logged loudly to stderr',
    );
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// The retry's own value -- surviving a genuinely TRANSIENT close() failure, the
// realistic real-world cause -- deserves its own regression guard, not just the "still fails after
// both attempts" case above.
test('a close() failure that clears on the SECOND attempt is retried successfully, with no stderr log for the transient first failure', async () => {
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  let closeAttempts = 0;

  try {
    await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
      const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
      const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
      const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
      await reserveOrphanedJob(engine, leaseStore, ownerLock, {
        leaseId: orphan.leaseId, preflightId: orphan.preflightId,
        reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
        jobId: geminiJobId, reviewerId: 'gemini',
      });
      await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
        kind: 'RESPONSE',
        envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
      });
      const orphanLease = await leaseStore.getLease(orphan.leaseId);
      advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

      const swept = await engine.recoverOrphanedLeases();

      assert.equal(closeAttempts, 2, 'the first (failing) and second (succeeding) attempts must both run');
      assert.equal(swept.length, 1, 'a transient close() failure that clears on retry must still be reported as recovered');
      assert.equal(swept[0].leaseId, orphan.leaseId);
      assert.equal((await leaseStore.getLease(orphan.leaseId)).state, 'ORPHANED_ON_RECOVERY');
    }, {
      wrapLeaseStore: (real) => ({
        ...real,
        async close(...args) {
          closeAttempts += 1;
          if (closeAttempts === 1) throw new Error('simulated transient disk hiccup');
          return real.close(...args);
        },
      }),
    });

    assert.equal(
      written.some((line) => line.includes('recoverStaleLease-close-failed')),
      false,
      'a transient failure the retry clears must never be logged as an unexpected close failure',
    );
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// processDispatchOutcome() (shared with the live dispatch path) has no try/catch of its own around
// scrubMappingStore.recall()/desubstituteFinding() -- a throw there happens AFTER leaseStore.reconcile() already durably committed a real cost, so
// this job ends up RECONCILED at real money with its advisory content never persisted. This is a
// pre-existing characteristic of the shared pipeline (the live path's own Step 3 rejection handler,
// a few hundred lines above, carries the identical, already-accepted limitation and reports no more
// than the bare ledger record either). This test proves the pre-pass's own catch logs the failure
// loudly, and the job's real cost/state is still correctly recoverable via a fresh ledger read.
test('a processDispatchOutcome failure AFTER a real reconcile (e.g. scrubMappingStore.recall() throwing) is logged loudly, and the job\'s real cost is still recoverable from the ledger', async () => {
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };

  try {
    await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
      const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
      const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
      const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
      await reserveOrphanedJob(engine, leaseStore, ownerLock, {
        leaseId: orphan.leaseId, preflightId: orphan.preflightId,
        reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
        jobId: geminiJobId, reviewerId: 'gemini',
      });
      await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
        kind: 'RESPONSE',
        envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody([{ severity: 'minor', section: 'x', root_cause: 'y', affected_behavior: 'z', consequence: 'w', evidence: ['e'] }])), 'utf8').toString('base64') }),
      });
      const orphanLease = await leaseStore.getLease(orphan.leaseId);
      advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

      const healthOutcomes = [];
      const engineWithFailingScrubRecall = createReviewEngine({
        leaseStore,
        // The SAME leaseStore instance (and therefore the SAME real ownership) the outer
        // `engine` already holds -- reused, not re-acquired, since only one process/handle can hold
        // ownership of a given data root at a time.
        ownerLock,
        approvalAdapter: createApprovingApproval(),
        dispatchAdapter: createOrderedFakeDispatch({ responses: [] }),
        resultStore: createResultStore({ dataRoot }),
        preflightContextStore: createPreflightContextStore({ dataRoot }),
        dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
        scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
        scrubMappingStore: {
          ...createScrubMappingStore({ dataRoot }),
          async recall() { throw new Error('simulated scrub-mapping disk failure'); },
        },
        clock: () => Date.parse(orphanLease.expiresAt) + 2 * 60 * 1000 + 1_000,
        sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
        repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
        // A throw here (after a real reconcile already landed) must still count toward the
        // consecutive-dispatch-failure health tracker -- see the pre-pass catch's own comment --
        // so this test tracks every call.
        dispatchHealthStore: {
          async recordOutcome({ succeeded }) { healthOutcomes.push(succeeded); return { shouldAlert: false }; },
          async markAlerted() {},
        },
      });

      const swept = await engineWithFailingScrubRecall.recoverOrphanedLeases();

      assert.deepEqual(healthOutcomes, [false], 'the post-reconcile throw must still be recorded as a dispatch-health failure, not silently invisible to the consecutive-failure alert');

      // Real money already committed by processDispatchOutcome's own reconcile() call before the
      // throw -- the fallback below must not (and, per the money-safety invariant, cannot) touch a
      // job that is no longer RESERVED, so this lease still closes as recovered.
      assert.equal(swept.length, 1);
      assert.equal(swept[0].reconciledJobs[0].costKind, 'KNOWN');
      assert.equal(swept[0].reconciledJobs[0].costUsd, 0.01);
      // The content itself is genuinely unrecoverable in this exact scenario (never persisted) --
      // this test's own point is that the failure is VISIBLE, not that content
      // processDispatchOutcome itself never got to persist can be recovered.
    });

    assert.equal(
      // Same redaction as above: this catch wraps processing of real reviewer content, so the raw
      // message is deliberately never interpolated -- only the generic marker.
      written.some((line) => line.includes('recoverStaleLease-pre-pass-failed') && line.includes('Error (detail redacted)')),
      true,
      'the post-reconcile pre-pass failure must be logged loudly to stderr',
    );
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// reviewerId on a job record is optional (lease-store.mjs's own consume(), "backward compatible
// with every existing direct caller"), and a long-lived ledger can hold jobs left stuck RESERVED by
// code versions predating when reviewerId was added to consume() at all. Without a fallback, such a
// job's real captured outcome would be unreachable by the pre-pass -- getReviewer(undefined)
// throws, silently reintroducing a worst-case overcharge for exactly this kind of legacy record. This test simulates that shape directly (a job
// reserved with no reviewerId at all, standing in for a pre-existing ledger record from before that
// field existed) and proves resolveStaleJobReviewer()'s itemMaxima-derived reverse lookup still
// finds the real reviewer identity and recovers the job at its real cost.
test('a stale RESERVED job with NO reviewerId on its own ledger record (a legacy pre-reviewerId record) still recovers at its real cost via the itemMaxima-derived reverse lookup', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
    const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
    const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
    const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    // Deliberately reservationUsd/jobId match the real gemini item, but reviewerId is OMITTED --
    // reserveOrphanedJob() only passes reviewerId through when the caller supplies it.
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId: orphan.leaseId, preflightId: orphan.preflightId,
      reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
      jobId: geminiJobId,
    });
    assert.equal((await leaseStore.getJob(geminiJobId)).reviewerId, undefined, 'the test fixture must actually omit reviewerId, or this test proves nothing');
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
    });
    const orphanLease = await leaseStore.getLease(orphan.leaseId);

    advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.equal(swept.length, 1);
    assert.equal(swept[0].reconciledJobs[0].costUsd, 0.01, 'must recover the REAL captured cost, not geminiMaxUsd\'s worst-case reservation');
    assert.equal(swept[0].reconciledJobs[0].costKind, 'KNOWN');
    assert.equal((await leaseStore.getLease(orphan.leaseId)).state, 'ORPHANED_ON_RECOVERY');
  });
});

// The final results-build loop must not check only `lease.state !== 'ACTIVE'`, which is too
// permissive. A genuinely still-alive, slow live review() call for the SAME lease (a multi-minute
// delay that orphanSweepGraceMs narrows but cannot fully eliminate) can independently reach
// finalizeReviewOutcome() and close that lease under its OWN specific halt code (e.g.
// PROVIDER_MISMATCH) while this recovery is still running -- and a state-only check would then
// misreport that unrelated completion as something THIS recovery resolved. 'ORPHANED_ON_RECOVERY'
// is the one close code exclusively produced by sweepOrphanedLeases() and this function's own
// explicit close-loop, never by the normal live path (a genuine PASS never calls close() at all --
// see finalizeReviewOutcome()'s own closeCode:null for that branch -- and every HALT closes under
// its own specific failure code) -- this test simulates exactly that interleaving via a hooked
// dispatchOutcomeStore.recall() that reconciles and closes the lease with an unrelated code partway
// through the pre-pass, standing in for a concurrent live call finishing first.
test('a lease closed under an unrelated code by a concurrent process partway through recovery is never misreported as resolved by this recovery', async () => {
  // Populated once preflightAndAuthorize()/reserveOrphanedJob() run inside `run` below; the
  // dispatchOutcomeStore hook (constructed up front, since withEngine builds the engine BEFORE
  // calling `run`) closes over this same object and reads it lazily, by which point it's filled in.
  const ids = {};
  let recallCount = 0;
  let leaseStoreForHook = null;
  let ownerLockForHook = null;

  await withEngine(async ({ engine, leaseStore, ownerLock, advance }) => {
    leaseStoreForHook = leaseStore;
    ownerLockForHook = ownerLock;
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const lease = await leaseStore.getLease(leaseId);

    ids.geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: ids.geminiJobId, reviewerId: 'gemini',
    });
    ids.grokJobId = testDeriveJobId(leaseId, 'grok', preflight.reviewContractSha256);
    const grokMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: grokMaxUsd, jobId: ids.grokJobId, reviewerId: 'grok',
    });
    ids.leaseId = leaseId;
    // Deliberately no dispatch-outcome fixture for either job -- both fall through the pre-pass;
    // the interleaved concurrent close (simulated below) happens before the fallback even runs.

    advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();

    assert.deepEqual(swept, [], 'a lease closed by an unrelated concurrent halt must not appear in this recovery\'s own results');
    assert.equal(recallCount >= 1, true, 'the hook must have actually run for this test to prove anything');

    const closedLease = await leaseStore.getLease(leaseId);
    assert.equal(closedLease.state, 'PROVIDER_MISMATCH', 'the concurrent process\'s own close code must survive, never overwritten by this recovery');
  }, {
    dispatchOutcomeStore: {
      async recall() {
        recallCount += 1;
        if (recallCount === 1) {
          // Simulates a concurrent, genuinely-alive live review() call reaching
          // finalizeReviewOutcome() and halting this SAME lease under its own specific code,
          // interleaved between this recovery's pre-pass and its later fallback/final read. This
          // is IN-PROCESS concurrency (two async operations racing within the same server
          // instance, e.g. a live review() call and this recovery sweep both running concurrently),
          // not a genuinely different owning process -- both legitimately share the SAME ownerLock,
          // since only one process/handle can hold real ledger ownership at a time (reconcile() can
          // only ever be called by a process currently holding ownership). Using a different/fake acquisitionId here
          // would not correctly model this scenario -- it would just fail closed instead.
          await leaseStoreForHook.reconcile(ids.geminiJobId, { costUsd: 0.005, costKind: 'KNOWN', acquisitionId: ownerLockForHook.acquisitionId });
          await leaseStoreForHook.reconcile(ids.grokJobId, { costUsd: 0.008, costKind: 'KNOWN', acquisitionId: ownerLockForHook.acquisitionId });
          await leaseStoreForHook.close(ids.leaseId, 'PROVIDER_MISMATCH', { acquisitionId: ownerLockForHook.acquisitionId });
        }
        return null; // no durable dispatch-outcome capture for this job either way
      },
    },
  });
});

// ---------------------------------------------------------------------------
// Durable result store wiring.
// ---------------------------------------------------------------------------

test('a successful reconcile durably records the advisory, recoverable by jobId alone', async () => {
  await withEngine(async ({ engine, resultStore }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');

    const geminiJobId = result.reviewers.gemini.jobId;
    const recalled = await resultStore.recall({ jobId: geminiJobId });
    assert.deepEqual(recalled, result.reviewers.gemini);
  });
});

test('a resultStore.record() failure does not turn a successful review into a reported failure, and logs a loud stderr warning', async () => {
  const calls = [];
  const failingResultStore = Object.freeze({
    async record(args) {
      calls.push(args);
      throw new Error('simulated disk failure');
    },
    async recall() { return null; },
  });

  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => {
    written.push(String(chunk));
    return true;
  };

  try {
    await withEngine(async ({ engine }) => {
      const { leaseId, preflightId } = await preflightAndAuthorize(engine);
      const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
      assert.equal(result.state, 'PASSED');
      assert.deepEqual(result.reviewers.gemini.advisory, { verdict: 'pass', findings: [] });
      assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [] });

      // record() was actually invoked once per reviewer, not merely "would
      // not have propagated if it had been called" -- proves the try/catch
      // wraps a real call site, not a dead one.
      assert.equal(calls.length, 2);

      // The catch block's stderr warning must be genuinely useful for future
      // debugging: it must name which job failed to persist and why, using
      // the same `<prefix>: <event> key=value...` shape as the existing
      // `openrouter-review-dispatch:` convention in
      // tools/openrouter-review-mcp-server.mjs.
      const combined = written.join('');
      assert.match(combined, /openrouter-review-engine: resultStore-record-failed/);
      assert.ok(combined.includes(result.reviewers.gemini.jobId), 'expected gemini jobId in the stderr warning');
      assert.ok(combined.includes(result.reviewers.grok.jobId), 'expected grok jobId in the stderr warning');
      // The raw message is deliberately redacted (this catch wraps a real, content-bearing
      // record() call) -- assert the safe marker, not the original text.
      assert.ok(combined.includes('Error (detail redacted)'), 'expected the redacted-error marker in the stderr warning');
    }, { resultStore: failingResultStore });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

// ---------------------------------------------------------------------------
// engine.result({ leaseId }) -- recovery keyed by leaseId alone
// ---------------------------------------------------------------------------

test('result() recovers full advisory content for a completed lease using nothing but leaseId', async () => {
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const reviewed = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(reviewed.state, 'PASSED');

    const recovered = await engine.result({ leaseId });
    assert.equal(recovered.leaseId, leaseId);
    assert.deepEqual(recovered.reviewers.gemini.advisory, { verdict: 'pass', findings: [] });
    assert.deepEqual(recovered.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
  });
});

test('result() rejects an unknown leaseId with LEASE_MISSING', async () => {
  await withEngine(async ({ engine }) => {
    await assert.rejects(
      () => engine.result({ leaseId: 'no-such-lease' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING',
    );
  });
});

// gemini here halts on UNKNOWN_COST (worst-case charged, no advisory content ever produced), so it
// is never durably recorded by resultStore -- only the clean-reconcile path records durably.
// Recovering it therefore falls through to the bare existingJob ledger fallback, which surfaces the
// job's own REAL persisted costKind (UNKNOWN_WORST_CASE_CHARGED) instead of the old, less
// informative RECOVERED_STATUS_ONLY stub. grok is left genuinely never-dispatched by an under-sized
// maxJobs of 1 (an easy real-world mistake that cross-lease dedup also guards against): its
// reservation fails in review()'s Step 2, which stops that pass with an ORDINARY_FAILURE, so it has
// no ledger job at all and falls all the way through to NOT_DISPATCHED. That failure is surfaced by
// a THROW, after the already-reserved subset has been finalized.
test('result() reports a reviewer that never dispatched as NOT_DISPATCHED, not a crash', async () => {
  const haltingDispatch = createOrderedFakeDispatch({ responses: [responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: {} })] });
  await withEngine(async ({ engine, leaseStore, ownerLock }) => {
    // Model a historical undersized lease; new authorization now refuses this cap.
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'engine test scope' });
    await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    const historicalLease = await leaseStore.createLease({
      preflightIds: [preflight.preflightId], requestedUsd: preflight.requestedUsd,
      maxJobs: 1, expiresAt: preflight.expiresAt, acquisitionId: ownerLock.acquisitionId,
    });
    const { preflightId } = preflight;
    const leaseId = historicalLease.id;
    await assert.rejects(
      () => engine.review({ leaseId, preflightId, source_text: 'x' }),
      (error) => error instanceof ReviewEngineError && error.code === 'LEASE_CAP_EXCEEDED',
    );

    const recovered = await engine.result({ leaseId });
    assert.equal(recovered.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');
    assert.equal(recovered.reviewers.gemini.state, 'RECONCILED');
    assert.equal(recovered.reviewers.grok.costKind, 'RECOVERED_STATUS_ONLY');
    assert.equal(recovered.reviewers.grok.state, 'NOT_DISPATCHED');
  }, { dispatch: haltingDispatch });
});

// The reviewer set for a lease is NOT recomputed from its
// `profile` alone -- `final_verification_v1` without a `changeKinds`
// override reserves only `grok`, not the full two-reviewer set every other
// test in this file exercises via `consequential_spec_v1`. `result()` reads
// the actually-reserved set back from the bound preflight's own durable
// `itemMaxima` (see review-engine.mjs's `result()`), so it must recover
// exactly the narrower set -- and must not report anything at all, not even
// a stub, for a reviewer that was never part of this lease's `itemMaxima`.
test('result() recovers only the narrower reviewer set a changeKinds-narrowed preflight actually reserved, not the full profile', async () => {
  const fakeDispatch = createOrderedFakeDispatch({ responses: [responseFor(grokPassBody())] });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, {
      profile: 'final_verification_v1',
      changeKinds: [],
    });
    const reviewed = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(reviewed.state, 'PASSED');

    const recovered = await engine.result({ leaseId });
    assert.equal(recovered.leaseId, leaseId);
    assert.deepEqual(recovered.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
    assert.equal(Object.hasOwn(recovered.reviewers, 'gemini'), false);
  }, { dispatch: fakeDispatch });
});

// ---------------------------------------------------------------------------
// Scrub-engine wiring. Every source_text fixture below uses a clean,
// obviously synthetic eight-digit run (the shared ACCT_C fixture) separated from its label by
// whitespace: \b\d{8,17}\b can never match across a letter/digit boundary,
// since both are \w, so a letter glued directly onto the digit run would
// leave no \b anywhere inside it and account_number_shape would never fire
// (see tests/openrouter-scrub-engine.test.mjs's own header comment on the
// same point). Every assertion below is against that fixture and its derived
// ACCOUNT_<hex> placeholder.
// ---------------------------------------------------------------------------

test('content that trips a hard-block category never reaches dispatch, and halts with CONTENT_BLOCKED', async () => {
  const blockingScrub = createScrubEngine({
    identityList: [],
    ollamaClient: Object.freeze({
      async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
      async checkReidentifiable() { return { ok: true, flagged: false }; },
    }),
  });
  await withEngine(async ({ engine, fakeDispatch }) => {
    await assert.rejects(
      () => engine.preflight({ source_text: `synthetic patient ${W_MEDICATION} history`, profile: 'consequential_spec_v1' }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTENT_BLOCKED',
    );
    assert.equal(fakeDispatch.calls.length, 0);
  }, { scrubEngine: blockingScrub });
});

test('substitution-eligible content is scrubbed before it is ever bound into the contract, and the request actually sent carries the placeholder, not the real value', async () => {
  const capturingDispatch = createCapturingDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
  await withEngine(async ({ engine }) => {
    const preflighted = await engine.preflight({ source_text: `account ${ACCT_C}`, profile: 'consequential_spec_v1' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: `account ${ACCT_C}` });
    const sentBody = JSON.parse(Buffer.from(capturingDispatch.calls[0].requestBytes).toString('utf8'));
    assert.doesNotMatch(sentBody.messages[1].content, new RegExp(ACCT_C));
    assert.match(sentBody.messages[1].content, /ACCOUNT_[0-9a-f]{8}/);
  }, { dispatch: capturingDispatch });
});

test('resubmitting the SAME substitution-eligible content at review() time still matches the hash bound at preflight -- CONTRACT_CHANGED does not spuriously fire', async () => {
  await withEngine(async ({ engine }) => {
    const preflighted = await engine.preflight({ source_text: `account ${ACCT_C}`, profile: 'consequential_spec_v1' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    const result = await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: `account ${ACCT_C}` });
    assert.equal(result.state, 'PASSED');
  });
});

// Uses createPlaceholderEchoingDispatch (defined near
// createOrderedFakeDispatch above) rather than withEngine's DEFAULT dispatch
// (a plain gemini/grok pass with EMPTY findings), under which
// `result.reviewers.gemini.advisory.findings[0]` would be `undefined` and
// reverse-substitution would never be exercised at all. The echoing
// dispatch reads the REAL
// placeholder token out of the actual dispatched request and echoes it back
// inside a finding's root_cause AND evidence fields, so this test proves
// reverse-substitution against the real, live-computed placeholder on both a
// plain-string field and a string-array field.
test('reverse-substitution restores real values in the live review() return path', async () => {
  const echoDispatch = createPlaceholderEchoingDispatch();
  await withEngine(async ({ engine }) => {
    const preflighted = await engine.preflight({ source_text: `account ${ACCT_C}`, profile: 'consequential_spec_v1' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    const result = await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: `account ${ACCT_C}` });
    assert.equal(result.state, 'PASSED');
    const finding = result.reviewers.gemini.advisory.findings[0];
    assert.doesNotMatch(finding.root_cause, /ACCOUNT_[0-9a-f]{8}/);
    assert.match(finding.root_cause, new RegExp(ACCT_C));
    assert.doesNotMatch(finding.evidence[0], /ACCOUNT_[0-9a-f]{8}/);
    assert.match(finding.evidence[0], new RegExp(ACCT_C));
  }, { dispatch: echoDispatch });
});

// With the default (empty-findings) dispatch a `findingsText` assertion
// would hold trivially regardless of whether result()'s own desubstitute()
// logic works at all. This test instead hand-plants a resultStore entry still
// carrying the raw placeholder -- simulating the exact scenario result()'s
// own code comment names as the reason its desubstitute() calls exist (a
// crash between processDispatchOutcome() reconciling and its already-
// restored result being durably stored) -- so this test actually exercises
// result()'s reverse-substitution, not merely its pass-through of
// already-restored content.
test('reverse-substitution also applies to the result() recovery path, using the durable scrub-mapping store', async () => {
  await withEngine(async ({ engine, scrubMappingStore, resultStore }) => {
    const preflighted = await engine.preflight({ source_text: `account ${ACCT_C}`, profile: 'consequential_spec_v1' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });

    const durableMapping = await scrubMappingStore.recall({ preflightId: preflighted.preflightId });
    assert.notEqual(durableMapping, null);
    const [placeholder] = Object.keys(durableMapping);
    assert.match(placeholder, /^ACCOUNT_[0-9a-f]{8}$/);
    assert.equal(durableMapping[placeholder], ACCT_C);

    // Hand-plant a resultStore entry for gemini's deterministic jobId that
    // still carries the RAW placeholder -- never went through review()'s
    // live processDispatchOutcome() path at all, so if result() did not do
    // its own reverse-substitution, the placeholder would leak straight
    // through unchanged.
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflighted.reviewContractSha256);
    await resultStore.record({
      jobId: geminiJobId,
      advisory: {
        reviewerId: 'gemini', jobId: geminiJobId, state: 'RECONCILED', costUsd: 0.01, costKind: 'KNOWN',
        provider: 'Google', model: 'google/gemini-3.1-pro-preview',
        advisory: {
          verdict: 'block',
          findings: [{
            severity: 'blocker', section: 'x', root_cause: `account ${placeholder} looks wrong`,
            affected_behavior: 'y', consequence: 'z', evidence: [`saw ${placeholder} on line 1`],
          }],
        },
      },
    });

    const recovered = await engine.result({ leaseId });
    const findingsText = JSON.stringify(recovered.reviewers.gemini.advisory);
    assert.doesNotMatch(findingsText, /ACCOUNT_[0-9a-f]{8}/);
    assert.match(findingsText, new RegExp(ACCT_C));
  });
});

test('a successful reverse-substitution deletes the durable mapping record', async () => {
  await withEngine(async ({ engine, scrubMappingStore }) => {
    const preflighted = await engine.preflight({ source_text: `account ${ACCT_C}`, profile: 'consequential_spec_v1' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: `account ${ACCT_C}` });
    await engine.result({ leaseId });
    assert.equal(await scrubMappingStore.recall({ preflightId: preflighted.preflightId }), null);
  });
});

// ---------------------------------------------------------------------------
// reviewContext-specific scrub/block coverage: every other test above
// either leaves reviewContext at its '' default or passes plain,
// non-substitution-eligible text, so nothing else proves that scrub-engine.mjs's scrub()/blocked-check wiring was
// actually reached on the reviewContext side of either preflight() or
// review() -- only on the source_text side. A future edit that broke
// reviewContext scrubbing specifically (wrong variable, a dropped
// reassignment, a skipped block-check) could leak PII to the third-party API
// while the entire rest of this suite stayed green. The four tests below
// close that gap directly: two exercise preflight()'s reviewContext scrub
// call, two exercise review()'s OWN reviewContext scrub call (a freshly
// re-supplied reviewContext at review() time, not the cached preflight-time
// value review() falls back to when reviewContext is omitted).
// ---------------------------------------------------------------------------

test('substitution-eligible reviewContext (not source_text) supplied at preflight() time is scrubbed before it is ever bound into the contract, and the request actually sent carries the placeholder, not the real value', async () => {
  const capturingDispatch = createCapturingDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
  await withEngine(async ({ engine }) => {
    const preflighted = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: `account ${ACCT_C}` });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    // reviewContext omitted here on purpose: this specifically proves
    // preflight()'s OWN scrub of reviewContext (the value it then caches and
    // durably stores), not review()'s separate re-scrub path (covered below).
    await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: 'x' });
    const sentBody = JSON.parse(Buffer.from(capturingDispatch.calls[0].requestBytes).toString('utf8'));
    assert.doesNotMatch(sentBody.messages[1].content, new RegExp(ACCT_C));
    assert.match(sentBody.messages[1].content, /ACCOUNT_[0-9a-f]{8}/);
  }, { dispatch: capturingDispatch });
});

test('hard-block content supplied as reviewContext (not source_text) at preflight() time halts with CONTENT_BLOCKED before any dispatch', async () => {
  const blockingScrub = createScrubEngine({
    identityList: [],
    ollamaClient: Object.freeze({
      async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
      async checkReidentifiable() { return { ok: true, flagged: false }; },
    }),
  });
  await withEngine(async ({ engine, fakeDispatch }) => {
    await assert.rejects(
      () => engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: `synthetic patient ${W_MEDICATION} history` }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTENT_BLOCKED',
    );
    assert.equal(fakeDispatch.calls.length, 0);
  }, { scrubEngine: blockingScrub });
});

test('a freshly-supplied reviewContext at review() time is scrubbed by review() itself, not merely reused from the cached preflight-time value -- the request actually sent carries the placeholder, not the real value', async () => {
  const capturingDispatch = createCapturingDispatch({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
  await withEngine(async ({ engine }) => {
    // Same raw reviewContext supplied at both preflight() and review() time:
    // scrub-engine.mjs's placeholder derivation is deterministic per
    // (preflightId, rawValue), so a working review()-side scrub lands on the
    // exact same placeholder preflight() already bound into the contract,
    // keeping this a clean PASS. If review()'s own scrub call were instead
    // silently dropped (effectiveReviewContext left as the raw text), the
    // dispatched request bytes below would contain the real account number
    // in plaintext -- the failure this test exists to catch.
    const preflighted = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: `account ${ACCT_C}` });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    const result = await engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: 'x', reviewContext: `account ${ACCT_C}` });
    assert.equal(result.state, 'PASSED');
    const sentBody = JSON.parse(Buffer.from(capturingDispatch.calls[0].requestBytes).toString('utf8'));
    assert.doesNotMatch(sentBody.messages[1].content, new RegExp(ACCT_C));
    assert.match(sentBody.messages[1].content, /ACCOUNT_[0-9a-f]{8}/);
  }, { dispatch: capturingDispatch });
});

// Regression guard: scrub-engine.mjs's desubstitute() must MERGE the
// in-process mappingCache entry with seedMapping, never pick EITHER one via
// `??`. `??` only falls back to seedMapping when the cache has NO entry at
// all -- but scrub() unconditionally caches its own `mapping`, even an EMPTY
// `{}`, on every successful call, and `{}` is truthy.
//
// This test reproduces the restart shape that exposes it: preflight()
// scrubs source_text ('x', nothing eligible) THEN reviewContext (a real
// account number) in engine1's process -- the combined mapping is what gets
// durably written to scrubMappingStore. "Restart": engine2 is a brand-new
// instance (empty scrubEngine mappingCache) whose ONLY scrub() call, inside
// review()'s own loadAndScrubSource(), re-scrubs source_text ALONE (reviewContext
// is OMITTED here on purpose -- the documented majority-case calling
// convention, falling back to the cached preflight-time context rather than
// re-scrubbing it). Because source_text has nothing eligible, that call
// legitimately produces `{}`, which would poison engine2's cache for this
// preflightId under a pick-one `??` -- so when the reviewer's response echoes
// the reviewContext's real placeholder back in a finding, desubstitute()
// would have nothing to restore it with even though scrubMappingStore still
// durably held it. Uses
// createPlaceholderEchoingDispatch (defined above) so the finding contains
// the REAL, live-computed placeholder token, not a guessed one.
test('reverse-substitution recovers a value scrubbed ONLY from reviewContext at preflight() time, after a process restart where review() re-scrubs source_text alone and reviewContext is omitted', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-xproc-scrubmap-'));
  try {
    let now = START;
    const clock = () => now;
    const approval = createApprovingApproval();
    const resultStore = createResultStore({ dataRoot });
    const preflightContextStore = createPreflightContextStore({ dataRoot });
    const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    const scrubMappingStore = createScrubMappingStore({ dataRoot });
    const engineOptions = {
      approvalAdapter: approval, resultStore, preflightContextStore, dispatchOutcomeStore, scrubMappingStore, clock,
      sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    };

    const leaseStore1 = createLeaseStore({ dataRoot, clock });
    // A real ownerLock, released before leaseStore2 acquires its own -- authorizeWorkflow()
    // below genuinely calls createLease(), and engine2's review() below is its first real dispatch,
    // so both need a currently-valid acquisitionId against their own leaseStore instance.
    const ownerLock1 = await leaseStore1.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const scrubEngine1 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const engine1 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore1, ownerLock: ownerLock1, dispatchAdapter: createOrderedFakeDispatch(), scrubEngine: scrubEngine1 });
    const { leaseId, preflightId } = await preflightAndAuthorize(engine1, { source_text: 'x', reviewContext: `account ${ACCT_C}` });
    await ownerLock1.release();

    const durableMapping = await scrubMappingStore.recall({ preflightId });
    assert.notEqual(durableMapping, null);
    assert.equal(Object.keys(durableMapping).length, 1);
    const [placeholder] = Object.keys(durableMapping);
    assert.equal(durableMapping[placeholder], ACCT_C);

    // "Restart": fresh leaseStore instance re-reading the same on-disk
    // ledger, and a fresh scrubEngine instance -- empty mappingCache, the
    // exact state a real process restart leaves behind.
    const leaseStore2 = createLeaseStore({ dataRoot, clock });
    const ownerLock2 = await leaseStore2.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const scrubEngine2 = createScrubEngine({ identityList: [], ollamaClient: passingOllama() });
    const echoDispatch = createPlaceholderEchoingDispatch();
    const engine2 = createReviewEngine({ ...engineOptions, leaseStore: leaseStore2, ownerLock: ownerLock2, dispatchAdapter: echoDispatch, scrubEngine: scrubEngine2 });

    // reviewContext OMITTED: review() falls back to the cached (durably
    // recovered) preflight-time context rather than re-scrubbing it, so this
    // is the ONLY scrub() call scrubEngine2 ever makes for this preflightId
    // -- against source_text alone, which has nothing eligible.
    const result = await engine2.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');
    const finding = result.reviewers.gemini.advisory.findings[0];
    assert.doesNotMatch(finding.root_cause, new RegExp(placeholder));
    assert.match(finding.root_cause, new RegExp(ACCT_C));
    assert.doesNotMatch(finding.evidence[0], new RegExp(placeholder));
    assert.match(finding.evidence[0], new RegExp(ACCT_C));
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a freshly-supplied reviewContext at review() time that trips a hard-block category halts with CONTENT_BLOCKED, never dispatching -- proves review() runs its OWN block-check, not just preflight()\'s', async () => {
  const blockingScrub = createScrubEngine({
    identityList: [],
    ollamaClient: Object.freeze({
      async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
      async checkReidentifiable() { return { ok: true, flagged: false }; },
    }),
  });
  await withEngine(async ({ engine, fakeDispatch }) => {
    // reviewContext is clean ('benign scope') at preflight() time -- the
    // block can ONLY be attributed to review()'s own scrub call on the
    // freshly-supplied, dirty reviewContext below, not to any check that ran
    // at preflight() time or a reused cached value. If review()'s
    // block-check were silently skipped, this would instead surface as
    // CONTRACT_CHANGED (a hash mismatch against the clean preflight-time
    // contract), never CONTENT_BLOCKED -- so this test's specific error-code
    // assertion has real teeth against that regression class too.
    const preflighted = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'benign scope' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflighted.preflightId, maxJobs: 2 });
    await assert.rejects(
      () => engine.review({ leaseId, preflightId: preflighted.preflightId, source_text: 'x', reviewContext: `synthetic patient ${W_MEDICATION} history` }),
      (error) => error instanceof ReviewEngineError && error.code === 'CONTENT_BLOCKED',
    );
    assert.equal(fakeDispatch.calls.length, 0);
  }, { scrubEngine: blockingScrub });
});

// Per-reviewer failure detail: a single top-level `error` is sufficient only when one reviewer can
// ever fail; once reviewers dispatch concurrently and can halt independently for different reasons, a caller needs to know
// WHICH reviewer failed and why. REVIEW_OUTPUT_SCHEMA is validated alongside it: that schema is
// .strict() and is deliberately kept in sync with the real response shape even though it is not
// wired into any live validation path (outputSchema was dropped from every registerTool() call), so
// an additive field that never reached it would be silent drift.
test('a halted reviewer carries its own failure detail on its own entry, mirroring the top-level error shape', async () => {
  const dispatch = createOrderedFakeDispatch({
    responses: [responseFor({ provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: 'not valid json' } }], usage: { cost: 0.01 } })],
  });
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'HALTED');
    assert.deepEqual(result.reviewers.gemini.error, result.error);
    assert.equal(result.reviewers.gemini.error.code, 'STRICT_OUTPUT_INVALID');
    assert.match(result.reviewers.gemini.error.message, /failed strict validation/);
    assert.equal(REVIEW_OUTPUT_SCHEMA.safeParse(result).success, true, 'the strict response schema must accept the new per-reviewer error field');
  }, { dispatch });
});

test('a cleanly-passing reviewer carries no failure detail at all', async () => {
  await withEngine(async ({ engine }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.equal(Object.hasOwn(result.reviewers.gemini, 'error'), false);
    assert.equal(Object.hasOwn(result.reviewers.grok, 'error'), false);
    assert.equal(REVIEW_OUTPUT_SCHEMA.safeParse(result).success, true);
  });
});

// ---------------------------------------------------------------------------
// createReviewEngine() requires ownerLock as a hard constructor dependency, validated the same way
// leaseStore/resultStore/etc already are.
// ---------------------------------------------------------------------------

/**
 * A DELEGATING stand-in for a real ownership
 * handle, with only the members in `overrides` replaced. An object spread (`{ ...handle }`) would
 * run each getter once and copy its value, silently freezing acquisitionId/generation/state at
 * spread time -- exactly how a re-arm bug could pass green. Every member here reads through to the
 * real handle on each access instead. A later data property in an object literal replaces an
 * accessor of the same name, so an override such as `acquisitionId: ''` still takes effect.
 */
function delegatingOwnerLock(handle, overrides = {}) {
  return Object.freeze({
    get dataRoot() { return handle.dataRoot; },
    get generation() { return handle.generation; },
    get acquisitionId() { return handle.acquisitionId; },
    get state() { return handle.state; },
    isOwner: () => handle.isOwner(),
    arm: (options) => handle.arm(options),
    release: (options) => handle.release(options),
    ...overrides,
  });
}

test('createReviewEngine: throws when ownerLock is missing or malformed', async () => {
  const base = await buildMinimalEngineOptions();
  try {
    assert.throws(() => createReviewEngine({ ...base, ownerLock: undefined }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, ownerLock: { acquisitionId: 'x' } }), TypeError); // missing isOwner/release
    assert.throws(() => createReviewEngine({ ...base, ownerLock: delegatingOwnerLock(base.ownerLock, { isOwner: undefined }) }), TypeError); // missing isOwner
    assert.throws(() => createReviewEngine({ ...base, ownerLock: delegatingOwnerLock(base.ownerLock, { acquisitionId: '' }) }), TypeError); // empty acquisitionId
  } finally {
    await base.ownerLock.release();
    await rm(base.dataRoot, { recursive: true, force: true });
  }
});

// pendingHealthVerdictStore/healthVerdictGraceMs/healthVerdictBackstopMs are constructor options with
// soft in-process defaults, validated like every other collaborator/tunable in this constructor
// (dispatchHealthStore gets requirePlainObject/requireFunction; orphanSweepGraceMs gets range
// validation). healthVerdictGraceMs/healthVerdictBackstopMs feed real arithmetic, so an unvalidated
// bad value would silently miscompute instead of failing loudly at construction.
test('createReviewEngine validates pendingHealthVerdictStore, healthVerdictGraceMs, and healthVerdictBackstopMs', async () => {
  const base = await buildMinimalEngineOptions();
  try {
    const validPendingHealthVerdictStore = {
      async record() {}, async recall() { return null; }, async remove() {}, async list() { return []; },
      async claim() { return { claimed: false }; }, async recallClaim() { return { status: 'absent' }; }, async releaseClaim() {},
    };
    // pendingHealthVerdictStore: not an object, or missing one of its 7 required methods (the last
    // three are the per-job claim methods).
    // (null, not undefined -- this option carries a default value in the destructured constructor
    // signature, so an explicit `undefined` would be replaced by that default before validation ever
    // runs, exactly like dispatchHealthStore's own soft default; null bypasses that substitution.)
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: null }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, record: undefined } }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, recall: undefined } }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, remove: undefined } }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, list: undefined } }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, claim: undefined } }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, recallClaim: undefined } }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: { ...validPendingHealthVerdictStore, releaseClaim: undefined } }), TypeError);
    // healthVerdictGraceMs: must be a positive safe integer.
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictGraceMs: 0 }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictGraceMs: -1 }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictGraceMs: 'not a number' }), TypeError);
    // healthVerdictBackstopMs: must be a positive safe integer.
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictBackstopMs: 0 }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictBackstopMs: -1 }), TypeError);
    assert.throws(() => createReviewEngine({ ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictBackstopMs: 'not a number' }), TypeError);
    // A fully valid set of overrides must still construct cleanly.
    assert.doesNotThrow(() => createReviewEngine({
      ...base, pendingHealthVerdictStore: validPendingHealthVerdictStore, healthVerdictGraceMs: 1000, healthVerdictBackstopMs: 2000,
    }));
  } finally {
    await base.ownerLock.release();
    await rm(base.dataRoot, { recursive: true, force: true });
  }
});

test('processDispatchOutcome clean-pass: skips resultStore.record() when ownerLock.isOwner() is false, but still reconciles the real cost', async () => {
  const recordCalls = [];
  const base = await buildMinimalEngineOptions();
  // Replaced wholesale, not mutated in place: createResultStore()'s real return value is frozen, so
  // reassigning .record directly on it would throw in this module's strict-mode context.
  const options = {
    ...base,
    resultStore: { ...base.resultStore, record: async (...args) => { recordCalls.push(args); } },
    // isOwner() is overridden to lie/report false while acquisitionId stays the SAME real, still-
    // valid value (delegated to base.ownerLock on every read, never a spread-time copy) -- this is
    // the intended scope-boundary decoupling: isOwner() is a plain
    // synchronous local flag, independent of whether acquisitionId still genuinely matches the
    // ledger's live owner. leaseStore.reconcile() below only ever checks acquisitionId, never
    // isOwner(), so it must still succeed at the real cost. (The ownership coordinator also sees
    // isOwner() false and calls arm(), which the real, already-armed handle resolves at once with no
    // I/O, followed by one cycle-work pass per call: an empty recovery sweep, then the
    // pending-health sweep -- so this fixture does generate some extra ledger traffic.)
    ownerLock: delegatingOwnerLock(base.ownerLock, { isOwner: () => false }),
  };
  const engine = createReviewEngine(options);
  try {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.equal(result.state, 'PASSED');
    assert.equal(recordCalls.length, 0, 'resultStore.record() must be skipped entirely while ownerLock.isOwner() reports false');
    // The real money-safety guarantee -- leaseStore.reconcile(), fully ledger-fenced by
    // acquisitionId -- is untouched by isOwner() and must still have committed both reviewers at
    // their real, known cost.
    assert.equal((await base.leaseStore.getJob(result.reviewers.gemini.jobId)).costKind, 'KNOWN');
    assert.equal((await base.leaseStore.getJob(result.reviewers.grok.jobId)).costKind, 'KNOWN');
  } finally {
    await base.ownerLock.release();
    await rm(base.dataRoot, { recursive: true, force: true });
  }
});

// Proves acquisitionId is genuinely FORWARDED and CHECKED through createReviewEngine()'s real
// leaseStore.*() call sites, not merely accepted at construction and then ignored -- a fully-faked
// leaseStore (as most of this file's other tests deliberately use, per this file's own header
// comment) would silently prove nothing about whether the argument is actually forwarded, since a
// fake always accepts whatever it's given. Builds its own real leaseStore/ownerLock (never
// buildMinimalEngineOptions()'s pre-acquired pair).
//
// Staleness is made by SUPERSESSION, not by release: under the handle state machine a released
// handle's acquisitionId reads null, so a released handle can never carry a stale id into a fenced
// write at all, whatever release() defaults to. The property this test exists for is "a superseded
// owner's id fails the fence closed", so this test supersedes the handle exactly as
// tests/openrouter-review-lease.test.mjs's "superseded by a genuine stale reclaim" test does: `first` never releases, so it still reports itself the owner and still
// carries its own, now-dead, acquisitionId, while the ledger's live owner is `second`.
test('acquisitionId forwarding: a SUPERSEDED ownerLock genuinely fails createLease closed (stale by supersession, not release; real leaseStore, not a fake)', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-forwarding-'));
  try {
    const base = await buildMinimalEngineOptions();
    try {
      // ONE controllable clock for this store AND the engine: the engine's notion of "now" (the
      // preflight's expiresAt) and the store's (its assertTimestampNotExpired checks) must agree, or
      // a mismatch would report the preflight expired before the real test is ever reached.
      let now = START;
      const clock = () => now;
      const leaseStore = createLeaseStore({
        dataRoot, clock, lockRetryMs: 5, lockStaleMs: 100,
        // Every recorded owner reads as dead, so `second` may reclaim once `first` is past lockStaleMs.
        isProcessAlive: () => false,
        monotonicNow: () => now,
        sleep: async (ms) => { now += ms; },
      });
      const first = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
      now += 200; // past lockStaleMs -- first now looks dead and stale to a new acquirer
      const second = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 1_000_000 });
      assert.equal(second.generation, 2);
      assert.notEqual(second.acquisitionId, first.acquisitionId, 'second reclaimed via staleness, not via first.release()');
      assert.equal(first.isOwner(), true, 'precondition: the superseded handle still believes it owns');

      const options = { ...base, leaseStore, ownerLock: first, clock };
      const engine = createReviewEngine(options);

      // authorizeWorkflow() itself calls leaseStore.createLease() with the stale acquisitionId --
      // this must fail closed with the PROCESS_OWNERSHIP_LOST classification, not silently
      // succeed by ignoring ownerLock.acquisitionId.
      const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'forwarding test' });
      await assert.rejects(
        engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
        (error) => {
          assert.equal(error.code, 'PROCESS_OWNERSHIP_LOST');
          assert.match(error.message, /does not currently hold process ownership/);
          return true;
        },
      );

      // Confirm no lease was actually created despite the attempt (createLease() genuinely never
      // committed, not merely that the caller saw an error).
      const rawSourceSha256 = createHash('sha256').update('x', 'utf8').digest('hex');
      assert.equal(await leaseStore.countLeasesForRawSource(rawSourceSha256), 0);
    } finally {
      // base's own ownerLock was never used by any real write in this test (the stale one above is
      // what the engine actually holds) -- release it and clean up its own separate dataRoot too.
      await base.ownerLock.release();
      await rm(base.dataRoot, { recursive: true, force: true });
    }
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test("translateConsumeError classifies a lost owner at consume() as PROCESS_OWNERSHIP_LOST, not LEASE_MISSING", async () => {
  // The neighbouring stale-ownerLock forwarding test above makes its handle stale BEFORE
  // authorizeWorkflow, by supersession, so it fails at createLease() and never reaches consume() at
  // all; the other explicit ownership test covers final close(). Nothing else exercises the
  // translator's own first branch.
  //
  // That branch matters because its fallthrough is the generic LEASE_MISSING catch-all: the
  // ownership message contains none of cap/closed/expired/contract/missing, so without the branch
  // a superseded owner is reported as a lease that does not exist -- telling an operator to go
  // create a new (paid) lease when the lease is fine and the real problem is that a second process
  // took the ledger.
  //
  // Ownership stays genuinely valid through authorizeWorkflow (so a REAL lease exists) and is lost
  // only at consume(), which is the one interleaving that reaches this branch.
  await withEngine(async ({ engine }) => {
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'consume ownership test' });
    const { leaseId } = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });

    const outcome = await engine.review({ leaseId, preflightId: preflight.preflightId, source_text: 'x' })
      .then((result) => ({ kind: 'returned', result }), (error) => ({ kind: 'threw', error }));

    const code = outcome.kind === 'threw' ? outcome.error.code : outcome.result?.error?.code;
    assert.equal(
      code,
      'PROCESS_OWNERSHIP_LOST',
      `a superseded owner must not be reported as a missing lease; got ${JSON.stringify(outcome.kind === 'threw' ? outcome.error.message : outcome.result)}`,
    );
  }, {
    wrapLeaseStore: (real) => ({
      ...real,
      async consume() {
        // The exact string lease-store.mjs's assertCurrentlyOwnsProcess() throws.
        throw new Error('caller does not currently hold process ownership of this data root');
      },
    }),
  });
});

// A successful review deliberately does NOT close its lease -- finalizeReviewOutcome returns
// `{ state: 'PASSED', closeCode: null }` (review-engine.mjs:726) and only calls leaseStore.close()
// when closeCode is non-null. So "ACTIVE, expired, no RESERVED jobs" is the ordinary resting state
// of every review that passed, not evidence of anything going wrong.
//
// That matters because ORPHANED_ON_RECOVERY is described in this file as the one close code
// produced exclusively by the orphan-recovery path. Anything that relabels a passed lease with it
// destroys that meaning for every successful review in the ledger.
test('engine.recoverOrphanedLeases() leaves a PASSED lease alone once it expires', async () => {
  await withEngine(async ({ engine, leaseStore, advance }) => {
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED', 'precondition: this review really did pass');

    const passedLease = await leaseStore.getLease(leaseId);
    assert.equal(passedLease.state, 'ACTIVE', 'precondition: a passed lease is deliberately left open');

    advance((Date.parse(passedLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);
    await engine.recoverOrphanedLeases();

    assert.equal((await leaseStore.getLease(leaseId)).state, 'ACTIVE');
  });
});

// ---------------------------------------------------------------------------
// resolvePendingHealthVerdicts() -- the sweep that resolves every due pending-verdict record
// ambiguousDispatching deferred, against whatever dispatchOutcomeStore actually captured, with a
// backstop that forces a failure verdict for a record long past due.
//
// Every notBeforeMs/recordedAtMs below is anchored to this file's own START constant (the fixed
// instant withEngine's fake `clock` is pinned to at construction -- see withEngine's own
// `let now = START; const clock = () => now;`), NOT real Date.now(). resolvePendingHealthVerdicts()
// reads "now" via this SAME injected clock (matching writePendingHealthVerdict()'s own
// choice), so a record's due-ness has to be judged relative to START, the only value `clock()`
// actually returns unless a test calls the harness's `advance()` -- none of these do, since a
// static offset from START (before it for "already due", after it for "not yet due") is sufficient
// and needs no time travel. Using real Date.now() here would make every "due" record permanently
// look not-due, since real time sits well after the frozen clock's START.
// ---------------------------------------------------------------------------

// A resolved success must NEVER be recorded via recordDispatchHealthOutcome() -- recordOutcome
// ({succeeded:true})'s unconditional reset has no per-job memory, so calling it here would silently
// erase an unrelated, still-current real failure recorded in the interim. This test's own
// recordOutcome({succeeded:false}) call below stands in for exactly that unrelated real failure, so
// the counter must stay UNCHANGED at 1 after the sweep resolves this job's genuine success --
// proving a resolved success resets nothing, not merely that this ONE job avoided being miscounted.
// See review-engine.mjs's resolvePendingHealthVerdicts() docstring and the "a delayed genuine
// success after an ambiguous force-close" test further below, which exercises the same guarantee
// end-to-end through the real ambiguousDispatching path rather than this synthetic setup.
test('resolvePendingHealthVerdicts: a captured RESPONSE that validates cleanly resolves as a success, and a resolved success never resets the streak', async () => {
  await withEngine(async ({ engine, dataRoot, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'a'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });
    await writeDispatchOutcomeFixture(dataRoot, jobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody()), 'utf8').toString('base64') }),
    });
    // Stands in for an unrelated, still-current real failure recorded before this sweep runs.
    await dispatchHealthStore.recordOutcome({ succeeded: false, alertThreshold: 3 });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 1, 'a resolved success must never reset the streak -- the unrelated real failure recorded above must survive unchanged');
    assert.equal(await pendingHealthVerdictStore.recall({ jobId }), null, 'the pending record must be deleted once resolved');
  });
});

// A response billed above its reservation is a real, completed dispatch, so
// the deferred health verdict counts it a success, not a pipeline failure (the overrun itself is
// reported through its own critical alert when the job is reconciled).
test('resolvePendingHealthVerdicts: a valid captured RESPONSE billed above its reservation resolves as a success', async () => {
  await withEngine(async ({ engine, dataRoot, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'e'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });
    await writeDispatchOutcomeFixture(dataRoot, jobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify({ ...grokPassBody(), usage: { cost: 0.75 } }), 'utf8').toString('base64') }),
    });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state?.consecutiveFailures ?? 0, 0, 'an above-reservation but valid response is not a dispatch failure');
    assert.equal(await pendingHealthVerdictStore.recall({ jobId }), null);
  });
});

test('resolvePendingHealthVerdicts: a captured RESPONSE that fails validation resolves as succeeded:false', async () => {
  await withEngine(async ({ engine, dataRoot, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'b'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });
    await writeDispatchOutcomeFixture(dataRoot, jobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify({ provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: 'not valid json findings' } }] }), 'utf8').toString('base64') }),
    });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 1);
    assert.equal(await pendingHealthVerdictStore.recall({ jobId }), null);
  });
});

test('resolvePendingHealthVerdicts: a captured FAILURE resolves as succeeded:false', async () => {
  await withEngine(async ({ engine, dataRoot, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'c'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });
    await writeDispatchOutcomeFixture(dataRoot, jobId, {
      kind: 'FAILURE',
      envelopeJsonText: JSON.stringify({ failureKind: 'TIMEOUT', message: 'deadline exceeded' }),
    });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 1);
  });
});

test('resolvePendingHealthVerdicts: nothing captured, past notBeforeMs but within the backstop, still resolves as succeeded:false', async () => {
  await withEngine(async ({ engine, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'd'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 1);
  });
});

test('resolvePendingHealthVerdicts: a record whose notBeforeMs has not yet passed is left untouched', async () => {
  await withEngine(async ({ engine, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'e'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now + 60000, recordedAtMs: now });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 0);
    assert.ok(await pendingHealthVerdictStore.recall({ jobId }), 'the record must still exist, unresolved');
  });
});

test('resolvePendingHealthVerdicts: the backstop skips the outcome check entirely for a record over an hour past notBeforeMs, even with a real captured success sitting there', async () => {
  await withEngine(async ({ engine, dataRoot, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'f'.repeat(64);
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - (61 * 60 * 1000), recordedAtMs: now - (61 * 60 * 1000) - 10000 });
    await writeDispatchOutcomeFixture(dataRoot, jobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody()), 'utf8').toString('base64') }),
    });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 1, 'the backstop must fire regardless of what dispatchOutcomeStore holds');
  });
});

// Deliberately overrides pendingHealthVerdictStore.list() to force the BAD record first in
// resolution order -- readdir()'s own return order is not something this test may rely on (not
// alphabetically sorted by contract, and not stable across filesystems), so without this override
// the test would only prove "an unrelated good record survives," never that the loop actually
// CONTINUES past a mid-batch throw. Forcing the bad record first makes getReviewer()'s throw for
// its unknown reviewerId happen strictly before the good record is ever reached, so the good
// record's own successful resolution can only be explained by the loop surviving that throw.
//
// badJobId's dispatch-outcome fixture is REQUIRED, not optional decoration: resolveOneHealthVerdict()
// calls dispatchOutcomeStore.recall() BEFORE getReviewer(), so with no fixture at all recall()
// returns null and the function returns false cleanly at that first check -- getReviewer() is never
// reached and no exception ever fires, and the test would claim to prove fault isolation without
// ever actually triggering a throw. A RESPONSE-kind
// fixture (any body) is enough to carry control flow past the recall() check into getReviewer(),
// which is what genuinely throws on the unknown reviewerId.
test('resolvePendingHealthVerdicts: multiple due records are each resolved independently; one bad record does not block the rest', async () => {
  const goodJobId = 'a1'.padEnd(64, '0');
  const badJobId = 'b2'.padEnd(64, '0');
  await withEngine(async ({ engine, dataRoot, pendingHealthVerdictStore }) => {
    const now = START;
    await pendingHealthVerdictStore.record({ jobId: goodJobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });
    await writeDispatchOutcomeFixture(dataRoot, goodJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody()), 'utf8').toString('base64') }),
    });
    await pendingHealthVerdictStore.record({ jobId: badJobId, reviewerId: 'not-a-real-reviewer', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });
    // Any captured RESPONSE body is sufficient -- resolveOneHealthVerdict() never gets past
    // getReviewer(record.reviewerId) for this record, so the body's own content is never inspected.
    await writeDispatchOutcomeFixture(dataRoot, badJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody()), 'utf8').toString('base64') }),
    });

    await engine.resolvePendingHealthVerdicts();

    assert.equal(
      await pendingHealthVerdictStore.recall({ jobId: goodJobId }),
      null,
      'the good record must still be resolved and deleted despite being processed AFTER the bad one throws',
    );
    assert.ok(
      await pendingHealthVerdictStore.recall({ jobId: badJobId }),
      'the bad record must still be PRESENT -- getReviewer() throwing must be caught before remove()/recordDispatchHealthOutcome() ever run for it, so it is neither deleted nor silently resolved',
    );
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async list() {
        const records = await inner.list();
        // badJobId sorted strictly first, regardless of the underlying store's own readdir() order.
        return [...records].sort((a, b) => {
          if (a.jobId === badJobId) return -1;
          if (b.jobId === badJobId) return 1;
          return 0;
        });
      },
    }),
  });
});

test('resolvePendingHealthVerdicts: delete-then-record ordering -- if the delete itself fails, recordDispatchHealthOutcome is never reached for that record', async () => {
  await withEngine(async ({ engine, pendingHealthVerdictStore, dispatchHealthStore }) => {
    const jobId = 'aa'.padEnd(64, '0');
    const now = START;
    await pendingHealthVerdictStore.record({ jobId, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: now - 1000, recordedAtMs: now - 10000 });

    await engine.resolvePendingHealthVerdicts();

    const state = await dispatchHealthStore.recall();
    assert.equal(state.consecutiveFailures, 0, 'a failed delete must prevent the health outcome from ever being recorded for this record, proving delete runs first');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async remove() { throw new Error('simulated delete failure'); },
    }),
  });
});

// ---------------------------------------------------------------------------
// End-to-end regression through the REAL ambiguousDispatching / resolvePendingHealthVerdicts() path
// -- not a synthetic pendingHealthVerdictStore.record() call like every sweep test above. Recording a
// failure immediately, before the real, often-delayed response has a chance to arrive, would
// miscount genuine OpenRouter successes as dispatch-health failures. This test covers that
// regression and the interleaving trap (a deferred success must not disturb an unrelated later real
// failure) together, in one ordered narrative against one engine.
// ---------------------------------------------------------------------------
test('a delayed genuine success after an ambiguous force-close does not count as a dispatch-health failure, and does not disturb an unrelated later real failure', async () => {
  // Position 1: grok's fresh dispatch during Step A's review() call (gemini is the ambiguous
  // reviewer there and is never redispatched -- see the sibling "DISPATCHING marker" test above for
  // the same shape). Position 2: Step B's own single reviewer (grok again, via a SEPARATE lease), a
  // genuine, definite INTERNAL_ERROR failure that has nothing to do with gemini's Step A job.
  const dispatch = createOrderedFakeDispatch({
    responses: [
      responseFor(grokPassBody()),
      { kind: 'FAILURE', failureKind: 'INTERNAL_ERROR', message: 'an unrelated, genuinely different dispatch failure' },
    ],
  });
  await withEngine(async ({
    engine, leaseStore, ownerLock, dataRoot, dispatchHealthStore, pendingHealthVerdictStore, advance,
  }) => {
    // --- Step A: reproduce the ambiguous force-close. ---
    const { preflight, leaseId, preflightId } = await preflightAndAuthorize(engine, { maxJobs: 2 });
    const geminiJobId = testDeriveJobId(leaseId, 'gemini', preflight.reviewContractSha256);
    const geminiMaxUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId, preflightId, reviewContractSha256: preflight.reviewContractSha256,
      reservationUsd: geminiMaxUsd, jobId: geminiJobId, reviewerId: 'gemini',
    });
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, { kind: 'DISPATCHING' });

    const resultA = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(resultA.state, 'HALTED');
    assert.equal(resultA.error.code, 'DISPATCH_UNKNOWN');
    assert.equal(resultA.reviewers.gemini.costKind, 'UNKNOWN_WORST_CASE_CHARGED');

    const stateAfterA = await dispatchHealthStore.recall();
    assert.equal(stateAfterA.consecutiveFailures, 0, 'the ambiguous force-close must NOT have counted as a failure yet -- it defers to the sweep instead of recording immediately');

    const pendingForGemini = await pendingHealthVerdictStore.recall({ jobId: geminiJobId });
    assert.ok(pendingForGemini, 'a pending-verdict record must exist for the ambiguously-closed gemini job');
    assert.equal(pendingForGemini.reviewerId, 'gemini');

    // --- Step B: an unrelated, genuinely different, real failure happens in between. ---
    // A SEPARATE preflightAndAuthorize() call against the SAME engine -- a new lease/preflight for a
    // different source_text (so this is a fresh document, not a "repeat authorization" of Step A's
    // own document), never touching gemini's Step A job at all. final_verification_v1 + changeKinds:
    // [] reserves only `grok` (reviewer-registry.mjs's own base reviewerIds for that profile, with no
    // changeKinds entry to widen it -- see the "haltAndClose records a dispatch-health failure by
    // default" test above for the same shape), so this dispatches exactly one reviewer against the
    // fake queue's 2nd, INTERNAL_ERROR response.
    const { leaseId: leaseIdB, preflightId: preflightIdB } = await preflightAndAuthorize(engine, {
      source_text: 'y', profile: 'final_verification_v1', changeKinds: [], maxJobs: 1,
    });
    const resultB = await engine.review({ leaseId: leaseIdB, preflightId: preflightIdB, source_text: 'y' });
    assert.equal(resultB.state, 'HALTED');
    assert.equal(resultB.error.code, 'TRANSPORT_FAILURE');

    const stateAfterB = await dispatchHealthStore.recall();
    assert.equal(stateAfterB.consecutiveFailures, 1, 'the real, unrelated failure must be counted');

    // --- Step C: the real, delayed response for gemini's ORIGINAL ambiguous job finally arrives. ---
    // Advance comfortably past the default 6-minute healthVerdictGraceMs but still well inside the
    // 1-hour backstop, so the sweep runs the real outcome check instead of skipping straight to
    // failure via the backstop.
    advance(7 * 60 * 1000);
    await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({
        httpStatus: 200,
        bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64'),
      }),
    });

    await engine.resolvePendingHealthVerdicts();

    assert.equal(
      await pendingHealthVerdictStore.recall({ jobId: geminiJobId }),
      null,
      "gemini's pending record must be resolved and deleted once the sweep processes it",
    );

    // --- Step D: the key assertion. ---
    // Unchanged from Step B: gemini's late-arriving genuine success must NOT reset/disturb the
    // unrelated real failure's own count. Were resolvePendingHealthVerdicts() to call
    // recordDispatchHealthOutcome({succeeded:true}) for gemini's resolution in a way that
    // unconditionally reset the streak (dispatch-health-store.mjs's recordOutcome() does exactly that
    // for ANY succeeded:true call, with no per-job memory, which is why recording immediately and
    // then retroactively correcting is unsafe), this would read 0 instead of 1.
    const finalState = await dispatchHealthStore.recall();
    assert.equal(finalState.consecutiveFailures, 1, "gemini's deferred success must not disturb grok's unrelated, still-current real failure");
  }, { dispatch });
});

// ---------------------------------------------------------------------------
// A lost-ownership failure is not a dispatch failure.
// ---------------------------------------------------------------------------

// The recoverOrphanedLeases counterpart of parallel-dispatch's "ownership lost at reconcile()" test.
// This process was superseded between the orphan being reserved and the recovery sweep, so every
// owner-fenced write now refuses. The pre-pass must still log the failure loudly, but must not count
// it toward the consecutive-dispatch-failure streak: nothing about the dispatch pipeline failed.
test('an orphan recovery whose reconcile fails on lost process ownership records no dispatch-health failure, and still logs the failure loudly', async () => {
  const ownershipLost = new Error('caller does not currently hold process ownership of this data root');
  const healthOutcomes = [];
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
      const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
      const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
      const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
      await reserveOrphanedJob(engine, leaseStore, ownerLock, {
        leaseId: orphan.leaseId, preflightId: orphan.preflightId,
        reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
        jobId: geminiJobId, reviewerId: 'gemini',
      });
      await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
        kind: 'RESPONSE',
        envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
      });
      const orphanLease = await leaseStore.getLease(orphan.leaseId);
      advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

      const swept = await engine.recoverOrphanedLeases();

      assert.deepEqual(swept, [], 'nothing could be resolved: every fenced write refused');
      assert.deepEqual(healthOutcomes, [], 'an ownership loss must not be recorded as a dispatch-health failure');
      assert.equal((await leaseStore.getJob(geminiJobId)).state, 'RESERVED', 'the refused writes committed nothing');
    }, {
      // A superseded owner: every owner-fenced write refuses with the exact message
      // lease-store.mjs's assertCurrentlyOwnsProcess() throws. Reads still work.
      wrapLeaseStore: (real) => ({
        ...real,
        async reconcile() { throw ownershipLost; },
        async sweepOrphanedLeases() { throw ownershipLost; },
        async close() { throw ownershipLost; },
      }),
      dispatchHealthStore: {
        async recordOutcome({ succeeded }) { healthOutcomes.push(succeeded); return { shouldAlert: false }; },
        async markAlerted() {},
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
  assert.ok(written.some((line) => line.includes('recoverStaleLease-pre-pass-failed')), 'the pre-pass failure is still logged loudly');
});

// The recoverStaleLease() pre-pass site: the orphan's captured outcome is recovered
// through a pre-pass whose getLease times out on the data-root lock. That timeout is not a dispatch
// failure. The fallback sweep then charges the job at worst case exactly as before, and THAT
// worst-case resolution still counts one failure (unchanged); only the pre-pass's own extra count
// is gone.
test('an orphan-recovery pre-pass whose getLease times out LEDGER_DATA_ROOT_LOCKED adds no dispatch-health failure of its own; the fallback still charges worst case and counts that one', async () => {
  const healthOutcomes = [];
  let lockTimeoutsRemaining = 0;
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance }) => {
      const orphan = await preflightAndAuthorize(engine, { maxJobs: 2, source_text: 'orphan source' });
      const geminiJobId = testDeriveJobId(orphan.leaseId, 'gemini', orphan.preflight.reviewContractSha256);
      const geminiMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd;
      await reserveOrphanedJob(engine, leaseStore, ownerLock, {
        leaseId: orphan.leaseId, preflightId: orphan.preflightId,
        reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: geminiMaxUsd,
        jobId: geminiJobId, reviewerId: 'gemini',
      });
      await writeDispatchOutcomeFixture(dataRoot, geminiJobId, {
        kind: 'RESPONSE',
        envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(geminiPassBody()), 'utf8').toString('base64') }),
      });
      const orphanLease = await leaseStore.getLease(orphan.leaseId);
      advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

      lockTimeoutsRemaining = 1; // the pre-pass's getLease is the first getLease the sweep makes
      const swept = await engine.recoverOrphanedLeases();

      assert.equal(lockTimeoutsRemaining, 0, 'precondition: the pre-pass hit the lock timeout');
      assert.deepEqual(healthOutcomes, [false], 'one failure, the fallback\'s worst-case resolution; the pre-pass lock timeout adds none');
      assert.equal(swept.length, 1, 'the fallback sweep still resolved the orphan');
      const geminiJob = await leaseStore.getJob(geminiJobId);
      assert.equal(geminiJob.state, 'RECONCILED');
      assert.equal(geminiJob.costKind, 'UNKNOWN_WORST_CASE_CHARGED', 'money unchanged: the fallback charges worst case, as for any failed pre-pass');
      assert.equal(geminiJob.costUsd, geminiMaxUsd);
    }, {
      wrapLeaseStore: (real) => ({
        ...real,
        async getLease(leaseId) {
          if (lockTimeoutsRemaining > 0) {
            lockTimeoutsRemaining -= 1;
            throw Object.assign(new Error('ledger data root is locked'), { code: LEDGER_DATA_ROOT_LOCKED_CODE });
          }
          return real.getLease(leaseId);
        },
      }),
      dispatchHealthStore: {
        async recordOutcome({ succeeded }) { healthOutcomes.push(succeeded); return { shouldAlert: false }; },
        async markAlerted() {},
      },
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
  assert.ok(written.some((line) => line.includes('recoverStaleLease-pre-pass-failed') && line.includes('LEDGER_DATA_ROOT_LOCKED (detail redacted')), 'the pre-pass failure is still logged loudly, naming the busy ledger');
});

// ---------------------------------------------------------------------------
// The scrub-mapping read does not race result()'s delete.
// ---------------------------------------------------------------------------

test('result retains the mapping between reconcile and durable content, then cleans it after durable recovery', async () => {
  await withEngine(async ({ engine, leaseStore, ownerLock, dataRoot, advance, resultStore, scrubMappingStore }) => {
    const sourceText = 'Coordinate the rollout with Jane Q. Public before the freeze.';
    // final_verification_v1 with an empty changeKinds dispatches grok alone: one reviewer, so its
    // reconcile is the one that makes the whole lease "every reviewer RECONCILED" for result().
    const orphan = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [], maxJobs: 1, source_text: sourceText });
    const mapping = await scrubMappingStore.recall({ preflightId: orphan.preflightId });
    const [placeholder] = Object.keys(mapping ?? {}).filter((key) => /jane q\. public/i.test(mapping[key]));
    assert.ok(placeholder, 'precondition: preflight substituted the identity and recorded its mapping durably');

    const grokJobId = testDeriveJobId(orphan.leaseId, 'grok', orphan.preflight.reviewContractSha256);
    const grokMaxUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await reserveOrphanedJob(engine, leaseStore, ownerLock, {
      leaseId: orphan.leaseId, preflightId: orphan.preflightId,
      reviewContractSha256: orphan.preflight.reviewContractSha256, reservationUsd: grokMaxUsd,
      jobId: grokJobId, reviewerId: 'grok',
    });
    const finding = {
      severity: 'minor', section: 'rollout', root_cause: `the plan never schedules ${placeholder}`,
      affected_behavior: 'z', consequence: 'w', evidence: [`the plan names ${placeholder}`],
    };
    await writeDispatchOutcomeFixture(dataRoot, grokJobId, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(grokPassBody([finding])), 'utf8').toString('base64') }),
    });
    const orphanLease = await leaseStore.getLease(orphan.leaseId);
    advance((Date.parse(orphanLease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);

    let deleteRaceFired = false;
    let interleavedResult;
    let mappingAtContentGap;
    const recoveringEngine = createReviewEngine({
      leaseStore: {
        ...leaseStore,
        async reconcile(jobId, options) {
          const reconciled = await leaseStore.reconcile(jobId, options);
          if (jobId === grokJobId && !deleteRaceFired) {
            deleteRaceFired = true;
            interleavedResult = await recoveringEngine.result({ leaseId: orphan.leaseId });
            mappingAtContentGap = await scrubMappingStore.recall({ preflightId: orphan.preflightId });
          }
          return reconciled;
        },
      },
      ownerLock,
      approvalAdapter: createApprovingApproval(),
      dispatchAdapter: createOrderedFakeDispatch({ responses: [] }),
      resultStore,
      preflightContextStore: createPreflightContextStore({ dataRoot }),
      dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
      scrubEngine: createScrubEngine({ identityList: ['jane q. public'], ollamaClient: passingOllama() }),
      scrubMappingStore,
      clock: () => Date.parse(orphanLease.expiresAt) + 2 * 60 * 1000 + 1_000,
      sourcePolicy, preflightPolicy, preflightTtlMs: 10 * 60 * 1000, installationHardMaximumUsd: 10,
      repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    });

    const swept = await recoveringEngine.recoverOrphanedLeases();

    const stored = await resultStore.recall({ jobId: grokJobId });
    const afterDurability = await recoveringEngine.result({ leaseId: orphan.leaseId });
    const mappingAfterDurability = await scrubMappingStore.recall({ preflightId: orphan.preflightId });
    assert.equal(deleteRaceFired, true, 'precondition: result() ran between reconciliation and durable content');
    assert.deepEqual({
      mappingAtContentGap,
      recoveredAtContentGap: interleavedResult.reviewers.grok.advisory,
      recoveredAfterDurability: afterDurability.reviewers.grok.advisory,
      mappingAfterDurability,
    }, {
      mappingAtContentGap: mapping,
      recoveredAtContentGap: stored.advisory,
      recoveredAfterDurability: stored.advisory,
      mappingAfterDurability: null,
    });
    assert.equal(swept.length, 1);
    assert.equal(swept[0].reconciledJobs[0].costKind, 'KNOWN', 'money behaviour unchanged: reconciled at the real cost');
    const [restored] = stored.advisory.findings;
    assert.equal(
      JSON.stringify(restored).includes(placeholder),
      false,
      `no raw placeholder may survive into the recovered advisory: ${JSON.stringify(restored)}`,
    );
    assert.match(restored.evidence[0], /Jane Q\. Public/);
  }, { scrubEngine: createScrubEngine({ identityList: ['jane q. public'], ollamaClient: passingOllama() }) });
});

// A reasoning-heavy response can be billed for far more completion tokens than max_tokens, because
// hidden reasoning counts as completion. Grok's reservation must therefore cover its endpoint's
// billable completion ceiling, so such a response fits within its reservation and reconciles at its
// real KNOWN cost with its content kept. The usage figures below are synthetic round numbers.
test('a Grok response billed past max_tokens by hidden reasoning fits its reservation and reconciles at its real KNOWN cost', async () => {
  const reasoningHeavyBody = {
    provider: 'xAI',
    choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }],
    usage: {
      prompt_tokens: 5_000,
      completion_tokens: 100_000,
      completion_tokens_details: { reasoning_tokens: 98_000 },
      cost: 0.6,
    },
  };
  const dispatch = createOrderedFakeDispatch({ responses: [responseFor(reasoningHeavyBody)] });
  await withEngine(async ({ engine, leaseStore }) => {
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, {
      profile: 'final_verification_v1', changeKinds: [], maxJobs: 1,
    });
    const grokMaxUsd = preflight.reviewers.find((reviewer) => reviewer.reviewerId === 'grok').maxUsd;
    assert.equal(grokMaxUsd >= 0.6, true, `Grok reservation ${grokMaxUsd} must cover a reasoning-heavy bill`);
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });
    assert.equal(result.state, 'PASSED');
    assert.equal(result.reviewers.grok.costKind, 'KNOWN');
    assert.equal(result.reviewers.grok.costUsd, 0.6);
    assert.deepEqual(result.reviewers.grok.advisory, { verdict: 'pass', findings: [] });
    const lease = await leaseStore.getLease(leaseId);
    assert.equal(lease.spentUsd, 0.6);
  }, { dispatch });
});
