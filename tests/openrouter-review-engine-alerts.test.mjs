import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { createFakeDispatchWorker } from './fixtures/openrouter-review/fake-dispatch-worker.mjs';

// Covers the review pipeline's two operational alerts: the 75%-of-monthly-cap proactive warning
// and the consecutive-dispatch-failure critical alert. Both
// alerts are wired into review-engine.mjs's own review() pipeline; the tests here exercise that
// wiring end to end (real leaseStore, real dispatchHealthStore) against fakes only for the two
// genuinely external collaborators -- keyStatusProbe (would otherwise shell out to PowerShell and
// touch a real credential) and alertStore (faked here so assertions can inspect exactly what was
// recorded, though alert-store.mjs itself has its own dedicated, already-green test suite).

const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };

function geminiPassBody(findings = []) {
  return { provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.01 } };
}
function grokPassBody(findings = []) {
  return { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: 0.02 } };
}
function responseFor(body, httpStatus = 200) {
  return { httpStatus, bodyText: JSON.stringify(body) };
}

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

function createFakeAlertStore() {
  const records = [];
  return Object.freeze({
    records,
    async record({ severity, reason, component }) {
      records.push({ severity, reason, component });
    },
    async list() {
      return records.slice();
    },
  });
}

function createThrowingListAlertStore() {
  return Object.freeze({
    async record() { throw new Error('alert store record failed'); },
    async list() { throw new Error('alert store list failed'); },
  });
}

function createFakeKeyStatusProbe(statusOrFn) {
  const calls = [];
  const resolve = typeof statusOrFn === 'function' ? statusOrFn : async () => statusOrFn;
  return Object.freeze({
    calls,
    async check() {
      calls.push(true);
      return resolve();
    },
  });
}

/**
 * Deterministic, in-memory stand-in for dispatch-health-store.mjs, with the same
 * recordOutcome({ succeeded, alertThreshold }) -> { consecutiveFailures, shouldAlert } and
 * markAlerted() contract (it mirrors review-engine.mjs's own createVolatileDispatchHealthStore,
 * which is module-private there and so cannot be imported).
 *
 * Used by exactly ONE test below -- the one that drives two genuinely concurrent halts within a
 * single batch. The real store is deliberately lock-free and does an unsynchronized read ->
 * compute -> write across two awaits, an accepted tradeoff (see its own docstring) that this fake
 * does NOT claim to fix. It exists so that one test
 * measures the property it names -- two halts in one batch producing two recorded failures --
 * rather than measuring filesystem timing, since a lost update there is observationally identical
 * to the sequential-counting bug the test is meant to catch. The whole update below runs
 * synchronously between the awaits a caller sees, so two concurrent callers can never interleave
 * one's read with the other's write.
 */
function createFakeDispatchHealthStore() {
  let consecutiveFailures = 0;
  let alertedForCurrentStreak = false;
  return Object.freeze({
    async recordOutcome({ succeeded, alertThreshold } = {}) {
      if (succeeded) {
        consecutiveFailures = 0;
        alertedForCurrentStreak = false;
        return { consecutiveFailures: 0, shouldAlert: false };
      }
      consecutiveFailures += 1;
      // Matches the real store exactly: the alerted flag is committed only by markAlerted(), never
      // inline here, so a caller whose alert write fails still gets shouldAlert:true next time.
      const shouldAlert = !alertedForCurrentStreak && consecutiveFailures >= alertThreshold;
      return { consecutiveFailures, shouldAlert };
    },
    async markAlerted() { alertedForCurrentStreak = true; },
  });
}

const ALWAYS_FAILS_DISPATCH_RESPONSES = [{ kind: 'FAILURE', failureKind: 'INTERNAL_ERROR', message: 'fake worker crash' }];

async function withAlertEngine(run, {
  installationHardMaximumUsd = 10, dispatch, alertStore, keyStatusProbe, consecutiveDispatchFailureAlertThreshold, orphanSweepGraceMs,
  dispatchHealthStore,
} = {}) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-alerts-'));
  const START = Date.parse('2026-09-15T12:00:00.000Z');
  let now = START;
  const clock = () => now;
  const advance = (ms) => { now += ms; };
  const leaseStore = createLeaseStore({ dataRoot, clock });
  // This harness's leaseStore is REAL, so
  // createReviewEngine's own required ownerLock must be a REAL handle acquired against it -- a
  // fake acquisitionId would never match this store's real currentOwner, and every test below that
  // reaches a real consume()/reconcile()/close()/createLease()/sweepOrphanedLeases() call would fail
  // closed with PROCESS_OWNERSHIP_LOST.
  const ownerLock = await leaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const fakeDispatch = dispatch ?? createFakeDispatchWorker({ responses: [responseFor(geminiPassBody()), responseFor(grokPassBody())] });
  const fakeAlertStore = alertStore ?? createFakeAlertStore();
  const fakeKeyStatusProbe = keyStatusProbe ?? createFakeKeyStatusProbe({ limit: null, limitRemaining: null, limitReset: null });
  // Defaults to the REAL durable store, so every existing test in this file keeps exercising the
  // production wiring end to end; only the concurrent-halt test below overrides it.
  const healthStore = dispatchHealthStore ?? createDispatchHealthStore({ dataRoot });
  const armFixtureOwner = () => ownerLock.arm({
    acquireTimeoutMs: 5_000,
    lockRetryMs: 250,
    caps: { installationHardMaximumUsd },
  });
  const engine = createReviewEngine({
    leaseStore,
    ownerLock,
    approvalAdapter: { async authorize() { return { outcome: 'APPROVED', nonce: 'n' }; } },
    dispatchAdapter: fakeDispatch,
    resultStore: createResultStore({ dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
    scrubMappingStore: createScrubMappingStore({ dataRoot }),
    clock,
    sourcePolicy: Object.freeze({ allowedRoots: [], maxSourceBytes: 10_000 }),
    preflightPolicy: Object.freeze({ maxRequestBytes: 200_000 }),
    installationHardMaximumUsd,
    repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    alertStore: fakeAlertStore,
    keyStatusProbe: fakeKeyStatusProbe,
    dispatchHealthStore: healthStore,
    ...(consecutiveDispatchFailureAlertThreshold === undefined ? {} : { consecutiveDispatchFailureAlertThreshold }),
    ...(orphanSweepGraceMs === undefined ? {} : { orphanSweepGraceMs }),
  });
  try {
    await run({ engine, fakeAlertStore, fakeKeyStatusProbe, fakeDispatch, leaseStore, ownerLock, armFixtureOwner, advance, START });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// Mirrors review-engine.mjs's own private deriveJobId() (not exported) exactly, matching the same
// deliberate re-derivation-not-import convention tests/openrouter-review-engine.test.mjs already
// uses (see that file's own testDeriveJobId for the reasoning: drift here fails loudly via an
// unexpected real dispatch, never silently).
function testDeriveJobId(leaseId, reviewerId, reviewContractSha256) {
  return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${reviewContractSha256}`, 'utf8').digest('hex');
}

async function runOneCycle(engine, sourceText) {
  const preflight = await engine.preflight({ source_text: sourceText, profile: 'consequential_spec_v1', reviewContext: 'alerts test' });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  return engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: sourceText });
}

/**
 * A deliberately SINGLE-reviewer cycle: final_verification_v1 resolves to reviewerIds ['grok']
 * alone (src/review-core/reviewer-registry.mjs) once an EMPTY changeKinds list adds nothing to it.
 * changeKinds is passed explicitly and is NOT optional for this profile -- source-contract.mjs's
 * reviewerIdsForPreflightProfile throws outright when it is undefined, so omitting it here would
 * fail every test below at preflight time instead of exercising the streak logic at all.
 *
 * The consecutive-dispatch-failure tests below count one dispatch outcome per batch, so a
 * single-reviewer profile keeps that arithmetic exactly one-outcome-per-cycle regardless of whether
 * reviewers dispatch sequentially or concurrently -- which is what those tests are actually about.
 * runOneCycle above stays on the two-reviewer consequential_spec_v1 for the per-BATCH spend-probe
 * tests, which genuinely need two.
 */
async function runOneSingleReviewerCycle(engine, sourceText) {
  const preflight = await engine.preflight({
    source_text: sourceText, profile: 'final_verification_v1', changeKinds: [], reviewContext: 'alerts test',
  });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  return engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: sourceText });
}

// ---------------------------------------------------------------------------
// 75%-of-monthly-cap alert
// ---------------------------------------------------------------------------

test('a PASSED two-reviewer batch checks the key-status probe exactly once (per-batch, not per-reviewer)', async () => {
  await withAlertEngine(async ({ engine, fakeKeyStatusProbe }) => {
    const result = await runOneCycle(engine, 'source one');
    assert.equal(result.state, 'PASSED');
    assert.equal(fakeKeyStatusProbe.calls.length, 1);
  });
});

test('spend usage below the threshold records no spend alert', async () => {
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: 100, limitRemaining: 50, limitReset: 'monthly' }); // 50% used
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    await runOneCycle(engine, 'source one');
    assert.equal(fakeAlertStore.records.filter((r) => r.severity === 'warning').length, 0);
  }, { keyStatusProbe });
});

test('spend usage at or above 75% records exactly one warning alert naming the percent and period', async () => {
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: 100, limitRemaining: 20, limitReset: 'monthly' }); // 80% used
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    await runOneCycle(engine, 'source one');
    const warnings = fakeAlertStore.records.filter((r) => r.severity === 'warning');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].component, 'openrouter-review');
    assert.match(warnings[0].reason, /75 percent/);
    assert.match(warnings[0].reason, /2026-09/);
    // Reason text must itself pass alert-store.mjs's own downstream-safety guard -- no dollar
    // sign, no run of 5+ digits either raw or after the downstream notifier's sanitization.
    assert.doesNotMatch(warnings[0].reason, /\$/);
    assert.doesNotMatch(warnings[0].reason, /\d{5,}/);
  }, { keyStatusProbe });
});

test('a second batch in the SAME billing period, still over threshold, does not re-alert', async () => {
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: 100, limitRemaining: 20, limitReset: 'monthly' });
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    await runOneCycle(engine, 'source one');
    await runOneCycle(engine, 'source two');
    const warnings = fakeAlertStore.records.filter((r) => r.severity === 'warning');
    assert.equal(warnings.length, 1, `expected exactly one warning across two batches in the same period, got: ${JSON.stringify(warnings)}`);
  }, { keyStatusProbe });
});

test('an already-recorded warning alert for the current period (seeded directly) suppresses a new one', async () => {
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: 100, limitRemaining: 20, limitReset: 'monthly' });
  const alertStore = createFakeAlertStore();
  alertStore.records.push({
    severity: 'warning',
    reason: 'openrouter monthly spend crossed 75 percent of cap for period 2026-09',
    component: 'openrouter-review',
  });
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    await runOneCycle(engine, 'source one');
    assert.equal(fakeAlertStore.records.filter((r) => r.severity === 'warning').length, 1, 'no NEW warning should have been appended');
  }, { keyStatusProbe, alertStore });
});

test('an unknown key status (probe failure) records no spend alert and does not throw', async () => {
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: null, limitRemaining: null, limitReset: null });
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    const result = await runOneCycle(engine, 'source one');
    assert.equal(result.state, 'PASSED');
    assert.equal(fakeAlertStore.records.filter((r) => r.severity === 'warning').length, 0);
  }, { keyStatusProbe });
});

test('a spend check whose alertStore itself throws does not fail the review() call', async () => {
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: 100, limitRemaining: 5, limitReset: 'monthly' });
  await withAlertEngine(async ({ engine }) => {
    const result = await runOneCycle(engine, 'source one');
    assert.equal(result.state, 'PASSED');
  }, { keyStatusProbe, alertStore: createThrowingListAlertStore() });
});

// ---------------------------------------------------------------------------
// Consecutive-dispatch-failure health alert
// ---------------------------------------------------------------------------

test('3 consecutive failed batches (default threshold) raise exactly one critical alert, and spend stays irrelevant', async () => {
  const dispatch = createFakeDispatchWorker({ responses: ALWAYS_FAILS_DISPATCH_RESPONSES });
  // Deliberately unknown/zero spend throughout -- proves the health alert is independent of the
  // 75%-cap alert: a pipeline that is completely broken should alert even when nothing has been
  // spent.
  const keyStatusProbe = createFakeKeyStatusProbe({ limit: null, limitRemaining: null, limitReset: null });
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    const first = await runOneSingleReviewerCycle(engine, 'fail one');
    const second = await runOneSingleReviewerCycle(engine, 'fail two');
    const third = await runOneSingleReviewerCycle(engine, 'fail three');
    assert.equal(first.state, 'HALTED');
    assert.equal(second.state, 'HALTED');
    assert.equal(third.state, 'HALTED');
    const criticals = fakeAlertStore.records.filter((r) => r.severity === 'critical');
    assert.equal(criticals.length, 1, `expected exactly one critical alert after the 3rd consecutive failure, got: ${JSON.stringify(criticals)}`);
    assert.equal(criticals[0].component, 'openrouter-review');
    assert.match(criticals[0].reason, /3/);
    assert.doesNotMatch(criticals[0].reason, /\$/);
  }, { dispatch, keyStatusProbe });
});

test('a 4th and 5th consecutive failure do not add further critical alerts for the same streak', async () => {
  const dispatch = createFakeDispatchWorker({ responses: ALWAYS_FAILS_DISPATCH_RESPONSES });
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    await runOneSingleReviewerCycle(engine, 'fail 1');
    await runOneSingleReviewerCycle(engine, 'fail 2');
    await runOneSingleReviewerCycle(engine, 'fail 3');
    await runOneSingleReviewerCycle(engine, 'fail 4');
    await runOneSingleReviewerCycle(engine, 'fail 5');
    const criticals = fakeAlertStore.records.filter((r) => r.severity === 'critical');
    assert.equal(criticals.length, 1);
  }, { dispatch });
});

test('a configured lower threshold (2) alerts sooner', async () => {
  const dispatch = createFakeDispatchWorker({ responses: ALWAYS_FAILS_DISPATCH_RESPONSES });
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    const first = await runOneSingleReviewerCycle(engine, 'fail 1');
    assert.equal(first.state, 'HALTED');
    assert.equal(fakeAlertStore.records.filter((r) => r.severity === 'critical').length, 0);
    const second = await runOneSingleReviewerCycle(engine, 'fail 2');
    assert.equal(second.state, 'HALTED');
    assert.equal(fakeAlertStore.records.filter((r) => r.severity === 'critical').length, 1);
  }, { dispatch, consecutiveDispatchFailureAlertThreshold: 2 });
});

test('a success in between two failures resets the streak, so 2 failures + 1 success + 1 failure does not alert at threshold 3', async () => {
  // Keyed on an explicit phase flag rather than a running call index: the previous version
  // hardcoded which call number was which reviewer, which silently breaks the moment batch
  // composition or dispatch ordering changes. The phase is flipped by the test between cycles, so
  // what each cycle does is stated where it is read.
  let failing = true;
  const dispatch = {
    async dispatch(request) {
      if (failing) return { kind: 'FAILURE', failureKind: 'INTERNAL_ERROR', message: 'fake crash' };
      const body = request.reviewerId === 'gemini' ? geminiPassBody() : grokPassBody();
      return { kind: 'RESPONSE', envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }) };
    },
  };
  await withAlertEngine(async ({ engine, fakeAlertStore }) => {
    const r1 = await runOneSingleReviewerCycle(engine, 'fail 1');
    const r2 = await runOneSingleReviewerCycle(engine, 'fail 2');
    failing = false;
    const r3 = await runOneSingleReviewerCycle(engine, 'pass 3');
    failing = true;
    const r4 = await runOneSingleReviewerCycle(engine, 'fail 4');
    assert.equal(r1.state, 'HALTED');
    assert.equal(r2.state, 'HALTED');
    assert.equal(r3.state, 'PASSED');
    assert.equal(r4.state, 'HALTED');
    // Without the reset the streak would be 3 by r4 and would have alerted; with it, r4 is a
    // streak of 1.
    assert.equal(fakeAlertStore.records.filter((r) => r.severity === 'critical').length, 0);
  }, { dispatch, consecutiveDispatchFailureAlertThreshold: 3 });
});

test('a health-store failure during recording does not fail the review() call', async () => {
  const dispatch = createFakeDispatchWorker({ responses: ALWAYS_FAILS_DISPATCH_RESPONSES });
  await withAlertEngine(async ({ engine }) => {
    const result = await runOneSingleReviewerCycle(engine, 'fail 1');
    assert.equal(result.state, 'HALTED');
  }, { dispatch, alertStore: createThrowingListAlertStore() });
});

// Regression test: recordDispatchHealthOutcome must not let dispatch-health-store.mjs commit
// `alertedForCurrentStreak: true` on the crossing call before the alertStore.record() write has
// actually succeeded. If that write then failed (this test) with the flag already durably true,
// EVERY later consecutive failure in the same streak would report shouldAlert:false and the alert
// would be lost forever for that streak -- silently defeating the whole point of the alert. The
// flag is therefore committed by a separate markAlerted() call made only after alertStore.record()
// actually succeeds.
test('a transient alert-store failure exactly at the crossing call does not permanently silence the critical alert for the rest of the streak', async () => {
  const dispatch = createFakeDispatchWorker({ responses: ALWAYS_FAILS_DISPATCH_RESPONSES });
  const records = [];
  let recordCallCount = 0;
  const flakyAlertStore = Object.freeze({
    async record({ severity, reason, component }) {
      recordCallCount += 1;
      if (recordCallCount === 1) throw new Error('simulated transient alert-store failure');
      records.push({ severity, reason, component });
    },
    async list() { return records.slice(); },
  });
  await withAlertEngine(async ({ engine }) => {
    const r1 = await runOneSingleReviewerCycle(engine, 'fail 1');
    const r2 = await runOneSingleReviewerCycle(engine, 'fail 2');
    const r3 = await runOneSingleReviewerCycle(engine, 'fail 3'); // crosses threshold 3; alertStore.record() throws here (1st call)
    assert.equal(r1.state, 'HALTED');
    assert.equal(r2.state, 'HALTED');
    assert.equal(r3.state, 'HALTED');
    assert.equal(records.filter((r) => r.severity === 'critical').length, 0, 'the alert write failed on the crossing call, so nothing should be recorded yet');

    const r4 = await runOneSingleReviewerCycle(engine, 'fail 4'); // must retry, since markAlerted() was never reached
    assert.equal(r4.state, 'HALTED');
    const criticals = records.filter((r) => r.severity === 'critical');
    assert.equal(criticals.length, 1, `the retry on the 4th consecutive failure must succeed and deliver exactly one critical alert, got: ${JSON.stringify(criticals)}`);

    // And once delivered, a further consecutive failure must NOT re-alert -- retry-on-failure must
    // not turn into always-retry-forever.
    const r5 = await runOneSingleReviewerCycle(engine, 'fail 5');
    assert.equal(r5.state, 'HALTED');
    assert.equal(records.filter((r) => r.severity === 'critical').length, 1);
  }, { dispatch, alertStore: flakyAlertStore });
});

// Regression test: an orphan-recovered job (a RESERVED dispatch force-closed at worst-case because
// its true outcome was never captured -- typically because the host process died mid-dispatch)
// must feed the consecutive-failure counter, via EITHER of the two paths that can recover one.
// Otherwise a pipeline stuck leaving orphaned jobs across restarts could rack up an unbounded run
// of real failures while this counter stayed at zero, never crossing the alert threshold. Both tests below
// use a threshold LOW enough that the recovery event(s) alone must cross it, so a broken
// implementation (recovery never touching the counter) provably fails these rather than merely
// under-testing them.

test('an orphaned job recovered via review()\'s own inline recovery path counts toward the consecutive-failure streak', async () => {
  const alertStore = createFakeAlertStore();
  await withAlertEngine(async ({ engine, leaseStore, ownerLock, armFixtureOwner, advance, START: startedAt }) => {
    const preflight = await engine.preflight({ source_text: 'orphan source', profile: 'consequential_spec_v1', reviewContext: 'orphan test' });
    const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const jobId = testDeriveJobId(authorization.leaseId, 'gemini', preflight.reviewContractSha256);
    // Reserve the job directly (bypassing dispatch entirely) -- simulates a dispatch that was
    // attempted but never reconciled, e.g. the Node process died before a durable outcome capture
    // (the STATUS_CONTROL_C_EXIT/WORKER_PRODUCED_NO_OUTCOME failure class).
    await armFixtureOwner();
    await leaseStore.consume(authorization.leaseId, preflight.reviewContractSha256, {
      reservationUsd: preflight.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd,
      jobId, acquisitionId: ownerLock.acquisitionId,
    });
    const lease = await leaseStore.getLease(authorization.leaseId);

    // Past expiresAt AND past the default 2-minute orphan-sweep grace window.
    advance((Date.parse(lease.expiresAt) - startedAt) + 2 * 60 * 1000 + 1_000);

    // Keep this valid fixture acquisition through review(): an unarmed handle would make the
    // arm-cycle sweep recover first and would stop exercising review's inline path.
    // runOperation releases this owner when review completes.
    const result = await engine.review({ leaseId: authorization.leaseId, preflightId: preflight.preflightId, source_text: 'orphan source' });
    assert.equal(result.state, 'HALTED');
    assert.equal(result.error.code, 'LEASE_EXPIRED');
    assert.equal(result.recoveredJobs.length, 1, 'sanity check: this really did go through the orphan-recovery path, not some other halt');

    // Threshold 1: the single recovered job alone must be enough to cross and alert.
    const criticals = alertStore.records.filter((r) => r.severity === 'critical');
    assert.equal(criticals.length, 1, `expected the orphan recovery itself to cross a threshold of 1, got: ${JSON.stringify(criticals)}`);
  }, { alertStore, consecutiveDispatchFailureAlertThreshold: 1 });
});

test('recoverOrphanedLeases() (the server-startup sweep) also counts every recovered job toward the consecutive-failure streak, across multiple leases in one sweep', async () => {
  const alertStore = createFakeAlertStore();
  await withAlertEngine(async ({ engine, leaseStore, ownerLock, armFixtureOwner, advance, START: startedAt }) => {
    // Two separate documents, each left with one orphaned RESERVED job -- 2 recovered jobs total,
    // against a threshold of 2, so BOTH must be counted for this to cross.
    const first = await engine.preflight({ source_text: 'orphan A', profile: 'consequential_spec_v1', reviewContext: 'orphan test' });
    const firstAuth = await engine.authorizeWorkflow({ preflightId: first.preflightId, maxJobs: 2 });
    await armFixtureOwner();
    let firstLease;
    try {
      await leaseStore.consume(firstAuth.leaseId, first.reviewContractSha256, {
        reservationUsd: first.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd,
        jobId: testDeriveJobId(firstAuth.leaseId, 'gemini', first.reviewContractSha256),
        acquisitionId: ownerLock.acquisitionId,
      });

      const second = await engine.preflight({ source_text: 'orphan B', profile: 'consequential_spec_v1', reviewContext: 'orphan test' });
      const secondAuth = await engine.authorizeWorkflow({ preflightId: second.preflightId, maxJobs: 2 });
      await armFixtureOwner();
      await leaseStore.consume(secondAuth.leaseId, second.reviewContractSha256, {
        reservationUsd: second.itemMaxima.find((item) => item.itemId === 'item-gemini').maxUsd,
        jobId: testDeriveJobId(secondAuth.leaseId, 'gemini', second.reviewContractSha256),
        acquisitionId: ownerLock.acquisitionId,
      });

      firstLease = await leaseStore.getLease(firstAuth.leaseId);
    } finally {
      await ownerLock.release({ final: false });
    }
    advance((Date.parse(firstLease.expiresAt) - startedAt) + 2 * 60 * 1000 + 1_000);

    const swept = await engine.recoverOrphanedLeases();
    assert.equal(swept.length, 2, 'sanity check: both orphaned leases were actually recovered by this sweep');
    assert.equal(swept[0].reconciledJobs.length + swept[1].reconciledJobs.length, 2);

    const criticals = alertStore.records.filter((r) => r.severity === 'critical');
    assert.equal(criticals.length, 1, `expected the 2 recovered jobs together to cross a threshold of 2, got: ${JSON.stringify(criticals)}`);
  }, { alertStore, consecutiveDispatchFailureAlertThreshold: 2 });
});

// Reviewers in a batch dispatch in parallel, so a two-reviewer batch in which BOTH reviewers halt
// feeds TWO failures into the streak counter, not one: the first reviewer's halt does not cancel
// the second. Threshold 2 with a SINGLE
// batch is what makes that provable: an implementation that still counted one outcome per batch
// would record a streak of 1 here and raise no alert at all. The fake health store (see its own
// docstring above) is what makes the count deterministic rather than a race against the real
// store's deliberately lock-free read-modify-write.
//
// The key-status assertion is the HALTED-path half of the per-batch invariant the
// "PASSED two-reviewer batch checks the key-status probe exactly once" test above states for the
// PASSED path. It catches haltAndClose running its own checkSpendAndMaybeAlert() per halt: two
// halts plus finalization would make three probe calls for one batch, each a real PowerShell
// process in production.
test('a two-reviewer batch in which both reviewers halt records two dispatch failures, not one, and still checks the key-status probe exactly once', async () => {
  const dispatch = createFakeDispatchWorker({ responses: ALWAYS_FAILS_DISPATCH_RESPONSES });
  await withAlertEngine(async ({ engine, fakeAlertStore, fakeKeyStatusProbe }) => {
    const result = await runOneCycle(engine, 'both reviewers fail');
    assert.equal(result.state, 'HALTED');
    assert.equal(result.reviewers.gemini.error.code, 'TRANSPORT_FAILURE');
    assert.equal(result.reviewers.grok.error.code, 'TRANSPORT_FAILURE');
    const criticals = fakeAlertStore.records.filter((r) => r.severity === 'critical');
    assert.equal(criticals.length, 1, `two halts in one batch must cross a threshold of 2 on their own, got: ${JSON.stringify(criticals)}`);
    assert.equal(fakeKeyStatusProbe.calls.length, 1, 'the spend probe is per-BATCH: finalization owns it, and a halted reviewer must not add a call of its own');
  }, {
    dispatch,
    consecutiveDispatchFailureAlertThreshold: 2,
    dispatchHealthStore: createFakeDispatchHealthStore(),
  });
});
