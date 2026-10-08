import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore, LEDGER_DATA_ROOT_LOCKED_CODE } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine, finalizeReviewOutcome, reserveReviewers, ReviewEngineError } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

// Engine-level coverage for on-demand ownership arming, run against a REAL createLeaseStore() on a
// fresh temp data root: the arming, cycle-recovery and bracket properties are claims about real
// ledger records, which a fake store would satisfy silently. Fully offline: fake dispatch and
// approval adapters, no OpenRouter request, no credential.

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const sourcePolicy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const START = Date.parse('2026-09-18T12:00:00.000Z');
const LEDGER_BUSY_MESSAGE = 'the review ledger is busy (another session is using it); retrying the same call is safe';

const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

function geminiPassBody() {
  return { provider: 'Google', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.01 } };
}

function grokPassBody() {
  return { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.02 } };
}

function responseEnvelope(body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

const passingDispatch = Object.freeze({
  async dispatch(request) { return responseEnvelope(request.reviewerId === 'gemini' ? geminiPassBody() : grokPassBody()); },
});

const approvingApproval = Object.freeze({
  async authorize() { return { outcome: 'APPROVED', nonce: 'fake-nonce' }; },
});

// The exact shape of error a real data-root lock timeout throws (lease-store.mjs dataRootLockedError):
// a plain Error carrying the code this file imports from the store, never a re-typed literal.
function ledgerLockedError() {
  return Object.assign(new Error('ledger data root is locked'), { code: LEDGER_DATA_ROOT_LOCKED_CODE });
}

function isLedgerBusy(error) {
  assert.ok(error instanceof ReviewEngineError, `expected a ReviewEngineError, got ${error?.name} with code ${error?.code}`);
  assert.equal(error.code, 'LEDGER_BUSY');
  assert.equal(error.message, LEDGER_BUSY_MESSAGE);
  return true;
}

// For the six per-site translation tests. A site translation builds its LEDGER_BUSY with no details at all, while the
// boundary translation (tested below) always adds details.originalMessage. So if a site's own translation is removed,
// the boundary still produces the same code and message, and only this absence check notices.
function isSiteLedgerBusy(error) {
  isLedgerBusy(error);
  assert.equal(Object.hasOwn(error, 'details'), false, 'a site translation carries no details (only the boundary adds details.originalMessage)');
  return true;
}

// Copied from tests/openrouter-review-lease-process-liveness.test.mjs (not exported there): seeds the
// RAW `.ledger-write.lock` mkdir mutex directly, so every later mutate() on this data root genuinely
// contends for it until the store's own lockTimeoutMs expires.
async function seedDataRootLock(dataRoot, { pid, timestamp, lockToken = randomUUID() }) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  await mkdir(lockRoot, { recursive: true });
  const owner = { pid, timestamp, lockToken };
  await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(owner)}\n`, 'utf8');
  return owner;
}

/**
 * One fresh temp data root, a REAL lease store (optionally wrapped), and an ownership handle made by
 * `makeOwnerLock` -- by default a pre-armed one from the legacy acquireProcessOwnership(), which
 * every engine version accepts. Tests build their engine(s) through `buildEngine(overrides)` so a
 * test that expects construction itself to throw can still use this harness. `clock` is the one
 * controllable clock every store and engine here shares, so a test can build a second store on the
 * same data root that agrees with the first about "now".
 */
async function withEngine(run, {
  makeOwnerLock = (store) => store.acquireProcessOwnership({ acquireTimeoutMs: 5_000 }),
  wrapLeaseStore,
  storeOptions = {},
  engineOptions = {},
} = {}) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-engine-arming-'));
  let now = START;
  const clock = () => now;
  const advance = (ms) => { now += ms; };
  try {
    const realLeaseStore = createLeaseStore({ dataRoot, clock, ...storeOptions });
    const leaseStore = wrapLeaseStore ? wrapLeaseStore(realLeaseStore) : realLeaseStore;
    const ownerLock = await makeOwnerLock(realLeaseStore);
    const buildEngine = (overrides = {}) => createReviewEngine({
      leaseStore,
      ownerLock,
      approvalAdapter: approvingApproval,
      dispatchAdapter: passingDispatch,
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
      ...engineOptions,
      ...overrides,
    });
    await run({ dataRoot, realLeaseStore, leaseStore, ownerLock, buildEngine, advance, clock });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function preflightAndAuthorize(engine, { source_text = 'x', profile = 'consequential_spec_v1', changeKinds, maxJobs = 2 } = {}) {
  const preflight = await engine.preflight({ source_text, profile, changeKinds, reviewContext: 'arming test scope' });
  const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs });
  return { preflight, leaseId: authorization.leaseId, preflightId: preflight.preflightId };
}

// ---------------------------------------------------------------------------
// Error vocabulary.
// ---------------------------------------------------------------------------

test('ReviewEngineError accepts the three ownership-arming codes and carries an optional, frozen, advisory details copy', () => {
  for (const code of ['PROCESS_OWNERSHIP_UNAVAILABLE', 'LEDGER_BUSY', 'OWNERSHIP_CAP_MISMATCH']) {
    const error = new ReviewEngineError(code, `${code} happened`);
    assert.equal(error.code, code);
    assert.equal(Object.hasOwn(error, 'details'), false, 'no details property at all when none is supplied');
  }

  const payload = { reason: 'LIVE_OWNER', owner: { pid: 4321, generation: 3, timestamp: '2026-09-18T12:00:00.000Z' }, ownerAgeMs: 12_000 };
  const withDetails = new ReviewEngineError('PROCESS_OWNERSHIP_UNAVAILABLE', 'held elsewhere', payload);
  assert.deepEqual(withDetails.details, payload);
  assert.equal(Object.isFrozen(withDetails.details), true);
  payload.reason = 'MUTATED_AFTER_CONSTRUCTION';
  assert.equal(withDetails.details.reason, 'LIVE_OWNER', 'details is a copy, never the caller\'s own object');

  for (const notPlain of [null, [], 'text', 7, new Date(0)]) {
    assert.throws(() => new ReviewEngineError('LEDGER_BUSY', 'busy', notPlain), TypeError);
  }
  assert.throws(() => new ReviewEngineError('NOT_A_REAL_CODE', 'x'), TypeError);
});

test('ReviewEngineError accepts the fixed process-ownership release-failure code', () => {
  const error = new ReviewEngineError(
    'PROCESS_OWNERSHIP_RELEASE_FAILED',
    'process ownership could not be released after an earlier operation; this server refuses new owner-sensitive work; preflight, status and result remain callable',
  );
  assert.equal(error.code, 'PROCESS_OWNERSHIP_RELEASE_FAILED');
});

test('status() reports a REAL data-root lock timeout as LEDGER_BUSY, not a raw lease-store error', async () => {
  await withEngine(async ({ dataRoot, buildEngine }) => {
    const engine = buildEngine();
    // Our own live pid and a fresh timestamp: never stale, never reclaimable, so the real store waits
    // out its 50 ms lockTimeoutMs and throws its real LEDGER_DATA_ROOT_LOCKED error.
    await seedDataRootLock(dataRoot, { pid: process.pid, timestamp: new Date(START).toISOString() });
    await assert.rejects(engine.status({ leaseId: 'any-lease' }), isSiteLedgerBusy);
  }, { storeOptions: { lockTimeoutMs: 50, lockRetryMs: 5 } });
});

test('result() reports a ledger-busy store read as LEDGER_BUSY', async () => {
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    await assert.rejects(engine.result({ leaseId: 'any-lease' }), isSiteLedgerBusy);
  }, { wrapLeaseStore: (real) => ({ ...real, async getLease() { throw ledgerLockedError(); } }) });
});

test('preflight() reports a ledger-busy createPreflight as LEDGER_BUSY', async () => {
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    await assert.rejects(
      engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' }),
      isSiteLedgerBusy,
    );
  }, { wrapLeaseStore: (real) => ({ ...real, async createPreflight() { throw ledgerLockedError(); } }) });
});

test('the getCachedPreflight() durable fallback reports a ledger-busy getPreflight as LEDGER_BUSY', async () => {
  await withEngine(async ({ buildEngine }) => {
    // A fresh engine has an empty in-process preflight cache, so authorizeWorkflow() must take the
    // durable leaseStore.getPreflight() fallback -- the read under test.
    const engine = buildEngine();
    await assert.rejects(
      engine.authorizeWorkflow({ preflightId: 'preflight-this-engine-never-cached', maxJobs: 1 }),
      isSiteLedgerBusy,
    );
  }, { wrapLeaseStore: (real) => ({ ...real, async getPreflight() { throw ledgerLockedError(); } }) });
});

test('a ledger-busy consume() is translated to LEDGER_BUSY, not the LEASE_MISSING catch-all', async () => {
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    await assert.rejects(engine.review({ leaseId, preflightId, source_text: 'x' }), isSiteLedgerBusy);
  }, { wrapLeaseStore: (real) => ({ ...real, async consume() { throw ledgerLockedError(); } }) });
});

test('a ledger-busy createLease() is translated to LEDGER_BUSY, not CONTRACT_CHANGED', async () => {
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    await assert.rejects(engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }), isSiteLedgerBusy);
  }, { wrapLeaseStore: (real) => ({ ...real, async createLease() { throw ledgerLockedError(); } }) });
});

// ---------------------------------------------------------------------------
// Boundary translation: EVERY non-arming store call reachable from a tool must surface a lock
// timeout as LEDGER_BUSY; the per-site translations above cannot reach every call on every path,
// so the export object applies one boundary.
// ---------------------------------------------------------------------------

function isBoundaryLedgerBusy(error) {
  isLedgerBusy(error);
  assert.deepEqual(error.details, { originalMessage: 'ledger data root is locked' }, 'the boundary keeps the raw message as advisory details');
  return true;
}

test('result() reports a ledger-busy store call made AFTER its opening getLease (its per-reviewer getJob) as LEDGER_BUSY', async () => {
  const getJobCalls = [];
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    const { leaseId } = await preflightAndAuthorize(engine);
    await assert.rejects(engine.result({ leaseId }), isBoundaryLedgerBusy);
    assert.equal(getJobCalls.length, 1, 'precondition: result() got past getLease and getPreflight to its first per-reviewer ledger read');
  }, { wrapLeaseStore: (real) => ({ ...real, async getJob(jobId) { getJobCalls.push(jobId); throw ledgerLockedError(); } }) });
});

test('review() reports a ledger-busy opening getLease as LEDGER_BUSY, and the boundary rethrows any other failure unchanged', async () => {
  let nextGetLeaseFailure = null;
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    const { leaseId, preflightId } = await preflightAndAuthorize(engine);
    nextGetLeaseFailure = ledgerLockedError();
    await assert.rejects(engine.review({ leaseId, preflightId, source_text: 'x' }), isBoundaryLedgerBusy);
    const unrelated = new Error('an unrelated store failure');
    nextGetLeaseFailure = unrelated;
    await assert.rejects(
      engine.review({ leaseId, preflightId, source_text: 'x' }),
      (error) => error === unrelated,
      'the boundary never catches anything but the raw lock code',
    );
  }, {
    wrapLeaseStore: (real) => ({
      ...real,
      async getLease(leaseId) {
        const failure = nextGetLeaseFailure;
        nextGetLeaseFailure = null;
        if (failure !== null) throw failure;
        return real.getLease(leaseId);
      },
    }),
  });
});

test('authorizeWorkflow() reports a ledger-busy autonomous prior-lease count (countLeasesForRawSource) as LEDGER_BUSY', async () => {
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine({ autonomousAuthorization: true });
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    await assert.rejects(engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }), isBoundaryLedgerBusy);
  }, { wrapLeaseStore: (real) => ({ ...real, async countLeasesForRawSource() { throw ledgerLockedError(); } }) });
});

test('the recoverOrphanedLeases export reports a ledger-busy opening findStaleReservedJobs as LEDGER_BUSY', async () => {
  const sweepCalls = [];
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine();
    await assert.rejects(engine.recoverOrphanedLeases(), isBoundaryLedgerBusy);
    assert.equal(sweepCalls.length, 1, 'precondition: the export reached its store-wide stale-job read');
  }, { wrapLeaseStore: (real) => ({ ...real, async findStaleReservedJobs(query) { sweepCalls.push(query); throw ledgerLockedError(); } }) });
});

// ---------------------------------------------------------------------------
// Retrying review() after LEDGER_BUSY resumes real progress and never redoes it (retrying the
// same call is safe, review() included). The progress here is the kind that costs money: a
// reviewer genuinely dispatched, its outcome captured on disk the way the dispatch worker writes it,
// and its job still RESERVED because the ledger was busy every time the engine tried to reconcile it.
// ---------------------------------------------------------------------------

test('a retried review() after LEDGER_BUSY recovers a dispatched, still-RESERVED job from its captured outcome, and never dispatches or charges it twice', async () => {
  let reconcileBusy = false;
  await withEngine(async ({ dataRoot, realLeaseStore, buildEngine }) => {
    const dispatchCalls = [];
    const outcomeStore = createDispatchOutcomeStore({ dataRoot });
    const engine = buildEngine({
      // A busy reconcile of this job's real outcome is retried within a bounded
      // budget before the path below runs. This no-wait sleep spends that budget at once (the engine
      // counts slept time even on this harness's frozen clock), so every step below ends as before.
      sleep: async () => {},
      dispatchAdapter: {
        async dispatch(request) {
          dispatchCalls.push(request.reviewerId);
          const outcome = responseEnvelope(grokPassBody());
          // As in production: the adapter claims the outcome file first, and the worker's durable
          // capture overwrites that claim before the outcome is returned.
          await outcomeStore.markDispatching({ jobId: request.jobId });
          await writeFile(dispatchOutcomePath({ dataRoot, jobId: request.jobId }), JSON.stringify(outcome), 'utf8');
          return outcome;
        },
      },
    });
    // final_verification_v1 with an empty changeKinds reserves grok alone.
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [], maxJobs: 1 });
    const input = { leaseId, preflightId, source_text: 'x' };

    // 1. The first call reserves and dispatches grok, but the ledger is busy for both of its
    //    reconciles (the clean pass, then the rejection loop's worst-case recovery), so the job stays
    //    RESERVED and uncharged, and the lease stays ACTIVE.
    reconcileBusy = true;
    const first = await engine.review(input);
    assert.deepEqual(dispatchCalls, ['grok'], 'precondition: the first call dispatched grok');
    assert.equal(first.state, 'HALTED');
    assert.equal(first.reviewers.grok.error.code, 'DISPATCH_UNKNOWN');
    // The worst-case recovery reconcile timed out too, so nothing charged the job: the entry is the
    // rejection loop's uncharged stub, not a full-reservation charge.
    assert.equal(first.reviewers.grok.state, 'RESERVED');
    assert.equal(first.reviewers.grok.costUsd, 0, 'a double lock timeout charges nothing');
    assert.equal(first.reviewers.grok.costKind, 'RECOVERED_STATUS_ONLY');
    const leaseAfterFirst = await realLeaseStore.getLease(leaseId);
    assert.equal(leaseAfterFirst.state, 'ACTIVE', 'a still-RESERVED job keeps its lease open');
    assert.ok(leaseAfterFirst.reservedUsd > 0, 'its reservation is still held, so the cap still counts it');
    const [reserved] = await realLeaseStore.findJobsForReviewerContract(first.reviewContractSha256, 'grok');
    assert.equal(reserved.state, 'RESERVED', 'precondition: real progress exists, a dispatched job still RESERVED');
    assert.equal((await outcomeStore.recall({ jobId: reserved.id })).kind, 'RESPONSE', 'precondition: its outcome is captured on disk');

    // 2. The retry while the ledger is still busy: Step 1's recovery reconcile of that job times out,
    //    and the caller gets LEDGER_BUSY with the job still RESERVED.
    const second = await engine.review(input).then(() => null, (error) => error);
    assert.deepEqual(dispatchCalls, ['grok'], 'the retry must never dispatch grok again');
    assert.ok(second !== null, 'the busy retry must reject, not return a result');
    isSiteLedgerBusy(second);
    assert.equal((await realLeaseStore.getJob(reserved.id)).state, 'RESERVED', 'the busy retry committed nothing');

    // 3. The retry once the ledger is free: the captured outcome is reconciled at its real cost.
    reconcileBusy = false;
    const third = await engine.review(input);
    assert.deepEqual(dispatchCalls, ['grok'], 'recovering the captured outcome must not dispatch grok again');
    assert.equal(third.state, 'PASSED');
    assert.equal(third.reviewers.grok.costKind, 'KNOWN');
    assert.equal(third.reviewers.grok.advisory?.verdict, 'pass');
    const jobs = await realLeaseStore.findJobsForReviewerContract(third.reviewContractSha256, 'grok');
    assert.equal(jobs.length, 1, 'one job: nothing was reserved a second time');
    assert.equal(jobs[0].state, 'RECONCILED');
    assert.equal(jobs[0].costUsd, 0.02, 'charged once, at the captured real cost, never at the reservation');
    const lease = await realLeaseStore.getLease(leaseId);
    assert.equal(lease.jobsConsumed, 1);
    assert.equal(lease.reservedUsd, 0);
    assert.equal(lease.spentUsd, 0.02);
  }, {
    wrapLeaseStore: (real) => ({
      ...real,
      async reconcile(jobId, options) {
        if (reconcileBusy) throw ledgerLockedError();
        return real.reconcile(jobId, options);
      },
    }),
  });
});

// ---------------------------------------------------------------------------
// On-demand arming through the ownership coordinator.
// ---------------------------------------------------------------------------

// A genuinely UNARMED handle -- production's real startup shape -- with short arm
// timings, so a regression fails in seconds instead of waiting out the 90 s production budget.
const UNARMED = Object.freeze({
  makeOwnerLock: (store) => store.createUnarmedOwnerHandle(),
  engineOptions: Object.freeze({ armTimeoutMs: 5_000, armLockRetryMs: 10 }),
});

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolveFn, rejectFn) => { resolve = resolveFn; reject = rejectFn; });
  return { promise, resolve, reject };
}

/**
 * Every processOwner record in append order. Copied from tests/openrouter-review-mcp-stdio.test.mjs
 * (not exported there): each ledger entry is one JSON file under <dataRoot>/ledger/ with a
 * fixed-width timestamp prefix, so a name sort is append order. A missing ledger directory reads as
 * "no records"; any other read error surfaces instead of being laundered into an empty result that
 * would satisfy an absence assertion.
 */
async function readProcessOwnerRecords(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const names = await readdir(ledgerRoot).catch((error) => {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  });
  const records = [];
  for (const name of names.filter((entry) => entry.endsWith('.json')).sort()) {
    // eslint-disable-next-line no-await-in-loop
    const record = JSON.parse(await readFile(join(ledgerRoot, name), 'utf8'));
    if (record && record.recordType === 'processOwner') records.push(record);
  }
  return records;
}

async function readLedgerFileNames(dataRoot) {
  const names = await readdir(join(dataRoot, 'ledger')).catch((error) => {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  });
  return names.filter((name) => name.endsWith('.json'));
}

async function withTimeout(promise, timeoutMs, message) {
  let timer;
  const timeout = new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs); });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function captureStderr() {
  const original = process.stderr.write;
  const lines = [];
  process.stderr.write = (chunk) => { lines.push(String(chunk)); return true; };
  return { lines, restore() { process.stderr.write = original; } };
}

// Counts recovery sweeps: recoverStaleLease() opens every sweep with exactly one
// findStaleReservedJobs() call, whether or not it then finds anything.
function countingSweeps(sweeps) {
  return (real) => ({
    ...real,
    async findStaleReservedJobs(options) {
      sweeps.push(options);
      return real.findStaleReservedJobs(options);
    },
  });
}

/**
 * Stands in for a PREVIOUS server session on the same data root: it acquires ownership the legacy
 * way, leaves one lease with a RESERVED job that never reconciled, releases cleanly, and the clock
 * then moves past that lease's expiry plus the default two-minute orphan grace window. The next
 * owner's recovery sweep must close it. The previous engine is pre-armed, so seeding runs no sweep.
 */
async function seedPreviousSessionOrphan({ realLeaseStore, buildEngine, advance }) {
  const previous = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const previousEngine = buildEngine({ ownerLock: previous });
  const orphan = await preflightAndAuthorize(previousEngine, { source_text: 'orphaned by a previous session', maxJobs: 2 });
  await previous.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
  await realLeaseStore.consume(orphan.leaseId, orphan.preflight.reviewContractSha256, {
    reservationUsd: 0.12, jobId: 'orphaned-by-previous-session', acquisitionId: previous.acquisitionId,
  });
  const lease = await realLeaseStore.getLease(orphan.leaseId);
  await previous.release();
  advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);
  return orphan;
}

// A real, genuinely alive process to name as a FOREIGN ownership holder. Copied from
// tests/openrouter-review-lease-process-liveness.test.mjs (not exported there): a second store in
// this same process cannot play that role, because it would share this process's own pid.
async function spawnLongLivedChild() {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { stdio: 'ignore' });
  await new Promise((resolve) => setTimeout(resolve, 200)); // let it actually start
  return child;
}

// Seeds a processOwner ACQUIRED record naming a specific pid directly, bypassing
// acquireProcessOwnership(). Copied from the same liveness test file.
async function seedAcquiredOwnerRecord(dataRoot, { pid, generation, timestamp }) {
  const ledgerRoot = join(dataRoot, 'ledger');
  await mkdir(ledgerRoot, { recursive: true });
  const record = {
    recordType: 'processOwner', state: 'ACQUIRED', pid, generation,
    acquisitionId: randomUUID(), timestamp,
  };
  await writeFile(join(ledgerRoot, `${timestamp.replace(/[:.]/g, '-')}-seed.json`), `${JSON.stringify(record)}\n`, 'utf8');
  return record;
}

test('createReviewEngine accepts a genuinely unarmed handle; constructing it arms nothing and writes no ledger record of any kind', async () => {
  await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
    assert.equal(ownerLock.state, 'unarmed', 'precondition: the harness handed over an unarmed handle');
    buildEngine();
    assert.equal(ownerLock.isOwner(), false);
    assert.equal(ownerLock.acquisitionId, null);
    assert.equal(ownerLock.state, 'unarmed', 'construction must not arm');
    assert.deepEqual(await readLedgerFileNames(dataRoot), [], 'construction must write no ledger record of any kind');
  }, UNARMED);
});

test('a session that only ever calls preflight, status and result never arms and writes no processOwner record', async () => {
  await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
    const engine = buildEngine();
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    assert.equal(typeof preflight.preflightId, 'string');
    await assert.rejects(engine.status({ leaseId: 'no-such-lease' }), (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING');
    await assert.rejects(engine.result({ leaseId: 'no-such-lease' }), (error) => error instanceof ReviewEngineError && error.code === 'LEASE_MISSING');
    assert.equal(ownerLock.state, 'unarmed');
    assert.deepEqual(await readProcessOwnerRecords(dataRoot), [], 'no ACQUIRED record: nothing owner-sensitive was ever called');
  }, UNARMED);
});

async function assertAuthorizeReviewUsesTwoReleasedOwnershipCycles({
  profile,
  maxJobs,
  expectedReviewers,
  dispatchAdapter = passingDispatch,
}) {
  await withEngine(async ({ dataRoot, realLeaseStore, ownerLock, buildEngine }) => {
    const engine = buildEngine({ dispatchAdapter });
    const preflight = await engine.preflight({
      source_text: 'x',
      profile,
      reviewContext: 'operation-release engine test',
    });

    const authorization = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs });
    assert.equal((await realLeaseStore.getLease(authorization.leaseId)).state, 'ACTIVE');
    assert.equal(ownerLock.isOwner(), false, 'authorizeWorkflow releases process ownership after its complete operation');
    assert.equal(ownerLock.state, 'unarmed');
    assert.equal(ownerLock.acquisitionId, null);

    const afterAuthorize = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(afterAuthorize.map((record) => record.state), ['ACQUIRED', 'RELEASED']);
    assert.equal(afterAuthorize[1].acquisitionId, afterAuthorize[0].acquisitionId);

    const result = await engine.review({
      leaseId: authorization.leaseId,
      preflightId: preflight.preflightId,
      source_text: 'x',
    });
    assert.equal(result.state, 'PASSED');
    assert.deepEqual(Object.keys(result.reviewers).sort(), [...expectedReviewers].sort());
    assert.equal(ownerLock.isOwner(), false, 'review releases its fresh process ownership after durable completion');

    const afterReview = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(afterReview.map((record) => record.state), ['ACQUIRED', 'RELEASED', 'ACQUIRED', 'RELEASED']);
    assert.equal(afterReview[1].acquisitionId, afterReview[0].acquisitionId);
    assert.equal(afterReview[3].acquisitionId, afterReview[2].acquisitionId);
    assert.notEqual(afterReview[2].acquisitionId, afterReview[0].acquisitionId, 'review uses a fresh fenced acquisition');
  }, UNARMED);
}

function physicalReleaseSwitch(dataRoot) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  let blocked = false;
  return Object.freeze({
    setBlocked(value) { blocked = value; },
    async renameImpl(from, to) {
      if (blocked && from === lockRoot) {
        throw Object.assign(new Error('private physical release path must stay redacted'), { code: 'EACCES' });
      }
      return rename(from, to);
    },
  });
}

test('paid authorize leaves its lease ACTIVE but releases ownership, then review re-arms that same lease and releases again', async () => {
  await assertAuthorizeReviewUsesTwoReleasedOwnershipCycles({
    profile: 'consequential_spec_v1',
    maxJobs: 2,
    expectedReviewers: ['gemini', 'grok'],
  });
});

test('free authorize and review use separate released ownership cycles around the same ACTIVE lease', async () => {
  const freeDispatch = Object.freeze({
    async dispatch() {
      return responseEnvelope({
        provider: 'Nvidia',
        choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }],
        usage: { cost: 0 },
      });
    },
  });
  await assertAuthorizeReviewUsesTwoReleasedOwnershipCycles({
    profile: 'spec_review_free_v1',
    maxJobs: 3,
    expectedReviewers: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
    dispatchAdapter: freeDispatch,
  });
});

test('paid allowance survives released engine cycles and sibling handoff, refuses the next paid review before dispatch, and leaves free review available', async () => {
  const dispatchCalls = [];
  const dispatchSpy = Object.freeze({
    async dispatch(request) {
      dispatchCalls.push(request.reviewerId);
      if (request.reviewerId === 'grok') return responseEnvelope(grokPassBody());
      return responseEnvelope({
        provider: 'Nvidia',
        choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }],
        usage: { cost: 0 },
      });
    },
  });

  await withEngine(async ({ dataRoot, realLeaseStore, buildEngine, clock }) => {
    const firstHandle = realLeaseStore.createUnarmedOwnerHandle();
    const firstEngine = buildEngine({ ownerLock: firstHandle, dispatchAdapter: dispatchSpy });
    const first = await preflightAndAuthorize(firstEngine, {
      source_text: 'first paid allowance document',
      profile: 'final_verification_v1',
      changeKinds: [],
      maxJobs: 1,
    });
    const firstResult = await firstEngine.review({
      leaseId: first.leaseId,
      preflightId: first.preflightId,
      source_text: 'first paid allowance document',
    });
    assert.equal(firstResult.state, 'PASSED');
    assert.deepEqual(dispatchCalls, ['grok']);
    const firstLease = await realLeaseStore.getLease(first.leaseId);
    const firstJob = await realLeaseStore.getJob(firstResult.reviewers.grok.jobId);
    assert.deepEqual(
      { jobsConsumed: firstLease.jobsConsumed, reservedUsd: firstLease.reservedUsd, spentUsd: firstLease.spentUsd, costKind: firstJob.costKind },
      { jobsConsumed: 1, reservedUsd: 0, spentUsd: 0.02, costKind: 'KNOWN' },
    );
    assert.equal(firstHandle.isOwner(), false);

    const siblingStore = createLeaseStore({ dataRoot, clock, dailyPaidJobAllowance: 1 });
    const siblingHandle = siblingStore.createUnarmedOwnerHandle();
    const siblingEngine = buildEngine({ leaseStore: siblingStore, ownerLock: siblingHandle, dispatchAdapter: dispatchSpy });
    const second = await preflightAndAuthorize(siblingEngine, {
      source_text: 'second paid allowance document',
      profile: 'final_verification_v1',
      changeKinds: [],
      maxJobs: 1,
    });
    await assert.rejects(
      siblingEngine.review({
        leaseId: second.leaseId,
        preflightId: second.preflightId,
        source_text: 'second paid allowance document',
      }),
      (error) => error instanceof ReviewEngineError && error.code === 'DAILY_ALLOWANCE_EXCEEDED',
    );
    assert.deepEqual(dispatchCalls, ['grok'], 'allowance refusal must occur before the sibling dispatch adapter is called');
    const refusedLease = await siblingStore.getLease(second.leaseId);
    assert.deepEqual(
      { jobsConsumed: refusedLease.jobsConsumed, reservedUsd: refusedLease.reservedUsd, spentUsd: refusedLease.spentUsd },
      { jobsConsumed: 0, reservedUsd: 0, spentUsd: 0 },
      'the refused paid review commits no reservation or charge',
    );
    assert.equal(siblingHandle.isOwner(), false);

    const free = await preflightAndAuthorize(siblingEngine, {
      source_text: 'free allowance-independent document',
      profile: 'spec_review_free_v1',
      maxJobs: 3,
    });
    const freeResult = await siblingEngine.review({
      leaseId: free.leaseId,
      preflightId: free.preflightId,
      source_text: 'free allowance-independent document',
    });
    assert.equal(freeResult.state, 'PASSED');
    assert.deepEqual(dispatchCalls, ['grok', 'nemotron_super', 'nemotron_ultra', 'nemotron_lightning']);
    const freeLease = await siblingStore.getLease(free.leaseId);
    const freeJobs = await Promise.all(Object.values(freeResult.reviewers).map(({ jobId }) => siblingStore.getJob(jobId)));
    assert.deepEqual(
      {
        jobsConsumed: freeLease.jobsConsumed,
        reservedUsd: freeLease.reservedUsd,
        spentUsd: freeLease.spentUsd,
        costKinds: freeJobs.map((job) => job.costKind).sort(),
      },
      { jobsConsumed: 3, reservedUsd: 0, spentUsd: 0, costKinds: ['KNOWN', 'KNOWN', 'KNOWN'] },
    );
    assert.equal(siblingHandle.isOwner(), false);

    const owners = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(owners.map((record) => record.state), [
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
    ]);
    for (let index = 0; index < owners.length; index += 2) {
      assert.equal(owners[index + 1].acquisitionId, owners[index].acquisitionId, `cycle ${index / 2 + 1} must release its own acquisition`);
      if (index > 0) assert.notEqual(owners[index].acquisitionId, owners[index - 2].acquisitionId, 'every later operation must re-arm with a fresh fence token');
    }
  }, {
    ...UNARMED,
    storeOptions: { dailyPaidJobAllowance: 1 },
  });
});

test('a review finishes durably and releases after its caller stops awaiting, and a fresh unarmed engine reads it without redispatch or reconciliation', async () => {
  const dispatchCalls = [];
  const reconcileCalls = [];
  await withEngine(async ({ dataRoot, realLeaseStore, ownerLock, buildEngine, clock }) => {
    const engine = buildEngine({
      dispatchAdapter: {
        async dispatch(request) {
          dispatchCalls.push(request.reviewerId);
          return responseEnvelope(grokPassBody());
        },
      },
    });
    const { leaseId, preflightId } = await preflightAndAuthorize(engine, {
      profile: 'final_verification_v1',
      changeKinds: [],
      maxJobs: 1,
    });

    const observedSettlement = createDeferred();
    const abandonedByCaller = engine.review({ leaseId, preflightId, source_text: 'x' });
    abandonedByCaller.then(observedSettlement.resolve, observedSettlement.reject);
    const completed = await observedSettlement.promise;
    assert.equal(completed.state, 'PASSED');
    assert.equal(ownerLock.isOwner(), false, 'the full tracked lifecycle releases even without a caller awaiting the returned promise');
    assert.deepEqual(dispatchCalls, ['grok']);
    assert.equal(reconcileCalls.length, 1);

    const recordsAfterCompletion = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(recordsAfterCompletion.map((record) => record.state), ['ACQUIRED', 'RELEASED', 'ACQUIRED', 'RELEASED']);

    const laterStore = createLeaseStore({ dataRoot, clock });
    const laterHandle = laterStore.createUnarmedOwnerHandle();
    const laterEngine = buildEngine({ leaseStore: laterStore, ownerLock: laterHandle });
    const recovered = await laterEngine.result({ leaseId });
    assert.equal(recovered.state, 'ACTIVE');
    assert.equal(recovered.reviewers.grok.state, 'RECONCILED');
    assert.deepEqual(dispatchCalls, ['grok'], 'result recovery never dispatches again');
    assert.equal(reconcileCalls.length, 1, 'result recovery never reconciles again');
    assert.equal(laterHandle.isOwner(), false, 'result remains ownerless');
    assert.deepEqual(await readProcessOwnerRecords(dataRoot), recordsAfterCompletion, 'ownerless result recovery writes no ownership record');
  }, {
    ...UNARMED,
    wrapLeaseStore: (real) => ({
      ...real,
      async reconcile(...args) {
        reconcileCalls.push(args[0]);
        return real.reconcile(...args);
      },
    }),
  });
});

test('successful authorize survives a real post-RELEASED cleanup failure, a barrier waiter gets the sticky code, and final shutdown cleanup writes no duplicate RELEASED', async () => {
  const releaseEntered = createDeferred();
  const allowCompletionRelease = createDeferred();
  let physicalBlocked = false;
  let physicalLockRoot = null;
  let realOwnerLock;
  const renameImpl = async (from, to) => {
    if (physicalBlocked && from === physicalLockRoot) {
      throw Object.assign(new Error('private physical release path must stay redacted'), { code: 'EACCES' });
    }
    return rename(from, to);
  };

  await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
    const engine = buildEngine({ dispatchHealthStore: createDispatchHealthStore({ dataRoot }) });
    const preflight = await engine.preflight({
      source_text: 'offline physical completion-release success path',
      profile: 'final_verification_v1',
      changeKinds: [],
      reviewContext: 'successful result must survive physical release cleanup failure',
    });

    const completedOperation = engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 1 });
    await releaseEntered.promise;
    const barrierWaiter = engine.authorizeWorkflow({ preflightId: 'never-minted-waiter-preflight', maxJobs: 1 });

    assert.deepEqual(
      await engine.awaitDrain({ timeoutMs: 50 }),
      { drained: false, outstandingCount: 2 },
      'the completed body waiting on release and the caller waiting behind its barrier both remain tracked',
    );

    allowCompletionRelease.resolve();
    const authorization = await completedOperation;
    assert.equal(typeof authorization.leaseId, 'string', 'the completed successful value wins over cleanup failure');
    await assert.rejects(barrierWaiter, (error) => {
      assert.equal(error.code, 'PROCESS_OWNERSHIP_RELEASE_FAILED');
      assert.equal(
        error.message,
        'process ownership could not be released after an earlier operation; this server refuses new owner-sensitive work; preflight, status and result remain callable',
      );
      return true;
    });

    assert.equal(ownerLock.state, 'release-pending');
    assert.equal(ownerLock.isOwner(), false);
    assert.equal(ownerLock.acquisitionId, null);
    assert.equal(ownerLock.generation, null);
    const afterFault = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(afterFault.map((record) => record.state), ['ACQUIRED', 'RELEASED']);
    assert.equal(afterFault[1].acquisitionId, afterFault[0].acquisitionId);
    await assert.rejects(readFile(join(dataRoot, 'dispatch-health.json'), 'utf8'), (error) => error.code === 'ENOENT');

    engine.beginShutdown();
    assert.deepEqual(await engine.awaitDrain({ timeoutMs: 5_000 }), { drained: true, outstandingCount: 0 });
    physicalBlocked = false;
    await ownerLock.release({ final: true });
    assert.equal(realOwnerLock.state, 'released');
    assert.deepEqual(await readProcessOwnerRecords(dataRoot), afterFault, 'final cleanup retries the exact pending lock and never appends another RELEASED');
  }, {
    storeOptions: {
      renameImpl,
      lockTimeoutMs: 30,
      lockRetryMs: 5,
    },
    makeOwnerLock: async (store) => {
      realOwnerLock = store.createUnarmedOwnerHandle();
      physicalLockRoot = join(realOwnerLock.dataRoot, '.ledger-write.lock');
      return Object.freeze({
        get dataRoot() { return realOwnerLock.dataRoot; },
        get generation() { return realOwnerLock.generation; },
        get acquisitionId() { return realOwnerLock.acquisitionId; },
        get state() { return realOwnerLock.state; },
        get everArmed() { return realOwnerLock.everArmed; },
        isOwner: () => realOwnerLock.isOwner(),
        arm: (options) => realOwnerLock.arm(options),
        async release(options) {
          if (options?.final !== true) {
            releaseEntered.resolve();
            await allowCompletionRelease.promise;
            physicalBlocked = true;
          }
          return realOwnerLock.release(options);
        },
      });
    },
  });
});

test('createReviewEngine validates arm timings and refuses malformed IDs or a handle without reusable arm/release methods', async () => {
  // The default (pre-armed) harness on purpose: over an unarmed handle, the constructor could throw
  // for an unrelated handle-shape reason and make every "must be refused" row below pass vacuously.
  await withEngine(async ({ buildEngine }) => {
    for (const bad of [0, -1, 1.5, '90000', Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => buildEngine({ armTimeoutMs: bad }), TypeError, `armTimeoutMs=${String(bad)} must be refused`);
      assert.throws(() => buildEngine({ armLockRetryMs: bad }), TypeError, `armLockRetryMs=${String(bad)} must be refused`);
    }
    assert.doesNotThrow(() => buildEngine({ armTimeoutMs: 1, armLockRetryMs: 1 }));
    const handleShape = { dataRoot: 'fake', isOwner: () => false, async arm() {}, async release() {} };
    assert.throws(() => buildEngine({ ownerLock: { ...handleShape, acquisitionId: '' } }), TypeError, 'an empty acquisitionId is never a valid handle');
    assert.throws(() => buildEngine({ ownerLock: { ...handleShape, acquisitionId: undefined } }), TypeError, 'undefined is not the unarmed null');
    // The unarmed shape the constructor accepts (acquisitionId null) must still carry a callable release: the
    // coordinator's compensating release and the shutdown sequence both call it.
    for (const release of [undefined, 'not callable']) {
      assert.throws(
        () => buildEngine({ ownerLock: { ...handleShape, acquisitionId: null, release } }),
        { name: 'TypeError', message: 'ownerLock.release must be a function' },
        `release=${String(release)} must be refused`,
      );
    }
    for (const arm of [undefined, 'not callable']) {
      assert.throws(
        () => buildEngine({ ownerLock: { ...handleShape, acquisitionId: null, arm } }),
        { name: 'TypeError', message: 'ownerLock.arm must be a function' },
        `arm=${String(arm)} must be refused because the engine re-arms after every completed operation`,
      );
    }
  });
});

test('review() and authorizeWorkflow() fired in the same tick share one arm, then the last completion releases it', async () => {
  await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
    const engine = buildEngine();
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    const [authorized, reviewed] = await Promise.allSettled([
      engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      engine.review({ leaseId: 'no-such-lease', preflightId: preflight.preflightId, source_text: 'x' }),
    ]);
    assert.equal(authorized.status, 'fulfilled', `authorizeWorkflow must succeed, got ${authorized.reason?.code}: ${authorized.reason?.message}`);
    assert.equal(reviewed.status, 'rejected');
    assert.equal(reviewed.reason.code, 'LEASE_MISSING', 'review() must get past the shared arm and fail only on its own missing lease');
    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => record.state), ['ACQUIRED', 'RELEASED'], 'one shared arm and one last-operation release');
    assert.equal(records[1].acquisitionId, records[0].acquisitionId);
    assert.equal(ownerLock.isOwner(), false);
  }, UNARMED);
});

test('shutdown that begins while the arm is suspended after its ACQUIRED commit releases that acquisition and rejects SHUTTING_DOWN; the ledger shows a matched ACQUIRED + RELEASED pair', async () => {
  const hookEntered = createDeferred();
  const resume = createDeferred();
  await withEngine(async ({ dataRoot, ownerLock, realLeaseStore, buildEngine }) => {
    const engine = buildEngine();
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    const authorizing = engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const reached = await Promise.race([
      hookEntered.promise.then(() => 'suspended-after-acquired'),
      authorizing.then(() => 'resolved', (error) => `rejected:${error?.code}`),
    ]);
    assert.equal(reached, 'suspended-after-acquired', 'precondition: the arm is parked after its ACQUIRED append is durable');
    engine.beginShutdown();
    resume.resolve();
    await assert.rejects(authorizing, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => record.state), ['ACQUIRED', 'RELEASED'], 'the compensating release must match the acquisition');
    assert.equal(records[1].acquisitionId, records[0].acquisitionId);
    assert.equal(records[1].generation, records[0].generation);
    assert.equal(ownerLock.state, 'released', 'the compensating release is final');
    const rawSourceSha256 = createHash('sha256').update('x', 'utf8').digest('hex');
    assert.equal(await realLeaseStore.countLeasesForRawSource(rawSourceSha256), 0, 'no lease was granted after shutdown began');
  }, {
    ...UNARMED,
    storeOptions: { afterOwnerAcquired: async () => { hookEntered.resolve(); await resume.promise; } },
  });
});

test('each newly armed paid-entry cycle runs orphan recovery once through the internal path before its triggering call', async () => {
  const sweeps = [];
  const stderr = captureStderr();
  try {
    await withEngine(async ({ realLeaseStore, ownerLock, buildEngine, advance }) => {
      const orphan = await seedPreviousSessionOrphan({ realLeaseStore, buildEngine, advance });
      assert.equal(sweeps.length, 0, 'precondition: seeding ran no sweep');
      const engine = buildEngine();
      await withTimeout(
        preflightAndAuthorize(engine, { source_text: 'the first document after the restart' }),
        5_000,
        'the first authorizeWorkflow on an unarmed engine never settled: the arm cycle deadlocked',
      );
      assert.equal(sweeps.length, 1, 'the arm cycle runs exactly one recovery sweep');
      assert.equal((await realLeaseStore.getLease(orphan.leaseId)).state, 'ORPHANED_ON_RECOVERY', 'the previous session orphan was recovered by the arm cycle');
      assert.equal(ownerLock.isOwner(), false, 'the first completed operation released its acquisition');

      await preflightAndAuthorize(engine, { source_text: 'a second document in a new ownership cycle' });
      assert.equal(sweeps.length, 2, 'a subsequent newly armed cycle runs its own recovery sweep');
    }, { ...UNARMED, wrapLeaseStore: countingSweeps(sweeps) });
  } finally {
    stderr.restore();
  }
  assert.ok(
    stderr.lines.some((line) => line.includes('openrouter-review-engine: arm-cycle-recovery-closed leases=1 jobs=1')),
    `expected one recovery summary line, got:\n${stderr.lines.join('')}`,
  );
});

// The pending store's per-job claim methods are present and return the contract's own shapes
// (recallClaim's neutral stub is { status: 'absent' }, never null), so this literal stays valid even
// if a test hands it a list() that returns a record.
function pendingHealthVerdictStoreWith(list) {
  return {
    async record() {}, async recall() { return null; }, async remove() {}, list,
    async claim() { return { claimed: false }; }, async recallClaim() { return { status: 'absent' }; }, async releaseClaim() {},
  };
}

test('a recovery that fails inside the arm cycle is logged (redacted) and never fails the triggering call, and the pending-health sweep still runs', async () => {
  const healthSweeps = [];
  const stderr = captureStderr();
  try {
    await withEngine(async ({ ownerLock, buildEngine }) => {
      const engine = buildEngine({
        pendingHealthVerdictStore: pendingHealthVerdictStoreWith(async () => { healthSweeps.push('list'); return []; }),
      });
      const authorized = await preflightAndAuthorize(engine);
      assert.equal(typeof authorized.leaseId, 'string', 'the call that triggered the arm still succeeds');
      assert.equal(ownerLock.isOwner(), false, 'the successful trigger releases after its operation');
      assert.deepEqual(healthSweeps, ['list'], 'a failed recovery must not skip the pending-health sweep');
    }, {
      ...UNARMED,
      wrapLeaseStore: (real) => ({ ...real, async findStaleReservedJobs() { throw new Error('simulated recovery failure with private detail'); } }),
    });
  } finally {
    stderr.restore();
  }
  assert.ok(
    stderr.lines.some((line) => line.includes('arm-cycle-recovery-failed') && line.includes('detail redacted')),
    `got:\n${stderr.lines.join('')}`,
  );
  assert.equal(stderr.lines.some((line) => line.includes('private detail')), false, 'the raw error text is never logged');
});

test('a pending-health sweep that fails inside the arm cycle is logged (redacted) and never fails the triggering call, and recovery still ran', async () => {
  const sweeps = [];
  const stderr = captureStderr();
  try {
    await withEngine(async ({ buildEngine }) => {
      const engine = buildEngine({
        pendingHealthVerdictStore: pendingHealthVerdictStoreWith(async () => { throw new Error('simulated health sweep failure with private detail'); }),
      });
      const authorized = await preflightAndAuthorize(engine);
      assert.equal(typeof authorized.leaseId, 'string', 'the call that triggered the arm still succeeds');
      assert.equal(sweeps.length, 1, 'recovery ran before the failing health sweep');
    }, { ...UNARMED, wrapLeaseStore: countingSweeps(sweeps) });
  } finally {
    stderr.restore();
  }
  assert.ok(
    stderr.lines.some((line) => line.includes('arm-cycle-health-sweep-failed') && line.includes('detail redacted')),
    `got:\n${stderr.lines.join('')}`,
  );
  assert.equal(stderr.lines.some((line) => line.includes('private detail')), false, 'the raw error text is never logged');
});

test('review() and authorizeWorkflow() fired together on an unarmed engine run exactly ONE recovery sweep between them', async () => {
  const sweeps = [];
  await withEngine(async ({ dataRoot, buildEngine }) => {
    const engine = buildEngine();
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    const [authorized, reviewed] = await Promise.allSettled([
      engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      engine.review({ leaseId: 'no-such-lease', preflightId: preflight.preflightId, source_text: 'x' }),
    ]);
    assert.equal(authorized.status, 'fulfilled', `authorizeWorkflow must succeed, got ${authorized.reason?.code}: ${authorized.reason?.message}`);
    assert.equal(reviewed.reason?.code, 'LEASE_MISSING');
    assert.equal(sweeps.length, 1, 'the single-flight must cover the recovery sweep, not just the arm');
    assert.deepEqual((await readProcessOwnerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED']);
  }, { ...UNARMED, wrapLeaseStore: countingSweeps(sweeps) });
});

test('the recoverOrphanedLeases export on an unarmed engine arms WITHOUT cycle recovery and sweeps exactly once, recovering a previous session orphan', async () => {
  const sweeps = [];
  await withEngine(async ({ realLeaseStore, ownerLock, buildEngine, advance }) => {
    const orphan = await seedPreviousSessionOrphan({ realLeaseStore, buildEngine, advance });
    const engine = buildEngine();
    const swept = await engine.recoverOrphanedLeases();
    assert.equal(sweeps.length, 1, 'the export performs the one sweep itself; the arm must not add a second');
    assert.equal(swept.length, 1, 'the sweep ran armed, so its fenced reconcile and close succeeded');
    assert.equal(swept[0].leaseId, orphan.leaseId);
    assert.equal((await realLeaseStore.getLease(orphan.leaseId)).state, 'ORPHANED_ON_RECOVERY');
    assert.equal(ownerLock.isOwner(), false, 'the explicit sweep releases after its complete operation');
  }, { ...UNARMED, wrapLeaseStore: countingSweeps(sweeps) });
});

// A two-process test cannot reliably tell an arm placed at the start of authorizeWorkflow from one
// placed just before createLease. This call-order test can: the arm's ACQUIRED append must land
// before the first ledger read the autonomous grant decision depends on.
test('the arm lands BEFORE authorizeWorkflow reads the ledger (the operation bracket): ACQUIRED precedes countLeasesForRawSource and createLease', async () => {
  const order = [];
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine({ autonomousAuthorization: true });
    await preflightAndAuthorize(engine);
    assert.deepEqual(order, ['ACQUIRED', 'countLeasesForRawSource', 'createLease']);
  }, {
    ...UNARMED,
    storeOptions: { afterOwnerAcquired: async () => { order.push('ACQUIRED'); } },
    wrapLeaseStore: (real) => ({
      ...real,
      async countLeasesForRawSource(rawSourceSha256) {
        order.push('countLeasesForRawSource');
        return real.countLeasesForRawSource(rawSourceSha256);
      },
      async createLease(input) {
        order.push('createLease');
        return real.createLease(input);
      },
    }),
  });
});

// The token snapshot applies to a handle that already OWNS. A hand-built handle that claims ownership but carries
// no acquisitionId is armed-looking and id-less at once; the snapshot must fail it closed rather than
// let a null reach the ledger's fence.
test('a handle that reports isOwner() but exposes no acquisitionId fails the owner-sensitive call closed at the token snapshot', async () => {
  await withEngine(async ({ buildEngine }) => {
    const idless = Object.freeze({ dataRoot: 'fake', generation: null, acquisitionId: null, isOwner: () => true, async arm() {}, async release() {} });
    const engine = buildEngine({ ownerLock: idless });
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    await assert.rejects(
      engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      (error) => error.message === 'owner token unavailable: the ownership handle is not armed',
    );
  });
});

// Without an abort seam, a stdin close while an arm polls against a live holder would stall the
// drain for the whole arm budget. The coordinator hands the arm isShuttingDown as its shouldAbort
// token, so beginShutdown() stops the wait within about one attempt plus one sleep.
test('beginShutdown() aborts an arm waiting on a live foreign holder: the call rejects SHUTTING_DOWN promptly, awaitDrain drains well inside the arm budget, and this process writes no ACQUIRED record', async () => {
  const holder = await spawnLongLivedChild();
  try {
    await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
      // A live, fresh foreign holder: never stale, never reclaimable, so the arm can only wait.
      await seedAcquiredOwnerRecord(dataRoot, { pid: holder.pid, generation: 1, timestamp: new Date(START).toISOString() });
      const engine = buildEngine({ armTimeoutMs: 30_000, armLockRetryMs: 25 });
      const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
      const outcome = engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }).then(() => 'resolved', (error) => error);
      const whileHeld = await Promise.race([outcome, new Promise((resolve) => { setTimeout(() => resolve('still waiting'), 500); })]);
      assert.equal(whileHeld, 'still waiting', 'precondition: the arm is genuinely polling against the live holder');
      assert.equal(ownerLock.state, 'arming');

      const shutdownBegan = Date.now();
      engine.beginShutdown();
      const drain = await engine.awaitDrain({ timeoutMs: 10_000 });
      const elapsedMs = Date.now() - shutdownBegan;
      assert.deepEqual(drain, { drained: true, outstandingCount: 0 }, 'the aborted arm must let the drain complete');
      assert.ok(elapsedMs < 5_000, `the arm must stop within about one attempt plus one sleep, not wait out its 30 s budget; took ${elapsedMs} ms`);
      const rejection = await outcome;
      assert.ok(rejection instanceof ReviewEngineError && rejection.code === 'SHUTTING_DOWN', `expected SHUTTING_DOWN, got ${rejection?.code ?? rejection}`);
      assert.equal(ownerLock.state, 'unarmed', 'an aborted arm returns the handle to unarmed');
      const records = await readProcessOwnerRecords(dataRoot);
      assert.equal(records.filter((record) => record.pid === process.pid).length, 0, 'this process never acquired');
    }, UNARMED);
  } finally {
    holder.kill();
  }
});

// On the ARMED path, an operation that outlives its caller records its outcome durably. One engine
// arms from an unarmed handle and
// runs a review whose caller walks away without reading the answer. A SECOND engine -- on its own
// createLeaseStore() instance for the same data root, with its own never-armed handle, standing in
// for a later session -- recovers the full advisory content through result() alone, and never arms
// or writes a processOwner record to do it.
test('a review armed and completed by one engine is recoverable in full through result() by a second, never-armed engine on the same data root, which writes no processOwner record', async () => {
  await withEngine(async ({ dataRoot, clock, ownerLock, buildEngine }) => {
    const first = buildEngine({
      dispatchHealthStore: createDispatchHealthStore({ dataRoot }),
      pendingHealthVerdictStore: createPendingHealthVerdictStore({ dataRoot }),
    });
    const { leaseId, preflightId } = await preflightAndAuthorize(first);
    // The caller starts the paid call and walks away: nothing reads this promise until the very end,
    // and then only to compare the live answer with the recovered one.
    const abandoned = first.review({ leaseId, preflightId, source_text: 'x' });
    const drain = await first.awaitDrain({ timeoutMs: 10_000 });
    assert.deepEqual(drain, { drained: true, outstandingCount: 0 }, 'precondition: the abandoned review ran to completion on its own');
    assert.equal(ownerLock.isOwner(), false, 'the abandoned operation still completed its automatic release');
    first.beginShutdown();
    assert.deepEqual(await first.awaitDrain({ timeoutMs: 10_000 }), { drained: true, outstandingCount: 0 });
    await ownerLock.release({ final: true });
    assert.equal(ownerLock.state, 'released', 'the original session has shut down before recovery');
    const ownerRecordsBefore = await readProcessOwnerRecords(dataRoot);

    const laterStore = createLeaseStore({ dataRoot, clock });
    const laterHandle = laterStore.createUnarmedOwnerHandle();
    // Every durable store and every in-memory cache belongs to the new engine.
    const later = buildEngine({
      leaseStore: laterStore, ownerLock: laterHandle,
      resultStore: createResultStore({ dataRoot }),
      preflightContextStore: createPreflightContextStore({ dataRoot }),
      dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
      scrubMappingStore: createScrubMappingStore({ dataRoot }),
      dispatchHealthStore: createDispatchHealthStore({ dataRoot }),
      pendingHealthVerdictStore: createPendingHealthVerdictStore({ dataRoot }),
    });
    const recovered = await later.result({ leaseId });

    const live = await abandoned;
    assert.deepEqual(Object.keys(recovered.reviewers).sort(), ['gemini', 'grok']);
    for (const reviewerId of ['gemini', 'grok']) {
      assert.equal(recovered.reviewers[reviewerId].advisory?.verdict, 'pass', `${reviewerId}: the recovered entry carries the advisory content`);
      assert.deepEqual(recovered.reviewers[reviewerId].advisory, live.reviewers[reviewerId].advisory, `${reviewerId}: the recovered advisory is the one the review produced`);
    }
    assert.equal(laterHandle.state, 'unarmed', 'result() never arms');
    assert.deepEqual(await readProcessOwnerRecords(dataRoot), ownerRecordsBefore, 'the second engine wrote no processOwner record');
  }, UNARMED);
});

// The arm cycle's ORDER: orphan recovery completes before
// the pending-health sweep starts. With nothing to recover, findStaleReservedJobs() is the whole of
// the recovery; it is held open for a moment, so a sweep started first, or concurrently, would
// visibly overtake it.
test('in the arm cycle, orphan recovery completes before the pending-health sweep starts', async () => {
  const events = [];
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine({
      pendingHealthVerdictStore: pendingHealthVerdictStoreWith(async () => { events.push('health-sweep:list'); return []; }),
    });
    await preflightAndAuthorize(engine);
    assert.deepEqual(events, ['recovery:start', 'recovery:settled', 'health-sweep:list']);
  }, {
    ...UNARMED,
    wrapLeaseStore: (real) => ({
      ...real,
      async findStaleReservedJobs(options) {
        events.push('recovery:start');
        const found = await real.findStaleReservedJobs(options);
        await new Promise((resolve) => { setTimeout(resolve, 50); });
        events.push('recovery:settled');
        return found;
      },
    }),
  });
});

// Cap stamping through createReviewEngine itself: the store stamps the cap the ENGINE enforces.
// The engine here is configured with 7 (every other fixture in this suite uses 10, so a hard-coded
// or defaulted cap cannot pass) and the store with a daily allowance of 13 (not its default 20). A
// sibling session configured with the usual 10 is then refused: its arm meets a live recorder whose
// caps differ, which is terminal once the recorder is probed and found genuine.
test('the ACQUIRED record carries the engine\'s own installationHardMaximumUsd and the store\'s own dailyPaidJobAllowance, and a live sibling engine configured with a different cap is refused OWNERSHIP_CAP_MISMATCH', async () => {
  await withEngine(async ({ dataRoot, clock, ownerLock, buildEngine }) => {
    await preflightAndAuthorize(buildEngine({ installationHardMaximumUsd: 7 }));
    const stamped = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(stamped.map((record) => record.state), ['ACQUIRED', 'RELEASED']);
    assert.equal(stamped[1].acquisitionId, stamped[0].acquisitionId);
    assert.deepEqual(stamped[0].caps, { installationHardMaximumUsd: 7, dailyPaidJobAllowance: 13 }, 'each cap is stamped by the layer that enforces it');

    // A sibling session on the same data root: its own store instance, its own never-armed handle.
    const siblingStore = createLeaseStore({ dataRoot, clock, dailyPaidJobAllowance: 13 });
    const siblingHandle = siblingStore.createUnarmedOwnerHandle();
    const sibling = buildEngine({ leaseStore: siblingStore, ownerLock: siblingHandle });
    const preflight = await sibling.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    const refusal = await sibling.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }).then(() => 'resolved', (error) => error);
    assert.ok(refusal instanceof ReviewEngineError, `expected a ReviewEngineError, got ${refusal?.code ?? refusal}`);
    assert.equal(refusal.code, 'OWNERSHIP_CAP_MISMATCH');
    assert.equal(refusal.details.recorded.installationHardMaximumUsd, 7);
    assert.equal(refusal.details.resolved.installationHardMaximumUsd, 10);
    assert.equal(siblingHandle.state, 'unarmed', 'the refused arm left the sibling unarmed');
    assert.deepEqual((await readProcessOwnerRecords(dataRoot)).map((record) => record.state), ['ACQUIRED', 'RELEASED'], 'the refused sibling wrote no record');
  }, { ...UNARMED, storeOptions: { dailyPaidJobAllowance: 13 } });
});

// Arm options and the abort seam, observed where they land: the engine passes its OWN arm options to
// ownerLock.arm(). 4321 and 37 match neither the production defaults nor the UNARMED harness
// values, so an engine that fell back to either would fail here.
test('the engine hands ownerLock.arm() its own armTimeoutMs and armLockRetryMs, its own cap, and its shutdown flag as shouldAbort', async () => {
  const armCalls = [];
  await withEngine(async ({ buildEngine }) => {
    const engine = buildEngine({ armTimeoutMs: 4_321, armLockRetryMs: 37 });
    await preflightAndAuthorize(engine);
    assert.equal(armCalls.length, 1, 'one arm');
    const [options] = armCalls;
    assert.equal(options.acquireTimeoutMs, 4_321, 'armTimeoutMs reaches the handle as acquireTimeoutMs');
    assert.equal(options.lockRetryMs, 37, 'armLockRetryMs reaches the handle as lockRetryMs');
    assert.deepEqual(options.caps, { installationHardMaximumUsd: 10 });
    assert.equal(typeof options.shouldAbort, 'function');
    assert.equal(options.shouldAbort(), false, 'not shutting down yet');
    engine.beginShutdown();
    assert.equal(options.shouldAbort(), true, 'shouldAbort reads this engine\'s own live shutdown flag');
  }, {
    ...UNARMED,
    makeOwnerLock: (store) => {
      const real = store.createUnarmedOwnerHandle();
      return Object.freeze({
        get dataRoot() { return real.dataRoot; },
        get generation() { return real.generation; },
        get acquisitionId() { return real.acquisitionId; },
        get state() { return real.state; },
        isOwner: () => real.isOwner(),
        arm: (options) => { armCalls.push(options); return real.arm(options); },
        release: (options) => real.release(options),
      });
    },
  });
});

// The cold-cache path of the call-order test above. That test authorizes on the engine that ran the
// preflight, so getCachedPreflight() is answered from memory. A restarted process has an empty cache, and its
// FIRST ledger read is the durable getPreflight() fallback: the arm must land before that read too.
test('on an engine whose preflight cache is cold, the arm lands BEFORE authorizeWorkflow\'s durable getPreflight fallback, its first ledger read', async () => {
  const order = [];
  let recording = false;
  await withEngine(async ({ buildEngine }) => {
    const preflight = await buildEngine({ autonomousAuthorization: true }).preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    // A second engine on the same stores stands in for a restarted process: nothing cached in memory.
    const restarted = buildEngine({ autonomousAuthorization: true });
    recording = true;
    await restarted.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    assert.deepEqual(order, ['ACQUIRED', 'getPreflight', 'countLeasesForRawSource', 'createLease']);
  }, {
    ...UNARMED,
    storeOptions: { afterOwnerAcquired: async () => { order.push('ACQUIRED'); } },
    wrapLeaseStore: (real) => ({
      ...real,
      async getPreflight(preflightId) {
        if (recording) order.push('getPreflight');
        return real.getPreflight(preflightId);
      },
      async countLeasesForRawSource(rawSourceSha256) {
        order.push('countLeasesForRawSource');
        return real.countLeasesForRawSource(rawSourceSha256);
      },
      async createLease(input) {
        order.push('createLease');
        return real.createLease(input);
      },
    }),
  });
});

// review() as the arming call. The shared-arm and shutdown tests above always arm through
// authorizeWorkflow; here review() is the first and only owner-sensitive call. It must start the arm itself (the hook is reached with no
// authorizeWorkflow anywhere), and inside trackInFlight: a drain begun while that arm is parked must
// still count it. The caller then gets SHUTTING_DOWN and the acquisition is released.
test('review() as the first owner-sensitive call on an unarmed engine starts the arm itself, inside trackInFlight: a drain begun while that arm is parked waits for it', async () => {
  const hookEntered = createDeferred();
  const resume = createDeferred();
  await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
    const engine = buildEngine();
    const reviewing = engine.review({ leaseId: 'no-such-lease', preflightId: 'no-such-preflight', source_text: 'x' });
    const reached = await Promise.race([
      hookEntered.promise.then(() => 'parked-after-acquired'),
      reviewing.then(() => 'resolved', (error) => `rejected:${error?.code}`),
    ]);
    assert.equal(reached, 'parked-after-acquired', 'precondition: review() started an arm of its own');
    engine.beginShutdown();
    assert.deepEqual(await engine.awaitDrain({ timeoutMs: 100 }), { drained: false, outstandingCount: 1 }, 'the parked arm is inside trackInFlight, so the drain waits for it');
    resume.resolve();
    await assert.rejects(reviewing, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
    assert.deepEqual(await engine.awaitDrain({ timeoutMs: 5_000 }), { drained: true, outstandingCount: 0 });
    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => record.state), ['ACQUIRED', 'RELEASED'], 'the compensating release matches the acquisition');
    assert.equal(ownerLock.state, 'released');
  }, {
    ...UNARMED,
    storeOptions: { afterOwnerAcquired: async () => { hookEntered.resolve(); await resume.promise; } },
  });
});

// "Retrying the same call later is safe", as the contention error tells the caller: the
// coordinator clears its cycle in a finally, so a failed arm never poisons the engine. The holder is
// another session on the same data root (its own store instance) and is genuinely live, because it
// carries this process's pid.
test('after an arm fails PROCESS_OWNERSHIP_UNAVAILABLE against a live holder, the same engine arms and grants on retry once that holder releases', async () => {
  await withEngine(async ({ dataRoot, clock, ownerLock, buildEngine }) => {
    const holder = await createLeaseStore({ dataRoot, clock }).acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const engine = buildEngine({ armTimeoutMs: 300, armLockRetryMs: 25 });
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    const refusal = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }).then(() => 'resolved', (error) => error);
    assert.ok(refusal instanceof ReviewEngineError && refusal.code === 'PROCESS_OWNERSHIP_UNAVAILABLE', `expected PROCESS_OWNERSHIP_UNAVAILABLE, got ${refusal?.code ?? refusal}`);
    assert.equal(refusal.details.reason, 'LIVE_OWNER');
    assert.equal(refusal.details.owner.generation, holder.generation);
    assert.equal(ownerLock.state, 'unarmed', 'the failed arm left the handle unarmed');

    await holder.release();
    const granted = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    assert.equal(typeof granted.leaseId, 'string', 'the retry on the same engine armed and granted');
    assert.equal(ownerLock.isOwner(), false, 'the successful retry releases after granting');
    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => record.state), ['ACQUIRED', 'RELEASED', 'ACQUIRED', 'RELEASED']);
    assert.equal(records[3].acquisitionId, records[2].acquisitionId);
  }, UNARMED);
});

// The third wrapper. A test above pins that review() arms inside trackInFlight; the
// recoverOrphanedLeases export arms through the same coordinator (runCycleRecovery: false), and its
// arm must be just as visible to a drain.
test('the recoverOrphanedLeases export arms inside trackInFlight: a drain begun while its arm is parked waits for it, and no sweep runs after shutdown', async () => {
  const hookEntered = createDeferred();
  const resume = createDeferred();
  const sweeps = [];
  await withEngine(async ({ dataRoot, ownerLock, buildEngine }) => {
    const engine = buildEngine();
    const recovering = engine.recoverOrphanedLeases();
    const reached = await Promise.race([
      hookEntered.promise.then(() => 'parked-after-acquired'),
      recovering.then(() => 'resolved', (error) => `rejected:${error?.code}`),
    ]);
    assert.equal(reached, 'parked-after-acquired', 'precondition: the export started an arm of its own');
    engine.beginShutdown();
    assert.deepEqual(await engine.awaitDrain({ timeoutMs: 100 }), { drained: false, outstandingCount: 1 }, 'the parked arm is inside trackInFlight, so the drain waits for it');
    resume.resolve();
    await assert.rejects(recovering, (error) => error instanceof ReviewEngineError && error.code === 'SHUTTING_DOWN');
    assert.deepEqual(await engine.awaitDrain({ timeoutMs: 5_000 }), { drained: true, outstandingCount: 0 });
    assert.equal(sweeps.length, 0, 'the compensated arm rejected before the export could sweep');
    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => record.state), ['ACQUIRED', 'RELEASED'], 'the compensating release matches the acquisition');
    assert.equal(ownerLock.state, 'released');
  }, {
    ...UNARMED,
    wrapLeaseStore: countingSweeps(sweeps),
    storeOptions: { afterOwnerAcquired: async () => { hookEntered.resolve(); await resume.promise; } },
  });
});

// The same export runs its ONE explicit orphan sweep and nothing else. Its arm asks
// for no cycle work (runCycleRecovery: false), so the pending-health sweep does not run inside the
// arm, and the export's own body never calls resolvePendingHealthVerdicts either (production never
// calls this export).
test('the recoverOrphanedLeases export runs only its own orphan sweep and never the pending-health sweep', async () => {
  const sweeps = [];
  const healthSweeps = [];
  await withEngine(async ({ ownerLock, buildEngine }) => {
    const engine = buildEngine({
      pendingHealthVerdictStore: pendingHealthVerdictStoreWith(async () => { healthSweeps.push('list'); return []; }),
    });
    await engine.recoverOrphanedLeases();
    assert.equal(ownerLock.isOwner(), false, 'the export released after its complete sweep');
    assert.equal(sweeps.length, 1, 'the export performs its one explicit orphan sweep');
    assert.deepEqual(healthSweeps, [], 'runCycleRecovery false runs no cycle work, and the export itself never runs the pending-health sweep');
  }, { ...UNARMED, wrapLeaseStore: countingSweeps(sweeps) });
});

// ---------------------------------------------------------------------------
// Owner token threading: the ownerToken is threaded through every fenced write.
// ---------------------------------------------------------------------------

/**
 * The source's CODE lines, for a static check that must not count prose. CRLF is normalized first
 * (a Windows checkout may use CRLF line endings); then full-line `//` comments, block and JSDoc
 * comments, and a trailing end-of-line comment (whitespace, `//`, whitespace, text) are dropped. Line-based on purpose, like
 * tests/openrouter-review-alert-wiring.test.mjs's readCreateReviewEngineCallBody(): a line counts once
 * however many times it names the property.
 */
function codeLinesOf(source) {
  const code = [];
  let inBlockComment = false;
  for (const line of source.replace(/\r\n/g, '\n').split('\n')) {
    const trimmed = line.trim();
    if (inBlockComment) {
      if (trimmed.includes('*/')) inBlockComment = false;
      continue;
    }
    if (trimmed.startsWith('/*')) {
      if (!trimmed.includes('*/')) inBlockComment = true;
      continue;
    }
    if (trimmed.startsWith('//')) continue;
    code.push(line.replace(/\s\/\/\s.*$/, ''));
  }
  return code;
}

async function codeLinesNaming(path, needle) {
  return codeLinesOf(await readFile(path, 'utf8')).filter((line) => line.includes(needle));
}

test('static check: live acquisition reads only validate construction or reject stale recovery writes; coordinator alone snapshots operation tokens', async () => {
  const engineLines = await codeLinesNaming('src/local-mcp/review-engine.mjs', 'ownerLock.acquisitionId');
  assert.equal(
    engineLines.length,
    2,
    `every fenced write must use the call's ownerToken, not the live handle; found ${engineLines.length} code lines:\n${engineLines.join('\n')}`,
  );
  assert.ok(engineLines.some((line) => line.includes('if (ownerLock.acquisitionId !== null) requireNonEmptyString(')), 'the constructor check for an armed handle');
  assert.ok(engineLines.some((line) => line.trim() === 'if (!ownerLock.isOwner() || ownerLock.acquisitionId !== ownerToken.acquisitionId) return;'),
    'the recovered-advisory guard compares against the original frozen operation token; it never adopts a newer acquisition');
  const coordinatorLines = await codeLinesNaming('src/local-mcp/ownership-coordinator.mjs', 'ownerLock.acquisitionId');
  assert.deepEqual(
    coordinatorLines.map((line) => line.trim()),
    [
      'const acquisitionId = ownerLock.acquisitionId;',
      'const ownerToken = Object.freeze({ acquisitionId: ownerLock.acquisitionId });',
    ],
    'the coordinator reads the live id only for complete-operation and cycle-work post-arm snapshots',
  );
  // The engine no longer owns a snapshot helper at all. A call receives the coordinator's immutable
  // token once and threads it through every reservation, reconcile, halt and close.
  const snapshotLines = await codeLinesNaming('src/local-mcp/review-engine.mjs', 'snapshotOwnerToken(');
  assert.deepEqual(snapshotLines, [], 'the engine cannot re-read the live handle inside an admitted operation');
});

test('every fenced write in a call uses the ownerToken snapshot taken when the call began, so a re-acquisition mid-call fails the write closed instead of adopting the new acquisition', async () => {
  await withEngine(async ({ realLeaseStore, ownerLock, buildEngine }) => {
    let reacquired = null;
    const engine = buildEngine({
      dispatchAdapter: {
        // Between this reviewer's reservation (made under the call's snapshot) and its reconcile,
        // the handle releases non-finally and re-arms: a NEW generation and a NEW acquisitionId.
        async dispatch() {
          if (reacquired === null) {
            const before = ownerLock.acquisitionId;
            await ownerLock.release({ final: false });
            await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
            reacquired = { before, after: ownerLock.acquisitionId };
          }
          return responseEnvelope(grokPassBody());
        },
      },
    });
    // final_verification_v1 with an empty changeKinds dispatches grok alone.
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    const result = await engine.review({ leaseId, preflightId, source_text: 'x' });

    assert.ok(reacquired !== null && typeof reacquired.after === 'string', 'precondition: the handle re-armed mid-call');
    assert.notEqual(reacquired.after, reacquired.before, 'precondition: the re-arm produced a new acquisitionId');
    assert.equal(
      result.reviewers.grok.error?.code,
      'PROCESS_OWNERSHIP_LOST',
      'the reconcile must carry the snapshot from the start of the call, which no longer owns the ledger',
    );
    // Same formula as review-engine.mjs's private deriveJobId(), re-derived rather than imported.
    const grokJobId = createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:grok:${preflight.reviewContractSha256}`, 'utf8').digest('hex');
    assert.equal((await realLeaseStore.getJob(grokJobId)).state, 'RESERVED', 'the refused reconcile committed nothing');
  }, UNARMED);
});

/**
 * Mid-operation SUPERSESSION for the token-snapshot behavioural tests below, made the way the store's
 * stale-handle test makes it: a SECOND createLeaseStore() on the same data root, whose
 * isProcessAlive reports this process dead and whose lockStaleMs (100 ms) this process's ACQUIRED
 * record has outlived, reclaims process ownership. The engine gets a delegating stand-in for its
 * real handle that, from the supersession on, reports the SUCCESSOR's acquisitionId: the id a
 * fenced write would carry if it re-read the live handle, or took a later snapshot, instead of using
 * the snapshot its call took when it armed. The ledger fence ACCEPTS that id, so such a write would
 * commit. Only the call's original snapshot is refused, so each test goes red if its write drops
 * the token (a TypeError, not the ownership refusal), reads the live handle, or snapshots late.
 */
function supersedableOwnerLock(real) {
  let successorAcquisitionId = null;
  const handle = Object.freeze({
    get dataRoot() { return real.dataRoot; },
    get generation() { return real.generation; },
    get acquisitionId() { return successorAcquisitionId ?? real.acquisitionId; },
    get state() { return real.state; },
    isOwner: () => real.isOwner(),
    arm: (options) => real.arm(options),
    release: (options) => real.release(options),
  });
  async function supersede({ dataRoot, clock, advance }) {
    const original = real.acquisitionId;
    advance(1_000); // this process's ACQUIRED record is now older than the successor's lockStaleMs
    const successorStore = createLeaseStore({ dataRoot, clock, lockStaleMs: 100, isProcessAlive: () => false });
    const successor = await successorStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    successorAcquisitionId = successor.acquisitionId;
    return { original, successor: successor.acquisitionId };
  }
  return { handle, supersede };
}

// The exact refusal lease-store.mjs's assertCurrentlyOwnsProcess() throws for a lost owner.
const OWNERSHIP_REFUSAL = /does not currently hold process ownership/;

/**
 * Like seedPreviousSessionOrphan(), but the orphan is RECOVERABLE at its real cost: one grok job,
 * reserved under its real derived jobId, whose dispatch completed and was captured durably before
 * the previous session went away. The next owner's recovery pre-pass reconciles it at KNOWN cost,
 * which leaves the lease with nothing RESERVED, so recovery closes it with an explicit close().
 */
async function seedPreviousSessionRecoverableOrphan({ dataRoot, realLeaseStore, buildEngine, advance }) {
  const previous = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  const previousEngine = buildEngine({ ownerLock: previous });
  // final_verification_v1 with an empty changeKinds dispatches grok alone.
  const orphan = await preflightAndAuthorize(previousEngine, { source_text: 'a recoverable orphan', profile: 'final_verification_v1', changeKinds: [], maxJobs: 1 });
  await previous.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
  const { reviewContractSha256 } = orphan.preflight;
  // Same formula as review-engine.mjs's private deriveJobId(), re-derived rather than imported.
  const jobId = createHash('sha256').update(`openrouter_review_job_v1:${orphan.leaseId}:grok:${reviewContractSha256}`, 'utf8').digest('hex');
  const reservationUsd = orphan.preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
  await realLeaseStore.consume(orphan.leaseId, reviewContractSha256, { reservationUsd, jobId, reviewerId: 'grok', acquisitionId: previous.acquisitionId });
  await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
  await writeFile(dispatchOutcomePath({ dataRoot, jobId }), JSON.stringify(responseEnvelope(grokPassBody())), 'utf8');
  const lease = await realLeaseStore.getLease(orphan.leaseId);
  await previous.release();
  advance((Date.parse(lease.expiresAt) - START) + 2 * 60 * 1000 + 1_000);
  return { ...orphan, jobId };
}

test('a stale operation token skips recovered-advisory persistence when its live owner remains true but its acquisition changes', async () => {
  let control;
  let targetJobId = null;
  let supersedeOnCaptureRead = null;
  let preserveStaleOwnerReport = false;
  const mutations = { consume: [], reconcile: [], close: [] };
  const resultRecords = [];
  let dispatchCalls = 0;

  await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
    const realResultStore = createResultStore({ dataRoot });
    const realDispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
    const resultStore = Object.freeze({
      ...realResultStore,
      async record(input) {
        resultRecords.push(input);
        return realResultStore.record(input);
      },
    });
    const dispatchOutcomeStore = Object.freeze({
      ...realDispatchOutcomeStore,
      async recall(input) {
        const captured = await realDispatchOutcomeStore.recall(input);
        const hook = input.jobId === targetJobId ? supersedeOnCaptureRead : null;
        if (hook !== null) {
          supersedeOnCaptureRead = null;
          await hook();
        }
        return captured;
      },
    });
    // Model the specific stale-token guard: a process-local handle can remain armed while the
    // durable acquisition identity has changed. The existing supersedable control supplies that
    // live successor id; this facade keeps isOwner true so the test proves identity is not omitted.
    const ownerLock = Object.freeze({
      get dataRoot() { return control.handle.dataRoot; },
      get generation() { return control.handle.generation; },
      get acquisitionId() { return control.handle.acquisitionId; },
      get state() { return control.handle.state; },
      isOwner: () => preserveStaleOwnerReport || control.handle.isOwner(),
      arm: (options) => control.handle.arm(options),
      release: (options) => control.handle.release(options),
    });
    const engine = buildEngine({
      ownerLock,
      resultStore,
      dispatchOutcomeStore,
      dispatchAdapter: { async dispatch() { dispatchCalls += 1; throw new Error('a reconciled captured job must not dispatch again'); } },
    });

    // Seed a cleanly reconciled grok job exactly as a previous owner would, while intentionally
    // leaving its recovered advisory out of resultStore. The new engine must reconstruct it from
    // the durable capture without a new reservation, dispatch, reconciliation, or close.
    const preflight = await engine.preflight({
      source_text: 'x', profile: 'final_verification_v1', changeKinds: [], reviewContext: 'arming test scope',
    });
    const previous = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const lease = await realLeaseStore.createLease({
      preflightIds: [preflight.preflightId], requestedUsd: preflight.requestedUsd, maxJobs: 1,
      expiresAt: preflight.expiresAt, acquisitionId: previous.acquisitionId,
    });
    targetJobId = createHash('sha256').update(
      `openrouter_review_job_v1:${lease.id}:grok:${preflight.reviewContractSha256}`, 'utf8',
    ).digest('hex');
    const reservationUsd = preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    await realLeaseStore.consume(lease.id, preflight.reviewContractSha256, {
      reservationUsd, jobId: targetJobId, reviewerId: 'grok', acquisitionId: previous.acquisitionId,
    });
    await realLeaseStore.reconcile(targetJobId, {
      costUsd: 0.02, costKind: 'KNOWN', acquisitionId: previous.acquisitionId,
    });
    await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
    await writeFile(dispatchOutcomePath({ dataRoot, jobId: targetJobId }), JSON.stringify(responseEnvelope(grokPassBody())), 'utf8');
    await previous.release();

    let ids = null;
    // recoverReconciledAdvisory has reconstructed the advisory at this point; supersede before
    // recallAdvisory reaches rememberRecoveredAdvisory's identity guard.
    supersedeOnCaptureRead = async () => {
      ids = await control.supersede({ dataRoot, clock, advance });
      preserveStaleOwnerReport = true;
    };
    const outcome = await engine.review({ leaseId: lease.id, preflightId: preflight.preflightId, source_text: 'x' });

    assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: ownership changed before recovered-result persistence');
    assert.equal(ownerLock.isOwner(), true, 'the old handle still reports ownership; the acquisition identity check is decisive');
    assert.equal(ownerLock.acquisitionId, ids.successor, 'the live handle now exposes the successor identity');
    assert.equal(outcome.state, 'PASSED');
    assert.equal(outcome.reviewers.grok.advisory.verdict, 'pass');
    assert.deepEqual(resultRecords, [], 'the stale call must not write a reconstructed advisory');
    assert.equal(await realResultStore.recall({ jobId: targetJobId }), null, 'no result file was persisted under the stale operation token');
    assert.equal(dispatchCalls, 0, 'the reconciled captured job is reused rather than dispatched again');
    assert.deepEqual(mutations.consume, [], 'recovery must not reserve another job');
    assert.deepEqual(mutations.reconcile, [], 'recovery must not reconcile an already-settled job');
    assert.deepEqual(mutations.close, [], 'a passing recovered advisory must not close the active lease');
  }, {
    ...UNARMED,
    makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
    wrapLeaseStore: (real) => ({
      ...real,
      async consume(...args) { mutations.consume.push(args); return real.consume(...args); },
      async reconcile(...args) { mutations.reconcile.push(args); return real.reconcile(...args); },
      async close(...args) { mutations.close.push(args); return real.close(...args); },
    }),
  });
});

test('a supersession in the middle of authorizeWorkflow fails its createLease closed with PROCESS_OWNERSHIP_LOST, carrying the snapshot the call armed with', async () => {
  let control;
  const createLeaseIds = [];
  await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
    let ids = null;
    const engine = buildEngine({
      approvalAdapter: {
        // Runs after the call armed and took its snapshot, and before createLease.
        async authorize() {
          ids = await control.supersede({ dataRoot, clock, advance });
          return { outcome: 'APPROVED', nonce: 'fake-nonce' };
        },
      },
    });
    const preflight = await engine.preflight({ source_text: 'x', profile: 'consequential_spec_v1', reviewContext: 'arming test scope' });
    const outcome = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }).then(() => 'resolved', (error) => error);

    assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: a successor took ownership mid-call with a new acquisitionId');
    assert.deepEqual(createLeaseIds, [ids.original], 'createLease must carry the snapshot the call armed with, never the successor id the live handle now reports');
    assert.ok(outcome instanceof ReviewEngineError, `expected a ReviewEngineError, got ${outcome}`);
    assert.equal(outcome.code, 'PROCESS_OWNERSHIP_LOST');
    assert.match(outcome.message, OWNERSHIP_REFUSAL);
    const rawSourceSha256 = createHash('sha256').update('x', 'utf8').digest('hex');
    assert.equal(await realLeaseStore.countLeasesForRawSource(rawSourceSha256), 0, 'the refused createLease committed nothing');
  }, {
    ...UNARMED,
    makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
    wrapLeaseStore: (real) => ({ ...real, async createLease(input) { createLeaseIds.push(input.acquisitionId); return real.createLease(input); } }),
  });
});

test('a supersession in the middle of an orphan-recovery sweep fails its sweepOrphanedLeases closed with the ownership refusal, carrying the snapshot the sweep armed with', async () => {
  let control;
  let onStaleRead = null;
  const sweepCalls = [];
  const stderr = captureStderr();
  try {
    await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
      const orphan = await seedPreviousSessionOrphan({ realLeaseStore, buildEngine, advance });
      const engine = buildEngine();
      let ids = null;
      // Recovery's first read runs after the export armed and took its snapshot; the successor takes
      // over right there, before the fenced sweepOrphanedLeases write.
      onStaleRead = async () => { ids = await control.supersede({ dataRoot, clock, advance }); };
      const swept = await engine.recoverOrphanedLeases();

      assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: a successor took ownership mid-sweep with a new acquisitionId');
      assert.deepEqual(sweepCalls.map((call) => call.acquisitionId), [ids.original], 'sweepOrphanedLeases must carry the snapshot the sweep armed with, never the successor id the live handle now reports');
      assert.match(sweepCalls[0].refusal ?? 'no refusal: the sweep committed', OWNERSHIP_REFUSAL);
      assert.deepEqual(swept, [], 'nothing was recovered under a superseded snapshot');
      assert.equal((await realLeaseStore.getLease(orphan.leaseId)).state, 'ACTIVE', 'the orphan lease is left for its new owner to recover');
      assert.equal((await realLeaseStore.getJob('orphaned-by-previous-session')).state, 'RESERVED', 'no worst-case charge was committed');
    }, {
      ...UNARMED,
      makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
      wrapLeaseStore: (real) => ({
        ...real,
        async findStaleReservedJobs(options) {
          const found = await real.findStaleReservedJobs(options);
          const hook = onStaleRead;
          onStaleRead = null;
          if (hook !== null) await hook();
          return found;
        },
        async sweepOrphanedLeases(options) {
          const call = { acquisitionId: options.acquisitionId, refusal: null };
          sweepCalls.push(call);
          try {
            return await real.sweepOrphanedLeases(options);
          } catch (error) {
            call.refusal = error.message;
            throw error;
          }
        },
      }),
    });
  } finally {
    stderr.restore();
  }
  assert.ok(stderr.lines.some((line) => line.includes('recoverStaleLease-fallback-sweep-failed')), `the refused sweep is still logged loudly; got:\n${stderr.lines.join('')}`);
});

test('a supersession after orphan recovery reconciled a job fails the explicit close closed with the ownership refusal, carrying the snapshot the sweep armed with', async () => {
  let control;
  let afterSweep = null;
  const closeCalls = [];
  const stderr = captureStderr();
  try {
    await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
      const orphan = await seedPreviousSessionRecoverableOrphan({ dataRoot, realLeaseStore, buildEngine, advance });
      const engine = buildEngine();
      let ids = null;
      // By the time the fallback sweep returns, the pre-pass has already reconciled the orphan's
      // one job at its real cost under the call's snapshot. The successor takes over right there,
      // before the lease's explicit ORPHANED_ON_RECOVERY close.
      afterSweep = async () => { ids = await control.supersede({ dataRoot, clock, advance }); };
      const swept = await engine.recoverOrphanedLeases();

      assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: a successor took ownership mid-recovery with a new acquisitionId');
      assert.equal((await realLeaseStore.getJob(orphan.jobId)).costKind, 'KNOWN', 'precondition: the pre-pass reconciled the job at its real cost before the supersession');
      assert.deepEqual(closeCalls.map((call) => call.acquisitionId), [ids.original, ids.original], 'the close and its one retry must both carry the snapshot the sweep armed with, never the successor id the live handle now reports');
      for (const call of closeCalls) assert.match(call.refusal ?? 'no refusal: the close committed', OWNERSHIP_REFUSAL);
      assert.deepEqual(swept, [], 'the lease is not reported as recovered');
      assert.equal((await realLeaseStore.getLease(orphan.leaseId)).state, 'ACTIVE', 'the lease was not closed under a superseded snapshot');
    }, {
      ...UNARMED,
      makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
      wrapLeaseStore: (real) => ({
        ...real,
        async sweepOrphanedLeases(options) {
          const swept = await real.sweepOrphanedLeases(options);
          const hook = afterSweep;
          afterSweep = null;
          if (hook !== null) await hook();
          return swept;
        },
        async close(leaseId, state, options) {
          const call = { acquisitionId: options?.acquisitionId, refusal: null };
          closeCalls.push(call);
          try {
            return await real.close(leaseId, state, options);
          } catch (error) {
            call.refusal = error.message;
            throw error;
          }
        },
      }),
    });
  } finally {
    stderr.restore();
  }
  assert.ok(stderr.lines.some((line) => line.includes('recoverStaleLease-close-failed')), `the refused close is still logged loudly; got:\n${stderr.lines.join('')}`);
});

/**
 * Records every call to one fenced lease-store method, for the review() supersession tests below:
 * the acquisitionId it carried, and the refusal the REAL ledger gave it (null if the write committed).
 */
function spiedCalls() {
  const calls = [];
  return {
    calls,
    async record(acquisitionId, work) {
      const call = { acquisitionId, refusal: null };
      calls.push(call);
      try {
        return await work();
      } catch (error) {
        call.refusal = error.message;
        throw error;
      }
    },
  };
}

// A body whose provider is not grok's expected xAI: processDispatchOutcome halts it through
// haltAndClose() at KNOWN cost, whose reconcile is a fenced write of its own.
function grokProviderMismatchBody() {
  return { provider: 'NotXai', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.02 } };
}

test('a supersession in the middle of review(), after its arm and before its reservation, fails consume closed with the ownership refusal, carrying the snapshot the call armed with', async () => {
  let control;
  let onFirstGetLease = null;
  const consume = spiedCalls();
  await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
    const engine = buildEngine();
    // final_verification_v1 with an empty changeKinds dispatches grok alone.
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    let ids = null;
    // review()'s opening getLease runs after the wrapper took its snapshot and before Step 2 builds
    // the reservation request: the successor takes over right there.
    onFirstGetLease = async () => { ids = await control.supersede({ dataRoot, clock, advance }); };
    const outcome = await engine.review({ leaseId, preflightId, source_text: 'x' }).then(() => 'resolved', (error) => error);

    assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: a successor took ownership mid-call with a new acquisitionId');
    assert.deepEqual(consume.calls.map((call) => call.acquisitionId), [ids.original], 'consume must carry the snapshot the call armed with, never the successor id the live handle now reports');
    assert.match(consume.calls[0].refusal ?? 'no refusal: consume committed', OWNERSHIP_REFUSAL);
    assert.ok(outcome instanceof ReviewEngineError, `expected a ReviewEngineError, got ${outcome}`);
    assert.equal(outcome.code, 'PROCESS_OWNERSHIP_LOST');
    const grokJobId = createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:grok:${preflight.reviewContractSha256}`, 'utf8').digest('hex');
    assert.equal(await realLeaseStore.getJob(grokJobId), null, 'the refused consume reserved nothing');
  }, {
    ...UNARMED,
    makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
    wrapLeaseStore: (real) => ({
      ...real,
      async getLease(leaseId) {
        const found = await real.getLease(leaseId);
        const hook = onFirstGetLease;
        onFirstGetLease = null;
        if (hook !== null) await hook();
        return found;
      },
      async consume(leaseId, reviewContractSha256, options) {
        return consume.record(options.acquisitionId, () => real.consume(leaseId, reviewContractSha256, options));
      },
    }),
  });
});

test('a supersession after a halted reviewer reconciled fails finalizeReviewOutcome\'s close closed with PROCESS_OWNERSHIP_LOST, carrying the snapshot the call armed with', async () => {
  let control;
  let afterReconcile = null;
  const close = spiedCalls();
  await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
    const engine = buildEngine({ dispatchAdapter: { async dispatch() { return responseEnvelope(grokProviderMismatchBody()); } } });
    const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
    let ids = null;
    // The halt's own reconcile commits under the call's snapshot; the successor takes over right
    // after it, before Step 5 closes the lease under the halt's code.
    afterReconcile = async () => { ids = await control.supersede({ dataRoot, clock, advance }); };
    const outcome = await engine.review({ leaseId, preflightId, source_text: 'x' }).then(() => 'resolved', (error) => error);

    assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: a successor took ownership mid-call with a new acquisitionId');
    const grokJobId = createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:grok:${preflight.reviewContractSha256}`, 'utf8').digest('hex');
    assert.equal((await realLeaseStore.getJob(grokJobId)).haltReason, 'PROVIDER_MISMATCH', 'precondition: the halt reconciled at KNOWN cost before the supersession');
    assert.deepEqual(close.calls.map((call) => call.acquisitionId), [ids.original], 'the close must carry the snapshot the call armed with, never the successor id the live handle now reports');
    assert.match(close.calls[0].refusal ?? 'no refusal: the close committed', OWNERSHIP_REFUSAL);
    assert.ok(outcome instanceof ReviewEngineError, `expected a ReviewEngineError, got ${outcome}`);
    assert.equal(outcome.code, 'PROCESS_OWNERSHIP_LOST');
    assert.equal((await realLeaseStore.getLease(leaseId)).state, 'ACTIVE', 'the lease was not closed under a superseded snapshot');
  }, {
    ...UNARMED,
    makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
    wrapLeaseStore: (real) => ({
      ...real,
      async reconcile(jobId, options) {
        const reconciled = await real.reconcile(jobId, options);
        const hook = afterReconcile;
        afterReconcile = null;
        if (hook !== null) await hook();
        return reconciled;
      },
      async close(leaseId, state, options) {
        return close.record(options?.acquisitionId, () => real.close(leaseId, state, options));
      },
    }),
  });
});

test('a supersession while a reviewer is dispatching fails haltAndClose\'s reconcile closed with the ownership refusal, carrying the snapshot the call armed with', async () => {
  let control;
  let supersedeInDispatch = null;
  const reconcile = spiedCalls();
  const stderr = captureStderr();
  try {
    await withEngine(async ({ dataRoot, clock, advance, realLeaseStore, buildEngine }) => {
      const engine = buildEngine({
        dispatchAdapter: {
          // After the reservation (made under the call's snapshot), before the halt's reconcile.
          async dispatch() {
            const hook = supersedeInDispatch;
            supersedeInDispatch = null;
            if (hook !== null) await hook();
            return responseEnvelope(grokProviderMismatchBody());
          },
        },
      });
      const { leaseId, preflightId, preflight } = await preflightAndAuthorize(engine, { profile: 'final_verification_v1', changeKinds: [] });
      let ids = null;
      supersedeInDispatch = async () => { ids = await control.supersede({ dataRoot, clock, advance }); };
      const outcome = await engine.review({ leaseId, preflightId, source_text: 'x' }).then((result) => result, (error) => error);

      assert.ok(ids !== null && ids.successor !== ids.original, 'precondition: a successor took ownership mid-call with a new acquisitionId');
      // The halt's reconcile, then the Step 3 rejection loop's recovery reconcile: both refused.
      assert.deepEqual(reconcile.calls.map((call) => call.acquisitionId), [ids.original, ids.original], 'the halt reconcile and its recovery reconcile must both carry the snapshot the call armed with, never the successor id the live handle now reports');
      for (const call of reconcile.calls) assert.match(call.refusal ?? 'no refusal: the reconcile committed', OWNERSHIP_REFUSAL);
      assert.ok(!(outcome instanceof Error), `review() still returns its HALTED result; got ${outcome?.code}: ${outcome?.message}`);
      assert.equal(outcome.reviewers.grok.error?.code, 'PROCESS_OWNERSHIP_LOST');
      const grokJobId = createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:grok:${preflight.reviewContractSha256}`, 'utf8').digest('hex');
      assert.equal((await realLeaseStore.getJob(grokJobId)).state, 'RESERVED', 'the refused reconciles committed nothing');
    }, {
      ...UNARMED,
      makeOwnerLock: (store) => { control = supersedableOwnerLock(store.createUnarmedOwnerHandle()); return control.handle; },
      wrapLeaseStore: (real) => ({
        ...real,
        async reconcile(jobId, options) {
          return reconcile.record(options.acquisitionId, () => real.reconcile(jobId, options));
        },
      }),
    });
  } finally {
    stderr.restore();
  }
  assert.ok(stderr.lines.some((line) => line.includes('dispatch-task-rejected reviewerId=grok')), `the refused halt is still logged loudly; got:\n${stderr.lines.join('')}`);
});

// A live ownership handle duck-types { acquisitionId } through a GETTER, so a token check that
// only asks for a non-empty string accepts it, and a write handed the handle reads the live id at
// write time. The two exported helpers validate their token first, before any store call, and accept
// only a frozen object whose own acquisitionId is a data property.
test('reserveReviewers and finalizeReviewOutcome refuse any ownerToken but a frozen { acquisitionId } data snapshot, the live handle included, before any store call', async () => {
  await withEngine(async ({ ownerLock }) => {
    const storeCalls = [];
    const recordingStore = {
      async findJobsForReviewerContract() { storeCalls.push('findJobsForReviewerContract'); return []; },
      async consume() { storeCalls.push('consume'); return {}; },
      async close() { storeCalls.push('close'); },
    };
    const candidates = [{ reviewerId: 'grok', jobId: 'job-token-check', reservationUsd: 0.1, countsTowardDailyAllowance: true }];
    const reserveWith = (ownerToken) => reserveReviewers({
      leaseStore: recordingStore, clock: () => 0, leaseId: 'lease-token-check', leaseExpiresAtMs: 1, reviewContractSha256: 'contract-token-check', candidates, ownerToken,
    });
    const finalizeWith = (ownerToken) => finalizeReviewOutcome({
      leaseStore: recordingStore, checkSpendAndMaybeAlert: async () => { storeCalls.push('checkSpendAndMaybeAlert'); },
      leaseId: 'lease-token-check', preflightId: 'preflight-token-check', reviewContractSha256: 'contract-token-check', reviewers: {}, orderedReviewerIds: [], ownerToken,
    });
    const refused = [
      ['the live handle (an accessor-backed acquisitionId)', ownerLock],
      ['an unfrozen snapshot', { acquisitionId: ownerLock.acquisitionId }],
      ['an inherited acquisitionId', Object.freeze(Object.create({ acquisitionId: ownerLock.acquisitionId }))],
      ['an empty id', Object.freeze({ acquisitionId: '' })],
      ['no token', undefined],
    ];
    for (const [label, bad] of refused) {
      await assert.rejects(reserveWith(bad), { name: 'TypeError', message: 'ownerToken must be a frozen { acquisitionId } snapshot' }, `reserveReviewers must refuse ${label}`);
      await assert.rejects(finalizeWith(bad), { name: 'TypeError', message: 'ownerToken must be a frozen { acquisitionId } snapshot' }, `finalizeReviewOutcome must refuse ${label}`);
    }
    assert.deepEqual(storeCalls, [], 'a refused token reaches no store call');

    const snapshot = Object.freeze({ acquisitionId: ownerLock.acquisitionId });
    assert.deepEqual((await reserveWith(snapshot)).reservedReviewerIds, ['grok'], 'a frozen snapshot is accepted');
    assert.equal((await finalizeWith(snapshot)).state, 'PASSED');
    assert.deepEqual(storeCalls, ['findJobsForReviewerContract', 'consume', 'checkSpendAndMaybeAlert']);
  });
});
