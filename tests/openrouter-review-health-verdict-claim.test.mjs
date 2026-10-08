import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

// The pending dispatch-health sweep's per-job claim.
//
// No process takes ownership at startup, so the sweep runs only from the ownership coordinator's
// arm cycle -- and the claim tested here is the defense-in-depth that keeps a verdict resolved at
// most once even if two processes ever do sweep at the same time. Without a claim, two processes
// sweeping the same due verdicts both record every one of them, double-counting each failure.
//
// What this file pins, and at which level:
//   - store level, one process: claim is an exclusive create that recallClaim reads back and list()
//     never returns; recallClaim is tri-state (absent / unreadable with the file's mtimeMs / held),
//     including an unreadable claim that vanishes before its stat; releaseClaim honours claimId and
//     never releases an unreadable claim by claimId; claim persists an optional gradeAsOfMs;
//     malformed input is refused before any I/O; and only the exclusive create's EEXIST reads as a
//     lost claim.
//   - store level, 2 and 4 REAL processes: each jobId is won exactly once, and the wins sum to K.
//     Counted at the claim results, never through dispatch-health.json, whose counter is measured
//     nondeterministic under concurrent writers with or without a claim.
//   - engine level, one process: the sweep's order (claim, re-read, remove, record, release), the
//     re-read that skips a record resolved elsewhere, and the lost-claim takeover rule: a claim that
//     vanished is claimed once more; an abandoned claim (readable and older than the backstop, or
//     unreadable and older than the grace) is taken over and its record counted exactly once, graded
//     as of the crashed claimer's time (its claimedAtMs, or the truncated file's mtimeMs floored to
//     a whole ms), not now;
//     a retry or takeover re-reads the record under its new claim, so a record its holder already
//     resolved is not counted twice; a fresh claim, readable or not, is skipped; a retry or takeover
//     that loses again skips. Plus the release that lets a record whose resolution threw be retried
//     by the next sweep.
//   - engine level, more than one engine or sweep over time: two real engines sweeping one due
//     record at once count it exactly once; a takeover's own claim carries the crashed claimer's
//     grading instant, so a second crash still grades a real success as a success, while a
//     takeover whose resolution throws still releases its claim, so nothing is retried forever,
//     and a real, fractional mtime is floored so the taker's own claim is valid; the volatile
//     default store honours the same claim contract; a claim whose release fails is logged,
//     strands its record only until the takeover bound, and is then counted once.
//
// The engine tests call engine.resolvePendingHealthVerdicts() directly, the way every existing
// sweep test does. Production reaches it only through the coordinator's arm cycle; the
// sweep itself never touches the lease store or the ownership handle, which is why these engines
// are built with a never-armed handle and write no ledger record at all.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const PENDING_HEALTH_VERDICT_STORE_PATH = resolve(REPO_ROOT, 'src', 'local-mcp', 'pending-health-verdict-store.mjs');

const START = Date.UTC(2026, 8, 18, 12, 0, 0);
const BACKSTOP_MS = 60 * 60 * 1000;
const GRACE_MS = 6 * 60 * 1000;
const JOB_A = 'a'.repeat(64);
const JOB_B = 'b'.repeat(64);
const CONCURRENT_CLAIM_JOB_COUNT = 16;
// Takeover fixtures in realistic order. A sweep claims a record only once it is due, so the
// record fell due before the crashed claimer took it. That claim is one ms past the backstop at START.
const CRASHED_CLAIM_AT_MS = START - BACKSTOP_MS - 1;
const DUE_BEFORE_CRASH_MS = CRASHED_CLAIM_AT_MS - 4999;

const notUsedRepeatAuthorizationJudge = { async judge() { throw new Error('not used in this test'); } };
const notUsedApprovalAdapter = { async authorize() { throw new Error('not used in this test'); } };
const notUsedDispatchAdapter = { async dispatch() { throw new Error('not used in this test'); } };
const sourcePolicy = Object.freeze({
  allowedRoots: [resolve(REPO_ROOT, 'tests', 'fixtures', 'openrouter-review', 'allowed')],
  maxSourceBytes: 10_000,
});
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });

// Copied from tests/openrouter-review-engine.test.mjs: a scrub engine whose local-LLM checks never
// block. The sweep never scrubs anything; this only satisfies createReviewEngine's validation.
function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

// Copied from tests/openrouter-pending-health-verdict-store.test.mjs.
async function withTempStore(fn) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-health-verdict-claim-'));
  try {
    await fn(createPendingHealthVerdictStore({ dataRoot }), dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// A trimmed copy of tests/openrouter-review-engine.test.mjs's withEngine: real stores in the given
// data root, a clock frozen at START unless the test moves it, and optional thin wraps of the REAL
// pending and health stores. The ownership handle is never armed (see the header comment above for
// why that is sufficient here). Returns the UNWRAPPED real stores next to the engine, so a test can
// set up and inspect state without going through its own wrappers. Tests that need two engines on
// one data root call this directly; every other test goes through withSweepEngine.
function createSweepEngine({ dataRoot, clock = () => START, wrapPendingHealthVerdictStore, wrapDispatchHealthStore }) {
  const leaseStore = createLeaseStore({ dataRoot, clock });
  const pendingStore = createPendingHealthVerdictStore({ dataRoot });
  const realDispatchHealthStore = createDispatchHealthStore({ dataRoot });
  const engine = createReviewEngine({
    leaseStore,
    ownerLock: leaseStore.createUnarmedOwnerHandle(),
    approvalAdapter: notUsedApprovalAdapter,
    dispatchAdapter: notUsedDispatchAdapter,
    resultStore: createResultStore({ dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
    scrubMappingStore: createScrubMappingStore({ dataRoot }),
    clock,
    sourcePolicy,
    preflightPolicy,
    installationHardMaximumUsd: 10,
    repeatAuthorizationJudge: notUsedRepeatAuthorizationJudge,
    dispatchHealthStore: wrapDispatchHealthStore ? wrapDispatchHealthStore(realDispatchHealthStore) : realDispatchHealthStore,
    pendingHealthVerdictStore: wrapPendingHealthVerdictStore ? wrapPendingHealthVerdictStore(pendingStore) : pendingStore,
    healthVerdictGraceMs: GRACE_MS,
    healthVerdictBackstopMs: BACKSTOP_MS,
  });
  return { engine, pendingStore, dispatchHealthStore: realDispatchHealthStore };
}

// One engine in its own temp data root. `options` are createSweepEngine's (clock and the two wraps).
async function withSweepEngine(run, options = {}) {
  await withSharedDataRoot(async (dataRoot) => {
    await run({ ...createSweepEngine({ dataRoot, ...options }), dataRoot });
  });
}

// A temp data root that more than one engine can share.
async function withSharedDataRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-health-verdict-claim-engine-'));
  try {
    await run(dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// Waits for a condition another engine's sweep sets. Bounded, so a broken interleaving fails the
// test that uses it instead of hanging the runner.
async function waitFor(condition, what) {
  const deadline = Date.now() + 10_000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolveWait) => { setTimeout(resolveWait, 1); });
  }
}

// A record that is due at START and well inside the backstop. With no dispatch outcome captured,
// the sweep resolves it as a failure (the existing "nothing captured" rule). The takeover tests
// pass an earlier notBeforeMs, so the record was already due when the crashed claimer took it.
async function seedDueRecord(pendingStore, jobId, reviewerId = 'grok', notBeforeMs = START - 1000) {
  await pendingStore.record({
    jobId, reviewerId, reservationUsd: 0.5, notBeforeMs, recordedAtMs: notBeforeMs - 9000,
  });
}

// Copied from tests/openrouter-review-engine.test.mjs.
async function writeDispatchOutcomeFixture(dataRoot, jobId, outcome) {
  const path = dispatchOutcomePath({ dataRoot, jobId });
  await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
  await writeFile(path, JSON.stringify(outcome), 'utf8');
}

// A captured RESPONSE the real grader accepts: tests/openrouter-review-engine.test.mjs's
// grokPassBody() (provider xAI, a clean pass verdict, a cost well inside the record's reservation).
async function writeCapturedSuccess(dataRoot, jobId) {
  const body = { provider: 'xAI', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ verdict: 'pass', findings: [] }) } }], usage: { cost: 0.02 } };
  await writeDispatchOutcomeFixture(dataRoot, jobId, {
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

// Stronger than consecutiveFailures === 0: the health store writes its file on every recordOutcome,
// so an absent file proves recordOutcome was never called at all.
async function assertNothingRecorded(dispatchHealthStore, message) {
  await assert.rejects(readFile(dispatchHealthStore.statePath, 'utf8'), (error) => error.code === 'ENOENT', message);
}

// The shape a crash mid-`wx`-write leaves behind: the exclusive create succeeded, the body did not
// finish. Its mtime is set explicitly, relative to the engine's frozen clock, so the grace comparison
// never depends on the host's real time. It is a whole ms; a real file's is fractional, which one
// grading-instant test covers by re-stamping the file.
async function writeTruncatedClaim(dataRoot, jobId, mtimeMs) {
  const claimPath = join(dataRoot, 'pending-health-verdicts', `${jobId}.claim`);
  const body = JSON.stringify({ jobId, claimId: 'crashed-mid-write', pid: 1, claimedAtMs: mtimeMs });
  await writeFile(claimPath, body.slice(0, 20), 'utf8');
  await utimes(claimPath, new Date(mtimeMs), new Date(mtimeMs));
  return claimPath;
}

// One stderr line per takeover, whatever else the sweep logs.
function takeoverLines(stderr) {
  return stderr.split('\n').filter((line) => line.includes('pending-health-verdict-claim-takeover'));
}

async function captureStderr(run) {
  const originalWrite = process.stderr.write;
  let captured = '';
  process.stderr.write = (chunk) => {
    captured += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  };
  try {
    await run();
  } finally {
    process.stderr.write = originalWrite;
  }
  return captured;
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs (not exported there): a BOUNDED wait for a
// child's real 'close', so a hung child fails this test instead of hanging the runner.
async function waitForChildClose(child, { timeoutMs = 40_000, describe = () => '' } = {}) {
  const closed = once(child, 'close');
  let timer;
  const timedOut = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`claim child did not exit within ${timeoutMs}ms${describe()}`)), timeoutMs);
  });
  try {
    return await Promise.race([closed, timedOut]);
  } finally {
    clearTimeout(timer);
  }
}

// The child module is generated in memory and imports the REAL store by file URL, following the
// stdio test's buildHarnessModuleSource precedent. Test-only env names, never OPENROUTER_REVIEW_MCP_*.
function buildClaimChildSource() {
  const storeUrl = pathToFileURL(PENDING_HEALTH_VERDICT_STORE_PATH).href;
  return `
import { readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createPendingHealthVerdictStore } from ${JSON.stringify(storeUrl)};

const dataRoot = process.env.OPENROUTER_REVIEW_CLAIM_TEST_DATA_ROOT;
const barrierDir = process.env.OPENROUTER_REVIEW_CLAIM_TEST_BARRIER_DIR;
const parties = Number(process.env.OPENROUTER_REVIEW_CLAIM_TEST_PARTIES);
const jobIds = JSON.parse(process.env.OPENROUTER_REVIEW_CLAIM_TEST_JOB_IDS);
const store = createPendingHealthVerdictStore({ dataRoot });

// File barrier: announce readiness, then wait until every party has, so the claims below race.
await writeFile(join(barrierDir, 'ready-' + process.pid), '', 'utf8');
const barrierDeadline = Date.now() + 20000;
while ((await readdir(barrierDir)).length < parties) {
  if (Date.now() > barrierDeadline) throw new Error('claim barrier timed out');
  await delay(1);
}

const won = [];
let lost = 0;
for (const jobId of jobIds) {
  const result = await store.claim({ jobId, nowMs: Date.now() });
  if (result.claimed === true) won.push({ jobId, claimId: result.claimId });
  else if (result.claimed === false) lost += 1;
  else throw new Error('claim returned neither claimed:true nor claimed:false');
}
process.stdout.write(JSON.stringify({ pid: process.pid, won, lost }));
`;
}

function spawnClaimChild({ dataRoot, barrierDir, parties, jobIds }) {
  const env = { ...process.env };
  delete env.OPENROUTER_REVIEW_MCP_DATA_ROOT;
  return spawn(process.execPath, ['--input-type=module', '-e', buildClaimChildSource()], {
    cwd: REPO_ROOT,
    env: {
      ...env,
      OPENROUTER_REVIEW_CLAIM_TEST_DATA_ROOT: dataRoot,
      OPENROUTER_REVIEW_CLAIM_TEST_BARRIER_DIR: barrierDir,
      OPENROUTER_REVIEW_CLAIM_TEST_PARTIES: String(parties),
      OPENROUTER_REVIEW_CLAIM_TEST_JOB_IDS: JSON.stringify(jobIds),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function collectChild(child) {
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const [code, signal] = await waitForChildClose(child, { timeoutMs: 30_000, describe: () => `; stderr so far: ${stderr}` });
  return { code, signal, stdout, stderr };
}

test('claim is an exclusive create of <jobId>.claim that recallClaim reads back and list() never returns', async () => {
  await withTempStore(async (store, dataRoot) => {
    await store.record({ jobId: JOB_A, reviewerId: 'grok', reservationUsd: 0.5, notBeforeMs: START, recordedAtMs: START });

    const first = await store.claim({ jobId: JOB_A, nowMs: START });
    assert.equal(first.claimed, true);
    assert.equal(typeof first.claimId, 'string');
    assert.ok(first.claimId.length > 0);
    assert.deepEqual(
      await store.recallClaim({ jobId: JOB_A }),
      { status: 'held', claim: { jobId: JOB_A, claimId: first.claimId, pid: process.pid, claimedAtMs: START } },
    );

    const second = await store.claim({ jobId: JOB_A, nowMs: START + 1 });
    assert.deepEqual(second, { claimed: false }, 'a second claim for the same jobId must lose');
    assert.equal((await store.recallClaim({ jobId: JOB_A })).claim?.claimId, first.claimId, 'a losing claim must never overwrite the winner');

    assert.deepEqual(
      (await readdir(join(dataRoot, 'pending-health-verdicts'))).sort(),
      [`${JOB_A}.claim`, `${JOB_A}.json`].sort(),
      'the claim lives next to its record, as one extra file',
    );
    assert.deepEqual((await store.list()).map((record) => record.jobId), [JOB_A], 'list() returns the record once and never the claim');
  });
});

test('releaseClaim with a mismatched claimId leaves the claim; the winning claimId or a null force-drop removes it; a claimId never removes an unreadable claim', async () => {
  await withTempStore(async (store, dataRoot) => {
    const won = await store.claim({ jobId: JOB_A, nowMs: START });

    await store.releaseClaim({ jobId: JOB_A, claimId: 'not-the-winning-claim-id' });
    assert.equal(
      (await store.recallClaim({ jobId: JOB_A })).claim?.claimId,
      won.claimId,
      'a mismatched claimId must leave the claim in place',
    );

    await store.releaseClaim({ jobId: JOB_A, claimId: won.claimId });
    assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'the winning claimId releases the claim');
    await store.releaseClaim({ jobId: JOB_A, claimId: won.claimId });

    const again = await store.claim({ jobId: JOB_A, nowMs: START });
    assert.equal(again.claimed, true, 'a released claim can be won again');
    await store.releaseClaim({ jobId: JOB_A, claimId: null });
    assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'claimId null force-drops whatever claim is there');
    await store.releaseClaim({ jobId: JOB_A, claimId: null });

    // A claim cut off mid-write, whose truncated body even starts with the claimId being released.
    // It may be another sweep's claim still being written, so only the sweep's takeover rule,
    // through a null force-drop, may remove it; a claimId never matches an unreadable claim.
    const claimPath = join(dataRoot, 'pending-health-verdicts', `${JOB_A}.claim`);
    await writeFile(claimPath, JSON.stringify({ claimId: 'mid-write', jobId: JOB_A }).slice(0, 24), 'utf8');
    assert.equal((await store.recallClaim({ jobId: JOB_A })).status, 'unreadable');
    await store.releaseClaim({ jobId: JOB_A, claimId: 'mid-write' });
    assert.equal((await store.recallClaim({ jobId: JOB_A })).status, 'unreadable', 'a claimId must never release an unreadable claim');
    await store.releaseClaim({ jobId: JOB_A, claimId: null });
    assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'a null force-drop removes an unreadable claim too');
  });
});

test('recallClaim reports absent, unreadable with the file\'s mtimeMs, or held, and rethrows any other read failure', async () => {
  await withTempStore(async (store, dataRoot) => {
    assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'no claim file at all');

    const verdictRoot = join(dataRoot, 'pending-health-verdicts');
    await mkdir(verdictRoot, { recursive: true });
    const claimBody = { jobId: JOB_A, claimId: 'some-claim', pid: process.pid, claimedAtMs: START };
    const unreadableBodies = [
      ['an empty file (crash right after the exclusive create)', ''],
      ['a truncated body (crash mid-write)', JSON.stringify(claimBody).slice(0, 20)],
      ['text that is not JSON', 'not valid json{{{'],
      ['a body missing a required field', JSON.stringify({ ...claimBody, pid: undefined })],
      ['a body naming a different jobId', JSON.stringify({ ...claimBody, jobId: JOB_B })],
      ['a gradeAsOfMs that is not a safe integer', JSON.stringify({ ...claimBody, gradeAsOfMs: 'soon' })],
    ];
    for (const [label, body] of unreadableBodies) {
      const claimPath = join(verdictRoot, `${JOB_A}.claim`);
      await writeFile(claimPath, body, 'utf8');
      await utimes(claimPath, new Date(START - 5000), new Date(START - 5000));
      assert.deepEqual(
        await store.recallClaim({ jobId: JOB_A }),
        { status: 'unreadable', mtimeMs: (await stat(claimPath)).mtimeMs },
        `${label} is unreadable, reported with the file's own mtimeMs`,
      );
    }

    await writeFile(join(verdictRoot, `${JOB_A}.claim`), JSON.stringify(claimBody), 'utf8');
    assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'held', claim: claimBody });

    await mkdir(join(verdictRoot, `${JOB_B}.claim`));
    await assert.rejects(
      () => store.recallClaim({ jobId: JOB_B }),
      (error) => error.code === 'EISDIR',
      'only ENOENT reads as absent; any other failure to read the claim is a real error, never a guess',
    );
  });
});

test('an unreadable claim that vanishes before its stat reads as absent; any other stat failure is rethrown', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-health-verdict-claim-stat-'));
  try {
    assert.throws(() => createPendingHealthVerdictStore({ dataRoot, statImpl: 'not a function' }), TypeError);
    assert.throws(() => createPendingHealthVerdictStore({ dataRoot, statImpl: null }), TypeError);
    const verdictRoot = join(dataRoot, 'pending-health-verdicts');
    await mkdir(verdictRoot, { recursive: true });
    const claimPath = join(verdictRoot, `${JOB_A}.claim`);

    // The claim's holder releases it between this read and its stat: the injected stat deletes the
    // file and then runs the REAL stat, so the ENOENT comes from the real filesystem.
    const statted = [];
    const vanishing = createPendingHealthVerdictStore({
      dataRoot,
      statImpl: async (path) => {
        statted.push(path);
        await rm(path);
        return stat(path);
      },
    });
    await writeFile(claimPath, 'not valid json{{{', 'utf8');
    assert.deepEqual(await vanishing.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'a claim released mid-read is absent, not an error');
    assert.deepEqual(statted, [claimPath], 'the unreadable body really was read before the file vanished');

    const injected = Object.assign(new Error('simulated stat permission failure'), { code: 'EPERM' });
    const failing = createPendingHealthVerdictStore({ dataRoot, statImpl: async () => { throw injected; } });
    await writeFile(claimPath, 'not valid json{{{', 'utf8');
    await assert.rejects(
      () => failing.recallClaim({ jobId: JOB_A }),
      (error) => error === injected,
      'only a claim that genuinely vanished reads as absent; any other stat failure must surface',
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('claim persists an optional gradeAsOfMs that recallClaim returns, and refuses one that is not a safe integer', async () => {
  await withTempStore(async (store) => {
    const carried = await store.claim({ jobId: JOB_A, nowMs: START, gradeAsOfMs: START - 5000 });
    assert.deepEqual(
      await store.recallClaim({ jobId: JOB_A }),
      { status: 'held', claim: { jobId: JOB_A, claimId: carried.claimId, pid: process.pid, claimedAtMs: START, gradeAsOfMs: START - 5000 } },
      'a takeover\'s claim carries the grading instant it inherited, next to its own claim time',
    );
    await assert.rejects(() => store.claim({ jobId: JOB_B, nowMs: START, gradeAsOfMs: 1.5 }), TypeError);
    await assert.rejects(() => store.claim({ jobId: JOB_B, nowMs: START, gradeAsOfMs: null }), TypeError);
    assert.deepEqual(await store.recallClaim({ jobId: JOB_B }), { status: 'absent' }, 'a refused claim writes nothing');
  });
});

test('claim, recallClaim and releaseClaim refuse malformed input before touching the disk', async () => {
  await withTempStore(async (store, dataRoot) => {
    await assert.rejects(() => store.claim({ jobId: 'not-a-job-id', nowMs: START }), TypeError);
    await assert.rejects(() => store.claim({ jobId: JOB_A, nowMs: 1.5 }), TypeError);
    await assert.rejects(() => store.claim({ jobId: JOB_A }), TypeError);
    await assert.rejects(() => store.recallClaim({ jobId: '../escape' }), TypeError);
    await assert.rejects(() => store.releaseClaim({ jobId: JOB_A }), TypeError, 'claimId must be explicit: a string, or null to force-drop');
    await assert.rejects(() => store.releaseClaim({ jobId: JOB_A, claimId: '' }), TypeError);
    await assert.rejects(() => store.releaseClaim({ jobId: 'not-a-job-id', claimId: null }), TypeError);
    await assert.rejects(
      readdir(join(dataRoot, 'pending-health-verdicts')),
      (error) => error.code === 'ENOENT',
      'a refused call must not even create the verdict directory',
    );
  });
});

test('claim rejects, never reports a lost claim, when the verdict directory cannot be created', async () => {
  await withTempStore(async (store, dataRoot) => {
    await writeFile(join(dataRoot, 'pending-health-verdicts'), 'a file where the directory should be', 'utf8');
    await assert.rejects(
      () => store.claim({ jobId: JOB_A, nowMs: START }),
      (error) => error.code === 'EEXIST' || error.code === 'ENOTDIR',
      'only the exclusive create itself may read as { claimed: false }; a broken directory is a real failure',
    );
  });
});

for (const parties of [2, 4]) {
  test(`${parties} real processes claiming the same ${CONCURRENT_CLAIM_JOB_COUNT} jobIds at once win each jobId exactly once`, { timeout: 60_000 }, async () => {
    const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-health-verdict-claim-concurrent-'));
    const children = [];
    try {
      const jobIds = Array.from({ length: CONCURRENT_CLAIM_JOB_COUNT }, (_unused, index) => createHash('sha256').update(`concurrent-claim-job-${index}`).digest('hex'));
      const barrierDir = join(dataRoot, 'barrier');
      await mkdir(barrierDir, { recursive: true });
      for (let index = 0; index < parties; index += 1) {
        children.push(spawnClaimChild({ dataRoot, barrierDir, parties, jobIds }));
      }
      const outcomes = await Promise.all(children.map((child) => collectChild(child)));
      for (const outcome of outcomes) {
        assert.equal(outcome.code, 0, `claim child exited ${outcome.code} (signal ${outcome.signal}); stderr: ${outcome.stderr}`);
      }

      const reports = outcomes.map((outcome) => JSON.parse(outcome.stdout));
      for (const report of reports) {
        assert.equal(report.won.length + report.lost, jobIds.length, 'every child must get an answer for every jobId');
      }
      // The sum first, so the named sabotage (a claim that ignores EEXIST) reddens on exactly this
      // assertion, with the actual total showing N times K.
      assert.equal(
        reports.reduce((sum, report) => sum + report.won.length, 0),
        jobIds.length,
        'the wins across every process must sum to exactly K',
      );
      // Then per jobId: a correct sum could still hide one jobId won twice and another never won.
      const winners = new Map(jobIds.map((jobId) => [jobId, []]));
      for (const report of reports) {
        for (const { jobId, claimId } of report.won) winners.get(jobId).push({ pid: report.pid, claimId });
      }
      for (const [jobId, won] of winners) {
        assert.equal(won.length, 1, `jobId ${jobId} must be won by exactly one of ${parties} processes, got ${won.length}`);
      }

      const store = createPendingHealthVerdictStore({ dataRoot });
      for (const [jobId, [winner]] of winners) {
        const onDisk = await store.recallClaim({ jobId });
        assert.equal(onDisk.status, 'held', 'every won claim must be on disk and readable');
        assert.equal(onDisk.claim.claimId, winner.claimId, 'the claim on disk must be the reported winner\'s');
        assert.equal(onDisk.claim.pid, winner.pid, 'and it must name the winning process');
      }
    } finally {
      for (const child of children) {
        if (child.exitCode === null && child.signalCode === null) child.kill();
      }
      await rm(dataRoot, { recursive: true, force: true });
    }
  });
}

test('a won claim runs claim, re-read, remove, record, release in that order, and the record is gone before the claim is released', async () => {
  const calls = [];
  let recordPresentAtRelease = null;
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);

    await engine.resolvePendingHealthVerdicts();

    assert.deepEqual(calls, ['claim', 'recall', 'remove', 'recordOutcome', 'releaseClaim']);
    assert.equal(recordPresentAtRelease, false, 'the record must already be removed when its claim is released');
    assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, 'nothing was captured, so the verdict is a failure');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'neither the record nor the claim is left behind');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      // Delegates straight to the real list(), so its internal record reads are not logged below.
      async list() { return inner.list(); },
      async claim(args) { calls.push('claim'); return inner.claim(args); },
      async recall(args) { calls.push('recall'); return inner.recall(args); },
      async remove(args) { calls.push('remove'); return inner.remove(args); },
      async releaseClaim(args) {
        calls.push('releaseClaim');
        recordPresentAtRelease = (await inner.recall({ jobId: args.jobId })) !== null;
        return inner.releaseClaim(args);
      },
    }),
    wrapDispatchHealthStore: (inner) => ({
      ...inner,
      async recordOutcome(args) { calls.push('recordOutcome'); return inner.recordOutcome(args); },
    }),
  });
});

test('a record another process resolved after this sweep listed it is skipped on the re-read under the claim', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);

    await engine.resolvePendingHealthVerdicts();

    await assertNothingRecorded(dispatchHealthStore, 'the job was already resolved elsewhere; resolving it again would double-count it');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the claim taken for the re-read must be released');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async list() {
        const snapshot = await inner.list();
        // Another process claims, resolves and removes this record, then releases its claim -- all
        // in the window after this sweep listed the record and before this sweep claims it.
        await inner.remove({ jobId: JOB_A });
        return snapshot;
      },
    }),
  });
});

test('a claim that vanished before it could be read is claimed once more, and its record is resolved and counted exactly once', async () => {
  const claimResults = [];
  let foreign = null;
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);
    foreign = await pendingStore.claim({ jobId: JOB_A, nowMs: START - 1000 });
    assert.equal(foreign.claimed, true);

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, 'the retry resolves the record and counts it exactly once');
    assert.deepEqual(claimResults, [false, true], 'one lost exclusive create, then exactly one retry, which wins');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'neither the record nor any claim is left behind');
    assert.deepEqual(takeoverLines(stderr), [], 'a vanished claim is retried, not taken over');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async claim(args) {
        const result = await inner.claim(args);
        claimResults.push(result.claimed);
        return result;
      },
      async recallClaim(args) {
        // The foreign holder releases its claim in the window between this sweep's lost exclusive
        // create and this read. Its own resolution threw, so the record is still there for a retry.
        await inner.releaseClaim({ jobId: args.jobId, claimId: foreign.claimId });
        return inner.recallClaim(args);
      },
    }),
  });
});

test('a vanished claim whose holder already resolved the record is claimed once more, and the re-read under that claim skips it', async () => {
  const claimResults = [];
  let foreign = null;
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);
    foreign = await pendingStore.claim({ jobId: JOB_A, nowMs: START - 1000 });
    assert.equal(foreign.claimed, true);

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    await assertNothingRecorded(dispatchHealthStore, 'the holder already resolved this record; the retry must re-read it and skip, not count it a second time');
    assert.deepEqual(claimResults, [false, true], 'one lost exclusive create, then exactly one retry, which wins');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the retry\'s own claim is released after the empty re-read');
    assert.deepEqual(takeoverLines(stderr), [], 'a vanished claim is retried, not taken over');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async claim(args) {
        const result = await inner.claim(args);
        claimResults.push(result.claimed);
        return result;
      },
      async recallClaim(args) {
        // The foreign holder finishes in the window between this sweep's lost exclusive create and
        // this read: it removes the record it resolved (step 4), then releases its claim (step 6).
        await inner.remove({ jobId: args.jobId });
        await inner.releaseClaim({ jobId: args.jobId, claimId: foreign.claimId });
        return inner.recallClaim(args);
      },
    }),
  });
});

test('a readable foreign claim older than healthVerdictBackstopMs is taken over, and its record is counted exactly once', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    // Realistic order: the record fell due before the crashed claimer took it. Nothing is captured,
    // so the takeover grades it as a failure against dispatchOutcomeStore.
    await seedDueRecord(pendingStore, JOB_A, 'grok', DUE_BEFORE_CRASH_MS);
    const crashed = await pendingStore.claim({ jobId: JOB_A, nowMs: CRASHED_CLAIM_AT_MS });
    assert.equal(crashed.claimed, true);

    const firstSweep = await captureStderr(() => engine.resolvePendingHealthVerdicts());
    const secondSweep = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.equal(
      (await dispatchHealthStore.recall()).consecutiveFailures,
      1,
      'a crashed claimer\'s record must be counted exactly once across both sweeps: never dropped, never twice',
    );
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the taken-over claim released');
    assert.deepEqual(
      takeoverLines(firstSweep),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
      'exactly one stderr line for the one takeover',
    );
    assert.equal(secondSweep, '', 'the second sweep finds nothing left to do');
  });
});

test('an unreadable (truncated) foreign claim older than healthVerdictGraceMs is taken over, and its record is counted exactly once', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    // Realistic order: the record fell due before the crashed claimer began writing its claim.
    const truncatedAtMs = START - GRACE_MS - 60_000;
    await seedDueRecord(pendingStore, JOB_A, 'grok', truncatedAtMs - 5000);
    await writeTruncatedClaim(dataRoot, JOB_A, truncatedAtMs);

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, 'the taken-over record is counted exactly once');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the truncated claim replaced, then released');
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=unreadable won=true`],
    );
  });
});

test('a taken-over readable claim is graded as of its claimedAtMs, so a captured success still inside the backstop then is not counted', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A, 'grok', DUE_BEFORE_CRASH_MS);
    await writeCapturedSuccess(dataRoot, JOB_A);
    const crashed = await pendingStore.claim({ jobId: JOB_A, nowMs: CRASHED_CLAIM_AT_MS });
    assert.equal(crashed.claimed, true);

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    // Measured from now, this record is past its backstop and would be forced to a failure. Measured
    // from the crashed claim, it was 4999 ms past due, so the captured success is what decides.
    await assertNothingRecorded(dispatchHealthStore, 'a real success whose sweep crashed must be graded, not forced to a failure by the time its claim sat abandoned');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the taken-over claim released');
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
      'exactly one stderr line for the one takeover',
    );
  });
});

test('a taken-over unreadable claim is graded as of the file\'s mtimeMs, so a captured success still inside the backstop then is not counted', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A, 'grok', DUE_BEFORE_CRASH_MS);
    await writeCapturedSuccess(dataRoot, JOB_A);
    await writeTruncatedClaim(dataRoot, JOB_A, CRASHED_CLAIM_AT_MS);

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    await assertNothingRecorded(dispatchHealthStore, 'a truncated claim has no claimedAtMs; its takeover must grade as of the file\'s mtimeMs, not now');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the truncated claim replaced, then released');
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=unreadable won=true`],
      'exactly one stderr line for the one takeover',
    );
  });
});

test('a takeover still force-fails a record that was already past its backstop when the crashed claimer took it', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    // Due one ms more than a whole backstop before the crashed claim: stale at the claimer's own
    // time, so the unchanged backstop rule applies and the captured success is never consulted.
    await seedDueRecord(pendingStore, JOB_A, 'grok', CRASHED_CLAIM_AT_MS - BACKSTOP_MS - 1);
    await writeCapturedSuccess(dataRoot, JOB_A);
    await pendingStore.claim({ jobId: JOB_A, nowMs: CRASHED_CLAIM_AT_MS });

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, 'a record already past its backstop at the crashed claim is force-failed, whatever was captured');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the taken-over claim released');
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
      'exactly one stderr line for the one takeover',
    );
  });
});

test('a stale claim whose record was resolved before the takeover is taken over, and the re-read under the new claim skips it', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A, 'grok', DUE_BEFORE_CRASH_MS);
    await pendingStore.claim({ jobId: JOB_A, nowMs: CRASHED_CLAIM_AT_MS });

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    await assertNothingRecorded(dispatchHealthStore, 'the record was already resolved; the takeover must re-read it and skip, not count it a second time');
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
      'the takeover itself still happens and logs its one line',
    );
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the taken-over claim is released after the empty re-read');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async releaseClaim(args) {
        // The old claimer was paused, not dead: after this sweep listed the record, it resumes and
        // removes the record it resolved, just before this sweep force-releases its claim.
        if (args.claimId === null) await inner.remove({ jobId: args.jobId });
        return inner.releaseClaim(args);
      },
    }),
  });
});

test('an unreadable foreign claim younger than or exactly at healthVerdictGraceMs is skipped: its claimer may still be writing it', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);
    await seedDueRecord(pendingStore, JOB_B);
    // A minute inside the grace: fresh by the grace, which the rule uses, not by some smaller bound.
    const claimPath = await writeTruncatedClaim(dataRoot, JOB_A, START - GRACE_MS + 60_000);
    // Exactly the grace old: still live, because the rule is strictly older.
    const atGracePath = await writeTruncatedClaim(dataRoot, JOB_B, START - GRACE_MS);
    const before = await readFile(claimPath, 'utf8');
    const atGraceBefore = await readFile(atGracePath, 'utf8');

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.ok(await pendingStore.recall({ jobId: JOB_A }), 'a record under a claim still being written is left for its claimer');
    assert.equal(await readFile(claimPath, 'utf8'), before, 'the young unreadable claim is untouched');
    assert.ok(await pendingStore.recall({ jobId: JOB_B }), 'an unreadable claim exactly at the grace age is still live (the rule is strictly older)');
    assert.equal(await readFile(atGracePath, 'utf8'), atGraceBefore, 'the unreadable claim at the grace age is untouched');
    await assertNothingRecorded(dispatchHealthStore, 'a skipped record must not be counted');
    assert.deepEqual(takeoverLines(stderr), []);
  });
});

test('a live foreign claim, younger than or exactly at the backstop, is skipped: record and claim stay and nothing is recorded', async () => {
  await withSweepEngine(async ({ engine, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);
    await seedDueRecord(pendingStore, JOB_B);
    const young = await pendingStore.claim({ jobId: JOB_A, nowMs: START - 1000 });
    const atBackstop = await pendingStore.claim({ jobId: JOB_B, nowMs: START - BACKSTOP_MS });

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.ok(await pendingStore.recall({ jobId: JOB_A }), 'a record under a live foreign claim is left for its claimer');
    assert.ok(await pendingStore.recall({ jobId: JOB_B }), 'a claim exactly at the backstop age is still live (the rule is strictly older)');
    assert.equal((await pendingStore.recallClaim({ jobId: JOB_A })).claim?.claimId, young.claimId, 'the foreign claim is untouched');
    assert.equal((await pendingStore.recallClaim({ jobId: JOB_B })).claim?.claimId, atBackstop.claimId, 'the foreign claim is untouched');
    await assertNothingRecorded(dispatchHealthStore, 'a skipped record must not be counted');
    assert.deepEqual(takeoverLines(stderr), []);
  });
});

test('a retry or a takeover that loses its claim again skips the record, which stays for the process that won', async () => {
  const intruders = new Map();
  let foreignA = null;
  await withSweepEngine(async ({ engine, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);
    // JOB_B in realistic order: due before its crashed claimer took it, an hour and a ms ago.
    await seedDueRecord(pendingStore, JOB_B, 'grok', DUE_BEFORE_CRASH_MS);
    foreignA = await pendingStore.claim({ jobId: JOB_A, nowMs: START - 1000 });
    await pendingStore.claim({ jobId: JOB_B, nowMs: CRASHED_CLAIM_AT_MS });

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.ok(await pendingStore.recall({ jobId: JOB_A }), 'a lost retry leaves the record for the process that won it');
    assert.ok(await pendingStore.recall({ jobId: JOB_B }), 'a lost takeover leaves the record for the process that won it');
    assert.deepEqual([...intruders.keys()].sort(), [JOB_A, JOB_B].sort(), 'both races must have run: a retry for JOB_A and a takeover for JOB_B');
    for (const jobId of [JOB_A, JOB_B]) {
      assert.equal((await pendingStore.recallClaim({ jobId })).claim?.claimId, intruders.get(jobId).claimId, 'the winner\'s claim is untouched');
    }
    await assertNothingRecorded(dispatchHealthStore, 'neither record may be counted by the process that lost');
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_B} found=held won=false`],
      'the lost retry is not a takeover; the lost takeover still logs its one line',
    );
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async recallClaim(args) {
        if (args.jobId !== JOB_A) return inner.recallClaim(args);
        // JOB_A: its holder releases, this sweep reads it as absent, and a third process claims it
        // before this sweep's one retry.
        await inner.releaseClaim({ jobId: JOB_A, claimId: foreignA.claimId });
        const seen = await inner.recallClaim(args);
        intruders.set(JOB_A, await inner.claim({ jobId: JOB_A, nowMs: START }));
        return seen;
      },
      async releaseClaim(args) {
        await inner.releaseClaim(args);
        // JOB_B: a third process claims it right after this sweep force-releases the stale claim.
        if (args.jobId === JOB_B && args.claimId === null) intruders.set(JOB_B, await inner.claim({ jobId: JOB_B, nowMs: START }));
      },
    }),
  });
});

test('a claim is released even when resolving its record throws, so the next sweep retries the record', async () => {
  const claimResults = [];
  await withSweepEngine(async ({ engine, dataRoot, pendingStore }) => {
    // An unknown reviewerId with a captured RESPONSE makes resolveOneHealthVerdict() throw inside
    // getReviewer() -- the same fault the existing engine.test.mjs isolation test injects.
    await seedDueRecord(pendingStore, JOB_A, 'not-a-real-reviewer');
    await writeDispatchOutcomeFixture(dataRoot, JOB_A, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from('{}', 'utf8').toString('base64') }),
    });

    await captureStderr(() => engine.resolvePendingHealthVerdicts());
    await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.deepEqual(claimResults, [true, true], 'the second sweep must be able to claim the record again');
    assert.ok(await pendingStore.recall({ jobId: JOB_A }), 'the record stays for a later retry');
    assert.deepEqual(await pendingStore.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'no claim is left behind');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async claim(args) {
        const result = await inner.claim(args);
        claimResults.push(result.claimed);
        return result;
      },
    }),
  });
});

test('two real engines sweeping the same due record at the same time record its verdict exactly once', async () => {
  await withSharedDataRoot(async (dataRoot) => {
    const reachedRemove = { A: false, B: false };
    const sweepDone = { A: false, B: false };
    const recordedBy = [];
    const buildEngine = (name, other) => createSweepEngine({
      dataRoot,
      wrapPendingHealthVerdictStore: (inner) => ({
        ...inner,
        async remove(args) {
          // Neither engine removes the record until the other has reached its own remove or finished
          // its sweep. So both have listed the record, and an engine that wrongly carried on past a
          // lost claim has re-read it too, before it disappears: the double count is deterministic.
          reachedRemove[name] = true;
          await waitFor(() => reachedRemove[other] || sweepDone[other], `engine ${other} to reach remove or finish`);
          return inner.remove(args);
        },
      }),
      wrapDispatchHealthStore: (inner) => ({
        ...inner,
        // Counted per engine: dispatch-health.json itself is not a reliable counter when two engines
        // write it at once, which is exactly the case a failure here would produce.
        async recordOutcome(args) { recordedBy.push(name); return inner.recordOutcome(args); },
      }),
    });
    const engineA = buildEngine('A', 'B');
    const engineB = buildEngine('B', 'A');
    await seedDueRecord(engineA.pendingStore, JOB_A);

    const sweep = async (name, built) => {
      try {
        await built.engine.resolvePendingHealthVerdicts();
      } finally {
        sweepDone[name] = true;
      }
    };
    const stderr = await captureStderr(() => Promise.all([sweep('A', engineA), sweep('B', engineB)]));

    assert.equal(recordedBy.length, 1, `the verdict must be recorded by exactly one of the two engines, got ${JSON.stringify(recordedBy)}`);
    assert.equal((await engineA.dispatchHealthStore.recall()).consecutiveFailures, 1, 'nothing was captured, so the one verdict is a failure');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is removed and the winner\'s claim released');
    assert.deepEqual(
      stderr.split('\n').filter((line) => line.includes('openrouter-review-engine:')),
      [],
      'the engine that lost the claim skips cleanly: no failure, release or takeover line from either engine',
    );
  });
});

test('a takeover carries the crashed claimer\'s grading instant in its own claim, so a second crash still grades a real success as a success', async () => {
  await withSharedDataRoot(async (dataRoot) => {
    // The first taker sweeps one ms past the crashed claim's backstop, the second one ms past the
    // first taker's own backstop.
    const FIRST_TAKER_AT_MS = START;
    const SECOND_TAKER_AT_MS = FIRST_TAKER_AT_MS + BACKSTOP_MS + 1;
    const firstTaker = createSweepEngine({
      dataRoot,
      clock: () => FIRST_TAKER_AT_MS,
      wrapPendingHealthVerdictStore: (inner) => ({
        ...inner,
        // Delegates straight to the real list(), whose internal reads must not hit the crash below.
        async list() { return inner.list(); },
        // The first taker dies between winning its claim and removing the record: its re-read never
        // returns, and a dead process releases nothing, so its own claim stays on disk.
        async recall() { throw new Error('simulated crash of the first taker'); },
        async releaseClaim(args) {
          if (args.claimId === null) return inner.releaseClaim(args);
          return undefined;
        },
      }),
    });
    await seedDueRecord(firstTaker.pendingStore, JOB_A, 'grok', DUE_BEFORE_CRASH_MS);
    await writeCapturedSuccess(dataRoot, JOB_A);
    await firstTaker.pendingStore.claim({ jobId: JOB_A, nowMs: CRASHED_CLAIM_AT_MS });

    const firstTakeover = await captureStderr(() => firstTaker.engine.resolvePendingHealthVerdicts());

    assert.deepEqual(
      takeoverLines(firstTakeover),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
      'the first taker takes the crashed claim over',
    );
    const left = await firstTaker.pendingStore.recallClaim({ jobId: JOB_A });
    assert.equal(left.status, 'held', 'the first taker died holding its own claim');
    assert.equal(left.claim.claimedAtMs, FIRST_TAKER_AT_MS, 'its claim is stamped with its own time, so it looks live for a whole backstop');
    assert.equal(left.claim.gradeAsOfMs, CRASHED_CLAIM_AT_MS, 'and carries the crashed claimer\'s grading instant');

    const secondTaker = createSweepEngine({ dataRoot, clock: () => SECOND_TAKER_AT_MS });
    const secondTakeover = await captureStderr(() => secondTaker.engine.resolvePendingHealthVerdicts());

    assert.deepEqual(
      takeoverLines(secondTakeover),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
      'the second taker takes the first taker\'s claim over',
    );
    // Measured from either taker's own claim time, this record is past its backstop and would be
    // forced to a failure. Measured from the carried instant, it was 4999 ms past due.
    await assertNothingRecorded(secondTaker.dispatchHealthStore, 'a real success whose sweep crashed twice must still be graded from the first crashed claim, not forced to a failure');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the second taker\'s claim released');
  });
});

test('a takeover whose resolution throws releases its claim, instant and all, so a record that can never be graded is still counted once, by the next sweep', async () => {
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    // An unknown reviewerId with a captured RESPONSE: resolveOneHealthVerdict() throws in
    // getReviewer() on every attempt, the same fault the release-for-retry test injects.
    await seedDueRecord(pendingStore, JOB_A, 'not-a-real-reviewer', DUE_BEFORE_CRASH_MS);
    await writeDispatchOutcomeFixture(dataRoot, JOB_A, {
      kind: 'RESPONSE',
      envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from('{}', 'utf8').toString('base64') }),
    });
    await pendingStore.claim({ jobId: JOB_A, nowMs: CRASHED_CLAIM_AT_MS });

    const takeoverSweep = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    await assertNothingRecorded(dispatchHealthStore, 'graded as of the crashed claim, the record reaches getReviewer(), which throws, so the takeover sweep counts nothing');
    assert.deepEqual(
      takeoverLines(takeoverSweep),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
    );
    assert.equal(
      takeoverSweep.split('\n').filter((line) => line.includes(`resolve-pending-health-verdict-failed jobId=${JOB_A}`)).length,
      1,
      'the throw is logged once',
    );
    assert.deepEqual(await pendingStore.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'the taken-over claim is released after the throw, carried instant and all');

    await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.equal(
      (await dispatchHealthStore.recall()).consecutiveFailures,
      1,
      'the next sweep claims it first try, measures its backstop from now, and counts it: it is never retried forever',
    );
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and no claim is left behind');
  });
});

test('an unreadable claim whose real mtime has a fractional millisecond is taken over and graded as of that mtime, floored to a whole ms', async () => {
  const claimCalls = [];
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A, 'grok', DUE_BEFORE_CRASH_MS);
    await writeCapturedSuccess(dataRoot, JOB_A);
    // writeTruncatedClaim pins a whole ms, but a file a real crash leaves behind has a fractional
    // mtimeMs (typical for freshly written files on Windows). Seconds with a fractional part keep
    // the sub-millisecond digits, so re-stamp the claim half a millisecond later.
    const claimPath = await writeTruncatedClaim(dataRoot, JOB_A, CRASHED_CLAIM_AT_MS);
    await utimes(claimPath, (CRASHED_CLAIM_AT_MS + 0.5) / 1000, (CRASHED_CLAIM_AT_MS + 0.5) / 1000);
    const { mtimeMs } = await stat(claimPath);
    assert.equal(Number.isSafeInteger(mtimeMs), false, `precondition: the claim file's mtimeMs must be fractional, got ${mtimeMs}`);

    const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    await assertNothingRecorded(dispatchHealthStore, 'a truncated claim with a fractional mtime must still be taken over and graded as of it, not forced to a failure');
    assert.deepEqual(
      stderr.split('\n').filter((line) => line.includes('resolve-pending-health-verdict-failed')),
      [],
      'the takeover\'s own claim must not throw: a real mtimeMs is fractional, and gradeAsOfMs must be a safe integer',
    );
    assert.deepEqual(
      takeoverLines(stderr),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=unreadable won=true`],
      'exactly one stderr line for the one takeover',
    );
    assert.deepEqual(
      claimCalls.map((args) => args.gradeAsOfMs),
      [undefined, Math.floor(mtimeMs)],
      'the first-try claim carries no instant; the takeover\'s claim carries the mtime floored to a whole ms',
    );
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the truncated claim replaced, then released');
  }, {
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async claim(args) { claimCalls.push(args); return inner.claim(args); },
    }),
  });
});

test('the volatile default pending store honours the same claim contract as the durable one', async () => {
  // The default every engine built without a pendingHealthVerdictStore gets. Every other test here
  // passes the durable store, so without this nothing ever calls these three methods. Imported
  // inside the test so the rest of this file still loads if that export is ever missing.
  const { createVolatilePendingHealthVerdictStore } = await import('../src/local-mcp/review-engine.mjs');
  const store = createVolatilePendingHealthVerdictStore();

  assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' });
  const first = await store.claim({ jobId: JOB_A, nowMs: START });
  assert.equal(first.claimed, true);
  assert.equal(typeof first.claimId, 'string');
  assert.deepEqual(await store.claim({ jobId: JOB_A, nowMs: START + 1 }), { claimed: false }, 'a second claim for the same jobId must lose');
  assert.deepEqual(
    await store.recallClaim({ jobId: JOB_A }),
    { status: 'held', claim: { jobId: JOB_A, claimId: first.claimId, pid: process.pid, claimedAtMs: START } },
    'recallClaim reports the winner, in the durable store\'s shape',
  );

  await store.releaseClaim({ jobId: JOB_A, claimId: 'not-the-winning-claim-id' });
  assert.equal((await store.recallClaim({ jobId: JOB_A })).claim?.claimId, first.claimId, 'a mismatched claimId must leave the claim in place');
  await store.releaseClaim({ jobId: JOB_A, claimId: first.claimId });
  assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'the winning claimId releases the claim');

  const carried = await store.claim({ jobId: JOB_A, nowMs: START, gradeAsOfMs: START - 5000 });
  assert.equal(carried.claimed, true, 'a released claim can be won again');
  assert.equal((await store.recallClaim({ jobId: JOB_A })).claim?.gradeAsOfMs, START - 5000, 'a carried gradeAsOfMs is kept');
  await store.releaseClaim({ jobId: JOB_A, claimId: null });
  assert.deepEqual(await store.recallClaim({ jobId: JOB_A }), { status: 'absent' }, 'claimId null force-drops whatever claim is there');
});

test('a claim whose release fails is logged once, strands its unresolved record only until the takeover bound, and is then counted exactly once', async () => {
  let nowMs = START;
  let removeFailuresLeft = 1;
  let releaseFailuresLeft = 1;
  const linesFor = (stderr, event) => stderr.split('\n').filter((line) => line.includes(`${event} jobId=${JOB_A}`));
  await withSweepEngine(async ({ engine, dataRoot, pendingStore, dispatchHealthStore }) => {
    await seedDueRecord(pendingStore, JOB_A);

    // First sweep: the remove fails, so the record stays, and then the release of its claim fails too.
    const firstSweep = await captureStderr(() => engine.resolvePendingHealthVerdicts());

    assert.equal(linesFor(firstSweep, 'pending-health-verdict-claim-release-failed').length, 1, 'exactly one claim-release-failed line for the release that failed');
    assert.equal(linesFor(firstSweep, 'resolve-pending-health-verdict-failed').length, 1, 'and one resolve failure, for the remove that failed first');
    assert.ok(await pendingStore.recall({ jobId: JOB_A }), 'the record was never removed');
    const stranded = await pendingStore.recallClaim({ jobId: JOB_A });
    assert.equal(stranded.status, 'held', 'the claim that could not be released is still on disk');

    // A minute later the stranded claim is still live to every sweep, so the record is skipped.
    nowMs = START + 60_000;
    const strandedSweep = await captureStderr(() => engine.resolvePendingHealthVerdicts());
    assert.equal(strandedSweep, '', 'inside the backstop the stranded record is skipped silently');
    await assertNothingRecorded(dispatchHealthStore, 'a stranded record is not counted while its claim still looks live');
    assert.equal((await pendingStore.recallClaim({ jobId: JOB_A })).claim?.claimId, stranded.claim.claimId, 'and its claim is untouched');

    // One ms past the stranded claim's backstop, the takeover rule recovers it.
    nowMs = START + BACKSTOP_MS + 1;
    const takeoverSweep = await captureStderr(() => engine.resolvePendingHealthVerdicts());
    assert.deepEqual(
      takeoverLines(takeoverSweep),
      [`openrouter-review-engine: pending-health-verdict-claim-takeover jobId=${JOB_A} found=held won=true`],
    );
    assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, 'graded as of the stranded claim and counted exactly once');
    assert.deepEqual(await readdir(join(dataRoot, 'pending-health-verdicts')), [], 'the record is resolved and the takeover\'s claim released');
  }, {
    clock: () => nowMs,
    wrapPendingHealthVerdictStore: (inner) => ({
      ...inner,
      async remove(args) {
        if (removeFailuresLeft > 0) {
          removeFailuresLeft -= 1;
          throw Object.assign(new Error('simulated remove failure'), { code: 'EPERM' });
        }
        return inner.remove(args);
      },
      async releaseClaim(args) {
        if (args.claimId !== null && releaseFailuresLeft > 0) {
          releaseFailuresLeft -= 1;
          throw Object.assign(new Error('simulated release failure'), { code: 'EPERM' });
        }
        return inner.releaseClaim(args);
      },
    }),
  });
});
