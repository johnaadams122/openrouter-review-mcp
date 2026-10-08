import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createDispatchOutcomeStore } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine, createVolatilePendingHealthVerdictStore } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

// Residual coverage for the pending-health claim path. These are intentionally separate from the
// main pending-health sweep tests so they can pin edge cases without modifying that file's
// coverage or fixtures.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const STORE_URL = pathToFileURL(resolve(REPO_ROOT, 'src', 'local-mcp', 'pending-health-verdict-store.mjs')).href;
const START = Date.UTC(2026, 8, 18, 12, 0, 0);
const JOB_A = 'a'.repeat(64);
const JOB_B = 'b'.repeat(64);

const noUse = Object.freeze({ async judge() { throw new Error('not used by a health sweep'); } });
const noApproval = Object.freeze({ async authorize() { throw new Error('not used by a health sweep'); } });
const noDispatch = Object.freeze({ async dispatch() { throw new Error('not used by a health sweep'); } });
const sourcePolicy = Object.freeze({ allowedRoots: [resolve(REPO_ROOT, 'tests', 'fixtures', 'openrouter-review', 'allowed')], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

async function withTempDataRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-health-claim-residuals-'));
  try {
    await run(dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// This is already armed by construction. Health sweeping is owner-independent itself, but this
// avoids making these residuals depend on the unarmed-entry ownership coordinator.
function preArmedOwnerHandle() {
  return Object.freeze({
    acquisitionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    isOwner: () => true,
    async arm() {},
    async release() {},
  });
}

function createSweepEngine({ dataRoot, pendingHealthVerdictStore, healthCalls }) {
  const leaseStore = createLeaseStore({ dataRoot, clock: () => START });
  const engine = createReviewEngine({
    leaseStore,
    ownerLock: preArmedOwnerHandle(),
    approvalAdapter: noApproval,
    dispatchAdapter: noDispatch,
    resultStore: createResultStore({ dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
    scrubMappingStore: createScrubMappingStore({ dataRoot }),
    clock: () => START,
    sourcePolicy,
    preflightPolicy,
    installationHardMaximumUsd: 10,
    repeatAuthorizationJudge: noUse,
    dispatchHealthStore: Object.freeze({
      async recordOutcome({ succeeded }) {
        healthCalls.push(succeeded);
        return { consecutiveFailures: healthCalls.length, shouldAlert: false };
      },
      async markAlerted() {},
    }),
    pendingHealthVerdictStore,
    healthVerdictGraceMs: 60_000,
    healthVerdictBackstopMs: 60 * 60 * 1000,
  });
  return engine;
}

async function seedDue(store, jobId) {
  await store.record({
    jobId,
    reviewerId: 'grok',
    reservationUsd: 0.5,
    notBeforeMs: START - 1,
    recordedAtMs: START - 2,
  });
}

async function captureStderr(run) {
  const original = process.stderr.write;
  let output = '';
  process.stderr.write = (chunk) => {
    output += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  };
  try {
    await run();
  } finally {
    process.stderr.write = original;
  }
  return output;
}

test('health sweep: a throwing claim or recallClaim is logged for that record and does not stop later due records', async () => {
  for (const throwingMethod of ['claim', 'recallClaim']) {
    // eslint-disable-next-line no-await-in-loop
    await withTempDataRoot(async (dataRoot) => {
      const durable = createPendingHealthVerdictStore({ dataRoot });
      await seedDue(durable, JOB_A);
      await seedDue(durable, JOB_B);
      // The recall branch is reached only after a real exclusive-create loss. A foreign claim gives
      // the sweep that exact premise without involving any later takeover behavior.
      if (throwingMethod === 'recallClaim') await durable.claim({ jobId: JOB_A, nowMs: START });
      const injected = Object.assign(new Error(`injected ${throwingMethod} failure`), { code: 'EIO' });
      const wrapped = Object.freeze({
        ...durable,
        async list() {
          // The residual requires a throw on one due record to leave later due records runnable.
          // Filesystem readdir order is unspecified, so force the throwing record first.
          return [
            await durable.recall({ jobId: JOB_A }),
            await durable.recall({ jobId: JOB_B }),
          ].filter((record) => record !== null);
        },
        async claim(input) {
          if (throwingMethod === 'claim' && input.jobId === JOB_A) throw injected;
          return durable.claim(input);
        },
        async recallClaim(input) {
          if (throwingMethod === 'recallClaim' && input.jobId === JOB_A) throw injected;
          return durable.recallClaim(input);
        },
      });
      const healthCalls = [];
      const engine = createSweepEngine({ dataRoot, pendingHealthVerdictStore: wrapped, healthCalls });

      const stderr = await captureStderr(() => engine.resolvePendingHealthVerdicts());

      assert.match(stderr, new RegExp(`resolve-pending-health-verdict-failed jobId=${JOB_A} error=Error`));
      assert.doesNotMatch(stderr, /injected (claim|recallClaim) failure|EIO/, 'the sweep logs the approved safe error detail, never the injected raw detail');
      assert.equal(await durable.recall({ jobId: JOB_A }) !== null, true, `${throwingMethod} record stays for a later sweep`);
      assert.equal(await durable.recall({ jobId: JOB_B }), null, `${throwingMethod} must not stop the later record`);
      assert.deepEqual(healthCalls, [false], 'only the later, normally resolved record records its failure');
    });
  }
});

test('health sweep: the real durable claim and releaseClaim rethrow native non-ENOENT filesystem failures from their own I/O', async () => {
  await withTempDataRoot(async (dataRoot) => {
    // This loader replaces only pending-health-verdict-store.mjs's writeFile binding. Its substitute
    // invokes the real node:fs/promises writeFile against a directory, yielding native EISDIR. The
    // child then calls the actual durable store's claim() so its EEXIST-only catch is exercised.
    const loaderPath = join(dataRoot, 'claim-write-loader.mjs');
    const mockPath = join(dataRoot, 'claim-write-native-error.mjs');
    const nativeFailureDirectory = join(dataRoot, 'native-write-target');
    await mkdir(nativeFailureDirectory);
    await writeFile(mockPath, `
import { writeFile as realWriteFile } from 'node:fs/promises';
export * from 'node:fs/promises';
export async function writeFile() {
  return realWriteFile(${JSON.stringify(nativeFailureDirectory)}, 'x', 'utf8');
}
`, 'utf8');
    await writeFile(loaderPath, `
const target = ${JSON.stringify(STORE_URL)};
const mock = ${JSON.stringify(pathToFileURL(mockPath).href)};
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'node:fs/promises' && context.parentURL === target) return { url: mock, shortCircuit: true };
  return nextResolve(specifier, context);
}
`, 'utf8');
    const childSource = `
import { createPendingHealthVerdictStore } from ${JSON.stringify(STORE_URL)};
const store = createPendingHealthVerdictStore({ dataRoot: process.env.HEALTH_RESIDUAL_DATA_ROOT });
try {
  await store.claim({ jobId: ${JSON.stringify(JOB_A)}, nowMs: ${START} });
  process.stdout.write(JSON.stringify({ unexpectedlyClaimed: true }));
} catch (error) {
  process.stdout.write(JSON.stringify({ code: error && error.code, message: error && error.message }));
}
`;
    const child = spawn(process.execPath, ['--experimental-loader', pathToFileURL(loaderPath).href, '--input-type=module', '--eval', childSource], {
      cwd: REPO_ROOT,
      env: { ...process.env, HEALTH_RESIDUAL_DATA_ROOT: dataRoot },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const [code, signal] = await once(child, 'close');
    assert.equal(code, 0, `claim native-error child exits cleanly (signal ${signal}); stderr: ${stderr}`);
    const claimReport = JSON.parse(stdout);
    assert.equal(claimReport.unexpectedlyClaimed, undefined, 'the actual claim() must not convert non-EEXIST into a lost claim');
    assert.equal(claimReport.code, 'EISDIR', `claim must rethrow the native writeFile error: ${claimReport.message}`);

    const durable = createPendingHealthVerdictStore({ dataRoot });
    const claimDirectory = join(dataRoot, 'pending-health-verdicts', `${JOB_B}.claim`);
    await mkdir(claimDirectory, { recursive: true });
    await assert.rejects(
      () => durable.releaseClaim({ jobId: JOB_B, claimId: null }),
      (error) => error && error.code === 'ERR_FS_EISDIR',
      'force-release reaches the real rm() and rethrows its non-ENOENT directory error',
    );
  });
});

test('health sweep: the volatile claim API rejects the same malformed claim inputs as the durable store', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const stores = [
      ['durable', createPendingHealthVerdictStore({ dataRoot })],
      ['volatile', createVolatilePendingHealthVerdictStore()],
    ];
    for (const [name, store] of stores) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.claim({ jobId: 'not-a-sha', nowMs: START }), TypeError, `${name} rejects malformed jobId`);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.claim({ jobId: JOB_A, nowMs: START + 0.5 }), TypeError, `${name} rejects non-safe-integer nowMs`);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.claim({ jobId: JOB_A, nowMs: START, gradeAsOfMs: NaN }), TypeError, `${name} rejects invalid gradeAsOfMs`);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.recallClaim({ jobId: 'not-a-sha' }), TypeError, `${name} rejects malformed recallClaim jobId`);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.releaseClaim({ jobId: 'not-a-sha', claimId: null }), TypeError, `${name} rejects malformed releaseClaim jobId`);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.releaseClaim({ jobId: JOB_A, claimId: '' }), TypeError, `${name} rejects empty claimId`);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => store.releaseClaim({ jobId: JOB_A, claimId: undefined }), TypeError, `${name} rejects omitted claimId`);
    }
  });
});
