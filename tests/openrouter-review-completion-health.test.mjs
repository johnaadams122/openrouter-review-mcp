import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import * as reviewEngine from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

// This file deliberately imports review-engine as a namespace, so a missing helper export fails
// as a clear assertion rather than as a module-load error. Every store below is a real temporary
// store; no credentials or network adapters.

const START = Date.parse('2026-09-19T12:00:00.000Z');
const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');

function passingOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

function completionBody(options = {}) {
  const {
    nativeFinishReason,
    content = JSON.stringify({ verdict: 'pass', findings: [] }),
  } = options;
  // Defaulting only when the option is absent lets a test pass a truly missing normalized field.
  const finishReason = Object.hasOwn(options, 'finishReason') ? options.finishReason : 'stop';
  const choice = { message: { content } };
  if (finishReason !== undefined) choice.finish_reason = finishReason;
  if (nativeFinishReason !== undefined) choice.native_finish_reason = nativeFinishReason;
  return { provider: 'xAI', usage: { cost: 0.02 }, choices: [choice] };
}

function responseOutcome(body) {
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body), 'utf8').toString('base64') }),
  });
}

async function writeCapture(dataRoot, jobId, body) {
  await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
  await writeFile(dispatchOutcomePath({ dataRoot, jobId }), JSON.stringify(responseOutcome(body)), 'utf8');
}

async function directoryBytes(path) {
  try {
    const names = (await readdir(path)).sort();
    return Promise.all(names.map(async (name) => ({ name, text: await readFile(join(path, name), 'utf8') })));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

async function withDeferredHealth(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-completion-health-'));
  const clock = () => START;
  const realLeaseStore = createLeaseStore({ dataRoot, clock });
  const ownerLock = realLeaseStore.createUnarmedOwnerHandle();
  const realResultStore = createResultStore({ dataRoot });
  const realMappingStore = createScrubMappingStore({ dataRoot });
  const resultWrites = [];
  const mappingWrites = [];
  const resultStore = Object.freeze({
    ...realResultStore,
    async record(input) { resultWrites.push(input); return realResultStore.record(input); },
  });
  const scrubMappingStore = Object.freeze({
    ...realMappingStore,
    async record(input) { mappingWrites.push(['record', input]); return realMappingStore.record(input); },
    async deleteMapping(input) { mappingWrites.push(['delete', input]); return realMappingStore.deleteMapping(input); },
  });
  const pendingHealthVerdictStore = createPendingHealthVerdictStore({ dataRoot });
  const dispatchHealthStore = createDispatchHealthStore({ dataRoot });
  const engine = reviewEngine.createReviewEngine({
    leaseStore: realLeaseStore,
    ownerLock,
    approvalAdapter: { async authorize() { throw new Error('not used by deferred-health tests'); } },
    dispatchAdapter: { async dispatch() { throw new Error('not used by deferred-health tests'); } },
    resultStore,
    preflightContextStore: createPreflightContextStore({ dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot }),
    scrubEngine: createScrubEngine({ identityList: [], ollamaClient: passingOllama() }),
    scrubMappingStore,
    clock,
    sourcePolicy: { allowedRoots: [allowedRoot], maxSourceBytes: 10_000 },
    preflightPolicy: { maxRequestBytes: 200_000 },
    preflightTtlMs: 10 * 60 * 1000,
    installationHardMaximumUsd: 10,
    repeatAuthorizationJudge: { async judge() { throw new Error('not used by deferred-health tests'); } },
    dispatchHealthStore,
    pendingHealthVerdictStore,
  });
  try {
    await run({
      dataRoot, engine, ownerLock, pendingHealthVerdictStore, dispatchHealthStore,
      resultWrites, mappingWrites,
    });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

function assertCompletionHelper() {
  assert.equal(
    typeof reviewEngine.isAcceptedReviewCompletion,
    'function',
    'review-engine must export isAcceptedReviewCompletion(body)',
  );
  return reviewEngine.isAcceptedReviewCompletion;
}

test('isAcceptedReviewCompletion accepts only an exact normalized first-choice stop', () => {
  const accepts = assertCompletionHelper();
  for (const nativeFinishReason of [undefined, null, 'STOP', 'end_turn', 'provider-specific']) {
    assert.equal(accepts(completionBody({ nativeFinishReason })), true, `native metadata ${String(nativeFinishReason)} must not invalidate normalized stop`);
  }
  assert.equal(accepts({ choices: [{ finish_reason: 'stop' }, { finish_reason: 'length' }] }), true, 'only the existing first choice controls completion');
  assert.equal(accepts({ choices: [{ finish_reason: 'length' }, { finish_reason: 'stop' }] }), false, 'a later stop must not rescue an incomplete first choice');
});

test('isAcceptedReviewCompletion refuses every non-exact, missing, or malformed normalized reason', () => {
  const accepts = assertCompletionHelper();
  for (const reason of ['length', 'error', 'tool_calls', 'content_filter', undefined, null, '', 'unknown', 0, true, {}, [], 'STOP', 'Stop', ' stop', 'stop ']) {
    assert.equal(accepts(completionBody({ finishReason: reason, nativeFinishReason: 'STOP' })), false, `must refuse ${JSON.stringify(reason)}`);
  }
  for (const finishReason of [undefined, 'length', 'error']) {
    for (const nativeFinishReason of ['stop', 'end_turn', 'STOP']) {
      assert.equal(
        accepts(completionBody({ finishReason, nativeFinishReason })),
        false,
        `native ${nativeFinishReason} must not rescue normalized ${String(finishReason)}`,
      );
    }
  }
  for (const body of [{}, { choices: [] }, { choices: [null] }, { choices: [{ finish_reason: 'length', native_finish_reason: 'stop' }] }]) {
    assert.equal(accepts(body), false, 'missing/invalid normalized first-choice completion must not be rescued by shape or native metadata');
  }
});

async function seedDuePendingCapture({ dataRoot, pendingHealthVerdictStore, jobId, body }) {
  await pendingHealthVerdictStore.record({
    jobId,
    reviewerId: 'grok',
    reservationUsd: 0.5,
    notBeforeMs: START - 1_000,
    recordedAtMs: START - 10_000,
  });
  await writeCapture(dataRoot, jobId, body);
}

test('deferred health: normalized stop removes its pending verdict without resetting an unrelated failure or touching review stores', async () => {
  await withDeferredHealth(async ({ dataRoot, engine, ownerLock, pendingHealthVerdictStore, dispatchHealthStore, resultWrites, mappingWrites }) => {
    const jobId = 'a'.repeat(64);
    await seedDuePendingCapture({ dataRoot, pendingHealthVerdictStore, jobId, body: completionBody() });
    await dispatchHealthStore.recordOutcome({ succeeded: false, alertThreshold: 3 });
    const before = {
      ledger: await directoryBytes(join(dataRoot, 'ledger')),
      results: await directoryBytes(join(dataRoot, 'dispatch-results')),
      mappings: await directoryBytes(join(dataRoot, 'scrub-mappings')),
    };

    await engine.resolvePendingHealthVerdicts();

    assert.equal(ownerLock.state, 'unarmed', 'the direct deferred-health sweep must never arm a real owner handle');
    assert.equal(await pendingHealthVerdictStore.recall({ jobId }), null);
    assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, 'a delayed completed success must not reset an unrelated failure');
    assert.deepEqual(resultWrites, []);
    assert.deepEqual(mappingWrites, []);
    assert.deepEqual(await directoryBytes(join(dataRoot, 'ledger')), before.ledger);
    assert.deepEqual(await directoryBytes(join(dataRoot, 'dispatch-results')), before.results);
    assert.deepEqual(await directoryBytes(join(dataRoot, 'scrub-mappings')), before.mappings);
  });
});

test('deferred health: every refused normalized reason removes once and increments failure once without review-store mutation', async (t) => {
  const cases = [
    ['length', 'length'], ['error', 'error'], ['tool_calls', 'tool_calls'], ['content_filter', 'content_filter'],
    ['missing', undefined], ['null', null], ['empty', ''], ['unknown', 'other'], ['different-case', 'STOP'], ['padded', ' stop'],
  ];
  for (const [index, [label, finishReason]] of cases.entries()) {
    await t.test(label, async () => {
      await withDeferredHealth(async ({ dataRoot, engine, ownerLock, pendingHealthVerdictStore, dispatchHealthStore, resultWrites, mappingWrites }) => {
        const jobId = 'bcdef0123456789a'[index].repeat(64);
        const body = completionBody({ finishReason, nativeFinishReason: finishReason === 'length' ? 'stop' : 'STOP' });
        if (label === 'missing') {
          assert.equal(Object.hasOwn(body.choices[0], 'finish_reason'), false, 'fixture precondition: missing means absent, never an implicit stop');
        }
        await seedDuePendingCapture({
          dataRoot, pendingHealthVerdictStore, jobId,
          body,
        });
        const before = {
          ledger: await directoryBytes(join(dataRoot, 'ledger')),
          results: await directoryBytes(join(dataRoot, 'dispatch-results')),
          mappings: await directoryBytes(join(dataRoot, 'scrub-mappings')),
        };

        await engine.resolvePendingHealthVerdicts();
        assert.equal(ownerLock.state, 'unarmed');
        assert.equal(await pendingHealthVerdictStore.recall({ jobId }), null, `${label}: due pending verdict is resolved`);
        assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, `${label}: refusal counts exactly one health failure`);
        await engine.resolvePendingHealthVerdicts();
        assert.equal((await dispatchHealthStore.recall()).consecutiveFailures, 1, `${label}: removed record cannot be counted twice`);
        assert.deepEqual(resultWrites, []);
        assert.deepEqual(mappingWrites, []);
        assert.deepEqual(await directoryBytes(join(dataRoot, 'ledger')), before.ledger);
        assert.deepEqual(await directoryBytes(join(dataRoot, 'dispatch-results')), before.results);
        assert.deepEqual(await directoryBytes(join(dataRoot, 'scrub-mappings')), before.mappings);
      });
    });
  }
});
