import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

const START = Date.parse('2026-09-19T00:00:00.000Z');
const sourcePolicy = Object.freeze({ allowedRoots: [resolve('tests/fixtures/openrouter-review/allowed')], maxSourceBytes: 10_000 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 200_000 });
const findings = Object.freeze([{ severity: 'minor', section: 'completion', root_cause: 'synthetic', affected_behavior: 'completion', consequence: 'validation', evidence: ['synthetic'] }]);

function jobId(leaseId, reviewerId, contract) { return createHash('sha256').update(`openrouter_review_job_v1:${leaseId}:${reviewerId}:${contract}`, 'utf8').digest('hex'); }
function ollama() { return { async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; }, async checkReidentifiable() { return { ok: true, flagged: false }; } }; }
function body(options = {}) {
  const { cost = 0.02, provider = 'xAI', content = JSON.stringify({ verdict: 'pass', findings }), native } = options;
  const reason = Object.hasOwn(options, 'reason') ? options.reason : 'stop';
  const choice = { message: { content } };
  if (reason !== undefined) choice.finish_reason = reason;
  if (native !== undefined) choice.native_finish_reason = native;
  return { provider, choices: [choice], usage: { cost } };
}
function response(options) { return { kind: 'RESPONSE', envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(body(options)), 'utf8').toString('base64') }) }; }
function responseRaw(value) { return { kind: 'RESPONSE', envelopeJsonText: JSON.stringify({ httpStatus: 200, bodyBase64: Buffer.from(JSON.stringify(value), 'utf8').toString('base64') }) }; }
async function bytes(root) { const d = join(root, 'ledger'); return Promise.all((await readdir(d)).filter((x) => x.endsWith('.json')).sort().map(async (x) => [x, await readFile(join(d, x), 'utf8')])); }
async function observed(action) { try { const value = await action(); return { kind: 'returned', state: value?.state, code: value?.error?.code }; } catch (error) { return { kind: 'rejected', code: error?.code }; } }
async function captureStderr(action) {
  const originalWrite = process.stderr.write;
  let stderr = '';
  process.stderr.write = (chunk) => { stderr += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk); return true; };
  try { return { value: await action(), stderr }; }
  finally { process.stderr.write = originalWrite; }
}

async function withFixture(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-completion-reason-'));
  let now = START;
  const clock = () => now;
  const realLeaseStore = createLeaseStore({ dataRoot, clock });
  const realResultStore = createResultStore({ dataRoot });
  const dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot });
  const scrubMappingStore = createScrubMappingStore({ dataRoot });
  const healthReal = createDispatchHealthStore({ dataRoot });
  const handles = new Set();
  async function writeCapture(id, value) { await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true }); await writeFile(dispatchOutcomePath({ dataRoot, jobId: id }), JSON.stringify(value), 'utf8'); }
  async function makeEngine({ dispatch = { async dispatch() { throw new Error('unexpected dispatch'); } } } = {}) {
    const ownerLock = realLeaseStore.createUnarmedOwnerHandle(); handles.add(ownerLock);
    const calls = { dispatch: 0, consume: 0, reconcile: 0, close: 0, result: 0, health: [] };
    const leaseStore = { ...realLeaseStore,
      async consume(...a) { calls.consume += 1; return realLeaseStore.consume(...a); },
      async reconcile(...a) { calls.reconcile += 1; return realLeaseStore.reconcile(...a); },
      async close(...a) { calls.close += 1; return realLeaseStore.close(...a); },
    };
    const resultStore = { ...realResultStore, async record(a) { calls.result += 1; return realResultStore.record(a); } };
    const health = { ...healthReal, async recordOutcome(a) { calls.health.push(a.succeeded); return healthReal.recordOutcome(a); } };
    const engine = createReviewEngine({ leaseStore, ownerLock,
      approvalAdapter: { async authorize() { return { outcome: 'APPROVED', nonce: 'test-nonce' }; } },
      dispatchAdapter: { async dispatch(a) { calls.dispatch += 1; return dispatch.dispatch(a); } }, resultStore,
      preflightContextStore: createPreflightContextStore({ dataRoot }), dispatchOutcomeStore,
      scrubEngine: createScrubEngine({ identityList: [], ollamaClient: ollama() }), scrubMappingStore,
      dispatchHealthStore: health, alertStore: { async record() {}, async list() { return []; } },
      repeatAuthorizationJudge: { async judge() { throw new Error('unexpected repeat judge'); } }, clock,
      sourcePolicy, preflightPolicy, preflightTtlMs: 600_000, installationHardMaximumUsd: 10,
    });
    return { engine, ownerLock, calls };
  }
  async function authorize(engine, sourceText = 'completion source') {
    const preflight = await engine.preflight({ source_text: sourceText, profile: 'final_verification_v1', changeKinds: [], reviewContext: 'completion fixture' });
    const auth = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 1 });
    return { ...auth, preflight, sourceText };
  }
  async function seedReserved({ reason, cost = 0.02, sourceText = 'completion source', reconciled = false }) {
    const seed = await makeEngine(); const auth = await authorize(seed.engine, sourceText); const reviewerId = 'grok'; const id = jobId(auth.leaseId, reviewerId, auth.preflight.reviewContractSha256); const item = auth.preflight.itemMaxima.find((x) => x.itemId === 'item-grok');
    await seed.ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 10, caps: { installationHardMaximumUsd: 10 } });
    await realLeaseStore.consume(auth.leaseId, auth.preflight.reviewContractSha256, { reservationUsd: item.maxUsd, jobId: id, reviewerId, acquisitionId: seed.ownerLock.acquisitionId });
    if (reconciled) await realLeaseStore.reconcile(id, { costUsd: cost, costKind: 'KNOWN', acquisitionId: seed.ownerLock.acquisitionId });
    await writeCapture(id, response({ reason, cost })); await seed.ownerLock.release({ final: false });
    return { ...auth, id, item };
  }
  try { await run({ dataRoot, realLeaseStore, realResultStore, scrubMappingStore, makeEngine, authorize, seedReserved, advance: (ms) => { now += ms; }, bytes: () => bytes(dataRoot) }); }
  finally { await Promise.all([...handles].map((h) => h.release({ final: true }).catch(() => {}))); await rm(dataRoot, { recursive: true, force: true }); }
}

for (const vector of [
  { label: 'stop', reason: 'stop' },
  { label: 'length', reason: 'length' },
  { label: 'error', reason: 'error' },
  { label: 'missing', reason: undefined },
  { label: 'unknown', reason: 'UNKNOWN_REASON_SENTINEL' },
  { label: 'complete-invalid-advisory', reason: 'stop', content: JSON.stringify({ verdict: 'invalid', findings: [] }) },
]) test(`fresh ${vector.label} completion preserves known cost and lifecycle`, async () => {
  await withFixture(async ({ makeEngine, authorize, realLeaseStore, realResultStore }) => {
    const worker = await makeEngine({ dispatch: { async dispatch() { return response({ reason: vector.reason, content: vector.content, native: 'NATIVE_REASON_SENTINEL' }); } } });
    const auth = await authorize(worker.engine);
    const captured = await captureStderr(() => worker.engine.review({ leaseId: auth.leaseId, preflightId: auth.preflight.preflightId, source_text: auth.sourceText }));
    const result = captured.value;
    const id = jobId(auth.leaseId, 'grok', auth.preflight.reviewContractSha256); const job = await realLeaseStore.getJob(id);
    if (vector.label === 'stop') {
      assert.deepEqual({ state: result.state, costUsd: job.costUsd, costKind: job.costKind, durable: await realResultStore.recall({ jobId: id }) !== null, health: worker.calls.health }, { state: 'PASSED', costUsd: 0.02, costKind: 'KNOWN', durable: true, health: [true] });
      return;
    }
    const durable = await realResultStore.recall({ jobId: id });
    const retry = await observed(() => worker.engine.review({ leaseId: auth.leaseId, preflightId: auth.preflight.preflightId, source_text: auth.sourceText }));
    await observed(() => worker.engine.result({ leaseId: auth.leaseId }));
    await observed(() => worker.engine.recoverOrphanedLeases());
    const snapshot = { code: result.error?.code, costUsd: job.costUsd, costKind: job.costKind, haltReason: job.haltReason, durable: durable !== null, calls: worker.calls, retry, leakedSentinel: JSON.stringify({ result, job }).includes('UNKNOWN_REASON_SENTINEL') || JSON.stringify({ result, job }).includes('NATIVE_REASON_SENTINEL') || captured.stderr.includes('UNKNOWN_REASON_SENTINEL') || captured.stderr.includes('NATIVE_REASON_SENTINEL') };
    assert.deepEqual(snapshot, { code: 'STRICT_OUTPUT_INVALID', costUsd: 0.02, costKind: 'KNOWN', haltReason: 'STRICT_OUTPUT_INVALID', durable: false, calls: { dispatch: 1, consume: 1, reconcile: 1, close: 1, result: 0, health: [false] }, retry: { kind: 'rejected', code: 'LEASE_CLOSED' }, leakedSentinel: false });
  });
});

for (const vector of [
  { label: 'missing-cost', outcome: responseRaw({ provider: 'xAI', choices: [{ finish_reason: 'length', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: {} }), code: 'UNKNOWN_COST', kind: 'UNKNOWN_WORST_CASE_CHARGED', max: true },
  { label: 'malformed-cost', outcome: responseRaw({ provider: 'xAI', choices: [{ finish_reason: 'length', message: { content: JSON.stringify({ verdict: 'pass', findings }) } }], usage: { cost: '0.02' } }), code: 'UNKNOWN_COST', kind: 'UNKNOWN_WORST_CASE_CHARGED', max: true },
  // A finite cost above the reservation is recorded as a KNOWN cost (and flagged), not UNKNOWN_COST,
  // so completion validation decides this vector's halt.
  { label: 'over-bound-cost', outcome: response({ reason: 'error', cost: 99 }), code: 'STRICT_OUTPUT_INVALID', kind: 'KNOWN', cost: 99, halt: 'STRICT_OUTPUT_INVALID' },
  { label: 'wrong-provider', outcome: response({ reason: 'length', provider: 'Not-xAI' }), code: 'PROVIDER_MISMATCH', kind: 'KNOWN', cost: 0.02, halt: 'PROVIDER_MISMATCH' },
  { label: 'zero-known-bad-completion', outcome: response({ reason: 'length', cost: 0 }), code: 'STRICT_OUTPUT_INVALID', kind: 'KNOWN', cost: 0, halt: 'STRICT_OUTPUT_INVALID' },
]) test(`precedence: ${vector.label} remains ahead of completion validation`, async () => {
  await withFixture(async ({ makeEngine, authorize, realLeaseStore }) => {
    const worker = await makeEngine({ dispatch: { async dispatch() { return vector.outcome; } } }); const auth = await authorize(worker.engine);
    const result = await worker.engine.review({ leaseId: auth.leaseId, preflightId: auth.preflight.preflightId, source_text: auth.sourceText }); const id = jobId(auth.leaseId, 'grok', auth.preflight.reviewContractSha256); const job = await realLeaseStore.getJob(id);
    const maxUsd = auth.preflight.itemMaxima.find((item) => item.itemId === 'item-grok').maxUsd;
    assert.deepEqual({ code: result.error?.code, costUsd: job.costUsd, costKind: job.costKind, haltReason: job.haltReason, health: worker.calls.health }, { code: vector.code, costUsd: vector.max ? maxUsd : vector.cost, costKind: vector.kind, haltReason: vector.halt, health: [false] });
  });
});

for (const vector of [
  { label: 'stop', reason: 'stop' },
  { label: 'length', reason: 'length' },
  { label: 'error', reason: 'error' },
  { label: 'missing', reason: undefined },
  { label: 'unknown', reason: 'UNKNOWN_REASON_SENTINEL' },
]) test(`RESERVED ${vector.label} capture replays without redispatch`, async () => {
  await withFixture(async ({ makeEngine, seedReserved, realLeaseStore, realResultStore }) => {
    const seeded = await seedReserved({ reason: vector.reason }); const worker = await makeEngine();
    const result = await worker.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: seeded.sourceText }); const job = await realLeaseStore.getJob(seeded.id);
    if (vector.label === 'stop') {
      assert.deepEqual({ state: result.state, costUsd: job.costUsd, costKind: job.costKind, durable: await realResultStore.recall({ jobId: seeded.id }) !== null, calls: worker.calls }, { state: 'PASSED', costUsd: 0.02, costKind: 'KNOWN', durable: true, calls: { dispatch: 0, consume: 0, reconcile: 1, close: 0, result: 1, health: [true] } });
      return;
    }
    const durable = await realResultStore.recall({ jobId: seeded.id });
    const retry = await observed(() => worker.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: seeded.sourceText }));
    await observed(() => worker.engine.result({ leaseId: seeded.leaseId }));
    await observed(() => worker.engine.recoverOrphanedLeases());
    assert.deepEqual({ code: result.error?.code, costUsd: job.costUsd, costKind: job.costKind, haltReason: job.haltReason, durable: durable !== null, calls: worker.calls, retry }, { code: 'STRICT_OUTPUT_INVALID', costUsd: 0.02, costKind: 'KNOWN', haltReason: 'STRICT_OUTPUT_INVALID', durable: false, calls: { dispatch: 0, consume: 0, reconcile: 1, close: 1, result: 0, health: [false] }, retry: { kind: 'rejected', code: 'LEASE_CLOSED' } });
  });
});

test('stale RESERVED zero-cost error halts once without recounting', async () => {
  await withFixture(async ({ makeEngine, seedReserved, advance, realLeaseStore }) => {
    const seeded = await seedReserved({ reason: 'error', cost: 0 }); const reservedLease = await realLeaseStore.getLease(seeded.leaseId);
    advance((Date.parse(reservedLease.expiresAt) - START) + 2 * 60_000 + 1_000); const worker = await makeEngine();
    await worker.engine.recoverOrphanedLeases(); const job = await realLeaseStore.getJob(seeded.id);
    await observed(() => worker.engine.recoverOrphanedLeases()); await observed(() => worker.engine.result({ leaseId: seeded.leaseId }));
    assert.deepEqual({ costUsd: job.costUsd, costKind: job.costKind, haltReason: job.haltReason, calls: worker.calls }, { costUsd: 0, costKind: 'KNOWN', haltReason: 'STRICT_OUTPUT_INVALID', calls: { dispatch: 0, consume: 0, reconcile: 1, close: 1, result: 0, health: [false] } });
  });
});

for (const vector of [
  { label: 'length', reason: 'length', cost: 0.02 },
  { label: 'error', reason: 'error', cost: 0.02 },
  { label: 'missing', reason: undefined, cost: 0.02 },
  { label: 'unknown', reason: 'UNKNOWN_REASON_SENTINEL', cost: 0.02 },
  { label: 'zero-error', reason: 'error', cost: 0 },
]) test(`already-reconciled ${vector.label} capture remains contentless`, async () => {
  await withFixture(async ({ makeEngine, seedReserved, authorize, realLeaseStore, realResultStore, bytes: ledgerBytes }) => {
    const seeded = await seedReserved({ reason: vector.reason, cost: vector.cost, reconciled: true, sourceText: `reconciled ${vector.label}` }); const before = await ledgerBytes();
    const reader = await makeEngine(); const result = await reader.engine.result({ leaseId: seeded.leaseId }); const afterReader = await ledgerBytes();
    assert.deepEqual({ advisory: result.reviewers.grok.advisory, bytesUnchanged: JSON.stringify(afterReader) === JSON.stringify(before), durable: await realResultStore.recall({ jobId: seeded.id }), calls: reader.calls }, { advisory: undefined, bytesUnchanged: true, durable: null, calls: { dispatch: 0, consume: 0, reconcile: 0, close: 0, result: 0, health: [] } });
    const same = await makeEngine(); const sameResult = await same.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: seeded.sourceText });
    const settled = await realLeaseStore.getJob(seeded.id);
    assert.deepEqual({ state: settled.state, costUsd: settled.costUsd, costKind: settled.costKind, haltReason: settled.haltReason, same: { code: sameResult.error?.code, dispatch: same.calls.dispatch, consume: same.calls.consume, reconcile: same.calls.reconcile, result: same.calls.result, health: same.calls.health } }, { state: 'RECONCILED', costUsd: vector.cost, costKind: 'KNOWN', haltReason: undefined, same: { code: 'CONTENT_LOST', dispatch: 0, consume: 0, reconcile: 0, result: 0, health: [] } });
    const next = await makeEngine(); const nextAuth = await authorize(next.engine, seeded.sourceText);
    const cross = await next.engine.review({ leaseId: nextAuth.leaseId, preflightId: nextAuth.preflight.preflightId, source_text: seeded.sourceText });
    const settledAfterCross = await realLeaseStore.getJob(seeded.id);
    assert.deepEqual({ code: cross.error?.code, calls: { dispatch: next.calls.dispatch, consume: next.calls.consume, reconcile: next.calls.reconcile, result: next.calls.result, health: next.calls.health }, settled: { state: settledAfterCross.state, costUsd: settledAfterCross.costUsd, costKind: settledAfterCross.costKind, haltReason: settledAfterCross.haltReason } }, { code: 'CONTENT_LOST', calls: { dispatch: 0, consume: 0, reconcile: 0, result: 0, health: [] }, settled: { state: 'RECONCILED', costUsd: vector.cost, costKind: 'KNOWN', haltReason: undefined } });
  });
});

test('already-reconciled stop capture can materialize only in armed review and cross-lease reuse', async () => {
  await withFixture(async ({ makeEngine, seedReserved, authorize, realResultStore, bytes: ledgerBytes }) => {
    const seeded = await seedReserved({ reason: 'stop', reconciled: true, sourceText: 'reconciled stop' }); const before = await ledgerBytes();
    const reader = await makeEngine(); const ownerless = await reader.engine.result({ leaseId: seeded.leaseId }); const afterReader = await ledgerBytes();
    assert.deepEqual({ advisory: ownerless.reviewers.grok.advisory?.verdict, bytesUnchanged: JSON.stringify(afterReader) === JSON.stringify(before), durable: await realResultStore.recall({ jobId: seeded.id }), calls: reader.calls }, { advisory: 'pass', bytesUnchanged: true, durable: null, calls: { dispatch: 0, consume: 0, reconcile: 0, close: 0, result: 0, health: [] } });
    const same = await makeEngine(); const sameResult = await same.engine.review({ leaseId: seeded.leaseId, preflightId: seeded.preflight.preflightId, source_text: seeded.sourceText });
    assert.deepEqual({ state: sameResult.state, durable: await realResultStore.recall({ jobId: seeded.id }) !== null, calls: same.calls }, { state: 'PASSED', durable: true, calls: { dispatch: 0, consume: 0, reconcile: 0, close: 0, result: 1, health: [] } });
    const next = await makeEngine(); const nextAuth = await authorize(next.engine, seeded.sourceText); const cross = await next.engine.review({ leaseId: nextAuth.leaseId, preflightId: nextAuth.preflight.preflightId, source_text: seeded.sourceText });
    assert.deepEqual({ state: cross.state, calls: next.calls }, { state: 'PASSED', calls: { dispatch: 0, consume: 0, reconcile: 0, close: 0, result: 0, health: [] } });
  });
});

test('a new authorized lease retries a known strict halt while historical durable content needs no envelope metadata', async () => {
  await withFixture(async ({ dataRoot, makeEngine, authorize }) => {
    const calls = []; const worker = await makeEngine({ dispatch: { async dispatch(request) { calls.push(request.jobId); return response({ reason: calls.length === 1 ? 'length' : 'stop' }); } } });
    const first = await authorize(worker.engine, 'retry source'); const failed = await worker.engine.review({ leaseId: first.leaseId, preflightId: first.preflight.preflightId, source_text: first.sourceText });
    const second = await authorize(worker.engine, 'retry source'); const passed = await worker.engine.review({ leaseId: second.leaseId, preflightId: second.preflight.preflightId, source_text: second.sourceText });
    const secondId = jobId(second.leaseId, 'grok', second.preflight.reviewContractSha256); await rm(dispatchOutcomePath({ dataRoot, jobId: secondId }), { force: true });
    const reader = await makeEngine(); const durable = await reader.engine.result({ leaseId: second.leaseId });
    const third = await authorize(worker.engine, 'retry source'); const reused = await worker.engine.review({ leaseId: third.leaseId, preflightId: third.preflight.preflightId, source_text: third.sourceText });
    assert.deepEqual({ first: failed.error?.code, second: passed.state, dispatches: calls.length, durable: durable.reviewers.grok.advisory?.verdict, reused: reused.state }, { first: 'STRICT_OUTPUT_INVALID', second: 'PASSED', dispatches: 2, durable: 'pass', reused: 'PASSED' });
  });
});
