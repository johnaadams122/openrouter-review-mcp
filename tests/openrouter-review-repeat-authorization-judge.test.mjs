import assert from 'node:assert/strict';
import test from 'node:test';
import { createRepeatAuthorizationJudge } from '../src/local-mcp/repeat-authorization-judge.mjs';

function ollamaResponse(responseText) {
  return { ok: true, json: async () => ({ response: responseText }) };
}

function fakeFetch(handler) {
  return async (url, init) => handler(url, init);
}

function judgeFor(fetchImpl) {
  return createRepeatAuthorizationJudge({ fetchImpl, baseUrl: 'http://localhost:11434', model: 'qwen2.5:7b', timeoutMs: 5000 });
}

test('a clean "justified: true" response is reported as justified with its reasoning', async () => {
  const judge = judgeFor(fakeFetch(async () => ollamaResponse(JSON.stringify({ justified: true, reasoning: 'the first attempt timed out before completing' }))));
  const verdict = await judge.judge({ reason: 'first attempt never finished', profile: 'impl_review_v1', priorLeaseCount: 1 });
  assert.deepEqual(verdict, { ok: true, justified: true, reasoning: 'the first attempt timed out before completing' });
});

test('a clean "justified: false" response is reported as not justified with its reasoning', async () => {
  const judge = judgeFor(fakeFetch(async () => ollamaResponse(JSON.stringify({ justified: false, reasoning: 'this looks like a retry loop, not a real necessity' }))));
  const verdict = await judge.judge({ reason: 'just try again', profile: 'impl_review_v1', priorLeaseCount: 4 });
  assert.deepEqual(verdict, { ok: true, justified: false, reasoning: 'this looks like a retry loop, not a real necessity' });
});

// Fail-closed: an unreachable/malformed/timed-out judge must report ok:false, never an implicit
// pass. The caller (review-engine.mjs) is responsible for treating ok:false as NOT justified --
// this module's own job is only to never claim ok:true when it cannot actually answer.
test('a network failure reports ok:false, justified:null -- never an implicit justification', async () => {
  const judge = judgeFor(fakeFetch(async () => { throw new Error('ECONNREFUSED'); }));
  const verdict = await judge.judge({ reason: 'x', profile: 'impl_review_v1', priorLeaseCount: 1 });
  assert.deepEqual(verdict, { ok: false, justified: null, reasoning: null });
});

test('a non-OK HTTP response reports ok:false', async () => {
  const judge = judgeFor(fakeFetch(async () => ({ ok: false, json: async () => ({}) })));
  const verdict = await judge.judge({ reason: 'x', profile: 'impl_review_v1', priorLeaseCount: 1 });
  assert.deepEqual(verdict, { ok: false, justified: null, reasoning: null });
});

test('a response body that is not valid JSON reports ok:false', async () => {
  const judge = judgeFor(fakeFetch(async () => ollamaResponse('sure, that seems fine to me')));
  const verdict = await judge.judge({ reason: 'x', profile: 'impl_review_v1', priorLeaseCount: 1 });
  assert.deepEqual(verdict, { ok: false, justified: null, reasoning: null });
});

test('a response whose "justified" field is missing or not a boolean reports ok:false, not a guessed default', async () => {
  const judge = judgeFor(fakeFetch(async () => ollamaResponse(JSON.stringify({ reasoning: 'yes I think so' }))));
  const verdict = await judge.judge({ reason: 'x', profile: 'impl_review_v1', priorLeaseCount: 1 });
  assert.equal(verdict.ok, false);
});

test('a response missing "reasoning" still reports the verdict, with a placeholder reasoning string', async () => {
  const judge = judgeFor(fakeFetch(async () => ollamaResponse(JSON.stringify({ justified: true }))));
  const verdict = await judge.judge({ reason: 'x', profile: 'impl_review_v1', priorLeaseCount: 1 });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.justified, true);
  assert.equal(typeof verdict.reasoning, 'string');
  assert.ok(verdict.reasoning.length > 0);
});

test('the prompt carries the reason, the profile, and the prior lease count so the judge has real context', async () => {
  let capturedBody;
  const judge = judgeFor(fakeFetch(async (url, init) => { capturedBody = JSON.parse(init.body); return ollamaResponse(JSON.stringify({ justified: false, reasoning: 'no' })); }));
  await judge.judge({ reason: 'the reviewer crashed mid-run', profile: 'impl_review_free_v1', priorLeaseCount: 2 });
  assert.match(capturedBody.prompt, /the reviewer crashed mid-run/);
  assert.match(capturedBody.prompt, /impl_review_free_v1/);
  assert.match(capturedBody.prompt, /2/);
  assert.equal(capturedBody.model, 'qwen2.5:7b');
  assert.equal(capturedBody.stream, false);
});

test('construction requires every collaborator', () => {
  assert.throws(() => createRepeatAuthorizationJudge({ baseUrl: 'http://localhost:11434', model: 'x', timeoutMs: 1000 }), /fetchImpl/);
  assert.throws(() => createRepeatAuthorizationJudge({ fetchImpl: fakeFetch(async () => {}), model: 'x', timeoutMs: 1000 }), /baseUrl/);
  assert.throws(() => createRepeatAuthorizationJudge({ fetchImpl: fakeFetch(async () => {}), baseUrl: 'http://x', timeoutMs: 1000 }), /model/);
  assert.throws(() => createRepeatAuthorizationJudge({ fetchImpl: fakeFetch(async () => {}), baseUrl: 'http://x', model: 'x' }), /timeoutMs/);
});

test('judge() rejects a missing or empty reason, profile, or a malformed priorLeaseCount', async () => {
  const judge = judgeFor(fakeFetch(async () => ollamaResponse(JSON.stringify({ justified: true, reasoning: 'ok' }))));
  await assert.rejects(() => judge.judge({ reason: '', profile: 'p', priorLeaseCount: 1 }), /reason/);
  await assert.rejects(() => judge.judge({ reason: 'r', profile: '', priorLeaseCount: 1 }), /profile/);
  await assert.rejects(() => judge.judge({ reason: 'r', profile: 'p', priorLeaseCount: -1 }), /priorLeaseCount/);
  await assert.rejects(() => judge.judge({ reason: 'r', profile: 'p', priorLeaseCount: 1.5 }), /priorLeaseCount/);
});
