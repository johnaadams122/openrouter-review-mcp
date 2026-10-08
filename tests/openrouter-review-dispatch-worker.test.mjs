import assert from 'node:assert/strict';
import test from 'node:test';
import { createFakeDispatchWorker } from './fixtures/openrouter-review/fake-dispatch-worker.mjs';

// Each test builds its own fake worker instance.
test('dispatch adapter never places an API key in arguments, request files, or result objects', async () => {
  const fakeDispatch = createFakeDispatchWorker();
  const result = await fakeDispatch.dispatch({ requestBytes: Buffer.from('{}'), jobId: 'j1' });
  assert.deepEqual(Object.keys(result), ['kind', 'envelopeJsonText']);
  assert.doesNotMatch(JSON.stringify(fakeDispatch.calls), /sk-or-v1-/i);
});

test('a successful dispatch returns raw response bytes as a secret-free envelope', async () => {
  const fakeDispatch = createFakeDispatchWorker({
    responses: [{ httpStatus: 200, bodyText: '{"id":"gen_fake","choices":[]}' }],
  });
  const result = await fakeDispatch.dispatch({ requestBytes: Buffer.from('{"model":"fake"}'), jobId: 'job-success' });
  assert.equal(result.kind, 'RESPONSE');
  const envelope = JSON.parse(result.envelopeJsonText);
  assert.deepEqual(Object.keys(envelope).sort(), ['bodyBase64', 'httpStatus']);
  assert.equal(envelope.httpStatus, 200);
  assert.equal(Buffer.from(envelope.bodyBase64, 'base64').toString('utf8'), '{"id":"gen_fake","choices":[]}');
  assert.equal(fakeDispatch.calls.length, 1);
  assert.deepEqual(fakeDispatch.calls[0], { jobId: 'job-success', requestByteLength: 16 });
});

test('a failed dispatch returns typed secret-free failure metadata, never provider or exception text', async () => {
  const fakeDispatch = createFakeDispatchWorker({
    responses: [{ kind: 'FAILURE', failureKind: 'TIMEOUT', message: 'request exceeded its deadline' }],
  });
  const result = await fakeDispatch.dispatch({ requestBytes: Buffer.from('{"model":"fake"}'), jobId: 'job-timeout' });
  assert.equal(result.kind, 'FAILURE');
  const envelope = JSON.parse(result.envelopeJsonText);
  assert.deepEqual(Object.keys(envelope).sort(), ['failureKind', 'message']);
  assert.equal(envelope.failureKind, 'TIMEOUT');
  assert.doesNotMatch(JSON.stringify(envelope), /sk-or-v1-/i);
});

test('the fake worker rejects a request that is missing requestBytes or jobId', async () => {
  const fakeDispatch = createFakeDispatchWorker();
  await assert.rejects(() => fakeDispatch.dispatch({ jobId: 'no-bytes' }), /requestBytes/);
  await assert.rejects(() => fakeDispatch.dispatch({ requestBytes: Buffer.from('{}') }), /jobId/);
  assert.equal(fakeDispatch.calls.length, 0);
});

test('each dispatch worker instance keeps its own independent call log', async () => {
  const first = createFakeDispatchWorker();
  const second = createFakeDispatchWorker();
  await first.dispatch({ requestBytes: Buffer.from('{}'), jobId: 'first-only' });
  assert.equal(first.calls.length, 1);
  assert.equal(second.calls.length, 0);
});
