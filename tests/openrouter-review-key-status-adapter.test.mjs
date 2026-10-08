import assert from 'node:assert/strict';
import test from 'node:test';
import { createKeyStatusProbeAdapter } from '../tools/openrouter-review-mcp-server.mjs';

// This adapter wraps tools/openrouter-review-key-status.ps1 (verified by source inspection in
// tests/openrouter-review-alert-store.test.mjs to never print the credential). These tests never
// spawn the real script -- `execute` is always a fake -- matching this repo's non-negotiable
// offline-tests rule: no OpenRouter request, no credentials, no network.

test('check() parses a well-formed key-status JSON line into limit/limitRemaining/limitReset', async () => {
  const execute = async () => ({ stdout: '{"limit":100,"limitRemaining":42.25,"limitReset":"monthly"}\n' });
  const adapter = createKeyStatusProbeAdapter({ execute });
  const status = await adapter.check();
  assert.deepEqual(status, { limit: 100, limitRemaining: 42.25, limitReset: 'monthly' });
});

test('check() degrades to all-null when execute() itself throws (process spawn failure)', async () => {
  const execute = async () => { throw new Error('spawn failed'); };
  const adapter = createKeyStatusProbeAdapter({ execute });
  const status = await adapter.check();
  assert.deepEqual(status, { limit: null, limitRemaining: null, limitReset: null });
});

test('check() degrades to all-null on empty stdout', async () => {
  const execute = async () => ({ stdout: '' });
  const adapter = createKeyStatusProbeAdapter({ execute });
  const status = await adapter.check();
  assert.deepEqual(status, { limit: null, limitRemaining: null, limitReset: null });
});

test('check() degrades to all-null on malformed (non-JSON) stdout', async () => {
  const execute = async () => ({ stdout: 'not json at all\n' });
  const adapter = createKeyStatusProbeAdapter({ execute });
  const status = await adapter.check();
  assert.deepEqual(status, { limit: null, limitRemaining: null, limitReset: null });
});

test('check() degrades to all-null when the parsed JSON has the wrong shape', async () => {
  const execute = async () => ({ stdout: '{"unexpected":true}\n' });
  const adapter = createKeyStatusProbeAdapter({ execute });
  const status = await adapter.check();
  assert.deepEqual(status, { limit: null, limitRemaining: null, limitReset: null });
});

test('check() passes the key-status script path to powershell.exe with -NoProfile -File, no other args', async () => {
  let capturedArgs;
  const execute = async (command, args) => {
    capturedArgs = args;
    return { stdout: '{"limit":null,"limitRemaining":null,"limitReset":null}\n' };
  };
  const adapter = createKeyStatusProbeAdapter({ execute });
  await adapter.check();
  assert.equal(capturedArgs[0], '-NoProfile');
  assert.equal(capturedArgs[1], '-File');
  assert.match(capturedArgs[2], /openrouter-review-key-status\.ps1$/);
  assert.equal(capturedArgs.length, 3, `expected exactly 3 args (no request/response file paths -- this probe is stateless), got: ${JSON.stringify(capturedArgs)}`);
});

test('check() never throws, even on a completely unexpected execute() rejection shape', async () => {
  const execute = async () => { throw 'a bare string rejection, not an Error'; }; // eslint-disable-line no-throw-literal
  const adapter = createKeyStatusProbeAdapter({ execute });
  await assert.doesNotReject(() => adapter.check());
});
