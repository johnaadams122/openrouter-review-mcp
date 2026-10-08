import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalJson } from '../src/local-mcp/shared/contracts.mjs';
import * as ollamaClientModule from '../src/local-mcp/ollama-client.mjs';

const { createOllamaClient } = ollamaClientModule;

function fakeFetch(responses) {
  let call = 0;
  return async (url, options) => {
    const response = responses[call++];
    if (response instanceof Error) throw response;
    return {
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: async () => response.body,
    };
  };
}

test('classifier contract is deeply frozen and its digest binds endpoint and static controls', () => {
  const { CLASSIFIER_CONTRACT_V1, classifierContractDigest } = ollamaClientModule;
  assert.equal(typeof CLASSIFIER_CONTRACT_V1, 'object');
  assert.equal(typeof classifierContractDigest, 'function');

  const assertDeepFrozen = (value) => {
    if (value === null || typeof value !== 'object') return;
    assert.equal(Object.isFrozen(value), true);
    for (const nested of Object.values(value)) assertDeepFrozen(nested);
  };
  assertDeepFrozen(CLASSIFIER_CONTRACT_V1);

  const endpoint = { baseUrl: 'http://localhost:11434', model: 'qwen2.5:7b', timeoutMs: 300_000 };
  const expected = createHash('sha256').update(canonicalJson({
    domain: 'shared-review-classifier-contract-v1',
    endpoint,
    contract: CLASSIFIER_CONTRACT_V1,
  }), 'utf8').digest('hex');
  const baseline = classifierContractDigest(endpoint);
  assert.equal(baseline, expected);
  for (const changed of [
    { ...endpoint, baseUrl: 'http://127.0.0.1:11434' },
    { ...endpoint, model: 'qwen2.5:14b' },
    { ...endpoint, timeoutMs: 300_001 },
  ]) {
    assert.notEqual(classifierContractDigest(changed), baseline);
  }

  // CLASSIFIER_CONTRACT_V1 is deep-frozen, so a static value cannot be injected. Instead the digest of the
  // CURRENT contract is pinned below as a golden value taken from production. Any edit to any value inside
  // the contract (retry, chunking, prompt, indicators, ...) changes this real digest and fails here; when a
  // contract change is intended, bump the version and re-pin. Split so the source holds no long digit run.
  const goldenBaseline = [
    'de29ac77dcc92ff0', '06239c15c8540f3a', '58b914296d530608', '05e6391e58b34376',
  ].join('');
  assert.equal(baseline, goldenBaseline, 'the classifier contract digest for the default endpoint is pinned');
  assert.equal(CLASSIFIER_CONTRACT_V1.retry.maxRetries, 1, 'the pinned digest covers the live contract object');
});

test('classifier runtime request and prompt framing are sourced from the hashed contract', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options, body: JSON.parse(options.body) });
    return { ok: true, status: 200, json: async () => ({ response: 'false' }) };
  };
  const endpoint = { baseUrl: 'http://localhost:11434', model: 'qwen2.5:7b', timeoutMs: 5_000 };
  const client = createOllamaClient({ fetchImpl, ...endpoint });
  const text = 'ordinary text';
  await client.checkUnknownThirdPartyPii(text);

  const contract = ollamaClientModule.CLASSIFIER_CONTRACT_V1;
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${endpoint.baseUrl}${contract.request.path}`);
  assert.equal(calls[0].options.method, contract.request.method);
  assert.deepEqual(calls[0].options.headers, contract.request.headers);
  assert.deepEqual(calls[0].body, {
    model: endpoint.model,
    prompt: [
      contract.prompt.instruction,
      contract.prompt.questions.unknownThirdPartyPii,
      contract.prompt.untrustedDocumentWarning,
      `${contract.prompt.beginMarker}${contract.prompt.documentSeparator}${text}${contract.prompt.documentSeparator}${contract.prompt.endMarker}`,
    ].join(contract.prompt.sectionSeparator),
    stream: contract.request.stream,
    truncate: contract.request.truncate,
    options: contract.request.options,
  });
});

test('classifier digest rejects unknown fields and accessors without reading them', () => {
  const endpoint = { baseUrl: 'http://localhost:11434', model: 'qwen2.5:7b', timeoutMs: 300_000 };
  assert.throws(() => ollamaClientModule.classifierContractDigest({ ...endpoint, digest: 'caller-value' }), TypeError);
  let reads = 0;
  const hostile = { ...endpoint };
  Object.defineProperty(hostile, 'model', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error('MODEL-ACCESSOR-SENTINEL');
    },
  });
  assert.throws(() => ollamaClientModule.classifierContractDigest(hostile), TypeError);
  assert.equal(reads, 0);
});

test('checkUnknownThirdPartyPii returns the parsed boolean on a clean HTTP 200', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'false' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  const result = await client.checkUnknownThirdPartyPii('ordinary text');
  assert.deepEqual(result, { ok: true, flagged: false });
});

test('checkUnknownThirdPartyPii reports flagged:true when the model says true', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'true' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  const result = await client.checkUnknownThirdPartyPii('Jane Smith, ACME Corp, 555-0100');
  assert.deepEqual(result, { ok: true, flagged: true });
});

test('checkReidentifiable follows the same ok/flagged contract', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'true' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  const result = await client.checkReidentifiable('age 34, night-shift lead, level-2 badge, Example City depot');
  assert.deepEqual(result, { ok: true, flagged: true });
});

test('a network failure (connection refused) reports ok:false, never throws', async () => {
  // maxRetries: 0 -- this test is about a SINGLE failure's outcome, not
  // retry behavior (covered separately below). Without this, the new
  // default retry would make a second call past the end of the single-
  // response fakeFetch array, which happens to also resolve ok:false (via
  // an out-of-bounds `undefined` response) but for the wrong reason --
  // silently relying on unspecified fakeFetch behavior instead of testing
  // the one failure mode this test names.
  const client = createOllamaClient({
    fetchImpl: fakeFetch([new Error('ECONNREFUSED')]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('a non-200 HTTP status reports ok:false, never throws', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ ok: false, status: 500, body: {} }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('an unparseable model response (not "true"/"false") reports ok:false', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'I am not sure, maybe?' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('checkUnknownThirdPartyPii sets an explicit num_ctx so a real-sized document does not silently fall back to Ollama\'s small runtime default', async () => {
  // Regression guard: a document of several thousand tokens sent through this
  // client with no num_ctx in the request options gets Ollama's own runtime
  // default of 4,096 tokens -- not the qwen2.5:7b model's 32,768-token capacity
  // (see `ollama show qwen2.5:7b`) -- and Ollama rejects it outright with a 400
  // exceed_context_size_error. That surfaces here as ok:false
  // ("local_llm_unavailable"), which fails the whole scrub engine closed for any
  // document over roughly 3,000 words, including the paid Gemini/Grok tier
  // (loadAndScrubSource() is the one choke point for both). num_ctx is set
  // explicitly to the model's 32,768-token context window.
  let capturedBody;
  const fetchImpl = async (url, options) => {
    capturedBody = JSON.parse(options.body);
    return { ok: true, status: 200, json: async () => ({ response: 'false' }) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  await client.checkUnknownThirdPartyPii('text');
  assert.equal(capturedBody.options.num_ctx, 32768, 'expected an explicit num_ctx in the request options');
});

test('createOllamaClient requires a fetchImpl', () => {
  assert.throws(() => createOllamaClient({ baseUrl: 'http://localhost:11434', model: 'x', timeoutMs: 1000 }), TypeError);
});

test('createOllamaClient requires a non-empty baseUrl', () => {
  assert.throws(
    () => createOllamaClient({ fetchImpl: fakeFetch([]), baseUrl: '', model: 'x', timeoutMs: 1000 }),
    TypeError,
  );
});

test('createOllamaClient requires a non-empty model', () => {
  assert.throws(
    () => createOllamaClient({ fetchImpl: fakeFetch([]), baseUrl: 'http://localhost:11434', model: '', timeoutMs: 1000 }),
    TypeError,
  );
});

test('createOllamaClient requires a positive safe-integer timeoutMs', () => {
  // Bundles every distinct way Number.isSafeInteger(timeoutMs) || timeoutMs <= 0
  // can reject a value, so one test covers the whole guard condition rather
  // than just one edge of it.
  const badTimeouts = [0, -1, 1.5, NaN, Infinity, 'not-a-number'];
  for (const timeoutMs of badTimeouts) {
    assert.throws(
      () => createOllamaClient({ fetchImpl: fakeFetch([]), baseUrl: 'http://localhost:11434', model: 'x', timeoutMs }),
      TypeError,
      `expected TypeError for timeoutMs=${String(timeoutMs)}`,
    );
  }
});

test('checkUnknownThirdPartyPii wires timeoutMs into an AbortSignal passed to fetchImpl', async () => {
  // Regression guard for a fetch call that silently drops `signal:` -- that
  // would let a hung Ollama request block forever instead of failing closed
  // with ok:false, which is worse than the timeout it's meant to produce.
  // No real network involved: fetchImpl just captures the signal it was
  // given and returns a normal response; the short real timer below only
  // proves the captured signal is actually tied to the configured
  // timeoutMs, not just some unrelated AbortSignal instance.
  let capturedSignal;
  const fetchImpl = async (url, options) => {
    capturedSignal = options.signal;
    return { ok: true, status: 200, json: async () => ({ response: 'false' }) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 15,
  });
  await client.checkUnknownThirdPartyPii('text');
  assert.ok(capturedSignal instanceof AbortSignal, 'expected fetchImpl to receive an AbortSignal in options.signal');
  assert.equal(capturedSignal.aborted, false, 'signal should not already be aborted at call time');
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(capturedSignal.aborted, true, 'signal should abort once the configured timeoutMs elapses');
});

test('checkUnknownThirdPartyPii requires text to be a string', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'false' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  await assert.rejects(() => client.checkUnknownThirdPartyPii(42), TypeError);
});

test('checkReidentifiable requires text to be a string', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'false' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  await assert.rejects(() => client.checkReidentifiable(null), TypeError);
});

// ---------------------------------------------------------------------------
// Retry-with-backoff for transient failures. Scope: this closes the "Ollama
// transiently unreachable at that specific moment" failure mode by retrying
// the LOCAL network call a bounded number of times -- it deliberately does NOT
// cache the verdict across separate scrub()/review() calls (cache-precedence
// bugs are subtle and hard to get right, and a verdict cache is a
// disproportionate tool for a transient-network-blip problem). `delayFn` is
// injectable (defaults to a real setTimeout-based delay) so tests never
// actually wait out a real delay -- matches this file's existing pattern of
// injecting fetchImpl for testability.
// ---------------------------------------------------------------------------

function noDelay() {
  return async () => {};
}

test('a single transient failure followed by a success is retried and reports the successful result', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([new Error('ECONNREFUSED'), { body: { response: 'true' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 1,
    delayFn: noDelay(),
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: true, flagged: true });
});

test('a transient non-200 status followed by a success is retried and reports the successful result', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ ok: false, status: 503, body: {} }, { body: { response: 'false' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 1,
    delayFn: noDelay(),
  });
  const result = await client.checkReidentifiable('text');
  assert.deepEqual(result, { ok: true, flagged: false });
});

test('a transient unparseable response followed by a success is retried (a cold-loading model can answer garbage once)', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([{ body: { response: 'loading, please wait' } }, { body: { response: 'true' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 1,
    delayFn: noDelay(),
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: true, flagged: true });
});

test('a sustained failure still reports ok:false after retries are exhausted, never throws', async () => {
  const fetchImpl = fakeFetch([new Error('ECONNREFUSED'), new Error('ECONNREFUSED'), new Error('ECONNREFUSED')]);
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 2,
    delayFn: noDelay(),
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('retries are bounded: a client configured with maxRetries:1 makes at most 2 attempts total', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error('ECONNREFUSED');
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 1,
    delayFn: noDelay(),
  });
  await client.checkUnknownThirdPartyPii('text');
  assert.equal(calls, 2, 'expected exactly 2 attempts (1 initial + 1 retry), not an unbounded retry loop');
});

test('a successful first attempt makes exactly one call -- no retry overhead on the happy path', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: true, status: 200, json: async () => ({ response: 'false' }) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 2,
    delayFn: noDelay(),
  });
  await client.checkUnknownThirdPartyPii('text');
  assert.equal(calls, 1, 'expected no retries after an immediate success');
});

test('maxRetries defaults to a positive value even when omitted (retry behavior is on by default, not opt-in)', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([new Error('ECONNREFUSED'), { body: { response: 'false' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    delayFn: noDelay(),
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: true, flagged: false });
});

test('maxRetries: 0 explicitly disables retries -- exactly one attempt, even on failure', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error('ECONNREFUSED');
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.equal(calls, 1, 'expected exactly 1 attempt with maxRetries:0, never a retry');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('createOllamaClient rejects a negative or non-integer maxRetries', () => {
  for (const maxRetries of [-1, 1.5, NaN, 'not-a-number']) {
    assert.throws(
      () => createOllamaClient({ fetchImpl: fakeFetch([]), baseUrl: 'http://localhost:11434', model: 'x', timeoutMs: 1000, maxRetries }),
      TypeError,
      `expected TypeError for maxRetries=${String(maxRetries)}`,
    );
  }
});

test('the real (non-injected) delayFn default actually waits between retries, not a synchronous no-op', async () => {
  // The only test in this file that doesn't inject delayFn -- proves the
  // production default really delays, so the injectable seam isn't hiding a
  // default that's secretly instant (which would make the retry pointless
  // against a server that's still starting up).
  const client = createOllamaClient({
    fetchImpl: fakeFetch([new Error('ECONNREFUSED'), { body: { response: 'false' } }]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 1,
    retryDelayMs: 30,
  });
  const start = Date.now();
  await client.checkUnknownThirdPartyPii('text');
  const elapsed = Date.now() - start;
  assert.ok(elapsed >= 25, `expected the real retry delay to actually elapse (>=25ms), got ${elapsed}ms`);
});

// ---------------------------------------------------------------------------
// Context-window chunking. A document whose prompt tokenizes past
// qwen2.5:7b's 32,768-token capacity, sent through this client as ONE
// request, is rejected whole by Ollama with an HTTP 400 of this shape:
//
//   HTTP 400 {"error":"{\"error\":{\"code\":400,\"message\":\"request (N
//   tokens) exceeds the available context size (32768 tokens), try increasing
//   it\",\"type\":\"exceed_context_size_error\",\"n_prompt_tokens\":N,
//   \"n_ctx\":32768}}"}
//
// Mapping that -- like every other non-200 -- to a bare ok:false, which
// scrub-engine.mjs reports as `local_llm_unavailable`, is actively misleading:
// Ollama itself is healthy, so the message sends diagnosis after a phantom
// outage instead of at the real, deterministic, size-dependent wall. Raising
// num_ctx cannot fix this (32,768 IS the model's
// capacity, and MAX_SOURCE_BYTES is 2MB), and truncating the text would
// silently skip content this check exists to screen -- so the text is split
// into context-sized, OVERLAPPING chunks and every chunk is checked.
//
// The aggregation rules below are the security contract and are asserted
// individually: any chunk flagged => flagged (block); any chunk unavailable
// => ok:false (block); clean only when EVERY chunk was actually checked.
// ---------------------------------------------------------------------------

// Emulates the real Ollama context-limit behavior: anything whose prompt is
// longer than `limitChars` comes back as the 400 body shape shown above
// (nested JSON-in-a-string included); anything shorter answers
// normally. `flagOn` lets one specific chunk answer "true".
function contextLimitedFetch({ limitChars, flagOn = null, calls = [] } = {}) {
  return async (url, options) => {
    const body = JSON.parse(options.body);
    calls.push(body.prompt);
    if (body.prompt.length > limitChars) {
      const inner = JSON.stringify({
        error: {
          code: 400,
          message: `request (${body.prompt.length} tokens) exceeds the available context size (${limitChars} tokens), try increasing it`,
          type: 'exceed_context_size_error',
          n_prompt_tokens: body.prompt.length,
          n_ctx: limitChars,
        },
      });
      const text = JSON.stringify({ error: inner });
      return { ok: false, status: 400, text: async () => text, json: async () => JSON.parse(text) };
    }
    const flagged = flagOn !== null && body.prompt.includes(flagOn);
    return { ok: true, status: 200, text: async () => '', json: async () => ({ response: flagged ? 'true' : 'false' }) };
  };
}

function longDocument(lines, filler = 'ordinary spec prose that says nothing sensitive at all') {
  return Array.from({ length: lines }, (_, i) => `line ${i} ${filler}`).join('\n');
}

test('a document larger than one context window is chunked and still checked -- not sent as one oversized request', async () => {
  // Regression test: without chunking this document would go out as a single
  // request, draw the 400 above, and report ok:false.
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 6000, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const text = longDocument(400);
  assert.ok(text.length > 20000, 'fixture must actually exceed several chunk budgets');
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: true, flagged: false });
  assert.ok(calls.length > 1, `expected the document to be split into several requests, got ${calls.length}`);
});

test('chunking covers EVERY line of the document -- no content is silently skipped', async () => {
  // The one property that makes chunking safe rather than a quiet weakening
  // of the gate: a line that never reaches the classifier is a line that was
  // never screened. Asserted over the union of every prompt actually sent.
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 6000, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const text = longDocument(400);
  await client.checkUnknownThirdPartyPii(text);
  const sent = calls.join('\n');
  for (const line of text.split('\n')) {
    assert.ok(sent.includes(line), `line never reached the classifier: ${line}`);
  }
});

test('adjacent chunks overlap, so content straddling a chunk boundary is still seen intact', async () => {
  // A name on one line and its phone number on the next must be visible
  // TOGETHER to at least one classifier call, or a chunk boundary becomes a
  // free evasion. Overlap is what guarantees that.
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 6000, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 400,
  });
  const text = longDocument(400);
  await client.checkUnknownThirdPartyPii(text);
  assert.ok(calls.length > 1, 'fixture must produce more than one chunk');
  // Every consecutive pair of adjacent lines in the source appears, adjacent,
  // in at least one single prompt.
  const lines = text.split('\n');
  for (let i = 0; i < lines.length - 1; i += 1) {
    const pair = `${lines[i]}\n${lines[i + 1]}`;
    assert.ok(calls.some((prompt) => prompt.includes(pair)), `adjacent-line pair split across every chunk: ${pair}`);
  }
});

test('a flag on ANY chunk flags the whole document', async () => {
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 6000, flagOn: 'line 380 ' }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const result = await client.checkUnknownThirdPartyPii(longDocument(400));
  assert.deepEqual(result, { ok: true, flagged: true });
});

test('one unreachable chunk fails the WHOLE document closed, even when every other chunk came back clean', async () => {
  // Fail-closed is the entire point of the ok/flagged split; chunking must
  // not turn "most of it was checked" into a pass.
  let call = 0;
  const fetchImpl = async () => {
    call += 1;
    if (call === 3) throw new Error('ECONNREFUSED');
    return { ok: true, status: 200, text: async () => '', json: async () => ({ response: 'false' }) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const result = await client.checkUnknownThirdPartyPii(longDocument(400));
  assert.equal(result.ok, false, 'a single unchecked chunk must fail the whole document closed');
  assert.equal(result.flagged, null);
});

test('a chunk that still overflows is split further and retried, so no static chunk budget can silently reintroduce the bug', async () => {
  // The chunk budget is a CHARACTER count, but the wall is a TOKEN count, and
  // no character budget bounds tokens for arbitrary content (dense Unicode,
  // base64, CJK). Adaptive re-splitting on the model's own overflow error is
  // what makes the fix content-independent instead of a better guess.
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 1500, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 8000, // deliberately far too large for the emulated limit
    chunkOverlapChars: 100,
  });
  const text = longDocument(200);
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: true, flagged: false });
  const sent = calls.filter((prompt) => prompt.length <= 1500).join('\n');
  for (const line of text.split('\n')) {
    assert.ok(sent.includes(line), `line never reached the classifier after re-splitting: ${line}`);
  }
});

test('content that cannot be split small enough fails CLOSED with reason "context_overflow", never a pass', async () => {
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 10 }), // nothing can ever fit
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const result = await client.checkUnknownThirdPartyPii(longDocument(50));
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'context_overflow' });
});

test('a context-overflow failure is reported as "context_overflow", NOT as an unavailable local LLM', async () => {
  // The diagnostic half: an overflow reported as `local_llm_unavailable`
  // while Ollama itself is healthy sends the investigation after an outage
  // that never happened.
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 10 }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('short text');
  assert.equal(result.reason, 'context_overflow');
});

test('a request that times out is reported as "timeout", not as an unavailable local LLM', async () => {
  // AbortSignal.timeout() rejects with a DOMException named TimeoutError.
  // A slow-but-alive model is a different operator action (wait / raise the
  // timeout) than a dead one (start Ollama), so it gets a different reason.
  const fetchImpl = async () => {
    throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'timeout' });
});

test('a genuine connection failure is still reported as "unavailable"', async () => {
  const client = createOllamaClient({
    fetchImpl: fakeFetch([new Error('ECONNREFUSED')]),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('a non-overflow HTTP error is still reported as "unavailable"', async () => {
  const fetchImpl = async () => ({ ok: false, status: 500, text: async () => 'internal error', json: async () => ({}) });
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii('text');
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'unavailable' });
});

test('a context-overflow response is NOT burned on pointless retries -- re-sending the identical oversized prompt can never succeed', async () => {
  let calls = 0;
  const fetchImpl = async (url, options) => {
    calls += 1;
    const body = JSON.parse(options.body);
    const inner = JSON.stringify({ error: { type: 'exceed_context_size_error', n_prompt_tokens: body.prompt.length, n_ctx: 10 } });
    const text = JSON.stringify({ error: inner });
    return { ok: false, status: 400, text: async () => text, json: async () => JSON.parse(text) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 3,
    delayFn: noDelay(),
    // Small enough that the first re-split attempt already hits the
    // un-splittable floor, so this measures retry behavior, not split depth.
    chunkOverlapChars: 200,
  });
  await client.checkUnknownThirdPartyPii('short');
  assert.equal(calls, 1, `an oversized prompt must not be retried verbatim; got ${calls} attempts`);
});

test('a small document still goes out as exactly one request -- chunking adds no overhead below the budget', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: true, status: 200, text: async () => '', json: async () => ({ response: 'false' }) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  await client.checkUnknownThirdPartyPii('a short document');
  assert.equal(calls, 1);
});

test('checkReidentifiable chunks on the same contract as checkUnknownThirdPartyPii', async () => {
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 6000, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const text = longDocument(400);
  const result = await client.checkReidentifiable(text);
  assert.deepEqual(result, { ok: true, flagged: false });
  const sent = calls.join('\n');
  for (const line of text.split('\n')) {
    assert.ok(sent.includes(line), `line never reached the re-identification check: ${line}`);
  }
});

test('the default maxChunkChars leaves real headroom under qwen2.5:7b\'s 32,768-token window', async () => {
  // Ordinary markdown tokenizes at several chars/token. The default budget
  // must hold even for much denser content than that -- at a pessimistic 1.5
  // chars/token it must still fit inside the window with room for the prompt
  // preamble and the generated answer.
  //
  // The LONGEST prompt of the run is measured, not the last one: for a chunked
  // document the most recent prompt is the trailing REMAINDER -- routinely the
  // smallest chunk of all -- so checking only that sample would let a budget
  // well past the window pass, depending purely on how large the remainder
  // happened to be. A guard that reads the wrong sample is not a guard.
  let longestPrompt = 0;
  let lastPrompt = 0;
  const fetchImpl = async (url, options) => {
    lastPrompt = JSON.parse(options.body).prompt.length;
    longestPrompt = Math.max(longestPrompt, lastPrompt);
    return { ok: true, status: 200, text: async () => '', json: async () => ({ response: 'false' }) };
  };
  const client = createOllamaClient({
    fetchImpl,
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
  });
  await client.checkUnknownThirdPartyPii(longDocument(20000));
  // Fixture validity, so this can never quietly become the vacuous version
  // again: the run must actually contain a chunk bigger than its last one, or
  // "longest" and "last" would be the same reading and the distinction above
  // would go untested.
  assert.ok(
    longestPrompt > lastPrompt,
    `fixture must produce a largest chunk that is not the final one; longest=${longestPrompt} last=${lastPrompt}`,
  );
  const worstCaseTokens = Math.ceil(longestPrompt / 1.5);
  assert.ok(
    worstCaseTokens < 32768,
    `a full default-budget chunk must fit the window even at 1.5 chars/token; got ${worstCaseTokens} tokens`,
  );
});

// Each classifier prompt encloses the source segment verbatim between fixed
// markers. Read the segment from those public framing boundaries rather than
// assuming a preamble length, while asserting that neither boundary is
// ambiguous and the end marker really terminates the prompt.
const BEGIN_UNTRUSTED_DOCUMENT = '[[[BEGIN_UNTRUSTED_DOCUMENT]]]';
const END_UNTRUSTED_DOCUMENT = '[[[END_UNTRUSTED_DOCUMENT]]]';

function segmentOf(prompt) {
  const prefix = `${BEGIN_UNTRUSTED_DOCUMENT}\n`;
  const suffix = `\n${END_UNTRUSTED_DOCUMENT}`;
  assert.equal(prompt.split(BEGIN_UNTRUSTED_DOCUMENT).length - 1, 1, 'prompt must carry exactly one begin marker');
  assert.equal(prompt.split(END_UNTRUSTED_DOCUMENT).length - 1, 1, 'prompt must carry exactly one end marker');
  const at = prompt.indexOf(prefix);
  assert.notEqual(at, -1, 'begin marker must follow the trusted preamble and end with a newline');
  assert.equal(prompt.endsWith(suffix), true, 'end marker must terminate the prompt after one newline');
  return prompt.slice(at + prefix.length, -suffix.length);
}

// A run of `count` distinct tokens, so any slice of the result occurs at
// exactly one position and coverage can be reconstructed by index. `sep`
// picks the shape: '\n' gives ordinary lines, ' ' gives one enormous
// unbroken line where the line-boundary path cannot apply at all and every
// cut has to fall mid-line.
function uniqueRun(count, sep) {
  return Array.from({ length: count }, (_, i) => `tok${i}abcdefghij`).join(sep);
}

test('coverage and overlap hold across many chunk geometries, including one enormous unbroken line', async () => {
  // The single-config tests above prove the properties for one shape. This
  // sweeps what decides where cuts land, because a chunker that drops content
  // only under some geometry is still a hole in the gate. Coverage is
  // reconstructed from the segments actually sent: each must start at or
  // before the end of what earlier segments already covered (no gap), and
  // together they must reach the end of the document.
  const geometries = [
    { text: uniqueRun(300, '\n'), maxChunkChars: 4000, chunkOverlapChars: 500 },
    { text: uniqueRun(300, '\n'), maxChunkChars: 1000, chunkOverlapChars: 100 },
    { text: uniqueRun(300, '\n'), maxChunkChars: 999, chunkOverlapChars: 1 },
    { text: uniqueRun(7, '\n'), maxChunkChars: 100, chunkOverlapChars: 49 },
    { text: uniqueRun(3000, ' '), maxChunkChars: 3000, chunkOverlapChars: 250 },
    { text: `${uniqueRun(2000, ' ')}\n${uniqueRun(2000, '-')}`, maxChunkChars: 4000, chunkOverlapChars: 300 },
  ];
  for (const { text, maxChunkChars, chunkOverlapChars } of geometries) {
    const label = `len=${text.length} max=${maxChunkChars} overlap=${chunkOverlapChars}`;
    const calls = [];
    const client = createOllamaClient({
      fetchImpl: contextLimitedFetch({ limitChars: Number.MAX_SAFE_INTEGER, calls }),
      baseUrl: 'http://localhost:11434',
      model: 'qwen2.5:7b',
      timeoutMs: 5000,
      maxRetries: 0,
      maxChunkChars,
      chunkOverlapChars,
    });
    const result = await client.checkUnknownThirdPartyPii(text);
    assert.deepEqual(result, { ok: true, flagged: false }, label);

    let covered = 0;
    let previousEnd = null;
    for (const prompt of calls) {
      const segment = segmentOf(prompt);
      const start = text.indexOf(segment);
      assert.notEqual(start, -1, `segment was not a verbatim slice of the source (${label})`);
      assert.ok(start <= covered, `gap in coverage at ${covered}, next segment starts at ${start} (${label})`);
      if (previousEnd !== null && text.length > maxChunkChars) {
        assert.ok(
          previousEnd - start >= Math.min(chunkOverlapChars, previousEnd),
          `chunks did not overlap: previous ended at ${previousEnd}, next starts at ${start} (${label})`,
        );
      }
      covered = Math.max(covered, start + segment.length);
      previousEnd = start + segment.length;
    }
    assert.equal(covered, text.length, `coverage stopped at ${covered} of ${text.length} (${label})`);
  }
});

test('createOllamaClient rejects a non-positive or non-integer maxChunkChars', () => {
  for (const maxChunkChars of [0, -1, 1.5, NaN, 'not-a-number']) {
    assert.throws(
      () => createOllamaClient({ fetchImpl: fakeFetch([]), baseUrl: 'http://localhost:11434', model: 'x', timeoutMs: 1000, maxChunkChars }),
      TypeError,
      `expected TypeError for maxChunkChars=${String(maxChunkChars)}`,
    );
  }
});

test('createOllamaClient rejects a chunkOverlapChars that is negative, non-integer, or at least half the chunk budget', () => {
  // Half, not the whole budget: a window can legitimately be cut at half the
  // budget (a line boundary), and the scan advances by (cut - overlap), so an
  // overlap of half or more stalls -- it would re-send the same window
  // forever instead of covering the document. 2000 below is exactly half of
  // the 4000 budget and must be rejected on the boundary, not just past it.
  for (const chunkOverlapChars of [-1, 1.5, NaN, 'not-a-number', 2000, 4000, 9000]) {
    assert.throws(
      () => createOllamaClient({
        fetchImpl: fakeFetch([]),
        baseUrl: 'http://localhost:11434',
        model: 'x',
        timeoutMs: 1000,
        maxChunkChars: 4000,
        chunkOverlapChars,
      }),
      TypeError,
      `expected TypeError for chunkOverlapChars=${String(chunkOverlapChars)}`,
    );
  }
});

// ---------------------------------------------------------------------------
// Re-split geometry. Re-split tests that only use a UNIFORM document -- evenly
// spaced short lines, where a line boundary always lands near the middle of
// whatever is being split -- cannot see geometry-dependent defects.
//
// Real documents are not uniform. A heading followed by a base64 data URI, a
// minified bundle, one very long paragraph: these put a line break near the
// START of a segment and then nothing for tens of thousands of characters.
// A halveSegment() that honours that boundary however early it sits makes the
// "right half" the entire parent segment again, returns null, and fails the
// WHOLE document closed -- with the same "too big" error chunking exists to
// eliminate. The tell is that two byte-adjacent documents behave oppositely:
// one character decides whether a 5,002-char document passes or is rejected
// outright.
// ---------------------------------------------------------------------------

// One short line, then a long run with no line break at all -- the shape that
// made halveSegment() return null. `sep` is the only difference between the
// failing document and its control.
function headingThenUnbrokenRun(runLength, sep = '\n') {
  return `x${sep}${'b'.repeat(runLength)}`;
}

test('a segment whose only line break sits at the very start is still re-split, not failed closed', async () => {
  // The byte-adjacent pair, run together on purpose: same length, same content,
  // one character apart. Without the boundary guard the newline version is
  // rejected after a single request while the control splits into four and
  // passes -- proof the discriminator is the document's GEOMETRY, not its size.
  for (const [label, text] of [
    ['leading newline', headingThenUnbrokenRun(5000, '\n')],
    ['no newline (control)', headingThenUnbrokenRun(5000, 'y')],
  ]) {
    const calls = [];
    const client = createOllamaClient({
      fetchImpl: contextLimitedFetch({ limitChars: 3000, calls }),
      baseUrl: 'http://localhost:11434',
      model: 'qwen2.5:7b',
      timeoutMs: 5000,
      maxRetries: 0,
      maxChunkChars: 4000,
      chunkOverlapChars: 200,
    });
    const result = await client.checkUnknownThirdPartyPii(text);
    assert.deepEqual(result, { ok: true, flagged: false }, `${label}: must be checked, not failed closed`);
    assert.ok(calls.length > 1, `${label}: expected re-splitting, got ${calls.length} request(s)`);
  }
});

test('a long unbroken blob after a heading is re-split at the SHIPPED defaults, not failed closed', async () => {
  // Run through the exact defaults the server uses (it passes no chunk options
  // at all): prose heading, a ~70,000-char base64 data URI with no line breaks
  // in it, then prose. Without the boundary guard this draws one request and a
  // context_overflow verdict on the whole document.
  const base64Blob = 'A1b2C3d4E5f6G7h8'.repeat(4384); // 70,144 chars, no line breaks
  const text = `# Design notes\ndata:image/png;base64,${base64Blob}\n\nThat image is the architecture sketch discussed above.`;
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 20000, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
  });
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: true, flagged: false });
  assert.ok(calls.length > 1, `expected the blob to be re-split, got ${calls.length} request(s)`);
});

test('the line break chunkText itself plants at exactly the overlap offset does not fail the next chunk closed', async () => {
  // Why the bug was systematic rather than exotic. chunkText cuts at a line
  // boundary and starts the NEXT chunk at (cut - overlap), which places that
  // very newline at relative offset exactly `overlapChars` in the next chunk.
  // If that chunk then runs on without another break, the boundary search finds
  // nothing better than its own opening newline, and cut === overlapChars is
  // precisely the case that produced a null re-split. The prefix below is sized
  // so the first cut really does land on a line boundary.
  const prefix = uniqueRun(240, '\n'); // 3,969 chars of ordinary short lines
  const text = `${prefix}\n${uniqueRun(600, '-')}`; // then one very long line
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 3000, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 4000,
    chunkOverlapChars: 200,
  });
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: true, flagged: false });
});

test('coverage and overlap survive FORCED re-splitting across non-uniform geometries', async () => {
  // The geometry sweep above proves coverage when nothing overflows. This one
  // sets the emulated context limit below the chunk budget so every chunk must
  // be re-split at least once, and checks the same two security properties on
  // the segments that were actually accepted -- a re-split that loses content is
  // a hole in the gate exactly like a chunker that loses content.
  const geometries = [
    { text: `# notes\n${uniqueRun(500, '-')}`, maxChunkChars: 4000, chunkOverlapChars: 200 },
    { text: `${uniqueRun(240, '\n')}\n${uniqueRun(600, '-')}`, maxChunkChars: 4000, chunkOverlapChars: 200 },
    { text: `${uniqueRun(400, '-')}\n${uniqueRun(400, '\n')}`, maxChunkChars: 3000, chunkOverlapChars: 300 },
    { text: `a\n${uniqueRun(800, ' ')}`, maxChunkChars: 5000, chunkOverlapChars: 400 },
  ];
  for (const { text, maxChunkChars, chunkOverlapChars } of geometries) {
    const limitChars = Math.floor(maxChunkChars / 2);
    const label = `len=${text.length} max=${maxChunkChars} overlap=${chunkOverlapChars} limit=${limitChars}`;
    const calls = [];
    const client = createOllamaClient({
      fetchImpl: contextLimitedFetch({ limitChars, calls }),
      baseUrl: 'http://localhost:11434',
      model: 'qwen2.5:7b',
      timeoutMs: 5000,
      maxRetries: 0,
      maxChunkChars,
      chunkOverlapChars,
    });
    const result = await client.checkUnknownThirdPartyPii(text);
    assert.deepEqual(result, { ok: true, flagged: false }, label);

    // Only the prompts the model actually answered count as screened; an
    // oversized one was rejected and replaced by its halves.
    const accepted = calls.filter((prompt) => prompt.length <= limitChars).map(segmentOf);
    assert.ok(accepted.length > 1, `expected forced re-splitting (${label})`);
    const spans = accepted
      .map((segment) => {
        const start = text.indexOf(segment);
        assert.notEqual(start, -1, `segment was not a verbatim slice of the source (${label})`);
        // Locating a segment by search is only sound while the match is
        // unique; every fixture above is built from distinct tokens precisely
        // so it is, and this keeps a future fixture from quietly breaking that.
        assert.equal(start, text.lastIndexOf(segment), `segment matched the source ambiguously (${label})`);
        return [start, start + segment.length];
      })
      .sort((a, b) => a[0] - b[0]);
    let covered = 0;
    for (let i = 0; i < spans.length; i += 1) {
      const [start, end] = spans[i];
      assert.ok(start <= covered, `gap in coverage at ${covered}, next accepted segment starts at ${start} (${label})`);
      // Coverage alone doesn't prove overlap -- a chunker that abuts segments
      // with zero shared characters (e.g. `segment.slice(cut)` instead of
      // `segment.slice(cut - overlapChars)`) still satisfies the coverage
      // check above while destroying the property overlap exists for: content
      // straddling a re-split boundary must appear intact in at least one
      // chunk. Checked against the min of the configured overlap and the
      // PREVIOUS segment's own length, matching the same accommodation the
      // geometry-sweep test above makes for a segment too short to carry the
      // full configured overlap.
      if (i > 0) {
        const [previousStart, previousEnd] = spans[i - 1];
        assert.ok(
          previousEnd - start >= Math.min(chunkOverlapChars, previousEnd - previousStart),
          `re-split segments did not overlap: previous ended at ${previousEnd}, next starts at ${start} (${label})`,
        );
      }
      covered = Math.max(covered, end);
    }
    assert.equal(covered, text.length, `coverage stopped at ${covered} of ${text.length} (${label})`);
  }
});

// ---------------------------------------------------------------------------
// Forward progress. The chunking loop advances by at least
// floor(maxChars/2) - overlap per window, which the constructor's guard must
// keep strictly positive. A `2 * overlap < maxChars` guard is not enough for an
// ODD budget: 2 * 499 < 999 passes, yet floor(999/2) - 499 = 0, so a
// constructor accepting {maxChunkChars: 999, chunkOverlapChars: 499} lets a
// check call spin in chunkText forever (a heap-limit FATAL ERROR under a
// constrained heap, before any network request). Not reachable from the
// shipped server (it passes no chunk options), but it sits inside a security
// gate.
// ---------------------------------------------------------------------------

test('createOllamaClient rejects an odd chunk budget whose forward progress would be exactly zero', async () => {
  // Each pair below passed the old `2 * overlap < maxChars` guard while leaving
  // floor(maxChars / 2) - overlap === 0 characters of progress per window.
  for (const [maxChunkChars, chunkOverlapChars] of [[999, 499], [1001, 500], [5, 2], [48001, 24000]]) {
    assert.equal(
      Math.floor(maxChunkChars / 2) - chunkOverlapChars,
      0,
      `fixture error: ${maxChunkChars}/${chunkOverlapChars} is not actually a zero-progress pair`,
    );
    assert.throws(
      () => createOllamaClient({
        fetchImpl: fakeFetch([]),
        baseUrl: 'http://localhost:11434',
        model: 'x',
        timeoutMs: 1000,
        maxChunkChars,
        chunkOverlapChars,
      }),
      TypeError,
      `expected TypeError for maxChunkChars=${maxChunkChars} chunkOverlapChars=${chunkOverlapChars}`,
    );
  }
});

test('the tightened guard still accepts every configuration that does make progress', async () => {
  // The fix must not become a blanket ban on odd budgets: these all leave at
  // least one character of forward progress and must keep working, including
  // the geometries the sweep above relies on.
  for (const [maxChunkChars, chunkOverlapChars] of [[4000, 1999], [999, 498], [100, 49], [999, 1], [48000, 2000]]) {
    assert.ok(
      Math.floor(maxChunkChars / 2) - chunkOverlapChars > 0,
      `fixture error: ${maxChunkChars}/${chunkOverlapChars} does not actually make progress`,
    );
    const client = createOllamaClient({
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => '', json: async () => ({ response: 'false' }) }),
      baseUrl: 'http://localhost:11434',
      model: 'x',
      timeoutMs: 1000,
      maxChunkChars,
      chunkOverlapChars,
    });
    const result = await client.checkUnknownThirdPartyPii(longDocument(200));
    assert.deepEqual(result, { ok: true, flagged: false }, `${maxChunkChars}/${chunkOverlapChars} must still work`);
  }
});

test('the chunking loop refuses to spin without forward progress, even with the constructor guard removed', { timeout: 10_000 }, async () => {
  // The constructor guard makes a zero-progress config unreachable, so the
  // loop's own invariant can only be exercised by deleting that guard -- which
  // is exactly the future edit the invariant exists to survive. A silent
  // infinite loop inside a security gate is the worst available failure: it
  // hangs the whole review with no diagnosis, or dies on a heap limit. This
  // imports a sabotaged copy of the module and requires a loud throw instead.
  // A bounded timeout here (rather than relying on the in-loop guard alone)
  // is defense-in-depth for this specific test: a future edit that weakens
  // BOTH the constructor guard and the in-loop check at once should fail this
  // test loudly and fast, not hang the whole suite.
  const source = await readFile(new URL('../src/local-mcp/ollama-client.mjs', import.meta.url), 'utf8');
  const guard = 'if (chunkOverlapChars >= Math.floor(maxChunkChars / 2)) {';
  assert.ok(source.includes(guard), 'constructor guard text not found -- this sabotage test needs updating');
  const directory = mkdtempSync(join(tmpdir(), 'ollama-client-sabotage-'));
  try {
    const file = join(directory, 'ollama-client.mjs');
    const contractsUrl = new URL('../src/local-mcp/shared/contracts.mjs', import.meta.url).href;
    writeFileSync(file, source
      .replace("from './shared/contracts.mjs';", `from '${contractsUrl}';`)
      .replace(guard, 'if (false) {'));
    const { createOllamaClient: createSabotagedClient } = await import(pathToFileURL(file).href);
    const client = createSabotagedClient({
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => '', json: async () => ({ response: 'false' }) }),
      baseUrl: 'http://localhost:11434',
      model: 'x',
      timeoutMs: 1000,
      maxChunkChars: 999,
      chunkOverlapChars: 499,
    });
    // A line start at exactly floor(maxChars / 2) is the earliest cut the loop
    // will honour, and it restarts at (cut - overlap) === 0. Nothing after it
    // breaks the line, so every iteration reproduces that same cut.
    const text = `${'z'.repeat(498)}\n${'y'.repeat(5000)}`;
    await assert.rejects(
      () => client.checkUnknownThirdPartyPii(text),
      /forward progress/i,
      'a zero-progress configuration must throw, never loop',
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Midpoint-fallback band: halveSegment() must not refuse a legitimate split for
// segment lengths in [overlapChars+2, 2*overlapChars+1]. When the found
// boundary is below minimumLeft, the code falls back to the midpoint -- but for
// a segment in that band, midpoint <= overlapChars, so a plain midpoint makes
// `cut - overlapChars <= 0`, the "right half" the WHOLE parent segment again,
// and the function return null: the same fail-the-whole-document-closed
// failure mode as the boundary branch above, relocated to the midpoint-fallback
// branch it falls through to. The fallback is therefore floored at
// overlapChars + 1. Not reachable at the shipped defaults (the constructor's
// own forward-progress guard keeps the TOP-level chunk's midpoint safely above
// overlapChars), but reachable once a segment has already been halved down
// into that band, or if an operator lowers maxChunkChars/raises
// chunkOverlapChars relative to a smaller effective context window. A segment
// truly BELOW the band (length <= overlapChars+1)
// has no valid split at all -- both halves would have to be shorter than the
// parent AND still carry the overlap, which is impossible below that floor --
// so null stays correct there; only the band above it was ever a bug.
// ---------------------------------------------------------------------------

// contextLimitedFetch's limitChars bounds the FULL PROMPT (fixed preamble +
// segment verbatim), not the segment alone -- every other fixture in this
// file picks limitChars generously above the preamble so that distinction
// never matters. The bands under test here are only tens of characters wide,
// so it does matter: this measures the real preamble length once, live
// against the shipped prompt text, rather than hardcoding it as a constant
// that would silently drift if the prompt wording ever changes.
async function measureThirdPartyPreambleLength() {
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: Number.MAX_SAFE_INTEGER, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'x',
    timeoutMs: 1000,
  });
  await client.checkUnknownThirdPartyPii('X');
  return calls[0].length - 1;
}

test('a segment in the [overlapChars+2, 2*overlapChars+1] band still re-splits, instead of failing the whole document closed', async () => {
  // overlapChars=10 -> the band is [12,21]. A 15-char unbroken run (no line
  // break at all, so the boundary path can never apply) sits inside it, and
  // maxChunkChars is set above the text length so chunkText hands the whole
  // thing to halveSegment as a single top-level segment -- isolating the
  // midpoint fallback from chunkText's own boundary logic.
  const overlapChars = 10;
  const text = 'a'.repeat(15);
  assert.ok(text.length >= overlapChars + 2 && text.length <= 2 * overlapChars + 1, 'fixture must land inside the midpoint-fallback band');
  const preambleLength = await measureThirdPartyPreambleLength();
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: preambleLength + 12, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 25,
    chunkOverlapChars: overlapChars,
  });
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: true, flagged: false }, 'must be checked via re-splitting, not failed closed');
  assert.ok(calls.length > 1, `expected re-splitting, got ${calls.length} request(s)`);
});

test('a segment genuinely too small to carry the overlap (length <= overlapChars+1) still fails closed -- not every null is a bug', async () => {
  // The floor below the band: no cut can produce two halves that are both
  // shorter than the parent and still share overlapChars characters, so
  // context_overflow (not a pass, not a hang) is the only correct outcome.
  const overlapChars = 10;
  const text = 'a'.repeat(overlapChars + 1); // 11 chars -- one below the midpoint-fallback band
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: 5 }), // nothing this small can ever fit
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 25,
    chunkOverlapChars: overlapChars,
  });
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'context_overflow' });
});

// ---------------------------------------------------------------------------
// Request budget for one askOverText() call. The midpoint-fallback floor above
// closes the null-return case by forcing a split even when the only available
// cut leaves very little real shrinkage -- and in that same band, the "right"
// half is barely smaller than its parent (cut is pinned to overlapChars+1, so
// the right half is only ONE character shorter than the segment it came from).
// Forcing that split WITHOUT also bounding total requests turns that band into
// a source of pathological amplification: a document that normally needs a
// handful of requests can need well over a hundred thousand. maxChunkRequests
// bounds total classifier requests for one check call and fails CLOSED (never
// a silent pass, never an unbounded loop) once exhausted.
// ---------------------------------------------------------------------------

test('createOllamaClient rejects a non-positive or non-integer maxChunkRequests', () => {
  for (const maxChunkRequests of [0, -1, 1.5, NaN, 'not-a-number']) {
    assert.throws(
      () => createOllamaClient({
        fetchImpl: fakeFetch([]),
        baseUrl: 'http://localhost:11434',
        model: 'x',
        timeoutMs: 1000,
        maxChunkRequests,
      }),
      TypeError,
      `expected TypeError for maxChunkRequests=${String(maxChunkRequests)}`,
    );
  }
});

test('askOverText fails CLOSED with reason "chunk_budget_exceeded" once a document would need more than maxChunkRequests, rather than continuing indefinitely', async () => {
  const calls = [];
  const client = createOllamaClient({
    // limitChars is generous -- nothing here overflows the emulated context
    // window. This isolates the request-count budget itself from the
    // re-split amplification the midpoint-fallback floor can trigger, which
    // is covered separately below.
    fetchImpl: contextLimitedFetch({ limitChars: Number.MAX_SAFE_INTEGER, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 1000,
    chunkOverlapChars: 100,
    maxChunkRequests: 3,
  });
  const text = longDocument(2000); // ordinary chunking alone needs well over 3 requests at this budget
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'chunk_budget_exceeded' });
  assert.ok(calls.length <= 3, `must stop AT the budget, not merely near it; got ${calls.length} calls`);
});

test('the request budget also bounds the re-split amplification the midpoint-fallback floor can trigger, instead of trading one runaway for another', async () => {
  // Inside the band, cut is pinned to overlapChars+1: every split spawns
  // a LEFT half of exactly that fixed size and a RIGHT half only ONE character
  // shorter than its parent. With overlapChars=50 and a 101-char starting
  // segment (top of the [52,101] band) checked against a 55-char cap, every
  // LEFT half (51 chars) passes immediately, so the entire cost is the RIGHT
  // chain counting down 101,100,99,...,56 before finally landing at 55 and
  // passing -- on the order of 90 requests for a single 101-character segment,
  // well before it would ever reach the genuine unsplittable floor at 51.
  // Without a request budget this scales with how far a segment starts above
  // the cap (up to tens of thousands of requests on a large document); with
  // it, the check fails closed promptly.
  const overlapChars = 50;
  const preambleLength = await measureThirdPartyPreambleLength();
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: preambleLength + 55, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 150, // > text.length, so chunkText hands over one unchanged top-level segment
    chunkOverlapChars: overlapChars,
    maxChunkRequests: 25,
  });
  const text = 'a'.repeat(101); // top of the [overlapChars+2, 2*overlapChars+1] = [52,101] band
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: false, flagged: null, reason: 'chunk_budget_exceeded' });
  assert.ok(calls.length <= 25, `must stop AT the budget, got ${calls.length} calls`);
});

test('a default-budget document that legitimately needs many chunks is still checked, not blocked by the new ceiling', async () => {
  // Regression guard: the new budget must be generous enough that it never
  // fires for ordinary chunking under the shipped default -- only the
  // pathological cases above should ever reach it.
  const calls = [];
  const client = createOllamaClient({
    fetchImpl: contextLimitedFetch({ limitChars: Number.MAX_SAFE_INTEGER, calls }),
    baseUrl: 'http://localhost:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 5000,
    maxRetries: 0,
    maxChunkChars: 1000,
    chunkOverlapChars: 100,
    // maxChunkRequests intentionally omitted -- exercises the real default.
  });
  const text = longDocument(2000);
  const result = await client.checkUnknownThirdPartyPii(text);
  assert.deepEqual(result, { ok: true, flagged: false });
  assert.ok(calls.length > 3, `fixture must actually need more than a token handful of requests, got ${calls.length}`);
});
