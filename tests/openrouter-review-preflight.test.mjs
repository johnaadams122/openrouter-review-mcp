import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { RESPONSE_FORMAT } from '../src/review-core/advisory-schema.mjs';
import { getReviewer } from '../src/review-core/reviewer-registry.mjs';
import {
  buildReviewRequest,
  calculateConservativeMaxUsd,
  loadReviewSource,
  preflightReview,
} from '../src/local-mcp/source-contract.mjs';

const allowedRoot = resolve('tests/fixtures/openrouter-review/allowed');
const policy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 1_024 });
const preflightPolicy = Object.freeze({ maxRequestBytes: 20_000 });

async function inlineSource() {
  return loadReviewSource({ source_text: 'design requirement' }, policy);
}

test('consequential profile builds the exact fixed Gemini then Grok requests', async () => {
  const source = await inlineSource();
  const reviewers = ['gemini', 'grok'].map((reviewerId) => getReviewer(reviewerId));
  for (const reviewer of reviewers) {
    const requestBody = (await import('../src/local-mcp/source-contract.mjs')).buildReviewRequest({ reviewer, sourceText: source.text, reviewContext: 'adversarial API review' });
    assert.deepEqual(requestBody.provider, {
      only: [reviewer.route],
      allow_fallbacks: false,
      require_parameters: true,
      zdr: true,
      data_collection: 'deny',
      max_price: { prompt: reviewer.priceCeiling.promptUsdPerMillionTokens, completion: reviewer.priceCeiling.completionUsdPerMillionTokens },
    });
    assert.deepEqual(requestBody.response_format, RESPONSE_FORMAT);
    assert.equal(requestBody.max_tokens, reviewer.request.maxTokens);
    assert.equal(requestBody.messages[1].content.includes('<source>\ndesign requirement\n</source>'), true);
  }
});

test('fixed profile selection builds deterministic model-visible cost bounds', async () => {
  const source = await inlineSource();
  const first = preflightReview({ source, profile: 'consequential_spec_v1', reviewContext: 'scope', policy: preflightPolicy });
  const second = preflightReview({ source, profile: 'consequential_spec_v1', reviewContext: 'scope', policy: preflightPolicy });
  assert.deepEqual(first, second);
  assert.deepEqual(first.reviewers.map((item) => item.reviewerId), ['gemini', 'grok']);
  for (const item of first.reviewers) {
    assert.equal(item.cost.modelVisibleInputTokenUpperBound, item.requestBytes);
  }
  // Gemini's bound still rests on its own max_tokens; Grok's rests on its declared billable
  // completion ceiling, because Grok 4.7 does not stop billing at max_tokens.
  const scopes = Object.fromEntries(first.reviewers.map((item) => [item.reviewerId, item.cost.costBoundScope]));
  assert.deepEqual(scopes, {
    gemini: 'model_visible_request_and_pinned_completion_only',
    grok: 'model_visible_request_and_declared_completion_ceiling',
  });
});

const geminiRequiredChangeKinds = Object.freeze([
  'spend',
  'token_unit_math',
  'serialization',
  'api_contract',
  'major_remediation',
]);

test('final verification requires an explicit valid change-kind classification', async () => {
  const source = await inlineSource();
  const baseInput = { source, profile: 'final_verification_v1', policy: preflightPolicy };

  assert.throws(() => preflightReview(baseInput), /changeKinds.*required/i);
  assert.throws(() => preflightReview({ ...baseInput, changeKinds: 'spend' }), /changeKinds.*array/i);
  assert.throws(() => preflightReview({ ...baseInput, changeKinds: ['unknown_kind'] }), /unknown change kind/i);
  assert.throws(() => preflightReview({ ...baseInput, changeKinds: ['spend', 'spend'] }), /duplicate change kind/i);
  assert.deepEqual(
    preflightReview({ ...baseInput, changeKinds: [] }).reviewers.map((item) => item.reviewerId),
    ['grok'],
  );
});

test('each Gemini-required final-verification kind adds Gemini to the ordered profile union and cost cap', async () => {
  const source = await inlineSource();
  const base = preflightReview({
    source,
    profile: 'final_verification_v1',
    changeKinds: [],
    policy: preflightPolicy,
  });

  for (const changeKind of geminiRequiredChangeKinds) {
    const conditional = preflightReview({
      source,
      profile: 'final_verification_v1',
      changeKinds: [changeKind],
      policy: preflightPolicy,
    });
    assert.deepEqual(conditional.reviewers.map((item) => item.reviewerId), ['grok', 'gemini']);
    assert.equal(conditional.totalMaxUsd, conditional.reviewers.reduce((total, reviewer) => total + reviewer.maxUsd, 0));
    assert.equal(conditional.totalMaxUsd > base.totalMaxUsd, true);
  }
});

test('the built Gemini body omits temperature on the wire; Grok still pins it', async () => {
  const gemini = buildReviewRequest({ reviewer: getReviewer('gemini'), sourceText: 'x', reviewContext: 'y' });
  const grok = buildReviewRequest({ reviewer: getReviewer('grok'), sourceText: 'x', reviewContext: 'y' });
  const geminiWire = JSON.parse(JSON.stringify(gemini));
  assert.equal('temperature' in geminiWire, false);
  assert.equal(grok.temperature, 0);
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(grok))), [
    'model', 'messages', 'reasoning', 'temperature', 'max_tokens', 'stream', 'provider', 'response_format',
  ]);
});

test('consequential profile rejects final-verification change kinds', async () => {
  const source = await inlineSource();
  assert.throws(
    () => preflightReview({
      source,
      profile: 'consequential_spec_v1',
      changeKinds: ['spend'],
      policy: preflightPolicy,
    }),
    /changeKinds.*final_verification_v1/i,
  );
});

test('model-visible request-byte bounds are monotonic for ASCII and Unicode payloads', () => {
  const ascii = calculateConservativeMaxUsd({ requestBytes: Buffer.byteLength('abcdef', 'utf8'), maxRequestBytes: 200, maxTokens: 0, priceCeiling: { prompt: 1, completion: 1 } });
  const unicode = calculateConservativeMaxUsd({ requestBytes: Buffer.byteLength('😀😀', 'utf8'), maxRequestBytes: 200, maxTokens: 0, priceCeiling: { prompt: 1, completion: 1 } });
  assert.equal(ascii.actualRequestBytes, 6);
  assert.equal(unicode.actualRequestBytes, 8);
  assert.equal(ascii.modelVisibleInputTokenUpperBound, 6);
  assert.equal(unicode.modelVisibleInputTokenUpperBound, 8);
  assert.equal(unicode.maxUsd >= ascii.maxUsd, true);
});

test('conservative cost rounds each reviewer maximum upward to a micro-dollar', () => {
  const cost = calculateConservativeMaxUsd({
    requestBytes: 5,
    maxRequestBytes: 200,
    maxTokens: 0,
    priceCeiling: { prompt: 0.1, completion: 0.1 },
  });
  assert.equal(cost.unroundedMaxUsd, 0.0000005);
  assert.equal(cost.maxUsd, 0.000001);
  assert.equal(cost.pinnedCompletionTokens, 0);
});

test('preflight rejects an exact request that exceeds its configured request-byte cap', async () => {
  const source = await inlineSource();
  assert.throws(
    () => preflightReview({ source, profile: 'final_verification_v1', changeKinds: [], policy: { maxRequestBytes: 1 } }),
    /maxRequestBytes/i,
  );
});

test('preflight rejects a forged source digest before applying the registry-capability gate', () => {
  const forgedSource = { text: 'same request text', sourceSha256: '0'.repeat(64), sourceLabel: 'inline' };
  assert.throws(() => preflightReview({ source: forgedSource, profile: 'final_verification_v1', changeKinds: [] }), /sourceSha256.*source\.text/i);
});

test('preflight is no-credential, no-transport, and writes no raw source artifact', async () => {
  const inspectionDir = await mkdtemp(join(tmpdir(), 'openrouter-review-preflight-inspection-'));
  const raw = ['a', 'b'].join('\n');
  try {
    const source = await loadReviewSource({ source_text: raw }, policy);
    const touched = { persistence: 0, transport: 0, credential: 0 };
    const result = preflightReview(
      { source, profile: 'final_verification_v1', changeKinds: [], reviewContext: '', policy: preflightPolicy },
      {
        persistence: { append: () => { touched.persistence += 1; throw new Error('persistence touched'); } },
        transport: { dispatch: () => { touched.transport += 1; throw new Error('transport touched'); } },
        credentialStore: { read: () => { touched.credential += 1; throw new Error('credential touched'); } },
      },
    );
    assert.equal(result.reviewers.length, 1);
    assert.deepEqual(touched, { persistence: 0, transport: 0, credential: 0 });
    assert.deepEqual(await readdir(inspectionDir), []);
  } finally {
    await rm(inspectionDir, { recursive: true, force: true });
  }
});

test('a prompted_json reviewer omits response_format and require_parameters, and sends zdr/data_collection from its own registry entry', async () => {
  const { buildReviewRequest } = await import('../src/local-mcp/source-contract.mjs');
  const { REVIEWERS } = await import('../src/review-core/reviewer-registry.mjs');
  const reviewer = REVIEWERS.nemotron_super;
  const requestBody = buildReviewRequest({ reviewer, sourceText: 'design requirement', reviewContext: 'adversarial API review' });

  assert.equal('response_format' in requestBody, false);
  assert.deepEqual(requestBody.provider, {
    only: [reviewer.route],
    allow_fallbacks: false,
    require_parameters: false,
    zdr: false,
    data_collection: 'allow',
    max_price: { prompt: 0, completion: 0 },
  });
  assert.match(requestBody.messages[0].content, /verdict/);
  assert.match(requestBody.messages[0].content, /findings/);
});

test('a strict_schema reviewer (existing behavior) still gets the unmodified system prompt and response_format', async () => {
  const { buildReviewRequest, SYSTEM_PROMPT_FOR_TESTS } = await import('../src/local-mcp/source-contract.mjs');
  const reviewer = getReviewer('gemini');
  const requestBody = buildReviewRequest({ reviewer, sourceText: 'design requirement', reviewContext: 'adversarial API review' });
  assert.equal(requestBody.messages[0].content, SYSTEM_PROMPT_FOR_TESTS);
  assert.deepEqual(requestBody.response_format, RESPONSE_FORMAT);
});

// Every registered profile must reference only operational reviewers, so a future profile
// shipped against a still-shelved reviewer fails immediately rather than silently.
// getReviewer('kimi') itself still throws -- see openrouter-review-registry.test.mjs's own
// coverage of that.
test('every registered profile references only operational reviewers', async () => {
  const { PROFILES } = await import('../src/review-core/reviewer-registry.mjs');
  for (const registeredProfile of Object.values(PROFILES)) {
    for (const reviewerId of registeredProfile.reviewerIds) {
      assert.doesNotThrow(() => getReviewer(reviewerId), `${registeredProfile.id} references non-operational reviewer ${reviewerId}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Grok worst-case billing bound. A provider that bills hidden reasoning past max_tokens breaks a
// bound built on max_tokens: a response can report completion tokens (mostly reasoning) several
// times max_tokens and be billed for all of them. Grok 4.7 does not stop billing at max_tokens,
// and it exposes no reasoning token budget (only reasoning.effort; reasoning cannot be disabled).
// The endpoint publishes max_completion_tokens 450,000 but, since the provider does not honour
// max_tokens, the bound uses the one limit generation cannot pass: the 500,000-token context
// window (prompt plus completion). Prompts of 200,000 tokens or more are billed at a higher tier
// (4/M prompt, 12/M completion). Both per the provider's published endpoint listing
// (GET /api/v1/models/x-ai/grok-4.7/endpoints). The EXAMPLE_* figures below are a synthetic
// worked example of such a bill, chosen as round numbers.
// ---------------------------------------------------------------------------

const EXAMPLE_REQUEST_BYTES = 20_000;
const EXAMPLE_PROMPT_TOKENS = 6_000;
const EXAMPLE_COMPLETION_TOKENS = 100_000;
const EXAMPLE_BILLED_USD = 0.612;
const GROK_ENDPOINT_MAX_COMPLETION_TOKENS = 450_000;
const GROK_CONTEXT_LENGTH_TOKENS = 500_000;
const GROK_LONG_PROMPT_MIN_TOKENS = 200_000;

function listPriceUsd({ promptTokens, completionTokens, prompt, completion }) {
  return ((promptTokens * prompt) + (completionTokens * completion)) / 1_000_000;
}

function grokBoundFor(requestBytes) {
  const grok = getReviewer('grok');
  return calculateConservativeMaxUsd({
    requestBytes,
    maxRequestBytes: 4_194_304,
    maxTokens: grok.request.maxTokens,
    priceCeiling: { prompt: grok.priceCeiling.promptUsdPerMillionTokens, completion: grok.priceCeiling.completionUsdPerMillionTokens },
    worstCaseBilling: grok.worstCaseBilling,
  });
}

test('without a worst-case billing declaration the bound is max_tokens at the completion ceiling, and says so', () => {
  const cost = calculateConservativeMaxUsd({
    requestBytes: 100, maxRequestBytes: 1_000, maxTokens: 50, priceCeiling: { prompt: 1, completion: 2 },
  });
  assert.equal(cost.maxUsd, 0.0002);
  assert.equal(cost.pinnedCompletionTokens, 50);
  assert.equal(cost.billableCompletionTokenUpperBound, 50);
  assert.deepEqual(cost.appliedPriceUsdPerMillionTokens, { prompt: 1, completion: 2 });
  assert.equal(cost.costBoundScope, 'model_visible_request_and_pinned_completion_only');
});

test('a declared billable completion-token ceiling replaces max_tokens in the worst case', () => {
  const cost = calculateConservativeMaxUsd({
    requestBytes: 100,
    maxRequestBytes: 1_000,
    maxTokens: 50,
    priceCeiling: { prompt: 1, completion: 2 },
    worstCaseBilling: { completionTokenCeiling: 400 },
  });
  assert.equal(cost.pinnedCompletionTokens, 50);
  assert.equal(cost.billableCompletionTokenUpperBound, 400);
  assert.equal(cost.maxUsd, 0.0009);
  assert.equal(cost.costBoundScope, 'model_visible_request_and_declared_completion_ceiling');
});

test('a declared completion-token ceiling below max_tokens is rejected, since it could only shrink the bound', () => {
  assert.throws(
    () => calculateConservativeMaxUsd({
      requestBytes: 100, maxRequestBytes: 1_000, maxTokens: 50, priceCeiling: { prompt: 1, completion: 2 },
      worstCaseBilling: { completionTokenCeiling: 49 },
    }),
    /completionTokenCeiling/,
  );
  for (const bad of [0.5, -1, Number.NaN, '400', undefined]) {
    assert.throws(
      () => calculateConservativeMaxUsd({
        requestBytes: 100, maxRequestBytes: 1_000, maxTokens: 0, priceCeiling: { prompt: 1, completion: 2 },
        worstCaseBilling: { completionTokenCeiling: bad },
      }),
      /completionTokenCeiling/,
    );
  }
});

test('long-prompt tier rates apply once request bytes could reach the tier threshold, and never lower a rate', () => {
  const worstCaseBilling = {
    completionTokenCeiling: 10,
    longPromptPricing: { minPromptTokens: 1_000, promptUsdPerMillionTokens: 4, completionUsdPerMillionTokens: 12 },
  };
  const base = { maxRequestBytes: 10_000, maxTokens: 10, priceCeiling: { prompt: 2, completion: 6 }, worstCaseBilling };
  // Every model-visible token uses at least one request byte, so 999 bytes cannot hold 1,000 tokens.
  const below = calculateConservativeMaxUsd({ ...base, requestBytes: 999 });
  assert.deepEqual(below.appliedPriceUsdPerMillionTokens, { prompt: 2, completion: 6 });
  const atThreshold = calculateConservativeMaxUsd({ ...base, requestBytes: 1_000 });
  assert.deepEqual(atThreshold.appliedPriceUsdPerMillionTokens, { prompt: 4, completion: 12 });
  assert.equal(atThreshold.maxUsd, listPriceUsd({ promptTokens: 1_000, completionTokens: 10, prompt: 4, completion: 12 }));
  // A tier that is cheaper than the base ceiling on one axis never lowers that axis.
  const mixed = calculateConservativeMaxUsd({
    ...base,
    requestBytes: 1_000,
    worstCaseBilling: { completionTokenCeiling: 10, longPromptPricing: { minPromptTokens: 1_000, promptUsdPerMillionTokens: 1, completionUsdPerMillionTokens: 12 } },
  });
  assert.deepEqual(mixed.appliedPriceUsdPerMillionTokens, { prompt: 2, completion: 12 });
});

test('Grok declares its context window as the completion ceiling, plus its long-prompt tier; Gemini declares nothing', () => {
  assert.deepEqual(getReviewer('grok').worstCaseBilling, {
    completionTokenCeiling: GROK_CONTEXT_LENGTH_TOKENS,
    longPromptPricing: { minPromptTokens: GROK_LONG_PROMPT_MIN_TOKENS, promptUsdPerMillionTokens: 4, completionUsdPerMillionTokens: 12 },
  });
  assert.equal(getReviewer('gemini').worstCaseBilling, undefined);
});

test('worked example: a max_tokens-only bound falls short of a bill far above max_tokens, the declared Grok ceiling covers it', () => {
  const grok = getReviewer('grok');
  const oldBound = calculateConservativeMaxUsd({
    requestBytes: EXAMPLE_REQUEST_BYTES,
    maxRequestBytes: 4_194_304,
    maxTokens: grok.request.maxTokens,
    priceCeiling: { prompt: 2, completion: 6 },
  });
  assert.equal(oldBound.maxUsd, 0.236608);
  assert.equal(
    listPriceUsd({ promptTokens: EXAMPLE_PROMPT_TOKENS, completionTokens: EXAMPLE_COMPLETION_TOKENS, prompt: 2, completion: 6 }) >= EXAMPLE_BILLED_USD - 1e-9,
    true,
  );
  const newBound = grokBoundFor(EXAMPLE_REQUEST_BYTES);
  assert.equal(newBound.maxUsd >= EXAMPLE_BILLED_USD, true);
  assert.equal(Math.abs(newBound.maxUsd - 3.04) < 0.000002, true);
});

test('Grok\'s bound covers every prompt and completion size its endpoint can bill, at either price tier', () => {
  for (const requestBytes of [1, EXAMPLE_REQUEST_BYTES, GROK_LONG_PROMPT_MIN_TOKENS - 1, GROK_LONG_PROMPT_MIN_TOKENS, 4_194_304]) {
    const bound = grokBoundFor(requestBytes);
    for (const promptTokens of [0, Math.floor(requestBytes / 2), requestBytes]) {
      const longTier = promptTokens >= GROK_LONG_PROMPT_MIN_TOKENS;
      const contextRemainder = Math.max(0, GROK_CONTEXT_LENGTH_TOKENS - promptTokens);
      for (const completionTokens of [0, 32_768, EXAMPLE_COMPLETION_TOKENS, GROK_ENDPOINT_MAX_COMPLETION_TOKENS, contextRemainder]) {
        const billed = listPriceUsd({ promptTokens, completionTokens, prompt: longTier ? 4 : 2, completion: longTier ? 12 : 6 });
        assert.equal(bound.maxUsd >= billed, true, `requestBytes=${requestBytes} prompt=${promptTokens} completion=${completionTokens}`);
      }
    }
  }
});

test('Gemini\'s preflight bound is unchanged: request bytes at its prompt ceiling plus its own max_tokens', async () => {
  const source = await inlineSource();
  const computed = preflightReview({ source, profile: 'consequential_spec_v1', reviewContext: 'scope', policy: preflightPolicy });
  const gemini = computed.reviewers.find((item) => item.reviewerId === 'gemini');
  const expected = Math.ceil(((gemini.requestBytes * 1.5) + (65_536 * 7.5))) / 1_000_000;
  assert.equal(gemini.maxUsd, expected);
  assert.equal(gemini.cost.billableCompletionTokenUpperBound, 65_536);
});

test('the Grok request actually sent is unchanged: same max_tokens, max_price, reasoning and keys', () => {
  const grok = buildReviewRequest({ reviewer: getReviewer('grok'), sourceText: 'x', reviewContext: 'y' });
  assert.equal(grok.max_tokens, 32_768);
  assert.deepEqual(grok.reasoning, { effort: 'high' });
  assert.deepEqual(grok.provider.max_price, { prompt: 2, completion: 6 });
  assert.equal(JSON.stringify(grok).includes('worstCaseBilling'), false);
  assert.equal(JSON.stringify(grok).includes('completionTokenCeiling'), false);
  // The bound prices prompt and completion only. The endpoint's one other surcharge, web_search,
  // is billed only when a request turns web search on, so the request must never do that.
  for (const webSearchTrigger of ['plugins', 'tools', 'tool_choice', 'web_search_options']) {
    assert.equal(webSearchTrigger in grok, false, `${webSearchTrigger} would enable a billable component the bound does not price`);
  }
  assert.equal(grok.model.includes(':online'), false);
});

test('a Grok preflight reserves at least a full context window of completion, so the example bill far above max_tokens fits', async () => {
  const source = await inlineSource();
  const computed = preflightReview({ source, profile: 'final_verification_v1', changeKinds: [], policy: preflightPolicy });
  const [grok] = computed.reviewers;
  assert.equal(grok.reviewerId, 'grok');
  assert.equal(grok.cost.billableCompletionTokenUpperBound, GROK_CONTEXT_LENGTH_TOKENS);
  assert.equal(grok.maxUsd >= listPriceUsd({ promptTokens: grok.requestBytes, completionTokens: GROK_CONTEXT_LENGTH_TOKENS, prompt: 2, completion: 6 }), true);
  assert.equal(grok.maxUsd >= EXAMPLE_BILLED_USD, true);
});
