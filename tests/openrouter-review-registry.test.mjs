import assert from 'node:assert/strict';
import test from 'node:test';
import {
  getProfile,
  getReviewer,
  PROFILES,
  QUALIFICATION_REFERENCE_SHA256,
  REGISTRY_SHA256,
  REVIEWERS,
} from '../src/review-core/reviewer-registry.mjs';
import { SCHEMA_SHA256 } from '../src/review-core/advisory-schema.mjs';

test('operational reviewers pin the qualified Gemini and Grok routes and request controls', () => {
  assert.deepEqual(getReviewer('gemini'), {
    id: 'gemini',
    status: 'operational',
    model: 'google/gemini-3.8-flash',
    route: 'google-vertex/global',
    expectedProvider: 'Google',
    request: {
      reasoning: { effort: 'high' },
      maxTokens: 65536,
      stream: false,
      provider: {
        zdr: true,
        dataCollection: 'deny',
        requireParameters: true,
        allowFallbacks: false,
      },
    },
    priceCeiling: { promptUsdPerMillionTokens: 1.5, completionUsdPerMillionTokens: 7.5 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
  });

  assert.deepEqual(getReviewer('grok'), {
    id: 'grok',
    status: 'operational',
    model: 'x-ai/grok-4.7',
    route: 'xai/zdr',
    expectedProvider: 'xAI',
    request: {
      reasoning: { effort: 'high' },
      temperature: 0,
      maxTokens: 32768,
      stream: false,
      provider: {
        zdr: true,
        dataCollection: 'deny',
        requireParameters: true,
        allowFallbacks: false,
      },
    },
    priceCeiling: { promptUsdPerMillionTokens: 2, completionUsdPerMillionTokens: 6 },
    worstCaseBilling: {
      completionTokenCeiling: 500000,
      longPromptPricing: { minPromptTokens: 200000, promptUsdPerMillionTokens: 4, completionUsdPerMillionTokens: 12 },
    },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
  });
});

test('profiles are fixed policy rather than caller-supplied model lists', () => {
  assert.deepEqual(getProfile('consequential_spec_v1'), {
    id: 'consequential_spec_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  });
  assert.deepEqual(getProfile('final_verification_v1'), {
    id: 'final_verification_v1',
    version: '1',
    reviewerIds: ['grok'],
    reviewerIdsForChangeKinds: {
      api_contract: ['grok', 'gemini'],
      major_remediation: ['grok', 'gemini'],
      serialization: ['grok', 'gemini'],
      spend: ['grok', 'gemini'],
      token_unit_math: ['grok', 'gemini'],
    },
  });
});

test('Kimi remains shelved and unlisted reviewer families are absent', () => {
  assert.throws(() => getReviewer('kimi'), /not operational/i);
  for (const reviewerId of ['deepseek', 'qwen', 'glm']) {
    assert.throws(() => getReviewer(reviewerId), /unknown reviewer/i);
  }
  assert.throws(() => getProfile('caller-selected-models'), /unknown profile/i);
});

test('inherited object keys are rejected as unknown reviewer and profile IDs', () => {
  for (const inheritedId of ['toString', 'constructor']) {
    assert.throws(() => getReviewer(inheritedId), new RegExp(`^Error: unknown reviewer: ${inheritedId}$`));
    assert.throws(() => getProfile(inheritedId), new RegExp(`^Error: unknown profile: ${inheritedId}$`));
  }
});

test('registry and qualification digests are pinned lowercase SHA-256 values', () => {
  assert.match(REGISTRY_SHA256, /^[a-f0-9]{64}$/);
  assert.equal(QUALIFICATION_REFERENCE_SHA256, 'ed903acc46ea9c96559f36db2ca8021b864574ee808631705ee357aeec4ee01f');
});

test('existing operational reviewers have no outputMode or trustTier field (untouched by the new tier)', () => {
  assert.equal('outputMode' in getReviewer('gemini'), false);
  assert.equal('outputMode' in getReviewer('grok'), false);
  assert.equal('trustTier' in getReviewer('gemini'), false);
  assert.equal('trustTier' in getReviewer('grok'), false);
});

// Pins the operational state of the two promoted free-tier reviewers.
test('the two promoted free-tier candidates are operational, untrusted, and prompted-json mode', () => {
  for (const reviewerId of ['nemotron_super', 'nemotron_ultra']) {
    assert.doesNotThrow(() => getReviewer(reviewerId));
  }
  assert.equal(REVIEWERS.nemotron_super.status, 'operational');
  assert.equal(REVIEWERS.nemotron_super.trustTier, 'untrusted');
  assert.equal(REVIEWERS.nemotron_super.outputMode, 'prompted_json');
  assert.equal(REVIEWERS.nemotron_super.model, 'nvidia/nemotron-3-super-120b-a12b:free');
  assert.equal(REVIEWERS.nemotron_super.request.provider.zdr, false);
  assert.equal(REVIEWERS.nemotron_super.request.provider.requireParameters, false);
  assert.equal(REVIEWERS.nemotron_super.priceCeiling.promptUsdPerMillionTokens, 0);
  assert.equal(REVIEWERS.nemotron_super.priceCeiling.completionUsdPerMillionTokens, 0);

  assert.equal(REVIEWERS.nemotron_ultra.status, 'operational');
  assert.equal(REVIEWERS.nemotron_ultra.trustTier, 'untrusted');
  assert.equal(REVIEWERS.nemotron_ultra.outputMode, 'prompted_json');
  assert.equal(REVIEWERS.nemotron_ultra.model, 'nvidia/nemotron-3-ultra-550b-a55b:free');
});

// Four of the free-tier candidates did not qualify and are shelved, matching kimi's own shelved
// shape (status + reason).
test('the four failed candidates are shelved with reasons', () => {
  const failedIds = ['gemma4', 'laguna', 'inkling', 'north_mini_code'];
  for (const reviewerId of failedIds) {
    assert.throws(() => getReviewer(reviewerId), /not operational/, `${reviewerId} should not be dispatchable`);
    const reviewer = REVIEWERS[reviewerId];
    assert.equal(reviewer.status, 'shelved', `${reviewerId}.status`);
    assert.equal(typeof reviewer.reason, 'string', `${reviewerId}.reason should be a string`);
    assert.ok(reviewer.reason.length > 0, `${reviewerId}.reason should not be empty`);
  }

  assert.equal(REVIEWERS.gemma4.model, 'google/gemma-4-31b-it:free');
  assert.equal(REVIEWERS.laguna.model, 'poolside/laguna-s-2.1:free');
  assert.equal(REVIEWERS.inkling.model, 'thinkingmachines/inkling:free');
  assert.equal(REVIEWERS.north_mini_code.model, 'cohere/north-mini-code:free');
});

// nemotron_lightning qualified alongside those candidates and stays operational while its four
// siblings above are shelved.
test('nemotron_lightning remains operational', () => {
  assert.doesNotThrow(() => getReviewer('nemotron_lightning'));
  assert.equal(REVIEWERS.nemotron_lightning.status, 'operational');
  assert.equal(REVIEWERS.nemotron_lightning.trustTier, 'untrusted');
  assert.equal(REVIEWERS.nemotron_lightning.outputMode, 'prompted_json');
  assert.equal(REVIEWERS.nemotron_lightning.model, 'nvidia/nemotron-3.5-lightning:free');
});

// At the shared 32,768-token untrusted-tier ceiling this model can return HTTP 200 with
// finish_reason:"length" and a null content field -- it spends its entire completion budget
// reasoning and never reaches the answer. OpenRouter's
// GET /api/v1/models/cohere/north-mini-code:free/endpoints reports max_completion_tokens:64000
// for this specific endpoint, so only north_mini_code's own request budget is raised to that
// ceiling; every other untrusted reviewer still uses the shared UNTRUSTED_TIER_REQUEST_CONTROLS.
// This is a targeted, single-reviewer override, not a blanket policy change.
test('north_mini_code has a raised completion-token budget, other untrusted reviewers unchanged', () => {
  assert.equal(REVIEWERS.north_mini_code.request.maxTokens, 64000);
  for (const reviewerId of ['gemma4', 'nemotron_lightning', 'laguna', 'inkling', 'nemotron_super', 'nemotron_ultra']) {
    assert.equal(REVIEWERS[reviewerId].request.maxTokens, 32768, `${reviewerId}.request.maxTokens should stay unchanged`);
  }
  // Every other field on north_mini_code's request (besides maxTokens and reasoning.effort,
  // covered by the dedicated test below) must still exactly match the shared untrusted-tier
  // controls.
  const { maxTokens: _ignoredBudget, reasoning: _ignoredReasoning, ...restOfNorthMiniCodeRequest } = REVIEWERS.north_mini_code.request;
  const { maxTokens: _ignoredSharedBudget, reasoning: _ignoredSharedReasoning, ...restOfSharedRequest } = REVIEWERS.gemma4.request;
  assert.deepEqual(restOfNorthMiniCodeRequest, restOfSharedRequest);
});

// Even at its endpoint's 64000-token completion ceiling (which cannot be raised further) the
// model can still hit finish_reason:"length", so reasoning effort is lowered for this reviewer to
// leave room in its completion budget for the answer itself.
test('north_mini_code also has a lowered reasoning effort, other untrusted reviewers unchanged', () => {
  assert.equal(REVIEWERS.north_mini_code.request.reasoning.effort, 'low');
  for (const reviewerId of ['gemma4', 'nemotron_lightning', 'laguna', 'inkling', 'nemotron_super', 'nemotron_ultra']) {
    assert.equal(REVIEWERS[reviewerId].request.reasoning.effort, 'high', `${reviewerId}.request.reasoning.effort should stay unchanged`);
  }
  // Every other field besides maxTokens and reasoning.effort must still match the shared
  // untrusted-tier controls exactly.
  const { maxTokens: _ignoredBudget, reasoning: _ignoredReasoning, ...restOfNorthMiniCodeRequest } = REVIEWERS.north_mini_code.request;
  const { maxTokens: _ignoredSharedBudget, reasoning: _ignoredSharedReasoning, ...restOfSharedRequest } = REVIEWERS.gemma4.request;
  assert.deepEqual(restOfNorthMiniCodeRequest, restOfSharedRequest);
});

test('the five new candidates are excluded from every existing profile', () => {
  const newIds = new Set(['gemma4', 'nemotron_lightning', 'laguna', 'inkling', 'north_mini_code']);
  for (const profileId of ['consequential_spec_v1', 'final_verification_v1', 'free_tier_experimental_v1', 'free_tier_experimental_ultra_only_v1']) {
    const profile = getProfile(profileId);
    for (const reviewerId of profile.reviewerIds) {
      assert.equal(newIds.has(reviewerId), false, `${profileId} should not reference ${reviewerId}`);
    }
  }
});

test('nemotron_lightning_only_v1 profile still exists, targeting the still-operational reviewer', () => {
  assert.deepEqual(getProfile('free_tier_experimental_nemotron_lightning_only_v1'), {
    id: 'free_tier_experimental_nemotron_lightning_only_v1',
    version: '1',
    reviewerIds: ['nemotron_lightning'],
  });
});

// The single-reviewer profiles for the four shelved candidates are removed.
// nemotron_lightning_only_v1 stays, since nemotron_lightning remains operational.
test('the four now-dead single-reviewer profiles for shelved candidates no longer exist', () => {
  for (const profileId of [
    'free_tier_experimental_gemma4_only_v1',
    'free_tier_experimental_laguna_only_v1',
    'free_tier_experimental_inkling_only_v1',
    'free_tier_experimental_north_mini_code_only_v1',
  ]) {
    assert.throws(() => getProfile(profileId), /unknown profile/, `${profileId} should no longer exist`);
  }
});

// Of the five free-tier candidates added together, only nemotron_lightning remains dispatchable.
test('only nemotron_lightning is dispatchable among the free candidates', () => {
  assert.doesNotThrow(() => getReviewer('nemotron_lightning'));
  for (const reviewerId of ['gemma4', 'laguna', 'inkling', 'north_mini_code']) {
    assert.throws(() => getReviewer(reviewerId), /not operational/, `${reviewerId} should no longer be dispatchable`);
  }
});

test('nemotron reviewers expect the exact provider casing OpenRouter actually returns', () => {
  // Regression guard: OpenRouter's response body carries `provider: "Nvidia"`
  // (title case), and review-engine.mjs's provider check
  // (`parsedBody.provider !== reviewer.expectedProvider`) is exact string equality
  // by design, so an all-caps 'NVIDIA' in the registry would produce a false
  // PROVIDER_MISMATCH halt on an otherwise valid, successfully-decoded response.
  assert.equal(REVIEWERS.nemotron_super.expectedProvider, 'Nvidia');
  assert.equal(REVIEWERS.nemotron_ultra.expectedProvider, 'Nvidia');
});

test('free_tier_experimental_v1 profile lists both nemotron candidates', () => {
  assert.deepEqual(getProfile('free_tier_experimental_v1'), {
    id: 'free_tier_experimental_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra'],
  });
});

// free_tier_experimental_v1 dispatches its reviewerIds in order and halts on the first
// failure, so a failing nemotron_super would keep nemotron_ultra from ever being reached. This
// profile targets ultra alone, without depending on super succeeding first. Purely
// additive: does not touch either existing candidate's own registry entry or either
// paid-tier profile, and (like free_tier_experimental_v1 itself) is unreachable until a
// human explicitly selects it -- both reviewer entries' own `status` gate still applies.
test('free_tier_experimental_ultra_only_v1 profile targets nemotron_ultra alone', () => {
  assert.deepEqual(getProfile('free_tier_experimental_ultra_only_v1'), {
    id: 'free_tier_experimental_ultra_only_v1',
    version: '1',
    reviewerIds: ['nemotron_ultra'],
  });
});

test('existing profiles are unaffected by the new reviewers', () => {
  assert.deepEqual(getProfile('consequential_spec_v1').reviewerIds, ['gemini', 'grok']);
  assert.deepEqual(getProfile('final_verification_v1').reviewerIds, ['grok']);
});

test('impl_review_v1 pairs the two paid reviewers, in gemini-then-grok order', () => {
  assert.deepEqual(getProfile('impl_review_v1'), {
    id: 'impl_review_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  });
});

test('impl_review_free_v1 lists all three qualified Nemotron reviewers', () => {
  assert.deepEqual(getProfile('impl_review_free_v1'), {
    id: 'impl_review_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  });
});

// reviewerIdsForChangeKinds is honored only for the literal profile id 'final_verification_v1'
// (source-contract.mjs:145). A map on any other profile is silently ignored, so its ABSENCE
// here is deliberate and worth pinning.
test('the implementation-review profiles carry no reviewerIdsForChangeKinds, which would be silently ignored', () => {
  assert.equal('reviewerIdsForChangeKinds' in getProfile('impl_review_v1'), false);
  assert.equal('reviewerIdsForChangeKinds' in getProfile('impl_review_free_v1'), false);
});

// Each review stage (spec, plan, implementation, code rescue, final verification) has a paid
// profile and a free-tier counterpart.
test('spec_review_free_v1 is the free-tier counterpart to consequential_spec_v1 for spec review', () => {
  assert.deepEqual(getProfile('spec_review_free_v1'), {
    id: 'spec_review_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  });
});

test('plan_review_v1 is a paid profile for plan review, matching the spec-review shape', () => {
  assert.deepEqual(getProfile('plan_review_v1'), {
    id: 'plan_review_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  });
});

test('plan_review_free_v1 is the free counterpart to plan_review_v1', () => {
  assert.deepEqual(getProfile('plan_review_free_v1'), {
    id: 'plan_review_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  });
});

test('code_rescue_v1 is a paid profile for code-rescue review', () => {
  assert.deepEqual(getProfile('code_rescue_v1'), {
    id: 'code_rescue_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  });
});

test('code_rescue_free_v1 is the free counterpart to code_rescue_v1', () => {
  assert.deepEqual(getProfile('code_rescue_free_v1'), {
    id: 'code_rescue_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  });
});

test('final_verification_free_v1 is the free-tier counterpart to final_verification_v1, with no change-kind branching', () => {
  assert.deepEqual(getProfile('final_verification_free_v1'), {
    id: 'final_verification_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  });
});

test('none of the 6 new profiles carry reviewerIdsForChangeKinds', () => {
  for (const profileId of [
    'spec_review_free_v1', 'plan_review_v1', 'plan_review_free_v1',
    'code_rescue_v1', 'code_rescue_free_v1', 'final_verification_free_v1',
  ]) {
    assert.equal('reviewerIdsForChangeKinds' in getProfile(profileId), false, `${profileId} should not have reviewerIdsForChangeKinds`);
  }
});

test('all 6 new profile ids are visible to the generic PROFILE_IDS derivation mcp-schemas.mjs uses', () => {
  const newIds = [
    'spec_review_free_v1', 'plan_review_v1', 'plan_review_free_v1',
    'code_rescue_v1', 'code_rescue_free_v1', 'final_verification_free_v1',
  ];
  for (const id of newIds) {
    assert.ok(Object.keys(PROFILES).includes(id), `${id} should be a key of PROFILES`);
  }
});
