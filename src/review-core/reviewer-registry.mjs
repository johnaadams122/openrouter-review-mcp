import { createHash } from 'node:crypto';
import { SCHEMA_SHA256 } from './advisory-schema.mjs';

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

const QUALIFICATION_REFERENCE = deepFreeze({
  document: 'qualification-reference-v1',
  sha256: 'ed903acc46ea9c96559f36db2ca8021b864574ee808631705ee357aeec4ee01f',
});

export const QUALIFICATION_REFERENCE_SHA256 = QUALIFICATION_REFERENCE.sha256;
export const PROMPT_VERSION = 'advisory_review_prompt_v1';

const FIXED_REQUEST_CONTROLS = deepFreeze({
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
});

// Untrusted-tier requests set zdr: false and dataCollection: 'allow' instead of the
// strict tier's zdr: true / 'deny', because free endpoints generally do not offer a
// zero-data-retention route; that is why this tier is kept separate. They also do
// NOT set requireParameters: true -- a free endpoint may not support every
// field FIXED_REQUEST_CONTROLS assumes (e.g. `reasoning.effort`), and
// requireParameters: true would make OpenRouter refuse to route at all rather than
// dropping an unsupported field. Untrusted-tier reviewers are best-effort by design;
// a field the endpoint ignores is an acceptable degradation, a refused route is not.
const UNTRUSTED_TIER_REQUEST_CONTROLS = deepFreeze({
  reasoning: { effort: 'high' },
  temperature: 0,
  maxTokens: 32768,
  stream: false,
  provider: {
    zdr: false,
    dataCollection: 'allow',
    requireParameters: false,
    allowFallbacks: false,
  },
});

// Gemini 3.8 Flash does not declare `temperature` on google-vertex/global
// (nor do 3.6 or 3.7 Flash -- this is a property of the modern Vertex Flash
// line, not a quirk of one build). With require_parameters:true and
// allow_fallbacks:false, sending a parameter the endpoint does not declare
// makes OpenRouter refuse to route at all. Derived by rest-destructure rather
// than hand-written so the provider privacy block stays the SAME frozen object
// as the strict tier -- a future change to zdr/dataCollection/requireParameters
// propagates here automatically instead of silently applying to Grok only.
// NOTE: check the endpoint list, never the model-level list -- the model-level
// supported_parameters is a union across endpoints and DOES include temperature
// (the AI Studio endpoints declare it; those are closed off by zdr:true).
const { temperature: _temperatureNotDeclaredOnThisEndpoint, ...GEMINI_FLASH_CONTROLS_BASE } =
  FIXED_REQUEST_CONTROLS;
const GEMINI_FLASH_REQUEST_CONTROLS = deepFreeze({
  ...GEMINI_FLASH_CONTROLS_BASE,
  maxTokens: 65536,
});

export const REVIEWERS = deepFreeze({
  gemini: {
    id: 'gemini',
    status: 'operational',
    model: 'google/gemini-3.8-flash',
    route: 'google-vertex/global',
    expectedProvider: 'Google',
    request: GEMINI_FLASH_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 1.5, completionUsdPerMillionTokens: 7.5 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
  },
  grok: {
    id: 'grok',
    status: 'operational',
    model: 'x-ai/grok-4.7',
    route: 'xai/zdr',
    expectedProvider: 'xAI',
    request: FIXED_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 2, completionUsdPerMillionTokens: 6 },
    // Reservation-only (never sent): Grok 4.7 does not stop billing at request.maxTokens.
    // A request can bill completion tokens (mostly reasoning) well beyond its max_tokens, and the
    // model exposes no reasoning token budget (effort only; reasoning cannot be disabled). The
    // endpoint publishes max_completion_tokens 450000, but a provider that ignored one published
    // limit is not trusted with another, so the worst case uses the 500000-token context window
    // (prompt plus completion cannot exceed it), plus the >=200k-prompt-token price tier. Both read
    // from GET /api/v1/models/x-ai/grok-4.7/endpoints (xai/zdr). Re-check both on any model or
    // route change.
    // Scope: that endpoint's complete published price list was prompt, completion, web_search,
    // input_cache_read and discount 0 (overrides: the same keys at the long-prompt tier). Reasoning is
    // billed as completion; a cache read is cheaper than the prompt rate; web_search is only billed
    // when a request enables web search, which this request never does (its exact keys are pinned
    // in tests/openrouter-review-preflight.test.mjs). A price component added later is outside this
    // bound and can only be caught at reconciliation.
    worstCaseBilling: {
      completionTokenCeiling: 500000,
      longPromptPricing: { minPromptTokens: 200000, promptUsdPerMillionTokens: 4, completionUsdPerMillionTokens: 12 },
    },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
  },
  kimi: {
    id: 'kimi',
    status: 'shelved',
    model: 'moonshotai/kimi-k3',
    route: 'modal/mxfp4',
    expectedProvider: 'Modal',
    reason: 'dense-document reasoning-high strict-schema qualification exhausted output without valid content',
  },
  nemotron_super: {
    id: 'nemotron_super',
    status: 'operational',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'nvidia/nemotron-3-super-120b-a12b:free',
    // Per GET /api/v1/models/nvidia/nemotron-3-super-120b-a12b:free/endpoints:
    // provider_name "Nvidia", tag "nvidia", status 0 (healthy).
    route: 'nvidia',
    // 'Nvidia' (title case), not 'NVIDIA' -- matches the exact provider string a
    // real response body carries; this check is exact string equality, so the
    // wrong casing alone would false-halt an otherwise valid response with
    // PROVIDER_MISMATCH.
    expectedProvider: 'Nvidia',
    request: UNTRUSTED_TIER_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'qualified in live review testing; returns schema-valid prompted JSON with usable findings',
  },
  nemotron_ultra: {
    id: 'nemotron_ultra',
    status: 'operational',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'nvidia/nemotron-3-ultra-550b-a55b:free',
    // Per GET /api/v1/models/nvidia/nemotron-3-ultra-550b-a55b:free/endpoints:
    // provider_name "Nvidia", tag "nvidia". The endpoint has reported status -2 (degraded) at
    // times, so a dispatch may fail for endpoint-health reasons unrelated to model quality.
    route: 'nvidia',
    // 'Nvidia' (title case), not 'NVIDIA' -- matches the exact provider string a
    // real response body carries; this check is exact string equality, so the
    // wrong casing alone would false-halt an otherwise valid response with
    // PROVIDER_MISMATCH.
    expectedProvider: 'Nvidia',
    request: UNTRUSTED_TIER_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'qualified in live review testing; returns schema-valid prompted JSON with usable findings',
  },
  // Further untrusted-tier candidates, same untrusted/prompted_json shape as the Nemotron
  // entries above. Only candidates whose training organization hosts the endpoint are listed
  // (checked via GET /api/v1/models/{id}/endpoints' provider_name/tag fields), one
  // representative per model family, so each can be qualified in isolation.
  //
  // Every route/expectedProvider value below comes from the /endpoints metadata's
  // provider_name/tag fields, not from a real dispatch. That metadata can differ from the
  // provider string a real response body carries (it suggests 'NVIDIA' for the Nemotron
  // entries, while real responses carry 'Nvidia'), so treat these values as starting points
  // to confirm against a live response, not as confirmed facts.
  gemma4: {
    id: 'gemma4',
    status: 'shelved',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'google/gemma-4-31b-it:free',
    // Per GET /api/v1/models/google/gemma-4-31b-it:free/endpoints:
    // provider_name "Google AI Studio", tag "google-ai-studio", status 0 (healthy). This
    // endpoint's own supported_parameters list DOES include structured_outputs -- unlike the
    // other four candidates here, it could in principle take the same strict response_format
    // path Gemini/Grok use. Deliberately NOT done yet: UNTRUSTED_TIER_REQUEST_CONTROLS fixes
    // requireParameters:false for every untrusted-tier reviewer (so an unsupported field
    // degrades gracefully instead of refusing to route at all), which means response_format
    // alone would only be best-effort here anyway, not truly enforced -- prompted_json's
    // explicit in-prompt schema instructions are the more reliable choice until this
    // candidate has qualification data showing the strict path is actually more reliable
    // for this endpoint, not merely possible.
    route: 'google-ai-studio',
    expectedProvider: 'Google AI Studio',
    request: UNTRUSTED_TIER_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'repeated HTTP 429 from Google AI Studio\'s shared free pool during live qualification -- standing capacity condition, not a capability failure; retryable after a real time gap, not disqualified on merit',
  },
  nemotron_lightning: {
    id: 'nemotron_lightning',
    status: 'operational',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'nvidia/nemotron-3.5-lightning:free',
    // Per GET /api/v1/models/nvidia/nemotron-3.5-lightning:free/endpoints:
    // provider_name "Nvidia", tag "nvidia/nvfp4" (NOT the bare "nvidia" tag nemotron_super/
    // nemotron_ultra use -- a different NVIDIA-hosted model can carry a different tag; do not
    // assume every NVIDIA entry shares one route value).
    route: 'nvidia/nvfp4',
    expectedProvider: 'Nvidia',
    request: UNTRUSTED_TIER_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'qualified in live review testing; returns schema-valid prompted JSON with usable findings',
  },
  laguna: {
    id: 'laguna',
    status: 'shelved',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'poolside/laguna-s-2.1:free',
    // Per GET /api/v1/models/poolside/laguna-s-2.1:free/endpoints:
    // provider_name "Poolside", tag "poolside/fp4", status 0 (healthy). No provider for this
    // model declares structured_outputs, so it cannot use the strict response_format path;
    // the untrusted/prompted_json tier does not need it. Poolside is a code-focused model
    // family, a plausible fit for code/spec review.
    route: 'poolside/fp4',
    expectedProvider: 'Poolside',
    request: UNTRUSTED_TIER_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'repeated HTTP 429 from Poolside\'s shared free pool during live qualification -- same standing-capacity shape as gemma4, not a capability failure',
  },
  inkling: {
    id: 'inkling',
    status: 'shelved',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'thinkingmachines/inkling:free',
    // Per GET /api/v1/models/thinkingmachines/inkling:free/endpoints:
    // provider_name "Thinking Machines", tag "thinkingmachines/nvfp4", status 0 (healthy).
    route: 'thinkingmachines/nvfp4',
    expectedProvider: 'Thinking Machines',
    request: UNTRUSTED_TIER_REQUEST_CONTROLS,
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'structural HTTP 403 ("only available on agentic harnesses") during live qualification, tied to this pipeline\'s deliberate omission of Referer/X-Title headers for privacy -- very likely a permanent mismatch, not a transient fault',
  },
  north_mini_code: {
    id: 'north_mini_code',
    status: 'shelved',
    trustTier: 'untrusted',
    outputMode: 'prompted_json',
    model: 'cohere/north-mini-code:free',
    // Per GET /api/v1/models/cohere/north-mini-code:free/endpoints:
    // provider_name "Cohere", tag "cohere", status 0 (healthy). Another code-focused model,
    // like Poolside's Laguna above.
    route: 'cohere',
    expectedProvider: 'Cohere',
    // A live qualification attempt at the shared UNTRUSTED_TIER_REQUEST_CONTROLS maxTokens
    // (32768) got HTTP 200 back with finish_reason:"length" and a null content field -- this
    // model spent its entire completion budget reasoning through the document and never
    // reached the answer. The same live endpoint check reports max_completion_tokens:64000
    // for this specific endpoint, so only this reviewer's own budget is raised to that
    // ceiling; no other untrusted-tier candidate has shown this symptom.
    //
    // A retry at maxTokens:64000 still hit finish_reason:"length" (nearly the whole budget
    // spent, mostly on reasoning) -- partial content this time, but cut off mid-JSON, at this
    // endpoint's own hard ceiling with no larger value to request. Lowering reasoning.effort
    // trades reasoning depth for room to actually finish the answer; untested whether this
    // preserves finding quality.
    request: deepFreeze({ ...UNTRUSTED_TIER_REQUEST_CONTROLS, maxTokens: 64000, reasoning: { effort: 'low' } }),
    priceCeiling: { promptUsdPerMillionTokens: 0, completionUsdPerMillionTokens: 0 },
    schemaSha256: SCHEMA_SHA256,
    qualificationReferenceSha256: QUALIFICATION_REFERENCE_SHA256,
    reason: 'cannot finish a review of a mid-size document within this endpoint\'s maximum completion tokens, even at reasoning.effort low',
  },
});

export const PROFILES = deepFreeze({
  consequential_spec_v1: {
    id: 'consequential_spec_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  },
  final_verification_v1: {
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
  },
  // Free-tier counterpart to consequential_spec_v1 (spec review).
  spec_review_free_v1: {
    id: 'spec_review_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  },
  // Implementation review, run after each completed task (the most frequently used profile).
  // Deliberately NO reviewerIdsForChangeKinds: source-contract.mjs:145 honors that field only
  // for the literal id 'final_verification_v1', so a map here would be silently ignored rather
  // than narrowing anything.
  impl_review_v1: {
    id: 'impl_review_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  },
  // The free-tier second opinion for implementation review. Separate profile, not extra reviewerIds on
  // impl_review_v1, because a profile halts on its first reviewer failure -- interleaving the
  // free tier with the paid pair would let a free-tier outage suppress a paid review.
  impl_review_free_v1: {
    id: 'impl_review_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  },
  // Plan review (paid and free tier). Shaped like consequential_spec_v1 (plan review judges a document's internal quality, same as spec
  // review, not a diff) rather than impl_review_v1.
  plan_review_v1: {
    id: 'plan_review_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  },
  plan_review_free_v1: {
    id: 'plan_review_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  },
  // Code-rescue review (paid and free tier).
  code_rescue_v1: {
    id: 'code_rescue_v1',
    version: '1',
    reviewerIds: ['gemini', 'grok'],
  },
  code_rescue_free_v1: {
    id: 'code_rescue_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  },
  // Free-tier counterpart to final_verification_v1 (final verification). Deliberately no
  // reviewerIdsForChangeKinds -- the free reviewers already all run together regardless of
  // change kind, matching impl_review_free_v1's own shape.
  final_verification_free_v1: {
    id: 'final_verification_free_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra', 'nemotron_lightning'],
  },
  free_tier_experimental_v1: {
    id: 'free_tier_experimental_v1',
    version: '1',
    reviewerIds: ['nemotron_super', 'nemotron_ultra'],
  },
  // A profile dispatches its reviewerIds in order and halts on the first failure, so a
  // nemotron_super failure in the profile above keeps nemotron_ultra from running. This
  // profile targets nemotron_ultra alone so it can be qualified without depending on
  // nemotron_super succeeding first.
  free_tier_experimental_ultra_only_v1: {
    id: 'free_tier_experimental_ultra_only_v1',
    version: '1',
    reviewerIds: ['nemotron_ultra'],
  },
  // Single-reviewer profile so a candidate can be qualified in isolation; a multi-reviewer
  // profile halts on its first reviewer failure. Its reviewer is operational, so the profile is
  // accepted by the normal preflight flow and any dispatch goes through the same approval and
  // spend-cap machinery as every other profile. getReviewer() still refuses any reviewer whose
  // status is not 'operational' (e.g. the shelved candidates above), which is why no
  // single-reviewer profile is defined for them.
  free_tier_experimental_nemotron_lightning_only_v1: {
    id: 'free_tier_experimental_nemotron_lightning_only_v1',
    version: '1',
    reviewerIds: ['nemotron_lightning'],
  },
});

export const REGISTRY_SHA256 = sha256({
  qualificationReference: QUALIFICATION_REFERENCE,
  promptVersion: PROMPT_VERSION,
  reviewers: REVIEWERS,
  profiles: PROFILES,
});

export function getReviewer(reviewerId) {
  if (!Object.hasOwn(REVIEWERS, reviewerId)) throw new Error(`unknown reviewer: ${reviewerId}`);
  const reviewer = REVIEWERS[reviewerId];
  if (reviewer.status !== 'operational') throw new Error(`reviewer is not operational: ${reviewerId}`);
  return reviewer;
}

export function getProfile(profileId) {
  if (!Object.hasOwn(PROFILES, profileId)) throw new Error(`unknown profile: ${profileId}`);
  const profile = PROFILES[profileId];
  return profile;
}

function requireLowercaseSha256(value, field) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${field} must be a non-empty string`);
  return value;
}

function requirePinnedValue(value, pinnedValue, field, pinDescription) {
  if (value !== undefined && value !== pinnedValue) {
    throw new TypeError(`${field} must match the ${pinDescription}`);
  }
  return pinnedValue;
}

export function buildReviewContract({
  sourceSha256,
  reviewContextSha256,
  profile,
  profileVersion,
  promptVersion,
  schemaSha256,
  registrySha256,
}) {
  const fixedProfile = getProfile(profile);
  const fixedProfileVersion = requirePinnedValue(profileVersion, fixedProfile.version, 'profileVersion', 'fixed profile');
  const fixedPromptVersion = requirePinnedValue(promptVersion, PROMPT_VERSION, 'promptVersion', 'pinned prompt version');
  const fixedSchemaSha256 = requirePinnedValue(schemaSha256, SCHEMA_SHA256, 'schemaSha256', 'pinned schema digest');
  const fixedRegistrySha256 = requirePinnedValue(registrySha256, REGISTRY_SHA256, 'registrySha256', 'pinned registry digest');

  return sha256({
    source_sha256: requireLowercaseSha256(sourceSha256, 'sourceSha256'),
    review_context_sha256: requireLowercaseSha256(reviewContextSha256, 'reviewContextSha256'),
    profile: fixedProfile.id,
    profile_version: fixedProfileVersion,
    prompt_version: fixedPromptVersion,
    schema_sha256: fixedSchemaSha256,
    registry_sha256: fixedRegistrySha256,
  });
}
