import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildReviewContract,
  getProfile,
  PROMPT_VERSION,
  REGISTRY_SHA256,
} from '../src/review-core/reviewer-registry.mjs';
import { SCHEMA_SHA256 } from '../src/review-core/advisory-schema.mjs';

const BASE_CONTRACT = {
  sourceSha256: 'a'.repeat(64),
  reviewContextSha256: 'b'.repeat(64),
  profile: getProfile('consequential_spec_v1').id,
  profileVersion: getProfile('consequential_spec_v1').version,
  promptVersion: PROMPT_VERSION,
  schemaSha256: SCHEMA_SHA256,
  registrySha256: REGISTRY_SHA256,
};

test('buildReviewContract reproduces the same 64-character digest for canonical equivalent inputs', () => {
  const first = buildReviewContract(BASE_CONTRACT);
  const reordered = buildReviewContract({
    registrySha256: BASE_CONTRACT.registrySha256,
    schemaSha256: BASE_CONTRACT.schemaSha256,
    promptVersion: BASE_CONTRACT.promptVersion,
    profileVersion: BASE_CONTRACT.profileVersion,
    profile: BASE_CONTRACT.profile,
    reviewContextSha256: BASE_CONTRACT.reviewContextSha256,
    sourceSha256: BASE_CONTRACT.sourceSha256,
  });

  assert.match(first, /^[a-f0-9]{64}$/);
  assert.equal(first, reordered);
});

test('buildReviewContract changes when bound source, context, or selected fixed profile changes', () => {
  const original = buildReviewContract(BASE_CONTRACT);
  const changedFields = {
    sourceSha256: 'c'.repeat(64),
    reviewContextSha256: 'd'.repeat(64),
    profile: 'final_verification_v1',
  };

  for (const [field, value] of Object.entries(changedFields)) {
    assert.notEqual(buildReviewContract({ ...BASE_CONTRACT, [field]: value }), original, field);
  }
});

test('buildReviewContract derives immutable metadata when callers omit it', () => {
  assert.equal(buildReviewContract({
    sourceSha256: BASE_CONTRACT.sourceSha256,
    reviewContextSha256: BASE_CONTRACT.reviewContextSha256,
    profile: BASE_CONTRACT.profile,
  }), buildReviewContract(BASE_CONTRACT));
});

test('buildReviewContract rejects caller metadata that does not match the fixed profile and policy pins', () => {
  assert.throws(
    () => buildReviewContract({ ...BASE_CONTRACT, profileVersion: '2' }),
    /profileVersion.*fixed profile/i,
  );
  assert.throws(
    () => buildReviewContract({ ...BASE_CONTRACT, promptVersion: 'advisory_review_prompt_v2' }),
    /promptVersion.*pinned/i,
  );
  assert.throws(
    () => buildReviewContract({ ...BASE_CONTRACT, schemaSha256: 'e'.repeat(64) }),
    /schemaSha256.*pinned/i,
  );
  assert.throws(
    () => buildReviewContract({ ...BASE_CONTRACT, registrySha256: 'f'.repeat(64) }),
    /registrySha256.*pinned/i,
  );
});
