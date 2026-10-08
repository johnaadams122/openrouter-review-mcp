import assert from 'node:assert/strict';
import test from 'node:test';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { ACCT_A, ACCT_B, USD, W_MEDICATION, reEscape } from './helpers/scanner-safe-fixtures.mjs';

const PREFLIGHT_ID = 'pf-' + 'a'.repeat(30);
const IDENTITY_LIST = ['jane q. public'];

function fakeOllama({ thirdParty = false, reidentifiable = false, unavailable = false } = {}) {
  return Object.freeze({
    async checkUnknownThirdPartyPii() {
      if (unavailable) return { ok: false, flagged: null };
      return { ok: true, flagged: thirdParty };
    },
    async checkReidentifiable() {
      if (unavailable) return { ok: false, flagged: null };
      return { ok: true, flagged: reidentifiable };
    },
  });
}

test('clean content passes through unchanged', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'an ordinary line of spec prose', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.equal(result.scrubbedText, 'an ordinary line of spec prose');
});

test('phi_vocabulary hard-blocks -- never substituted', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `patient ${W_MEDICATION} list from the clinic`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['phi_vocabulary']);
});

test('a line repeating a weak medical word with no medical context is not hard-blocked as phi_vocabulary', async () => {
  // Regression: the real line shape from a code review the
  // shared service refused with a generic REQUEST_FAILED because the scrubber blocked it.
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const text =
    "if (diagnostic !== '' && diagnostic !== 'CAPTURE_FAILED') throw fail('Managed worker diagnostic is invalid.')";
  const result = await engine.scrub({ text, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.equal(result.scrubbedText, text);
});

test('cui_dod_id hard-blocks -- never substituted', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'CUI//SP-PRVCY sample document', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['cui_dod_id']);
});

test('vendor_api_key hard-blocks -- credentials are never substitution-eligible', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'sk-ant-api03-' + 'a'.repeat(24), preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['vendor_api_key']);
});

test('an unknown-third-party PII combination hard-blocks via the local-LLM check', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama({ thirdParty: true }) });
  const result = await engine.scrub({ text: 'Jane Doe, 555-0100, works at Contoso', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['unknown_third_party_pii']);
});

// Fixture note: every account_number_shape fixture below is a clean 8-17
// digit run (the shared ACCT_A fixture after the word 'account'), never a letter-interrupted token such as
// 'account 9ZQ' followed by that same digit run (see tests/openrouter-scrub-patterns.test.mjs,
// "classifyLine flags an 8-17 digit run"): \b\d{8,17}\b can never match
// across a letter/digit boundary because both are \w, so "ZQ" glues onto the
// surrounding digits and no \b exists anywhere inside the token.
// classifyLine() returns [] for such a letter-interrupted token (no
// account_number_shape hit), which would make every substitution assertion
// below false-fail.
test('account_number_shape substitutes and passes when the smell test is clean', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.notEqual(result.scrubbedText, `account ${ACCT_A}`);
  assert.match(result.scrubbedText, /^account ACCOUNT_[0-9a-f]{8}$/);
});

test('the same real value produces the SAME placeholder within one review (repeated mentions stay coherent)', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const first = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  const second = await engine.scrub({ text: `ref: ${ACCT_A} again`, preflightId: PREFLIGHT_ID });
  const firstToken = first.scrubbedText.match(/ACCOUNT_[0-9a-f]{8}/)[0];
  const secondToken = second.scrubbedText.match(/ACCOUNT_[0-9a-f]{8}/)[0];
  assert.equal(firstToken, secondToken);
});

test('the same real value produces a DIFFERENT placeholder across two different preflightIds', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const first = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: 'pf-' + 'a'.repeat(30) });
  const second = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: 'pf-' + 'b'.repeat(30) });
  assert.notEqual(first.scrubbedText, second.scrubbedText);
});

test('scrubbing the SAME (text, preflightId) pair twice is deterministic -- required for CONTRACT_CHANGED to keep working', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const first = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  const second = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(first.scrubbedText, second.scrubbedText);
});

test('the re-identification smell test hard-blocks even after a clean substitution', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama({ reidentifiable: true }) });
  const result = await engine.scrub({ text: `account ${ACCT_A}, with location details`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['reidentifiable']);
});

test('Ollama being unreachable during either local-LLM check fails CLOSED (blocks), never silently passes', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama({ unavailable: true }) });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['local_llm_unavailable']);
});

// ---------------------------------------------------------------------------
// Accurate reporting of WHY a local-LLM check could not run. Every case
// below still BLOCKS; only the label differs. A deterministic, size-dependent
// context-window overflow reported as `local_llm_unavailable` would send
// diagnosis chasing an outage that never happened while Ollama is healthy.
// The category is the only thing the operator ever sees (review-engine.mjs
// joins blockedCategories straight into its CONTENT_BLOCKED message), so it
// has to name the real condition.
// ---------------------------------------------------------------------------

function ollamaFailingWith(reason) {
  return Object.freeze({
    async checkUnknownThirdPartyPii() {
      return { ok: false, flagged: null, reason };
    },
    async checkReidentifiable() {
      return { ok: false, flagged: null, reason };
    },
  });
}

test('a context-window overflow is reported as local_llm_context_overflow, not as an unavailable local LLM', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: ollamaFailingWith('context_overflow') });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.equal(result.scrubbedText, null);
  assert.deepEqual(result.blockedCategories, ['local_llm_context_overflow']);
});

test('a local-LLM timeout is reported as local_llm_timeout, not as an unavailable local LLM', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: ollamaFailingWith('timeout') });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.equal(result.scrubbedText, null);
  assert.deepEqual(result.blockedCategories, ['local_llm_timeout']);
});

test('a chunk-request-budget exhaustion is reported as local_llm_chunk_budget_exceeded, not as an unavailable local LLM', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: ollamaFailingWith('chunk_budget_exceeded') });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.equal(result.scrubbedText, null);
  assert.deepEqual(result.blockedCategories, ['local_llm_chunk_budget_exceeded']);
});

test('an explicit unavailable reason still reports local_llm_unavailable', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: ollamaFailingWith('unavailable') });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['local_llm_unavailable']);
});

test('a reason that names an Object.prototype member maps to local_llm_unavailable, not to an inherited value', async () => {
  // The reason->category table is a plain object, so a bare `table[reason]`
  // lookup would resolve 'constructor' / 'toString' / 'valueOf' up the
  // prototype chain and put a FUNCTION into blockedCategories, which
  // review-engine.mjs then joins straight into its operator-facing
  // CONTENT_BLOCKED message. It still blocks either way -- this is about the
  // mapping answering only for keys it actually owns, in a component whose
  // whole job is to be predictable when something unexpected arrives.
  for (const reason of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
    const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: ollamaFailingWith(reason) });
    const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
    assert.equal(result.blocked, true, `expected a block for reason=${reason}`);
    assert.deepEqual(result.blockedCategories, ['local_llm_unavailable'], `reason=${reason}`);
  }
});

test('an unrecognized or missing reason still BLOCKS, falling back to local_llm_unavailable', async () => {
  // Fail-closed must not depend on recognizing the reason string: a client
  // that reports something this mapping has never heard of still blocks.
  for (const reason of [undefined, null, 'something_new']) {
    const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: ollamaFailingWith(reason) });
    const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
    assert.equal(result.blocked, true, `expected a block for reason=${String(reason)}`);
    assert.deepEqual(result.blockedCategories, ['local_llm_unavailable']);
  }
});

test('the re-identification check reports its own failure reason, not only the third-party check', async () => {
  // Both call sites must map -- the second one runs after smell test 1, so a
  // mapping applied to only the first would leave the misleading label in
  // place for exactly the second half of the gate.
  const engine = createScrubEngine({
    identityList: IDENTITY_LIST,
    ollamaClient: Object.freeze({
      async checkUnknownThirdPartyPii() {
        return { ok: true, flagged: false };
      },
      async checkReidentifiable() {
        return { ok: false, flagged: null, reason: 'context_overflow' };
      },
    }),
  });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['local_llm_context_overflow']);
});

test('desubstitute reverses every placeholder back to its real value', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const scrubbed = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  const restored = await engine.desubstitute({ text: `finding about ${scrubbed.scrubbedText}`, preflightId: PREFLIGHT_ID });
  assert.equal(restored, `finding about account ${ACCT_A}`);
});

test('desubstitute on a preflightId with no recorded mapping returns the text unchanged', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const restored = await engine.desubstitute({ text: 'no placeholders here', preflightId: 'pf-' + 'z'.repeat(30) });
  assert.equal(restored, 'no placeholders here');
});

test('desubstitute accepts a seedMapping for a cross-process cache miss (recovered from durable storage)', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const restored = await engine.desubstitute({
    text: 'finding about ACCOUNT_deadbeef',
    preflightId: 'pf-' + 'y'.repeat(30),
    seedMapping: { ACCOUNT_deadbeef: '9ZQ24681357' },
  });
  assert.equal(restored, 'finding about 9ZQ24681357');
});

// Regression test: desubstitute() must merge the in-process mappingCache
// entry with seedMapping, not pick EITHER one via `??`. `??` only falls back
// to seedMapping when the cache has NO entry at all (`undefined`) -- but
// scrub() unconditionally caches its own `mapping`, including an EMPTY `{}`,
// on every successful call. `{}` is truthy, so a fresh-process scrub() call
// that legitimately finds nothing eligible in whatever text IT was given
// still poisons the cache for that preflightId, and a `??` lookup never
// falls back to seedMapping again after that -- silently losing a real value
// that a durable seedMapping still held.
// Simulates the exact restart shape: engine1 accumulates a mapping across
// two scrub() calls (source text with nothing eligible, then a second call
// carrying a real account number -- mirroring preflight()'s own
// source-then-reviewContext scrub order); that accumulated mapping is what a
// caller would durably persist to scrubMappingStore. engine2 is a BRAND NEW
// instance (fresh, empty mappingCache -- simulating a process restart) that
// performs exactly ONE scrub() call whose own text has nothing
// substitution-eligible (mirroring review()'s loadAndScrubSource() re-scrub
// of source_text alone, with reviewContext omitted) -- this is what caches
// `{}` in engine2 for this preflightId. desubstitute() is
// then called on engine2, passing engine1's accumulated mapping as
// seedMapping -- the real value must still come back.
test('desubstitute merges the durable seedMapping with a same-process cache entry, even an EMPTY one left by an unrelated scrub() call (cross-process restart)', async () => {
  const preflightId = 'pf-' + 'r'.repeat(30);

  const engine1 = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  await engine1.scrub({ text: 'plain source text, nothing eligible here', preflightId });
  const second = await engine1.scrub({ text: `account ${ACCT_A}`, preflightId });
  assert.equal(second.blocked, false);
  const accumulatedMapping = second.mapping;
  assert.equal(Object.keys(accumulatedMapping).length, 1);
  const [placeholder] = Object.keys(accumulatedMapping);
  assert.equal(accumulatedMapping[placeholder], ACCT_A);

  // Fresh engine instance -- empty mappingCache, simulating a restart.
  const engine2 = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const poisoning = await engine2.scrub({ text: 'plain source text, nothing eligible here', preflightId });
  assert.equal(poisoning.blocked, false);
  assert.deepEqual(poisoning.mapping, {});

  const restored = await engine2.desubstitute({
    text: `finding mentions ${placeholder}`,
    preflightId,
    seedMapping: accumulatedMapping,
  });
  assert.equal(restored, `finding mentions ${ACCT_A}`);
});

test('createScrubEngine requires an identityList array and an ollamaClient', () => {
  assert.throws(() => createScrubEngine({ ollamaClient: fakeOllama() }), TypeError);
  assert.throws(() => createScrubEngine({ identityList: [] }), TypeError);
});

// Identity-substitution coverage: the tests above never put IDENTITY_LIST's
// value into a scrub()'d text, so the identity-substitution path itself -- as
// opposed to just the constructor's identityList validation -- is covered
// below, alongside a regression test for mapping-cache aliasing.

test('an identity-list match gets substituted and the returned mapping records it', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'jane q. public visited the office', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, /jane q\. public/i);
  assert.match(result.scrubbedText, /^PERSON_[0-9a-f]{8} visited the office$/);
  const [placeholder] = result.scrubbedText.match(/PERSON_[0-9a-f]{8}/);
  assert.equal(result.mapping[placeholder], 'jane q. public');
});

test('the same identity name on two different lines gets the same placeholder in one scrub() call', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({
    text: 'line one about jane q. public\nline two also mentions Jane Q. Public again',
    preflightId: PREFLIGHT_ID,
  });
  assert.equal(result.blocked, false);
  const tokens = result.scrubbedText.match(/PERSON_[0-9a-f]{8}/g);
  assert.equal(tokens.length, 2);
  assert.equal(tokens[0], tokens[1]);
  assert.doesNotMatch(result.scrubbedText, /jane|public/i);
});

test('an identity list with an overlapping shorter entry substitutes the longer match, leaking nothing', async () => {
  // Regression test: identityList ['alex', 'alex sample example'] against
  // 'Alex Sample Example...' must not leave 'Sample Example' unredacted,
  // which happens if the shorter entry's substitution runs first and
  // consumes the document's only match before the longer entry's own
  // .replace() gets a chance to find anything.
  const engine = createScrubEngine({ identityList: ['alex', 'alex sample example'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'Alex Sample Example was seen at the front desk.', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, /alex|sample|example/i);
  assert.match(result.scrubbedText, /^PERSON_[0-9a-f]{8} was seen at the front desk\.$/);
  const [placeholder] = result.scrubbedText.match(/PERSON_[0-9a-f]{8}/);
  assert.equal(result.mapping[placeholder], 'Alex Sample Example');
});

test('a full scrub()+desubstitute() round trip through an identity match restores the original casing', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const scrubbed = await engine.scrub({ text: 'Jane Q. Public called.', preflightId: PREFLIGHT_ID });
  const restored = await engine.desubstitute({ text: scrubbed.scrubbedText, preflightId: PREFLIGHT_ID });
  assert.equal(restored, 'Jane Q. Public called.');
});

test('a hard-blocked scrub() call never pollutes a later successful scrub() mapping for the same preflightId', async () => {
  // Regression test: if mappingCache.get(preflightId) returned a live
  // reference into the Map, not a copy, a blocked call's substitutions (which
  // never reach mappingCache.set()) would still mutate the shared cached
  // object in place before the block is even detected.
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const pf = PREFLIGHT_ID;
  const first = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: pf });
  assert.equal(first.blocked, false);

  const blocked = await engine.scrub({
    text: 'jane q. public used sk-ant-api03-' + 'a'.repeat(24),
    preflightId: pf,
  });
  assert.equal(blocked.blocked, true);

  const third = await engine.scrub({ text: `ref: ${ACCT_A} again`, preflightId: pf });
  assert.equal(third.blocked, false);
  assert.deepEqual(third.mapping, first.mapping);
  assert.equal(Object.values(third.mapping).some((v) => v === 'jane q. public'), false);
});

// Crossing overlaps: substituting entries longest-first would only close
// CONTAINMENT overlaps (one entry's match fully inside another's). It does
// nothing for CROSSING overlaps, where two entries' matches partially overlap
// without either containing the other -- sorting by length can't fix that
// shape no matter the order, because whichever entry substitutes first only
// consumes its OWN span, silently dropping the non-overlapping remainder of
// the other entry's span. Substitution therefore uses interval-merging (find
// every match from every entry, merge overlapping/touching spans, redact the
// merged union), which closes both shapes uniformly.

test('crossing identity-list entries (neither contains the other) still redact the full union, leaking nothing', async () => {
  // Regression test: identityList ['alex sample', 'sample example'] against
  // 'Alex Sample Example...' must redact the full union. Redacting only
  // whichever entry's span substitutes first would leave 'Alex' in plaintext
  // (output 'Alex PERSON_xxxxxxxx was seen...').
  const engine = createScrubEngine({ identityList: ['alex sample', 'sample example'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'Alex Sample Example was seen at the front desk.', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, /alex|sample|example/i);
  assert.match(result.scrubbedText, /^PERSON_[0-9a-f]{8} was seen at the front desk\.$/);
  const [placeholder] = result.scrubbedText.match(/PERSON_[0-9a-f]{8}/);
  assert.equal(result.mapping[placeholder], 'Alex Sample Example');
});

test('the returned mapping is frozen -- a caller mutating it cannot silently corrupt the cached copy', async () => {
  const engine = createScrubEngine({ identityList: IDENTITY_LIST, ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(Object.isFrozen(result.mapping), true);
  assert.throws(() => {
    result.mapping.INJECTED = 'attacker-controlled';
  }, TypeError);
});

// Identity-residue backstop: classifyLine() never emits an identity category
// -- identity detection is a wholly separate path
// (findIdentityIntervals()/matchesIdentityList()) that classifyLine() knows
// nothing about. So smell test 1's re-scan, which re-runs classifyLine() on
// scrubbedText to catch account_number_shape/dollar_figure residue, also
// re-runs matchesIdentityList() as the equivalent regex-level backstop
// confirming identity-list content is actually gone.

test('smell test 1 hard-blocks residual identity-list content in scrubbedText, not just account/dollar shapes', async () => {
  // Proves the check has real hole-catching teeth, not just that the code
  // path exists: the interval-merge substitution logic does not leave
  // identity residue directly, so this exploits a DIFFERENT, legitimate
  // route into smell test 1's input: identity matching runs against the
  // ORIGINAL text, and 'account_' (with the trailing underscore) does not
  // appear anywhere in 'account' followed by the ACCT_A digit run -- so identity substitution
  // correctly finds nothing to redact on this line. The account_number_shape
  // substitution then stamps the line with a placeholder in the literal shape
  // 'ACCOUNT_<8 hex chars>' -- which itself contains 'account_' as a
  // case-insensitive substring. Without the identity re-scan this scenario
  // would pass unblocked (blocked: false, scrubbedText:
  // 'account ACCOUNT_4b3af891'); matchesIdentityList() catches it on the
  // smell-test re-scan.
  const engine = createScrubEngine({ identityList: ['account_'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `account ${ACCT_A}`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, true);
  assert.deepEqual(result.blockedCategories, ['identity_residual']);
});

// Empty identityList entries: the identity_residual re-check above calls
// matchesIdentityList(), and `anyString.includes('')` is always true in JS.
// Without a guard, identityList: [''] would hard-block EVERY scrub() call,
// including fully clean text with zero identity/account/dollar content,
// mislabeled identity_residual. The guard lives at the source
// (scrub-patterns.mjs, mirroring findIdentityIntervals()'s own empty-entry
// check) rather than filtering identityList at construction time, since
// matchesIdentityList is an independently-tested, general-purpose exported
// function -- its own contract should hold regardless of caller.

test('an empty-string identityList entry does not hard-block clean content', async () => {
  const engine = createScrubEngine({ identityList: [''], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'an ordinary line of spec prose', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.equal(result.scrubbedText, 'an ordinary line of spec prose');
});

// Cross-category glue: if account_number_shape/dollar_figure substitution ran
// as a SEPARATE, later sequential pass over text identity substitution had
// already mutated, it would leak. account_number_shape's detector requires a
// real \b word-boundary on both sides of the digit run; letters/digits/
// underscore are all \w, so an identityList entry with a stray
// leading/trailing space (an ordinary config typo) could have its
// substitution consume the whitespace adjacent to a digit run, gluing the
// placeholder token directly onto the digits with no separator -- erasing
// the boundary BOTH the primary substitution and the smell-test-1 backstop
// (the identical regex) need to see. For example, identityList:
// ['jane q. public '] (trailing space) against a line holding that identity
// followed by the ACCT_A digit run would produce blocked:false, with the
// raw account number glued onto the PERSON placeholder, unredacted.
//
// Substitution is therefore ONE interval-merge pass across ALL
// substitution-eligible categories (identity, account_number_shape,
// dollar_figure) against the ORIGINAL, untouched line -- not just within
// the identity category. Where a category's span touches or overlaps
// another category's span (the glue scenario above), they merge into a
// single 'mixed'-prefixed placeholder covering the full union, so there's no
// leftover digit run for any detector to fail to see. This structurally
// eliminates the whole overlap/glue bug class rather than patching one
// instance of it.

test('a trailing space on an identityList entry does not glue a placeholder onto an adjacent account number', async () => {
  const engine = createScrubEngine({ identityList: ['jane q. public '], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `jane q. public ${ACCT_A} was noted`, preflightId: PREFLIGHT_ID });
  // Either outcome is acceptable -- a clean block, or a genuine redaction --
  // as long as nothing leaks. The interval-merge design produces a genuine
  // redaction here (the touching
  // identity + account spans merge into one), so assert that outcome
  // specifically, plus the leak-proof property either way.
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp(ACCT_A));
  assert.match(result.scrubbedText, /^REDACTED_[0-9a-f]{8} was noted$/);
});

test('a leading space on an identityList entry does not glue a placeholder onto an adjacent account number', async () => {
  const engine = createScrubEngine({ identityList: [' jane q. public'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `account ${ACCT_A} jane q. public entered it`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp(ACCT_A));
  assert.match(result.scrubbedText, /^account REDACTED_[0-9a-f]{8} entered it$/);
});

test('a whitespace-only identityList entry does not over-match ordinary text', async () => {
  const engine = createScrubEngine({ identityList: [' '], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'an ordinary line of spec prose', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.equal(result.scrubbedText, 'an ordinary line of spec prose');
});

test('createScrubEngine rejects a non-string identityList entry with a clear error at construction time', () => {
  assert.throws(() => createScrubEngine({ identityList: ['jane', null], ollamaClient: fakeOllama() }), TypeError);
  assert.throws(() => createScrubEngine({ identityList: [42], ollamaClient: fakeOllama() }), TypeError);
});

test('an account number and an identity mention that do NOT touch each other still substitute independently', async () => {
  // Sanity check for the interval-merge design: merging must not over-merge
  // unrelated content that merely shares a line -- only spans that actually
  // touch or overlap should fuse.
  const engine = createScrubEngine({ identityList: ['jane q. public'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({
    text: `account ${ACCT_A} was flagged for review, contact jane q. public`,
    preflightId: PREFLIGHT_ID,
  });
  assert.equal(result.blocked, false);
  assert.match(result.scrubbedText, /^account ACCOUNT_[0-9a-f]{8} was flagged for review, contact PERSON_[0-9a-f]{8}$/);
});

test('an account number and a dollar figure on the same line, not overlapping, both substitute independently', async () => {
  const engine = createScrubEngine({ identityList: [], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `account ${ACCT_A} owes ${USD}1,200.00`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.match(result.scrubbedText, /^account ACCOUNT_[0-9a-f]{8} owes AMOUNT_[0-9a-f]{8}$/);
});

// findShapeSpans()'s dollar_figure branch must match whole-dollar and
// single-decimal figures too: a pattern restricted to comma-grouped or
// exactly-two-decimal amounts never adds them to the substitution span set
// at all -- not blocked, not substituted, sent to the external reviewers
// verbatim. See the matching scrub-patterns.mjs pattern and its tests.
test('a whole-dollar amount with no decimal is substituted, not left in plaintext', async () => {
  const engine = createScrubEngine({ identityList: [], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `threshold is <${USD}123`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp(reEscape(`${USD}123`) + '\\b'));
  assert.match(result.scrubbedText, /^threshold is <AMOUNT_[0-9a-f]{8}$/);
});

test('a dollar amount with a single decimal digit is substituted, not left in plaintext', async () => {
  const engine = createScrubEngine({ identityList: [], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `XYZ ${USD}45.6 sample line`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp(reEscape(`${USD}45.6`) + '\\b'));
  assert.match(result.scrubbedText, /^XYZ AMOUNT_[0-9a-f]{8} sample line$/);
});

test('several whole-dollar figures on one line all substitute, none glue together or leak', async () => {
  const engine = createScrubEngine({ identityList: [], ollamaClient: fakeOllama() });
  const result = await engine.scrub({
    text: `item a >${USD}11, item b+c <${USD}22, item d <${USD}333`,
    preflightId: PREFLIGHT_ID,
  });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp([11, 22, 333].map((n) => reEscape(`${USD}${n}`) + '\\b').join('|')));
  assert.match(
    result.scrubbedText,
    /^item a >AMOUNT_[0-9a-f]{8}, item b\+c <AMOUNT_[0-9a-f]{8}, item d <AMOUNT_[0-9a-f]{8}$/,
  );
});

// The decimal tail must be uncapped: capping findShapeSpans()'s decimal tail
// at 1-2 digits leaves a 3+-decimal-digit dollar figure only PARTIALLY
// substituted -- the leftover decimal digits glue onto the placeholder with
// no boundary (e.g. scrubbedText 'AMOUNT_c0bf5a95.567'), and the smell-test
// re-scan (account_number_shape's own (?<!\d\.) lookbehind) only catches
// this by luck when the placeholder's own HMAC hex tail happens to end in a
// digit, so most preflightIds would leak it straight through unblocked.
test('a dollar figure with three or more decimal digits substitutes completely, nothing glued onto the placeholder', async () => {
  const engine = createScrubEngine({ identityList: [], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: `the price is ${USD}1,234.567 today`, preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp(reEscape(`${USD}1,234.567`) + '|\\.567'));
  assert.match(result.scrubbedText, /^the price is AMOUNT_[0-9a-f]{8} today$/);
});

// Every occurrence per line: shape-span-finding must locate EVERY
// account_number_shape/dollar_figure occurrence on a line, not just the
// FIRST. A SECOND same-category occurrence that never reaches the
// merge-eligible span set lets an identity-glue landing specifically on that
// second occurrence defeat its word boundary the same way, and smell-test-1
// would miss it too if classifyLine() also only located the first
// occurrence. This is not account_number_shape-specific: it applies
// identically to dollar_figure's no-comma variant (which has its own
// trailing \b). Both classifyLine() (scrub-patterns.mjs) and this module's
// shape-span-finding therefore cover every occurrence, with per-occurrence
// timestamp suppression (not just per-line).

test('two account numbers on one line with an identity-glue on the SECOND one leak nothing', async () => {
  // Without every-occurrence span finding: blocked:false, scrubbedText:
  // 'account ACCOUNT_<hex> review; PERSON_<hex>' followed directly by the ACCT_B digits --
  // the second account number (the ACCT_B fixture) glues onto the identity
  // placeholder and leaks in plaintext.
  const engine = createScrubEngine({ identityList: ['jane q. public '], ollamaClient: fakeOllama() });
  const result = await engine.scrub({
    text: `account ${ACCT_A} review; jane q. public ${ACCT_B} flagged`,
    preflightId: PREFLIGHT_ID,
  });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp(`${ACCT_A}|${ACCT_B}`));
});

test('two dollar figures on one line with an identity-glue on the SECOND one leak nothing', async () => {
  // Without every-occurrence span finding: blocked:false, scrubbedText:
  // 'paid AMOUNT_xxxxxxxx first, then AMOUNT-then-PERSON glued together with no space' --
  // the second dollar figure (the six-hundred fixture) glues onto the identity placeholder
  // and leaks in plaintext; a first-occurrence-only classifyLine() would also
  // miss it on re-scan.
  const engine = createScrubEngine({ identityList: [' jane q. public'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({
    text: `paid ${USD}100.00 first, then ${USD}600.00 jane q. public confirmed it`,
    preflightId: PREFLIGHT_ID,
  });
  assert.equal(result.blocked, false);
  assert.doesNotMatch(result.scrubbedText, new RegExp([`${USD}100.00`, `${USD}600.00`].map(reEscape).join('|')));
});

test('a suppressed timestamp and a real account number on the same line: the timestamp is left alone, the account number is redacted', async () => {
  // End-to-end version of the classifyLine() per-occurrence suppression test in
  // openrouter-scrub-patterns.test.mjs -- confirms not just that classifyLine()
  // flags the category, but that the ENGINE correctly leaves
  // the suppressed timestamp untouched while still substituting the real
  // account number found alongside it on the same line.
  const engine = createScrubEngine({ identityList: [], ollamaClient: fakeOllama() });
  const result = await engine.scrub({
    text: `created_ms: 1755993600000, account ${ACCT_A}`,
    preflightId: PREFLIGHT_ID,
  });
  assert.equal(result.blocked, false);
  assert.match(result.scrubbedText, /^created_ms: 1755993600000, account ACCOUNT_[0-9a-f]{8}$/);
});

// Unicode case folding: findIdentityIntervals() must not lowercase both
// `line` and `entry` (line.toLowerCase()/entry.toLowerCase()), locate
// matches with indexOf() in that LOWERED domain, and return those SAME
// offsets to slice the ORIGINAL, un-lowercased `line`.
// String.prototype.toLowerCase() is not length-preserving across the full
// Unicode range -- 'İ' (Turkish capital dotless-I, U+0130) lowercases to a
// 2-code-unit string ('i' + combining dot above), not 1 -- so any expanding
// character before a match (or inside the entry itself) would desync every
// subsequent lowered-domain offset from the real position in `line`,
// leaking real name characters in plaintext and corrupting the recorded
// mapping value. Neither smell-test-1's matchesIdentityList re-check nor
// the deterministic regex re-scan could catch this, since the corruption
// itself destroys the substring they'd be looking for. Matching directly
// against the original `line` with a case-insensitive regex keeps
// match.index/match[0].length real positions in `line` -- never a
// separately lowercased, differently-lengthed copy.

test('an expanding-under-lowercase character BEFORE an identity match does not desync the redaction offset', async () => {
  // With lowered-domain offsets: scrubbedText
  // 'İ prefix jPERSON_3b63b267was here' -- the leading "j" leaks in
  // plaintext (glued onto the placeholder with no separator), and the
  // recorded mapping value is the wrong, truncated 'ane q. public '.
  const engine = createScrubEngine({ identityList: ['jane q. public'], ollamaClient: fakeOllama() });
  const pf = PREFLIGHT_ID;
  const result = await engine.scrub({ text: 'İ prefix jane q. public was here', preflightId: pf });
  assert.equal(result.blocked, false);
  assert.match(result.scrubbedText, /^İ prefix PERSON_[0-9a-f]{8} was here$/);
  const [placeholder] = result.scrubbedText.match(/PERSON_[0-9a-f]{8}/);
  assert.equal(result.mapping[placeholder], 'jane q. public');
  const restored = await engine.desubstitute({ text: result.scrubbedText, preflightId: pf });
  assert.equal(restored, 'İ prefix jane q. public was here');
});

test('an identityList entry that itself contains an expanding-under-lowercase character redacts with a correct boundary', async () => {
  // With lowered-domain offsets: scrubbedText
  // 'contact PERSON_287c2103today' -- the character after the entry is
  // silently swallowed (end offset overruns using the case-folded, longer
  // length instead of the real entry length), leaving no separator before
  // "today".
  const engine = createScrubEngine({ identityList: ['İstanbul Corp'], ollamaClient: fakeOllama() });
  const result = await engine.scrub({ text: 'contact İstanbul Corp today', preflightId: PREFLIGHT_ID });
  assert.equal(result.blocked, false);
  assert.match(result.scrubbedText, /^contact PERSON_[0-9a-f]{8} today$/);
  const [placeholder] = result.scrubbedText.match(/PERSON_[0-9a-f]{8}/);
  assert.equal(result.mapping[placeholder], 'İstanbul Corp');
});
