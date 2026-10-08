import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EXTRA_PROTECTED_TERMS_HEADER,
  EXTRA_PROTECTED_TERMS_MAX_BYTES,
  NO_EXTRA_PROTECTED_TERMS,
  classifyLine,
  createLineClassifier,
  parseExtraProtectedTerms,
  validateExtraProtectedTerms,
} from '../src/local-mcp/scrub-patterns.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { ACCT_LONG, PHI_MARKER_ALTERNATION, W_DIAGNOSIS, W_MEDICATION, W_PSYCHIATRIC } from './helpers/scanner-safe-fixtures.mjs';

// Every protected term in this file is invented. The owner's real extra terms live outside git and are
// read at run time; these tests prove the MECHANISM with stand-ins that occupy the same positions the old
// built-in terms did: two single-word markers, one two-word marker phrase, and one context-only word.
const SYNTHETIC_TERMS = Object.freeze({
  markers: Object.freeze(['ZQBOARD', 'ZQPANEL', 'zq review panel']),
  contextTerms: Object.freeze(['ZQ', 'ZQBOARD']),
});

function termsFile(lines) {
  return Buffer.from(lines.join('\n'), 'utf8');
}

const VALID_FILE_LINES = Object.freeze([
  '# synthetic extra protected terms, test fixture only',
  EXTRA_PROTECTED_TERMS_HEADER,
  '',
  'marker ZQBOARD',
  'marker   ZQPANEL  ',
  'marker zq   review panel',
  '# context words make a weak generic marker reportable',
  'context ZQ',
  'context ZQBOARD',
]);

// ---------------------------------------------------------------------------------------------------
// The old classifier, rebuilt as an oracle. Before this change, scrub-patterns.mjs held ONE marker
// alternation and ONE context alternation, with the owner's terms written inline beside the generic
// words. The oracle below is that exact structure with the synthetic terms in the owner's slots, so a
// line-by-line comparison proves configured terms follow the same marker and context rules the
// built-in ones did -- not merely that "some" blocking happens.
// ---------------------------------------------------------------------------------------------------
const ORACLE_MARKERS = new RegExp(
  '\\b(ZQBOARD|ZQPANEL|zq\\s+review\\s+panel|'
  + `${PHI_MARKER_ALTERNATION})\\b`,
  'i',
);
const ORACLE_WEAK = /\b(diagnos\w*|prognos\w*|disorder\w*)\b/gi;
const ORACLE_CONTEXT = new RegExp(
  '\\b(patient|clinic\\w*|medical|health|doctor|physician|provider|'
  + 'treatment|symptom\\w*|condition|injur\\w*|disabilit\\w*|profile|exam|'
  + 'referral|ZQ|ZQBOARD|record|note|history\\s+of|icd|cpt)\\b',
  'i',
);
function oraclePhi(line) {
  if (!ORACLE_MARKERS.test(line)) return false;
  if (ORACLE_CONTEXT.test(line)) return true;
  return ORACLE_MARKERS.test(line.replace(ORACLE_WEAK, ' '));
}

const CORPUS = Object.freeze([
  'ZQBOARD timeline Q1-Q3',
  'zqboard timeline',
  'the ZQBOARDS were stacked',
  'preZQBOARD value',
  'ZQPANEL notes',
  'ZQ  review\tpanel scheduled',
  'zq review panelist',
  'ZQ diagnosis pending',
  'ZQ by itself is not a marker',
  'diagnosis and prognosis both present',
  'the linter throws away the diagnosis on parse failure',
  `patient ${W_DIAGNOSIS} pending review`,
  `${W_MEDICATION} schedule changed`,
  'disorder in the build graph',
  'disorders of the queue with ZQ attached',
  'an ordinary line of spec prose',
  `ZQBOARD and ${W_MEDICATION} record`,
  'history  of ZQPANEL',
  'post ZQ-diagnosis',
]);

test('generic protected-health words still block with no extra terms configured', () => {
  for (const classify of [classifyLine, createLineClassifier(), createLineClassifier({ extraProtectedTerms: NO_EXTRA_PROTECTED_TERMS })]) {
    assert.deepEqual(classify(`${W_MEDICATION} schedule changed`), ['phi_vocabulary']);
    assert.deepEqual(classify(`patient ${W_DIAGNOSIS} pending review`), ['phi_vocabulary']);
    assert.deepEqual(classify(`${W_PSYCHIATRIC} follow-up booked`), ['phi_vocabulary']);
    assert.deepEqual(classify('the linter throws away the diagnosis on parse failure'), []);
    assert.deepEqual(classify('an ordinary line of spec prose'), []);
  }
});

test('a synthetic extra marker is not protected until it is configured', () => {
  assert.deepEqual(classifyLine('ZQBOARD timeline Q1-Q3'), []);
  assert.deepEqual(createLineClassifier()('ZQBOARD timeline Q1-Q3'), []);
  const classify = createLineClassifier({ extraProtectedTerms: SYNTHETIC_TERMS });
  assert.deepEqual(classify('ZQBOARD timeline Q1-Q3'), ['phi_vocabulary']);
  assert.deepEqual(classify('zqboard timeline'), ['phi_vocabulary'], 'case-insensitive, like the old built-ins');
  assert.deepEqual(classify('ZQ   Review\tpanel scheduled'), ['phi_vocabulary'], 'a phrase matches any whitespace run');
  assert.deepEqual(classify('the ZQBOARDS were stacked'), [], 'whole words only, like the old built-ins');
  assert.deepEqual(classify('zq review panelist'), [], 'a phrase also ends on a word boundary');
});

test('a configured context word makes a weak generic marker reportable, exactly as the old built-in context words did', () => {
  assert.deepEqual(classifyLine('ZQ diagnosis pending'), []);
  const classify = createLineClassifier({ extraProtectedTerms: SYNTHETIC_TERMS });
  assert.deepEqual(classify('ZQ diagnosis pending'), ['phi_vocabulary']);
  assert.deepEqual(classify('ZQ by itself is not a marker'), [], 'a context word alone never blocks');
});

test('configured terms classify every corpus line exactly like the old single-regex structure', () => {
  const classify = createLineClassifier({ extraProtectedTerms: SYNTHETIC_TERMS });
  for (const line of CORPUS) {
    assert.equal(classify(line).includes('phi_vocabulary'), oraclePhi(line), line);
  }
  // The oracle is not vacuous: it disagrees with the generic-only classifier somewhere.
  assert.ok(CORPUS.some((line) => oraclePhi(line) !== classifyLine(line).includes('phi_vocabulary')));
});

test('extra protected terms combine with every other category on the same line', () => {
  const classify = createLineClassifier({ extraProtectedTerms: SYNTHETIC_TERMS });
  const hits = classify(`ZQBOARD record, account ${ACCT_LONG}`);
  assert.deepEqual(new Set(hits), new Set(['phi_vocabulary', 'account_number_shape']));
});

test('the terms file parser accepts the documented format and returns normalized frozen lists', () => {
  const parsed = parseExtraProtectedTerms(termsFile(VALID_FILE_LINES));
  assert.deepEqual(parsed, { markers: ['ZQBOARD', 'ZQPANEL', 'zq review panel'], contextTerms: ['ZQ', 'ZQBOARD'] });
  assert.ok(Object.isFrozen(parsed) && Object.isFrozen(parsed.markers) && Object.isFrozen(parsed.contextTerms));
  // Windows line endings are fine; the hash pin covers the exact bytes either way.
  assert.deepEqual(parseExtraProtectedTerms(Buffer.from(VALID_FILE_LINES.join('\r\n'), 'utf8')), parsed);
  // A file may list only context words or only markers.
  assert.deepEqual(parseExtraProtectedTerms(termsFile([EXTRA_PROTECTED_TERMS_HEADER, 'context ZQ'])), { markers: [], contextTerms: ['ZQ'] });
});

test('the terms file parser refuses every malformed shape, without echoing term content', () => {
  const secretish = 'ZQSECRETWORD';
  const cases = [
    ['empty file', Buffer.alloc(0)],
    ['missing header', termsFile([`marker ${secretish}`])],
    ['wrong header', termsFile(['extra-protected-terms-v0', `marker ${secretish}`])],
    ['header only, no terms', termsFile([EXTRA_PROTECTED_TERMS_HEADER])],
    ['unknown kind', termsFile([EXTRA_PROTECTED_TERMS_HEADER, `markers ${secretish}`])],
    ['kind without a term', termsFile([EXTRA_PROTECTED_TERMS_HEADER, 'marker'])],
    ['regex syntax in a term', termsFile([EXTRA_PROTECTED_TERMS_HEADER, `marker ${secretish}.*`])],
    ['non-ASCII letter', termsFile([EXTRA_PROTECTED_TERMS_HEADER, `marker ${secretish}é`])],
    ['control character', termsFile([EXTRA_PROTECTED_TERMS_HEADER, `marker ${secretish}\u0007`])],
    ['duplicate marker, case-insensitive', termsFile([EXTRA_PROTECTED_TERMS_HEADER, `marker ${secretish}`, `marker ${secretish.toLowerCase()}`])],
    ['duplicate context word', termsFile([EXTRA_PROTECTED_TERMS_HEADER, `context ${secretish}`, `context ${secretish}`])],
    ['byte-order mark', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), termsFile([EXTRA_PROTECTED_TERMS_HEADER, `marker ${secretish}`])])],
    ['invalid UTF-8', Buffer.concat([termsFile([EXTRA_PROTECTED_TERMS_HEADER, `marker ${secretish}`]), Buffer.from([0xc3, 0x28])])],
    ['over the byte limit', Buffer.alloc(EXTRA_PROTECTED_TERMS_MAX_BYTES + 1, 0x41)],
    ['not bytes', `${EXTRA_PROTECTED_TERMS_HEADER}\nmarker ${secretish}`],
  ];
  for (const [label, input] of cases) {
    assert.throws(() => parseExtraProtectedTerms(input), (error) => {
      assert.ok(error instanceof TypeError, label);
      assert.equal(error.message.includes(secretish), false, `${label}: the error must not echo a term`);
      assert.equal(error.message.toLowerCase().includes(secretish.toLowerCase()), false, `${label}: not even lower-cased`);
      return true;
    }, label);
  }
});

test('the same word may be both a marker and a context word, as the old built-in lists allowed', () => {
  const parsed = parseExtraProtectedTerms(termsFile([EXTRA_PROTECTED_TERMS_HEADER, 'marker ZQBOARD', 'context ZQBOARD']));
  assert.deepEqual(parsed, { markers: ['ZQBOARD'], contextTerms: ['ZQBOARD'] });
});

test('validateExtraProtectedTerms accepts only normalized term lists and rejects any other shape', () => {
  assert.deepEqual(validateExtraProtectedTerms({ markers: [], contextTerms: [] }), { markers: [], contextTerms: [] });
  assert.deepEqual(validateExtraProtectedTerms(SYNTHETIC_TERMS), { markers: [...SYNTHETIC_TERMS.markers], contextTerms: [...SYNTHETIC_TERMS.contextTerms] });
  const bad = [
    null,
    [],
    { markers: [] },
    { markers: [], contextTerms: [], extra: [] },
    { markers: 'ZQBOARD', contextTerms: [] },
    { markers: [7], contextTerms: [] },
    { markers: ['ZQ  BOARD'], contextTerms: [] },
    { markers: [' ZQBOARD'], contextTerms: [] },
    { markers: ['ZQ|BOARD'], contextTerms: [] },
    { markers: ['ZQBOARD', 'zqboard'], contextTerms: [] },
  ];
  for (const value of bad) assert.throws(() => validateExtraProtectedTerms(value), TypeError, JSON.stringify(value));
});

// ---------------------------------------------------------------------------------------------------
// The scrub engine is what both the per-session server and the shared executor construct; these tests
// prove a configured term reaches its hard-block path (and its smell-test re-scan) unchanged.
// ---------------------------------------------------------------------------------------------------
const PREFLIGHT_ID = 'pf-' + 'e'.repeat(30);
function cleanOllama() {
  return Object.freeze({
    async checkUnknownThirdPartyPii() { return { ok: true, flagged: false }; },
    async checkReidentifiable() { return { ok: true, flagged: false }; },
  });
}

test('the scrub engine hard-blocks a configured extra term with the same phi_vocabulary category', async () => {
  const configured = createScrubEngine({ identityList: [], extraProtectedTerms: SYNTHETIC_TERMS, ollamaClient: cleanOllama() });
  const blocked = await configured.scrub({ text: 'intro line\nZQBOARD timeline Q1-Q3', preflightId: PREFLIGHT_ID });
  assert.equal(blocked.blocked, true);
  assert.deepEqual(blocked.blockedCategories, ['phi_vocabulary']);
  assert.equal(blocked.scrubbedText, null);

  const generic = createScrubEngine({ identityList: [], ollamaClient: cleanOllama() });
  const passed = await generic.scrub({ text: 'intro line\nZQBOARD timeline Q1-Q3', preflightId: PREFLIGHT_ID });
  assert.equal(passed.blocked, false, 'without the configured term the same text is not protected');
});

test('the scrub engine still blocks generic words when extra terms are configured', async () => {
  const configured = createScrubEngine({ identityList: [], extraProtectedTerms: SYNTHETIC_TERMS, ollamaClient: cleanOllama() });
  const blocked = await configured.scrub({ text: `patient ${W_MEDICATION} list from the clinic`, preflightId: PREFLIGHT_ID });
  assert.deepEqual(blocked.blockedCategories, ['phi_vocabulary']);
});

test('the scrub engine refuses malformed extra terms at construction', () => {
  for (const extraProtectedTerms of [null, 'ZQBOARD', { markers: ['ZQ.*'], contextTerms: [] }, { markers: [], contextTerms: [], more: [] }]) {
    assert.throws(
      () => createScrubEngine({ identityList: [], extraProtectedTerms, ollamaClient: cleanOllama() }),
      TypeError,
      JSON.stringify(extraProtectedTerms),
    );
  }
});
