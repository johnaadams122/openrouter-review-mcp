import assert from 'node:assert/strict';
import test from 'node:test';
import { PHI_GENERIC_MARKERS_PATTERN, classifyLine, matchesIdentityList } from '../src/local-mcp/scrub-patterns.mjs';
import { ACCT_C, ACCT_LONG, DATE_SHAPED_ID, DOD_ID_SHAPE, PHI_MARKER_ALTERNATION, USD, W_DIAGNOSIS, W_DIAGNOSTIC, W_MEDICATION, W_PSYCHIATRIC } from './helpers/scanner-safe-fixtures.mjs';

// The scrubber assembles its generic health-marker word list from parts at load (so the repository's
// own push scanner does not flag the word list). This pins the compiled pattern to the original
// single-literal spelling, which the helper rebuilds from parts: same source text, same flags.
test('the generic health-marker pattern compiles to exactly the original literal pattern', () => {
  const original = new RegExp(`\\b(${PHI_MARKER_ALTERNATION})\\b`, 'i');
  assert.equal(PHI_GENERIC_MARKERS_PATTERN.source, original.source);
  assert.equal(PHI_GENERIC_MARKERS_PATTERN.flags, original.flags);
});

test('classifyLine flags a dollar-figure table shape', () => {
  assert.deepEqual(classifyLine(`balance: ${USD}12,345.67`), ['dollar_figure']);
});

// A pattern requiring comma-grouping or exactly two decimals misses
// whole-dollar and single-decimal amounts, so the pattern
// accepts any $-prefixed number with optional comma-grouping and an optional
// decimal tail -- a $ sign already disambiguates "this is currency" from any
// other digit-shape category, so there is no false-positive cost to dropping
// the two-decimal requirement.
test('classifyLine flags a whole-dollar amount with no decimal', () => {
  assert.deepEqual(classifyLine(`the budget cap is ${USD}300`), ['dollar_figure']);
});

test('classifyLine flags a dollar amount with a single decimal digit', () => {
  assert.deepEqual(classifyLine(`widget price ${USD}12.5 each`), ['dollar_figure']);
});

test('classifyLine flags every whole-dollar figure on a line with several', () => {
  const hits = classifyLine(`tier A ${USD}10, tier B ${USD}20, tier C ${USD}300`);
  assert.deepEqual(hits, ['dollar_figure']);
});

// Capping the decimal tail at 1-2 digits would leave a dollar figure with
// 3+ decimal digits (e.g. a fractional-cent price) only PARTIALLY matched --
// classifyLine() would still fire (this test), but scrub-engine.mjs's
// findShapeSpans() would only capture the first two decimal digits, leaving
// the rest glued onto the placeholder with no boundary. The decimal tail is
// therefore uncapped (`(?:\.\d+)?`).
test('classifyLine flags a dollar figure with three or more decimal digits', () => {
  assert.deepEqual(classifyLine(`the price is ${USD}1,234.567 today`), ['dollar_figure']);
});

test('classifyLine flags an 8-17 digit run as account_number_shape', () => {
  // A letter-interrupted digit string has no internal word boundary: _NUM_SHAPE
  // is \b\d{8,17}\b, and \b never breaks between a letter and a digit (both
  // are \w), so the fixture is a clean 8-17 digit run.
  assert.deepEqual(classifyLine(`account ${ACCT_C}`), ['account_number_shape']);
});

test('classifyLine does not flag a plausible unix-epoch-ms value with timestamp context', () => {
  assert.deepEqual(classifyLine('created_ms: 1755993600000'), []);
});

test('classifyLine still flags account_number_shape when a second digit run is real, even if the FIRST is a suppressed timestamp', () => {
  // Checking only the FIRST _NUM_SHAPE match on a line would judge the line
  // clean when that first match is a suppressed plausible timestamp -- even
  // when a SECOND digit run on the same line is a non-suppressed account
  // number. Every digit-run match is checked independently (same line-level
  // hasTsContext flag, but per-occurrence suppression), flagging the
  // category if at least one occurrence is non-suppressed.
  assert.deepEqual(classifyLine(`created_ms: 1755993600000, account ${ACCT_C}`), ['account_number_shape']);
});

test('classifyLine flags an 8-digit YYYYMMDD date as account_number_shape when there is no timestamp context word', () => {
  // Suppression is context-gated, not value-range-gated alone.
  assert.deepEqual(classifyLine(`order id ${DATE_SHAPED_ID}`), ['account_number_shape']);
});

test('classifyLine flags phi_vocabulary for a strong PHI marker', () => {
  assert.deepEqual(classifyLine(`${W_MEDICATION} schedule changed`), ['phi_vocabulary']);
});

test('classifyLine does NOT flag phi_vocabulary for a weak marker with no medical corroboration', () => {
  // "diagnosis" alone, in a software-debugging sentence, is not PHI.
  assert.deepEqual(classifyLine('the linter throws away the diagnosis on parse failure'), []);
});

test('classifyLine flags phi_vocabulary for a weak marker WITH medical corroboration on the same line', () => {
  assert.deepEqual(classifyLine(`patient ${W_DIAGNOSIS} pending review`), ['phi_vocabulary']);
});

// Regression: the weak-word exemption removed only the
// FIRST standalone weak word on a line (its regex had no global flag), so a line holding two or
// more of them was hard-blocked as phi_vocabulary. The shared service hides the block reason, so
// a real code review failed with a generic REQUEST_FAILED. This is the exact line shape that did.
test('classifyLine does NOT flag phi_vocabulary when one line repeats a weak marker with no medical corroboration', () => {
  const realFailingLine =
    "if (diagnostic !== '' && diagnostic !== 'CAPTURE_FAILED') throw fail('Managed worker diagnostic is invalid.')";
  assert.deepEqual(classifyLine(realFailingLine), []);
});

test('classifyLine does NOT flag phi_vocabulary when one line mixes different weak stems', () => {
  assert.deepEqual(classifyLine('the diagnostic and prognostic checks handle a disorder state'), []);
});

test('classifyLine weak-marker exemption is case-insensitive for every occurrence on the line', () => {
  assert.deepEqual(classifyLine('Diagnostic output and DIAGNOSTIC output and diagnostic output'), []);
});

test('classifyLine gives the same answer on every call for a line with repeated weak markers', () => {
  // The weak-marker regex is global; a stateful lastIndex would make repeated calls disagree.
  // Fails against the pre-fix regex too (it consistently answers phi_vocabulary, not clean).
  const line = 'the diagnostic path logs the diagnostic result and a diagnostic summary';
  const answers = new Set();
  for (let call = 0; call < 6; call += 1) answers.add(JSON.stringify(classifyLine(line)));
  assert.deepEqual([...answers], ['[]']);
});

// Guards: widening the exemption to every occurrence must not exempt a line that has real PHI
// evidence. These two pass both before and after the fix; they pin the boundary of the exemption.
test('classifyLine still flags a strong PHI marker even when the same line repeats weak markers', () => {
  assert.deepEqual(classifyLine(`${W_PSYCHIATRIC} ${W_DIAGNOSTIC} ${W_DIAGNOSTIC}`), ['phi_vocabulary']);
});

test('classifyLine still flags repeated weak markers when medical context is on the same line', () => {
  assert.deepEqual(classifyLine(`patient ${W_DIAGNOSTIC} and ${W_DIAGNOSTIC} notes`), ['phi_vocabulary']);
});

test('classifyLine flags cui_dod_id for a DoD ID number shape', () => {
  // A bare 10-digit number is ALSO a plausible account_number_shape
  // (_NUM_SHAPE is \b\d{8,17}\b, no timestamp-context word here to suppress
  // it), and there is no cui_dod_id/account_number_shape suppression.
  // Multiple simultaneous hits are the expected behavior of this classifier
  // (see the "returns multiple categories" test below), so both categories
  // firing here is correct, not a defect to suppress.
  assert.deepEqual(new Set(classifyLine(`DoD ID: ${DOD_ID_SHAPE}`)), new Set(['account_number_shape', 'cui_dod_id']));
});

test('classifyLine flags cui_dod_id for an explicit CUI marking', () => {
  assert.deepEqual(classifyLine('CUI//SP-PRVCY handling required'), ['cui_dod_id']);
});

test('classifyLine flags vendor_api_key for a real-shaped Anthropic key', () => {
  assert.deepEqual(classifyLine('sk-ant-api03-' + 'a'.repeat(24)), ['vendor_api_key']);
});

test('classifyLine flags generic_secret for an unquoted assignment with digit entropy', () => {
  assert.deepEqual(classifyLine("\u0041\u0050\u0049\u005f\u004b\u0045\u0059\u003d\u0061\u0062\u0063\u0031\u0032\u0033\u0064\u0065\u0066\u0034\u0035\u0036\u0067\u0068\u0069\u0037"), ['generic_secret']);
});

test('classifyLine returns multiple categories when several fire on one line', () => {
  const hits = classifyLine(`${W_MEDICATION} record, account ${ACCT_LONG}, ${USD}1,200.00 owed`);
  assert.deepEqual(new Set(hits), new Set(['phi_vocabulary', 'account_number_shape', 'dollar_figure']));
});

test('classifyLine returns no hits for an ordinary sentence', () => {
  assert.deepEqual(classifyLine('the scrub engine runs before any hash is computed'), []);
});

test('classifyLine rejects a non-string line', () => {
  assert.throws(() => classifyLine(null), TypeError);
  assert.throws(() => classifyLine(undefined), TypeError);
});

test('matchesIdentityList does a case-insensitive substring match against known entries', () => {
  const identityList = ['jane q. public', 'acme corp'];
  assert.equal(matchesIdentityList('Jane Q. Public called today', identityList), true);
  assert.equal(matchesIdentityList('ACME CORP invoice attached', identityList), true);
  assert.equal(matchesIdentityList('no match here', identityList), false);
});

test('matchesIdentityList rejects a non-array identityList', () => {
  assert.throws(() => matchesIdentityList('text', null), TypeError);
});

test('matchesIdentityList rejects a non-string text', () => {
  assert.throws(() => matchesIdentityList(null, ['a']), TypeError);
  assert.throws(() => matchesIdentityList(undefined, ['a']), TypeError);
});

test('matchesIdentityList does not match everything when identityList contains an empty-string entry', () => {
  // `anyString.includes('')` is always true in JS, so an unguarded empty
  // entry would report a match against ANY text. Through scrub-engine.mjs's
  // smell test, identityList: [''] would then hard-block every scrub() call,
  // including fully clean text, mislabeled identity_residual. Mirrors the
  // length===0 guard scrub-engine.mjs's findIdentityIntervals() already has.
  assert.equal(matchesIdentityList('anything', ['']), false);
  // A real entry alongside an empty one still matches correctly.
  assert.equal(matchesIdentityList('Jane Q. Public called', ['', 'jane q. public']), true);
});

test('matchesIdentityList does not over-match when identityList contains a whitespace-only entry', () => {
  // Same failure shape one level up from the empty-string case: a
  // whitespace-only entry (e.g. ' ', '\t') doesn't match EVERYTHING, but an
  // unguarded raw-length check lets it over-match every run of that exact
  // whitespace anywhere in the document. Checked on trimmed length instead.
  assert.equal(matchesIdentityList('an ordinary line of spec prose', [' ']), false);
  assert.equal(matchesIdentityList('a line with a\ttab in it', ['\t']), false);
});
