// A raw error.message interpolated into a stderr.write(...) diagnostic line could, at several
// sites in review-engine.mjs, carry a fragment of real reviewer-generated or document content
// into an unredacted local log. safeErrorDetail() is the single choke point every such site
// routes through instead of interpolating error.message directly.
//
// safeErrorDetail() NEVER passes error.message through, under any condition, and never trusts a
// `.code`/`.name` value by SHAPE -- only by exact membership in a small, fixed, hardcoded set.
// Every conditional-passthrough design is forgeable: a message-SHAPE check ("<CODE>:
// description") by any application error whose message happens to start that way; a
// `.code`-ALLOWLIST-by-real-Node-codes check equally, since `.code` is just a plain settable
// property; an open-ended SHAPE check on `.code`/`.name` (uppercase letters/digits/underscores,
// length-capped) ALSO, since some real secrets and content fragments (e.g. an AWS-style
// access-key ID) are indistinguishable by shape alone from a genuine enum-style code. There is no property
// on a plain JS Error that reliably proves genuine origin, so this function reports only a
// generic label (a `.code`/`.name` value that is byte-for-byte a member of a fixed set of known
// constants, else 'Error') plus a fixed marker -- never the message text itself, and never an
// unrecognized `.code`/`.name` value, regardless of what produced the error.
import assert from 'node:assert/strict';
import test from 'node:test';
import { safeErrorDetail } from '../src/local-mcp/review-engine.mjs';

test('a genuine Node syscall error reports its .code as the label, never its .message', () => {
  const error = Object.assign(new Error("\u0045\u004e\u004f\u0045\u004e\u0054\u003a\u0020\u006e\u006f\u0020\u0073\u0075\u0063\u0068\u0020\u0066\u0069\u006c\u0065\u0020\u006f\u0072\u0020\u0064\u0069\u0072\u0065\u0063\u0074\u006f\u0072\u0079\u002c\u0020\u006f\u0070\u0065\u006e\u0020\u0027\u0043\u003a\u005c\u0064\u0061\u0074\u0061\u005c\u006c\u0065\u0064\u0067\u0065\u0072\u005c\u0078\u002e\u006a\u0073\u006f\u006e\u0027"), { code: 'ENOENT' });
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'ENOENT (detail redacted)');
  assert.ok(!detail.includes('no such file or directory'), 'the message text must never appear, even for a genuine Node error');
});

test('a ReviewEngineError-shaped error reports its enum .code as the label, message never included', () => {
  const error = Object.assign(new Error('reviewContext must be a string'), { code: 'SOURCE_INVALID', name: 'ReviewEngineError' });
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'SOURCE_INVALID (detail redacted)');
});

test('a custom application error whose message could carry content-derived text never has that text shown', () => {
  const error = Object.assign(new Error('expected string at findings[2].description, got: "the actual real finding text that must never reach a log verbatim"'), { code: 'STRICT_OUTPUT_INVALID' });
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'STRICT_OUTPUT_INVALID (detail redacted)');
  assert.ok(!detail.includes('the actual real finding text'));
});

test('a plain Error with no .code falls back to the generic "Error" label (mixed-case .name is not a plausible enum shape)', () => {
  const error = new Error('some free-form real content fragment that happened to be in a thrown Error');
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'Error (detail redacted)');
  assert.ok(!detail.includes('free-form real content'));
});

test('a non-Error rejection value (e.g. a thrown string or plain object) is never interpolated directly', () => {
  assert.equal(safeErrorDetail('some raw rejection string'), 'non-Error rejection (detail redacted)');
  assert.equal(safeErrorDetail(undefined), 'non-Error rejection (detail redacted)');
  assert.equal(safeErrorDetail(null), 'non-Error rejection (detail redacted)');
});

test('a forged .code equal to a real Node syscall code (e.g. "ENOENT") on a content-bearing error still never shows the message', () => {
  // A .code-allowlist design would fail here: nothing stops an application/content-derived error
  // from carrying .code = 'ENOENT'. The implementation never treats ANY .code value as proof
  // .message is safe.
  const error = Object.assign(
    new Error('the actual real document content that must never reach a log verbatim'),
    { code: 'ENOENT' },
  );
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'ENOENT (detail redacted)');
  assert.ok(!detail.includes('the actual real document content'));
});

test('a .code value that is itself not a plausible enum shape (e.g. contains spaces or lowercase) falls back to a generic label, never printed verbatim', () => {
  const error = Object.assign(new Error('irrelevant'), { code: 'this is not a real code, it has spaces and lowercase' });
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'Error (detail redacted)');
  assert.ok(!detail.includes('this is not a real code'));
});

test('an unrecognized .code value falls back to the generic "Error" label even when it is exactly 40 uppercase/digit/underscore characters (closed-set membership, not shape)', () => {
  // This function's output also reaches a more exposed channel (a caller-visible MCP result, not
  // just a local log). A shape-only regex gate (uppercase letters/digits/underscores, up to 41
  // chars) would accept ANY string of that shape, including one that encodes real content: an
  // access-key-style ID and an arbitrary content fragment written in that shape are both
  // indistinguishable, by shape alone, from a genuine enum-style code like "LEASE_MISSING".
  // Only closed-set MEMBERSHIP in a fixed, hardcoded list
  // of known codes can close this: an attacker can choose any string, but cannot forge equality
  // with a specific constant they don't already know unless it happens to already be a real,
  // meaningless-in-isolation code word.
  const shapedButUnknown = 'AKIAIOSFODNN7EXAMPLE_LOOKS_LIKE_A_SECRET';
  assert.equal(shapedButUnknown.length <= 41, true, 'fixture must actually match the old shape regex to prove this is a real regression, not a vacuous case');
  const detail = safeErrorDetail(Object.assign(new Error('x'), { code: shapedButUnknown }));
  assert.equal(detail, 'Error (detail redacted)');
  assert.ok(!detail.includes("\u0041\u004b\u0049\u0041\u0049\u004f\u0053\u0046\u004f\u0044\u004e\u004e\u0037\u0045\u0058\u0041\u004d\u0050\u004c\u0045"), 'a shape-plausible but unrecognized code must never be printed verbatim');
});

test('a genuine ReviewEngineError code not in the current fixed list would already fail construction, but safeErrorDetail itself never trusts an unrecognized code by shape alone', () => {
  const forgedFutureCode = 'SOME_NEW_ERROR_CODE_NOT_YET_ADDED';
  const detail = safeErrorDetail(Object.assign(new Error('irrelevant'), { code: forgedFutureCode }));
  assert.equal(detail, 'Error (detail redacted)');
});

test('an unrecognized .name value that is shape-plausible (e.g. a forged custom Error subclass name) falls back to the generic "Error" label, not the forged name', () => {
  const forgedName = 'FORGED_ERROR_NAME_WITH_SECRET';
  assert.equal(forgedName.length <= 41, true, 'fixture must actually match the old shape regex to prove this is a real regression, not a vacuous case');
  const error = new Error('irrelevant');
  error.name = forgedName;
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'Error (detail redacted)');
});

// Reading `.code`/`.name` TWICE (once for a `typeof` check, once again to use the value) would
// be unsafe against a getter with side effects -- a value that is a known-safe string on the
// first read could differ (or throw) on the second. safeErrorDetail() must read each
// property EXACTLY ONCE and never let a misbehaving getter make it throw, since it exists
// specifically to be callable from any catch block without extra care.
test('a .code getter that would return a DIFFERENT value on a second read is only ever consulted once, never re-read', () => {
  let reads = 0;
  const error = new Error('irrelevant');
  Object.defineProperty(error, 'code', {
    get() {
      reads += 1;
      if (reads > 1) throw new Error('should never be read twice');
      return 'ENOENT';
    },
  });
  const detail = safeErrorDetail(error);
  assert.equal(detail, 'ENOENT (detail redacted)');
  assert.equal(reads, 1, '.code must be read exactly once');
});

test('a .code getter that throws never crashes safeErrorDetail -- it degrades to the generic "Error" label', () => {
  const error = new Error('irrelevant');
  Object.defineProperty(error, 'code', {
    get() { throw new Error('the actual real content that must never propagate as an uncaught throw'); },
  });
  assert.doesNotThrow(() => safeErrorDetail(error));
  assert.equal(safeErrorDetail(error), 'Error (detail redacted)');
});

test('a .name getter that throws never crashes safeErrorDetail -- it degrades to the generic "Error" label', () => {
  const error = new Error('irrelevant');
  Object.defineProperty(error, 'name', {
    get() { throw new Error('the actual real content that must never propagate as an uncaught throw'); },
  });
  assert.doesNotThrow(() => safeErrorDetail(error));
  assert.equal(safeErrorDetail(error), 'Error (detail redacted)');
});

test('a throwing .code getter does not blot out a still-valid, still-recognized .name -- each property is read independently', () => {
  const error = new Error('irrelevant');
  Object.defineProperty(error, 'code', { get() { throw new Error('boom'); } });
  error.name = 'ReviewEngineError';
  assert.equal(safeErrorDetail(error), 'ReviewEngineError (detail redacted)');
});
