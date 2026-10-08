import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

function runHook(payload) {
  const stdout = execFileSync(process.execPath, ['hooks/review-nudge.mjs'], {
    input: JSON.stringify(payload), encoding: 'utf8',
  });
  return stdout.trim() === '' ? null : JSON.parse(stdout);
}

test('writing a spec emits an additionalContext nudge naming the review profile', () => {
  const output = runHook({
    tool_name: 'Write',
    tool_input: { file_path: "\u0043\u003a\u005c\u0072\u0065\u0070\u006f\u005c\u0064\u006f\u0063\u0073\u005c\u0073\u0075\u0070\u0065\u0072\u0070\u006f\u0077\u0065\u0072\u0073\u005c\u0073\u0070\u0065\u0063\u0073\u005c\u0032\u0030\u0032\u0036\u002d\u0030\u0039\u002d\u0030\u0031\u002d\u0074\u0068\u0069\u006e\u0067\u002d\u0064\u0065\u0073\u0069\u0067\u006e\u002e\u006d\u0064" },
  });
  assert.equal(output.hookSpecificOutput.hookEventName, 'PostToolUse');
  assert.match(output.hookSpecificOutput.additionalContext, /impl_review_v1|cross-vendor/i);
});

test('writing an unrelated file emits nothing', () => {
  assert.equal(runHook({ tool_name: 'Write', tool_input: { file_path: "\u0043\u003a\u005c\u0072\u0065\u0070\u006f\u005c\u0073\u0072\u0063\u005c\u0074\u0068\u0069\u006e\u0067\u002e\u006d\u006a\u0073" } }), null);
});

test('a malformed payload exits quietly rather than breaking the session', () => {
  const stdout = execFileSync(process.execPath, ['hooks/review-nudge.mjs'], { input: 'not json', encoding: 'utf8' });
  assert.equal(stdout.trim(), '');
});
