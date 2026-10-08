import assert from 'node:assert/strict';
import test from 'node:test';
import { RESPONSE_FORMAT, SCHEMA_SHA256, stripJsonFraming, validateAdvisoryContent } from '../src/review-core/advisory-schema.mjs';

const VALID_FINDING = {
  severity: 'major',
  section: 'validation',
  root_cause: 'the result omits a required guard',
  affected_behavior: 'malformed responses are accepted',
  consequence: 'the review can fail open',
  evidence: ['the guard is absent from the response path'],
};

test('RESPONSE_FORMAT pins the strict OpenRouter advisory review schema', () => {
  assert.deepEqual(RESPONSE_FORMAT, {
    type: 'json_schema',
    json_schema: {
      name: 'openrouter_advisory_review_v1',
      strict: true,
      schema: {
        type: 'object',
        additionalProperties: false,
        required: ['verdict', 'findings'],
        properties: {
          verdict: { type: 'string', enum: ['pass', 'block'] },
          findings: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['severity', 'section', 'root_cause', 'affected_behavior', 'consequence', 'evidence'],
              properties: {
                severity: { type: 'string', enum: ['blocker', 'major', 'minor'] },
                section: { type: 'string', minLength: 1 },
                root_cause: { type: 'string', minLength: 1 },
                affected_behavior: { type: 'string', minLength: 1 },
                consequence: { type: 'string', minLength: 1 },
                evidence: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 } },
              },
            },
          },
        },
      },
    },
  });
});

test('SCHEMA_SHA256 is a stable 64-character lowercase hex digest', () => {
  assert.equal(SCHEMA_SHA256, 'e37a3122fdc622ef3d99cdd022e3a456d15dfa17f76fd25d3aa57bfe906c2878');
  assert.match(SCHEMA_SHA256, /^[0-9a-f]{64}$/);
});

test('validateAdvisoryContent accepts valid review content with a compact result contract', () => {
  assert.deepEqual(validateAdvisoryContent(JSON.stringify({ verdict: 'block', findings: [VALID_FINDING] })), {
    ok: true,
    reason: null,
    verdict: 'block',
    findingCount: 1,
  });
});

test('validateAdvisoryContent rejects extra review-root properties', () => {
  const result = validateAdvisoryContent(JSON.stringify({ verdict: 'pass', findings: [], unexpected: true }));
  assert.deepEqual(result, {
    ok: false,
    reason: 'review content has an unexpected property "unexpected"',
    verdict: null,
    findingCount: null,
  });
});

test('validateAdvisoryContent rejects extra finding properties', () => {
  const result = validateAdvisoryContent(JSON.stringify({
    verdict: 'block',
    findings: [{ ...VALID_FINDING, unexpected: true }],
  }));
  assert.deepEqual(result, {
    ok: false,
    reason: 'findings[0] has an unexpected property "unexpected"',
    verdict: 'block',
    findingCount: null,
  });
});

test('validateAdvisoryContent caps an oversized unexpected finding property name in the reason string', () => {
  const longName = 'x'.repeat(500);
  const result = validateAdvisoryContent(JSON.stringify({
    verdict: 'block',
    findings: [{ ...VALID_FINDING, [longName]: true }],
  }));
  assert.equal(result.ok, false);
  assert.ok(result.reason.length < 200, `reason should be capped, was ${result.reason.length} chars`);
  assert.match(result.reason, /^findings\[0\] has an unexpected property "x+\.\.\. \(truncated, 500 chars total\)"$/);
});

test('validateAdvisoryContent caps an oversized unexpected review-root property name in the reason string', () => {
  const longName = 'y'.repeat(500);
  const result = validateAdvisoryContent(JSON.stringify({ verdict: 'pass', findings: [], [longName]: true }));
  assert.equal(result.ok, false);
  assert.ok(result.reason.length < 200, `reason should be capped, was ${result.reason.length} chars`);
  assert.match(result.reason, /^review content has an unexpected property "y+\.\.\. \(truncated, 500 chars total\)"$/);
});

test('validateAdvisoryContent caps an oversized invalid finding.severity value in the reason string', () => {
  const longSeverity = 'z'.repeat(500);
  const result = validateAdvisoryContent(JSON.stringify({
    verdict: 'block',
    findings: [{ ...VALID_FINDING, severity: longSeverity }],
  }));
  assert.equal(result.ok, false);
  assert.ok(result.reason.length < 200, `reason should be capped, was ${result.reason.length} chars`);
  assert.match(result.reason, /^findings\[0\]\.severity "z+\.\.\. \(truncated, 500 chars total\)" is outside the enum$/);
});

test('validateAdvisoryContent caps an oversized invalid verdict value in the reason string', () => {
  const longVerdict = 'w'.repeat(500);
  const result = validateAdvisoryContent(JSON.stringify({ verdict: longVerdict, findings: [] }));
  assert.equal(result.ok, false);
  assert.ok(result.reason.length < 200, `reason should be capped, was ${result.reason.length} chars`);
  assert.match(result.reason, /^verdict "w+\.\.\. \(truncated, 500 chars total\)" is outside the enum$/);
});

test('validateAdvisoryContent reports a short, ordinary invalid value unchanged (no truncation marker)', () => {
  const result = validateAdvisoryContent(JSON.stringify({ verdict: 'critical', findings: [] }));
  assert.deepEqual(result, {
    ok: false,
    reason: 'verdict "critical" is outside the enum',
    verdict: null,
    findingCount: null,
  });
});

test('validateAdvisoryContent describes a non-string invalid severity value structurally, not via toString coercion', () => {
  const result = validateAdvisoryContent(JSON.stringify({
    verdict: 'block',
    findings: [{ ...VALID_FINDING, severity: ['a', 'b'] }],
  }));
  assert.equal(result.ok, false);
  // Array.prototype.toString() would silently comma-join to "a,b" -- assert the safer
  // JSON-shaped rendering is used instead so structure (and any embedded quoting) is visible.
  assert.equal(result.reason, 'findings[0].severity "["a","b"]" is outside the enum');
});

test('stripJsonFraming removes a fenced json code block and surrounding whitespace', () => {
  const fenced = '```json\n{"verdict":"pass","findings":[]}\n```';
  assert.equal(stripJsonFraming(fenced), '{"verdict":"pass","findings":[]}');
});

test('stripJsonFraming removes a bare fence without a json language tag', () => {
  const fenced = '```\n{"verdict":"pass","findings":[]}\n```';
  assert.equal(stripJsonFraming(fenced), '{"verdict":"pass","findings":[]}');
});

test('stripJsonFraming trims whitespace around unfenced content and leaves it otherwise unchanged', () => {
  assert.equal(stripJsonFraming('  \n{"verdict":"pass","findings":[]}\n  '), '{"verdict":"pass","findings":[]}');
});

test('stripJsonFraming leaves malformed/non-JSON text unchanged (only trimmed) so downstream validation still fails as expected', () => {
  assert.equal(stripJsonFraming('  here is my review: not json  '), 'here is my review: not json');
});

test('stripJsonFraming rejects non-string input', () => {
  assert.throws(() => stripJsonFraming(42), /text must be a string/);
});

test('stripJsonFraming does not strip a fence when there is leading prose before it (falls through to trim-only)', () => {
  const withProse = "Here's my review:\n```json\n{\"verdict\":\"pass\",\"findings\":[]}\n```";
  assert.equal(stripJsonFraming(withProse), withProse.trim());
});

test('stripJsonFraming with two fenced blocks in one response merges them into one capture (documented, not a bug -- still fails safe downstream)', () => {
  const twoFences = '```json\n{"a":1}\n```\nsome text\n```json\n{"b":2}\n```';
  assert.equal(stripJsonFraming(twoFences), '{"a":1}\n```\nsome text\n```json\n{"b":2}');
});
