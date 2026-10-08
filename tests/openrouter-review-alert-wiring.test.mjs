import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD,
  DEFAULT_SPEND_ALERT_THRESHOLD_FRACTION,
} from '../src/local-mcp/review-engine.mjs';
import { resolveConsecutiveDispatchFailureAlertThreshold } from '../tools/openrouter-review-mcp-server.mjs';

// Mirrors tests/openrouter-review-daily-allowance.test.mjs's own resolver-plus-wiring pattern: a
// source-grep test alone can prove a string EXISTS but never that it is actually WIRED -- so the
// resolver itself is imported and exercised directly, and a SEPARATE test below proves the
// resolved value actually reaches createReviewEngine, not somewhere it would be silently ignored.

// A checkout may use CRLF line endings (`core.autocrlf=true`, same concern handled in
// tests/openrouter-review-dispatch-launcher.test.mjs), so a bare `'\n}\n'` search against the raw
// source would return -1 -- `body` would then become nearly the ENTIRE REST OF THE FILE rather
// than just the createReviewEngine call site, and the wiring tests below could pass for the wrong
// reason (their regexes happen not to match anywhere else in the file). Normalizing to LF first,
// plus asserting neither indexOf call returns -1, makes a moved anchor fail loudly rather than
// silently searching the wrong span.
async function readCreateReviewEngineCallBody() {
  const source = (await readFile('tools/openrouter-review-mcp-server.mjs', 'utf8')).replace(/\r\n/g, '\n');
  const startIdx = source.indexOf('return createReviewEngine(');
  assert.notEqual(startIdx, -1, 'return createReviewEngine( not found in tools/openrouter-review-mcp-server.mjs');
  const createCall = source.slice(startIdx);
  const endIdx = createCall.indexOf('\n}\n');
  assert.notEqual(endIdx, -1, 'closing \\n}\\n not found after the createReviewEngine call');
  return createCall.slice(0, endIdx);
}

test('the exported default thresholds match the values documented in review-engine.mjs', () => {
  assert.equal(DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD, 3);
  assert.equal(DEFAULT_SPEND_ALERT_THRESHOLD_FRACTION, 0.75);
});

test('the consecutive-dispatch-failure alert threshold defaults to 3 when the env var is unset', () => {
  assert.equal(resolveConsecutiveDispatchFailureAlertThreshold({}), 3);
});

test('the consecutive-dispatch-failure alert threshold honors a valid env override', () => {
  assert.equal(resolveConsecutiveDispatchFailureAlertThreshold({ OPENROUTER_REVIEW_MCP_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD: '5' }), 5);
});

test('a malformed consecutive-dispatch-failure alert threshold fails closed', () => {
  assert.throws(
    () => resolveConsecutiveDispatchFailureAlertThreshold({ OPENROUTER_REVIEW_MCP_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD: 'three' }),
    /must be a positive integer/
  );
  assert.throws(
    () => resolveConsecutiveDispatchFailureAlertThreshold({ OPENROUTER_REVIEW_MCP_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD: '0' }),
    /must be a positive integer/
  );
  assert.throws(
    () => resolveConsecutiveDispatchFailureAlertThreshold({ OPENROUTER_REVIEW_MCP_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD: '-1' }),
    /must be a positive integer/
  );
});

// Separately assert the resolved threshold, the real key-status probe, and the real durable
// dispatch-health store actually reach createReviewEngine's constructor call in
// buildProductionEngine, since the resolver/adapter/store existing and working in isolation
// (proven above and in their own dedicated test files) does not by itself prove any of them were
// actually passed to the right place.
test('the resolved threshold, key-status probe, and dispatch-health store are wired into createReviewEngine, not left unused', async () => {
  const body = await readCreateReviewEngineCallBody();
  assert.match(body, /consecutiveDispatchFailureAlertThreshold:\s*resolveConsecutiveDispatchFailureAlertThreshold\(\)/);
  assert.match(body, /keyStatusProbe:\s*createKeyStatusProbeAdapter\(\)/);
  assert.match(body, /dispatchHealthStore:\s*createDispatchHealthStore\(\{\s*dataRoot:\s*config\.dataRoot\s*\}\)/);
});

// Same reasoning as the test above, for the two health-verdict timing knobs:
// resolveProductionEngineConfig resolving them correctly (proven in
// tests/openrouter-review-dispatch-config.test.mjs) does not by itself prove either value
// reaches createReviewEngine rather than being silently ignored in buildProductionEngine.
test('the resolved health-verdict grace and backstop overrides are wired into createReviewEngine, not left unused', async () => {
  const body = await readCreateReviewEngineCallBody();
  assert.match(body, /healthVerdictGraceMs:\s*config\.healthVerdictGraceMs/);
  assert.match(body, /healthVerdictBackstopMs:\s*config\.healthVerdictBackstopMs/);
});
