import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { DEFAULT_ARM_LOCK_RETRY_MS, DEFAULT_ARM_TIMEOUT_MS } from '../src/local-mcp/ownership-coordinator.mjs';
import { resolveProductionEngineConfig } from '../tools/openrouter-review-mcp-server.mjs';

// A review dispatch (a full structured-JSON code review over up to ~2MB of
// source) is a much heavier generation workload than the 3-call arithmetic
// smoke-test harness, so a 120000ms timeout borrowed from that harness (a
// 150000ms hard-kill ceiling with the adapter's 30000ms headroom) is far too
// short. These tests pin that the dispatch timeout default is well above it
// and operator-configurable, the same pattern used for the installation spend
// ceiling.

const BASE_ENV = Object.freeze({
  OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD: '5',
  LOCALAPPDATA: 'C:\\fake-local-appdata',
  // Required, with no default: the explicit choice of no owner-supplied extra protected terms.
  OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_PATH: 'none',
});

test('resolveProductionEngineConfig defaults dispatchTimeoutMs well above the old 120s smoke-test-borrowed value', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.ok(
    resolved.config.dispatchTimeoutMs >= 600_000,
    `expected dispatchTimeoutMs >= 600000, got ${resolved.config.dispatchTimeoutMs}`,
  );
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS: '900000',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.dispatchTimeoutMs, 900_000);
});

test('resolveProductionEngineConfig fails closed on a non-numeric dispatch timeout override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS: 'not-a-number',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS/);
});

test('resolveProductionEngineConfig fails closed on a non-positive dispatch timeout override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS: '0',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS/);
});

// The resolver uses the same Number.isSafeInteger rule as createDispatchAdapter's
// own constructor. Accepting any finite positive number (e.g. "1.5") would let a
// fractional override pass config resolution (ok:true) and then crash later
// inside buildProductionEngine's engine construction instead of failing cleanly
// here. Both timeout-shaped env vars validate with that rule.
test('resolveProductionEngineConfig fails closed on a non-integer (fractional) dispatch timeout override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS: '1.5',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS/);
});

// With a 600000ms dispatch timeout and two reviewers dispatched sequentially,
// a worst case of ~1,260,000ms (21 min) exceeds review-engine.mjs's own
// default preflightTtlMs (15 min) --
// the human-approved lease window. Without a wider (or bounded) window, a
// legitimately slow-but-successful second reviewer would routinely halt on
// LEASE_EXPIRED even though nothing unsafe happened. This mirrors the
// dispatch timeout's own env var / default / fail-closed shape.
test('resolveProductionEngineConfig defaults preflightTtlMs to at least 1,260,000ms (worst-case sequential dispatch) plus margin', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.ok(
    resolved.config.preflightTtlMs >= 1_800_000,
    `expected preflightTtlMs >= 1800000, got ${resolved.config.preflightTtlMs}`,
  );
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS: '2400000',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.preflightTtlMs, 2_400_000);
});

test('resolveProductionEngineConfig fails closed on a non-integer preflight TTL override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS: '2.5',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS/);
});

test('resolveProductionEngineConfig fails closed on a non-positive preflight TTL override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS: '-1',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS/);
});

// Orphan recovery: a lease can be left ACTIVE with a RESERVED job when the
// process that reserved it is replaced before it can reconcile. The grace
// window before a stale RESERVED job is treated as safe to force-close follows
// the same env var / default / fail-closed shape as the two timeouts above.
test('resolveProductionEngineConfig defaults orphanSweepGraceMs to at least 120,000ms (4x the dispatch adapter\'s own ~30s worst-case backstop overshoot)', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.ok(
    resolved.config.orphanSweepGraceMs >= 120_000,
    `expected orphanSweepGraceMs >= 120000, got ${resolved.config.orphanSweepGraceMs}`,
  );
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS: '300000',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.orphanSweepGraceMs, 300_000);
});

test('resolveProductionEngineConfig fails closed on a non-integer orphan sweep grace override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS: '2.5',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS/);
});

test('resolveProductionEngineConfig fails closed on a non-positive orphan sweep grace override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS: '0',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS/);
});

// Deferred dispatch-health reconciliation: healthVerdictGraceMs/healthVerdictBackstopMs are
// createReviewEngine constructor options with their own in-process defaults (6 min / 1 hr).
// Like every sibling timing knob in this file (dispatch timeout, preflight TTL, orphan sweep
// grace), they also get an env-var override resolved through resolveProductionEngineConfig.
// These tests mirror the orphan sweep grace group above exactly: default, explicit override, and
// fail-closed on a non-integer or non-positive value, all diagnosed at config-resolution time.
test('resolveProductionEngineConfig defaults healthVerdictGraceMs to review-engine.mjs\'s own 6-minute default', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.healthVerdictGraceMs, 6 * 60 * 1000);
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS: '120000',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.healthVerdictGraceMs, 120_000);
});

test('resolveProductionEngineConfig fails closed on a non-integer health verdict grace override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS: '2.5',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS/);
});

test('resolveProductionEngineConfig fails closed on a non-positive health verdict grace override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS: '0',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS/);
});

test('resolveProductionEngineConfig defaults healthVerdictBackstopMs to review-engine.mjs\'s own 1-hour default', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.healthVerdictBackstopMs, 60 * 60 * 1000);
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS: '1800000',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.healthVerdictBackstopMs, 1_800_000);
});

test('resolveProductionEngineConfig fails closed on a non-integer health verdict backstop override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS: '2.5',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS/);
});

test('resolveProductionEngineConfig fails closed on a non-positive health verdict backstop override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS: '0',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS/);
});

// The scrub engine's Ollama base URL / model / timeout are resolved through
// resolveProductionEngineConfig rather than read directly off process.env
// inside buildProductionEngine, so that function stays a pure function of its
// already-validated config argument and a bad
// OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS value fails with a message naming
// the env var and the bad value, not incidentally deep inside
// createOllamaClient's own Number.isSafeInteger check. These tests mirror the dispatch
// timeout / preflight TTL / orphan sweep grace groups above: default,
// explicit override, and (for the numeric timeout) fail-closed on a
// non-numeric or non-positive value, all diagnosed at config-resolution
// time, before any engine construction.
test('resolveProductionEngineConfig defaults ollamaBaseUrl to the local Ollama daemon', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.ollamaBaseUrl, 'http://localhost:11434');
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_OLLAMA_URL override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_OLLAMA_URL: 'http://localhost:22222',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.ollamaBaseUrl, 'http://localhost:22222');
});

test('resolveProductionEngineConfig defaults ollamaModel to qwen2.5:7b', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.ollamaModel, 'qwen2.5:7b');
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_OLLAMA_MODEL override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_OLLAMA_MODEL: 'llama3:8b',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.ollamaModel, 'llama3:8b');
});

test('resolveProductionEngineConfig defaults ollamaTimeoutMs to a value a real full-size chunk can actually finish in', () => {
  // A single local-model classification of a full-size chunk can take minutes
  // under load, so a short wall would turn an alive-but-busy model into an
  // ok:false, which the scrub engine then reports as a blocked send. A
  // timeout is not how a DOWN Ollama fails (that is an immediate connection
  // refusal), so a generous wall costs nothing in the outage case and only
  // bounds a genuine hang.
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.ollamaTimeoutMs, 300_000);
  assert.ok(
    resolved.config.ollamaTimeoutMs >= 120_000,
    'the default must leave minutes of headroom for a slow local classification',
  );
});

test('resolveProductionEngineConfig honors an explicit OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS: '5000',
  });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.ollamaTimeoutMs, 5_000);
});

test('resolveProductionEngineConfig fails closed on a non-numeric Ollama timeout override, naming the env var and the bad value', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS: 'not-a-number',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS/);
  assert.match(resolved.reason, /not-a-number/);
});

test('resolveProductionEngineConfig fails closed on a non-positive Ollama timeout override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS: '0',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS/);
});

test('resolveProductionEngineConfig fails closed on a fractional Ollama timeout override', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS: '1.5',
  });
  assert.equal(resolved.ok, false);
  assert.match(resolved.reason, /OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS/);
});

// ---------------------------------------------------------------------------
// The arm budget and the arming loop's base retry interval are operator settings resolved here,
// like every sibling timing knob in this file: default, explicit override, and fail-closed on
// anything that is not a positive integer. The defaults are the coordinator's own exported
// constants, so the server and the engine can never drift apart. The two wiring tests further down
// pin the import and the propagation into createReviewEngine.
// ---------------------------------------------------------------------------
const ARM_TIMEOUT_VAR = 'OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS';
const ARM_LOCK_RETRY_VAR = 'OPENROUTER_REVIEW_MCP_ARM_LOCK_RETRY_MS';

// Every rejected value must fail the WHOLE config (never a silent fallback to the default), name the
// variable, and quote the value it rejected, so the operator can see which setting to fix.
function assertArmSettingFailsClosed(varName, raw) {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV, [varName]: raw });
  assert.equal(resolved.ok, false, `${varName}=${JSON.stringify(raw)} must fail closed`);
  assert.ok(resolved.reason.includes(varName), `the reason must name ${varName}; got ${resolved.reason}`);
  assert.ok(resolved.reason.includes(JSON.stringify(raw)), `the reason must quote the rejected value; got ${resolved.reason}`);
}

test('resolveProductionEngineConfig defaults armTimeoutMs and armLockRetryMs to ownership-coordinator.mjs\'s own exported defaults', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.config.armTimeoutMs, DEFAULT_ARM_TIMEOUT_MS);
  assert.equal(resolved.config.armLockRetryMs, DEFAULT_ARM_LOCK_RETRY_MS);
});

test('resolveProductionEngineConfig honors valid OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS and OPENROUTER_REVIEW_MCP_ARM_LOCK_RETRY_MS overrides, down to the smallest positive integer', () => {
  for (const [armTimeoutRaw, armLockRetryRaw, expected] of [['5000', '75', [5_000, 75]], ['1', '1', [1, 1]]]) {
    const resolved = resolveProductionEngineConfig({
      ...BASE_ENV,
      [ARM_TIMEOUT_VAR]: armTimeoutRaw,
      [ARM_LOCK_RETRY_VAR]: armLockRetryRaw,
    });
    assert.equal(resolved.ok, true, `${armTimeoutRaw}/${armLockRetryRaw} must be accepted; got ${JSON.stringify(resolved)}`);
    assert.deepEqual([resolved.config.armTimeoutMs, resolved.config.armLockRetryMs], expected);
  }
});

test('a zero or negative OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS fails closed', () => {
  for (const raw of ['0', '-1', '-250']) assertArmSettingFailsClosed(ARM_TIMEOUT_VAR, raw);
});

test('a non-integer or garbage OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS fails closed', () => {
  for (const raw of ['2.5', 'not-a-number', '250ms', 'Infinity']) assertArmSettingFailsClosed(ARM_TIMEOUT_VAR, raw);
});

test('a zero or negative OPENROUTER_REVIEW_MCP_ARM_LOCK_RETRY_MS fails closed', () => {
  for (const raw of ['0', '-1', '-250']) assertArmSettingFailsClosed(ARM_LOCK_RETRY_VAR, raw);
});

test('a non-integer or garbage OPENROUTER_REVIEW_MCP_ARM_LOCK_RETRY_MS fails closed', () => {
  for (const raw of ['2.5', 'not-a-number', '250ms', 'Infinity']) assertArmSettingFailsClosed(ARM_LOCK_RETRY_VAR, raw);
});

// ---------------------------------------------------------------------------
// OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS is RETIRED. It bounded the startup
// acquire, and there is no startup acquire any more. It must not be silently repurposed as the arm
// budget (that would change the meaning of a number an operator already chose), it must never fail
// startup (it is not parsed at all now), and a set value must produce exactly one warning telling the
// operator to delete it, because an existing client configuration may still set it.
// ---------------------------------------------------------------------------
test('a garbage value in the retired acquire-timeout variable warns instead of failing startup', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS: 'not-a-number',
  });
  assert.equal(resolved.ok, true, `a retired variable must never fail startup; got ${JSON.stringify(resolved)}`);
  assert.ok(Array.isArray(resolved.warnings), 'resolveProductionEngineConfig must return a warnings array on success');
  assert.equal(resolved.warnings.length, 1);
  assert.match(resolved.warnings[0], /OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS/);
  assert.match(resolved.warnings[0], /no longer does anything/);
  assert.match(resolved.warnings[0], /[Dd]elete it/);
});

test('a numeric retired value gives exactly one warning and is not repurposed as the arm budget', () => {
  const resolved = resolveProductionEngineConfig({
    ...BASE_ENV,
    OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS: '45000',
  });
  assert.equal(resolved.ok, true);
  assert.ok(Array.isArray(resolved.warnings), 'resolveProductionEngineConfig must return a warnings array on success');
  assert.equal(resolved.warnings.length, 1);
  assert.equal(resolved.config.armTimeoutMs, DEFAULT_ARM_TIMEOUT_MS, 'the retired value must not leak into the arm budget');
});

test('an unset or blank retired variable gives no warning', () => {
  for (const env of [{ ...BASE_ENV }, { ...BASE_ENV, OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS: '   ' }]) {
    const resolved = resolveProductionEngineConfig(env);
    assert.equal(resolved.ok, true);
    assert.ok(Array.isArray(resolved.warnings), 'resolveProductionEngineConfig must return a warnings array on success');
    assert.deepEqual(resolved.warnings, []);
  }
});

test('the retired acquire timeout is no longer a config field at all', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV });
  assert.equal(resolved.ok, true);
  assert.equal(Object.hasOwn(resolved.config, 'acquireProcessOwnershipTimeoutMs'), false);
});

// Same approach as tests/openrouter-review-alert-wiring.test.mjs: normalize CRLF to LF
// first and fail loudly on a moved anchor, rather than silently searching the rest of the file.
async function readCreateReviewEngineCallBody() {
  const source = (await readFile('tools/openrouter-review-mcp-server.mjs', 'utf8')).replace(/\r\n/g, '\n');
  const startIdx = source.indexOf('return createReviewEngine(');
  assert.notEqual(startIdx, -1, 'return createReviewEngine( not found in tools/openrouter-review-mcp-server.mjs');
  const createCall = source.slice(startIdx);
  const endIdx = createCall.indexOf('\n}\n');
  assert.notEqual(endIdx, -1, 'closing \n}\n not found after the createReviewEngine call');
  return createCall.slice(0, endIdx);
}

// Propagation. Resolving the two values correctly (above) does not prove they reach the engine: a
// value resolved and never passed is silently replaced by the engine's own default. The call-site
// body is read CRLF-normalized, with both anchors asserted, so a moved anchor fails loudly.
test('the resolved arm timeout and arm lock retry are propagated into createReviewEngine, not left unused', async () => {
  const body = await readCreateReviewEngineCallBody();
  assert.match(body, /armTimeoutMs:\s*config\.armTimeoutMs/);
  assert.match(body, /armLockRetryMs:\s*config\.armLockRetryMs/);
});

// Defaults. The default-value test above cannot tell an imported constant from a re-typed copy
// of the same number; this pins the import, so a future edit to the coordinator's defaults reaches
// the server too.
test('the server takes the arm defaults from ownership-coordinator.mjs rather than re-typing them', async () => {
  const source = (await readFile('tools/openrouter-review-mcp-server.mjs', 'utf8')).replace(/\r\n/g, '\n');
  assert.match(source, /import \{ DEFAULT_ARM_LOCK_RETRY_MS, DEFAULT_ARM_TIMEOUT_MS \} from '\.\.\/src\/local-mcp\/ownership-coordinator\.mjs';/);
  assert.match(source, /parsePositiveIntegerMsOverride\(env, ARM_TIMEOUT_ENV_VAR, DEFAULT_ARM_TIMEOUT_MS\)/);
  assert.match(source, /parsePositiveIntegerMsOverride\(env, ARM_LOCK_RETRY_ENV_VAR, DEFAULT_ARM_LOCK_RETRY_MS\)/);
});
