// The per-session server's extra-protected-terms setting. It has no default: the operator must set
// OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_PATH to the literal "none" or to an absolute file path,
// and a path must come with OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_SHA256. Every term is invented.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { EXTRA_PROTECTED_TERMS_HEADER, NO_EXTRA_PROTECTED_TERMS } from '../src/local-mcp/scrub-patterns.mjs';
import { loadExtraProtectedTerms, resolveProductionEngineConfig } from '../tools/openrouter-review-mcp-server.mjs';
import { tempDirFor } from './helpers/test-cleanup.mjs';

const PATH_VAR = 'OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_PATH';
const SHA_VAR = 'OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_SHA256';
const BASE_ENV = Object.freeze({
  OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD: '5',
  OPENROUTER_REVIEW_MCP_DATA_ROOT: resolve('..', 'synthetic-data-root'),
});
const TERMS_TEXT = `# synthetic test fixture\n${EXTRA_PROTECTED_TERMS_HEADER}\nmarker ZQBOARD\ncontext ZQ\n`;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('an unset or blank extra-terms path refuses to start instead of defaulting to no extra terms', () => {
  for (const env of [{ ...BASE_ENV }, { ...BASE_ENV, [PATH_VAR]: '   ' }]) {
    const resolved = resolveProductionEngineConfig(env);
    assert.equal(resolved.ok, false);
    assert.match(resolved.reason, new RegExp(PATH_VAR));
    assert.match(resolved.reason, /none/);
  }
});

test('the literal none is an explicit, valid choice and must not carry a hash', () => {
  const resolved = resolveProductionEngineConfig({ ...BASE_ENV, [PATH_VAR]: 'none' });
  assert.equal(resolved.ok, true);
  assert.deepEqual(resolved.config.extraProtectedTermsSetting, { kind: 'none' });
  const withHash = resolveProductionEngineConfig({ ...BASE_ENV, [PATH_VAR]: 'none', [SHA_VAR]: 'ab'.repeat(32) });
  assert.equal(withHash.ok, false);
  assert.match(withHash.reason, new RegExp(SHA_VAR));
});

test('a terms path must be absolute and pinned by a SHA-256', () => {
  const absolute = resolve('..', 'synthetic-owner-folder', 'extra-terms.txt');
  const digest = 'AB'.repeat(32);
  const good = resolveProductionEngineConfig({ ...BASE_ENV, [PATH_VAR]: absolute, [SHA_VAR]: digest });
  assert.equal(good.ok, true);
  assert.deepEqual(good.config.extraProtectedTermsSetting, { kind: 'file', path: absolute, sha256: digest.toLowerCase() });
  for (const [label, env] of [
    ['relative path', { [PATH_VAR]: 'extra-terms.txt', [SHA_VAR]: digest }],
    ['missing hash', { [PATH_VAR]: absolute }],
    ['blank hash', { [PATH_VAR]: absolute, [SHA_VAR]: ' ' }],
    ['short hash', { [PATH_VAR]: absolute, [SHA_VAR]: 'ab'.repeat(31) }],
    ['non-hex hash', { [PATH_VAR]: absolute, [SHA_VAR]: 'zz'.repeat(32) }],
    ['wrong-case none', { [PATH_VAR]: 'None' }],
  ]) {
    const resolved = resolveProductionEngineConfig({ ...BASE_ENV, ...env });
    assert.equal(resolved.ok, false, label);
  }
});

test('loading none yields exactly the shared empty term set', async () => {
  assert.equal(await loadExtraProtectedTerms({ kind: 'none' }), NO_EXTRA_PROTECTED_TERMS);
});

test('loading a pinned file returns its parsed terms', async (t) => {
  const dir = await tempDirFor(t, 'openrouter-extra-terms-config-');
  const path = join(dir, 'extra-terms.txt');
  await writeFile(path, TERMS_TEXT, 'utf8');
  const terms = await loadExtraProtectedTerms({ kind: 'file', path, sha256: sha256(await readFile(path)) });
  assert.deepEqual(terms, { markers: ['ZQBOARD'], contextTerms: ['ZQ'] });
});

test('loading refuses a missing, changed, malformed or oversized file without echoing its terms or its path', async (t) => {
  const dir = await tempDirFor(t, 'openrouter-extra-terms-config-');
  const path = join(dir, 'extra-terms.txt');
  await writeFile(path, TERMS_TEXT, 'utf8');
  const pinned = sha256(await readFile(path));
  // Every refusal names the setting to fix, never the owner's file location or a term.
  const redacted = (forbidden) => (error) => {
    assert.match(error.message, new RegExp(PATH_VAR));
    for (const value of [dir, 'extra-terms.txt', 'absent.txt', ...forbidden]) {
      assert.equal(error.message.includes(value), false, `message must not contain ${value}`);
    }
    return true;
  };

  await assert.rejects(loadExtraProtectedTerms({ kind: 'file', path: join(dir, 'absent.txt'), sha256: pinned }), redacted([]), 'missing file');

  await writeFile(path, `${TERMS_TEXT}marker ZQPANEL\n`, 'utf8');
  await assert.rejects(loadExtraProtectedTerms({ kind: 'file', path, sha256: pinned }), (error) => {
    assert.match(error.message, new RegExp(SHA_VAR));
    return redacted(['ZQPANEL', 'ZQBOARD'])(error);
  }, 'changed file');

  const malformed = `${EXTRA_PROTECTED_TERMS_HEADER}\nmarker ZQ.*BOARD\n`;
  await writeFile(path, malformed, 'utf8');
  await assert.rejects(loadExtraProtectedTerms({ kind: 'file', path, sha256: sha256(Buffer.from(malformed, 'utf8')) }), redacted(['ZQ.*BOARD']), 'malformed file');

  const huge = Buffer.alloc(300 * 1024, 0x41);
  await writeFile(path, huge);
  await assert.rejects(loadExtraProtectedTerms({ kind: 'file', path, sha256: sha256(huge) }), redacted([]), 'oversized file');
});

test('loading refuses a setting object it does not recognize', async () => {
  for (const setting of [undefined, null, {}, { kind: 'file' }, { kind: 'other' }]) {
    await assert.rejects(loadExtraProtectedTerms(setting), TypeError, JSON.stringify(setting));
  }
});

// Wiring. A resolved and loaded setting proves nothing if the production scrub engine is built without
// it; this pins the one production construction site in the per-session server. The behavioural proof
// that a configured term really blocks through the real entry point is in tests/openrouter-review-mcp-stdio.test.mjs.
test('the per-session server passes the loaded terms into its scrub engine', async () => {
  const source = (await readFile('tools/openrouter-review-mcp-server.mjs', 'utf8')).replace(/\r\n/g, '\n');
  const start = source.indexOf('scrubEngine: createScrubEngine({');
  assert.notEqual(start, -1, 'scrub engine construction not found');
  const body = source.slice(start, source.indexOf('}),', start));
  assert.match(body, /extraProtectedTerms:\s*config\.extraProtectedTerms/);
  assert.match(source, /const extraProtectedTerms = await loadExtraProtectedTerms\(resolved\.config\.extraProtectedTermsSetting\);/);
  assert.match(source, /buildProductionEngine\(\{ \.\.\.resolved\.config, identityList, extraProtectedTerms \}/);
});
