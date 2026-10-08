import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';

const PREFLIGHT_ID = '1a7fb234-723a-4e20-bd31-361152a4deff';

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-preflight-context-store-'));
  const store = createPreflightContextStore({ dataRoot });
  try {
    await run({ store, dataRoot });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('record then recall round-trips the reviewContext exactly, including an empty string', async () => {
  await withStore(async ({ store }) => {
    await store.record({ preflightId: PREFLIGHT_ID, reviewContext: 'clear as many findings as are genuinely safe' });
    assert.equal(await store.recall({ preflightId: PREFLIGHT_ID }), 'clear as many findings as are genuinely safe');
  });
});

test('record then recall round-trips an empty-string reviewContext, not null', async () => {
  await withStore(async ({ store }) => {
    await store.record({ preflightId: PREFLIGHT_ID, reviewContext: '' });
    assert.equal(await store.recall({ preflightId: PREFLIGHT_ID }), '');
  });
});

test('recall of an unknown preflightId returns null, not a throw', async () => {
  await withStore(async ({ store }) => {
    assert.equal(await store.recall({ preflightId: 'no-such-preflight' }), null);
  });
});

test('recall of a corrupt context file returns null instead of throwing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({ preflightId: PREFLIGHT_ID, reviewContext: 'x' });
    const contextRoot = join(dataRoot, 'preflight-contexts');
    await writeFile(join(contextRoot, `${PREFLIGHT_ID}.json`), 'not valid json{{{', 'utf8');
    assert.equal(await store.recall({ preflightId: PREFLIGHT_ID }), null);
  });
});

test('record rejects a non-string reviewContext and writes nothing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await assert.rejects(
      () => store.record({ preflightId: PREFLIGHT_ID, reviewContext: 42 }),
      TypeError,
    );
    await assert.rejects(() => readdir(join(dataRoot, 'preflight-contexts')));
  });
});

test('record rejects an empty preflightId and writes nothing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await assert.rejects(
      () => store.record({ preflightId: '', reviewContext: 'x' }),
      TypeError,
    );
    await assert.rejects(() => readdir(join(dataRoot, 'preflight-contexts')));
  });
});

test('a record write is atomic: exactly one file, never a leftover .tmp', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({ preflightId: PREFLIGHT_ID, reviewContext: 'x'.repeat(500) });
    const names = await readdir(join(dataRoot, 'preflight-contexts'));
    assert.equal(names.length, 1);
    assert.equal(names[0], `${PREFLIGHT_ID}.json`);
  });
});

test('BOM-prefixed context file (mirrors PowerShell Set-Content -Encoding utf8) still parses', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const contextRoot = join(dataRoot, 'preflight-contexts');
    await store.record({ preflightId: PREFLIGHT_ID, reviewContext: 'placeholder' });
    await writeFile(join(contextRoot, `${PREFLIGHT_ID}.json`), `${"\ufeff"}${JSON.stringify('bom text')}`, 'utf8');
    assert.equal(await store.recall({ preflightId: PREFLIGHT_ID }), 'bom text');
  });
});
