import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile, mkdir, utimes } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { loadIdentityList, sweepStaleScrubMappings } from '../tools/openrouter-review-mcp-server.mjs';

test('sweepStaleScrubMappings deletes mappings older than the cutoff, leaves recent ones', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-cleanup-sweep-'));
  try {
    const store = createScrubMappingStore({ dataRoot });
    await store.record({ preflightId: 'old-preflight-id', mapping: { A: 'b' } });
    await store.record({ preflightId: 'new-preflight-id', mapping: { C: 'd' } });

    const oldPath = join(dataRoot, 'scrub-mappings', 'old-preflight-id.json');
    const oldTime = new Date(Date.now() - 25 * 60 * 60 * 1000); // 25h ago
    await utimes(oldPath, oldTime, oldTime);

    const deletedCount = await sweepStaleScrubMappings({ scrubMappingStore: store, maxAgeMs: 24 * 60 * 60 * 1000 });

    assert.equal(deletedCount, 1);
    assert.equal(await store.recall({ preflightId: 'old-preflight-id' }), null);
    assert.notEqual(await store.recall({ preflightId: 'new-preflight-id' }), null);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// The module's own comment above IDENTITY_LIST_PATH claims fail-closed
// behavior on a "missing or empty" identity list. The missing half comes from
// readFile's own ENOENT; these tests cover the empty half: an existing file
// with zero usable entries must not parse to [] and let the server start
// with identity-based matching silently disabled.
test('loadIdentityList throws on a file that is empty', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-identity-list-'));
  try {
    const path = join(dataRoot, 'identity_list.local.txt');
    await writeFile(path, '', 'utf8');
    await assert.rejects(() => loadIdentityList(path), /identity list.*is empty/i);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('loadIdentityList throws on a file containing only blank lines and comments', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-identity-list-'));
  try {
    const path = join(dataRoot, 'identity_list.local.txt');
    await writeFile(path, '# a comment\n\n   \n# another comment\n', 'utf8');
    await assert.rejects(() => loadIdentityList(path), /identity list.*is empty/i);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('loadIdentityList throws on a missing file (the already-working half of the fail-closed contract)', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-identity-list-'));
  try {
    const path = join(dataRoot, 'does-not-exist.txt');
    await assert.rejects(() => loadIdentityList(path));
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('loadIdentityList returns trimmed entries, skipping blank lines and comments, when the file has real content', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-identity-list-'));
  try {
    const path = join(dataRoot, 'identity_list.local.txt');
    await writeFile(path, '# a comment\n  Alex Example  \n\nSam Sample\n', 'utf8');
    const entries = await loadIdentityList(path);
    assert.deepEqual(entries, ['Alex Example', 'Sam Sample']);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});
