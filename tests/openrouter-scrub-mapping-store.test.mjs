import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import test from 'node:test';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';

const PREFLIGHT_ID = 'a'.repeat(36);

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-scrub-mapping-store-'));
  const store = createScrubMappingStore({ dataRoot });
  try {
    await run({ store, dataRoot });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('record then recall round-trips the mapping exactly', async () => {
  await withStore(async ({ store }) => {
    const mapping = { ACCOUNT_a1b2c3d4: '9ZQ24681357', PERSON_e5f6a7b8: 'Jane Q. Public' };
    await store.record({ preflightId: PREFLIGHT_ID, mapping });
    assert.deepEqual(await store.recall({ preflightId: PREFLIGHT_ID }), mapping);
  });
});

test('recall of an unknown preflightId returns null, not a throw', async () => {
  await withStore(async ({ store }) => {
    assert.equal(await store.recall({ preflightId: 'b'.repeat(36) }), null);
  });
});

test('recall of a corrupt mapping file returns null instead of throwing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({ preflightId: PREFLIGHT_ID, mapping: {} });
    const mappingRoot = join(dataRoot, 'scrub-mappings');
    await writeFile(join(mappingRoot, `${PREFLIGHT_ID}.json`), 'not valid json{{{', 'utf8');
    assert.equal(await store.recall({ preflightId: PREFLIGHT_ID }), null);
  });
});

test('deleteMapping removes the file; a subsequent recall returns null', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({ preflightId: PREFLIGHT_ID, mapping: { X: 'y' } });
    await store.deleteMapping({ preflightId: PREFLIGHT_ID });
    assert.equal(await store.recall({ preflightId: PREFLIGHT_ID }), null);
    assert.deepEqual(await readdir(join(dataRoot, 'scrub-mappings')), []);
  });
});

test('deleteMapping on an already-missing preflightId is a silent no-op, not a throw', async () => {
  await withStore(async ({ store }) => {
    await store.deleteMapping({ preflightId: 'never-existed' });
  });
});

test('a record write is atomic: exactly one file, never a leftover .tmp', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({ preflightId: PREFLIGHT_ID, mapping: { A: 'b' } });
    const names = await readdir(join(dataRoot, 'scrub-mappings'));
    assert.equal(names.length, 1);
    assert.equal(names[0], `${PREFLIGHT_ID}.json`);
  });
});

test('record rejects a malformed preflightId and writes nothing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await assert.rejects(() => store.record({ preflightId: '', mapping: {} }), TypeError);
    await assert.rejects(() => readdir(join(dataRoot, 'scrub-mappings')));
  });
});

test('listStaleBefore returns preflightIds whose mapping file mtime is older than the given cutoff', async () => {
  await withStore(async ({ store }) => {
    await store.record({ preflightId: PREFLIGHT_ID, mapping: { A: 'b' } });
    const future = new Date(Date.now() + 60_000).toISOString();
    const past = new Date(Date.now() - 60_000).toISOString();
    assert.deepEqual(await store.listStaleBefore(future), [PREFLIGHT_ID]);
    assert.deepEqual(await store.listStaleBefore(past), []);
  });
});

test('listStaleBefore rejects a non-ISO cutoff instead of silently matching nothing', async () => {
  await withStore(async ({ store }) => {
    await assert.rejects(() => store.listStaleBefore('not-a-date'), TypeError);
    await assert.rejects(() => store.listStaleBefore(undefined), TypeError);
  });
});

// ---------------------------------------------------------------------------
// listStaleBefore() must survive a mapping that another server process deletes between its
// readdir and its stat. With no startup ownership acquire serializing server starts, a second
// sweep (or a second process's result() delete-on-success) can land in that window, and an ENOENT
// thrown here would escape main()'s startup try and exit the server before it ever connected.
//
// The race is made deterministic through the store's optional statImpl seam. The injected stat
// deletes the file and then calls the REAL stat, so the ENOENT comes from the real filesystem.
// ---------------------------------------------------------------------------

const CUTOFF_LEAD_MS = 60_000;

// A cutoff after "now", so every mapping a test writes counts as stale unless it vanished.
function staleCutoffInTheFuture() {
  return new Date(Date.now() + CUTOFF_LEAD_MS).toISOString();
}

async function withStatSeamStore(statImpl, run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-scrub-mapping-store-'));
  try {
    await run({ store: createScrubMappingStore({ dataRoot, statImpl }), dataRoot });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('createScrubMappingStore validates the optional statImpl seam, and listStaleBefore stats through it', async () => {
  assert.throws(() => createScrubMappingStore({ dataRoot: 'not-used', statImpl: 'not a function' }), TypeError);
  assert.throws(() => createScrubMappingStore({ dataRoot: 'not-used', statImpl: null }), TypeError);

  const statted = [];
  await withStatSeamStore(async (path) => {
    statted.push(basename(path));
    return stat(path);
  }, async ({ store }) => {
    await store.record({ preflightId: PREFLIGHT_ID, mapping: { A: 'b' } });
    assert.deepEqual(await store.listStaleBefore(staleCutoffInTheFuture()), [PREFLIGHT_ID]);
  });
  assert.deepEqual(statted, [`${PREFLIGHT_ID}.json`], 'listStaleBefore must stat every listed mapping through the injected seam');
});

test('listStaleBefore skips a mapping deleted between its readdir and its stat, and still returns every other stale name', async () => {
  const vanishing = 'c'.repeat(36);
  const surviving = 'd'.repeat(36);
  const statted = [];
  // Stands in for a concurrent server process -- its own startup sweep, or result()'s delete-on-success --
  // deleting `vanishing` after this sweep's readdir listed it: the file is removed right before the
  // REAL stat runs on it.
  await withStatSeamStore(async (path) => {
    statted.push(basename(path));
    if (basename(path) === `${vanishing}.json`) await rm(path);
    return stat(path);
  }, async ({ store, dataRoot }) => {
    await store.record({ preflightId: vanishing, mapping: { A: 'b' } });
    await store.record({ preflightId: surviving, mapping: { C: 'd' } });

    const stale = await store.listStaleBefore(staleCutoffInTheFuture());

    assert.deepEqual(stale, [surviving], 'the vanished name is skipped, and the sweep carries on to every other name');
    assert.deepEqual(
      [...statted].sort(),
      [`${surviving}.json`, `${vanishing}.json`].sort(),
      'readdir listed both names, so the delete really landed between the readdir and the stat',
    );
    assert.deepEqual(await readdir(join(dataRoot, 'scrub-mappings')), [`${surviving}.json`]);
  });
});

test('listStaleBefore still rejects on a stat error that is not ENOENT', async () => {
  const failures = [
    Object.assign(new Error('simulated stat permission failure'), { code: 'EPERM' }),
    // A non-ENOENT stat failure reproducible on Windows without privilege: two directory
    // junctions pointing at each other. The real-entry startup test uses exactly that seam, so
    // this store must keep throwing on it.
    Object.assign(new Error('simulated stat failure on a junction loop'), { code: 'ELOOP' }),
    new Error('simulated stat failure that carries no code at all'),
  ];
  for (const injected of failures) {
    // eslint-disable-next-line no-await-in-loop
    await withStatSeamStore(async () => { throw injected; }, async ({ store }) => {
      await store.record({ preflightId: PREFLIGHT_ID, mapping: { A: 'b' } });
      await assert.rejects(
        () => store.listStaleBefore(staleCutoffInTheFuture()),
        (error) => error === injected,
        'only a mapping that genuinely vanished may be skipped; any other stat failure must still surface',
      );
    });
  }
});
