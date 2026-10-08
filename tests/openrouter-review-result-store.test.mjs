import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createResultStore } from '../src/local-mcp/result-store.mjs';

const JOB_ID = 'a'.repeat(64);

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-result-store-'));
  const store = createResultStore({ dataRoot });
  try {
    await run({ store, dataRoot });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('record then recall round-trips the advisory exactly', async () => {
  await withStore(async ({ store }) => {
    const advisory = { verdict: 'pass', findings: [] };
    await store.record({ jobId: JOB_ID, advisory });
    const recalled = await store.recall({ jobId: JOB_ID });
    assert.deepEqual(recalled, advisory);
  });
});

test('recall of an unknown jobId returns null, not a throw', async () => {
  await withStore(async ({ store }) => {
    assert.equal(await store.recall({ jobId: 'b'.repeat(64) }), null);
  });
});

test('recall of a corrupt result file returns null instead of throwing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({ jobId: JOB_ID, advisory: { verdict: 'pass', findings: [] } });
    const resultRoot = join(dataRoot, 'dispatch-results');
    await writeFile(join(resultRoot, `${JOB_ID}.json`), 'not valid json{{{', 'utf8');
    assert.equal(await store.recall({ jobId: JOB_ID }), null);
  });
});

test('record rejects a malformed jobId and writes nothing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await assert.rejects(
      () => store.record({ jobId: 'not-a-hash', advisory: { verdict: 'pass', findings: [] } }),
      TypeError,
    );
    await assert.rejects(() => readdir(join(dataRoot, 'dispatch-results')));
  });
});

test('a record write is atomic: exactly one file, never a leftover .tmp', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.record({
      jobId: JOB_ID,
      advisory: {
        verdict: 'block',
        findings: [{ severity: 'blocker', section: 'x', root_cause: 'y', affected_behavior: 'z', consequence: 'w', evidence: ['e'] }],
      },
    });
    const names = await readdir(join(dataRoot, 'dispatch-results'));
    assert.equal(names.length, 1);
    assert.equal(names[0], `${JOB_ID}.json`);
  });
});
