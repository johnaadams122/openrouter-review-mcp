import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';

async function withTempStore(fn) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-pending-health-verdict-'));
  try {
    await fn(createPendingHealthVerdictStore({ dataRoot }), dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

const JOB_ID = 'a'.repeat(64);

test('createPendingHealthVerdictStore requires a non-empty dataRoot', () => {
  assert.throws(() => createPendingHealthVerdictStore({}), TypeError);
  assert.throws(() => createPendingHealthVerdictStore({ dataRoot: '' }), TypeError);
});

test('record() writes, recall() reads it back exactly', async () => {
  await withTempStore(async (store) => {
    const record = { jobId: JOB_ID, reviewerId: 'grok', reservationUsd: 0.25, notBeforeMs: 1000, recordedAtMs: 500 };
    await store.record(record);
    const recalled = await store.recall({ jobId: JOB_ID });
    assert.deepEqual(recalled, record);
  });
});

test('recall() on a jobId that was never written returns null', async () => {
  await withTempStore(async (store) => {
    assert.equal(await store.recall({ jobId: JOB_ID }), null);
  });
});

test('recall() on a corrupt file returns null rather than throwing', async () => {
  await withTempStore(async (store, dataRoot) => {
    const { mkdir, writeFile } = await import('node:fs/promises');
    await mkdir(join(dataRoot, 'pending-health-verdicts'), { recursive: true });
    await writeFile(join(dataRoot, 'pending-health-verdicts', `${JOB_ID}.json`), 'not json', 'utf8');
    assert.equal(await store.recall({ jobId: JOB_ID }), null);
  });
});

test('record() overwrites an existing record for the same jobId (no accumulation)', async () => {
  await withTempStore(async (store) => {
    await store.record({ jobId: JOB_ID, reviewerId: 'grok', reservationUsd: 0.1, notBeforeMs: 1000, recordedAtMs: 500 });
    await store.record({ jobId: JOB_ID, reviewerId: 'gemini', reservationUsd: 0.2, notBeforeMs: 2000, recordedAtMs: 600 });
    const recalled = await store.recall({ jobId: JOB_ID });
    assert.equal(recalled.reviewerId, 'gemini');
  });
});

test('remove() deletes the record; a second remove() on an absent record does not throw', async () => {
  await withTempStore(async (store) => {
    await store.record({ jobId: JOB_ID, reviewerId: 'grok', reservationUsd: 0.1, notBeforeMs: 1000, recordedAtMs: 500 });
    await store.remove({ jobId: JOB_ID });
    assert.equal(await store.recall({ jobId: JOB_ID }), null);
    await store.remove({ jobId: JOB_ID }); // must not throw
  });
});

test('list() returns every currently-pending record', async () => {
  await withTempStore(async (store) => {
    const jobIdB = 'b'.repeat(64);
    await store.record({ jobId: JOB_ID, reviewerId: 'grok', reservationUsd: 0.1, notBeforeMs: 1000, recordedAtMs: 500 });
    await store.record({ jobId: jobIdB, reviewerId: 'gemini', reservationUsd: 0.2, notBeforeMs: 2000, recordedAtMs: 600 });
    const all = await store.list();
    assert.equal(all.length, 2);
    assert.deepEqual(new Set(all.map((r) => r.jobId)), new Set([JOB_ID, jobIdB]));
  });
});

test('list() on an empty/nonexistent directory returns an empty array, not a throw', async () => {
  await withTempStore(async (store) => {
    assert.deepEqual(await store.list(), []);
  });
});

test('record() rejects a malformed jobId', async () => {
  await withTempStore(async (store) => {
    await assert.rejects(store.record({ jobId: 'not-a-real-jobid', reviewerId: 'grok', reservationUsd: 0.1, notBeforeMs: 1000, recordedAtMs: 500 }), TypeError);
  });
});

test('recall() returns null when the file body jobId does not match the requested/filename jobId', async () => {
  await withTempStore(async (store, dataRoot) => {
    const { mkdir, writeFile } = await import('node:fs/promises');
    const jobIdB = 'b'.repeat(64);
    await mkdir(join(dataRoot, 'pending-health-verdicts'), { recursive: true });
    await writeFile(
      join(dataRoot, 'pending-health-verdicts', `${JOB_ID}.json`),
      JSON.stringify({ jobId: jobIdB, reviewerId: 'grok', reservationUsd: 0.1, notBeforeMs: 1000, recordedAtMs: 500 }),
      'utf8',
    );
    assert.equal(await store.recall({ jobId: JOB_ID }), null);
  });
});
