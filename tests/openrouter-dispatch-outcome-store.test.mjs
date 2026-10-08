import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';

const JOB_ID = 'a'.repeat(64);

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-dispatch-outcome-store-'));
  const store = createDispatchOutcomeStore({ dataRoot });
  try {
    await run({ store, dataRoot });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function writeOutcomeFixture(dataRoot, jobId, outcome) {
  const path = dispatchOutcomePath({ dataRoot, jobId });
  await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
  await writeFile(path, JSON.stringify(outcome), 'utf8');
  return path;
}

test('dispatchOutcomePath places every jobId under <dataRoot>/dispatch-outcomes/<jobId>.json', async () => {
  await withStore(async ({ dataRoot }) => {
    assert.equal(dispatchOutcomePath({ dataRoot, jobId: JOB_ID }), join(dataRoot, 'dispatch-outcomes', `${JOB_ID}.json`));
  });
});

test('recall reads a durably-written RESPONSE outcome exactly as written', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const outcome = { kind: 'RESPONSE', envelopeJsonText: '{"httpStatus":200,"bodyBase64":"eyJhIjoxfQ=="}' };
    await writeOutcomeFixture(dataRoot, JOB_ID, outcome);
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), outcome);
  });
});

test('recall reads a durably-written FAILURE outcome exactly as written', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const outcome = { kind: 'FAILURE', envelopeJsonText: '{"failureKind":"TIMEOUT","message":"x"}' };
    await writeOutcomeFixture(dataRoot, JOB_ID, outcome);
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), outcome);
  });
});

test('recall of an unknown jobId returns null, not a throw', async () => {
  await withStore(async ({ store }) => {
    assert.equal(await store.recall({ jobId: 'b'.repeat(64) }), null);
  });
});

test('recall strips a leading UTF-8 BOM (mirrors PowerShell Set-Content -Encoding utf8 elsewhere in this project)', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const outcome = { kind: 'RESPONSE', envelopeJsonText: '{"httpStatus":200,"bodyBase64":""}' };
    const path = dispatchOutcomePath({ dataRoot, jobId: JOB_ID });
    await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
    await writeFile(path, `${"\ufeff"}${JSON.stringify(outcome)}`, 'utf8');
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), outcome);
  });
});

test('recall of a corrupt (non-JSON) outcome file returns null instead of throwing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const path = dispatchOutcomePath({ dataRoot, jobId: JOB_ID });
    await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
    await writeFile(path, 'not valid json{{{', 'utf8');
    assert.equal(await store.recall({ jobId: JOB_ID }), null);
  });
});

test('recall of a well-formed JSON file with the wrong shape returns null, not a malformed outcome', async () => {
  await withStore(async ({ store, dataRoot }) => {
    for (const badShape of [
      { kind: 'BOGUS', envelopeJsonText: '{}' },
      { kind: 'RESPONSE' },
      { envelopeJsonText: '{}' },
      { kind: 'RESPONSE', envelopeJsonText: 42 },
      null,
      'a string, not an object',
      [],
    ]) {
      const path = dispatchOutcomePath({ dataRoot, jobId: JOB_ID });
      await mkdir(join(dataRoot, 'dispatch-outcomes'), { recursive: true });
      await writeFile(path, JSON.stringify(badShape), 'utf8');
      assert.equal(await store.recall({ jobId: JOB_ID }), null, `expected null for shape ${JSON.stringify(badShape)}`);
    }
  });
});

test('dispatchOutcomePath and recall both reject a malformed jobId', async () => {
  await withStore(async ({ store }) => {
    assert.throws(() => dispatchOutcomePath({ dataRoot: '/tmp', jobId: 'not-a-hash' }), TypeError);
    await assert.rejects(() => store.recall({ jobId: 'not-a-hash' }), TypeError);
  });
});

test('recall reads a durably-written DISPATCHING marker exactly as written', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await writeOutcomeFixture(dataRoot, JOB_ID, { kind: 'DISPATCHING' });
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), { kind: 'DISPATCHING' });
  });
});

// Why the marker exists: the Node process serving a dispatch can be
// killed/replaced BEFORE it ever spawns tools/openrouter-review-dispatch.ps1
// -- e.g. between writing the request file and calling execute(). The
// durable RESPONSE/FAILURE capture above can only protect an outcome the
// script actually got to write; it does nothing for a dispatch that was
// never even attempted. markDispatching() is the Node-side write of a
// lightweight marker at the earliest safe point BEFORE execute() is called (see
// tools/openrouter-review-mcp-server.mjs), so review-engine.mjs's recovery
// logic can distinguish "no marker at all" (dispatch() was never invoked --
// provably zero risk of a duplicate OpenRouter call, safe to redispatch)
// from "DISPATCHING marker present, no RESPONSE/FAILURE yet" (a dispatch
// was attempted and its outcome is genuinely unknown -- must not redispatch).
// The script's own atomic RESPONSE/FAILURE write (unchanged) simply
// overwrites this marker once the real outcome is known.
test('markDispatching writes a DISPATCHING marker that recall() reads back', async () => {
  await withStore(async ({ store }) => {
    await store.markDispatching({ jobId: JOB_ID });
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), { kind: 'DISPATCHING' });
  });
});

test('markDispatching creates the dispatch-outcomes directory itself, not relying on a caller-side mkdir', async () => {
  await withStore(async ({ store, dataRoot }) => {
    // Deliberately no mkdir here -- a fresh dataRoot has no dispatch-outcomes/
    // subdirectory at all yet.
    await store.markDispatching({ jobId: JOB_ID });
    const names = await readdir(join(dataRoot, 'dispatch-outcomes'));
    assert.deepEqual(names, [`${JOB_ID}.json`]);
  });
});

test('markDispatching write is atomic: exactly one file, never a leftover .tmp', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.markDispatching({ jobId: JOB_ID });
    const names = await readdir(join(dataRoot, 'dispatch-outcomes'));
    assert.equal(names.length, 1);
    assert.equal(names[0], `${JOB_ID}.json`);
  });
});

test('markDispatching then a later real PowerShell-style write overwrites the marker (recall sees the final outcome, not the marker)', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await store.markDispatching({ jobId: JOB_ID });
    const finalOutcome = { kind: 'RESPONSE', envelopeJsonText: '{"httpStatus":200,"bodyBase64":""}' };
    // Simulates openrouter-review-dispatch.ps1's own later, separate write to
    // the exact same path -- this store never mediates that write, only reads.
    await writeOutcomeFixture(dataRoot, JOB_ID, finalOutcome);
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), finalOutcome);
  });
});

test('markDispatching rejects a malformed jobId and writes nothing', async () => {
  await withStore(async ({ store, dataRoot }) => {
    await assert.rejects(() => store.markDispatching({ jobId: 'not-a-hash' }), TypeError);
    await assert.rejects(() => readdir(join(dataRoot, 'dispatch-outcomes')));
  });
});

// A temp-file + unconditional rename write would OVERWRITE whatever was
// already at the final path -- silently destroying an already-captured real
// RESPONSE if a second, racing dispatch attempt for the same jobId ever
// reached this write (e.g. a client-side timeout followed by a retry that
// genuinely overlaps the still-in-flight original call). markDispatching()
// must instead be an EXCLUSIVE claim -- the atomic primitive that both (a)
// makes "the marker exists" mean "exactly one caller ever successfully
// started a dispatch for this jobId, never two", and (b) makes it
// impossible for this write to ever clobber existing content, real or not.
test('markDispatching is an exclusive claim: a second call for the same jobId throws EEXIST and leaves the first marker untouched', async () => {
  await withStore(async ({ store }) => {
    await store.markDispatching({ jobId: JOB_ID });
    await assert.rejects(
      () => store.markDispatching({ jobId: JOB_ID }),
      (error) => error && error.code === 'EEXIST',
    );
    assert.deepEqual(await store.recall({ jobId: JOB_ID }), { kind: 'DISPATCHING' });
  });
});

test('markDispatching never clobbers an already-captured real RESPONSE outcome -- it throws EEXIST and the original content is unchanged', async () => {
  await withStore(async ({ store, dataRoot }) => {
    const realOutcome = { kind: 'RESPONSE', envelopeJsonText: '{"httpStatus":200,"bodyBase64":"cmVhbA=="}' };
    await writeOutcomeFixture(dataRoot, JOB_ID, realOutcome);

    await assert.rejects(
      () => store.markDispatching({ jobId: JOB_ID }),
      (error) => error && error.code === 'EEXIST',
    );

    assert.deepEqual(await store.recall({ jobId: JOB_ID }), realOutcome);
  });
});
