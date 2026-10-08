import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createAlertStore } from '../src/local-mcp/alert-store.mjs';
import { USD } from './helpers/scanner-safe-fixtures.mjs';

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-alerts-'));
  try {
    await run(createAlertStore({ dataRoot, clock: () => Date.parse('2026-09-01T10:00:00.000Z') }), dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('an alert is appended as one JSON line with the ecosystem field names', async () => {
  await withStore(async (store, dataRoot) => {
    await store.record({ severity: 'info', reason: 'dispatch batch complete', component: 'openrouter-review' });
    const text = await readFile(join(dataRoot, 'alerts.jsonl'), 'utf8');
    const lines = text.trim().split('\n');
    assert.equal(lines.length, 1);
    assert.deepEqual(JSON.parse(lines[0]), {
      severity: 'info',
      reason: 'dispatch batch complete',
      component: 'openrouter-review',
      timestamp: '2026-09-01T10:00:00.000Z',
    });
  });
});

test('appending twice keeps both lines, newest last', async () => {
  await withStore(async (store, dataRoot) => {
    await store.record({ severity: 'info', reason: 'first', component: 'openrouter-review' });
    await store.record({ severity: 'warning', reason: 'second', component: 'openrouter-review' });
    const lines = (await readFile(join(dataRoot, 'alerts.jsonl'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[1]).reason, 'second');
  });
});

// A downstream notifier may guard with /\$|\d{5,}/ and REPLACE THE ENTIRE MESSAGE with a generic
// one if a reason matches. A dollar sign or a 5+ digit run in an alert reason would therefore
// silently destroy the very information the alert exists to carry, so the store refuses it at the
// source rather than emitting something that gets blanked.
test('a reason containing a dollar sign or a long digit run is refused', async () => {
  await withStore(async (store) => {
    await assert.rejects(
      () => store.record({ severity: 'warning', reason: `spent ${USD}3 of ${USD}9`, component: 'openrouter-review' }),
      /must not contain/
    );
    await assert.rejects(
      () => store.record({ severity: 'warning', reason: 'token count 123456', component: 'openrouter-review' }),
      /must not contain/
    );
  });
});

// Downstream sanitization may lowercase the reason and strip EVERY character outside
// [a-z0-9_.-] -- including spaces, commas, and colons -- before the digit-run guard runs. That
// means digit groups that look separated in the raw reason merge into one contiguous run
// downstream, even though a naive check against the raw string sees them as short and harmless.
// A check that only tests the raw string would therefore accept reasons that still get silently
// blanked by a downstream notifier once written -- the exact failure mode the store's own
// record() docstring claims is impossible.
test('a reason whose digits merge into a 5+ run only after downstream sanitization is refused', async () => {
  await withStore(async (store) => {
    const bypassReasons = [
      'queue depth 12 345 items',
      'cost is 12,345 units',
      'retry after 12:345 ms',
      'port 1234 5 open',
    ];
    for (const reason of bypassReasons) {
      await assert.rejects(
        () => store.record({ severity: 'warning', reason, component: 'openrouter-review' }),
        /must not contain/,
        `expected "${reason}" to be refused -- it renders as a 5+ digit run after downstream sanitization`
      );
    }
  });
});

test('an unknown severity is refused', async () => {
  await withStore(async (store) => {
    await assert.rejects(
      () => store.record({ severity: 'catastrophic', reason: 'x', component: 'openrouter-review' }),
      /severity must be one of/
    );
  });
});

// list() lets a caller check whether it already recorded a given alert (e.g. "already warned for
// this billing period") before writing a duplicate. The append-only alerts.jsonl file this store
// already durably maintains is the natural, single source of truth for that -- reusing it here
// means the dedup state survives a process restart for free, with no second store invented.
test('list returns an empty array when nothing has been recorded yet', async () => {
  await withStore(async (store) => {
    assert.deepEqual(await store.list(), []);
  });
});

test('list returns every recorded alert, fully parsed, in append order', async () => {
  await withStore(async (store) => {
    await store.record({ severity: 'info', reason: 'first', component: 'openrouter-review' });
    await store.record({ severity: 'warning', reason: 'second', component: 'openrouter-review' });
    const entries = await store.list();
    assert.equal(entries.length, 2);
    assert.deepEqual(entries[0], {
      severity: 'info',
      reason: 'first',
      component: 'openrouter-review',
      timestamp: '2026-09-01T10:00:00.000Z',
    });
    assert.equal(entries[1].reason, 'second');
  });
});

test('list on a dataRoot whose alerts.jsonl was never created returns an empty array, not a throw', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-alerts-unwritten-'));
  try {
    const store = createAlertStore({ dataRoot });
    assert.deepEqual(await store.list(), []);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// This script touches the real credential, so it is verified by source inspection only rather
// than executed in a test.
test('the key-status probe is read-only, prints no secret, and reuses the DPAPI pattern', async () => {
  const source = await readFile('tools/openrouter-review-key-status.ps1', 'utf8');
  assert.match(source, /Add-Type -AssemblyName System\.Security/);
  assert.match(source, /ProtectedData\]::Unprotect/);
  assert.match(source, /api\/v1\/key/);
  assert.match(source, /'GET'/);
  // The Authorization header value must never be written to output.
  assert.doesNotMatch(source, /Write-Output\s+\$authorizationHeaderValue/);
  assert.doesNotMatch(source, /Write-Host\s+\$authorizationHeaderValue/);
});
