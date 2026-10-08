import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';

async function withStore(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-dispatch-health-'));
  try {
    await run(createDispatchHealthStore({ dataRoot }), dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

test('a fresh store starts at zero consecutive failures', async () => {
  await withStore(async (store) => {
    // No outcome recorded yet -- nothing to assert via recordOutcome without mutating state, so
    // this is proven indirectly: the very first failure below must report consecutiveFailures: 1,
    // which is only possible if the starting count was 0.
    const result = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.equal(result.consecutiveFailures, 1);
    assert.equal(result.shouldAlert, false);
  });
});

test('consecutive failures increment the streak, cross the threshold, and (once markAlerted() is called by the caller) do not re-alert', async () => {
  await withStore(async (store) => {
    const first = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.deepEqual(first, { consecutiveFailures: 1, shouldAlert: false });
    const second = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.deepEqual(second, { consecutiveFailures: 2, shouldAlert: false });
    const third = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.deepEqual(third, { consecutiveFailures: 3, shouldAlert: true });
    // The realistic caller sequence: recordOutcome() reports shouldAlert:true, the caller
    // actually delivers the alert, THEN commits markAlerted() -- see this store's own
    // recordOutcome()/markAlerted() docstrings for why the commit is a separate, caller-driven
    // step rather than automatic (a caller whose alert delivery fails must NOT commit this, so
    // the next consecutive failure can retry -- covered by its own dedicated tests below).
    await store.markAlerted();
    // A 4th, 5th, ... consecutive failure must NOT re-alert for the same streak -- that would spam
    // a human with the same "pipeline is broken" news repeatedly while nothing new has happened.
    const fourth = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.deepEqual(fourth, { consecutiveFailures: 4, shouldAlert: false });
    const fifth = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.deepEqual(fifth, { consecutiveFailures: 5, shouldAlert: false });
  });
});

test('a success resets the streak and the alerted flag, so a later streak can alert again', async () => {
  await withStore(async (store) => {
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    const crossed = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.deepEqual(crossed, { consecutiveFailures: 2, shouldAlert: true });

    const reset = await store.recordOutcome({ succeeded: true, alertThreshold: 2 });
    assert.deepEqual(reset, { consecutiveFailures: 0, shouldAlert: false });

    // A brand new streak must be able to cross and alert again -- the alerted flag from the
    // PRIOR streak must not leak into this one.
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    const crossedAgain = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.deepEqual(crossedAgain, { consecutiveFailures: 2, shouldAlert: true });
  });
});

test('state survives being reconstructed fresh from the same dataRoot (restart survival)', async () => {
  await withStore(async (store, dataRoot) => {
    await store.recordOutcome({ succeeded: false, alertThreshold: 5 });
    await store.recordOutcome({ succeeded: false, alertThreshold: 5 });

    // A brand new store instance against the SAME dataRoot simulates a process restart: this is
    // the exact property that motivates this store's existence over an in-process counter. A
    // counter that resets to zero on every restart would undercount failure streaks, since server
    // restarts are a common cause of dispatch failures.
    const reconnected = createDispatchHealthStore({ dataRoot });
    const third = await reconnected.recordOutcome({ succeeded: false, alertThreshold: 5 });
    assert.equal(third.consecutiveFailures, 3);
  });
});

test('a corrupt state file degrades to a fresh streak rather than throwing', async () => {
  await withStore(async (store, dataRoot) => {
    await writeFile(join(dataRoot, 'dispatch-health.json'), 'not valid json{{{', 'utf8');
    const result = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.equal(result.consecutiveFailures, 1);
  });
});

test('a state file with the wrong shape degrades to a fresh streak rather than throwing', async () => {
  await withStore(async (store, dataRoot) => {
    await writeFile(join(dataRoot, 'dispatch-health.json'), JSON.stringify({ unrelated: true }), 'utf8');
    const result = await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    assert.equal(result.consecutiveFailures, 1);
  });
});

test('recordOutcome rejects a non-boolean succeeded', async () => {
  await withStore(async (store) => {
    await assert.rejects(() => store.recordOutcome({ succeeded: 'no', alertThreshold: 3 }), /succeeded must be a boolean/);
  });
});

test('recordOutcome rejects a non-positive-integer alertThreshold', async () => {
  await withStore(async (store) => {
    await assert.rejects(() => store.recordOutcome({ succeeded: false, alertThreshold: 0 }), /alertThreshold must be a positive safe integer/);
    await assert.rejects(() => store.recordOutcome({ succeeded: false, alertThreshold: 1.5 }), /alertThreshold must be a positive safe integer/);
  });
});

test('createDispatchHealthStore requires a non-empty dataRoot', () => {
  assert.throws(() => createDispatchHealthStore({}), /dataRoot must be a non-empty string/);
  assert.throws(() => createDispatchHealthStore({ dataRoot: '' }), /dataRoot must be a non-empty string/);
});

// ---------------------------------------------------------------------------
// markAlerted(): a caller (review-engine.mjs) must be able to defer committing "this streak was
// alerted" until AFTER it has actually, successfully delivered the alert -- see this store's own
// recordOutcome()/markAlerted() docstrings for the failure this decouples (if recordOutcome()
// committed the flag unconditionally on a crossing call, a caller whose own alert write then
// failed would lose the alert for that streak, since every later consecutive failure in the same
// streak would see the flag already true).
// ---------------------------------------------------------------------------

test('recordOutcome alone (no markAlerted call) does NOT suppress a later crossing report in the same streak -- retry semantics', async () => {
  await withStore(async (store) => {
    const first = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    const second = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.equal(second.shouldAlert, true, 'the 2nd failure crosses the threshold');
    // markAlerted() was never called -- simulates the caller's own alert write having failed.
    const third = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.equal(third.shouldAlert, true, 'without markAlerted(), the NEXT consecutive failure must retry, not silently give up');
    void first;
  });
});

test('markAlerted() durably suppresses further reports for the rest of the same streak', async () => {
  await withStore(async (store) => {
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    const crossed = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.equal(crossed.shouldAlert, true);
    await store.markAlerted();
    const afterMark = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.equal(afterMark.shouldAlert, false, 'markAlerted() must suppress further reports for the rest of THIS streak');
  });
});

test('markAlerted() survives a fresh store reconstructed from the same dataRoot (restart survival)', async () => {
  await withStore(async (store, dataRoot) => {
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    await store.markAlerted();

    const reconnected = createDispatchHealthStore({ dataRoot });
    const afterRestart = await reconnected.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.equal(afterRestart.shouldAlert, false, 'the alerted flag must survive a process restart, same as the counter itself');
  });
});

test('a success after markAlerted() resets BOTH the streak and the alerted flag, so a fresh streak can alert again', async () => {
  await withStore(async (store) => {
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    await store.markAlerted();
    await store.recordOutcome({ succeeded: true, alertThreshold: 2 });

    await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    const crossedAgain = await store.recordOutcome({ succeeded: false, alertThreshold: 2 });
    assert.equal(crossedAgain.shouldAlert, true);
  });
});

test('recall() returns the current state without mutating it', async () => {
  await withStore(async (store) => {
    const before = await store.recall();
    assert.deepEqual(before, { consecutiveFailures: 0, alertedForCurrentStreak: false });
    await store.recordOutcome({ succeeded: false, alertThreshold: 3 });
    const after = await store.recall();
    assert.equal(after.consecutiveFailures, 1);
  });
});
