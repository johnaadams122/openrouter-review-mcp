import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { ReviewEngineError } from '../src/local-mcp/review-engine.mjs';
import { readFile } from 'node:fs/promises';

// A source-grep test can prove a string EXISTS but never that it is WIRED. Import and exercise the
// real resolver so a misplaced option (e.g. passed to createReviewEngine instead of
// createLeaseStore, where it would be silently ignored) cannot leave this green.
import { resolveDailyPaidJobAllowance } from '../tools/openrouter-review-mcp-server.mjs';

const HASH = 'a'.repeat(64);

// A fixed, injectable clock: the day boundary is UTC, so a test that used the real clock would
// behave differently depending on when in the day it ran.
function clockAt(iso) {
  let now = Date.parse(iso);
  return { clock: () => now, advanceTo: (next) => { now = Date.parse(next); } };
}

async function withStore(iso, run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-allowance-'));
  const time = clockAt(iso);
  try {
    const store = createLeaseStore({ dataRoot, clock: time.clock, dailyPaidJobAllowance: 2 });
    // createLease()/consume() are owner-sensitive -- a
    // REAL acquireProcessOwnership() call is required here, not a fake acquisitionId, since this is
    // a real leaseStore fixture, not a fake collaborator.
    const ownerLock = await store.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    await run(store, time, dataRoot, ownerLock);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function seedLease(store, { expiresAt }, ownerLock) {
  const preflight = await store.createPreflight({
    reviewContractSha256: HASH, sourceSha256: HASH, rawSourceSha256: HASH, profile: 'impl_review_v1', profileVersion: '1',
    schemaSha256: HASH, registrySha256: HASH,
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: 1 }, { itemId: 'item-grok', maxUsd: 1 }],
    requestedUsd: 2, expiresAt,
  });
  return store.createLease({ preflightIds: [preflight.id], requestedUsd: 2, maxJobs: 9, expiresAt, acquisitionId: ownerLock.acquisitionId });
}

test('a paid job beyond the daily allowance is refused before any dispatch', async () => {
  await withStore('2026-09-01T10:00:00.000Z', async (store, time, dataRoot, ownerLock) => {
    const lease = await seedLease(store, { expiresAt: '2026-09-01T23:00:00.000Z' }, ownerLock);
    await store.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
    await store.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
    await assert.rejects(
      () => store.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId }),
      // The message must NOT contain the word "cap": translateConsumeError's first test is /cap/i
      // and would misreport this as LEASE_CAP_EXCEEDED.
      (error) => error instanceof RangeError && /daily dispatch allowance exhausted/.test(error.message)
    );
  });
});

test('free-tier jobs never consume the paid allowance', async () => {
  await withStore('2026-09-01T10:00:00.000Z', async (store, time, dataRoot, ownerLock) => {
    const lease = await seedLease(store, { expiresAt: '2026-09-01T23:00:00.000Z' }, ownerLock);
    for (let index = 0; index < 5; index += 1) {
      await store.consume(lease.id, HASH, { reservationUsd: 0, countsTowardDailyAllowance: false, acquisitionId: ownerLock.acquisitionId });
    }
    const job = await store.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
    assert.equal(job.state, 'RESERVED');
  });
});

test('the allowance resets on the next UTC day', async () => {
  await withStore('2026-09-01T22:00:00.000Z', async (store, time, dataRoot, ownerLock) => {
    const first = await seedLease(store, { expiresAt: '2026-09-01T23:30:00.000Z' }, ownerLock);
    await store.consume(first.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
    await store.consume(first.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
    time.advanceTo('2026-09-02T01:00:00.000Z');
    const second = await seedLease(store, { expiresAt: '2026-09-02T12:00:00.000Z' }, ownerLock);
    const job = await store.consume(second.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
    assert.equal(job.state, 'RESERVED');
  });
});

test('the allowance still gates when a burst of calls straddles a UTC day boundary at a frozen clock reading', async () => {
  // Regression guard: append() stamps records with a
  // monotonically-increasing value (Math.max(Number(clock()), lastRecordTime + 1)), not a raw
  // clock() read, so a burst of consume() calls landing within one clock() tick a few ms before
  // UTC midnight can have append()'s +1ms bumps roll the PERSISTED (and counted) timestamp into
  // the next day while a naive check kept computing "today" from a fresh clock() read that never
  // advances. That splits the count across two buckets: the frozen "today" bucket stops growing
  // once appends cross into tomorrow, and the check keeps comparing against that now-permanently-
  // stuck (and under-allowance) bucket -- bypassing the guardrail entirely, forever, once crossed.
  // Needs an allowance the pre-boundary ticks alone can't reach (2-3 ms of headroom here, so
  // allowance=5 crosses before it caps) -- a small allowance like withStore()'s default masks the
  // bug by blocking for an unrelated reason before the boundary is ever reached. With a naive
  // check this would admit 15/15 where 5 should have been the ceiling. The store derives the
  // check's day key from the exact same monotonic formula append() uses, so the two can never
  // disagree.
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-allowance-boundary-'));
  const frozenAt = Date.parse('2026-09-01T23:59:59.995Z');
  try {
    const store = createLeaseStore({ dataRoot, clock: () => frozenAt, dailyPaidJobAllowance: 5 });
    // A real ownerLock, same reasoning as withStore() above.
    const ownerLock = await store.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const preflight = await store.createPreflight({
      reviewContractSha256: HASH, sourceSha256: HASH, rawSourceSha256: HASH, profile: 'impl_review_v1', profileVersion: '1',
      schemaSha256: HASH, registrySha256: HASH,
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 10 }],
      requestedUsd: 10, expiresAt: '2026-09-05T00:00:00.000Z',
    });
    const lease = await store.createLease({ preflightIds: [preflight.id], requestedUsd: 10, maxJobs: 50, expiresAt: '2026-09-05T00:00:00.000Z', acquisitionId: ownerLock.acquisitionId });
    let admitted = 0;
    let blocked = 0;
    for (let index = 0; index < 15; index += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await store.consume(lease.id, HASH, { reservationUsd: 0.01, countsTowardDailyAllowance: true, acquisitionId: ownerLock.acquisitionId });
        admitted += 1;
      } catch (error) {
        if (!(error instanceof RangeError) || !/daily dispatch allowance exhausted/.test(error.message)) throw error;
        blocked += 1;
      }
    }
    // Bounded, not unbounded: 2 admits legitimately land on 2026-09-01 before the persisted
    // timestamps genuinely cross into 2026-09-02 (append()'s +1ms bumps eat the ~2ms of headroom
    // left after acquireProcessOwnership()+preflight+lease creation each took a monotonic tick
    // first -- acquireProcessOwnership() itself is a real ledger append that runs before any of
    // this test's own setup and consumes one ms of the 5ms headroom this frozen clock leaves before
    // midnight), then 2026-09-02 gets its own fresh allowance of 5 -- 7 total, each day
    // independently honoring its own cap. The failure this guards against is not "7 instead of 5"
    // -- it is unbounded (15/15, every remaining call forever, since a frozen check's bucket stops
    // growing entirely once appends cross).
    assert.equal(admitted, 7);
    assert.equal(blocked, 8);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the count is rebuilt from the ledger by a fresh store (survives a restart)', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-allowance-restart-'));
  const time = clockAt('2026-09-01T10:00:00.000Z');
  try {
    const first = createLeaseStore({ dataRoot, clock: time.clock, dailyPaidJobAllowance: 2 });
    // A real ownerLock, released before `second` acquires its own -- both stores run in this
    // same test process, so a second acquireProcessOwnership() would otherwise contend forever
    // against a "live" owner (same real OS pid) if `first`'s were never released. This also
    // genuinely simulates the restart the test's own name describes: the old process releases
    // cleanly before the new one starts.
    const firstOwnerLock = await first.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const lease = await seedLease(first, { expiresAt: '2026-09-01T23:00:00.000Z' }, firstOwnerLock);
    await first.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: firstOwnerLock.acquisitionId });
    await first.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: firstOwnerLock.acquisitionId });
    await firstOwnerLock.release();

    const second = createLeaseStore({ dataRoot, clock: time.clock, dailyPaidJobAllowance: 2 });
    const secondOwnerLock = await second.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    await assert.rejects(
      () => second.consume(lease.id, HASH, { reservationUsd: 0.1, countsTowardDailyAllowance: true, acquisitionId: secondOwnerLock.acquisitionId }),
      (error) => /daily dispatch allowance exhausted/.test(error.message)
    );
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('DAILY_ALLOWANCE_EXCEEDED is a constructible engine error code', () => {
  const error = new ReviewEngineError('DAILY_ALLOWANCE_EXCEEDED', 'daily dispatch allowance exhausted for 2026-09-01');
  assert.equal(error.code, 'DAILY_ALLOWANCE_EXCEEDED');
});

test('the daily allowance defaults to 20 when the env var is unset', () => {
  assert.equal(resolveDailyPaidJobAllowance({}), 20);
});

test('the daily allowance honors a valid env override', () => {
  assert.equal(resolveDailyPaidJobAllowance({ OPENROUTER_REVIEW_MCP_DAILY_PAID_JOB_ALLOWANCE: '5' }), 5);
});

test('a malformed daily allowance fails closed rather than silently widening the guardrail', () => {
  assert.throws(
    () => resolveDailyPaidJobAllowance({ OPENROUTER_REVIEW_MCP_DAILY_PAID_JOB_ALLOWANCE: 'twenty' }),
    /must be a positive integer/
  );
  assert.throws(
    () => resolveDailyPaidJobAllowance({ OPENROUTER_REVIEW_MCP_DAILY_PAID_JOB_ALLOWANCE: '0' }),
    /must be a positive integer/
  );
});

// Separately assert the option actually reaches createLeaseStore, since that is the wiring the
// resolver alone cannot prove.
test('the resolved allowance is passed into createLeaseStore, not somewhere it would be ignored', async () => {
  const source = await readFile('tools/openrouter-review-mcp-server.mjs', 'utf8');
  const createCall = source.slice(source.indexOf('createLeaseStore('));
  const body = createCall.slice(0, createCall.indexOf('})') + 2);
  assert.match(body, /dailyPaidJobAllowance:\s*resolveDailyPaidJobAllowance\(\)/);
});
