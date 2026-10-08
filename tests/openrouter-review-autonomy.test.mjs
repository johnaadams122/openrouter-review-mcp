import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { createReviewEngine } from '../src/local-mcp/review-engine.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';

// createReviewEngine validates EVERY collaborator at construction (review-engine.mjs:186-215).
// The full required set, verified by reading those lines -- omitting any one throws a TypeError
// before a single test body runs:
//   leaseStore, approvalAdapter.authorize, dispatchAdapter.dispatch,
//   resultStore.{record,recall}, preflightContextStore.{record,recall},
//   dispatchOutcomeStore.recall, scrubEngine.{scrub,desubstitute},
//   scrubMappingStore.{record,recall,deleteMapping}, clock,
//   sourcePolicy, preflightPolicy, and installationHardMaximumUsd
//   (a finite non-negative number with NO default -- authorizeWorkflow:516 compares against it).
// Minimal reusable lifecycle stand-in for the hand-built no-op leaseStore fake below. The engine
// releases ownership after every completed owner-sensitive operation, so this must re-arm with a fresh
// token instead of pretending ownership lasts for the engine lifetime. Real-store cases below use
// real handles because a fake token can never pass their ownership fence.
function createFakeOwnerLock() {
  let generation = 0;
  let acquisitionId = null;
  let terminal = false;
  return Object.freeze({
    dataRoot: '/fake',
    get generation() { return acquisitionId === null ? null : generation; },
    get acquisitionId() { return acquisitionId; },
    isOwner: () => acquisitionId !== null,
    async arm() {
      if (terminal) throw new Error('fake ownership handle is terminal');
      if (acquisitionId !== null) return;
      generation += 1;
      acquisitionId = `fake-owner-cycle-${generation}`;
    },
    async release({ final = true } = {}) {
      acquisitionId = null;
      if (final) terminal = true;
    },
  });
}

function buildEngine(overrides = {}) {
  const approvals = [];
  const engine = createReviewEngine({
    leaseStore: {
      async createPreflight(input) { return { ...input, id: 'preflight-1', state: 'PREFLIGHTED' }; },
      async createLease(input) { return { ...input, id: 'lease-1', state: 'ACTIVE' }; },
      async consume() { throw new Error('not used in this test'); },
      async reconcile() {}, async close() {}, async sweepOrphanedLeases() {}, async renew() {},
      async getLease() { return null; }, async getJob() { return null; }, async getPreflight() { return null; },
      // Every test using this default fake exercises a first-use call, never a repeat -- so 0 is
      // correct here, not a stand-in. Tests that DO exercise a repeat use the real lease-store.mjs
      // (see withRealLeaseStoreEngine below), never this fake.
      async countLeasesForRawSource() { return 0; },
    },
    ownerLock: createFakeOwnerLock(),
    approvalAdapter: {
      async authorize(request) { approvals.push(request); return { outcome: 'APPROVED', nonce: 'n' }; },
    },
    dispatchAdapter: { async dispatch() { throw new Error('not used in this test'); } },
    resultStore: { async record() {}, async recall() { return null; } },
    preflightContextStore: { async record() {}, async recall() { return null; } },
    dispatchOutcomeStore: { async markDispatching() {}, async record() {}, async recall() { return null; } },
    // Both real call sites (`loadAndScrubSource` and `preflight()`'s reviewContext scrub) call
    // `scrubEngine.scrub({ text, preflightId })` -- an object, not a string; same for
    // `desubstitute`. A fake taking a bare `text` argument would make `scrubResult.scrubbedText`
    // the whole input object, and the downstream `sha256(scrubResult.scrubbedText)` would throw a
    // `TypeError` from `createHash().update()` before any autonomy behavior is ever exercised.
    // Destructuring `{ text }` here gives a no-op passthrough fake.
    scrubEngine: {
      async scrub({ text }) { return { scrubbedText: text, mapping: {} }; },
      async desubstitute({ text }) { return text; },
    },
    scrubMappingStore: {
      async record() {}, async recall() { return null; }, async deleteMapping() {},
    },
    clock: () => Date.parse('2026-09-01T10:00:00.000Z'),
    // source-contract.mjs's preflightReview() requires `preflightPolicy.maxRequestBytes`
    // (source-contract.mjs:138, "must be a positive safe integer"); the preflight lifetime is the
    // separate top-level `preflightTtlMs` engine option, not a preflightPolicy field. 200_000
    // matches the value already established by tests/openrouter-review-engine.test.mjs:19.
    sourcePolicy: { allowedRoots: [], maxSourceBytes: 2_000_000 },
    preflightPolicy: { maxRequestBytes: 200_000 },
    installationHardMaximumUsd: 5,
    // Most tests in this file never exercise a repeat, so the default stays a
    // never-called fake, matching this file's existing "not used in this test" convention for
    // dispatchAdapter above. Tests that DO exercise the repeat-authorization gate override this.
    repeatAuthorizationJudge: { async judge() { throw new Error('not used in this test'); } },
    ...overrides,
  });
  return { engine, approvals };
}

test('autonomous mode is OFF by default: the approval adapter is still consulted', () => {
  const { engine } = buildEngine();
  assert.equal(typeof engine.authorizeWorkflow, 'function');
  // The default must be conservative: an engine built with no autonomy option behaves exactly as
  // it did before this feature existed.
  assert.equal(engine.isAutonomousAuthorizationEnabled(), false);
});

test('autonomous mode reports enabled when explicitly switched on', () => {
  const { engine } = buildEngine({ autonomousAuthorization: true });
  assert.equal(engine.isAutonomousAuthorizationEnabled(), true);
});

test('with autonomy on, no approval window is opened and a lease is still created', async () => {
  const { engine, approvals } = buildEngine({ autonomousAuthorization: true });
  // Seed a preflight so authorizeWorkflow has a cached contract to bind.
  const preflight = await engine.preflight({
    profile: 'impl_review_v1',
    source_text: 'a document to review',
  });
  const lease = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  assert.equal(lease.state, 'ACTIVE');
  assert.equal(approvals.length, 0, 'autonomous mode must not open an approval window');
});

test('with autonomy off, the approval window is still opened', async () => {
  const { engine, approvals } = buildEngine();
  const preflight = await engine.preflight({
    profile: 'impl_review_v1',
    source_text: 'a document to review',
  });
  await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  assert.equal(approvals.length, 1, 'non-autonomous mode must still require approval');
});

test('an autonomous authorization records an info-severity alert', async () => {
  const alerts = [];
  const { engine } = buildEngine({
    autonomousAuthorization: true,
    alertStore: { async record(alert) { alerts.push(alert); } },
  });
  const preflight = await engine.preflight({ profile: 'impl_review_v1', source_text: 'doc' });
  await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  assert.equal(alerts.length, 1);
  // 'info' specifically: a downstream notifier rate-limits pushes, so routine records must not be
  // pushed or they will crowd out the alerts that matter.
  assert.equal(alerts[0].severity, 'info');
  assert.equal(alerts[0].component, 'openrouter-review');
  assert.match(alerts[0].reason, /autonomous/i);
});

test('an alert-store failure never blocks an authorization that is otherwise valid', async () => {
  const { engine } = buildEngine({
    autonomousAuthorization: true,
    alertStore: { async record() { throw new Error('disk full'); } },
  });
  const preflight = await engine.preflight({ profile: 'impl_review_v1', source_text: 'doc' });
  const lease = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  assert.equal(lease.state, 'ACTIVE');
});

// --- Repeat-authorization justification gate -------------------------------------------------
//
// Under autonomy, the first authorization for a document is free, but a repeat for the same
// document requires a justification, so a caller cannot invoke authorizeWorkflow more than once
// against the same document with zero friction. Every test below uses the REAL lease-store.mjs (temp dataRoot), not the fake static
// stub `buildEngine()` uses by default -- a fake `createLease` returning a fresh object every
// call would pass a "distinct lease" assertion for the wrong reason, and only the real
// implementation's countLeasesForRawSource can prove the gate is actually consulting real state.

function fakeJudge(verdict) {
  const calls = [];
  return {
    calls,
    async judge(request) { calls.push(request); return verdict; },
  };
}

// Stands in for a real Ollama round trip or a human clicking through a popup -- both take real
// time, during which a second concurrent call can land. Without serializedByRawSource in
// review-engine.mjs, two concurrent calls racing through this delay both read the same
// prior-lease count and both get justified, producing more leases than justification events.
function slowFakeJudge(verdict, delayMs) {
  const calls = [];
  return {
    calls,
    async judge(request) {
      calls.push(request);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return verdict;
    },
  };
}

// The hard maximum in these real-store tests is 5, not 1: the Grok reservation covers its whole
// context window (a reasoning model can bill reasoning past max_tokens), so one Gemini plus Grok
// impl_review_v1 lease for a short document requests more than a cap of 1 would allow. Each lease
// still fits under the cap individually, which is all these repeat-authorization tests rely on.
async function withRealLeaseStoreEngine(overrides, run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-repeat-authorize-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const built = buildEngine({ autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 5, ...overrides });
    const preflight = await built.engine.preflight({ profile: 'impl_review_v1', source_text: 'a document to review' });
    await run({ ...built, preflight });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// Guards against a bypass: keying the repeat check on preflightId alone would let a caller reset
// the count to zero just by calling preflight() again for the SAME document, since preflight()
// always mints a fresh preflightId even for byte-identical content. This test re-preflights the same raw source_text and proves
// the SECOND, freshly-minted preflightId is still correctly recognized as a repeat.
test('re-preflighting the SAME document and authorizing under the fresh preflightId is still treated as a repeat, not reset to first-use', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-repeat-via-repreflight-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const { engine, approvals } = buildEngine({ autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 5 });
    const sourceText = 'the exact same document, byte for byte';

    const firstPreflight = await engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    await engine.authorizeWorkflow({ preflightId: firstPreflight.preflightId, maxJobs: 2 });

    const secondPreflight = await engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    assert.notEqual(secondPreflight.preflightId, firstPreflight.preflightId, 'preflight() always mints a fresh ID, even for identical content');

    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: secondPreflight.preflightId, maxJobs: 2 }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION',
      'a fresh preflightId for the SAME document must still be recognized as a repeat, not silently granted as first-use'
    );
    assert.equal(approvals.length, 0, 'the refused repeat must never open the popup');

    // And a justified repeat via the new preflightId still succeeds, proving the gate isn't just
    // permanently locking the document out once repeated -- it still allows a real justification.
    const judge = fakeJudge({ ok: true, justified: true, reasoning: 'legitimate retry' });
    const { engine: engineWithJudge } = buildEngine({ autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 5, repeatAuthorizationJudge: judge });
    const lease = await engineWithJudge.authorizeWorkflow({
      preflightId: secondPreflight.preflightId, maxJobs: 2,
      justification: { source: 'llm', reason: 'legitimate retry of the same document' },
    });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(judge.calls[0].priorLeaseCount, 1, 'the judge must see the TRUE prior count across both preflightIds, not just this one');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

// Two authorizeWorkflow calls for the same document, fired without waiting for each other
// (ordinary, legal MCP client behavior -- the SDK dispatches incoming requests without serializing
// them), could each read the SAME (stale) prior-lease count. The design deliberately allows more
// than one justified repeat -- there is no hard cap on repeat COUNT, only a requirement that each
// one is justified -- so the risk is not "too many repeats granted"; it's that concurrent calls
// could each be judged against a stale,
// non-incrementing count instead of the true, escalating one (1, 2, 3, ...), defeating the
// compounding-scrutiny signal a real judge is supposed to receive (its own prompt literally says
// "Approvals already granted for this same document before this request: N" -- a real judge should
// reasonably grow more skeptical as N grows). This test fires several concurrent repeat requests,
// each independently justified, through a deliberately slow judge and confirms serialization makes
// each one see the TRUE, strictly-increasing count -- not that only one succeeds.
test('concurrent repeat-authorization calls for the SAME document are serialized, so each sees the true, strictly-increasing prior-lease count instead of a stale one', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-repeat-race-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const judge = slowFakeJudge({ ok: true, justified: true, reasoning: 'legitimate retry' }, 50);
    const { engine } = buildEngine({ autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 100, repeatAuthorizationJudge: judge });
    const preflight = await engine.preflight({ profile: 'impl_review_v1', source_text: 'a document to review' });

    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }); // first use, free

    const CONCURRENT_ATTEMPTS = 5;
    const results = await Promise.allSettled(
      Array.from({ length: CONCURRENT_ATTEMPTS }, () => engine.authorizeWorkflow({
        preflightId: preflight.preflightId, maxJobs: 2,
        justification: { source: 'llm', reason: 'legitimate retry of the same document' },
      }))
    );

    const granted = results.filter((result) => result.status === 'fulfilled');
    assert.equal(granted.length, CONCURRENT_ATTEMPTS, 'every independently-justified repeat is allowed -- there is no hard cap on repeat count, only on each one being justified');

    // The invariant that actually matters: each judge call saw a DISTINCT, strictly-increasing
    // prior count (1, 2, 3, 4, 5), never a stale duplicate. Without serializedByRawSource, two
    // concurrent calls landing in the same window would both read the same count.
    assert.equal(judge.calls.length, CONCURRENT_ATTEMPTS);
    const seenCounts = judge.calls.map((call) => call.priorLeaseCount).sort((a, b) => a - b);
    assert.deepEqual(seenCounts, [1, 2, 3, 4, 5], `expected each concurrent call to see a distinct, sequential prior count, got ${JSON.stringify(seenCounts)}`);

    const record = await realLeaseStore.getPreflight(preflight.preflightId);
    assert.equal(await realLeaseStore.countLeasesForRawSource(record.rawSourceSha256), 1 + CONCURRENT_ATTEMPTS, 'total leases: the free first use plus every independently-justified repeat');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('concurrent FIRST-USE authorizeWorkflow calls for the SAME never-before-seen document also serialize -- only one is free, the rest need justification', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-first-use-race-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const { engine } = buildEngine({ autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 100 });
    const preflight = await engine.preflight({ profile: 'impl_review_v1', source_text: 'a brand new document, never authorized before' });

    const CONCURRENT_ATTEMPTS = 5;
    const results = await Promise.allSettled(
      Array.from({ length: CONCURRENT_ATTEMPTS }, () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }))
    );

    const granted = results.filter((result) => result.status === 'fulfilled');
    assert.equal(granted.length, 1, `expected exactly 1 of ${CONCURRENT_ATTEMPTS} concurrent first-use calls to be free -- the rest must require justification, not also be granted free`);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the first authorizeWorkflow call for a preflight needs no justification, exactly as before', async () => {
  await withRealLeaseStoreEngine({}, async ({ engine, approvals, preflight }) => {
    const lease = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(approvals.length, 0);
  });
});

test('a second authorizeWorkflow call for the same preflight is refused without justification, and neither the popup nor the LLM judge is ever consulted', async () => {
  const judge = fakeJudge({ ok: true, justified: true, reasoning: 'yes' });
  await withRealLeaseStoreEngine({ repeatAuthorizationJudge: judge }, async ({ engine, approvals, preflight }) => {
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION'
    );
    assert.equal(approvals.length, 0, 'a refused repeat must never open the popup');
    assert.equal(judge.calls.length, 0, 'a refused repeat must never consult the LLM judge either');
  });
});

test('a repeat with a malformed justification object (wrong source, missing reason) is refused the same as no justification at all', async () => {
  await withRealLeaseStoreEngine({}, async ({ engine, preflight }) => {
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const attempt = (justification) => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2, justification });
    await assert.rejects(() => attempt({ source: 'robot', reason: 'x' }), (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION');
    await assert.rejects(() => attempt({ source: 'human' }), (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION');
    await assert.rejects(() => attempt({ source: 'llm', reason: '' }), (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION');
    await assert.rejects(() => attempt('just trust me'), (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION');
  });
});

test('an LLM-justified repeat succeeds when the judge says justified:true, and the judge receives the real reason, profile, and prior lease count', async () => {
  const judge = fakeJudge({ ok: true, justified: true, reasoning: 'the first run crashed before completing' });
  await withRealLeaseStoreEngine({ repeatAuthorizationJudge: judge }, async ({ engine, approvals, preflight }) => {
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const lease = await engine.authorizeWorkflow({
      preflightId: preflight.preflightId, maxJobs: 2,
      justification: { source: 'llm', reason: 'the first run crashed before it finished' },
    });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(approvals.length, 0, 'an LLM-justified repeat must still never open the popup');
    assert.equal(judge.calls.length, 1);
    assert.equal(judge.calls[0].reason, 'the first run crashed before it finished');
    assert.equal(judge.calls[0].profile, 'impl_review_v1');
    assert.equal(judge.calls[0].priorLeaseCount, 1);
  });
});

test('an LLM-declined repeat (justified:false) is refused with REPEAT_AUTHORIZATION_NOT_JUSTIFIED', async () => {
  const judge = fakeJudge({ ok: true, justified: false, reasoning: 'this looks like a retry loop' });
  await withRealLeaseStoreEngine({ repeatAuthorizationJudge: judge }, async ({ engine, preflight }) => {
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2, justification: { source: 'llm', reason: 'just try again' } }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_NOT_JUSTIFIED' && /retry loop/.test(error.message)
    );
  });
});

test('an unreachable LLM judge (ok:false) fails CLOSED -- never treated as an implicit justification', async () => {
  const judge = fakeJudge({ ok: false, justified: null, reasoning: null });
  await withRealLeaseStoreEngine({ repeatAuthorizationJudge: judge }, async ({ engine, preflight }) => {
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2, justification: { source: 'llm', reason: 'x' } }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_NOT_JUSTIFIED'
    );
  });
});

test('a human-justified repeat opens the real approval popup, and succeeds only if it approves', async () => {
  await withRealLeaseStoreEngine({}, async ({ engine, approvals, preflight }) => {
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const lease = await engine.authorizeWorkflow({
      preflightId: preflight.preflightId, maxJobs: 2,
      justification: { source: 'human', reason: 'operator confirmed this is a legitimate retry' },
    });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(approvals.length, 1, 'a human-justified repeat must open exactly one popup');
  });
});

test('a human-justified repeat that the popup denies fails with APPROVAL_DENIED, and no lease is created', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-repeat-denied-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    let calls = 0;
    const { engine, preflight } = await (async () => {
      const built = buildEngine({
        autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 5,
        approvalAdapter: { async authorize() { calls += 1; return { outcome: 'DENIED', nonce: 'n' }; } },
      });
      const preflight = await built.engine.preflight({ profile: 'impl_review_v1', source_text: 'a document to review' });
      return { ...built, preflight };
    })();
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 }); // first use, autonomy, no popup
    await assert.rejects(
      () => engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2, justification: { source: 'human', reason: 'x' } }),
      (error) => error.code === 'APPROVAL_DENIED'
    );
    assert.equal(calls, 1);
    const record = await realLeaseStore.getPreflight(preflight.preflightId);
    assert.equal(await realLeaseStore.countLeasesForRawSource(record.rawSourceSha256), 1, 'the denied repeat must not have created a second lease');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('a justified repeat records an alert noting it was a justified repeat and via which path', async () => {
  const alerts = [];
  const judge = fakeJudge({ ok: true, justified: true, reasoning: 'legitimate retry' });
  await withRealLeaseStoreEngine(
    { repeatAuthorizationJudge: judge, alertStore: { async record(alert) { alerts.push(alert); } } },
    async ({ engine, preflight }) => {
      await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
      await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2, justification: { source: 'llm', reason: 'legitimate retry' } });
      assert.equal(alerts.length, 2);
      assert.match(alerts[0].reason, /autonomous authorization granted/);
      assert.doesNotMatch(alerts[0].reason, /repeat/);
      assert.match(alerts[1].reason, /justified repeat via llm/);
    }
  );
});

test('outside autonomy, repeats are unaffected: no justification is required and the popup opens every time, same as before this gate existed', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-off-repeat-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const { engine, approvals } = buildEngine({ leaseStore: realLeaseStore, ownerLock: realOwnerLock, clock, installationHardMaximumUsd: 5 });
    const preflight = await engine.preflight({ profile: 'impl_review_v1', source_text: 'a document to review' });
    await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const second = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    assert.equal(second.state, 'ACTIVE');
    assert.equal(approvals.length, 2, 'non-autonomous mode already requires a popup every call -- this gate adds nothing there');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('the server exposes autonomy as an opt-in env var, defaulting to off', async () => {
  const source = await readFile('tools/openrouter-review-mcp-server.mjs', 'utf8');
  assert.match(source, /OPENROUTER_REVIEW_MCP_AUTONOMOUS_AUTHORIZATION/);
  assert.match(source, /autonomousAuthorization/);
  assert.match(source, /createAlertStore/);
  // Opt-in means the ONLY enabling value is an explicit '1' -- an unset or misspelled value must
  // leave the human gate in place rather than silently removing it.
  assert.match(source, /===\s*'1'/);
});

// --- Ledger cross-check for repeat authorization ----------------------------------------------

async function withRealStoresEngine(overrides, run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-ledger-check-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    // A REAL ownerLock, since this leaseStore is real -- buildEngine()'s own default
    // createFakeOwnerLock() would never match this store's real currentOwner.
    const realOwnerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const realResultStore = createResultStore({ dataRoot });
    const alerts = [];
    const built = buildEngine({
      autonomousAuthorization: true, leaseStore: realLeaseStore, ownerLock: realOwnerLock, resultStore: realResultStore,
      clock, installationHardMaximumUsd: 5,
      alertStore: { async record(alert) { alerts.push(alert); } },
      ...overrides,
    });
    await run({ ...built, leaseStore: realLeaseStore, ownerLock: realOwnerLock, resultStore: realResultStore, alerts });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

// Seeds a REAL first lease for `sourceText` with both impl_review_v1 reviewers resolved one way or
// the other (never left job === null, which resolveDocumentOutcome always reads as AMBIGUOUS
// regardless of outcome).
async function seedResolvedPriorLease({ engine, leaseStore, ownerLock, resultStore }, sourceText, { geminiSucceeds, grokSucceeds }) {
  const firstPreflight = await engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
  const firstLease = await engine.authorizeWorkflow({ preflightId: firstPreflight.preflightId, maxJobs: 2 });

  // authorizeWorkflow completed its own ownership cycle and released this real handle. Re-arm
  // with the same cap configuration before fixture-only fenced writes, then release so the next
  // public authorization proves a new operation cycle rather than borrowing fixture ownership.
  await ownerLock.arm({ acquireTimeoutMs: 5_000, lockRetryMs: 250, caps: { installationHardMaximumUsd: 5 } });
  try {
    for (const [reviewerId, succeeds] of [['gemini', geminiSucceeds], ['grok', grokSucceeds]]) {
      const maxUsd = firstPreflight.itemMaxima.find((item) => item.itemId === `item-${reviewerId}`).maxUsd;
      const jobId = createHash('sha256').update(`openrouter_review_job_v1:${firstLease.leaseId}:${reviewerId}:${firstPreflight.reviewContractSha256}`, 'utf8').digest('hex');
      await leaseStore.consume(firstLease.leaseId, firstPreflight.reviewContractSha256, { reservationUsd: maxUsd, jobId, reviewerId, acquisitionId: ownerLock.acquisitionId });
      if (succeeds) {
        await leaseStore.reconcile(jobId, { costUsd: maxUsd, costKind: 'KNOWN', acquisitionId: ownerLock.acquisitionId });
        await resultStore.record({ jobId, advisory: { verdict: 'pass', findings: [] } });
      } else {
        await leaseStore.reconcile(jobId, { costUsd: maxUsd, costKind: 'KNOWN', haltReason: 'PROVIDER_MISMATCH', acquisitionId: ownerLock.acquisitionId });
      }
    }
  } finally {
    await ownerLock.release({ final: false });
  }
}

test('authorizeWorkflow: a repeat is refused with no LLM call when the ledger proves the prior attempt succeeded', async () => {
  const judge = fakeJudge({ ok: true, justified: true, reasoning: 'should never be reached' });
  await withRealStoresEngine({ repeatAuthorizationJudge: judge }, async (ctx) => {
    const sourceText = 'a document whose prior review genuinely passed';
    await seedResolvedPriorLease(ctx, sourceText, { geminiSucceeds: true, grokSucceeds: true });

    const repeatPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    await assert.rejects(
      () => ctx.engine.authorizeWorkflow({
        preflightId: repeatPreflight.preflightId, maxJobs: 2,
        justification: { source: 'llm', reason: 'want another opinion' },
      }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
    );
    assert.equal(judge.calls.length, 0, 'the LLM must never be consulted when the ledger already disproves the claim');

    // Also refused with NO justification supplied at all.
    await assert.rejects(
      () => ctx.engine.authorizeWorkflow({ preflightId: repeatPreflight.preflightId, maxJobs: 2 }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
    );
  });
});

test('authorizeWorkflow: a human can still override a ledger-proven-success denial via the real approval path', async () => {
  await withRealStoresEngine({}, async (ctx) => {
    const sourceText = 'a document whose prior review genuinely passed, but a human wants it again';
    await seedResolvedPriorLease(ctx, sourceText, { geminiSucceeds: true, grokSucceeds: true });

    const repeatPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    const lease = await ctx.engine.authorizeWorkflow({
      preflightId: repeatPreflight.preflightId, maxJobs: 2,
      justification: { source: 'human', reason: 'want it re-verified anyway' },
    });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(ctx.approvals.length, 1, 'the real approval path must still be reachable for a human override');
  });
});

test('authorizeWorkflow: a genuine MIX of succeeded and failed reviewers is NOT auto-granted -- falls through to a real LLM judgment', async () => {
  const judge = fakeJudge({ ok: true, justified: true, reasoning: 'retrying the one reviewer that failed' });
  await withRealStoresEngine({ repeatAuthorizationJudge: judge }, async (ctx) => {
    const sourceText = 'a document where one reviewer passed and the other halted';
    await seedResolvedPriorLease(ctx, sourceText, { geminiSucceeds: true, grokSucceeds: false });

    const repeatPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    const lease = await ctx.engine.authorizeWorkflow({
      preflightId: repeatPreflight.preflightId, maxJobs: 2,
      justification: { source: 'llm', reason: 'retrying the one reviewer that failed' },
    });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(judge.calls.length, 1, 'a genuine mix must NOT auto-grant -- the LLM must actually be consulted, unlike a total failure');
    assert.equal(judge.calls[0].priorLeaseCount, 1);
  });
});

test('authorizeWorkflow: a repeat is granted with no LLM/popup call when the ledger proves the prior attempt genuinely failed', async () => {
  const judge = fakeJudge({ ok: true, justified: true, reasoning: 'should never be reached' });
  await withRealStoresEngine({ repeatAuthorizationJudge: judge }, async (ctx) => {
    const sourceText = 'a document whose prior review genuinely halted on one reviewer';
    await seedResolvedPriorLease(ctx, sourceText, { geminiSucceeds: false, grokSucceeds: false });

    const repeatPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    const lease = await ctx.engine.authorizeWorkflow({
      preflightId: repeatPreflight.preflightId, maxJobs: 2,
      justification: { source: 'llm', reason: 'retrying since the last one halted' },
    });
    assert.equal(lease.state, 'ACTIVE');
    assert.equal(judge.calls.length, 0, 'the LLM must never be consulted when the ledger already corroborates the claim');
    assert.equal(ctx.approvals.length, 0, 'no popup either');
    assert.match(ctx.alerts[ctx.alerts.length - 1].reason, /justified repeat via ledger/);
  });
});

test('authorizeWorkflow: a FAILED-ledger repeat still requires SOME justification -- omitting it is refused, not silently granted', async () => {
  await withRealStoresEngine({}, async (ctx) => {
    const sourceText = 'a document whose prior review genuinely halted, but the caller forgets justification';
    await seedResolvedPriorLease(ctx, sourceText, { geminiSucceeds: false, grokSucceeds: false });

    const repeatPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    await assert.rejects(
      () => ctx.engine.authorizeWorkflow({ preflightId: repeatPreflight.preflightId, maxJobs: 2 }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_REQUIRES_JUSTIFICATION',
    );
  });
});

// Regression: a first use must NEVER call resolveDocumentOutcome, and therefore never call
// leaseStore.getMostRecentLeaseForRawSource -- proven directly (not just inferred from the ternary
// guard in the implementation) by using a leaseStore fake that doesn't even define that method.
// buildEngine's own default fake leaseStore already lacks it, so this doubles as documentation for
// why every pre-existing first-use test in this file would immediately start throwing a loud
// TypeError if this guard were ever accidentally removed.
test('authorizeWorkflow: a first-use authorization never calls resolveDocumentOutcome (leaseStore lacks getMostRecentLeaseForRawSource entirely)', async () => {
  const { engine } = buildEngine({ autonomousAuthorization: true });
  const preflight = await engine.preflight({ profile: 'impl_review_v1', source_text: 'a brand new document' });
  const lease = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
  assert.equal(lease.state, 'ACTIVE');
});

test('authorizeWorkflow: an ambiguous ledger (never dispatched, even after the prior lease expired) still falls through to the real LLM/human path', async () => {
  const judge = fakeJudge({ ok: true, justified: false, reasoning: 'no real necessity stated' });
  await withRealStoresEngine({ repeatAuthorizationJudge: judge }, async (ctx) => {
    const sourceText = 'a document authorized once and never used, then repeated after expiry';
    const firstPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    await ctx.engine.authorizeWorkflow({ preflightId: firstPreflight.preflightId, maxJobs: 2 });

    const repeatPreflight = await ctx.engine.preflight({ profile: 'impl_review_v1', source_text: sourceText });
    await assert.rejects(
      () => ctx.engine.authorizeWorkflow({
        preflightId: repeatPreflight.preflightId, maxJobs: 2,
        justification: { source: 'llm', reason: 'the last one supposedly failed' },
      }),
      (error) => error.code === 'REPEAT_AUTHORIZATION_NOT_JUSTIFIED',
    );
    assert.equal(judge.calls.length, 1, 'an undispatched-and-never-used prior lease must still fall through to a REAL LLM judgment, never an automatic grant');
    assert.equal(judge.calls[0].priorLeaseCount, 1);
  });
});

// The maxJobs capacity check must refuse an undersized authorization before the autonomy repeat gate
// observes (or makes) any authorization-specific state. This uses the real
// temporary store and owner lifecycle, while narrow wrappers make a mistaken
// repeat lookup loud and count every prohibited collaborator call.
test('autonomy rejects undersized first use and genuine repeats before approval, judge, alert, lease creation, dispatch, or repeat reads', async () => {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-autonomy-capacity-check-'));
  try {
    const clock = () => Date.parse('2026-09-01T10:00:00.000Z');
    const realLeaseStore = createLeaseStore({ dataRoot, clock });
    const ownerLock = await realLeaseStore.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const observations = {
      approvalCalls: 0, judgeCalls: 0, alertCalls: 0, createLeaseCalls: 0,
      dispatchCalls: 0, countLeasesForRawSourceCalls: 0, getMostRecentLeaseForRawSourceCalls: 0,
    };
    let failIfRepeatRead = false;
    const leaseStore = {
      ...realLeaseStore,
      async countLeasesForRawSource(...args) {
        observations.countLeasesForRawSourceCalls += 1;
        if (failIfRepeatRead) throw new Error('capacity-check: countLeasesForRawSource must not be called for an undersized authorization');
        return realLeaseStore.countLeasesForRawSource(...args);
      },
      async getMostRecentLeaseForRawSource(...args) {
        observations.getMostRecentLeaseForRawSourceCalls += 1;
        if (failIfRepeatRead) throw new Error('capacity-check: getMostRecentLeaseForRawSource must not be called for an undersized authorization');
        return realLeaseStore.getMostRecentLeaseForRawSource(...args);
      },
      async createLease(...args) {
        observations.createLeaseCalls += 1;
        return realLeaseStore.createLease(...args);
      },
    };
    const { engine } = buildEngine({
      autonomousAuthorization: true, leaseStore, ownerLock, clock, installationHardMaximumUsd: 5,
      approvalAdapter: {
        async authorize() {
          observations.approvalCalls += 1;
          return { outcome: 'APPROVED', nonce: 'capacity-check-approval' };
        },
      },
      repeatAuthorizationJudge: {
        async judge() {
          observations.judgeCalls += 1;
          return { ok: true, justified: true, reasoning: 'capacity-check test approval' };
        },
      },
      alertStore: { async record() { observations.alertCalls += 1; } },
      dispatchAdapter: {
        async dispatch() {
          observations.dispatchCalls += 1;
          throw new Error('capacity-check authorization test must not dispatch');
        },
      },
    });
    const preflight = await engine.preflight({
      profile: 'impl_review_v1', source_text: 'synthetic autonomy capacity-check document',
    });
    assert.equal(preflight.reviewers.length, 2, 'the capacity-check fixture must use two selected reviewers');

    const snapshot = () => ({ ...observations });
    const delta = (before, after) => Object.fromEntries(
      Object.keys(observations).map((key) => [key, after[key] - before[key]]),
    );
    async function attempt(label, justification) {
      const before = snapshot();
      const [outcome] = await Promise.allSettled([
        engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 1, justification }),
      ]);
      return { label, outcome, deltas: delta(before, snapshot()) };
    }

    failIfRepeatRead = true;
    const refusedFirstUse = [];
    for (const [label, justification] of [
      ['first use without justification', undefined],
      ['first use with human justification', { source: 'human', reason: 'retry' }],
      ['first use with LLM justification', { source: 'llm', reason: 'retry' }],
    ]) {
      // Capture every side effect/outcome before any assertion can hide it.
      // eslint-disable-next-line no-await-in-loop
      refusedFirstUse.push(await attempt(label, justification));
    }

    failIfRepeatRead = false;
    const beforeCorrection = snapshot();
    const corrected = await engine.authorizeWorkflow({ preflightId: preflight.preflightId, maxJobs: 2 });
    const afterCorrection = snapshot();

    failIfRepeatRead = true;
    const refusedGenuineRepeats = [];
    for (const [label, justification] of [
      ['genuine repeat without justification', undefined],
      ['genuine repeat with human justification', { source: 'human', reason: 'retry' }],
      ['genuine repeat with LLM justification', { source: 'llm', reason: 'retry' }],
    ]) {
      // Capture every side effect/outcome before any assertion can hide it.
      // eslint-disable-next-line no-await-in-loop
      refusedGenuineRepeats.push(await attempt(label, justification));
    }

    const expectedCapacityRefusals = [
      ...refusedFirstUse.map(({ label }) => label),
      ...refusedGenuineRepeats.map(({ label }) => label),
    ].map((label) => ({
      label,
      status: 'rejected',
      code: 'LEASE_CAP_EXCEEDED',
      message: 'maxJobs (1) must be at least the preflight reviewer count (2)',
      details: { maxJobs: 1, reviewerCount: 2 },
      deltas: {
        approvalCalls: 0, judgeCalls: 0, alertCalls: 0, createLeaseCalls: 0,
        dispatchCalls: 0, countLeasesForRawSourceCalls: 0, getMostRecentLeaseForRawSourceCalls: 0,
      },
    }));
    const observedCapacityRefusals = [...refusedFirstUse, ...refusedGenuineRepeats].map((result) => ({
      label: result.label,
      status: result.outcome.status,
      code: result.outcome.reason?.code,
      message: result.outcome.reason?.message,
      details: result.outcome.reason?.details,
      deltas: result.deltas,
    }));
    // Assert only after every negative first-use and genuine-repeat path has
    // completed, so an early success/error cannot hide a later side effect.
    assert.deepEqual(observedCapacityRefusals, expectedCapacityRefusals);
    assert.equal(corrected.state, 'ACTIVE', 'the same unexpired preflight must accept the corrected cap');
    assert.equal(corrected.maxJobs, 2, 'the capacity check must preserve the caller supplied corrected cap');
    assert.deepEqual(delta(beforeCorrection, afterCorrection), {
      approvalCalls: 0, judgeCalls: 0, alertCalls: 1, createLeaseCalls: 1,
      dispatchCalls: 0, countLeasesForRawSourceCalls: 1, getMostRecentLeaseForRawSourceCalls: 0,
    }, 'the corrected first authorization must retain ordinary autonomous first-use behavior');
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});
