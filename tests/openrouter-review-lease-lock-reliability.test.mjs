// acquireDataRootLock()'s release rename can fail transiently under concurrent load (e.g. an
// EPERM on Windows), which would leave the ledger lock stuck for every other acquirer ("ledger
// data root is locked"). lease-store.mjs therefore gives the release rename its own, much larger
// retry budget (RELEASE_RENAME_RETRY_ATTEMPTS), so the realistic transient case succeeds.
//
// If that much larger budget is STILL exhausted (a rare residual, not the realistic case this
// budget targets), release() logs loudly to stderr and returns normally -- it never throws,
// under any condition. Surfacing this case as a thrown error would break mutate()'s callers in
// review-engine.mjs, none of which expect a new post-effect failure mode to escape after their
// work already committed. See RELEASE_RENAME_RETRY_ATTEMPTS's own comment in lease-store.mjs.
// mutate() itself therefore needs no special-casing -- its one-line try/finally is unchanged,
// and this file's tests reflect that directly.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';

const HASH = 'a'.repeat(64);

// Returns a FACTORY of (lockRoot) -> renameImpl, not a renameImpl directly: the flaky behavior
// must never apply to the data-root lock's own acquire-side publish (a fresh staging
// directory -> lockRoot, see createAndPublishLockRoot in lease-store.mjs), only to renames that
// move content OUT of lockRoot (this file's release-direction rename, and -- unexercised by any
// test in this file today -- the stale-reclaim rename). All three call renameImpl, but only
// the publish direction has `from !== lockRoot`; the other two both have `from === lockRoot`.
// Without this distinction, injecting a failure here would also break the ACQUIRE these tests
// don't mean to exercise, since every store operation also needs one successful rename for the
// atomic publish.
function makeFlakyRename({ realRename, failuresBeforeSuccess = Infinity, code = 'EPERM' }) {
  return (lockRoot) => {
    let calls = 0;
    return async (from, to) => {
      if (from !== lockRoot) return realRename(from, to);
      calls += 1;
      if (calls <= failuresBeforeSuccess) {
        const error = new Error(`simulated transient rename failure #${calls}`);
        error.code = code;
        throw error;
      }
      return realRename(from, to);
    };
  };
}

async function withStore(makeRenameImpl, run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-lock-'));
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  const store = createLeaseStore({ dataRoot, renameImpl: makeRenameImpl(lockRoot) });
  try {
    await run({ store, dataRoot });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

async function createBoundPreflight(store) {
  return store.createPreflight({
    reviewContractSha256: HASH,
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256: 'e'.repeat(64),
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'c'.repeat(64),
    registrySha256: 'd'.repeat(64),
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }],
    requestedUsd: 0.20,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  });
}

test('a release rename that fails transiently beyond the OLD 400ms budget (16x25ms) still succeeds under the new, much larger release-specific budget', async () => {
  const { rename: realRename } = await import('node:fs/promises');
  // 25 consecutive failures: more than the shared RENAME_RETRY_ATTEMPTS (16), comfortably less
  // than RELEASE_RENAME_RETRY_ATTEMPTS (120) -- exactly the gap the larger release budget covers.
  const renameImpl = makeFlakyRename({ realRename, failuresBeforeSuccess: 25 });
  await withStore(renameImpl, async ({ store }) => {
    const preflight = await createBoundPreflight(store);
    assert.ok(preflight.id, 'the mutate() call (createPreflight) must complete successfully despite sustained transient release contention');
    // A second store operation proves the lock was genuinely released (not left stuck) --
    // if release had silently failed to actually free lockRoot, this call would itself hang
    // or time out trying to re-acquire it.
    const second = await store.getPreflight(preflight.id);
    assert.equal(second.id, preflight.id);
  });
});

test('a release rename that NEVER succeeds is logged loudly to stderr, but the caller\'s own successful result still resolves normally, not thrown', async () => {
  const { rename: realRename } = await import('node:fs/promises');
  const renameImpl = makeFlakyRename({ realRename, failuresBeforeSuccess: Infinity });
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  let preflight;
  try {
    await withStore(renameImpl, async ({ store }) => {
      preflight = await createBoundPreflight(store);
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
  assert.ok(preflight?.id, 'createPreflight must resolve normally with its real result, even though its own lock release could never actually complete');
  const diagnostic = written.join('');
  assert.match(diagnostic, /openrouter-review-lease-store: release-rename-failed \(detail redacted\); exact local cleanup remains pending/);
  assert.doesNotMatch(diagnostic, /simulated transient rename failure|ledger-write\.lock/i);
});

test('a release rename failing with a non-retryable error code is also logged, and the caller\'s result still resolves normally', async () => {
  const { rename: realRename } = await import('node:fs/promises');
  const renameImpl = makeFlakyRename({ realRename, failuresBeforeSuccess: Infinity, code: 'EACCES' });
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  let preflight;
  try {
    await withStore(renameImpl, async ({ store }) => {
      preflight = await createBoundPreflight(store);
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
  assert.ok(preflight?.id);
  const diagnostic = written.join('');
  assert.match(diagnostic, /openrouter-review-lease-store: release-rename-failed \(detail redacted\); exact local cleanup remains pending/);
  assert.doesNotMatch(diagnostic, /simulated transient rename failure|ledger-write\.lock/i);
});

test('accepted residual: once the release budget is exhausted the lock stays held and later operations fail with the existing lock error', async () => {
  const { rename: realRename } = await import('node:fs/promises');
  const renameImpl = makeFlakyRename({ realRename, failuresBeforeSuccess: Infinity });
  const originalStderrWrite = process.stderr.write;
  process.stderr.write = () => true;
  try {
    // A short lockTimeoutMs so the second call's own wait for the (still genuinely held)
    // lock resolves quickly instead of this test waiting out the real default (2000ms).
    const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-lease-lock-'));
    const lockRoot = join(dataRoot, '.ledger-write.lock');
    const store = createLeaseStore({ dataRoot, renameImpl: renameImpl(lockRoot), lockTimeoutMs: 100, lockRetryMs: 10 });
    try {
      const preflight = await createBoundPreflight(store);
      assert.ok(preflight.id, 'the first mutation still succeeds and is durably recorded');
      // The lock genuinely could not be released -- confirmed by the SAME store instance's
      // own next mutate()-based call failing against it, not a fresh acquire from scratch.
      await assert.rejects(
        () => createBoundPreflight(store),
        /ledger data root is locked/,
        'a later operation must hit the pre-existing lock-contention error, proving the residual is real and not merely theorized -- this is the accepted tradeoff RELEASE_RENAME_RETRY_ATTEMPTS\'s own comment documents, not an oversight',
      );
      // Even a READ (getPreflight) goes through the same mutate()/acquireDataRootLock() path
      // (this store always locks for ledger access, to guarantee a fresh replay) -- so the
      // residual is total for this process's continued access to this data root, not limited
      // to writes: confirmed directly here rather than assumed. The already-durably-written
      // FIRST record itself is untouched on disk throughout (a release problem never corrupts
      // or loses data that already committed) -- only this
      // process's own ability to reach it again is what the residual costs.
      await assert.rejects(() => store.getPreflight(preflight.id), /ledger data root is locked/);
    } finally {
      await rm(dataRoot, { recursive: true, force: true });
    }
  } finally {
    process.stderr.write = originalStderrWrite;
  }
});

test('when the mutation itself fails, the ORIGINAL work error is what surfaces -- release() failing too (in the finally) never masks or replaces it', async () => {
  const { rename: realRename } = await import('node:fs/promises');
  const renameImpl = makeFlakyRename({ realRename, failuresBeforeSuccess: Infinity });
  const originalStderrWrite = process.stderr.write;
  const written = [];
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    await withStore(renameImpl, async ({ store }) => {
      await assert.rejects(
        () => store.createPreflight({ reviewContractSha256: HASH }), // missing required fields -> work() itself throws
        (error) => {
          assert.match(error.message, /must be an? /i, 'the real validation failure must surface unchanged -- mutate() applies no special-casing for a concurrent release failure');
          return true;
        },
      );
    });
  } finally {
    process.stderr.write = originalStderrWrite;
  }
  // release() still runs in mutate()'s finally regardless of whether work() threw, and still
  // logs its own failure unconditionally -- an operator watching logs sees it either way.
  assert.equal(written.some((line) => line.includes('release-rename-failed')), true);
});
