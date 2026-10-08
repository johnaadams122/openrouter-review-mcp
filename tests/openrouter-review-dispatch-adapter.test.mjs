import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createDispatchAdapter } from '../tools/openrouter-review-mcp-server.mjs';

// These tests pin the timestamped stderr instrumentation (start/done/error,
// with reviewerId+jobId+elapsedMs) so a slow or failed dispatch is diagnosable.
// Without it, a long gap between reservation and reconciliation in the ledger
// says nothing about when the underlying execFile call started, when it ended,
// or which reviewer/job it was for.

async function withTempDataRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-dispatch-adapter-test-'));
  try {
    return await run(dataRoot);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

function fakeClockSequence(values) {
  let index = 0;
  return () => {
    const value = values[Math.min(index, values.length - 1)];
    index += 1;
    return value;
  };
}

// dispatchOutcomePath() (dispatch-outcome-store.mjs) requires jobId to be a
// 64-character lowercase SHA-256 hex string -- the exact shape deriveJobId()
// in review-engine.mjs always produces, and the same strict format
// result-store.mjs's own jobId-keyed file path enforces -- so a jobId can
// never smuggle a path-traversal segment into the file path it's embedded in.
// Each test job gets a distinct, valid 64-hex value, defined once here so a
// log-content assertion that needs to recognize "its" jobId can do so
// precisely.
const JOB_ABC = 'a'.repeat(64);
const JOB_XYZ = 'b'.repeat(64);
const JOB_BOUND = 'c'.repeat(64);
const JOB_LOOSE = 'd'.repeat(64);
const JOB_PAST = 'e'.repeat(64);
const JOB_DEFAULT_LOG = 'f'.repeat(64);

test('dispatch() logs a start line with reviewerId, jobId, and timeoutMs before calling execute', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const logs = [];
    const execute = async () => ({ stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' });
    const adapter = createDispatchAdapter({
      dataRoot,
      execute,
      timeoutMs: 900_000,
      clock: fakeClockSequence([1_000, 1_500]),
      log: (message) => logs.push(message),
    });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_ABC, reviewerId: 'grok' });

    const startLine = logs.find((line) => line.includes('start'));
    assert.ok(startLine, `expected a start log line, got: ${JSON.stringify(logs)}`);
    assert.match(startLine, new RegExp(`jobId=${JOB_ABC}`));
    assert.match(startLine, /reviewerId=grok/);
    assert.match(startLine, /timeoutMs=900000/);
  });
});

test('dispatch() logs a done line with elapsedMs computed from the injected clock on success', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const logs = [];
    const execute = async () => ({ stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' });
    const adapter = createDispatchAdapter({
      dataRoot,
      execute,
      timeoutMs: 900_000,
      clock: fakeClockSequence([1_000, 181_000]),
      log: (message) => logs.push(message),
    });

    const result = await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_ABC, reviewerId: 'grok' });

    assert.deepEqual(result, { kind: 'RESPONSE', envelopeJsonText: '{}' });
    const doneLine = logs.find((line) => line.includes('done'));
    assert.ok(doneLine, `expected a done log line, got: ${JSON.stringify(logs)}`);
    assert.match(doneLine, /elapsedMs=180000/);
    assert.match(doneLine, /kind=RESPONSE/);
  });
});

test('dispatch() logs an error line with elapsedMs and rethrows when execute() rejects (matches production DISPATCH_UNKNOWN path)', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const logs = [];
    const killedTimeoutError = Object.assign(new Error('Command failed'), { killed: true, signal: 'SIGTERM' });
    const execute = async () => { throw killedTimeoutError; };
    const adapter = createDispatchAdapter({
      dataRoot,
      execute,
      timeoutMs: 900_000,
      clock: fakeClockSequence([1_000, 931_000]),
      log: (message) => logs.push(message),
    });

    await assert.rejects(
      adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_ABC, reviewerId: 'grok' }),
      killedTimeoutError,
    );

    const errorLine = logs.find((line) => line.includes('error'));
    assert.ok(errorLine, `expected an error log line, got: ${JSON.stringify(logs)}`);
    assert.match(errorLine, /elapsedMs=930000/);
    assert.match(errorLine, /killed=true/);
  });
});

// Content-leak parity with review-engine.mjs's safeErrorDetail(): these two log() calls route a
// caught error through the shared safeErrorDetail() choke point, so a raw error.message never
// reaches stderr. Every PowerShell-side failure path already uses a hardcoded message string
// (never $_.Exception.Message), but the redaction gates on exact closed-set membership, never on
// a believed-safe origin.
test('dispatch() never embeds a raw error.message into the mark-dispatching-failed log line', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const logs = [];
    const execute = async () => ({ stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' });
    const secretBearingError = Object.assign(new Error('leaked document content: SSN 123-45-6789'), { code: 'EIO' });
    const failingDispatchOutcomeStore = {
      async recall() { return null; },
      async markDispatching() { throw secretBearingError; },
    };
    const adapter = createDispatchAdapter({
      dataRoot, execute, dispatchOutcomeStore: failingDispatchOutcomeStore,
      log: (message) => logs.push(message),
    });

    await assert.rejects(
      adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_ABC, reviewerId: 'grok' }),
      secretBearingError,
    );

    const failureLine = logs.find((line) => line.includes('mark-dispatching-failed'));
    assert.ok(failureLine, `expected a mark-dispatching-failed log line, got: ${JSON.stringify(logs)}`);
    assert.ok(
      !failureLine.includes('leaked document content') && !failureLine.includes('123-45-6789'),
      `expected the raw error message to be redacted, got: ${failureLine}`,
    );
  });
});

test('dispatch() never embeds a raw error.message into the post-claim error log line', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const logs = [];
    const secretBearingError = new Error('Command failed: leaked document content: SSN 123-45-6789');
    const execute = async () => { throw secretBearingError; };
    const adapter = createDispatchAdapter({
      dataRoot, execute,
      log: (message) => logs.push(message),
    });

    await assert.rejects(
      adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_XYZ, reviewerId: 'gemini' }),
      secretBearingError,
    );

    const errorLine = logs.find((line) => line.includes('openrouter-review-dispatch: error'));
    assert.ok(errorLine, `expected an error log line, got: ${JSON.stringify(logs)}`);
    assert.ok(
      !errorLine.includes('leaked document content') && !errorLine.includes('123-45-6789'),
      `expected the raw error message to be redacted, got: ${errorLine}`,
    );
  });
});

test('dispatch() still deletes its per-job request file after execute() rejects', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const execute = async () => { throw new Error('boom'); };
    const adapter = createDispatchAdapter({ dataRoot, execute, log: () => {} });

    await assert.rejects(adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_XYZ, reviewerId: 'gemini' }));

    const requestFiles = await readdir(join(dataRoot, 'dispatch-requests'));
    assert.deepEqual(requestFiles, []);
  });
});

// Money safety: review-engine.mjs reserves a job for a later reviewer while the
// lease is still active, then dispatches it. A dispatch given a full fresh
// timeoutMs regardless of how much of the lease's authorized window is left
// would let a slow earlier reviewer push a later reviewer's paid dispatch past
// the lease's own expiresAt, since lease-store.mjs's reconcile() never
// re-checks expiry (only consume() does, and only at reservation time).
//
// A pre-subtracted RELATIVE duration is not enough either: computed before this
// function's own `mkdir`/`writeFile` calls and then added to `startedAtMs`
// sampled AFTER that I/O, every intervening await (this function's own I/O,
// plus the caller's leaseStore.consume()) would silently push the real deadline
// later instead of eating into the authorized budget. The adapter therefore
// takes an ABSOLUTE deadline (`notAfterMs`, an epoch-ms timestamp, not a
// duration) and computes the effective timeout from a FRESH clock() read taken
// AFTER its own I/O, so drift from that I/O is subtracted rather than silently
// granted back.
test('dispatch() computes the effective deadline from a FRESH post-I/O clock read against an absolute notAfterMs, not a pre-subtracted duration', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let capturedTimeoutOption;
    let capturedDeadlineArg;
    let capturedResponsePathArg;
    const execute = async (_cmd, args, options) => {
      // deadlineUtc is the SECOND-to-last CLI arg, not the last: responsePath
      // is appended after it (see createDispatchAdapter's execute() call), so
      // the PowerShell script can find deadlineUtc and responsePath at fixed,
      // stable positions regardless of anything upstream.
      capturedDeadlineArg = args[args.length - 2];
      capturedResponsePathArg = args[args.length - 1];
      capturedTimeoutOption = options.timeout;
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    // notAfterMs = 91_000 (an absolute deadline set by the caller at some
    // earlier point). But dispatch()'s own startedAtMs -- sampled via clock()
    // AFTER its mkdir/writeFile I/O -- lands at 21_000, simulating 20s of
    // real setup delay between when the caller decided on notAfterMs and
    // when this function actually got to it. The effective budget must
    // reflect what's ACTUALLY left from that later instant (91_000-21_000 =
    // 70_000), not the caller's original, now-stale 90_000 figure.
    const adapter = createDispatchAdapter({
      dataRoot,
      execute,
      timeoutMs: 600_000,
      clock: fakeClockSequence([21_000, 21_500]),
      log: () => {},
    });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_BOUND, reviewerId: 'grok', notAfterMs: 91_000 });

    assert.equal(capturedTimeoutOption, 70_000 + 30_000);
    assert.equal(capturedDeadlineArg, new Date(21_000 + 70_000).toISOString());
    assert.equal(capturedResponsePathArg, join(dataRoot, 'dispatch-outcomes', `${JOB_BOUND}.json`));
  });
});

test('dispatch() never loosens the deadline when notAfterMs leaves more time than the configured timeoutMs', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let capturedTimeoutOption;
    const execute = async (_cmd, _args, options) => {
      capturedTimeoutOption = options.timeout;
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    const adapter = createDispatchAdapter({
      dataRoot,
      execute,
      timeoutMs: 90_000,
      clock: fakeClockSequence([1_000, 1_500]),
      log: () => {},
    });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_LOOSE, reviewerId: 'grok', notAfterMs: 1_000 + 600_000 });

    assert.equal(capturedTimeoutOption, 90_000 + 30_000);
  });
});

test('dispatch() clamps to a zero-or-negative effective budget (never a negative execute timeout) when notAfterMs has already passed by the time I/O finishes', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let capturedTimeoutOption;
    let capturedDeadlineArg;
    let capturedResponsePathArg;
    const execute = async (_cmd, args, options) => {
      // deadlineUtc is the SECOND-to-last CLI arg, not the last: responsePath
      // is appended after it (see createDispatchAdapter's execute() call), so
      // the PowerShell script can find deadlineUtc and responsePath at fixed,
      // stable positions regardless of anything upstream.
      capturedDeadlineArg = args[args.length - 2];
      capturedResponsePathArg = args[args.length - 1];
      capturedTimeoutOption = options.timeout;
      return { stdout: '{"kind":"FAILURE","envelopeJsonText":"{\\"failureKind\\":\\"DEADLINE_EXCEEDED\\",\\"message\\":\\"x\\"}"}\n' };
    };
    const adapter = createDispatchAdapter({
      dataRoot,
      execute,
      timeoutMs: 600_000,
      clock: fakeClockSequence([50_000, 50_500]),
      log: () => {},
    });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_PAST, reviewerId: 'grok', notAfterMs: 10_000 });

    assert.equal(capturedTimeoutOption, 0 + 30_000);
    assert.equal(capturedDeadlineArg, new Date(50_000).toISOString());
    assert.equal(capturedResponsePathArg, join(dataRoot, 'dispatch-outcomes', `${JOB_PAST}.json`));
  });
});

// openrouter-review-dispatch.ps1 invoked directly, even with detached:true,
// dies alongside a killed or replaced Node parent on Windows.
// createDispatchAdapter's default target is therefore the launcher
// (openrouter-review-dispatch-launcher.ps1), which runs the worker under a
// Windows Scheduled Task instead -- see the launcher's own header and
// tests/openrouter-review-dispatch-launcher.test.mjs for its contract.
test('dispatch() defaults to invoking the Task-Scheduler launcher, not the worker script directly', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let capturedScriptArg;
    const execute = async (_cmd, args) => {
      capturedScriptArg = args[2]; // ['-NoProfile', '-File', scriptPath, ...]
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    const adapter = createDispatchAdapter({ dataRoot, execute, log: () => {} });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_ABC, reviewerId: 'grok' });

    assert.match(capturedScriptArg, /openrouter-review-dispatch-launcher\.ps1$/);
  });
});

test('dispatch() rejects a non-safe-integer notAfterMs override', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const adapter = createDispatchAdapter({ dataRoot, execute: async () => ({ stdout: '' }), log: () => {} });

    await assert.rejects(
      adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: 'job-bad-max', reviewerId: 'grok', notAfterMs: 1.5 }),
      TypeError,
    );
  });
});

test('dispatch() defaults to writing log lines to process.stderr when no log override is supplied', async () => {
  await withTempDataRoot(async (dataRoot) => {
    const execute = async () => ({ stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' });
    const adapter = createDispatchAdapter({ dataRoot, execute });

    const originalWrite = process.stderr.write;
    const writes = [];
    process.stderr.write = (chunk, ...rest) => { writes.push(String(chunk)); return originalWrite.call(process.stderr, ...rest.length ? [chunk, ...rest] : [chunk]); };
    try {
      await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_DEFAULT_LOG, reviewerId: 'grok' });
    } finally {
      process.stderr.write = originalWrite;
    }

    assert.ok(writes.some((chunk) => chunk.includes(JOB_DEFAULT_LOG)), `expected stderr to receive a dispatch log line, got: ${JSON.stringify(writes)}`);
  });
});

// The Node process serving a dispatch can be killed or replaced BEFORE it
// ever spawns tools/openrouter-review-dispatch.ps1, leaving a request file on
// disk and no dispatch outcome at all. review-engine.mjs's recovery logic must
// tell "dispatch never attempted" (safe to redispatch) from "dispatch
// attempted, outcome unknown" (must not redispatch). These tests pin the
// two-part design at this adapter: a durable DISPATCHING marker written before
// execute() is ever called, and detached:true as a best-effort defense against
// the PowerShell child being torn down alongside a killed Node parent.
const JOB_MARKER = '1'.repeat(64);
const JOB_DETACHED = '2'.repeat(64);
const JOB_MARKER_FAILS = '3'.repeat(64);

test('dispatch() durably writes a DISPATCHING marker before ever invoking execute()', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let markerDuringExecute = null;
    const execute = async () => {
      markerDuringExecute = await readFile(dispatchOutcomePath({ dataRoot, jobId: JOB_MARKER }), 'utf8').catch(() => null);
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    const adapter = createDispatchAdapter({ dataRoot, execute, log: () => {} });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_MARKER, reviewerId: 'grok' });

    assert.ok(markerDuringExecute, 'expected a DISPATCHING marker file to already exist by the time execute() is invoked');
    assert.deepEqual(JSON.parse(markerDuringExecute), { kind: 'DISPATCHING' });
  });
});

test('dispatch() calls execute() with detached: true (best-effort: lets the PowerShell child survive a killed/replaced Node parent)', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let capturedOptions;
    const execute = async (_cmd, _args, options) => {
      capturedOptions = options;
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    const adapter = createDispatchAdapter({ dataRoot, execute, log: () => {} });

    await adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_DETACHED, reviewerId: 'grok' });

    assert.equal(capturedOptions.detached, true);
  });
});

// markDispatching() succeeding is a HARD precondition: dispatch() must never
// call execute() without a successful claim. If markDispatching() could fail
// (disk error, or losing an exclusive-claim race to a concurrent dispatch
// attempt for the same jobId) while execute() still ran, "no marker found"
// would no longer be conclusive proof that no OpenRouter call was ever made,
// and review-engine.mjs's redispatch decision (which relies on exactly that
// proof) could trigger a duplicate paid API call.
test('a markDispatching failure is a hard precondition failure -- dispatch() never invokes execute() and rejects', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let executeCalled = false;
    const execute = async () => {
      executeCalled = true;
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    const failingDispatchOutcomeStore = {
      async recall() { return null; },
      async markDispatching() { throw Object.assign(new Error('disk full'), { code: 'EIO' }); },
    };
    const adapter = createDispatchAdapter({
      dataRoot, execute, dispatchOutcomeStore: failingDispatchOutcomeStore, log: () => {},
    });

    await assert.rejects(
      () => adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_MARKER_FAILS, reviewerId: 'grok' }),
      (error) => error.message.includes('disk full'),
    );

    assert.equal(executeCalled, false, 'execute() must never run without a successful markDispatching() claim');
  });
});

// The exclusive-claim shape dispatch-outcome-store.mjs actually throws
// (EEXIST from `flag: 'wx'`) when another dispatch attempt already claimed
// this jobId -- the concrete case the hard-precondition rule above exists to
// handle safely, not just a generic disk error.
test('losing the exclusive-claim race (EEXIST) is also a hard precondition failure -- dispatch() never invokes execute()', async () => {
  await withTempDataRoot(async (dataRoot) => {
    let executeCalled = false;
    const execute = async () => {
      executeCalled = true;
      return { stdout: '{"kind":"RESPONSE","envelopeJsonText":"{}"}\n' };
    };
    const alreadyClaimedStore = {
      async recall() { return null; },
      async markDispatching() { throw Object.assign(new Error('EEXIST: file already exists'), { code: 'EEXIST' }); },
    };
    const adapter = createDispatchAdapter({
      dataRoot, execute, dispatchOutcomeStore: alreadyClaimedStore, log: () => {},
    });

    await assert.rejects(
      () => adapter.dispatch({ requestBytes: Buffer.from('{}'), jobId: JOB_MARKER_FAILS, reviewerId: 'grok' }),
      (error) => error.code === 'EEXIST',
    );

    assert.equal(executeCalled, false, 'losing the claim race must never still trigger a real dispatch');
  });
});
