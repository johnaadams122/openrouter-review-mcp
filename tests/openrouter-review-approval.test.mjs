import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { resolve } from 'node:path';
import test from 'node:test';
import { createApprovalAdapter } from '../src/local-mcp/adapters.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';

async function withRoot(run) {
  const dataRoot = await mkdtemp(join(tmpdir(), 'openrouter-review-approval-'));
  const now = Date.parse('2026-08-17T12:00:00.000Z');
  try {
    await run({ dataRoot, now });
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
}

function request(expiresAt = '2026-08-17T12:10:00.000Z') {
  return {
    preflightHashes: ['a'.repeat(64)],
    profiles: ['consequential_spec_v1'],
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }],
    requestedUsd: 0.20,
    maxJobs: 1,
    expiresAt,
  };
}

test('approval adapter writes a redacted request and accepts only the matching approval nonce', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    let workerRequest;
    const approval = createApprovalAdapter({
      dataRoot,
      clock: () => now,
      worker: async (value) => {
        workerRequest = value;
        return `APPROVED ${value.nonce}`;
      },
    });

    const result = await approval.authorize(request());
    assert.deepEqual(result, { outcome: 'APPROVED', nonce: workerRequest.nonce });
    assert.match(workerRequest.nonce, /^[0-9a-f-]{36}$/);
    assert.equal(workerRequest.approvalPhrase, `APPROVE ${workerRequest.nonce}`);
    assert.match(workerRequest.requestSha256, /^[a-f0-9]{64}$/);

    const records = await readdir(join(dataRoot, 'approval-requests'));
    assert.equal(records.length, 1);
    const persisted = await readFile(join(dataRoot, 'approval-requests', records[0]), 'utf8');
    assert.doesNotMatch(persisted, /sourceText|requestBody|responseBody|apiKey/i);
    assert.match(persisted, /consequential_spec_v1/);
  });
});

test('approval data tampered with a preserved nonce is rejected after the worker returns', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    const approval = createApprovalAdapter({
      dataRoot,
      clock: () => now,
      worker: async (value, requestPath) => {
        const onDisk = JSON.parse(await readFile(requestPath, 'utf8'));
        onDisk.requestedUsd = 0.19;
        await writeFile(requestPath, `${JSON.stringify(onDisk)}\n`, 'utf8');
        return `APPROVED ${value.nonce}`;
      },
    });
    await assert.rejects(() => approval.authorize(request()), /integrity|hash/i);
  });
});

test('a request tampered after publish but before the worker runs is rejected by the pre-worker check', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    let workerCalls = 0;
    const approval = createApprovalAdapter({
      dataRoot,
      clock: () => now,
      afterPublish: async (requestPath) => {
        const onDisk = JSON.parse(await readFile(requestPath, 'utf8'));
        onDisk.requestedUsd = 0.01;
        await writeFile(requestPath, `${JSON.stringify(onDisk)}\n`, 'utf8');
      },
      worker: async (value) => { workerCalls += 1; return `APPROVED ${value.nonce}`; },
    });
    await assert.rejects(() => approval.authorize(request()), /integrity|hash/i);
    // The pre-worker check must be the one that caught this -- if it were
    // dead code, the worker would still have run and only the post-worker
    // check would have caught the tamper.
    assert.equal(workerCalls, 0);
  });
});

test('an approval request cannot claim a later expiry than the lease it is bound to', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    const store = createLeaseStore({ dataRoot, clock: () => now });
    // createLease() is owner-sensitive -- a REAL
    // acquireProcessOwnership() call is required here, not a fake acquisitionId, since this is a
    // real leaseStore fixture, not a fake collaborator.
    const ownerLock = await store.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const preflight = await store.createPreflight({
      reviewContractSha256: 'a'.repeat(64),
      sourceSha256: 'b'.repeat(64),
      rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1',
      profileVersion: '1',
      schemaSha256: 'c'.repeat(64),
      registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }],
      requestedUsd: 0.20,
      expiresAt: '2026-08-17T12:10:00.000Z',
    });
    const lease = await store.createLease({
      preflightIds: [preflight.id],
      requestedUsd: 0.20,
      maxJobs: 1,
      expiresAt: '2026-08-17T12:05:00.000Z',
      acquisitionId: ownerLock.acquisitionId,
    });

    const approval = createApprovalAdapter({ dataRoot, clock: () => now });
    await assert.rejects(
      () => approval.authorize(request('2026-08-17T12:06:00.000Z'), { leaseExpiresAt: lease.expiresAt }),
      /exceeds.*lease/i,
    );
  });
});

test('an approval bound to a real lease converts a late APPROVED to timed out using the lease\'s own expiry', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    const store = createLeaseStore({ dataRoot, clock: () => now });
    // A real ownerLock, same reasoning as the sibling test above.
    const ownerLock = await store.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
    const preflight = await store.createPreflight({
      reviewContractSha256: 'a'.repeat(64),
      sourceSha256: 'b'.repeat(64),
      rawSourceSha256: 'e'.repeat(64),
      profile: 'consequential_spec_v1',
      profileVersion: '1',
      schemaSha256: 'c'.repeat(64),
      registrySha256: 'd'.repeat(64),
      itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.20 }],
      requestedUsd: 0.20,
      expiresAt: '2026-08-17T12:10:00.000Z',
    });
    const lease = await store.createLease({
      preflightIds: [preflight.id],
      requestedUsd: 0.20,
      maxJobs: 1,
      expiresAt: '2026-08-17T12:05:00.000Z',
      acquisitionId: ownerLock.acquisitionId,
    });

    let clockNow = now;
    const approval = createApprovalAdapter({
      dataRoot,
      clock: () => clockNow,
      worker: async (value) => {
        // The worker takes long enough that the lease's real expiry (12:05)
        // passes before it returns APPROVED.
        clockNow = Date.parse('2026-08-17T12:06:00.000Z');
        return `APPROVED ${value.nonce}`;
      },
    });

    const result = await approval.authorize(request(lease.expiresAt), { leaseExpiresAt: lease.expiresAt });
    assert.equal(result.outcome, 'TIMED_OUT');
  });
});

test('approval granted after expiry is converted to timed out after the worker returns', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    let clockNow = now;
    const approval = createApprovalAdapter({
      dataRoot,
      clock: () => clockNow,
      worker: async (value) => {
        clockNow = Date.parse('2026-08-17T12:10:00.000Z');
        return `APPROVED ${value.nonce}`;
      },
    });
    const result = await approval.authorize(request());
    assert.equal(result.outcome, 'TIMED_OUT');
  });
});

test('approval denial and timeout create no lease and reserve no spend', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    const store = createLeaseStore({ dataRoot, clock: () => now });
    for (const outcome of ['DENIED', 'TIMED_OUT']) {
      const approval = createApprovalAdapter({
        dataRoot,
        clock: () => now,
        worker: async (value) => `${outcome} ${value.nonce}`,
      });
      const result = await approval.authorize(request());
      assert.equal(result.outcome, outcome);
      assert.equal(await store.getLease('not-created'), null);
    }
  });
});

test('expired or tampered approvals fail closed before a lease can be created', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    let calls = 0;
    const approval = createApprovalAdapter({
      dataRoot,
      clock: () => now,
      worker: async (value) => { calls += 1; return `APPROVED wrong-${value.nonce}`; },
    });
    await assert.rejects(() => approval.authorize(request('2026-08-17T11:59:59.000Z')), /expired/i);
    assert.equal(calls, 0);
    await assert.rejects(() => approval.authorize(request()), /nonce/i);
    await assert.rejects(() => approval.authorize({ ...request(), sourceText: 'do not persist' }), /forbidden/i);
  });
});

for (const shellPaths of [{}, {
  commandProcessorPath: "\u0043\u003a\u005c\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u005c\u0053\u0079\u0073\u0074\u0065\u006d\u0033\u0032\u005c\u0063\u006d\u0064\u002e\u0065\u0078\u0065",
  powershellPath: "\u0043\u003a\u005c\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u005c\u0053\u0079\u0073\u0074\u0065\u006d\u0033\u0032\u005c\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u0050\u006f\u0077\u0065\u0072\u0053\u0068\u0065\u006c\u006c\u005c\u0076\u0031\u002e\u0030\u005c\u0070\u006f\u0077\u0065\u0072\u0073\u0068\u0065\u006c\u006c\u002e\u0065\u0078\u0065",
}]) test(`the real approval path uses a hidden start/wait wrapper and reads its result (${shellPaths.commandProcessorPath ? 'absolute system paths' : 'legacy defaults'})`, async () => {
  await withRoot(async ({ dataRoot, now }) => {
    let capturedCommand;
    let capturedArgs;
    let capturedOptions;
    const spawnProcess = (command, args, options) => {
      capturedCommand = command;
      capturedArgs = args;
      capturedOptions = options;
      const child = new EventEmitter();
      const requestPath = args[args.length - 2];
      const resultPath = args[args.length - 1];
      const nonce = basename(requestPath, '.json');
      queueMicrotask(async () => {
        await writeFile(resultPath, JSON.stringify({ outcome: 'APPROVED', nonce }), 'utf8');
        child.emit('exit', 0, null);
      });
      return child;
    };

    const approval = createApprovalAdapter({ dataRoot, clock: () => now, spawnProcess, ...shellPaths });
    const result = await approval.authorize(request());

    assert.equal(result.outcome, 'APPROVED');
    // cmd's `start` is what gives the target program its own independent,
    // genuinely interactive console -- a direct spawn of
    // powershell.exe, even detached with stdio:'ignore', does not: Windows
    // redirects 'ignore' to the NUL device rather than the new console's own
    // buffers, so Read-Host returns instantly instead of waiting for input.
    assert.equal(capturedCommand, shellPaths.commandProcessorPath ?? 'cmd.exe');
    assert.deepEqual(capturedArgs.slice(0, 4), ['/c', 'start', 'OpenRouter Review Authorization', '/wait']);
    assert.equal(capturedArgs[4], shellPaths.powershellPath ?? 'powershell.exe');
    assert.deepEqual(capturedArgs.slice(5, 7), ['-NoProfile', '-File']);
    // `/wait` makes the cmd.exe wrapper block until the target program exits,
    // so no `detached` is needed -- only the wrapper's OWN window is hidden;
    // `start` still shows its own separate window for the target program.
    assert.equal(capturedOptions.detached, undefined);
    assert.equal(capturedOptions.stdio, 'ignore');
    assert.equal(capturedOptions.windowsHide, true);

    // The transient result file is cleaned up, not left behind as a second
    // source of truth alongside the lease-store's own ledger.
    const resultPath = capturedArgs[capturedArgs.length - 1];
    await assert.rejects(() => readFile(resultPath, 'utf8'));
  });
});

test('a spawn failure (e.g. powershell.exe not found) rejects authorize() instead of hanging', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    const spawnProcess = () => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('error', new Error('spawn powershell.exe ENOENT')));
      return child;
    };
    const approval = createApprovalAdapter({ dataRoot, clock: () => now, spawnProcess });
    await assert.rejects(() => approval.authorize(request()), /ENOENT/);
  });
});

test('an approval window that exits without writing a result file fails closed with a clear error', async () => {
  await withRoot(async ({ dataRoot, now }) => {
    const spawnProcess = () => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    };
    const approval = createApprovalAdapter({ dataRoot, clock: () => now, spawnProcess });
    await assert.rejects(() => approval.authorize(request()), /closed without recording an outcome/i);
  });
});

test('visible PowerShell authorization script accepts the request and result paths and never reads an API key', async () => {
  const script = await readFile(resolve('tools/openrouter-review-authorize.ps1'), 'utf8');
  assert.match(script, /param\s*\(\s*\[.*RequestPath[\s\S]*ResultPath/s);
  assert.match(script, /APPROVE \$nonce/);
  assert.match(script, /Write-ResultAtomic -Path \$ResultPath -Outcome \$outcome -Nonce \$nonce/);
  assert.match(script, /requestSha256/);
  assert.doesNotMatch(script, /api.?key|credential|authorization header/i);
});
