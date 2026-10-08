import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/sdk/types.js';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';

// Always-connect ownership arming: real-entry-point tests. Every test here but one spawns tools/openrouter-review-mcp-server.mjs exactly
// as `npm run mcp:start` does -- no harness module, no fake engine -- because what they prove is what
// the shipped main() does: connect whatever other sessions are doing, arm only on demand, report
// arm refusals as {code, message} tool errors, and shut down honestly. The one exception (the static
// startup-failure-catch test) reads main()'s startup-failure catch from source: the release it pins is a no-op on the only handle state
// startup can reach, so no process run can observe it.
//
// Hermetic by construction, not by luck:
//   - every inherited OPENROUTER_REVIEW_MCP_* variable is stripped (hermeticEnv), so an ambient
//     operator setting -- including the retired acquire timeout, which now prints a warning line --
//     cannot change what a test means;
//   - the data root is a fresh temp directory, never the real installation ledger;
//   - the identity list is a fixture file, never the host's real one;
//   - preflight's local-LLM classifications go to an in-process node:http fake answering
//     {"response":"false"}, reached through OPENROUTER_REVIEW_MCP_OLLAMA_URL -- the variable the
//     server resolves into createOllamaClient's baseUrl -- and every test that preflights asserts
//     the fake actually served those requests, so a wrong variable name cannot silently fall back
//     to a real local Ollama.
//
// What these tests may call. tools/list, preflight, status and result touch no approval adapter,
// no dispatch adapter, no credential and no network. authorize_workflow is called ONLY with a
// preflightId no preflight() ever minted: the engine's wrapper arms first, and the inner
// authorizeWorkflow resolves the preflight as its very first step and throws CONTRACT_CHANGED
// before the approval adapter is reachable -- so the call can arm, or be refused an arm, but can
// never open an approval window. The contention test below calls openrouter_review_document only
// with schema-valid IDs that no store ever minted: a refusal occurs in the ownership wrapper before
// the inner lookup and therefore before any dispatch path can be reached.
//
// Shutdown is always driven by closing stdin and waiting for the child's 'close' event (so its
// stderr is complete), never by a signal: on Windows a signal is indistinguishable from a hard
// kill (see the ownership-lifecycle header in tests/openrouter-review-mcp-stdio.test.mjs).
//
// Helpers marked "copied from tests/openrouter-review-mcp-stdio.test.mjs" are copied, not imported:
// importing a test file makes node --test register and run all of that file's tests here as well.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const SERVER_PATH = resolve(REPO_ROOT, 'tools', 'openrouter-review-mcp-server.mjs');

const CONNECTED_LINE = 'openrouter-review-mcp-server: connected via stdio.';
// The line a clean shutdown prints when this process never armed, and the pre-existing line it
// prints when it did. Pinned as whole literals so a drifted wording cannot satisfy a negative arm.
const NEVER_ARMED_SHUTDOWN_LINE = 'openrouter-review-mcp-server: shutdown after a clean drain; this process never held process ownership.';
const RELEASED_SHUTDOWN_LINE = 'openrouter-review-mcp-server: shutdown released process ownership after a clean drain.';
const FORMERLY_OWNED_SHUTDOWN_LINE = 'openrouter-review-mcp-server: shutdown after a clean drain; process ownership had already been released before final shutdown cleanup.';
const WARNING_PREFIX = 'openrouter-review-mcp-server: warning: ';
const SCRUB_SWEEP_FAILED_PREFIX = 'openrouter-review-mcp-server: startup scrub-mapping sweep failed';

// Arm settings every server in this file gets (the server reads them from its arm env vars). Far
// under wrapChildAsJsonRpcSession's 10 s client-side request timeout, so an arm that is refused
// answers inside one request instead of the test's client giving up first.
const ARM_BUDGET_MS = 1500;
const ARM_LOCK_RETRY_TEST_MS = 50;
const NEVER_MINTED_PREFLIGHT_ID = 'always-connect-never-minted-preflight';

// Copied from tests/openrouter-review-mcp-stdio.test.mjs.
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isJsonRpcMessage(value) {
  if (!isPlainObject(value) || value.jsonrpc !== '2.0') return false;
  return Object.hasOwn(value, 'id') || typeof value.method === 'string';
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs (see its docstring there): line-buffered
// JSON-RPC over the child's stdio, with a hard 10 s client-side request timeout.
function wrapChildAsJsonRpcSession(child) {
  let stdoutRemainder = '';
  let nonJsonStdout = '';
  let stderrBuffer = '';
  const pending = new Map();
  let nextId = 1;
  let exited = false;
  let exitInfo = null;

  child.on('exit', (code, signal) => {
    exited = true;
    exitInfo = { code, signal };
  });
  // 'close' (not 'exit') fires only after stdout/stderr have finished
  // emitting, so stderrBuffer is complete here -- used to fail every
  // in-flight request fast, with real diagnostics, instead of leaving each
  // one to burn its full timeout when the server process dies unexpectedly
  // (e.g. the entry point module fails to load).
  child.on('close', (code, signal) => {
    for (const [id, waiter] of pending) {
      pending.delete(id);
      waiter({ id, error: { code: null, message: `server process exited (code=${code}, signal=${signal}) before responding; stderr: ${stderrBuffer}` } });
    }
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderrBuffer += chunk; });

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdoutRemainder += chunk;
    let newlineIndex = stdoutRemainder.indexOf('\n');
    while (newlineIndex !== -1) {
      const line = stdoutRemainder.slice(0, newlineIndex).replace(/\r$/, '');
      stdoutRemainder = stdoutRemainder.slice(newlineIndex + 1);
      newlineIndex = stdoutRemainder.indexOf('\n');
      if (line.length === 0) continue;
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        nonJsonStdout += `${line}\n`;
        continue;
      }
      if (!isJsonRpcMessage(parsed)) {
        nonJsonStdout += `${line}\n`;
        continue;
      }
      if (Object.hasOwn(parsed, 'id') && (Object.hasOwn(parsed, 'result') || Object.hasOwn(parsed, 'error'))) {
        const waiter = pending.get(parsed.id);
        if (waiter) {
          pending.delete(parsed.id);
          waiter(parsed);
        }
      }
      // Server-to-client notifications (no `id`, e.g. a future logging
      // message) are valid JSON-RPC and therefore correctly excluded from
      // nonJsonStdout, but this harness has no assertions that need to
      // inspect them, so they are simply not retained.
    }
  });

  function send(message) {
    child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  async function request(method, params) {
    const id = nextId;
    nextId += 1;
    const responseArrived = new Promise((resolveWaiter, rejectWaiter) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        rejectWaiter(new Error(`timed out waiting for a response to ${method} (id ${id}); stderr so far: ${stderrBuffer}`));
      }, 10_000);
      pending.set(id, (message) => {
        clearTimeout(timer);
        resolveWaiter(message);
      });
    });
    send({ jsonrpc: '2.0', id, method, params });
    const message = await responseArrived;
    if (message.error) {
      throw Object.assign(new Error(message.error.message), { code: message.error.code, data: message.error.data });
    }
    return message.result;
  }

  function notify(method, params) {
    send({ jsonrpc: '2.0', method, params });
  }

  async function callTool(name, toolArguments) {
    return request('tools/call', { name, arguments: toolArguments });
  }

  // Always awaits the child's ACTUAL exit, so `exitInfo` is populated by the time any caller
  // reads it. The 5s kill stays as a last resort for a child that will not shut down, but the
  // previous version RACED it -- close() resolved at the 5s mark without waiting for the kill to
  // land, leaving exitInfo null or, worse, { code: null, signal: 'SIGTERM' }. On Windows a hard
  // kill leaves the ledger byte-identical to a correctly WITHHELD release (an ACQUIRED record with
  // no RELEASED counterpart), so a shutdown assertion reading exitInfo mid-kill could have passed
  // on a TerminateProcess. Awaiting the real exit makes such a run fail loudly instead. The timer
  // is also cleared on the normal path; an uncleared one used to hold Node's event loop open for
  // five seconds after every close.
  async function close() {
    if (exited) return;
    child.stdin.end();
    const closed = once(child, 'exit');
    const killTimer = setTimeout(() => { if (!exited) child.kill(); }, 5_000);
    try {
      await closed;
    } finally {
      clearTimeout(killTimer);
    }
  }

  return {
    request,
    notify,
    callTool,
    close,
    get nonJsonStdout() { return nonJsonStdout; },
    get stderr() { return stderrBuffer; },
    get exitInfo() { return exitInfo; },
  };
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs.
async function completeInitializeHandshake(session, clientName) {
  await session.request('initialize', {
    protocolVersion: LATEST_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: clientName, version: '0.0.1' },
  });
  session.notify('notifications/initialized', {});
  return session;
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs: every processOwner record in append order;
// a missing ledger directory reads as no records, any other read error surfaces.
async function readProcessOwnerRecords(dataRoot) {
  const ledgerRoot = join(dataRoot, 'ledger');
  const names = await readdir(ledgerRoot).catch((error) => {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  });
  const records = [];
  for (const name of names.filter((entry) => entry.endsWith('.json')).sort()) {
    // eslint-disable-next-line no-await-in-loop
    const record = JSON.parse(await readFile(join(ledgerRoot, name), 'utf8'));
    if (record && record.recordType === 'processOwner') records.push(record);
  }
  return records;
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs.
function countOccurrences(text, marker) {
  return text.split(marker).length - 1;
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs: only the lines the shipped entry point wrote.
function serverDiagnosticLines(stderr) {
  return stderr
    .split('\n')
    .map((line) => line.replace(/\r$/, ''))
    .filter((line) => line.startsWith('openrouter-review-mcp-server:'));
}

// Copied from tests/openrouter-review-mcp-stdio.test.mjs: waits for the real 'close' (stderr complete),
// bounded, so a regression that hangs the child fails this test instead of hanging the runner.
async function waitForChildClose(child, { timeoutMs = 40_000, describe = () => '' } = {}) {
  const closed = once(child, 'close');
  let timer;
  const timedOut = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`server process did not exit within ${timeoutMs}ms${describe()}`)), timeoutMs);
  });
  try {
    return await Promise.race([closed, timedOut]);
  } finally {
    clearTimeout(timer);
  }
}

// Copied from tests/openrouter-review-lease-process-liveness.test.mjs (not exported there): seed a
// processOwner ACQUIRED record naming a specific pid, bypassing acquireProcessOwnership().
async function seedAcquiredOwnerRecord(dataRoot, { pid, generation, timestamp }) {
  const ledgerRoot = join(dataRoot, 'ledger');
  await mkdir(ledgerRoot, { recursive: true });
  const record = {
    recordType: 'processOwner', state: 'ACQUIRED', pid, generation,
    acquisitionId: randomUUID(), timestamp,
  };
  await writeFile(join(ledgerRoot, `${timestamp.replace(/[:.]/g, '-')}-seed.json`), `${JSON.stringify(record)}\n`, 'utf8');
  return record;
}

// Copied from tests/openrouter-review-lease-process-liveness.test.mjs (not exported there): seed the
// raw .ledger-write.lock mutex directly, naming a specific pid.
async function seedDataRootLock(dataRoot, { pid, timestamp, lockToken = randomUUID() }) {
  const lockRoot = join(dataRoot, '.ledger-write.lock');
  await mkdir(lockRoot, { recursive: true });
  const owner = { pid, timestamp, lockToken };
  await writeFile(join(lockRoot, 'owner.json'), `${JSON.stringify(owner)}\n`, 'utf8');
  return owner;
}


// Strips EVERY inherited OPENROUTER_REVIEW_MCP_* variable, then applies the test's own. Structural
// rather than a hand-kept list: a list silently goes stale the day the server grows a new variable.
function hermeticEnv(extraEnv) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('OPENROUTER_REVIEW_MCP_')) env[key] = value;
  }
  // The extra-protected-terms setting is mandatory; tests that need terms pass their own.
  return { ...env, OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_PATH: 'none', ...extraEnv };
}

// A stand-in for the local Ollama daemon: POST /api/generate answers {"response":"false"}, which
// ollama-client.mjs parses as "not flagged" (its parseBooleanResponse). Records every request so a
// test can prove the server really classified through THIS fake and not a real local model.
async function startFakeOllama() {
  const requests = [];
  let nextGate = null;
  const server = createServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', async () => {
      requests.push({ method: request.method, url: request.url, body });
      if (request.method === 'POST' && request.url === '/api/generate') {
        const gate = nextGate;
        nextGate = null;
        if (gate !== null) {
          gate.enteredResolve();
          await gate.releasePromise;
        }
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ response: gate?.response ?? 'false' }));
        return;
      }
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'not found' }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    gateNext(response = 'false') {
      assert.equal(nextGate, null, 'only one fake-Ollama request gate may be pending');
      let enteredResolve;
      let releaseResolve;
      const entered = new Promise((resolveEntered) => { enteredResolve = resolveEntered; });
      const releasePromise = new Promise((resolveRelease) => { releaseResolve = resolveRelease; });
      nextGate = { response, enteredResolve, releasePromise };
      return { entered, release: releaseResolve };
    },
    async close() {
      server.closeAllConnections();
      await new Promise((resolveClose) => { server.close(() => resolveClose()); });
    },
  };
}

// One temp directory per test: the data root lives inside it, next to the fixture identity list, so a
// single rm() removes everything the test created.
async function makeWorkDir(label) {
  const workDir = await mkdtemp(join(tmpdir(), `openrouter-review-always-connect-${label}-`));
  const identityListPath = join(workDir, 'fixture-identity-list.txt');
  await writeFile(identityListPath, '# test fixture, never a real identity\nZyqvor Fixturename\n', 'utf8');
  return { workDir, dataRoot: join(workDir, 'data'), identityListPath };
}

// Spawns the REAL shipped entry point and completes the MCP handshake. `ollamaBaseUrl` defaults to a
// closed port, so a test that never preflights cannot reach any model by accident.
async function startRealServer({ dataRoot, identityListPath, ollamaBaseUrl = 'http://127.0.0.1:9', env: extraEnv = {} }) {
  const child = spawn(process.execPath, [SERVER_PATH], {
    cwd: REPO_ROOT,
    env: hermeticEnv({
      OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD: '10',
      OPENROUTER_REVIEW_MCP_DATA_ROOT: dataRoot,
      OPENROUTER_REVIEW_MCP_IDENTITY_LIST_PATH: identityListPath,
      OPENROUTER_REVIEW_MCP_OLLAMA_URL: ollamaBaseUrl,
      OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS: String(ARM_BUDGET_MS),
      OPENROUTER_REVIEW_MCP_ARM_LOCK_RETRY_MS: String(ARM_LOCK_RETRY_TEST_MS),
      ...extraEnv,
    }),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  // An EPIPE on a child that already exited must not become an unhandled 'error' event that kills the
  // whole test file.
  child.stdin.on('error', () => {});
  try {
    const session = await completeInitializeHandshake(wrapChildAsJsonRpcSession(child), 'openrouter-review-always-connect-test');
    return { child, session };
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    throw error;
  }
}

// Closes stdin -- the real-world shutdown trigger -- and waits for 'close', so session.stderr is
// complete when this returns.
async function stopServerAndWait(child, session) {
  if (child.exitCode === null && child.signalCode === null) child.stdin.end();
  const [code, signal] = await waitForChildClose(child, { describe: () => `; stderr so far: ${session.stderr}` });
  return { code, signal };
}

// The foreign holder: THIS test process takes real process ownership of the data root. Its pid is
// genuinely alive, so the server under test sees LIVE_OWNER through the real, un-faked liveness check.
async function holdOwnership(dataRoot) {
  const store = createLeaseStore({ dataRoot });
  const handle = await store.acquireProcessOwnership({ acquireTimeoutMs: 5_000 });
  return { store, handle };
}

// A preflight plus an ACTIVE lease, written by the foreign holder under its own acquisitionId (the
// same field shapes as seedOrphanedLeaseForRecovery in tests/openrouter-review-mcp-stdio.test.mjs),
// so the server under test has a real lease for status() and result() to read.
async function seedActiveLease({ store, handle }) {
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  const preflight = await store.createPreflight({
    reviewContractSha256: 'a'.repeat(64),
    sourceSha256: 'b'.repeat(64),
    rawSourceSha256: 'e'.repeat(64),
    profile: 'consequential_spec_v1',
    profileVersion: '1',
    schemaSha256: 'c'.repeat(64),
    registrySha256: 'd'.repeat(64),
    itemMaxima: [{ itemId: 'item-gemini', maxUsd: 0.2 }],
    requestedUsd: 0.2,
    expiresAt,
  });
  return store.createLease({
    preflightIds: [preflight.id],
    requestedUsd: 0.2,
    maxJobs: 1,
    expiresAt,
    acquisitionId: handle.acquisitionId,
  });
}

// A pid that is provably dead: spawn, hard-kill, let the OS reap it (the same 300 ms margin
// tests/openrouter-review-lease-process-liveness.test.mjs uses), then assert the premise.
async function spawnDeadPid() {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { stdio: 'ignore' });
  await once(child, 'spawn');
  const { pid } = child;
  child.kill('SIGKILL');
  await once(child, 'exit');
  await delay(300);
  assert.throws(() => process.kill(pid, 0), (error) => error.code === 'ESRCH', `pid ${pid} must be dead before it is seeded`);
  return pid;
}

test('the real entry point connects while another live process holds process ownership, and preflight, status and result all work', { timeout: 60_000 }, async () => {
  // The headline property. A startup acquire would spend its whole budget (90 s by default) polling
  // LIVE_OWNER right here, the MCP client would give up first, and a client session whose first
  // connect fails may never retry. Nothing at startup waits for ownership, and the three tools that
  // never arm keep working under a live foreign holder.
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('live-holder');
  const fakeOllama = await startFakeOllama();
  let holder;
  try {
    holder = await holdOwnership(dataRoot);
    const seededLease = await seedActiveLease(holder);

    const { child, session } = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl });
    let exit;
    try {
      const listed = await session.request('tools/list', {});
      assert.equal(listed.tools.length, 5);

      const preflight = await session.callTool('openrouter_review_preflight', {
        source_text: 'always-connect live-holder source',
        profile: 'consequential_spec_v1',
        reviewContext: 'always-connect live-holder scope',
      });
      assert.equal(preflight.isError, undefined, `preflight must succeed under a live foreign holder; got ${JSON.stringify(preflight)}`);
      assert.equal(typeof preflight.structuredContent.preflightId, 'string');
      assert.deepEqual(preflight.structuredContent.reviewers.map((reviewer) => reviewer.reviewerId).sort(), ['gemini', 'grok']);
      // Hermeticity asserted, not assumed: the classifications went to THIS fake.
      assert.ok(fakeOllama.requests.length > 0, 'preflight must have classified through the fake Ollama');
      assert.ok(fakeOllama.requests.every((entry) => entry.method === 'POST' && entry.url === '/api/generate'));

      const status = await session.callTool('openrouter_review_status', { leaseId: seededLease.id });
      assert.equal(status.isError, undefined, `status must succeed under a live foreign holder; got ${JSON.stringify(status)}`);
      assert.equal(status.structuredContent.leaseId, seededLease.id);
      assert.equal(status.structuredContent.state, 'ACTIVE');

      const result = await session.callTool('openrouter_review_result', { leaseId: seededLease.id });
      assert.equal(result.isError, undefined, `result must succeed under a live foreign holder; got ${JSON.stringify(result)}`);
      assert.equal(result.structuredContent.leaseId, seededLease.id);
      assert.equal(result.structuredContent.reviewers.gemini.state, 'NOT_DISPATCHED');

      // None of the three armed: the foreign holder's ACQUIRED is still the only processOwner record.
      const owners = await readProcessOwnerRecords(dataRoot);
      assert.deepEqual(owners.map((record) => [record.state, record.pid]), [['ACQUIRED', process.pid]]);
      assert.equal(session.nonJsonStdout, '');
    } finally {
      exit = await stopServerAndWait(child, session);
    }

    // A server that preflighted and never armed still shuts down honestly under a live foreign
    // holder: exit 0, the never-armed line, and no release claim. This is NOT the guard for the
    // post-preflight exit crash that exitAfterShutdown prevents: status and result run after the
    // preflight here, which closes that race window (this test stays green with an immediate
    // process.exit() put back). The guard is the stdio file's post-preflight exit test.
    assert.deepEqual(exit, { code: 0, signal: null }, `stderr: ${session.stderr}`);
    assert.deepEqual(serverDiagnosticLines(session.stderr), [CONNECTED_LINE, NEVER_ARMED_SHUTDOWN_LINE]);
  } finally {
    if (holder) await holder.handle.release();
    await fakeOllama.close();
    await rm(workDir, { recursive: true, force: true });
  }
});

test('a server that never arms exits 0 on stdin close, writes no processOwner record, and says it never held process ownership', { timeout: 60_000 }, async () => {
  // A session that does real, non-arming work -- a status read, which goes through the ledger -- and
  // then goes away. An unarmed release is a clean no-op, so the exit is 0 and no processOwner record
  // is written at startup or at shutdown. The shutdown line must not claim a release that never
  // happened; it says ownership was never held.
  //
  // Deliberately no preflight here: this test pins the never-armed shutdown after ledger work, and a
  // preflight is covered twice elsewhere. The live-holder test above preflights and then asserts the
  // same exit 0 and line pair; the stdio file's "...client goes away right after a preflight still
  // exits 0, not a libuv abort" test closes stdin straight after one. That test exists because an
  // immediate process.exit() at the end of shutdown can die on the libuv assertion
  // `!(handle->flags & UV_HANDLE_CLOSING)` (src\win\async.c) with exit code 0xC0000409 when stdin
  // closes within moments of a local-model fetch; the server avoids it by ending through
  // exitAfterShutdown(), which lets the event loop empty first.
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('never-armed');
  try {
    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    let exit;
    try {
      const status = await session.callTool('openrouter_review_status', { leaseId: 'no-such-lease' });
      assert.equal(JSON.parse(status.content[0].text).code, 'LEASE_MISSING');
    } finally {
      exit = await stopServerAndWait(child, session);
    }

    // First, because it is the property this test exists for.
    assert.deepEqual(
      (await readProcessOwnerRecords(dataRoot)).map((record) => record.state),
      [],
      'a server that never armed must write no processOwner record, at startup or at shutdown',
    );
    assert.deepEqual(exit, { code: 0, signal: null });
    // Exact list: nothing else was reported, the never-armed line appears once, and the release line
    // (which would claim a handover that never happened) does not appear at all.
    assert.deepEqual(serverDiagnosticLines(session.stderr), [CONNECTED_LINE, NEVER_ARMED_SHUTDOWN_LINE]);
    assert.equal(countOccurrences(session.stderr, RELEASED_SHUTDOWN_LINE), 0);
    assert.equal(session.nonJsonStdout, '');
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('a startup failure before any arm exits 1 with its ORIGINAL error as its only stderr line, and writes no processOwner record', { timeout: 60_000 }, async () => {
  // An unopenable identity-list path is a guaranteed startup failure. What this test asserts, and all
  // it asserts: exit 1, empty stdout, the ORIGINAL error (Node's ENOENT naming the missing file) as the
  // only line the server wrote to stderr, and no processOwner entry in the ledger afterwards. It
  // deliberately does NOT observe two things, because an unarmed handle makes both invisible from
  // outside the process: whether main() built its handle before loading the list, and whether the
  // catch called release({ final: true }) at all (an unarmed release writes nothing and prints nothing
  // either way). The static startup-failure-catch test below pins that release call from source.
  // What this test does bite on is a startup acquire coming back: that run leaves
  // [ 'ACQUIRED', 'RELEASED' ] behind.
  const { workDir, dataRoot } = await makeWorkDir('startup-failure');
  try {
    const child = spawn(process.execPath, [SERVER_PATH], {
      cwd: REPO_ROOT,
      env: hermeticEnv({
        OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD: '10',
        OPENROUTER_REVIEW_MCP_DATA_ROOT: dataRoot,
        OPENROUTER_REVIEW_MCP_IDENTITY_LIST_PATH: join(workDir, 'no-such-identity-list.txt'),
      }),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    try {
      const [code, signal] = await waitForChildClose(child, { describe: () => `; stderr so far: ${stderr}` });

      assert.deepEqual(
        (await readProcessOwnerRecords(dataRoot)).map((record) => record.state),
        [],
        'a startup that failed before any arm must leave no processOwner record',
      );
      assert.deepEqual({ code, signal }, { code: 1, signal: null });
      assert.equal(stdout, '');
      const diagnostics = serverDiagnosticLines(stderr);
      assert.equal(diagnostics.length, 1, `expected exactly one server diagnostic; got: ${JSON.stringify(diagnostics)}`);
      assert.match(diagnostics[0], /^openrouter-review-mcp-server: failed to start: ENOENT: no such file or directory, open '/);
      assert.ok(diagnostics[0].includes('no-such-identity-list.txt'), `expected the original error to name the missing file; got: ${diagnostics[0]}`);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('a startup scrub-mapping sweep that throws is logged once and the server still connects and serves', { timeout: 60_000 }, async () => {
  // The startup scrub-mapping sweep takes no ownership, but ownerless is not the same as safe: two
  // starters' sweeps can race readdir against stat, and a loser's ENOENT would fail main(), i.e. a
  // failed first connect, which a client session may never retry. The store skips a vanished name,
  // and main() also guards the call, so the guard must hold for ANY throw.
  //
  // An unreadable or ENOTDIR mapping root would NOT test that: listStaleBefore swallows every readdir
  // error and returns []. What still throws is a stat() failing with anything other than ENOENT. Two
  // junctions pointing at each other make stat() fail with ELOOP on Windows (Node v24); creating a
  // junction needs no privilege, and rm({ recursive, force }) removes the pair cleanly.
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('scrub-sweep-throws');
  try {
    const mappingRoot = join(dataRoot, 'scrub-mappings');
    await mkdir(mappingRoot, { recursive: true });
    await symlink(join(mappingRoot, 'loop-b.json'), join(mappingRoot, 'loop-a.json'), 'junction');
    await symlink(join(mappingRoot, 'loop-a.json'), join(mappingRoot, 'loop-b.json'), 'junction');
    // The premise, asserted: the sweep's stat() really throws, and not with the one code it skips.
    await assert.rejects(stat(join(mappingRoot, 'loop-a.json')), (error) => error.code === 'ELOOP');

    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    let exit;
    try {
      const listed = await session.request('tools/list', {});
      assert.equal(listed.tools.length, 5);
    } finally {
      exit = await stopServerAndWait(child, session);
    }

    assert.deepEqual(exit, { code: 0, signal: null });
    const diagnostics = serverDiagnosticLines(session.stderr);
    const sweepFailures = diagnostics.filter((line) => line.startsWith(SCRUB_SWEEP_FAILED_PREFIX));
    assert.equal(sweepFailures.length, 1, `expected exactly one sweep-failure line; got: ${JSON.stringify(diagnostics)}`);
    assert.match(sweepFailures[0], /ELOOP/);
    // Logged BEFORE connecting, then the ordinary lifecycle, and nothing else.
    assert.deepEqual(diagnostics, [sweepFailures[0], CONNECTED_LINE, NEVER_ARMED_SHUTDOWN_LINE]);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('a server that armed and released mid-life reports formerly-owned at shutdown without appending another RELEASED record', { timeout: 60_000 }, async () => {
  // The other half of the honest-shutdown-line rule. Production has exactly one way to hold ownership: an arm during the
  // session's life, on a handle that was still unarmed when the shutdown handlers were installed.
  // Every other test in this file ends never-armed, and the stdio file's harness shutdown tests use a
  // handle armed BEFORE the handlers exist, so none of them can tell "the line reads the handle's state
  // at shutdown" from "the line reads a state captured at install time". This one can: under the
  // second, a session that armed and paid would announce that it never held ownership while its own
  // ledger shows ACQUIRED and RELEASED, the exact lie this rule exists to prevent. The arm is
  // triggered on purpose with a never-minted preflightId (popup-safe, see the file header), and
  // shutdown waits for 'close', so stderr is complete when it is read.
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('armed-mid-life');
  try {
    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    let exit;
    try {
      await session.request('tools/list', {});
      // The premise: nothing is owned before the first arm, so the arm below is what takes ownership.
      assert.deepEqual(
        (await readProcessOwnerRecords(dataRoot)).map((record) => record.state),
        [],
        'a connected server must hold nothing before its first arm',
      );

      const armingCall = await session.callTool('openrouter_review_authorize_workflow', {
        preflightId: NEVER_MINTED_PREFLIGHT_ID,
        maxJobs: 1,
      });
      // The arm succeeded (nothing held the data root); then the inner call failed on the unknown
      // preflight, before any approval adapter could be reached.
      assert.equal(armingCall.isError, true, `expected a tool error; got ${JSON.stringify(armingCall)}`);
      assert.equal(JSON.parse(armingCall.content[0].text).code, 'CONTRACT_CHANGED');
      assert.deepEqual(
        (await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid]),
        [['ACQUIRED', child.pid], ['RELEASED', child.pid]],
        'the complete operation must acquire and release before shutdown',
      );
      const beforeShutdown = await readProcessOwnerRecords(dataRoot);
      assert.equal(beforeShutdown.length, 2);
    } finally {
      exit = await stopServerAndWait(child, session);
    }

    assert.deepEqual(exit, { code: 0, signal: null }, `stderr: ${session.stderr}`);
    // The release really happened, and it is this server's own: same pid, same acquisition.
    const owners = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(owners.map((record) => [record.state, record.pid]), [['ACQUIRED', child.pid], ['RELEASED', child.pid]]);
    assert.equal(owners[1].acquisitionId, owners[0].acquisitionId);
    // Final shutdown cleanup was a no-op, so it must not claim a fresh release.
    assert.deepEqual(serverDiagnosticLines(session.stderr), [CONNECTED_LINE, FORMERLY_OWNED_SHUTDOWN_LINE]);
    assert.equal(countOccurrences(session.stderr, NEVER_ARMED_SHUTDOWN_LINE), 0, 'a server that armed must never claim it held nothing');
    assert.equal(countOccurrences(session.stderr, RELEASED_SHUTDOWN_LINE), 0, 'a no-op final cleanup must never claim it released current ownership');
    assert.equal(session.nonJsonStdout, '');
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('main()\'s startup-failure catch writes the ORIGINAL error first and then releases the handle with final: true (static, CRLF-safe)', async () => {
  // Server contract: startup-failure cleanup calls ownerLock.release({ final: true }) and still
  // preserves the original error. No process run can observe that call: nothing on the startup path
  // arms, and an unarmed release writes nothing and prints nothing (see the startup-failure test
  // above). So it is pinned from source, read CRLF-normalized with every anchor asserted, so a moved
  // anchor fails loudly instead of silently matching the rest of the file.
  const source = (await readFile(SERVER_PATH, 'utf8')).replace(/\r\n/g, '\n');
  const marker = 'openrouter-review-mcp-server: failed to start: ';
  const writeIdx = source.indexOf(marker);
  assert.notEqual(writeIdx, -1, 'the startup-failure diagnostic was not found in tools/openrouter-review-mcp-server.mjs');
  assert.equal(source.indexOf(marker, writeIdx + 1), -1, 'expected exactly one startup-failure diagnostic in the server');
  const exitIdx = source.indexOf('process.exitCode = 1;', writeIdx);
  assert.notEqual(exitIdx, -1, 'process.exitCode = 1; not found after the startup-failure diagnostic');
  // Between the ORIGINAL error's write and the catch's exit code: the release must be there, AFTER the
  // write (so a release failure can never be the only thing reported), and final.
  assert.match(
    source.slice(writeIdx, exitIdx),
    /if \(ownerLock\) \{\s*try \{\s*await ownerLock\.release\(\{ final: true \}\);/,
    'the startup-failure catch must call release({ final: true }) on the handle after writing the original error',
  );
});

test('a set retired OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS gives exactly one warning line and the server still connects, garbage value included', { timeout: 60_000 }, async () => {
  // A plausible legacy value and a garbage value must both warn once and still serve ('not-a-number'
  // was fatal at startup while the variable still governed the startup acquire).
  for (const retiredValue of ['20000', 'not-a-number']) {
    // eslint-disable-next-line no-await-in-loop
    const { workDir, dataRoot, identityListPath } = await makeWorkDir('retired-acquire-timeout');
    try {
      // eslint-disable-next-line no-await-in-loop
      const { child, session } = await startRealServer({
        dataRoot,
        identityListPath,
        env: { OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS: retiredValue },
      });
      let exit;
      try {
        // eslint-disable-next-line no-await-in-loop
        const listed = await session.request('tools/list', {});
        assert.equal(listed.tools.length, 5);
      } finally {
        // eslint-disable-next-line no-await-in-loop
        exit = await stopServerAndWait(child, session);
      }

      assert.deepEqual(exit, { code: 0, signal: null }, `retired value ${JSON.stringify(retiredValue)}`);
      const diagnostics = serverDiagnosticLines(session.stderr);
      const warnings = diagnostics.filter((line) => line.startsWith(WARNING_PREFIX));
      assert.equal(warnings.length, 1, `expected exactly one warning line for ${JSON.stringify(retiredValue)}; got: ${JSON.stringify(diagnostics)}`);
      assert.match(warnings[0], /OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS/);
      assert.match(warnings[0], /no longer does anything/);
      // Written before startup, then the ordinary never-armed lifecycle, and nothing else.
      assert.deepEqual(diagnostics, [warnings[0], CONNECTED_LINE, NEVER_ARMED_SHUTDOWN_LINE]);
    } finally {
      // eslint-disable-next-line no-await-in-loop
      await rm(workDir, { recursive: true, force: true });
    }
  }
});

// authorize_workflow with a preflightId no preflight() ever minted (popup-safe, see the file header):
// the wrapper arms before the inner call looks the preflight up, so an arm refusal is what comes back.
// Asserts the minimum refusal contract on every refusal: isError, and a body that parses as {code, message}.
async function callArmingAuthorize(session) {
  const response = await session.callTool('openrouter_review_authorize_workflow', {
    preflightId: NEVER_MINTED_PREFLIGHT_ID,
    maxJobs: 1,
  });
  assert.equal(response.isError, true, `expected a tool error; got ${JSON.stringify(response)}`);
  assert.equal(response.content.length, 1);
  const payload = JSON.parse(response.content[0].text);
  assert.equal(typeof payload.code, 'string');
  assert.equal(typeof payload.message, 'string');
  return payload;
}

test('LIVE_OWNER -- an arm refused by a live foreign holder is PROCESS_OWNERSHIP_UNAVAILABLE, naming the holder pid and age', { timeout: 60_000 }, async () => {
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('live-owner');
  let holder;
  try {
    holder = await holdOwnership(dataRoot);
    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    try {
      const payload = await callArmingAuthorize(session);
      assert.equal(payload.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
      // `\\b` is doubled on purpose: inside a template literal a single `\b` is a BACKSPACE character,
      // not a regex word boundary, and a pattern built from it can never match.
      assert.match(payload.message, new RegExp(`\\bpid ${process.pid}\\b`));
      assert.match(payload.message, /owner for \d+s/);
      assert.match(payload.message, /preflight, status and result still work/);
      assert.equal(Object.hasOwn(payload, 'details'), true, 'the engine\'s advisory details must reach the wire');
      assert.equal(payload.details.reason, 'LIVE_OWNER');
      assert.equal(payload.details.owner.pid, process.pid);
      assert.equal(payload.details.owner.generation, holder.handle.generation);
      assert.equal(Object.hasOwn(payload.details.owner, 'acquisitionId'), false, 'the fence token never leaves the store');
      assert.equal(typeof payload.details.ownerAgeMs, 'number');
      // A refused arm writes nothing: the holder's ACQUIRED is still the only processOwner record.
      assert.deepEqual((await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid]), [['ACQUIRED', process.pid]]);
    } finally {
      await stopServerAndWait(child, session);
    }
  } finally {
    if (holder) await holder.handle.release();
    await rm(workDir, { recursive: true, force: true });
  }
});

test('NOT_YET_STALE -- an arm refused by a dead but not-yet-stale predecessor names its pid and record age', { timeout: 60_000 }, async (t) => {
  // A genuinely dead pid on a fresh ACQUIRED record: the real liveness check reports it dead, and the
  // record is far younger than the store's 60 s lockStaleMs, so every attempt is NOT_YET_STALE.
  //
  // That premise can break under the test's feet. Windows hands a freed pid out again, measured within
  // about 1.5 s on a busy host, and between spawnDeadPid()'s single ESRCH check and the arm's last
  // attempt this test spans about 2 s (longer under a full-suite run). A reused pid is alive and the
  // record is fresh, so the store correctly answers LIVE_OWNER for it: the start-time probe that would
  // unmask the reuse runs only on a record that is already stale. That answer is right and is not this
  // test's subject, so it is recognised by its exact shape (a LIVE_OWNER refusal naming the very pid
  // this test seeded as dead) and the premise is rebuilt with a fresh dead pid and a fresh data root.
  // Bounded: three attempts, then a failure that says the premise could not be established, never a
  // silent pass. A store that reported every dead pid as alive would fail all three and land there too.
  const maxPremiseAttempts = 3;
  const reusedPids = [];
  for (let attempt = 1; attempt <= maxPremiseAttempts; attempt += 1) {
    // eslint-disable-next-line no-await-in-loop
    const { workDir, dataRoot, identityListPath } = await makeWorkDir(`not-yet-stale-${attempt}`);
    try {
      // eslint-disable-next-line no-await-in-loop
      const deadPid = await spawnDeadPid();
      // eslint-disable-next-line no-await-in-loop
      await seedAcquiredOwnerRecord(dataRoot, { pid: deadPid, generation: 1, timestamp: new Date().toISOString() });

      // eslint-disable-next-line no-await-in-loop
      const { child, session } = await startRealServer({ dataRoot, identityListPath });
      try {
        // eslint-disable-next-line no-await-in-loop
        const payload = await callArmingAuthorize(session);
        if (payload.details?.reason === 'LIVE_OWNER' && payload.details.owner?.pid === deadPid) {
          reusedPids.push(deadPid);
          t.diagnostic(`attempt ${attempt}: pid ${deadPid} was reused by another process before the arm read it; retrying with a fresh dead pid`);
          continue;
        }
        assert.equal(payload.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
        assert.match(payload.message, new RegExp(`\\bpid ${deadPid}\\b`)); // doubled `\\b`, as in the LIVE_OWNER test
        assert.match(payload.message, /\(\d+s old\)/);
        assert.match(payload.message, /not yet stale/);
        assert.equal(Object.hasOwn(payload, 'details'), true, 'the engine\'s advisory details must reach the wire');
        assert.equal(payload.details.reason, 'NOT_YET_STALE');
        assert.equal(payload.details.owner.pid, deadPid);
        assert.equal(Object.hasOwn(payload.details.owner, 'acquisitionId'), false);
        // eslint-disable-next-line no-await-in-loop
        assert.deepEqual((await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid]), [['ACQUIRED', deadPid]]);
        return;
      } finally {
        // eslint-disable-next-line no-await-in-loop
        await stopServerAndWait(child, session);
      }
    } finally {
      // eslint-disable-next-line no-await-in-loop
      await rm(workDir, { recursive: true, force: true });
    }
  }
  assert.fail(`the NOT_YET_STALE premise could not be established: in all ${maxPremiseAttempts} attempts the seeded dead pid came back as a LIVE_OWNER (pids ${reusedPids.join(', ')}). Either Windows reused every one of them before the arm read it, or the store now reports dead pids as alive, which would be a regression.`);
});

test('DATA_ROOT_LOCKED -- an arm that never got the ledger lock is still PROCESS_OWNERSHIP_UNAVAILABLE and names no pid, while a non-arming status call on the same ledger is LEDGER_BUSY', { timeout: 60_000 }, async () => {
  // The raw .ledger-write.lock mutex, held in the name of THIS live test process: nothing can reclaim
  // it, so every ledger call in the server times out on it. Startup itself touches no ledger lock,
  // which is why the server still connects.
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('data-root-locked');
  try {
    await seedDataRootLock(dataRoot, { pid: process.pid, timestamp: new Date().toISOString() });

    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    try {
      // An ARM that exhausts its budget is PROCESS_OWNERSHIP_UNAVAILABLE whatever its last reason.
      // The lock names a pid, but that pid holds a different lock and owns nothing, so the
      // message must not pretend to identify a holder.
      const refusal = await callArmingAuthorize(session);
      assert.equal(refusal.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
      assert.doesNotMatch(refusal.message, /\bpid\b/i);
      assert.equal(refusal.message.includes(String(process.pid)), false);
      assert.match(refusal.message, /no holder could be identified/);
      assert.equal(Object.hasOwn(refusal, 'details'), true, 'the engine\'s advisory details must reach the wire');
      assert.equal(refusal.details.reason, 'DATA_ROOT_LOCKED');
      assert.equal(Object.hasOwn(refusal.details, 'owner'), false);

      // A NON-arming call that loses the same lock is a different failure with a different meaning:
      // the ledger was busy, and retrying the same call is safe.
      const status = await session.callTool('openrouter_review_status', { leaseId: 'any-lease-id' });
      assert.equal(status.isError, true, `expected a tool error; got ${JSON.stringify(status)}`);
      const busy = JSON.parse(status.content[0].text);
      assert.equal(busy.code, 'LEDGER_BUSY');
      assert.match(busy.message, /the review ledger is busy/);
      assert.equal(Object.hasOwn(busy, 'details'), false, 'LEDGER_BUSY carries no details');

      // No processOwner record was written. That is all this asserts: readProcessOwnerRecords reads a
      // missing ledger directory and an empty one alike as no records.
      assert.deepEqual(await readProcessOwnerRecords(dataRoot), []);
    } finally {
      await stopServerAndWait(child, session);
    }
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

// A live foreign holder whose ACQUIRED record carries spend caps, as a server configured with a
// different OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD would leave: THIS test process arms a
// real handle. arm() stamps the cap it is given and this store's own dailyPaidJobAllowance.
async function holdCappedOwnership(dataRoot, { installationHardMaximumUsd }) {
  const store = createLeaseStore({ dataRoot });
  const handle = store.createUnarmedOwnerHandle();
  await handle.arm({ acquireTimeoutMs: 5_000, lockRetryMs: ARM_LOCK_RETRY_TEST_MS, caps: { installationHardMaximumUsd } });
  return { store, handle };
}

test('OWNERSHIP_CAP_MISMATCH -- an arm refused by a live owner armed with a different cap reaches the wire as {code, message, details: {recorded, resolved}}', { timeout: 60_000 }, async () => {
  // The engine-level cap-mismatch tests stop at the engine; this is the one test in which a cap
  // disagreement travels through the real server wiring and toolErrorFromEngineError. The holder is
  // this live process, armed with cap 7; startRealServer configures the server with 10. The store's
  // cap check runs before its LIVE_OWNER branch, so the answer is the cap refusal: the first attempt
  // probes the holder's start time outside the lock, finds it genuine, and the follow-up attempt is
  // terminal.
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('cap-mismatch');
  let holder;
  try {
    holder = await holdCappedOwnership(dataRoot, { installationHardMaximumUsd: 7 });
    // The premise: the only processOwner record is this live process's ACQUIRED, stamped with cap 7
    // and this store's default daily allowance of 20.
    assert.deepEqual(
      (await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid, record.caps]),
      [['ACQUIRED', process.pid, { installationHardMaximumUsd: 7, dailyPaidJobAllowance: 20 }]],
    );

    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    try {
      const payload = await callArmingAuthorize(session);
      assert.equal(payload.code, 'OWNERSHIP_CAP_MISMATCH', `expected the cap refusal, not a contention reason; got ${JSON.stringify(payload)}`);
      // Both values named, the equal member not named, and no currency sign.
      assert.match(payload.message, /installationHardMaximumUsd recorded 7 vs this server 10/);
      assert.doesNotMatch(payload.message, /dailyPaidJobAllowance/, 'an equal member is not named as a difference');
      assert.equal(payload.message.includes('$'), false);
      assert.equal(Object.hasOwn(payload, 'details'), true, 'the engine\'s advisory details must reach the wire');
      // The whole object, exactly: the caps the holder's record carries, and the caps this server's arm
      // resolved (its own configured cap and its own store's allowance). A server that armed
      // with a cap other than its configured one, or a serializer that dropped or reshaped either
      // half, fails here.
      assert.deepEqual(payload.details, {
        recorded: { installationHardMaximumUsd: 7, dailyPaidJobAllowance: 20 },
        resolved: { installationHardMaximumUsd: 10, dailyPaidJobAllowance: 20 },
      });
      // A refused arm writes nothing: the holder's ACQUIRED is still the only processOwner record.
      assert.deepEqual((await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid]), [['ACQUIRED', process.pid]]);
    } finally {
      await stopServerAndWait(child, session);
    }
  } finally {
    if (holder) await holder.handle.release();
    await rm(workDir, { recursive: true, force: true });
  }
});

test('closing stdin while an arm waits on a live foreign holder aborts the arm inside the drain -- exit 0 well within the real drain budget, with the never-armed line', { timeout: 60_000 }, async () => {
  // The drain budget is the server's REAL default (DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_MS, 30 000 ms): the
  // helper strips every inherited override and this test sets none. The arm budget is deliberately
  // LONGER than that drain, as production's is (90 000 ms), so an arm that shutdown failed to abort
  // would still be polling when the drain gave up -- exit 1 after about 30 s instead of exit 0 now.
  const longArmBudgetMs = 45_000;
  const realDrainBudgetMs = 30_000;
  assert.ok(longArmBudgetMs > realDrainBudgetMs, 'the arm budget must outlast the drain, as it does in production');

  const { workDir, dataRoot, identityListPath } = await makeWorkDir('arm-abort-on-shutdown');
  let holder;
  let reachedEnd = false;
  try {
    holder = await holdOwnership(dataRoot);
    const { child, session } = await startRealServer({
      dataRoot,
      identityListPath,
      env: { OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS: String(longArmBudgetMs) },
    });
    try {
      // Not awaited: this arm polls LIVE_OWNER and only ends when shutdown aborts it. Its outcome is
      // captured rather than awaited, because whether the SHUTTING_DOWN answer is written before the
      // process exits is a race between two promise chains inside the child.
      let armingOutcome = null;
      session.callTool('openrouter_review_authorize_workflow', {
        preflightId: NEVER_MINTED_PREFLIGHT_ID,
        maxJobs: 1,
      }).then((response) => { armingOutcome = { response }; }, (error) => { armingOutcome = { error }; });

      // Synchronization, not a sleep. status was written to the pipe after authorize, and the path from
      // receiving authorize to trackInFlight registering it -- and the coordinator starting its arm --
      // is microtasks only (SDK input validation, the tool callback, the engine wrapper's synchronous
      // start). status's own answer needs real file I/O under the ledger lock, and no I/O completes
      // before pending microtasks drain. So when this answer arrives, the arm was admitted BEFORE
      // shutdown began, and anything that stops it afterwards is the abort, not an entry refusal.
      const status = await session.callTool('openrouter_review_status', { leaseId: 'no-such-lease' });
      assert.equal(JSON.parse(status.content[0].text).code, 'LEASE_MISSING');

      const closedAt = performance.now();
      const exit = await stopServerAndWait(child, session);
      const shutdownMs = performance.now() - closedAt;

      assert.deepEqual(exit, { code: 0, signal: null }, 'an aborted arm lets the drain complete: exit 0, a NUMBER, never a signal');
      assert.ok(shutdownMs < 10_000, `the abort must land well inside the ${realDrainBudgetMs} ms drain budget; shutdown took ${Math.round(shutdownMs)} ms`);
      assert.equal(countOccurrences(session.stderr, 'shutdown drain timed out'), 0, `the drain must not time out; stderr: ${session.stderr}`);
      // The aborted arm returned the handle to unarmed, so the honest line is the never-armed one.
      assert.equal(countOccurrences(session.stderr, NEVER_ARMED_SHUTDOWN_LINE), 1, `stderr: ${session.stderr}`);
      assert.equal(countOccurrences(session.stderr, RELEASED_SHUTDOWN_LINE), 0, 'nothing was held, so no release may be announced');
      // If the tool answer did get out before the exit, it must be the translated abort, never a lease
      // and never a timed-out arm.
      if (armingOutcome && armingOutcome.response) {
        assert.equal(armingOutcome.response.isError, true);
        assert.equal(JSON.parse(armingOutcome.response.content[0].text).code, 'SHUTTING_DOWN');
      }

      // A PREMISE check, not evidence of the abort: while this test process holds a live, seconds-old
      // ownership record, every arm attempt is refused LIVE_OWNER, so this server could not have written
      // any processOwner record whether or not shutdown aborted its arm. It reddens only if the store
      // ever took over a live, fresh owner. The committed-then-compensated half of an aborted arm is
      // covered at the engine level.
      const owners = await readProcessOwnerRecords(dataRoot);
      assert.equal(owners.some((record) => record.pid === child.pid), false, `the exited server must never have recorded ownership; got ${JSON.stringify(owners)}`);
      assert.deepEqual(owners.map((record) => [record.state, record.pid]), [['ACQUIRED', process.pid]]);
      reachedEnd = true;
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
  } finally {
    // Cleanup must not replace this test's own failure. When the drain times out (for example with
    // the abort deliberately broken), exitAfterShutdown's fallback process.exit() can land while the still-polling arm holds
    // the ledger's data-root lock. That orphaned lock is far younger than the store's stale-lock
    // bound, so this release then times out with LEDGER_DATA_ROOT_LOCKED and, thrown from here, would
    // hide the real assertion. So only after a failure, and only that code, is tolerated; on the
    // passing path (reachedEnd) every release error still fails the test.
    if (holder) {
      try {
        await holder.handle.release();
      } catch (releaseError) {
        if (reachedEnd || releaseError?.code !== 'LEDGER_DATA_ROOT_LOCKED') throw releaseError;
      }
    }
    await rm(workDir, { recursive: true, force: true });
  }
});

test('a refused arm still shuts down cleanly on stdin close and never writes this server as an owner', { timeout: 60_000 }, async () => {
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('refused-arm-clean-shutdown');
  let holder;
  try {
    holder = await holdOwnership(dataRoot);
    const { child, session } = await startRealServer({ dataRoot, identityListPath });
    let exit;
    try {
      const payload = await callArmingAuthorize(session);
      assert.equal(payload.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
    } finally {
      exit = await stopServerAndWait(child, session);
    }
    assert.deepEqual(exit, { code: 0, signal: null }, `stderr: ${session.stderr}`);
    assert.deepEqual(serverDiagnosticLines(session.stderr), [CONNECTED_LINE, NEVER_ARMED_SHUTDOWN_LINE]);
    assert.deepEqual(
      (await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid]),
      [['ACQUIRED', process.pid]],
      'the refused server must leave no ACQUIRED or RELEASED record of its own',
    );
  } finally {
    if (holder) await holder.handle.release();
    await rm(workDir, { recursive: true, force: true });
  }
});

test('B is refused while A has active gated work, then the same B session arms after A completes and releases', { timeout: 60_000 }, async () => {
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('two-process-handoff');
  const fakeOllama = await startFakeOllama();
  let first;
  let second;
  let judgeGate;
  try {
    const autonomousEnv = { OPENROUTER_REVIEW_MCP_AUTONOMOUS_AUTHORIZATION: '1' };
    first = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });
    const firstPid = first.child.pid;
    const preflight = await first.session.callTool('openrouter_review_preflight', {
      source_text: 'offline active two-process contention source',
      profile: 'consequential_spec_v1',
      reviewContext: 'active two-process contention',
    });
    const firstAuthorization = await first.session.callTool('openrouter_review_authorize_workflow', {
      preflightId: preflight.structuredContent.preflightId,
      maxJobs: 2,
    });
    assert.equal(firstAuthorization.isError, undefined);

    judgeGate = fakeOllama.gateNext('{"justified":true,"reasoning":"offline test gate"}');
    const activeAuthorization = first.session.callTool('openrouter_review_authorize_workflow', {
      preflightId: preflight.structuredContent.preflightId,
      maxJobs: 2,
      justification: { source: 'llm', reason: 'offline gated ownership contention' },
    });
    await judgeGate.entered;

    second = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });
    const refused = await callArmingAuthorize(second.session);
    assert.equal(refused.code, 'PROCESS_OWNERSHIP_UNAVAILABLE');

    judgeGate.release();
    assert.equal((await activeAuthorization).isError, undefined);

    const retried = await callArmingAuthorize(second.session);
    assert.equal(retried.code, 'CONTRACT_CHANGED', 'the still-connected B session must retry and arm after A completed');
    assert.deepEqual((await readProcessOwnerRecords(dataRoot)).map((record) => [record.state, record.pid]), [
      ['ACQUIRED', firstPid],
      ['RELEASED', firstPid],
      ['ACQUIRED', firstPid],
      ['RELEASED', firstPid],
      ['ACQUIRED', second.child.pid],
      ['RELEASED', second.child.pid],
    ]);
  } finally {
    if (judgeGate) judgeGate.release();
    if (second) await stopServerAndWait(second.child, second.session);
    if (first) await stopServerAndWait(first.child, first.session);
    await fakeOllama.close();
    await rm(workDir, { recursive: true, force: true });
  }
});

test('live stdio sessions hand ownership A to B and back to A after each completed operation', { timeout: 60_000 }, async () => {
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('live-a-b-a-handoff');
  let first;
  let second;
  try {
    first = await startRealServer({ dataRoot, identityListPath });
    second = await startRealServer({ dataRoot, identityListPath });
    const firstPid = first.child.pid;
    const secondPid = second.child.pid;

    assert.equal((await callArmingAuthorize(first.session)).code, 'CONTRACT_CHANGED');
    assert.equal(first.child.exitCode, null, 'A remains connected after releasing its completed operation');

    assert.equal((await callArmingAuthorize(second.session)).code, 'CONTRACT_CHANGED');
    assert.equal(second.child.exitCode, null, 'B uses its existing connection after A releases');

    assert.equal((await callArmingAuthorize(first.session)).code, 'CONTRACT_CHANGED');
    assert.equal(first.child.exitCode, null, 'A reuses its existing connection after B releases');

    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => [record.state, record.pid]), [
      ['ACQUIRED', firstPid],
      ['RELEASED', firstPid],
      ['ACQUIRED', secondPid],
      ['RELEASED', secondPid],
      ['ACQUIRED', firstPid],
      ['RELEASED', firstPid],
    ]);
    assert.equal(records[1].acquisitionId, records[0].acquisitionId);
    assert.equal(records[3].acquisitionId, records[2].acquisitionId);
    assert.equal(records[5].acquisitionId, records[4].acquisitionId);
    assert.notEqual(records[2].acquisitionId, records[0].acquisitionId);
    assert.notEqual(records[4].acquisitionId, records[2].acquisitionId);
  } finally {
    if (second) await stopServerAndWait(second.child, second.session);
    if (first) await stopServerAndWait(first.child, first.session);
    await rm(workDir, { recursive: true, force: true });
  }
});

test('a real in-flight repeat authorization retains ownership while its local judge is gated, then both live sessions hand off and remain reusable', { timeout: 60_000 }, async () => {
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('active-operation-contention');
  const fakeOllama = await startFakeOllama();
  let first;
  let second;
  let scrubGate;
  try {
    const autonomousEnv = { OPENROUTER_REVIEW_MCP_AUTONOMOUS_AUTHORIZATION: '1' };
    first = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });
    second = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });

    const sourceText = 'offline active-operation contention source';
    const preflight = await first.session.callTool('openrouter_review_preflight', {
      source_text: sourceText,
      profile: 'consequential_spec_v1',
      reviewContext: 'active-operation contention',
    });
    assert.equal(preflight.isError, undefined, `free preflight must succeed through fake Ollama: ${JSON.stringify(preflight)}`);
    const authorization = await first.session.callTool('openrouter_review_authorize_workflow', {
      preflightId: preflight.structuredContent.preflightId,
      maxJobs: 2,
    });
    assert.equal(authorization.isError, undefined, `first autonomous authorization must succeed without a human phrase: ${JSON.stringify(authorization)}`);

    scrubGate = fakeOllama.gateNext('{"justified":true,"reasoning":"offline test gate"}');
    const activeAuthorization = first.session.callTool('openrouter_review_authorize_workflow', {
      preflightId: preflight.structuredContent.preflightId,
      maxJobs: 2,
      justification: {
        source: 'llm',
        reason: 'offline test of a gated local repeat-authorization judge',
      },
    });
    await scrubGate.entered;

    const blockedWhileActive = await callArmingAuthorize(second.session);
    assert.equal(blockedWhileActive.code, 'PROCESS_OWNERSHIP_UNAVAILABLE', 'B is refused while A has genuine admitted work');

    scrubGate.release();
    const repeated = await activeAuthorization;
    assert.equal(repeated.isError, undefined, `the gated local judge must approve without any provider dispatch: ${JSON.stringify(repeated)}`);

    assert.equal((await callArmingAuthorize(second.session)).code, 'CONTRACT_CHANGED', 'B acquires on its existing connection after A finishes');
    assert.equal((await callArmingAuthorize(first.session)).code, 'CONTRACT_CHANGED', 'A acquires again on its existing connection after B finishes');
    assert.equal(first.child.exitCode, null);
    assert.equal(second.child.exitCode, null);

    const records = await readProcessOwnerRecords(dataRoot);
    assert.deepEqual(records.map((record) => record.state), [
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
      'ACQUIRED', 'RELEASED',
    ]);
  } finally {
    if (scrubGate) scrubGate.release();
    if (second) await stopServerAndWait(second.child, second.session);
    if (first) await stopServerAndWait(first.child, first.session);
    await fakeOllama.close();
    await rm(workDir, { recursive: true, force: true });
  }
});

test('while A has active gated work, B and C document calls are refused before inner lookup, then their same sessions serve status and fake-Ollama preflight', { timeout: 60_000 }, async () => {
  const { workDir, dataRoot, identityListPath } = await makeWorkDir('three-session-document-contention');
  const fakeOllama = await startFakeOllama();
  let seedHolder;
  let owner;
  let second;
  let third;
  let judgeGate;
  try {
    seedHolder = await holdOwnership(dataRoot);
    const seededLease = await seedActiveLease(seedHolder);
    await seedHolder.handle.release();
    seedHolder = undefined;

    const autonomousEnv = { OPENROUTER_REVIEW_MCP_AUTONOMOUS_AUTHORIZATION: '1' };
    owner = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });
    const ownerPreflight = await owner.session.callTool('openrouter_review_preflight', {
      source_text: 'offline active three-session contention source',
      profile: 'consequential_spec_v1',
      reviewContext: 'active three-session contention',
    });
    const ownerAuthorization = await owner.session.callTool('openrouter_review_authorize_workflow', {
      preflightId: ownerPreflight.structuredContent.preflightId,
      maxJobs: 2,
    });
    assert.equal(ownerAuthorization.isError, undefined);

    judgeGate = fakeOllama.gateNext('{"justified":true,"reasoning":"offline test gate"}');
    const activeAuthorization = owner.session.callTool('openrouter_review_authorize_workflow', {
      preflightId: ownerPreflight.structuredContent.preflightId,
      maxJobs: 2,
      justification: { source: 'llm', reason: 'offline gated ownership contention' },
    });
    await judgeGate.entered;

    second = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });
    third = await startRealServer({ dataRoot, identityListPath, ollamaBaseUrl: fakeOllama.baseUrl, env: autonomousEnv });
    const blockedInput = {
      leaseId: 'never-minted-lease-for-contention',
      preflightId: 'never-minted-preflight-for-contention',
      source_text: 'schema-valid unpaid contention probe source',
      reviewContext: 'must be refused by ownership before this is used',
    };
    const blocked = await Promise.all([
      second.session.callTool('openrouter_review_document', blockedInput),
      third.session.callTool('openrouter_review_document', blockedInput),
    ]);
    for (const response of blocked) {
      assert.equal(response.isError, true, `document call must be an ownership error: ${JSON.stringify(response)}`);
      assert.equal(JSON.parse(response.content[0].text).code, 'PROCESS_OWNERSHIP_UNAVAILABLE');
    }

    for (const [label, session] of [['B', second.session], ['C', third.session]]) {
      // These are the same still-connected sessions that just received the contention response.
      // eslint-disable-next-line no-await-in-loop
      const status = await session.callTool('openrouter_review_status', { leaseId: seededLease.id });
      assert.equal(status.isError, undefined, `${label} status must remain usable after a refused document call`);
      assert.equal(status.structuredContent.state, 'ACTIVE');
      // eslint-disable-next-line no-await-in-loop
      const preflight = await session.callTool('openrouter_review_preflight', {
        source_text: `same-session ${label} free preflight`,
        profile: 'consequential_spec_v1',
        reviewContext: 'unpaid fake-Ollama validation',
      });
      assert.equal(preflight.isError, undefined, `${label} preflight must remain usable after a refused document call`);
    }
    assert.ok(fakeOllama.requests.length >= 4, 'both same-session preflights must call the hermetic fake Ollama');
    judgeGate.release();
    assert.equal((await activeAuthorization).isError, undefined, 'A completes and releases after the ownerless same-session reads finish');
  } finally {
    if (judgeGate) judgeGate.release();
    if (third) await stopServerAndWait(third.child, third.session);
    if (second) await stopServerAndWait(second.child, second.session);
    if (owner) await stopServerAndWait(owner.child, owner.session);
    if (seedHolder) await seedHolder.handle.release();
    await fakeOllama.close();
    await rm(workDir, { recursive: true, force: true });
  }
});
