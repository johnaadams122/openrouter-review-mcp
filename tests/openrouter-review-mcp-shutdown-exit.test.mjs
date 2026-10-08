import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

// exitAfterShutdown() (tools/openrouter-review-mcp-server.mjs) ends the process by letting the
// event loop empty instead of calling process.exit() straight away -- see its own comment for the
// Windows libuv abort that forced this. That trade gives up process.exit()'s guarantee that the
// process actually ends, and the only thing that keeps it is the function's fallback timer. None of
// the stdio tests hold the loop open after shutdown, so deleting that timer leaves all of them
// green. This file is the one place it is exercised.
//
// It needs no MCP session, so it lives in its own file.

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_URL = pathToFileURL(resolve(__dirname, '..', 'tools', 'openrouter-review-mcp-server.mjs')).href;

// Distinct from 0, and from the 1 Node itself reports for an uncaught error such as a failed import,
// so a child that never reached exitAfterShutdown() cannot pass as one that exited through it.
const REQUESTED_EXIT_CODE = 7;
const ARMED_MARKER = 'shutdown-exit-test: armed';

test('exitAfterShutdown still ends a process whose event loop is held open, with the requested code', { timeout: 30_000 }, async () => {
  // A ref'd interval stands in for work a timed-out drain leaves running, such as a real dispatch
  // child process: with only process.exitCode set, the loop never empties and the process never
  // ends. The module's main() stays inert here because it is guarded on process.argv[1], which
  // `node --input-type=module -e` leaves undefined.
  const source = `
import { exitAfterShutdown } from ${JSON.stringify(SERVER_URL)};
setInterval(() => {}, 60_000);
process.stderr.write(${JSON.stringify(`${ARMED_MARKER}\n`)});
exitAfterShutdown(${REQUESTED_EXIT_CODE});
`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.stdout.resume();

  // Bounded, so the regression this test exists for -- a process that never ends -- fails here
  // with its stderr instead of hanging the runner.
  let timer;
  const timedOut = new Promise((resolveTimeout) => {
    timer = setTimeout(() => resolveTimeout('timed out'), 15_000);
  });
  try {
    const outcome = await Promise.race([once(child, 'close'), timedOut]);
    assert.notEqual(outcome, 'timed out', `the process was still running 15s after exitAfterShutdown(); stderr: ${stderr}`);
    const [exitCode, exitSignal] = outcome;
    assert.ok(stderr.includes(ARMED_MARKER), `the child never reached exitAfterShutdown(); stderr: ${stderr}`);
    assert.deepEqual({ exitCode, exitSignal }, { exitCode: REQUESTED_EXIT_CODE, exitSignal: null }, `stderr: ${stderr}`);
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
});
