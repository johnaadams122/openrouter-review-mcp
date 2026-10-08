import assert from 'node:assert/strict';
import { execFile as execFileCallback, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);

const signalLogPath = fileURLToPath(new URL('../tools/openrouter-review-ctrl-signal-log.ps1', import.meta.url));
const workerPath = fileURLToPath(new URL('../tools/openrouter-review-dispatch.ps1', import.meta.url));
const launcherPath = fileURLToPath(new URL('../tools/openrouter-review-dispatch-launcher.ps1', import.meta.url));
const signalLogSource = readFileSync(signalLogPath, 'utf8').replace(/\r\n/g, '\n');
const workerSource = readFileSync(workerPath, 'utf8').replace(/\r\n/g, '\n');
const launcherSource = readFileSync(launcherPath, 'utf8').replace(/\r\n/g, '\n');

// These tests prove the STATUS_CONTROL_C_EXIT failure-log module is wired safely: they only
// prove the instrumentation ITSELF is wired correctly -- they cannot prove what causes a given
// termination, which requires a real occurrence with this armed.

test('the failure-log module is dot-sourced by the worker INSIDE its dot-source guard, not at top-level parse time', () => {
  // Both the worker and launcher have their own existing test files that dot-source them to
  // exercise pure helper functions offline -- if this install call ran unconditionally at
  // top-level, dot-sourcing for that unrelated purpose would install a real native console
  // handler in the test process itself. Anchoring to the guard's own opening brace, the same
  // technique the launcher's own test file already uses for a different assertion (see
  // "the unanchored version of this test... matched from the FIRST catch" comment there).
  const guardIndex = workerSource.indexOf("if ($MyInvocation.InvocationName -ne '.') {");
  assert.ok(guardIndex > 0, 'expected to find the dot-source guard');
  const installIndex = workerSource.indexOf("Install-OpenRouterCtrlSignalLog -LogPath", guardIndex);
  assert.ok(installIndex > guardIndex, 'expected the install call inside (after) the guard');
  assert.ok(!workerSource.slice(0, guardIndex).includes('Install-OpenRouterCtrlSignalLog'),
    'the install call must not also appear before the guard (i.e. unconditionally)');
  assert.match(workerSource.slice(guardIndex, installIndex + 200), /-Role 'worker'/);
});

test('the failure-log module is dot-sourced by the launcher INSIDE its dot-source guard, not at top-level parse time', () => {
  const guardIndex = launcherSource.indexOf("if ($MyInvocation.InvocationName -ne '.') {");
  assert.ok(guardIndex > 0, 'expected to find the dot-source guard');
  const installIndex = launcherSource.indexOf("Install-OpenRouterCtrlSignalLog -LogPath", guardIndex);
  assert.ok(installIndex > guardIndex, 'expected the install call inside (after) the guard');
  assert.ok(!launcherSource.slice(0, guardIndex).includes('Install-OpenRouterCtrlSignalLog'),
    'the install call must not also appear before the guard (i.e. unconditionally)');
  assert.match(launcherSource.slice(guardIndex, installIndex + 200), /-Role 'launcher'/);
});

// Dot-sourcing the failure-log module runs Add-Type at PARSE time, outside any function body --
// so Install-OpenRouterCtrlSignalLog's own internal error handling (which only covers the
// SetConsoleCtrlHandler call itself) could never catch a compilation failure there,
// contradicting this instrumentation's own stated goal ("must never be why a dispatch fails").
// Both call sites therefore wrap the dot-source + install in their own
// try/catch; these tests pin that wrap exists, anchored to the actual dot-source line so a
// try/catch added somewhere else in the file couldn't satisfy this vacuously.
test('the worker wraps the failure-log dot-source + install in its own try/catch', () => {
  const dotSourceIndex = workerSource.indexOf(". (Join-Path $PSScriptRoot 'openrouter-review-ctrl-signal-log.ps1')");
  assert.ok(dotSourceIndex > 0, 'expected to find the failure-log dot-source line');
  const before = workerSource.slice(0, dotSourceIndex);
  const lastTry = before.lastIndexOf('try {');
  const lastCatchBeforeTry = before.lastIndexOf('catch {', lastTry);
  assert.ok(lastTry > lastCatchBeforeTry, 'expected a try { immediately preceding the dot-source, not a stale catch from earlier in the file');
  assert.ok(dotSourceIndex - lastTry < 100, 'the try { should be the one immediately wrapping the dot-source, not an unrelated earlier one');
  const after = workerSource.slice(dotSourceIndex);
  const catchIndex = after.indexOf('catch {');
  assert.ok(catchIndex > 0 && catchIndex < 300, 'expected a catch block shortly after the dot-source');
});

test('the launcher wraps the failure-log dot-source + install in its own try/catch', () => {
  const dotSourceIndex = launcherSource.indexOf(". (Join-Path $PSScriptRoot 'openrouter-review-ctrl-signal-log.ps1')");
  assert.ok(dotSourceIndex > 0, 'expected to find the failure-log dot-source line');
  const before = launcherSource.slice(0, dotSourceIndex);
  const lastTry = before.lastIndexOf('try {');
  assert.ok(dotSourceIndex - lastTry < 100, 'the try { should be the one immediately wrapping the dot-source, not an unrelated earlier one');
  const after = launcherSource.slice(dotSourceIndex);
  const catchIndex = after.indexOf('catch {');
  assert.ok(catchIndex > 0 && catchIndex < 300, 'expected a catch block shortly after the dot-source');
});

test('dot-sourcing the worker for its own existing tests does not install a real console handler', () => {
  // Confirms the guard above actually holds at runtime, not just by source position: the
  // worker's own existing test file already dot-sources it this way for unrelated helper
  // functions (New-OpenRouterFailureLine etc.) -- if this error report broke that isolation,
  // it would be a real regression in an already-passing test file, not just a theoretical risk.
  const command = `& { . '${workerPath}' -RequestPath 'unused' -DeadlineUtc '2099-01-01T00:00:00.000Z' -ResponsePath 'unused'; Write-Output 'DOT_SOURCE_OK' }`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], { encoding: 'utf8' });
  assert.equal(result.status, 0, `powershell exited ${result.status}: ${result.stderr}`);
  assert.equal(result.stdout.trim(), 'DOT_SOURCE_OK');
});

const CTRL_TYPES = [
  { value: 0, name: 'CTRL_C' },
  { value: 1, name: 'CTRL_BREAK' },
  { value: 2, name: 'CTRL_CLOSE' },
  { value: 5, name: 'CTRL_LOGOFF' },
  { value: 6, name: 'CTRL_SHUTDOWN' },
  { value: 99, name: 'UNKNOWN_99' },
];

test('HandleCtrl classifies and logs all five real signal types plus an unknown value, via direct method call', () => {
  // Direct method call (not real OS signal delivery) so this exercises the logging and
  // classification logic for CTRL_CLOSE/LOGOFF/SHUTDOWN too -- those three cannot safely be
  // triggered for real inside a test process without actually terminating it.
  const dir = mkdtempSync(join(tmpdir(), 'openrouter-ctrl-diag-'));
  try {
    const logPath = join(dir, 'ctrl-signals.log');
    const calls = CTRL_TYPES.map((c) => `[OpenRouterReviewDispatch.ConsoleCtrlSignalLog]::HandleCtrl(${c.value}) | Out-Null`).join('; ');
    const command = `& { . '${signalLogPath}'; [OpenRouterReviewDispatch.ConsoleCtrlSignalLog]::Install('${logPath.replace(/\\/g, '\\\\')}', 'test') | Out-Null; ${calls} }`;
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], { encoding: 'utf8' });
    assert.equal(result.status, 0, `powershell exited ${result.status}: ${result.stderr}`);

    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, CTRL_TYPES.length);
    lines.forEach((line, index) => {
      assert.match(line, /^\S+\trole=test\tpid=\d+\tsignal=\S+$/, `line ${index} malformed: ${line}`);
      assert.match(line, new RegExp(`signal=${CTRL_TYPES[index].name}$`), `line ${index} expected ${CTRL_TYPES[index].name}: ${line}`);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('HandleCtrl returns true (suppress default termination) only for CTRL_C and CTRL_BREAK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'openrouter-ctrl-diag-'));
  try {
    const logPath = join(dir, 'ctrl-signals.log');
    const command = `& { . '${signalLogPath}'; [OpenRouterReviewDispatch.ConsoleCtrlSignalLog]::Install('${logPath.replace(/\\/g, '\\\\')}', 'test') | Out-Null; ` +
      CTRL_TYPES.map((c) => `Write-Output "${c.value}=$([OpenRouterReviewDispatch.ConsoleCtrlSignalLog]::HandleCtrl(${c.value}))"`).join('; ') + ' }';
    const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], { encoding: 'utf8' });
    assert.equal(result.status, 0, `powershell exited ${result.status}: ${result.stderr}`);
    const returned = Object.fromEntries(result.stdout.trim().split('\n').map((l) => l.replace(/\r$/, '').split('=')));
    assert.equal(returned['0'], 'True', 'CTRL_C must be suppressible');
    assert.equal(returned['1'], 'True', 'CTRL_BREAK must be suppressible');
    assert.equal(returned['2'], 'False', 'CTRL_CLOSE cannot actually be suppressed by Windows; must not claim otherwise');
    assert.equal(returned['5'], 'False', 'CTRL_LOGOFF cannot actually be suppressed by Windows; must not claim otherwise');
    assert.equal(returned['6'], 'False', 'CTRL_SHUTDOWN cannot actually be suppressed by Windows; must not claim otherwise');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The two tests above prove the classification/logging logic in isolation. This one proves
// the actual P/Invoke wiring (DllImport signature, delegate marshaling, SetConsoleCtrlHandler
// registration) works end-to-end against a REAL OS-delivered signal, which is exactly the
// part most likely to have a real bug (a wrong signature or an uncollected delegate would
// either silently no-op or crash) -- and is the part most important to have validated before
// relying on it during a real, paid dispatch.
//
// Spawn shape mirrors the REAL production launcher spawn exactly (tools/
// openrouter-review-mcp-server.mjs's createDispatchAdapter: execFile(powershellPath,
// ['-NoProfile', '-File', scriptPath, ...], { windowsHide: true, detached: true, ... })) --
// deliberately NOT an arbitrary "close enough" spawn. An earlier draft of this test used
// windowsHide:false plus a PowerShell-level `-WindowStyle Hidden` argument instead, on the
// theory that Node's windowsHide might prevent console allocation entirely; that combination
// reproducibly failed (empty log, no survival) while THIS exact shape, verified directly
// against the genuine production code path, reproducibly succeeds -- so the earlier failure
// was a property of that non-representative spawn shape, not of the failure-log module itself.
test('a real CTRL_BREAK delivered by the OS is caught, logged, and successfully suppressed end-to-end', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'openrouter-ctrl-diag-'));
  try {
    const logPath = join(dir, 'ctrl-signals.log');
    // Written to a real .ps1 file and invoked via -File (exactly how the production worker
    // and launcher are always actually invoked -- never -Command with an inline script) so
    // this test isn't also exercising Node's-argv-quoting-through-PowerShell's-own-command-
    // line-reparsing, a known-fragile combination unrelated to what this test is verifying.
    const scriptPath = join(dir, 'ctrl-break-probe.ps1');
    const logPathLiteral = logPath.replace(/'/g, "''");
    writeFileSync(scriptPath, [
      `. '${signalLogPath.replace(/'/g, "''")}'`,
      `[OpenRouterReviewDispatch.ConsoleCtrlSignalLog]::Install('${logPathLiteral}', 'test') | Out-Null`,
      "Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);' -Name Gen -Namespace OpenRouterCtrlTest",
      // CTRL_BREAK_EVENT = 1, group 0 = the caller's own console (this process, since it has
      // its own process group under detached:true) -- if suppression genuinely works, the
      // script keeps running past this line to the final Write-Output below.
      '[OpenRouterCtrlTest.Gen]::GenerateConsoleCtrlEvent(1, 0) | Out-Null',
      'Start-Sleep -Milliseconds 300',
      "Write-Output 'SURVIVED'",
    ].join("\n"), 'utf8');

    let stdout = '';
    let stderr = '';
    let failed = false;
    try {
      const result = await execFile('powershell.exe', ['-NoProfile', '-File', scriptPath], {
        windowsHide: true,
        detached: true,
        maxBuffer: 32 * 1024 * 1024,
      });
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (error) {
      failed = true;
      stdout = error.stdout ?? '';
      stderr = error.stderr ?? String(error);
    }

    assert.equal(failed, false, `powershell failed: ${stderr}`);
    assert.match(stdout, /SURVIVED/, 'the process must survive a suppressed CTRL_BREAK and reach its final output');

    const lines = readFileSync(logPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    assert.match(lines[0], /signal=CTRL_BREAK$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
