import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(new URL('../tools/openrouter-review-dispatch-launcher.ps1', import.meta.url));
const source = readFileSync(scriptPath, 'utf8');
// core.autocrlf converts this file's LF-stored blob to CRLF on a fresh checkout (git worktree,
// clone, CI) -- normalized once here so the bare-\n literal searches below match either way.
const normalizedSource = source.replace(/\r\n/g, '\n');

// A direct execFile child -- even with detached:true -- and a WMI-created
// grandchild with no process-tree relationship to the Node parent both die
// within about a second of that Node parent being force-killed. A Windows
// Scheduled Task (LogonType Interactive) survives an identical kill. This
// launcher's whole job is getting openrouter-review-dispatch.ps1 running under
// such a task and relaying its outcome back -- these tests pin those
// properties, plus the pure-logic helper functions that don't require touching
// Task Scheduler/DPAPI/network to exercise offline.

test('the launcher registers the scheduled task with LogonType Interactive, never S4U or an unattended logon type', () => {
  // An S4U or ServiceAccount logon cannot unlock CurrentUser-scoped DPAPI, and
  // the worker script this launcher runs decrypts the OpenRouter credential via
  // CurrentUser-scoped DPAPI. The launcher's header comment deliberately
  // DISCUSSES S4U (to document why it is not used), so this asserts on the
  // actual -LogonType usage, not a blanket ban on the word.
  assert.match(source, /-LogonType Interactive/);
  assert.doesNotMatch(source, /-LogonType\s+(S4U|ServiceAccount|Password|Group)\b/);
});

test('the launcher resolves the worker script via $PSScriptRoot rather than a hardcoded or duplicated path', () => {
  assert.match(source, /\$PSScriptRoot/);
  assert.match(source, /Join-Path \$PSScriptRoot 'openrouter-review-dispatch\.ps1'/);
});

test('the launcher derives a per-job task name so concurrent dispatches (e.g. Grok + Gemini) cannot collide', () => {
  assert.match(source, /\$jobId = \[System\.IO\.Path\]::GetFileNameWithoutExtension\(\$ResponsePath\)/);
  assert.match(source, /\$taskName = "OpenRouterReviewDispatch-\$jobId"/);
});

// The unanchored version of this test (`/catch \{[\s\S]*?TASK_SCHEDULE_FAILED/`) matched
// from the FIRST `catch {` in the file -- the empty `catch { }` inside
// Write-LauncherOutcomeAtomic -- and would pass even if TASK_SCHEDULE_FAILED lived
// anywhere later in the file, proving nothing about which catch block actually writes it.
// This anchors specifically to the try/catch wrapping Register-ScheduledTask/
// Start-ScheduledTask, and bounds the gap so a catch block far away can't satisfy it.
test('the launcher writes a durable, specific FAILURE outcome when task registration/start itself throws', () => {
  const startIndex = source.indexOf('Start-ScheduledTask -TaskName $taskName');
  assert.ok(startIndex > 0, 'expected to find the Start-ScheduledTask call');
  const catchIndex = source.indexOf('catch {', startIndex);
  assert.ok(catchIndex > startIndex, 'expected a catch block immediately after the registration try block');
  const failureIndex = source.indexOf('TASK_SCHEDULE_FAILED', catchIndex);
  assert.ok(failureIndex > catchIndex && failureIndex - catchIndex < 800, 'expected TASK_SCHEDULE_FAILED inside THIS catch block, not a later, unrelated one');
  const catchBlock = source.slice(catchIndex, failureIndex + 400);
  assert.match(catchBlock, /Write-LauncherOutcomeAtomic -Path \$ResponsePath -Line \$line/);
});

test('the launcher writes a durable, specific FAILURE outcome when the task finishes but the worker never wrote a terminal outcome', () => {
  assert.match(source, /'DONE_NO_OUTCOME'\)\s*\{[\s\S]*?WORKER_PRODUCED_NO_OUTCOME/);
});

// Without an exit code, this failure kind carries no troubleshooting signal beyond "never wrote a
// terminal outcome". The worker's
// own top-level try/catch (openrouter-review-dispatch.ps1's bottom guard) catches every
// exception INSIDE Invoke-OpenRouterReviewDispatch and always durably writes an outcome --
// so the ONLY way this failure kind can happen at all is something failing OUTSIDE that
// catch (module load time, e.g. Add-Type -AssemblyName System.Security; or parameter
// binding before the worker's own code ever runs). Task Scheduler still records a real
// LastTaskResult exit code for that case even though the worker wrote nothing itself --
// surfacing it turns a future occurrence into an actual explainable signal instead of a
// dead end.
test('the WORKER_PRODUCED_NO_OUTCOME failure message includes the task\'s LastTaskResult exit code for troubleshooting', () => {
  // Anchored to the actual if-branch (`'DONE_NO_OUTCOME') {`), not a bare substring match --
  // 'DONE_NO_OUTCOME' also appears earlier in this file inside Get-DispatchPollAction's own
  // doc comment, which a plain indexOf would find first and anchor to instead (the sibling
  // test two above this one anchors the same way).
  const branchMatch = source.match(/'DONE_NO_OUTCOME'\)\s*\{/);
  assert.ok(branchMatch, 'expected to find the DONE_NO_OUTCOME branch');
  const branchIndex = branchMatch.index;
  const failureIndex = source.indexOf('WORKER_PRODUCED_NO_OUTCOME', branchIndex);
  assert.ok(failureIndex > branchIndex, 'expected WORKER_PRODUCED_NO_OUTCOME after the DONE_NO_OUTCOME branch');
  const messageStart = source.indexOf('-Message', failureIndex);
  const messageEnd = source.indexOf('\n', messageStart);
  const messageArg = source.slice(messageStart, messageEnd);
  assert.match(messageArg, /\$taskInfo\.LastTaskResult/, 'expected the failure message to interpolate the task\'s actual LastTaskResult exit code');
});

// This is the single most important safety property in this file: if the launcher's own
// patience runs out (the while loop exits without ever hitting a `DONE_*` action's `exit
// 0`), it must NOT touch -ResponsePath or unregister the task -- either action could race
// a still-in-flight worker and corrupt or lose a real outcome. Anchored to the code AFTER
// the while loop's own closing brace, not just a nearby comment string, so an
// Unregister-ScheduledTask/Write-LauncherOutcomeAtomic call added anywhere inside the loop
// body (which this slice does not cover) would not accidentally satisfy this test.
test('the give-up-waiting path (patience exhausted) does not write ResponsePath or unregister the task', () => {
  const loopStart = normalizedSource.indexOf('while ([DateTimeOffset]::UtcNow -lt $waitUntilUtc)');
  assert.ok(loopStart > 0, 'expected to find the poll while-loop');
  const loopEnd = normalizedSource.indexOf('\n    }\n\n    # This launcher', loopStart);
  assert.ok(loopEnd > loopStart, 'expected to find the while-loop\'s closing brace immediately before the give-up comment');
  const tail = normalizedSource.slice(loopEnd);
  assert.doesNotMatch(tail, /Write-LauncherOutcomeAtomic/);
  assert.doesNotMatch(tail, /Unregister-ScheduledTask/);
  assert.match(tail, /^\s*exit 0\s*$/m);
});

test('the scheduled task is registered with battery power restrictions explicitly disabled and an explicit ExecutionTimeLimit', () => {
  // Task Scheduler's DEFAULT settings (DisallowStartIfOnBatteries, StopIfGoingOnBatteries,
  // a 72-hour ExecutionTimeLimit) would silently block every on-battery dispatch and kill an
  // in-flight worker the instant the machine goes on battery -- the same symptom this whole
  // mechanism exists to eliminate. New-ScheduledTaskSettingsSet with these flags produces
  // DisallowStartIfOnBatteries=False / StopIfGoingOnBatteries=False.
  assert.match(source, /-AllowStartIfOnBatteries/);
  assert.match(source, /-DontStopIfGoingOnBatteries/);
  assert.match(source, /-ExecutionTimeLimit \$executionTimeLimit/);
  assert.match(source, /Register-ScheduledTask -TaskName \$taskName -Action \$action -Principal \$principal -Settings \$settings -Force/);
});

test('the launcher gives up BEFORE Node\'s own execute() timeout would kill it, not after', () => {
  // If the launcher's own wait window is longer than Node's execute() timeout
  // (effectiveTimeoutMs + 30_000 from spawn -- see createDispatchAdapter in
  // tools/openrouter-review-mcp-server.mjs), Node always kills the launcher first and the
  // give-up path below can never actually run in production. 15s of headroom past the
  // deadline is comfortably under Node's 30s margin.
  assert.match(source, /\$waitUntilUtc = \$deadline\.AddSeconds\((\d+)\)/);
  const [, headroomSeconds] = source.match(/\$waitUntilUtc = \$deadline\.AddSeconds\((\d+)\)/);
  assert.ok(Number(headroomSeconds) < 30, `expected launcher headroom (${headroomSeconds}s) to stay under Node's 30s post-deadline kill margin`);
});

// Defense in depth: the launcher checks for an already-terminal outcome before registering a new
// task. In normal operation that path is not reachable (dispatch-outcome-store.mjs's
// markDispatching() exclusive claim, checked upstream before execute() is ever invoked, already
// makes a second launcher invocation for the same jobId impossible), but the check is cheap.
test('the launcher checks for an existing terminal outcome BEFORE ever touching Task Scheduler', () => {
  const preflightIndex = source.indexOf('$preExistingOutcome = Read-TerminalOutcomeLine -Path $ResponsePath');
  assert.ok(preflightIndex > 0, 'expected the pre-existing-outcome check to exist');
  const registerIndex = source.indexOf('Register-ScheduledTask -TaskName $taskName');
  assert.ok(registerIndex > preflightIndex, 'expected the outcome check to run BEFORE Register-ScheduledTask, not after');
});

// STATUS_CONTROL_C_EXIT (0xC000013A) is the NT status a console process gets from the DEFAULT
// Ctrl+C handler when it receives CTRL_C_EVENT/CTRL_BREAK_EVENT and does not intercept it -- it is
// not a generic crash or timeout code. With LogonType Interactive and no window-hiding flag, the
// worker's powershell.exe would run as a real, focusable console window on the interactive desktop
// for its whole run (which can last minutes), producing almost no console output -- visually
// indistinguishable from "hung", and exposed to an accidental Ctrl+C. Other background PowerShell
// spawns in this codebase hide their window too (the approval flow's own outer cmd.exe wrapper is
// hidden, per openrouter-review-approval.test.mjs). Hiding the window doesn't touch LogonType
// (still Interactive, so DPAPI decrypt is unaffected -- window visibility and logon type are
// orthogonal) and doesn't change how this launcher detects completion (it polls
// Get-ScheduledTaskInfo/-ResponsePath, never the window itself).
test('the worker runs with a hidden window, matching every other background PowerShell spawn in this project', () => {
  // Anchored to the real $argumentLine assignment, not a bare source-wide regex -- the literal
  // "-WindowStyle Hidden" also appears in the launcher's own comment above the assignment
  // (documenting why the flag exists), so an unanchored match would keep passing even if a
  // future edit reverted the real argument line while leaving the comment in place. Same
  // collision class the WORKER_PRODUCED_NO_OUTCOME test above guards against.
  const assignIndex = source.indexOf('$argumentLine =');
  assert.ok(assignIndex > 0, 'expected to find the $argumentLine assignment');
  const lineEnd = source.indexOf('\n', assignIndex);
  const assignLine = source.slice(assignIndex, lineEnd);
  assert.match(assignLine, /-WindowStyle Hidden/);
  assert.ok(
    assignLine.indexOf('-WindowStyle Hidden') < assignLine.indexOf('-File'),
    'expected -WindowStyle Hidden before -File -- powershell.exe treats everything after -File as the script path/its own args'
  );
});

test('the launcher durably writes INVALID_DEADLINE to ResponsePath, matching every other failure path', () => {
  // Like TASK_SCHEDULE_FAILED, this must be written durably, not only printed to stdout. An
  // unparseable deadline (in practice, only reachable if Node itself ever produced a malformed
  // ISO8601 string, which it does not) would otherwise leave -ResponsePath stuck at DISPATCHING
  // forever instead of a specific, durable failure.
  const catchIndex = normalizedSource.indexOf("catch {\n        $line = New-LauncherFailureLine -FailureKind 'INVALID_DEADLINE'");
  assert.ok(catchIndex > 0, 'expected the INVALID_DEADLINE catch block');
  const tail = normalizedSource.slice(catchIndex, catchIndex + 300);
  assert.match(tail, /Write-LauncherOutcomeAtomic -Path \$ResponsePath -Line \$line/);
});

test('a real end-to-end launcher invocation with a pre-existing outcome relays it immediately and registers no task', () => {
  const base = tmpdir();
  const dir = mkdtempSync(join(base, 'openrouter-launcher-preexisting-'));
  try {
    const jobId = '9'.repeat(64);
    const responsePath = join(dir, `${jobId}.json`);
    const line = JSON.stringify({ kind: 'RESPONSE', envelopeJsonText: '{"httpStatus":200,"bodyBase64":"eA=="}' });
    writeFileSync(responsePath, line, 'utf8');
    const taskName = `OpenRouterReviewDispatch-${jobId}`;

    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-File', scriptPath,
      join(dir, 'unused-request.json'),
      new Date(Date.now() + 120_000).toISOString(),
      responsePath,
    ], { encoding: 'utf8' });

    assert.equal(result.status, 0, `launcher exited ${result.status}: ${result.stderr}`);
    assert.deepEqual(JSON.parse(result.stdout.trim()), JSON.parse(line));

    const taskCheck = spawnSync('powershell.exe', ['-NoProfile', '-Command', `(Get-ScheduledTask -TaskName '${taskName}' -ErrorAction SilentlyContinue) -ne $null`], { encoding: 'utf8' });
    assert.equal(taskCheck.stdout.trim(), 'False', 'expected no scheduled task to have been registered when an outcome already existed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the launcher never shells out to any script other than openrouter-review-dispatch.ps1 itself', () => {
  // Guards against this launcher growing its own second worker implementation
  // or delegating to something else entirely -- the worker script's own
  // header documents "never shells out to any other OpenRouter-dispatching
  // script in this repository", and this launcher is meant to be its only
  // caller-side counterpart, not a second dispatch path.
  const psInvocations = source.match(/-Execute\s+'([^']+)'/g) ?? [];
  assert.deepEqual(psInvocations, ["-Execute 'powershell.exe'"]);
  assert.match(source, /openrouter-review-dispatch\.ps1/);
});

function runLauncherFunction(functionCall) {
  const command = `& { . '${scriptPath}' -RequestPath 'unused' -DeadlineUtc '2099-01-01T00:00:00.000Z' -ResponsePath 'unused'; ${functionCall} }`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], { encoding: 'utf8' });
  assert.equal(result.status, 0, `powershell exited ${result.status}: ${result.stderr}`);
  return result.stdout.trim();
}

test('dot-sourcing the launcher does not itself start dispatching (no side effects at parse time)', () => {
  const output = runLauncherFunction("Write-Output 'DOT_SOURCE_OK'");
  assert.equal(output, 'DOT_SOURCE_OK');
});

test('New-LauncherFailureLine produces the same {kind,envelopeJsonText} shape dispatch-outcome-store.mjs validates', () => {
  const output = runLauncherFunction("New-LauncherFailureLine -FailureKind 'TASK_SCHEDULE_FAILED' -Message 'boom'");
  const parsed = JSON.parse(output);
  assert.equal(parsed.kind, 'FAILURE');
  const envelope = JSON.parse(parsed.envelopeJsonText);
  assert.equal(envelope.failureKind, 'TASK_SCHEDULE_FAILED');
  assert.equal(envelope.message, 'boom');
});

test('Read-TerminalOutcomeLine returns null for a missing file', () => {
  const missingPath = join(tmpdir(), `openrouter-launcher-test-missing-${Date.now()}.json`);
  const output = runLauncherFunction(`$r = Read-TerminalOutcomeLine -Path '${missingPath}'; Write-Output "RESULT=[$r]"`);
  assert.equal(output, 'RESULT=[]');
});

test('Read-TerminalOutcomeLine returns null for a DISPATCHING-only marker (not yet terminal)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'openrouter-launcher-test-'));
  try {
    const markerPath = join(dir, 'marker.json');
    writeFileSync(markerPath, JSON.stringify({ kind: 'DISPATCHING' }), 'utf8');
    const output = runLauncherFunction(`$r = Read-TerminalOutcomeLine -Path '${markerPath}'; Write-Output "RESULT=[$r]"`);
    assert.equal(output, 'RESULT=[]');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Read-TerminalOutcomeLine returns the trimmed content for a real RESPONSE outcome', () => {
  const dir = mkdtempSync(join(tmpdir(), 'openrouter-launcher-test-'));
  try {
    const responsePath = join(dir, 'response.json');
    const line = JSON.stringify({ kind: 'RESPONSE', envelopeJsonText: '{"httpStatus":200,"bodyBase64":"eA=="}' });
    writeFileSync(responsePath, line, 'utf8');
    const output = runLauncherFunction(`$r = Read-TerminalOutcomeLine -Path '${responsePath}'; Write-Output $r`);
    assert.deepEqual(JSON.parse(output), JSON.parse(line));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Get-DispatchPollAction: Start-ScheduledTask is asynchronous, so a task can legitimately still
// read `Ready`/`Queued` moments after being started -- indistinguishable, by state alone, from a
// task that ran to completion. A sampling-based gate (only trusting a non-running reading once
// this launcher had directly OBSERVED the task Running at least once) would miss a task that
// starts and finishes faster than the poll interval. HasRunEvidence/IsRunningNow (backed by
// Get-ScheduledTaskInfo's LastRunTime/LastTaskResult in the real loop, see below) avoid that --
// LastRunTime is a fact Task Scheduler records the instant the task launches, independent of
// this launcher's own polling cadence.
const pollActionCases = [
  { name: 'no run evidence yet, no outcome -> keep polling (covers both "not started yet" and a battery-blocked task that never starts)', hasRunEvidence: false, isRunningNow: false, outcomeLine: null, expected: 'KEEP_POLLING' },
  { name: 'currently running (has run evidence too, as it always would while running), no outcome -> keep polling', hasRunEvidence: true, isRunningNow: true, outcomeLine: null, expected: 'KEEP_POLLING' },
  { name: 'run evidence present, not running now, still no outcome -> genuinely done, no outcome', hasRunEvidence: true, isRunningNow: false, outcomeLine: null, expected: 'DONE_NO_OUTCOME' },
  { name: 'a real outcome appears while still running -> done with outcome, relay it immediately (proves DONE_WITH_OUTCOME is checked first, not gated on IsRunningNow)', hasRunEvidence: true, isRunningNow: true, outcomeLine: '{"kind":"RESPONSE","envelopeJsonText":"{}"}', expected: 'DONE_WITH_OUTCOME' },
  { name: 'a real outcome is present even with no run evidence at all -> done with outcome takes priority (the fast-completion case: LastRunTime evidence lags a real outcome file write by nothing, but if it somehow did, the outcome file still wins)', hasRunEvidence: false, isRunningNow: false, outcomeLine: '{"kind":"FAILURE","envelopeJsonText":"{}"}', expected: 'DONE_WITH_OUTCOME' },
];

for (const testCase of pollActionCases) {
  test(`Get-DispatchPollAction: ${testCase.name}`, () => {
    const outcomeArg = testCase.outcomeLine === null ? '$null' : `'${testCase.outcomeLine.replace(/'/g, "''")}'`;
    const call = `Get-DispatchPollAction -HasRunEvidence $${testCase.hasRunEvidence} -IsRunningNow $${testCase.isRunningNow} -OutcomeLine ${outcomeArg}`;
    const output = runLauncherFunction(call);
    assert.equal(output, testCase.expected);
  });
}

test('the real poll loop derives IsRunningNow/HasRunEvidence from Get-ScheduledTaskInfo, not from Get-ScheduledTask state sampling', () => {
  // Get-DispatchPollAction is covered as a pure function above; this proves the loop actually
  // WIRES it up, querying LastTaskResult/LastRunTime (the facts the design relies on) rather
  // than sampled task State.
  const loopStart = normalizedSource.indexOf('while ([DateTimeOffset]::UtcNow -lt $waitUntilUtc)');
  assert.ok(loopStart > 0, 'expected to find the poll while-loop');
  const loopEnd = normalizedSource.indexOf('\n    }\n\n    # This launcher', loopStart);
  const loopBody = normalizedSource.slice(loopStart, loopEnd);
  assert.match(loopBody, /Get-ScheduledTaskInfo -TaskName \$taskName/);
  assert.match(loopBody, /\$taskInfo\.LastTaskResult -eq \$script:SCHED_S_TASK_RUNNING/);
  assert.match(loopBody, /\[DateTimeOffset\]\$taskInfo\.LastRunTime\) -ge \$runEvidenceFloorUtc/);
  assert.doesNotMatch(loopBody, /Get-ScheduledTask -TaskName \$taskName/, 'the loop should no longer poll task State directly -- LastTaskResult/LastRunTime replaced it');
});

test('the run-evidence floor is buffered below $startedAtUtc, not compared to it directly', () => {
  // Get-ScheduledTaskInfo's LastRunTime resolution is whole seconds, so an unbuffered
  // same-second comparison against $startedAtUtc can read "not yet run" even though the task
  // already ran.
  assert.match(source, /\$runEvidenceFloorUtc = \$startedAtUtc\.AddSeconds\(-\d+\)/);
});

test('Read-TerminalOutcomeLine returns the trimmed content for a real FAILURE outcome', () => {
  const dir = mkdtempSync(join(tmpdir(), 'openrouter-launcher-test-'));
  try {
    const responsePath = join(dir, 'failure.json');
    const line = JSON.stringify({ kind: 'FAILURE', envelopeJsonText: '{"failureKind":"NETWORK_ERROR","message":"x"}' });
    writeFileSync(responsePath, line, 'utf8');
    const output = runLauncherFunction(`$r = Read-TerminalOutcomeLine -Path '${responsePath}'; Write-Output $r`);
    assert.deepEqual(JSON.parse(output), JSON.parse(line));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
