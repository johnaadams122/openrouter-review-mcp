import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const scriptPath = fileURLToPath(new URL('../tools/openrouter-review-dispatch.ps1', import.meta.url));

// A $remainingMs computed once, near the top of Invoke-OpenRouterReviewDispatch
// (right after parsing -DeadlineUtc), and reused for
// $webRequest.Timeout/.ReadWriteTimeout AFTER the request-file read and DPAPI
// credential decrypt -- both real I/O that can take real time -- would let a
// slow decrypt start the actual HTTP dispatch after the caller's deadline had
// passed, with nothing catching it. The same class of drift is guarded at this
// script's two JS-side callers (review-engine.mjs, the dispatch adapter in
// openrouter-review-mcp-server.mjs); this is the third and final layer,
// immediately before the real network call.
//
// This script has no dependency-injected clock (unlike the JS adapters'
// `clock` parameter), so the actual race this fix closes cannot be
// deterministically reproduced here without either refactoring the script to
// accept a mockable time source, or a flaky Start-Sleep-based test -- neither
// attempted. This is a disclosed structural regression guard instead: it
// proves the fix is textually in place (a second, later UtcNow read feeds
// the actual .Timeout/.ReadWriteTimeout assignment, not the earlier one used
// only for the fail-fast pre-I/O check), so a future edit that "simplifies"
// this back to one computation is caught, even though the test cannot
// exercise the timing itself.
test('the dispatch script re-derives its HTTP timeout from a fresh deadline check taken after request-file/credential I/O, not the earlier fail-fast check', () => {
  const source = readFileSync(scriptPath, 'utf8');
  const utcNowReads = source.match(/\[DateTimeOffset\]::UtcNow/g) ?? [];
  assert.equal(utcNowReads.length, 2, 'expected exactly two UtcNow reads: the early fail-fast gate, and the late re-derivation immediately before use');

  const decryptIndex = source.indexOf('[Security.Cryptography.ProtectedData]::Unprotect');
  const secondUtcNowIndex = source.indexOf('[DateTimeOffset]::UtcNow', source.indexOf('[DateTimeOffset]::UtcNow') + 1);
  const timeoutAssignIndex = source.indexOf('$webRequest.Timeout =');
  assert.ok(decryptIndex > 0 && secondUtcNowIndex > 0 && timeoutAssignIndex > 0, 'expected all three anchors to be present');
  assert.ok(decryptIndex < secondUtcNowIndex, 'the fresh deadline check must come AFTER the DPAPI decrypt, not before it');
  assert.ok(secondUtcNowIndex < timeoutAssignIndex, 'the fresh deadline check must come immediately before the .Timeout assignment');

  assert.match(source, /\$webRequest\.Timeout = \$effectiveRemainingMs/);
  assert.match(source, /\$webRequest\.ReadWriteTimeout = \$effectiveRemainingMs/);

  // The source ordering and the assignments' variable alone do not prove
  // the fail-closed guard itself exists -- so a future edit deleting
  // just the `-le 0` check (leaving the computation and assignments intact)
  // would pass every other assertion here while reintroducing the exact
  // failure mode the guard exists to prevent: a zero-or-negative value
  // reaching $webRequest.Timeout/.ReadWriteTimeout, which .NET rejects for
  // ReadWriteTimeout as an invalid argument rather than the clean
  // DEADLINE_EXCEEDED failure line every other terminal path in this script
  // returns.
  assert.match(source, /if \(\$effectiveRemainingMs -le 0\)/);
  assert.match(source, /DEADLINE_EXCEEDED.*deadline passed during request-file\/credential setup/);
});

// Dot-sourcing (InvocationName '.') defines the functions and runs the file's
// top-level preamble without invoking Invoke-OpenRouterReviewDispatch, so this
// never makes an HTTPS request and never touches the real DPAPI credential
// file -- it only proves the preamble makes
// [Security.Cryptography.ProtectedData] resolvable under -NoProfile, using a
// synthetic, non-secret blob protected by a separate setup call.
test('dispatch script preamble makes ProtectedData.Unprotect resolvable under -NoProfile', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'openrouter-review-dispatch-test-'));
  const credentialPath = join(tempDir, 'fixture-credential.dpapi');
  try {
    const setupCommand = `Add-Type -AssemblyName System.Security; $bytes = [Text.Encoding]::UTF8.GetBytes('fixture-not-a-real-key'); $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); [IO.File]::WriteAllBytes('${credentialPath}', $protected)`;
    const setup = spawnSync('powershell.exe', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', setupCommand,
    ], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(setup.status, 0, setup.stderr);

    const command = `& { . '${scriptPath}' -RequestPath 'unused' -DeadlineUtc 'unused' -ResponsePath 'unused'; $bytes = [IO.File]::ReadAllBytes('${credentialPath}'); $key = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); Write-Output ('UNPROTECT_OK=' + ([Text.Encoding]::UTF8.GetString($key) -eq 'fixture-not-a-real-key')) }`;
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command,
    ], { cwd: projectRoot, encoding: 'utf8', timeout: 30_000 });

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stderr, /Unable to find type/);
    assert.match(result.stdout, /UNPROTECT_OK=True/);
  }
  finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// The calling Node process can itself be replaced mid-dispatch, losing
// whatever this script printed to stdout even on a real, successful
// response. This script therefore ALSO durably writes its outcome to -ResponsePath
// before ever returning it on stdout, so a later process can recover it. This
// test exercises the real script end-to-end (no fake) via its fastest
// no-network, no-credential failure path (an already-past deadline) and
// proves the durable file and stdout carry the identical outcome -- a real
// behavioral proof, not just a source-text pattern match.
test('the dispatch script durably writes its outcome to -ResponsePath before returning it on stdout', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'openrouter-review-dispatch-outcome-test-'));
  try {
    const requestPath = join(tempDir, 'request.json');
    const responsePath = join(tempDir, 'outcomes', 'fake-job-id.json');
    writeFileSync(requestPath, JSON.stringify({ model: 'x', messages: [] }), 'utf8');

    const pastDeadline = new Date(Date.now() - 60_000).toISOString();
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, requestPath, pastDeadline, responsePath,
    ], { cwd: projectRoot, encoding: 'utf8', timeout: 30_000 });

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);

    const stdoutLine = result.stdout.trim().split(/\r?\n/).filter((line) => line.length > 0).pop();
    const parsedStdout = JSON.parse(stdoutLine);
    assert.equal(parsedStdout.kind, 'FAILURE');
    const stdoutEnvelope = JSON.parse(parsedStdout.envelopeJsonText);
    assert.equal(stdoutEnvelope.failureKind, 'DEADLINE_EXCEEDED');

    const responseText = readFileSync(responsePath, 'utf8').replace((new RegExp("\u005e\ufeff", "")), '');
    assert.deepEqual(JSON.parse(responseText), parsedStdout, 'the durable file must carry the exact same outcome as stdout');
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// The durable write must never crash the script or change its stdout
// contract if the response directory can't be created (e.g. a file, not a
// directory, sits where the parent directory needs to be) -- best-effort
// only, per Write-OpenRouterOutcomeAtomic's own doc comment.
test('an unwritable -ResponsePath does not change the stdout outcome or crash the script', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'openrouter-review-dispatch-outcome-fail-test-'));
  try {
    const requestPath = join(tempDir, 'request.json');
    writeFileSync(requestPath, JSON.stringify({ model: 'x', messages: [] }), 'utf8');
    // A file (not a directory) occupying the path a subdirectory needs.
    const blockerPath = join(tempDir, 'blocker-not-a-directory');
    writeFileSync(blockerPath, 'x', 'utf8');
    const responsePath = join(blockerPath, 'fake-job-id.json');

    const pastDeadline = new Date(Date.now() - 60_000).toISOString();
    const result = spawnSync('powershell.exe', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, requestPath, pastDeadline, responsePath,
    ], { cwd: projectRoot, encoding: 'utf8', timeout: 30_000 });

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    const stdoutLine = result.stdout.trim().split(/\r?\n/).filter((line) => line.length > 0).pop();
    const parsedStdout = JSON.parse(stdoutLine);
    assert.equal(parsedStdout.kind, 'FAILURE');
    assert.equal(JSON.parse(parsedStdout.envelopeJsonText).failureKind, 'DEADLINE_EXCEEDED');
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('Invoke-OpenRouterReviewDispatch is not run merely by dot-sourcing the script', () => {
  const command = `& { . '${scriptPath}' -RequestPath 'unused' -DeadlineUtc 'unused' -ResponsePath 'unused'; Write-Output 'DOT_SOURCE_OK' }`;
  const result = spawnSync('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command,
  ], { cwd: projectRoot, encoding: 'utf8', timeout: 30_000 });

  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /DOT_SOURCE_OK/);
});
