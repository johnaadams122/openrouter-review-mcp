import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const FORBIDDEN_FIELD = /^(?:source_?text|request_?body|response_?body|api_?key)$/i;
const HASH = /^[a-f0-9]{64}$/;
const DEFAULT_SCRIPT_PATH = fileURLToPath(new URL('../../tools/openrouter-review-authorize.ps1', import.meta.url));

function requireObject(value, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  return value;
}

function requireUsd(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new TypeError(`${name} must be a finite non-negative USD amount`);
  return value;
}

function requirePositiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`);
  return value;
}

function assertNoForbiddenFields(value) {
  if (Array.isArray(value)) return value.forEach(assertNoForbiddenFields);
  if (value !== null && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      if (FORBIDDEN_FIELD.test(key)) throw new TypeError(`forbidden field: ${key}`);
      assertNoForbiddenFields(nested);
    }
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function requestHash(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

function normalizeRequest(input, nonce) {
  assertNoForbiddenFields(input);
  requireObject(input, 'approval request');
  if (!Array.isArray(input.preflightHashes) || input.preflightHashes.length === 0 || input.preflightHashes.some((value) => typeof value !== 'string' || !HASH.test(value))) {
    throw new TypeError('preflightHashes must be a non-empty array of SHA-256 digests');
  }
  if (!Array.isArray(input.profiles) || input.profiles.length === 0 || input.profiles.some((value) => typeof value !== 'string' || value.length === 0)) {
    throw new TypeError('profiles must be a non-empty array');
  }
  if (!Array.isArray(input.itemMaxima) || input.itemMaxima.length === 0) throw new TypeError('itemMaxima must be a non-empty array');
  const itemMaxima = input.itemMaxima.map((item, index) => {
    requireObject(item, `itemMaxima[${index}]`);
    if (typeof item.itemId !== 'string' || item.itemId.length === 0) throw new TypeError(`itemMaxima[${index}].itemId must be an opaque ID`);
    return { itemId: item.itemId, maxUsd: requireUsd(item.maxUsd, `itemMaxima[${index}].maxUsd`) };
  });
  const requestedUsd = requireUsd(input.requestedUsd, 'requestedUsd');
  if (requestedUsd > itemMaxima.reduce((total, item) => total + item.maxUsd, 0)) throw new RangeError('requestedUsd exceeds per-item maxima');
  if (typeof input.expiresAt !== 'string' || !Number.isFinite(Date.parse(input.expiresAt))) throw new TypeError('expiresAt must be an ISO timestamp');
  const unsigned = {
    authorizationSchema: 'openrouter_review_authorization_v1',
    nonce,
    approvalPhrase: `APPROVE ${nonce}`,
    preflightHashes: [...input.preflightHashes],
    profiles: [...input.profiles],
    itemMaxima,
    requestedUsd,
    maxJobs: requirePositiveInteger(input.maxJobs, 'maxJobs'),
    expiresAt: input.expiresAt,
  };
  return Object.freeze({ ...unsigned, requestSha256: requestHash(unsigned) });
}

function verifySealedRequest(value, expectedNonce, expectedHash) {
  requireObject(value, 'authorization request');
  if (value.nonce !== expectedNonce) throw new Error('approval request nonce does not match');
  if (value.requestSha256 !== expectedHash) throw new Error('approval request integrity hash does not match');
  const { requestSha256: actualHash, ...unsigned } = value;
  if (requestHash(unsigned) !== actualHash) throw new Error('approval request integrity hash is invalid');
  return value;
}

function parseOutcome(value, expectedNonce) {
  let outcome;
  let nonce;
  if (typeof value === 'string') {
    const match = /^(APPROVED|DENIED|TIMED_OUT) (\S+)\s*$/.exec(value);
    if (!match) throw new Error('approval worker returned an invalid result');
    [, outcome, nonce] = match;
  } else {
    requireObject(value, 'approval worker result');
    ({ outcome, nonce } = value);
    if (!['APPROVED', 'DENIED', 'TIMED_OUT'].includes(outcome) || typeof nonce !== 'string') throw new Error('approval worker returned an invalid result');
  }
  if (nonce !== expectedNonce) throw new Error('approval worker nonce does not match the request');
  return Object.freeze({ outcome, nonce });
}

/**
 * Runs the real authorization script in a genuinely visible, independent
 * console window and resolves once it exits.
 *
 * Two more direct approaches do not work: (1) piping the child's stdio to capture its result -- fully
 * redirected stdio suppresses Windows' console allocation for a
 * console-subsystem process regardless of `windowsHide`, so `Read-Host`
 * blocks forever on a pipe no human could type into; (2) spawning directly
 * with `detached: true, stdio: 'ignore'` -- this DOES get a console window,
 * but Windows' `'ignore'` redirects the child's own standard handles to the
 * NUL device rather than to that new console's input/output buffers, so
 * `Read-Host` returns instantly on empty input instead of ever waiting.
 * `cmd.exe /c start "title" /wait <program> <args>` is the mechanism
 * that works: `start` gives the target program its own
 * independent console wired to real, working stdin/stdout, and `/wait` makes
 * the cmd.exe wrapper block until that program exits, so awaiting the
 * wrapper's own `'exit'` event is sufficient -- no `detached` needed. The
 * wrapper's own window is hidden (`windowsHide: true`); only the
 * `start`-launched target window is ever shown to the user. Because the
 * target's stdio still isn't captured, the script writes its result to
 * `resultPath`, read only after the wrapper process exits.
 */
function runApprovalWindow({ spawnProcess, commandProcessorPath, powershellPath, scriptPath, requestPath, resultPath }) {
  return new Promise((resolveRun, reject) => {
    const child = spawnProcess(commandProcessorPath, [
      '/c', 'start', 'OpenRouter Review Authorization', '/wait',
      powershellPath, '-NoProfile', '-File', scriptPath, requestPath, resultPath,
    ], {
      stdio: 'ignore',
      windowsHide: true,
    });
    child.once('error', reject);
    child.once('exit', () => resolveRun());
  });
}

/**
 * Creates the human-approval boundary.  The only production child-process
 * payload is an on-disk redacted request path; this adapter never accepts or
 * reads an API key.
 */
export function createApprovalAdapter({
  dataRoot,
  clock = () => Date.now(),
  worker,
  scriptPath = DEFAULT_SCRIPT_PATH,
  powershellPath = 'powershell.exe',
  commandProcessorPath = 'cmd.exe',
  spawnProcess = spawn,
  afterPublish,
} = {}) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  if (worker !== undefined && typeof worker !== 'function') throw new TypeError('worker must be a function');
  if (typeof spawnProcess !== 'function') throw new TypeError('spawnProcess must be a function');
  if (afterPublish !== undefined && typeof afterPublish !== 'function') throw new TypeError('afterPublish must be a function');
  const requestRoot = join(dataRoot, 'approval-requests');
  const resultRoot = join(dataRoot, 'approval-results');

  return Object.freeze({
    async authorize(input, { leaseExpiresAt } = {}) {
      const nonce = randomUUID();
      const request = normalizeRequest(input, nonce);
      if (leaseExpiresAt !== undefined) {
        if (typeof leaseExpiresAt !== 'string' || !Number.isFinite(Date.parse(leaseExpiresAt))) throw new TypeError('leaseExpiresAt must be an ISO timestamp');
        if (Date.parse(request.expiresAt) > Date.parse(leaseExpiresAt)) throw new RangeError('approval request expiry exceeds the bound lease/preflight expiry');
      }
      if (Date.parse(request.expiresAt) <= Number(clock())) throw new Error('approval request is expired');
      await mkdir(requestRoot, { recursive: true });
      const requestPath = join(requestRoot, `${nonce}.json`);
      const temporaryPath = `${requestPath}.${randomUUID()}.tmp`;
      await writeFile(temporaryPath, `${JSON.stringify(request)}\n`, { encoding: 'utf8', flag: 'wx' });
      await rename(temporaryPath, requestPath);
      // Test seam only: lets a test tamper the on-disk file in the window
      // after publish but before this pre-worker check runs, proving the
      // check actually catches tampering rather than merely asserting it.
      if (afterPublish) await afterPublish(requestPath);
      await verifySealedRequest(JSON.parse(await readFile(requestPath, 'utf8')), nonce, request.requestSha256);

      let workerResult;
      if (worker) {
        workerResult = await worker(request, requestPath);
      } else {
        await mkdir(resultRoot, { recursive: true });
        const resultPath = join(resultRoot, `${nonce}.json`);
        try {
          await runApprovalWindow({ spawnProcess, commandProcessorPath, powershellPath, scriptPath, requestPath, resultPath });
          try {
            // Strip a possible leading UTF-8 BOM defensively: PowerShell's
            // Set-Content -Encoding utf8 writes one (fixed at the source in
            // openrouter-review-authorize.ps1, but this guards against the
            // same class of bug recurring here again).
            const resultText = (await readFile(resultPath, 'utf8')).replace((new RegExp("\u005e\ufeff", "")), '');
            workerResult = JSON.parse(resultText);
          } catch {
            throw new Error('the approval window closed without recording an outcome');
          }
        } finally {
          await rm(resultPath, { force: true }).catch(() => {});
        }
      }
      await verifySealedRequest(JSON.parse(await readFile(requestPath, 'utf8')), nonce, request.requestSha256);
      const outcome = parseOutcome(workerResult, nonce);
      // The late-approval-expiry guard is bound to the tighter of the
      // request's own expiry and the real lease/preflight expiry it was
      // authorized against (when supplied), so a request whose expiry was
      // mis-set relative to its lease cannot smuggle a late approval through.
      const boundExpiresAtMs = leaseExpiresAt !== undefined
        ? Math.min(Date.parse(request.expiresAt), Date.parse(leaseExpiresAt))
        : Date.parse(request.expiresAt);
      if (boundExpiresAtMs <= Number(clock())) return Object.freeze({ outcome: 'TIMED_OUT', nonce });
      return outcome;
    },
  });
}
