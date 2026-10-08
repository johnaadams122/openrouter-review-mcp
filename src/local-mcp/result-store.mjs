import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const JOB_ID = /^[a-f0-9]{64}$/;

function requireJobId(value) {
  if (typeof value !== 'string' || !JOB_ID.test(value)) {
    throw new TypeError('jobId must be a 64-character lowercase SHA-256 hex string');
  }
  return value;
}

function requireAdvisory(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('advisory must be an object');
  }
  return value;
}

/**
 * Durable, redacted per-job advisory store -- the { verdict, findings }
 * (wrapped in review-engine.mjs's own reviewer-entry shape) a successful
 * review() reconcile already computes, persisted to
 * <dataRoot>/dispatch-results/<jobId>.json the instant it exists, so it
 * survives the caller's connection dropping before the original response
 * arrives. Deliberately separate from lease-store.mjs's own ledger, which by
 * design never carries review content. Mirrors adapters.mjs's
 * approval-results/ safe-write convention: write to a `.tmp` sibling, then
 * atomically rename into place -- never a bare writeFile to the final path.
 * Unlike approval-results/ (deleted immediately after its one-shot window
 * closes), a dispatch result file is never deleted here: the whole point is
 * surviving a connection that is already gone, so the first successful
 * "read" is not guaranteed to be the original caller.
 */
export function createResultStore({ dataRoot }) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  const resultRoot = join(dataRoot, 'dispatch-results');

  return Object.freeze({
    async record({ jobId, advisory } = {}) {
      requireJobId(jobId);
      requireAdvisory(advisory);
      await mkdir(resultRoot, { recursive: true });
      const finalPath = join(resultRoot, `${jobId}.json`);
      const temporaryPath = `${finalPath}.${randomUUID()}.tmp`;
      await writeFile(temporaryPath, `${JSON.stringify(advisory)}\n`, { encoding: 'utf8', flag: 'wx' });
      await rename(temporaryPath, finalPath);
    },

    async recall({ jobId } = {}) {
      requireJobId(jobId);
      const finalPath = join(resultRoot, `${jobId}.json`);
      try {
        const text = (await readFile(finalPath, 'utf8')).replace(/^\uFEFF/, '');
        return JSON.parse(text);
      } catch {
        return null;
      }
    },
  });
}
