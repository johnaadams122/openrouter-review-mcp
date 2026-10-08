import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

function requirePreflightId(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    throw new TypeError('preflightId must be a non-empty opaque ID');
  }
  return value;
}

function requireReviewContext(value) {
  if (typeof value !== 'string') throw new TypeError('reviewContext must be a string');
  return value;
}

/**
 * Durable, per-preflight store for the one piece of `preflight()` input that
 * lease-store.mjs's own redacted ledger deliberately never carries:
 * `reviewContext` (free-form operator-supplied text, not a hash). Everything
 * else `review-engine.mjs`'s in-process `preflightCache` needs to survive a
 * lost connection or process restart -- reviewContractSha256, sourceSha256,
 * profile, profileVersion, itemMaxima, requestedUsd, expiresAt -- is already
 * durable via `leaseStore.getPreflight()`; `review()`'s own `reviewer` list
 * is separately reconstructable from `itemMaxima` via the fixed reviewer
 * registry. This store closes the one remaining gap.
 *
 * Why this exists: `authorizeWorkflow()`'s human-approval step is
 * unavoidably slow (a person has to read and type an exact phrase), and the
 * MCP host can restart the stdio server process during exactly that wait.
 * An in-process-only preflight-identity check (`getCachedPreflight`, a Map)
 * always misses after that kind of restart even though the lease itself
 * (already durable) was created just fine, so a caller holding nothing but
 * the original `leaseId`/`preflightId` pair -- the only thing an MCP caller
 * across a tool-call boundary ever has -- could never complete `document()`.
 * Persisting `reviewContext` per preflight lets that check survive a restart.
 *
 * Mirrors `result-store.mjs`'s established convention exactly: atomic
 * temp-file + rename write to `<dataRoot>/preflight-contexts/<preflightId>.json`,
 * a defensive UTF-8 BOM strip on read (Windows PowerShell 5.1's
 * `Set-Content -Encoding utf8` writes one; nothing here writes through
 * PowerShell, but stripping defensively costs nothing and matches the
 * sibling store), and a corrupt/missing file recalls as `null` rather than
 * throwing. Unlike `approval-results/` (deleted after its one-shot window),
 * and exactly like `result-store.mjs`, a context file is never deleted here:
 * the whole point is surviving a connection that is already gone, so the
 * first successful read is not guaranteed to be the original caller.
 */
export function createPreflightContextStore({ dataRoot }) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  const contextRoot = join(dataRoot, 'preflight-contexts');

  return Object.freeze({
    async record({ preflightId, reviewContext } = {}) {
      requirePreflightId(preflightId);
      requireReviewContext(reviewContext);
      await mkdir(contextRoot, { recursive: true });
      const finalPath = join(contextRoot, `${preflightId}.json`);
      const temporaryPath = `${finalPath}.${randomUUID()}.tmp`;
      await writeFile(temporaryPath, `${JSON.stringify(reviewContext)}\n`, { encoding: 'utf8', flag: 'wx' });
      await rename(temporaryPath, finalPath);
    },

    async recall({ preflightId } = {}) {
      requirePreflightId(preflightId);
      const finalPath = join(contextRoot, `${preflightId}.json`);
      try {
        const text = (await readFile(finalPath, 'utf8')).replace((new RegExp("\u005e\ufeff", "")), '');
        const parsed = JSON.parse(text);
        return typeof parsed === 'string' ? parsed : null;
      } catch {
        return null;
      }
    },
  });
}
