import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const PREFLIGHT_ID = /^[A-Za-z0-9-]{1,256}$/;

function requirePreflightId(value) {
  if (typeof value !== 'string' || !PREFLIGHT_ID.test(value)) {
    throw new TypeError('preflightId must be a non-empty opaque ID');
  }
  return value;
}

function requireMapping(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('mapping must be an object');
  }
  return value;
}

function requireCutoffIso(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new TypeError('cutoffIso must be an ISO timestamp');
  }
  return value;
}

/**
 * Durable, per-review placeholder<->real-value mapping store. Copies
 * result-store.mjs's exact atomic-write convention (temp file + `wx` +
 * rename), so this survives a host restarting the server process mid-review.
 * Unlike result-store.mjs (which never deletes -- its whole point is
 * surviving a connection that's already gone), this store's records are
 * intentionally short-lived: deleted immediately on a successful
 * reverse-substitution (see review-engine.mjs), with listStaleBefore() as a
 * backstop for an abandoned review whose reverse-substitution never ran (see
 * sweepStaleScrubMappings in tools/openrouter-review-mcp-server.mjs).
 */
export function createScrubMappingStore({
  dataRoot,
  // Test-only seam, mirroring lease-store.mjs's renameImpl: lets a test land a deterministic
  // concurrent delete between listStaleBefore()'s readdir and its stat without mocking
  // node:fs/promises. Production code never overrides this.
  statImpl = stat,
}) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  if (typeof statImpl !== 'function') throw new TypeError('statImpl must be a function');
  const mappingRoot = join(dataRoot, 'scrub-mappings');

  return Object.freeze({
    async record({ preflightId, mapping } = {}) {
      requirePreflightId(preflightId);
      requireMapping(mapping);
      await mkdir(mappingRoot, { recursive: true });
      const finalPath = join(mappingRoot, `${preflightId}.json`);
      const temporaryPath = `${finalPath}.${randomUUID()}.tmp`;
      await writeFile(temporaryPath, `${JSON.stringify(mapping)}\n`, { encoding: 'utf8', flag: 'wx' });
      await rename(temporaryPath, finalPath);
    },

    async recall({ preflightId } = {}) {
      requirePreflightId(preflightId);
      const finalPath = join(mappingRoot, `${preflightId}.json`);
      try {
        const text = (await readFile(finalPath, 'utf8')).replace(/^\uFEFF/, '');
        return JSON.parse(text);
      } catch {
        return null;
      }
    },

    async deleteMapping({ preflightId } = {}) {
      requirePreflightId(preflightId);
      const finalPath = join(mappingRoot, `${preflightId}.json`);
      try {
        await rm(finalPath, { force: true });
      } catch {
        // A delete failure here is a bounded-lifetime miss, not a
        // correctness issue -- listStaleBefore()'s sweep is the backstop.
      }
    },

    async listStaleBefore(cutoffIso) {
      requireCutoffIso(cutoffIso);
      const cutoffMs = Date.parse(cutoffIso);
      let names;
      try {
        names = await readdir(mappingRoot);
      } catch {
        return [];
      }
      const stale = [];
      for (const name of names) {
        if (!name.endsWith('.json')) continue;
        let info;
        try {
          // eslint-disable-next-line no-await-in-loop
          info = await statImpl(join(mappingRoot, name));
        } catch (error) {
          // With no startup ownership acquire serializing server starts, another server process
          // can delete this mapping between the readdir
          // above and this stat -- its own startup sweep, or result()'s delete-on-success. A mapping
          // that no longer exists is not stale, it is gone, so it is skipped. Only ENOENT is: every
          // other stat failure still throws, so a real disk problem is never hidden.
          if (error && error.code === 'ENOENT') continue;
          throw error;
        }
        if (info.mtimeMs < cutoffMs) stale.push(name.slice(0, -'.json'.length));
      }
      return stale;
    },
  });
}
