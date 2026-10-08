import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const JOB_ID = /^[a-f0-9]{64}$/;

function requireJobId(value) {
  if (typeof value !== 'string' || !JOB_ID.test(value)) {
    throw new TypeError('jobId must be a 64-character lowercase SHA-256 hex string');
  }
  return value;
}

function isValidRecord(value) {
  return value !== null
    && typeof value === 'object'
    && JOB_ID.test(value.jobId)
    && typeof value.reviewerId === 'string' && value.reviewerId.length > 0
    && typeof value.reservationUsd === 'number' && Number.isFinite(value.reservationUsd) && value.reservationUsd >= 0
    && Number.isSafeInteger(value.notBeforeMs)
    && Number.isSafeInteger(value.recordedAtMs);
}

function isValidClaim(value) {
  return value !== null
    && typeof value === 'object'
    && JOB_ID.test(value.jobId)
    && typeof value.claimId === 'string' && value.claimId.length > 0
    && Number.isSafeInteger(value.pid)
    && Number.isSafeInteger(value.claimedAtMs)
    && (value.gradeAsOfMs === undefined || Number.isSafeInteger(value.gradeAsOfMs));
}

/**
 * Durable, per-job record of an `ambiguousDispatching` force-close whose dispatch-health verdict
 * has been deliberately DEFERRED rather than recorded immediately. Mirrors
 * preflight-context-store.mjs's atomic temp-file + `wx`-flag + rename write convention, including
 * the defensive UTF-8 BOM strip on read and a corrupt/missing file recalling as `null` rather than
 * throwing. Unlike that store (which never deletes), a record here IS deleted once
 * resolvePendingHealthVerdicts() has recorded its real verdict -- deleted BEFORE the verdict is
 * recorded, deliberately, so a crash between the two can only under-count (miss this one job),
 * never double-count.
 *
 * Concurrent record() calls for the SAME jobId are not supported -- the rename() step can throw
 * EPERM/EBUSY on Windows when two writers race for the same final path (the same accepted gap as
 * preflight-context-store.mjs). Every real caller writes a given jobId exactly once.
 *
 * Per-job claim: claim() is an EXCLUSIVE create of `<jobId>.claim` next to the record, using
 * dispatch-outcome-store.mjs's markDispatching() idiom -- `flag: 'wx'` straight at the final path,
 * with no temp file and no rename, so there is nothing for Windows to fail with EPERM/EBUSY and
 * exactly one caller across every process can win. EEXIST from that create is the only thing that
 * reads as `{ claimed: false }`; anything else, including a failure to create the directory, is
 * rethrown. list() never returns a claim (it keeps only `.json` names).
 * recallClaim() is tri-state: `{ status: 'absent' }` only when the file does not exist;
 * `{ status: 'unreadable', mtimeMs }` when it exists but does not hold this job's valid claim (a
 * crash mid-`wx`-write leaves it empty or truncated), with the file's own mtime so the sweep can
 * tell a claim still being written from an abandoned one; `{ status: 'held', claim }` otherwise.
 * Any other read or stat failure is rethrown, never guessed at.
 * releaseClaim() removes the file only for the claimId that won it, or unconditionally when handed
 * `claimId: null` (the sweep's takeover of an abandoned claim); a missing file is not an error.
 * Its read-then-remove is not atomic; the sweep's ordering (a record is always removed before its
 * claim is released, and every claimer re-reads the record under its claim) is what keeps that gap
 * from resolving a verdict twice.
 * claim() also persists an optional `gradeAsOfMs` that recallClaim() returns as given: the instant
 * a takeover grades its record as of, carried in the taker's own claim so a later takeover of THAT
 * claim still grades from it. A claim made without one carries none. Like claimedAtMs it must be a
 * safe integer, so a caller carrying a file's mtimeMs, which is fractional, floors it.
 * `statImpl` is a test-only seam, mirroring lease-store.mjs's renameImpl: it lets a test land a
 * deterministic release between readClaim()'s read and its stat. Production never passes it.
 */
export function createPendingHealthVerdictStore({ dataRoot, statImpl = stat }) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  if (typeof statImpl !== 'function') throw new TypeError('statImpl must be a function');
  const verdictRoot = join(dataRoot, 'pending-health-verdicts');

  function pathFor(jobId) {
    return join(verdictRoot, `${requireJobId(jobId)}.json`);
  }

  function claimPathFor(jobId) {
    return join(verdictRoot, `${requireJobId(jobId)}.claim`);
  }

  // Shared by recallClaim() and releaseClaim() so neither method needs `this`: a caller, or a test
  // wrapper, that copies these methods off the frozen store still gets working ones. Tri-state, see
  // the docstring above.
  async function readClaim(jobId) {
    const claimPath = claimPathFor(jobId);
    let raw;
    try {
      raw = await readFile(claimPath, 'utf8');
    } catch (error) {
      if (error && error.code === 'ENOENT') return { status: 'absent' };
      throw error;
    }
    let parsed = null;
    try {
      // The same defensive BOM strip recall() does, spelled as a char-code check so this source
      // carries no invisible character.
      parsed = JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw);
    } catch {
      parsed = null;
    }
    if (isValidClaim(parsed) && parsed.jobId === jobId) {
      const claim = { jobId: parsed.jobId, claimId: parsed.claimId, pid: parsed.pid, claimedAtMs: parsed.claimedAtMs };
      if (parsed.gradeAsOfMs !== undefined) claim.gradeAsOfMs = parsed.gradeAsOfMs;
      return { status: 'held', claim };
    }
    try {
      const { mtimeMs } = await statImpl(claimPath);
      return { status: 'unreadable', mtimeMs };
    } catch (error) {
      // Removed between the read and the stat: its holder released it.
      if (error && error.code === 'ENOENT') return { status: 'absent' };
      throw error;
    }
  }

  return Object.freeze({
    async record({ jobId, reviewerId, reservationUsd, notBeforeMs, recordedAtMs } = {}) {
      requireJobId(jobId);
      if (typeof reviewerId !== 'string' || reviewerId.length === 0) throw new TypeError('reviewerId must be a non-empty string');
      if (typeof reservationUsd !== 'number' || !Number.isFinite(reservationUsd) || reservationUsd < 0) throw new TypeError('reservationUsd must be a finite non-negative number');
      if (!Number.isSafeInteger(notBeforeMs)) throw new TypeError('notBeforeMs must be a safe integer');
      if (!Number.isSafeInteger(recordedAtMs)) throw new TypeError('recordedAtMs must be a safe integer');
      await mkdir(verdictRoot, { recursive: true });
      const finalPath = pathFor(jobId);
      const temporaryPath = `${finalPath}.${randomUUID()}.tmp`;
      await writeFile(
        temporaryPath,
        JSON.stringify({ jobId, reviewerId, reservationUsd, notBeforeMs, recordedAtMs }),
        { encoding: 'utf8', flag: 'wx' },
      );
      await rename(temporaryPath, finalPath);
    },

    async recall({ jobId } = {}) {
      requireJobId(jobId);
      try {
        const text = (await readFile(pathFor(jobId), 'utf8')).replace((new RegExp("\u005e\ufeff", "")), '');
        const parsed = JSON.parse(text);
        if (!isValidRecord(parsed) || parsed.jobId !== jobId) return null;
        return parsed;
      } catch {
        return null;
      }
    },

    async remove({ jobId } = {}) {
      requireJobId(jobId);
      try {
        await rm(pathFor(jobId));
      } catch (error) {
        if (error && error.code !== 'ENOENT') throw error;
      }
    },

    async list() {
      let entries;
      try {
        entries = await readdir(verdictRoot);
      } catch (error) {
        if (error && error.code === 'ENOENT') return [];
        throw error;
      }
      const records = [];
      for (const entry of entries) {
        if (!entry.endsWith('.json')) continue;
        const jobId = entry.slice(0, -'.json'.length);
        if (!JOB_ID.test(jobId)) continue;
        const record = await this.recall({ jobId });
        if (record) records.push(record);
      }
      return records;
    },

    async claim({ jobId, nowMs, gradeAsOfMs } = {}) {
      requireJobId(jobId);
      if (!Number.isSafeInteger(nowMs)) throw new TypeError('nowMs must be a safe integer');
      if (gradeAsOfMs !== undefined && !Number.isSafeInteger(gradeAsOfMs)) {
        throw new TypeError('gradeAsOfMs, when given, must be a safe integer');
      }
      // Outside the try below on purpose: mkdir({ recursive: true }) itself throws EEXIST when a
      // FILE sits where the directory should be (as observed on Windows), and that must surface as a
      // real failure, never be mistaken for another process holding this claim.
      await mkdir(verdictRoot, { recursive: true });
      const claimId = randomUUID();
      try {
        // JSON.stringify drops an undefined gradeAsOfMs, so a claim made without one carries none.
        await writeFile(
          claimPathFor(jobId),
          JSON.stringify({ jobId, claimId, pid: process.pid, claimedAtMs: nowMs, gradeAsOfMs }),
          { encoding: 'utf8', flag: 'wx' },
        );
      } catch (error) {
        if (error && error.code === 'EEXIST') return { claimed: false };
        throw error;
      }
      return { claimed: true, claimId };
    },

    async recallClaim({ jobId } = {}) {
      requireJobId(jobId);
      return readClaim(jobId);
    },

    async releaseClaim({ jobId, claimId } = {}) {
      requireJobId(jobId);
      if (claimId !== null && (typeof claimId !== 'string' || claimId.length === 0)) {
        throw new TypeError('claimId must be a non-empty string, or null to force-drop the claim');
      }
      if (claimId !== null) {
        const held = await readClaim(jobId);
        // Only the claimId that won a claim releases it. Someone else's claim, or an unreadable one,
        // is left for its owner or for the sweep's stale-claim takeover rule; releasing it here could let a
        // second process resolve the same verdict.
        if (held.status !== 'held' || held.claim.claimId !== claimId) return;
      }
      try {
        await rm(claimPathFor(jobId));
      } catch (error) {
        if (error && error.code !== 'ENOENT') throw error;
      }
    },
  });
}
