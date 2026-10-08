import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const JOB_ID = /^[a-f0-9]{64}$/;

function requireJobId(value) {
  if (typeof value !== 'string' || !JOB_ID.test(value)) {
    throw new TypeError('jobId must be a 64-character lowercase SHA-256 hex string');
  }
  return value;
}

function isValidOutcome(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.kind === 'DISPATCHING') return true;
  return (value.kind === 'RESPONSE' || value.kind === 'FAILURE') && typeof value.envelopeJsonText === 'string';
}

/**
 * Mostly read-only from Node's side: the WRITER of a final RESPONSE/FAILURE
 * outcome is tools/openrouter-review-dispatch.ps1 itself (see
 * Write-OpenRouterOutcomeAtomic there), not this module -- the whole point
 * is capturing that outcome durably from inside the one process that
 * actually knows what OpenRouter said, before handing it back to a Node
 * parent that might already be gone by the time it tries to read stdout.
 * The one exception is `markDispatching()` below, written by Node itself.
 *
 * Why this exists: the calling Node process
 * (openrouter-review-mcp-server.mjs) can itself be replaced mid-dispatch by
 * something outside this repository's control, discarding whatever the
 * PowerShell dispatch script returned on stdout -- even a real, successful
 * response -- leaving review-engine.mjs's existingJob recovery with nothing
 * to go on but "unknown outcome, charge worst case." review-engine.mjs's
 * review() consults this store before giving up on a
 * RESERVED-but-never-reconciled job, so a genuinely successful response
 * that arrived after its original caller was already gone is recoverable
 * instead of lost.
 *
 * A narrower, earlier gap in the same class: the Node process can be
 * killed/replaced BEFORE it ever spawns the PowerShell script at all --
 * e.g. between writing the request file and calling execute(). The
 * RESPONSE/FAILURE capture above can only protect an outcome the script
 * actually got to write; it has nothing to say about a dispatch that was
 * never even attempted, so without a marker review()'s recovery logic would
 * have to treat "no capture found" as ambiguous and always charge
 * worst-case, even in the common case where no OpenRouter call was ever
 * made. `markDispatching()` closes that gap: Node writes a
 * lightweight `{kind:'DISPATCHING'}` marker to this SAME path, atomically,
 * immediately before calling execute() (see
 * tools/openrouter-review-mcp-server.mjs). review()'s recovery can then
 * tell apart three states by reading this one file: nothing on disk at all
 * (dispatch() was never invoked -- provably zero risk of a duplicate
 * OpenRouter call, safe to redispatch using the existing reservation), a
 * DISPATCHING marker with no later overwrite (a dispatch was attempted and
 * its outcome is genuinely unknown -- must not redispatch, unchanged
 * worst-case behavior), or a real RESPONSE/FAILURE (the script's own
 * atomic write, which always overwrites whatever marker preceded it at
 * this same path -- recovered and validated exactly as before).
 *
 * Two properties make "no marker" conclusive: (1) markDispatching() is not
 * best-effort -- if a failed write were logged and swallowed and execute()
 * ran anyway, "no marker" would prove nothing; (2) it must never overwrite --
 * a temp-file + unconditional rename would replace whatever was already at
 * the final path, so a second, racing dispatch attempt for the same jobId
 * (e.g. a client-side timeout followed by a retry that genuinely overlaps
 * the still-in-flight original call) could silently clobber an
 * already-captured real RESPONSE with a bare marker.
 * markDispatching() is therefore an EXCLUSIVE, atomic claim (`flag: 'wx'` directly
 * at the final path, no temp file, no rename): it throws an EEXIST-coded
 * error if ANYTHING already exists there, real outcome or another marker,
 * and never overwrites. The caller (tools/openrouter-review-mcp-server.mjs)
 * treats ANY markDispatching() failure -- EEXIST or otherwise -- as a
 * hard precondition failure: execute() is never called without a successful
 * claim, so "no marker" really does mean "dispatch() was never invoked,"
 * and at most one caller can ever win the claim for a given jobId, closing
 * both the false-proof and the clobber/double-dispatch risk in one change.
 */
export function dispatchOutcomePath({ dataRoot, jobId }) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  return join(dataRoot, 'dispatch-outcomes', `${requireJobId(jobId)}.json`);
}

export function createDispatchOutcomeStore({ dataRoot }) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  const outcomeRoot = join(dataRoot, 'dispatch-outcomes');

  return Object.freeze({
    async recall({ jobId } = {}) {
      const finalPath = dispatchOutcomePath({ dataRoot, jobId });
      try {
        const text = (await readFile(finalPath, 'utf8')).replace((new RegExp("\u005e\ufeff", "")), '');
        const parsed = JSON.parse(text);
        return isValidOutcome(parsed) ? parsed : null;
      } catch {
        return null;
      }
    },

    // NOT best-effort: this is a hard precondition the caller must honor
    // (see the class doc comment above). `flag: 'wx'` (O_CREAT | O_EXCL)
    // makes the create itself the atomic claim -- it throws with
    // `error.code === 'EEXIST'` if anything is already at this path, real
    // outcome or another marker, and never overwrites either way. The
    // caller (tools/openrouter-review-mcp-server.mjs) must not call
    // execute() unless this resolves successfully.
    async markDispatching({ jobId } = {}) {
      requireJobId(jobId);
      await mkdir(outcomeRoot, { recursive: true });
      const finalPath = dispatchOutcomePath({ dataRoot, jobId });
      await writeFile(finalPath, JSON.stringify({ kind: 'DISPATCHING' }), { encoding: 'utf8', flag: 'wx' });
    },
  });
}
