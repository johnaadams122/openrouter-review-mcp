import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

function freshState() {
  return { consecutiveFailures: 0, alertedForCurrentStreak: false };
}

function isValidState(value) {
  return value !== null
    && typeof value === 'object'
    && Number.isSafeInteger(value.consecutiveFailures)
    && value.consecutiveFailures >= 0
    && typeof value.alertedForCurrentStreak === 'boolean';
}

/*
 * Durable consecutive-dispatch-failure counter. The streak survives a server restart (a single
 * JSON file written via temp file + atomic rename), because restarts are themselves a common
 * cause of dispatch failures and an in-memory counter would reset exactly when it matters.
 */
export function createDispatchHealthStore({ dataRoot } = {}) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot must be a non-empty string');
  const statePath = join(dataRoot, 'dispatch-health.json');

  async function readState() {
    let text;
    try {
      text = await readFile(statePath, 'utf8');
    } catch (error) {
      if (error && error.code === 'ENOENT') return freshState();
      // A genuine disk-read failure degrades to a fresh streak, same posture as the corrupt-JSON
      // case below -- this counter must never be why a real dispatch outcome fails to record.
      return freshState();
    }
    try {
      const parsed = JSON.parse(text);
      return isValidState(parsed) ? parsed : freshState();
    } catch {
      return freshState();
    }
  }

  async function writeState(state) {
    await mkdir(dataRoot, { recursive: true });
    const temporaryPath = `${statePath}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
    await writeFile(temporaryPath, JSON.stringify(state), 'utf8');
    await rename(temporaryPath, statePath);
  }

  return Object.freeze({
    statePath,
    /**
     * Records one dispatch outcome and returns the freshly updated
     * `{ consecutiveFailures, shouldAlert }`. `succeeded: true` resets the streak (and the
     * alerted flag) to zero/false. `succeeded: false` increments the streak; `shouldAlert` is
     * true once a call within a streak first reaches `alertThreshold` AND the streak has not
     * already been durably marked alerted via markAlerted() below.
     *
     * Deliberately does NOT itself set `alertedForCurrentStreak: true` on a crossing call:
     * setting that flag durably in THIS same write, before the caller has actually delivered the
     * alert, would lose the alert whenever the caller's own alertStore.record() call then fails
     * (a transient disk error, or -- worse -- a deterministic failure, e.g. an
     * operator-misconfigured alertThreshold whose digits trip alert-store.mjs's own
     * dollar/digit-run guard). The flag would already be durably true, so every FURTHER
     * consecutive failure in the same streak would recompute `shouldAlert: false` and the alert
     * would be lost for that streak. Only markAlerted() persists the
     * flag, and callers must call it only after the alert has actually, successfully been
     * recorded -- see review-engine.mjs's recordDispatchHealthOutcome. Until markAlerted() is
     * called, the NEXT consecutive failure recomputes `shouldAlert: true` again and retries,
     * which trades "possible duplicate alert after a crash between a successful write and the
     * markAlerted() call" for "never silently losing an alert" -- the correct direction for a
     * feature whose whole point is that a human finds out.
     */
    async recordOutcome({ succeeded, alertThreshold } = {}) {
      if (typeof succeeded !== 'boolean') throw new TypeError('succeeded must be a boolean');
      if (!Number.isSafeInteger(alertThreshold) || alertThreshold <= 0) {
        throw new TypeError('alertThreshold must be a positive safe integer');
      }
      const state = await readState();
      let next;
      let shouldAlert = false;
      if (succeeded) {
        next = freshState();
      } else {
        const consecutiveFailures = state.consecutiveFailures + 1;
        shouldAlert = !state.alertedForCurrentStreak && consecutiveFailures >= alertThreshold;
        next = { consecutiveFailures, alertedForCurrentStreak: state.alertedForCurrentStreak };
      }
      await writeState(next);
      return { consecutiveFailures: next.consecutiveFailures, shouldAlert };
    },

    /**
     * Durably marks the CURRENT streak as already alerted. Must only be called after the
     * caller's own alert write has actually succeeded (see recordOutcome's docstring above for
     * why). A success recorded via recordOutcome() in between (which resets the streak) makes
     * this a harmless no-op on the now-irrelevant flag of a streak that already ended -- there is
     * no meaningful streak left for it to mark.
     */
    async markAlerted() {
      const state = await readState();
      await writeState({ ...state, alertedForCurrentStreak: true });
    },

    async recall() {
      return readState();
    },
  });
}
