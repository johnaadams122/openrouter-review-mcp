import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

// The severity vocabulary matches what downstream alert consumers key off: exactly these three
// strings. 'info' is deliberately the routine level -- a downstream notifier may rate-limit
// pushes per rolling hour, so a routine per-batch record at any pushing severity would consume
// that budget and suppress the alerts that actually need to reach a human.
const SEVERITIES = Object.freeze(['info', 'warning', 'critical']);

// A downstream alert notifier may blank any message matching /\$|\d{5,}/ and replace it with a
// generic string. Refusing those characters here means an alert either carries its real
// information or fails loudly at the write -- it can never be silently emptied downstream.
// Write currency as the word USD, and keep long identifiers out of the reason text.
const FORBIDDEN_IN_RAW_REASON = /\$|\d{5,}/;

// The raw check above is not enough on its own. Downstream sanitization may lowercase the reason
// and strip EVERY character outside [a-z0-9_.-] -- including spaces, commas, and colons -- before
// the digit-run guard runs. So "12 345", "12,345", and "12:345" all look like short, harmless runs
// to a check against the raw string, but collapse into one contiguous 5-digit run downstream and
// still get blanked. Simulate that exact strip before testing for a digit run, or a reason like
// "queue depth 12 345 items" passes here and is silently emptied later anyway.
// (The dollar sign needs no separate post-strip check: '$' is not in the preserved character set,
// so that sanitization always removes it regardless of what survives the raw check above.)
//
// One deliberate asymmetry: downstream sanitization may truncate to 40 chars BEFORE testing for a
// digit run; this check does not truncate and scans the whole reason. That can only make this
// check MORE cautious than the downstream behavior, never less -- a 40-char window is always a
// strict prefix of what this scans in full, so any digit run the downstream check would react to
// is necessarily visible here too. Worst case is an over-cautious false rejection of a reason that
// would have been safe past character 40, never a false accept of one that gets silently blanked.
const DOWNSTREAM_REASON_STRIP = /[^a-z0-9_.-]/g;
const DOWNSTREAM_DIGIT_RUN = /\d{5,}/;

function wouldBeBlankedDownstream(reason) {
  return DOWNSTREAM_DIGIT_RUN.test(reason.toLowerCase().replace(DOWNSTREAM_REASON_STRIP, ''));
}

export function createAlertStore({ dataRoot, clock = () => Date.now() } = {}) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot must be a non-empty string');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  const alertPath = join(dataRoot, 'alerts.jsonl');

  return Object.freeze({
    alertPath,
    async record({ severity, reason, component } = {}) {
      if (!SEVERITIES.includes(severity)) throw new TypeError(`severity must be one of ${SEVERITIES.join(', ')}`);
      if (typeof reason !== 'string' || reason.length === 0) throw new TypeError('reason must be a non-empty string');
      if (FORBIDDEN_IN_RAW_REASON.test(reason) || wouldBeBlankedDownstream(reason)) {
        throw new TypeError('reason must not contain a dollar sign or a run of five or more digits');
      }
      if (typeof component !== 'string' || component.length === 0) throw new TypeError('component must be a non-empty string');
      await mkdir(dataRoot, { recursive: true });
      const line = JSON.stringify({ severity, reason, component, timestamp: new Date(Number(clock())).toISOString() });
      // Append, never rewrite: this file is an audit trail, and a concurrent second server
      // process must never truncate the first one's history.
      await appendFile(alertPath, `${line}\n`, 'utf8');
    },

    // Read-only. Used by the 75%-of-monthly-cap alert: a caller
    // that wants to alert "the first time" a threshold crosses in a given period needs to check
    // what it has already recorded before writing a duplicate. Reusing THIS file for that check
    // (rather than a second, purpose-built dedup store) means that check survives a process
    // restart for free, using the exact same durable file record() already maintains -- no new
    // state, no new write path, nothing that could drift from what record() actually wrote.
    // A missing file (nothing ever recorded) returns an empty array rather than throwing, mirroring
    // record()'s own mkdir-on-write posture: a reader must not need the file to already exist.
    async list() {
      let text;
      try {
        text = await readFile(alertPath, 'utf8');
      } catch (error) {
        if (error && error.code === 'ENOENT') return [];
        throw error;
      }
      const trimmed = text.trim();
      if (trimmed.length === 0) return [];
      return trimmed.split('\n').map((line) => JSON.parse(line));
    },
  });
}
