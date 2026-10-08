#!/usr/bin/env node
/**
 * PostToolUse hook: reminds the agent to run the cross-vendor review lens when an
 * implementation task completes (impl review) and when the whole task list completes (code
 * rescue and final verification) -- the stages review-nudge.mjs (spec/plan writes) does not
 * cover.
 *
 * Why TodoWrite, not a plan-file edit: a plan document's own `- [ ]` / `- [x]` checkboxes are
 * often flipped in one bulk edit at the very end rather than live as each task finishes, which
 * would make an Edit-based trigger fire once, at the wrong moment, for the wrong reason.
 * TodoWrite is the live per-task tracking mechanism, so a newly-completed todo is the real
 * observable signal for "a task just finished." If task tracking ever stops using TodoWrite,
 * this assumption should be revisited.
 *
 * Detects two distinct moments from the SAME tool, by diffing against the previous call:
 *   - a todo transitions to status:"completed" that wasn't completed before -> impl-review nudge
 *   - the whole todo list becomes fully completed, having not been fully completed before ->
 *     code-rescue + final-verification nudge (both belong "near the end," so one combined
 *     nudge names both rather than trying to force an artificial ordering between them)
 * A single call that finishes the last task can trigger both at once; the nudges are then
 * combined into one message, matching how a human would read that moment.
 *
 * State: TodoWrite always sends the FULL current list, not a delta, so detecting "newly"
 * completed requires remembering the previous call's list. Keyed by session_id (falls back to
 * a shared 'unknown' key if absent) under a temp directory -- deliberately outside the git
 * repo, since this is ephemeral per-session tracking state, not repository content.
 * TASK_COMPLETION_NUDGE_STATE_DIR overrides the location for tests.
 *
 * Same fail-quiet posture as review-nudge.mjs: a hook that throws breaks the session for
 * everyone, so any malformed input, missing state, or corrupt state file degrades to "nothing
 * remembered" rather than raising.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function stateDir() {
  return process.env.TASK_COMPLETION_NUDGE_STATE_DIR
    || join(tmpdir(), 'openrouter-review-mcp-task-completion-nudge');
}

function statePath(sessionId) {
  const safe = /^[A-Za-z0-9_-]+$/.test(sessionId) ? sessionId : 'unknown';
  return join(stateDir(), `${safe}.json`);
}

function loadPreviousTodos(sessionId) {
  try {
    const raw = readFileSync(statePath(sessionId), 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed?.todos) ? parsed.todos : [];
  } catch {
    return [];
  }
}

function saveTodos(sessionId, todos) {
  // Mirrors loadPreviousTodos' fail-quiet posture: a hook that throws breaks the session for
  // everyone, so a write failure (locked/missing temp dir, disk full, a TOCTOU race on the
  // existsSync check) degrades to "this call's state isn't persisted" rather than crashing.
  try {
    const dir = stateDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(statePath(sessionId), JSON.stringify({ todos }), 'utf8');
  } catch {
    // best-effort; see comment above
  }
}

function isFullyCompleted(todos) {
  return todos.length > 0 && todos.every((todo) => todo?.status === 'completed');
}

// Identity is POSITIONAL, not content-keyed: TodoWrite content strings are human-readable labels
// and can legitimately repeat (e.g. two different tasks both named "Run tests"). Keying on
// content alone means completing the second one silently produces no nudge, because its label was
// already in a "previously completed" set from the first. TodoWrite
// always sends the full ordered list (not a delta), so a todo's index is a stable-enough identity
// for the common case (new items appended, existing ones updated in place). A todo counts as
// "already completed" at a given slot only if the previous call's SAME index also had that exact
// content AND was already completed -- if the list is reordered/spliced, the worst case is an
// extra nudge for an already-reviewed task, never a missed one.
function newlyCompletedTasks(previousTodos, todos) {
  const result = [];
  todos.forEach((todo, index) => {
    if (todo?.status !== 'completed') return;
    const previous = previousTodos[index];
    const alreadyCompletedHere = previous && previous.content === todo.content && previous.status === 'completed';
    if (!alreadyCompletedHere) result.push(todo);
  });
  return result;
}

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('end', () => {
  let payload;
  try { payload = JSON.parse(raw); } catch { process.exit(0); }

  if (payload?.tool_name !== 'TodoWrite') process.exit(0);
  const todos = payload?.tool_input?.todos;
  if (!Array.isArray(todos) || todos.length === 0) process.exit(0);

  const sessionId = typeof payload?.session_id === 'string' && payload.session_id.length > 0
    ? payload.session_id : 'unknown';

  const previousTodos = loadPreviousTodos(sessionId);
  const newlyCompleted = newlyCompletedTasks(previousTodos, todos);
  const wasFullyCompleted = isFullyCompleted(previousTodos);
  const isNowFullyCompleted = isFullyCompleted(todos);

  saveTodos(sessionId, todos);

  const messages = [];
  if (newlyCompleted.length > 0) {
    const names = newlyCompleted.map((todo) => `"${todo.content}"`).join(', ');
    messages.push(
      `Task(s) just completed: ${names}. Consider an implementation review -- run the cross-vendor ` +
      'review lens over the diff for this task (openrouter_review_preflight with impl_review_v1, ' +
      'then authorize and document), fold findings in, report-only. ' +
      'If it cannot run, say so explicitly rather than silently skipping it.',
    );
  }
  if (isNowFullyCompleted && !wasFullyCompleted) {
    messages.push(
      'The whole task list just became complete. Consider a code-rescue review and a final ' +
      'verification -- run the cross-vendor review lens over the full diff (code_rescue_v1) ' +
      'and the final cross-check against the original requirements and plan ' +
      '(final_verification_v1) before reporting the work done. ' +
      'If either cannot run, say so explicitly rather than silently skipping it.',
    );
  }
  if (messages.length === 0) process.exit(0);

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: messages.join(' '),
    },
  }));
  process.exit(0);
});
