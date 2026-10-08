import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

function runHook(payload, env) {
  const stdout = execFileSync(process.execPath, ['hooks/task-completion-nudge.mjs'], {
    input: JSON.stringify(payload), encoding: 'utf8', env: { ...process.env, ...env },
  });
  return stdout.trim() === '' ? null : JSON.parse(stdout);
}

function freshStateDir() {
  const dir = mkdtempSync(join(tmpdir(), 'task-completion-nudge-test-'));
  return { dir, env: { TASK_COMPLETION_NUDGE_STATE_DIR: dir } };
}

test('a todo newly marked completed emits an impl-review nudge naming it', () => {
  const { dir, env } = freshStateDir();
  try {
    const output = runHook({
      session_id: 's1',
      tool_name: 'TodoWrite',
      tool_input: { todos: [
        { content: 'Write the failing tests', status: 'completed', activeForm: 'Writing the failing tests' },
        { content: 'Implement the fix', status: 'in_progress', activeForm: 'Implementing the fix' },
      ] },
    }, env);
    assert.equal(output.hookSpecificOutput.hookEventName, 'PostToolUse');
    assert.match(output.hookSpecificOutput.additionalContext, /impl_review_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
    assert.match(output.hookSpecificOutput.additionalContext, /Write the failing tests/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('re-seeing the same completed todo on a later call emits nothing (no duplicate nudge)', () => {
  const { dir, env } = freshStateDir();
  try {
    const todos = [
      { content: 'Write the failing tests', status: 'completed', activeForm: 'Writing the failing tests' },
      { content: 'Implement the fix', status: 'in_progress', activeForm: 'Implementing the fix' },
    ];
    runHook({ session_id: 's1', tool_name: 'TodoWrite', tool_input: { todos } }, env);
    const second = runHook({ session_id: 's1', tool_name: 'TodoWrite', tool_input: { todos } }, env);
    assert.equal(second, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the todo list newly becoming fully completed emits a rescue+final-verification nudge', () => {
  const { dir, env } = freshStateDir();
  try {
    const inProgress = [
      { content: 'Write the failing tests', status: 'completed', activeForm: 'Writing the failing tests' },
      { content: 'Implement the fix', status: 'in_progress', activeForm: 'Implementing the fix' },
    ];
    runHook({ session_id: 's2', tool_name: 'TodoWrite', tool_input: { todos: inProgress } }, env);
    const allDone = [
      { content: 'Write the failing tests', status: 'completed', activeForm: 'Writing the failing tests' },
      { content: 'Implement the fix', status: 'completed', activeForm: 'Implementing the fix' },
    ];
    const output = runHook({ session_id: 's2', tool_name: 'TodoWrite', tool_input: { todos: allDone } }, env);
    assert.match(output.hookSpecificOutput.additionalContext, /code_rescue_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
    assert.match(output.hookSpecificOutput.additionalContext, /final_verification_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a single call that both completes a task AND finishes the whole list combines both nudges', () => {
  const { dir, env } = freshStateDir();
  try {
    const started = [{ content: 'Only task', status: 'in_progress', activeForm: 'Doing the only task' }];
    runHook({ session_id: 's3', tool_name: 'TodoWrite', tool_input: { todos: started } }, env);
    const done = [{ content: 'Only task', status: 'completed', activeForm: 'Doing the only task' }];
    const output = runHook({ session_id: 's3', tool_name: 'TodoWrite', tool_input: { todos: done } }, env);
    assert.match(output.hookSpecificOutput.additionalContext, /impl_review_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
    assert.match(output.hookSpecificOutput.additionalContext, /code_rescue_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
    assert.match(output.hookSpecificOutput.additionalContext, /final_verification_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('re-completing after a fresh todo is added is a genuinely new all-complete event', () => {
  const { dir, env } = freshStateDir();
  try {
    const oneDone = [{ content: 'Task A', status: 'completed', activeForm: 'Doing Task A' }];
    runHook({ session_id: 's4', tool_name: 'TodoWrite', tool_input: { todos: oneDone } }, env);
    const twoAdded = [
      { content: 'Task A', status: 'completed', activeForm: 'Doing Task A' },
      { content: 'Task B', status: 'in_progress', activeForm: 'Doing Task B' },
    ];
    runHook({ session_id: 's4', tool_name: 'TodoWrite', tool_input: { todos: twoAdded } }, env);
    const bothDone = [
      { content: 'Task A', status: 'completed', activeForm: 'Doing Task A' },
      { content: 'Task B', status: 'completed', activeForm: 'Doing Task B' },
    ];
    const output = runHook({ session_id: 's4', tool_name: 'TodoWrite', tool_input: { todos: bothDone } }, env);
    assert.match(output.hookSpecificOutput.additionalContext, /final_verification_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('different session ids are tracked independently', () => {
  const { dir, env } = freshStateDir();
  try {
    const todos = [{ content: 'Task X', status: 'completed', activeForm: 'Doing Task X' }];
    const first = runHook({ session_id: 'session-a', tool_name: 'TodoWrite', tool_input: { todos } }, env);
    const second = runHook({ session_id: 'session-b', tool_name: 'TodoWrite', tool_input: { todos } }, env);
    assert.notEqual(first, null);
    assert.notEqual(second, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an unrelated tool call emits nothing', () => {
  const { dir, env } = freshStateDir();
  try {
    assert.equal(runHook({ session_id: 's5', tool_name: 'Write', tool_input: { file_path: 'x.mjs' } }, env), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a TodoWrite call with no todos array emits nothing', () => {
  const { dir, env } = freshStateDir();
  try {
    assert.equal(runHook({ session_id: 's6', tool_name: 'TodoWrite', tool_input: {} }, env), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a malformed payload exits quietly rather than breaking the session', () => {
  const { dir, env } = freshStateDir();
  try {
    const stdout = execFileSync(process.execPath, ['hooks/task-completion-nudge.mjs'], {
      input: 'not json', encoding: 'utf8', env: { ...process.env, ...env },
    });
    assert.equal(stdout.trim(), '');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('duplicate task names at different positions each get their own newly-completed nudge', () => {
  const { dir, env } = freshStateDir();
  try {
    const started = [
      { content: 'Write tests', status: 'completed', activeForm: 'Writing tests' },
      { content: 'Write tests', status: 'in_progress', activeForm: 'Writing tests' },
    ];
    const first = runHook({ session_id: 's8', tool_name: 'TodoWrite', tool_input: { todos: started } }, env);
    assert.notEqual(first, null);
    const second = [
      { content: 'Write tests', status: 'completed', activeForm: 'Writing tests' },
      { content: 'Write tests', status: 'completed', activeForm: 'Writing tests' },
    ];
    // Completing the SECOND same-named todo must still fire -- a content-keyed "already
    // completed" set would wrongly treat it as a duplicate of the first and emit nothing.
    const output = runHook({ session_id: 's8', tool_name: 'TodoWrite', tool_input: { todos: second } }, env);
    assert.notEqual(output, null);
    assert.match(output.hookSpecificOutput.additionalContext, /impl_review_v1/);
    assert.doesNotMatch(output.hookSpecificOutput.additionalContext, /_free_v1/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('re-seeing the same completed todo at the same position a third time still emits nothing', () => {
  const { dir, env } = freshStateDir();
  try {
    const started = [
      { content: 'Write tests', status: 'completed', activeForm: 'Writing tests' },
      { content: 'Write tests', status: 'in_progress', activeForm: 'Writing tests' },
    ];
    runHook({ session_id: 's9', tool_name: 'TodoWrite', tool_input: { todos: started } }, env);
    const both = [
      { content: 'Write tests', status: 'completed', activeForm: 'Writing tests' },
      { content: 'Write tests', status: 'completed', activeForm: 'Writing tests' },
    ];
    runHook({ session_id: 's9', tool_name: 'TodoWrite', tool_input: { todos: both } }, env);
    const again = runHook({ session_id: 's9', tool_name: 'TodoWrite', tool_input: { todos: both } }, env);
    assert.equal(again, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a state directory that cannot be written to degrades quietly instead of crashing', () => {
  const { dir, env } = freshStateDir();
  try {
    // Point the state dir at a path that already exists as a FILE, not a directory -- mkdirSync
    // and writeFileSync both fail against this, simulating a locked/missing temp dir or a
    // disk-full condition.
    const blockedDir = join(dir, 'blocked-as-file');
    writeFileSync(blockedDir, 'not a directory', 'utf8');
    const todos = [{ content: 'Task Z', status: 'completed', activeForm: 'Doing Task Z' }];
    const output = runHook(
      { session_id: 's10', tool_name: 'TodoWrite', tool_input: { todos } },
      { TASK_COMPLETION_NUDGE_STATE_DIR: blockedDir },
    );
    // The call must still produce its nudge (this call's own logic doesn't depend on the write
    // succeeding) and, critically, must not throw / exit non-zero.
    assert.notEqual(output, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a corrupt state file is treated as empty history rather than crashing', () => {
  const { dir, env } = freshStateDir();
  try {
    const todos = [{ content: 'Task Y', status: 'completed', activeForm: 'Doing Task Y' }];
    // Prime a corrupt state file for this session before the hook ever runs.
    writeFileSync(join(dir, 's7.json'), 'not valid json', 'utf8');
    const output = runHook({ session_id: 's7', tool_name: 'TodoWrite', tool_input: { todos } }, env);
    assert.notEqual(output, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
