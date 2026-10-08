// One cleanup hook per test, with every step guaranteed to run.
//
// Two node:test behaviours make plain t.after hooks leak (both observed on Node v24):
//   * hooks run in REGISTRATION order, and when one throws, every later t.after hook on that test is skipped;
//   * a test that times out still runs its t.after hooks, but a `finally` block inside the stuck test body never runs.
// So a real-disk fixture (registered first) can be removed while a child the test spawned later still holds files in it, and a
// failed removal skips the hook that stops that child. onCleanup fixes both: each context gets ONE t.after hook, which runs
// the registered steps newest-first (a child is stopped before the fixture it uses is removed), runs every step even when
// one fails, and only then fails the test with the collected errors. Use it instead of t.after for any cleanup that shares a
// test with another cleanup, and instead of `finally` for temp folders (tempDirFor), so a timed-out test still cleans up.
//
// `t` may be a node:test context or any object with an after(callback, options) method, such as the guards test file's
// file-level collector. Do not call onCleanup from inside a cleanup step: a step added while the hook runs is not run.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// A per-test timeout does not cover a t.after hook: the hook stays under the command-line value unless it
// carries its own. Real-disk cleanup (icacls reset plus recursive rm) can take minutes on a slow Windows host, so the one hook gets the
// same 900000 ms the real-disk tests use.
export const CLEANUP_HOOK_TIMEOUT_MS = 900_000;

const stacks = new WeakMap();

export function onCleanup(t, step) {
  if (typeof step !== 'function') throw new TypeError('cleanup step must be a function');
  let steps = stacks.get(t);
  if (steps === undefined) {
    const registered = [];
    // Register the hook BEFORE remembering the context: if t.after throws (for example, the test has already ended), no
    // later step is silently queued on a hook that does not exist.
    t.after(async () => {
      if (stacks.get(t) === registered) stacks.delete(t);
      await runCleanupSteps(registered);
    }, { timeout: CLEANUP_HOOK_TIMEOUT_MS });
    stacks.set(t, registered);
    steps = registered;
  }
  steps.push(step);
}

// Runs every step newest-first. A step's failure is kept, never allowed to stop the next step; one failure is rethrown as
// itself, several as one AggregateError whose message names each of them.
export async function runCleanupSteps(steps) {
  const failures = [];
  for (const step of steps.splice(0).reverse()) {
    try {
      await step();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    const detail = failures.map((error) => (error instanceof Error ? error.message : String(error))).join('; ');
    throw new AggregateError(failures, `${failures.length} cleanup steps failed: ${detail}`);
  }
}

// Recursive removal that rides out the short EBUSY/EPERM/ENOTEMPTY windows Windows leaves after a child process exits
// (fs.rm retries those codes itself, with a linear back-off). A missing path counts as removed. Still throws if the tree
// cannot be removed, so the failure reaches the test instead of leaving a silent leftover.
export async function removeTree(path) {
  await rm(path, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

// A stand-in for a node:test context, for tests OF cleanup behaviour. It records hooks in registration order and runs them
// the way node:test does: once each, in that order, stopping at the first one that throws. So a second hook that a helper
// registers on its own shows up in `hooks`, and would be skipped here exactly as node:test would skip it.
export function createRecordingContext() {
  const hooks = [];
  return {
    hooks,
    after(callback, options) { hooks.push({ callback, options }); },
    async runHooksLikeNodeTest() {
      for (const hook of hooks) await hook.callback();
    },
  };
}

// A fresh folder under the OS temp folder whose removal is registered with onCleanup, so it is removed even when the test
// times out. `prefix` should end in '-' so a leftover folder is easy to recognise.
export async function tempDirFor(t, prefix) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  onCleanup(t, () => removeTree(directory));
  return directory;
}

// Pending cleanup steps for a whole test file, run from ONE file-level after() hook: `after(() => registry.runAll(), ...)`.
// For children and folders a test creates before its own `finally`, which node:test never runs when the test times out.
// runAll() runs every pending step newest-first (so a child registered after its folder is stopped before the folder is
// removed), keeps going past a failure, and then reports the failures the same way runCleanupSteps does. A step leaves the
// registry only once it has run without throwing; a test may also delete() a step it has already handled itself.
export function createCleanupRegistry() {
  const steps = new Set();
  const registry = {
    add(step) {
      if (typeof step !== 'function') throw new TypeError('cleanup step must be a function');
      steps.add(step);
      return step;
    },
    delete(step) { steps.delete(step); },
    has(step) { return steps.has(step); },
    get size() { return steps.size; },
    async runAll() {
      const failures = [];
      for (const step of [...steps].reverse()) {
        try {
          await step();
          steps.delete(step);
        } catch (error) {
          failures.push(error);
        }
      }
      if (failures.length === 1) throw failures[0];
      if (failures.length > 1) {
        const detail = failures.map((error) => (error instanceof Error ? error.message : String(error))).join('; ');
        throw new AggregateError(failures, `${failures.length} cleanup steps failed: ${detail}`);
      }
    },
    // A fresh folder under the OS temp folder, removed by runAll() unless the test removed it first (then that step is a
    // no-op). `prefix` should end in '-' so a leftover folder is easy to recognise.
    async tempDir(prefix) {
      const directory = await mkdtemp(join(tmpdir(), prefix));
      registry.add(() => removeTree(directory));
      return directory;
    },
  };
  return registry;
}
