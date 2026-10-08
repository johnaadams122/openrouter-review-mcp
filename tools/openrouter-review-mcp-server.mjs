import { execFile as execFileCallback } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  TOOL_NAMES,
  PREFLIGHT_INPUT_SCHEMA,
  AUTHORIZE_WORKFLOW_INPUT_SCHEMA,
  REVIEW_INPUT_SCHEMA,
  STATUS_INPUT_SCHEMA,
  RESULT_INPUT_SCHEMA,
  SUBMIT_INPUT_SCHEMA, SUBMIT_OUTPUT_SCHEMA,
  REQUEST_RESULT_INPUT_SCHEMA, REQUEST_RESULT_OUTPUT_SCHEMA,
  CANCEL_INPUT_SCHEMA, CANCEL_OUTPUT_SCHEMA,
  formatToolResult,
} from '../src/local-mcp/mcp-schemas.mjs';
import {
  DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD,
  MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD,
  ReviewEngineError,
  createReviewEngine,
  safeErrorDetail,
} from '../src/local-mcp/review-engine.mjs';
import { createAlertStore } from '../src/local-mcp/alert-store.mjs';
import { createApprovalAdapter } from '../src/local-mcp/adapters.mjs';
import { createDispatchHealthStore } from '../src/local-mcp/dispatch-health-store.mjs';
import { createDispatchOutcomeStore, dispatchOutcomePath } from '../src/local-mcp/dispatch-outcome-store.mjs';
import { createPendingHealthVerdictStore } from '../src/local-mcp/pending-health-verdict-store.mjs';
import { createLeaseStore } from '../src/local-mcp/lease-store.mjs';
import { DEFAULT_ARM_LOCK_RETRY_MS, DEFAULT_ARM_TIMEOUT_MS } from '../src/local-mcp/ownership-coordinator.mjs';
import { createOllamaClient } from '../src/local-mcp/ollama-client.mjs';
import { createRepeatAuthorizationJudge } from '../src/local-mcp/repeat-authorization-judge.mjs';
import { createPreflightContextStore } from '../src/local-mcp/preflight-context-store.mjs';
import { createResultStore } from '../src/local-mcp/result-store.mjs';
import { createScrubEngine } from '../src/local-mcp/scrub-engine.mjs';
import { EXTRA_PROTECTED_TERMS_MAX_BYTES, NO_EXTRA_PROTECTED_TERMS, parseExtraProtectedTerms } from '../src/local-mcp/scrub-patterns.mjs';
import { createScrubMappingStore } from '../src/local-mcp/scrub-mapping-store.mjs';
import { canonicalJson, sharedError } from '../src/local-mcp/shared/contracts.mjs';

/**
 * Stdio-only MCP entry point exposing exactly five tools -- preflight,
 * authorize_workflow, review (openrouter_review_document), status, and
 * result -- wired directly to a review engine's
 * (src/local-mcp/review-engine.mjs)
 * preflight/authorizeWorkflow/review/status/result methods. This module never
 * reimplements engine logic, never reads a credential itself, and never
 * dispatches an OpenRouter request itself: every side effect happens inside
 * the engine and the adapters it was built with.
 *
 * No HTTP/SSE transport, no resources, no prompts, no dynamic tool list, and
 * no MCP-client registration code live here (this file never edits any
 * external client's config to make itself discoverable -- that remains a
 * separate, human action). `createReviewMcpServer(engine)` builds the server
 * against a caller-supplied engine and never touches a transport itself;
 * `main()` below is the one caller that connects it with `StdioServerTransport`
 * (the only transport this project ever uses) for a real process, exactly as
 * the harness in tests/openrouter-review-mcp-stdio.test.mjs already does for
 * a test engine.
 *
 * All startup/diagnostic/error logging uses process.stderr.write directly
 * (never console.*) so stdout carries only newline-delimited JSON-RPC.
 */

const SERVER_INFO = Object.freeze({ name: 'openrouter-review-mcp', version: '0.1.0' });

function requireEngine(engine) {
  if (engine === null || typeof engine !== 'object') throw new TypeError('engine must be an object');
  for (const method of ['preflight', 'authorizeWorkflow', 'status', 'review', 'result']) {
    if (typeof engine[method] !== 'function') throw new TypeError(`engine.${method} must be a function`);
  }
  return engine;
}

/**
 * Converts a thrown ReviewEngineError into a structured MCP tool error
 * (isError: true, with the engine's own {code, message} serialized as text)
 * instead of the SDK's default bare-message error, so a caller can branch on
 * `code` programmatically. Any other thrown error is rethrown and left to the
 * SDK's own top-level handler -- this function only formats known,
 * already-classified engine errors, it never decides new error semantics.
 *
 * When the engine attached an advisory `details` object (for example the
 * reason, holder pid and age behind a PROCESS_OWNERSHIP_UNAVAILABLE), it is
 * added to the same JSON body.
 * `{ code, message }` stays the whole contract and callers must not require
 * `details`. `Object.hasOwn` rather than a truthiness test, so an error
 * without details serializes exactly as it always has.
 */
function toolErrorFromEngineError(error) {
  // Shared errors carry only a fixed code/message. Read no getters and never
  // copy a supplied message or diagnostic into caller-visible shared errors.
  const code = error !== null && (typeof error === 'object' || typeof error === 'function')
    ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined;
  try {
    const fixed = sharedError(code);
    return {content:[{type:'text',text:JSON.stringify({code:fixed.code,message:fixed.message})}],isError:true};
  } catch { /* The historical engine error path below stays unchanged. */ }
  if (!(error instanceof ReviewEngineError)) throw error;
  const body = { code: error.code, message: error.message };
  if (Object.hasOwn(error, 'details')) body.details = error.details;
  return {
    content: [{ type: 'text', text: JSON.stringify(body) }],
    isError: true,
  };
}

const PREFLIGHT_DESCRIPTION = 'Computes a source-bound review contract for the chosen review profile (the profile decides which reviewers run and whether they are paid) and reserves a redacted, expiring preflight identity, without dispatching any request or spending money. Exactly one of source_text or source_path is required.';

const REPEAT_AUTHORIZATION_TEXT = 'When autonomy is on, the FIRST call for a given DOCUMENT (by its raw content, not by preflightId -- re-preflighting the same document does not reset this) is granted directly with no prompt; any SUBSEQUENT call for the same document is refused unless a `justification` object is supplied ({source: "human"|"llm", reason}), and this server\'s own ledger then decides: if the most recent prior review of that document failed, any justification is granted directly (no prompt, no judge); if it succeeded, an "llm" justification is refused and a "human" one opens the real approval prompt; otherwise "human" opens the real approval prompt and "llm" asks a local judge and only proceeds if it agrees. When autonomy is off, every call (first or repeat) opens the prompt.';

const PER_SESSION_DESCRIPTIONS = Object.freeze({
  authorize: 'Binds a prior preflight to a source-bound workflow-budget lease. By default this opens a visible operator approval prompt and creates no lease if the approval is denied or times out. On this per-session server, autonomous authorization is an operator setting in the server\'s environment (OPENROUTER_REVIEW_MCP_AUTONOMOUS_AUTHORIZATION=1); the caller cannot turn it on or off. ' + REPEAT_AUTHORIZATION_TEXT,
  document: 'Runs the reviewers of the lease\'s profile against an active lease, reserving and reconciling spend as it goes, and returns each reviewer\'s verdict and findings (state PASSED, or HALTED with the reason when a reviewer could not complete). This is the one tool that calls the paid OpenRouter API. The call blocks until the review finishes, which can take several minutes. If your client stops waiting first (some clients cut tool calls off after about 60 seconds), the review keeps running and is still billed: do not repeat this call while it may still be running, because a repeat that finds a reviewer still dispatching halts the lease at its worst-case charge. Instead poll openrouter_review_result with the leaseId until every reviewer is RECONCILED. Repeating the call after the lease has finished only recovers its status. Exactly one of source_text or source_path is required.',
});

const SHARED_DESCRIPTIONS = Object.freeze({
  authorize: 'Binds a prior preflight to a source-bound workflow-budget lease on the shared review service. Whether authorization is autonomous is a setting of the shared review installation, chosen by its operator when it was installed; this bridge\'s own environment does not change it, and the caller cannot turn it on or off. When autonomy is off, each call opens a visible operator approval prompt and creates no lease if the approval is denied or times out. ' + REPEAT_AUTHORIZATION_TEXT,
  document: 'Submits the review to the shared review service (or rejoins the request already submitted for identical arguments) and waits up to about 45 seconds. If the review finishes in that time, returns each reviewer\'s verdict and findings (state PASSED, or HALTED with the reason when a reviewer could not complete). Otherwise returns {state: "PENDING", receipt, message}: the review has not failed. If receipt is set, call openrouter_review_request_result with receipt.receiptId until pending is false, or repeat this call with identical arguments; if receipt is null, the service is still accepting the request, so repeat this call. Both rejoin the same request; the service never starts a second review for it. The reviewers are those of the lease\'s profile. Exactly one of source_text or source_path is required.',
});

/**
 * Builds the McpServer with all five tools registered against the given
 * engine. Pure and side-effect free beyond object construction: it neither
 * touches process.stdin/stdout nor constructs a transport, which is what
 * keeps it directly unit-testable in-process as well as over a real stdio
 * child process.
 */
export function createReviewMcpServer(engine) {
  requireEngine(engine);
  const server = new McpServer(SERVER_INFO);
  const sharedMethods = ['submitReview','requestResult','cancelRequest'];
  const sharedCount = sharedMethods.filter(method=>typeof engine[method]==='function').length;
  if (sharedCount !== 0 && sharedCount !== sharedMethods.length) throw new TypeError('shared engine requires all receipt methods');
  // The shared bridge and the per-session server wait for reviews and decide autonomy differently,
  // so the descriptions a caller reads must match the mode it is talking to.
  const text = sharedCount === sharedMethods.length ? SHARED_DESCRIPTIONS : PER_SESSION_DESCRIPTIONS;

  server.registerTool(TOOL_NAMES.PREFLIGHT, {
    title: 'Preflight OpenRouter Review',
    description: PREFLIGHT_DESCRIPTION,
    inputSchema: PREFLIGHT_INPUT_SCHEMA,
    // No outputSchema: @modelcontextprotocol/sdk@1.30.0 stamps its
    // Zod-v4-derived outputSchema JSON with "$schema": draft-07, which some MCP clients' Ajv
    // validators reject outright (2020-12-only, no draft-07 meta-schema loaded) before the tool
    // can even be called. review-engine.mjs's own construction is still the real shape guarantee.
    annotations: {
      title: 'Preflight OpenRouter Review',
      readOnlyHint: true,
      idempotentHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  }, async (args) => {
    try {
      return formatToolResult(await engine.preflight(args));
    } catch (error) {
      return toolErrorFromEngineError(error);
    }
  });

  server.registerTool(TOOL_NAMES.AUTHORIZE_WORKFLOW, {
    title: 'Authorize OpenRouter Review Workflow',
    description: text.authorize,
    inputSchema: AUTHORIZE_WORKFLOW_INPUT_SCHEMA,
    // See PREFLIGHT's registerTool call above for why outputSchema is omitted here.
    annotations: {
      title: 'Authorize OpenRouter Review Workflow',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  }, async (args) => {
    try {
      return formatToolResult(await engine.authorizeWorkflow(args));
    } catch (error) {
      return toolErrorFromEngineError(error);
    }
  });

  server.registerTool(TOOL_NAMES.REVIEW, {
    title: 'Run OpenRouter Review',
    description: text.document,
    inputSchema: REVIEW_INPUT_SCHEMA,
    // See PREFLIGHT's registerTool call above for why outputSchema is omitted here.
    annotations: {
      title: 'Run OpenRouter Review',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  }, async (args) => {
    try {
      return formatToolResult(await engine.review(args));
    } catch (error) {
      return toolErrorFromEngineError(error);
    }
  });

  server.registerTool(TOOL_NAMES.STATUS, {
    title: 'Get OpenRouter Review Lease Status',
    description: 'Reports the redacted lease ledger view (state, requested/reserved/spent USD, jobs consumed) for a given leaseId, without exposing raw source text or provider response bodies.',
    inputSchema: STATUS_INPUT_SCHEMA,
    // See PREFLIGHT's registerTool call above for why outputSchema is omitted here.
    annotations: {
      title: 'Get OpenRouter Review Lease Status',
      readOnlyHint: true,
      idempotentHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  }, async (args) => {
    try {
      return formatToolResult(await engine.status(args));
    } catch (error) {
      return toolErrorFromEngineError(error);
    }
  });

  server.registerTool(TOOL_NAMES.RESULT, {
    title: 'Recover OpenRouter Review Result',
    description: 'Recovers a completed review\'s advisory content (verdict + findings per reviewer) using nothing but the leaseId, independent of any in-process cache -- the correct way to fetch a real answer after openrouter_review_document\'s own response was lost (e.g. a client-side timeout). Never dispatches or spends; safe to call repeatedly from any process at any time.',
    inputSchema: RESULT_INPUT_SCHEMA,
    // See PREFLIGHT's registerTool call above for why outputSchema is omitted here.
    annotations: {
      title: 'Recover OpenRouter Review Result',
      readOnlyHint: true,
      idempotentHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  }, async (args) => {
    try {
      return formatToolResult(await engine.result(args));
    } catch (error) {
      return toolErrorFromEngineError(error);
    }
  });

  if (sharedCount === sharedMethods.length) {
    const tools = [
      [TOOL_NAMES.SUBMIT,'Submit OpenRouter Review','Accepts one source-bound review into the bounded shared queue and returns its durable receipt. Wait for this receipt at the reviewed workflow step; unrelated work may continue. Accepted retries use the original snapshot.',SUBMIT_INPUT_SCHEMA,SUBMIT_OUTPUT_SCHEMA,'submitReview',false],
      [TOOL_NAMES.REQUEST_RESULT,'Get OpenRouter Review Receipt','Returns promptly: {pending: true, receipt} while the review is still running, or the retained terminal result ({pending: false, outcome}). Poll it (for example every 15 to 30 seconds) until pending is false. This read never dispatches a review. A terminal failure does not mean the review passed.',REQUEST_RESULT_INPUT_SCHEMA,REQUEST_RESULT_OUTPUT_SCHEMA,'requestResult',true],
      [TOOL_NAMES.CANCEL,'Cancel OpenRouter Review Request','Requests cancellation for an accepted receipt. Work already dispatched still settles its accounting; cancellation never refunds uncertain calls or starts replacements.',CANCEL_INPUT_SCHEMA,CANCEL_OUTPUT_SCHEMA,'cancelRequest',false],
    ];
    for (const [name,title,description,inputSchema,outputSchema,method,readOnlyHint] of tools) {
      server.registerTool(name,{title,description,inputSchema,annotations:{title,readOnlyHint,idempotentHint:true,destructiveHint:false,openWorldHint:method==='submitReview'}},async args=>{
        try {
          // Canonicalization rejects getters and non-JSON values before schema
          // parsing, so private fields cannot escape through a loose adapter.
          const result=JSON.parse(canonicalJson(await engine[method](args)));
          return formatToolResult(outputSchema.parse(result));
        } catch (error) {
          let fixed = sharedError('REQUEST_FAILED');
          try { fixed = sharedError(Object.getOwnPropertyDescriptor(error, 'code')?.value); }
          catch { /* Unknown engine and adapter diagnostics remain private. */ }
          return {content:[{type:'text',text:JSON.stringify({code:fixed.code,message:fixed.message})}],isError:true};
        }
      });
    }
  }
  return server;
}

// ---------------------------------------------------------------------------
// Production wiring: leaseStore + approvalAdapter come from their own
// constructors (createLeaseStore, createApprovalAdapter); the dispatch adapter
// wrapping tools/openrouter-review-dispatch.ps1 is defined here, following the
// exact same shape createApprovalAdapter (src/local-mcp/adapters.mjs) uses for
// its own one-shot PowerShell worker: write a request file, invoke a fixed
// script path with execFile, read back exactly one line of JSON. No dynamic
// import, no caller-supplied module path, no env-var-selected code -- the
// script path is fixed so nothing outside this file chooses what runs.
// ---------------------------------------------------------------------------

// A direct execFile child of this process -- even with detached:true -- dies
// alongside this Node process when it's killed or replaced (confirmed with a
// controlled, zero-cost experiment). createDispatchAdapter's default target is
// therefore the launcher, not the worker script (openrouter-review-dispatch.ps1)
// directly -- see openrouter-review-dispatch-launcher.ps1's own header for why
// a Windows Scheduled Task (not detached:true, not a WMI-created process, both
// of which also die) is the mechanism that actually survives. The launcher
// itself resolves the worker script's path via $PSScriptRoot, so no
// worker-script-path constant is needed here.
const DISPATCH_LAUNCHER_SCRIPT_PATH = fileURLToPath(new URL('./openrouter-review-dispatch-launcher.ps1', import.meta.url));
// Read-only key-status probe (tools/openrouter-review-key-status.ps1) -- unlike the
// dispatch launcher above, this script is entirely self-contained (no request/response file
// arguments, no Task-Scheduler indirection): it decrypts the DPAPI credential itself, makes one
// GET against /api/v1/key, and always exits 0 with exactly one JSON line, degrading to
// {"limit":null,...} on any internal failure. See tests/openrouter-review-alert-store.test.mjs for
// the source-inspection proof it never prints the credential.
const KEY_STATUS_SCRIPT_PATH = fileURLToPath(new URL('./openrouter-review-key-status.ps1', import.meta.url));
const execFile = promisify(execFileCallback);

// A full structured-JSON code review over up to ~2MB of source text can run
// for several minutes -- a far heavier workload than the 3-call arithmetic
// sanity check, which uses a 120000ms `request_timeout_ms`.
// 600 s leaves headroom for it; the
// timestamped dispatch logging shows how long real dispatches take.
// Operator-overridable via OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS (see
// resolveProductionEngineConfig).
const DEFAULT_DISPATCH_TIMEOUT_MS = 600_000;

// OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS is RETIRED, and so is the 90 s default it
// overrode. Both bounded main()'s own startup ownership acquire,
// and main() no longer acquires at startup: ownership is taken on demand by the first owner-sensitive
// tool call (an "arm"), whose budget is OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS below, defaulting to
// ownership-coordinator.mjs's DEFAULT_ARM_TIMEOUT_MS. The retired value is deliberately NOT reused as
// the arm budget: that would silently change the meaning of a number an operator already chose for a
// different wait. A still-set value only produces one startup warning line.
//
// Why it is retired: a 90 s startup acquire is longer than a typical MCP client's own connect timeout
// (30 s for some clients). A second server started while a first was alive spent the whole window
// polling LIVE_OWNER, the client gave up first with a bare CONNECT_TIMEOUT, and a client session whose
// first connect fails may never retry. Lowering the budget only made that failure faster; not
// acquiring at startup is what removes it.

// Budget awaitDrain() gets to let already-admitted owner-sensitive work finish before the shutdown
// sequence decides between releasing process ownership cleanly and exiting with work outstanding.
// Operator-overridable via OPENROUTER_REVIEW_MCP_SHUTDOWN_DRAIN_TIMEOUT_MS.
const DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_MS = 30_000;

/**
 * Wraps the one-shot tools/openrouter-review-dispatch.ps1 worker as a
 * `dispatchAdapter` (see review-engine.mjs's own docstring for the exact
 * `dispatch({ requestBytes, jobId, reviewerId }) -> { kind, envelopeJsonText }`
 * contract). Writes requestBytes to a per-job temp file under
 * `<dataRoot>/dispatch-requests/`, invokes the script with that path and a
 * computed deadline, parses the script's single stdout JSON line, and -- unlike
 * the approval adapter's redacted, intentionally-retained request file --
 * always deletes its own request file afterward, because unlike an approval
 * request (which strips source_text by construction, see adapters.mjs's
 * FORBIDDEN_FIELD check), a dispatch request body necessarily contains the
 * full review source and prompt text, which should not accumulate on disk.
 * This module never reads or decrypts the credential itself; only the script
 * does, and only when actually invoked by a real `review()` call.
 */
/**
 * Timestamped, single-line stderr diagnostics for dispatch, the part of this
 * codebase where a slow or lost request is hardest to diagnose after the fact
 * (see the DEFAULT_DISPATCH_TIMEOUT_MS comment above): start/done/error,
 * always including reviewerId + jobId + elapsedMs so a slow or hung reviewer
 * can be localized from logs alone, without repeating a paid request to find
 * out where the time went. `log` is injectable (matches every other adapter's DI
 * pattern in this file/adapters.mjs) so tests can assert on it directly
 * instead of capturing real stderr; the default target is process.stderr.write,
 * per this file's own standing rule that stdout carries only JSON-RPC.
 */
function defaultDispatchLog(message) {
  process.stderr.write(`${message}\n`);
}

export function createDispatchAdapter({
  dataRoot,
  scriptPath = DISPATCH_LAUNCHER_SCRIPT_PATH,
  powershellPath = 'powershell.exe',
  execute = execFile,
  clock = () => Date.now(),
  timeoutMs = DEFAULT_DISPATCH_TIMEOUT_MS,
  log = defaultDispatchLog,
  dispatchOutcomeStore = createDispatchOutcomeStore({ dataRoot }),
} = {}) {
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) throw new TypeError('dataRoot is required');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  if (typeof execute !== 'function') throw new TypeError('execute must be a function');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be a positive safe integer');
  if (typeof log !== 'function') throw new TypeError('log must be a function');
  if (typeof dispatchOutcomeStore !== 'object' || dispatchOutcomeStore === null || typeof dispatchOutcomeStore.markDispatching !== 'function') {
    throw new TypeError('dispatchOutcomeStore must provide a markDispatching function');
  }
  const requestRoot = join(dataRoot, 'dispatch-requests');
  const outcomeRoot = join(dataRoot, 'dispatch-outcomes');

  return Object.freeze({
    // `notAfterMs`, when supplied, is the caller's (review-engine.mjs's) own
    // authorization-derived ceiling -- the lease's fixed expiresAt, as an
    // ABSOLUTE epoch-ms timestamp, so a dispatch can never outlive the
    // authorization that admitted it. It is deliberately NOT a pre-subtracted
    // relative duration, which would be unsafe --
    // computing the effective timeout from a relative duration BEFORE this
    // function's own mkdir/writeFile I/O, then adding it to a `startedAtMs`
    // sampled AFTER that I/O, silently pushed the real deadline later by
    // however long every intervening await took (this function's own I/O,
    // plus the caller's leaseStore.consume() before dispatch() was even
    // called). Anchoring to a fixed absolute instant and re-deriving the
    // effective timeout from a FRESH clock() read taken after this
    // function's own I/O eliminates that drift by construction: whatever
    // time already elapsed is naturally subtracted, never granted back.
    // It only ever TIGHTENS the effective deadline, never loosens it past
    // this adapter's own configured `timeoutMs` -- a caller cannot use it to
    // authorize more time than the operator configured, only less -- and
    // clamps at zero rather than going negative if the deadline has already
    // passed by the time this function gets to it, which then flows into
    // the dispatch script's own pre-existing DEADLINE_EXCEEDED failure path.
    async dispatch({ requestBytes, jobId, reviewerId, notAfterMs }) {
      if (!Buffer.isBuffer(requestBytes)) throw new TypeError('requestBytes must be a Buffer');
      if (typeof jobId !== 'string' || jobId.length === 0) throw new TypeError('jobId must be a non-empty string');
      if (notAfterMs !== undefined && !Number.isSafeInteger(notAfterMs)) {
        throw new TypeError('notAfterMs must be a safe integer epoch-ms timestamp when provided');
      }
      await mkdir(requestRoot, { recursive: true });
      const requestPath = join(requestRoot, `${jobId}-${randomUUID()}.json`);
      await writeFile(requestPath, requestBytes);
      // Durable-capture destination (see dispatch-outcome-store.mjs and the
      // matching write in openrouter-review-dispatch.ps1's
      // Write-OpenRouterOutcomeAtomic): the script writes its own outcome
      // here the instant it has one, before ever returning on stdout, so a
      // later process can recover it if THIS process dies before reading
      // stdout. mkdir here (not left to the script) so a missing directory
      // can never itself be the reason the script's own best-effort write
      // silently no-ops.
      await mkdir(outcomeRoot, { recursive: true });
      const responsePath = dispatchOutcomePath({ dataRoot, jobId });
      const startedAtMs = Number(clock());
      const effectiveTimeoutMs = notAfterMs === undefined
        ? timeoutMs
        : Math.max(0, Math.min(timeoutMs, notAfterMs - startedAtMs));
      const label = `jobId=${jobId} reviewerId=${reviewerId ?? 'unknown'} timeoutMs=${effectiveTimeoutMs}`;
      log(`openrouter-review-dispatch: start ${label}`);
      // This Node process can itself be killed or replaced between the mkdir
      // above and the execute() call below, leaving a request file on disk
      // while the PowerShell script was never even spawned. Writing this
      // marker HERE, immediately before execute(), is what lets a later
      // recovery attempt (review-engine.mjs's existingJob/RESERVED branch)
      // prove the negative -- "no marker at all" means dispatch() genuinely
      // never got this far, so redispatching carries zero risk of a
      // duplicate OpenRouter call.
      //
      // NOT best-effort: a swallowed failure here, followed by execute() running
      // anyway, would make "no marker" a false proof -- exactly the risk of
      // a real duplicate OpenRouter call this marker exists to prevent. This
      // call is a HARD precondition: its failure (a genuine disk error, or
      // losing the exclusive-claim race to a concurrent dispatch attempt for
      // the SAME jobId -- see dispatch-outcome-store.mjs's `flag: 'wx'`,
      // which throws EEXIST rather than ever overwriting) must abort this
      // whole attempt before execute() is ever called, not after. Folded
      // into the same try/catch/finally as execute() below so it gets
      // identical error-logging, rethrow, and request-file cleanup --
      // review-engine.mjs's existing "dispatch threw" handling (halt at
      // worst-case, never redispatch) already covers this safely, the exact
      // same way it already covers a genuinely ambiguous DISPATCHING marker.
      let claimedDispatch = false;
      try {
        await dispatchOutcomeStore.markDispatching({ jobId });
        claimedDispatch = true;
        const deadlineUtc = new Date(startedAtMs + effectiveTimeoutMs).toISOString();
        const { stdout } = await execute(
          powershellPath,
          ['-NoProfile', '-File', scriptPath, requestPath, deadlineUtc, responsePath],
          {
            windowsHide: true,
            // Best-effort: lets the PowerShell child continue running (and
            // reach its OWN durable outcome write, see
            // openrouter-review-dispatch.ps1's Write-OpenRouterOutcomeAtomic)
            // even if this Node process is itself killed/replaced mid-flight.
            // Not verified to survive every platform's process/job-object
            // teardown behavior (unlike the marker above,
            // which is provably correct regardless of platform specifics) --
            // documented as an accepted, unverified defense-in-depth measure,
            // not a confirmed fix on its own.
            detached: true,
            maxBuffer: 32 * 1024 * 1024,
            // Backstop only: the script bounds its own HTTP call against
            // deadlineUtc internally. This kills the PowerShell process itself
            // if it hangs before ever reaching that internal deadline check
            // (e.g. stuck on process startup or module load), with headroom
            // added so it never fires ahead of the script's own deadline.
            timeout: effectiveTimeoutMs + 30_000,
          },
        );
        const elapsedMs = Number(clock()) - startedAtMs;
        const line = String(stdout).split('\n').map((candidate) => candidate.trim()).find((candidate) => candidate.length > 0);
        if (!line) {
          log(`openrouter-review-dispatch: empty-stdout ${label} elapsedMs=${elapsedMs}`);
          throw new Error('the dispatch worker produced no stdout line');
        }
        const parsed = JSON.parse(line);
        log(`openrouter-review-dispatch: done ${label} elapsedMs=${elapsedMs} kind=${parsed.kind}`);
        return parsed;
      } catch (error) {
        const elapsedMs = Number(clock()) - startedAtMs;
        if (!claimedDispatch) {
          log(`openrouter-review-dispatch: mark-dispatching-failed ${label} elapsedMs=${elapsedMs} message=${safeErrorDetail(error)}`);
        } else {
          log(`openrouter-review-dispatch: error ${label} elapsedMs=${elapsedMs} killed=${Boolean(error && error.killed)} message=${safeErrorDetail(error)}`);
        }
        throw error;
      } finally {
        await rm(requestPath, { force: true }).catch(() => {});
      }
    },
  });
}

// Read-only probe timeout: this is a single, tiny GET against OpenRouter's own /api/v1/key,
// nothing like the size or cost of a real review dispatch, so a short, fixed timeout is
// appropriate -- no operator override exists for this one (unlike DEFAULT_DISPATCH_TIMEOUT_MS),
// deliberately: a slow/hung key-status check must never be allowed to meaningfully delay a real
// document() call, so it stays short and fixed rather than growing an env-var surface for a
// best-effort side probe.
const DEFAULT_KEY_STATUS_TIMEOUT_MS = 20_000;

// The shape check-status callers actually rely on: exactly the three fields the PS script's own
// header docstring promises, everything else (an extra field, a wrong type) treated as
// untrustworthy and degraded the same way a transport failure already is.
function isValidKeyStatus(value) {
  return value !== null
    && typeof value === 'object'
    && (value.limit === null || typeof value.limit === 'number')
    && (value.limitRemaining === null || typeof value.limitRemaining === 'number')
    && (value.limitReset === null || typeof value.limitReset === 'string');
}

const UNKNOWN_KEY_STATUS = Object.freeze({ limit: null, limitRemaining: null, limitReset: null });

/**
 * Wraps the read-only tools/openrouter-review-key-status.ps1 probe as a
 * `keyStatusProbe` for review-engine.mjs: `check() -> { limit, limitRemaining, limitReset }`.
 * Unlike createDispatchAdapter above, this never writes a request file, never touches
 * dispatchOutcomeStore, and never needs a jobId/deadline -- the script itself is a single,
 * parameterless, side-effect-free GET, so this wrapper is intentionally much thinner.
 *
 * Matches the script's own graceful-degradation contract: any failure on this side (spawn error,
 * empty/malformed/wrong-shaped stdout, a thrown rejection of any shape) degrades to
 * `UNKNOWN_KEY_STATUS` rather than throwing. This is a best-effort side probe for a proactive
 * spend alert, never part of the money-safety-critical path -- a caller (review-engine.mjs) must
 * be able to treat "unknown" as simply "cannot compute a percentage yet," never as a reason a real
 * review() call should fail.
 */
export function createKeyStatusProbeAdapter({
  scriptPath = KEY_STATUS_SCRIPT_PATH,
  powershellPath = 'powershell.exe',
  execute = execFile,
  timeoutMs = DEFAULT_KEY_STATUS_TIMEOUT_MS,
} = {}) {
  if (typeof execute !== 'function') throw new TypeError('execute must be a function');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be a positive safe integer');

  return Object.freeze({
    async check() {
      try {
        const { stdout } = await execute(
          powershellPath,
          ['-NoProfile', '-File', scriptPath],
          { windowsHide: true, timeout: timeoutMs, maxBuffer: 1024 * 1024 },
        );
        const line = String(stdout).split('\n').map((candidate) => candidate.trim()).find((candidate) => candidate.length > 0);
        if (!line) return UNKNOWN_KEY_STATUS;
        const parsed = JSON.parse(line);
        return isValidKeyStatus(parsed) ? parsed : UNKNOWN_KEY_STATUS;
      } catch {
        // Deliberately swallows every failure shape (a thrown Error, a rejected non-Error value,
        // a JSON.parse SyntaxError) -- see this function's own docstring for why.
        return UNKNOWN_KEY_STATUS;
      }
    },
  });
}

// Directly reuses tools/openrouter-review-dispatch.ps1's own already-reviewed
// $script:MaxRequestBytes constant (4194304) as this process's
// preflightPolicy.maxRequestBytes, instead of inventing a second figure that
// could silently drift from the one the dispatch worker actually enforces.
const MAX_REQUEST_BYTES = 4_194_304;
// Raw source text is wrapped in a system prompt, JSON-schema literals, and
// request framing before it becomes a request body, so this stays well under
// MAX_REQUEST_BYTES to leave headroom for that overhead.
const MAX_SOURCE_BYTES = 2_000_000;

// Reads an operator-maintained identity list from the path in
// OPENROUTER_REVIEW_MCP_IDENTITY_LIST_PATH (IDENTITY_LIST_PATH_ENV_VAR below);
// a missing or empty list fails closed at startup (loadIdentityList below).
// Do not embed a machine path.
const SCRUB_MAPPING_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Exported for direct testing against any path. Fails closed on BOTH halves
 * the module comment above claims: a missing/unreadable file throws via
 * readFile's own ENOENT (never caught here), and an existing-but-empty (or
 * comment/blank-line-only) file throws explicitly too. Without this check, an
 * operator-maintained file truncated or accidentally saved empty would parse
 * to [] and let the server start
 * with identity-based matching (findIdentityIntervals/matchesIdentityList in
 * scrub-engine.mjs) silently disabled -- exactly the degraded-scrub-engine
 * scenario this whole fail-closed check exists to prevent.
 */
export async function loadIdentityList(path) {
  const text = await readFile(path, 'utf8');
  const entries = text.split('\n').map((line) => line.trim()).filter((line) => line.length > 0 && !line.startsWith('#'));
  if (entries.length === 0) throw new Error(`identity list at ${path} is empty`);
  return entries;
}

/**
 * Loads the owner-supplied extra protected terms named by the resolved
 * setting (resolveExtraProtectedTermsSetting below). `{ kind: 'none' }` is the
 * explicit choice of no extra terms. For `{ kind: 'file', path, sha256 }`
 * this reads the file, refuses it unless its exact bytes hash to the pinned
 * SHA-256, and parses it (scrub-patterns.mjs parseExtraProtectedTerms). Every
 * failure -- a missing or unreadable file, changed bytes, an oversized or
 * malformed file -- throws, so main() refuses to start rather than starting
 * with the owner's terms silently missing. No error message carries a term
 * or the file's location: each names the setting to fix instead (the path is
 * the owner's private choice, and startup errors reach client logs).
 */
export async function loadExtraProtectedTerms(setting) {
  if (setting === null || typeof setting !== 'object') throw new TypeError('extra protected terms setting is required');
  if (setting.kind === 'none') return NO_EXTRA_PROTECTED_TERMS;
  if (setting.kind !== 'file' || typeof setting.path !== 'string' || typeof setting.sha256 !== 'string') {
    throw new TypeError('extra protected terms setting is not recognized');
  }
  const named = `the extra protected terms file named by ${EXTRA_PROTECTED_TERMS_PATH_ENV_VAR}`;
  let bytes;
  try {
    bytes = await readFile(setting.path);
  } catch (error) {
    // The native error message embeds the path, so only its code is kept.
    const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{1,31}$/.test(error.code) ? error.code : 'ERROR';
    throw new Error(`${named} could not be read (${code}); the server will not start without it`);
  }
  try {
    if (bytes.byteLength > EXTRA_PROTECTED_TERMS_MAX_BYTES) {
      throw new Error(`${named} exceeds ${EXTRA_PROTECTED_TERMS_MAX_BYTES} bytes`);
    }
    if (createHash('sha256').update(bytes).digest('hex') !== setting.sha256) {
      throw new Error(`${named} does not match ${EXTRA_PROTECTED_TERMS_SHA256_ENV_VAR}; it was changed or the pinned hash is wrong, so the server will not start without it`);
    }
    try {
      return parseExtraProtectedTerms(bytes);
    } catch (error) {
      // parseExtraProtectedTerms messages name at most a line number, never a term.
      throw new Error(`${named} is malformed: ${error.message}`);
    }
  } finally {
    bytes.fill(0);
  }
}

/**
 * Bounded-lifetime cleanup for scrub mappings that outlived a normal
 * delete-on-success (an abandoned review, a crash before result() ever ran).
 * Exported for direct testing without spinning up the whole server.
 */
export async function sweepStaleScrubMappings({ scrubMappingStore, maxAgeMs = SCRUB_MAPPING_MAX_AGE_MS }) {
  const cutoffIso = new Date(Date.now() - maxAgeMs).toISOString();
  const stalePreflightIds = await scrubMappingStore.listStaleBefore(cutoffIso);
  for (const preflightId of stalePreflightIds) {
    // eslint-disable-next-line no-await-in-loop
    await scrubMappingStore.deleteMapping({ preflightId });
  }
  return stalePreflightIds.length;
}

const INSTALLATION_HARD_MAXIMUM_ENV_VAR = 'OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD';
const DATA_ROOT_ENV_VAR = 'OPENROUTER_REVIEW_MCP_DATA_ROOT';
const ALLOWED_ROOTS_ENV_VAR = 'OPENROUTER_REVIEW_MCP_ALLOWED_ROOTS';
const DISPATCH_TIMEOUT_ENV_VAR = 'OPENROUTER_REVIEW_MCP_DISPATCH_TIMEOUT_MS';
const PREFLIGHT_TTL_ENV_VAR = 'OPENROUTER_REVIEW_MCP_PREFLIGHT_TTL_MS';
const ORPHAN_SWEEP_GRACE_ENV_VAR = 'OPENROUTER_REVIEW_MCP_ORPHAN_SWEEP_GRACE_MS';
const HEALTH_VERDICT_GRACE_ENV_VAR = 'OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_GRACE_MS';
const HEALTH_VERDICT_BACKSTOP_ENV_VAR = 'OPENROUTER_REVIEW_MCP_HEALTH_VERDICT_BACKSTOP_MS';
// RETIRED: kept only so resolveProductionEngineConfig can warn that it is still set. It is never
// parsed; see RETIRED_ACQUIRE_TIMEOUT_WARNING below.
const ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_ENV_VAR = 'OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS';
// The budget for one on-demand arm, and the arming loop's base retry
// interval (the store stretches it by each attempt's measured cost and jitters it). Their defaults are
// DEFAULT_ARM_TIMEOUT_MS / DEFAULT_ARM_LOCK_RETRY_MS, imported from ownership-coordinator.mjs rather
// than re-typed here, so the server and the engine cannot drift apart.
const ARM_TIMEOUT_ENV_VAR = 'OPENROUTER_REVIEW_MCP_ARM_TIMEOUT_MS';
const ARM_LOCK_RETRY_ENV_VAR = 'OPENROUTER_REVIEW_MCP_ARM_LOCK_RETRY_MS';
const RETIRED_ACQUIRE_TIMEOUT_WARNING = `${ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_ENV_VAR} is set, but it no longer does anything: this server no longer takes process ownership at startup, so there is no startup wait for it to bound, and it is not used as the on-demand ownership budget either (that is ${ARM_TIMEOUT_ENV_VAR}). Delete it from this MCP client's server configuration.`;
const SHUTDOWN_DRAIN_TIMEOUT_ENV_VAR = 'OPENROUTER_REVIEW_MCP_SHUTDOWN_DRAIN_TIMEOUT_MS';
// The identity-list path. Required: there is no built-in default path. Being an env var also lets a
// test point the real entry point at a fixture list: the startup-failure test needs a failure source
// located after main() has built its ownership handle, and the real-entry tests need a hermetic list
// rather than an operator's real one.
const IDENTITY_LIST_PATH_ENV_VAR = 'OPENROUTER_REVIEW_MCP_IDENTITY_LIST_PATH';
// Owner-supplied extra protected terms. Mandatory, with no default: the path variable must be the literal
// "none" or an absolute file path, and a path must come with the SHA-256 of the file's exact bytes.
const EXTRA_PROTECTED_TERMS_PATH_ENV_VAR = 'OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_PATH';
const EXTRA_PROTECTED_TERMS_SHA256_ENV_VAR = 'OPENROUTER_REVIEW_MCP_EXTRA_PROTECTED_TERMS_SHA256';
const OLLAMA_BASE_URL_ENV_VAR = 'OPENROUTER_REVIEW_MCP_OLLAMA_URL';
const OLLAMA_MODEL_ENV_VAR = 'OPENROUTER_REVIEW_MCP_OLLAMA_MODEL';
const OLLAMA_TIMEOUT_ENV_VAR = 'OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS';
const DAILY_PAID_JOB_ALLOWANCE_ENV_VAR = 'OPENROUTER_REVIEW_MCP_DAILY_PAID_JOB_ALLOWANCE';
const DEFAULT_DAILY_PAID_JOB_ALLOWANCE = 20;
const AUTONOMOUS_AUTHORIZATION_ENV_VAR = 'OPENROUTER_REVIEW_MCP_AUTONOMOUS_AUTHORIZATION';

// Opt-in, and only on an exact '1'. Anything else -- unset, empty, 'true', 'yes', a typo --
// leaves the live human approval gate in place. A guardrail this important must never be
// removed by a value someone did not mean to set.
function resolveAutonomousAuthorization(env = process.env) {
  return env[AUTONOMOUS_AUTHORIZATION_ENV_VAR] === '1';
}

export function resolveDailyPaidJobAllowance(env = process.env) {
  const raw = env[DAILY_PAID_JOB_ALLOWANCE_ENV_VAR];
  if (raw === undefined || raw === '') return DEFAULT_DAILY_PAID_JOB_ALLOWANCE;
  const parsed = Number(raw);
  // Fail closed and loudly: a typo here would otherwise silently widen a spend guardrail.
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TypeError(`${DAILY_PAID_JOB_ALLOWANCE_ENV_VAR} must be a positive integer`);
  }
  return parsed;
}

const CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD_ENV_VAR = 'OPENROUTER_REVIEW_MCP_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD';

// Same {env-override, fail-closed-on-garbage} shape as resolveDailyPaidJobAllowance above, for
// the consecutive-dispatch-failure health alert's threshold (see review-engine.mjs's own
// DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD for the justification behind the default
// value itself). An operator-settable env var, not just a constructor default, so a human can tune
// it without a code change -- mirrors every other operator-tunable constant in this file
// (dispatch timeout, preflight TTL, orphan sweep grace, daily paid job allowance).
export function resolveConsecutiveDispatchFailureAlertThreshold(env = process.env) {
  const raw = env[CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD_ENV_VAR];
  if (raw === undefined || raw === '') return DEFAULT_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD;
  const parsed = Number(raw);
  // Same upper bound as createReviewEngine's own constructor validation (see
  // MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD in review-engine.mjs) -- checked here too so
  // a misconfigured env var fails at server startup with a clear reason, not only once this value
  // reaches the engine constructor.
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD) {
    throw new TypeError(`${CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD_ENV_VAR} must be a positive integer no greater than ${MAX_CONSECUTIVE_DISPATCH_FAILURE_ALERT_THRESHOLD}`);
  }
  return parsed;
}

// Defaults for the scrub engine's local Ollama classifier calls (see
// ollama-client.mjs and scrub-engine.mjs's checkUnknownThirdPartyPii /
// checkReidentifiable). Default local classifier model; override with
// OPENROUTER_REVIEW_MCP_OLLAMA_MODEL.
//
// The timeout is generous because ONE local classification of a large
// markdown document can take minutes, especially while the GPU is contended;
// a short wall would abort an alive, working model mid-inference and the
// scrub engine would report the result as a blocked send. 300s is not a
// licence to hang:
// a genuinely DOWN Ollama fails by immediate connection refusal, not by
// timeout, so this ceiling only ever bounds a real hang -- it never slows the
// outage path. Override with OPENROUTER_REVIEW_MCP_OLLAMA_TIMEOUT_MS on a
// faster or slower host.
const DEFAULT_OLLAMA_BASE_URL = 'http://localhost:11434';
const DEFAULT_OLLAMA_MODEL = 'qwen2.5:7b';
const DEFAULT_OLLAMA_TIMEOUT_MS = 300_000;

// Matches review-engine.mjs's own createReviewEngine default and rationale
// for orphanSweepGraceMs: 4x the dispatch adapter's own ~30s
// worst-case execFile-backstop overshoot past a lease's expiresAt, so
// recovery never races a dispatch that may still be legitimately finishing.
const DEFAULT_ORPHAN_SWEEP_GRACE_MS = 120_000;

// Mirrors review-engine.mjs's own createReviewEngine defaults for these two constructor options
// EXACTLY (6 min / 1 hr) -- leaving both env vars unset must reproduce today's behavior
// byte-for-byte, not a new, independently-chosen default.
const DEFAULT_HEALTH_VERDICT_GRACE_MS = 6 * 60 * 1000;
const DEFAULT_HEALTH_VERDICT_BACKSTOP_MS = 60 * 60 * 1000;

// review-engine.mjs's own default preflightTtlMs (15 min) is too short for
// the worst-case sequential two-reviewer dispatch under the dispatch timeout
// above (~1,260,000ms / 21 min). 1,800,000ms (30 min) covers a worst-case
// sequential two-reviewer dispatch with headroom. Genuine safety against a dispatch
// outliving this window regardless of its value is enforced separately in
// review-engine.mjs's review() (see its own comment on the fixed absolute
// deadline passed to dispatchAdapter.dispatch as `notAfterMs`); this default exists
// so the common, expected-slow case actually succeeds instead of routinely
// hitting LEASE_EXPIRED.
const DEFAULT_PREFLIGHT_TTL_MS = 1_800_000;

/**
 * Shared parse/validate shape for an optional, positive-integer-milliseconds
 * env var override with a safe default: unset uses `defaultValueMs`; set to
 * an unparseable, fractional, or non-positive value fails closed (`ok:false`)
 * rather than silently falling back or crashing later inside engine
 * construction (createDispatchAdapter's own constructor requires
 * Number.isSafeInteger, so accepting any finite positive number here would let
 * e.g. "1.5" pass and then throw deep inside buildProductionEngine instead of
 * failing cleanly at config resolution).
 */
function parsePositiveIntegerMsOverride(env, varName, defaultValueMs) {
  const raw = env[varName];
  if (typeof raw !== 'string' || raw.trim().length === 0) return { ok: true, value: defaultValueMs };
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return { ok: false, reason: `${varName} must be a positive integer number of milliseconds; got ${JSON.stringify(raw)}.` };
  }
  return { ok: true, value: parsed };
}

/**
 * Same {ok, value|reason} shape as parsePositiveIntegerMsOverride above, for
 * a plain non-empty-string override (Ollama base URL / model) instead of a
 * numeric one: unset or whitespace-only uses `defaultValue`; anything else
 * is used verbatim (trimmed). There is no separate "invalid shape" to fail
 * closed on for an opaque string the way there is for a number -- the
 * unset-vs-set distinction is the whole check -- but the shape is kept
 * identical to the numeric helper so every override in
 * resolveProductionEngineConfig reads and fails the same way.
 */
function parseNonEmptyStringOverride(env, varName, defaultValue) {
  const raw = env[varName];
  if (typeof raw !== 'string' || raw.trim().length === 0) return { ok: true, value: defaultValue };
  return { ok: true, value: raw.trim() };
}

/**
 * Resolves the configuration a real, running server needs, entirely from
 * environment variables set by whoever launches `npm run mcp:start` -- never
 * from a caller-supplied module path or any other code-selecting mechanism.
 *
 * `installationHardMaximumUsd` (the ceiling review-engine.mjs enforces before
 * any approval prompt even opens) has NO default: picking a real-money spend
 * ceiling is a decision only the operator can make, so this code never
 * invents one. A missing value is therefore treated as "not configured yet"
 * rather than silently defaulted, and `main()` fails cleanly (stderr-only,
 * non-zero exit, no transport touched) -- the unconfigured state is safe by
 * default, and a properly configured operator gets a working stdio MCP
 * server.
 *
 * `dataRoot` and `allowedRoots` have safe defaults: `dataRoot` falls back to
 * the already-documented `%LOCALAPPDATA%\OpenRouterReviewMcp`, and
 * `allowedRoots` defaults to an empty list, which does not block startup --
 * it only means `source_path` calls fail with a clear SOURCE_INVALID error
 * (loadReviewSource requires a non-empty allowedRoots) until the operator
 * opts a directory in. `source_text` calls are unaffected either way.
 *
 * On success the result also carries `warnings`, an array of operator-facing
 * notices that never fail startup -- today only a still-set, retired
 * OPENROUTER_REVIEW_MCP_ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_MS. `main()` prints
 * each one as a single `openrouter-review-mcp-server: warning:` line.
 */
/**
 * Resolves the mandatory extra-protected-terms setting from the environment. Unset or blank is refused
 * (never read as "no extra terms"); "none" must not carry a hash; a path must be absolute and pinned by a
 * 64-hex SHA-256 (either case accepted, as Get-FileHash prints upper case).
 */
function resolveExtraProtectedTermsSetting(env) {
  const rawPath = env[EXTRA_PROTECTED_TERMS_PATH_ENV_VAR];
  const rawSha = env[EXTRA_PROTECTED_TERMS_SHA256_ENV_VAR];
  const shaSet = typeof rawSha === 'string' && rawSha.trim().length > 0;
  if (typeof rawPath !== 'string' || rawPath.trim().length === 0) {
    return {
      ok: false,
      reason: `${EXTRA_PROTECTED_TERMS_PATH_ENV_VAR} is not set. Set it to none for no extra protected terms, or to the absolute path of the owner's extra-protected-terms file together with ${EXTRA_PROTECTED_TERMS_SHA256_ENV_VAR}. It has no default, so a forgotten setting cannot silently drop protected terms.`,
    };
  }
  const path = rawPath.trim();
  if (path === 'none') {
    if (shaSet) return { ok: false, reason: `${EXTRA_PROTECTED_TERMS_SHA256_ENV_VAR} must not be set when ${EXTRA_PROTECTED_TERMS_PATH_ENV_VAR} is none.` };
    return { ok: true, value: Object.freeze({ kind: 'none' }) };
  }
  if (!isAbsolute(path)) {
    return { ok: false, reason: `${EXTRA_PROTECTED_TERMS_PATH_ENV_VAR} must be none or an absolute path.` };
  }
  const sha = shaSet ? rawSha.trim() : '';
  if (!/^[0-9a-fA-F]{64}$/.test(sha)) {
    return { ok: false, reason: `${EXTRA_PROTECTED_TERMS_SHA256_ENV_VAR} must be the 64-hex SHA-256 of the file named by ${EXTRA_PROTECTED_TERMS_PATH_ENV_VAR}.` };
  }
  return { ok: true, value: Object.freeze({ kind: 'file', path, sha256: sha.toLowerCase() }) };
}

export function resolveProductionEngineConfig(env = process.env) {
  const rawMax = env[INSTALLATION_HARD_MAXIMUM_ENV_VAR];
  if (typeof rawMax !== 'string' || rawMax.trim().length === 0) {
    return {
      ok: false,
      reason: `${INSTALLATION_HARD_MAXIMUM_ENV_VAR} is not set. This is the operator-chosen hard ceiling, in USD, on any single preflight-authorized workflow -- a spend decision this server will not make on its own. Set it in the environment that launches "npm run mcp:start" and retry.`,
    };
  }
  const installationHardMaximumUsd = Number(rawMax);
  if (!Number.isFinite(installationHardMaximumUsd) || installationHardMaximumUsd < 0) {
    return {
      ok: false,
      reason: `${INSTALLATION_HARD_MAXIMUM_ENV_VAR} must be a finite non-negative number in USD; got ${JSON.stringify(rawMax)}.`,
    };
  }

  const dataRoot = env[DATA_ROOT_ENV_VAR]
    ?? (env.LOCALAPPDATA ? join(env.LOCALAPPDATA, 'OpenRouterReviewMcp') : undefined);
  if (typeof dataRoot !== 'string' || dataRoot.length === 0) {
    return {
      ok: false,
      reason: `no data root could be resolved: set ${DATA_ROOT_ENV_VAR} explicitly (neither it nor %LOCALAPPDATA% is set).`,
    };
  }

  const allowedRoots = (env[ALLOWED_ROOTS_ENV_VAR] ?? '')
    .split(';')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  // Unset falls back to each constant's own default (see their comments for
  // why). Unlike the spend ceiling above, both have safe defaults and are not
  // mandatory -- only an explicitly-set, unparseable/non-integer/non-positive
  // value fails closed.
  const dispatchTimeoutResolved = parsePositiveIntegerMsOverride(env, DISPATCH_TIMEOUT_ENV_VAR, DEFAULT_DISPATCH_TIMEOUT_MS);
  if (!dispatchTimeoutResolved.ok) return dispatchTimeoutResolved;
  const preflightTtlResolved = parsePositiveIntegerMsOverride(env, PREFLIGHT_TTL_ENV_VAR, DEFAULT_PREFLIGHT_TTL_MS);
  if (!preflightTtlResolved.ok) return preflightTtlResolved;
  const orphanSweepGraceResolved = parsePositiveIntegerMsOverride(env, ORPHAN_SWEEP_GRACE_ENV_VAR, DEFAULT_ORPHAN_SWEEP_GRACE_MS);
  if (!orphanSweepGraceResolved.ok) return orphanSweepGraceResolved;
  const healthVerdictGraceResolved = parsePositiveIntegerMsOverride(env, HEALTH_VERDICT_GRACE_ENV_VAR, DEFAULT_HEALTH_VERDICT_GRACE_MS);
  if (!healthVerdictGraceResolved.ok) return healthVerdictGraceResolved;
  const healthVerdictBackstopResolved = parsePositiveIntegerMsOverride(env, HEALTH_VERDICT_BACKSTOP_ENV_VAR, DEFAULT_HEALTH_VERDICT_BACKSTOP_MS);
  if (!healthVerdictBackstopResolved.ok) return healthVerdictBackstopResolved;
  const armTimeoutResolved = parsePositiveIntegerMsOverride(env, ARM_TIMEOUT_ENV_VAR, DEFAULT_ARM_TIMEOUT_MS);
  if (!armTimeoutResolved.ok) return armTimeoutResolved;
  const armLockRetryResolved = parsePositiveIntegerMsOverride(env, ARM_LOCK_RETRY_ENV_VAR, DEFAULT_ARM_LOCK_RETRY_MS);
  if (!armLockRetryResolved.ok) return armLockRetryResolved;
  const shutdownDrainTimeoutResolved = parsePositiveIntegerMsOverride(env, SHUTDOWN_DRAIN_TIMEOUT_ENV_VAR, DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_MS);
  if (!shutdownDrainTimeoutResolved.ok) return shutdownDrainTimeoutResolved;
  const ollamaBaseUrlResolved = parseNonEmptyStringOverride(env, OLLAMA_BASE_URL_ENV_VAR, DEFAULT_OLLAMA_BASE_URL);
  if (!ollamaBaseUrlResolved.ok) return ollamaBaseUrlResolved;
  const ollamaModelResolved = parseNonEmptyStringOverride(env, OLLAMA_MODEL_ENV_VAR, DEFAULT_OLLAMA_MODEL);
  if (!ollamaModelResolved.ok) return ollamaModelResolved;
  const ollamaTimeoutResolved = parsePositiveIntegerMsOverride(env, OLLAMA_TIMEOUT_ENV_VAR, DEFAULT_OLLAMA_TIMEOUT_MS);
  if (!ollamaTimeoutResolved.ok) return ollamaTimeoutResolved;
  const extraProtectedTermsResolved = resolveExtraProtectedTermsSetting(env);
  if (!extraProtectedTermsResolved.ok) return extraProtectedTermsResolved;

  // Advisory only, never a failure: a presence check using the same blank-means-unset rule as the
  // parsers above, and deliberately NOT a parse, so a garbage value can no longer stop startup the way
  // it could while this variable still governed something. main() prints each entry once.
  const warnings = [];
  const retiredAcquireTimeout = env[ACQUIRE_PROCESS_OWNERSHIP_TIMEOUT_ENV_VAR];
  if (typeof retiredAcquireTimeout === 'string' && retiredAcquireTimeout.trim().length > 0) {
    warnings.push(RETIRED_ACQUIRE_TIMEOUT_WARNING);
  }

  return {
    ok: true,
    config: {
      dataRoot,
      installationHardMaximumUsd,
      dispatchTimeoutMs: dispatchTimeoutResolved.value,
      preflightTtlMs: preflightTtlResolved.value,
      orphanSweepGraceMs: orphanSweepGraceResolved.value,
      healthVerdictGraceMs: healthVerdictGraceResolved.value,
      healthVerdictBackstopMs: healthVerdictBackstopResolved.value,
      armTimeoutMs: armTimeoutResolved.value,
      armLockRetryMs: armLockRetryResolved.value,
      shutdownDrainTimeoutMs: shutdownDrainTimeoutResolved.value,
      ollamaBaseUrl: ollamaBaseUrlResolved.value,
      ollamaModel: ollamaModelResolved.value,
      ollamaTimeoutMs: ollamaTimeoutResolved.value,
      extraProtectedTermsSetting: extraProtectedTermsResolved.value,
      sourcePolicy: Object.freeze({ allowedRoots, maxSourceBytes: MAX_SOURCE_BYTES }),
      preflightPolicy: Object.freeze({ maxRequestBytes: MAX_REQUEST_BYTES }),
    },
    warnings,
  };
}

/**
 * Builds the real production review engine: the two adapters that already
 * existed for real (createLeaseStore, createApprovalAdapter, both using
 * their own built-in defaults -- the already-existing
 * tools/openrouter-review-authorize.ps1 script for approval) plus the
 * dispatch adapter defined above. Constructing these touches no credential
 * and makes no network call; only an actual `authorize_workflow` or `review`
 * tool call (driven by a real MCP client, never by this file) invokes
 * PowerShell.
 *
 * `leaseStore` and `ownerLock` are caller-supplied rather than constructed here: the handle
 * `main()` builds must come from the SAME leaseStore instance this engine writes through. A second,
 * independent leaseStore here (as this function once had) would arm against one instance's
 * in-memory ledger state while the engine wrote through another, which defeats the ownership fence.
 * The handle arrives UNARMED and the engine arms it on demand (see main()'s own comment).
 */
function buildProductionEngine(config, { leaseStore, ownerLock }) {
  return createReviewEngine({
    leaseStore,
    ownerLock,
    approvalAdapter: createApprovalAdapter({ dataRoot: config.dataRoot }),
    dispatchAdapter: createDispatchAdapter({ dataRoot: config.dataRoot, timeoutMs: config.dispatchTimeoutMs }),
    resultStore: createResultStore({ dataRoot: config.dataRoot }),
    preflightContextStore: createPreflightContextStore({ dataRoot: config.dataRoot }),
    dispatchOutcomeStore: createDispatchOutcomeStore({ dataRoot: config.dataRoot }),
    scrubEngine: createScrubEngine({
      identityList: config.identityList,
      // Loaded and hash-checked in main(); passed explicitly so the owner's terms cannot drop out.
      extraProtectedTerms: config.extraProtectedTerms,
      ollamaClient: createOllamaClient({
        fetchImpl: fetch,
        baseUrl: config.ollamaBaseUrl,
        model: config.ollamaModel,
        timeoutMs: config.ollamaTimeoutMs,
      }),
    }),
    scrubMappingStore: createScrubMappingStore({ dataRoot: config.dataRoot }),
    sourcePolicy: config.sourcePolicy,
    preflightPolicy: config.preflightPolicy,
    preflightTtlMs: config.preflightTtlMs,
    orphanSweepGraceMs: config.orphanSweepGraceMs,
    // The on-demand arm's budget and base retry interval. Resolved
    // above like every sibling timing knob; a value resolved but not passed here would be silently
    // replaced by the engine's own default (the wiring test in tests/openrouter-review-dispatch-config.test.mjs).
    armTimeoutMs: config.armTimeoutMs,
    armLockRetryMs: config.armLockRetryMs,
    installationHardMaximumUsd: config.installationHardMaximumUsd,
    autonomousAuthorization: resolveAutonomousAuthorization(),
    alertStore: createAlertStore({ dataRoot: config.dataRoot }),
    // Spend and health alerts (alert-store.mjs plus the key-status probe): a read-only probe of
    // OpenRouter's own live spend-cap status for the 75%-of-monthly-cap warning, and a durable,
    // restart-surviving counter for the consecutive-dispatch-failure critical alert. See
    // review-engine.mjs's own checkSpendAndMaybeAlert/recordDispatchHealthOutcome docstrings for
    // why each is wired the way it is.
    keyStatusProbe: createKeyStatusProbeAdapter(),
    dispatchHealthStore: createDispatchHealthStore({ dataRoot: config.dataRoot }),
    pendingHealthVerdictStore: createPendingHealthVerdictStore({ dataRoot: config.dataRoot }),
    healthVerdictGraceMs: config.healthVerdictGraceMs,
    healthVerdictBackstopMs: config.healthVerdictBackstopMs,
    consecutiveDispatchFailureAlertThreshold: resolveConsecutiveDispatchFailureAlertThreshold(),
    // Reuses the SAME already-resolved local Ollama connection info as the scrub engine above --
    // a repeat-authorization justification judgment is a lightweight, short-prompt local call,
    // not something that needs its own env vars or its own endpoint.
    repeatAuthorizationJudge: createRepeatAuthorizationJudge({
      fetchImpl: fetch,
      baseUrl: config.ollamaBaseUrl,
      model: config.ollamaModel,
      timeoutMs: config.ollamaTimeoutMs,
    }),
  });
}

// Single-flight for the same reason release() itself is: a signal and a transport close can both
// arrive for one process, and the drain-then-release sequence must not run twice.
let shutdownPromise = null;

// Exported ONLY so the stdio integration suite's generated harness can wire the REAL shutdown
// lifecycle instead of hand-copying it. A harness that replicated this function and
// runShutdownSequence below would be a vacuous pass, because a test asserting on a copy stays
// green when the single-flight guard, the withhold-release branch, the 0/1 exit code or the stdin
// listeners are deleted from THIS file. Exporting is purely additive -- nothing here
// reads module state that main() has to have set up first, every dependency arrives as a parameter,
// and main()'s own self-invocation at the bottom of this file stays guarded on process.argv[1].
export function installShutdownHandlers({ server, engine, ownerLock, drainTimeoutMs }) {
  const handler = () => { startShutdownSequence({ server, engine, ownerLock, drainTimeoutMs }); };
  // Registered for completeness and for any non-Windows host, but do not rely on either one here:
  // this server's own platform is Windows, where SIGTERM cannot actually be DELIVERED (a listener
  // can be registered, but kill('SIGTERM') terminates via TerminateProcess and no handler runs) and
  // SIGINT requires an attached console the client never gives this process. Measured: killing the
  // real entry point with SIGTERM exited on the signal with no shutdown output and no RELEASED
  // record, while the stdin path below released cleanly on the same build.
  process.on('SIGINT', handler);
  process.on('SIGTERM', handler);
  // stdin EOF is the DOMINANT real-world shutdown trigger for a stdio server -- it is what happens
  // every time an MCP client goes away -- and transport.onclose does not cover it. Established by
  // running the real entry point, not by reading: without these listeners, closing the child's
  // stdin exits the process 0 with no shutdown output and no RELEASED record, leaving ownership held.
  //
  // The reason is in the SDK: StdioServerTransport registers stdin listeners for 'data' and 'error'
  // only (server/stdio.js:14-26, :54-68). Nothing calls its close() at EOF, so its onclose never
  // fires; the process simply runs out of work and exits cleanly with ownership still ACQUIRED.
  // Without this, each abandoned server leaves an ACQUIRED record with no RELEASED counterpart,
  // blocking the next server until it goes stale.
  //
  // Both events are registered because 'close' can arrive without 'end' if the stream is destroyed
  // rather than ended; the single-flight guard makes the overlap harmless.
  process.stdin.on('end', handler);
  process.stdin.on('close', handler);
}

/**
 * Fire-and-forget entry point for the three callers that cannot await -- two signal handlers and
 * transport.onclose, all synchronous.
 *
 * The .catch() is not defensive padding. runShutdownSequence() is async, so calling it from a
 * synchronous handler produces a promise nobody holds; if it ever rejected, Node's post-v15 default
 * would turn that into an unhandledRejection and kill the process mid-shutdown -- skipping
 * ownerLock.release() and leaving ownership held, which is precisely the failure this whole
 * sequence exists to prevent. runShutdownSequence is written not to reject, and this is the backstop for a future edit that
 * breaks that property.
 */
export function startShutdownSequence(options) {
  return runShutdownSequence(options).catch((error) => {
    process.stderr.write(`openrouter-review-mcp-server: shutdown sequence failed: ${error && error.message ? error.message : String(error)}\n`);
    process.exit(1);
  });
}

/**
 * Refuse new owner-sensitive work, let what is already admitted finish, then release process
 * ownership only if it genuinely did.
 *
 * Releasing after a TIMED-OUT drain would be the dangerous move: outstanding work still holds
 * acquisitionId and would keep issuing owner-fenced writes after ownership was handed back. So a
 * timeout exits WITHOUT releasing and lets the successor reclaim through the normal dead-and-stale
 * path -- slower, but never a write from a process that no longer owns the ledger.
 *
 * Every await is individually guarded so this function does not reject: a failure in any one step
 * must still leave the process able to exit rather than hanging with an open transport. Setting
 * process.exitCode alone does NOT terminate a process holding an open stdio transport with active
 * listeners, so this closes the server and then ends through exitAfterShutdown(), whose fallback
 * timer forces the exit if anything still holds the loop open.
 */
async function runShutdownSequence({ server, engine, ownerLock, drainTimeoutMs }) {
  if (!shutdownPromise) {
    shutdownPromise = (async () => {
      let drained = false;
      let outstandingCount = 0;
      // Exit 0 must mean BOTH halves of a clean shutdown: in-flight work finished AND process
      // ownership was handed back. `drained` alone only covers the first. A throw from
      // ownerLock.release() below is caught and logged, so without this flag a shutdown that
      // abandoned its ACQUIRED record would still report success on the one signal a supervisor
      // or the MCP client actually reads.
      let ownershipReleased = false;
      try {
        engine.beginShutdown();
        ({ drained, outstandingCount } = await engine.awaitDrain({ timeoutMs: drainTimeoutMs }));
      } catch (error) {
        // Treated exactly like a timed-out drain: ownership is NOT released, because a drain whose
        // own outcome is unknown is no evidence that outstanding work has stopped.
        process.stderr.write(`openrouter-review-mcp-server: shutdown drain failed, not releasing process ownership: ${safeErrorDetail(error)}\n`);
      }
      if (drained) {
        try {
          // Read BEFORE release(), which moves every state to
          // 'released'. A process that never armed holds nothing, and release({ final: true }) is a
          // clean no-op for it; announcing "released process ownership" there would make this line
          // lie on exactly the sessions -- every one that never ran a paid call -- where an operator
          // most needs to know that nothing was ever held.
          //
          // Read HERE, at shutdown, and from the real handle. The handle is still unarmed when the
          // shutdown handlers are installed and arms in place later, so a state captured at install
          // time, or read from a spread copy of the handle, would print the never-armed line for a
          // session that armed and paid (guarded by a test in
          // tests/openrouter-review-always-connect-stdio.test.mjs).
          //
          // This snapshots BOTH current ownership and the handle's sticky history only after the
          // drain. A completing operation can release during that drain, so the middle diagnostic is
          // deliberately timed relative to final shutdown cleanup rather than shutdown initiation.
          // release-pending is logically non-owning too: final release below retries only its exact
          // physical cleanup and must not claim that it appended a fresh RELEASED record.
          if (typeof ownerLock.everArmed !== 'boolean') throw new TypeError('ownerLock.everArmed must be a boolean');
          const everArmed = ownerLock.everArmed;
          const stateAtDrain = ownerLock.state;
          const ownedAtDrain = ownerLock.isOwner() === true;
          // Explicitly final: this process is ending, so its handle must never be armed again.
          await ownerLock.release({ final: true });
          // The one line on the SUCCESS path. Every branch that FAILS to hand ownership back
          // already says so on stderr; without this line a clean shutdown and one that abandoned
          // ownership entirely would produce byte-identical output -- a single startup line --
          // and that silence makes a lingering-owner CONNECT_TIMEOUT hard to diagnose.
          //
          // stderr, never stdout: this is an MCP stdio server and a stray stdout write corrupts the
          // protocol. The stdio test file's single-flight test already guards that and would redden
          // on `nonJsonStdout` if this ever moved.
          //
          // Deliberately INSIDE the try and AFTER the await, so it can only ever follow a release
          // that actually completed: a throwing release() jumps straight to the catch below and
          // this never runs. Equally deliberately NOT in main()'s startup-failure cleanup, which
          // also releases successfully -- a second `openrouter-review-mcp-server:` line there would
          // break the exact-one-diagnostic assertion the startup-failure test makes
          // (tests/openrouter-review-always-connect-stdio.test.mjs).
          //
          // Honest limit: ownerLock.release() is a no-op when a successor has already superseded
          // this handle (lease-store.mjs), so this line means the release path completed cleanly,
          // not that a fresh RELEASED record was necessarily appended.
          let successLine;
          if (!everArmed) {
            successLine = 'openrouter-review-mcp-server: shutdown after a clean drain; this process never held process ownership.\n';
          } else if (stateAtDrain === 'release-pending') {
            successLine = 'openrouter-review-mcp-server: shutdown completed pending process-ownership release cleanup after a clean drain.\n';
          } else if (ownedAtDrain) {
            successLine = 'openrouter-review-mcp-server: shutdown released process ownership after a clean drain.\n';
          } else {
            successLine = 'openrouter-review-mcp-server: shutdown after a clean drain; process ownership had already been released before final shutdown cleanup.\n';
          }
          process.stderr.write(successLine);
          // Set in the SAME place, and under the same conditions, as the success line above: only
          // after an await that actually completed. A throwing release() jumps to the catch below
          // and this never runs, so the exit code and the stderr diagnostic can never disagree.
          ownershipReleased = true;
        } catch (error) {
          process.stderr.write(`openrouter-review-mcp-server: failed to release process ownership during shutdown: ${safeErrorDetail(error)}\n`);
        }
      } else {
        process.stderr.write(`openrouter-review-mcp-server: shutdown drain timed out with ${outstandingCount} operation(s) still outstanding -- exiting without initiating additional process-ownership release; outstanding work or cleanup remains unresolved.\n`);
      }
      try {
        await server.close();
      } catch (error) {
        process.stderr.write(`openrouter-review-mcp-server: error closing the server during shutdown: ${safeErrorDetail(error)}\n`);
      }
      // Both halves, not just the drain. A timed-out drain never attempts a release, so
      // ownershipReleased stays false and this exits 1; a drained-but-release-failed shutdown
      // exits 1 as well. A process that never armed takes the drained branch too: its release({ final: true }) is a no-op that completes, so it sets
      // ownershipReleased and exits 0 with the never-armed line, having had nothing to hand back.
      // Still exitAfterShutdown(), never a direct process.exit(): a preflight's fetch() calls
      // leave V8 background work that an immediate exit races (exitAfterShutdown's own comment).
      exitAfterShutdown(drained && ownershipReleased ? 0 : 1);
    })();
  }
  return shutdownPromise;
}

// How long a finished shutdown lets the event loop empty on its own before forcing the exit.
const SHUTDOWN_EXIT_FALLBACK_MS = 2_000;

/**
 * Ends the process with `code` by letting the event loop run dry, and calls process.exit() only
 * if something still holds the loop open after SHUTDOWN_EXIT_FALLBACK_MS.
 *
 * Calling process.exit() straight away crashed this server on Windows (observed on Node
 * v24.16.0): closing stdin right after a preflight exited 0xC0000409 with "Assertion
 * failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 94", 3/3, instead of 0.
 * The evidence points to a Node-on-Windows race, not this server's logic: after a few fetch()
 * round trips V8 recompiles undici's WebAssembly HTTP parser on a background thread, and
 * process.exit() tears the V8 platform down without waiting for that job. That mechanism is
 * inferred from the experiments below, not observed directly. Measured without this server at all: four fetch() calls then process.exit(0) aborts 5/5, the
 * same with process.exitCode exits 0 5/5, and --no-wasm-dynamic-tiering or --liftoff-only (no
 * background WebAssembly recompile) also exit 0 5/5. The handle involved is read from Node's
 * source, not observed in a debugger: WorkerThreadsTaskRunner::Shutdown (node_platform.cc) closes
 * the delayed-task scheduler's async handle BEFORE joining the worker threads, so a job posting a
 * delayed task in between wakes a closing handle. A natural exit drains the platform's tasks first
 * (SpinEventLoop -> DrainTasks, api/embed_helpers.cc).
 *
 * The fallback keeps the old guarantee that shutdown never hangs: a drain that timed out can leave
 * work (and its handles) running, and the successor can only reclaim ownership once this process
 * is gone. The timer is unref'd, so it never delays a loop that has nothing left to do. When it
 * does fire, process.exit() can still meet the same race, but only if work is still making fetch()
 * calls two seconds after shutdown finished.
 *
 * Exported only so tests/openrouter-review-mcp-shutdown-exit.test.mjs can drive the real function
 * in a child process whose event loop is deliberately held open; nothing else imports it.
 */
export function exitAfterShutdown(code) {
  process.exitCode = code;
  setTimeout(() => { process.exit(code); }, SHUTDOWN_EXIT_FALLBACK_MS).unref();
}

/**
 * Real stdio entry point. When the operator has not configured
 * `OPENROUTER_REVIEW_MCP_INSTALLATION_HARD_MAXIMUM_USD`, this fails cleanly
 * (stderr-only diagnostic, non-zero exit, stdout untouched, no transport ever
 * constructed) -- safe by default. When configured, it builds the real
 * production engine above, registers it with `createReviewMcpServer`, and
 * connects a real `StdioServerTransport`, so `npm run mcp:start` serves a
 * JSON-RPC stdio session.
 *
 * Takes NO process ownership at startup. It builds `leaseStore`, hands the
 * engine an UNARMED handle from `leaseStore.createUnarmedOwnerHandle()` -- no I/O, no ledger
 * record -- and connects. The engine's ownership coordinator arms that same handle on the first
 * owner-sensitive tool call; `preflight`, `status` and `result` never arm. The engine's constructor
 * accepts an unarmed handle (`acquisitionId === null`), and that is exactly what stops another live
 * server's ownership from blocking this one's connect.
 * Orphan recovery and the pending-health sweep do not run here either; both run inside the first
 * arm cycle, which is the only place this process can own the ledger.
 *
 * The whole startup path, transport connection included, lives in ONE try block whose catch
 * releases the handle with `release({ final: true })` and still reports the ORIGINAL startup error.
 * Its counterpart on the clean-exit side is the stdin/SIGINT/SIGTERM/transport-close shutdown
 * sequence above, which drains admitted work -- an in-flight arm included -- and then releases the
 * same handle.
 */
async function main() {
  const resolved = resolveProductionEngineConfig();
  if (!resolved.ok) {
    process.stderr.write(`openrouter-review-mcp-server: cannot start -- ${resolved.reason}\n`);
    process.exitCode = 1;
    return;
  }
  // Before anything else runs, so an operator reading the log sees the notice first.
  for (const warning of resolved.warnings) {
    process.stderr.write(`openrouter-review-mcp-server: warning: ${warning}\n`);
  }

  // Declared outside the try so the catch can release the handle, and so the shutdown handlers
  // installed inside it close over the real references. The handle is one object for the whole life
  // of this process: arming happens in place behind it (lease-store.mjs), so handlers that closed over
  // it here still see the armed state after a later tool call arms it.
  let server;
  let engine;
  let ownerLock;
  try {
    const leaseStore = createLeaseStore({ dataRoot: resolved.config.dataRoot, dailyPaidJobAllowance: resolveDailyPaidJobAllowance() });
    // NO process ownership at startup. The handle starts unarmed -- no
    // I/O, no ledger record -- and the engine's ownership coordinator arms it on the first
    // owner-sensitive tool call (authorize_workflow, openrouter_review_document, or the
    // recoverOrphanedLeases export). A startup acquire would race every other client's server for
    // the one owner slot, and a client session whose first connect fails may never retry, so losing
    // that race would cost the whole session its review tools.
    ownerLock = leaseStore.createUnarmedOwnerHandle();
    // Fails closed the same way a missing installationHardMaximumUsd already
    // does above: an unconfigured, unreadable or empty identity list means this
    // file's own fail-closed contract is unmet, so the server does not start
    // rather than starting with a silently degraded scrub engine.
    const identityListPath = process.env[IDENTITY_LIST_PATH_ENV_VAR];
    if (!identityListPath) throw new Error(`${IDENTITY_LIST_PATH_ENV_VAR} must be configured`);
    const identityList = await loadIdentityList(identityListPath);
    // Same fail-closed contract for the owner's extra protected terms: a configured file that is missing,
    // changed or malformed stops startup instead of starting without those terms.
    const extraProtectedTerms = await loadExtraProtectedTerms(resolved.config.extraProtectedTermsSetting);
    engine = buildProductionEngine({ ...resolved.config, identityList, extraProtectedTerms }, { leaseStore, ownerLock });
    server = createReviewMcpServer(engine);
    // No startup orphan recovery and no startup pending-health sweep.
    // Orphan recovery performs owner-fenced writes, so it runs inside the first arm cycle, right
    // after the arm (review-engine.mjs runCycleWork); the engine logs a one-line summary there when
    // it closes anything. The pending-health sweep moved into the same cycle: it writes
    // dispatch-health.json, which has no cross-process lock, and with every session's server now
    // connected, only the one armed owner may write it.
    //
    // The one startup sweep that stays is scrub-mapping retention, in its OWN log-and-continue try.
    // It is ownerless, and ownerless is not the same as safe: two starters' sweeps can race readdir
    // against stat, and a throw from the loser would fail startup -- exactly the never-retried failed
    // connect that taking no ownership at startup exists to prevent. scrub-mapping-store.mjs now skips a name that vanished in
    // between, and this guard covers whatever else the sweep can throw. Nothing it does is worth
    // refusing to serve over; the next startup simply sweeps again.
    try {
      const sweptCount = await sweepStaleScrubMappings({ scrubMappingStore: createScrubMappingStore({ dataRoot: resolved.config.dataRoot }) });
      if (sweptCount > 0) {
        process.stderr.write(`openrouter-review-mcp-server: startup sweep deleted ${sweptCount} stale scrub-mapping record(s).\n`);
      }
    } catch (error) {
      process.stderr.write(`openrouter-review-mcp-server: startup scrub-mapping sweep failed; continuing without it (the next startup sweeps again): ${error && error.message ? error.message : String(error)}\n`);
    }

    server.server.onerror = (error) => {
      process.stderr.write(`openrouter-review-mcp-server: transport error: ${error && error.message ? error.message : String(error)}\n`);
    };

    const transport = new StdioServerTransport();
    // Set BEFORE connect() deliberately. The SDK does not discard this: Protocol.connect() assigns
    // this._transport first, then reads the transport's existing onclose and CHAINS it ahead of its
    // own (shared/protocol.js:219-223) -- verified against the installed 1.30.0, whose own doc
    // comment claiming it replaces already-set callbacks is stale for onclose/onerror/onmessage.
    // Setting it after connect() would instead clobber the SDK's own handler.
    transport.onclose = () => { startShutdownSequence({ server, engine, ownerLock, drainTimeoutMs: resolved.config.shutdownDrainTimeoutMs }); };
    installShutdownHandlers({ server, engine, ownerLock, drainTimeoutMs: resolved.config.shutdownDrainTimeoutMs });
    await server.connect(transport);
  } catch (error) {
    // One catch for the whole startup path, transport connection included, so a server.connect()
    // failure still releases the handle like every other startup failure.
    //
    // Covers every startup failure uniformly: a missing identity list, buildProductionEngine()
    // throwing, and a transport that will not connect. An ownership timeout is no longer one of them:
    // main() takes no ownership at startup, so another live server cannot fail it.
    process.stderr.write(`openrouter-review-mcp-server: failed to start: ${error && error.message ? error.message : String(error)}\n`);
    // A release() failure here must never replace the ORIGINAL startup error -- it is reported
    // separately and the original still determines the exit. Nothing on the startup path arms, so
    // today this is a no-op on an unarmed handle (no I/O, no ledger record); `final: true` still
    // matters, because it retires the handle so nothing can arm it afterwards.
    if (ownerLock) {
      try {
        await ownerLock.release({ final: true });
      } catch (releaseError) {
        process.stderr.write(`openrouter-review-mcp-server: startup-failure cleanup also failed to release process ownership: ${releaseError && releaseError.message ? releaseError.message : String(releaseError)}\n`);
      }
    }
    process.exitCode = 1;
    return;
  }

  process.stderr.write('openrouter-review-mcp-server: connected via stdio.\n');
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
