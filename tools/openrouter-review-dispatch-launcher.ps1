<#
One-shot Task-Scheduler launcher for openrouter-review-dispatch.ps1.

Why a Scheduled Task: a dispatch worker spawned as a direct child of the Node review-engine
process -- even with execFile's `detached: true` -- dies alongside its Node parent when that
parent is killed or replaced. So does a child spawned via WMI's Win32_Process.Create (a
process with NO process-tree relationship to the Node parent at all, parented instead by
WmiPrvSE.exe) -- so this is not a simple process-tree/job-object-inheritance story, and
"detached" cannot be trusted as a survival mechanism. A Windows Scheduled Task, started via
Start-ScheduledTask and executing under the Task Scheduler service (svchost.exe), with no
process-tree relationship to the caller, survives an identical kill, and the DPAPI credential
decrypt this dispatch depends on still completes normally after its triggering process is
force-killed mid-flight.

Why PrincipalLogonType Interactive (NOT S4U, NOT "run whether user is logged on or not"):
`[Security.Cryptography.ProtectedData]::Unprotect(..., CurrentUser)` succeeds under this
configuration, while a windowless S4U or ServiceAccount logon cannot unlock CurrentUser-scoped
DPAPI -- and this script's whole reason for existing is to run openrouter-review-dispatch.ps1,
which decrypts the OpenRouter API credential via exactly that CurrentUser-scoped DPAPI call.

Deliberately does NOT modify openrouter-review-dispatch.ps1 itself, which documents its own
constraint ("never shells out to any other OpenRouter-dispatching script in this repository")
-- this script is the caller, never the callee, and the worker script is unaware it is being
run under a scheduled task rather than a direct child process.

Contract with the caller (createDispatchAdapter in tools/openrouter-review-mcp-server.mjs):
identical positional args (RequestPath, DeadlineUtc, ResponsePath) and an identical stdout
contract (at most one line, the same {"kind":"RESPONSE"|"FAILURE",...} envelope
openrouter-review-dispatch.ps1 itself would have printed) -- so this script is a drop-in
replacement for the direct execFile target. If THIS launcher process is itself killed
BEFORE Node's own execute() timeout also fires (i.e. Node survives and is the one waiting on
this launcher), Node sees empty stdout, throws, and haltAndClose reconciles/closes the lease
in that same turn (openrouter-review-mcp-server.mjs / review-engine.mjs) -- the still-running
task can still complete and write a real outcome afterward, but nothing reads it again in
that case. The "outcome survives even if the caller is gone" guarantee this whole mechanism
exists for applies specifically to the case where NODE ITSELF also dies or is replaced. In
that case the existing dispatchOutcomeStore recovery path in review-engine.mjs (which reads
-ResponsePath directly, never this script's stdout) already knows how to pick up a real
outcome later, unchanged by anything in this file.

Design notes:
1. Start-ScheduledTask is asynchronous, so a task can still read `Ready` or `Queued` moments
   after being started. The poll loop must never treat that as "already finished", which
   would durably overwrite the DISPATCHING marker with a false FAILURE and unregister the
   task while it might still be about to run. Polling the sampled task State is not enough
   either -- see Get-DispatchPollAction's own doc comment below for the
   Get-ScheduledTaskInfo-LastRunTime-based mechanism used instead.
2. Register-ScheduledTask gets explicit -Settings (see below). Task Scheduler's default power
   conditions (DisallowStartIfOnBatteries, StopIfGoingOnBatteries, a 72-hour
   ExecutionTimeLimit) would silently block every on-battery dispatch (the same false-FAILURE
   path as (1)) and kill an in-flight worker the instant the machine goes on battery. Both
   battery conditions are disabled, and ExecutionTimeLimit is bounded to the dispatch's own
   deadline plus fixed headroom: a real hard-kill backstop for the worker, since Node's own
   execute() timeout only ever reaches this launcher, not the worker running under the task.
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $RequestPath,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string] $DeadlineUtc,

    [Parameter(Mandatory = $true, Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string] $ResponsePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Mirrors openrouter-review-dispatch.ps1's own Write-OpenRouterOutcomeAtomic exactly
# (temp file + explicit no-BOM UTF8Encoding + atomic Move-Item) -- best-effort only, per
# that script's own documented rationale: a durable-write failure here must never be
# allowed to crash this launcher, since the worker's own write (if it ever runs) is the
# primary source of truth either way.
function Write-LauncherOutcomeAtomic {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Line)
    try {
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        $temp = "$Path.$([guid]::NewGuid().ToString()).tmp"
        [System.IO.File]::WriteAllText($temp, $Line, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $Path -Force
    }
    catch { }
}

function New-LauncherFailureLine {
    param([Parameter(Mandatory = $true)][string]$FailureKind, [Parameter(Mandatory = $true)][string]$Message)
    $envelope = [ordered]@{ failureKind = $FailureKind; message = $Message }
    $envelopeJsonText = ($envelope | ConvertTo-Json -Compress -Depth 6)
    $outer = [ordered]@{ kind = 'FAILURE'; envelopeJsonText = $envelopeJsonText }
    return ($outer | ConvertTo-Json -Compress -Depth 3)
}

# Reads -ResponsePath and returns $null unless it holds a TERMINAL outcome (RESPONSE or
# FAILURE) -- a DISPATCHING marker (written by Node before this launcher was even spawned,
# see dispatch-outcome-store.mjs's markDispatching()) or a missing/unparseable file both
# read as "not done yet", which is the correct read while the task may still be running.
function Read-TerminalOutcomeLine {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $text = [System.IO.File]::ReadAllText($Path) -replace "^\xEF\xBB\xBF", ''
        $parsed = $text | ConvertFrom-Json
        if ($parsed.kind -eq 'RESPONSE' -or $parsed.kind -eq 'FAILURE') { return $text.Trim() }
        return $null
    }
    catch { return $null }
}

# Task Scheduler's documented "task is currently running" LastTaskResult sentinel
# (SCHED_S_TASK_RUNNING, 0x00041301). The worker script always `exit 0` on every path (success and every failure
# kind alike -- see openrouter-review-dispatch.ps1's own bottom guard), so a COMPLETED run's
# LastTaskResult is always 0 here, never a value that could collide with this sentinel.
$script:SCHED_S_TASK_RUNNING = 267009

# Pure decision function for one poll iteration -- deliberately takes primitive values
# (never calls Get-ScheduledTaskInfo/reads a file itself) so it is testable offline without
# touching Task Scheduler. Returns one of:
#   'DONE_WITH_OUTCOME'  -- a real terminal outcome is on disk; relay it. Checked first and
#                           takes priority regardless of the other two signals, so a task
#                           that finishes and writes its outcome faster than this launcher's
#                           poll interval is still caught on the very next poll.
#   'DONE_NO_OUTCOME'    -- the task genuinely ran (real evidence, not just "we happened to
#                           catch it in the Running state") and is not running now, but left
#                           no terminal outcome; this launcher must write one itself.
#   'KEEP_POLLING'       -- not conclusive yet.
#
# $HasRunEvidence is deliberately NOT gated on this launcher having SAMPLED the `Running`
# state at least once via polling, which has two related gaps: (a) a task that starts and
# finishes faster than the ~500ms poll interval could be missed entirely, turning a fast
# worker death into a slow, generic "unknown outcome" instead of a fast, specific one;
# (b) a single transient Get-ScheduledTask query failure (silently swallowed by
# -ErrorAction SilentlyContinue) right after a sampled Running observation could read as
# "task gone" and falsely trigger DONE_NO_OUTCOME. $HasRunEvidence is instead derived from
# Get-ScheduledTaskInfo's LastRunTime -- a fact Task Scheduler itself records the instant
# the task launches, independent of whether THIS launcher's polling cadence ever observed
# it running -- compared against a timestamp captured just before Start-ScheduledTask was
# called (with a small buffer; LastRunTime's own resolution is whole seconds, so a
# same-second comparison without a buffer can read as "not yet run" even though the task
# already ran). Recomputed
# FRESH every poll from a live query rather than cached in a flag, so a single transient
# query failure this iteration can only ever read as "no evidence YET" (falls through to
# KEEP_POLLING), never flips a previously-true reading back to false, and never combines a
# stale cached true with a fresh false to produce an incorrect conclusion.
#
# A task that never starts at all (e.g. blocked by a battery power condition -- see design
# note 2 in the header) never accumulates $HasRunEvidence and falls
# through to KEEP_POLLING until this launcher's own overall wait window expires, landing in
# the safe give-up path below rather than a false DONE_NO_OUTCOME write.
function Get-DispatchPollAction {
    param(
        [Parameter(Mandatory = $true)][bool]$HasRunEvidence,
        [Parameter(Mandatory = $true)][bool]$IsRunningNow,
        [AllowNull()][string]$OutcomeLine
    )
    if ($OutcomeLine) { return 'DONE_WITH_OUTCOME' }
    if ($IsRunningNow) { return 'KEEP_POLLING' }
    if ($HasRunEvidence) { return 'DONE_NO_OUTCOME' }
    return 'KEEP_POLLING'
}

# Guards the real invocation logic below from also running when this script is
# dot-sourced (". script.ps1") purely to access the helper functions above for
# testing -- the same pattern openrouter-review-dispatch.ps1 itself already
# uses. Node's execFile always invokes this script via `-File`, never
# dot-sources it, so this guard changes nothing about production behavior.
if ($MyInvocation.InvocationName -ne '.') {
    # Diagnostic instrumentation for STATUS_CONTROL_C_EXIT failures -- see
    # openrouter-review-ctrl-signal-log.ps1's own header for the full rationale. This
    # launcher's own process (a direct Node child, not the Task-Scheduler-hosted worker) is a
    # distinct candidate for the same failure: a launcher killed this way never reaches its
    # own WORKER_PRODUCED_NO_OUTCOME self-write. Installed before any Task Scheduler work.
    #
    # Wrapped in its own try/catch: dot-sourcing runs the module's Add-Type at parse time,
    # outside any function body, so Install-OpenRouterCtrlSignalLog's own internal error
    # handling (which only covers the SetConsoleCtrlHandler call itself) can never catch an
    # Add-Type compilation failure. This diagnostic must never be why a real dispatch fails.
    try {
        . (Join-Path $PSScriptRoot 'openrouter-review-ctrl-signal-log.ps1')
        Install-OpenRouterCtrlSignalLog -LogPath (Join-Path (Split-Path -Parent $ResponsePath) 'ctrl-signals.log') -Role 'launcher' | Out-Null
    }
    catch {
        Write-Warning "console-control diagnostics could not be installed: $($_.Exception.Message)"
    }
    $jobId = [System.IO.Path]::GetFileNameWithoutExtension($ResponsePath)
    $taskName = "OpenRouterReviewDispatch-$jobId"
    $workerScriptPath = Join-Path $PSScriptRoot 'openrouter-review-dispatch.ps1'

    # Defense in depth: a real terminal outcome already sitting at -ResponsePath means
    # dispatch already happened -- relay it and never touch Task Scheduler at all. In normal
    # operation this branch is not reachable (dispatch-outcome-store.mjs's markDispatching()
    # exclusive `wx` claim, checked by the Node-side caller before execute() is ever invoked,
    # already makes it structurally impossible for this launcher to be invoked twice for the
    # same jobId). It costs one file read on every invocation and closes the gap outright if
    # that upstream invariant is ever weakened by a future change elsewhere in the codebase.
    $preExistingOutcome = Read-TerminalOutcomeLine -Path $ResponsePath
    if ($preExistingOutcome) {
        Write-Output $preExistingOutcome
        exit 0
    }

    try {
        $deadline = [DateTimeOffset]::Parse($DeadlineUtc).ToUniversalTime()
    }
    catch {
        $line = New-LauncherFailureLine -FailureKind 'INVALID_DEADLINE' -Message 'deadline could not be parsed as a timestamp'
        Write-LauncherOutcomeAtomic -Path $ResponsePath -Line $line
        Write-Output $line
        exit 0
    }
    # Deliberately LESS headroom than Node's own execute() timeout
    # (effectiveTimeoutMs + 30_000 from spawn, i.e. ~30s past this same deadline -- see
    # createDispatchAdapter in tools/openrouter-review-mcp-server.mjs) so this launcher
    # reaches its own safe give-up path before Node kills it, rather than always being
    # killed first. The worker's own two-tier deadline check means it returns close to
    # $deadline either way (RESPONSE, or its own DEADLINE_EXCEEDED), not near +30s.
    $waitUntilUtc = $deadline.AddSeconds(15)
    # Hard backstop for the WORKER running under the task -- Node's own execute() timeout
    # now only ever reaches this launcher, not the worker, so without an explicit limit
    # here the task would inherit Task Scheduler's own default (72 hours).
    $executionTimeLimit = ($deadline - [DateTimeOffset]::UtcNow) + [TimeSpan]::FromMinutes(30)
    if ($executionTimeLimit -lt [TimeSpan]::FromMinutes(5)) { $executionTimeLimit = [TimeSpan]::FromMinutes(5) }

    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }

        # -WindowStyle Hidden prevents the worker's console from receiving a Ctrl+C.
        # STATUS_CONTROL_C_EXIT (0xC000013A) is the NT status a console process gets from its
        # DEFAULT Ctrl+C handler, not a generic crash -- without this flag, LogonType
        # Interactive gives this worker a real, focusable console window that sits nearly
        # silent on the desktop for minutes, exposed to an accidental Ctrl+C. Matches the other
        # background PowerShell spawns in this codebase (including the approval flow's own
        # outer cmd.exe wrapper), which also hide their window. Orthogonal to LogonType (still
        # Interactive, so DPAPI CurrentUser decrypt is unaffected) and to this launcher's own
        # completion detection (polls Get-ScheduledTaskInfo/-ResponsePath, never the window
        # itself).
        $argumentLine = '-NoProfile -WindowStyle Hidden -File "{0}" "{1}" "{2}" "{3}"' -f $workerScriptPath, $RequestPath, $DeadlineUtc, $ResponsePath
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argumentLine
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
        # AllowStartIfOnBatteries / DontStopIfGoingOnBatteries: without these, Task
        # Scheduler's DEFAULT settings silently block every dispatch on battery power and
        # kill an already-running worker the instant the machine goes on battery -- the
        # exact symptom this whole mechanism exists to eliminate. MultipleInstances
        # IgnoreNew is defense-in-depth (task names are already unique per jobId, and a
        # second launcher for the same jobId cannot reach this far -- see
        # dispatch-outcome-store.mjs's markDispatching() exclusive claim).
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit $executionTimeLimit -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        # Captured immediately before the call whose effect it's meant to bound -- see
        # $runEvidenceFloorUtc below and Get-DispatchPollAction's doc comment.
        $startedAtUtc = [DateTimeOffset]::UtcNow
        Start-ScheduledTask -TaskName $taskName
    }
    catch {
        # Registration/start itself never got the worker running at all -- this is the
        # ONE case where THIS launcher, not the worker, is the authority on what
        # happened, so it writes the durable outcome itself (overwriting the
        # DISPATCHING marker Node already wrote) rather than leaving review-engine.mjs
        # to guess from an ambiguous marker.
        $line = New-LauncherFailureLine -FailureKind 'TASK_SCHEDULE_FAILED' -Message "the scheduled task could not be registered or started: $($_.Exception.Message)"
        Write-LauncherOutcomeAtomic -Path $ResponsePath -Line $line
        Write-Output $line
        exit 0
    }

    # LastRunTime's own resolution is whole seconds, so
    # a same-second comparison against $startedAtUtc without a buffer can read "not yet run"
    # even though Task Scheduler already launched it moments after $startedAtUtc was
    # captured. 2s comfortably absorbs that truncation. Not a meaningful stale-evidence risk:
    # this exact task NAME was just freshly (re-)registered a few lines above (wiping any
    # prior LastRunTime), and distinct dispatch attempts always get distinct jobId-derived
    # task names.
    $runEvidenceFloorUtc = $startedAtUtc.AddSeconds(-2)

    while ([DateTimeOffset]::UtcNow -lt $waitUntilUtc) {
        Start-Sleep -Milliseconds 500
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $isRunningNow = [bool]($taskInfo -and $taskInfo.LastTaskResult -eq $script:SCHED_S_TASK_RUNNING)
        $hasRunEvidence = $false
        if ($taskInfo -and $taskInfo.LastRunTime) {
            try { $hasRunEvidence = ([DateTimeOffset]$taskInfo.LastRunTime) -ge $runEvidenceFloorUtc }
            catch { $hasRunEvidence = $false }
        }
        $outcomeLine = Read-TerminalOutcomeLine -Path $ResponsePath

        $pollAction = Get-DispatchPollAction -HasRunEvidence $hasRunEvidence -IsRunningNow $isRunningNow -OutcomeLine $outcomeLine
        if ($pollAction -eq 'DONE_WITH_OUTCOME') {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Output $outcomeLine
            exit 0
        }
        if ($pollAction -eq 'DONE_NO_OUTCOME') {
            # The task genuinely ran (real LastRunTime evidence, not just "we happened to
            # sample it mid-run") and is not running now, but ResponsePath still shows no
            # terminal outcome -- the worker exited without ever reaching its own catch-all
            # write (an extremely narrow window, e.g. a module-load failure before its own
            # try/catch is even entered). This launcher is now the only source of truth
            # left, so it writes a durable, specific failure rather than leaving the
            # ambiguous DISPATCHING marker in place forever. $taskInfo.LastTaskResult is
            # included because it's the one diagnostic fact Task Scheduler itself captured
            # about this exact failure (the worker's own bottom guard always `exit 0`s on
            # every path it ever reaches, so a non-zero value here can only come from
            # something outside that guard -- a real, actionable signal for a future
            # occurrence instead of a dead end).
            $line = New-LauncherFailureLine -FailureKind 'WORKER_PRODUCED_NO_OUTCOME' -Message "the scheduled task finished (LastTaskResult=$($taskInfo.LastTaskResult)) but the worker never wrote a terminal outcome"
            Write-LauncherOutcomeAtomic -Path $ResponsePath -Line $line
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Output $line
            exit 0
        }
        # KEEP_POLLING: covers both "still running" and "no run evidence yet" (which
        # includes a task Task Scheduler is silently refusing to start at all, e.g. a
        # battery power condition that somehow still applied) -- either way, not
        # conclusive yet, so loop again rather than guess.
    }

    # This launcher's own patience has run out without ever reaching a conclusive
    # DONE_* action -- the task may still genuinely be running server-side (or, in the
    # no-run-evidence case, may never have started at all). Deliberately do NOT
    # unregister the task and do NOT write anything to -ResponsePath here: doing either
    # could race a still-in-flight worker. Exiting with empty stdout is the existing,
    # already-safe "unknown outcome" path -- review-engine.mjs's recovery logic already
    # halts at worst-case on an ambiguous DISPATCHING marker (or picks up a real outcome
    # later via dispatchOutcomeStore.recall() if the worker finishes after this launcher
    # gives up).
    exit 0
}
