<#
Diagnostic instrumentation for intermittent STATUS_CONTROL_C_EXIT (0xC000013A) terminations of
the dispatch worker and its launcher: logs which console control signal arrived. Hiding the
worker's console window does not by itself rule out such terminations, and after-the-fact
inspection (Task Scheduler state, the Windows Event Log) cannot say which signal caused one,
so this module captures that evidence at the actual moment of failure.

Installs a native (not PowerShell-scriptblock) console control handler via
SetConsoleCtrlHandler. All logic runs as plain compiled C#, and deliberately never calls back
into the PowerShell engine from the handler thread -- SetConsoleCtrlHandler invokes its
callback on an OS-created thread outside the normal pipeline/runspace execution model, and
Windows PowerShell 5.1's runspace is not documented as safe to re-enter from an arbitrary
native callback thread. Keeping the handler as a static compiled method with no dependency
on the runspace avoids that risk entirely.

For CTRL_C and CTRL_BREAK, returning true from the handler suppresses the default
termination per the documented Win32 contract -- this diagnostic doubles as a real fix for
those two signal types if either turns out to be the actual cause here. CTRL_CLOSE,
CTRL_LOGOFF, and CTRL_SHUTDOWN cannot be suppressed this way (Windows forcibly terminates the
process a short, fixed time after delivery regardless of what any handler returns) -- but the
log line below is written synchronously inside the handler, before that forced termination,
so which one of the five occurred is captured either way.

Deliberately guarded by the caller (only installed when NOT dot-sourced -- see the
`$MyInvocation.InvocationName -ne '.'` check at each call site) so the existing test files for
both the worker and the launcher, which dot-source those scripts to exercise their pure
helper functions offline, never install a real native handler in the test process itself.
#>

Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace OpenRouterReviewDispatch {
    public static class ConsoleCtrlSignalLog {
        public delegate bool HandlerRoutine(uint ctrlType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentProcessId();

        // Held in a static field so the delegate is never garbage-collected while native code
        // still holds a reference to it -- a delegate passed to unmanaged code with no
        // surviving managed reference is a documented source of crashes once native code
        // later invokes a callback into freed memory.
        private static HandlerRoutine _handler;
        private static string _logPath;
        private static string _role;

        public static string DescribeCtrlType(uint ctrlType) {
            switch (ctrlType) {
                case 0: return "CTRL_C";
                case 1: return "CTRL_BREAK";
                case 2: return "CTRL_CLOSE";
                case 5: return "CTRL_LOGOFF";
                case 6: return "CTRL_SHUTDOWN";
                default: return "UNKNOWN_" + ctrlType;
            }
        }

        // Public (not private) so a test can exercise the logging/classification logic for
        // every signal type directly, including the three (CLOSE/LOGOFF/SHUTDOWN) that cannot
        // safely be triggered for real inside a test process without actually terminating it.
        public static bool HandleCtrl(uint ctrlType) {
            try {
                string line = DateTime.UtcNow.ToString("o") + "\trole=" + _role +
                    "\tpid=" + GetCurrentProcessId() + "\tsignal=" + DescribeCtrlType(ctrlType) + "\n";
                File.AppendAllText(_logPath, line);
            } catch { }
            // Only CTRL_C and CTRL_BREAK are suppressible; see the module header comment.
            return ctrlType == 0 || ctrlType == 1;
        }

        public static bool Install(string logPath, string role) {
            _logPath = logPath;
            _role = role;
            _handler = new HandlerRoutine(HandleCtrl);
            return SetConsoleCtrlHandler(_handler, true);
        }
    }
}
'@ -ErrorAction Stop

function Install-OpenRouterCtrlSignalLog {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][ValidateSet('launcher', 'worker')][string]$Role
    )
    $directory = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $installed = [OpenRouterReviewDispatch.ConsoleCtrlSignalLog]::Install($LogPath, $Role)
    if (-not $installed) {
        # Non-fatal: this is diagnostic instrumentation, not a safety mechanism the rest of
        # the script depends on. Losing it should never be why a dispatch fails.
        Write-Warning 'SetConsoleCtrlHandler registration failed; console-control diagnostics disabled for this process.'
    }
    return $installed
}
