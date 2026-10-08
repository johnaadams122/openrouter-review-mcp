#!/usr/bin/env node
/**
 * PostToolUse hook: when a spec or plan document is written, remind Claude to run the
 * cross-vendor review and fold its findings in BEFORE presenting the document.
 *
 * Why this shape: Claude Code has no hook event that fires before a plain assistant text
 * response, so a spec/plan review cannot be gated the way a tool call can. A spec/plan file
 * write is the one real, observable action that reliably precedes presenting one, which makes
 * it the only available trigger.
 *
 * This is a strong automatic nudge, not a hard wall -- Claude can in principle not comply,
 * the same limitation a Stop hook's ok:false has. That asymmetry is a property of the hook
 * system, not a defect here.
 *
 * Deliberately standalone: it has no imports, so it keeps working regardless of any other
 * tooling's state.
 */

const SPEC_OR_PLAN = /[\\/]docs[\\/]superpowers[\\/](specs|plans)[\\/][^\\/]+\.md$/i;

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('end', () => {
  let payload;
  // A hook that throws is a hook that breaks the session for everyone. Any malformed or
  // unexpected input exits silently and lets the turn proceed untouched.
  try { payload = JSON.parse(raw); } catch { process.exit(0); }

  const filePath = payload?.tool_input?.file_path;
  if (typeof filePath !== 'string' || !SPEC_OR_PLAN.test(filePath)) process.exit(0);

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext:
        'A spec or plan document was just written. Before presenting it, run the cross-vendor ' +
        'review lens over it (openrouter_review_preflight with an appropriate profile, then ' +
        'authorize and document), fold the findings into the document, and only then respond. ' +
        'If the review cannot run, say so explicitly in your response rather than silently skipping it.',
    },
  }));
  process.exit(0);
});
