// Local, free judgment for whether a REPEAT autonomous authorization is justified. Mirrors
// ollama-client.mjs's direct-HTTP-to-local-Ollama call shape (same endpoint convention, same
// fail-closed philosophy) but is a deliberately separate, smaller module: unlike
// ollama-client.mjs's PII/content-safety checks (a whole-document scan, chunked for large
// inputs -- see that file's own header for why), this judges a short, caller-supplied reason
// string. A justification reason is never document-sized, so no chunking is needed here.
//
// Fail-closed by construction: ok:false (unreachable, timeout, malformed response, an answer
// missing the required "justified" boolean) means "the judge could not run," and the caller
// (review-engine.mjs's repeat-authorization branch) MUST treat that the same as justified:false --
// never as an implicit pass. This module never guesses a default when it cannot parse a real
// answer.
//
// Deliberately no retry-with-backoff (unlike ollama-client.mjs's ask()): a transient failure here
// only denies ONE repeat-authorization attempt, which the caller can simply retry or fall back to
// the human-justification path for -- a much lower cost than ollama-client.mjs's own case, where a
// false-closed PII check forces redoing an entire slow, human-gated authorize cycle. Keeping this
// module to a single attempt avoids adding retry-timing complexity for a low-stakes-to-retry path.

function requireFunction(value, field) {
  if (typeof value !== 'function') throw new TypeError(`${field} must be a function`);
  return value;
}

function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${field} must be a non-empty string`);
  return value;
}

function requireNonNegativeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be a non-negative safe integer`);
  return value;
}

// The default answer is NO on purpose: this is a security gate, not a helpfulness prompt. Only a
// genuine operational necessity (the prior attempt visibly failed or never completed) should ever
// produce justified:true -- a request to simply spend more, review more, or route around a limit
// must not.
function buildPrompt({ reason, profile, priorLeaseCount }) {
  return [
    'You are a strict security gate. A document has ALREADY been auto-approved once for review',
    "under an automated system with no human watching. Now the SAME document's automated caller",
    'is asking to be approved again. Your default answer is NO. Only answer YES if the stated',
    'reason describes a genuine operational necessity -- the prior attempt visibly failed, timed',
    'out, or was never completed, and this is a legitimate retry of the SAME already-approved work',
    '-- rather than a request to spend more, review more, or bypass a limit.',
    '',
    `Review profile: ${profile}`,
    `Approvals already granted for this same document before this request: ${priorLeaseCount}`,
    `Caller's stated reason for requesting another approval: ${reason}`,
    '',
    'Respond with ONLY a single JSON object and nothing else: {"justified": boolean, "reasoning": "one short sentence"}',
  ].join('\n');
}

function parseJudgeResponse(raw) {
  if (typeof raw !== 'string') return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || typeof parsed.justified !== 'boolean') return null;
  const reasoning = typeof parsed.reasoning === 'string' && parsed.reasoning.length > 0 ? parsed.reasoning : 'no reasoning provided';
  return { justified: parsed.justified, reasoning };
}

export function createRepeatAuthorizationJudge({ fetchImpl, baseUrl, model, timeoutMs } = {}) {
  requireFunction(fetchImpl, 'fetchImpl');
  requireNonEmptyString(baseUrl, 'baseUrl');
  requireNonEmptyString(model, 'model');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be a positive safe integer');

  return Object.freeze({
    async judge({ reason, profile, priorLeaseCount } = {}) {
      requireNonEmptyString(reason, 'reason');
      requireNonEmptyString(profile, 'profile');
      requireNonNegativeInteger(priorLeaseCount, 'priorLeaseCount');

      let response;
      try {
        response = await fetchImpl(`${baseUrl}/api/generate`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            model,
            prompt: buildPrompt({ reason, profile, priorLeaseCount }),
            stream: false,
            truncate: false,
            options: { temperature: 0 },
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch {
        return { ok: false, justified: null, reasoning: null };
      }
      if (!response.ok) return { ok: false, justified: null, reasoning: null };

      let body;
      try {
        body = await response.json();
      } catch {
        return { ok: false, justified: null, reasoning: null };
      }

      const parsed = parseJudgeResponse(body?.response);
      if (parsed === null) return { ok: false, justified: null, reasoning: null };
      return { ok: true, ...parsed };
    },
  });
}
