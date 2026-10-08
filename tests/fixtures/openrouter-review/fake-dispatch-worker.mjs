// Fake dispatch worker for offline tests only.
//
// It stands in for tools/openrouter-review-dispatch.ps1 behind the same
// JS-level boundary the real worker's adapter will expose: dispatch({
// requestBytes, jobId }) -> { kind, envelopeJsonText }. It never accepts,
// stores, or could leak a credential -- there is no parameter for one, so
// `calls` (the log of every invocation) can never contain one either. That
// is the boundary the dispatch-worker tests exist to prove.

function requireRequest(request) {
  if (request === null || typeof request !== 'object') throw new TypeError('dispatch request must be an object');
  if (!Buffer.isBuffer(request.requestBytes)) throw new TypeError('requestBytes must be a Buffer');
  if (typeof request.jobId !== 'string' || request.jobId.length === 0) throw new TypeError('jobId must be a non-empty string');
  return request;
}

function defaultResponseOutcome() {
  return { httpStatus: 200, bodyText: '{"id":"gen_fake","choices":[]}' };
}

function buildResultLine(outcome) {
  if (outcome && outcome.kind === 'FAILURE') {
    return Object.freeze({
      kind: 'FAILURE',
      envelopeJsonText: JSON.stringify({
        failureKind: outcome.failureKind ?? 'INTERNAL_ERROR',
        message: outcome.message ?? 'fake dispatch worker failure',
      }),
    });
  }
  const resolved = outcome ?? defaultResponseOutcome();
  const bodyBytes = Buffer.isBuffer(resolved.bodyBytes) ? resolved.bodyBytes : Buffer.from(resolved.bodyText ?? '{}', 'utf8');
  return Object.freeze({
    kind: 'RESPONSE',
    envelopeJsonText: JSON.stringify({
      httpStatus: resolved.httpStatus ?? 200,
      bodyBase64: bodyBytes.toString('base64'),
    }),
  });
}

/**
 * Creates an isolated fake dispatch worker for one test. `responses`, when
 * given, is consumed in order (one entry per call); the last entry repeats
 * for any call beyond the list. With no `responses`, every call succeeds
 * with a small fixed fake response.
 */
export function createFakeDispatchWorker({ responses } = {}) {
  const calls = [];
  const queue = Array.isArray(responses) ? responses : null;

  async function dispatch(request) {
    const { requestBytes, jobId } = requireRequest(request);
    // Record only opaque, secret-free call shape -- byte length and job id,
    // nothing derived from request content and nothing credential-shaped.
    calls.push({ jobId, requestByteLength: requestBytes.length });
    const outcome = queue ? queue[Math.min(calls.length - 1, queue.length - 1)] : undefined;
    return buildResultLine(outcome);
  }

  return Object.freeze({ dispatch, calls });
}
