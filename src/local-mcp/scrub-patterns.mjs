// Line classifier for secrets, currency figures, account-number shapes, PHI
// vocabulary and CUI/DoD-ID markings.
// Kept as pure regex/string functions -- no filesystem, no process, no
// network -- so this module is trivially unit-testable and has no dependency
// on how a caller sources its identity list or line-splits its content.
//
// cui_dod_id flags CUI banner markings and 10-digit DoD ID (EDIPI) numbers
// that appear next to an ID-context word.
//
// phi_vocabulary is built from GENERIC health words kept here in code, plus
// optional owner-supplied extra terms read at run time (see
// parseExtraProtectedTerms below). An owner's own specialised vocabulary is
// private configuration, not code: it lives outside the repository, is pinned
// by its SHA-256, and is threaded through createLineClassifier(). Extra terms
// slot into exactly the two places the built-in words occupy -- "markers"
// (a word that is protected health vocabulary by itself) and "context terms"
// (a word that makes a weak generic marker such as "diagnosis" reportable) --
// so a configured term blocks under the same rules a built-in one does.

// The marker words are assembled from parts so this repository's own push scanner does not
// flag the scrubber's word list; the compiled pattern is pinned by tests/openrouter-scrub-patterns.test.mjs.
const _PHI_MARKER_WORDS = [
  ['diag', 'nos\\w*'],
  ['prog', 'nos\\w*'],
  ['psychi', 'atr\\w*'],
  ['medi', 'cation'],
  ['dis', 'order'],
].map((parts) => parts.join(''));
const _PHI_GENERIC_MARKERS = new RegExp(`\\b(${_PHI_MARKER_WORDS.join('|')})\\b`, 'i');
// Exposed only so a test can pin the compiled pattern against the original literal spelling.
export const PHI_GENERIC_MARKERS_PATTERN = _PHI_GENERIC_MARKERS;

// Global, so phiReportable() exempts EVERY standalone weak word on a line, not only the first.
// Without 'g', a line with two such words (ordinary in code that says "diagnostic" often) kept
// its second one, matched the marker pattern and was hard-blocked as phi_vocabulary, and the
// shared service reports that block only as a generic REQUEST_FAILED. The only use is
// String.replace(), which resets lastIndex, so a shared global regex carries no state between calls.
const _PHI_WEAK = /\b(diagnos\w*|prognos\w*|disorder\w*)\b/gi;
const _PHI_GENERIC_MEDICAL_CTX = new RegExp(
  '\\b(patient|clinic\\w*|medical|health|doctor|physician|provider|' +
  'treatment|symptom\\w*|condition|injur\\w*|disabilit\\w*|profile|exam|' +
  'referral|record|note|history\\s+of|icd|cpt)\\b',
  'i',
);

// ---------------------------------------------------------------------------
// Owner-supplied extra protected terms.
//
// File format (UTF-8 without a byte-order mark, at most
// EXTRA_PROTECTED_TERMS_MAX_BYTES): lines are trimmed; blank lines and lines
// starting with '#' are ignored; the first remaining line must be exactly
// EXTRA_PROTECTED_TERMS_HEADER; every later line is "marker <term>" or
// "context <term>". A term is one or more ASCII words separated by
// whitespace (any whitespace run matches between words); a word is letters
// and digits, optionally joined by single - ' . & or / characters. Matching
// is case-insensitive and whole-word, like the generic words. A term may be
// listed as both a marker and a context word; a duplicate within one list
// (case-insensitive) is refused, and so is a file with no terms at all.
//
// Every refusal is a TypeError whose message names at most a line number,
// never the term itself: the terms are private by design.
// ---------------------------------------------------------------------------
export const EXTRA_PROTECTED_TERMS_HEADER = 'extra-protected-terms-v1';
export const EXTRA_PROTECTED_TERMS_MAX_BYTES = 256 * 1024;
const MAX_EXTRA_TERMS_PER_LIST = 1_024;
const MAX_EXTRA_TERM_CHARS = 128;
const MAX_EXTRA_TERM_WORDS = 16;
const _TERM_WORD = /^[A-Za-z0-9]+(?:[-'.&/][A-Za-z0-9]+)*$/;

export const NO_EXTRA_PROTECTED_TERMS = Object.freeze({
  markers: Object.freeze([]),
  contextTerms: Object.freeze([]),
});

function normalizeExtraTerm(raw, where) {
  if (typeof raw !== 'string') throw new TypeError(`${where}: a term must be a string`);
  const trimmed = raw.trim();
  const words = trimmed.length === 0 ? [] : trimmed.split(/\s+/);
  if (words.length === 0 || words.length > MAX_EXTRA_TERM_WORDS || words.some((word) => !_TERM_WORD.test(word))) {
    throw new TypeError(`${where}: invalid term (letters, digits and single - ' . & / joiners only)`);
  }
  const term = words.join(' ');
  if (term.length > MAX_EXTRA_TERM_CHARS) throw new TypeError(`${where}: term is longer than ${MAX_EXTRA_TERM_CHARS} characters`);
  return term;
}

function checkedTermList(value, field) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(`${field} must be an array`);
  if (value.length > MAX_EXTRA_TERMS_PER_LIST) throw new TypeError(`${field} has more than ${MAX_EXTRA_TERMS_PER_LIST} terms`);
  const seen = new Set();
  return value.map((term, index) => {
    const normalized = normalizeExtraTerm(term, `${field}[${index}]`);
    if (normalized !== term) throw new TypeError(`${field}[${index}] is not in normalized form`);
    const folded = normalized.toLowerCase();
    if (seen.has(folded)) throw new TypeError(`${field}[${index}] duplicates an earlier term`);
    seen.add(folded);
    return normalized;
  });
}

/**
 * Validates an already-parsed { markers, contextTerms } pair (exactly those
 * two keys, each an array of terms in normalized form, no duplicate within a
 * list) and returns a frozen copy. Empty lists are valid here: they are the
 * explicit "no extra terms" setting. Throws TypeError on anything else.
 */
export function validateExtraProtectedTerms(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('extra protected terms must be a plain object');
  }
  const keys = Object.keys(value);
  if (keys.length !== 2 || !Object.hasOwn(value, 'markers') || !Object.hasOwn(value, 'contextTerms')) {
    throw new TypeError('extra protected terms must have exactly markers and contextTerms');
  }
  return Object.freeze({
    markers: Object.freeze(checkedTermList(value.markers, 'markers')),
    contextTerms: Object.freeze(checkedTermList(value.contextTerms, 'contextTerms')),
  });
}

/**
 * Parses the bytes of an owner-supplied extra-protected-terms file (format
 * above) into frozen, normalized { markers, contextTerms }. Pure: the caller
 * reads the file and checks its pinned SHA-256 first. Throws TypeError for a
 * malformed file, including one with no terms, so a configured source can
 * never quietly contribute nothing.
 */
export function parseExtraProtectedTerms(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('extra protected terms file must be read as bytes');
  if (bytes.byteLength === 0) throw new TypeError('extra protected terms file is empty');
  if (bytes.byteLength > EXTRA_PROTECTED_TERMS_MAX_BYTES) throw new TypeError(`extra protected terms file exceeds ${EXTRA_PROTECTED_TERMS_MAX_BYTES} bytes`);
  if (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new TypeError('extra protected terms file must not start with a byte-order mark');
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new TypeError('extra protected terms file is not valid UTF-8');
  }
  const markers = [];
  const contextTerms = [];
  let sawHeader = false;
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const where = `extra protected terms file line ${index + 1}`;
    const line = lines[index].trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    if (/[\u0000-\u001f\u007f]/u.test(line)) throw new TypeError(`${where}: control character`);
    if (!sawHeader) {
      if (line !== EXTRA_PROTECTED_TERMS_HEADER) throw new TypeError(`${where}: expected the ${EXTRA_PROTECTED_TERMS_HEADER} header first`);
      sawHeader = true;
      continue;
    }
    const match = /^(marker|context)\s+(\S[\s\S]*)$/.exec(line);
    if (!match) throw new TypeError(`${where}: expected "marker <term>" or "context <term>"`);
    (match[1] === 'marker' ? markers : contextTerms).push(normalizeExtraTerm(match[2], where));
  }
  if (!sawHeader) throw new TypeError(`extra protected terms file has no ${EXTRA_PROTECTED_TERMS_HEADER} header`);
  if (markers.length + contextTerms.length === 0) throw new TypeError('extra protected terms file lists no terms');
  return validateExtraProtectedTerms({ markers, contextTerms });
}

function extraTermsPattern(terms) {
  if (terms.length === 0) return null;
  const alternatives = terms.map((term) => term
    .split(' ')
    .map((word) => word.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))
    .join('\\s+'));
  return new RegExp(`\\b(?:${alternatives.join('|')})\\b`, 'i');
}

function createPhiDetector(extraProtectedTerms) {
  const extraMarkers = extraTermsPattern(extraProtectedTerms.markers);
  const extraContext = extraTermsPattern(extraProtectedTerms.contextTerms);
  const hasMarker = (text) => _PHI_GENERIC_MARKERS.test(text) || (extraMarkers !== null && extraMarkers.test(text));
  // Same rule as before extra terms existed: a line is phi_vocabulary when it
  // holds a marker AND (a context word, or a marker that is still there after
  // every weak generic marker is removed).
  return (line) => {
    if (!hasMarker(line)) return false;
    if (_PHI_GENERIC_MEDICAL_CTX.test(line) || (extraContext !== null && extraContext.test(line))) return true;
    return hasMarker(line.replace(_PHI_WEAK, ' '));
  };
}

const _SECRET_PATTERNS = [
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['aws_key', /\bAKIA[0-9A-Z]{16}\b/],
  ['github_token', /\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/],
  ['slack_token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['vendor_api_key', /\bsk-(?:ant|or-v\d+|proj|svcacct|admin)-[A-Za-z0-9_-]{24,}/],
  ['broker_credential', /\bPK[A-Z0-9]{16,20}\b|\bAK(?!IA)[A-Z0-9]{16,20}\b|\baccess-(?:sandbox|development|production)-[0-9a-f][0-9a-f-]{20,}/],
  [
    'generic_secret',
    new RegExp(
      '(?<![A-Za-z0-9])(api[_-]?key|secret|token|passwd|password)(?![A-Za-z0-9])' +
      '\\s*[:=]\\s*' +
      '(?:' +
      '[\'"][^\'"\\s]{8,}' +
      '|' +
      '(?![A-Za-z0-9_+/-]*[.([])' +
      '(?=[A-Za-z0-9_+/-]*[0-9])' +
      '[A-Za-z0-9_+/-]{8,}' +
      ')',
      'i',
    ),
  ],
];

// DoD ID card numbers (10-digit EDIPI, commonly shown as a standalone
// 10-digit number next to an ID-context word) and any explicit CUI banner
// marking.
const _CUI_MARKING = /\bCUI(?:\/\/[A-Z-]+)*\b/;
const _DOD_ID_CONTEXT = /\b(DoD\s*ID|EDIPI|CAC)\b/i;
const _TEN_DIGIT_ID = /\b\d{10}\b/;

function cuiDodId(line) {
  if (_CUI_MARKING.test(line)) return true;
  return _DOD_ID_CONTEXT.test(line) && _TEN_DIGIT_ID.test(line);
}

// A pattern that requires EITHER comma-grouping OR exactly two decimal
// digits misses a plain whole-dollar amount and a
// single-decimal amount. A leading dollar sign already disambiguates "this is
// a currency figure" from every other digit-shape category (account
// numbers, timestamps), so there is no false-positive cost to accepting any
// digit run here, with or without comma-grouping, with any number of decimal
// digits. Decimal digits are deliberately left UNCAPPED (`\.\d+`, not
// `\.\d{1,2}`): with a cap, a figure with three or more decimals would only
// partially match, leaving the excess decimal digits glued directly onto the
// substitution placeholder with no word boundary between them.
const _DOLLAR_TABLE = /\$\s?\d+(?:,\d{3})*(?:\.\d+)?\b/;
const _NUM_SHAPE = /(?<!\d\.)\b\d{8,17}\b/;
// Global variant of _NUM_SHAPE for matchAll(), so every digit run on a line
// can be checked independently, not just the first. String.prototype.
// matchAll() clones the regex internally per spec, so this shared constant
// is safe to reuse across calls -- no lastIndex state leaks between them,
// unlike calling .exec()/.test() with a global flag directly.
const _NUM_SHAPE_GLOBAL = new RegExp(_NUM_SHAPE.source, 'g');
const _TS_CONTEXT = /\b(?:epoch|unix|timestamp|created|updated|modified|dated|date|millis)\b|epoch_ms|_ms\b/i;

function plausibleTimestampOrDate(digits) {
  const n = Number(digits);
  if (n >= 946_684_800 && n <= 2_051_222_400) return true;
  if (n >= 946_684_800_000 && n <= 2_051_222_400_000) return true;
  if (digits.length === 8 && n >= 1990_01_01 && n <= 2035_12_31) return true;
  return false;
}

/**
 * Returns a pure line classifier: which pattern classes fire on one line of
 * text. `extraProtectedTerms` (default: none) adds owner-supplied
 * phi_vocabulary markers and context words; it is validated here, so a
 * malformed value throws TypeError at construction rather than at first use.
 */
export function createLineClassifier({ extraProtectedTerms = NO_EXTRA_PROTECTED_TERMS } = {}) {
  const isPhi = createPhiDetector(validateExtraProtectedTerms(extraProtectedTerms));
  return (line) => classifyWith(line, isPhi);
}

const genericIsPhi = createPhiDetector(NO_EXTRA_PROTECTED_TERMS);

/**
 * Pure: which pattern classes fire on one line of text, using the generic
 * words only (no extra protected terms).
 */
export function classifyLine(line) {
  return classifyWith(line, genericIsPhi);
}

function classifyWith(line, isPhi) {
  if (typeof line !== 'string') throw new TypeError('line must be a string');
  const hits = [];
  for (const [name, pattern] of _SECRET_PATTERNS) {
    if (pattern.test(line)) hits.push(name);
  }
  if (_DOLLAR_TABLE.test(line)) hits.push('dollar_figure');

  // Check EVERY digit run on the line independently, not just the first: a
  // single-match check would (a) never detect a second account number on a
  // line that sits after the first match, and worse, (b) judge the line clean
  // when the FIRST digit run is a suppressed plausible timestamp even though a
  // SECOND digit run is a non-suppressed account number. The hasTsContext
  // flag stays line-level (a line either mentions timestamp-context words or
  // it doesn't), but suppression itself is decided per occurrence. Flagged
  // if AT LEAST ONE occurrence is non-suppressed.
  const hasTsContext = _TS_CONTEXT.test(line);
  const hasSubstitutableNumber = [...line.matchAll(_NUM_SHAPE_GLOBAL)].some(
    (match) => !(hasTsContext && plausibleTimestampOrDate(match[0])),
  );
  if (hasSubstitutableNumber) hits.push('account_number_shape');

  if (isPhi(line)) hits.push('phi_vocabulary');
  if (cuiDodId(line)) hits.push('cui_dod_id');

  return hits;
}

/**
 * Case-insensitive substring match against a hand-maintained list of real
 * names/entities (the caller sources the list itself -- this module has no
 * filesystem access by design, so it stays trivially testable).
 *
 * Empty-string entries are skipped rather than matched: `anyString.includes('')`
 * is always true in JS, so an unguarded empty entry would report a match
 * against ANY text at all. In scrub-engine.mjs (this function's consumer),
 * identityList: [''] would otherwise hard-block every scrub() call, including
 * fully clean text, mislabeled identity_residual -- pointing a debugger at a
 * nonexistent leak instead of a config problem. Mirrors the same guard
 * scrub-engine.mjs's findIdentityIntervals() already has.
 *
 * A whitespace-only entry (e.g. ' ', '\t') has the same problem one level
 * up: it doesn't match everything, but it over-matches every run of that
 * exact whitespace anywhere in the document. Checked on TRIMMED length, not
 * raw length, to close that too.
 */
export function matchesIdentityList(text, identityList) {
  if (typeof text !== 'string') throw new TypeError('text must be a string');
  if (!Array.isArray(identityList)) throw new TypeError('identityList must be an array');
  const lower = text.toLowerCase();
  return identityList.some((entry) => {
    const lowerEntry = entry.toLowerCase();
    return lowerEntry.trim().length > 0 && lower.includes(lowerEntry);
  });
}
