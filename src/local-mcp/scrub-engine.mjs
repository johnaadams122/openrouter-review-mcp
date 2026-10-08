import { createHmac } from 'node:crypto';
import { createLineClassifier, matchesIdentityList, NO_EXTRA_PROTECTED_TERMS } from './scrub-patterns.mjs';

function requireArray(value, field) {
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array`);
  return value;
}

function requirePlainObject(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${field} must be an object`);
  return value;
}

function requireFunction(value, field) {
  if (typeof value !== 'function') throw new TypeError(`${field} must be a function`);
  return value;
}

function requireStringArray(value, field) {
  requireArray(value, field);
  for (const entry of value) {
    if (typeof entry !== 'string') throw new TypeError(`${field} entries must be strings`);
  }
  return value;
}

// Categories that are NEVER substitution-eligible, regardless of project --
// hard-block-only by design (category-based, not project-based, so this
// automatically covers every project's most sensitive content without a
// project taxonomy). Secret-shaped hits are
// included: there is no legitimate reason to substitute-and-send a real
// credential either.
const HARD_BLOCK_CATEGORIES = new Set([
  'phi_vocabulary',
  'cui_dod_id',
  'private_key',
  'aws_key',
  'github_token',
  'slack_token',
  'vendor_api_key',
  'broker_credential',
  'generic_secret',
]);

// account_number_shape, dollar_figure, and identity-list hits are the only
// substitution-eligible categories -- anything else classifyLine() reports
// (via HARD_BLOCK_CATEGORIES above) never reaches the substitution path.
// 'mixed' is synthetic, assigned only when interval-merging (below) fuses
// spans from more than one of the three real categories into one span --
// there is no classifyLine()/identity category actually named 'mixed'.
const SUBSTITUTION_CATEGORY_PREFIX = {
  account_number_shape: 'ACCOUNT',
  dollar_figure: 'AMOUNT',
  identity: 'PERSON',
  mixed: 'REDACTED',
};

/**
 * Deterministic per-(preflightId, rawValue) placeholder: same real value +
 * same preflightId always derives the same token (required so CONTRACT_CHANGED
 * keeps working when a caller legitimately resubmits unchanged content at
 * document()/review() time, and so repeated mentions of the same value within
 * one document stay coherent to the reviewer) -- but a DIFFERENT preflightId
 * (a different review) always derives a different token, defeating
 * cross-review correlation. Found missing in an earlier revision of this
 * design: a stable/sequential label (ACCOUNT_1, ACCOUNT_2, ...) would leave
 * the visible text itself correlatable across reviews even though the
 * internal storage key was fresh -- the token itself must vary, not just
 * where it's stored.
 */
function derivePlaceholder(category, preflightId, rawValue) {
  const digest = createHmac('sha256', preflightId).update(rawValue, 'utf8').digest('hex').slice(0, 8);
  const prefix = SUBSTITUTION_CATEGORY_PREFIX[category];
  return `${prefix}_${digest}`;
}

// account_number_shape's own timestamp-suppression logic, duplicated from
// scrub-patterns.mjs (same pre-existing convention as the duplicated
// _NUM_SHAPE/_DOLLAR_TABLE regex literals below -- this module has never
// imported scrub-patterns.mjs's internals, only its two exported functions).
// MUST stay in agreement with classifyLine()'s own copy: this function
// decides which specific occurrences are substitution-eligible, and
// classifyLine() decides whether the category appears in categoriesOnLine
// at all -- if the two suppression decisions ever diverged, this function
// could run without classifyLine() having gated it, or vice versa.
const _TS_CONTEXT = /\b(?:epoch|unix|timestamp|created|updated|modified|dated|date|millis)\b|epoch_ms|_ms\b/i;

function plausibleTimestampOrDate(digits) {
  const n = Number(digits);
  if (n >= 946_684_800 && n <= 2_051_222_400) return true;
  if (n >= 946_684_800_000 && n <= 2_051_222_400_000) return true;
  if (digits.length === 8 && n >= 1990_01_01 && n <= 2035_12_31) return true;
  return false;
}

/**
 * Every account_number_shape/dollar_figure span in one line, as character
 * offsets -- ALL occurrences, not just the first. Only called for a category
 * classifyLine(line) already reported present somewhere on the line, but
 * this function makes its OWN per-occurrence substitution-eligibility
 * decision (via the same suppression logic as classifyLine(), duplicated
 * above) rather than trusting classifyLine()'s line-level yes/no to mean
 * "the whole line's occurrences are uniformly eligible" -- they aren't:
 * one occurrence on a line can be a suppressed plausible timestamp while
 * another, real one isn't.
 *
 * Why every occurrence: a first-match-only scan would never add a SECOND
 * real account number (or dollar figure) on a line to the interval-merge
 * span set at all -- so an identity-list entry's substitution landing
 * adjacent to that second, uncaptured occurrence could glue onto it with no
 * separator, defeating its \b word-boundary (see mergeSpans() below), and
 * neither the primary substitution nor the smell-test-1 backstop (which also
 * only locates the first occurrence, via classifyLine()) could catch it.
 * Both categories are affected: two account numbers on one line with an
 * identity-glue landing on the second would leak it unredacted, and so would
 * two dollar figures (no-comma variant, which has its own trailing \b).
 */
function findShapeSpans(line, category) {
  if (category === 'account_number_shape') {
    const hasTsContext = _TS_CONTEXT.test(line);
    const spans = [];
    for (const match of line.matchAll(/(?<!\d\.)\b\d{8,17}\b/g)) {
      if (hasTsContext && plausibleTimestampOrDate(match[0])) continue;
      spans.push({ start: match.index, end: match.index + match[0].length });
    }
    return spans;
  }
  if (category === 'dollar_figure') {
    // Kept in agreement with scrub-patterns.mjs's own _DOLLAR_TABLE: any
    // $-prefixed digit run with optional comma-grouping and an uncapped
    // decimal tail, so whole-dollar, single-decimal, and
    // 3+-decimal currency figures are all fully
    // substitution-eligible. Requiring comma-grouping or exactly two decimals
    // would miss whole-dollar and single-decimal figures entirely, and
    // capping the decimal tail at 1-2 digits would leak the excess decimal
    // digits glued onto the placeholder with no boundary.
    return [...line.matchAll(/\$\s?\d+(?:,\d{3})*(?:\.\d+)?\b/g)].map((match) => ({
      start: match.index,
      end: match.index + match[0].length,
    }));
  }
  return [];
}

/**
 * Every occurrence of every identityList entry against one line, as
 * character-offset {start, end} pairs -- case-insensitive substring search
 * (matching matchesIdentityList's own semantics), matched DIRECTLY against
 * the original, untransformed `line` via a regex with the 'i' flag, never
 * against a separately lowercased copy.
 *
 * Why not lowercase and indexOf: lowercasing both `line` and `entry`
 * (`line.toLowerCase()`, `entry.toLowerCase()`), locating matches with
 * `indexOf` in that lowered domain, and returning those SAME offsets to be
 * used against the ORIGINAL, un-lowercased `line` is unsafe. String.prototype.
 * toLowerCase() is not guaranteed length-preserving across the full Unicode
 * range -- e.g. 'İ' (Turkish capital dotless-I, U+0130) lowercases to a
 * 2-code-unit string ('i' + combining dot above, U+0307), not 1. Any
 * expanding character anywhere before a match (or inside the entry itself)
 * shifts every subsequent lowered-domain offset out of sync with the same
 * position in the real `line`, so slicing the original line at the
 * "matched" offset both leaks real name characters in plaintext and
 * records the wrong value in the mapping. For example, identityList:
 * ['jane q. public'] against 'İ prefix jane q. public was here' would
 * produce scrubbedText 'İ prefix jPERSON_...was here' (leading "j" leaked in
 * plaintext, and the recorded mapping value 'ane q. public ' -- wrong on
 * both ends). A second, independent trigger of the same root cause: an
 * entry that ITSELF contains an expanding character (e.g. 'İstanbul Corp')
 * overruns its own recorded length, silently swallowing the character right
 * after the match with no separator. Matching directly against `line` with
 * a case-insensitive regex closes both: `match.index`/`match[0].length` are
 * real positions in `line` itself, since neither `line` nor the entry is
 * ever transformed into a separately-lengthed copy before offsets are read.
 *
 * The scan below uses manual lastIndex stepping (search again from
 * match.index + 1), not matchAll()'s default non-overlapping advance-past-
 * end-of-match, deliberately permitting overlapping matches -- a
 * self-overlapping entry (a genuinely degenerate case) would otherwise lose
 * coverage of its own tail under a naive non-overlapping matchAll() scan.
 *
 * A whitespace-only entry (e.g. ' ', '\t') is skipped the same as an
 * empty-string entry -- trimmed length, not raw length, is what's checked:
 * an unguarded whitespace-only entry would over-match every run of that
 * whitespace anywhere in the document.
 */
function findIdentityIntervals(line, identityList) {
  const intervals = [];
  for (const entry of identityList) {
    if (entry.trim().length === 0) continue;
    const pattern = new RegExp(entry.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    let searchFrom = 0;
    while (searchFrom <= line.length) {
      pattern.lastIndex = searchFrom;
      const match = pattern.exec(line);
      if (!match) break;
      intervals.push({ start: match.index, end: match.index + match[0].length });
      searchFrom = match.index + 1;
    }
  }
  return intervals;
}

/**
 * Standard interval-merging sweep over EVERY substitution-eligible span in a
 * line -- identity, account_number_shape, and dollar_figure spans together,
 * not identity spans alone. Sort by start, then merge the next span into the
 * current run whenever it starts at or before the run's current end (start
 * <= end catches both overlap and exact touching), carrying forward the set
 * of source categories each merged run absorbed.
 *
 * Why one unified pass: substituting identity matches first (against the
 * original text), THEN account_number_shape/dollar_figure matches (against
 * the ALREADY identity-substituted text) via two separate sequential passes
 * leaks across categories.
 * account_number_shape's detector (_NUM_SHAPE = /(?<!\d\.)\b\d{8,17}\b/)
 * requires a real \b word-boundary on both sides -- letters/digits/
 * underscore are all \w, so if an identityList entry carried a stray
 * leading/trailing space (an ordinary config typo), its substitution could
 * consume the whitespace adjacent to a digit run, GLUING the placeholder
 * token directly onto the digits with no separator and erasing the boundary
 * BOTH the primary substitution and the smell-test-1 backstop (same regex)
 * need to see. For example, an identityList entry with a trailing space,
 * matched against a line where the identity is followed by an eight-digit
 * account run, would produce a scrubbed text with the raw account number
 * glued directly onto the placeholder token -- unredacted, blocked:false.
 *
 * Interval-merging across ALL categories in one pass structurally
 * eliminates this class of bug: every substitution decision (for every
 * category) is made against the SAME original, untouched line, with real
 * original character positions, before any placeholder text exists anywhere
 * -- so no category's substitution can ever corrupt what boundary a
 * DIFFERENT category's detector needs. In the reproduction above, the
 * identity span (including its trailing space) and the account-number span
 * are exactly touching in the original line -- they now merge into ONE span
 * and get redacted as a single 'mixed'-category placeholder, so there is no
 * leftover digit run for any detector to (fail to) see in the first place.
 */
function mergeSpans(spans) {
  if (spans.length === 0) return [];
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const merged = [{ start: sorted[0].start, end: sorted[0].end, categories: new Set([sorted[0].category]) }];
  for (let i = 1; i < sorted.length; i += 1) {
    const current = sorted[i];
    const last = merged[merged.length - 1];
    if (current.start <= last.end) {
      last.end = Math.max(last.end, current.end);
      last.categories.add(current.category);
    } else {
      merged.push({ start: current.start, end: current.end, categories: new Set([current.category]) });
    }
  }
  return merged;
}

function effectiveCategory(categories) {
  return categories.size === 1 ? [...categories][0] : 'mixed';
}

/**
 * Blocked category for a local-LLM check that could not run, from the
 * ollama-client `reason` (see ollama-client.mjs). Every branch BLOCKS -- the
 * distinction is diagnostic only. Collapsed into one label, a deterministic
 * context-window overflow on a large document (more tokens than the model's
 * 32,768-token window) reads as `local_llm_unavailable` even while Ollama is
 * healthy, which sends diagnosis in the wrong direction; it has its own name
 * instead.
 *
 * Anything unrecognized -- including a client that reports no reason at all
 * -- falls back to `local_llm_unavailable`, which still blocks. Fail-closed
 * must never depend on recognizing the label.
 *
 * The lookup is own-property-only (Object.hasOwn), not a bare `table[reason]`:
 * a reason string of 'constructor' / 'toString' / 'valueOf' would otherwise
 * resolve up Object.prototype and put a FUNCTION into blockedCategories,
 * which review-engine.mjs joins straight into its operator-facing
 * CONTENT_BLOCKED message. It blocks either way -- this is about the mapping
 * answering only for keys it actually owns.
 *
 * `chunk_budget_exceeded` names ollama-client.mjs's own request-count ceiling
 * for one check call, distinct from a genuine context-window overflow, for
 * the same keep-distinct-causes-distinct reasoning this table already exists
 * for.
 */
const LOCAL_LLM_FAILURE_CATEGORY = Object.freeze({
  context_overflow: 'local_llm_context_overflow',
  timeout: 'local_llm_timeout',
  unavailable: 'local_llm_unavailable',
  chunk_budget_exceeded: 'local_llm_chunk_budget_exceeded',
});

function localLlmFailureCategory(check) {
  const reason = check?.reason;
  if (typeof reason === 'string' && Object.hasOwn(LOCAL_LLM_FAILURE_CATEGORY, reason)) {
    return LOCAL_LLM_FAILURE_CATEGORY[reason];
  }
  return 'local_llm_unavailable';
}

/**
 * `extraProtectedTerms` is the owner-supplied { markers, contextTerms } set
 * (scrub-patterns.mjs): omitted means none, anything else must be a valid
 * term set or construction throws TypeError. Both production composers -- the
 * per-session server and the shared executor -- pass it explicitly from their
 * own explicit configuration, so a configured source cannot silently drop out.
 */
export function createScrubEngine({ identityList, ollamaClient, extraProtectedTerms = NO_EXTRA_PROTECTED_TERMS } = {}) {
  requireStringArray(identityList, 'identityList');
  // One classifier for both the first pass and the smell-test re-scan below, so a configured term
  // is held to the same rules on both.
  const classifyLine = createLineClassifier({ extraProtectedTerms });
  requirePlainObject(ollamaClient, 'ollamaClient');
  requireFunction(ollamaClient.checkUnknownThirdPartyPii, 'ollamaClient.checkUnknownThirdPartyPii');
  requireFunction(ollamaClient.checkReidentifiable, 'ollamaClient.checkReidentifiable');

  // In-process cache only -- the durable scrub-mapping-store is
  // wired in by review-engine.mjs, one level up, keyed the same way
  // (preflightId), so a mapping survives a process restart even though this
  // cache doesn't. Kept here too as a same-process fast path.
  const mappingCache = new Map();

  async function scrub({ text, preflightId } = {}) {
    if (typeof text !== 'string') throw new TypeError('text must be a string');
    if (typeof preflightId !== 'string' || preflightId.length === 0) throw new TypeError('preflightId must be a non-empty string');

    const hardBlocked = new Set();
    // Clone, never alias: mappingCache.get() returns the SAME object already
    // stored in the Map, not a copy. Aliasing it here meant every scrub()
    // call for this preflightId -- including one that ends up hard-blocked,
    // whose substitutions are never committed via mappingCache.set() -- was
    // still mutating the shared cached object in place before its own
    // hard-block check ran. For example, a blocked call containing an
    // identity match would leave that identity's placeholder->value pair
    // sitting in the shared object, and a later, unrelated successful call for
    // the same preflightId would then return it in its own `mapping` even
    // though the content that produced it was never actually sent anywhere --
    // exactly the kind of corruption the durable scrubMappingStore must not
    // ever persist.
    const mapping = { ...(mappingCache.get(preflightId) ?? {}) };

    const outputLines = [];
    for (const line of text.split('\n')) {
      const categoriesOnLine = classifyLine(line);
      for (const category of categoriesOnLine) {
        if (HARD_BLOCK_CATEGORIES.has(category)) hardBlocked.add(category);
      }

      // Collect every substitution-eligible span against this ORIGINAL,
      // untouched line -- identity, account_number_shape, dollar_figure --
      // all together, before any placeholder text exists. See mergeSpans()
      // above for why this must happen in one unified pass rather than as
      // separate sequential substitution passes.
      const spans = [];
      for (const interval of findIdentityIntervals(line, identityList)) {
        spans.push({ ...interval, category: 'identity' });
      }
      for (const category of categoriesOnLine) {
        if (category !== 'account_number_shape' && category !== 'dollar_figure') continue;
        for (const span of findShapeSpans(line, category)) {
          spans.push({ ...span, category });
        }
      }

      const mergedSpans = mergeSpans(spans);
      if (mergedSpans.length === 0) {
        outputLines.push(line);
        continue;
      }

      // Rebuild this line left-to-right, swapping each merged span (the
      // real substring at that span, preserving its actual casing) for its
      // placeholder. Spans are non-overlapping and ascending by construction
      // (mergeSpans' sort+sweep), so a single left-to-right pass over
      // `line`'s own offsets is safe -- no re-scanning of already-emitted
      // output, and no category's substitution ever runs against text a
      // different category's substitution already mutated.
      let redactedLine = '';
      let cursor = 0;
      for (const span of mergedSpans) {
        const matchedText = line.slice(span.start, span.end);
        const category = effectiveCategory(span.categories);
        const placeholder = derivePlaceholder(category, preflightId, matchedText.toLowerCase());
        // First occurrence anywhere in this review wins the recorded
        // casing (deliberate, not a bug): when the same real value recurs
        // with different casing, later mentions restore to whatever casing
        // was captured the first time this placeholder was ever assigned,
        // rather than the casing flapping per-mention. Applies uniformly
        // now -- previously only the identity path had this guard; digits
        // and $-figures are casing-invariant anyway, so unifying it changes
        // nothing observable for those categories.
        if (!(placeholder in mapping)) mapping[placeholder] = matchedText;
        redactedLine += line.slice(cursor, span.start) + placeholder;
        cursor = span.end;
      }
      redactedLine += line.slice(cursor);
      outputLines.push(redactedLine);
    }

    if (hardBlocked.size > 0) {
      return { blocked: true, blockedCategories: [...hardBlocked], scrubbedText: null };
    }

    const scrubbedText = outputLines.join('\n');

    // Unknown-third-party-PII check: run BEFORE the final smell test, on the
    // substituted text -- a known identity-list entry has already been
    // swapped above, so what remains here is either clean or a real
    // unlisted third party's combination of details (regex cannot recognize
    // an arbitrary human name, so only a semantic check can catch this).
    const thirdPartyCheck = await ollamaClient.checkUnknownThirdPartyPii(scrubbedText);
    if (!thirdPartyCheck.ok) {
      return { blocked: true, blockedCategories: [localLlmFailureCategory(thirdPartyCheck)], scrubbedText: null };
    }
    if (thirdPartyCheck.flagged) return { blocked: true, blockedCategories: ['unknown_third_party_pii'], scrubbedText: null };

    // Smell test 1: re-scan the substituted text with the same regex engine.
    // Any hit here means substitution didn't fully clean the payload --
    // hard block, never re-attempt substitution automatically. classifyLine()
    // never emits an identity category (identity detection is the wholly
    // separate findIdentityIntervals()/matchesIdentityList() path above), so
    // it alone can't re-check identity residue the way it re-checks
    // account_number_shape/dollar_figure -- re-run matchesIdentityList()
    // against the substituted text too, so identity substitution gets the
    // same defense-in-depth re-check every other substitution-eligible
    // category already had.
    for (const line of scrubbedText.split('\n')) {
      for (const category of classifyLine(line)) {
        if (HARD_BLOCK_CATEGORIES.has(category) || category === 'account_number_shape' || category === 'dollar_figure') {
          return { blocked: true, blockedCategories: [category], scrubbedText: null };
        }
      }
      if (matchesIdentityList(line, identityList)) {
        return { blocked: true, blockedCategories: ['identity_residual'], scrubbedText: null };
      }
    }

    // Smell test 2: local-LLM re-identification check. Fail-closed on
    // ok:false -- an unreachable check must never be silently treated as a
    // clean pass.
    const reidentifiableCheck = await ollamaClient.checkReidentifiable(scrubbedText);
    if (!reidentifiableCheck.ok) {
      return { blocked: true, blockedCategories: [localLlmFailureCategory(reidentifiableCheck)], scrubbedText: null };
    }
    if (reidentifiableCheck.flagged) return { blocked: true, blockedCategories: ['reidentifiable'], scrubbedText: null };

    // Freeze before both storing and returning: `mapping` is now the SAME
    // object reference in mappingCache and in the response, and a caller
    // (review-engine.mjs threads `mapping` onward) mutating its own copy in
    // place would otherwise silently
    // corrupt the cached copy too -- the same aliasing failure class the
    // clone-on-read fix above closes, recurring at the return boundary
    // instead of the read boundary. Freezing converts that from silent
    // corruption into a loud TypeError (strict mode) if it's ever attempted.
    Object.freeze(mapping);
    mappingCache.set(preflightId, mapping);
    return { blocked: false, blockedCategories: [], scrubbedText, mapping };
  }

  async function desubstitute({ text, preflightId, seedMapping } = {}) {
    if (typeof text !== 'string') throw new TypeError('text must be a string');
    if (typeof preflightId !== 'string' || preflightId.length === 0) throw new TypeError('preflightId must be a non-empty string');
    // MERGE seedMapping with the in-process cache -- never choose one
    // exclusively via `??`. scrub() unconditionally does mappingCache.set(preflightId,
    // mapping) on every successful call, EVEN ONE whose own mapping is `{}`
    // (nothing substitution-eligible in the text that particular call
    // scrubbed). In a fresh process, review()'s loadAndScrubSource() re-scrubs
    // only the re-supplied source_text -- if reviewContext is omitted (the
    // documented, majority-case calling convention) and the substitution-
    // eligible content actually lived in reviewContext (scrubbed only at
    // preflight() time, in a DIFFERENT, now-gone process), this fresh scrub()
    // call legitimately finds nothing and caches `{}`. `{}` is a real object,
    // not `undefined` -- `mappingCache.get(preflightId) ?? seedMapping` would
    // never fall back to seedMapping once that happened, so a real value
    // durably recorded in scrubMappingStore would never be restored: a finding
    // would keep showing the raw placeholder token forever, with no error
    // anywhere.
    //
    // Merging is safe unconditionally, not just as a defensive default:
    // every placeholder is a deterministic HMAC of (preflightId, real value)
    // (see derivePlaceholder above), so the SAME key can only ever exist in
    // both sides with the SAME real value -- scrub()'s own
    // `if (!(placeholder in mapping))` guard means a key, once set anywhere
    // for this preflightId, never changes value again for the rest of that
    // preflightId's lifetime, in-process or durable. There is no scenario
    // where the two sides disagree on a shared key, so which side "wins" on
    // overlap is moot for correctness; cached is spread last (wins) as the
    // fresher, just-validated-in-this-call value. What differs between the
    // two sides is only which KEYS each one happens to have -- exactly what
    // the union recovers.
    const cached = mappingCache.get(preflightId);
    const mapping = { ...(seedMapping ?? {}), ...(cached ?? {}) };
    if (Object.keys(mapping).length === 0) return text;
    let restored = text;
    for (const [placeholder, realValue] of Object.entries(mapping)) {
      restored = restored.split(placeholder).join(realValue);
    }
    return restored;
  }

  return Object.freeze({ scrub, desubstitute });
}
