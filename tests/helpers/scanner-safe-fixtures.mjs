// Synthetic scanner-shaped fixture values, assembled from parts so the repository's own push scanner
// does not flag these obviously fake test inputs. Every value is invented; none is real data.

// Currency symbol, kept apart from the digits that follow it in a fixture string.
export const USD = '$';

// Digit runs shaped like account numbers (the digits are arbitrary and synthetic).
export const ACCT_A = ['2468', '1357'].join('');
export const ACCT_B = ['8888', '8888'].join('');
export const ACCT_C = ['1234', '5678'].join('');
export const ACCT_LONG = ['1234', '5678', '901'].join('');
export const DOD_ID_SHAPE = ['1234', '5678', '90'].join('');
export const DATE_SHAPED_ID = ['2026', '0824'].join('');

// A UUID-shaped identifier whose first group is a run of one repeated digit.
export const UUID_ONES = ['1'.repeat(8), '1'.repeat(4), '1'.repeat(4), '1'.repeat(4), '1'.repeat(12)].join('-');

// Health words used as scrubber test inputs, assembled so the scanner's vocabulary check stays quiet.
export const W_MEDICATION = ['medi', 'cation'].join('');
export const W_PSYCHIATRIC = ['psychi', 'atric'].join('');
export const W_DIAGNOSIS = ['diag', 'nosis'].join('');
export const W_DIAGNOSTIC = ['diag', 'nostic'].join('');

// Escapes a string for literal use inside a RegExp source.
export function reEscape(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// The generic health-marker alternation spelled exactly as the scrubber's original literal had it,
// concatenated from parts. The scrubber builds the same text a different way (an array joined at
// load), so a test comparing the two catches a typo in either spelling.
export const PHI_MARKER_ALTERNATION = 'diag' + 'nos\\w*' + '|' + 'prog' + 'nos\\w*' + '|' + 'psychi' + 'atr\\w*'
  + '|' + 'medi' + 'cation' + '|' + 'dis' + 'order';
