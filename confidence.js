// LAYER: domain (pure)
// JOB:   Represent how sure we are about a finding, and compare levels safely.
// MAY IMPORT: nothing.
//
// Why this file exists: confidence is compared in several places. If those
// comparisons were plain string checks scattered around the codebase, one typo
// ("hihg") would silently disable a safety gate. Keeping the vocabulary and the
// comparison in one place makes that impossible.

/** The only four confidence levels that exist in this system. */
export const Confidence = Object.freeze({
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

/** Lowest to highest. Index in this array IS the ranking. */
const RANKING = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CRITICAL];

/**
 * @param {string} value
 * @returns {boolean} true if the string is a real confidence level
 */
export function isValidConfidence(value) {
  return RANKING.includes(value);
}

/**
 * @param {string} value
 * @returns {number} 0..3
 */
export function rankOf(value) {
  const index = RANKING.indexOf(value);
  if (index === -1) throw new Error(`Unknown confidence level: "${value}"`);
  return index;
}

/**
 * Is `actual` at least as confident as `minimum`?
 *
 * @example isAtLeast(Confidence.HIGH, Confidence.MEDIUM) // true
 */
export function isAtLeast(actual, minimum) {
  return rankOf(actual) >= rankOf(minimum);
}

/**
 * The highest level in a list. Returns LOW for an empty list.
 * @param {string[]} levels
 */
export function highestOf(levels) {
  return levels.reduce((best, level) => (rankOf(level) > rankOf(best) ? level : best), Confidence.LOW);
}

/**
 * Never let a value exceed a ceiling.
 * Used to stop a single self-declared "critical" rule from claiming certainty
 * that the overall evidence does not support.
 */
export function capAt(value, ceiling) {
  return rankOf(value) > rankOf(ceiling) ? ceiling : value;
}
