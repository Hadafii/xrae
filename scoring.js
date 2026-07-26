// LAYER: domain (pure)
// JOB:   Turn a pile of evidence into a single score and confidence level.
// MAY IMPORT: other domain files only. No I/O, no clock, no config file.
//
// ============================================================================
// READ THIS BEFORE CHANGING ANY NUMBER IN THIS FILE
// ============================================================================
// This is the most safety-critical file in the project. Getting it wrong means
// suspending paying customers who did nothing wrong.
//
// The old SonarX did `score += weight` and stored the total forever. That is
// broken in three ways, and all three are fixed here:
//
//   1. UNBOUNDED       Enough weak indicators eventually beat any threshold.
//                      -> Fixed by FAMILY_CAPS.
//   2. FAKE INDEPENDENCE  The same rule matching 20 files counted 20 times.
//                      -> Fixed by deduplication + corroboration multiplier.
//   3. NO DECAY        A clean server gaining +5 of noise per cycle was
//                      GUARANTEED to cross 100 eventually. That is a timer,
//                      not a detector.
//                      -> Fixed by exponential decay.
//
// Why corroboration matters, with numbers (see design doc section 6.2):
// on a 200-server node with 1% abuse, a single-layer detector at 3% false
// positive rate gives 23% precision - meaning 77% of enforcement hits innocent
// customers. Requiring three independent families raises that to ~99%.
// ============================================================================

import { Confidence, capAt, highestOf } from './confidence.js';
import { groupByFamily } from './evidence.js';

/**
 * No single family may contribute more than this. Stops one noisy evidence
 * source from single-handedly reaching the threshold.
 */
export const FAMILY_CAPS = Object.freeze({
  signature: 80,
  structure: 50,
  entropy: 20,
  behavior: 30,
  network: 30,
});

/**
 * How much the total is worth given how many independent families agree.
 * One family alone is heavily discounted because one-family evidence is
 * exactly what benign files produce.
 */
export const CORROBORATION_MULTIPLIER = Object.freeze({
  0: 0,
  1: 0.45,
  2: 0.85,
  3: 1.0, // 3 or more
});

const DEFAULT_FAMILY_CAP = 40;

/**
 * @typedef {object} Verdict
 * @property {number}   cycleScore    points earned in this cycle alone
 * @property {number}   totalScore    decayed history + cycleScore
 * @property {string}   confidence
 * @property {string[]} families      which families contributed
 * @property {boolean}  hasStandalone was there an unambiguous indicator?
 * @property {number}   detections    consecutive cycles with findings
 * @property {import('./evidence.js').Evidence[]} reasons
 */

/** A verdict for a server where nothing at all was found. */
export function cleanVerdict(decayedScore = 0) {
  return Object.freeze({
    cycleScore: 0,
    totalScore: decayedScore,
    confidence: Confidence.LOW,
    families: [],
    hasStandalone: false,
    detections: 0,
    reasons: [],
  });
}

/**
 * Exponential decay. After one half-life, a score is worth half as much.
 *
 * @param {number} score
 * @param {number} updatedAtMs  when the score was last written
 * @param {number} halfLifeHours
 * @param {number} nowMs
 * @returns {number}
 */
export function decay(score, updatedAtMs, halfLifeHours, nowMs) {
  if (!score || !updatedAtMs) return 0;
  if (halfLifeHours <= 0) throw new Error('halfLifeHours must be greater than zero');

  const elapsedHours = (nowMs - updatedAtMs) / 3_600_000;
  if (elapsedHours <= 0) return score;

  const remaining = score * 0.5 ** (elapsedHours / halfLifeHours);
  // Below half a point is noise; round it away so records can be dropped.
  return remaining < 0.5 ? 0 : remaining;
}

/**
 * Collapse repeated hits of the same rule into one entry.
 * Keeps the heaviest instance and records how many others there were.
 *
 * @param {import('./evidence.js').Evidence[]} evidence
 * @returns {import('./evidence.js').Evidence[]}
 */
function deduplicateByRule(evidence) {
  /** @type {Map<string, {item: any, count: number}>} */
  const byRule = new Map();

  for (const item of evidence) {
    const existing = byRule.get(item.ruleId);
    if (!existing) {
      byRule.set(item.ruleId, { item, count: 1 });
      continue;
    }
    existing.count += 1;
    if (item.weight > existing.item.weight) existing.item = item;
  }

  return [...byRule.values()].map(({ item, count }) =>
    count === 1 ? item : { ...item, detail: `${item.detail} (+${count - 1} more location(s))` },
  );
}

/**
 * Decide the confidence level for a set of evidence.
 *
 * Two rules working in opposite directions:
 *   - A ceiling: poorly corroborated findings cannot claim high certainty,
 *     no matter what an individual rule declares about itself.
 *   - A promotion: three or more independent families agreeing on a "high"
 *     indicator is as strong as one unambiguous indicator. Without this,
 *     enforcement could only ever fire on standalone rules and the whole
 *     corroboration model would be decorative.
 */
function resolveConfidence(evidence, familyCount, hasStandalone) {
  const declared = highestOf(evidence.map((item) => item.confidence));
  if (hasStandalone) return declared;

  const ceiling =
    familyCount >= 3 ? Confidence.CRITICAL : familyCount === 2 ? Confidence.HIGH : Confidence.MEDIUM;

  const capped = capAt(declared, ceiling);
  if (capped === Confidence.HIGH && familyCount >= 3) return Confidence.CRITICAL;
  return capped;
}

/**
 * Fuses evidence into a Verdict.
 *
 * Deliberately a class rather than a bare function: it holds tuning parameters,
 * which makes it trivial to construct with test values and impossible to
 * accidentally depend on global config.
 */
export class ScoreCalculator {
  /**
   * @param {object} options
   * @param {number} options.halfLifeHours
   * @param {Record<string, number>} [options.familyCaps]
   * @param {number} [options.maxReasons] how many reasons to keep for reporting
   */
  constructor({ halfLifeHours, familyCaps = FAMILY_CAPS, maxReasons = 25 }) {
    if (!Number.isFinite(halfLifeHours) || halfLifeHours <= 0) {
      throw new Error('ScoreCalculator needs a positive halfLifeHours');
    }
    this.halfLifeHours = halfLifeHours;
    this.familyCaps = familyCaps;
    this.maxReasons = maxReasons;
  }

  /**
   * @param {object} input
   * @param {import('./evidence.js').Evidence[]} input.evidence
   * @param {{score: number, updatedAtMs: number, detections: number}} input.previous
   * @param {number} input.nowMs
   * @returns {Verdict}
   */
  calculate({ evidence, previous, nowMs }) {
    const decayedHistory = decay(previous.score ?? 0, previous.updatedAtMs ?? 0, this.halfLifeHours, nowMs);

    if (evidence.length === 0) return cleanVerdict(decayedHistory);

    const unique = deduplicateByRule(evidence);
    const byFamily = groupByFamily(unique);

    let cappedTotal = 0;
    for (const [family, items] of byFamily) {
      const familyTotal = items.reduce((sum, item) => sum + item.weight, 0);
      cappedTotal += Math.min(familyTotal, this.familyCaps[family] ?? DEFAULT_FAMILY_CAP);
    }

    const families = [...byFamily.keys()];
    const hasStandalone = unique.some((item) => item.standalone);
    const multiplier = hasStandalone
      ? 1.0
      : CORROBORATION_MULTIPLIER[Math.min(families.length, 3)] ?? 1.0;

    const cycleScore = Math.round(cappedTotal * multiplier);

    return Object.freeze({
      cycleScore,
      totalScore: decayedHistory + cycleScore,
      confidence: resolveConfidence(unique, families.length, hasStandalone),
      families,
      hasStandalone,
      detections: cycleScore > 0 ? (previous.detections ?? 0) + 1 : 0,
      reasons: unique.sort((a, b) => b.weight - a.weight).slice(0, this.maxReasons),
    });
  }
}
