// LAYER: domain (pure)
// JOB:   Define what a single piece of evidence is, and refuse to create an
//        invalid one.
// MAY IMPORT: other domain files only.
//
// Design note for whoever maintains this next:
// "Family" is the most important field here. Two pieces of evidence from the
// same family are NOT independent - twenty files containing the same string is
// one fact, not twenty. The scoring rules in scoring.js lean entirely on this
// grouping, so if you add a new family, read that file first.

import { isValidConfidence } from './confidence.js';

/**
 * Independent sources of evidence. Independence is the whole point: agreement
 * between two families is meaningful, agreement inside one family is not.
 */
export const EvidenceFamily = Object.freeze({
  /** A known-bad string was found inside a file. */
  SIGNATURE: 'signature',
  /** The shape of the data matches something malicious (e.g. a pool config). */
  STRUCTURE: 'structure',
  /** Statistical property, e.g. entropy suggesting a packed binary. */
  ENTROPY: 'entropy',
  /** How the server behaves at runtime, e.g. CPU pinned flat. */
  BEHAVIOR: 'behavior',
  /** Who the container talks to, measured inside its own namespace. */
  NETWORK: 'network',
});

const ALL_FAMILIES = Object.values(EvidenceFamily);

/**
 * @typedef {object} Evidence
 * @property {string}  ruleId      stable identifier, e.g. "miner.stratum.tcp"
 * @property {string}  family      one of EvidenceFamily
 * @property {string}  category    human grouping, e.g. "MINER"
 * @property {number}  weight      raw contribution before fusion
 * @property {string}  confidence  one of Confidence
 * @property {boolean} standalone  may this alone justify a verdict?
 * @property {string}  detail      human-readable explanation
 */

/**
 * Build a validated Evidence object.
 *
 * Validation is strict on purpose. A malformed rule that silently produced
 * NaN weight would corrupt every score on the node, and the failure would be
 * invisible. Loud rejection at creation time is much cheaper.
 *
 * @returns {Evidence}
 */
export function createEvidence({ ruleId, family, category, weight, confidence, standalone = false, detail = '' }) {
  if (!ruleId || typeof ruleId !== 'string') throw new Error('Evidence needs a ruleId');
  if (!ALL_FAMILIES.includes(family)) throw new Error(`Evidence "${ruleId}" has unknown family "${family}"`);
  if (!Number.isFinite(weight) || weight < 0) throw new Error(`Evidence "${ruleId}" has invalid weight ${weight}`);
  if (!isValidConfidence(confidence)) throw new Error(`Evidence "${ruleId}" has invalid confidence "${confidence}"`);

  return Object.freeze({
    ruleId,
    family,
    category: category || 'UNKNOWN',
    weight: Math.round(weight),
    confidence,
    standalone: Boolean(standalone),
    detail: String(detail),
  });
}

/**
 * Group evidence by family. Returns a Map so ordering is stable.
 * @param {Evidence[]} evidence
 * @returns {Map<string, Evidence[]>}
 */
export function groupByFamily(evidence) {
  const grouped = new Map();
  for (const item of evidence) {
    if (!grouped.has(item.family)) grouped.set(item.family, []);
    grouped.get(item.family).push(item);
  }
  return grouped;
}

/**
 * Apply a multiplier to a piece of evidence, returning a new object.
 * Used for context weighting (a string in a log file means less than the same
 * string in an executable).
 * @param {Evidence} evidence
 * @param {number} multiplier
 * @returns {Evidence}
 */
export function reweigh(evidence, multiplier) {
  return createEvidence({ ...evidence, weight: evidence.weight * multiplier });
}
