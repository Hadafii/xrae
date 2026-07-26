// LAYER: domain (pure)
// JOB:   Given a verdict, decide what X-Rae is allowed to do about it.
// MAY IMPORT: other domain files only.
//
// ============================================================================
// This file is where a detection becomes a business consequence, so it is
// written to be readable by someone who is not a programmer.
//
// The guiding rule, from the design doc:
//
//   A false negative costs a few cents of stolen CPU and gets caught next
//   cycle. A false positive costs a customer, a refund, and a bad review.
//   The cost ratio is roughly 1000:1, so this file must always FAIL TOWARDS
//   DOING NOTHING.
// ============================================================================

import { Confidence, isAtLeast } from './confidence.js';

/**
 * The response ladder. Higher number = more consequence for the customer.
 *
 * THROTTLE is the most valuable level and the old SonarX did not have it:
 * lowering a container's CPU quota removes almost all of the economic
 * incentive to mine, is instantly reversible, and if we are wrong the customer
 * merely gets a slower server instead of no server.
 *
 * Policy consequence: THROTTLE may be aggressive. SUSPEND must be conservative.
 */
export const ResponseLevel = Object.freeze({
  NONE: 'none',
  OBSERVE: 'observe',
  ALERT: 'alert',
  THROTTLE: 'throttle',
  SUSPEND: 'suspend',
  BLOCKED: 'blocked', // wanted to act, a guardrail stopped us
});

/** What the operator configured X-Rae to be allowed to do at most. */
export const PolicyMode = Object.freeze({
  /** Look, record, alert nobody automatically. The default. */
  OBSERVE: 'observe',
  /** Look and alert humans. Never touch a server. */
  ALERT: 'alert',
  /** May throttle, but never suspend. */
  THROTTLE: 'throttle',
  /** May suspend, subject to every guardrail below. */
  ENFORCE: 'enforce',
});

/**
 * @typedef {object} Decision
 * @property {string} level   a ResponseLevel
 * @property {string} reason  why, in plain language, for the audit log
 */

function decision(level, reason) {
  return Object.freeze({ level, reason });
}

/**
 * @typedef {object} CycleStats
 * @property {number} serversAssessed
 * @property {number} serversOverThreshold
 * @property {number} actionsTaken
 */

/**
 * Decides the response for one server.
 *
 * Deliberately has no knowledge of HTTP, Pterodactyl, Discord, or files. It
 * takes numbers in and returns a decision out, which is why it can be tested
 * exhaustively without any infrastructure.
 */
export class EnforcementPolicy {
  /**
   * @param {object} options
   * @param {string} options.mode                    a PolicyMode
   * @param {number} options.riskThreshold
   * @param {string} options.minConfidenceToAlert
   * @param {string} options.minConfidenceToThrottle
   * @param {string} options.minConfidenceToSuspend
   * @param {number} options.consecutiveDetections   cycles in a row before acting
   * @param {number} options.maxActionsPerCycle
   * @param {number} options.anomalyAbortRatio       0..1
   * @param {number} options.renotifyCooldownMinutes
   * @param {string[]} options.ignoredServers
   */
  constructor(options) {
    this.mode = options.mode;
    this.riskThreshold = options.riskThreshold;
    this.minConfidenceToAlert = options.minConfidenceToAlert;
    this.minConfidenceToThrottle = options.minConfidenceToThrottle;
    this.minConfidenceToSuspend = options.minConfidenceToSuspend;
    this.consecutiveDetections = options.consecutiveDetections;
    this.maxActionsPerCycle = options.maxActionsPerCycle;
    this.anomalyAbortRatio = options.anomalyAbortRatio;
    this.renotifyCooldownMinutes = options.renotifyCooldownMinutes;
    this.ignoredServers = options.ignoredServers ?? [];
  }

  /**
   * @param {object} input
   * @param {import('./scoring.js').Verdict} input.verdict
   * @param {{lastNotifiedAtMs?: number}} input.previous
   * @param {CycleStats} input.cycleStats
   * @param {string} input.serverId
   * @param {number} input.nowMs
   * @returns {Decision}
   */
  decide({ verdict, previous, cycleStats, serverId, nowMs }) {
    if (this.ignoredServers.includes(String(serverId))) {
      return decision(ResponseLevel.NONE, 'server is on the operator ignore list');
    }

    const isReportable = this.#isReportable(verdict);
    if (!isReportable) return decision(ResponseLevel.NONE, 'below reporting threshold');

    if (!isAtLeast(verdict.confidence, this.minConfidenceToAlert)) {
      return decision(ResponseLevel.NONE, `confidence ${verdict.confidence} is below the alert floor`);
    }

    if (this.#isInCooldown(previous, nowMs)) {
      return decision(ResponseLevel.NONE, 'already reported recently, staying quiet');
    }

    // From here on we are definitely telling a human. The question is only
    // whether we also touch the server.
    const intended = this.#intendedAction(verdict);

    // Both of these mean "tell a human, touch nothing", so they get the
    // explanation of why no action was taken rather than a generic message.
    if (intended === ResponseLevel.ALERT || intended === ResponseLevel.OBSERVE) {
      return decision(intended, this.#explainWhyNoAction(verdict));
    }

    const guardrail = this.#checkGuardrails(cycleStats);
    if (guardrail) return guardrail;

    return decision(intended, `verdict is ${verdict.confidence} across ${verdict.families.length} evidence family(ies)`);
  }

  /**
   * Worth telling a human about? Either it crossed the score threshold, or it
   * contains something unambiguous (a stratum URL needs no corroboration).
   */
  #isReportable(verdict) {
    const overThreshold = verdict.totalScore >= this.riskThreshold;
    const unambiguous = verdict.hasStandalone && isAtLeast(verdict.confidence, Confidence.CRITICAL);
    return overThreshold || unambiguous;
  }

  #isInCooldown(previous, nowMs) {
    const last = previous?.lastNotifiedAtMs ?? 0;
    if (!last) return false;
    return nowMs - last < this.renotifyCooldownMinutes * 60_000;
  }

  /** The strongest action the configuration and the evidence both permit. */
  #intendedAction(verdict) {
    if (this.mode === PolicyMode.OBSERVE) return ResponseLevel.OBSERVE;
    if (this.mode === PolicyMode.ALERT) return ResponseLevel.ALERT;

    const persistent = verdict.detections >= this.consecutiveDetections;
    const overThreshold = verdict.totalScore >= this.riskThreshold;

    if (
      this.mode === PolicyMode.ENFORCE &&
      overThreshold &&
      persistent &&
      isAtLeast(verdict.confidence, this.minConfidenceToSuspend)
    ) {
      return ResponseLevel.SUSPEND;
    }

    if (
      (this.mode === PolicyMode.ENFORCE || this.mode === PolicyMode.THROTTLE) &&
      overThreshold &&
      persistent &&
      isAtLeast(verdict.confidence, this.minConfidenceToThrottle)
    ) {
      return ResponseLevel.THROTTLE;
    }

    return ResponseLevel.ALERT;
  }

  #explainWhyNoAction(verdict) {
    if (this.mode === PolicyMode.OBSERVE || this.mode === PolicyMode.ALERT) {
      return `policy mode is "${this.mode}", so no action is taken`;
    }
    if (verdict.detections < this.consecutiveDetections) {
      return `seen in ${verdict.detections} of the required ${this.consecutiveDetections} consecutive cycles`;
    }
    return `confidence ${verdict.confidence} is below the action floor`;
  }

  /**
   * The anti-cascade guardrails. These exist because a bad rule must never be
   * able to turn itself into a fleet-wide outage.
   */
  #checkGuardrails(cycleStats) {
    // Guardrail 1: fleet anomaly.
    // There is no realistic scenario where a quarter of a node starts mining
    // at the same moment. If we see that, the far likelier explanation is that
    // our own detector is broken.
    const enoughSamplesToJudge = cycleStats.serversAssessed > 4;
    const trippedRatio = cycleStats.serversOverThreshold / Math.max(1, cycleStats.serversAssessed);

    if (enoughSamplesToJudge && trippedRatio > this.anomalyAbortRatio) {
      const percent = Math.round(trippedRatio * 100);
      return decision(
        ResponseLevel.BLOCKED,
        `${cycleStats.serversOverThreshold} of ${cycleStats.serversAssessed} servers (${percent}%) tripped this ` +
          `cycle, above the ${Math.round(this.anomalyAbortRatio * 100)}% anomaly limit. This pattern means the ` +
          'detector is faulty, not that the whole node is abusive. All action halted for this cycle.',
      );
    }

    // Guardrail 2: per-cycle action budget.
    if (cycleStats.actionsTaken >= this.maxActionsPerCycle) {
      return decision(
        ResponseLevel.BLOCKED,
        `the per-cycle action limit of ${this.maxActionsPerCycle} was already reached; deferred to the next cycle`,
      );
    }

    return null;
  }
}
