// LAYER: application
// JOB:   Orchestrate one complete scan cycle.
// MAY IMPORT: domain, and the port contracts. Never infrastructure.
//
// ============================================================================
// WHY THIS IS SPLIT INTO TWO PHASES
// ============================================================================
// Phase 1: assess every server, decide nothing.
// Phase 2: now that we know how many servers tripped, decide and act.
//
// The old SonarX decided inside the loop. That made the fleet-anomaly guardrail
// impossible: by the time you noticed half the node was flagged, you had
// already suspended the first half. Two phases is not extra ceremony - it is
// the only ordering in which the guardrail can work.
// ============================================================================

import { ResponseLevel } from '../domain/policy.js';

/** What one server looked like after phase 1. */
class Assessment {
  constructor(server, previous, verdict) {
    this.server = server;
    this.previous = previous;
    this.verdict = verdict;
  }
}

export class RunScanCycle {
  /**
   * All dependencies are injected. There is no `new` of anything concrete in
   * this file, which is what makes it testable without a panel or a filesystem.
   *
   * @param {object} deps
   * @param {import('./ports.js').ServerRepository} deps.serverRepository
   * @param {import('./collect-evidence.js').EvidenceCollectionService} deps.evidenceService
   * @param {import('../domain/scoring.js').ScoreCalculator} deps.scoreCalculator
   * @param {import('../domain/policy.js').EnforcementPolicy} deps.policy
   * @param {import('./ports.js').StateRepository} deps.stateRepository
   * @param {import('./ports.js').Notifier} deps.notifier
   * @param {import('./ports.js').Enforcer} deps.enforcer
   * @param {import('./ports.js').Clock} deps.clock
   * @param {import('./ports.js').Logger} deps.logger
   * @param {object} deps.settings
   * @param {number} deps.settings.riskThreshold
   * @param {number} deps.settings.delayBetweenServersMs
   * @param {number} deps.settings.throttleToCpuPercent
   * @param {boolean} deps.settings.dryRun
   */
  constructor(deps) {
    Object.assign(this, deps);
  }

  /**
   * @param {{aborted: boolean}} cancellation  simple flag object, set on SIGTERM
   * @returns {Promise<{assessed: number, overThreshold: number, actions: number}>}
   */
  async execute(cancellation = { aborted: false }) {
    const startedMs = this.clock.nowMs();

    const servers = await this.serverRepository.listActive();
    this.logger.info(`cycle start: ${servers.length} active server(s)`);

    this.stateRepository.forgetMissing(servers.map((s) => s.identifier));
    await this.evidenceService.prepareCycle();

    const assessments = await this.#assessAll(servers, cancellation);
    const summary = await this.#actOnAll(assessments, cancellation);

    await this.stateRepository.save();

    const seconds = ((this.clock.nowMs() - startedMs) / 1000).toFixed(1);
    this.logger.info(
      `cycle done in ${seconds}s: ${summary.assessed} assessed, ` +
        `${summary.overThreshold} over threshold, ${summary.actions} action(s) taken`,
    );
    return summary;
  }

  /** PHASE 1 - gather and score. No side effects on any server. */
  async #assessAll(servers, cancellation) {
    const assessments = [];

    for (const server of servers) {
      if (cancellation.aborted) break;

      const previous = this.stateRepository.get(server.identifier);
      const evidence = await this.evidenceService.collectFor(server);

      const verdict = this.scoreCalculator.calculate({
        evidence,
        previous: { score: previous.score, updatedAtMs: previous.updatedAtMs, detections: previous.detections },
        nowMs: this.clock.nowMs(),
      });

      assessments.push(new Assessment(server, previous, verdict));

      if (verdict.cycleScore > 0) {
        this.logger.info(
          `${server.identifier} "${server.name}": +${verdict.cycleScore} -> ${Math.round(verdict.totalScore)} ` +
            `[${verdict.confidence}] families=${verdict.families.join(',')}`,
        );
      } else {
        this.logger.debug(`${server.identifier}: nothing found`);
      }

      if (this.settings.delayBetweenServersMs > 0) {
        await this.clock.sleep(this.settings.delayBetweenServersMs);
      }
    }

    return assessments;
  }

  /** PHASE 2 - now the whole picture is known, decide and act. */
  async #actOnAll(assessments, cancellation) {
    const overThreshold = assessments.filter((a) => a.verdict.totalScore >= this.settings.riskThreshold).length;

    const cycleStats = {
      serversAssessed: assessments.length,
      serversOverThreshold: overThreshold,
      actionsTaken: 0,
    };

    let anomalyAnnounced = false;

    for (const assessment of assessments) {
      if (cancellation.aborted) break;

      const decision = this.policy.decide({
        verdict: assessment.verdict,
        previous: assessment.previous,
        cycleStats,
        serverId: assessment.server.identifier,
        nowMs: this.clock.nowMs(),
      });

      if (decision.level === ResponseLevel.BLOCKED && !anomalyAnnounced) {
        anomalyAnnounced = true;
        this.logger.error(`guardrail engaged: ${decision.reason}`);
        await this.notifier.sendNotice({
          level: 'high',
          title: 'Action halted by safety guardrail',
          body: `${decision.reason}\n\nEvidence collection continues. Review the rule pack before re-enabling.`,
        });
      }

      const outcome = await this.#applyDecision(assessment, decision, cycleStats);
      this.#persist(assessment, outcome);
    }

    return { assessed: assessments.length, overThreshold, actions: cycleStats.actionsTaken };
  }

  /**
   * Carry out one decision. Returns what actually happened, which may differ
   * from what was decided (dry run, unsupported action, or a failed API call).
   */
  async #applyDecision(assessment, decision, cycleStats) {
    const { server, verdict } = assessment;
    let effective = decision;
    let failureNote;

    const wantsAction = decision.level === ResponseLevel.SUSPEND || decision.level === ResponseLevel.THROTTLE;

    if (wantsAction && this.settings.dryRun) {
      this.logger.warn(`DRY RUN: would ${decision.level} ${server.identifier} (${server.name})`);
      effective = { level: ResponseLevel.ALERT, reason: `dry run - would have applied "${decision.level}"` };
    } else if (wantsAction && !this.enforcer.supports(decision.level)) {
      this.logger.warn(`enforcer cannot ${decision.level}; alerting instead`);
      effective = { level: ResponseLevel.ALERT, reason: `"${decision.level}" is not supported by this enforcer` };
    } else if (wantsAction) {
      try {
        if (decision.level === ResponseLevel.SUSPEND) {
          await this.enforcer.suspend(server);
        } else {
          await this.enforcer.throttle(server, this.settings.throttleToCpuPercent);
        }
        cycleStats.actionsTaken += 1;
        this.logger.warn(
          `${decision.level} applied to ${server.identifier} (${server.name}) at score ${Math.round(verdict.totalScore)}`,
        );
      } catch (error) {
        failureNote = `action failed: ${error.message}`;
        this.logger.error(`${decision.level} failed for ${server.identifier}: ${error.message}`);
        effective = { level: ResponseLevel.ALERT, reason: failureNote };
      }
    }

    const shouldTellHumans = effective.level !== ResponseLevel.NONE;
    let notified = false;

    if (shouldTellHumans) {
      notified = await this.notifier.sendAlert({
        server,
        verdict,
        decision: effective,
        riskThreshold: this.settings.riskThreshold,
        failureNote,
      });
    }

    return { level: effective.level, notified };
  }

  #persist(assessment, outcome) {
    const { server, previous, verdict } = assessment;

    // Note: cpuSamples is deliberately absent. The CPU collector owns that
    // field and writes it itself; StateRepository.set merges rather than
    // replaces, so we must not mention fields we do not own.
    this.stateRepository.set(server.identifier, {
      score: verdict.totalScore,
      updatedAtMs: this.clock.nowMs(),
      detections: verdict.detections,
      reasons: verdict.reasons.map((r) => ({ ruleId: r.ruleId, family: r.family, detail: r.detail })),
      lastNotifiedAtMs: outcome.notified ? this.clock.nowMs() : previous.lastNotifiedAtMs ?? 0,
      lastAction: outcome.level === ResponseLevel.NONE ? previous.lastAction ?? null : outcome.level,
    });
  }
}
