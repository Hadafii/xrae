// LAYER: infrastructure
// JOB:   Notice a server whose CPU is pinned flat, which is what mining looks
//        like and what normal gameplay does not.
// IMPLEMENTS: EvidenceCollector port.
//
// ============================================================================
// A HEURISTIC WE DELIBERATELY REMOVED
// ============================================================================
// SonarX also flagged "artificial throttling": mean CPU between 60% and 80%
// with low variance. That describes a healthy, busy Minecraft server exactly as
// well as it describes a throttled miner. A rule that cannot tell the
// difference must not get a vote, so it is gone rather than down-weighted.
//
// What remains needs a long window on purpose. At a 15 minute interval, 12
// samples is three hours of consistent evidence. A game server can pin the CPU
// for one cycle during world generation; it does not do so flat for three hours.
// ============================================================================

import { createEvidence, EvidenceFamily } from '../../domain/evidence.js';
import { Confidence } from '../../domain/confidence.js';

const MAX_SAMPLES_KEPT = 30;

/** @implements {import('../../application/ports.js').EvidenceCollector} */
export class CpuBehaviorCollector {
  name = 'cpu';

  /**
   * @param {object} deps
   * @param {import('../panel/pterodactyl.js').PterodactylMetricsProvider} deps.metrics
   * @param {import('../../application/ports.js').StateRepository} deps.stateRepository
   * @param {import('../../application/ports.js').Logger} deps.logger
   * @param {object} deps.settings
   * @param {number} deps.settings.minSamples
   * @param {number} deps.settings.sustainedPercent
   * @param {number} deps.settings.maxStdDev
   */
  constructor({ metrics, stateRepository, logger, settings }) {
    this.metrics = metrics;
    this.stateRepository = stateRepository;
    this.logger = logger;
    this.settings = settings;
  }

  /** @param {import('../../application/ports.js').ServerRef} server */
  async collect(server) {
    if (!this.metrics.available) return [];

    const reading = await this.metrics.read(server.identifier);
    if (!reading) return [];

    const stored = this.stateRepository.get(server.identifier);

    // A stopped server's old samples say nothing about now, so throw them away.
    if (reading.state !== 'running') {
      if ((stored.cpuSamples ?? []).length > 0) {
        this.stateRepository.set(server.identifier, { cpuSamples: [] });
      }
      return [];
    }

    const samples = [...(stored.cpuSamples ?? []), this.#normalise(reading.cpuPercent, server.cpuLimitPercent)]
      .slice(-MAX_SAMPLES_KEPT);

    // This collector owns the cpuSamples field. StateRepository.set merges, so
    // writing it here does not disturb anything else.
    this.stateRepository.set(server.identifier, { cpuSamples: samples });

    return this.#evaluate(samples);
  }

  /**
   * Pterodactyl reports cpu_absolute as a percentage of ONE core, so a server
   * with a 400% limit can legitimately report 400. Normalising against the
   * server's own limit is what makes the threshold comparable across plans.
   */
  #normalise(cpuAbsolute, limitPercent) {
    const limit = limitPercent > 0 ? limitPercent : 100;
    return Math.round((cpuAbsolute / limit) * 1000) / 10;
  }

  #evaluate(samples) {
    if (samples.length < this.settings.minSamples) return [];

    const window = samples.slice(-this.settings.minSamples);
    const mean = window.reduce((sum, value) => sum + value, 0) / window.length;
    const variance = window.reduce((sum, value) => sum + (value - mean) ** 2, 0) / window.length;
    const stdDev = Math.sqrt(variance);

    const isPinned = mean >= this.settings.sustainedPercent && stdDev <= this.settings.maxStdDev;
    if (!isPinned) return [];

    return [
      createEvidence({
        ruleId: 'behavior.cpu_pinned',
        family: EvidenceFamily.BEHAVIOR,
        category: 'MINER',
        weight: 28,
        confidence: Confidence.MEDIUM,
        standalone: false,
        detail: `CPU held at ${mean.toFixed(1)}% (deviation ${stdDev.toFixed(2)}) across ${window.length} samples`,
      }),
    ];
  }
}
