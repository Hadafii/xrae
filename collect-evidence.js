// LAYER: application
// JOB:   Run every evidence collector for one server and merge the results.
// MAY IMPORT: domain, and the port contracts. Never infrastructure.
//
// This is the Open/Closed Principle in practice: to add a new kind of
// detection you write a new collector and register it in composition-root.js.
// You never edit this file, and you never edit the scoring engine.

/**
 * Collects evidence from all registered sources.
 *
 * Failure isolation is the main value here. If the network collector cannot
 * read /proc because a capability is missing, that must not prevent the
 * filesystem collector from running. A partially blind scan is useful; a
 * crashed scan is not.
 */
export class EvidenceCollectionService {
  /**
   * @param {object} deps
   * @param {import('./ports.js').EvidenceCollector[]} deps.collectors
   * @param {import('./ports.js').Logger} deps.logger
   */
  constructor({ collectors, logger }) {
    if (!Array.isArray(collectors) || collectors.length === 0) {
      throw new Error('EvidenceCollectionService needs at least one collector');
    }
    this.collectors = collectors;
    this.logger = logger;
  }

  /** Called once per cycle, before any server is examined. */
  async prepareCycle() {
    for (const collector of this.collectors) {
      if (typeof collector.prepare !== 'function') continue;
      try {
        await collector.prepare();
      } catch (error) {
        this.logger.warn(`collector "${collector.name}" failed to prepare: ${error.message}`);
      }
    }
  }

  /**
   * @param {import('./ports.js').ServerRef} server
   * @returns {Promise<import('../domain/evidence.js').Evidence[]>}
   */
  async collectFor(server) {
    const collected = [];

    for (const collector of this.collectors) {
      try {
        const evidence = await collector.collect(server);
        if (!Array.isArray(evidence)) {
          this.logger.warn(`collector "${collector.name}" returned a non-array; ignoring it`);
          continue;
        }
        collected.push(...evidence);
      } catch (error) {
        // A collector that throws is a bug in that collector. Log it, keep going.
        this.logger.error(`collector "${collector.name}" threw on ${server.identifier}: ${error.message}`);
      }
    }

    return collected;
  }
}
