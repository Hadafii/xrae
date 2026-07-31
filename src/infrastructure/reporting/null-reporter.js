// LAYER: infrastructure
// JOB:   Satisfy the CycleReporter port when no panel is configured.
//
// The alternative was letting `reporter` be null and sprinkling `if (this.reporter)`
// through the use case. A do-nothing adapter keeps the application layer free of
// that branch, and keeps "no panel configured" from being a special case that
// only shows up at runtime.

export class NullCycleReporter {
  constructor({ logger } = {}) {
    this.enabled = false;
    this.logger = logger;
  }

  async reportCycle(report) {
    this.logger?.debug(
      `reporting disabled: ${report.scanned} scanned, ${report.entries.length} with findings`,
    );

    return [];
  }

  async keepalive() {
    return [];
  }
}
