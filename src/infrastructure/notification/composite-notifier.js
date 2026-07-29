// LAYER: infrastructure
// JOB:   Fan one notification out to several sinks behind a single Notifier.
//
// The alternative was giving RunScanCycle a list of notifiers. That would make
// the application layer responsible for knowing how many places a message goes,
// which is a deployment question, not a use-case question. With this adapter
// the use case still sees exactly one Notifier and the composition root decides
// how many there really are.

export class CompositeNotifier {
  /** @param {{notifiers: object[], logger: object}} deps */
  constructor({ notifiers, logger }) {
    this.notifiers = (notifiers ?? []).filter(Boolean);
    this.logger = logger;
    this.enabled = this.notifiers.some((notifier) => notifier.enabled);
  }

  async sendAlert(report) {
    return this.#fanOut('sendAlert', report);
  }

  async sendNotice(notice) {
    return this.#fanOut('sendNotice', notice);
  }

  /**
   * One failing sink must not silence the others, so every sink is attempted
   * and the result is "at least one got through".
   */
  async #fanOut(method, payload) {
    const results = await Promise.allSettled(
      this.notifiers.map((notifier) => notifier[method](payload)),
    );

    let delivered = false;

    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value !== false) {
        delivered = true;

        return;
      }
      const reason = result.status === 'rejected' ? result.reason?.message : 'refused';

      this.logger?.warn(
        `notifier ${this.notifiers[index]?.constructor?.name ?? index} failed: ${reason}`,
      );
    });

    return delivered;
  }
}
