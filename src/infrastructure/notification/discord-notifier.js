// LAYER: infrastructure
// JOB:   Deliver an alert somewhere a human will see it.
// IMPLEMENTS: Notifier port.
//
// Note the split: this class knows about delivery, ComponentsV2Builder knows
// about message shape. That is why the builder can be unit tested without a
// network, and why swapping Discord for Slack means writing a new notifier and
// a new builder, touching nothing else.

import { ComponentsV2Builder } from './components-v2-builder.js';

export class DiscordNotifier {
  /**
   * @param {object} deps
   * @param {string} deps.webhookUrl
   * @param {ComponentsV2Builder} deps.builder
   * @param {import('../http/resilient-http-client.js').ResilientHttpClient} deps.http
   * @param {import('../../application/ports.js').Logger} deps.logger
   */
  constructor({ webhookUrl, builder, http, logger }) {
    this.webhookUrl = webhookUrl;
    this.builder = builder;
    this.http = http;
    this.logger = logger;
    this.componentsV2Works = true;
  }

  get enabled() {
    return Boolean(this.webhookUrl);
  }

  /** Components V2 needs this query parameter on webhook execution. */
  #url() {
    const joiner = this.webhookUrl.includes('?') ? '&' : '?';
    return `${this.webhookUrl}${joiner}with_components=true`;
  }

  async #post(payload) {
    return this.http.send(this.#url(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      parseJson: false,
      label: 'discord webhook',
    });
  }

  /** @param {import('../../application/ports.js').AlertReport} report */
  async sendAlert(report) {
    if (!this.enabled) return false;

    const payload = this.componentsV2Works
      ? this.builder.buildAlert(report)
      : this.builder.buildLegacyAlert(report);

    try {
      await this.#post(payload);
      return true;
    } catch (error) {
      // A 400 on a V2 payload means this webhook or API version will not take
      // components. Degrade once, permanently, rather than losing every future
      // alert. An alert that renders plainly beats no alert at all.
      if (this.componentsV2Works && error.status === 400) {
        this.logger.warn(`Discord rejected the Components V2 payload; falling back to embeds. ${error.body ?? ''}`);
        this.componentsV2Works = false;
        try {
          await this.#post(this.builder.buildLegacyAlert(report));
          return true;
        } catch (fallbackError) {
          this.logger.error(`fallback alert also failed: ${fallbackError.message}`);
          return false;
        }
      }
      this.logger.error(`could not deliver alert: ${error.message}`);
      return false;
    }
  }

  async sendNotice(notice) {
    if (!this.enabled) return false;
    try {
      await this.#post(this.builder.buildNotice(notice));
      return true;
    } catch (error) {
      this.logger.error(`could not deliver notice: ${error.message}`);
      return false;
    }
  }
}

/**
 * Prints alerts to the log instead of sending them. Used when no webhook is
 * configured, and by `xrae scan --dry-run`.
 * @implements {import('../../application/ports.js').Notifier}
 */
export class ConsoleNotifier {
  constructor({ logger }) {
    this.logger = logger;
    this.enabled = true;
  }

  async sendAlert({ server, verdict, decision, riskThreshold }) {
    this.logger.warn(
      `ALERT [${decision.level}] ${server.identifier} "${server.name}" ` +
        `score=${Math.round(verdict.totalScore)}/${riskThreshold} confidence=${verdict.confidence}`,
    );
    for (const reason of verdict.reasons.slice(0, 8)) {
      this.logger.warn(`    - ${reason.ruleId}: ${reason.detail}`);
    }
    this.logger.warn(`    reason for outcome: ${decision.reason}`);
    return true;
  }

  async sendNotice({ title, body }) {
    this.logger.warn(`NOTICE ${title}: ${body}`);
    return true;
  }
}
