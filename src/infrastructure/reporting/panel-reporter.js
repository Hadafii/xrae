// LAYER: infrastructure
// JOB:   Speak the X-Rae panel protocol (docs/TRD/05-agent-protocol.md in the
//        raehost-xrae repo). Implements the CycleReporter port.
// MAY IMPORT: infrastructure and the port shapes. Never domain internals.
//
// ============================================================================
// THREE RULES THIS ADAPTER LIVES BY
// ============================================================================
// 1. Never throw. A panel outage must cost telemetry, never protection. Every
//    public method swallows its errors and logs them.
// 2. The agent always initiates. Nothing here listens on a port.
// 3. Truncate to the panel's documented limits BEFORE sending. The panel
//    rejects an over-long field with 400 for the whole batch, so one pathological
//    file path would otherwise cost us an entire cycle of evidence.
// ============================================================================

import { randomUUID } from 'node:crypto';

/** Mirrors the panel's Zod limits. Kept here so a violation never reaches the wire. */
const LIMIT = {
  servers: 500,
  reasons: 25,
  ruleId: 100,
  detail: 500,
  category: 60,
  name: 190,
  identifier: 20,
  decisionReason: 255,
  failureNote: 500,
};

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function clamp(value, max) {
  if (value === null || value === undefined) return undefined;
  const text = String(value);

  return text.length > max ? text.slice(0, max) : text;
}

function toInt(value) {
  const rounded = Math.round(Number(value) || 0);

  return rounded < 0 ? 0 : rounded;
}

export class PanelReporter {
  /**
   * @param {object} deps
   * @param {string} deps.baseUrl        e.g. https://xrae.raehost.com
   * @param {string} deps.token          per-node bearer token
   * @param {object} deps.http           ResilientHttpClient, its OWN instance
   * @param {object} deps.logger
   * @param {string} deps.agentVersion
   * @param {object} [deps.appliedConfig] remembers which config hash is running
   */
  constructor({ baseUrl, token, http, logger, agentVersion, appliedConfig }) {
    this.enabled = Boolean(baseUrl && token);
    this.baseUrl = String(baseUrl ?? '').replace(/\/+$/, '');
    this.token = token;
    this.http = http;
    this.logger = logger;
    this.agentVersion = agentVersion ?? 'unknown';
    this.appliedConfig = appliedConfig ?? null;
    /** Advertised by the panel on the last heartbeat. Null until we hear from it. */
    this.desiredConfigHash = null;
  }

  get #headers() {
    return {
      Authorization: `Bearer ${this.token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Xrae-Protocol': '1',
      'X-Xrae-Agent': this.agentVersion,
    };
  }

  /**
   * One cycle, two calls: the findings, then the heartbeat that carries the
   * counters and collects any pending commands. The heartbeat runs even when
   * the report failed, because a node whose reports are failing is exactly the
   * node an operator needs to see as alive but struggling.
   */
  async reportCycle(report) {
    if (!this.enabled) return [];

    const cycleId = randomUUID();

    if (report.entries.length > 0) {
      await this.#sendReport(cycleId, report);
    }

    return this.#sendHeartbeat(cycleId, report);
  }

  /**
   * A heartbeat carrying no cycle.
   *
   * Without this the panel only hears from a node when a full scan finishes, so
   * a fresh install sat at "never connected" for a whole interval, and a node
   * whose cycles were throwing (a wrong Pterodactyl key, an unreadable volumes
   * path) never appeared at all. That is the worst possible failure for an
   * abuse-detection fleet: the broken node is indistinguishable from one that
   * was never installed.
   *
   * `cycle` is optional in the panel's schema precisely so this can exist.
   *
   * @param {string} reason why we are checking in, for the local log only
   */
  async keepalive(reason = 'keepalive') {
    if (!this.enabled) return [];

    const body = {
      agent_version: this.agentVersion,
      config_hash: this.appliedConfig?.hash ?? null,
    };

    try {
      const response = await this.http.send(`${this.baseUrl}/api/agent/heartbeat`, {
        method: 'POST',
        headers: this.#headers,
        body: JSON.stringify(body),
        label: `panel ${reason}`,
      });

      const data = response.data?.data ?? {};

      this.desiredConfigHash = data.desired_config_hash ?? null;
      this.logger.debug(`panel ${reason} acknowledged`);

      return Array.isArray(data.commands) ? data.commands : [];
    } catch (error) {
      this.#explain(reason, error);

      return [];
    }
  }

  async #sendReport(cycleId, report) {
    const entries = report.entries.slice(0, LIMIT.servers);

    if (entries.length < report.entries.length) {
      // Say so out loud. A silent cap reads as "everything was reported".
      this.logger.warn(
        `report capped at ${LIMIT.servers} servers, ${report.entries.length - entries.length} omitted`,
      );
    }

    const body = {
      cycle_id: cycleId,
      started_at: new Date(report.startedAtMs).toISOString(),
      finished_at: new Date(report.finishedAtMs).toISOString(),
      servers: entries.map((entry) => this.#toServerPayload(entry, report.riskThreshold)),
    };

    try {
      const response = await this.http.send(`${this.baseUrl}/api/agent/reports`, {
        method: 'POST',
        headers: this.#headers,
        body: JSON.stringify(body),
        label: 'panel report',
      });

      if (response.data?.data?.duplicate) {
        this.logger.debug(`panel already had cycle ${cycleId}`);
      } else {
        this.logger.debug(`reported ${entries.length} finding(s) to the panel`);
      }
    } catch (error) {
      this.#explain('report', error);
    }
  }

  async #sendHeartbeat(cycleId, report) {
    const body = {
      agent_version: this.agentVersion,
      config_hash: this.appliedConfig?.hash ?? null,
      cycle: {
        cycle_id: cycleId,
        scanned_count: toInt(report.scanned),
        flagged_count: toInt(report.flagged),
        action_count: toInt(report.actions),
        duration_ms: toInt(report.finishedAtMs - report.startedAtMs),
      },
    };

    try {
      const response = await this.http.send(`${this.baseUrl}/api/agent/heartbeat`, {
        method: 'POST',
        headers: this.#headers,
        body: JSON.stringify(body),
        label: 'panel heartbeat',
      });

      const data = response.data?.data ?? {};

      this.desiredConfigHash = data.desired_config_hash ?? null;

      return Array.isArray(data.commands) ? data.commands : [];
    } catch (error) {
      this.#explain('heartbeat', error);

      return [];
    }
  }

  /** True when the panel wants us running a config we are not running. */
  get configOutOfDate() {
    if (!this.enabled || !this.desiredConfigHash) return false;

    return this.desiredConfigHash !== (this.appliedConfig?.hash ?? null);
  }

  /** Returns the panel's config, or null if it could not be fetched. */
  async fetchConfig() {
    if (!this.enabled) return null;

    try {
      const response = await this.http.send(`${this.baseUrl}/api/agent/config`, {
        method: 'GET',
        headers: this.#headers,
        label: 'panel config',
      });

      return response.data?.data ?? null;
    } catch (error) {
      this.#explain('config pull', error);

      return null;
    }
  }

  async ackCommands(commandIds, results = []) {
    if (!this.enabled || commandIds.length === 0) return;

    try {
      await this.http.send(`${this.baseUrl}/api/agent/commands/ack`, {
        method: 'POST',
        headers: this.#headers,
        body: JSON.stringify({ command_ids: commandIds, results }),
        label: 'panel ack',
      });
    } catch (error) {
      this.#explain('command ack', error);
    }
  }

  #toServerPayload(entry, riskThreshold) {
    const { server, verdict, decision, action } = entry;

    return {
      identifier: clamp(server.identifier, LIMIT.identifier),
      uuid: UUID_PATTERN.test(String(server.uuid ?? '')) ? server.uuid : null,
      name: clamp(server.name, LIMIT.name) ?? null,
      verdict: {
        score: toInt(verdict.totalScore),
        cycle_score: toInt(verdict.cycleScore),
        confidence: verdict.confidence,
        families: verdict.families ?? [],
        has_standalone: Boolean(verdict.hasStandalone),
        detections: toInt(verdict.detections),
        reasons: (verdict.reasons ?? []).slice(0, LIMIT.reasons).map((reason) => ({
          ruleId: clamp(reason.ruleId, LIMIT.ruleId),
          family: reason.family,
          category: clamp(reason.category, LIMIT.category),
          weight: toInt(reason.weight),
          confidence: reason.confidence,
          standalone: Boolean(reason.standalone),
          detail: clamp(reason.detail, LIMIT.detail) ?? '',
        })),
      },
      decision: {
        level: decision.level,
        reason: clamp(decision.reason, LIMIT.decisionReason) ?? null,
      },
      risk_threshold: toInt(riskThreshold) || null,
      action: action
        ? {
            performed: action.performed,
            success: Boolean(action.success),
            failure_note: clamp(action.failureNote, LIMIT.failureNote) ?? null,
          }
        : null,
    };
  }

  /**
   * A revoked token is an operator problem, not a transient one, so it gets a
   * louder line than a timeout. The agent keeps scanning either way.
   */
  #explain(what, error) {
    const status = error?.status;

    if (status === 401 || status === 403) {
      this.logger.error(
        `panel ${what} rejected (HTTP ${status}): this node's token is invalid, revoked or disabled. ` +
          `Scanning and enforcement continue locally. Re-run install.sh with a fresh token to restore reporting.`,
      );

      return;
    }
    if (status === 400) {
      this.logger.error(`panel ${what} rejected as malformed (HTTP 400): ${error.message}`);

      return;
    }

    this.logger.warn(`panel ${what} failed: ${error?.message ?? error}`);
  }
}
