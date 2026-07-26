// LAYER: infrastructure
// JOB:   Talk to Pterodactyl.
//
// ============================================================================
// WHY THREE CLASSES INSTEAD OF ONE "PanelClient"
// ============================================================================
// This is the Interface Segregation Principle, and it buys something concrete.
//
// A single fat PanelClient would mean that a test for the scoring logic has to
// stub out suspend(), even though scoring never suspends anything. Worse, any
// class holding a PanelClient reference would hold the ability to suspend
// servers, whether it needed it or not.
//
// Split up:
//   PterodactylServerRepository  reads the server list          (no write power)
//   PterodactylMetricsProvider   reads live CPU                 (no write power)
//   PterodactylEnforcer          suspends                       (write power)
//
// Only the enforcer can change anything, and only the cycle holds one.
// ============================================================================

import { HttpError } from '../http/resilient-http-client.js';

/**
 * Private helper shared by the three adapters. Not exported: nothing outside
 * this file should be able to make arbitrary panel calls.
 */
class PterodactylApi {
  /**
   * @param {object} deps
   * @param {string} deps.baseUrl
   * @param {string} deps.applicationKey
   * @param {string} deps.clientKey
   * @param {string} deps.userAgent
   * @param {import('../http/resilient-http-client.js').ResilientHttpClient} deps.http
   */
  constructor({ baseUrl, applicationKey, clientKey, userAgent, http }) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.applicationKey = applicationKey;
    this.clientKey = clientKey;
    this.userAgent = userAgent;
    this.http = http;
  }

  #headers(key) {
    return {
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': this.userAgent,
    };
  }

  /** Application API: admin-level, sees all servers. */
  application(path, { method = 'GET', parseJson = true } = {}) {
    if (!this.applicationKey) throw new Error('panel.applicationKey is not configured');
    return this.http.send(this.baseUrl + path, {
      method,
      headers: this.#headers(this.applicationKey),
      parseJson,
      label: `panel ${method} ${path}`,
    });
  }

  /** Client API: acts as a user, used only for live resource stats. */
  client(path) {
    if (!this.clientKey) throw new Error('panel.clientKey is not configured');
    return this.http.send(this.baseUrl + path, {
      headers: this.#headers(this.clientKey),
      label: `panel GET ${path}`,
    });
  }
}

export function createPterodactylApi(config, http) {
  return new PterodactylApi({
    baseUrl: config.panel.url,
    applicationKey: config.panel.applicationKey,
    clientKey: config.panel.clientKey,
    userAgent: config.panel.userAgent,
    http,
  });
}

/** @implements {import('../../application/ports.js').ServerRepository} */
export class PterodactylServerRepository {
  /**
   * @param {PterodactylApi} api
   * @param {object} options
   * @param {number} options.nodeId  0 means every node the key can see
   */
  constructor(api, { nodeId }) {
    this.api = api;
    this.nodeId = nodeId;
  }

  /** Confirms the key works before the first cycle. Used by `xrae doctor`. */
  async checkAccess() {
    const { data } = await this.api.application('/api/application/servers?per_page=1');
    return { visibleServers: data?.meta?.pagination?.total ?? 0 };
  }

  /** @returns {Promise<import('../../application/ports.js').ServerRef[]>} */
  async listActive() {
    const servers = [];
    let page = 1;
    let totalPages = 1;
    const pageLimit = 200; // stops an infinite loop if the panel misreports

    while (page <= totalPages && page <= pageLimit) {
      const { data } = await this.api.application(`/api/application/servers?page=${page}&per_page=100`);

      for (const entry of data?.data ?? []) {
        const attributes = entry?.attributes;
        if (!attributes) continue;
        if (attributes.suspended) continue;
        if (this.nodeId && attributes.node !== this.nodeId) continue;

        servers.push({
          id: attributes.id,
          identifier: attributes.identifier,
          uuid: attributes.uuid,
          name: attributes.name,
          nodeId: attributes.node,
          cpuLimitPercent: attributes.limits?.cpu ?? 0,
        });
      }

      totalPages = data?.meta?.pagination?.total_pages ?? 1;
      page += 1;
    }

    return servers;
  }
}

/** Live CPU usage for one server. */
export class PterodactylMetricsProvider {
  /** @param {PterodactylApi} api */
  constructor(api, { logger }) {
    this.api = api;
    this.logger = logger;
  }

  get available() {
    return Boolean(this.api.clientKey);
  }

  /**
   * @param {string} identifier
   * @returns {Promise<{cpuPercent: number, state: string} | null>}
   */
  async read(identifier) {
    if (!this.available) return null;

    try {
      const { data } = await this.api.client(`/api/client/servers/${identifier}/resources`);
      const resources = data?.attributes?.resources;
      if (!resources) return null;
      return {
        cpuPercent: resources.cpu_absolute ?? 0,
        state: data?.attributes?.current_state ?? 'unknown',
      };
    } catch (error) {
      // Not being able to read stats is normal (server offline, key scope).
      // It must never break the cycle.
      this.logger.debug(`metrics unavailable for ${identifier}: ${error.message}`);
      return null;
    }
  }
}

/** @implements {import('../../application/ports.js').Enforcer} */
export class PterodactylEnforcer {
  /** @param {PterodactylApi} api */
  constructor(api, { logger }) {
    this.api = api;
    this.logger = logger;
  }

  /**
   * Throttling needs the Wings API (per-container CPU quota), which this
   * adapter does not speak yet. Saying so honestly is important: the use case
   * checks `supports()` and downgrades to an alert rather than silently doing
   * nothing.
   *
   * When someone adds a WingsEnforcer later, nothing in domain/ or
   * application/ has to change. That is the Open/Closed Principle paying off.
   */
  supports(level) {
    return level === 'suspend';
  }

  /** @param {import('../../application/ports.js').ServerRef} server */
  async suspend(server) {
    // Suspending an already-suspended server is harmless, which is the only
    // reason it is safe to retry this POST.
    await this.api.application(`/api/application/servers/${server.id}/suspend`, {
      method: 'POST',
      parseJson: false,
    });
  }

  async throttle() {
    throw new HttpError('throttle is not supported by PterodactylEnforcer; a Wings adapter is needed');
  }
}

/** Used in dry-run mode and by `xrae doctor`. Does nothing, loudly. */
export class NoopEnforcer {
  constructor({ logger }) {
    this.logger = logger;
  }
  supports() {
    return false;
  }
  async suspend(server) {
    this.logger.warn(`NoopEnforcer: refusing to suspend ${server.identifier}`);
  }
  async throttle(server) {
    this.logger.warn(`NoopEnforcer: refusing to throttle ${server.identifier}`);
  }
}
