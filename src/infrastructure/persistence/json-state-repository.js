// LAYER: infrastructure
// JOB:   Remember scores and cached file fingerprints between runs.
// IMPLEMENTS: StateRepository port.
//
// Why a JSON file and not SQLite: the dataset is a few hundred servers, and
// SQLite would mean a native dependency inside a privileged agent. Zero
// dependencies is worth more here than query power we do not need.
//
// Writes are atomic (temp file -> fsync -> rename). A crash mid-write must not
// be able to wipe the score history of every server on the node.

import fs from 'node:fs/promises';
import path from 'node:path';

/** @returns {import('../../application/ports.js').ServerState} */
function emptyState() {
  return {
    score: 0,
    updatedAtMs: 0,
    detections: 0,
    lastNotifiedAtMs: 0,
    lastAction: null,
    cpuSamples: [],
    reasons: [],
  };
}

/** @implements {import('../../application/ports.js').StateRepository} */
export class JsonStateRepository {
  /**
   * @param {object} options
   * @param {string} options.filePath
   * @param {number} options.maxCacheEntries
   * @param {import('../../application/ports.js').Logger} options.logger
   * @param {import('../../application/ports.js').Clock} options.clock
   */
  constructor({ filePath, maxCacheEntries, logger, clock }) {
    this.filePath = path.resolve(filePath);
    this.maxCacheEntries = maxCacheEntries;
    this.logger = logger;
    this.clock = clock;

    /** @type {Map<string, import('../../application/ports.js').ServerState>} */
    this.servers = new Map();
    /** @type {Map<string, any>} */
    this.cache = new Map();
    this.hasUnsavedChanges = false;
  }

  async load() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });

    let raw;
    try {
      raw = await fs.readFile(this.filePath, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') {
        this.logger.info(`no previous state, starting fresh (${this.filePath})`);
        return;
      }
      throw error;
    }

    try {
      const parsed = JSON.parse(raw);
      for (const [id, state] of Object.entries(parsed.servers ?? {})) {
        this.servers.set(id, { ...emptyState(), ...state });
      }
      for (const [key, value] of Object.entries(parsed.fileCache ?? {})) {
        this.cache.set(key, value);
      }
      this.logger.info(`loaded ${this.servers.size} server record(s), ${this.cache.size} cached file(s)`);
    } catch (error) {
      // A corrupt state file must never stop detection. Move it aside, carry on.
      const backup = `${this.filePath}.corrupt.${Date.now()}`;
      this.logger.error(`state file is unreadable (${error.message}); moved to ${backup}`);
      await fs.rename(this.filePath, backup).catch(() => {});
    }
  }

  async save() {
    if (!this.hasUnsavedChanges) return;
    this.#pruneCache();

    const payload = {
      version: 1,
      savedAtMs: this.clock.nowMs(),
      servers: Object.fromEntries(this.servers),
      fileCache: Object.fromEntries(this.cache),
    };

    const tempPath = `${this.filePath}.tmp`;
    const handle = await fs.open(tempPath, 'w', 0o600);
    try {
      await handle.writeFile(JSON.stringify(payload));
      await handle.sync(); // survive a power loss, not just a process crash
    } finally {
      await handle.close();
    }
    await fs.rename(tempPath, this.filePath);
    this.hasUnsavedChanges = false;
  }

  /** @returns {import('../../application/ports.js').ServerState} */
  get(serverIdentifier) {
    return this.servers.get(serverIdentifier) ?? emptyState();
  }

  /**
   * MERGES `partial` into the stored record. See the port docs for why:
   * different components own different fields.
   */
  set(serverIdentifier, partial) {
    const current = this.servers.get(serverIdentifier) ?? emptyState();
    this.servers.set(serverIdentifier, { ...current, ...partial });
    this.hasUnsavedChanges = true;
  }

  /** Drop records for servers that no longer exist on this node. */
  forgetMissing(activeIdentifiers) {
    const active = new Set(activeIdentifiers);
    for (const id of [...this.servers.keys()]) {
      if (active.has(id)) continue;
      this.servers.delete(id);
      this.hasUnsavedChanges = true;
    }
  }

  /** A tiny key/value view handed to the file analyzer. */
  fileCache() {
    return {
      get: (key) => {
        const entry = this.cache.get(key);
        if (entry) entry.seenAtMs = this.clock.nowMs();
        return entry ?? null;
      },
      set: (key, value) => {
        this.cache.set(key, { ...value, seenAtMs: this.clock.nowMs() });
        this.hasUnsavedChanges = true;
      },
    };
  }

  /** Keep the most recently seen entries, discard the rest. */
  #pruneCache() {
    if (this.cache.size <= this.maxCacheEntries) return;
    const newestFirst = [...this.cache.entries()].sort((a, b) => (b[1].seenAtMs ?? 0) - (a[1].seenAtMs ?? 0));
    this.cache = new Map(newestFirst.slice(0, this.maxCacheEntries));
    this.logger.debug(`pruned file cache to ${this.cache.size} entries`);
  }
}
