// LAYER: infrastructure
// JOB:   Remember which panel config version this node is running.
//
// ============================================================================
// WHY WE STORE THE PANEL'S HASH INSTEAD OF COMPUTING OUR OWN
// ============================================================================
// The panel decides whether a node is in sync by comparing hashes. If the agent
// computed its own hash it would have to reproduce the panel's canonical JSON
// serialisation exactly, forever. One whitespace or key-ordering difference and
// every node reports as permanently out of date, pulling config in a loop.
//
// So we record the hash the panel gave us when we applied its config, and echo
// it back. Nothing to keep in sync, and a node that has never pulled reports
// null, which the panel already reads as "send it the config".
// ============================================================================

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export class AppliedConfigStore {
  constructor({ filePath, logger }) {
    this.filePath = filePath;
    this.logger = logger;
    this.hash = null;
    this.version = null;
    this.appliedAtMs = null;
  }

  load() {
    if (!existsSync(this.filePath)) return this;

    try {
      const parsed = JSON.parse(readFileSync(this.filePath, 'utf8'));

      this.hash = parsed.hash ?? null;
      this.version = parsed.version ?? null;
      this.appliedAtMs = parsed.appliedAtMs ?? null;
    } catch (error) {
      // A corrupt marker is not fatal: reporting null just means we pull once.
      this.logger?.warn(`could not read applied config marker: ${error.message}`);
    }

    return this;
  }

  /**
   * Persist the hash for the NEXT start, without changing what this process
   * reports.
   *
   * The distinction matters: a staged config is not a running config. If the
   * live reporter started echoing the new hash the moment the file was written,
   * the panel would show the node as in sync while it was still scanning on the
   * old rules, and the sync column would be worse than useless. The marker is
   * written together with the config file it describes, so whatever starts next
   * reads a hash that genuinely matches the config it loaded.
   */
  recordForNextStart({ hash, version }) {
    this.#write({ hash: hash ?? null, version: version ?? null, appliedAtMs: Date.now() });
  }

  /** Atomic write, so a crash mid-save cannot leave an unreadable marker. */
  record({ hash, version }) {
    this.hash = hash ?? null;
    this.version = version ?? null;
    this.appliedAtMs = Date.now();

    this.#write({ hash: this.hash, version: this.version, appliedAtMs: this.appliedAtMs });
  }

  #write(payload) {
    try {
      mkdirSync(dirname(this.filePath), { recursive: true });

      const temporary = `${this.filePath}.tmp`;

      writeFileSync(temporary, JSON.stringify(payload, null, 2), { mode: 0o640 });
      renameSync(temporary, this.filePath);
    } catch (error) {
      // Losing the marker costs one extra config pull after a restart, which is
      // cheaper than failing the cycle that just succeeded.
      this.logger?.warn(`could not persist applied config marker: ${error.message}`);
    }
  }
}
