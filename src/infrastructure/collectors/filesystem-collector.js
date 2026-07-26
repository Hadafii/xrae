// LAYER: infrastructure
// JOB:   Turn "a server's volume directory" into evidence.
// IMPLEMENTS: EvidenceCollector port.
//
// This class only wires the walker to the analyzer. It contains no detection
// logic of its own, which is why it is short - and short is the point.

import path from 'node:path';
import { ScanBudget, resolveWithinRoot, BudgetExhausted } from '../filesystem/safe-walker.js';

/** @implements {import('../../application/ports.js').EvidenceCollector} */
export class FilesystemCollector {
  name = 'filesystem';

  /**
   * @param {object} deps
   * @param {import('../filesystem/safe-walker.js').SafeDirectoryWalker} deps.walker
   * @param {import('../filesystem/file-analyzer.js').FileContentAnalyzer} deps.analyzer
   * @param {import('../../application/ports.js').StateRepository} deps.stateRepository
   * @param {import('../../application/ports.js').Clock} deps.clock
   * @param {import('../../application/ports.js').Logger} deps.logger
   * @param {object} deps.settings
   * @param {string} deps.settings.volumesPath
   * @param {number} deps.settings.maxFilesPerServer
   * @param {number} deps.settings.maxBytesPerServer
   * @param {number} deps.settings.serverDeadlineMs
   */
  constructor({ walker, analyzer, stateRepository, clock, logger, settings }) {
    this.walker = walker;
    this.analyzer = analyzer;
    this.stateRepository = stateRepository;
    this.clock = clock;
    this.logger = logger;
    this.settings = settings;
  }

  /**
   * @param {import('../../application/ports.js').ServerRef} server
   * @returns {Promise<import('../../domain/evidence.js').Evidence[]>}
   */
  async collect(server) {
    const volumePath = path.join(this.settings.volumesPath, server.uuid);
    const safeRoot = resolveWithinRoot(this.settings.volumesPath, volumePath);

    if (!safeRoot) {
      // Either the volume does not exist (server never started) or it resolves
      // outside the volumes directory, which would be an escape attempt.
      this.logger.debug(`${server.identifier}: no usable volume at ${volumePath}`);
      return [];
    }

    const budget = new ScanBudget({
      maxFiles: this.settings.maxFilesPerServer,
      maxBytes: this.settings.maxBytesPerServer,
      deadlineMs: this.settings.serverDeadlineMs,
      clock: this.clock,
    });

    const cache = this.stateRepository.fileCache();
    const evidence = [];

    try {
      for await (const file of this.walker.walk(safeRoot, budget)) {
        const found = await this.analyzer.analyze({
          absolutePath: file.absolutePath,
          relativePath: file.relativePath,
          fileName: file.fileName,
          budget,
          cache,
        });
        if (found.length > 0) evidence.push(...found);
      }
    } catch (error) {
      if (error instanceof BudgetExhausted) {
        // A partial scan is still useful. Say so, do not pretend it was complete.
        this.logger.warn(`${server.identifier}: ${error.message}; scan was partial`);
      } else {
        throw error;
      }
    }

    this.logger.debug(
      `${server.identifier}: ${budget.filesUsed} file(s) read, ` +
        `skipped ${budget.skipped.symlinks} symlink(s), ${budget.skipped.specialFiles} special file(s)`,
    );

    return evidence;
  }
}
