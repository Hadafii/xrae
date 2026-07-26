// LAYER: infrastructure
// JOB:   Walk a tenant's volume directory without letting the tenant hurt us.
//
// ============================================================================
// THREAT MODEL FOR THIS FILE - read before changing anything
// ============================================================================
// Every byte and every directory entry below the scan root is controlled by a
// customer who may want to attack us. They can create symlinks, FIFOs, device
// nodes, symlink loops, million-entry directories and 40-level nesting.
//
// The old SonarX used statSync (which FOLLOWS symlinks) with no depth limit and
// no deadline. A customer could therefore:
//   - point a symlink at /etc and have our root process read it
//   - create a FIFO and deadlock the scanner forever
//   - create a symlink loop and hang it
//
// Four guarantees this file provides:
//   1. Symlinks are never followed.
//   2. Only regular files are handed onward.
//   3. Every walk is bounded by depth, file count, byte count and wall clock.
//   4. The scan root is verified to resolve inside the volumes directory.
// ============================================================================

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';

/** Thrown when a budget runs out. Not an error - a normal, expected stop. */
export class BudgetExhausted extends Error {
  constructor(which) {
    super(`scan budget exhausted: ${which}`);
    this.name = 'BudgetExhausted';
    this.which = which;
  }
}

/**
 * Tracks how much work a single server's scan is allowed to consume.
 * One instance per server per cycle.
 */
export class ScanBudget {
  /**
   * @param {object} limits
   * @param {number} limits.maxFiles
   * @param {number} limits.maxBytes
   * @param {number} limits.deadlineMs
   * @param {import('../../application/ports.js').Clock} limits.clock
   */
  constructor({ maxFiles, maxBytes, deadlineMs, clock }) {
    this.maxFiles = maxFiles;
    this.maxBytes = maxBytes;
    this.clock = clock;
    this.expiresAtMs = clock.nowMs() + deadlineMs;
    this.filesUsed = 0;
    this.bytesUsed = 0;
    this.skipped = { symlinks: 0, specialFiles: 0, excluded: 0, tooLarge: 0 };
  }

  get expired() {
    return this.clock.nowMs() > this.expiresAtMs;
  }

  takeFile() {
    this.filesUsed += 1;
    if (this.filesUsed > this.maxFiles) throw new BudgetExhausted('maxFiles');
  }

  takeBytes(count) {
    this.bytesUsed += count;
    if (this.bytesUsed > this.maxBytes) throw new BudgetExhausted('maxBytes');
  }
}

/**
 * Confirm a directory really lives inside the allowed root after resolving
 * every symlink. Called once per server, on the volume root only.
 *
 * @param {string} allowedRoot
 * @param {string} candidate
 * @returns {string|null} the real path, or null if it escapes or is missing
 */
export function resolveWithinRoot(allowedRoot, candidate) {
  let realRoot;
  let realCandidate;
  try {
    realRoot = fs.realpathSync(allowedRoot);
    realCandidate = fs.realpathSync(candidate);
  } catch {
    return null;
  }

  const prefix = realRoot.endsWith(path.sep) ? realRoot : realRoot + path.sep;
  if (realCandidate !== realRoot && !realCandidate.startsWith(prefix)) return null;
  return realCandidate;
}

/** Directories that are always skipped: huge, tenant-writable, pure noise. */
const ALWAYS_SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', '.cache']);

export class SafeDirectoryWalker {
  /**
   * @param {object} options
   * @param {number} options.maxDepth
   * @param {boolean} options.scanHidden
   * @param {string[]} options.excludedRelativePaths
   * @param {import('../../application/ports.js').Logger} options.logger
   */
  constructor({ maxDepth, scanHidden, excludedRelativePaths, logger }) {
    this.maxDepth = maxDepth;
    this.scanHidden = scanHidden;
    this.excluded = (excludedRelativePaths ?? []).map((p) => p.replace(/\/+$/, ''));
    this.logger = logger;
  }

  /**
   * Yields regular files below `root`.
   *
   * @param {string} root
   * @param {ScanBudget} budget
   * @returns {AsyncGenerator<{absolutePath: string, relativePath: string, fileName: string}>}
   */
  async *walk(root, budget) {
    const stack = [{ directory: root, depth: 0 }];

    while (stack.length > 0) {
      if (budget.expired) throw new BudgetExhausted('deadline');

      const { directory, depth } = stack.pop();
      if (depth > this.maxDepth) continue;

      let entries;
      try {
        entries = await fsp.readdir(directory, { withFileTypes: true });
      } catch (error) {
        // Missing, unreadable or looping directories are expected. Skip quietly.
        if (!['ENOENT', 'EACCES', 'ELOOP', 'ENOTDIR'].includes(error.code)) {
          this.logger.debug(`cannot read ${directory}: ${error.code ?? error.message}`);
        }
        continue;
      }

      for (const entry of entries) {
        const absolutePath = path.join(directory, entry.name);
        const relativePath = path.relative(root, absolutePath);

        // GUARANTEE 1. This single check closes container escape, FIFO deadlock
        // and symlink loops in one line.
        if (entry.isSymbolicLink()) {
          budget.skipped.symlinks += 1;
          continue;
        }

        if (this.#isExcluded(relativePath)) {
          budget.skipped.excluded += 1;
          continue;
        }

        if (entry.isDirectory()) {
          if (ALWAYS_SKIP_DIRS.has(entry.name) || (!this.scanHidden && entry.name.startsWith('.'))) {
            budget.skipped.excluded += 1;
            continue;
          }
          stack.push({ directory: absolutePath, depth: depth + 1 });
          continue;
        }

        // GUARANTEE 2. Block devices, character devices, sockets and FIFOs
        // are dropped here, before anything tries to open them.
        if (!entry.isFile()) {
          budget.skipped.specialFiles += 1;
          continue;
        }

        if (!this.scanHidden && entry.name.startsWith('.')) {
          budget.skipped.excluded += 1;
          continue;
        }

        yield { absolutePath, relativePath, fileName: entry.name };
      }
    }
  }

  #isExcluded(relativePath) {
    return this.excluded.some(
      (excluded) => relativePath === excluded || relativePath.startsWith(excluded + path.sep),
    );
  }
}
