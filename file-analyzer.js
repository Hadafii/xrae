// LAYER: infrastructure
// JOB:   Look inside one file and report what rules it matches.
//
// Two things here are easy to get wrong, so they are called out explicitly.
//
// 1. HOW THE FILE IS OPENED
//    We open with O_NOFOLLOW and O_NONBLOCK, and we stat the FILE DESCRIPTOR,
//    not the path. This closes a race: the walker saw a regular file, but a
//    tenant can replace it with a symlink in the microseconds before we open
//    it. With O_NOFOLLOW that swap makes open() fail instead of succeed.
//
// 2. HOW MUCH IS READ
//    The old SonarX read only the first and last 16 KiB. Padding a payload
//    into the middle of a file defeated it completely. We read the whole file
//    in 1 MiB chunks with a 4 KiB overlap, so a match spanning a chunk
//    boundary is still found. The extra I/O is paid for by the fingerprint
//    cache: an unchanged file is not re-read on the next cycle.

import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

import { createEvidence, EvidenceFamily } from '../../domain/evidence.js';
import {
  RULE_PACK,
  REGEX_RULES,
  NEVER_SCAN_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  NATURALLY_HIGH_ENTROPY,
  SCRIPT_EXTENSIONS,
  CONFIG_EXTENSIONS,
  TEXT_EXTENSIONS,
  FILE_CLASS_WEIGHT,
  SIGNATURE_FLOOD_THRESHOLD,
  FLOOD_WEIGHT_MULTIPLIER,
  validateRulePack,
} from '../../domain/rules.js';

const O_NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fs.constants.O_NONBLOCK ?? 0;

const CHUNK_BYTES = 1024 * 1024;
const OVERLAP_BYTES = 4096;
const ENTROPY_SAMPLE_BYTES = 256 * 1024;
const REGEX_WINDOW_BYTES = 128 * 1024;
const FINGERPRINT_HEAD_BYTES = 64 * 1024;

/** What kind of file this is, which changes how much a match is worth. */
export function classifyFile(fileName) {
  const extension = path.extname(fileName).slice(1).toLowerCase();

  if (NEVER_SCAN_EXTENSIONS.has(extension)) return { extension, fileClass: 'skip' };
  if (ARCHIVE_EXTENSIONS.has(extension)) return { extension, fileClass: 'archive' };
  if (SCRIPT_EXTENSIONS.has(extension)) return { extension, fileClass: 'script' };
  if (TEXT_EXTENSIONS.has(extension)) return { extension, fileClass: 'text' };
  if (CONFIG_EXTENSIONS.has(extension)) return { extension, fileClass: 'config' };

  const looksLikeBinary = ['', 'bin', 'so', 'elf', 'exe', 'dll', 'out', 'dylib'].includes(extension);
  return { extension, fileClass: looksLikeBinary ? 'executable' : 'unknown' };
}

/** Shannon entropy in bits per byte. 8.0 is perfectly random. */
export function shannonEntropy(buffer) {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i += 1) counts[buffer[i]] += 1;

  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const probability = counts[i] / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/** Lowercase only ASCII letters, leaving binary bytes untouched. */
function lowercaseAscii(source, length) {
  const output = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i += 1) {
    const byte = source[i];
    output[i] = byte >= 0x41 && byte <= 0x5a ? byte + 32 : byte;
  }
  return output;
}

function detectFileMagic(head) {
  if (head.length >= 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) return 'elf';
  if (head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a) return 'pe';
  if (head.length >= 2 && head[0] === 0x23 && head[1] === 0x21) return 'shebang';
  return null;
}

export class FileContentAnalyzer {
  /**
   * @param {object} options
   * @param {object} options.settings
   * @param {number} options.settings.maxFileBytes
   * @param {number} options.settings.entropyThreshold
   * @param {number} options.settings.entropyMinFileBytes
   * @param {string[]} options.settings.excludedRuleIds
   * @param {string[]} options.settings.excludedFileNames
   * @param {string[]} options.settings.excludedExtensions
   * @param {boolean} options.settings.scanArchives
   * @param {import('../../application/ports.js').Logger} options.logger
   */
  constructor({ settings, logger }) {
    this.settings = settings;
    this.logger = logger;

    validateRulePack(RULE_PACK);

    // Compile once at construction, not per file. Buffer.indexOf uses a fast
    // native search, which is why plain substrings are preferred over regex.
    this.compiledRules = RULE_PACK.filter((rule) => !settings.excludedRuleIds.includes(rule.id)).map((rule) => ({
      rule,
      needle: Buffer.from(rule.pattern.toLowerCase(), 'latin1'),
    }));

    this.regexRules = REGEX_RULES.filter((rule) => !settings.excludedRuleIds.includes(rule.id));
  }

  /**
   * @param {object} input
   * @param {string} input.absolutePath
   * @param {string} input.relativePath
   * @param {string} input.fileName
   * @param {import('./safe-walker.js').ScanBudget} input.budget
   * @param {{get: Function, set: Function}} input.cache
   * @returns {Promise<import('../../domain/evidence.js').Evidence[]>}
   */
  async analyze({ absolutePath, relativePath, fileName, budget, cache }) {
    const { extension, fileClass } = classifyFile(fileName);

    if (fileClass === 'skip') return [];
    if (fileClass === 'archive' && !this.settings.scanArchives) return [];
    if (this.settings.excludedExtensions.includes(extension)) return [];
    if (this.settings.excludedFileNames.includes(fileName.toLowerCase())) return [];

    let fd;
    try {
      fd = fs.openSync(absolutePath, fs.constants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    } catch (error) {
      if (error.code === 'ELOOP') {
        this.logger.debug(`refused a symlink swapped in under us: ${relativePath}`);
      }
      return [];
    }

    try {
      return this.#analyzeOpenFile({ fd, relativePath, extension, fileClass, budget, cache });
    } catch (error) {
      if (error.name === 'BudgetExhausted') throw error;
      this.logger.debug(`could not analyze ${relativePath}: ${error.message}`);
      return [];
    } finally {
      try {
        fs.closeSync(fd);
      } catch {
        /* already closed */
      }
    }
  }

  #analyzeOpenFile({ fd, relativePath, extension, fileClass, budget, cache }) {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size === 0) return [];

    const readLimit = Math.min(stat.size, this.settings.maxFileBytes);
    if (stat.size > this.settings.maxFileBytes) budget.skipped.tooLarge += 1;

    const headSize = Math.min(readLimit, FINGERPRINT_HEAD_BYTES);
    const head = Buffer.allocUnsafe(headSize);
    fs.readSync(fd, head, 0, headSize, 0);

    const fingerprint = this.#fingerprint(stat, head);
    const cached = cache?.get(fingerprint);
    if (cached) {
      // The file has not changed since we last looked at it, so neither has
      // the answer. This is what makes full-file scanning affordable.
      return cached.evidence.map((item) => createEvidence(item));
    }

    budget.takeFile();
    budget.takeBytes(readLimit);

    const found = new Map();
    this.#scanForSignatures({ fd, readLimit, relativePath, budget, found });
    this.#scanWithRegex({ fd, readLimit, relativePath, found });
    this.#scanEntropy({ fd, readLimit, stat, extension, fileClass, relativePath, found });

    const evidence = this.#applyWeighting([...found.values()], fileClass, relativePath);
    cache?.set(fingerprint, { evidence });
    return evidence;
  }

  /** Cheap but change-sensitive: size, mtime and the head block. */
  #fingerprint(stat, head) {
    return crypto
      .createHash('sha256')
      .update(`${stat.size}:${Math.trunc(stat.mtimeMs)}:`)
      .update(head)
      .digest('hex')
      .slice(0, 32);
  }

  #scanForSignatures({ fd, readLimit, relativePath, budget, found }) {
    const buffer = Buffer.allocUnsafe(CHUNK_BYTES);
    let carryOver = Buffer.alloc(0);
    let offset = 0;

    while (offset < readLimit) {
      if (budget.expired) return;

      const wanted = Math.min(CHUNK_BYTES, readLimit - offset);
      const got = fs.readSync(fd, buffer, 0, wanted, offset);
      if (got <= 0) return;

      const lowered = lowercaseAscii(buffer, got);
      // Prepending the tail of the previous chunk is what lets a match that
      // straddles a chunk boundary still be found.
      const window = carryOver.length > 0 ? Buffer.concat([carryOver, lowered]) : lowered;

      for (const { rule, needle } of this.compiledRules) {
        if (found.has(rule.id)) continue;
        if (window.indexOf(needle) === -1) continue;

        found.set(rule.id, {
          ruleId: rule.id,
          family: EvidenceFamily.SIGNATURE,
          category: rule.category,
          weight: rule.weight,
          confidence: rule.confidence,
          standalone: rule.standalone,
          detail: `matched "${rule.pattern}" in ${relativePath}`,
        });
      }

      carryOver = window.subarray(Math.max(0, window.length - OVERLAP_BYTES));
      offset += got;
    }
  }

  #scanWithRegex({ fd, readLimit, relativePath, found }) {
    if (this.regexRules.length === 0) return;

    const windowSize = Math.min(readLimit, REGEX_WINDOW_BYTES);
    const window = Buffer.allocUnsafe(windowSize);
    fs.readSync(fd, window, 0, windowSize, 0);
    const text = window.toString('latin1');

    for (const rule of this.regexRules) {
      if (found.has(rule.id)) continue;
      if (!rule.regex.test(text)) continue;

      found.set(rule.id, {
        ruleId: rule.id,
        family: rule.family,
        category: rule.category,
        weight: rule.weight,
        confidence: rule.confidence,
        standalone: rule.standalone,
        detail: `${rule.detail} in ${relativePath}`,
      });
    }
  }

  #scanEntropy({ fd, readLimit, stat, extension, fileClass, relativePath, found }) {
    // Entropy only means something for things that could be a packed payload.
    // Archives and databases are high-entropy by design; measuring them just
    // manufactures false positives.
    const worthMeasuring =
      !NATURALLY_HIGH_ENTROPY.has(extension) &&
      (fileClass === 'executable' || fileClass === 'unknown') &&
      stat.size >= this.settings.entropyMinFileBytes;

    if (!worthMeasuring) return;

    const sampleSize = Math.min(readLimit, ENTROPY_SAMPLE_BYTES);
    const sample = Buffer.allocUnsafe(sampleSize);
    fs.readSync(fd, sample, 0, sampleSize, 0);

    const entropy = shannonEntropy(sample);
    if (entropy < this.settings.entropyThreshold) return;

    const magic = detectFileMagic(sample);
    found.set('packing.high_entropy', {
      ruleId: 'packing.high_entropy',
      family: EvidenceFamily.ENTROPY,
      category: 'OBFUSCATION',
      weight: 20,
      confidence: 'low',
      standalone: false,
      detail: `entropy ${entropy.toFixed(2)}${magic ? ` in a ${magic} file` : ''} (${relativePath})`,
    });
  }

  /**
   * Adjust weights for context, and defuse "reference list" files.
   *
   * The flood guard is the single most effective false-positive control in the
   * scanner. A file matching eight or more different rules is a blocklist, a
   * log, a wiki dump, or a security tool - real malware matches a handful.
   * Without this, X-Rae flags its own rule pack.
   */
  #applyWeighting(rawFindings, fileClass, relativePath) {
    const signatureCount = rawFindings.filter((f) => f.family === EvidenceFamily.SIGNATURE).length;

    if (signatureCount >= SIGNATURE_FLOOD_THRESHOLD) {
      this.logger.debug(
        `${relativePath} matched ${signatureCount} different rules; treating it as a reference list, not a threat`,
      );
      return rawFindings.map((finding) =>
        createEvidence({
          ...finding,
          weight: Math.max(1, Math.round(finding.weight * FLOOD_WEIGHT_MULTIPLIER)),
          confidence: 'low',
          standalone: false,
          detail: `${finding.detail} [suppressed: file looks like a reference list]`,
        }),
      );
    }

    const multiplier = FILE_CLASS_WEIGHT[fileClass] ?? FILE_CLASS_WEIGHT.unknown;
    return rawFindings.map((finding) =>
      createEvidence({ ...finding, weight: Math.max(1, Math.round(finding.weight * multiplier)) }),
    );
  }
}
