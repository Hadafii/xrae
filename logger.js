// LAYER: infrastructure
// JOB:   Write log lines, with credentials stripped out first.
// IMPLEMENTS: Logger port.
//
// Redaction is not optional. Operators routinely paste logs into Discord or a
// support ticket when asking for help, and this process handles a Pterodactyl
// application key - which is full panel admin. One careless paste should not
// hand over the platform.

const LEVEL_RANK = { error: 0, warn: 1, info: 2, debug: 3 };

/** Patterns that must never reach a log line. Add to this list, never remove. */
const SECRET_PATTERNS = [
  [/ptla_[A-Za-z0-9_-]+/g, 'ptla_<redacted>'],
  [/ptlc_[A-Za-z0-9_-]+/g, 'ptlc_<redacted>'],
  [/https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g, '<discord-webhook-redacted>'],
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1<redacted>'],
];

/**
 * Exported separately so the test suite can assert that redaction works.
 * @param {unknown} value
 * @returns {string}
 */
export function redactSecrets(value) {
  let text = typeof value === 'string' ? value : describe(value);
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    text = text.replace(pattern, replacement);
  }
  return text;
}

function describe(value) {
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** @implements {import('../../application/ports.js').Logger} */
export class ConsoleLogger {
  /**
   * @param {object} [options]
   * @param {'error'|'warn'|'info'|'debug'} [options.level]
   * @param {boolean} [options.useColor]
   */
  constructor({ level = 'info', useColor = process.stdout.isTTY === true } = {}) {
    this.level = level;
    this.useColor = useColor;
  }

  setLevel(level) {
    if (level in LEVEL_RANK) this.level = level;
  }

  error(...args) { this.#write('error', args); }
  warn(...args) { this.#write('warn', args); }
  info(...args) { this.#write('info', args); }
  debug(...args) { this.#write('debug', args); }

  #write(level, args) {
    if (LEVEL_RANK[level] > LEVEL_RANK[this.level]) return;

    const colors = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[36m', debug: '\x1b[90m' };
    const message = args.map(redactSecrets).join(' ');
    const prefix = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)}`;
    const line = this.useColor ? `${colors[level]}${prefix}\x1b[0m ${message}` : `${prefix} ${message}`;
    const stream = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
    stream.write(line + '\n');
  }
}

/**
 * Collects log lines instead of printing them. Used by tests and by the
 * `doctor` command.
 * @implements {import('../../application/ports.js').Logger}
 */
export class MemoryLogger {
  constructor() {
    /** @type {Array<{level: string, message: string}>} */
    this.lines = [];
  }
  error(...a) { this.lines.push({ level: 'error', message: a.map(redactSecrets).join(' ') }); }
  warn(...a) { this.lines.push({ level: 'warn', message: a.map(redactSecrets).join(' ') }); }
  info(...a) { this.lines.push({ level: 'info', message: a.map(redactSecrets).join(' ') }); }
  debug(...a) { this.lines.push({ level: 'debug', message: a.map(redactSecrets).join(' ') }); }
}
