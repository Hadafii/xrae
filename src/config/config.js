// LAYER: config (sits beside infrastructure; only the CLI and composition root
//        use it, never domain or application)
// JOB:   Turn a file plus some environment variables into one validated object.
//
// Two deliberate choices:
//
// 0. THERE ARE TWO FILES, AND THEY HAVE DIFFERENT JOBS.
//      config.json   settings. Safe to read, safe to share, safe to commit.
//      xrae.env      credentials. Mode 0600, never shared.
//
//    Precedence, highest wins: real environment -> xrae.env -> config.json ->
//    defaults. `xrae doctor` prints where each credential actually came from,
//    because a key set in two places with different values is a real footgun:
//    you rotate the one in config.json, the stale one in the environment keeps
//    winning, and nothing tells you.
//
// 1. THE FILE IS JSON, WITH // COMMENTS ALLOWED.
//    Not YAML. YAML would mean an npm dependency, and X-Rae has zero of those
//    on purpose - a privileged agent with no supply chain cannot be backdoored
//    through one. Comment stripping is ten lines and every editor already
//    highlights JSON.
//
// 2. VALIDATION REFUSES TO START, IT DOES NOT WARN.
//    A misconfigured detector that suspends customers is worse than a detector
//    that will not boot. Fail loudly, at startup, where someone is watching.

import fs from 'node:fs';
import path from 'node:path';
import { loadEnvFileInto } from './env-file.js';
import { PolicyMode } from '../domain/policy.js';
import { Confidence, isValidConfidence } from '../domain/confidence.js';

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** Every setting X-Rae understands, with the value used if you omit it. */
export const DEFAULT_CONFIG = {
  logLevel: 'info',

  panel: {
    url: '',
    applicationKey: '',
    clientKey: '',
    userAgent: 'X-Rae/1.0',
    timeoutMs: 10000,
    allowInsecureTransport: false,
    retry: { maxAttempts: 4, baseDelayMs: 500, maxDelayMs: 15000, maxRetryAfterMs: 60000 },
    circuitBreaker: { failureThreshold: 8, cooldownMs: 60000 },
  },

  notify: {
    discordWebhook: '',
    panelBaseUrl: '',
    timeoutMs: 10000,
    retry: { maxAttempts: 5, baseDelayMs: 1000, maxDelayMs: 30000, maxRetryAfterMs: 60000 },
    circuitBreaker: { failureThreshold: 10, cooldownMs: 120000 },
  },

  scanner: {
    volumesPath: '/var/lib/pterodactyl/volumes',
    nodeId: 0,
    intervalMinutes: 15,
    delayBetweenServersMs: 250,
    scanHidden: true,
    scanArchives: false,
    collectCpu: true,
    collectConnections: true,
    maxDepth: 12,
    maxFilesPerServer: 20000,
    maxFileBytes: 67108864,
    maxBytesPerServer: 2147483648,
    serverDeadlineMs: 120000,
  },

  detection: {
    entropyThreshold: 7.6,
    entropyMinFileBytes: 65536,
    cpuMinSamples: 12,
    cpuSustainedPercent: 92,
    cpuMaxStdDev: 4,
  },

  policy: {
    mode: PolicyMode.OBSERVE,
    riskThreshold: 100,
    minConfidenceToAlert: Confidence.MEDIUM,
    minConfidenceToThrottle: Confidence.HIGH,
    minConfidenceToSuspend: Confidence.CRITICAL,
    consecutiveDetections: 2,
    maxActionsPerCycle: 3,
    anomalyAbortRatio: 0.25,
    scoreHalfLifeHours: 24,
    renotifyCooldownMinutes: 120,
    throttleToCpuPercent: 25,
    ignoredServers: [],
  },

  exclusions: {
    ruleIds: [],
    fileNames: [],
    extensions: [],
    relativePaths: [],
  },

  state: {
    path: '/var/lib/x-rae/state.json',
    maxCacheEntries: 50000,
  },
};

/**
 * The settings that doctor reports a source for. These are the ones people set
 * in more than one place and then lose track of.
 */
export const TRACKED_SECRETS = [
  { label: 'panel application key', variable: 'XRAE_PANEL_APP_KEY', keyPath: ['panel', 'applicationKey'] },
  { label: 'panel client key', variable: 'XRAE_PANEL_CLIENT_KEY', keyPath: ['panel', 'clientKey'] },
  { label: 'Discord webhook', variable: 'XRAE_DISCORD_WEBHOOK', keyPath: ['notify', 'discordWebhook'] },
];

/** Secrets belong in the environment, not in a file on disk. */
const ENVIRONMENT_OVERRIDES = [
  ['XRAE_PANEL_URL', ['panel', 'url']],
  ['XRAE_PANEL_APP_KEY', ['panel', 'applicationKey']],
  ['XRAE_PANEL_CLIENT_KEY', ['panel', 'clientKey']],
  ['XRAE_DISCORD_WEBHOOK', ['notify', 'discordWebhook']],
  ['XRAE_VOLUMES_PATH', ['scanner', 'volumesPath']],
  ['XRAE_NODE_ID', ['scanner', 'nodeId']],
  ['XRAE_MODE', ['policy', 'mode']],
  ['XRAE_LOG_LEVEL', ['logLevel']],
  ['XRAE_STATE_PATH', ['state', 'path']],
];

/**
 * Strip // and /* *\/ comments from JSON, ignoring anything inside a string.
 * Small enough to read in one sitting, which is the point.
 */
export function stripJsonComments(text) {
  let output = '';
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (char === '\n') { inLineComment = false; output += char; }
      continue;
    }
    if (inBlockComment) {
      if (char === '*' && next === '/') { inBlockComment = false; i += 1; }
      continue;
    }
    if (inString) {
      output += char;
      if (char === '\\') { output += next ?? ''; i += 1; continue; }
      if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; output += char; continue; }
    if (char === '/' && next === '/') { inLineComment = true; i += 1; continue; }
    if (char === '/' && next === '*') { inBlockComment = true; i += 1; continue; }
    output += char;
  }
  return output;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(base, override) {
  if (!isPlainObject(override)) return base;
  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value === undefined || value === null) continue;
    result[key] = isPlainObject(value) && isPlainObject(base[key]) ? deepMerge(base[key], value) : value;
  }
  return result;
}

function applyEnvironment(config) {
  for (const [variable, keyPath] of ENVIRONMENT_OVERRIDES) {
    const raw = process.env[variable];
    if (raw === undefined || raw === '') continue;

    let cursor = config;
    for (const key of keyPath.slice(0, -1)) cursor = cursor[key];
    const finalKey = keyPath.at(-1);
    const existing = cursor[finalKey];

    if (typeof existing === 'number') {
      const parsed = Number(raw);
      cursor[finalKey] = Number.isFinite(parsed) ? parsed : existing;
    } else if (typeof existing === 'boolean') {
      cursor[finalKey] = /^(1|true|yes|on)$/i.test(raw);
    } else {
      cursor[finalKey] = raw;
    }
  }
  return config;
}

/**
 * Refuse a file that other local users can read.
 *
 * Applied to xrae.env unconditionally, and to config.json ONLY when that file
 * actually contains a credential. A settings file with no secrets in it is
 * meant to be readable - insisting on 0600 there would be security theatre that
 * teaches operators to ignore the warning.
 *
 * @param {string} filePath
 * @param {string} [because] appended to the message, explaining what leaks
 * @returns {string|null} an error message, or null if the file is fine
 */
export function checkFilePermissions(filePath, because = 'It holds credentials') {
  // Windows has no POSIX mode bits - Node reports a fabricated 0666 for every
  // file, so on win32 this check can only produce false positives. Real
  // deployments are Linux + systemd, where the check stays fully active;
  // Windows dev machines rely on NTFS ACLs, which stat() cannot see.
  if (process.platform === 'win32') return null;

  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return null;
  }
  const mode = stat.mode & 0o777;

  // What we actually care about, in order of severity:
  //
  //   other-anything  any local user can read a panel admin key. Never allowed.
  //   group-write     the service user could rewrite its own credentials.
  //                   Never allowed.
  //   group-read      ALLOWED, and in fact the recommended deployment. The
  //                   service runs as an unprivileged user, so it has to be able
  //                   to read this file. root:xrae 0640 lets it read and not
  //                   write, which is stricter than making the service the owner.
  //
  // Demanding 0600 here looks tighter but is worse in practice: it forces the
  // file to be owned by the service user, which means a compromised agent can
  // rewrite its own config.
  const worldAccess = mode & 0o007;
  const groupWrite = mode & 0o020;

  if (!worldAccess && !groupWrite) return null;

  const problem = worldAccess ? 'is accessible to all local users' : 'is group-writable';
  return (
    `${filePath} has mode 0${mode.toString(8)} and ${problem}. ${because}.\n` +
    `    Fix it with one of:\n` +
    `      sudo chown root:xrae ${filePath} && sudo chmod 640 ${filePath}   # service reads, only root writes\n` +
    `      sudo chmod 600 ${filePath}                                       # if you run X-Rae as root's own user`
  );
}

/** Does this config object contain anything that must stay private? */
export function containsSecrets(fromFile) {
  return TRACKED_SECRETS.some((secret) => Boolean(readValueAt(fromFile, secret.keyPath)));
}

function validate(config) {
  const problems = [];
  const require = (condition, message) => { if (!condition) problems.push(message); };

  require(Boolean(config.panel.url), 'panel.url is required');
  require(
    Boolean(config.panel.applicationKey),
    'panel.applicationKey is required (or set the XRAE_PANEL_APP_KEY environment variable)',
  );

  if (config.panel.url) {
    let parsed = null;
    try { parsed = new URL(config.panel.url); } catch { problems.push(`panel.url is not a valid URL: ${config.panel.url}`); }

    if (parsed) {
      const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
      require(
        parsed.protocol === 'https:' || isLoopback || config.panel.allowInsecureTransport,
        'panel.url uses plain http:// to a remote host, which sends the API key in clear text. ' +
          'Use https, or set panel.allowInsecureTransport to true if the traffic truly stays on this machine.',
      );
    }
  }

  if (config.notify.discordWebhook) {
    try {
      require(new URL(config.notify.discordWebhook).protocol === 'https:', 'notify.discordWebhook must use https');
    } catch {
      problems.push('notify.discordWebhook is not a valid URL');
    }
  }

  require(Object.values(PolicyMode).includes(config.policy.mode),
    `policy.mode must be one of ${Object.values(PolicyMode).join(', ')} (got "${config.policy.mode}")`);

  for (const key of ['minConfidenceToAlert', 'minConfidenceToThrottle', 'minConfidenceToSuspend']) {
    require(isValidConfidence(config.policy[key]), `policy.${key} must be low, medium, high or critical`);
  }

  require(config.policy.scoreHalfLifeHours > 0, 'policy.scoreHalfLifeHours must be greater than 0');
  require(config.policy.anomalyAbortRatio > 0 && config.policy.anomalyAbortRatio <= 1,
    'policy.anomalyAbortRatio must be between 0 and 1');
  require(config.scanner.intervalMinutes >= 1, 'scanner.intervalMinutes must be at least 1');
  require(config.scanner.maxDepth >= 1, 'scanner.maxDepth must be at least 1');

  // Acting on servers without telling anyone is not acceptable.
  if (config.policy.mode === PolicyMode.ENFORCE || config.policy.mode === PolicyMode.THROTTLE) {
    require(config.policy.consecutiveDetections >= 1,
      'policy.consecutiveDetections must be at least 1 when actions are enabled');
    require(config.policy.maxActionsPerCycle >= 1,
      'policy.maxActionsPerCycle must be at least 1 when actions are enabled');
    require(Boolean(config.notify.discordWebhook),
      `policy.mode "${config.policy.mode}" would act on servers with no webhook configured, ` +
        'meaning silent enforcement. Configure notify.discordWebhook first.');
  }

  // EACCES is deliberately NOT a validation failure. On a locked-down node a
  // manual `sudo -u xrae` shell cannot traverse /var/lib/pterodactyl at all,
  // while the systemd unit holds CAP_DAC_READ_SEARCH and reads it fine.
  // Reporting that as "does not exist" sent an operator down the wrong path.
  // Doctor checks readability separately and explains the capability story.
  let volumesStat = null;
  try {
    volumesStat = fs.statSync(config.scanner.volumesPath);
  } catch (error) {
    if (error.code !== 'EACCES' && error.code !== 'EPERM') {
      problems.push(`scanner.volumesPath does not exist: ${config.scanner.volumesPath}`);
    }
  }
  if (volumesStat && !volumesStat.isDirectory()) {
    problems.push(`scanner.volumesPath is not a directory: ${config.scanner.volumesPath}`);
  }

  if (problems.length > 0) {
    throw new ConfigError('Configuration is not usable:\n\n  - ' + problems.join('\n  - ') + '\n');
  }
}

function normalise(config) {
  config.panel.url = config.panel.url.replace(/\/+$/, '');
  config.notify.panelBaseUrl = (config.notify.panelBaseUrl || config.panel.url).replace(/\/+$/, '');
  config.scanner.volumesPath = path.resolve(config.scanner.volumesPath);
  config.policy.ignoredServers = (config.policy.ignoredServers ?? []).map(String);
  config.exclusions.extensions = (config.exclusions.extensions ?? []).map((e) => String(e).replace(/^\./, '').toLowerCase());
  config.exclusions.fileNames = (config.exclusions.fileNames ?? []).map((f) => String(f).toLowerCase());
  config.exclusions.ruleIds = (config.exclusions.ruleIds ?? []).map(String);
  return config;
}

/**
 * Where to look for the credentials file.
 *
 * Convention over configuration: it sits next to config.json and is called
 * xrae.env. Predictable beats flexible for something an operator has to find
 * while a node is on fire.
 *
 * @param {object} options
 * @param {string} [options.configFilePath]
 * @param {string} [options.explicitEnvFilePath]
 * @returns {string|null}
 */
export function resolveEnvFilePath({ configFilePath, explicitEnvFilePath } = {}) {
  if (explicitEnvFilePath) return path.resolve(explicitEnvFilePath);
  if (process.env.XRAE_ENV_FILE) return path.resolve(process.env.XRAE_ENV_FILE);
  if (configFilePath) return path.join(path.dirname(path.resolve(configFilePath)), 'xrae.env');
  return null;
}

function readValueAt(object, keyPath) {
  let cursor = object;
  for (const key of keyPath) {
    if (cursor === undefined || cursor === null) return undefined;
    cursor = cursor[key];
  }
  return cursor;
}

/**
 * Work out where each credential actually came from, and flag any that are set
 * in two places at once.
 */
function describeSecretSources({ fromFile, envFilePath, envFileResult, preexistingEnv }) {
  const sources = {};
  const conflicts = [];

  for (const secret of TRACKED_SECRETS) {
    const inRealEnv = Boolean(preexistingEnv[secret.variable]);
    const inEnvFile = envFileResult?.applied.includes(secret.variable) ?? false;
    const shadowedInEnvFile = envFileResult?.alreadySet.includes(secret.variable) ?? false;
    const inConfigFile = Boolean(readValueAt(fromFile, secret.keyPath));

    if (inRealEnv) sources[secret.label] = 'environment';
    else if (inEnvFile) sources[secret.label] = envFilePath ?? 'env file';
    else if (inConfigFile) sources[secret.label] = 'config.json';
    else sources[secret.label] = 'not set';

    // Two definitions of the same credential is how a rotated key silently
    // fails to take effect. Say so loudly.
    if (inRealEnv && inConfigFile) {
      conflicts.push(
        `${secret.label} is set in BOTH config.json and the environment. The environment wins, ` +
          `so editing config.json will appear to do nothing. Remove one of them.`,
      );
    } else if (shadowedInEnvFile && inConfigFile) {
      conflicts.push(
        `${secret.label} is set in BOTH config.json and ${envFilePath}. The env file wins. Remove one of them.`,
      );
    } else if (inEnvFile && inConfigFile) {
      conflicts.push(
        `${secret.label} is set in BOTH config.json and ${envFilePath}. The env file wins. Remove one of them.`,
      );
    }
  }

  return { sources, conflicts };
}

/**
 * @param {object} [options]
 * @param {string} [options.filePath]
 * @param {string} [options.envFilePath]      override the xrae.env location
 * @param {boolean} [options.skipValidation]  used by `xrae init`
 * @returns {{config: object, warnings: string[], sources: Record<string,string>, envFilePath: string|null, envFileLoaded: boolean}}
 */
export function loadConfig({ filePath, envFilePath, skipValidation = false } = {}) {
  const warnings = [];
  let fromFile = {};

  if (filePath) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      throw new ConfigError(
        `Config file not found: ${resolved}\n\nRun "xrae init" to create one.`,
      );
    }

    try {
      fromFile = JSON.parse(stripJsonComments(fs.readFileSync(resolved, 'utf8'))) ?? {};
    } catch (error) {
      throw new ConfigError(`Config file is not valid JSON: ${error.message}`);
    }

    // Only a config that actually holds a key needs to be locked down. One that
    // just holds settings is meant to be readable and shareable.
    if (containsSecrets(fromFile)) {
      const permissionProblem = checkFilePermissions(
        resolved,
        'It contains an API key or webhook (move those to xrae.env instead)',
      );
      if (permissionProblem) throw new ConfigError(permissionProblem);
    }
  }

  // Snapshot the real environment BEFORE the env file touches it, so we can
  // tell the two apart when reporting sources.
  const preexistingEnv = { ...process.env };

  const resolvedEnvFile = resolveEnvFilePath({ configFilePath: filePath, explicitEnvFilePath: envFilePath });
  let envFileResult = null;

  if (resolvedEnvFile && fs.existsSync(resolvedEnvFile)) {
    const permissionProblem = checkFilePermissions(resolvedEnvFile, 'It holds panel admin credentials');
    if (permissionProblem) throw new ConfigError(permissionProblem);
    try {
      envFileResult = loadEnvFileInto(resolvedEnvFile);
    } catch (error) {
      throw new ConfigError(`Could not read ${resolvedEnvFile}: ${error.message}`);
    }
  }

  const { sources, conflicts } = describeSecretSources({
    fromFile,
    envFilePath: resolvedEnvFile,
    envFileResult,
    preexistingEnv,
  });
  warnings.push(...conflicts);

  const config = normalise(applyEnvironment(deepMerge(DEFAULT_CONFIG, fromFile)));
  if (!skipValidation) validate(config);

  return {
    config,
    warnings,
    sources,
    envFilePath: resolvedEnvFile,
    envFileLoaded: envFileResult !== null,
  };
}
