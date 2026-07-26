// LAYER: cli
// JOB:   The commands an operator actually types.
//
// Design goal: nobody should have to read the source to get X-Rae running.
// `xrae init` writes the config, `xrae doctor` proves it works, `xrae scan
// --dry-run` shows what it would do. Only then does anyone start the service.

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

import { loadConfig, DEFAULT_CONFIG, checkFilePermissions, ConfigError } from '../config/config.js';
import { buildApplication } from '../composition-root.js';
import { ConsoleLogger } from '../infrastructure/system/logger.js';
import { PolicyMode } from '../domain/policy.js';
import { RULE_PACK, REGEX_RULES, validateRulePack } from '../domain/rules.js';

const CHECK = '  \x1b[32m✓\x1b[0m';
const CROSS = '  \x1b[31m✗\x1b[0m';
const WARN = '  \x1b[33m!\x1b[0m';

function print(line = '') {
  stdout.write(line + '\n');
}

// ---------------------------------------------------------------------------
// xrae init
// ---------------------------------------------------------------------------

/**
 * Interactive setup. Asks the four things that cannot be guessed, uses sensible
 * defaults for the other forty, and writes the file with mode 0600.
 */
export async function commandInit({ configPath }) {
  const resolved = path.resolve(configPath);

  if (fs.existsSync(resolved)) {
    print(`\nA config already exists at ${resolved}`);
    print('Nothing was changed. Delete it first if you want to start over.\n');
    return 1;
  }

  print('\n  X-Rae setup');
  print('  ───────────');
  print('  Four questions. Everything else gets a safe default.\n');

  const rl = readline.createInterface({ input: stdin, output: stdout });

  try {
    const panelUrl = await ask(rl, 'Panel URL', 'https://panel.example.com');
    const applicationKey = await ask(rl, 'Application API key (ptla_...)', '');
    const clientKey = await ask(rl, 'Client API key (ptlc_..., optional, enables CPU checks)', '');
    const webhook = await ask(rl, 'Discord webhook URL (optional)', '');
    const nodeId = await ask(rl, 'Node ID to scan (0 = all nodes this key can see)', '0');
    const volumesPath = await ask(rl, 'Volumes path', DEFAULT_CONFIG.scanner.volumesPath);

    const contents = renderConfigFile({
      panelUrl: panelUrl.replace(/\/+$/, ''),
      applicationKey,
      clientKey,
      webhook,
      nodeId: Number(nodeId) || 0,
      volumesPath,
    });

    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, contents, { mode: 0o600 });
    fs.chmodSync(resolved, 0o600);

    print(`\n${CHECK} wrote ${resolved} (mode 0600)`);
    print('');
    print('  Next:');
    print(`    xrae doctor --config ${resolved}          check everything works`);
    print(`    xrae scan --config ${resolved} --dry-run  see what it would do`);
    print('');
    print('  The config starts in "observe" mode. It will not touch any server.');
    print('  Leave it there for a couple of weeks before enabling enforcement.\n');
    return 0;
  } finally {
    rl.close();
  }
}

async function ask(rl, question, defaultValue) {
  const suffix = defaultValue ? ` [${defaultValue}]` : '';
  const answer = (await rl.question(`  ${question}${suffix}: `)).trim();
  return answer || defaultValue;
}

function renderConfigFile({ panelUrl, applicationKey, clientKey, webhook, nodeId, volumesPath }) {
  return `// X-Rae configuration
// Comments are allowed in this file. Every setting not listed here uses its
// default - run "xrae doctor" to see the values in effect.
{
  "panel": {
    "url": ${JSON.stringify(panelUrl)},
    // Leave these empty and use environment variables instead if you prefer:
    //   XRAE_PANEL_APP_KEY, XRAE_PANEL_CLIENT_KEY
    "applicationKey": ${JSON.stringify(applicationKey)},
    "clientKey": ${JSON.stringify(clientKey)}
  },

  "notify": {
    "discordWebhook": ${JSON.stringify(webhook)}
  },

  "scanner": {
    "volumesPath": ${JSON.stringify(volumesPath)},
    "nodeId": ${nodeId},
    "intervalMinutes": 15
  },

  "policy": {
    // observe   look and record, never alert automatically  <-- start here
    // alert     tell humans, never touch a server
    // throttle  may reduce CPU, never suspend
    // enforce   may suspend, subject to every guardrail
    "mode": "observe",

    "riskThreshold": 100,
    "minConfidenceToSuspend": "critical",

    // Must trip this many cycles in a row before any action.
    "consecutiveDetections": 2,

    // Hard ceiling on actions per cycle, so a bad rule cannot cascade.
    "maxActionsPerCycle": 3,

    // If more than this fraction of the node trips at once, X-Rae assumes it
    // is broken rather than that everyone started mining, and stops acting.
    "anomalyAbortRatio": 0.25,

    // Evidence fades. Noise cannot accumulate its way to a suspension.
    "scoreHalfLifeHours": 24
  },

  "exclusions": {
    // Turn off a specific rule:      "ruleIds": ["tunnel.nezha.agent"]
    // Never open a file by name:     "fileNames": ["blocklist.txt"]
    // Skip a path in every volume:   "relativePaths": ["plugins/BigPlugin"]
    "ruleIds": [],
    "fileNames": [],
    "extensions": [],
    "relativePaths": []
  }
}
`;
}

// ---------------------------------------------------------------------------
// xrae doctor
// ---------------------------------------------------------------------------

/**
 * Checks everything that commonly goes wrong, in the order it usually goes
 * wrong, and says exactly how to fix each one.
 */
export async function commandDoctor({ configPath }) {
  print('\n  X-Rae health check');
  print('  ──────────────────\n');

  let failures = 0;
  let warnings = 0;

  // 1. Node version
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  if (nodeMajor >= 20) {
    print(`${CHECK} Node.js ${process.versions.node}`);
  } else {
    print(`${CROSS} Node.js ${process.versions.node} is too old; version 20 or newer is required`);
    failures += 1;
  }

  // 2. Rule pack integrity
  try {
    validateRulePack(RULE_PACK);
    print(`${CHECK} rule pack valid (${RULE_PACK.length} text rules, ${REGEX_RULES.length} pattern rules)`);
  } catch (error) {
    print(`${CROSS} rule pack is invalid:\n${error.message}`);
    failures += 1;
  }

  // 3. Config file
  const resolved = path.resolve(configPath);
  if (!fs.existsSync(resolved)) {
    print(`${CROSS} no config at ${resolved}\n      fix: xrae init --config ${resolved}`);
    return finishDoctor(failures + 1, warnings);
  }

  const permissionProblem = checkFilePermissions(resolved);
  if (permissionProblem) {
    print(`${CROSS} config permissions are unsafe\n      ${permissionProblem.split('\n').join('\n      ')}`);
    return finishDoctor(failures + 1, warnings);
  }
  print(`${CHECK} config file readable and private (${resolved})`);

  let config;
  try {
    ({ config } = loadConfig({ filePath: resolved }));
    print(`${CHECK} config is valid`);
  } catch (error) {
    if (error instanceof ConfigError) {
      print(`${CROSS} ${error.message.split('\n').join('\n      ')}`);
      return finishDoctor(failures + 1, warnings);
    }
    throw error;
  }

  // 4. Privilege check
  if (process.getuid && process.getuid() === 0) {
    print(`${WARN} running as root. X-Rae does not need it - see systemd/x-rae.service`);
    warnings += 1;
  } else {
    print(`${CHECK} not running as root`);
  }

  // 5. Volumes directory
  try {
    const entries = fs.readdirSync(config.scanner.volumesPath);
    print(`${CHECK} volumes directory readable (${entries.length} entries)`);
  } catch (error) {
    print(`${CROSS} cannot read ${config.scanner.volumesPath}: ${error.code}`);
    print('      fix: grant CAP_DAC_READ_SEARCH, or run as a user with read access');
    failures += 1;
  }

  // 6. State directory
  try {
    fs.mkdirSync(path.dirname(config.state.path), { recursive: true });
    fs.accessSync(path.dirname(config.state.path), fs.constants.W_OK);
    print(`${CHECK} state directory writable (${path.dirname(config.state.path)})`);
  } catch (error) {
    print(`${CROSS} cannot write to ${path.dirname(config.state.path)}: ${error.code}`);
    failures += 1;
  }

  const app = buildApplication({ config, dryRun: true, logger: new ConsoleLogger({ level: 'error' }) });

  // 7. Panel connectivity and credentials
  try {
    const access = await app.serverRepository.checkAccess();
    print(`${CHECK} panel reachable, key can see ${access.visibleServers} server(s)`);
    if (access.visibleServers === 0) {
      print(`${WARN} the key sees zero servers - check it is an Application key, not a Client key`);
      warnings += 1;
    }
  } catch (error) {
    print(`${CROSS} panel check failed: ${error.message}`);
    if (error.status === 401 || error.status === 403) {
      print('      fix: the application key is wrong or lacks permission');
    }
    failures += 1;
  }

  // 8. Optional capabilities
  if (config.scanner.collectCpu) {
    if (config.panel.clientKey) print(`${CHECK} CPU behaviour checks enabled`);
    else {
      print(`${WARN} CPU behaviour checks are on but no clientKey is set; this evidence source is inactive`);
      warnings += 1;
    }
  }

  if (config.scanner.collectConnections) {
    const canRead = await app.containerResolver.checkPermissions();
    if (canRead) print(`${CHECK} network attribution available`);
    else {
      print(`${WARN} network attribution unavailable (needs CAP_SYS_PTRACE); that evidence source is inactive`);
      warnings += 1;
    }
  }

  // 9. Notification
  if (app.notifier.enabled && config.notify.discordWebhook) print(`${CHECK} Discord webhook configured`);
  else {
    print(`${WARN} no Discord webhook; alerts will only appear in the log`);
    warnings += 1;
  }

  // 10. Policy summary - the part people misconfigure and never notice
  print('');
  print('  Policy in effect:');
  print(`    mode                  ${config.policy.mode}${config.policy.mode === PolicyMode.OBSERVE ? '  (will not touch any server)' : ''}`);
  print(`    risk threshold        ${config.policy.riskThreshold}`);
  print(`    suspend needs         ${config.policy.minConfidenceToSuspend} confidence, ${config.policy.consecutiveDetections} consecutive cycle(s)`);
  print(`    max actions / cycle   ${config.policy.maxActionsPerCycle}`);
  print(`    anomaly abort         above ${Math.round(config.policy.anomalyAbortRatio * 100)}% of the node tripping`);
  print(`    score half-life       ${config.policy.scoreHalfLifeHours}h`);

  return finishDoctor(failures, warnings);
}

function finishDoctor(failures, warnings) {
  print('');
  if (failures > 0) {
    print(`  ${failures} problem(s) must be fixed before X-Rae will run.\n`);
    return 1;
  }
  print(`  Ready.${warnings > 0 ? ` ${warnings} warning(s) - optional features are inactive.` : ''}\n`);
  return 0;
}

// ---------------------------------------------------------------------------
// xrae scan  /  xrae run
// ---------------------------------------------------------------------------

export async function commandScan({ configPath, dryRun, verbose, once }) {
  const { config } = loadConfig({ filePath: configPath });
  const logger = new ConsoleLogger({ level: verbose ? 'debug' : config.logLevel });

  const app = buildApplication({ config, dryRun, logger });

  logger.info(`X-Rae starting - mode=${config.policy.mode}${dryRun ? ' (dry run: no action possible)' : ''}`);
  if (process.getuid && process.getuid() === 0) {
    logger.warn('running as root, which is not required. See systemd/x-rae.service.');
  }

  await app.stateRepository.load();

  // A plain object rather than AbortController: the use case only needs to ask
  // "should I stop?", and a boolean is easier for a newcomer to follow.
  const cancellation = { aborted: false };
  const stop = (signalName) => {
    logger.info(`${signalName} received; finishing the current server then stopping`);
    cancellation.aborted = true;
  };
  process.on('SIGINT', () => stop('SIGINT'));
  process.on('SIGTERM', () => stop('SIGTERM'));

  do {
    try {
      await app.runScanCycle.execute(cancellation);
    } catch (error) {
      logger.error(`cycle failed: ${error.stack ?? error.message}`);
    }

    if (once || cancellation.aborted) break;
    await app.clock.sleep(config.scanner.intervalMinutes * 60_000, cancellation);
  } while (!cancellation.aborted);

  await app.stateRepository.save().catch((error) => logger.error(`final save failed: ${error.message}`));
  logger.info('stopped cleanly');
  return 0;
}

// ---------------------------------------------------------------------------
// xrae explain <identifier>
// ---------------------------------------------------------------------------

/**
 * Shows the stored evidence for one server.
 *
 * This exists because of a rule from the design doc: if we cannot explain to a
 * customer why they were actioned, we should not have actioned them.
 */
export async function commandExplain({ configPath, identifier }) {
  const { config } = loadConfig({ filePath: configPath });
  const app = buildApplication({ config, dryRun: true, logger: new ConsoleLogger({ level: 'error' }) });
  await app.stateRepository.load();

  const state = app.stateRepository.get(identifier);

  print(`\n  Server ${identifier}`);
  print('  ' + '─'.repeat(identifier.length + 7) + '\n');

  if (!state.updatedAtMs) {
    print('  No record. Either this server has never been scanned, or it was clean\n  and its record was never written.\n');
    return 0;
  }

  print(`  stored score        ${Math.round(state.score)} (threshold ${config.policy.riskThreshold})`);
  print(`  consecutive trips   ${state.detections}`);
  print(`  last action         ${state.lastAction ?? 'none'}`);
  print(`  last updated        ${new Date(state.updatedAtMs).toISOString()}`);
  print(`  CPU samples held    ${(state.cpuSamples ?? []).length}`);

  const hoursSince = (Date.now() - state.updatedAtMs) / 3_600_000;
  const decayed = state.score * 0.5 ** (hoursSince / config.policy.scoreHalfLifeHours);
  print(`  score after decay   ${Math.round(decayed)}  (${hoursSince.toFixed(1)}h elapsed)`);

  if ((state.reasons ?? []).length === 0) {
    print('\n  No evidence recorded.\n');
    return 0;
  }

  print('\n  Evidence:');
  for (const reason of state.reasons) {
    print(`    [${reason.family}] ${reason.ruleId}`);
    print(`        ${reason.detail}`);
  }
  print('');
  return 0;
}
