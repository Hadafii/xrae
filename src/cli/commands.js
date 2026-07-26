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

import { loadConfig, DEFAULT_CONFIG, checkFilePermissions, resolveEnvFilePath, ConfigError } from '../config/config.js';
import { buildApplication } from '../composition-root.js';
import { ConsoleLogger } from '../infrastructure/system/logger.js';
import { PolicyMode } from '../domain/policy.js';
import { RULE_PACK, REGEX_RULES, validateRulePack } from '../domain/rules.js';

const CHECK = '  \x1b[32m✓\x1b[0m';
const CROSS = '  \x1b[31m✗\x1b[0m';
const WARN = '  \x1b[33m!\x1b[0m';

/** Must match SERVICE_USER in install.sh and User= in the systemd unit. */
const SERVICE_GROUP = 'xrae';

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
  const resolvedConfig = path.resolve(configPath);
  const resolvedEnv = resolveEnvFilePath({ configFilePath: resolvedConfig });

  if (fs.existsSync(resolvedConfig)) {
    print(`\nA config already exists at ${resolvedConfig}`);
    print('Nothing was changed. Delete it first if you want to start over.\n');
    return 1;
  }

  print('\n  X-Rae setup');
  print('  ───────────');
  print('  Six questions. Everything else gets a safe default.');
  print('');
  print('  Two files get written:');
  print(`    ${resolvedConfig}   settings   (mode 0644, safe to share)`);
  print(`    ${resolvedEnv}      credentials (mode 0600, never share)`);
  print('');
  print('  Keeping them apart matters: you can paste config.json into a support');
  print('  thread without leaking a key that controls your whole panel.\n');

  const rl = readline.createInterface({ input: stdin, output: stdout });

  try {
    const panelUrl = await ask(rl, 'Panel URL', 'https://panel.example.com');
    const nodeId = await ask(rl, 'Node ID to scan (0 = all nodes this key can see)', '0');
    const volumesPath = await ask(rl, 'Volumes path', DEFAULT_CONFIG.scanner.volumesPath);

    print('\n  Now the credentials. These go in xrae.env, not config.json.');
    print('  Leave any of them blank and fill it in later.\n');

    const applicationKey = await ask(rl, 'Application API key (ptla_...)', '');
    const clientKey = await ask(rl, 'Client API key (ptlc_..., optional, enables CPU checks)', '');
    const webhook = await ask(rl, 'Discord webhook URL (optional)', '');

    fs.mkdirSync(path.dirname(resolvedConfig), { recursive: true });

    fs.writeFileSync(
      resolvedConfig,
      renderConfigFile({
        panelUrl: panelUrl.replace(/\/+$/, ''),
        nodeId: Number(nodeId) || 0,
        volumesPath,
        envFilePath: resolvedEnv,
      }),
      { mode: 0o644 },
    );

    // Never clobber an existing credentials file - it may already hold keys
    // that the operator does not have another copy of.
    let envWritten = false;
    let envMode = '0600';
    if (fs.existsSync(resolvedEnv)) {
      print(`\n${WARN} ${resolvedEnv} already exists and was left untouched.`);
    } else {
      fs.writeFileSync(resolvedEnv, renderEnvFile({ applicationKey, clientKey, webhook }), { mode: 0o600 });
      envMode = grantServiceGroupRead(resolvedEnv);
      envWritten = true;
    }

    print(`\n${CHECK} wrote ${resolvedConfig} (mode 0644, no secrets in it)`);
    if (envWritten) print(`${CHECK} wrote ${resolvedEnv} (mode ${envMode})`);
    print('');
    print('  Next:');
    print(`    xrae doctor --config ${resolvedConfig}          check everything works`);
    print(`    xrae scan --config ${resolvedConfig} --dry-run  see what it would do`);
    print('');
    print('  The config starts in "observe" mode. It will not touch any server.');
    print('  Leave it there for a couple of weeks before enabling enforcement.\n');
    return 0;
  } finally {
    rl.close();
  }
}

/**
 * Hand a secrets file to the service group so the unprivileged agent can READ it
 * while only root can WRITE it.
 *
 * Why bother: `xrae init` is run with sudo, so the file lands as root:root 0600.
 * The service then runs as the "xrae" user and cannot open it - the unit starts
 * and immediately fails to authenticate, which is a miserable thing to debug.
 * root:xrae 0640 fixes that without making the agent the owner of its own
 * credentials.
 *
 * @param {string} filePath
 * @param {string} [groupName]
 * @returns {string} the mode actually applied, for printing
 */
function grantServiceGroupRead(filePath, groupName = SERVICE_GROUP) {
  const runningAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  if (!runningAsRoot) return '0600';

  const gid = lookupGroupId(groupName);
  if (gid === null) {
    // The group does not exist yet, e.g. init was run before install.sh.
    // 0600 is the safe answer; doctor will tell them what to do next.
    return '0600';
  }

  try {
    fs.chownSync(filePath, 0, gid);
    fs.chmodSync(filePath, 0o640);
    return `0640 root:${groupName}`;
  } catch {
    return '0600';
  }
}

/**
 * Look up a gid by name. Node has no getgrnam, and X-Rae has no dependencies,
 * so read /etc/group directly. Returns null if the group is absent.
 */
function lookupGroupId(groupName) {
  try {
    for (const line of fs.readFileSync('/etc/group', 'utf8').split('\n')) {
      const [name, , gid] = line.split(':');
      if (name === groupName && gid) return Number(gid);
    }
  } catch {
    /* not a Linux-like system, or /etc/group unreadable */
  }
  return null;
}

async function ask(rl, question, defaultValue) {
  const suffix = defaultValue ? ` [${defaultValue}]` : '';
  const answer = (await rl.question(`  ${question}${suffix}: `)).trim();
  return answer || defaultValue;
}

function renderConfigFile({ panelUrl, nodeId, volumesPath, envFilePath }) {
  return `// X-Rae settings.
//
// Comments are allowed in this file. Anything not listed here uses its default -
// run "xrae doctor" to see the values actually in effect.
//
// CREDENTIALS DO NOT BELONG IN THIS FILE.
// They live in ${envFilePath}, which X-Rae loads automatically because it sits
// next to this file. Precedence, highest first:
//     real environment  ->  ${path.basename(envFilePath)}  ->  this file  ->  defaults
//
// You CAN put keys here (panel.applicationKey and so on) and it will work, but
// then this file is a secret too, and X-Rae will refuse to start unless it is
// mode 0600.
{
  "panel": {
    "url": ${JSON.stringify(panelUrl)}
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

function renderEnvFile({ applicationKey, clientKey, webhook }) {
  const line = (variable, value, note) =>
    `${note}\n${value ? '' : '# '}${variable}=${value}\n`;

  return `# X-Rae credentials.
#
# MODE 0600. Never commit this, never paste it into a support thread.
# X-Rae loads this file automatically because it sits next to config.json.
# systemd also loads it via EnvironmentFile=, so both paths behave the same.
#
# A value already exported in the real environment overrides anything here.

${line('XRAE_PANEL_APP_KEY', applicationKey, '# Application API key. Full panel admin - treat it like a root password.')}
${line('XRAE_PANEL_CLIENT_KEY', clientKey, '# Client API key. Optional. Only needed for CPU behaviour evidence.')}
${line('XRAE_DISCORD_WEBHOOK', webhook, '# Discord webhook. Required before enabling throttle or enforce mode.')}
# Other variables X-Rae understands, if you prefer them over config.json:
# XRAE_PANEL_URL=https://panel.example.com
# XRAE_VOLUMES_PATH=/var/lib/pterodactyl/volumes
# XRAE_NODE_ID=1
# XRAE_MODE=observe
# XRAE_LOG_LEVEL=info
# XRAE_STATE_PATH=/var/lib/x-rae/state.json
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

  print(`${CHECK} config file found (${resolved})`);

  let config;
  let sources = {};
  let configWarnings = [];
  let envFilePath = null;
  let envFileLoaded = false;
  try {
    ({ config, sources, warnings: configWarnings, envFilePath, envFileLoaded } = loadConfig({ filePath: resolved }));
    print(`${CHECK} config is valid`);
  } catch (error) {
    if (error instanceof ConfigError) {
      print(`${CROSS} ${error.message.split('\n').join('\n      ')}`);
      return finishDoctor(failures + 1, warnings);
    }
    throw error;
  }

  // 4. Credentials: where did they actually come from?
  if (envFileLoaded) {
    print(`${CHECK} credentials file loaded (${envFilePath})`);
  } else if (envFilePath && !fs.existsSync(envFilePath)) {
    print(`${WARN} no credentials file at ${envFilePath}`);
    print('      that is fine if your keys come from systemd or your shell');
    warnings += 1;
  }

  print('');
  print('  Credential sources:');
  for (const [label, source] of Object.entries(sources)) {
    const marker = source === 'not set' ? WARN : CHECK;
    print(`${marker} ${label.padEnd(22)} ${source}`);
  }
  print('');

  // A credential defined in two places is how a rotated key silently fails to
  // take effect. This is a hard failure, not a note.
  for (const warning of configWarnings) {
    print(`${CROSS} ${warning}`);
    failures += 1;
  }

  // 5. Privilege check
  if (process.getuid && process.getuid() === 0) {
    print(`${WARN} running as root. X-Rae does not need it - see systemd/x-rae.service`);
    warnings += 1;
  } else {
    print(`${CHECK} not running as root`);
  }

  // 6. Volumes directory
  try {
    const entries = fs.readdirSync(config.scanner.volumesPath);
    print(`${CHECK} volumes directory readable (${entries.length} entries)`);
  } catch (error) {
    if (error.code === 'EACCES' || error.code === 'EPERM') {
      print(`${WARN} cannot read ${config.scanner.volumesPath} from this shell (${error.code})`);
      print('      expected on a locked-down node: a manual shell has no capabilities, while');
      print('      the systemd unit grants CAP_DAC_READ_SEARCH so the running service can read it.');
      print('      verify with: systemctl start x-rae && journalctl -u x-rae -f');
      warnings += 1;
    } else {
      print(`${CROSS} cannot read ${config.scanner.volumesPath}: ${error.code}`);
      print('      fix: check the path in config.json against system.data in /etc/pterodactyl/config.yml');
      failures += 1;
    }
  }

  // 7. State directory
  try {
    fs.mkdirSync(path.dirname(config.state.path), { recursive: true });
    fs.accessSync(path.dirname(config.state.path), fs.constants.W_OK);
    print(`${CHECK} state directory writable (${path.dirname(config.state.path)})`);
  } catch (error) {
    print(`${CROSS} cannot write to ${path.dirname(config.state.path)}: ${error.code}`);
    failures += 1;
  }

  const app = buildApplication({ config, dryRun: true, logger: new ConsoleLogger({ level: 'error' }) });

  // 8. Panel connectivity
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

  // 9. Optional capabilities
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

  // 10. Notification
  if (app.notifier.enabled && config.notify.discordWebhook) print(`${CHECK} Discord webhook configured`);
  else {
    print(`${WARN} no Discord webhook; alerts will only appear in the log`);
    warnings += 1;
  }

  // 11. Policy summary - the part people misconfigure and never notice
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
  const { config, warnings } = loadConfig({ filePath: configPath });
  const logger = new ConsoleLogger({ level: verbose ? 'debug' : config.logLevel });

  // A credential set in two places must never be discovered by surprise later.
  for (const warning of warnings) logger.warn(warning);

  const app = buildApplication({ config, dryRun, logger });

  logger.info(`X-Rae starting - mode=${config.policy.mode}${dryRun ? ' (dry run: no action possible)' : ''}`);
  if (process.getuid && process.getuid() === 0) {
    logger.warn('running as root, which is not required. See systemd/x-rae.service.');
  }

  await app.stateRepository.load();

  // Continuous mode announces itself once. The predecessor died silently on
  // reboot for weeks before anyone noticed; a startup notice makes presence -
  // and absence - visible in the same channel the alerts arrive in.
  if (!once) {
    const nodeLabel = config.scanner.nodeId === 0 ? 'all nodes this key can see' : `node ${config.scanner.nodeId}`;
    await app.notifier.sendNotice({
      level: 'info',
      title: `X-Rae active on ${nodeLabel}`,
      body:
        `Mode \`${config.policy.mode}\`${dryRun ? ' (dry run: no action possible)' : ''} · ` +
        `scanning every ${config.scanner.intervalMinutes} min · ` +
        `threshold ${config.policy.riskThreshold}`,
    });
  }

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

// ---------------------------------------------------------------------------
// xrae notify-test
// ---------------------------------------------------------------------------

/**
 * Sends one test notice through the real notifier. Exists so an operator can
 * prove the webhook works BEFORE trusting it to carry a real alert - a webhook
 * that was deleted on the Discord side fails silently until the day it matters.
 */
export async function commandNotifyTest({ configPath, verbose }) {
  const { config, warnings } = loadConfig({ filePath: configPath });
  const logger = new ConsoleLogger({ level: verbose ? 'debug' : 'warn' });
  for (const warning of warnings) logger.warn(warning);

  if (!config.notify.discordWebhook) {
    print(`\n${CROSS} no Discord webhook configured`);
    print('      fix: set XRAE_DISCORD_WEBHOOK in xrae.env, then run this again\n');
    return 1;
  }

  const app = buildApplication({ config, dryRun: true, logger });

  print('\n  Sending a test notice to Discord...');
  const delivered = await app.notifier.sendNotice({
    title: 'Webhook test',
    body:
      'If you can read this, X-Rae can reach a human when it matters.\n\n' +
      `Sent by \`xrae notify-test\` · mode \`${config.policy.mode}\` · node ` +
      `${config.scanner.nodeId === 0 ? 'all visible' : config.scanner.nodeId}`,
    level: 'info',
  });

  if (delivered) {
    print(`${CHECK} delivered - check the channel\n`);
    return 0;
  }

  print(`${CROSS} delivery failed (the log line above has the HTTP reason)`);
  print('      common causes: webhook deleted on the Discord side, a typo in the');
  print('      URL, or Discord returning 429 during an incident\n');
  return 1;
}
