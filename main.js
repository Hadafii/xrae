// LAYER: cli
// JOB:   Parse arguments and hand off to a command. Nothing else.

import { ConfigError } from '../config/config.js';
import { commandInit, commandDoctor, commandScan, commandExplain } from './commands.js';

export const VERSION = '1.0.0';
const DEFAULT_CONFIG_PATH = '/etc/x-rae/config.json';

const HELP = `
  X-Rae ${VERSION}   abuse detection for Pterodactyl nodes

  USAGE
    xrae <command> [options]

  COMMANDS
    init                 create a config file, interactively
    doctor               check the config, credentials and permissions
    scan                 run one cycle and exit
    run                  run continuously (this is what systemd uses)
    explain <id>         show the stored evidence for one server
    version              print the version

  OPTIONS
    -c, --config <path>  config file (default: ${DEFAULT_CONFIG_PATH})
        --dry-run        make action physically impossible; report intent only
    -v, --verbose        debug logging
    -h, --help           this text

  GETTING STARTED
    xrae init
    xrae doctor
    xrae scan --dry-run --verbose
    systemctl start x-rae

  SECRETS
    Credentials live in "xrae.env", NEXT TO your config.json. X-Rae finds and
    loads it automatically - systemd loads the same file via EnvironmentFile=,
    so a manual run and the running service see identical values.

      /etc/x-rae/config.json  ->  /etc/x-rae/xrae.env

    Keep it somewhere else with:  XRAE_ENV_FILE=/run/secrets/xrae.env
    A real environment variable always wins over the file.

    Recognised: XRAE_PANEL_URL, XRAE_PANEL_APP_KEY, XRAE_PANEL_CLIENT_KEY,
    XRAE_DISCORD_WEBHOOK, XRAE_VOLUMES_PATH, XRAE_NODE_ID, XRAE_MODE,
    XRAE_LOG_LEVEL, XRAE_STATE_PATH, XRAE_CONFIG, XRAE_ENV_FILE.
    See xrae.env.example for what each one does.
`;

function parseArguments(argv) {
  const options = {
    command: 'help',
    configPath: process.env.XRAE_CONFIG || DEFAULT_CONFIG_PATH,
    dryRun: false,
    verbose: false,
    positional: [],
  };

  const rest = [...argv];
  if (rest.length > 0 && !rest[0].startsWith('-')) options.command = rest.shift();

  while (rest.length > 0) {
    const argument = rest.shift();
    switch (argument) {
      case '-c':
      case '--config':
        options.configPath = rest.shift();
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '-v':
      case '--verbose':
        options.verbose = true;
        break;
      case '-h':
      case '--help':
        options.command = 'help';
        break;
      default:
        if (argument.startsWith('-')) {
          process.stderr.write(`Unknown option: ${argument}\nRun "xrae --help".\n`);
          process.exit(2);
        }
        options.positional.push(argument);
    }
  }

  return options;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);

  try {
    switch (options.command) {
      case 'init':
        return await commandInit(options);

      case 'doctor':
        return await commandDoctor(options);

      case 'scan':
        return await commandScan({ ...options, once: true });

      case 'run':
        return await commandScan({ ...options, once: false });

      case 'explain': {
        const identifier = options.positional[0];
        if (!identifier) {
          process.stderr.write('Usage: xrae explain <server-identifier>\n');
          return 2;
        }
        return await commandExplain({ ...options, identifier });
      }

      case 'version':
        process.stdout.write(`${VERSION}\n`);
        return 0;

      case 'help':
        process.stdout.write(HELP);
        return 0;

      default:
        process.stderr.write(`Unknown command: ${options.command}\nRun "xrae --help".\n`);
        return 2;
    }
  } catch (error) {
    // Configuration problems get a clean message; everything else gets a stack,
    // because an unexpected crash is a bug we want reported properly.
    if (error instanceof ConfigError) {
      process.stderr.write(`\n${error.message}\n`);
      return 2;
    }
    process.stderr.write(`\nUnexpected error: ${error.stack ?? error.message}\n`);
    return 1;
  }
}
