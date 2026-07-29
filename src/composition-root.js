// LAYER: composition root
// JOB:   Build every object and connect them. This is the ONLY file allowed to
//        decide which concrete class is used for which port.
//
// ============================================================================
// READ THIS FILE FIRST IF YOU ARE NEW TO THE PROJECT
// ============================================================================
// There is no dependency injection framework, no decorators and no magic.
// It is a function that news up objects in order, top to bottom. You can follow
// the whole system by reading it once.
//
// This is what makes the architecture pay off in practice:
//   - Want to send alerts to Slack instead of Discord? Write SlackNotifier,
//     change one line here.
//   - Want to add throttling? Write WingsEnforcer, change one line here.
//   - Want to add a new detection source? Write a collector, add it to the
//     collectors array here.
// In all three cases, nothing in src/domain/ or src/application/ changes.
// ============================================================================

import { ScoreCalculator } from './domain/scoring.js';
import { EnforcementPolicy, PolicyMode } from './domain/policy.js';

import { EvidenceCollectionService } from './application/collect-evidence.js';
import { RunScanCycle } from './application/run-scan-cycle.js';

import { ConsoleLogger } from './infrastructure/system/logger.js';
import { SystemClock } from './infrastructure/system/clock.js';
import { ContainerProcessResolver } from './infrastructure/system/container-resolver.js';
import { RetryPolicy, CircuitBreaker, ResilientHttpClient } from './infrastructure/http/resilient-http-client.js';
import {
  createPterodactylApi,
  PterodactylServerRepository,
  PterodactylMetricsProvider,
  PterodactylEnforcer,
  NoopEnforcer,
} from './infrastructure/panel/pterodactyl.js';
import { JsonStateRepository } from './infrastructure/persistence/json-state-repository.js';
import { SafeDirectoryWalker } from './infrastructure/filesystem/safe-walker.js';
import { FileContentAnalyzer } from './infrastructure/filesystem/file-analyzer.js';
import { FilesystemCollector } from './infrastructure/collectors/filesystem-collector.js';
import { CpuBehaviorCollector } from './infrastructure/collectors/cpu-collector.js';
import { NetworkCollector } from './infrastructure/collectors/connection-collector.js';
import { ProcessCommandCollector } from './infrastructure/collectors/process-collector.js';
import { ComponentsV2Builder } from './infrastructure/notification/components-v2-builder.js';
import { DiscordNotifier, ConsoleNotifier } from './infrastructure/notification/discord-notifier.js';
import { CompositeNotifier } from './infrastructure/notification/composite-notifier.js';
import { PanelReporter } from './infrastructure/reporting/panel-reporter.js';
import { NullCycleReporter } from './infrastructure/reporting/null-reporter.js';
import { AppliedConfigStore } from './infrastructure/reporting/applied-config-store.js';
import { VERSION as AGENT_VERSION } from './version.js';

/**
 * Panel-managed files sit beside state.json. That directory is the only path
 * the hardened systemd unit can write to: /etc is mounted read-only, so the
 * agent could not persist a pulled config there even as root.
 */
function appliedConfigPath(statePath) {
  return statePath.replace(/[^/\\]+$/, 'applied-config.json');
}

export function panelConfigPath(statePath) {
  return statePath.replace(/[^/\\]+$/, 'panel-config.json');
}

/**
 * @param {object} options
 * @param {object} options.config      a validated config object
 * @param {boolean} [options.dryRun]
 * @param {import('./application/ports.js').Logger} [options.logger]
 * @returns {object} everything the CLI needs
 */
export function buildApplication({ config, dryRun = false, logger }) {
  // ---- 1. Things everything else needs -----------------------------------
  const log = logger ?? new ConsoleLogger({ level: config.logLevel });
  const clock = new SystemClock();

  // ---- 2. Outbound HTTP, one client per remote service --------------------
  // Separate clients so a dead Discord webhook cannot open the circuit that
  // protects panel calls, and vice versa.
  const panelHttp = new ResilientHttpClient({
    retryPolicy: new RetryPolicy(config.panel.retry),
    circuitBreaker: new CircuitBreaker({ name: 'panel', ...config.panel.circuitBreaker, clock, logger: log }),
    logger: log,
    clock,
    timeoutMs: config.panel.timeoutMs,
  });

  const notifyHttp = new ResilientHttpClient({
    retryPolicy: new RetryPolicy(config.notify.retry),
    circuitBreaker: new CircuitBreaker({ name: 'discord', ...config.notify.circuitBreaker, clock, logger: log }),
    logger: log,
    clock,
    timeoutMs: config.notify.timeoutMs,
  });

  // ---- 3. Panel adapters (three narrow interfaces, one API client) --------
  const panelApi = createPterodactylApi(config, panelHttp);
  const serverRepository = new PterodactylServerRepository(panelApi, { nodeId: config.scanner.nodeId });
  const metrics = new PterodactylMetricsProvider(panelApi, { logger: log });

  // Dry run must be incapable of acting, not merely instructed not to.
  const enforcer = dryRun ? new NoopEnforcer({ logger: log }) : new PterodactylEnforcer(panelApi, { logger: log });

  // ---- 4. State ----------------------------------------------------------
  const stateRepository = new JsonStateRepository({
    filePath: config.state.path,
    maxCacheEntries: config.state.maxCacheEntries,
    logger: log,
    clock,
  });

  // ---- 5. Notification ---------------------------------------------------
  const notifier = config.notify.discordWebhook
    ? new DiscordNotifier({
        webhookUrl: config.notify.discordWebhook,
        builder: new ComponentsV2Builder({ panelBaseUrl: config.notify.panelBaseUrl, nodeId: config.scanner.nodeId }),
        http: notifyHttp,
        logger: log,
      })
    : new ConsoleNotifier({ logger: log });

  // ---- 5b. Reporting to the X-Rae panel ----------------------------------
  // Its OWN http client, so a dead panel opens its own breaker and cannot take
  // the Pterodactyl calls (server list, suspend) down with it.
  const reportingConfigured = Boolean(config.reporting?.url && config.reporting?.token);

  const reporter = reportingConfigured
    ? new PanelReporter({
        baseUrl: config.reporting.url,
        token: config.reporting.token,
        agentVersion: AGENT_VERSION,
        appliedConfig: new AppliedConfigStore({
          filePath: appliedConfigPath(config.state.path),
          logger: log,
        }).load(),
        http: new ResilientHttpClient({
          retryPolicy: new RetryPolicy(config.reporting.retry),
          circuitBreaker: new CircuitBreaker({
            name: 'xrae-panel',
            ...config.reporting.circuitBreaker,
            clock,
            logger: log,
          }),
          logger: log,
          clock,
          timeoutMs: config.reporting.timeoutMs,
        }),
        logger: log,
      })
    : new NullCycleReporter({ logger: log });

  // ---- 6. Evidence collectors -------------------------------------------
  // TO ADD A NEW DETECTION SOURCE: build it above, push it below. Done.
  const containerResolver = new ContainerProcessResolver({
    volumesPath: config.scanner.volumesPath,
    logger: log,
  });

  const collectors = [
    new FilesystemCollector({
      walker: new SafeDirectoryWalker({
        maxDepth: config.scanner.maxDepth,
        scanHidden: config.scanner.scanHidden,
        excludedRelativePaths: config.exclusions.relativePaths,
        logger: log,
      }),
      analyzer: new FileContentAnalyzer({
        settings: {
          maxFileBytes: config.scanner.maxFileBytes,
          entropyThreshold: config.detection.entropyThreshold,
          entropyMinFileBytes: config.detection.entropyMinFileBytes,
          excludedRuleIds: config.exclusions.ruleIds,
          excludedFileNames: config.exclusions.fileNames,
          excludedExtensions: config.exclusions.extensions,
          scanArchives: config.scanner.scanArchives,
        },
        logger: log,
      }),
      stateRepository,
      clock,
      logger: log,
      settings: {
        volumesPath: config.scanner.volumesPath,
        maxFilesPerServer: config.scanner.maxFilesPerServer,
        maxBytesPerServer: config.scanner.maxBytesPerServer,
        serverDeadlineMs: config.scanner.serverDeadlineMs,
      },
    }),
  ];

  if (config.scanner.collectCpu) {
    collectors.push(
      new CpuBehaviorCollector({
        metrics,
        stateRepository,
        logger: log,
        settings: {
          minSamples: config.detection.cpuMinSamples,
          sustainedPercent: config.detection.cpuSustainedPercent,
          maxStdDev: config.detection.cpuMaxStdDev,
        },
      }),
    );
  }

  if (config.scanner.collectConnections) {
    collectors.push(new NetworkCollector({ resolver: containerResolver, logger: log }));
    collectors.push(new ProcessCommandCollector({ resolver: containerResolver, logger: log }));
  }

  // ---- 7. Domain services (pure, no I/O) ---------------------------------
  const scoreCalculator = new ScoreCalculator({ halfLifeHours: config.policy.scoreHalfLifeHours });

  const policy = new EnforcementPolicy({
    mode: config.policy.mode,
    riskThreshold: config.policy.riskThreshold,
    minConfidenceToAlert: config.policy.minConfidenceToAlert,
    minConfidenceToThrottle: config.policy.minConfidenceToThrottle,
    minConfidenceToSuspend: config.policy.minConfidenceToSuspend,
    consecutiveDetections: config.policy.consecutiveDetections,
    maxActionsPerCycle: config.policy.maxActionsPerCycle,
    anomalyAbortRatio: config.policy.anomalyAbortRatio,
    renotifyCooldownMinutes: config.policy.renotifyCooldownMinutes,
    ignoredServers: config.policy.ignoredServers,
  });

  // ---- 8. The use case ---------------------------------------------------
  const runScanCycle = new RunScanCycle({
    serverRepository,
    evidenceService: new EvidenceCollectionService({ collectors, logger: log }),
    scoreCalculator,
    policy,
    stateRepository,
    notifier,
    reporter,
    enforcer,
    clock,
    logger: log,
    settings: {
      riskThreshold: config.policy.riskThreshold,
      delayBetweenServersMs: config.scanner.delayBetweenServersMs,
      throttleToCpuPercent: config.policy.throttleToCpuPercent,
      dryRun,
    },
  });

  return {
    config,
    logger: log,
    clock,
    runScanCycle,
    stateRepository,
    serverRepository,
    notifier,
    reporter,
    panelConfigPath: panelConfigPath(config.state.path),
    containerResolver,
    isReadOnlyMode: dryRun || config.policy.mode === PolicyMode.OBSERVE || config.policy.mode === PolicyMode.ALERT,
  };
}
