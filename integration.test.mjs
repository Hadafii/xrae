// Integration test.
//
// Runs a complete cycle with fake adapters in place of the panel, the
// filesystem and Discord. No network, no temp files, no waiting.
//
// This is the payoff of the port/adapter split: the use case under test is the
// real one, byte for byte the same code that runs in production, but every
// boundary is a five-line stub.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { RunScanCycle } from '../src/application/run-scan-cycle.js';
import { EvidenceCollectionService } from '../src/application/collect-evidence.js';
import { ScoreCalculator } from '../src/domain/scoring.js';
import { EnforcementPolicy, PolicyMode, ResponseLevel } from '../src/domain/policy.js';
import { createEvidence, EvidenceFamily } from '../src/domain/evidence.js';
import { Confidence } from '../src/domain/confidence.js';
import { FakeClock } from '../src/infrastructure/system/clock.js';
import { MemoryLogger } from '../src/infrastructure/system/logger.js';
import { JsonStateRepository } from '../src/infrastructure/persistence/json-state-repository.js';

// --- Fakes -----------------------------------------------------------------

function fakeServer(index) {
  return {
    id: index,
    identifier: `srv${index}`,
    uuid: `uuid-${index}`,
    name: `Server ${index}`,
    nodeId: 1,
    cpuLimitPercent: 100,
  };
}

class FakeServerRepository {
  constructor(count) {
    this.servers = Array.from({ length: count }, (_, i) => fakeServer(i + 1));
  }
  async listActive() {
    return this.servers;
  }
}

/** Returns whatever evidence the test tells it to, per server. */
class ScriptedCollector {
  name = 'scripted';
  constructor(evidenceByIdentifier) {
    this.evidenceByIdentifier = evidenceByIdentifier;
  }
  async collect(server) {
    return this.evidenceByIdentifier[server.identifier] ?? [];
  }
}

class BrokenCollector {
  name = 'broken';
  async collect() {
    throw new Error('this collector is deliberately broken');
  }
}

class RecordingNotifier {
  enabled = true;
  constructor() {
    this.alerts = [];
    this.notices = [];
  }
  async sendAlert(report) {
    this.alerts.push(report);
    return true;
  }
  async sendNotice(notice) {
    this.notices.push(notice);
    return true;
  }
}

class RecordingEnforcer {
  constructor({ failOn = [] } = {}) {
    this.suspended = [];
    this.throttled = [];
    this.failOn = failOn;
  }
  supports(level) {
    return level === ResponseLevel.SUSPEND || level === ResponseLevel.THROTTLE;
  }
  async suspend(server) {
    if (this.failOn.includes(server.identifier)) throw new Error('panel said no');
    this.suspended.push(server.identifier);
  }
  async throttle(server) {
    this.throttled.push(server.identifier);
  }
}

class InMemoryStateRepository extends JsonStateRepository {
  constructor(clock) {
    super({ filePath: '/dev/null', maxCacheEntries: 100, logger: new MemoryLogger(), clock });
  }
  async load() {}
  async save() {}
}

// --- Builder ---------------------------------------------------------------

function buildCycle({
  serverCount = 3,
  evidenceByIdentifier = {},
  mode = PolicyMode.ENFORCE,
  policyOverrides = {},
  enforcer = new RecordingEnforcer(),
  extraCollectors = [],
  dryRun = false,
} = {}) {
  const clock = new FakeClock();
  const logger = new MemoryLogger();
  const notifier = new RecordingNotifier();
  const stateRepository = new InMemoryStateRepository(clock);

  const policy = new EnforcementPolicy({
    mode,
    riskThreshold: 100,
    minConfidenceToAlert: Confidence.MEDIUM,
    minConfidenceToThrottle: Confidence.HIGH,
    minConfidenceToSuspend: Confidence.CRITICAL,
    consecutiveDetections: 1,
    maxActionsPerCycle: 3,
    anomalyAbortRatio: 0.25,
    renotifyCooldownMinutes: 0,
    ignoredServers: [],
    ...policyOverrides,
  });

  const cycle = new RunScanCycle({
    serverRepository: new FakeServerRepository(serverCount),
    evidenceService: new EvidenceCollectionService({
      collectors: [new ScriptedCollector(evidenceByIdentifier), ...extraCollectors],
      logger,
    }),
    scoreCalculator: new ScoreCalculator({ halfLifeHours: 24 }),
    policy,
    stateRepository,
    notifier,
    enforcer,
    clock,
    logger,
    settings: { riskThreshold: 100, delayBetweenServersMs: 0, throttleToCpuPercent: 25, dryRun },
  });

  return { cycle, notifier, enforcer, stateRepository, logger, clock };
}

const unambiguousMining = [
  createEvidence({
    ruleId: 'miner.stratum.tcp',
    family: EvidenceFamily.SIGNATURE,
    category: 'MINER',
    weight: 55,
    confidence: Confidence.CRITICAL,
    standalone: true,
    detail: 'stratum URL found',
  }),
  createEvidence({
    ruleId: 'behavior.cpu_pinned',
    family: EvidenceFamily.BEHAVIOR,
    category: 'MINER',
    weight: 28,
    confidence: Confidence.MEDIUM,
    standalone: false,
    detail: 'CPU pinned',
  }),
  createEvidence({
    ruleId: 'network.pool_port.14444',
    family: EvidenceFamily.NETWORK,
    category: 'MINER',
    weight: 25,
    confidence: Confidence.MEDIUM,
    standalone: false,
    detail: 'pool port',
  }),
];

// --- Tests -----------------------------------------------------------------

describe('a full scan cycle', () => {
  test('leaves a clean fleet alone', async () => {
    const { cycle, notifier, enforcer } = buildCycle();
    const summary = await cycle.execute();

    assert.equal(summary.assessed, 3);
    assert.equal(summary.overThreshold, 0);
    assert.equal(notifier.alerts.length, 0);
    assert.equal(enforcer.suspended.length, 0);
  });

  test('suspends one clearly guilty server and nobody else', async () => {
    const { cycle, notifier, enforcer } = buildCycle({
      evidenceByIdentifier: { srv2: unambiguousMining },
    });

    await cycle.execute();

    assert.deepEqual(enforcer.suspended, ['srv2']);
    assert.equal(notifier.alerts.length, 1);
    assert.equal(notifier.alerts[0].decision.level, ResponseLevel.SUSPEND);
  });

  test('observe mode reports but never acts', async () => {
    const { cycle, notifier, enforcer } = buildCycle({
      mode: PolicyMode.OBSERVE,
      evidenceByIdentifier: { srv1: unambiguousMining },
    });

    await cycle.execute();

    assert.equal(enforcer.suspended.length, 0);
    assert.equal(notifier.alerts[0].decision.level, ResponseLevel.OBSERVE);
  });

  test('dry run makes action physically impossible', async () => {
    const { cycle, notifier, enforcer } = buildCycle({
      dryRun: true,
      evidenceByIdentifier: { srv1: unambiguousMining },
    });

    await cycle.execute();

    assert.equal(enforcer.suspended.length, 0);
    assert.match(notifier.alerts[0].decision.reason, /dry run/);
  });

  test('a fleet-wide trip halts enforcement and warns the operator', async () => {
    // Eight of ten servers flagged: the detector is wrong, not the fleet.
    const evidenceByIdentifier = {};
    for (let i = 1; i <= 8; i += 1) evidenceByIdentifier[`srv${i}`] = unambiguousMining;

    const { cycle, notifier, enforcer } = buildCycle({ serverCount: 10, evidenceByIdentifier });
    await cycle.execute();

    assert.equal(enforcer.suspended.length, 0, 'nothing may be suspended during an anomaly');
    assert.equal(notifier.notices.length, 1, 'the operator must be told exactly once');
    assert.match(notifier.notices[0].title, /guardrail/i);
    assert.ok(notifier.alerts.every((alert) => alert.decision.level === ResponseLevel.BLOCKED));
  });

  test('the per-cycle action budget caps the damage a rule change can do', async () => {
    // Four guilty servers out of forty: below the anomaly ratio, so enforcement
    // runs - but the budget still stops at three.
    const evidenceByIdentifier = {};
    for (let i = 1; i <= 4; i += 1) evidenceByIdentifier[`srv${i}`] = unambiguousMining;

    const { cycle, enforcer } = buildCycle({
      serverCount: 40,
      evidenceByIdentifier,
      policyOverrides: { maxActionsPerCycle: 3 },
    });

    await cycle.execute();
    assert.equal(enforcer.suspended.length, 3);
  });

  test('a failed suspension downgrades to an alert instead of being silent', async () => {
    const { cycle, notifier, enforcer } = buildCycle({
      evidenceByIdentifier: { srv1: unambiguousMining },
      enforcer: new RecordingEnforcer({ failOn: ['srv1'] }),
    });

    await cycle.execute();

    assert.equal(enforcer.suspended.length, 0);
    assert.equal(notifier.alerts[0].decision.level, ResponseLevel.ALERT);
    assert.match(notifier.alerts[0].failureNote, /panel said no/);
  });

  test('one broken collector does not stop the others', async () => {
    const { cycle, enforcer, logger } = buildCycle({
      evidenceByIdentifier: { srv1: unambiguousMining },
      extraCollectors: [new BrokenCollector()],
    });

    await cycle.execute();

    assert.deepEqual(enforcer.suspended, ['srv1'], 'detection must survive a faulty evidence source');
    assert.ok(logger.lines.some((line) => line.message.includes('deliberately broken')));
  });

  test('persistence requirements delay action across cycles', async () => {
    const { cycle, enforcer } = buildCycle({
      // Two corroborating families, no unambiguous indicator: 45 points per
      // cycle, so it takes three cycles to pass a threshold of 100.
      evidenceByIdentifier: { srv1: [unambiguousMining[1], unambiguousMining[2]] },
      policyOverrides: { consecutiveDetections: 3, minConfidenceToSuspend: Confidence.MEDIUM },
    });

    await cycle.execute();
    assert.equal(enforcer.suspended.length, 0, 'one cycle is never enough');

    await cycle.execute();
    assert.equal(enforcer.suspended.length, 0, 'two cycles is still not enough');

    await cycle.execute();
    // By the third cycle the score has accumulated past the threshold AND the
    // persistence requirement is satisfied.
    assert.equal(enforcer.suspended.length, 1);
  });

  test('scores decay when the evidence goes away', async () => {
    const { cycle, stateRepository, clock } = buildCycle({
      evidenceByIdentifier: { srv1: [unambiguousMining[1]] },
      mode: PolicyMode.OBSERVE,
    });

    await cycle.execute();
    const afterFirst = stateRepository.get('srv1').score;
    assert.ok(afterFirst > 0);

    // Two days pass with nothing found. The score must fade, not persist.
    cycle.evidenceService.collectors[0].evidenceByIdentifier = {};
    clock.advanceHours(48);
    await cycle.execute();

    const afterDecay = stateRepository.get('srv1').score;
    assert.ok(afterDecay < afterFirst / 3, `expected decay, went from ${afterFirst} to ${afterDecay}`);
  });

  test('a cancelled cycle stops cleanly', async () => {
    const { cycle, notifier } = buildCycle({
      serverCount: 5,
      evidenceByIdentifier: { srv1: unambiguousMining },
    });

    await cycle.execute({ aborted: true });
    assert.equal(notifier.alerts.length, 0, 'an aborted cycle must not act on anything');
  });
});
