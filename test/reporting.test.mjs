// Covers the panel reporting adapter: the payload it puts on the wire, and the
// promise that a panel outage never costs protection.

import test from 'node:test';
import assert from 'node:assert/strict';

import { PanelReporter } from '../src/infrastructure/reporting/panel-reporter.js';
import { NullCycleReporter } from '../src/infrastructure/reporting/null-reporter.js';
import { CompositeNotifier } from '../src/infrastructure/notification/composite-notifier.js';
import { validatePanelConfig } from '../src/cli/commands.js';

class MemoryLogger {
  constructor() {
    this.lines = { error: [], warn: [], info: [], debug: [] };
  }
  error(...a) { this.lines.error.push(a.join(' ')); }
  warn(...a) { this.lines.warn.push(a.join(' ')); }
  info(...a) { this.lines.info.push(a.join(' ')); }
  debug(...a) { this.lines.debug.push(a.join(' ')); }
}

/** Records every call and replies with whatever the test queued. */
class FakeHttp {
  constructor(responses = {}) {
    this.calls = [];
    this.responses = responses;
  }
  async send(url, options) {
    this.calls.push({ url, options, body: options.body ? JSON.parse(options.body) : null });

    const key = Object.keys(this.responses).find((path) => url.endsWith(path));
    const reply = key ? this.responses[key] : { status: 200, data: { success: true, data: {} } };

    if (reply instanceof Error) throw reply;

    return reply;
  }
}

function makeEntry(overrides = {}) {
  return {
    server: {
      id: 1,
      identifier: 'a1b2c3d4',
      uuid: '8f14e45f-ceea-4a7a-9f6e-2b1c3d4e5f60',
      name: 'Minecraft Survival',
      nodeId: 4,
      cpuLimitPercent: 100,
    },
    verdict: {
      totalScore: 148.6,
      cycleScore: 62.2,
      confidence: 'critical',
      families: ['signature', 'network'],
      hasStandalone: true,
      detections: 3,
      reasons: [
        {
          ruleId: 'miner.stratum.tcp',
          family: 'network',
          category: 'MINER',
          weight: 60,
          confidence: 'critical',
          standalone: true,
          detail: 'stratum pool on :3333',
        },
      ],
    },
    decision: { level: 'suspend', reason: 'standalone critical rule' },
    action: { performed: 'suspend', success: true },
    ...overrides,
  };
}

function makeReport(entries = [makeEntry()]) {
  return {
    startedAtMs: 1_700_000_000_000,
    finishedAtMs: 1_700_000_004_210,
    scanned: 87,
    flagged: 2,
    actions: 1,
    riskThreshold: 100,
    entries,
  };
}

function buildReporter(responses) {
  const http = new FakeHttp(responses);
  const logger = new MemoryLogger();
  const reporter = new PanelReporter({
    baseUrl: 'https://xrae.raehost.com/',
    token: 'xrae_node_abc',
    http,
    logger,
    agentVersion: '1.0.0',
    appliedConfig: { hash: 'a'.repeat(64) },
  });

  return { reporter, http, logger };
}

test('the reporter posts findings then heartbeats', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport());

  assert.equal(http.calls.length, 2);
  assert.match(http.calls[0].url, /\/api\/agent\/reports$/);
  assert.match(http.calls[1].url, /\/api\/agent\/heartbeat$/);
  // Trailing slash on the base URL must not produce a double slash.
  assert.equal(http.calls[0].url, 'https://xrae.raehost.com/api/agent/reports');
});

test('both calls carry the node token and the protocol version', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport());

  for (const call of http.calls) {
    assert.equal(call.options.headers.Authorization, 'Bearer xrae_node_abc');
    assert.equal(call.options.headers['X-Xrae-Protocol'], '1');
    assert.equal(call.options.headers['X-Xrae-Agent'], '1.0.0');
  }
});

test('the report body never claims a node id', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport());

  // Identity comes from the token. A node id in the body would be a claim the
  // panel must then decide whether to trust.
  assert.equal('node_id' in http.calls[0].body, false);
  assert.equal('node_id' in http.calls[1].body, false);
});

test('one cycle id ties the report and the heartbeat together', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport());

  const [report, heartbeat] = http.calls;

  assert.equal(report.body.cycle_id, heartbeat.body.cycle.cycle_id);
  assert.match(report.body.cycle_id, /^[0-9a-f-]{36}$/);
});

test('scores are sent as integers', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport());

  const server = http.calls[0].body.servers[0];

  assert.equal(server.verdict.score, 149);
  assert.equal(server.verdict.cycle_score, 62);
  assert.equal(Number.isInteger(server.verdict.score), true);
});

test('over-long evidence is truncated, never dropped', async () => {
  const entry = makeEntry();

  entry.verdict.reasons[0].detail = 'x'.repeat(900);
  entry.verdict.reasons[0].ruleId = 'y'.repeat(150);

  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport([entry]));

  const reason = http.calls[0].body.servers[0].verdict.reasons[0];

  // The panel rejects the WHOLE batch on an over-long field, so one pathological
  // path would otherwise cost a full cycle of evidence.
  assert.equal(reason.detail.length, 500);
  assert.equal(reason.ruleId.length, 100);
});

test('a non-uuid server uuid becomes null rather than a 400', async () => {
  const entry = makeEntry();

  entry.server.uuid = 'not-a-uuid';

  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport([entry]));

  assert.equal(http.calls[0].body.servers[0].uuid, null);
});

test('a clean cycle heartbeats without posting a report', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport([]));

  assert.equal(http.calls.length, 1);
  assert.match(http.calls[0].url, /heartbeat$/);
  assert.equal(http.calls[0].body.cycle.scanned_count, 87);
});

test('the heartbeat echoes the applied config hash', async () => {
  const { reporter, http } = buildReporter();

  await reporter.reportCycle(makeReport([]));

  assert.equal(http.calls[0].body.config_hash, 'a'.repeat(64));
});

test('a failed report still heartbeats, so the node stays visible', async () => {
  const { reporter, http, logger } = buildReporter({
    '/api/agent/reports': new Error('connection reset'),
  });

  const commands = await reporter.reportCycle(makeReport());

  assert.equal(http.calls.length, 2);
  assert.equal(commands.length, 0);
  assert.equal(logger.lines.warn.some((line) => line.includes('report failed')), true);
});

test('reporting never throws, whatever the panel does', async () => {
  const { reporter } = buildReporter({
    '/api/agent/reports': new Error('boom'),
    '/api/agent/heartbeat': new Error('boom'),
  });

  // A panel outage must cost telemetry, never a scan.
  const commands = await reporter.reportCycle(makeReport());

  assert.deepEqual(commands, []);
});

test('a revoked token is reported as an operator problem, not a blip', async () => {
  const rejection = Object.assign(new Error('HTTP 401'), { status: 401 });
  const { reporter, logger } = buildReporter({ '/api/agent/heartbeat': rejection });

  await reporter.reportCycle(makeReport([]));

  const message = logger.lines.error.join(' ');

  assert.match(message, /revoked|invalid/i);
  assert.match(message, /continue/i);
});

test('commands come back from the heartbeat', async () => {
  const { reporter } = buildReporter({
    '/api/agent/heartbeat': {
      status: 200,
      data: {
        success: true,
        data: {
          desired_config_hash: 'b'.repeat(64),
          commands: [{ id: 55, type: 'rescan_now', payload: null }],
        },
      },
    },
  });

  const commands = await reporter.reportCycle(makeReport([]));

  assert.equal(commands.length, 1);
  assert.equal(commands[0].type, 'rescan_now');
});

test('a differing desired hash marks the config out of date', async () => {
  const { reporter } = buildReporter({
    '/api/agent/heartbeat': {
      status: 200,
      data: { success: true, data: { desired_config_hash: 'b'.repeat(64), commands: [] } },
    },
  });

  assert.equal(reporter.configOutOfDate, false);
  await reporter.reportCycle(makeReport([]));
  assert.equal(reporter.configOutOfDate, true);
});

test('a matching desired hash leaves the config alone', async () => {
  const { reporter } = buildReporter({
    '/api/agent/heartbeat': {
      status: 200,
      data: { success: true, data: { desired_config_hash: 'a'.repeat(64), commands: [] } },
    },
  });

  await reporter.reportCycle(makeReport([]));
  assert.equal(reporter.configOutOfDate, false);
});

test('a reporter without a token is disabled and silent', async () => {
  const http = new FakeHttp();
  const reporter = new PanelReporter({
    baseUrl: 'https://xrae.raehost.com',
    token: '',
    http,
    logger: new MemoryLogger(),
  });

  assert.equal(reporter.enabled, false);
  assert.deepEqual(await reporter.reportCycle(makeReport()), []);
  assert.equal(http.calls.length, 0);
});

test('the null reporter satisfies the port without doing anything', async () => {
  const reporter = new NullCycleReporter({ logger: new MemoryLogger() });

  assert.equal(reporter.enabled, false);
  assert.deepEqual(await reporter.reportCycle(makeReport()), []);
});

test('a composite notifier delivers even when one sink fails', async () => {
  const good = { enabled: true, sendAlert: async () => true, sendNotice: async () => true };
  const bad = {
    enabled: true,
    sendAlert: async () => { throw new Error('discord down'); },
    sendNotice: async () => { throw new Error('discord down'); },
  };
  const logger = new MemoryLogger();
  const composite = new CompositeNotifier({ notifiers: [bad, good], logger });

  assert.equal(await composite.sendAlert({}), true);
  assert.equal(logger.lines.warn.length, 1);
});

test('a composite with every sink failing reports failure', async () => {
  const bad = {
    enabled: true,
    sendAlert: async () => { throw new Error('down'); },
    sendNotice: async () => false,
  };
  const composite = new CompositeNotifier({ notifiers: [bad], logger: new MemoryLogger() });

  assert.equal(await composite.sendAlert({}), false);
  assert.equal(await composite.sendNotice({}), false);
});

test('pushed config is structurally validated before it is trusted', () => {
  assert.deepEqual(validatePanelConfig({ scanner: { intervalMinutes: 15 } }), []);

  assert.equal(validatePanelConfig(null).length, 1);
  assert.equal(validatePanelConfig({ scanner: { intervalMinutes: 0 } }).length, 1);
  assert.equal(validatePanelConfig({ policy: { riskThreshold: -5 } }).length, 1);
  assert.equal(validatePanelConfig({ policy: { mode: 'destroy' } }).length, 1);
  assert.equal(validatePanelConfig({ exclusions: { ruleIds: 'nope' } }).length, 1);
});
