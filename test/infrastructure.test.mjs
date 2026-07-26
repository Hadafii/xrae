// Infrastructure tests.
//
// These touch the real filesystem and a fake fetch. They cover the properties
// that would actually hurt someone if they broke: hostile-input handling,
// retry behaviour, secret redaction, and the Discord payload contract.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { SafeDirectoryWalker, ScanBudget, resolveWithinRoot, BudgetExhausted } from '../src/infrastructure/filesystem/safe-walker.js';
import { FileContentAnalyzer, classifyFile, shannonEntropy } from '../src/infrastructure/filesystem/file-analyzer.js';
import { RetryPolicy, CircuitBreaker, ResilientHttpClient, HttpError } from '../src/infrastructure/http/resilient-http-client.js';
import { ComponentsV2Builder, IS_COMPONENTS_V2, sanitiseForDiscord } from '../src/infrastructure/notification/components-v2-builder.js';
import { DiscordNotifier } from '../src/infrastructure/notification/discord-notifier.js';
import { JsonStateRepository } from '../src/infrastructure/persistence/json-state-repository.js';
import { MemoryLogger, redactSecrets } from '../src/infrastructure/system/logger.js';
import { FakeClock } from '../src/infrastructure/system/clock.js';
import { ResponseLevel } from '../src/domain/policy.js';
import { Confidence } from '../src/domain/confidence.js';

const logger = new MemoryLogger();
const clock = new FakeClock();

let workspace;
let volumeRoot;
let serverDirectory;
let symlinksSupported = true;

before(async () => {
  workspace = await fsp.mkdtemp(path.join(os.tmpdir(), 'xrae-test-'));
  volumeRoot = path.join(workspace, 'volumes');
  serverDirectory = path.join(volumeRoot, '11111111-2222-3333-4444-555555555555');
  await fsp.mkdir(path.join(serverDirectory, 'plugins'), { recursive: true });

  await fsp.writeFile(path.join(serverDirectory, 'server.properties'), 'motd=hello\nmax-players=20\n');

  // The payload sits 200 KB into the file, well past the 16 KB head window the
  // old scanner used. If full-file scanning regresses, this test fails.
  const padding = Buffer.alloc(200_000, 0x41);
  await fsp.writeFile(
    path.join(serverDirectory, 'plugins', 'update.bin'),
    Buffer.concat([padding, Buffer.from('pool = stratum+tcp://xmr.example.org:14444\n'), padding]),
  );

  // Hostile inputs. Creating symlinks needs elevation on Windows; when that
  // fails the symlink-specific tests skip honestly instead of failing the
  // whole file. They still run on every Linux machine and in CI.
  try {
    await fsp.symlink('/etc', path.join(serverDirectory, 'escape-attempt'));
  } catch {
    symlinksSupported = false;
  }
  try {
    execFileSync('mkfifo', [path.join(serverDirectory, 'deadlock.fifo')]);
  } catch {
    /* mkfifo unavailable in this environment; the symlink case still runs */
  }
});

after(async () => {
  await fsp.rm(workspace, { recursive: true, force: true });
});

function makeBudget() {
  return new ScanBudget({ maxFiles: 5000, maxBytes: 1e9, deadlineMs: 30_000, clock: new FakeClock(Date.now()) });
}

function makeWalker() {
  return new SafeDirectoryWalker({ maxDepth: 8, scanHidden: true, excludedRelativePaths: [], logger });
}

function makeAnalyzer(overrides = {}) {
  return new FileContentAnalyzer({
    logger,
    settings: {
      maxFileBytes: 64 * 1024 * 1024,
      entropyThreshold: 7.6,
      entropyMinFileBytes: 65536,
      excludedRuleIds: [],
      excludedFileNames: [],
      excludedExtensions: [],
      scanArchives: false,
      ...overrides,
    },
  });
}

describe('safe directory walker', () => {
  test('never yields a symlink or a special file', async (t) => {
    if (!symlinksSupported) return t.skip('symlink creation needs elevation on this platform');
    const budget = makeBudget();
    const names = [];
    for await (const file of makeWalker().walk(serverDirectory, budget)) names.push(file.fileName);

    assert.ok(names.includes('server.properties'));
    assert.ok(names.includes('update.bin'));
    assert.ok(!names.includes('escape-attempt'), 'a symlink must never be handed onward');
    assert.ok(!names.includes('deadlock.fifo'), 'a FIFO must never be handed onward');
    assert.equal(budget.skipped.symlinks, 1);
  });

  test('refuses a scan root that resolves outside the volumes directory', (t) => {
    if (!symlinksSupported) return t.skip('symlink creation needs elevation on this platform');
    const outside = path.join(volumeRoot, 'points-elsewhere');
    fs.symlinkSync(os.tmpdir(), outside);

    assert.equal(resolveWithinRoot(volumeRoot, outside), null, 'escaping root must be rejected');
    assert.ok(resolveWithinRoot(volumeRoot, serverDirectory), 'a legitimate volume must be accepted');

    fs.unlinkSync(outside);
  });

  test('stops when the file budget runs out', async () => {
    const tinyBudget = new ScanBudget({ maxFiles: 0, maxBytes: 1e9, deadlineMs: 30_000, clock: new FakeClock(Date.now()) });
    await assert.rejects(async () => {
      for await (const file of makeWalker().walk(serverDirectory, tinyBudget)) {
        void file;
        tinyBudget.takeFile(); // the analyzer does this in production
      }
    }, BudgetExhausted);
  });
});

describe('file analyzer', () => {
  test('finds an indicator buried in the middle of a file', async () => {
    const found = await makeAnalyzer().analyze({
      absolutePath: path.join(serverDirectory, 'plugins', 'update.bin'),
      relativePath: 'plugins/update.bin',
      fileName: 'update.bin',
      budget: makeBudget(),
      cache: null,
    });

    const ruleIds = found.map((f) => f.ruleId);
    assert.ok(ruleIds.includes('miner.stratum.tcp'), `expected the stratum rule, got: ${ruleIds.join(', ')}`);
  });

  test('leaves an ordinary config file alone', async () => {
    const found = await makeAnalyzer().analyze({
      absolutePath: path.join(serverDirectory, 'server.properties'),
      relativePath: 'server.properties',
      fileName: 'server.properties',
      budget: makeBudget(),
      cache: null,
    });
    assert.equal(found.length, 0);
  });

  test('treats a file full of indicators as a reference list, not a threat', async () => {
    const listPath = path.join(serverDirectory, 'known-bad-strings.txt');
    await fsp.writeFile(
      listPath,
      ['xmrig', 'minerd', 'cpuminer', 'randomx', 'cryptonight', 'kawpow', 'etchash', 'nanopool.org', 'nicehash.com', 'coinhive'].join('\n'),
    );

    const found = await makeAnalyzer().analyze({
      absolutePath: listPath,
      relativePath: 'known-bad-strings.txt',
      fileName: 'known-bad-strings.txt',
      budget: makeBudget(),
      cache: null,
    });

    const totalWeight = found.reduce((sum, item) => sum + item.weight, 0);
    assert.ok(found.length >= 8, 'the rules should still match');
    assert.ok(totalWeight < 60, `flooded weight should be crushed, got ${totalWeight}`);
    assert.ok(found.every((item) => item.standalone === false), 'nothing in a reference list may stand alone');
  });

  test('the cache returns the same answer without re-reading', async () => {
    const store = new Map();
    const cache = { get: (key) => store.get(key) ?? null, set: (key, value) => store.set(key, value) };
    const target = {
      absolutePath: path.join(serverDirectory, 'plugins', 'update.bin'),
      relativePath: 'plugins/update.bin',
      fileName: 'update.bin',
      cache,
    };

    const first = await makeAnalyzer().analyze({ ...target, budget: makeBudget() });
    const secondBudget = makeBudget();
    const second = await makeAnalyzer().analyze({ ...target, budget: secondBudget });

    assert.deepEqual(first.map((f) => f.ruleId), second.map((f) => f.ruleId));
    assert.equal(secondBudget.filesUsed, 0, 'a cached file must not consume the read budget');
  });

  test('classifies files the way the weighting expects', () => {
    assert.equal(classifyFile('libthing.so').fileClass, 'executable');
    assert.equal(classifyFile('start.sh').fileClass, 'script');
    assert.equal(classifyFile('config.yml').fileClass, 'config');
    assert.equal(classifyFile('latest.log').fileClass, 'text');
    assert.equal(classifyFile('texture.png').fileClass, 'skip');
    assert.equal(classifyFile('world.zip').fileClass, 'archive');
  });

  test('entropy behaves as expected at the extremes', () => {
    assert.equal(shannonEntropy(Buffer.alloc(1000, 0x41)), 0);
    assert.ok(shannonEntropy(Buffer.from(Array.from({ length: 4096 }, (_, i) => i % 256))) > 7.9);
  });
});

describe('resilient http client', () => {
  function build({ responses, maxAttempts = 3 }) {
    let callCount = 0;
    const client = new ResilientHttpClient({
      retryPolicy: new RetryPolicy({ maxAttempts, baseDelayMs: 1, maxDelayMs: 2, maxRetryAfterMs: 1000, random: () => 0 }),
      circuitBreaker: new CircuitBreaker({ name: 'test', failureThreshold: 2, cooldownMs: 1000, clock, logger }),
      logger,
      clock,
      timeoutMs: 1000,
      fetchImpl: async () => {
        const next = responses[Math.min(callCount, responses.length - 1)];
        callCount += 1;
        return next();
      },
    });
    return { client, callCount: () => callCount };
  }

  const ok = (body = '{}') => () => new Response(body, { status: 200 });
  const status = (code, headers = {}) => () => new Response('boom', { status: code, headers });

  test('retries a 503 and then succeeds', async () => {
    const { client, callCount } = build({ responses: [status(503), ok('{"ok":true}')] });
    const result = await client.send('https://example.test/a', { label: 'test' });
    assert.equal(result.data.ok, true);
    assert.equal(callCount(), 2);
  });

  test('does not retry a 403, because that is a config error not a blip', async () => {
    const { client, callCount } = build({ responses: [status(403)] });
    await assert.rejects(() => client.send('https://example.test/b', { label: 'test' }), HttpError);
    assert.equal(callCount(), 1, 'a 403 must be reported immediately, not retried');
  });

  test('honours Retry-After on a 429', async () => {
    const policy = new RetryPolicy({ maxAttempts: 2, baseDelayMs: 1000, maxDelayMs: 5000, maxRetryAfterMs: 60000 });
    assert.equal(policy.delayFromRetryAfter('3'), 3000);
    assert.equal(policy.delayFromRetryAfter('999999'), 60000, 'an absurd value must be capped');
    assert.equal(policy.delayFromRetryAfter(null), null);
  });

  test('the circuit opens after repeated failures and fails fast', async () => {
    const { client } = build({ responses: [status(500)], maxAttempts: 1 });
    await assert.rejects(() => client.send('https://example.test/c', { label: 'one' }));
    await assert.rejects(() => client.send('https://example.test/c', { label: 'two' }));
    await assert.rejects(
      () => client.send('https://example.test/c', { label: 'three' }),
      /circuit breaker is open/,
    );
  });

  test('backoff uses full jitter so nodes do not retry in lockstep', () => {
    const policy = new RetryPolicy({ maxAttempts: 5, baseDelayMs: 100, maxDelayMs: 10000, maxRetryAfterMs: 1000, random: () => 0.5 });
    assert.equal(policy.delayFor(0), 50);
    assert.equal(policy.delayFor(1), 100);
    assert.equal(policy.delayFor(2), 200);
  });
});

describe('discord components v2', () => {
  const report = {
    server: { id: 7, identifier: 'ab12cd34', uuid: 'u', name: '@everyone `**pwn**`', nodeId: 3, cpuLimitPercent: 100 },
    verdict: {
      totalScore: 142, cycleScore: 142, confidence: Confidence.CRITICAL, families: ['signature', 'network'],
      hasStandalone: true, detections: 2,
      reasons: [{ ruleId: 'miner.stratum.tcp', family: 'signature', detail: 'matched in plugins/update.bin' }],
    },
    decision: { level: ResponseLevel.SUSPEND, reason: 'unambiguous mining indicator' },
    riskThreshold: 100,
  };

  const builder = new ComponentsV2Builder({ panelBaseUrl: 'https://panel.example.com' });

  test('sets the flag and omits the forbidden fields', () => {
    const payload = builder.buildAlert(report);
    assert.equal(payload.flags, IS_COMPONENTS_V2);
    assert.equal(payload.flags, 32768);
    assert.equal(payload.content, undefined, 'content is forbidden once the V2 flag is set');
    assert.equal(payload.embeds, undefined, 'embeds are forbidden once the V2 flag is set');
    assert.equal(payload.components[0].type, 17, 'the top level must be a Container');
  });

  test('neutralises a hostile server name', () => {
    const serialised = JSON.stringify(builder.buildAlert(report));
    assert.ok(!serialised.includes('@everyone'), 'a tenant must not be able to ping the staff channel');
    assert.deepEqual(builder.buildAlert(report).allowed_mentions, { parse: [] });
    assert.equal(sanitiseForDiscord('a`b*c_d~e|f'), 'abcdef');
  });

  test('uses a link button, the only kind a webhook can send', () => {
    const container = builder.buildAlert(report).components[0];
    const section = container.components.find((component) => component.type === 9);
    assert.equal(section.accessory.style, 5);
    assert.ok(section.accessory.url.startsWith('https://panel.example.com/server/ab12cd34'));
  });

  test('always explains the outcome', () => {
    const serialised = JSON.stringify(builder.buildAlert(report));
    assert.ok(serialised.includes('Why this outcome'));
    assert.ok(serialised.includes('unambiguous mining indicator'));
  });

  test('falls back to an embed when Discord rejects components', async () => {
    const sent = [];
    let firstCall = true;

    const notifier = new DiscordNotifier({
      webhookUrl: 'https://discord.com/api/webhooks/1/token',
      builder,
      logger,
      http: {
        send: async (_url, options) => {
          sent.push(JSON.parse(options.body));
          if (firstCall) {
            firstCall = false;
            throw new HttpError('rejected', { status: 400, body: 'invalid components' });
          }
          return { status: 204, data: null, raw: '' };
        },
      },
    });

    assert.equal(await notifier.sendAlert(report), true);
    assert.equal(sent.length, 2);
    assert.equal(sent[0].flags, 32768, 'the first attempt uses V2');
    assert.ok(sent[1].embeds, 'the retry falls back to a classic embed');
    assert.equal(notifier.componentsV2Works, false, 'the downgrade is remembered');
  });

  test('adds with_components=true to the webhook url', async () => {
    let capturedUrl = '';
    const notifier = new DiscordNotifier({
      webhookUrl: 'https://discord.com/api/webhooks/1/token',
      builder,
      logger,
      http: { send: async (url) => { capturedUrl = url; return { status: 204, data: null, raw: '' }; } },
    });
    await notifier.sendAlert(report);
    assert.ok(capturedUrl.includes('with_components=true'), 'without this, Discord ignores the components');
  });
});

describe('secret redaction', () => {
  test('strips panel keys and webhook urls', () => {
    assert.ok(!redactSecrets('key is ptla_AbCdEf123456').includes('AbCdEf123456'));
    assert.ok(!redactSecrets('key is ptlc_XyZ987654').includes('XyZ987654'));
    assert.ok(!redactSecrets('Authorization: Bearer sk-abcdef123456').includes('sk-abcdef123456'));
    assert.ok(
      !redactSecrets('hook https://discord.com/api/webhooks/123456789/AbCdEfGhIj-KlMnOp').includes('AbCdEfGhIj'),
    );
  });
});

describe('state repository', () => {
  test('merges instead of overwriting, so collectors keep their own fields', async () => {
    const filePath = path.join(workspace, 'state.json');
    const repository = new JsonStateRepository({ filePath, maxCacheEntries: 10, logger, clock });
    await repository.load();

    repository.set('abc123', { cpuSamples: [90, 91, 92] });
    repository.set('abc123', { score: 55, detections: 1 });

    const state = repository.get('abc123');
    assert.deepEqual(state.cpuSamples, [90, 91, 92], 'the CPU collector owns this field and must keep it');
    assert.equal(state.score, 55);
  });

  test('survives a round trip through disk', async () => {
    const filePath = path.join(workspace, 'state-roundtrip.json');
    const first = new JsonStateRepository({ filePath, maxCacheEntries: 10, logger, clock });
    await first.load();
    first.set('abc123', { score: 42, detections: 2 });
    await first.save();

    const second = new JsonStateRepository({ filePath, maxCacheEntries: 10, logger, clock });
    await second.load();
    assert.equal(second.get('abc123').score, 42);

    if (process.platform !== 'win32') {
      const mode = fs.statSync(filePath).mode & 0o777;
      assert.equal(mode & 0o077, 0, 'the state file must not be readable by other users');
    }
  });

  test('forgets servers that no longer exist', async () => {
    const repository = new JsonStateRepository({ filePath: path.join(workspace, 's2.json'), maxCacheEntries: 10, logger, clock });
    await repository.load();
    repository.set('keep', { score: 1 });
    repository.set('drop', { score: 1 });
    repository.forgetMissing(['keep']);

    assert.equal(repository.get('keep').score, 1);
    assert.equal(repository.get('drop').score, 0);
  });
});

describe('credentials: env file versus config.json', () => {
  test('parses the boring subset and nothing more', async () => {
    const { parseEnvFile } = await import('../src/config/env-file.js');

    const parsed = parseEnvFile(`
# a comment
XRAE_PANEL_APP_KEY=ptla_plain
export XRAE_PANEL_CLIENT_KEY="ptlc_quoted"
XRAE_DISCORD_WEBHOOK='https://discord.com/api/webhooks/1/tok'
XRAE_MODE=observe   # trailing comment
NOT VALID=ignored
BLANK=
`);

    assert.equal(parsed.XRAE_PANEL_APP_KEY, 'ptla_plain');
    assert.equal(parsed.XRAE_PANEL_CLIENT_KEY, 'ptlc_quoted');
    assert.equal(parsed.XRAE_DISCORD_WEBHOOK, 'https://discord.com/api/webhooks/1/tok');
    assert.equal(parsed.XRAE_MODE, 'observe', 'a trailing comment must be stripped');
    assert.equal(parsed.BLANK, '');
    assert.equal('NOT VALID' in parsed, false);
  });

  test('keeps a hash that is part of the value', async () => {
    const { parseEnvFile } = await import('../src/config/env-file.js');
    assert.equal(parseEnvFile('KEY=abc#def').KEY, 'abc#def', 'a # with no space before it is data, not a comment');
  });

  test('the real environment always wins over the file', async () => {
    const { loadEnvFileInto } = await import('../src/config/env-file.js');
    const envFile = path.join(workspace, 'creds.env');
    await fsp.writeFile(envFile, 'XRAE_PANEL_APP_KEY=from_file\nXRAE_DISCORD_WEBHOOK=from_file\n', { mode: 0o600 });

    const fakeEnvironment = { XRAE_PANEL_APP_KEY: 'from_real_env' };
    const result = loadEnvFileInto(envFile, fakeEnvironment);

    assert.equal(fakeEnvironment.XRAE_PANEL_APP_KEY, 'from_real_env', 'systemd and the shell must not be overridden');
    assert.equal(fakeEnvironment.XRAE_DISCORD_WEBHOOK, 'from_file');
    assert.deepEqual(result.alreadySet, ['XRAE_PANEL_APP_KEY']);
    assert.deepEqual(result.applied, ['XRAE_DISCORD_WEBHOOK']);
  });

  test('the env file must not be readable by other users', async (t) => {
    if (process.platform === 'win32') return t.skip('POSIX mode bits do not exist on Windows; the check is active on Linux only');
    const { checkFilePermissions } = await import('../src/config/config.js');
    const loose = path.join(workspace, 'loose.env');
    await fsp.writeFile(loose, 'XRAE_PANEL_APP_KEY=x\n', { mode: 0o644 });

    assert.match(checkFilePermissions(loose) ?? '', /must not be\s+readable by other users|chmod 600/);
    await fsp.chmod(loose, 0o600);
    assert.equal(checkFilePermissions(loose), null);
  });

  test('the env file is looked for next to config.json', async () => {
    const { resolveEnvFilePath } = await import('../src/config/config.js');
    assert.equal(
      resolveEnvFilePath({ configFilePath: '/etc/x-rae/config.json' }),
      path.resolve('/etc/x-rae/xrae.env'),
      'convention over configuration: predictable beats flexible when a node is on fire',
    );
    assert.equal(resolveEnvFilePath({ explicitEnvFilePath: '/run/secrets/x.env' }), path.resolve('/run/secrets/x.env'));
  });
});
