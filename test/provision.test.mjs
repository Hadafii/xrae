import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  readWingsConfig,
  mergeEnvFile,
  isPlaceholder,
  resolveNodeId,
  verifyPanel,
} from '../src/cli/provision.js';

// A realistic Wings config.yml, including the parts we do not care about, so the
// reader is proven to skip them rather than proven to work on a toy input.
const WINGS_YAML = `debug: false
uuid: 8f14e45f-ceea-467a-9f6e-2b1c3d4e5f60
token_id: aBcDeFgH
token: someverylongwingstoken
api:
  host: 0.0.0.0
  port: 8080
  ssl:
    enabled: true
system:
  root_directory: /var/lib/pterodactyl
  username: pterodactyl
  data: /var/lib/pterodactyl/volumes
  sftp:
    bind_port: 2022
allowed_mounts: []
remote: 'https://panel.raehost.com'
`;

test('reads the three scalars the installer needs from Wings config', () => {
  const parsed = readWingsConfig(WINGS_YAML);

  assert.equal(parsed.uuid, '8f14e45f-ceea-467a-9f6e-2b1c3d4e5f60');
  assert.equal(parsed.remote, 'https://panel.raehost.com');
  assert.equal(parsed.volumesPath, '/var/lib/pterodactyl/volumes');
});

test('does not confuse a nested key with the top-level one it shares a name with', () => {
  // `system.sftp` has its own nested keys; a naive line scan picks up the wrong
  // `data:` or treats an indented `remote:` as the panel URL.
  const parsed = readWingsConfig(`system:
  data: /srv/daemon-data/volumes
  sftp:
    remote: nonsense
remote: https://real.example.com
`);

  assert.equal(parsed.volumesPath, '/srv/daemon-data/volumes');
  assert.equal(parsed.remote, 'https://real.example.com');
});

test('a custom volumes path is read, not assumed', () => {
  // The whole point: scanning /var/lib/pterodactyl/volumes on a node whose data
  // is elsewhere finds nothing and looks exactly like a clean node.
  const parsed = readWingsConfig('system:\n  data: /mnt/disk2/volumes\n');

  assert.equal(parsed.volumesPath, '/mnt/disk2/volumes');
});

test('quotes and trailing comments are stripped', () => {
  const parsed = readWingsConfig(`remote: "https://panel.example.com"  # the panel
system:
  data: '/var/lib/pterodactyl/volumes'
`);

  assert.equal(parsed.remote, 'https://panel.example.com');
  assert.equal(parsed.volumesPath, '/var/lib/pterodactyl/volumes');
});

test('an unrecognisable file yields nulls, never a guess', () => {
  const parsed = readWingsConfig('this is not yaml at all\n');

  assert.equal(parsed.uuid, null);
  assert.equal(parsed.remote, null);
  assert.equal(parsed.volumesPath, null);
});

test('placeholders are recognised as unconfigured', () => {
  for (const value of ['ptla_replace_me', 'ptla_YOUR_APPLICATION_KEY', 'changeme', 'replace-me']) {
    assert.equal(isPlaceholder(value), true, value);
  }
  assert.equal(isPlaceholder('ptla_9f3a2c8d7e6b5a4c3d2e1f0a'), false);
  assert.equal(isPlaceholder(''), false);
  assert.equal(isPlaceholder(undefined), false);
});

test('merging an env file keeps credentials that are already there', () => {
  // `xrae init` used to refuse to touch an existing file and silently discard
  // what the operator had just typed.
  const merged = mergeEnvFile('XRAE_PANEL_APP_KEY=ptla_real\nXRAE_DISCORD_WEBHOOK=https://hook\n', {
    XRAE_REPORTING_URL: 'https://xrae.raehost.com',
    XRAE_REPORTING_TOKEN: 'xrae_node_abc',
  });

  assert.match(merged, /XRAE_PANEL_APP_KEY=ptla_real/);
  assert.match(merged, /XRAE_DISCORD_WEBHOOK=https:\/\/hook/);
  assert.match(merged, /XRAE_REPORTING_URL=https:\/\/xrae\.raehost\.com/);
  assert.match(merged, /XRAE_REPORTING_TOKEN=xrae_node_abc/);
});

test('a rotated token replaces in place rather than stacking a duplicate', () => {
  // systemd takes the LAST assignment, so duplicates are a confusing way to be
  // wrong: the file shows the new token and the service uses it, or not,
  // depending on order.
  const merged = mergeEnvFile('XRAE_REPORTING_TOKEN=old\n', {
    XRAE_REPORTING_TOKEN: 'new',
  });

  assert.equal(merged.match(/XRAE_REPORTING_TOKEN=/g).length, 1);
  assert.match(merged, /XRAE_REPORTING_TOKEN=new/);
});

test('merging never writes an empty value over a real one', () => {
  const merged = mergeEnvFile('XRAE_PANEL_APP_KEY=ptla_real\n', {
    XRAE_PANEL_APP_KEY: '',
  });

  assert.match(merged, /XRAE_PANEL_APP_KEY=ptla_real/);
});

test('merging an empty file produces a valid one', () => {
  const merged = mergeEnvFile('', { XRAE_REPORTING_TOKEN: 'abc' });

  assert.match(merged, /^XRAE_REPORTING_TOKEN=abc$/m);
  assert.ok(merged.endsWith('\n'));
});

test('the node id is resolved from the Wings uuid, not guessed', () => {
  // nodeId 0 means "every node this key can see", so a per-node agent left at
  // the default has the whole fleet reporting the whole fleet.
  const nodes = {
    data: [
      { attributes: { id: 3, uuid: 'other-uuid' } },
      { attributes: { id: 7, uuid: 'mine-uuid' } },
    ],
  };
  const fetchImpl = async () => ({ ok: true, json: async () => nodes });

  return resolveNodeId({
    panelUrl: 'https://panel.example.com',
    applicationKey: 'ptla_x',
    uuid: 'mine-uuid',
    fetchImpl,
  }).then((id) => assert.equal(id, 7));
});

test('an unmatched uuid resolves to null so the caller can say so', async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => ({ data: [] }) });

  assert.equal(
    await resolveNodeId({
      panelUrl: 'https://panel.example.com',
      applicationKey: 'ptla_x',
      uuid: 'mine-uuid',
      fetchImpl,
    }),
    null,
  );
});

test('a failing Pterodactyl API resolves to null rather than throwing', async () => {
  const rejecting = async () => ({ ok: false, status: 403, json: async () => ({}) });
  const throwing = async () => {
    throw new Error('ECONNREFUSED');
  };

  assert.equal(await resolveNodeId({ panelUrl: 'https://p', applicationKey: 'k', uuid: 'u', fetchImpl: rejecting }), null);
  assert.equal(await resolveNodeId({ panelUrl: 'https://p', applicationKey: 'k', uuid: 'u', fetchImpl: throwing }), null);
});

test('missing inputs skip the lookup entirely', async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;

    return { ok: true, json: async () => ({ data: [] }) };
  };

  await resolveNodeId({ panelUrl: '', applicationKey: 'k', uuid: 'u', fetchImpl });
  await resolveNodeId({ panelUrl: 'https://p', applicationKey: '', uuid: 'u', fetchImpl });
  await resolveNodeId({ panelUrl: 'https://p', applicationKey: 'k', uuid: null, fetchImpl });

  assert.equal(called, false);
});

test('the panel token is verified before anything is written', async () => {
  const captured = {};
  const fetchImpl = async (url, init) => {
    captured.url = url;
    captured.method = init.method;
    captured.auth = init.headers.Authorization;
    captured.protocol = init.headers['X-Xrae-Protocol'];

    return { ok: true, status: 200 };
  };

  const verdict = await verifyPanel({
    panelUrl: 'https://xrae.raehost.com/',
    token: 'xrae_node_abc',
    agentVersion: '1.4.0',
    fetchImpl,
  });

  assert.equal(verdict.ok, true);
  assert.equal(captured.url, 'https://xrae.raehost.com/api/agent/heartbeat');
  assert.equal(captured.method, 'POST');
  assert.equal(captured.auth, 'Bearer xrae_node_abc');
  assert.equal(captured.protocol, '1');
});

test('a rejected token is reported as a rejected token, not a generic failure', async () => {
  const verdict = await verifyPanel({
    panelUrl: 'https://xrae.raehost.com',
    token: 'wrong',
    agentVersion: '1.4.0',
    fetchImpl: async () => ({ ok: false, status: 401 }),
  });

  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /rejected this token/);
});

test('an unreachable panel is reported without throwing', async () => {
  const verdict = await verifyPanel({
    panelUrl: 'https://xrae.raehost.com',
    token: 'x',
    agentVersion: '1.4.0',
    fetchImpl: async () => {
      throw new Error('getaddrinfo ENOTFOUND');
    },
  });

  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /ENOTFOUND/);
});
