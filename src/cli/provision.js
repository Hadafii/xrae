// LAYER: cli
// JOB:   Turn "I have a token from the panel" into a running, reporting agent
//        in one non-interactive step.

import fs from 'node:fs';
import path from 'node:path';

/**
 * Where Wings keeps its own configuration. Everything X-Rae needs to scan a node
 * is already in there, because Wings and X-Rae look at the same volumes.
 */
export const WINGS_CONFIG_PATH = '/etc/pterodactyl/config.yml';

/**
 * A deliberately tiny reader for the four scalars we want out of Wings' config.
 *
 * Not a YAML parser and not trying to be. Pulling in a dependency would break
 * this project's zero-dependency property for the sake of `system.data`, and a
 * full parser would fail on constructs we do not care about. Unknown shapes
 * yield null and the caller falls back to a flag or a default, which is the
 * behaviour that matters: never guess a volumes path.
 *
 * @param {string} text contents of config.yml
 */
export function readWingsConfig(text) {
  const result = { uuid: null, remote: null, volumesPath: null };
  const lines = text.split('\n');

  const unquote = (value) =>
    value
      .trim()
      .replace(/\s+#.*$/, '')
      .replace(/^['"]|['"]$/g, '')
      .trim() || null;

  let inSystem = false;

  for (const raw of lines) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;

    const indented = /^\s/.test(raw);

    if (!indented) {
      inSystem = /^system\s*:/.test(raw);

      const top = raw.match(/^(uuid|remote)\s*:\s*(.*)$/);

      if (top) result[top[1]] = unquote(top[2]);

      continue;
    }

    if (inSystem) {
      const data = raw.match(/^\s+data\s*:\s*(.*)$/);

      if (data) result.volumesPath = unquote(data[1]);
    }
  }

  return result;
}

export function detectWingsConfig(configPath = WINGS_CONFIG_PATH) {
  try {
    return readWingsConfig(fs.readFileSync(configPath, 'utf8'));
  } catch {
    return { uuid: null, remote: null, volumesPath: null };
  }
}

/**
 * Resolve the numeric Pterodactyl node id from the Wings uuid.
 *
 * This matters more than it looks. `nodeId: 0` means "every node this key can
 * see", so a per-node agent left at the default enumerates and reports the whole
 * fleet, and every node in the fleet reports every other node's servers. Wings
 * knows its own uuid but not its numeric id, so the application API is the only
 * place the mapping exists.
 *
 * @returns {Promise<number|null>} null when it cannot be determined, never a guess
 */
export async function resolveNodeId({ panelUrl, applicationKey, uuid, fetchImpl = fetch }) {
  if (!panelUrl || !applicationKey || !uuid) return null;

  const base = panelUrl.replace(/\/+$/, '');

  try {
    const response = await fetchImpl(`${base}/api/application/nodes?per_page=200`, {
      headers: {
        Authorization: `Bearer ${applicationKey}`,
        Accept: 'application/json',
      },
    });

    if (!response.ok) return null;

    const body = await response.json();
    const nodes = Array.isArray(body?.data) ? body.data : [];
    const match = nodes.find((entry) => entry?.attributes?.uuid === uuid);

    return match?.attributes?.id ?? null;
  } catch {
    return null;
  }
}

/**
 * Merge keys into an env file without discarding what is already there.
 *
 * `xrae init` used to refuse to touch an existing file, print one warning line,
 * and silently throw away the credentials the operator had just typed. Merging
 * is the behaviour people expect from an installer they run twice.
 *
 * Existing values win: a re-run with `--ptero-key` omitted must not blank the
 * key from the first run.
 */
export function mergeEnvFile(existing, additions) {
  const lines = existing ? existing.split('\n') : [];
  const present = new Set();

  for (const line of lines) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=/);

    if (match) present.add(match[1]);
  }

  const appended = [];

  for (const [key, value] of Object.entries(additions)) {
    if (!value) continue;

    if (present.has(key)) {
      for (let index = 0; index < lines.length; index += 1) {
        if (new RegExp(`^\\s*${key}\\s*=`).test(lines[index])) {
          lines[index] = `${key}=${value}`;
        }
      }
      continue;
    }

    appended.push(`${key}=${value}`);
  }

  if (appended.length === 0) return `${lines.join('\n').replace(/\n+$/, '')}\n`;

  return `${[...lines, '', '# Written by xrae provision.', ...appended]
    .join('\n')
    .replace(/\n+$/, '')}\n`;
}

/**
 * A placeholder is worse than an empty value: it is non-empty, so it passes
 * every "is this set?" check, and then fails at the first real API call. The
 * shipped example used to carry one uncommented, which produced a node that
 * validated cleanly and never reported anything.
 *
 * One definition, shared with startup validation, so the installer cannot accept
 * a value the agent will later refuse.
 */
export { isPlaceholderSecret as isPlaceholder } from '../config/config.js';

export async function verifyPanel({ panelUrl, token, agentVersion, fetchImpl = fetch }) {
  const base = panelUrl.replace(/\/+$/, '');

  try {
    const response = await fetchImpl(`${base}/api/agent/heartbeat`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-Xrae-Protocol': '1',
        'X-Xrae-Agent': agentVersion,
      },
      body: JSON.stringify({ agent_version: agentVersion }),
    });

    if (response.status === 401) return { ok: false, reason: 'the panel rejected this token' };
    if (!response.ok) return { ok: false, reason: `the panel answered ${response.status}` };

    return { ok: true };
  } catch (error) {
    return { ok: false, reason: error?.message ?? 'the panel was unreachable' };
  }
}
