// LAYER: config
// JOB:   Read an environment file so credentials never have to live in
//        config.json.
//
// Why this exists at all: systemd loads /etc/xrae/xrae.env for you via
// EnvironmentFile=, but when an operator runs `xrae doctor` by hand from a
// shell, those variables are not set. Without this file, doctor would report
// "no credentials" on a perfectly working install, which is the kind of
// confusing failure that makes people give up on a tool.
//
// PRECEDENCE, highest wins:
//
//   1. real environment   (systemd EnvironmentFile, or `export` in your shell)
//   2. the env file       (loaded here, never overwriting the above)
//   3. config.json
//   4. built-in defaults
//
// A variable already present in the real environment is NEVER overwritten. That
// is what makes systemd and manual runs behave identically.

import fs from 'node:fs';

/**
 * Parse KEY=value lines.
 *
 * Deliberately a small, boring subset: comments, optional `export` prefix,
 * optional quotes. No variable interpolation, no multi-line values. A parser
 * that guesses is worse than one that is predictable.
 *
 * @param {string} text
 * @returns {Record<string, string>}
 */
export function parseEnvFile(text) {
  /** @type {Record<string, string>} */
  const values = {};

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;

    const withoutExport = line.startsWith('export ') ? line.slice(7).trim() : line;
    const separator = withoutExport.indexOf('=');
    if (separator === -1) continue;

    const key = withoutExport.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    let value = withoutExport.slice(separator + 1).trim();

    const isQuoted =
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")));

    if (isQuoted) {
      value = value.slice(1, -1);
    } else {
      // Strip a trailing comment, but only when it is clearly separate. This
      // keeps a '#' inside a webhook token or password intact.
      const comment = value.search(/\s+#/);
      if (comment !== -1) value = value.slice(0, comment).trim();
    }

    values[key] = value;
  }

  return values;
}

/**
 * Load an env file into process.env without clobbering anything already set.
 *
 * @param {string} filePath
 * @returns {{applied: string[], alreadySet: string[]}}
 */
export function loadEnvFileInto(filePath, environment = process.env) {
  const values = parseEnvFile(fs.readFileSync(filePath, 'utf8'));
  const applied = [];
  const alreadySet = [];

  for (const [key, value] of Object.entries(values)) {
    if (environment[key] !== undefined && environment[key] !== '') {
      // The real environment wins. Recording this lets doctor warn about a
      // credential that is defined twice with different values.
      alreadySet.push(key);
      continue;
    }
    environment[key] = value;
    applied.push(key);
  }

  return { applied, alreadySet };
}
