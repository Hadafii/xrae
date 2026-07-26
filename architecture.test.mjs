// The architecture test.
//
// ============================================================================
// WHY THIS FILE MATTERS MORE THAN IT LOOKS
// ============================================================================
// Clean architecture usually rots for one reason: the layering is a diagram in
// a wiki that nobody runs. Six months later someone imports a database client
// into a domain file because it was quicker, review misses it, and the
// boundaries are gone.
//
// This test makes the boundary a build failure instead of a convention. It reads
// the actual import statements and enforces:
//
//   domain/       may import NOTHING except other domain files.
//                 No node builtins. No npm. No application. No infrastructure.
//
//   application/  may import domain and application only.
//                 Talks to the outside world exclusively through ports.js.
//
//   infrastructure/ may import anything. It is the outside world.
//
// If you need to break one of these rules, you almost certainly have a design
// problem rather than a test problem.
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

/** Every .js file under a directory, recursively. */
function listSourceFiles(directory) {
  const found = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) found.push(...listSourceFiles(fullPath));
    else if (entry.name.endsWith('.js')) found.push(fullPath);
  }
  return found;
}

/**
 * Pull out the module specifiers from real `import` statements.
 * Deliberately ignores JSDoc `import('...')` type references, which are
 * comments and carry no runtime dependency.
 */
function findImports(sourceCode) {
  const withoutComments = sourceCode
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

  const specifiers = [];
  const staticImport = /^\s*import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/gm;
  const dynamicImport = /(?<!\.)\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

  for (const match of withoutComments.matchAll(staticImport)) specifiers.push(match[1]);
  for (const match of withoutComments.matchAll(dynamicImport)) specifiers.push(match[1]);
  return specifiers;
}

function layerOf(absolutePath) {
  const relative = path.relative(SOURCE_ROOT, absolutePath);
  const [first] = relative.split(path.sep);
  return relative.includes(path.sep) ? first : 'root';
}

/** Where does an import point: which layer, or 'external'? */
function targetOf(importingFile, specifier) {
  if (!specifier.startsWith('.')) {
    return specifier.startsWith('node:') ? 'node-builtin' : 'npm-package';
  }
  const resolved = path.resolve(path.dirname(importingFile), specifier);
  return layerOf(resolved);
}

test('domain depends on nothing but itself', () => {
  const violations = [];

  for (const file of listSourceFiles(path.join(SOURCE_ROOT, 'domain'))) {
    for (const specifier of findImports(fs.readFileSync(file, 'utf8'))) {
      const target = targetOf(file, specifier);
      if (target === 'domain') continue;

      violations.push(
        `${path.relative(SOURCE_ROOT, file)} imports "${specifier}" (${target}). ` +
          'Domain must stay pure: no I/O, no framework, no node builtins.',
      );
    }
  }

  assert.deepEqual(violations, [], `\n${violations.join('\n')}\n`);
});

test('application depends only on domain and itself', () => {
  const allowed = new Set(['domain', 'application']);
  const violations = [];

  for (const file of listSourceFiles(path.join(SOURCE_ROOT, 'application'))) {
    for (const specifier of findImports(fs.readFileSync(file, 'utf8'))) {
      const target = targetOf(file, specifier);
      if (allowed.has(target)) continue;

      violations.push(
        `${path.relative(SOURCE_ROOT, file)} imports "${specifier}" (${target}). ` +
          'Use a port from application/ports.js instead, and wire the real thing in composition-root.js.',
      );
    }
  }

  assert.deepEqual(violations, [], `\n${violations.join('\n')}\n`);
});

test('the project has zero npm dependencies', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(SOURCE_ROOT, '..', 'package.json'), 'utf8'));
  assert.deepEqual(
    manifest.dependencies ?? {},
    {},
    'X-Rae is a privileged agent. A dependency it does not have cannot be used to backdoor it.',
  );

  const npmImports = [];
  for (const file of listSourceFiles(SOURCE_ROOT)) {
    for (const specifier of findImports(fs.readFileSync(file, 'utf8'))) {
      if (targetOf(file, specifier) === 'npm-package') {
        npmImports.push(`${path.relative(SOURCE_ROOT, file)} -> ${specifier}`);
      }
    }
  }
  assert.deepEqual(npmImports, [], `\n${npmImports.join('\n')}\n`);
});

test('only the composition root decides which concrete adapter is used', () => {
  // If a use case imports an adapter directly, dependency injection is being
  // bypassed and the layering is decorative.
  const offenders = [];

  for (const file of listSourceFiles(path.join(SOURCE_ROOT, 'application'))) {
    const source = fs.readFileSync(file, 'utf8');
    if (/new\s+(Pterodactyl|Discord|Json|Console|System)\w*\(/.test(source)) {
      offenders.push(path.relative(SOURCE_ROOT, file));
    }
  }

  assert.deepEqual(offenders, [], `These files construct infrastructure directly: ${offenders.join(', ')}`);
});

test('every detection rule declares when it is wrong', async () => {
  // The fpProfile field is what stops the rule pack filling up with guesses.
  const { RULE_PACK, REGEX_RULES } = await import('../src/domain/rules.js');

  for (const rule of [...RULE_PACK, ...REGEX_RULES]) {
    assert.ok(
      rule.fpProfile && rule.fpProfile.length >= 10,
      `rule "${rule.id}" has no usable fpProfile. Describe when this rule fires on an innocent server.`,
    );
  }
});

test('xrae.env.example documents exactly the variables the code reads', () => {
  // Documentation that nothing verifies is documentation that goes stale.
  // If you add an environment variable, this test tells you where to write it
  // down; if you delete one, it tells you to stop advertising it.
  const projectRoot = path.join(SOURCE_ROOT, '..');
  const collect = (text) => new Set(text.match(/XRAE_[A-Z_]+/g) ?? []);

  const documented = collect(fs.readFileSync(path.join(projectRoot, 'xrae.env.example'), 'utf8'));
  const readByCode = collect(
    fs.readFileSync(path.join(SOURCE_ROOT, 'config', 'config.js'), 'utf8') +
      fs.readFileSync(path.join(SOURCE_ROOT, 'cli', 'main.js'), 'utf8'),
  );

  const undocumented = [...readByCode].filter((name) => !documented.has(name)).sort();
  const stale = [...documented].filter((name) => !readByCode.has(name)).sort();

  assert.deepEqual(undocumented, [], `read by the code but missing from xrae.env.example: ${undocumented.join(', ')}`);
  assert.deepEqual(stale, [], `advertised in xrae.env.example but ignored by the code: ${stale.join(', ')}`);
});

test('the env template does not use shell syntax systemd will silently ignore', () => {
  // systemd's EnvironmentFile is not a shell script. `export FOO=bar` sets a
  // variable literally named "export FOO", and the failure is invisible - the
  // service starts and then cannot authenticate. Catch it in the template.
  const template = fs.readFileSync(path.join(SOURCE_ROOT, '..', 'xrae.env.example'), 'utf8');

  const offendingLines = template
    .split('\n')
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => {
      const active = line.trim();
      if (active === '' || active.startsWith('#')) return false;
      return /^export\s/.test(active) || /=\S*\$\{?[A-Za-z_]/.test(active) || /=.*\s+#/.test(active);
    })
    .map(({ line, number }) => `line ${number}: ${line}`);

  assert.deepEqual(offendingLines, [], `\n${offendingLines.join('\n')}\n`);
});
