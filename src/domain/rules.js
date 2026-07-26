// LAYER: domain (pure)
// JOB:   Hold every detection rule as data, and refuse to accept a rule that
//        has not been thought through.
// MAY IMPORT: other domain files only.
//
// ============================================================================
// HOW TO ADD A RULE (this is the most common change anyone will make here)
// ============================================================================
// 1. Add an entry to RULE_PACK below.
// 2. Fill in `fpProfile`. This is MANDATORY and the loader rejects rules
//    without it. It answers: "when would this rule fire on an innocent
//    server?" If you cannot answer that, you do not understand your rule yet
//    and it is not ready.
// 3. Only set `standalone: true` if there is NO legitimate reason for a game
//    server to contain this. A stratum URL qualifies. The word "xmrig" does
//    not - it appears in blocklists, logs and security tools.
// 4. Run `node test/run-all.mjs`. Then run it in observe mode for a week.
//
// RULE DELETED ON PURPOSE - do not add these back:
//   curl, wget, python, bash, perl, gcc, make, nmap, tcpdump, wireshark
// Every Linux game image contains those strings. They detect "a computer",
// not an attacker. A rule that cannot discriminate must not get a vote.
// ============================================================================

import { Confidence } from './confidence.js';
import { EvidenceFamily } from './evidence.js';

const { LOW, MEDIUM, HIGH, CRITICAL } = Confidence;

/**
 * @typedef {object} Rule
 * @property {string}  id
 * @property {string}  pattern     lowercase text to look for
 * @property {string}  category
 * @property {number}  weight
 * @property {string}  confidence
 * @property {boolean} standalone
 * @property {string}  fpProfile   when this rule is wrong. MANDATORY.
 */

/** @type {Rule[]} */
export const RULE_PACK = [
  // --- Mining, protocol level. Nothing legitimate speaks stratum. ----------
  { id: 'miner.stratum.tcp', pattern: 'stratum+tcp://', category: 'MINER', weight: 55, confidence: CRITICAL, standalone: true,
    fpProfile: 'Only a mining tutorial or a blocklist pasted into a file. Rare enough to accept.' },
  { id: 'miner.stratum.ssl', pattern: 'stratum+ssl://', category: 'MINER', weight: 55, confidence: CRITICAL, standalone: true,
    fpProfile: 'Same as stratum.tcp.' },

  // --- Mining, known software. Strong, but not proof alone. ----------------
  { id: 'miner.xmrig', pattern: 'xmrig', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'Appears in antivirus signature lists, security tooling, blog posts and admin notes.' },
  { id: 'miner.minerd', pattern: 'minerd', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    fpProfile: 'Same as xmrig.' },
  { id: 'miner.cpuminer', pattern: 'cpuminer', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    fpProfile: 'Same as xmrig.' },
  { id: 'miner.donate.level', pattern: 'donate-level', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    fpProfile: 'An xmrig config field name. Could appear in documentation.' },

  // --- Mining algorithms. Weak: these words appear in crypto libraries. ----
  { id: 'miner.algo.randomx', pattern: 'randomx', category: 'MINER', weight: 20, confidence: MEDIUM, standalone: false,
    fpProfile: 'Generic algorithm name; may appear in unrelated crypto libraries.' },
  { id: 'miner.algo.cryptonight', pattern: 'cryptonight', category: 'MINER', weight: 22, confidence: MEDIUM, standalone: false,
    fpProfile: 'Same as randomx.' },
  { id: 'miner.algo.kawpow', pattern: 'kawpow', category: 'MINER', weight: 18, confidence: MEDIUM, standalone: false,
    fpProfile: 'Same as randomx.' },
  { id: 'miner.algo.etchash', pattern: 'etchash', category: 'MINER', weight: 18, confidence: MEDIUM, standalone: false,
    fpProfile: 'Same as randomx.' },

  // --- Mining pool hostnames. --------------------------------------------
  { id: 'miner.pool.supportxmr', pattern: 'supportxmr.com', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    fpProfile: 'Only in a blocklist or documentation.' },
  { id: 'miner.pool.moneroocean', pattern: 'moneroocean.stream', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    fpProfile: 'Only in a blocklist or documentation.' },
  { id: 'miner.pool.nanopool', pattern: 'nanopool.org', category: 'MINER', weight: 35, confidence: HIGH, standalone: false,
    fpProfile: 'Only in a blocklist or documentation.' },
  { id: 'miner.pool.nicehash', pattern: 'nicehash.com', category: 'MINER', weight: 35, confidence: HIGH, standalone: false,
    fpProfile: 'Only in a blocklist or documentation.' },
  { id: 'miner.pool.hashvault', pattern: 'hashvault.pro', category: 'MINER', weight: 35, confidence: HIGH, standalone: false,
    fpProfile: 'Only in a blocklist or documentation.' },
  { id: 'miner.pool.herominers', pattern: 'herominers.com', category: 'MINER', weight: 35, confidence: HIGH, standalone: false,
    fpProfile: 'Only in a blocklist or documentation.' },

  // --- Browser / WASM mining, usually inside a web panel plugin. -----------
  { id: 'miner.web.coinhive', pattern: 'coinhive', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'Dead service; mostly appears in historical blocklists now.' },
  { id: 'miner.web.coinimp', pattern: 'coinimp', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'Mostly appears in historical blocklists and malware write-ups now.' },

  // --- Tunnels and proxies. Policy violations more than attacks. -----------
  // Note: several hosts legitimately allow these. Keep weights modest and
  // never standalone.
  { id: 'tunnel.frpc.config', pattern: 'frpc.toml', category: 'TUNNEL', weight: 30, confidence: MEDIUM, standalone: false,
    fpProfile: 'A tenant legitimately exposing a dev service, if your AUP allows it.' },
  { id: 'tunnel.ngrok.token', pattern: 'ngrok authtoken', category: 'TUNNEL', weight: 35, confidence: HIGH, standalone: false,
    fpProfile: 'Legitimate debugging by a developer tenant.' },
  { id: 'tunnel.chisel', pattern: 'jpillora/chisel', category: 'TUNNEL', weight: 35, confidence: HIGH, standalone: false,
    fpProfile: 'Legitimate tunnelling, allowed on some platforms.' },
  { id: 'tunnel.nezha.agent', pattern: 'nezha-agent', category: 'TUNNEL', weight: 30, confidence: MEDIUM, standalone: false,
    fpProfile: 'A monitoring agent; some tenants install it on purpose.' },

  // --- Command and control. -----------------------------------------------
  { id: 'c2.reverse.shell.devtcp', pattern: 'bash -i >& /dev/tcp/', category: 'C2', weight: 55, confidence: CRITICAL, standalone: true,
    fpProfile: 'Appears in pentest cheat sheets and CTF writeups. Otherwise unambiguous.' },
  { id: 'c2.cobaltstrike.beacon', pattern: 'beacon.x64.dll', category: 'C2', weight: 60, confidence: CRITICAL, standalone: true,
    fpProfile: 'Effectively never legitimate on a game node.' },
  { id: 'c2.meterpreter', pattern: 'meterpreter', category: 'C2', weight: 50, confidence: HIGH, standalone: false,
    fpProfile: 'Security research, training material.' },
  { id: 'c2.sliver.server', pattern: 'sliver-server', category: 'C2', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'Security research.' },

  // --- Local privilege escalation and container escape. -------------------
  { id: 'exploit.dirtypipe', pattern: 'dirtypipe', category: 'EXPLOIT', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'Patch notes, security scanners, CVE databases.' },
  { id: 'exploit.pwnkit', pattern: 'pwnkit', category: 'EXPLOIT', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'Patch notes, CVE databases and vulnerability scanners mention it by name.' },
  { id: 'exploit.docker.socket', pattern: '/var/run/docker.sock', category: 'EXPLOIT', weight: 50, confidence: HIGH, standalone: false,
    fpProfile: 'Docker documentation, compose files a tenant copied in.' },
  { id: 'exploit.release.agent', pattern: 'notify_on_release', category: 'EXPLOIT', weight: 45, confidence: HIGH, standalone: false,
    fpProfile: 'cgroup documentation.' },
];

/**
 * Rules that need a regular expression rather than a plain substring.
 * Kept small: regex over multi-megabyte buffers is expensive, so only
 * high-value patterns earn a place.
 *
 * @type {Array<Rule & {regex: RegExp, family: string, detail: string}>}
 */
/**
 * A Monero address: base58, 95 chars, starts 4 or 8. Shared between the
 * on-disk regex scan and the live-process scan so both agree on what a wallet
 * looks like.
 */
export const MONERO_WALLET_REGEX = /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/;

export const REGEX_RULES = [
  {
    id: 'miner.wallet.monero',
    regex: MONERO_WALLET_REGEX,
    family: EvidenceFamily.STRUCTURE,
    category: 'MINER',
    weight: 50,
    confidence: CRITICAL,
    standalone: true,
    detail: 'Monero wallet address embedded in a file',
    fpProfile: 'A 95-character base58 string that is not a wallet. Astronomically unlikely.',
    pattern: '(regex)',
  },
  {
    id: 'miner.config.pool.shape',
    regex: /"(?:url|pool)"\s*:\s*"[^"]+"[\s\S]{0,400}?"(?:user|wallet)"\s*:\s*"[^"]+"/i,
    family: EvidenceFamily.STRUCTURE,
    category: 'MINER',
    weight: 45,
    confidence: HIGH,
    standalone: false,
    detail: 'Mining pool configuration structure',
    fpProfile: 'Any JSON config with both a "url" and a "user" field nearby - e.g. a database config.',
    pattern: '(regex)',
  },
];

/**
 * ============================================================================
 * LIVE-PROCESS RULES - matched against /proc/<pid>/cmdline and the exe target
 * ============================================================================
 * These exist because content scanning alone missed a real miner: the binary
 * was packed (so its strings never appeared in plaintext) and the pool URL and
 * wallet were passed as command-line arguments, never written to a file.
 *
 * A RUNNING process is a much stronger subject than a file on disk. The word
 * "xmrig" in a file might be a blocklist; a process whose executable IS xmrig,
 * launched with --donate-level against a mining pool, is not ambiguous. That is
 * why several of these are standalone in the process context even though the
 * same string is not standalone as file content.
 *
 * Family is BEHAVIOR, which is capped at 30 in scoring. That cap is deliberate:
 * one family should not auto-suspend alone. But standalone+CRITICAL still makes
 * a finding REPORTABLE, so a live miner always raises an alert even when the
 * score is capped, and auto-suspend still requires corroboration + threshold.
 *
 * @type {Rule[]}
 */
export const PROCESS_RULES = [
  { id: 'process.miner.stratum.tcp', pattern: 'stratum+tcp://', category: 'MINER', weight: 60, confidence: CRITICAL, standalone: true,
    detail: 'live process speaking the stratum mining protocol',
    fpProfile: 'A running process using stratum. The only benign case is an operator deliberately mining, which is exactly what we want reported.' },
  { id: 'process.miner.stratum.ssl', pattern: 'stratum+ssl://', category: 'MINER', weight: 60, confidence: CRITICAL, standalone: true,
    detail: 'live process speaking stratum over TLS',
    fpProfile: 'Same as the plain stratum case; a live mining connection, not file content.' },
  { id: 'process.miner.donate_level', pattern: '--donate-level', category: 'MINER', weight: 55, confidence: CRITICAL, standalone: true,
    detail: 'xmrig donate-level flag on a running process',
    fpProfile: 'The xmrig/xmr-stak donate flag on a live command line. A game server never passes it; a mining benchmark would, and should be flagged.' },
  { id: 'process.miner.wallet.monero', regex: MONERO_WALLET_REGEX, pattern: '(regex)', category: 'MINER', weight: 55, confidence: CRITICAL, standalone: true,
    detail: 'Monero wallet address passed as a process argument',
    fpProfile: 'A 95-char base58 Monero address in live argv. Astronomically unlikely to occur by chance.' },

  { id: 'process.miner.pool.supportxmr', pattern: 'supportxmr.com', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    detail: 'connecting to the supportxmr mining pool', fpProfile: 'A monitoring tool referencing the pool host. Non-standalone so corroboration is required to act.' },
  { id: 'process.miner.pool.moneroocean', pattern: 'moneroocean.stream', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    detail: 'connecting to the MoneroOcean mining pool', fpProfile: 'Same as supportxmr: a pool hostname in arguments.' },
  { id: 'process.miner.pool.nanopool', pattern: 'nanopool.org', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'connecting to the Nanopool mining pool', fpProfile: 'A pool hostname in arguments; non-standalone.' },
  { id: 'process.miner.pool.hashvault', pattern: 'hashvault.pro', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'connecting to the HashVault mining pool', fpProfile: 'A pool hostname in arguments; non-standalone.' },
  { id: 'process.miner.pool.herominers', pattern: 'herominers.com', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'connecting to a HeroMiners mining pool', fpProfile: 'A pool hostname in arguments; non-standalone.' },
  { id: 'process.miner.pool.nicehash', pattern: 'nicehash.com', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'connecting to the NiceHash marketplace', fpProfile: 'A pool hostname in arguments; non-standalone.' },

  { id: 'process.miner.bin.xmrig', pattern: 'xmrig', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    detail: 'executable or argument named xmrig', fpProfile: 'A process whose binary is named like a known miner. Non-standalone: a researcher could run one, so corroboration is required.' },
  { id: 'process.miner.bin.xmrstak', pattern: 'xmr-stak', category: 'MINER', weight: 45, confidence: HIGH, standalone: false,
    detail: 'executable or argument named xmr-stak', fpProfile: 'A known miner binary name; non-standalone.' },
  { id: 'process.miner.bin.cpuminer', pattern: 'cpuminer', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'executable or argument named cpuminer', fpProfile: 'A known miner binary name; non-standalone.' },
  { id: 'process.miner.bin.minerd', pattern: 'minerd', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'executable or argument named minerd', fpProfile: 'A known miner binary name; non-standalone.' },
  { id: 'process.miner.bin.trex', pattern: 't-rex', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'executable or argument named t-rex', fpProfile: 'A known GPU miner binary name; non-standalone.' },
  { id: 'process.miner.bin.nbminer', pattern: 'nbminer', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'executable or argument named nbminer', fpProfile: 'A known GPU miner binary name; non-standalone.' },
  { id: 'process.miner.bin.phoenixminer', pattern: 'phoenixminer', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'executable or argument named phoenixminer', fpProfile: 'A known GPU miner binary name; non-standalone.' },
  { id: 'process.miner.bin.lolminer', pattern: 'lolminer', category: 'MINER', weight: 40, confidence: HIGH, standalone: false,
    detail: 'executable or argument named lolminer', fpProfile: 'A known GPU miner binary name; non-standalone.' },

  { id: 'process.miner.algo.randomx', pattern: 'randomx', category: 'MINER', weight: 22, confidence: MEDIUM, standalone: false,
    detail: 'RandomX mining algorithm flag', fpProfile: 'The RandomX algorithm name in arguments; could appear unrelated, so low weight and non-standalone.' },
  { id: 'process.miner.algo.cryptonight', pattern: 'cryptonight', category: 'MINER', weight: 22, confidence: MEDIUM, standalone: false,
    detail: 'CryptoNight mining algorithm flag', fpProfile: 'The CryptoNight algorithm name in arguments; low weight, non-standalone.' },
];

/**
 * Outbound ports that are miner-pool defaults AND do not collide with games.
 *
 * The old SonarX also listed 7777, 8080, 8888, 6666, 9999 and 8008.
 * 7777 is Terraria, Unturned, ARK and Satisfactory. 8080 is every web panel
 * in existence. Those flagged a large share of the fleet, which is exactly how
 * a detector becomes a denial-of-service tool. They are gone.
 *
 * Even these are never standalone evidence.
 */
export const MINER_POOL_PORTS = Object.freeze([3333, 5555, 14433, 14444, 18081, 18089, 45560, 45700]);

/**
 * The same string means different things depending on what file it is in.
 * A binary containing "xmrig" is far more interesting than a log mentioning it.
 */
export const FILE_CLASS_WEIGHT = Object.freeze({
  executable: 1.0,
  script: 0.95,
  config: 0.75,
  text: 0.5,
  unknown: 0.85,
});

/** File types we never open at all: game assets and media. */
export const NEVER_SCAN_EXTENSIONS = Object.freeze(new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tga', 'webp', 'ico', 'svg', 'psd',
  'mp3', 'mp4', 'wav', 'ogg', 'webm', 'mkv', 'avi', 'mov', 'flac', 'bik', 'fsb',
  'ttf', 'otf', 'woff', 'woff2',
  'pak', 'uasset', 'uexp', 'umap', 'ubulk', 'assets', 'bundle', 'resource',
  'vpk', 'bsp', 'mdl', 'vtf', 'wad', 'pk3', 'pbo', 'bisign', 'rgssad', 'rgss3a',
  'mca', 'mcr', 'nbt', 'schematic', 'ldb', 'sst',
  'sav', 'sii', 'scs', 'ydr', 'ytd', 'ymap', 'ymt', 'ybn', 'yft', 'rpf',
  'iso', 'img', 'vdi', 'vmdk', 'pdf',
]));

/** Compressed containers. Searching for plaintext inside them is pointless. */
export const ARCHIVE_EXTENSIONS = Object.freeze(new Set([
  'zip', 'jar', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar', 'tar', 'lz4', 'br',
]));

/** Formats whose entropy is naturally high, so entropy proves nothing. */
export const NATURALLY_HIGH_ENTROPY = Object.freeze(new Set([
  ...ARCHIVE_EXTENSIONS, 'db', 'sqlite', 'sqlite3', 'sqlitedb', 'mdb', 'lock',
]));

export const SCRIPT_EXTENSIONS = Object.freeze(new Set(['js', 'mjs', 'cjs', 'py', 'sh', 'bash', 'pl', 'rb', 'php', 'lua', 'ps1']));

export const CONFIG_EXTENSIONS = Object.freeze(new Set(['json', 'yml', 'yaml', 'ini', 'conf', 'cfg', 'toml', 'properties', 'env', 'xml']));

export const TEXT_EXTENSIONS = Object.freeze(new Set(['txt', 'log', 'md']));

/**
 * If one file matches this many DIFFERENT rules, it is almost certainly a
 * blocklist, a log, documentation, or a security tool - not a payload.
 * Real malware matches a handful of rules, not twenty.
 *
 * This also stops the embarrassing case of X-Rae detecting its own rule pack.
 */
export const SIGNATURE_FLOOD_THRESHOLD = 8;

/** How much weight survives when the flood guard fires. */
export const FLOOD_WEIGHT_MULTIPLIER = 0.15;

/**
 * Validate a rule pack. Called at startup so a malformed rule fails loudly
 * instead of quietly corrupting every score on the node.
 *
 * @param {Rule[]} rules
 * @returns {Rule[]} the same rules, if they are all valid
 */
export function validateRulePack(rules) {
  const seen = new Set();
  const problems = [];

  for (const rule of rules) {
    if (!rule.id) problems.push('a rule has no id');
    if (seen.has(rule.id)) problems.push(`duplicate rule id: ${rule.id}`);
    seen.add(rule.id);

    if (!rule.pattern) problems.push(`${rule.id}: missing pattern`);
    if (!Number.isFinite(rule.weight) || rule.weight <= 0) problems.push(`${rule.id}: weight must be positive`);
    if (![LOW, MEDIUM, HIGH, CRITICAL].includes(rule.confidence)) problems.push(`${rule.id}: invalid confidence`);

    // The rule that keeps this project honest.
    if (!rule.fpProfile || rule.fpProfile.length < 10) {
      problems.push(`${rule.id}: fpProfile is required - describe when this rule is WRONG`);
    }
    if (rule.standalone && rule.confidence !== CRITICAL) {
      problems.push(`${rule.id}: a standalone rule must be CRITICAL confidence`);
    }
  }

  if (problems.length > 0) {
    throw new Error('Invalid rule pack:\n  - ' + problems.join('\n  - '));
  }
  return rules;
}
