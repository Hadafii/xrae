// LAYER: infrastructure
// JOB:   Inspect what each container is actually RUNNING, not just what sits on
//        its disk.
// IMPLEMENTS: EvidenceCollector port.
//
// ============================================================================
// WHY THIS COLLECTOR EXISTS
// ============================================================================
// A real miner slipped past the filesystem scanner on a production node. It
// evaded content detection three ways at once:
//   - the xmrig binary was packed, so its strings were not in plaintext,
//   - the pool URL was passed as a command-line argument, never on disk,
//   - it connected on :443 with TLS, so no pool-port matched.
//
// But the kernel still held the truth in /proc/<pid>: the launch arguments
// ("-o pool.supportxmr.com:443 -u <wallet> --donate-level=0") and the exe
// symlink target ("/home/container/plugins/.data/xmrig"). A running process is
// a far stronger subject than a file, so several of these signals are
// standalone here even though the same string is not standalone as file text.
//
// Attribution is per-container: the resolver maps a server UUID to its PID via
// mountinfo, so one tenant's process can never raise another tenant's score.
// ============================================================================

import { createEvidence, EvidenceFamily } from '../../domain/evidence.js';
import { PROCESS_RULES } from '../../domain/rules.js';

const MAX_DETAIL_PATH = 120;

/** @implements {import('../../application/ports.js').EvidenceCollector} */
export class ProcessCommandCollector {
  name = 'process';

  /**
   * @param {object} deps
   * @param {import('../system/container-resolver.js').ContainerProcessResolver} deps.resolver
   * @param {import('../../application/ports.js').Logger} deps.logger
   * @param {typeof PROCESS_RULES} [deps.rules]
   */
  constructor({ resolver, logger, rules = PROCESS_RULES }) {
    this.resolver = resolver;
    this.logger = logger;
    this.rules = rules;
  }

  /** Rebuild the uuid->pid map once per cycle. Idempotent; safe alongside the network collector. */
  async prepare() {
    await this.resolver.refresh();
  }

  /** @param {import('../../application/ports.js').ServerRef} server */
  async collect(server) {
    const pid = this.resolver.pidFor(server.uuid);
    if (!pid) return []; // not running, or we lack permission - both normal

    // The contract forbids throwing. Any read failure yields no evidence, not a
    // crash that would take down the other collectors.
    let cmdline = '';
    let exe = '';
    try {
      cmdline = await this.resolver.readCmdline(pid);
      exe = await this.resolver.readExeTarget(pid);
    } catch (error) {
      this.logger.debug(`process collector could not read pid ${pid}: ${error.message}`);
      return [];
    }

    const combined = `${exe} ${cmdline}`;
    if (!combined.trim()) return [];
    const haystack = combined.toLowerCase();
    const where = truncatePath(exe || cmdline);

    const evidence = [];
    for (const rule of this.rules) {
      const matched = rule.regex ? rule.regex.test(cmdline) : haystack.includes(rule.pattern);
      if (!matched) continue;

      evidence.push(
        createEvidence({
          ruleId: rule.id,
          family: EvidenceFamily.BEHAVIOR,
          category: rule.category,
          weight: rule.weight,
          confidence: rule.confidence,
          standalone: rule.standalone,
          detail: `${rule.detail} (pid ${pid}: ${where})`,
        }),
      );
    }

    return evidence;
  }
}

function truncatePath(value) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return text.length <= MAX_DETAIL_PATH ? text : text.slice(0, MAX_DETAIL_PATH - 1) + '…';
}
