// LAYER: infrastructure
// JOB:   Look at who a container is talking to - and only that container.
// IMPLEMENTS: EvidenceCollector port.
//
// See container-resolver.js for why per-container attribution is not optional.

import { createEvidence, EvidenceFamily } from '../../domain/evidence.js';
import { Confidence } from '../../domain/confidence.js';
import { MINER_POOL_PORTS } from '../../domain/rules.js';

/** /proc socket table state code for ESTABLISHED. */
const STATE_ESTABLISHED = '01';

/** More external connections than this is unusual for a game server. */
const HIGH_FANOUT_THRESHOLD = 60;

/** @implements {import('../../application/ports.js').EvidenceCollector} */
export class NetworkCollector {
  name = 'network';

  /**
   * @param {object} deps
   * @param {import('../system/container-resolver.js').ContainerProcessResolver} deps.resolver
   * @param {import('../../application/ports.js').Logger} deps.logger
   * @param {number[]} [deps.suspiciousPorts]
   */
  constructor({ resolver, logger, suspiciousPorts = MINER_POOL_PORTS }) {
    this.resolver = resolver;
    this.logger = logger;
    this.suspiciousPorts = new Set(suspiciousPorts);
  }

  /** Rebuild the pid map once per cycle. */
  async prepare() {
    await this.resolver.refresh();
  }

  /** @param {import('../../application/ports.js').ServerRef} server */
  async collect(server) {
    const pid = this.resolver.pidFor(server.uuid);
    if (!pid) return []; // server is not running, or we lack permission

    const tables = [
      await this.resolver.readSocketTable(pid, 'tcp'),
      await this.resolver.readSocketTable(pid, 'tcp6'),
    ];

    const connections = tables.flatMap((table) => this.#parseTable(table));
    const external = connections.filter((c) => !isPrivateAddress(c.remoteIp));

    const evidence = [];
    const reportedPorts = new Set();

    for (const connection of external) {
      if (!this.suspiciousPorts.has(connection.remotePort)) continue;
      if (reportedPorts.has(connection.remotePort)) continue;
      reportedPorts.add(connection.remotePort);

      evidence.push(
        createEvidence({
          ruleId: `network.pool_port.${connection.remotePort}`,
          family: EvidenceFamily.NETWORK,
          category: 'MINER',
          weight: 25,
          confidence: Confidence.MEDIUM,
          // A port number is never enough on its own to punish someone.
          standalone: false,
          detail: `established outbound connection to ${connection.remoteIp ?? 'remote'}:${connection.remotePort}, a known pool port`,
        }),
      );
    }

    if (external.length > HIGH_FANOUT_THRESHOLD) {
      evidence.push(
        createEvidence({
          ruleId: 'network.high_fanout',
          family: EvidenceFamily.NETWORK,
          category: 'SUSPICIOUS',
          weight: 12,
          confidence: Confidence.LOW,
          standalone: false,
          detail: `${external.length} concurrent external connections`,
        }),
      );
    }

    return evidence;
  }

  #parseTable(table) {
    const rows = table.split('\n').slice(1); // first line is the header
    const connections = [];

    for (const row of rows) {
      const columns = row.trim().split(/\s+/);
      if (columns.length < 4) continue;
      if (columns[3] !== STATE_ESTABLISHED) continue;

      const [remoteHex, portHex] = columns[2].split(':');
      const remotePort = Number.parseInt(portHex, 16);
      if (!Number.isFinite(remotePort)) continue;

      connections.push({
        remotePort,
        remoteIp: remoteHex.length === 8 ? hexToIpv4(remoteHex) : null,
      });
    }
    return connections;
  }
}

/** /proc stores IPv4 little-endian, so the octets come out backwards. */
function hexToIpv4(hex) {
  const octets = [];
  for (let i = 6; i >= 0; i -= 2) octets.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return octets.join('.');
}

/** Traffic inside the node or to RFC1918 space is not interesting here. */
function isPrivateAddress(ip) {
  if (!ip) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}
