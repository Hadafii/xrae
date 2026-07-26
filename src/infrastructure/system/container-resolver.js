// LAYER: infrastructure
// JOB:   Find which process belongs to which server, so network activity can be
//        attributed to the right tenant.
//
// ============================================================================
// THIS FILE FIXES THE WORST BUG IN THE ORIGINAL SONARX
// ============================================================================
// The old version read the HOST's /proc/net/tcp - a single list of every
// connection on the machine - and then added the resulting score to EVERY
// server in the loop.
//
// So one tenant running ARK on port 7777 raised the risk score of every other
// tenant on the node. With auto-suspend enabled, that is a fleet-wide outage
// waiting for a trigger, and it is trivially weaponisable: put a "suspicious"
// connection on the node and everyone else gets punished.
//
// Host-wide network data is not weak evidence. It is not evidence at all,
// because it cannot be attributed to a subject.
//
// HOW THE ATTRIBUTION WORKS
// Pterodactyl bind-mounts each server's volume into its container. That means
// /proc/<pid>/mountinfo for a container process contains the host path of the
// volume, which contains the server UUID. Find that line, and you have mapped
// a PID to a server - with no Docker socket and no extra dependency.
//
// From the PID we can read /proc/<pid>/net/tcp, which is that container's own
// network namespace and nobody else's.
// ============================================================================

import fsp from 'node:fs/promises';
import path from 'node:path';

export class ContainerProcessResolver {
  /**
   * @param {object} deps
   * @param {string} deps.volumesPath
   * @param {import('../../application/ports.js').Logger} deps.logger
   */
  constructor({ volumesPath, logger }) {
    this.volumesPath = volumesPath;
    this.logger = logger;
    /** @type {Map<string, string>} uuid -> pid */
    this.pidByUuid = new Map();
    /** @type {boolean|null} */
    this.canReadOtherProcesses = null;
  }

  /**
   * Can this process read another process's network namespace at all?
   * Needs root, or CAP_SYS_PTRACE plus CAP_DAC_READ_SEARCH.
   */
  async checkPermissions() {
    if (this.canReadOtherProcesses !== null) return this.canReadOtherProcesses;

    try {
      await fsp.readFile('/proc/1/net/tcp', 'utf8');
      this.canReadOtherProcesses = true;
    } catch (error) {
      this.canReadOtherProcesses = false;
      this.logger.warn(
        'network attribution is unavailable: cannot read /proc/<pid>/net ' +
          `(${error.code ?? error.message}). Grant CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, ` +
          'or set scanner.collectConnections to false to stop this warning.',
      );
    }
    return this.canReadOtherProcesses;
  }

  /** Rebuild the map. Called once per cycle, not once per server. */
  async refresh() {
    if (!(await this.checkPermissions())) return;

    this.pidByUuid.clear();
    const marker = this.volumesPath.endsWith(path.sep) ? this.volumesPath : this.volumesPath + path.sep;

    let processIds;
    try {
      processIds = (await fsp.readdir('/proc')).filter((entry) => /^\d+$/.test(entry));
    } catch (error) {
      this.logger.warn(`cannot list /proc: ${error.message}`);
      return;
    }

    for (const pid of processIds) {
      const uuid = await this.#uuidForProcess(pid, marker);
      if (uuid && !this.pidByUuid.has(uuid)) this.pidByUuid.set(uuid, pid);
    }

    this.logger.debug(`mapped ${this.pidByUuid.size} container namespace(s)`);
  }

  async #uuidForProcess(pid, marker) {
    let mountInfo;
    try {
      mountInfo = await fsp.readFile(`/proc/${pid}/mountinfo`, 'utf8');
    } catch {
      return null; // process exited, or not permitted - both normal
    }

    const markerIndex = mountInfo.indexOf(marker);
    if (markerIndex === -1) return null;

    const afterMarker = mountInfo.slice(markerIndex + marker.length);
    const candidate = afterMarker.split(/[\s/]/, 1)[0];
    return /^[0-9a-f]{8}-[0-9a-f-]{4,27}$/i.test(candidate) ? candidate : null;
  }

  /** @returns {string|null} pid, or null if the server has no running process */
  pidFor(uuid) {
    return this.pidByUuid.get(uuid) ?? null;
  }

  /** Read one of the container's own socket tables. */
  async readSocketTable(pid, table) {
    try {
      return await fsp.readFile(`/proc/${pid}/net/${table}`, 'utf8');
    } catch {
      return '';
    }
  }

  /**
   * The process's launch arguments, exactly as the kernel kept them. This is
   * the one place a miner's real pool URL and wallet survive even when the
   * binary is packed and the config is passed on the command line - both were
   * used to evade the on-disk scanner in a real incident.
   * @returns {Promise<string>} space-joined argv, or '' if unreadable
   */
  async readCmdline(pid) {
    try {
      const raw = await fsp.readFile(`/proc/${pid}/cmdline`, 'utf8');
      return raw.replace(/\0/g, ' ').trim();
    } catch {
      return '';
    }
  }

  /**
   * The real path of the running binary, following the exe symlink. Survives
   * an attacker renaming argv[0], and reveals a hidden location such as
   * plugins/.data/xmrig.
   * @returns {Promise<string>} the target path, or '' if unreadable
   */
  async readExeTarget(pid) {
    try {
      return await fsp.readlink(`/proc/${pid}/exe`);
    } catch {
      return '';
    }
  }
}
