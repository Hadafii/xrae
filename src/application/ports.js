// LAYER: application
// JOB:   Declare every contract the application needs from the outside world.
// MAY IMPORT: domain only.
//
// ============================================================================
// WHY THIS FILE EXISTS
// ============================================================================
// JavaScript has no `interface` keyword, so this file IS our interface list.
// Every one of these is implemented by something in src/infrastructure/.
//
// The rule that makes the architecture work:
//
//     The application and domain layers may only ever talk to these contracts.
//     They must never import anything from src/infrastructure/.
//
// That rule is not a convention you have to remember - test/architecture.test.mjs
// checks it automatically and fails the build if you break it.
//
// The practical payoff: to test a use case you pass in fake objects, and to
// swap Pterodactyl for something else you write one new adapter and change one
// line in composition-root.js. Nothing in domain/ or application/ moves.
//
// HOW TO ADD A NEW PORT
// 1. Add the @typedef here, with a comment explaining the contract.
// 2. Write an adapter in src/infrastructure/ that satisfies it.
// 3. Wire it in src/composition-root.js.
// ============================================================================

/**
 * A server as the application cares about it. Deliberately not a Pterodactyl
 * shape - if we swap panels, this stays the same.
 *
 * @typedef {object} ServerRef
 * @property {string|number} id          panel-internal id, used for actions
 * @property {string} identifier         short id shown to humans, e.g. "a1b2c3d4"
 * @property {string} uuid               full uuid, matches the volume directory
 * @property {string} name               tenant-chosen name. UNTRUSTED INPUT.
 * @property {number} nodeId
 * @property {number} cpuLimitPercent    0 means unlimited
 */

/**
 * Lists the servers we are responsible for.
 *
 * @typedef {object} ServerRepository
 * @property {() => Promise<ServerRef[]>} listActive
 *   Servers that are not already suspended. Throws if the panel is unreachable.
 */

/**
 * One source of evidence. This is the extension point of the whole system:
 * adding a new detection capability means writing a new collector, not editing
 * the engine.
 *
 * CONTRACT - all implementations must honour this:
 *   - Return an array. Never null, never undefined.
 *   - Return an EMPTY array when the source is unavailable. Do not throw.
 *     A broken collector must never stop the other collectors from running.
 *   - Never mutate the ServerRef.
 *
 * @typedef {object} EvidenceCollector
 * @property {string} name  used in logs, e.g. "filesystem"
 * @property {(server: ServerRef) => Promise<import('../domain/evidence.js').Evidence[]>} collect
 * @property {() => Promise<void>} [prepare]
 *   Optional once-per-cycle setup, e.g. rebuilding a pid lookup table.
 */

/**
 * Remembers what we saw last time, so scores can decay and persistence can be
 * measured.
 *
 * @typedef {object} ServerState
 * @property {number} score
 * @property {number} updatedAtMs
 * @property {number} detections           consecutive cycles with findings
 * @property {number} lastNotifiedAtMs
 * @property {string|null} lastAction
 * @property {number[]} cpuSamples
 * @property {Array<{ruleId: string, family: string, detail: string}>} reasons
 *
 * @typedef {object} StateRepository
 * @property {() => Promise<void>} load
 * @property {() => Promise<void>} save
 * @property {(serverIdentifier: string) => ServerState} get
 * @property {(serverIdentifier: string, partial: Partial<ServerState>) => void} set
 *   MERGES the given fields into the stored state. It does not replace the
 *   whole record. This lets a collector own one field (e.g. the CPU collector
 *   owns cpuSamples) without the cycle overwriting it.
 * @property {(activeIdentifiers: string[]) => void} forgetMissing
 * @property {() => {get: (key: string) => any, set: (key: string, value: any) => void}} fileCache
 *   A cheap key/value cache so unchanged files are not re-read every cycle.
 */

/**
 * Tells humans what happened.
 *
 * @typedef {object} AlertReport
 * @property {ServerRef} server
 * @property {import('../domain/scoring.js').Verdict} verdict
 * @property {import('../domain/policy.js').Decision} decision
 * @property {number} riskThreshold
 * @property {string} [failureNote]  set when an action was attempted and failed
 *
 * @typedef {object} Notifier
 * @property {boolean} enabled
 * @property {(report: AlertReport) => Promise<boolean>} sendAlert
 * @property {(notice: {title: string, body: string, level: string}) => Promise<boolean>} sendNotice
 */

/**
 * Reports the WHOLE cycle to a central panel, including servers that came back
 * clean.
 *
 * Why this is separate from Notifier: a notifier tells humans about something
 * worth reading and deliberately stays quiet otherwise. A reporter is
 * telemetry. "97 scanned, nothing found" is worthless as a message and
 * essential as a record, because it is the only thing that distinguishes a
 * healthy quiet node from an agent that died. Overloading sendAlert would have
 * meant one of those two jobs done badly.
 *
 * CONTRACT - all implementations must honour this:
 *   - Never throw. The panel is optional infrastructure; a reporting failure
 *     must never abort a scan or stop enforcement.
 *   - Return the commands the panel wants run, or an empty array.
 *
 * @typedef {object} CycleEntry
 * @property {ServerRef} server
 * @property {import('../domain/scoring.js').Verdict} verdict
 * @property {import('../domain/policy.js').Decision} decision
 * @property {{performed: string, success: boolean, failureNote?: string}|null} action
 *   What was actually done, which may differ from what was decided.
 *
 * @typedef {object} CycleReport
 * @property {number} startedAtMs
 * @property {number} finishedAtMs
 * @property {number} scanned
 * @property {number} flagged
 * @property {number} actions
 * @property {number} riskThreshold   in force for this cycle, so the panel can
 *   show a score in the context it was judged against
 * @property {CycleEntry[]} entries
 *   Only servers that produced evidence or were acted on. Clean servers are
 *   counted in `scanned` and never listed: a row per clean server per cycle
 *   would dominate the panel's database and say nothing.
 *
 * @typedef {object} PanelCommand
 * @property {number} id
 * @property {string} type            "rescan_now" | "sync_config"
 * @property {any} payload
 *
 * @typedef {object} CycleReporter
 * @property {boolean} enabled
 * @property {(report: CycleReport) => Promise<PanelCommand[]>} reportCycle
 */

/**
 * Actually does something to a server.
 *
 * Split into separate methods rather than one `act(level)` so that a partial
 * implementation is honest: an adapter that can suspend but cannot throttle
 * simply reports throttling as unsupported instead of silently doing nothing.
 *
 * @typedef {object} Enforcer
 * @property {(server: ServerRef) => Promise<void>} suspend
 * @property {(server: ServerRef, cpuPercent: number) => Promise<void>} throttle
 * @property {(level: string) => boolean} supports
 */

/**
 * Time, injected rather than read from the global clock, so tests are
 * deterministic and do not have to wait.
 *
 * @typedef {object} Clock
 * @property {() => number} nowMs
 * @property {(ms: number) => Promise<void>} sleep
 */

/**
 * @typedef {object} Logger
 * @property {(...args: any[]) => void} error
 * @property {(...args: any[]) => void} warn
 * @property {(...args: any[]) => void} info
 * @property {(...args: any[]) => void} debug
 */

export {};
