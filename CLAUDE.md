# CLAUDE.md

Context for Claude Code working in this repository. Read this fully before the
first edit.

---

## What this is

X-Rae is an abuse-detection agent for Pterodactyl game-hosting nodes. It scans
tenant volumes, watches CPU and per-container network activity, scores what it
finds, and can alert, throttle or suspend a server.

**It runs privileged on machines that host attacker-controlled workloads, and it
can take paying customers offline.** Every design decision in this repo follows
from those two facts. When a change would trade safety for capability, the
answer is no unless the user explicitly asks for it and understands the cost.

Zero npm dependencies. No build step. Node >= 20.

---

## Commands

```bash
npm test                                  # 77 tests, ~0.5s, no network needed
node --test test/architecture.test.mjs    # layer rules only
node bin/xrae --help
node bin/xrae doctor  --config <path>     # validates config, creds, permissions
node bin/xrae scan    --config <path> --dry-run --verbose
node bin/xrae explain <server-identifier> --config <path>
node bin/xrae notify-test --config <path>  # sends one test notice to the webhook
```

Always run `npm test` before reporting a task complete. It is fast and there is
no excuse for skipping it.

Windows dev: use `--config config.dev.json` (local fixtures under `dev/`).
POSIX permission checks are skipped on win32 (`checkFilePermissions`), and 3
tests skip honestly (symlink creation and mode bits need Linux). Full fidelity
lives in WSL or on a real node; the suite must be fully green on Linux.

---

## THE ONE RULE

```
domain/  ←  application/  ←  infrastructure/  ←  cli/
                 "may import" points left
```

| Layer | May import | Notes |
|---|---|---|
| `src/domain/` | **only `src/domain/`** | No `node:fs`, no `node:crypto`, no npm, nothing. Pure functions and data. |
| `src/application/` | `domain/` + `application/` | Reaches the outside world only through `application/ports.js`. |
| `src/infrastructure/` | anything | Implements the ports. |
| `src/cli/`, `src/config/` | anything | |
| `src/composition-root.js` | anything | The **only** file that picks concrete classes. |

`test/architecture.test.mjs` parses real import statements and fails the build on
violation. It is not decoration.

**If that test fails, fix the import — do not edit the test.** The test failing
means the design went wrong, not that the rule is inconvenient. If a use case
seems to need `node:fs`, it needs a new port instead.

---

## Non-negotiable constraints

| Constraint | Enforced by | Why |
|---|---|---|
| Zero npm dependencies | architecture test | A privileged agent with no supply chain cannot be backdoored through one. |
| Domain layer is pure | architecture test | Makes the scoring and policy logic exhaustively testable and reviewable. |
| Every rule has a real `fpProfile` | `validateRulePack` + test | If you cannot say when a rule is wrong, you do not understand it yet. |
| `xrae.env.example` matches the code | architecture test | Docs nothing verifies are docs that go stale. |
| No `child_process`, no `eval` | code review | The agent reads hostile files as a privileged user. It must never execute. |
| Default `policy.mode` is `observe` | config defaults | Rule weights are uncalibrated. See "Current state". |
| Secrets never in `config.json` | `xrae init`, doctor | `config.json` is the file operators paste into support threads. |

---

## The safety model, in one paragraph

A false negative costs a few cents of stolen CPU and gets caught next cycle. A
false positive costs a customer, a refund and a bad review — roughly a 1000:1
cost ratio. Worse, a tenant who can *trigger* false positives on demand holds a
fleet-wide denial-of-service primitive: plant a trigger, get neighbours
suspended. **Detection precision is therefore a security control, not a quality
metric,** and this codebase always fails toward doing nothing.

Concretely, that is why:
- evidence from one family is discounted to 0.45x (corroboration required),
- scores decay (so noise cannot accumulate its way to a suspension),
- action requires N consecutive cycles,
- more than 25% of a node tripping at once halts all enforcement,
- `--dry-run` swaps in `NoopEnforcer` so acting is *impossible*, not merely
  forbidden.

---

## Where things live

```
src/domain/          confidence, evidence, scoring, policy, rules   (pure)
src/application/     ports.js, collect-evidence.js, run-scan-cycle.js
src/infrastructure/  http/ panel/ filesystem/ collectors/ notification/
                     persistence/ system/
src/config/          config.js (load + validate), env-file.js
src/cli/             main.js (arg parsing), commands.js (init/doctor/scan/explain)
src/composition-root.js
test/                architecture, domain, infrastructure, integration
```

Read `src/composition-root.js` early. It wires everything top to bottom with no
framework and no magic; it is the fastest way to understand the system.

---

## Common tasks

**Add a detection rule** → one data entry in `src/domain/rules.js`. Fill in
`fpProfile`. Only set `standalone: true` if there is no legitimate reason for a
game server to contain it (a `stratum+tcp://` URL qualifies; the string `xmrig`
does not — it appears in blocklists and security tools).

**Add an evidence source** → new collector in
`src/infrastructure/collectors/`, honour the `EvidenceCollector` contract
(return an array, empty when unavailable, never throw), register it in the
composition root. Nothing in `domain/` or `application/` changes.

**Add CPU throttling (R2)** → write `WingsEnforcer` implementing the `Enforcer`
port with `supports('throttle') === true`, swap one line in the composition
root. The domain already models `ResponseLevel.THROTTLE`.

**Swap Discord for Slack** → new notifier + builder, one line in the composition
root.

---

## Regressions that look like improvements

These are the changes most likely to seem helpful and be actively harmful. Do
not make them without the user explicitly asking, and push back when asked.

1. **Adding an npm package** ("just use `yaml`/`dotenv`/`zod`"). The zero-dep
   property is a security control. Config comments are handled by a 40-line
   comment stripper; env files by `src/config/env-file.js`.

2. **Editing or deleting `test/architecture.test.mjs`** to make a build pass.

3. **Broadening rules to "catch more"** — `curl`, `wget`, `python`, `bash`,
   `gcc`, `nmap`, `tcpdump`. These were deliberately deleted. They match most
   legitimate Linux game images: they detect *a computer*, not an attacker, and
   they are exactly what makes the detector weaponizable.

4. **Re-adding ports 7777, 8080, 8888, 6666, 9999, 8008** to
   `MINER_POOL_PORTS`. 7777 is Terraria/ARK/Unturned/Satisfactory. 8080 is every
   web panel. Only non-colliding pool ports belong there.

5. **Lowering `consecutiveDetections`, raising `anomalyAbortRatio`, or raising
   `maxActionsPerCycle`** to make detection "more responsive". Those numbers are
   the anti-cascade guardrails.

6. **Changing the default `policy.mode` to anything but `observe`.**

7. **Removing the signature flood guard** because it "suppresses real
   detections". A file matching 8+ different rules is a blocklist, a log or a
   security tool. Without the guard, X-Rae flags its own rule pack.

8. **Reading only the head of a file for speed.** The original SonarX read 16 KiB
   of head and tail; padding a payload into the middle defeated it entirely.
   Full-file chunked scanning with 4 KiB overlap is affordable because unchanged
   files are served from the fingerprint cache.

9. **`stat()` on a path before `open()`.** That is a TOCTOU race — a tenant can
   swap the file for a symlink in between. Always `open()` with `O_NOFOLLOW |
   O_NONBLOCK` and `fstat()` the descriptor.

10. **Following symlinks "to scan more thoroughly".** A symlink to `/etc` in a
    tenant volume plus a privileged reader is a container escape.

11. **Reading host-wide `/proc/net/tcp`.** This was the worst bug in the
    original: one tenant's connection raised every other tenant's score. Network
    evidence must be attributed per container namespace via
    `container-resolver.js`, or it is not evidence at all.

12. **Requiring mode `0600` on the credentials file.** The service runs as the
    unprivileged `xrae` user and must be able to read it. Correct is
    `0640 root:xrae` — readable by the service, writable only by root. Reject
    world access and group-write; allow group-read.

13. **Putting credentials back in `config.json` "for simplicity".**

---

## Repo-specific traps

- **systemd `EnvironmentFile` is not a shell script.** `export FOO=bar` sets a
  variable literally named `export FOO`; there is no variable expansion; a
  trailing `# comment` becomes part of the value. A test guards
  `xrae.env.example` against this.

- **Discord Components V2**: flag is `1 << 15` (32768); webhook execution needs
  `?with_components=true`; `content` and `embeds` are forbidden once the flag is
  set; webhooks cannot receive interactions so buttons must be link style 5.
  Server names are tenant-controlled — always sanitise, always send
  `allowed_mentions: { parse: [] }`.

- **`StateRepository.set()` merges, it does not replace.** Different components
  own different fields (the CPU collector owns `cpuSamples`). Never write a
  field you do not own.

- **Two-phase cycle.** `run-scan-cycle.js` assesses every server before acting on
  any. Do not "simplify" it into one loop — the fleet-anomaly guardrail is only
  computable once all servers have been assessed.

- **Test files must be named `*.test.mjs`.** The runner globs on that. If files
  arrive flattened or renamed (e.g. `architecture_test.mjs`), the suite silently
  does not run and the layer rules stop being enforced.

---

## Current state and open work

- 40 files, ~4.8k lines. Run `npm test` for the current suite - it must be green.
- **R-09 is open: all rule weights are educated guesses, not calibrated.** There
  is no labelled corpus yet. This is why `observe` is the default and why nobody
  should enable `enforce` on the strength of these numbers.
- Enforcement gate before `enforce` mode is ever enabled: a red-team exercise
  where an engineer is given a tenant volume and the task "get another tenant
  suspended". If they succeed, the design is not ready.
- The process collector (`collectors/process-collector.js`) reads
  `/proc/<pid>/cmdline` and the exe target to catch a running miner that evaded
  the on-disk scan (packed binary, pool URL in argv, TLS on 443). Its evidence
  is the BEHAVIOR family; the family cap lifted 30 -> 40 so a corroborated
  CRITICAL miner can cross the threshold. Single-family behavior still cannot
  self-suspend. See the regression tests in domain.test.mjs.
- `WingsEnforcer` for CPU throttling is the highest-value next feature.
- W^X (`MemoryDenyWriteExecute`) is off in the systemd unit: V8's JIT and
  undici's WASM HTTP parser both need W+X pages. To earn it back, swap the
  http client's `fetch` transport for `node:https` first, then re-add the
  directive - never re-add it alone, the service core-dumps on boot.
- Longer term: split-plane architecture, moving the panel admin key off the node
  entirely (a compromised node currently yields full panel control). The port
  boundaries are already shaped for this.

---

## Style

- Comments explain **why**, not what. Several files carry a header block
  explaining the threat they defend against — keep those current when editing.
- Intention-revealing names, no abbreviations, small functions.
- JSDoc types, checked by `jsconfig.json` (`checkJs: true`). No TypeScript.
- Prefer deleting a bad rule over down-weighting it. Weight zero times many
  rules still accumulates.
- If a change cannot be explained to a customer whose server it would suspend,
  it does not belong in this repo.
