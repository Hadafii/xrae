import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ScoreCalculator, CORROBORATION_MULTIPLIER, PERSISTENCE_CAP } from '../src/domain/scoring.js';
import { EvidenceFamily, createEvidence } from '../src/domain/evidence.js';
import { isBuildArtifactPath } from '../src/infrastructure/filesystem/file-analyzer.js';

/**
 * Every case here is taken from a real production alert on 2026-07-31, where four
 * innocent Minecraft servers were reported as "running or carrying a
 * cryptocurrency miner" at scores of 453 to 1494 against a threshold of 100.
 */

const CYCLE_MS = 15 * 60 * 1000;
const HALF_LIFE_HOURS = 24;

function minerAlgoEvidence() {
  // What actually fired: one weight-20, non-standalone, MEDIUM rule.
  return [
    createEvidence({
      ruleId: 'miner.algo.randomx',
      family: EvidenceFamily.SIGNATURE,
      category: 'MINER',
      weight: 20,
      confidence: 'medium',
      standalone: false,
      detail: 'matched "randomx" in libraries/net/minecraft/server/1.21.11/server-1.21.11-mappings.tsrg',
    }),
  ];
}

/** Replays N cycles of identical evidence, the way a static file is rescanned. */
function replay(calculator, evidence, cycles) {
  let previous = { score: 0, updatedAtMs: 0, detections: 0 };
  let verdict;

  for (let cycle = 0; cycle < cycles; cycle += 1) {
    const nowMs = cycle * CYCLE_MS;

    verdict = calculator.calculate({ evidence, previous, nowMs });
    previous = { score: verdict.totalScore, updatedAtMs: nowMs, detections: verdict.detections };
  }

  return verdict;
}

test('a single weak rule cannot reach the threshold, however long it persists', () => {
  const calculator = new ScoreCalculator({ halfLifeHours: HALF_LIFE_HOURS });

  // 149 cycles is what the production alert reported. It scored 726.
  const after149 = replay(calculator, minerAlgoEvidence(), 149);

  assert.ok(
    after149.totalScore < 100,
    `one weight-20 rule reached ${after149.totalScore}; the threshold is 100`,
  );

  // And it must not creep past it later either: a year of cycles is still safe.
  const afterAYear = replay(calculator, minerAlgoEvidence(), 35_040);

  assert.ok(afterAYear.totalScore < 100, `still climbing: ${afterAYear.totalScore}`);
});

test('the score converges instead of tracking how long we have been looking', () => {
  const calculator = new ScoreCalculator({ halfLifeHours: HALF_LIFE_HOURS });
  const evidence = minerAlgoEvidence();

  const early = replay(calculator, evidence, 10);
  const late = replay(calculator, evidence, 1000);

  // Before the cap, 1000 cycles scored ~139x one cycle. Now the two agree.
  assert.equal(late.totalScore, early.totalScore);
  assert.equal(late.totalScore, late.cycleScore * PERSISTENCE_CAP);
});

test('persistence still counts, it is just bounded', () => {
  const calculator = new ScoreCalculator({ halfLifeHours: HALF_LIFE_HOURS });
  const evidence = minerAlgoEvidence();

  const first = replay(calculator, evidence, 1);
  const settled = replay(calculator, evidence, 50);

  // A finding that will not go away is worth more than one seen once.
  assert.ok(settled.totalScore > first.totalScore);
  assert.equal(settled.totalScore, first.cycleScore * PERSISTENCE_CAP);
});

test('a genuinely corroborated miner still crosses the threshold on the first cycle', () => {
  // The control: the fix must not blind the detector. Three families agreeing is
  // what a real miner looks like.
  const calculator = new ScoreCalculator({ halfLifeHours: HALF_LIFE_HOURS });
  const evidence = [
    createEvidence({
      ruleId: 'miner.xmrig',
      family: EvidenceFamily.SIGNATURE,
      category: 'MINER',
      weight: 60,
      confidence: 'critical',
      standalone: true,
      detail: 'xmrig',
    }),
    createEvidence({
      ruleId: 'miner.pool.supportxmr',
      family: EvidenceFamily.NETWORK,
      category: 'MINER',
      weight: 40,
      confidence: 'high',
      standalone: false,
      detail: 'supportxmr.com',
    }),
    createEvidence({
      ruleId: 'process.miner.bin.xmrig',
      family: EvidenceFamily.BEHAVIOR,
      category: 'MINER',
      weight: 40,
      confidence: 'high',
      standalone: false,
      detail: 'running process xmrig',
    }),
  ];

  const verdict = replay(calculator, evidence, 1);

  assert.ok(verdict.totalScore >= 100, `real miner only scored ${verdict.totalScore}`);
  assert.equal(verdict.families.length, 3);
  assert.equal(verdict.hasStandalone, true);
});

test('a score drops promptly when the corroborating evidence disappears', () => {
  const calculator = new ScoreCalculator({ halfLifeHours: HALF_LIFE_HOURS });
  const strong = [
    createEvidence({
      ruleId: 'miner.xmrig',
      family: EvidenceFamily.SIGNATURE,
      category: 'MINER',
      weight: 60,
      confidence: 'critical',
      standalone: true,
      detail: 'xmrig',
    }),
  ];

  const high = replay(calculator, strong, 20);
  const nowWeak = calculator.calculate({
    evidence: minerAlgoEvidence(),
    previous: { score: high.totalScore, updatedAtMs: 0, detections: 20 },
    nowMs: CYCLE_MS,
  });

  // The cap tracks the CURRENT cycle, so a cleaned server stops looking guilty
  // instead of coasting on history for days.
  assert.ok(nowWeak.totalScore < high.totalScore);
  assert.ok(nowWeak.totalScore < 100);
});

test('the multiplier table still discounts single-family evidence hardest', () => {
  // Guards the constant the whole analysis above rests on.
  assert.equal(CORROBORATION_MULTIPLIER[1], 0.45);
  assert.ok(CORROBORATION_MULTIPLIER[1] < CORROBORATION_MULTIPLIER[2]);
  assert.ok(CORROBORATION_MULTIPLIER[2] < CORROBORATION_MULTIPLIER[3]);
});

test('the exact paths from the production alerts are recognised as build artifacts', () => {
  const realPaths = [
    'plugins/.paper-remapped/mappings/reversed/5028247881868F33795961B8387BB1B13C018B83E4523A7',
    'plugins/.paper-remapped/mappings/reversed/2C6AB97F550526F9E7C363EC5352500AFA558525BEDA078',
    'libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-map',
    'libraries/net/minecraft/server/1.21.11/server-1.21.11-mappings.tsrg',
  ];

  for (const relativePath of realPaths) {
    assert.equal(isBuildArtifactPath(relativePath), true, relativePath);
  }
});

test('customer content is never mistaken for a build artifact', () => {
  // The line that matters: suppressing too much is how a scanner goes blind.
  const customerPaths = [
    'plugins/EssentialsX/config.yml',
    'world/level.dat',
    'xmrig',
    'plugins/evil.jar',
    'mods/coolmod.jar',
    'start.sh',
    'cache/mylibraries/thing.jar',
    'server.properties',
  ];

  for (const relativePath of customerPaths) {
    assert.equal(isBuildArtifactPath(relativePath), false, relativePath);
  }
});

test('build-artifact matching is case and separator insensitive', () => {
  assert.equal(isBuildArtifactPath('Libraries/Net/Minecraft/x-mappings.TSRG'), true);
  assert.equal(isBuildArtifactPath('plugins\\.paper-remapped\\mappings\\reversed\\abc'), true);
});
