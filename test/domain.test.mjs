// Domain tests.
//
// Notice what is missing: no temp directories, no mock HTTP server, no waiting.
// The domain is pure, so these tests are instant and never flaky. That is the
// practical reward for keeping I/O out of it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { Confidence, isAtLeast, capAt, highestOf } from '../src/domain/confidence.js';
import { createEvidence, EvidenceFamily } from '../src/domain/evidence.js';
import { ScoreCalculator, decay } from '../src/domain/scoring.js';
import { EnforcementPolicy, PolicyMode, ResponseLevel } from '../src/domain/policy.js';
import { RULE_PACK, validateRulePack } from '../src/domain/rules.js';

const NOW = 1_700_000_000_000;
const HOUR = 3_600_000;

/** Small helper so the tests read like sentences. */
function evidence(family, weight, confidence = Confidence.MEDIUM, standalone = false) {
  return createEvidence({
    ruleId: `test.${family}.${weight}`,
    family,
    category: 'TEST',
    weight,
    confidence,
    standalone,
    detail: 'test evidence',
  });
}

const noHistory = { score: 0, updatedAtMs: 0, detections: 0 };

describe('confidence', () => {
  test('orders levels correctly', () => {
    assert.ok(isAtLeast(Confidence.CRITICAL, Confidence.LOW));
    assert.ok(isAtLeast(Confidence.MEDIUM, Confidence.MEDIUM));
    assert.ok(!isAtLeast(Confidence.LOW, Confidence.HIGH));
  });

  test('caps and picks the highest', () => {
    assert.equal(capAt(Confidence.CRITICAL, Confidence.MEDIUM), Confidence.MEDIUM);
    assert.equal(capAt(Confidence.LOW, Confidence.HIGH), Confidence.LOW);
    assert.equal(highestOf([Confidence.LOW, Confidence.HIGH, Confidence.MEDIUM]), Confidence.HIGH);
  });

  test('rejects a typo instead of silently misbehaving', () => {
    assert.throws(() => isAtLeast('hihg', Confidence.LOW), /Unknown confidence/);
  });
});

describe('evidence', () => {
  test('refuses to be constructed badly', () => {
    assert.throws(() => evidence('not-a-family', 10), /unknown family/);
    assert.throws(() => createEvidence({ ruleId: 'x', family: EvidenceFamily.SIGNATURE, weight: NaN, confidence: Confidence.LOW }), /invalid weight/);
    assert.throws(() => createEvidence({ ruleId: 'x', family: EvidenceFamily.SIGNATURE, weight: 5, confidence: 'nope' }), /invalid confidence/);
  });
});

describe('score decay', () => {
  test('halves after one half-life', () => {
    assert.equal(Math.round(decay(100, NOW - 24 * HOUR, 24, NOW)), 50);
    assert.equal(Math.round(decay(100, NOW - 48 * HOUR, 24, NOW)), 25);
  });

  test('reaches zero eventually, so noise cannot accumulate forever', () => {
    assert.equal(decay(100, NOW - 30 * 24 * HOUR, 24, NOW), 0);
  });

  test('leaves a fresh score untouched', () => {
    assert.equal(decay(100, NOW, 24, NOW), 100);
  });
});

describe('scoring', () => {
  const calculator = new ScoreCalculator({ halfLifeHours: 24 });

  test('a clean server scores nothing', () => {
    const verdict = calculator.calculate({ evidence: [], previous: noHistory, nowMs: NOW });
    assert.equal(verdict.cycleScore, 0);
    assert.equal(verdict.detections, 0);
  });

  test('one weak family alone cannot reach the threshold', () => {
    // This is the core false-positive protection. Two medium signature hits
    // must not be enough to suspend anybody.
    const verdict = calculator.calculate({
      evidence: [evidence(EvidenceFamily.SIGNATURE, 20), evidence(EvidenceFamily.SIGNATURE, 18)],
      previous: noHistory,
      nowMs: NOW,
    });
    assert.ok(verdict.cycleScore < 100, `expected under 100, got ${verdict.cycleScore}`);
    assert.equal(verdict.confidence, Confidence.MEDIUM, 'one family cannot claim more than medium');
  });

  test('the same rule in many files counts once', () => {
    const repeated = Array.from({ length: 20 }, () => evidence(EvidenceFamily.SIGNATURE, 45, Confidence.HIGH));
    const verdict = calculator.calculate({ evidence: repeated, previous: noHistory, nowMs: NOW });

    assert.equal(verdict.reasons.length, 1, 'twenty matches of one rule is one fact');
    assert.ok(verdict.cycleScore < 100);
    assert.match(verdict.reasons[0].detail, /\+19 more/);
  });

  test('a family cannot exceed its cap', () => {
    const many = [
      evidence(EvidenceFamily.SIGNATURE, 45, Confidence.HIGH),
      createEvidence({ ruleId: 'a', family: EvidenceFamily.SIGNATURE, category: 'T', weight: 45, confidence: Confidence.HIGH }),
      createEvidence({ ruleId: 'b', family: EvidenceFamily.SIGNATURE, category: 'T', weight: 45, confidence: Confidence.HIGH }),
      createEvidence({ ruleId: 'c', family: EvidenceFamily.SIGNATURE, category: 'T', weight: 45, confidence: Confidence.HIGH }),
    ];
    const verdict = calculator.calculate({ evidence: many, previous: noHistory, nowMs: NOW });
    // 4 x 45 = 180 raw, capped to 80, then x0.45 for one family = 36.
    assert.equal(verdict.cycleScore, 36);
  });

  test('three independent families escalate to critical', () => {
    const verdict = calculator.calculate({
      evidence: [
        evidence(EvidenceFamily.SIGNATURE, 45, Confidence.HIGH),
        evidence(EvidenceFamily.ENTROPY, 20, Confidence.LOW),
        evidence(EvidenceFamily.BEHAVIOR, 28),
        evidence(EvidenceFamily.NETWORK, 25),
      ],
      previous: noHistory,
      nowMs: NOW,
    });
    assert.ok(verdict.totalScore >= 100, `expected 100 or more, got ${verdict.totalScore}`);
    assert.equal(verdict.confidence, Confidence.CRITICAL);
    assert.equal(verdict.families.length, 4);
  });

  test('a corroborated live miner crosses the threshold and is suspendable', () => {
    // Regression guard for the real incident: a running xmrig (behavior,
    // standalone CRITICAL) corroborated by a pool signature on disk and a
    // packed binary must score high enough to act on, not stall below 100.
    const verdict = calculator.calculate({
      evidence: [
        evidence(EvidenceFamily.BEHAVIOR, 55, Confidence.CRITICAL, true),  // --donate-level
        evidence(EvidenceFamily.SIGNATURE, 40, Confidence.HIGH),           // supportxmr in a config
        evidence(EvidenceFamily.ENTROPY, 20, Confidence.MEDIUM),           // packed binary
      ],
      previous: noHistory,
      nowMs: NOW,
    });
    assert.ok(verdict.totalScore >= 100, `a corroborated miner must be suspendable, got ${verdict.totalScore}`);
    assert.equal(verdict.confidence, Confidence.CRITICAL);
    assert.ok(verdict.hasStandalone);
  });

  test('a live miner that left no disk trace still alerts but does not self-suspend', () => {
    // Fully evasive case: behavior family only. Capped below the threshold, so
    // no auto-suspend - but standalone CRITICAL keeps it reportable.
    const verdict = calculator.calculate({
      evidence: [evidence(EvidenceFamily.BEHAVIOR, 55, Confidence.CRITICAL, true)],
      previous: noHistory,
      nowMs: NOW,
    });
    assert.ok(verdict.totalScore < 100, 'a single family must not reach the suspend threshold alone');
    assert.equal(verdict.confidence, Confidence.CRITICAL);
    assert.ok(verdict.hasStandalone, 'but it is still reportable, so an alert fires');
  });

  test('an unambiguous indicator is not discounted', () => {
    const verdict = calculator.calculate({
      evidence: [evidence(EvidenceFamily.SIGNATURE, 55, Confidence.CRITICAL, true)],
      previous: noHistory,
      nowMs: NOW,
    });
    assert.equal(verdict.cycleScore, 55, 'standalone evidence keeps its full weight');
    assert.equal(verdict.confidence, Confidence.CRITICAL);
    assert.ok(verdict.hasStandalone);
  });

  test('persistence is counted across cycles', () => {
    const first = calculator.calculate({
      evidence: [evidence(EvidenceFamily.SIGNATURE, 30)],
      previous: noHistory,
      nowMs: NOW,
    });
    assert.equal(first.detections, 1);

    const second = calculator.calculate({
      evidence: [evidence(EvidenceFamily.SIGNATURE, 30)],
      previous: { score: first.totalScore, updatedAtMs: NOW, detections: first.detections },
      nowMs: NOW,
    });
    assert.equal(second.detections, 2);
    assert.ok(second.totalScore > first.totalScore, 'repeated findings accumulate');
  });

  test('a clean cycle resets the persistence counter', () => {
    const verdict = calculator.calculate({
      evidence: [],
      previous: { score: 90, updatedAtMs: NOW, detections: 5 },
      nowMs: NOW,
    });
    assert.equal(verdict.detections, 0);
  });
});

describe('enforcement policy', () => {
  const basePolicy = {
    mode: PolicyMode.ENFORCE,
    riskThreshold: 100,
    minConfidenceToAlert: Confidence.MEDIUM,
    minConfidenceToThrottle: Confidence.HIGH,
    minConfidenceToSuspend: Confidence.CRITICAL,
    consecutiveDetections: 2,
    maxActionsPerCycle: 3,
    anomalyAbortRatio: 0.25,
    renotifyCooldownMinutes: 120,
    ignoredServers: [],
  };

  const guilty = {
    totalScore: 200,
    cycleScore: 200,
    confidence: Confidence.CRITICAL,
    hasStandalone: true,
    detections: 3,
    families: ['signature', 'behavior', 'network'],
    reasons: [],
  };

  const calmCycle = { serversAssessed: 50, serversOverThreshold: 1, actionsTaken: 0 };

  function decide(policyOverrides, verdict = guilty, cycleStats = calmCycle, previous = {}) {
    const policy = new EnforcementPolicy({ ...basePolicy, ...policyOverrides });
    return policy.decide({ verdict, previous, cycleStats, serverId: 'abc123', nowMs: NOW });
  }

  test('observe mode never acts, no matter how bad it looks', () => {
    assert.equal(decide({ mode: PolicyMode.OBSERVE }).level, ResponseLevel.OBSERVE);
  });

  test('alert mode never acts either', () => {
    assert.equal(decide({ mode: PolicyMode.ALERT }).level, ResponseLevel.ALERT);
  });

  test('throttle mode stops short of suspending', () => {
    assert.equal(decide({ mode: PolicyMode.THROTTLE }).level, ResponseLevel.THROTTLE);
  });

  test('enforce mode suspends a clear, persistent case', () => {
    assert.equal(decide({}).level, ResponseLevel.SUSPEND);
  });

  test('one bad cycle is not enough', () => {
    const oneCycle = { ...guilty, detections: 1 };
    const outcome = decide({}, oneCycle);
    assert.equal(outcome.level, ResponseLevel.ALERT);
    assert.match(outcome.reason, /consecutive cycles/);
  });

  test('a fleet-wide trip halts everything', () => {
    // 30 of 40 servers flagged at once means the detector is wrong, not that
    // three quarters of customers started mining simultaneously.
    const outcome = decide({}, guilty, { serversAssessed: 40, serversOverThreshold: 30, actionsTaken: 0 });
    assert.equal(outcome.level, ResponseLevel.BLOCKED);
    assert.match(outcome.reason, /detector is faulty/);
  });

  test('the per-cycle action budget is respected', () => {
    const outcome = decide({}, guilty, { serversAssessed: 40, serversOverThreshold: 2, actionsTaken: 3 });
    assert.equal(outcome.level, ResponseLevel.BLOCKED);
    assert.match(outcome.reason, /per-cycle action limit/);
  });

  test('the ignore list wins over everything', () => {
    assert.equal(decide({ ignoredServers: ['abc123'] }).level, ResponseLevel.NONE);
  });

  test('a recently reported server stays quiet', () => {
    const outcome = decide({}, guilty, calmCycle, { lastNotifiedAtMs: NOW - 10 * 60_000 });
    assert.equal(outcome.level, ResponseLevel.NONE);
  });

  test('low confidence is reported to nobody', () => {
    const weak = { ...guilty, confidence: Confidence.LOW, hasStandalone: false };
    assert.equal(decide({}, weak).level, ResponseLevel.NONE);
  });

  test('an unambiguous finding is reported even below the score threshold', () => {
    const belowThreshold = { ...guilty, totalScore: 55, detections: 1 };
    const outcome = decide({}, belowThreshold);
    assert.notEqual(outcome.level, ResponseLevel.NONE);
  });
});

describe('rule pack', () => {
  test('is valid as shipped', () => {
    assert.doesNotThrow(() => validateRulePack(RULE_PACK));
  });

  test('rejects a rule with no false-positive profile', () => {
    assert.throws(
      () => validateRulePack([{ id: 'x', pattern: 'y', weight: 10, confidence: Confidence.LOW, fpProfile: '' }]),
      /fpProfile is required/,
    );
  });

  test('rejects a standalone rule that is not critical', () => {
    assert.throws(
      () => validateRulePack([{
        id: 'x', pattern: 'y', weight: 10, confidence: Confidence.HIGH,
        standalone: true, fpProfile: 'a long enough explanation',
      }]),
      /must be CRITICAL/,
    );
  });

  test('does not contain the noisy rules we deleted on purpose', () => {
    const banned = ['curl', 'wget', 'python', 'bash', 'perl', 'gcc', 'make', 'nmap', 'tcpdump', 'wireshark'];
    for (const pattern of banned) {
      assert.equal(
        RULE_PACK.some((rule) => rule.pattern === pattern),
        false,
        `"${pattern}" matches most legitimate Linux game servers and must never be a rule`,
      );
    }
  });
});
