import { describe, it, expect } from 'vitest';
import { benchmarkRules, formatTimings } from '../../src/perf/benchmark.js';
import { allRules } from '../../src/rules/engine.js';
import type { ParsedResource } from '../../src/types.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeNetworkPolicy(name: string, ns = 'default'): ParsedResource {
  return {
    kind: 'NetworkPolicy',
    apiVersion: 'networking.k8s.io/v1',
    metadata: { name, namespace: ns },
    spec: {
      podSelector: {},
      ingress: [{ from: [{}] }],
    },
    file: 'test.yaml',
    line: 1,
  };
}

// ─── benchmarkRules ───────────────────────────────────────────────────────────

describe('benchmarkRules', () => {
  it('returns a findings array', () => {
    const resources = [makeNetworkPolicy('test')];
    const result = benchmarkRules(resources, allRules);
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('returns a timings array with one entry per rule', () => {
    const resources = [makeNetworkPolicy('test')];
    const subset = allRules.slice(0, 5);
    const result = benchmarkRules(resources, subset);
    expect(result.timings).toHaveLength(5);
  });

  it('each timing entry has ruleId, durationMs, and findingCount', () => {
    const resources = [makeNetworkPolicy('test')];
    const subset = allRules.slice(0, 3);
    const result = benchmarkRules(resources, subset);
    for (const t of result.timings) {
      expect(typeof t.ruleId).toBe('string');
      expect(t.ruleId.length).toBeGreaterThan(0);
      expect(typeof t.durationMs).toBe('number');
      expect(t.durationMs).toBeGreaterThanOrEqual(0);
      expect(typeof t.findingCount).toBe('number');
      expect(t.findingCount).toBeGreaterThanOrEqual(0);
    }
  });

  it('totalDurationMs is a non-negative number', () => {
    const resources = [makeNetworkPolicy('test')];
    const result = benchmarkRules(resources, allRules);
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('finding count in timings sums to total findings length', () => {
    const resources = [makeNetworkPolicy('test')];
    const subset = allRules.slice(0, 10);
    const result = benchmarkRules(resources, subset);
    const sumFromTimings = result.timings.reduce((s, t) => s + t.findingCount, 0);
    expect(sumFromTimings).toBe(result.findings.length);
  });

  it('works with an empty resource list', () => {
    const result = benchmarkRules([], allRules);
    expect(result.findings).toEqual([]);
    expect(result.timings).toHaveLength(allRules.length);
  });

  it('works with an empty rules list', () => {
    const resources = [makeNetworkPolicy('test')];
    const result = benchmarkRules(resources, []);
    expect(result.findings).toEqual([]);
    expect(result.timings).toHaveLength(0);
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('timing ruleIds match the rule IDs from the rules array', () => {
    const subset = allRules.slice(0, 5);
    const result = benchmarkRules([], subset);
    const timingIds = result.timings.map((t) => t.ruleId);
    const ruleIds = subset.map((r) => r.id);
    expect(timingIds).toEqual(ruleIds);
  });

  it('returns more findings than zero for a wildcard NetworkPolicy', () => {
    const resources = [makeNetworkPolicy('wildcard-test')];
    const result = benchmarkRules(resources, allRules);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('NW1001 timing has findingCount >= 1 for wildcard-ingress policy', () => {
    const resources = [makeNetworkPolicy('wildcard')];
    const nw1001 = allRules.filter((r) => r.id === 'NW1001');
    const result = benchmarkRules(resources, nw1001);
    const t = result.timings.find((t) => t.ruleId === 'NW1001');
    expect(t).toBeDefined();
    expect(t!.findingCount).toBeGreaterThanOrEqual(1);
  });
});

// ─── formatTimings ────────────────────────────────────────────────────────────

describe('formatTimings', () => {
  it('returns empty string for empty timings array', () => {
    expect(formatTimings([], 0)).toBe('');
  });

  it('includes rule IDs in the output', () => {
    const timings = [{ ruleId: 'NW1001', durationMs: 1.5, findingCount: 2 }];
    const out = formatTimings(timings, 10);
    expect(out).toContain('NW1001');
  });

  it('includes the total duration', () => {
    const timings = [{ ruleId: 'NW1001', durationMs: 1.5, findingCount: 2 }];
    const out = formatTimings(timings, 42.7);
    expect(out).toContain('42.70ms');
  });

  it('includes finding count', () => {
    const timings = [{ ruleId: 'NW2001', durationMs: 0.1, findingCount: 7 }];
    const out = formatTimings(timings, 5);
    expect(out).toContain('7');
  });

  it('sorts by duration descending (slowest rule first)', () => {
    const timings = [
      { ruleId: 'FAST', durationMs: 0.1, findingCount: 0 },
      { ruleId: 'SLOW', durationMs: 99.9, findingCount: 0 },
    ];
    const out = formatTimings(timings, 100);
    const slowIdx = out.indexOf('SLOW');
    const fastIdx = out.indexOf('FAST');
    expect(slowIdx).toBeLessThan(fastIdx);
  });
});
