import { describe, it, expect } from 'vitest';
import {
  formatPodMatrixTty,
  formatPodMatrixJson,
} from '../../src/formatters/pod_matrix.js';
import type { PodReachabilityResult } from '../../src/reachability/pod_evaluator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResult(
  fromName: string,
  fromNs: string,
  toName: string,
  toNs: string,
  allowed: boolean,
  reason: string,
): PodReachabilityResult {
  return {
    from: { name: fromName, namespace: fromNs, kind: 'Deployment', labels: {} },
    to: { name: toName, namespace: toNs, kind: 'Deployment', labels: {} },
    allowed,
    reason,
  };
}

// ---------------------------------------------------------------------------
// formatPodMatrixTty
// ---------------------------------------------------------------------------

describe('formatPodMatrixTty', () => {
  it('returns message when no results', () => {
    const output = formatPodMatrixTty([]);
    expect(output).toBe('No workloads found — nothing to display.');
  });

  it('shows workload names in output', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'frontend', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('web');
    expect(output).toContain('api');
    expect(output).toContain('frontend');
  });

  it('shows ALLOW for allowed entries', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'frontend', true, 'policy-allow'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('ALLOW');
  });

  it('shows DENY for denied entries', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'frontend', false, 'policy-deny'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('DENY');
  });

  it('includes summary with allowed/denied counts', () => {
    const results = [
      makeResult('web', 'ns', 'api', 'ns', true, 'no-policy'),
      makeResult('api', 'ns', 'web', 'ns', false, 'policy-deny'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('Summary: 1 allowed, 1 denied');
  });

  it('shows reason breakdown', () => {
    const results = [
      makeResult('web', 'ns', 'api', 'ns', true, 'no-policy'),
      makeResult('api', 'ns', 'web', 'ns', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('no-policy: 2');
  });

  it('namespace filter: only shows pairs involving the namespace', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'backend', true, 'policy-allow'),
      makeResult('db', 'database', 'cache', 'cache-ns', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results, { namespace: 'frontend' });
    expect(output).toContain('web');
    expect(output).not.toContain('db');
    expect(output).not.toContain('cache');
  });

  it('namespace filter returns message when no matches', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'backend', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results, { namespace: 'nonexistent' });
    expect(output).toContain('No reachability data for namespace "nonexistent"');
  });

  it('includes header row with FROM \\ TO', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'frontend', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('FROM \\ TO');
  });

  it('handles multiple workloads correctly', () => {
    const results = [
      makeResult('a', 'ns', 'b', 'ns', true, 'no-policy'),
      makeResult('a', 'ns', 'c', 'ns', false, 'policy-deny'),
      makeResult('b', 'ns', 'a', 'ns', true, 'no-policy'),
      makeResult('b', 'ns', 'c', 'ns', false, 'policy-deny'),
      makeResult('c', 'ns', 'a', 'ns', true, 'no-policy'),
      makeResult('c', 'ns', 'b', 'ns', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('Summary: 4 allowed, 2 denied');
  });

  it('displays workload labels as namespace/kind/name', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'frontend', true, 'no-policy'),
    ];
    const output = formatPodMatrixTty(results);
    expect(output).toContain('frontend/Deployment/web');
    expect(output).toContain('frontend/Deployment/api');
  });
});

// ---------------------------------------------------------------------------
// formatPodMatrixJson
// ---------------------------------------------------------------------------

describe('formatPodMatrixJson', () => {
  it('returns valid JSON string', () => {
    const results = [
      makeResult('web', 'ns', 'api', 'ns', true, 'no-policy'),
    ];
    const output = formatPodMatrixJson(results);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('JSON has type field "pod-reachability"', () => {
    const results = [makeResult('web', 'ns', 'api', 'ns', true, 'no-policy')];
    const parsed = JSON.parse(formatPodMatrixJson(results));
    expect(parsed.type).toBe('pod-reachability');
  });

  it('JSON has results array with correct structure', () => {
    const results = [
      makeResult('web', 'frontend', 'api', 'frontend', true, 'policy-allow'),
    ];
    const parsed = JSON.parse(formatPodMatrixJson(results));
    expect(parsed.results).toHaveLength(1);
    expect(parsed.results[0].from.name).toBe('web');
    expect(parsed.results[0].to.name).toBe('api');
    expect(parsed.results[0].allowed).toBe(true);
    expect(parsed.results[0].reason).toBe('policy-allow');
  });

  it('JSON has summary with total/allowed/denied counts', () => {
    const results = [
      makeResult('web', 'ns', 'api', 'ns', true, 'no-policy'),
      makeResult('api', 'ns', 'web', 'ns', false, 'policy-deny'),
    ];
    const parsed = JSON.parse(formatPodMatrixJson(results));
    expect(parsed.summary.total).toBe(2);
    expect(parsed.summary.allowed).toBe(1);
    expect(parsed.summary.denied).toBe(1);
  });

  it('JSON summary includes byReason breakdown', () => {
    const results = [
      makeResult('a', 'ns', 'b', 'ns', true, 'no-policy'),
      makeResult('b', 'ns', 'a', 'ns', true, 'no-policy'),
      makeResult('c', 'ns', 'a', 'ns', false, 'policy-deny'),
    ];
    const parsed = JSON.parse(formatPodMatrixJson(results));
    expect(parsed.summary.byReason['no-policy']).toBe(2);
    expect(parsed.summary.byReason['policy-deny']).toBe(1);
  });

  it('JSON result includes WorkloadInfo fields', () => {
    const r: PodReachabilityResult = {
      from: { name: 'web', namespace: 'frontend', kind: 'Deployment', labels: { app: 'web' } },
      to: { name: 'api', namespace: 'backend', kind: 'StatefulSet', labels: { app: 'api' } },
      allowed: false,
      reason: 'policy-deny',
    };
    const parsed = JSON.parse(formatPodMatrixJson([r]));
    const result = parsed.results[0];
    expect(result.from.kind).toBe('Deployment');
    expect(result.from.labels).toEqual({ app: 'web' });
    expect(result.to.kind).toBe('StatefulSet');
    expect(result.to.namespace).toBe('backend');
  });

  it('returns correct structure for empty results', () => {
    const parsed = JSON.parse(formatPodMatrixJson([]));
    expect(parsed.type).toBe('pod-reachability');
    expect(parsed.results).toHaveLength(0);
    expect(parsed.summary.total).toBe(0);
    expect(parsed.summary.allowed).toBe(0);
    expect(parsed.summary.denied).toBe(0);
  });
});
