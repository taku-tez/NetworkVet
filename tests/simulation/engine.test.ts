import { describe, it, expect } from 'vitest';
import { mergeSimulatedResources, computeSimulationDiff } from '../../src/simulation/engine.js';
import type { ParsedResource } from '../../src/types.js';
import type { PodReachabilityResult } from '../../src/reachability/pod_evaluator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResource(kind: string, name: string, namespace: string | undefined, extra: Partial<ParsedResource> = {}): ParsedResource {
  return {
    kind,
    apiVersion: 'v1',
    metadata: {
      name,
      ...(namespace !== undefined ? { namespace } : {}),
    },
    spec: {},
    file: 'test.yaml',
    line: 1,
    ...extra,
  };
}

function makeWorkloadInfo(name: string, namespace: string) {
  return { name, namespace, kind: 'Deployment', labels: {} };
}

function makePodResult(
  fromName: string,
  fromNs: string,
  toName: string,
  toNs: string,
  allowed: boolean
): PodReachabilityResult {
  return {
    from: makeWorkloadInfo(fromName, fromNs),
    to: makeWorkloadInfo(toName, toNs),
    allowed,
    reason: allowed ? 'policy-allow' : 'policy-deny',
  };
}

// ---------------------------------------------------------------------------
// mergeSimulatedResources
// ---------------------------------------------------------------------------

describe('mergeSimulatedResources — replace existing resource', () => {
  it('replaces a resource with the same kind/namespace/name', () => {
    const existing = [makeResource('NetworkPolicy', 'deny-all', 'default')];
    const simulated = [makeResource('NetworkPolicy', 'deny-all', 'default', { spec: { podSelector: {} } })];

    const merged = mergeSimulatedResources(existing, simulated);
    expect(merged).toHaveLength(1);
    expect(merged[0].spec).toEqual({ podSelector: {} });
  });

  it('replaces only the matching resource, leaves others unchanged', () => {
    const existing = [
      makeResource('NetworkPolicy', 'deny-all', 'default'),
      makeResource('NetworkPolicy', 'allow-ingress', 'default'),
    ];
    const simulated = [makeResource('NetworkPolicy', 'deny-all', 'default', { spec: { replaced: true } as Record<string, unknown> })];

    const merged = mergeSimulatedResources(existing, simulated);
    expect(merged).toHaveLength(2);
    const replaced = merged.find((r) => r.metadata.name === 'deny-all');
    expect((replaced?.spec as Record<string, unknown>).replaced).toBe(true);
    const unchanged = merged.find((r) => r.metadata.name === 'allow-ingress');
    expect(unchanged).toBeDefined();
  });
});

describe('mergeSimulatedResources — append new resource', () => {
  it('appends a resource that does not exist in the existing set', () => {
    const existing = [makeResource('Deployment', 'web', 'default')];
    const simulated = [makeResource('NetworkPolicy', 'new-policy', 'default')];

    const merged = mergeSimulatedResources(existing, simulated);
    expect(merged).toHaveLength(2);
    expect(merged.some((r) => r.kind === 'NetworkPolicy' && r.metadata.name === 'new-policy')).toBe(true);
  });

  it('appends resources with different namespace even if name/kind match', () => {
    const existing = [makeResource('NetworkPolicy', 'deny-all', 'ns-a')];
    const simulated = [makeResource('NetworkPolicy', 'deny-all', 'ns-b')];

    const merged = mergeSimulatedResources(existing, simulated);
    expect(merged).toHaveLength(2);
  });

  it('appends resource with undefined namespace if existing has a defined namespace', () => {
    const existing = [makeResource('NetworkPolicy', 'deny-all', 'default')];
    const simulated = [makeResource('ClusterRole', 'deny-all', undefined)];

    const merged = mergeSimulatedResources(existing, simulated);
    expect(merged).toHaveLength(2);
  });
});

describe('mergeSimulatedResources — unchanged resources', () => {
  it('leaves resources not referenced by simulated unchanged', () => {
    const existing = [
      makeResource('Deployment', 'api', 'default'),
      makeResource('Service', 'api-svc', 'default'),
    ];
    const simulated: ParsedResource[] = [];

    const merged = mergeSimulatedResources(existing, simulated);
    expect(merged).toHaveLength(2);
    expect(merged[0]).toBe(existing[0]);
    expect(merged[1]).toBe(existing[1]);
  });

  it('does not mutate the original existing array', () => {
    const existing = [makeResource('NetworkPolicy', 'deny-all', 'default')];
    const originalRef = existing[0];
    const simulated = [makeResource('NetworkPolicy', 'deny-all', 'default', { spec: { modified: true } as Record<string, unknown> })];

    mergeSimulatedResources(existing, simulated);
    expect(existing[0]).toBe(originalRef);
  });
});

// ---------------------------------------------------------------------------
// computeSimulationDiff
// ---------------------------------------------------------------------------

describe('computeSimulationDiff — gained paths', () => {
  it('identifies a path that was denied and is now allowed as gained', () => {
    const before = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', false)];
    const after = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)];

    const diff = computeSimulationDiff(before, after);
    expect(diff.gained).toHaveLength(1);
    expect(diff.gained[0].from.name).toBe('frontend');
    expect(diff.gained[0].to.name).toBe('backend');
    expect(diff.lost).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(0);
  });

  it('identifies a new path that appears as allowed as gained', () => {
    const before: PodReachabilityResult[] = [];
    const after = [makePodResult('new-svc', 'ns-a', 'db', 'ns-b', true)];

    const diff = computeSimulationDiff(before, after);
    expect(diff.gained).toHaveLength(1);
    expect(diff.gained[0].from.name).toBe('new-svc');
  });
});

describe('computeSimulationDiff — lost paths', () => {
  it('identifies a path that was allowed and is now denied as lost', () => {
    const before = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)];
    const after = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', false)];

    const diff = computeSimulationDiff(before, after);
    expect(diff.lost).toHaveLength(1);
    expect(diff.lost[0].from.name).toBe('frontend');
    expect(diff.gained).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(0);
  });
});

describe('computeSimulationDiff — unchanged paths', () => {
  it('identifies a path that remains allowed as unchanged', () => {
    const before = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)];
    const after = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)];

    const diff = computeSimulationDiff(before, after);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.gained).toHaveLength(0);
    expect(diff.lost).toHaveLength(0);
  });

  it('identifies a path that remains denied as unchanged', () => {
    const before = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', false)];
    const after = [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', false)];

    const diff = computeSimulationDiff(before, after);
    expect(diff.unchanged).toHaveLength(1);
  });
});

describe('computeSimulationDiff — edge cases', () => {
  it('returns empty diff for empty before and after', () => {
    const diff = computeSimulationDiff([], []);
    expect(diff.gained).toHaveLength(0);
    expect(diff.lost).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(0);
  });

  it('handles all paths unchanged', () => {
    const results = [
      makePodResult('a', 'ns-1', 'b', 'ns-2', true),
      makePodResult('c', 'ns-1', 'd', 'ns-2', false),
    ];
    const diff = computeSimulationDiff(results, results);
    expect(diff.unchanged).toHaveLength(2);
    expect(diff.gained).toHaveLength(0);
    expect(diff.lost).toHaveLength(0);
  });

  it('handles mix of gained, lost, and unchanged', () => {
    const before = [
      makePodResult('a', 'ns', 'b', 'ns', true),   // will become denied → lost
      makePodResult('c', 'ns', 'd', 'ns', false),   // will become allowed → gained
      makePodResult('e', 'ns', 'f', 'ns', true),    // stays allowed → unchanged
    ];
    const after = [
      makePodResult('a', 'ns', 'b', 'ns', false),
      makePodResult('c', 'ns', 'd', 'ns', true),
      makePodResult('e', 'ns', 'f', 'ns', true),
    ];

    const diff = computeSimulationDiff(before, after);
    expect(diff.gained).toHaveLength(1);
    expect(diff.gained[0].from.name).toBe('c');
    expect(diff.lost).toHaveLength(1);
    expect(diff.lost[0].from.name).toBe('a');
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.unchanged[0].from.name).toBe('e');
  });
});
