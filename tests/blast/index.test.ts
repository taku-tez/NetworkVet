import { describe, it, expect } from 'vitest';
import { parseWorkloadRef, computeBlastRadius } from '../../src/blast/index.js';
import type { ParsedResource } from '../../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDeployment(name: string, namespace: string, labels: Record<string, string> = {}): ParsedResource {
  return {
    kind: 'Deployment',
    apiVersion: 'apps/v1',
    metadata: { name, namespace, labels },
    spec: {},
  } as unknown as ParsedResource;
}

function makeResources(workloads: Array<{ name: string; namespace: string; labels?: Record<string, string> }>): ParsedResource[] {
  return workloads.map(({ name, namespace, labels = {} }) => makeDeployment(name, namespace, labels));
}

// ---------------------------------------------------------------------------
// parseWorkloadRef
// ---------------------------------------------------------------------------

describe('parseWorkloadRef', () => {
  it('parses "ns/name" format correctly', () => {
    const result = parseWorkloadRef('my-ns/my-app');
    expect(result.namespace).toBe('my-ns');
    expect(result.name).toBe('my-app');
  });

  it('parses "name" without slash defaults to "default" namespace', () => {
    const result = parseWorkloadRef('my-app');
    expect(result.namespace).toBe('default');
    expect(result.name).toBe('my-app');
  });

  it('handles namespace with hyphen and name with hyphen', () => {
    const result = parseWorkloadRef('prod-ns/api-server');
    expect(result.namespace).toBe('prod-ns');
    expect(result.name).toBe('api-server');
  });

  it('handles namespace with multiple slashes — uses first slash', () => {
    // Only the first slash is treated as separator
    const result = parseWorkloadRef('ns/name/extra');
    expect(result.namespace).toBe('ns');
    expect(result.name).toBe('name/extra');
  });
});

// ---------------------------------------------------------------------------
// computeBlastRadius — error cases
// ---------------------------------------------------------------------------

describe('computeBlastRadius — error when origin not found', () => {
  it('throws when origin workload does not exist', () => {
    const resources = makeResources([{ name: 'frontend', namespace: 'app' }]);
    expect(() => computeBlastRadius(resources, 'app/nonexistent')).toThrow();
  });

  it('error message mentions the requested workload ref', () => {
    const resources = makeResources([{ name: 'frontend', namespace: 'app' }]);
    expect(() => computeBlastRadius(resources, 'app/nonexistent')).toThrowError(/nonexistent/);
  });

  it('error message includes available workloads', () => {
    const resources = makeResources([{ name: 'frontend', namespace: 'app' }]);
    expect(() => computeBlastRadius(resources, 'app/nonexistent')).toThrowError(/frontend/);
  });

  it('throws when no resources provided', () => {
    expect(() => computeBlastRadius([], 'default/app')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// computeBlastRadius — no reachable workloads (fully isolated)
// ---------------------------------------------------------------------------

describe('computeBlastRadius — isolated origin', () => {
  it('returns empty reachable array when origin has no outbound paths', () => {
    // Two workloads in same namespace but we have a deny-all policy on target
    // Actually — with no policy and same namespace, they are reachable via "no-policy"
    // So to test isolation, we need to put them in separate namespaces with no cross-ns rules
    const resources: ParsedResource[] = [
      makeDeployment('frontend', 'ns-a'),
      makeDeployment('backend', 'ns-b'),
    ];
    const result = computeBlastRadius(resources, 'ns-a/frontend');
    // Cross-namespace pairs are excluded when no namespaceSelector policies exist
    expect(result.reachable).toHaveLength(0);
    expect(result.origin.name).toBe('frontend');
    expect(result.origin.namespace).toBe('ns-a');
  });

  it('returns origin in depth map with depth 0', () => {
    const resources: ParsedResource[] = [
      makeDeployment('frontend', 'ns-a'),
      makeDeployment('backend', 'ns-b'),
    ];
    const result = computeBlastRadius(resources, 'ns-a/frontend');
    expect(result.depth.get('ns-a/frontend')).toBe(0);
  });

  it('unreachable contains all other workloads when origin is isolated', () => {
    const resources: ParsedResource[] = [
      makeDeployment('frontend', 'ns-a'),
      makeDeployment('backend', 'ns-b'),
    ];
    const result = computeBlastRadius(resources, 'ns-a/frontend');
    expect(result.unreachable).toHaveLength(1);
    expect(result.unreachable[0].name).toBe('backend');
  });
});

// ---------------------------------------------------------------------------
// computeBlastRadius — simple chain A→B→C (BFS depth)
// ---------------------------------------------------------------------------

describe('computeBlastRadius — simple chain A→B→C', () => {
  // All three workloads in same namespace, no NetworkPolicy → default allow
  // A→B (depth 1), B→C (depth 2 from A)
  function makeChainResources(): ParsedResource[] {
    return [
      makeDeployment('workload-a', 'default'),
      makeDeployment('workload-b', 'default'),
      makeDeployment('workload-c', 'default'),
    ];
  }

  it('finds all reachable workloads in same namespace (no-policy)', () => {
    const result = computeBlastRadius(makeChainResources(), 'default/workload-a');
    // In same namespace with no NP, all workloads are reachable from each other
    expect(result.reachable.length).toBeGreaterThan(0);
  });

  it('origin is not included in reachable array', () => {
    const result = computeBlastRadius(makeChainResources(), 'default/workload-a');
    const reachableNames = result.reachable.map((w) => w.name);
    expect(reachableNames).not.toContain('workload-a');
  });

  it('origin has depth 0', () => {
    const result = computeBlastRadius(makeChainResources(), 'default/workload-a');
    expect(result.depth.get('default/workload-a')).toBe(0);
  });

  it('directly reachable workloads have depth 1', () => {
    const result = computeBlastRadius(makeChainResources(), 'default/workload-a');
    // In no-policy scenario, all same-namespace workloads are directly reachable
    for (const w of result.reachable) {
      const key = `${w.namespace}/${w.name}`;
      const d = result.depth.get(key);
      expect(d).toBeDefined();
      expect(d).toBeGreaterThanOrEqual(1);
    }
  });

  it('unreachable is empty when all workloads are reachable', () => {
    const result = computeBlastRadius(makeChainResources(), 'default/workload-a');
    expect(result.unreachable).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// computeBlastRadius — high-risk target detection
// ---------------------------------------------------------------------------

describe('computeBlastRadius — high-risk target detection', () => {
  it('detects "kubernetes" as a high-risk target when reachable', () => {
    // Deploy 'kubernetes' in same namespace as origin → reachable via no-policy
    const resources: ParsedResource[] = [
      makeDeployment('my-app', 'default'),
      makeDeployment('kubernetes', 'default'),
    ];
    const result = computeBlastRadius(resources, 'default/my-app');
    expect(result.highRiskTargets).toContain('default/kubernetes');
  });

  it('detects "kube-apiserver" as a high-risk target', () => {
    const resources: ParsedResource[] = [
      makeDeployment('my-app', 'kube-system'),
      makeDeployment('kube-apiserver', 'kube-system'),
    ];
    const result = computeBlastRadius(resources, 'kube-system/my-app');
    expect(result.highRiskTargets).toContain('kube-system/kube-apiserver');
  });

  it('detects "etcd" as a high-risk target', () => {
    const resources: ParsedResource[] = [
      makeDeployment('my-app', 'kube-system'),
      makeDeployment('etcd', 'kube-system'),
    ];
    const result = computeBlastRadius(resources, 'kube-system/my-app');
    expect(result.highRiskTargets).toContain('kube-system/etcd');
  });

  it('detects "metrics-server" as a high-risk target', () => {
    const resources: ParsedResource[] = [
      makeDeployment('my-app', 'kube-system'),
      makeDeployment('metrics-server', 'kube-system'),
    ];
    const result = computeBlastRadius(resources, 'kube-system/my-app');
    expect(result.highRiskTargets).toContain('kube-system/metrics-server');
  });

  it('does not flag non-high-risk workloads', () => {
    const resources: ParsedResource[] = [
      makeDeployment('my-app', 'default'),
      makeDeployment('safe-service', 'default'),
    ];
    const result = computeBlastRadius(resources, 'default/my-app');
    expect(result.highRiskTargets).toHaveLength(0);
  });

  it('returns empty highRiskTargets when no high-risk workloads are reachable', () => {
    const resources: ParsedResource[] = [
      makeDeployment('frontend', 'ns-a'),
    ];
    const result = computeBlastRadius(resources, 'ns-a/frontend');
    expect(result.highRiskTargets).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// computeBlastRadius — unreachable workloads
// ---------------------------------------------------------------------------

describe('computeBlastRadius — unreachable workload enumeration', () => {
  it('correctly enumerates unreachable workloads in other namespaces', () => {
    const resources: ParsedResource[] = [
      makeDeployment('app-a', 'ns-1'),
      makeDeployment('app-b', 'ns-2'),
      makeDeployment('app-c', 'ns-3'),
    ];
    const result = computeBlastRadius(resources, 'ns-1/app-a');
    // No cross-namespace policies, so ns-2 and ns-3 are unreachable
    expect(result.unreachable.length).toBe(2);
    const unreachableNames = result.unreachable.map((w) => w.name);
    expect(unreachableNames).toContain('app-b');
    expect(unreachableNames).toContain('app-c');
  });

  it('origin is not in unreachable list', () => {
    const resources: ParsedResource[] = [
      makeDeployment('frontend', 'default'),
      makeDeployment('backend', 'ns-2'),
    ];
    const result = computeBlastRadius(resources, 'default/frontend');
    const unreachableNames = result.unreachable.map((w) => w.name);
    expect(unreachableNames).not.toContain('frontend');
  });

  it('reachable workloads are not in unreachable list', () => {
    const resources: ParsedResource[] = [
      makeDeployment('frontend', 'default'),
      makeDeployment('backend', 'default'),
      makeDeployment('isolated', 'other-ns'),
    ];
    const result = computeBlastRadius(resources, 'default/frontend');
    const reachableKeys = new Set(result.reachable.map((w) => `${w.namespace}/${w.name}`));
    for (const w of result.unreachable) {
      expect(reachableKeys.has(`${w.namespace}/${w.name}`)).toBe(false);
    }
  });

  it('total workloads = 1 (origin) + reachable + unreachable', () => {
    const resources: ParsedResource[] = [
      makeDeployment('a', 'default'),
      makeDeployment('b', 'default'),
      makeDeployment('c', 'ns-2'),
    ];
    const result = computeBlastRadius(resources, 'default/a');
    const total = 1 + result.reachable.length + result.unreachable.length;
    expect(total).toBe(3);
  });
});
