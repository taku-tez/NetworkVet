import { describe, it, expect } from 'vitest';
import { formatBlastRadiusTty, formatBlastRadiusJson } from '../../src/formatters/blast.js';
import type { BlastRadiusResult } from '../../src/blast/index.js';
import type { WorkloadInfo } from '../../src/reachability/pod_evaluator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeWorkload(name: string, namespace: string, kind = 'Deployment'): WorkloadInfo {
  return { name, namespace, kind, labels: {} };
}

function makeEmptyResult(originName: string, originNs = 'default'): BlastRadiusResult {
  const origin = makeWorkload(originName, originNs);
  const depth = new Map<string, number>();
  depth.set(`${originNs}/${originName}`, 0);
  return {
    origin,
    reachable: [],
    unreachable: [],
    highRiskTargets: [],
    depth,
  };
}

function makeResultWithReachable(
  originName: string,
  originNs: string,
  reachable: WorkloadInfo[],
  unreachable: WorkloadInfo[] = [],
  highRiskTargets: string[] = [],
): BlastRadiusResult {
  const origin = makeWorkload(originName, originNs);
  const depth = new Map<string, number>();
  depth.set(`${originNs}/${originName}`, 0);
  reachable.forEach((w, i) => {
    depth.set(`${w.namespace}/${w.name}`, i + 1);
  });
  return {
    origin,
    reachable,
    unreachable,
    highRiskTargets,
    depth,
  };
}

// ---------------------------------------------------------------------------
// formatBlastRadiusTty — header
// ---------------------------------------------------------------------------

describe('formatBlastRadiusTty — header', () => {
  it('shows "Blast Radius:" in the header', () => {
    const result = makeEmptyResult('my-app', 'production');
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('Blast Radius:');
  });

  it('includes the origin namespace/name in the header', () => {
    const result = makeEmptyResult('my-app', 'production');
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('production/my-app');
  });

  it('shows correct origin for default namespace', () => {
    const result = makeEmptyResult('frontend', 'default');
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('default/frontend');
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusTty — reachable workloads section
// ---------------------------------------------------------------------------

describe('formatBlastRadiusTty — reachable workloads', () => {
  it('shows "Reachable workloads (N):" with correct count', () => {
    const result = makeResultWithReachable('origin', 'ns', [
      makeWorkload('backend', 'ns'),
      makeWorkload('db', 'ns'),
    ]);
    const output = formatBlastRadiusTty(result);
    expect(output).toMatch(/Reachable workloads \(2\)/);
  });

  it('shows "(none)" when no reachable workloads', () => {
    const result = makeEmptyResult('frontend', 'ns');
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('(none)');
  });

  it('shows depth information for reachable workloads', () => {
    const result = makeResultWithReachable('origin', 'ns', [
      makeWorkload('backend', 'ns'),
    ]);
    const output = formatBlastRadiusTty(result);
    expect(output).toMatch(/\[depth=1\]/);
  });

  it('shows namespace/name for each reachable workload', () => {
    const result = makeResultWithReachable('origin', 'ns', [
      makeWorkload('backend', 'ns'),
    ]);
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('ns/backend');
  });

  it('shows kind for each reachable workload', () => {
    const result = makeResultWithReachable('origin', 'ns', [
      makeWorkload('backend', 'ns', 'StatefulSet'),
    ]);
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('StatefulSet');
  });

  it('shows reachable count of 0 for empty result', () => {
    const result = makeEmptyResult('app', 'default');
    const output = formatBlastRadiusTty(result);
    expect(output).toMatch(/Reachable workloads \(0\)/);
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusTty — HIGH RISK markers
// ---------------------------------------------------------------------------

describe('formatBlastRadiusTty — HIGH RISK markers', () => {
  it('shows "HIGH RISK" for high-risk targets', () => {
    const kubernetesWorkload = makeWorkload('kubernetes', 'default');
    const depth = new Map<string, number>();
    depth.set('default/origin', 0);
    depth.set('default/kubernetes', 1);
    const result: BlastRadiusResult = {
      origin: makeWorkload('origin', 'default'),
      reachable: [kubernetesWorkload],
      unreachable: [],
      highRiskTargets: ['default/kubernetes'],
      depth,
    };
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('HIGH RISK');
  });

  it('shows high-risk count line when targets exist', () => {
    const depth = new Map<string, number>();
    depth.set('ns/app', 0);
    depth.set('ns/etcd', 1);
    const result: BlastRadiusResult = {
      origin: makeWorkload('app', 'ns'),
      reachable: [makeWorkload('etcd', 'ns')],
      unreachable: [],
      highRiskTargets: ['ns/etcd'],
      depth,
    };
    const output = formatBlastRadiusTty(result);
    expect(output).toMatch(/High-risk targets reachable: 1/);
  });

  it('does not show HIGH RISK section when no high-risk targets', () => {
    const result = makeResultWithReachable('origin', 'ns', [
      makeWorkload('safe-app', 'ns'),
    ]);
    const output = formatBlastRadiusTty(result);
    expect(output).not.toMatch(/High-risk targets reachable/);
  });

  it('lists high-risk target keys in the HIGH RISK section', () => {
    const depth = new Map<string, number>();
    depth.set('ns/app', 0);
    depth.set('ns/kubernetes', 1);
    const result: BlastRadiusResult = {
      origin: makeWorkload('app', 'ns'),
      reachable: [makeWorkload('kubernetes', 'ns')],
      unreachable: [],
      highRiskTargets: ['ns/kubernetes'],
      depth,
    };
    const output = formatBlastRadiusTty(result);
    expect(output).toContain('ns/kubernetes');
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusTty — contained count
// ---------------------------------------------------------------------------

describe('formatBlastRadiusTty — contained count', () => {
  it('shows "Contained (not reachable): N workloads"', () => {
    const result = makeResultWithReachable(
      'origin', 'ns',
      [makeWorkload('reachable', 'ns')],
      [makeWorkload('isolated', 'other-ns'), makeWorkload('isolated2', 'other-ns2')],
    );
    const output = formatBlastRadiusTty(result);
    expect(output).toMatch(/Contained \(not reachable\): 2 workloads/);
  });

  it('shows 0 contained workloads when all are reachable', () => {
    const result = makeResultWithReachable('origin', 'ns', [makeWorkload('all', 'ns')]);
    const output = formatBlastRadiusTty(result);
    expect(output).toMatch(/Contained \(not reachable\): 0 workloads/);
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusJson — valid JSON structure
// ---------------------------------------------------------------------------

describe('formatBlastRadiusJson — valid JSON structure', () => {
  it('returns valid JSON', () => {
    const result = makeEmptyResult('my-app', 'default');
    expect(() => JSON.parse(formatBlastRadiusJson(result))).not.toThrow();
  });

  it('has type field set to "blast-radius"', () => {
    const result = makeEmptyResult('my-app', 'default');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.type).toBe('blast-radius');
  });

  it('includes origin object', () => {
    const result = makeEmptyResult('my-app', 'production');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.origin).toBeDefined();
    expect(parsed.origin.name).toBe('my-app');
    expect(parsed.origin.namespace).toBe('production');
  });

  it('includes reachable array', () => {
    const result = makeEmptyResult('my-app', 'default');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(Array.isArray(parsed.reachable)).toBe(true);
  });

  it('includes unreachable array', () => {
    const result = makeEmptyResult('my-app', 'default');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(Array.isArray(parsed.unreachable)).toBe(true);
  });

  it('includes highRiskTargets array', () => {
    const result = makeEmptyResult('my-app', 'default');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(Array.isArray(parsed.highRiskTargets)).toBe(true);
  });

  it('includes summary object with required fields', () => {
    const result = makeEmptyResult('my-app', 'default');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.summary).toBeDefined();
    expect(typeof parsed.summary.totalWorkloads).toBe('number');
    expect(typeof parsed.summary.reachableCount).toBe('number');
    expect(typeof parsed.summary.unreachableCount).toBe('number');
    expect(typeof parsed.summary.highRiskCount).toBe('number');
    expect(typeof parsed.summary.maxDepth).toBe('number');
  });

  it('summary counts are correct for empty result', () => {
    const result = makeEmptyResult('my-app', 'default');
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.summary.reachableCount).toBe(0);
    expect(parsed.summary.unreachableCount).toBe(0);
    expect(parsed.summary.highRiskCount).toBe(0);
    expect(parsed.summary.maxDepth).toBe(0);
    expect(parsed.summary.totalWorkloads).toBe(1); // just origin
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusJson — populated result
// ---------------------------------------------------------------------------

describe('formatBlastRadiusJson — populated result', () => {
  it('summary counts match actual arrays', () => {
    const result = makeResultWithReachable(
      'origin', 'ns',
      [makeWorkload('b', 'ns'), makeWorkload('c', 'ns')],
      [makeWorkload('isolated', 'other-ns')],
    );
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.summary.reachableCount).toBe(2);
    expect(parsed.summary.unreachableCount).toBe(1);
    expect(parsed.summary.totalWorkloads).toBe(4); // 1 origin + 2 reachable + 1 unreachable
  });

  it('maxDepth reflects the deepest reachable workload', () => {
    const origin = makeWorkload('origin', 'ns');
    const depth = new Map<string, number>();
    depth.set('ns/origin', 0);
    depth.set('ns/b', 1);
    depth.set('ns/c', 3);
    const result: BlastRadiusResult = {
      origin,
      reachable: [makeWorkload('b', 'ns'), makeWorkload('c', 'ns')],
      unreachable: [],
      highRiskTargets: [],
      depth,
    };
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.summary.maxDepth).toBe(3);
  });

  it('highRiskCount matches highRiskTargets array length', () => {
    const depth = new Map<string, number>();
    depth.set('ns/origin', 0);
    depth.set('ns/kubernetes', 1);
    depth.set('ns/etcd', 2);
    const result: BlastRadiusResult = {
      origin: makeWorkload('origin', 'ns'),
      reachable: [makeWorkload('kubernetes', 'ns'), makeWorkload('etcd', 'ns')],
      unreachable: [],
      highRiskTargets: ['ns/kubernetes', 'ns/etcd'],
      depth,
    };
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.summary.highRiskCount).toBe(2);
  });

  it('is pretty-printed (multi-line)', () => {
    const result = makeEmptyResult('app', 'default');
    const output = formatBlastRadiusJson(result);
    expect(output).toContain('\n');
  });

  it('round-trips reachable workload data correctly', () => {
    const result = makeResultWithReachable('origin', 'ns', [
      makeWorkload('target', 'ns', 'StatefulSet'),
    ]);
    const parsed = JSON.parse(formatBlastRadiusJson(result));
    expect(parsed.reachable).toHaveLength(1);
    expect(parsed.reachable[0].name).toBe('target');
    expect(parsed.reachable[0].namespace).toBe('ns');
    expect(parsed.reachable[0].kind).toBe('StatefulSet');
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusTty — empty blast radius graceful handling
// ---------------------------------------------------------------------------

describe('formatBlastRadiusTty — empty blast radius', () => {
  it('does not throw for empty result', () => {
    const result = makeEmptyResult('app', 'default');
    expect(() => formatBlastRadiusTty(result)).not.toThrow();
  });

  it('produces non-empty output string', () => {
    const result = makeEmptyResult('app', 'default');
    const output = formatBlastRadiusTty(result);
    expect(output.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// formatBlastRadiusJson — empty blast radius graceful handling
// ---------------------------------------------------------------------------

describe('formatBlastRadiusJson — empty blast radius', () => {
  it('does not throw for empty result', () => {
    const result = makeEmptyResult('app', 'default');
    expect(() => formatBlastRadiusJson(result)).not.toThrow();
  });

  it('produces valid JSON for empty result', () => {
    const result = makeEmptyResult('app', 'default');
    expect(() => JSON.parse(formatBlastRadiusJson(result))).not.toThrow();
  });
});
