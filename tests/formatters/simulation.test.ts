import { describe, it, expect } from 'vitest';
import { formatSimulationTty, formatSimulationJson } from '../../src/formatters/simulation.js';
import type { SimulationDiff } from '../../src/simulation/engine.js';
import type { PodReachabilityResult } from '../../src/reachability/pod_evaluator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeWorkloadInfo(name: string, namespace: string) {
  return { name, namespace, kind: 'Deployment', labels: {} };
}

function makePodResult(
  fromName: string,
  fromNs: string,
  toName: string,
  toNs: string,
  allowed: boolean,
  reason = allowed ? 'policy-allow' : 'policy-deny'
): PodReachabilityResult {
  return {
    from: makeWorkloadInfo(fromName, fromNs),
    to: makeWorkloadInfo(toName, toNs),
    allowed,
    reason,
  };
}

function emptyDiff(): SimulationDiff {
  return { gained: [], lost: [], unchanged: [] };
}

// ---------------------------------------------------------------------------
// formatSimulationTty
// ---------------------------------------------------------------------------

describe('formatSimulationTty — header', () => {
  it('includes the simulatedFile name in header', () => {
    const output = formatSimulationTty(emptyDiff(), 'my-policy.yaml');
    expect(output).toContain('my-policy.yaml');
  });

  it('includes "Simulation: applying" in header', () => {
    const output = formatSimulationTty(emptyDiff(), 'test.yaml');
    expect(output).toMatch(/Simulation: applying/);
  });
});

describe('formatSimulationTty — no changes', () => {
  it('shows "No reachability changes" when diff is empty', () => {
    const output = formatSimulationTty(emptyDiff(), 'test.yaml');
    expect(output).toMatch(/No reachability changes/);
  });

  it('does not show GAINED/LOST sections when diff is empty', () => {
    const output = formatSimulationTty(emptyDiff(), 'test.yaml');
    expect(output).not.toMatch(/GAINED paths/);
    expect(output).not.toMatch(/LOST paths/);
  });
});

describe('formatSimulationTty — gained paths section', () => {
  it('shows "GAINED paths (N)" header with count', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      gained: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toMatch(/GAINED paths \(1\)/);
  });

  it('shows "+" prefix for gained paths', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      gained: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toMatch(/\+/);
  });

  it('shows from/to namespace and name in gained path lines', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      gained: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toContain('ns-a/frontend');
    expect(output).toContain('ns-b/backend');
  });

  it('shows reason in square brackets for gained path lines', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      gained: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true, 'policy-allow')],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toContain('[policy-allow]');
  });
});

describe('formatSimulationTty — lost paths section', () => {
  it('shows "LOST paths (N)" header with count', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      lost: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', false)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toMatch(/LOST paths \(1\)/);
  });

  it('shows "-" prefix for lost paths', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      lost: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', false)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toMatch(/-/);
  });

  it('shows from/to namespace and name in lost path lines', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      lost: [makePodResult('worker', 'ns-x', 'db', 'ns-y', false)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toContain('ns-x/worker');
    expect(output).toContain('ns-y/db');
  });
});

describe('formatSimulationTty — summary line', () => {
  it('shows summary with gained/lost/unchanged counts', () => {
    const diff: SimulationDiff = {
      gained: [makePodResult('a', 'ns', 'b', 'ns', true)],
      lost: [makePodResult('c', 'ns', 'd', 'ns', false)],
      unchanged: [makePodResult('e', 'ns', 'f', 'ns', true)],
    };
    const output = formatSimulationTty(diff, 'test.yaml');
    expect(output).toMatch(/Summary:/);
    expect(output).toMatch(/1 gained/);
    expect(output).toMatch(/1 lost/);
    expect(output).toMatch(/1 unchanged/);
  });

  it('shows summary even when diff is empty', () => {
    const output = formatSimulationTty(emptyDiff(), 'test.yaml');
    expect(output).toMatch(/Summary:/);
    expect(output).toMatch(/0 gained/);
    expect(output).toMatch(/0 lost/);
    expect(output).toMatch(/0 unchanged/);
  });
});

// ---------------------------------------------------------------------------
// formatSimulationJson
// ---------------------------------------------------------------------------

describe('formatSimulationJson — valid JSON structure', () => {
  it('returns valid JSON', () => {
    const output = formatSimulationJson(emptyDiff(), 'test.yaml');
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('has type field set to "simulation-diff"', () => {
    const parsed = JSON.parse(formatSimulationJson(emptyDiff(), 'test.yaml'));
    expect(parsed.type).toBe('simulation-diff');
  });

  it('includes simulatedFile in output', () => {
    const parsed = JSON.parse(formatSimulationJson(emptyDiff(), 'my-policy.yaml'));
    expect(parsed.simulatedFile).toBe('my-policy.yaml');
  });

  it('has gained, lost, unchanged arrays', () => {
    const parsed = JSON.parse(formatSimulationJson(emptyDiff(), 'test.yaml'));
    expect(Array.isArray(parsed.gained)).toBe(true);
    expect(Array.isArray(parsed.lost)).toBe(true);
    expect(Array.isArray(parsed.unchanged)).toBe(true);
  });

  it('has summary object with gained/lost/unchanged counts', () => {
    const parsed = JSON.parse(formatSimulationJson(emptyDiff(), 'test.yaml'));
    expect(parsed.summary).toBeDefined();
    expect(typeof parsed.summary.gained).toBe('number');
    expect(typeof parsed.summary.lost).toBe('number');
    expect(typeof parsed.summary.unchanged).toBe('number');
  });
});

describe('formatSimulationJson — populated diff', () => {
  it('includes correct summary counts', () => {
    const diff: SimulationDiff = {
      gained: [makePodResult('a', 'ns', 'b', 'ns', true)],
      lost: [makePodResult('c', 'ns', 'd', 'ns', false)],
      unchanged: [
        makePodResult('e', 'ns', 'f', 'ns', true),
        makePodResult('g', 'ns', 'h', 'ns', false),
      ],
    };
    const parsed = JSON.parse(formatSimulationJson(diff, 'test.yaml'));
    expect(parsed.summary.gained).toBe(1);
    expect(parsed.summary.lost).toBe(1);
    expect(parsed.summary.unchanged).toBe(2);
  });

  it('round-trips gained path data correctly', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      gained: [makePodResult('frontend', 'ns-a', 'backend', 'ns-b', true)],
    };
    const parsed = JSON.parse(formatSimulationJson(diff, 'test.yaml'));
    expect(parsed.gained).toHaveLength(1);
    expect(parsed.gained[0].from.name).toBe('frontend');
    expect(parsed.gained[0].from.namespace).toBe('ns-a');
    expect(parsed.gained[0].to.name).toBe('backend');
    expect(parsed.gained[0].to.namespace).toBe('ns-b');
    expect(parsed.gained[0].allowed).toBe(true);
  });

  it('round-trips lost path data correctly', () => {
    const diff: SimulationDiff = {
      ...emptyDiff(),
      lost: [makePodResult('worker', 'ns-x', 'db', 'ns-y', false)],
    };
    const parsed = JSON.parse(formatSimulationJson(diff, 'test.yaml'));
    expect(parsed.lost).toHaveLength(1);
    expect(parsed.lost[0].from.name).toBe('worker');
    expect(parsed.lost[0].allowed).toBe(false);
  });

  it('is pretty-printed (multi-line)', () => {
    const output = formatSimulationJson(emptyDiff(), 'test.yaml');
    expect(output).toContain('\n');
  });

  it('simulatedFile name appears in output string', () => {
    const output = formatSimulationJson(emptyDiff(), 'k8s/new-policy.yaml');
    expect(output).toContain('k8s/new-policy.yaml');
  });
});
