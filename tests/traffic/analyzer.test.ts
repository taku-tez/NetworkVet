import { describe, it, expect } from 'vitest';
import { analyzeTraffic, detectPolicyGaps } from '../../src/traffic/analyzer.js';
import type { TrafficFlow } from '../../src/traffic/types.js';
import type { ParsedResource } from '../../src/types.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

function makeFlow(overrides: Partial<TrafficFlow> & { verdict: TrafficFlow['verdict'] }): TrafficFlow {
  return {
    timestamp: '2024-01-15T10:00:00Z',
    sourceNamespace: 'frontend',
    sourcePod: 'frontend-abc',
    destNamespace: 'payments',
    destPod: 'payments-svc',
    destPort: 8080,
    protocol: 'TCP',
    ...overrides,
  };
}

function makeNetworkPolicy(
  name: string,
  namespace: string,
  spec: Record<string, unknown>,
): ParsedResource {
  return {
    kind: 'NetworkPolicy',
    apiVersion: 'networking.k8s.io/v1',
    metadata: { name, namespace },
    spec,
    file: 'np.yaml',
    line: 1,
  };
}

function makeService(
  name: string,
  namespace: string,
  ports: Array<{ port: number; targetPort?: number }>,
): ParsedResource {
  return {
    kind: 'Service',
    apiVersion: 'v1',
    metadata: { name, namespace },
    spec: { type: 'ClusterIP', ports },
    file: 'svc.yaml',
    line: 1,
  };
}

// ─── detectPolicyGaps ─────────────────────────────────────────────────────────

describe('detectPolicyGaps', () => {
  it('returns a gap when allowed traffic reaches namespace with no NetworkPolicy', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destNamespace: 'payments', destPort: 8080 })];
    const resources: ParsedResource[] = []; // no NetworkPolicies at all
    const gaps = detectPolicyGaps(flows, resources);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].destNamespace).toBe('payments');
    expect(gaps[0].destPort).toBe(8080);
    expect(gaps[0].observedCount).toBe(1);
  });

  it('counts multiple flows through the same gap', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', destNamespace: 'payments', destPort: 8080 }),
      makeFlow({ verdict: 'ALLOW', destNamespace: 'payments', destPort: 8080 }),
      makeFlow({ verdict: 'ALLOW', destNamespace: 'payments', destPort: 8080 }),
    ];
    const gaps = detectPolicyGaps(flows, []);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].observedCount).toBe(3);
  });

  it('does not return a gap when namespace has an ingress NetworkPolicy', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destNamespace: 'payments', destPort: 8080 })];
    const resources = [
      makeNetworkPolicy('allow-frontend', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{ from: [{ namespaceSelector: { matchLabels: { name: 'frontend' } } }] }],
      }),
    ];
    const gaps = detectPolicyGaps(flows, resources);
    expect(gaps).toHaveLength(0);
  });

  it('ignores DROP flows when counting gaps', () => {
    const flows = [
      makeFlow({ verdict: 'DROP', destNamespace: 'payments', destPort: 8080 }),
    ];
    const gaps = detectPolicyGaps(flows, []);
    expect(gaps).toHaveLength(0);
  });

  it('ignores flows with no destNamespace', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destNamespace: '' })];
    const gaps = detectPolicyGaps(flows, []);
    expect(gaps).toHaveLength(0);
  });

  it('creates separate gap entries for different (dest, port) combinations', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments', destPort: 8080 }),
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'backend',  destNamespace: 'monitoring', destPort: 9090 }),
    ];
    const gaps = detectPolicyGaps(flows, []);
    expect(gaps).toHaveLength(2);
    const dests = gaps.map((g) => g.destNamespace).sort();
    expect(dests).toContain('payments');
    expect(dests).toContain('monitoring');
  });

  it('returns empty array when flows list is empty', () => {
    expect(detectPolicyGaps([], [])).toHaveLength(0);
  });
});

// ─── analyzeTraffic ───────────────────────────────────────────────────────────

describe('analyzeTraffic — basic counts', () => {
  it('counts total, allowed, and dropped flows', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW' }),
      makeFlow({ verdict: 'ALLOW' }),
      makeFlow({ verdict: 'DROP' }),
      makeFlow({ verdict: 'AUDIT' }),
    ];
    const result = analyzeTraffic(flows, []);
    expect(result.totalFlows).toBe(4);
    expect(result.allowedFlows).toBe(2);
    expect(result.droppedFlows).toBe(1);
  });

  it('returns zero counts for empty flows', () => {
    const result = analyzeTraffic([], []);
    expect(result.totalFlows).toBe(0);
    expect(result.allowedFlows).toBe(0);
    expect(result.droppedFlows).toBe(0);
    expect(result.violations).toHaveLength(0);
    expect(result.policyGaps).toHaveLength(0);
  });
});

describe('analyzeTraffic — policy-gap violations', () => {
  it('produces a policy-gap violation for allowed traffic to unprotected namespace', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destNamespace: 'payments' })];
    const result = analyzeTraffic(flows, []);
    const policyGapViolations = result.violations.filter((v) => v.type === 'policy-gap');
    expect(policyGapViolations.length).toBeGreaterThan(0);
    expect(policyGapViolations[0].severity).toBe('warning');
  });

  it('does not produce policy-gap when namespace has NetworkPolicy', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destNamespace: 'payments' })];
    const resources = [
      makeNetworkPolicy('allow-policy', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const policyGapViolations = result.violations.filter((v) => v.type === 'policy-gap');
    expect(policyGapViolations).toHaveLength(0);
  });

  it('deduplicates policy-gap violations for same (src, dst, port)', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments', destPort: 8080 }),
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments', destPort: 8080 }),
    ];
    const result = analyzeTraffic(flows, []);
    const gapViolations = result.violations.filter((v) => v.type === 'policy-gap');
    expect(gapViolations).toHaveLength(1);
  });
});

describe('analyzeTraffic — unexpected-allow violations', () => {
  it('detects unexpected-allow when traffic reaches a namespace with policy that should block it', () => {
    // payments has a NetworkPolicy allowing only from "trusted" namespace,
    // but we see traffic from "frontend" (not trusted)
    const flows = [
      makeFlow({
        verdict: 'ALLOW',
        sourceNamespace: 'frontend',
        destNamespace: 'payments',
      }),
    ];
    const resources = [
      makeNetworkPolicy('allow-trusted-only', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{
          from: [{
            namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'trusted' } },
          }],
        }],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const unexpectedAllow = result.violations.filter((v) => v.type === 'unexpected-allow');
    expect(unexpectedAllow).toHaveLength(1);
    expect(unexpectedAllow[0].severity).toBe('error');
  });

  it('does not fire unexpected-allow when empty namespaceSelector (allow all)', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments' })];
    const resources = [
      makeNetworkPolicy('allow-all-ns', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{ from: [{ namespaceSelector: {} }] }],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const unexpectedAllow = result.violations.filter((v) => v.type === 'unexpected-allow');
    expect(unexpectedAllow).toHaveLength(0);
  });

  it('does not fire unexpected-allow when source matches name label', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments' })];
    const resources = [
      makeNetworkPolicy('allow-frontend', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{
          from: [{ namespaceSelector: { matchLabels: { name: 'frontend' } } }],
        }],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const unexpectedAllow = result.violations.filter((v) => v.type === 'unexpected-allow');
    expect(unexpectedAllow).toHaveLength(0);
  });

  it('deduplicates unexpected-allow for same (src, dst) pair', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments' }),
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments' }),
    ];
    const resources = [
      makeNetworkPolicy('deny-all', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{ from: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'trusted' } } }] }],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const unexpectedAllow = result.violations.filter((v) => v.type === 'unexpected-allow');
    expect(unexpectedAllow).toHaveLength(1);
  });
});

describe('analyzeTraffic — unexpected-deny violations', () => {
  it('detects unexpected-deny when DROP flow matches a declared allow rule', () => {
    const flows = [
      makeFlow({
        verdict: 'DROP',
        sourceNamespace: 'frontend',
        destNamespace: 'payments',
      }),
    ];
    const resources = [
      makeNetworkPolicy('allow-frontend', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{
          from: [{ namespaceSelector: { matchLabels: { name: 'frontend' } } }],
        }],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const unexpectedDeny = result.violations.filter((v) => v.type === 'unexpected-deny');
    expect(unexpectedDeny).toHaveLength(1);
    expect(unexpectedDeny[0].severity).toBe('warning');
  });

  it('does not fire unexpected-deny when DROP has no matching allow policy', () => {
    const flows = [makeFlow({ verdict: 'DROP', sourceNamespace: 'attacker', destNamespace: 'payments' })];
    const resources = [
      makeNetworkPolicy('allow-trusted', 'payments', {
        podSelector: {},
        policyTypes: ['Ingress'],
        ingress: [{ from: [{ namespaceSelector: { matchLabels: { name: 'trusted' } } }] }],
      }),
    ];
    const result = analyzeTraffic(flows, resources);
    const unexpectedDeny = result.violations.filter((v) => v.type === 'unexpected-deny');
    expect(unexpectedDeny).toHaveLength(0);
  });
});

describe('analyzeTraffic — shadow-traffic violations', () => {
  it('detects shadow-traffic when port is not in any Service', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', destPort: 9999, destNamespace: 'backend' }),
    ];
    const resources = [
      makeService('my-svc', 'backend', [{ port: 8080 }]),
    ];
    const result = analyzeTraffic(flows, resources);
    const shadow = result.violations.filter((v) => v.type === 'shadow-traffic');
    expect(shadow).toHaveLength(1);
    expect(shadow[0].severity).toBe('info');
    expect(shadow[0].message).toContain('9999');
  });

  it('does not fire shadow-traffic when port matches a Service', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destPort: 8080, destNamespace: 'backend' })];
    const resources = [makeService('my-svc', 'backend', [{ port: 8080 }])];
    const result = analyzeTraffic(flows, resources);
    const shadow = result.violations.filter((v) => v.type === 'shadow-traffic');
    expect(shadow).toHaveLength(0);
  });

  it('does not fire shadow-traffic when no Services are defined (knownPorts empty)', () => {
    const flows = [makeFlow({ verdict: 'ALLOW', destPort: 9999, destNamespace: 'backend' })];
    const result = analyzeTraffic(flows, []);
    const shadow = result.violations.filter((v) => v.type === 'shadow-traffic');
    expect(shadow).toHaveLength(0);
  });

  it('deduplicates shadow-traffic per (dest, port)', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', destPort: 9999, destNamespace: 'backend' }),
      makeFlow({ verdict: 'ALLOW', destPort: 9999, destNamespace: 'backend' }),
    ];
    const resources = [makeService('svc', 'backend', [{ port: 8080 }])];
    const result = analyzeTraffic(flows, resources);
    const shadow = result.violations.filter((v) => v.type === 'shadow-traffic');
    expect(shadow).toHaveLength(1);
  });
});

describe('analyzeTraffic — policyGaps field', () => {
  it('populates policyGaps with deduplicated gaps with counts', () => {
    const flows = [
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments', destPort: 8080 }),
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'frontend', destNamespace: 'payments', destPort: 8080 }),
      makeFlow({ verdict: 'ALLOW', sourceNamespace: 'backend', destNamespace: 'monitoring', destPort: 9090 }),
    ];
    const result = analyzeTraffic(flows, []);
    expect(result.policyGaps.length).toBeGreaterThanOrEqual(1);
    const paymentsGap = result.policyGaps.find((g) => g.destNamespace === 'payments');
    expect(paymentsGap).toBeDefined();
    expect(paymentsGap?.observedCount).toBe(2);
  });
});
