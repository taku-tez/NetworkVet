import { describe, it, expect } from 'vitest';
import { generateFixes } from '../../src/fixer/generator.js';
import type { Finding, ParsedResource } from '../../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'NW1003',
    severity: 'high',
    kind: 'Namespace',
    name: 'default',
    namespace: 'default',
    file: 'test.yaml',
    line: 1,
    message: 'Test finding',
    ...overrides,
  };
}

function makeServiceResource(namespace: string, ports: number[]): ParsedResource {
  return {
    kind: 'Service',
    apiVersion: 'v1',
    metadata: { name: 'my-svc', namespace },
    spec: {
      type: 'ClusterIP',
      ports: ports.map((p) => ({ port: p, targetPort: p })),
    },
    file: 'svc.yaml',
    line: 1,
  };
}

function makeIngressResource(namespace: string, name: string, hosts: string[]): ParsedResource {
  return {
    kind: 'Ingress',
    apiVersion: 'networking.k8s.io/v1',
    metadata: { name, namespace },
    spec: {
      rules: hosts.map((host) => ({
        host,
        http: { paths: [{ path: '/', pathType: 'Prefix', backend: { service: { name: 'svc', port: { number: 80 } } } }] },
      })),
    },
    file: 'ingress.yaml',
    line: 1,
  };
}

// ---------------------------------------------------------------------------
// Basic structure
// ---------------------------------------------------------------------------

describe('generateFixes — empty findings', () => {
  it('returns empty array when no findings', () => {
    const result = generateFixes([], []);
    expect(result).toEqual([]);
  });
});

describe('generateFixes — FixSuggestion shape', () => {
  it('returns correct shape for a finding', () => {
    const f = makeFinding({ id: 'NW1003', kind: 'Namespace', name: 'default', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.findingId).toBe('NW1003');
    expect(s.resource).toBe('Namespace/default');
    expect(s.namespace).toBe('default');
    expect(typeof s.description).toBe('string');
    expect(s.description.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('generateFixes — deduplication', () => {
  it('deduplicates same rule + namespace + kind + name', () => {
    const f1 = makeFinding({ id: 'NW1003', namespace: 'default', kind: 'Namespace', name: 'default' });
    const f2 = makeFinding({ id: 'NW1003', namespace: 'default', kind: 'Namespace', name: 'default' });
    const result = generateFixes([f1, f2], []);
    expect(result).toHaveLength(1);
  });

  it('keeps two different namespaces as separate suggestions', () => {
    const f1 = makeFinding({ id: 'NW1003', namespace: 'ns-a', name: 'ns-a', kind: 'Namespace' });
    const f2 = makeFinding({ id: 'NW1003', namespace: 'ns-b', name: 'ns-b', kind: 'Namespace' });
    const result = generateFixes([f1, f2], []);
    expect(result).toHaveLength(2);
  });

  it('keeps two different rule IDs as separate suggestions', () => {
    const f1 = makeFinding({ id: 'NW1001', namespace: 'default', kind: 'NetworkPolicy', name: 'allow-all' });
    const f2 = makeFinding({ id: 'NW1002', namespace: 'default', kind: 'NetworkPolicy', name: 'allow-all' });
    const result = generateFixes([f1, f2], []);
    expect(result).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// i18n — English (default)
// ---------------------------------------------------------------------------

describe('generateFixes — language: en (default)', () => {
  it('returns English description by default', () => {
    const f = makeFinding({ id: 'NW1003', namespace: 'default', kind: 'Namespace', name: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.description).toMatch(/default-deny/i);
  });

  it('also populates descriptionJa with Japanese text', () => {
    const f = makeFinding({ id: 'NW1003', namespace: 'default', kind: 'Namespace', name: 'default' });
    const [s] = generateFixes([f], [], 'en');
    expect(s.descriptionJa).toBeDefined();
    expect(s.descriptionJa).toMatch(/NetworkPolicy/);
  });
});

// ---------------------------------------------------------------------------
// i18n — Japanese
// ---------------------------------------------------------------------------

describe('generateFixes — language: ja', () => {
  it('returns Japanese description when lang=ja', () => {
    const f = makeFinding({ id: 'NW1003', namespace: 'default', kind: 'Namespace', name: 'default' });
    const [s] = generateFixes([f], [], 'ja');
    expect(s.description).toMatch(/NetworkPolicy/);
    // should be the Japanese string, not the English one
    expect(s.description).not.toMatch(/Add a default-deny/i);
  });

  it('NW1001 Japanese description contains Japanese characters', () => {
    const f = makeFinding({ id: 'NW1001', kind: 'NetworkPolicy', name: 'np', namespace: 'default' });
    const [s] = generateFixes([f], [], 'ja');
    expect(s.description).toMatch(/イングレスピア/);
  });
});

// ---------------------------------------------------------------------------
// YAML fix snippets — NetworkPolicy rules
// ---------------------------------------------------------------------------

describe('generateFixes — NW1003 default-deny YAML', () => {
  it('includes the namespace in the YAML snippet', () => {
    const f = makeFinding({ id: 'NW1003', kind: 'Namespace', name: 'payments', namespace: 'payments' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toBeDefined();
    expect(s.fix).toMatch(/namespace: payments/);
    expect(s.fix).toMatch(/default-deny-all/);
    expect(s.fix).toMatch(/policyTypes/);
  });
});

describe('generateFixes — NW1001 restrict ingress', () => {
  it('generates restrict-ingress YAML', () => {
    const f = makeFinding({ id: 'NW1001', kind: 'NetworkPolicy', name: 'allow-all', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toBeDefined();
    expect(s.fix).toMatch(/namespaceSelector/);
    expect(s.fix).toMatch(/Ingress/);
  });

  it('auto-detects ports from Service resources', () => {
    const f = makeFinding({ id: 'NW1001', kind: 'NetworkPolicy', name: 'allow-all', namespace: 'mynamespace' });
    const svc = makeServiceResource('mynamespace', [8080, 9000]);
    const [s] = generateFixes([f], [svc]);
    expect(s.fix).toMatch(/port: 8080/);
    expect(s.fix).toMatch(/port: 9000/);
  });

  it('does not include ports from a different namespace', () => {
    const f = makeFinding({ id: 'NW1001', kind: 'NetworkPolicy', name: 'allow-all', namespace: 'ns-a' });
    const svc = makeServiceResource('ns-b', [3000]);
    const [s] = generateFixes([f], [svc]);
    expect(s.fix).not.toMatch(/port: 3000/);
  });
});

describe('generateFixes — NW1002 restrict egress', () => {
  it('generates restrict-egress YAML', () => {
    const f = makeFinding({ id: 'NW1002', kind: 'NetworkPolicy', name: 'allow-all-out', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toBeDefined();
    expect(s.fix).toMatch(/Egress/);
    expect(s.fix).toMatch(/namespaceSelector/);
  });
});

describe('generateFixes — NW1006 DNS egress', () => {
  it('generates DNS egress rule YAML', () => {
    const f = makeFinding({ id: 'NW1006', kind: 'NetworkPolicy', name: 'restrict', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toBeDefined();
    expect(s.fix).toMatch(/port: 53/);
    expect(s.fix).toMatch(/UDP/);
    expect(s.fix).toMatch(/TCP/);
  });
});

describe('generateFixes — NW1004 pod selector', () => {
  it('includes matchLabels in the YAML fix', () => {
    const f = makeFinding({ id: 'NW1004', kind: 'NetworkPolicy', name: 'np', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/matchLabels/);
    expect(s.fix).toMatch(/podSelector/);
  });
});

describe('generateFixes — NW1005 namespace selector', () => {
  it('includes namespaceSelector fix', () => {
    const f = makeFinding({ id: 'NW1005', kind: 'NetworkPolicy', name: 'np', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/namespaceSelector/);
    expect(s.fix).toMatch(/metadata.name/);
  });
});

// ---------------------------------------------------------------------------
// YAML fix snippets — Service rules
// ---------------------------------------------------------------------------

describe('generateFixes — NW2002 externalTrafficPolicy', () => {
  it('generates externalTrafficPolicy: Local fix', () => {
    const f = makeFinding({ id: 'NW2002', kind: 'Service', name: 'my-lb', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/externalTrafficPolicy: Local/);
  });
});

describe('generateFixes — NW2003 loadBalancerSourceRanges', () => {
  it('generates loadBalancerSourceRanges YAML', () => {
    const f = makeFinding({ id: 'NW2003', kind: 'Service', name: 'my-lb', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/loadBalancerSourceRanges/);
    expect(s.fix).toMatch(/10\.0\.0\.0\/8/);
  });
});

describe('generateFixes — NW2004 SSH port', () => {
  it('generates SSH port removal fix', () => {
    const f = makeFinding({ id: 'NW2004', kind: 'Service', name: 'ssh-svc', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/port: 22/);
    expect(s.fix).toMatch(/Delete/i);
  });
});

// ---------------------------------------------------------------------------
// YAML fix snippets — Ingress rules
// ---------------------------------------------------------------------------

describe('generateFixes — NW3001 TLS', () => {
  it('generates TLS YAML with detected hosts', () => {
    const f = makeFinding({ id: 'NW3001', kind: 'Ingress', name: 'my-ing', namespace: 'default' });
    const ing = makeIngressResource('default', 'my-ing', ['app.example.com']);
    const [s] = generateFixes([f], [ing]);
    expect(s.fix).toMatch(/tls:/);
    expect(s.fix).toMatch(/app\.example\.com/);
  });

  it('falls back to placeholder host when no Ingress found', () => {
    const f = makeFinding({ id: 'NW3001', kind: 'Ingress', name: 'missing-ing', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/tls:/);
    expect(s.fix).toMatch(/your\.domain\.example\.com/);
  });
});

describe('generateFixes — NW3002 HSTS', () => {
  it('generates HSTS annotation YAML', () => {
    const f = makeFinding({ id: 'NW3002', kind: 'Ingress', name: 'my-ing', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/nginx\.ingress\.kubernetes\.io\/hsts/);
    expect(s.fix).toMatch(/"true"/);
  });
});

describe('generateFixes — NW3003 SSL redirect', () => {
  it('generates ssl-redirect annotation YAML', () => {
    const f = makeFinding({ id: 'NW3003', kind: 'Ingress', name: 'my-ing', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/ssl-redirect/);
    expect(s.fix).toMatch(/"true"/);
  });
});

// ---------------------------------------------------------------------------
// Cluster-level rules
// ---------------------------------------------------------------------------

describe('generateFixes — NW4001 namespace default-deny', () => {
  it('generates default-deny YAML for the namespace', () => {
    const f = makeFinding({ id: 'NW4001', kind: 'Namespace', name: 'prod', namespace: 'prod' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/namespace: prod/);
    expect(s.fix).toMatch(/default-deny-all/);
  });
});

describe('generateFixes — NW4002 non-enforcing CNI', () => {
  it('has a description but no YAML fix (infrastructure change required)', () => {
    const f = makeFinding({ id: 'NW4002', kind: 'DaemonSet', name: 'kube-flannel', namespace: 'kube-system' });
    const [s] = generateFixes([f], []);
    expect(s.description).toMatch(/CNI/i);
    expect(s.fix).toBeUndefined();
  });
});

describe('generateFixes — NW4005 block cloud metadata', () => {
  it('generates egress block for 169.254.169.254', () => {
    const f = makeFinding({ id: 'NW4005', kind: 'Namespace', name: 'default', namespace: 'default' });
    const [s] = generateFixes([f], []);
    expect(s.fix).toMatch(/169\.254\.169\.254\/32/);
    expect(s.fix).toMatch(/Egress/);
  });
});

// ---------------------------------------------------------------------------
// Generic fallback for unknown rule IDs
// ---------------------------------------------------------------------------

describe('generateFixes — generic fallback', () => {
  it('returns a suggestion for an unknown rule ID with no YAML fix', () => {
    const f = makeFinding({ id: 'NWUNKNOWN', kind: 'NetworkPolicy', name: 'np', namespace: 'default', message: 'some issue' });
    const [s] = generateFixes([f], []);
    expect(s.findingId).toBe('NWUNKNOWN');
    expect(s.description).toBeTruthy();
    expect(s.fix).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Multiple findings across namespaces
// ---------------------------------------------------------------------------

describe('generateFixes — multiple namespaces', () => {
  it('generates one suggestion per unique namespace finding', () => {
    const findings: Finding[] = [
      makeFinding({ id: 'NW1003', namespace: 'ns-a', name: 'ns-a', kind: 'Namespace' }),
      makeFinding({ id: 'NW1003', namespace: 'ns-b', name: 'ns-b', kind: 'Namespace' }),
      makeFinding({ id: 'NW1003', namespace: 'ns-c', name: 'ns-c', kind: 'Namespace' }),
    ];
    const result = generateFixes(findings, []);
    expect(result).toHaveLength(3);
    const namespaces = result.map((s) => s.namespace);
    expect(namespaces).toContain('ns-a');
    expect(namespaces).toContain('ns-b');
    expect(namespaces).toContain('ns-c');
  });
});

// ---------------------------------------------------------------------------
// Port auto-detection edge cases
// ---------------------------------------------------------------------------

describe('generateFixes — port auto-detection', () => {
  it('returns sorted ports from namespace services', () => {
    const f = makeFinding({ id: 'NW1009', kind: 'Deployment', name: 'api', namespace: 'backend' });
    const svc1 = makeServiceResource('backend', [9000]);
    const svc2 = makeServiceResource('backend', [8080]);
    const [s] = generateFixes([f], [svc1, svc2]);
    // Should appear in sorted order
    const fix = s.fix ?? '';
    const idx8080 = fix.indexOf('8080');
    const idx9000 = fix.indexOf('9000');
    expect(idx8080).toBeLessThan(idx9000);
  });

  it('NW1010 includes auto-detected ports from same namespace', () => {
    const f = makeFinding({ id: 'NW1010', kind: 'Deployment', name: 'worker', namespace: 'jobs' });
    const svc = makeServiceResource('jobs', [5000]);
    const [s] = generateFixes([f], [svc]);
    expect(s.fix).toMatch(/port: 5000/);
  });
});
