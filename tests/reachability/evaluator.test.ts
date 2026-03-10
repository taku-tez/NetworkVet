import { describe, it, expect } from 'vitest';
import { computeReachability } from '../../src/reachability/evaluator.js';
import { parseContent } from '../../src/parser/index.js';

function parse(yaml: string) {
  return parseContent(yaml, 'test.yaml');
}

// ---------------------------------------------------------------------------
// Helpers to build concise YAML snippets
// ---------------------------------------------------------------------------

const deploymentYaml = (name: string, ns: string) => `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${ns}
spec:
  replicas: 1
`;

const namespacePolicyYaml = (name: string, ns: string, extra = '') => `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${name}
  namespace: ${ns}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
${extra}`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('computeReachability', () => {
  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  it('returns empty matrix for empty resources', () => {
    const result = computeReachability([]);
    expect(Object.keys(result.matrix)).toHaveLength(0);
    expect(result.unprotectedNamespaces).toHaveLength(0);
    expect(result.openPaths).toHaveLength(0);
  });

  it('handles single namespace with no NetworkPolicy', () => {
    const resources = parse(deploymentYaml('app', 'default'));
    const result = computeReachability(resources);
    expect(result.matrix['default']['default'].status).toBe('allowed (no policy)');
    expect(result.unprotectedNamespaces).toContain('default');
  });

  it('handles single namespace with default-deny ingress policy', () => {
    const yaml = namespacePolicyYaml('deny-all', 'isolated');
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const selfEntry = result.matrix['isolated']['isolated'];
    expect(selfEntry.status).toBe('denied');
    expect(selfEntry.risk).toBe('none');
  });

  it('self-to-self with no policy is allowed (no policy)', () => {
    const resources = parse(deploymentYaml('app', 'frontend'));
    const result = computeReachability(resources);
    expect(result.matrix['frontend']['frontend'].status).toBe('allowed (no policy)');
  });

  // -------------------------------------------------------------------------
  // No-policy namespace
  // -------------------------------------------------------------------------

  it('marks namespace with no NetworkPolicy as unprotected', () => {
    const yaml = `
${deploymentYaml('web', 'payments')}
---
${deploymentYaml('api', 'backend')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    expect(result.unprotectedNamespaces).toContain('payments');
    expect(result.unprotectedNamespaces).toContain('backend');
  });

  it('traffic to namespace with no ingress policy is "allowed (no policy)" with medium risk', () => {
    const yaml = `
${deploymentYaml('web', 'frontend')}
---
${deploymentYaml('db', 'database')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['frontend']['database'];
    expect(entry.status).toBe('allowed (no policy)');
    expect(entry.risk).toBe('medium');
    expect(entry.reason).toContain('no ingress NetworkPolicy');
  });

  it('open paths include allowed-no-policy entries', () => {
    const resources = parse(deploymentYaml('app', 'ns-a'));
    const result = computeReachability(resources);
    expect(result.openPaths.length).toBeGreaterThan(0);
    expect(result.openPaths.every((p) => p.status !== 'denied')).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Default-deny policy
  // -------------------------------------------------------------------------

  it('default-deny policy (empty ingress array) denies all sources', () => {
    const yaml = `
${deploymentYaml('app', 'frontend')}
---
${namespacePolicyYaml('deny-all', 'backend', '  ingress: []')}
---
${deploymentYaml('api', 'backend')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    expect(result.matrix['frontend']['backend'].status).toBe('denied');
    expect(result.matrix['frontend']['backend'].risk).toBe('none');
  });

  it('default-deny policy is not in unprotectedNamespaces', () => {
    const yaml = namespacePolicyYaml('deny-all', 'secure');
    const resources = parse(yaml);
    const result = computeReachability(resources);
    expect(result.unprotectedNamespaces).not.toContain('secure');
  });

  it('default-deny entry is not in openPaths', () => {
    const yaml = `
${deploymentYaml('app', 'src')}
---
${namespacePolicyYaml('deny-all', 'dst', '  ingress: []')}
${deploymentYaml('svc', 'dst')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const denied = result.openPaths.filter(
      (p) => p.from === 'src' && p.to === 'dst',
    );
    expect(denied).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Allow-all (from: [{}]) — high risk
  // -------------------------------------------------------------------------

  it('from: [{}] produces allowed with high risk', () => {
    const yaml = `
${deploymentYaml('client', 'frontend')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - {}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['frontend']['backend'];
    expect(entry.status).toBe('allowed');
    expect(entry.risk).toBe('high');
    expect(entry.reason).toContain('from: [{}]');
  });

  it('ingress rule with no from clause produces allowed with high risk', () => {
    const yaml = `
${deploymentYaml('client', 'ns-a')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-no-from
  namespace: ns-b
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - port: 80
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['ns-a']['ns-b'];
    expect(entry.status).toBe('allowed');
    expect(entry.risk).toBe('high');
  });

  it('high-risk entries appear in openPaths', () => {
    const yaml = `
${deploymentYaml('client', 'ns-a')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: ns-b
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - {}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    expect(result.openPaths.some((p) => p.from === 'ns-a' && p.to === 'ns-b')).toBe(true);
  });

  // -------------------------------------------------------------------------
  // namespaceSelector match → allowed, low risk
  // -------------------------------------------------------------------------

  it('specific namespaceSelector matching source → allowed, low risk', () => {
    const yaml = `
${deploymentYaml('client', 'frontend')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: frontend
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['frontend']['backend'];
    expect(entry.status).toBe('allowed');
    expect(entry.risk).toBe('low');
    expect(entry.reason).toContain('frontend');
  });

  it('namespaceSelector with name: label matching source → allowed, low risk', () => {
    const yaml = `
${deploymentYaml('client', 'monitoring')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: payments
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['monitoring']['payments'];
    expect(entry.status).toBe('allowed');
    expect(entry.risk).toBe('low');
  });

  it('namespaceSelector: {} (empty) → allowed, high risk', () => {
    const yaml = `
${deploymentYaml('client', 'ns-x')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ns
  namespace: ns-y
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector: {}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['ns-x']['ns-y'];
    expect(entry.status).toBe('allowed');
    expect(entry.risk).toBe('high');
  });

  // -------------------------------------------------------------------------
  // namespaceSelector not matching → denied
  // -------------------------------------------------------------------------

  it('specific namespaceSelector NOT matching source → denied', () => {
    const yaml = `
${deploymentYaml('client', 'external')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-internal-only
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: internal
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['external']['backend'];
    expect(entry.status).toBe('denied');
    expect(entry.risk).toBe('none');
  });

  it('podSelector-only peer does not match cross-namespace → denied', () => {
    const yaml = `
${deploymentYaml('client', 'ns-a')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pod-selector-only
  namespace: ns-b
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: allowed-app
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const entry = result.matrix['ns-a']['ns-b'];
    expect(entry.status).toBe('denied');
  });

  // -------------------------------------------------------------------------
  // Mixed namespaces (realistic scenario)
  // -------------------------------------------------------------------------

  it('handles three-namespace scenario correctly', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: frontend
spec:
  replicas: 1
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: frontend
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: backend
spec:
  replicas: 1
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: database
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress: []
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: db
  namespace: database
spec:
  replicas: 1
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);

    // frontend → backend: allowed (specific selector)
    expect(result.matrix['frontend']['backend'].status).toBe('allowed');
    expect(result.matrix['frontend']['backend'].risk).toBe('low');

    // frontend → database: denied (default deny)
    expect(result.matrix['frontend']['database'].status).toBe('denied');

    // backend → database: denied
    expect(result.matrix['backend']['database'].status).toBe('denied');

    // database not unprotected
    expect(result.unprotectedNamespaces).not.toContain('database');

    // frontend is unprotected
    expect(result.unprotectedNamespaces).toContain('frontend');
  });

  // -------------------------------------------------------------------------
  // openPaths / unprotectedNamespaces accuracy
  // -------------------------------------------------------------------------

  it('openPaths does not include denied entries', () => {
    const yaml = `
${deploymentYaml('a', 'ns-a')}
---
${namespacePolicyYaml('deny-all', 'ns-b', '  ingress: []')}
${deploymentYaml('b', 'ns-b')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const denyPaths = result.openPaths.filter((p) => p.status === 'denied');
    expect(denyPaths).toHaveLength(0);
  });

  it('unprotectedNamespaces are exactly the ones with no ingress policy', () => {
    const yaml = `
${deploymentYaml('a', 'protected')}
---
${namespacePolicyYaml('some-policy', 'protected', `  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: protected`)}
---
${deploymentYaml('b', 'unprotected')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    expect(result.unprotectedNamespaces).toContain('unprotected');
    expect(result.unprotectedNamespaces).not.toContain('protected');
  });

  it('matrix contains entries for all namespace pairs', () => {
    const yaml = `
${deploymentYaml('a', 'ns-1')}
---
${deploymentYaml('b', 'ns-2')}
---
${deploymentYaml('c', 'ns-3')}
`;
    const resources = parse(yaml);
    const result = computeReachability(resources);
    const nss = ['ns-1', 'ns-2', 'ns-3'];
    for (const src of nss) {
      for (const dst of nss) {
        expect(result.matrix[src]?.[dst]).toBeDefined();
      }
    }
  });
});
