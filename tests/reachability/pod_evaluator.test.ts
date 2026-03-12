import { describe, it, expect } from 'vitest';
import {
  extractWorkloads,
  matchesPodSelector,
  computePodReachability,
  type WorkloadInfo,
} from '../../src/reachability/pod_evaluator.js';
import { parseContent } from '../../src/parser/index.js';

function parse(yaml: string) {
  return parseContent(yaml, 'test.yaml');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResource(kind: string, name: string, namespace: string, labels?: Record<string, string>) {
  return {
    kind,
    apiVersion: 'apps/v1',
    metadata: { name, namespace, labels },
    spec: {},
    file: 'test.yaml',
    line: 1,
  };
}

const deployYaml = (name: string, ns: string, labels = '') => `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${ns}
  ${labels ? `labels:\n    ${labels}` : ''}
spec:
  replicas: 1
`;

const podYaml = (name: string, ns: string, labels = '') => `
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${ns}
  ${labels ? `labels:\n    ${labels}` : ''}
spec:
  containers: []
`;

const statefulSetYaml = (name: string, ns: string) => `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ${name}
  namespace: ${ns}
spec:
  replicas: 1
`;

const netpolYaml = (name: string, ns: string, extra = '') => `
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
// extractWorkloads
// ---------------------------------------------------------------------------

describe('extractWorkloads', () => {
  it('finds Deployments', () => {
    const resources = parse(deployYaml('web', 'frontend'));
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(1);
    expect(workloads[0].name).toBe('web');
    expect(workloads[0].namespace).toBe('frontend');
    expect(workloads[0].kind).toBe('Deployment');
  });

  it('finds StatefulSets', () => {
    const resources = parse(statefulSetYaml('db', 'backend'));
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(1);
    expect(workloads[0].kind).toBe('StatefulSet');
  });

  it('finds Pods', () => {
    const resources = parse(podYaml('my-pod', 'default'));
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(1);
    expect(workloads[0].kind).toBe('Pod');
  });

  it('finds DaemonSets', () => {
    const yaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-agent
  namespace: monitoring
spec: {}
`;
    const resources = parse(yaml);
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(1);
    expect(workloads[0].kind).toBe('DaemonSet');
  });

  it('finds Jobs', () => {
    const yaml = `
apiVersion: batch/v1
kind: Job
metadata:
  name: migration
  namespace: ops
spec: {}
`;
    const resources = parse(yaml);
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(1);
    expect(workloads[0].kind).toBe('Job');
  });

  it('skips Services, NetworkPolicies, and other non-workload kinds', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: default
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: default
spec:
  podSelector: {}
`;
    const resources = parse(yaml);
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(0);
  });

  it('skips workloads without a namespace', () => {
    const r = makeResource('Deployment', 'no-ns', undefined as unknown as string);
    const workloads = extractWorkloads([r as Parameters<typeof extractWorkloads>[0][0]]);
    expect(workloads).toHaveLength(0);
  });

  it('extracts labels from workload metadata', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: backend
  labels:
    app: api
    tier: backend
spec: {}
`;
    const resources = parse(yaml);
    const workloads = extractWorkloads(resources);
    expect(workloads[0].labels).toEqual({ app: 'api', tier: 'backend' });
  });

  it('returns empty labels map when metadata has no labels', () => {
    const resources = parse(deployYaml('web', 'frontend'));
    const workloads = extractWorkloads(resources);
    expect(workloads[0].labels).toEqual({});
  });

  it('finds multiple workloads across namespaces', () => {
    const yaml = `
${deployYaml('web', 'frontend')}
---
${statefulSetYaml('db', 'backend')}
---
${podYaml('worker', 'ops')}
`;
    const resources = parse(yaml);
    const workloads = extractWorkloads(resources);
    expect(workloads).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// matchesPodSelector
// ---------------------------------------------------------------------------

describe('matchesPodSelector', () => {
  it('empty selector (undefined) matches all pods', () => {
    expect(matchesPodSelector(undefined, { app: 'web' })).toBe(true);
  });

  it('empty selector ({}) matches all pods', () => {
    expect(matchesPodSelector({}, { app: 'web' })).toBe(true);
  });

  it('empty selector ({}) matches pod with no labels', () => {
    expect(matchesPodSelector({}, {})).toBe(true);
  });

  it('specific label selector matches pod with matching labels', () => {
    expect(matchesPodSelector({ app: 'web' }, { app: 'web', tier: 'frontend' })).toBe(true);
  });

  it('specific label selector does not match pod with different label value', () => {
    expect(matchesPodSelector({ app: 'api' }, { app: 'web' })).toBe(false);
  });

  it('specific label selector does not match pod missing the label', () => {
    expect(matchesPodSelector({ app: 'web' }, {})).toBe(false);
  });

  it('multi-label selector requires all labels to match', () => {
    const labels = { app: 'web', env: 'prod' };
    expect(matchesPodSelector({ app: 'web', env: 'prod' }, labels)).toBe(true);
    expect(matchesPodSelector({ app: 'web', env: 'staging' }, labels)).toBe(false);
  });

  it('subset match: selector with fewer labels matches pod with more', () => {
    expect(matchesPodSelector({ app: 'web' }, { app: 'web', env: 'prod', version: '1' })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computePodReachability
// ---------------------------------------------------------------------------

describe('computePodReachability', () => {
  it('returns empty array when no workloads exist', () => {
    const resources = parse(netpolYaml('deny-all', 'default'));
    const results = computePodReachability(resources);
    expect(results).toHaveLength(0);
  });

  it('returns empty array for single workload (no self-pairs)', () => {
    const resources = parse(deployYaml('web', 'frontend'));
    const results = computePodReachability(resources);
    expect(results).toHaveLength(0);
  });

  it('default-allow: no NetworkPolicies → all pairs have reason "no-policy"', () => {
    const yaml = `
${deployYaml('web', 'frontend')}
---
${deployYaml('api', 'frontend')}
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    expect(results).toHaveLength(2); // web→api, api→web
    expect(results.every((r) => r.reason === 'no-policy')).toBe(true);
    expect(results.every((r) => r.allowed === true)).toBe(true);
  });

  it('default-deny: ingress policy with no rules → all pairs denied with "policy-deny"', () => {
    const yaml = `
${deployYaml('web', 'ns-a')}
---
${deployYaml('api', 'ns-a')}
---
${netpolYaml('deny-all', 'ns-a', '  ingress: []')}
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((r) => r.reason === 'policy-deny')).toBe(true);
    expect(results.every((r) => r.allowed === false)).toBe(true);
  });

  it('targeted NetworkPolicy allows matching pods with "policy-allow"', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
  labels:
    app: web
spec: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: app
  labels:
    app: api
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-api
  namespace: app
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    const webToApi = results.find(
      (r) => r.from.name === 'web' && r.to.name === 'api',
    );
    const apiToWeb = results.find(
      (r) => r.from.name === 'api' && r.to.name === 'web',
    );

    expect(webToApi).toBeDefined();
    expect(webToApi!.allowed).toBe(true);
    expect(webToApi!.reason).toBe('policy-allow');

    // api → web: no policy on web, so default allow
    expect(apiToWeb).toBeDefined();
    expect(apiToWeb!.reason).toBe('no-policy');
    expect(apiToWeb!.allowed).toBe(true);
  });

  it('non-matching podSelector in ingress → policy-deny', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: app
  labels:
    tier: frontend
spec: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: app
  labels:
    tier: backend
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-only-db
  namespace: app
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              tier: db
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    const frontendToBackend = results.find(
      (r) => r.from.name === 'frontend' && r.to.name === 'backend',
    );
    expect(frontendToBackend).toBeDefined();
    expect(frontendToBackend!.allowed).toBe(false);
    expect(frontendToBackend!.reason).toBe('policy-deny');
  });

  it('ingress rule with no from clause allows all sources', () => {
    const yaml = `
${deployYaml('web', 'ns-a')}
---
${deployYaml('api', 'ns-a')}
---
${netpolYaml('allow-all-ingress', 'ns-a', `  ingress:
    - ports:
        - port: 80`)}
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    expect(results.every((r) => r.allowed === true)).toBe(true);
    expect(results.every((r) => r.reason === 'policy-allow')).toBe(true);
  });

  it('cross-namespace pairs are not included when no namespaceSelector policies exist', () => {
    const yaml = `
${deployYaml('web', 'frontend')}
---
${deployYaml('api', 'backend')}
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    // No cross-namespace results when no namespaceSelector policies
    expect(results).toHaveLength(0);
  });

  it('cross-namespace pairs included when namespaceSelector policies exist', () => {
    const yaml = `
${deployYaml('web', 'frontend')}
---
${deployYaml('api', 'backend')}
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
    const results = computePodReachability(resources);
    const frontendToBackend = results.find(
      (r) => r.from.namespace === 'frontend' && r.to.namespace === 'backend',
    );
    expect(frontendToBackend).toBeDefined();
    expect(frontendToBackend!.allowed).toBe(true);
    expect(frontendToBackend!.reason).toBe('policy-allow');
  });

  it('cross-namespace: namespaceSelector not matching source → policy-deny', () => {
    const yaml = `
${deployYaml('web', 'external')}
---
${deployYaml('api', 'backend')}
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
    const results = computePodReachability(resources);
    const externalToBackend = results.find(
      (r) => r.from.namespace === 'external' && r.to.namespace === 'backend',
    );
    expect(externalToBackend).toBeDefined();
    expect(externalToBackend!.allowed).toBe(false);
    expect(externalToBackend!.reason).toBe('policy-deny');
  });

  it('cross-namespace: namespaceSelector: {} allows all namespaces', () => {
    const yaml = `
${deployYaml('web', 'frontend')}
---
${deployYaml('api', 'backend')}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ns
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector: {}
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    const frontendToBackend = results.find(
      (r) => r.from.namespace === 'frontend' && r.to.namespace === 'backend',
    );
    expect(frontendToBackend).toBeDefined();
    expect(frontendToBackend!.allowed).toBe(true);
  });

  it('returns correct WorkloadInfo in from/to fields', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: frontend
  labels:
    app: web
spec: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: frontend
  labels:
    app: api
spec: {}
`;
    const resources = parse(yaml);
    const results = computePodReachability(resources);
    expect(results).toHaveLength(2);
    const webToApi = results.find(
      (r) => r.from.name === 'web' && r.to.name === 'api',
    );
    expect(webToApi!.from).toMatchObject({
      name: 'web',
      namespace: 'frontend',
      kind: 'Deployment',
      labels: { app: 'web' },
    });
    expect(webToApi!.to).toMatchObject({
      name: 'api',
      namespace: 'frontend',
      kind: 'Deployment',
    });
  });
});
