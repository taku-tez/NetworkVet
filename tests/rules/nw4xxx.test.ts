import { describe, it, expect } from 'vitest';
import { parseContent } from '../../src/parser/index.js';
import { buildContext } from '../../src/rules/engine.js';
import {
  NW4001,
  NW4002,
  NW4003,
  NW4004,
  NW4005,
} from '../../src/rules/nw4xxx.js';

function check(rule: typeof NW4001, yaml: string) {
  const resources = parseContent(yaml, 'test.yaml');
  const ctx = buildContext(resources);
  return rule.check(resources, ctx);
}

describe('NW4001 — No default-deny NetworkPolicy in namespace', () => {
  it('triggers when namespace has NetworkPolicies but no default-deny', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              env: production
`;
    const findings = check(NW4001, yaml);
    expect(findings.some(f => f.id === 'NW4001')).toBe(true);
  });

  it('does not trigger when namespace has a default-deny ingress policy', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: backend
`;
    const findings = check(NW4001, yaml);
    expect(findings.filter(f => f.id === 'NW4001')).toHaveLength(0);
  });

  it('does not trigger when a default-deny egress policy exists', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: staging
spec:
  podSelector: {}
  policyTypes:
    - Egress
`;
    expect(check(NW4001, yaml).filter(f => f.id === 'NW4001')).toHaveLength(0);
  });
});

describe('NW4002 — CNI does not support NetworkPolicy', () => {
  it('triggers when Flannel DaemonSet is detected in kube-system', () => {
    const yaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-flannel-ds
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: flannel
  template:
    spec:
      containers:
        - name: kube-flannel
          image: flannel/flannel:v0.22.0
`;
    const findings = check(NW4002, yaml);
    expect(findings.some(f => f.id === 'NW4002')).toBe(true);
  });

  it('triggers when Flannel ConfigMap is in kube-flannel namespace', () => {
    const yaml = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-flannel-cfg
  namespace: kube-flannel
data:
  cni-conf.json: |
    {"name":"cbr0","cniVersion":"0.3.1","plugins":[{"type":"flannel"}]}
`;
    const findings = check(NW4002, yaml);
    expect(findings.some(f => f.id === 'NW4002')).toBe(true);
  });

  it('does not trigger when no Flannel resources are found', () => {
    const yaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: calico-node
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
`;
    expect(check(NW4002, yaml).filter(f => f.id === 'NW4002')).toHaveLength(0);
  });
});

describe('NW4003 — Cross-namespace traffic not restricted', () => {
  it('triggers when NetworkPolicy has no namespace restriction in ingress', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: client
`;
    const findings = check(NW4003, yaml);
    expect(findings.some(f => f.id === 'NW4003')).toBe(true);
  });

  it('does not trigger when namespaceSelector is used in ingress', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-ns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              env: production
`;
    expect(check(NW4003, yaml).filter(f => f.id === 'NW4003')).toHaveLength(0);
  });

  it('does not trigger for namespace with no ingress rules', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: isolated
spec:
  podSelector: {}
  policyTypes:
    - Ingress
`;
    // No ingress rules — no cross-namespace traffic possible
    expect(check(NW4003, yaml).filter(f => f.id === 'NW4003')).toHaveLength(0);
  });
});

describe('NW4004 — kube-dns accessible from all namespaces', () => {
  it('triggers when kube-system resources exist but no DNS NetworkPolicy', () => {
    const yaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: coredns
  namespace: kube-system
spec: {}
`;
    const findings = check(NW4004, yaml);
    expect(findings.some(f => f.id === 'NW4004')).toBe(true);
  });

  it('does not trigger when a DNS NetworkPolicy exists in kube-system', () => {
    const yaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: coredns
  namespace: kube-system
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-coredns
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      k8s-app: kube-dns
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              dns-access: allowed
`;
    const findings = check(NW4004, yaml);
    expect(findings.filter(f => f.id === 'NW4004')).toHaveLength(0);
  });

  it('does not trigger when no kube-system resources present', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: production
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    expect(check(NW4004, yaml).filter(f => f.id === 'NW4004')).toHaveLength(0);
  });
});

describe('NW4005 — Metadata API not blocked in egress policies', () => {
  it('triggers when namespace has egress policies without blocking 169.254.169.254', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              env: production
      ports:
        - port: 443
`;
    const findings = check(NW4005, yaml);
    expect(findings.some(f => f.id === 'NW4005')).toBe(true);
  });

  it('does not trigger when 169.254.169.254/32 is explicitly blocked via except', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
`;
    const findings = check(NW4005, yaml);
    expect(findings.filter(f => f.id === 'NW4005')).toHaveLength(0);
  });

  it('does not trigger when no egress policies exist', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-only
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: client
`;
    expect(check(NW4005, yaml).filter(f => f.id === 'NW4005')).toHaveLength(0);
  });

  it('does not trigger when metadata IP is directly referenced', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata-direct
  namespace: staging
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 169.254.169.254/32
`;
    const findings = check(NW4005, yaml);
    expect(findings.filter(f => f.id === 'NW4005')).toHaveLength(0);
  });

  it('does NOT trigger when namespace has a deny-all egress policy', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
`;
    const findings = check(NW4005, yaml);
    expect(findings.some(f => f.id === 'NW4005')).toBe(false);
  });

  it('triggers when namespace has workloads but NO egress NetworkPolicy', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: production
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: api:latest
`;
    const findings = check(NW4005, yaml);
    expect(findings.some(f => f.id === 'NW4005')).toBe(true);
    expect(findings.find(f => f.id === 'NW4005')?.message).toContain('no egress NetworkPolicy');
  });

  it('does NOT trigger for namespace with workloads AND a deny-all egress policy', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: production
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: api:latest
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
`;
    const findings = check(NW4005, yaml);
    expect(findings.some(f => f.id === 'NW4005')).toBe(false);
  });
});
