import { describe, it, expect } from 'vitest';
import { parseContent } from '../../src/parser/index.js';
import { buildContext } from '../../src/rules/engine.js';
import {
  NW1001,
  NW1002,
  NW1003,
  NW1004,
  NW1005,
  NW1006,
  NW1007,
  NW1008,
  NW1009,
  NW1010,
} from '../../src/rules/nw1xxx.js';

function check(rule: typeof NW1001, yaml: string) {
  const resources = parseContent(yaml, 'test.yaml');
  const ctx = buildContext(resources);
  return rule.check(resources, ctx);
}

describe('NW1001 — Ingress from: [{}] allows all sources', () => {
  it('triggers when ingress has empty peer {}', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: default
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
`;
    const findings = check(NW1001, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1001');
    expect(findings[0].severity).toBe('high');
  });

  it('does not trigger when ingress has specific peer', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restricted-ingress
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
`;
    const findings = check(NW1001, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger when no ingress rules defined', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-only
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector: {}
`;
    const findings = check(NW1001, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger on Service resources', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    const findings = check(NW1001, yaml);
    expect(findings).toHaveLength(0);
  });
});

describe('NW1002 — Egress to: [{}] allows all destinations', () => {
  it('triggers when egress has empty peer {}', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - {}
`;
    const findings = check(NW1002, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1002');
    expect(findings[0].severity).toBe('high');
  });

  it('does not trigger when egress has specific destination', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restricted-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - port: 53
          protocol: UDP
`;
    const findings = check(NW1002, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger when no egress defined', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-only
  namespace: default
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
    const findings = check(NW1002, yaml);
    expect(findings).toHaveLength(0);
  });
});

describe('NW1003 — Namespace has no NetworkPolicy', () => {
  it('triggers when a Namespace resource has workloads but no NetworkPolicy', () => {
    // Bug 6: bare Namespace with no workloads should NOT fire; with workloads, it should.
    const yaml = `
apiVersion: v1
kind: Namespace
metadata:
  name: unprotected
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: unprotected
spec:
  replicas: 1
`;
    const findings = check(NW1003, yaml);
    expect(findings.some(f => f.id === 'NW1003' && f.namespace === 'unprotected')).toBe(true);
  });

  it('does NOT trigger for a Namespace resource that has no workloads (only RBAC)', () => {
    // Bug 6: cert-manager installs Role/RoleBinding into kube-system for leader
    // election — those resources do not generate traffic, so kube-system should
    // not be flagged by NW1003.
    const yaml = `
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-manager-leader-election
  namespace: kube-system
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cert-manager-leader-election
  namespace: kube-system
roleRef:
  kind: Role
  name: cert-manager-leader-election
  apiGroup: rbac.authorization.k8s.io
subjects: []
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.id === 'NW1003' && f.namespace === 'kube-system')).toHaveLength(0);
  });

  it('does NOT trigger for implied namespace that has only RBAC resources', () => {
    // Bug 6: no Namespace resource, only Role/RoleBinding — should not fire.
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: leader-election
  namespace: kube-system
rules: []
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.namespace === 'kube-system')).toHaveLength(0);
  });

  it('does not trigger when namespace has a NetworkPolicy', () => {
    const yaml = `
apiVersion: v1
kind: Namespace
metadata:
  name: protected
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: protected
spec:
  replicas: 1
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: protected
spec:
  podSelector: {}
  policyTypes:
    - Ingress
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.id === 'NW1003' && f.namespace === 'protected')).toHaveLength(0);
  });

  it('reports implied namespaces from workloads without NetworkPolicies', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: isolated-ns
spec:
  replicas: 1
`;
    const findings = check(NW1003, yaml);
    expect(findings.some(f => f.id === 'NW1003' && f.namespace === 'isolated-ns')).toBe(true);
  });

  it('reports implied namespace with the actual source file, not "<cluster>" (Bug 7)', () => {
    // The finding should reference the file where the triggering workload lives.
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: myns
spec:
  replicas: 1
`;
    const resources = parseContent(yaml, '/path/to/deploy.yaml');
    const ctx = buildContext(resources);
    const findings = NW1003.check(resources, ctx);
    const finding = findings.find(f => f.id === 'NW1003' && f.namespace === 'myns');
    expect(finding).toBeDefined();
    expect(finding!.file).toBe('/path/to/deploy.yaml');
    expect(finding!.file).not.toBe('<cluster>');
  });

  it('does NOT report "default" namespace from cluster-scoped resources (regression: ArgoCD pattern)', () => {
    // ArgoCD manifests have no namespace in metadata — resources are applied
    // with `kubectl -n argocd apply`.  ClusterRole etc. must not create a
    // false-positive for "default" namespace.
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: argocd-application-controller
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argocd-application-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: argocd-application-controller
subjects: []
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.id === 'NW1003' && f.namespace === 'default')).toHaveLength(0);
  });

  it('does NOT report implied namespace for namespace-scoped resources without explicit namespace', () => {
    // Manifests designed to be applied with -n flag should not generate
    // a false-positive for "default".
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: argocd-server
  template:
    metadata:
      labels:
        app: argocd-server
    spec:
      containers: []
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.id === 'NW1003' && f.namespace === 'default')).toHaveLength(0);
  });

  it('does NOT trigger for ValidatingWebhookConfiguration (cert-manager pattern)', () => {
    const yaml = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: cert-manager-webhook
webhooks: []
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.namespace === 'default')).toHaveLength(0);
  });

  it('triggers for Service in namespace with no NetworkPolicy (Service is a workload kind)', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: app-ns
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    const findings = check(NW1003, yaml);
    expect(findings.some(f => f.id === 'NW1003' && f.namespace === 'app-ns')).toBe(true);
  });

  it('does NOT trigger for ConfigMap-only namespace (not a workload)', () => {
    const yaml = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: config-only-ns
data:
  key: value
`;
    const findings = check(NW1003, yaml);
    expect(findings.filter(f => f.namespace === 'config-only-ns')).toHaveLength(0);
  });
});

describe('NW1004 — NetworkPolicy podSelector: {} targets all pods', () => {
  it('triggers when podSelector is empty and policy has actual ingress rules', () => {
    // A policy with podSelector: {} AND non-empty ingress rules is NOT a
    // default-deny — it deliberately allows all pods to receive traffic from
    // specific peers, which is overly broad.
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: blanket-policy
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
`;
    const findings = check(NW1004, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1004');
    expect(findings[0].severity).toBe('medium');
  });

  it('does NOT trigger on default-deny policies (podSelector: {} with empty ingress)', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
`;
    const findings = check(NW1004, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does NOT trigger on default-deny-all policies', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`;
    const findings = check(NW1004, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger when podSelector has matchLabels', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: targeted-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
    - Ingress
`;
    const findings = check(NW1004, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger on non-NetworkPolicy resources', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: default
spec:
  selector: {}
`;
    const findings = check(NW1004, yaml);
    expect(findings).toHaveLength(0);
  });
});

describe('NW1005 — NetworkPolicy allows traffic from all namespaces', () => {
  it('triggers when namespaceSelector is empty {}', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ns
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - namespaceSelector: {}
`;
    const findings = check(NW1005, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1005');
  });

  it('does not trigger when namespaceSelector has labels', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: specific-ns
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              env: production
`;
    const findings = check(NW1005, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger when only podSelector is used in from', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pod-selector-only
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: client
`;
    const findings = check(NW1005, yaml);
    expect(findings).toHaveLength(0);
  });
});

describe('NW1006 — NetworkPolicy does not restrict egress DNS', () => {
  it('triggers when egress policy does not allow port 53', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: default
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
    const findings = check(NW1006, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1006');
    expect(findings[0].severity).toBe('info');
  });

  it('does not trigger when port 53 is allowed', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allows-dns
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
`;
    const findings = check(NW1006, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not trigger when Egress is not in policyTypes', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-only
  namespace: default
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
    const findings = check(NW1006, yaml);
    expect(findings).toHaveLength(0);
  });
});

describe('NW1007 — NetworkPolicy allows traffic from kube-system', () => {
  it('triggers when ingress allows kube-system by name label', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-kube-system
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
`;
    const findings = check(NW1007, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1007');
  });

  it('triggers when using legacy name: kube-system label', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-kube-system-legacy
  namespace: default
spec:
  podSelector: {}
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: kube-system
`;
    const findings = check(NW1007, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger when allowing a different namespace', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: default
spec:
  podSelector: {}
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
`;
    const findings = check(NW1007, yaml);
    expect(findings).toHaveLength(0);
  });
});

describe('NW1008 — NetworkPolicy with empty policyTypes', () => {
  it('triggers when policyTypes is missing', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-policy-types
  namespace: default
spec:
  podSelector: {}
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: client
`;
    const findings = check(NW1008, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW1008');
    expect(findings[0].severity).toBe('info');
  });

  it('does not trigger when policyTypes is set', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: with-policy-types
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`;
    const findings = check(NW1008, yaml);
    expect(findings).toHaveLength(0);
  });

  it('triggers when policyTypes is empty array', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: empty-policy-types
  namespace: default
spec:
  podSelector: {}
  policyTypes: []
`;
    const findings = check(NW1008, yaml);
    expect(findings).toHaveLength(1);
  });
});

describe('NW1009 — Ingress policy missing for workload', () => {
  it('triggers when Deployment has no NetworkPolicy with Ingress', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
`;
    const findings = check(NW1009, yaml);
    expect(findings.some(f => f.id === 'NW1009')).toBe(true);
  });

  it('does not trigger when namespace has NetworkPolicy with Ingress', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-ingress
  namespace: default
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
    const findings = check(NW1009, yaml);
    expect(findings.filter(f => f.id === 'NW1009')).toHaveLength(0);
  });

  it('triggers for StatefulSet with no ingress policy', () => {
    const yaml = `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-db
  namespace: database
spec:
  replicas: 1
  serviceName: my-db
`;
    const findings = check(NW1009, yaml);
    expect(findings.some(f => f.id === 'NW1009' && f.name === 'my-db')).toBe(true);
  });
});

describe('NW1010 — Egress policy missing for workload', () => {
  it('triggers when Deployment has no NetworkPolicy with Egress', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
`;
    const findings = check(NW1010, yaml);
    expect(findings.some(f => f.id === 'NW1010')).toBe(true);
  });

  it('does not trigger when namespace has NetworkPolicy with Egress', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress: []
`;
    const findings = check(NW1010, yaml);
    expect(findings.filter(f => f.id === 'NW1010')).toHaveLength(0);
  });

  it('triggers for DaemonSet with no egress policy', () => {
    const yaml = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-agent
  namespace: logging
spec: {}
`;
    const findings = check(NW1010, yaml);
    expect(findings.some(f => f.id === 'NW1010' && f.name === 'log-agent')).toBe(true);
  });

  it('does NOT trigger for workloads without an explicit namespace (regression: ArgoCD pattern)', () => {
    // Manifests designed to be applied with `kubectl -n argocd apply` have no
    // namespace in metadata.  These should NOT produce findings because we
    // cannot know their target namespace statically.
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-server
spec:
  replicas: 1
`;
    const findings = check(NW1010, yaml);
    expect(findings.filter(f => f.id === 'NW1010')).toHaveLength(0);
  });
});

describe('NW1009/NW1010 — regression: workloads without explicit namespace', () => {
  it('NW1009 does not fire for a Deployment without namespace', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
`;
    const findings = check(NW1009, yaml);
    expect(findings.filter(f => f.id === 'NW1009')).toHaveLength(0);
  });

  it('NW1009 still fires for a Deployment WITH explicit namespace and no policy', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
  namespace: myns
spec:
  replicas: 1
`;
    const findings = check(NW1009, yaml);
    expect(findings.filter(f => f.id === 'NW1009' && f.namespace === 'myns')).toHaveLength(1);
  });
});
