import { describe, it, expect } from 'vitest';
import { parseContent } from '../src/parser/index.js';

describe('parser', () => {
  describe('parseContent - basic parsing', () => {
    it('parses a single NetworkPolicy document', () => {
      const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
`;
      const resources = parseContent(yaml, 'test.yaml');
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('NetworkPolicy');
      expect(resources[0].metadata.name).toBe('allow-app');
      expect(resources[0].metadata.namespace).toBe('production');
      expect(resources[0].file).toBe('test.yaml');
    });

    it('parses a Service document', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: default
spec:
  type: ClusterIP
  selector:
    app: myapp
  ports:
    - port: 80
      targetPort: 8080
`;
      const resources = parseContent(yaml);
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('Service');
      expect(resources[0].metadata.name).toBe('my-service');
    });

    it('parses an Ingress document', () => {
      const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: default
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-service
                port:
                  number: 80
`;
      const resources = parseContent(yaml);
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('Ingress');
      expect(resources[0].metadata.name).toBe('my-ingress');
    });

    it('returns empty array for empty content', () => {
      expect(parseContent('')).toHaveLength(0);
      expect(parseContent('   ')).toHaveLength(0);
    });

    it('skips documents without kind or apiVersion', () => {
      const yaml = `
name: foo
data: bar
`;
      expect(parseContent(yaml)).toHaveLength(0);
    });

    it('skips malformed YAML', () => {
      const yaml = `
apiVersion: v1
kind: Service
  invalid: yaml: content: [unclosed
`;
      const results = parseContent(yaml);
      expect(results).toHaveLength(0);
    });
  });

  describe('parseContent - multi-document YAML', () => {
    it('parses multiple documents separated by ---', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: svc-one
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: policy-one
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`;
      const resources = parseContent(yaml, 'multi.yaml');
      expect(resources).toHaveLength(2);
      expect(resources[0].kind).toBe('Service');
      expect(resources[1].kind).toBe('NetworkPolicy');
    });

    it('parses 3+ documents in a single file', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: svc-a
  namespace: ns-a
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: svc-b
  namespace: ns-b
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-a
  namespace: ns-a
spec: {}
`;
      const resources = parseContent(yaml);
      expect(resources).toHaveLength(3);
      expect(resources.map((r) => r.kind)).toEqual(['Service', 'Service', 'Ingress']);
    });

    it('handles --- at document start', () => {
      const yaml = `---
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: default
spec: {}
`;
      const resources = parseContent(yaml);
      expect(resources).toHaveLength(1);
      expect(resources[0].metadata.name).toBe('my-svc');
    });

    it('skips empty documents between separators', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: svc-a
  namespace: default
spec: {}
---
---
apiVersion: v1
kind: Service
metadata:
  name: svc-b
  namespace: default
spec: {}
`;
      const resources = parseContent(yaml);
      expect(resources).toHaveLength(2);
    });
  });

  describe('parseContent - metadata handling', () => {
    it('stores undefined namespace when namespace is not specified in metadata', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: no-ns-svc
spec: {}
`;
      const resources = parseContent(yaml);
      // Namespace-scoped resources without an explicit namespace field get
      // undefined — the target namespace is determined at apply-time (e.g.
      // `kubectl -n myns apply -f …`), not in the manifest itself.
      expect(resources[0].metadata.namespace).toBeUndefined();
    });

    it('stores undefined namespace for cluster-scoped resources', () => {
      const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-cluster-role
rules: []
`;
      const resources = parseContent(yaml);
      expect(resources[0].kind).toBe('ClusterRole');
      expect(resources[0].metadata.namespace).toBeUndefined();
    });

    it('parses labels and annotations', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: annotated-svc
  namespace: default
  labels:
    app: myapp
    env: prod
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  type: LoadBalancer
  ports:
    - port: 80
`;
      const resources = parseContent(yaml);
      expect(resources[0].metadata.labels?.['app']).toBe('myapp');
      expect(resources[0].metadata.annotations?.['service.beta.kubernetes.io/aws-load-balancer-type']).toBe('nlb');
    });

    it('parses Namespace resources', () => {
      const yaml = `
apiVersion: v1
kind: Namespace
metadata:
  name: production
`;
      const resources = parseContent(yaml);
      expect(resources[0].kind).toBe('Namespace');
      expect(resources[0].metadata.name).toBe('production');
    });

    it('tracks file path in parsed resource', () => {
      const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: default
spec: {}
`;
      const resources = parseContent(yaml, '/path/to/manifest.yaml');
      expect(resources[0].file).toBe('/path/to/manifest.yaml');
    });

    it('tracks approximate line numbers for multi-doc', () => {
      const yaml = `apiVersion: v1
kind: Service
metadata:
  name: svc-one
  namespace: default
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: svc-two
  namespace: default
spec: {}
`;
      const resources = parseContent(yaml);
      expect(resources[0].line).toBe(1);
      expect(resources[1].line).toBeGreaterThan(1);
    });
  });

  describe('parseContent - various resource kinds', () => {
    it('parses Deployment', () => {
      const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
`;
      const resources = parseContent(yaml);
      expect(resources[0].kind).toBe('Deployment');
    });

    it('parses StatefulSet', () => {
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
      const resources = parseContent(yaml);
      expect(resources[0].kind).toBe('StatefulSet');
      expect(resources[0].metadata.namespace).toBe('database');
    });

    it('parses ConfigMap', () => {
      const yaml = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: kube-system
spec: {}
`;
      const resources = parseContent(yaml);
      expect(resources[0].kind).toBe('ConfigMap');
      expect(resources[0].metadata.namespace).toBe('kube-system');
    });
  });
});
