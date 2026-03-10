import { describe, it, expect } from 'vitest';
import { parseContent } from '../../src/parser/index.js';
import { buildContext } from '../../src/rules/engine.js';
import {
  NW3001,
  NW3002,
  NW3003,
  NW3004,
  NW3005,
  NW3006,
  NW3007,
} from '../../src/rules/nw3xxx.js';

function check(rule: typeof NW3001, yaml: string) {
  const resources = parseContent(yaml, 'test.yaml');
  const ctx = buildContext(resources);
  return rule.check(resources, ctx);
}

describe('NW3001 — Ingress without TLS configured', () => {
  it('triggers when Ingress has no TLS section', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: no-tls-ingress
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
                name: my-svc
                port:
                  number: 80
`;
    const findings = check(NW3001, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3001');
    expect(findings[0].severity).toBe('error');
  });

  it('triggers when TLS is empty array', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: empty-tls
  namespace: default
spec:
  tls: []
  rules:
    - host: example.com
`;
    const findings = check(NW3001, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger when TLS is configured', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-ingress
  namespace: default
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-svc
                port:
                  number: 443
`;
    expect(check(NW3001, yaml)).toHaveLength(0);
  });
});

describe('NW3002 — Ingress TLS but no HSTS annotation', () => {
  it('triggers when TLS is present but no HSTS annotation', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-no-hsts
  namespace: default
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
`;
    const findings = check(NW3002, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3002');
    expect(findings[0].severity).toBe('warning');
  });

  it('does not trigger when nginx.ingress.kubernetes.io/hsts is true', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-with-hsts
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/hsts: "true"
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
`;
    expect(check(NW3002, yaml)).toHaveLength(0);
  });

  it('does not trigger when no TLS is configured (NW3001 handles that)', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: no-tls
  namespace: default
spec:
  rules:
    - host: example.com
`;
    expect(check(NW3002, yaml)).toHaveLength(0);
  });
});

describe('NW3003 — Ingress without HTTP to HTTPS redirect', () => {
  it('triggers when TLS present but no ssl-redirect annotation', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-no-redirect
  namespace: default
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
`;
    const findings = check(NW3003, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3003');
  });

  it('does not trigger when ssl-redirect annotation is true', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-with-redirect
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
`;
    expect(check(NW3003, yaml)).toHaveLength(0);
  });

  it('does not trigger when force-ssl-redirect is set', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: force-https
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
`;
    expect(check(NW3003, yaml)).toHaveLength(0);
  });
});

describe('NW3004 — Ingress with wildcard host', () => {
  it('triggers when host is wildcard *', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wildcard-ingress
  namespace: default
spec:
  rules:
    - host: "*"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: catch-all
                port:
                  number: 80
`;
    const findings = check(NW3004, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3004');
    expect(findings[0].severity).toBe('warning');
  });

  it('triggers when host is empty/missing', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: no-host-ingress
  namespace: default
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: catch-all
                port:
                  number: 80
`;
    const findings = check(NW3004, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger when host is specific', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: specific-host
  namespace: default
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
`;
    expect(check(NW3004, yaml)).toHaveLength(0);
  });
});

describe('NW3005 — Ingress without ssl-redirect annotation', () => {
  it('triggers when ssl-redirect annotation is missing', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: no-annotation
  namespace: default
spec:
  rules:
    - host: example.com
`;
    const findings = check(NW3005, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3005');
    expect(findings[0].severity).toBe('info');
  });

  it('does not trigger when annotation is present (true)', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: with-annotation
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
    - host: example.com
`;
    expect(check(NW3005, yaml)).toHaveLength(0);
  });

  it('does not trigger when annotation is explicitly false', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: explicit-no-redirect
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
spec:
  rules:
    - host: example.com
`;
    expect(check(NW3005, yaml)).toHaveLength(0);
  });
});

describe('NW3006 — Ingress exposes admin/internal paths', () => {
  it('triggers for /admin path', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
  namespace: default
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /admin
            pathType: Prefix
            backend:
              service:
                name: admin-svc
                port:
                  number: 8080
`;
    const findings = check(NW3006, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3006');
    expect(findings[0].severity).toBe('warning');
  });

  it('triggers for /_ path prefix', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: internal-path
  namespace: default
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /_status
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 8080
`;
    const findings = check(NW3006, yaml);
    expect(findings).toHaveLength(1);
  });

  it('triggers for /metrics path', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: metrics-ingress
  namespace: default
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /metrics
            pathType: Exact
            backend:
              service:
                name: app
                port:
                  number: 8080
`;
    const findings = check(NW3006, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger for /api path', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: default
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 8080
`;
    expect(check(NW3006, yaml)).toHaveLength(0);
  });
});

describe('NW3007 — Ingress references non-existent Service backend', () => {
  it('triggers when referenced Service does not exist', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: broken-ingress
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
                name: missing-service
                port:
                  number: 80
`;
    const findings = check(NW3007, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW3007');
    expect(findings[0].severity).toBe('error');
    expect(findings[0].message).toContain('missing-service');
  });

  it('does not trigger when referenced Service exists in same namespace', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: valid-ingress
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
    expect(check(NW3007, yaml)).toHaveLength(0);
  });

  it('triggers when Service exists in different namespace', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: cross-ns-svc
  namespace: other-ns
spec:
  type: ClusterIP
  ports:
    - port: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cross-ns-ingress
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
                name: cross-ns-svc
                port:
                  number: 80
`;
    const findings = check(NW3007, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger when Ingress has no rules', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: empty-ingress
  namespace: default
spec: {}
`;
    expect(check(NW3007, yaml)).toHaveLength(0);
  });
});
