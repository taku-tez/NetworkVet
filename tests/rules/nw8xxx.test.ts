import { describe, it, expect } from 'vitest';
import { parseContent } from '../../src/parser/index.js';
import { buildContext } from '../../src/rules/engine.js';
import { nw8Rules } from '../../src/rules/nw8xxx.js';

const [nw8001, nw8002, nw8003, nw8004, nw8005] = nw8Rules;

function check(rule: (typeof nw8Rules)[number], yaml: string) {
  const resources = parseContent(yaml, 'test.yaml');
  const ctx = buildContext(resources);
  return rule.check(resources, ctx);
}

// ─── NW8001 ──────────────────────────────────────────────────────────────────

describe('NW8001 — HTTPRoute without TLS termination', () => {
  it('fires when HTTPRoute has a parentRef with sectionName "http"', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
      sectionName: http
  rules:
    - backendRefs:
        - name: my-service
          port: 8080
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW8001');
    expect(findings[0].severity).toBe('medium');
  });

  it('fires when HTTPRoute has no sectionName set (defaults to non-https)', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: my-service
          port: 8080
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW8001');
  });

  it('fires when HTTPRoute has no parentRefs at all', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: orphan-route
  namespace: default
spec:
  rules:
    - backendRefs:
        - name: my-service
          port: 80
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not fire when sectionName is "https"', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: tls-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
      sectionName: https
  rules:
    - backendRefs:
        - name: my-service
          port: 8080
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire when sectionName is "tls"', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: tls-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
      sectionName: tls
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-Gateway API HTTPRoute kind', () => {
    const yaml = `
apiVersion: some.other.api/v1
kind: HTTPRoute
metadata:
  name: other-route
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire for regular Ingress resources', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: default
spec:
  rules:
    - host: example.com
`;
    const findings = check(nw8001, yaml);
    expect(findings).toHaveLength(0);
  });
});

// ─── NW8002 ──────────────────────────────────────────────────────────────────

describe('NW8002 — Gateway allows routes from all namespaces', () => {
  it('fires when a listener has allowedRoutes.namespaces.from === "All"', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: All
`;
    const findings = check(nw8002, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW8002');
    expect(findings[0].severity).toBe('medium');
  });

  it('fires for each listener with from: All', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: All
    - name: https
      port: 443
      protocol: HTTPS
      allowedRoutes:
        namespaces:
          from: All
      tls:
        certificateRefs:
          - name: my-cert
`;
    const findings = check(nw8002, yaml);
    expect(findings).toHaveLength(2);
  });

  it('does not fire when allowedRoutes.namespaces.from === "Same"', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Same
`;
    const findings = check(nw8002, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire when allowedRoutes.namespaces.from === "Selector"', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              app: my-app
`;
    const findings = check(nw8002, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire when no allowedRoutes are configured', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
`;
    const findings = check(nw8002, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-Gateway API Gateway kind', () => {
    const yaml = `
apiVersion: some.other.api/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  listeners:
    - name: http
      allowedRoutes:
        namespaces:
          from: All
`;
    const findings = check(nw8002, yaml);
    expect(findings).toHaveLength(0);
  });
});

// ─── NW8003 ──────────────────────────────────────────────────────────────────

describe('NW8003 — HTTPRoute cross-namespace backendRef without ReferenceGrant', () => {
  it('fires when cross-namespace backendRef exists and no ReferenceGrant', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: backend-svc
          namespace: backend-ns
          port: 8080
`;
    const findings = check(nw8003, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW8003');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].message).toContain('backend-ns');
  });

  it('does not fire when a matching ReferenceGrant exists', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: backend-svc
          namespace: backend-ns
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-httproute
  namespace: backend-ns
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: app-ns
  to:
    - group: ""
      kind: Service
`;
    const findings = check(nw8003, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire for same-namespace backendRef', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: backend-svc
          namespace: app-ns
          port: 8080
`;
    const findings = check(nw8003, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire when no namespace is specified in backendRef (same-namespace implied)', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: backend-svc
          port: 8080
`;
    const findings = check(nw8003, yaml);
    expect(findings).toHaveLength(0);
  });

  it('fires multiple times for multiple cross-namespace refs without grants', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: svc-1
          namespace: ns-1
          port: 8080
        - name: svc-2
          namespace: ns-2
          port: 9090
`;
    const findings = check(nw8003, yaml);
    expect(findings).toHaveLength(2);
  });

  it('does not fire when ReferenceGrant exists for one ns but not another', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: svc-1
          namespace: ns-1
          port: 8080
        - name: svc-2
          namespace: ns-2
          port: 9090
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-httproute
  namespace: ns-1
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: app-ns
  to:
    - group: ""
      kind: Service
`;
    const findings = check(nw8003, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('ns-2');
  });
});

// ─── NW8004 ──────────────────────────────────────────────────────────────────

describe('NW8004 — Gateway HTTPS/TLS listener missing certificateRefs', () => {
  it('fires when HTTPS listener has no tls section', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW8004');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].message).toContain('https');
  });

  it('fires when HTTPS listener has empty certificateRefs', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs: []
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(1);
  });

  it('fires when TLS listener has no certificateRefs', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: tls-listener
      port: 443
      protocol: TLS
      tls:
        mode: Terminate
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('tls-listener');
  });

  it('does not fire when HTTPS listener has certificateRefs', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - name: my-tls-secret
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire for HTTP listener (no TLS required)', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(0);
  });

  it('fires for HTTPS listener but not HTTP listener in the same Gateway', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  gatewayClassName: my-gateway-class
  listeners:
    - name: http
      port: 80
      protocol: HTTP
    - name: https
      port: 443
      protocol: HTTPS
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('https');
  });

  it('does not fire for non-Gateway API Gateway kind', () => {
    const yaml = `
apiVersion: some.other.api/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: default
spec:
  listeners:
    - name: https
      protocol: HTTPS
`;
    const findings = check(nw8004, yaml);
    expect(findings).toHaveLength(0);
  });
});

// ─── NW8005 ──────────────────────────────────────────────────────────────────

describe('NW8005 — GRPCRoute cross-namespace backendRef without ReferenceGrant', () => {
  it('fires when GRPCRoute has cross-namespace backendRef without ReferenceGrant', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: grpc-service
          namespace: backend-ns
          port: 9090
`;
    const findings = check(nw8005, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW8005');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].message).toContain('backend-ns');
  });

  it('does not fire when a matching ReferenceGrant exists for GRPCRoute', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: grpc-service
          namespace: backend-ns
          port: 9090
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-grpcroute
  namespace: backend-ns
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: GRPCRoute
      namespace: app-ns
  to:
    - group: ""
      kind: Service
`;
    const findings = check(nw8005, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire when a HTTPRoute ReferenceGrant exists but not GRPCRoute', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: grpc-service
          namespace: backend-ns
          port: 9090
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-httproute-only
  namespace: backend-ns
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: app-ns
  to:
    - group: ""
      kind: Service
`;
    const findings = check(nw8005, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not fire for same-namespace GRPCRoute backendRef', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: grpc-service
          namespace: app-ns
          port: 9090
`;
    const findings = check(nw8005, yaml);
    expect(findings).toHaveLength(0);
  });

  it('does not fire when no namespace specified in backendRef', () => {
    const yaml = `
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: GRPCRoute
metadata:
  name: my-grpc-route
  namespace: app-ns
spec:
  parentRefs:
    - name: my-gateway
  rules:
    - backendRefs:
        - name: grpc-service
          port: 9090
`;
    const findings = check(nw8005, yaml);
    expect(findings).toHaveLength(0);
  });
});

// ─── Edge cases & rule registration ──────────────────────────────────────────

describe('NW8 rules — registration and metadata', () => {
  it('exports exactly 5 rules', () => {
    expect(nw8Rules).toHaveLength(5);
  });

  it('all rules have unique IDs', () => {
    const ids = nw8Rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(5);
  });

  it('rule IDs are NW8001–NW8005', () => {
    const ids = nw8Rules.map((r) => r.id).sort();
    expect(ids).toEqual(['NW8001', 'NW8002', 'NW8003', 'NW8004', 'NW8005']);
  });

  it('NW8001 has medium severity', () => {
    expect(nw8001.severity).toBe('medium');
  });

  it('NW8002 has medium severity', () => {
    expect(nw8002.severity).toBe('medium');
  });

  it('NW8003 has high severity', () => {
    expect(nw8003.severity).toBe('high');
  });

  it('NW8004 has high severity', () => {
    expect(nw8004.severity).toBe('high');
  });

  it('NW8005 has high severity', () => {
    expect(nw8005.severity).toBe('high');
  });

  it('all rules have a non-empty description', () => {
    for (const rule of nw8Rules) {
      expect(rule.description.length).toBeGreaterThan(0);
    }
  });
});
