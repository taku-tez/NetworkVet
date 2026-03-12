import { describe, it, expect } from 'vitest';
import { parseContent } from '../../src/parser/index.js';
import { runRules } from '../../src/rules/engine.js';

describe('networkvet.io/ignore annotation (inline ignore)', () => {
  it('suppresses a specific rule for a resource with the annotation', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: default
  annotations:
    networkvet.io/ignore: "NW1001"
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
  policyTypes:
    - Ingress
`;
    const resources = parseContent(yaml, 'test.yaml');
    const findings = runRules(resources, []);
    expect(findings.some(f => f.id === 'NW1001' && f.name === 'allow-all-ingress')).toBe(false);
  });

  it('does not suppress other rules on the same resource', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: default
  annotations:
    networkvet.io/ignore: "NW1001"
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
  egress:
    - to:
        - {}
  policyTypes:
    - Ingress
    - Egress
`;
    const resources = parseContent(yaml, 'test.yaml');
    const findings = runRules(resources, []);
    // NW1001 is suppressed but NW1002 (egress wildcard) should still fire
    expect(findings.some(f => f.id === 'NW1001' && f.name === 'allow-all-ingress')).toBe(false);
    expect(findings.some(f => f.id === 'NW1002' && f.name === 'allow-all-ingress')).toBe(true);
  });

  it('supports multiple rule IDs in the annotation (comma-separated)', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: default
  annotations:
    networkvet.io/ignore: "NW1001, NW1002"
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
  egress:
    - to:
        - {}
  policyTypes:
    - Ingress
    - Egress
`;
    const resources = parseContent(yaml, 'test.yaml');
    const findings = runRules(resources, []);
    expect(findings.some(f => f.id === 'NW1001' && f.name === 'allow-all')).toBe(false);
    expect(findings.some(f => f.id === 'NW1002' && f.name === 'allow-all')).toBe(false);
  });

  it('does not affect other resources without the annotation', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-annotated
  namespace: default
  annotations:
    networkvet.io/ignore: "NW1001"
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
  policyTypes:
    - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-plain
  namespace: default
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
  policyTypes:
    - Ingress
`;
    const resources = parseContent(yaml, 'test.yaml');
    const findings = runRules(resources, []);
    expect(findings.some(f => f.id === 'NW1001' && f.name === 'allow-all-annotated')).toBe(false);
    expect(findings.some(f => f.id === 'NW1001' && f.name === 'allow-all-plain')).toBe(true);
  });

  it('is case-insensitive for rule IDs in the annotation', () => {
    const yaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: default
  annotations:
    networkvet.io/ignore: "nw1001"
spec:
  podSelector: {}
  ingress:
    - from:
        - {}
  policyTypes:
    - Ingress
`;
    const resources = parseContent(yaml, 'test.yaml');
    const findings = runRules(resources, []);
    expect(findings.some(f => f.id === 'NW1001' && f.name === 'allow-all-ingress')).toBe(false);
  });
});
