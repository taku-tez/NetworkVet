import { describe, it, expect } from 'vitest';
import {
  generateRegoForRule,
  generateRegoForFindings,
  generateGatekeeperConstraint,
  generateConftestPolicy,
  REGO_SUPPORTED_RULES,
} from '../../src/rego/generator.js';
import type { Finding } from '../../src/types.js';

// ─── Helper ───────────────────────────────────────────────────────────────────

function makeFinding(id: string, severity: Finding['severity'] = 'high'): Finding {
  return {
    id,
    severity,
    message: `Test finding for ${id}`,
    resource: 'test-resource',
    file: 'test.yaml',
    line: 1,
    kind: 'NetworkPolicy',
  };
}

// ─── generateRegoForRule ──────────────────────────────────────────────────────

describe('generateRegoForRule', () => {
  it('returns null for an unknown rule ID', () => {
    expect(generateRegoForRule('NW9999')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(generateRegoForRule('')).toBeNull();
  });

  it('is case-insensitive (lowercase input)', () => {
    const policy = generateRegoForRule('nw1001');
    expect(policy).not.toBeNull();
    expect(policy!.ruleId).toBe('NW1001');
  });

  it('returns a RegoPolicy for NW1001 with correct fields', () => {
    const policy = generateRegoForRule('NW1001');
    expect(policy).not.toBeNull();
    expect(policy!.ruleId).toBe('NW1001');
    expect(policy!.name).toBe('nw1001_deny_wildcard_ingress');
    expect(policy!.package).toBe('networkvet.nw1001');
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('package networkvet.nw1001');
    expect(policy!.rego).toContain('violation[{"msg": msg}]');
  });

  it('returns a RegoPolicy for NW1002', () => {
    const policy = generateRegoForRule('NW1002');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('egress');
  });

  it('returns a RegoPolicy for NW1003 with warn enforcement', () => {
    const policy = generateRegoForRule('NW1003');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('Namespace');
  });

  it('returns a RegoPolicy for NW2001 with warn enforcement', () => {
    const policy = generateRegoForRule('NW2001');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('NodePort');
  });

  it('returns a RegoPolicy for NW2002', () => {
    const policy = generateRegoForRule('NW2002');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('LoadBalancer');
    expect(policy!.rego).toContain('externalTrafficPolicy');
  });

  it('returns a RegoPolicy for NW3001 with deny enforcement', () => {
    const policy = generateRegoForRule('NW3001');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('Ingress');
  });

  it('returns a RegoPolicy for NW3004', () => {
    const policy = generateRegoForRule('NW3004');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('wildcard');
  });

  it('returns a RegoPolicy for NW5001 with deny enforcement', () => {
    const policy = generateRegoForRule('NW5001');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('AuthorizationPolicy');
  });

  it('returns a RegoPolicy for NW5005 with warn enforcement', () => {
    const policy = generateRegoForRule('NW5005');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('PERMISSIVE');
  });

  it('returns a RegoPolicy for NW5006 with deny enforcement', () => {
    const policy = generateRegoForRule('NW5006');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('DISABLE');
  });

  it('returns a RegoPolicy for NW6001 with deny enforcement', () => {
    const policy = generateRegoForRule('NW6001');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('world');
  });

  it('returns a RegoPolicy for NW6005 with deny enforcement', () => {
    const policy = generateRegoForRule('NW6005');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('0.0.0.0/0');
  });

  it('returns a RegoPolicy for NW1004 with warn enforcement', () => {
    const policy = generateRegoForRule('NW1004');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('podSelector');
  });

  it('returns a RegoPolicy for NW1005 with deny enforcement', () => {
    const policy = generateRegoForRule('NW1005');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('namespaceSelector');
  });

  it('returns a RegoPolicy for NW2003 with warn enforcement', () => {
    const policy = generateRegoForRule('NW2003');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('LoadBalancer');
    expect(policy!.rego).toContain('loadBalancerSourceRanges');
  });

  it('returns a RegoPolicy for NW2004 with warn enforcement', () => {
    const policy = generateRegoForRule('NW2004');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('22');
  });

  it('returns a RegoPolicy for NW2006 with deny enforcement', () => {
    const policy = generateRegoForRule('NW2006');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('externalIPs');
  });

  it('returns a RegoPolicy for NW2008 with deny enforcement', () => {
    const policy = generateRegoForRule('NW2008');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('ExternalName');
    expect(policy!.rego).toContain('cluster.local');
  });

  it('returns a RegoPolicy for NW3002 with warn enforcement', () => {
    const policy = generateRegoForRule('NW3002');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('hsts');
  });

  it('returns a RegoPolicy for NW3003 with warn enforcement', () => {
    const policy = generateRegoForRule('NW3003');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('ssl-redirect');
  });

  it('returns a RegoPolicy for NW3006 with warn enforcement', () => {
    const policy = generateRegoForRule('NW3006');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('admin');
  });

  it('returns a RegoPolicy for NW4001 with warn enforcement', () => {
    const policy = generateRegoForRule('NW4001');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('NetworkPolicy');
  });

  it('returns a RegoPolicy for NW4005 with deny enforcement', () => {
    const policy = generateRegoForRule('NW4005');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('169.254.169.254');
  });

  it('returns a RegoPolicy for NW5002 with deny enforcement', () => {
    const policy = generateRegoForRule('NW5002');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('AuthorizationPolicy');
  });

  it('returns a RegoPolicy for NW5003 with warn enforcement', () => {
    const policy = generateRegoForRule('NW5003');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('methods');
  });

  it('returns a RegoPolicy for NW5004 with deny enforcement', () => {
    const policy = generateRegoForRule('NW5004');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('ALLOW');
  });

  it('returns a RegoPolicy for NW5007 with warn enforcement', () => {
    const policy = generateRegoForRule('NW5007');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('matchLabels');
  });

  it('returns a RegoPolicy for NW5008 with warn enforcement', () => {
    const policy = generateRegoForRule('NW5008');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('namespaces');
  });

  it('returns a RegoPolicy for NW6002 with warn enforcement', () => {
    const policy = generateRegoForRule('NW6002');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('world');
  });

  it('returns a RegoPolicy for NW6003 with deny enforcement', () => {
    const policy = generateRegoForRule('NW6003');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('"all"');
  });

  it('returns a RegoPolicy for NW6004 with warn enforcement', () => {
    const policy = generateRegoForRule('NW6004');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('endpointSelector');
  });

  it('returns a RegoPolicy for NW6006 with warn enforcement', () => {
    const policy = generateRegoForRule('NW6006');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('nodeSelector');
  });

  it('returns a RegoPolicy for NW6007 with warn enforcement', () => {
    const policy = generateRegoForRule('NW6007');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('matchPattern');
  });

  it('returns a RegoPolicy for NW1006 with warn enforcement', () => {
    const policy = generateRegoForRule('NW1006');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('warn');
    expect(policy!.rego).toContain('53');
  });

  it('returns a RegoPolicy for NW1007', () => {
    const policy = generateRegoForRule('NW1007');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('kube-system');
  });

  it('returns a RegoPolicy for NW1008', () => {
    const policy = generateRegoForRule('NW1008');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('policyTypes');
  });

  it('returns a RegoPolicy for NW1009', () => {
    const policy = generateRegoForRule('NW1009');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('Deployment');
  });

  it('returns a RegoPolicy for NW1010', () => {
    const policy = generateRegoForRule('NW1010');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('Egress');
  });

  it('returns a RegoPolicy for NW2005', () => {
    const policy = generateRegoForRule('NW2005');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('None');
  });

  it('returns a RegoPolicy for NW2007', () => {
    const policy = generateRegoForRule('NW2007');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('sessionAffinity');
  });

  it('returns a RegoPolicy for NW3005', () => {
    const policy = generateRegoForRule('NW3005');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('ssl-redirect');
  });

  it('returns a RegoPolicy for NW3007', () => {
    const policy = generateRegoForRule('NW3007');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('backend');
  });

  it('returns a RegoPolicy for NW4002', () => {
    const policy = generateRegoForRule('NW4002');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('flannel');
  });

  it('returns a RegoPolicy for NW4003', () => {
    const policy = generateRegoForRule('NW4003');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('namespaceSelector');
  });

  it('returns a RegoPolicy for NW4004', () => {
    const policy = generateRegoForRule('NW4004');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('kube-system');
  });

  it('returns a RegoPolicy for NW6008', () => {
    const policy = generateRegoForRule('NW6008');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('http');
  });

  it('returns a RegoPolicy for NW7001 (AWS NLB)', () => {
    const policy = generateRegoForRule('NW7001');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('nlb');
  });

  it('returns a RegoPolicy for NW7002 (AWS access logs)', () => {
    const policy = generateRegoForRule('NW7002');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('access-log-enabled');
  });

  it('returns a RegoPolicy for NW7003 (AWS SSL cert)', () => {
    const policy = generateRegoForRule('NW7003');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('ssl-cert');
  });

  it('returns a RegoPolicy for NW7004 (AWS TLS policy)', () => {
    const policy = generateRegoForRule('NW7004');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('negotiation-policy');
  });

  it('returns a RegoPolicy for NW7005 (ALB scheme)', () => {
    const policy = generateRegoForRule('NW7005');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('alb');
  });

  it('returns a RegoPolicy for NW7006 (ALB security group) with deny enforcement', () => {
    const policy = generateRegoForRule('NW7006');
    expect(policy).not.toBeNull();
    expect(policy!.enforcementAction).toBe('deny');
    expect(policy!.rego).toContain('security-groups');
  });

  it('returns a RegoPolicy for NW7007 (ALB ssl-policy)', () => {
    const policy = generateRegoForRule('NW7007');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('ssl-policy');
  });

  it('returns a RegoPolicy for NW7008 (AWS draining)', () => {
    const policy = generateRegoForRule('NW7008');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('draining');
  });

  it('returns a RegoPolicy for NW7009 (GKE LB)', () => {
    const policy = generateRegoForRule('NW7009');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('gke.io');
  });

  it('returns a RegoPolicy for NW7010 (GCE HTTP)', () => {
    const policy = generateRegoForRule('NW7010');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('gce');
  });

  it('returns a RegoPolicy for NW7011 (GKE type annotation)', () => {
    const policy = generateRegoForRule('NW7011');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('load-balancer-type');
  });

  it('returns a RegoPolicy for NW7012 (GKE Cloud Armor)', () => {
    const policy = generateRegoForRule('NW7012');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('BackendConfig');
  });

  it('returns a RegoPolicy for NW7013 (AKS explicit public)', () => {
    const policy = generateRegoForRule('NW7013');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('azure-load-balancer-internal');
  });

  it('returns a RegoPolicy for NW7014 (AKS no annotation)', () => {
    const policy = generateRegoForRule('NW7014');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('azure');
  });

  it('returns a RegoPolicy for NW7015 (AGIC WAF)', () => {
    const policy = generateRegoForRule('NW7015');
    expect(policy).not.toBeNull();
    expect(policy!.rego).toContain('waf');
  });

  it('all returned policies have non-empty description', () => {
    for (const ruleId of REGO_SUPPORTED_RULES) {
      const policy = generateRegoForRule(ruleId);
      expect(policy!.description.length, `description for ${ruleId}`).toBeGreaterThan(0);
    }
  });

  it('package matches ruleId lowercase', () => {
    for (const ruleId of REGO_SUPPORTED_RULES) {
      const policy = generateRegoForRule(ruleId);
      expect(policy!.package).toBe(`networkvet.${ruleId.toLowerCase()}`);
    }
  });
});

// ─── generateRegoForFindings ──────────────────────────────────────────────────

describe('generateRegoForFindings', () => {
  it('returns empty array for empty findings list', () => {
    expect(generateRegoForFindings([])).toEqual([]);
  });

  it('returns policies for known rule IDs in findings', () => {
    const findings = [makeFinding('NW1001'), makeFinding('NW2001')];
    const policies = generateRegoForFindings(findings);
    expect(policies).toHaveLength(2);
    expect(policies.map((p) => p.ruleId)).toContain('NW1001');
    expect(policies.map((p) => p.ruleId)).toContain('NW2001');
  });

  it('deduplicates findings with the same rule ID', () => {
    const findings = [makeFinding('NW1001'), makeFinding('NW1001'), makeFinding('NW1001')];
    const policies = generateRegoForFindings(findings);
    expect(policies).toHaveLength(1);
  });

  it('silently skips findings for unknown rule IDs', () => {
    const findings = [makeFinding('NW9999'), makeFinding('NW1001')];
    const policies = generateRegoForFindings(findings);
    expect(policies).toHaveLength(1);
    expect(policies[0].ruleId).toBe('NW1001');
  });

  it('returns empty when all findings have unknown rule IDs', () => {
    const findings = [makeFinding('NW8000'), makeFinding('NW9000')];
    expect(generateRegoForFindings(findings)).toHaveLength(0);
  });

  it('is case-insensitive for finding IDs', () => {
    const findings = [makeFinding('nw1001')];
    const policies = generateRegoForFindings(findings);
    expect(policies).toHaveLength(1);
    expect(policies[0].ruleId).toBe('NW1001');
  });
});

// ─── generateGatekeeperConstraint ────────────────────────────────────────────

describe('generateGatekeeperConstraint', () => {
  it('generates a ConstraintTemplate YAML with correct apiVersion', () => {
    const policy = generateRegoForRule('NW1001')!;
    const yaml = generateGatekeeperConstraint(policy);
    expect(yaml).toContain('apiVersion: templates.gatekeeper.sh/v1');
    expect(yaml).toContain('kind: ConstraintTemplate');
  });

  it('includes the rule description in annotations', () => {
    const policy = generateRegoForRule('NW1001')!;
    const yaml = generateGatekeeperConstraint(policy);
    expect(yaml).toContain('description:');
  });

  it('includes the Rego body indented in the YAML', () => {
    const policy = generateRegoForRule('NW1001')!;
    const yaml = generateGatekeeperConstraint(policy);
    expect(yaml).toContain('        package networkvet.nw1001');
    expect(yaml).toContain('        violation[{\"msg\": msg}]');
  });

  it('uses the correct metadata name (lowercase rule ID)', () => {
    const policy = generateRegoForRule('NW1001')!;
    const yaml = generateGatekeeperConstraint(policy);
    expect(yaml).toContain('name: networkvetnw1001');
  });

  it('generates for NW5001 with AuthorizationPolicy content', () => {
    const policy = generateRegoForRule('NW5001')!;
    const yaml = generateGatekeeperConstraint(policy);
    expect(yaml).toContain('AuthorizationPolicy');
  });

  it('targets admission.k8s.gatekeeper.sh', () => {
    const policy = generateRegoForRule('NW2001')!;
    const yaml = generateGatekeeperConstraint(policy);
    expect(yaml).toContain('target: admission.k8s.gatekeeper.sh');
  });
});

// ─── generateConftestPolicy ───────────────────────────────────────────────────

describe('generateConftestPolicy', () => {
  it('replaces violation with deny for deny-enforcement rules', () => {
    const policy = generateRegoForRule('NW1001')!;
    const conftest = generateConftestPolicy(policy);
    expect(conftest).toContain('deny[msg]');
    expect(conftest).not.toContain('violation[{"msg": msg}]');
  });

  it('replaces violation with warn for warn-enforcement rules', () => {
    const policy = generateRegoForRule('NW2001')!;
    const conftest = generateConftestPolicy(policy);
    expect(conftest).toContain('warn[msg]');
    expect(conftest).not.toContain('violation[{"msg": msg}]');
  });

  it('includes a header comment referencing the rule ID', () => {
    const policy = generateRegoForRule('NW3001')!;
    const conftest = generateConftestPolicy(policy);
    expect(conftest).toContain('# NetworkVet NW3001');
  });

  it('includes conftest usage comment', () => {
    const policy = generateRegoForRule('NW1001')!;
    const conftest = generateConftestPolicy(policy);
    expect(conftest).toContain('conftest');
  });

  it('preserves the package declaration', () => {
    const policy = generateRegoForRule('NW6001')!;
    const conftest = generateConftestPolicy(policy);
    expect(conftest).toContain('package networkvet.nw6001');
  });
});

// ─── REGO_SUPPORTED_RULES ─────────────────────────────────────────────────────

describe('REGO_SUPPORTED_RULES', () => {
  it('is a non-empty array', () => {
    expect(REGO_SUPPORTED_RULES.length).toBeGreaterThan(0);
  });

  it('contains expected rule IDs', () => {
    expect(REGO_SUPPORTED_RULES).toContain('NW1001');
    expect(REGO_SUPPORTED_RULES).toContain('NW5001');
    expect(REGO_SUPPORTED_RULES).toContain('NW6005');
    expect(REGO_SUPPORTED_RULES).toContain('NW1004');
    expect(REGO_SUPPORTED_RULES).toContain('NW1005');
    expect(REGO_SUPPORTED_RULES).toContain('NW2003');
    expect(REGO_SUPPORTED_RULES).toContain('NW2004');
    expect(REGO_SUPPORTED_RULES).toContain('NW2006');
    expect(REGO_SUPPORTED_RULES).toContain('NW2008');
    expect(REGO_SUPPORTED_RULES).toContain('NW3002');
    expect(REGO_SUPPORTED_RULES).toContain('NW3003');
    expect(REGO_SUPPORTED_RULES).toContain('NW3006');
    expect(REGO_SUPPORTED_RULES).toContain('NW4001');
    expect(REGO_SUPPORTED_RULES).toContain('NW4005');
    expect(REGO_SUPPORTED_RULES).toContain('NW5002');
    expect(REGO_SUPPORTED_RULES).toContain('NW5003');
    expect(REGO_SUPPORTED_RULES).toContain('NW5004');
    expect(REGO_SUPPORTED_RULES).toContain('NW5007');
    expect(REGO_SUPPORTED_RULES).toContain('NW5008');
    expect(REGO_SUPPORTED_RULES).toContain('NW6002');
    expect(REGO_SUPPORTED_RULES).toContain('NW6003');
    expect(REGO_SUPPORTED_RULES).toContain('NW6004');
    expect(REGO_SUPPORTED_RULES).toContain('NW6006');
    expect(REGO_SUPPORTED_RULES).toContain('NW6007');
    expect(REGO_SUPPORTED_RULES).toContain('NW7001');
    expect(REGO_SUPPORTED_RULES).toContain('NW7015');
    expect(REGO_SUPPORTED_RULES).toContain('NW1006');
    expect(REGO_SUPPORTED_RULES).toContain('NW4002');
  });

  it('all entries are valid rule IDs that generateRegoForRule can resolve', () => {
    for (const ruleId of REGO_SUPPORTED_RULES) {
      expect(generateRegoForRule(ruleId), `rule ${ruleId}`).not.toBeNull();
    }
  });
});
