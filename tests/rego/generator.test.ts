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

function makeFinding(id: string, severity: Finding['severity'] = 'error'): Finding {
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
  });

  it('all entries are valid rule IDs that generateRegoForRule can resolve', () => {
    for (const ruleId of REGO_SUPPORTED_RULES) {
      expect(generateRegoForRule(ruleId), `rule ${ruleId}`).not.toBeNull();
    }
  });
});
