import { describe, it, expect } from 'vitest';
import { generateRegoForRule, REGO_SUPPORTED_RULES } from '../../src/rego/generator.js';

const NW8_RULE_IDS = ['NW8001', 'NW8002', 'NW8003', 'NW8004', 'NW8005'];

describe('NW8xxx — Rego policy presence', () => {
  for (const ruleId of NW8_RULE_IDS) {
    it(`${ruleId} is present in REGO_SUPPORTED_RULES`, () => {
      expect(REGO_SUPPORTED_RULES).toContain(ruleId);
    });

    it(`${ruleId} returns a non-null RegoPolicy`, () => {
      const policy = generateRegoForRule(ruleId);
      expect(policy).not.toBeNull();
    });

    it(`${ruleId} Rego contains "package" keyword`, () => {
      const policy = generateRegoForRule(ruleId);
      expect(policy!.rego).toContain('package');
    });

    it(`${ruleId} Rego contains "deny" or "violation" rule`, () => {
      const policy = generateRegoForRule(ruleId);
      const hasDeny = policy!.rego.includes('deny[') || policy!.rego.includes('violation[');
      expect(hasDeny).toBe(true);
    });

    it(`${ruleId} has the correct package name`, () => {
      const policy = generateRegoForRule(ruleId);
      expect(policy!.rego).toContain(`package networkvet.${ruleId.toLowerCase()}`);
    });

    it(`${ruleId} has a non-empty description`, () => {
      const policy = generateRegoForRule(ruleId);
      expect(policy!.description.length).toBeGreaterThan(0);
    });
  }
});

describe('NW8xxx — Rego policy content validation', () => {
  it('NW8001 Rego targets HTTPRoute kind', () => {
    const policy = generateRegoForRule('NW8001');
    expect(policy!.rego).toContain('HTTPRoute');
  });

  it('NW8001 Rego checks gateway.networking.k8s.io apiVersion', () => {
    const policy = generateRegoForRule('NW8001');
    expect(policy!.rego).toContain('gateway.networking.k8s.io');
  });

  it('NW8002 Rego targets Gateway kind', () => {
    const policy = generateRegoForRule('NW8002');
    expect(policy!.rego).toContain('Gateway');
  });

  it('NW8002 Rego checks for "All" namespace policy', () => {
    const policy = generateRegoForRule('NW8002');
    expect(policy!.rego).toContain('"All"');
  });

  it('NW8003 Rego targets HTTPRoute kind', () => {
    const policy = generateRegoForRule('NW8003');
    expect(policy!.rego).toContain('HTTPRoute');
  });

  it('NW8003 Rego checks backendRefs namespace', () => {
    const policy = generateRegoForRule('NW8003');
    expect(policy!.rego).toContain('backendRefs');
  });

  it('NW8004 Rego targets Gateway kind', () => {
    const policy = generateRegoForRule('NW8004');
    expect(policy!.rego).toContain('Gateway');
  });

  it('NW8004 Rego checks HTTPS protocol', () => {
    const policy = generateRegoForRule('NW8004');
    expect(policy!.rego).toContain('HTTPS');
  });

  it('NW8004 Rego checks certificateRefs', () => {
    const policy = generateRegoForRule('NW8004');
    expect(policy!.rego).toContain('certificateRefs');
  });

  it('NW8005 Rego targets GRPCRoute kind', () => {
    const policy = generateRegoForRule('NW8005');
    expect(policy!.rego).toContain('GRPCRoute');
  });

  it('NW8005 Rego checks backendRefs namespace', () => {
    const policy = generateRegoForRule('NW8005');
    expect(policy!.rego).toContain('backendRefs');
  });
});

describe('NW8xxx — case-insensitive lookup', () => {
  for (const ruleId of NW8_RULE_IDS) {
    it(`${ruleId} can be looked up with lowercase`, () => {
      const policy = generateRegoForRule(ruleId.toLowerCase());
      expect(policy).not.toBeNull();
      expect(policy!.ruleId).toBe(ruleId);
    });
  }
});
