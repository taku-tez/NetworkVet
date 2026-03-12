import { describe, it, expect } from 'vitest';
import { formatComplianceTty, formatComplianceJson } from '../../src/formatters/compliance.js';
import type { Finding } from '../../src/types.js';

function makeFinding(id: string, severity: Finding['severity'] = 'high'): Finding {
  return {
    id,
    severity,
    kind: 'NetworkPolicy',
    name: 'test-policy',
    namespace: 'default',
    file: 'test.yaml',
    line: 1,
    message: `Test finding for ${id}`,
  };
}

describe('formatComplianceTty', () => {
  it('returns a string', () => {
    const output = formatComplianceTty([makeFinding('NW1001')]);
    expect(typeof output).toBe('string');
  });

  it('contains the rule ID', () => {
    const output = formatComplianceTty([makeFinding('NW1001')]);
    expect(output).toContain('NW1001');
  });

  it('contains CIS framework reference for NW1001', () => {
    const output = formatComplianceTty([makeFinding('NW1001')]);
    expect(output).toContain('CIS');
    expect(output).toContain('5.3.2');
  });

  it('contains NSA framework reference for NW3001', () => {
    const output = formatComplianceTty([makeFinding('NW3001')]);
    expect(output).toContain('NSA');
  });

  it('returns no-findings message for empty input', () => {
    const output = formatComplianceTty([]);
    expect(output).toContain('No findings');
  });

  it('filters by CIS framework', () => {
    const findings = [makeFinding('NW1001'), makeFinding('NW3001')];
    const output = formatComplianceTty(findings, 'cis');
    expect(output).toContain('CIS');
  });

  it('filters by NSA framework', () => {
    const findings = [makeFinding('NW5005')];
    const output = formatComplianceTty(findings, 'nsa');
    expect(output).toContain('NSA');
  });

  it('includes total count', () => {
    const output = formatComplianceTty([makeFinding('NW1001'), makeFinding('NW4002')]);
    expect(output).toContain('Total:');
  });

  it('handles findings with no compliance mapping', () => {
    const output = formatComplianceTty([makeFinding('NW9999' as 'NW1001')]);
    expect(typeof output).toBe('string');
  });
});

describe('formatComplianceJson', () => {
  it('returns valid JSON', () => {
    const output = formatComplianceJson([makeFinding('NW1001')]);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('JSON contains complianceFindings array', () => {
    const output = formatComplianceJson([makeFinding('NW1001')]);
    const parsed = JSON.parse(output);
    expect(Array.isArray(parsed.complianceFindings)).toBe(true);
  });

  it('each finding has compliance array', () => {
    const output = formatComplianceJson([makeFinding('NW1001')]);
    const parsed = JSON.parse(output);
    expect(parsed.complianceFindings[0].compliance).toBeDefined();
    expect(Array.isArray(parsed.complianceFindings[0].compliance)).toBe(true);
  });

  it('filters by NSA when framework=nsa', () => {
    const output = formatComplianceJson([makeFinding('NW1001')], 'nsa');
    const parsed = JSON.parse(output);
    const refs = parsed.complianceFindings[0]?.compliance ?? [];
    expect(refs.every((r: { framework: string }) => r.framework === 'NSA')).toBe(true);
  });

  it('returns total count', () => {
    const output = formatComplianceJson([makeFinding('NW1001'), makeFinding('NW3001')]);
    const parsed = JSON.parse(output);
    expect(typeof parsed.total).toBe('number');
  });
});
