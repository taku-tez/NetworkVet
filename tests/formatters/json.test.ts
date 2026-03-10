import { describe, it, expect } from 'vitest';
import { formatJson } from '../../src/formatters/json.js';
import type { Finding } from '../../src/types.js';

const sampleFindings: Finding[] = [
  {
    id: 'NW1001',
    severity: 'error',
    kind: 'NetworkPolicy',
    name: 'allow-all',
    namespace: 'default',
    file: 'policies.yaml',
    line: 10,
    message: 'Ingress from: [{}] allows all sources',
    detail: 'Remove the empty peer',
  },
  {
    id: 'NW2001',
    severity: 'warning',
    kind: 'Service',
    name: 'my-nodeport',
    namespace: 'production',
    file: 'services.yaml',
    line: 5,
    message: 'Service uses NodePort',
  },
];

describe('formatJson', () => {
  it('returns valid JSON', () => {
    const output = formatJson(sampleFindings);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('includes version field', () => {
    const parsed = JSON.parse(formatJson(sampleFindings));
    expect(parsed.version).toBe('0.3.0');
  });

  it('includes timestamp field', () => {
    const parsed = JSON.parse(formatJson(sampleFindings));
    expect(parsed.timestamp).toBeDefined();
    expect(new Date(parsed.timestamp).toISOString()).toBeTruthy();
  });

  it('includes summary with correct counts', () => {
    const parsed = JSON.parse(formatJson(sampleFindings));
    expect(parsed.summary.total).toBe(2);
    expect(parsed.summary.errors).toBe(1);
    expect(parsed.summary.warnings).toBe(1);
    expect(parsed.summary.infos).toBe(0);
  });

  it('includes all findings in output', () => {
    const parsed = JSON.parse(formatJson(sampleFindings));
    expect(parsed.findings).toHaveLength(2);
  });

  it('includes all finding fields', () => {
    const parsed = JSON.parse(formatJson(sampleFindings));
    const finding = parsed.findings[0];
    expect(finding.id).toBe('NW1001');
    expect(finding.severity).toBe('error');
    expect(finding.kind).toBe('NetworkPolicy');
    expect(finding.name).toBe('allow-all');
    expect(finding.namespace).toBe('default');
    expect(finding.file).toBe('policies.yaml');
    expect(finding.line).toBe(10);
    expect(finding.message).toContain('allows all sources');
    expect(finding.detail).toBe('Remove the empty peer');
  });

  it('handles empty findings array', () => {
    const parsed = JSON.parse(formatJson([]));
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.summary.total).toBe(0);
    expect(parsed.summary.errors).toBe(0);
    expect(parsed.summary.warnings).toBe(0);
    expect(parsed.summary.infos).toBe(0);
  });

  it('correctly counts info severity', () => {
    const findings: Finding[] = [
      {
        id: 'NW3005',
        severity: 'info',
        kind: 'Ingress',
        name: 'my-ingress',
        namespace: 'default',
        file: 'ingress.yaml',
        line: 1,
        message: 'Missing ssl-redirect annotation',
      },
    ];
    const parsed = JSON.parse(formatJson(findings));
    expect(parsed.summary.infos).toBe(1);
    expect(parsed.summary.errors).toBe(0);
    expect(parsed.summary.warnings).toBe(0);
  });

  it('outputs pretty-printed JSON', () => {
    const output = formatJson(sampleFindings);
    // Pretty-printed JSON has newlines and indentation
    expect(output).toContain('\n');
    expect(output).toContain('  ');
  });

  it('findings without detail field omit it', () => {
    const findings: Finding[] = [
      {
        id: 'NW2001',
        severity: 'warning',
        kind: 'Service',
        name: 'svc',
        namespace: 'default',
        file: 'svc.yaml',
        line: 1,
        message: 'NodePort service',
      },
    ];
    const parsed = JSON.parse(formatJson(findings));
    expect(parsed.findings[0].detail).toBeUndefined();
  });
});
