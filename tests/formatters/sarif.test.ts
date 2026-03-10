import { describe, it, expect } from 'vitest';
import { formatSarif } from '../../src/formatters/sarif.js';
import type { Finding } from '../../src/types.js';

const sampleFindings: Finding[] = [
  {
    id: 'NW1001',
    severity: 'error',
    kind: 'NetworkPolicy',
    name: 'allow-all',
    namespace: 'default',
    file: '/project/k8s/policies.yaml',
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
    file: '/project/k8s/services.yaml',
    line: 5,
    message: 'Service uses NodePort',
  },
  {
    id: 'NW3005',
    severity: 'info',
    kind: 'Ingress',
    name: 'my-ingress',
    namespace: 'default',
    file: '/project/k8s/ingress.yaml',
    line: 1,
    message: 'Missing ssl-redirect annotation',
  },
];

describe('formatSarif', () => {
  it('returns valid JSON', () => {
    const output = formatSarif(sampleFindings);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('outputs SARIF 2.1.0 version', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    expect(parsed.version).toBe('2.1.0');
  });

  it('includes correct $schema', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    expect(parsed.$schema).toContain('sarif-schema-2.1.0');
  });

  it('includes runs array with one run', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    expect(parsed.runs).toHaveLength(1);
  });

  it('includes tool driver info', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    const driver = parsed.runs[0].tool.driver;
    expect(driver.name).toBe('NetworkVet');
    expect(driver.version).toBe('0.1.0');
    expect(driver.informationUri).toContain('NetworkVet');
  });

  it('includes rules in driver', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    const rules = parsed.runs[0].tool.driver.rules;
    expect(rules.length).toBeGreaterThan(0);
    const ruleIds = rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toContain('NW1001');
    expect(ruleIds).toContain('NW2001');
    expect(ruleIds).toContain('NW3005');
  });

  it('deduplicates rules when same ID appears multiple times', () => {
    const findings: Finding[] = [
      {
        id: 'NW1001',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p1',
        namespace: 'ns1',
        file: 'a.yaml',
        line: 1,
        message: 'msg1',
      },
      {
        id: 'NW1001',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p2',
        namespace: 'ns2',
        file: 'b.yaml',
        line: 5,
        message: 'msg2',
      },
    ];
    const parsed = JSON.parse(formatSarif(findings));
    const rules = parsed.runs[0].tool.driver.rules;
    const nw1001Rules = rules.filter((r: { id: string }) => r.id === 'NW1001');
    expect(nw1001Rules).toHaveLength(1);
  });

  it('maps error severity to SARIF level "error"', () => {
    const findings: Finding[] = [
      {
        id: 'NW1001',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p1',
        namespace: 'default',
        file: 'test.yaml',
        line: 1,
        message: 'error finding',
      },
    ];
    const parsed = JSON.parse(formatSarif(findings));
    const result = parsed.runs[0].results[0];
    expect(result.level).toBe('error');
  });

  it('maps warning severity to SARIF level "warning"', () => {
    const findings: Finding[] = [
      {
        id: 'NW2001',
        severity: 'warning',
        kind: 'Service',
        name: 's1',
        namespace: 'default',
        file: 'test.yaml',
        line: 1,
        message: 'warning finding',
      },
    ];
    const parsed = JSON.parse(formatSarif(findings));
    const result = parsed.runs[0].results[0];
    expect(result.level).toBe('warning');
  });

  it('maps info severity to SARIF level "note"', () => {
    const findings: Finding[] = [
      {
        id: 'NW3005',
        severity: 'info',
        kind: 'Ingress',
        name: 'i1',
        namespace: 'default',
        file: 'test.yaml',
        line: 1,
        message: 'info finding',
      },
    ];
    const parsed = JSON.parse(formatSarif(findings));
    const result = parsed.runs[0].results[0];
    expect(result.level).toBe('note');
  });

  it('includes physicalLocation with file URI', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    const result = parsed.runs[0].results[0];
    expect(result.locations[0].physicalLocation).toBeDefined();
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBeTruthy();
  });

  it('includes line numbers in region when line > 0', () => {
    const findings: Finding[] = [
      {
        id: 'NW1001',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p1',
        namespace: 'default',
        file: 'test.yaml',
        line: 42,
        message: 'test',
      },
    ];
    const parsed = JSON.parse(formatSarif(findings));
    const result = parsed.runs[0].results[0];
    expect(result.locations[0].physicalLocation.region.startLine).toBe(42);
  });

  it('includes logicalLocations with resource path', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    const result = parsed.runs[0].results[0];
    const logicalLoc = result.locations[0].logicalLocations[0];
    expect(logicalLoc.name).toContain('NetworkPolicy');
    expect(logicalLoc.name).toContain('allow-all');
    expect(logicalLoc.kind).toBe('resource');
  });

  it('includes detail in result properties when present', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    const result = parsed.runs[0].results[0];
    expect(result.properties.detail).toBeDefined();
  });

  it('handles empty findings array', () => {
    const parsed = JSON.parse(formatSarif([]));
    expect(parsed.runs[0].results).toHaveLength(0);
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('normalizes absolute paths to relative URIs', () => {
    const parsed = JSON.parse(formatSarif(sampleFindings));
    const uri = parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    // Should not start with / in SARIF
    expect(uri).not.toMatch(/^\//);
  });
});
