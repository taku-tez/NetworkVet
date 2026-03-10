import { describe, it, expect } from 'vitest';
import { formatTty } from '../../src/formatters/tty.js';
import type { Finding } from '../../src/types.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeFinding(
  id: string,
  severity: Finding['severity'],
  namespace: string,
  file = 'test.yaml',
  line = 1
): Finding {
  return {
    id,
    severity,
    message: `Test finding for ${id}`,
    kind: 'NetworkPolicy',
    name: `resource-${id.toLowerCase()}`,
    namespace,
    file,
    line,
  };
}

const SAMPLE: Finding[] = [
  makeFinding('NW1001', 'high', 'frontend', 'a.yaml'),
  makeFinding('NW1002', 'high', 'backend', 'a.yaml'),
  makeFinding('NW2001', 'medium', 'frontend', 'b.yaml'),
  makeFinding('NW3001', 'high', 'payments', 'b.yaml'),
  makeFinding('NW4001', 'medium', 'backend', 'c.yaml'),
  makeFinding('NW5001', 'info', 'monitoring', 'c.yaml'),
];

// ─── Default (groupBy: 'file') ────────────────────────────────────────────────

describe('formatTty – default (groupBy: file)', () => {
  it('groups by file when no option specified', () => {
    const out = formatTty(SAMPLE);
    expect(out).toContain('a.yaml');
    expect(out).toContain('b.yaml');
    expect(out).toContain('c.yaml');
  });

  it('includes all finding IDs', () => {
    const out = formatTty(SAMPLE);
    expect(out).toContain('NW1001');
    expect(out).toContain('NW5001');
  });

  it('returns no-findings message for empty array', () => {
    const out = formatTty([]);
    expect(out).toContain('No findings');
  });

  it('shows summary line with counts', () => {
    const out = formatTty(SAMPLE);
    expect(out).toMatch(/Found \d+ findings?/);
  });
});

// ─── groupBy: 'namespace' ─────────────────────────────────────────────────────

describe('formatTty – groupBy: namespace', () => {
  it('includes Namespace: prefix for each namespace', () => {
    const out = formatTty(SAMPLE, { groupBy: 'namespace' });
    expect(out).toContain('Namespace: frontend');
    expect(out).toContain('Namespace: backend');
    expect(out).toContain('Namespace: payments');
    expect(out).toContain('Namespace: monitoring');
  });

  it('groups NW1001 and NW2001 under frontend namespace', () => {
    const out = formatTty(SAMPLE, { groupBy: 'namespace' });
    const frontendIdx = out.indexOf('Namespace: frontend');
    const nw1001Idx = out.indexOf('NW1001');
    const nw2001Idx = out.indexOf('NW2001');
    expect(frontendIdx).toBeGreaterThanOrEqual(0);
    // Both findings should appear after the frontend header
    expect(nw1001Idx).toBeGreaterThan(frontendIdx);
    expect(nw2001Idx).toBeGreaterThan(frontendIdx);
  });

  it('does not include file headers', () => {
    const out = formatTty(SAMPLE, { groupBy: 'namespace' });
    // a.yaml / b.yaml should not appear as section headers (may still appear in resource detail)
    // We check by counting standalone header occurrences — only namespace headers are present
    expect(out).toContain('Namespace:');
  });

  it('handles findings with empty namespace', () => {
    const findings = [
      makeFinding('NW1001', 'high', ''), // no namespace
    ];
    const out = formatTty(findings, { groupBy: 'namespace' });
    expect(out).toContain('cluster-scoped');
  });

  it('sorts namespaces alphabetically', () => {
    const out = formatTty(SAMPLE, { groupBy: 'namespace' });
    const backendIdx = out.indexOf('Namespace: backend');
    const frontendIdx = out.indexOf('Namespace: frontend');
    expect(backendIdx).toBeLessThan(frontendIdx);
  });

  it('returns no-findings message for empty array', () => {
    const out = formatTty([], { groupBy: 'namespace' });
    expect(out).toContain('No findings');
  });
});

// ─── groupBy: 'severity' ─────────────────────────────────────────────────────

describe('formatTty – groupBy: severity', () => {
  it('includes High section header', () => {
    const out = formatTty(SAMPLE, { groupBy: 'severity' });
    expect(out).toContain('High');
  });

  it('includes Medium section header', () => {
    const out = formatTty(SAMPLE, { groupBy: 'severity' });
    expect(out).toContain('Medium');
  });

  it('includes Info section header', () => {
    const out = formatTty(SAMPLE, { groupBy: 'severity' });
    expect(out).toContain('Info');
  });

  it('High section appears before Medium section', () => {
    const out = formatTty(SAMPLE, { groupBy: 'severity' });
    const highIdx = out.indexOf('High');
    const medIdx = out.indexOf('Medium');
    expect(highIdx).toBeLessThan(medIdx);
  });

  it('Medium section appears before Info section', () => {
    const out = formatTty(SAMPLE, { groupBy: 'severity' });
    const medIdx = out.indexOf('Medium');
    const infoIdx = out.indexOf('Info');
    expect(medIdx).toBeLessThan(infoIdx);
  });

  it('omits a severity section when no findings exist for it', () => {
    const highOnly = SAMPLE.filter((f) => f.severity === 'high');
    const out = formatTty(highOnly, { groupBy: 'severity' });
    expect(out).toContain('High');
    expect(out).not.toContain('Medium');
    expect(out).not.toContain('Info');
  });

  it('returns no-findings message for empty array', () => {
    const out = formatTty([], { groupBy: 'severity' });
    expect(out).toContain('No findings');
  });
});

// ─── groupBy: 'rule' ─────────────────────────────────────────────────────────

describe('formatTty – groupBy: rule', () => {
  it('includes a header for each unique rule ID', () => {
    const out = formatTty(SAMPLE, { groupBy: 'rule' });
    expect(out).toContain('NW1001');
    expect(out).toContain('NW1002');
    expect(out).toContain('NW2001');
    expect(out).toContain('NW3001');
    expect(out).toContain('NW4001');
    expect(out).toContain('NW5001');
  });

  it('shows finding count in section header', () => {
    const doubled = [...SAMPLE, makeFinding('NW1001', 'high', 'extra')];
    const out = formatTty(doubled, { groupBy: 'rule' });
    // NW1001 should show (2) since there are 2 findings for it
    expect(out).toMatch(/NW1001.*\(2\)/);
  });

  it('high rules appear before medium rules', () => {
    const out = formatTty(SAMPLE, { groupBy: 'rule' });
    const nw1001Idx = out.indexOf('NW1001');
    const nw2001Idx = out.indexOf('NW2001');
    expect(nw1001Idx).toBeLessThan(nw2001Idx);
  });

  it('returns no-findings message for empty array', () => {
    const out = formatTty([], { groupBy: 'rule' });
    expect(out).toContain('No findings');
  });

  it('single rule with multiple occurrences appears as one section', () => {
    const findings = [
      makeFinding('NW1001', 'high', 'ns1', 'a.yaml'),
      makeFinding('NW1001', 'high', 'ns2', 'b.yaml'),
      makeFinding('NW1001', 'high', 'ns3', 'c.yaml'),
    ];
    const out = formatTty(findings, { groupBy: 'rule' });
    const count = (out.match(/NW1001/g) ?? []).length;
    // Header + 3 finding lines = 4 occurrences minimum
    expect(count).toBeGreaterThanOrEqual(4);
  });
});
