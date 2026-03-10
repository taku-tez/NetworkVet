import { describe, it, expect } from 'vitest';
import { formatTty } from '../../src/formatters/tty.js';
import type { Finding } from '../../src/types.js';

const sampleFindings: Finding[] = [
  {
    id: 'NW1001',
    severity: 'error',
    kind: 'NetworkPolicy',
    name: 'allow-all',
    namespace: 'default',
    file: 'k8s/policies.yaml',
    line: 10,
    message: 'Ingress from: [{}] allows traffic from all sources',
    detail: 'Remove the empty peer object',
  },
  {
    id: 'NW2001',
    severity: 'warning',
    kind: 'Service',
    name: 'my-nodeport',
    namespace: 'default',
    file: 'k8s/services.yaml',
    line: 5,
    message: 'Service uses NodePort which exposes ports on all cluster nodes',
  },
  {
    id: 'NW3005',
    severity: 'info',
    kind: 'Ingress',
    name: 'my-ingress',
    namespace: 'default',
    file: 'k8s/ingress.yaml',
    line: 1,
    message: 'Ingress is missing ssl-redirect annotation',
  },
];

describe('formatTty', () => {
  it('returns success message when no findings', () => {
    const output = formatTty([]);
    expect(output).toContain('No findings');
  });

  it('includes file names in output', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('k8s/policies.yaml');
    expect(output).toContain('k8s/services.yaml');
    expect(output).toContain('k8s/ingress.yaml');
  });

  it('includes rule IDs in output', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('NW1001');
    expect(output).toContain('NW2001');
    expect(output).toContain('NW3005');
  });

  it('includes severity labels', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('error');
    expect(output).toContain('warning');
    expect(output).toContain('info');
  });

  it('includes resource names', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('allow-all');
    expect(output).toContain('my-nodeport');
  });

  it('includes finding messages', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('allows traffic from all sources');
    expect(output).toContain('exposes ports on all cluster nodes');
  });

  it('includes detail text when present', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('Remove the empty peer object');
  });

  it('includes summary with counts', () => {
    const output = formatTty(sampleFindings);
    expect(output).toContain('3 finding');
    expect(output).toContain('1 error');
    expect(output).toContain('1 warning');
    expect(output).toContain('1 info');
  });

  it('groups findings by file', () => {
    const findings: Finding[] = [
      {
        id: 'NW1001',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p1',
        namespace: 'default',
        file: 'file-a.yaml',
        line: 1,
        message: 'msg1',
      },
      {
        id: 'NW1002',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p2',
        namespace: 'default',
        file: 'file-a.yaml',
        line: 20,
        message: 'msg2',
      },
      {
        id: 'NW2001',
        severity: 'warning',
        kind: 'Service',
        name: 's1',
        namespace: 'default',
        file: 'file-b.yaml',
        line: 1,
        message: 'msg3',
      },
    ];
    const output = formatTty(findings);
    // file-a.yaml should appear before its findings
    const fileAIdx = output.indexOf('file-a.yaml');
    const fileBIdx = output.indexOf('file-b.yaml');
    const msg1Idx = output.indexOf('msg1');
    const msg3Idx = output.indexOf('msg3');
    expect(fileAIdx).toBeLessThan(msg1Idx);
    expect(fileBIdx).toBeLessThan(msg3Idx);
  });

  it('handles single finding correctly', () => {
    const findings: Finding[] = [
      {
        id: 'NW3001',
        severity: 'error',
        kind: 'Ingress',
        name: 'my-ingress',
        namespace: 'production',
        file: 'ingress.yaml',
        line: 1,
        message: 'Ingress has no TLS',
      },
    ];
    const output = formatTty(findings);
    expect(output).toContain('1 finding');
    expect(output).toContain('1 error');
  });

  it('shows line numbers when line > 0', () => {
    const findings: Finding[] = [
      {
        id: 'NW1001',
        severity: 'error',
        kind: 'NetworkPolicy',
        name: 'p1',
        namespace: 'default',
        file: 'test.yaml',
        line: 42,
        message: 'test message',
      },
    ];
    const output = formatTty(findings);
    expect(output).toContain(':42');
  });
});
