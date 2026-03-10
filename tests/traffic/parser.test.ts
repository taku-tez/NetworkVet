import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import {
  parseHubbleLogs,
  parseFalcoLogs,
  parseGenericLogs,
  detectLogFormat,
} from '../../src/traffic/parser.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES = join(__dirname, '../../tests/fixtures/traffic');

// ─── parseHubbleLogs ──────────────────────────────────────────────────────────

describe('parseHubbleLogs', () => {
  it('parses a FORWARDED flow as verdict ALLOW', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:00Z',
      verdict: 'FORWARDED',
      source: { namespace: 'frontend', pod_name: 'frontend-abc' },
      destination: { namespace: 'payments', pod_name: 'payments-xyz', port: 8080 },
      l4: { TCP: { destination_port: 8080 } },
      IP: { source: '10.0.0.5', destination: '10.0.1.10' },
    });
    const flows = parseHubbleLogs(line);
    expect(flows).toHaveLength(1);
    expect(flows[0].verdict).toBe('ALLOW');
    expect(flows[0].sourceNamespace).toBe('frontend');
    expect(flows[0].sourcePod).toBe('frontend-abc');
    expect(flows[0].destNamespace).toBe('payments');
    expect(flows[0].destPod).toBe('payments-xyz');
    expect(flows[0].destPort).toBe(8080);
    expect(flows[0].protocol).toBe('TCP');
    expect(flows[0].sourceIP).toBe('10.0.0.5');
    expect(flows[0].destIP).toBe('10.0.1.10');
    expect(flows[0].timestamp).toBe('2024-01-15T10:00:00Z');
  });

  it('parses a DROPPED flow as verdict DROP', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:01Z',
      verdict: 'DROPPED',
      source: { namespace: 'worker', pod_name: 'worker-1' },
      destination: { namespace: 'payments', pod_name: 'payments-svc', port: 8080 },
      l4: { TCP: { destination_port: 8080 } },
      drop_reason: 'Policy denied',
    });
    const flows = parseHubbleLogs(line);
    expect(flows).toHaveLength(1);
    expect(flows[0].verdict).toBe('DROP');
    expect(flows[0].reason).toBe('Policy denied');
  });

  it('parses an AUDIT flow', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:02Z',
      verdict: 'AUDIT',
      source: { namespace: 'ingress-nginx', pod_name: 'controller-abc' },
      destination: { namespace: 'frontend', pod_name: 'frontend-abc', port: 80 },
      l4: { TCP: { destination_port: 80 } },
    });
    const flows = parseHubbleLogs(line);
    expect(flows[0].verdict).toBe('AUDIT');
  });

  it('falls back to UNKNOWN for unrecognised verdict', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:03Z',
      verdict: 'ERROR',
      source: { namespace: 'ns', pod_name: 'pod' },
      destination: { namespace: 'ns2', pod_name: 'pod2' },
    });
    const flows = parseHubbleLogs(line);
    expect(flows[0].verdict).toBe('UNKNOWN');
  });

  it('extracts UDP port from l4.UDP', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:04Z',
      verdict: 'FORWARDED',
      source: { namespace: 'ns1', pod_name: 'pod1' },
      destination: { namespace: 'ns2', pod_name: 'pod2' },
      l4: { UDP: { destination_port: 53 } },
    });
    const flows = parseHubbleLogs(line);
    expect(flows[0].destPort).toBe(53);
    expect(flows[0].protocol).toBe('UDP');
  });

  it('skips malformed (non-JSON) lines', () => {
    const content = 'not json\n' + JSON.stringify({
      time: '2024-01-15T10:00:05Z',
      verdict: 'FORWARDED',
      source: { namespace: 'ns', pod_name: 'pod' },
      destination: { namespace: 'ns2', pod_name: 'pod2' },
    });
    const flows = parseHubbleLogs(content);
    expect(flows).toHaveLength(1);
  });

  it('skips empty lines silently', () => {
    const flows = parseHubbleLogs('\n\n\n');
    expect(flows).toHaveLength(0);
  });

  it('skips JSON objects with no namespace or pod info', () => {
    const line = JSON.stringify({ verdict: 'FORWARDED', time: '2024-01-15T10:00:00Z' });
    const flows = parseHubbleLogs(line);
    expect(flows).toHaveLength(0);
  });

  it('parses multiple lines', () => {
    const lines = [
      JSON.stringify({ time: 'T1', verdict: 'FORWARDED', source: { namespace: 'a', pod_name: 'p1' }, destination: { namespace: 'b', pod_name: 'p2' } }),
      JSON.stringify({ time: 'T2', verdict: 'DROPPED',   source: { namespace: 'c', pod_name: 'p3' }, destination: { namespace: 'd', pod_name: 'p4' } }),
    ].join('\n');
    const flows = parseHubbleLogs(lines);
    expect(flows).toHaveLength(2);
    expect(flows[0].verdict).toBe('ALLOW');
    expect(flows[1].verdict).toBe('DROP');
  });

  it('parses the fixture file without throwing', () => {
    const content = readFileSync(join(FIXTURES, 'hubble-flows.json'), 'utf8');
    const flows = parseHubbleLogs(content);
    expect(flows.length).toBeGreaterThan(0);
    // The last line is intentionally malformed; should be skipped
    for (const f of flows) {
      expect(['ALLOW', 'DROP', 'AUDIT', 'UNKNOWN']).toContain(f.verdict);
    }
  });

  it('returns empty array for empty input', () => {
    expect(parseHubbleLogs('')).toHaveLength(0);
  });
});

// ─── parseFalcoLogs ───────────────────────────────────────────────────────────

describe('parseFalcoLogs', () => {
  it('parses a WARNING priority event as AUDIT', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:01.000000000Z',
      rule: 'Unexpected outbound connection destination',
      priority: 'WARNING',
      output: 'Unexpected outbound (fd.rport=443 namespace=frontend pod=frontend-abc)',
      source: 'syscall',
    });
    const flows = parseFalcoLogs(line);
    expect(flows).toHaveLength(1);
    expect(flows[0].verdict).toBe('AUDIT');
    expect(flows[0].sourceNamespace).toBe('frontend');
    expect(flows[0].sourcePod).toBe('frontend-abc');
    expect(flows[0].destPort).toBe(443);
    expect(flows[0].reason).toBe('Unexpected outbound connection destination');
  });

  it('parses a CRITICAL priority event as DROP', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:02.000000000Z',
      rule: 'Netcat Remote Code Execution',
      priority: 'CRITICAL',
      output: 'Netcat (fd.rport=4444 namespace=compromised pod=bad-pod)',
      source: 'syscall',
    });
    const flows = parseFalcoLogs(line);
    expect(flows[0].verdict).toBe('DROP');
  });

  it('parses ERROR priority as DROP', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:03.000000000Z',
      rule: 'Database access',
      priority: 'ERROR',
      output: 'DB connection (fd.rport=5432 namespace=worker pod=worker-1)',
      source: 'syscall',
    });
    const flows = parseFalcoLogs(line);
    expect(flows[0].verdict).toBe('DROP');
  });

  it('extracts port from fd.name pattern', () => {
    const line = JSON.stringify({
      time: '2024-01-15T10:00:04.000000000Z',
      rule: 'Test',
      priority: 'WARNING',
      output: 'Test (fd.name=34.229.1.2:443 namespace=frontend pod=pod-abc)',
      source: 'syscall',
    });
    const flows = parseFalcoLogs(line);
    expect(flows[0].destPort).toBe(443);
    expect(flows[0].destIP).toBe('34.229.1.2');
  });

  it('skips non-Falco JSON (missing rule/priority/output)', () => {
    const line = JSON.stringify({ foo: 'bar', baz: 123 });
    const flows = parseFalcoLogs(line);
    expect(flows).toHaveLength(0);
  });

  it('skips malformed lines', () => {
    const content = 'not json\n' + JSON.stringify({
      time: '2024-01-15T10:00:00Z',
      rule: 'Test',
      priority: 'WARNING',
      output: 'Test (namespace=ns pod=pod)',
    });
    const flows = parseFalcoLogs(content);
    expect(flows).toHaveLength(1);
  });

  it('returns empty array for empty input', () => {
    expect(parseFalcoLogs('')).toHaveLength(0);
  });

  it('parses the fixture file without throwing', () => {
    const content = readFileSync(join(FIXTURES, 'falco-events.json'), 'utf8');
    const flows = parseFalcoLogs(content);
    expect(flows.length).toBeGreaterThan(0);
  });
});

// ─── parseGenericLogs ─────────────────────────────────────────────────────────

describe('parseGenericLogs', () => {
  const HEADER = 'timestamp,src_ns,src_pod,dst_ns,dst_pod,dst_port,protocol,verdict';

  it('parses a simple ALLOW line', () => {
    const content = HEADER + '\n2024-01-15T10:00:00Z,frontend,frontend-app,payments,payments-svc,8080,TCP,ALLOW';
    const flows = parseGenericLogs(content);
    expect(flows).toHaveLength(1);
    expect(flows[0].verdict).toBe('ALLOW');
    expect(flows[0].sourceNamespace).toBe('frontend');
    expect(flows[0].sourcePod).toBe('frontend-app');
    expect(flows[0].destNamespace).toBe('payments');
    expect(flows[0].destPod).toBe('payments-svc');
    expect(flows[0].destPort).toBe(8080);
    expect(flows[0].protocol).toBe('TCP');
  });

  it('parses DROP and maps DENY/DENIED to DROP', () => {
    const content = HEADER + '\n2024-01-15T10:00:01Z,a,pod-a,b,pod-b,443,TCP,DROP\n2024-01-15T10:00:02Z,c,pod-c,d,pod-d,80,TCP,DENIED';
    const flows = parseGenericLogs(content);
    expect(flows[0].verdict).toBe('DROP');
    expect(flows[1].verdict).toBe('DROP');
  });

  it('maps ALLOWED and FORWARDED to ALLOW', () => {
    const content = HEADER + '\n2024-01-15T10:00:00Z,a,pod-a,b,pod-b,8080,TCP,ALLOWED\n2024-01-15T10:00:01Z,c,pod-c,d,pod-d,8080,TCP,FORWARDED';
    const flows = parseGenericLogs(content);
    expect(flows[0].verdict).toBe('ALLOW');
    expect(flows[1].verdict).toBe('ALLOW');
  });

  it('skips comment lines starting with #', () => {
    const content = '# comment\n' + HEADER + '\n# another comment\n2024-01-15T10:00:00Z,a,p,b,q,80,TCP,ALLOW';
    const flows = parseGenericLogs(content);
    expect(flows).toHaveLength(1);
  });

  it('skips lines with fewer than 7 columns', () => {
    const content = HEADER + '\na,b,c,d,e,f'; // only 6 columns
    const flows = parseGenericLogs(content);
    expect(flows).toHaveLength(0);
  });

  it('works without a header row', () => {
    const content = '2024-01-15T10:00:00Z,frontend,app,payments,svc,8080,TCP,ALLOW';
    const flows = parseGenericLogs(content);
    expect(flows).toHaveLength(1);
    expect(flows[0].sourceNamespace).toBe('frontend');
  });

  it('returns empty array for empty input', () => {
    expect(parseGenericLogs('')).toHaveLength(0);
  });

  it('maps unknown verdict to UNKNOWN', () => {
    const content = HEADER + '\n2024-01-15T10:00:00Z,a,p,b,q,80,TCP,WEIRD';
    const flows = parseGenericLogs(content);
    expect(flows[0].verdict).toBe('UNKNOWN');
  });

  it('parses the fixture CSV file without throwing', () => {
    const content = readFileSync(join(FIXTURES, 'generic-flows.csv'), 'utf8');
    const flows = parseGenericLogs(content);
    expect(flows.length).toBeGreaterThan(0);
    for (const f of flows) {
      expect(['ALLOW', 'DROP', 'AUDIT', 'UNKNOWN']).toContain(f.verdict);
    }
  });

  it('parses multiple rows with mixed verdicts', () => {
    const content = [
      HEADER,
      '2024-01-15T10:00:00Z,frontend,app,payments,svc,8080,TCP,ALLOW',
      '2024-01-15T10:00:01Z,attacker,pod,kube-system,apiserver,6443,TCP,DROP',
      '2024-01-15T10:00:02Z,backend,pod,monitoring,prometheus,9090,TCP,ALLOW',
    ].join('\n');
    const flows = parseGenericLogs(content);
    expect(flows).toHaveLength(3);
    expect(flows[0].verdict).toBe('ALLOW');
    expect(flows[1].verdict).toBe('DROP');
    expect(flows[2].verdict).toBe('ALLOW');
  });
});

// ─── detectLogFormat ──────────────────────────────────────────────────────────

describe('detectLogFormat', () => {
  it('detects hubble format from source/destination fields', () => {
    const line = JSON.stringify({
      verdict: 'FORWARDED',
      source: { namespace: 'ns' },
      destination: { namespace: 'ns2' },
    });
    expect(detectLogFormat(line)).toBe('hubble');
  });

  it('detects falco format from rule/priority/output fields', () => {
    const line = JSON.stringify({
      rule: 'Test rule',
      priority: 'WARNING',
      output: 'some output',
    });
    expect(detectLogFormat(line)).toBe('falco');
  });

  it('falls back to generic for CSV-like content', () => {
    const content = 'timestamp,src_ns,src_pod,dst_ns,dst_pod,dst_port,protocol,verdict\n2024-01-15,ns,pod,ns2,pod2,8080,TCP,ALLOW';
    expect(detectLogFormat(content)).toBe('generic');
  });

  it('returns generic for empty content', () => {
    expect(detectLogFormat('')).toBe('generic');
  });

  it('returns generic for comment-only content', () => {
    expect(detectLogFormat('# just a comment\n# another')).toBe('generic');
  });
});
