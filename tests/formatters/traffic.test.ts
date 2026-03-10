import { describe, it, expect } from 'vitest';
import { formatTrafficTty, formatTrafficJson } from '../../src/formatters/traffic.js';
import type { TrafficAnalysisResult } from '../../src/traffic/types.js';

// ─── fixtures ─────────────────────────────────────────────────────────────────

function makeResult(overrides: Partial<TrafficAnalysisResult> = {}): TrafficAnalysisResult {
  return {
    totalFlows: 100,
    allowedFlows: 85,
    droppedFlows: 15,
    violations: [],
    policyGaps: [],
    ...overrides,
  };
}

const sampleFlow = {
  timestamp: '2024-01-15T10:00:00Z',
  sourceNamespace: 'frontend',
  sourcePod: 'frontend-abc',
  destNamespace: 'payments',
  destPod: 'payments-svc',
  destPort: 8080,
  protocol: 'TCP',
  verdict: 'ALLOW' as const,
};

// ─── formatTrafficTty ─────────────────────────────────────────────────────────

describe('formatTrafficTty', () => {
  it('includes the total flow count in the header', () => {
    const output = formatTrafficTty(makeResult({ totalFlows: 1247 }));
    expect(output).toContain('1,247');
    expect(output).toContain('flows observed');
  });

  it('shows allowed and dropped counts', () => {
    const output = formatTrafficTty(makeResult({ allowedFlows: 1200, droppedFlows: 47 }));
    expect(output).toContain('1,200');
    expect(output).toContain('47');
  });

  it('shows "Policy Gaps: none" when there are no gaps', () => {
    const output = formatTrafficTty(makeResult({ policyGaps: [] }));
    expect(output).toContain('Policy Gaps: none');
  });

  it('shows "Violations: none" when there are no violations', () => {
    const output = formatTrafficTty(makeResult({ violations: [] }));
    expect(output).toContain('Violations: none');
  });

  it('renders policy gap entries with source → destination and count', () => {
    const result = makeResult({
      policyGaps: [{
        sourceNamespace: 'frontend',
        destNamespace: 'payments',
        destPort: 8080,
        observedCount: 523,
        message: 'no policy in payments',
      }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('Policy Gaps (1)');
    expect(output).toContain('frontend');
    expect(output).toContain('payments');
    expect(output).toContain('8080');
    expect(output).toContain('523');
  });

  it('renders violation entries with type label and severity icon', () => {
    const result = makeResult({
      violations: [{
        type: 'unexpected-allow',
        flow: sampleFlow,
        message: 'possible bypass',
        severity: 'error',
      }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('Violations (1)');
    expect(output).toContain('unexpected-allow');
    expect(output).toContain('frontend');
    expect(output).toContain('payments');
    expect(output).toContain('possible bypass');
  });

  it('uses ✖ icon for error severity', () => {
    const result = makeResult({
      violations: [{
        type: 'unexpected-allow',
        flow: sampleFlow,
        message: 'error violation',
        severity: 'error',
      }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('✖');
  });

  it('uses ⚠ icon for warning severity', () => {
    const result = makeResult({
      violations: [{
        type: 'policy-gap',
        flow: sampleFlow,
        message: 'warning violation',
        severity: 'warning',
      }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('⚠');
  });

  it('uses · icon for info severity', () => {
    const result = makeResult({
      violations: [{
        type: 'shadow-traffic',
        flow: sampleFlow,
        message: 'info note',
        severity: 'info',
      }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('·');
  });

  it('shows plural "times" when observedCount > 1', () => {
    const result = makeResult({
      policyGaps: [{ sourceNamespace: 'a', destNamespace: 'b', destPort: 80, observedCount: 5, message: 'x' }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('times');
  });

  it('shows singular "time" when observedCount is 1', () => {
    const result = makeResult({
      policyGaps: [{ sourceNamespace: 'a', destNamespace: 'b', destPort: 80, observedCount: 1, message: 'x' }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('1 time');
    expect(output).not.toContain('1 times');
  });

  it('includes the separator line', () => {
    const output = formatTrafficTty(makeResult());
    expect(output).toContain('─');
  });

  it('includes the ALLOW verdict in violation header', () => {
    const result = makeResult({
      violations: [{
        type: 'policy-gap',
        flow: { ...sampleFlow, verdict: 'ALLOW' },
        message: 'gap',
        severity: 'warning',
      }],
    });
    const output = formatTrafficTty(result);
    expect(output).toContain('ALLOW');
  });
});

// ─── formatTrafficJson ────────────────────────────────────────────────────────

describe('formatTrafficJson', () => {
  it('produces valid JSON', () => {
    const result = makeResult();
    expect(() => JSON.parse(formatTrafficJson(result))).not.toThrow();
  });

  it('includes totalFlows, allowedFlows, droppedFlows', () => {
    const result = makeResult({ totalFlows: 50, allowedFlows: 40, droppedFlows: 10 });
    const parsed = JSON.parse(formatTrafficJson(result)) as TrafficAnalysisResult;
    expect(parsed.totalFlows).toBe(50);
    expect(parsed.allowedFlows).toBe(40);
    expect(parsed.droppedFlows).toBe(10);
  });

  it('includes violations array', () => {
    const result = makeResult({
      violations: [{
        type: 'policy-gap',
        flow: sampleFlow,
        message: 'gap message',
        severity: 'warning',
      }],
    });
    const parsed = JSON.parse(formatTrafficJson(result)) as TrafficAnalysisResult;
    expect(parsed.violations).toHaveLength(1);
    expect(parsed.violations[0].type).toBe('policy-gap');
  });

  it('includes policyGaps array', () => {
    const result = makeResult({
      policyGaps: [{
        sourceNamespace: 'frontend',
        destNamespace: 'payments',
        destPort: 8080,
        observedCount: 100,
        message: 'gap',
      }],
    });
    const parsed = JSON.parse(formatTrafficJson(result)) as TrafficAnalysisResult;
    expect(parsed.policyGaps).toHaveLength(1);
    expect(parsed.policyGaps[0].destNamespace).toBe('payments');
  });

  it('is pretty-printed (has newlines)', () => {
    const output = formatTrafficJson(makeResult());
    expect(output).toContain('\n');
  });
});
