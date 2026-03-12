import { describe, it, expect } from 'vitest';

// Unit-test the severity threshold logic used by --fail-on
describe('--fail-on severity threshold logic', () => {
  const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function wouldExit1(findings: Array<{ severity: string }>, failOn: string): boolean {
    const threshold = SEVERITY_RANK[failOn] ?? 1;
    return findings.some((f) => (SEVERITY_RANK[f.severity] ?? 4) <= threshold);
  }

  it('fails on critical when fail-on=critical', () => {
    expect(wouldExit1([{ severity: 'critical' }], 'critical')).toBe(true);
  });

  it('does not fail on high when fail-on=critical', () => {
    expect(wouldExit1([{ severity: 'high' }], 'critical')).toBe(false);
  });

  it('fails on high when fail-on=high (default)', () => {
    expect(wouldExit1([{ severity: 'high' }], 'high')).toBe(true);
  });

  it('fails on critical when fail-on=high', () => {
    expect(wouldExit1([{ severity: 'critical' }], 'high')).toBe(true);
  });

  it('fails on medium when fail-on=medium', () => {
    expect(wouldExit1([{ severity: 'medium' }], 'medium')).toBe(true);
  });

  it('does not fail on medium when fail-on=high', () => {
    expect(wouldExit1([{ severity: 'medium' }], 'high')).toBe(false);
  });

  it('fails on low when fail-on=low', () => {
    expect(wouldExit1([{ severity: 'low' }], 'low')).toBe(true);
  });

  it('does not fail on info when fail-on=low', () => {
    expect(wouldExit1([{ severity: 'info' }], 'low')).toBe(false);
  });

  it('fails on info when fail-on=info', () => {
    expect(wouldExit1([{ severity: 'info' }], 'info')).toBe(true);
  });

  it('no findings → no failure', () => {
    expect(wouldExit1([], 'high')).toBe(false);
  });
});
