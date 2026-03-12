import { describe, it, expect } from 'vitest';
import { getComplianceRefs, getRulesForFramework, COMPLIANCE_MAP } from '../../src/compliance/mapping.js';

describe('getComplianceRefs', () => {
  it('returns refs for NW1001', () => {
    const refs = getComplianceRefs('NW1001');
    expect(refs.length).toBeGreaterThan(0);
    expect(refs.some((r) => r.framework === 'CIS')).toBe(true);
    expect(refs.some((r) => r.framework === 'NSA')).toBe(true);
  });

  it('is case-insensitive', () => {
    const refs = getComplianceRefs('nw1001');
    expect(refs.length).toBeGreaterThan(0);
  });

  it('returns empty array for unknown rule', () => {
    expect(getComplianceRefs('NW9999')).toEqual([]);
  });

  it('returns CIS refs for NW4002', () => {
    const refs = getComplianceRefs('NW4002');
    expect(refs.some((r) => r.framework === 'CIS' && r.id === '5.3.1')).toBe(true);
  });

  it('all refs have non-empty id and title', () => {
    for (const [ruleId, refs] of Object.entries(COMPLIANCE_MAP)) {
      for (const ref of refs) {
        expect(ref.id.length, `${ruleId} ref id`).toBeGreaterThan(0);
        expect(ref.title.length, `${ruleId} ref title`).toBeGreaterThan(0);
      }
    }
  });

  it('NSA refs have § prefix in id', () => {
    for (const refs of Object.values(COMPLIANCE_MAP)) {
      for (const ref of refs) {
        if (ref.framework === 'NSA') {
          expect(ref.id).toMatch(/^§/);
        }
      }
    }
  });
});

describe('getRulesForFramework', () => {
  it('returns rules for CIS framework', () => {
    const rules = getRulesForFramework('CIS');
    expect(rules.length).toBeGreaterThan(0);
    expect(rules).toContain('NW1001');
    expect(rules).toContain('NW4002');
  });

  it('returns rules for NSA framework', () => {
    const rules = getRulesForFramework('NSA');
    expect(rules.length).toBeGreaterThan(0);
    expect(rules).toContain('NW3001');
    expect(rules).toContain('NW5005');
  });

  it('NSA has more rules than CIS', () => {
    expect(getRulesForFramework('NSA').length).toBeGreaterThan(
      getRulesForFramework('CIS').length
    );
  });
});
