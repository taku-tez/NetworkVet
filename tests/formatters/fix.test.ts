import { describe, it, expect } from 'vitest';
import { formatFixTty, formatFixJson } from '../../src/formatters/fix.js';
import type { FixSuggestion } from '../../src/fixer/generator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSuggestion(overrides: Partial<FixSuggestion> = {}): FixSuggestion {
  return {
    findingId: 'NW1003',
    resource: 'Namespace/default',
    namespace: 'default',
    description: 'Add a default-deny NetworkPolicy to restrict all traffic.',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// formatFixTty — empty case
// ---------------------------------------------------------------------------

describe('formatFixTty — empty suggestions', () => {
  it('returns a no-suggestions message when the list is empty', () => {
    const output = formatFixTty([]);
    expect(output).toMatch(/no fix suggestions/i);
  });
});

// ---------------------------------------------------------------------------
// formatFixTty — header
// ---------------------------------------------------------------------------

describe('formatFixTty — header', () => {
  it('shows a header with the suggestion count', () => {
    const s = makeSuggestion();
    const output = formatFixTty([s]);
    expect(output).toMatch(/Fix Suggestions \(1\)/);
  });

  it('shows correct count for multiple suggestions', () => {
    const output = formatFixTty([makeSuggestion(), makeSuggestion({ findingId: 'NW1001' })]);
    expect(output).toMatch(/Fix Suggestions \(2\)/);
  });
});

// ---------------------------------------------------------------------------
// formatFixTty — suggestion content
// ---------------------------------------------------------------------------

describe('formatFixTty — suggestion fields', () => {
  it('includes finding ID', () => {
    const output = formatFixTty([makeSuggestion({ findingId: 'NW2003' })]);
    expect(output).toMatch(/NW2003/);
  });

  it('includes resource name', () => {
    const output = formatFixTty([makeSuggestion({ resource: 'Service/my-lb' })]);
    expect(output).toMatch(/Service\/my-lb/);
  });

  it('includes namespace', () => {
    const output = formatFixTty([makeSuggestion({ namespace: 'production' })]);
    expect(output).toMatch(/production/);
  });

  it('includes the description', () => {
    const output = formatFixTty([makeSuggestion({ description: 'Do something important.' })]);
    expect(output).toMatch(/Do something important\./);
  });
});

// ---------------------------------------------------------------------------
// formatFixTty — YAML fix snippet
// ---------------------------------------------------------------------------

describe('formatFixTty — YAML fix snippet', () => {
  it('includes the YAML snippet when fix is provided', () => {
    const s = makeSuggestion({
      fix: 'spec:\n  podSelector: {}',
    });
    const output = formatFixTty([s]);
    expect(output).toMatch(/Suggested fix:/);
    expect(output).toMatch(/spec:/);
    expect(output).toMatch(/podSelector/);
  });

  it('does not include "Suggested fix:" when fix is absent', () => {
    const s = makeSuggestion({ fix: undefined });
    const output = formatFixTty([s]);
    expect(output).not.toMatch(/Suggested fix:/);
  });

  it('indents YAML snippet lines', () => {
    const s = makeSuggestion({ fix: 'apiVersion: networking.k8s.io/v1' });
    const output = formatFixTty([s]);
    // The YAML line should appear indented (at least 4 spaces)
    expect(output).toMatch(/    apiVersion: networking\.k8s\.io\/v1/);
  });
});

// ---------------------------------------------------------------------------
// formatFixTty — separator
// ---------------------------------------------------------------------------

describe('formatFixTty — separator lines', () => {
  it('includes separator between suggestions', () => {
    const s1 = makeSuggestion({ findingId: 'NW1001' });
    const s2 = makeSuggestion({ findingId: 'NW1002' });
    const output = formatFixTty([s1, s2]);
    // Should have separator dashes
    expect(output).toMatch(/---/);
  });
});

// ---------------------------------------------------------------------------
// formatFixTty — multiple suggestions
// ---------------------------------------------------------------------------

describe('formatFixTty — multiple suggestions content', () => {
  it('renders all suggestion IDs', () => {
    const suggestions = [
      makeSuggestion({ findingId: 'NW1001', resource: 'NetworkPolicy/np1' }),
      makeSuggestion({ findingId: 'NW3001', resource: 'Ingress/ing1' }),
      makeSuggestion({ findingId: 'NW4001', resource: 'Namespace/ns1' }),
    ];
    const output = formatFixTty(suggestions);
    expect(output).toMatch(/NW1001/);
    expect(output).toMatch(/NW3001/);
    expect(output).toMatch(/NW4001/);
  });
});

// ---------------------------------------------------------------------------
// formatFixJson — basic structure
// ---------------------------------------------------------------------------

describe('formatFixJson — empty list', () => {
  it('returns a valid JSON empty array', () => {
    const output = formatFixJson([]);
    expect(() => JSON.parse(output)).not.toThrow();
    expect(JSON.parse(output)).toEqual([]);
  });
});

describe('formatFixJson — single suggestion', () => {
  it('returns valid JSON array with one element', () => {
    const s = makeSuggestion();
    const output = formatFixJson([s]);
    const parsed = JSON.parse(output);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(1);
  });

  it('round-trips all fields', () => {
    const s: FixSuggestion = {
      findingId: 'NW2002',
      resource: 'Service/lb',
      namespace: 'frontend',
      description: 'Set externalTrafficPolicy: Local.',
      descriptionJa: 'ローカルに設定してください。',
      fix: 'spec:\n  externalTrafficPolicy: Local',
    };
    const parsed = JSON.parse(formatFixJson([s]));
    expect(parsed[0]).toMatchObject(s);
  });
});

describe('formatFixJson — multiple suggestions', () => {
  it('serialises all entries', () => {
    const suggestions = [
      makeSuggestion({ findingId: 'NW1001' }),
      makeSuggestion({ findingId: 'NW1002' }),
    ];
    const parsed = JSON.parse(formatFixJson(suggestions));
    expect(parsed).toHaveLength(2);
    expect(parsed[0].findingId).toBe('NW1001');
    expect(parsed[1].findingId).toBe('NW1002');
  });
});

describe('formatFixJson — suggestion without fix field', () => {
  it('omits fix field when undefined', () => {
    const s = makeSuggestion({ fix: undefined });
    const parsed = JSON.parse(formatFixJson([s]));
    expect(parsed[0].fix).toBeUndefined();
  });
});

describe('formatFixJson — suggestion with descriptionJa', () => {
  it('includes descriptionJa when present', () => {
    const s = makeSuggestion({ descriptionJa: '日本語の説明' });
    const parsed = JSON.parse(formatFixJson([s]));
    expect(parsed[0].descriptionJa).toBe('日本語の説明');
  });
});

describe('formatFixJson — pretty-printed output', () => {
  it('is indented (not a single line)', () => {
    const s = makeSuggestion();
    const output = formatFixJson([s]);
    expect(output.includes('\n')).toBe(true);
  });
});
