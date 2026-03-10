import { describe, it, expect } from 'vitest';
import { formatDiffTty, formatDiffJson } from '../../src/formatters/diff.js';
import type { DiffResult } from '../../src/diff/index.js';
import type { Finding } from '../../src/types.js';
import type { ReachabilityEntry } from '../../src/reachability/evaluator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'NW1001',
    severity: 'error',
    kind: 'NetworkPolicy',
    name: 'allow-all',
    namespace: 'default',
    file: 'test.yaml',
    line: 1,
    message: 'ingress allows all sources',
    ...overrides,
  };
}

function makeEntry(from: string, to: string): ReachabilityEntry {
  return {
    from,
    to,
    status: 'allowed (no policy)',
    risk: 'medium',
    reason: `${from} -> ${to} allowed`,
  };
}

function emptyDiff(): DiffResult {
  return {
    newFindings: [],
    resolvedFindings: [],
    unchangedFindings: [],
    newOpenPaths: [],
    resolvedOpenPaths: [],
  };
}

// ---------------------------------------------------------------------------
// formatDiffTty — header
// ---------------------------------------------------------------------------

describe('formatDiffTty — header', () => {
  it('includes the report title', () => {
    const output = formatDiffTty(emptyDiff());
    expect(output).toMatch(/NetworkVet Diff Report/);
  });

  it('includes a separator line', () => {
    const output = formatDiffTty(emptyDiff());
    // separator contains a run of ─ or - chars
    expect(output).toMatch(/[─\-]{10,}/);
  });
});

// ---------------------------------------------------------------------------
// formatDiffTty — new issues section
// ---------------------------------------------------------------------------

describe('formatDiffTty — new issues section', () => {
  it('shows "New issues (0)" when there are no new findings', () => {
    const output = formatDiffTty(emptyDiff());
    expect(output).toMatch(/New issues \(0\)/);
    expect(output).toMatch(/\(none\)/);
  });

  it('shows "New issues (N)" with the count when there are new findings', () => {
    const diff = { ...emptyDiff(), newFindings: [makeFinding()] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/New issues \(1\)/);
  });

  it('shows "+" prefix for new findings', () => {
    const diff = { ...emptyDiff(), newFindings: [makeFinding()] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/\+/);
  });

  it('includes the rule ID in new findings', () => {
    const diff = { ...emptyDiff(), newFindings: [makeFinding({ id: 'NW1001' })] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/NW1001/);
  });

  it('includes severity in new findings', () => {
    const diff = { ...emptyDiff(), newFindings: [makeFinding({ severity: 'warning' })] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/warning/);
  });

  it('includes resource name in new findings', () => {
    const diff = { ...emptyDiff(), newFindings: [makeFinding({ kind: 'NetworkPolicy', name: 'allow-all' })] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/NetworkPolicy\/allow-all/);
  });
});

// ---------------------------------------------------------------------------
// formatDiffTty — resolved issues section
// ---------------------------------------------------------------------------

describe('formatDiffTty — resolved issues section', () => {
  it('shows "Resolved issues (0)" when there are none', () => {
    const output = formatDiffTty(emptyDiff());
    expect(output).toMatch(/Resolved issues \(0\)/);
  });

  it('shows "Resolved issues (N)" with count', () => {
    const diff = { ...emptyDiff(), resolvedFindings: [makeFinding({ id: 'NW3001' })] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/Resolved issues \(1\)/);
  });

  it('shows "-" prefix for resolved findings', () => {
    const diff = { ...emptyDiff(), resolvedFindings: [makeFinding()] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/-/);
  });

  it('includes the rule ID of the resolved finding', () => {
    const diff = { ...emptyDiff(), resolvedFindings: [makeFinding({ id: 'NW3001' })] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/NW3001/);
  });
});

// ---------------------------------------------------------------------------
// formatDiffTty — open paths sections
// ---------------------------------------------------------------------------

describe('formatDiffTty — new open paths section', () => {
  it('shows "New open paths (0)" when none', () => {
    const output = formatDiffTty(emptyDiff());
    expect(output).toMatch(/New open paths \(0\)/);
  });

  it('shows correct count for new open paths', () => {
    const diff = { ...emptyDiff(), newOpenPaths: [makeEntry('frontend', 'backend')] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/New open paths \(1\)/);
  });

  it('shows namespace arrow notation for open paths', () => {
    const diff = { ...emptyDiff(), newOpenPaths: [makeEntry('frontend', 'backend')] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/frontend/);
    expect(output).toMatch(/backend/);
    expect(output).toMatch(/→|->|→/);
  });
});

describe('formatDiffTty — resolved open paths section', () => {
  it('shows "Resolved open paths (0)" when none', () => {
    const output = formatDiffTty(emptyDiff());
    expect(output).toMatch(/Resolved open paths \(0\)/);
  });

  it('shows correct count for resolved open paths', () => {
    const diff = { ...emptyDiff(), resolvedOpenPaths: [makeEntry('a', 'b')] };
    const output = formatDiffTty(diff);
    expect(output).toMatch(/Resolved open paths \(1\)/);
  });
});

// ---------------------------------------------------------------------------
// formatDiffTty — (none) shown for empty sections
// ---------------------------------------------------------------------------

describe('formatDiffTty — (none) for empty sections', () => {
  it('shows (none) for all sections when diff is empty', () => {
    const output = formatDiffTty(emptyDiff());
    const noneMatches = (output.match(/\(none\)/g) ?? []).length;
    // Should appear at least once for each of the 4 sections
    expect(noneMatches).toBeGreaterThanOrEqual(4);
  });
});

// ---------------------------------------------------------------------------
// formatDiffJson — structure
// ---------------------------------------------------------------------------

describe('formatDiffJson — valid JSON', () => {
  it('returns valid JSON', () => {
    const output = formatDiffJson(emptyDiff());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('JSON contains all DiffResult keys', () => {
    const parsed = JSON.parse(formatDiffJson(emptyDiff()));
    expect(parsed).toHaveProperty('newFindings');
    expect(parsed).toHaveProperty('resolvedFindings');
    expect(parsed).toHaveProperty('unchangedFindings');
    expect(parsed).toHaveProperty('newOpenPaths');
    expect(parsed).toHaveProperty('resolvedOpenPaths');
  });

  it('is pretty-printed (multi-line)', () => {
    const output = formatDiffJson(emptyDiff());
    expect(output).toContain('\n');
  });
});

describe('formatDiffJson — populated diff', () => {
  it('round-trips findings correctly', () => {
    const f = makeFinding({ id: 'NW2002' });
    const diff = { ...emptyDiff(), newFindings: [f] };
    const parsed = JSON.parse(formatDiffJson(diff));
    expect(parsed.newFindings).toHaveLength(1);
    expect(parsed.newFindings[0].id).toBe('NW2002');
  });

  it('round-trips open paths correctly', () => {
    const path = makeEntry('ns-a', 'ns-b');
    const diff = { ...emptyDiff(), newOpenPaths: [path] };
    const parsed = JSON.parse(formatDiffJson(diff));
    expect(parsed.newOpenPaths[0].from).toBe('ns-a');
    expect(parsed.newOpenPaths[0].to).toBe('ns-b');
  });
});
