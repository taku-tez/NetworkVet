import { describe, it, expect } from 'vitest';
import { formatDot } from '../../src/formatters/dot.js';
import type { ReachabilityResult, ReachabilityEntry } from '../../src/reachability/evaluator.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEntry(
  from: string,
  to: string,
  status: ReachabilityEntry['status'],
  risk: ReachabilityEntry['risk'],
): ReachabilityEntry {
  return { from, to, status, risk, reason: `${from}->${to} ${status}` };
}

function makeResult(
  namespaces: string[],
  entries: ReachabilityEntry[],
  unprotected: string[] = [],
): ReachabilityResult {
  const matrix: Record<string, Record<string, ReachabilityEntry>> = {};
  for (const src of namespaces) {
    matrix[src] = {};
    for (const dst of namespaces) {
      const e = entries.find((x) => x.from === src && x.to === dst);
      if (e) matrix[src][dst] = e;
    }
  }
  const openPaths = entries.filter(
    (e) => e.status !== 'denied' && e.risk !== 'none',
  );
  return { matrix, unprotectedNamespaces: unprotected, openPaths };
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

describe('formatDot — basic structure', () => {
  it('starts with digraph declaration', () => {
    const result = makeResult(['a', 'b'], [makeEntry('a', 'b', 'allowed', 'low')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/^digraph networkvet \{/);
  });

  it('ends with closing brace', () => {
    const result = makeResult(['a', 'b'], [makeEntry('a', 'b', 'allowed', 'low')]);
    const dot = formatDot(result);
    expect(dot.trimEnd()).toMatch(/\}$/);
  });

  it('contains rankdir=LR', () => {
    const result = makeResult(['a'], []);
    const dot = formatDot(result);
    expect(dot).toMatch(/rankdir=LR/);
  });

  it('contains node shape directive', () => {
    const result = makeResult(['a'], []);
    const dot = formatDot(result);
    expect(dot).toMatch(/node \[/);
    expect(dot).toMatch(/shape=box/);
  });
});

// ---------------------------------------------------------------------------
// Empty matrix
// ---------------------------------------------------------------------------

describe('formatDot — empty matrix', () => {
  it('returns valid DOT with no nodes for empty result', () => {
    const result: ReachabilityResult = { matrix: {}, unprotectedNamespaces: [], openPaths: [] };
    const dot = formatDot(result);
    expect(dot).toMatch(/digraph networkvet/);
    // Should not throw and should form a valid structure
    expect(dot).toContain('}');
  });
});

// ---------------------------------------------------------------------------
// Namespace nodes
// ---------------------------------------------------------------------------

describe('formatDot — namespace nodes', () => {
  it('emits a node for each namespace', () => {
    const result = makeResult(['frontend', 'backend'], [makeEntry('frontend', 'backend', 'allowed', 'low')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/"frontend"/);
    expect(dot).toMatch(/"backend"/);
  });

  it('protected namespace gets green fill color', () => {
    const result = makeResult(['safe'], [], []);
    const dot = formatDot(result);
    expect(dot).toMatch(/"safe" \[fillcolor="#90EE90"/);
  });

  it('unprotected namespace gets yellow fill color', () => {
    const result = makeResult(['unsafe'], [], ['unsafe']);
    const dot = formatDot(result);
    expect(dot).toMatch(/"unsafe" \[fillcolor="#FFD700"/);
  });

  it('unprotected namespace label contains "(unprotected)"', () => {
    const result = makeResult(['exposed'], [], ['exposed']);
    const dot = formatDot(result);
    expect(dot).toMatch(/unprotected/);
  });

  it('multiple namespaces all appear as nodes', () => {
    const namespaces = ['ns-a', 'ns-b', 'ns-c'];
    const result = makeResult(namespaces, []);
    const dot = formatDot(result);
    for (const ns of namespaces) {
      expect(dot).toContain(`"${ns}"`);
    }
  });
});

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

describe('formatDot — edges', () => {
  it('emits an edge for non-self namespace pair', () => {
    const result = makeResult(['a', 'b'], [makeEntry('a', 'b', 'allowed', 'low')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/"a" -> "b"/);
  });

  it('does not emit self-loop edges', () => {
    const result = makeResult(['a', 'b'], [makeEntry('a', 'b', 'allowed', 'low')]);
    const dot = formatDot(result);
    expect(dot).not.toMatch(/"a" -> "a"/);
    expect(dot).not.toMatch(/"b" -> "b"/);
  });

  it('allowed edge uses green color', () => {
    const result = makeResult(['x', 'y'], [makeEntry('x', 'y', 'allowed', 'low')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/color="green"/);
  });

  it('allowed (no policy) edge uses orange color and dashed style', () => {
    const result = makeResult(['x', 'y'], [makeEntry('x', 'y', 'allowed (no policy)', 'medium')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/color="orange"/);
    expect(dot).toMatch(/style=dashed/);
  });

  it('denied edge uses gray color and dotted style', () => {
    const result = makeResult(['x', 'y'], [makeEntry('x', 'y', 'denied', 'none')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/color="gray"/);
    expect(dot).toMatch(/style=dotted/);
  });

  it('high-risk allowed edge uses red color', () => {
    const result = makeResult(['x', 'y'], [makeEntry('x', 'y', 'allowed', 'high')]);
    const dot = formatDot(result);
    expect(dot).toMatch(/color="red"/);
  });

  it('edge labels match the traffic status', () => {
    const r1 = makeResult(['a', 'b'], [makeEntry('a', 'b', 'allowed', 'low')]);
    expect(formatDot(r1)).toMatch(/label="allowed"/);

    const r2 = makeResult(['a', 'b'], [makeEntry('a', 'b', 'denied', 'none')]);
    expect(formatDot(r2)).toMatch(/label="denied"/);
  });

  it('emits edges in both directions when both exist', () => {
    const entries = [
      makeEntry('a', 'b', 'allowed', 'low'),
      makeEntry('b', 'a', 'denied', 'none'),
    ];
    const result = makeResult(['a', 'b'], entries);
    const dot = formatDot(result);
    expect(dot).toMatch(/"a" -> "b"/);
    expect(dot).toMatch(/"b" -> "a"/);
  });
});

// ---------------------------------------------------------------------------
// Three-namespace scenario
// ---------------------------------------------------------------------------

describe('formatDot — three-namespace scenario', () => {
  it('renders all three namespaces and their edges', () => {
    const entries: ReachabilityEntry[] = [
      makeEntry('frontend', 'backend', 'allowed', 'low'),
      makeEntry('frontend', 'payments', 'allowed (no policy)', 'medium'),
      makeEntry('backend', 'payments', 'denied', 'none'),
      makeEntry('backend', 'frontend', 'denied', 'none'),
      makeEntry('payments', 'frontend', 'denied', 'none'),
      makeEntry('payments', 'backend', 'denied', 'none'),
    ];
    const result = makeResult(['frontend', 'backend', 'payments'], entries, ['payments']);
    const dot = formatDot(result);

    expect(dot).toContain('"frontend"');
    expect(dot).toContain('"backend"');
    expect(dot).toContain('"payments"');
    expect(dot).toMatch(/"frontend" -> "backend"/);
    expect(dot).toMatch(/"frontend" -> "payments"/);
    expect(dot).toMatch(/"backend" -> "payments"/);
    // payments is unprotected — should have yellow fill
    expect(dot).toMatch(/"payments" \[fillcolor="#FFD700"/);
  });
});
