import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Finding } from '../../src/types.js';
import type { ReachabilityEntry } from '../../src/reachability/evaluator.js';
import type { BaselineEntry } from '../../src/diff/index.js';

// ---------------------------------------------------------------------------
// Mock node:fs so we never touch the real filesystem
// ---------------------------------------------------------------------------

vi.mock('node:fs', () => ({
  default: {
    writeFileSync: vi.fn(),
    readFileSync: vi.fn(),
  },
}));

// Import the module under test AFTER mocking
const { saveBaseline, loadBaseline, diffWithBaseline } = await import('../../src/diff/index.js');
import fs from 'node:fs';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'NW1003',
    severity: 'error',
    kind: 'Namespace',
    name: 'default',
    namespace: 'default',
    file: 'test.yaml',
    line: 1,
    message: 'Test finding',
    ...overrides,
  };
}

function makeEntry(
  from: string,
  to: string,
  status: ReachabilityEntry['status'] = 'allowed (no policy)',
  risk: ReachabilityEntry['risk'] = 'medium',
): ReachabilityEntry {
  return { from, to, status, risk, reason: `${from}->${to}` };
}

function makeBaseline(findings: Finding[], openPaths: ReachabilityEntry[] = []): BaselineEntry {
  return {
    timestamp: '2024-01-01T00:00:00.000Z',
    findings,
    reachability: openPaths.length > 0
      ? { matrix: {}, unprotectedNamespaces: [], openPaths }
      : undefined,
  };
}

// ---------------------------------------------------------------------------
// saveBaseline
// ---------------------------------------------------------------------------

describe('saveBaseline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls writeFileSync with the given path', () => {
    saveBaseline([], undefined, '/tmp/baseline.json');
    expect(fs.writeFileSync).toHaveBeenCalledWith(
      '/tmp/baseline.json',
      expect.any(String),
      'utf8',
    );
  });

  it('writes valid JSON containing findings', () => {
    const f = makeFinding({ id: 'NW1001' });
    saveBaseline([f], undefined, '/tmp/b.json');
    const written = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    const parsed = JSON.parse(written);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].id).toBe('NW1001');
  });

  it('sets a timestamp field', () => {
    saveBaseline([], undefined, '/tmp/b.json');
    const written = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    const parsed = JSON.parse(written);
    expect(typeof parsed.timestamp).toBe('string');
    expect(parsed.timestamp.length).toBeGreaterThan(0);
  });

  it('includes reachability when provided', () => {
    const reachability = { matrix: {}, unprotectedNamespaces: [], openPaths: [] };
    saveBaseline([], reachability, '/tmp/b.json');
    const written = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    const parsed = JSON.parse(written);
    expect(parsed.reachability).toBeDefined();
  });

  it('omits reachability when undefined', () => {
    saveBaseline([], undefined, '/tmp/b.json');
    const written = (fs.writeFileSync as ReturnType<typeof vi.fn>).mock.calls[0][1] as string;
    const parsed = JSON.parse(written);
    expect(parsed.reachability).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// loadBaseline
// ---------------------------------------------------------------------------

describe('loadBaseline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reads the file and parses JSON', () => {
    const entry: BaselineEntry = { timestamp: 'ts', findings: [] };
    (fs.readFileSync as ReturnType<typeof vi.fn>).mockReturnValue(JSON.stringify(entry));
    const result = loadBaseline('/tmp/b.json');
    expect(result.timestamp).toBe('ts');
    expect(result.findings).toEqual([]);
  });

  it('calls readFileSync with utf8 encoding', () => {
    (fs.readFileSync as ReturnType<typeof vi.fn>).mockReturnValue('{"timestamp":"t","findings":[]}');
    loadBaseline('/tmp/b.json');
    expect(fs.readFileSync).toHaveBeenCalledWith('/tmp/b.json', 'utf8');
  });

  it('throws if file is not valid JSON', () => {
    (fs.readFileSync as ReturnType<typeof vi.fn>).mockReturnValue('not json');
    expect(() => loadBaseline('/tmp/b.json')).toThrow();
  });

  it('round-trips findings correctly', () => {
    const f = makeFinding({ id: 'NW2003' });
    const entry: BaselineEntry = { timestamp: 'ts', findings: [f] };
    (fs.readFileSync as ReturnType<typeof vi.fn>).mockReturnValue(JSON.stringify(entry));
    const loaded = loadBaseline('/tmp/b.json');
    expect(loaded.findings[0].id).toBe('NW2003');
  });
});

// ---------------------------------------------------------------------------
// diffWithBaseline — findings
// ---------------------------------------------------------------------------

describe('diffWithBaseline — new findings', () => {
  it('detects a finding present in current but not baseline', () => {
    const current = { findings: [makeFinding({ id: 'NW1001' })], reachability: undefined };
    const baseline = makeBaseline([]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('NW1001');
  });

  it('returns empty newFindings when all current findings are in baseline', () => {
    const f = makeFinding();
    const current = { findings: [f], reachability: undefined };
    const baseline = makeBaseline([f]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newFindings).toHaveLength(0);
  });
});

describe('diffWithBaseline — resolved findings', () => {
  it('detects a finding in baseline that is gone in current', () => {
    const f = makeFinding({ id: 'NW3001' });
    const current = { findings: [], reachability: undefined };
    const baseline = makeBaseline([f]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.resolvedFindings).toHaveLength(1);
    expect(diff.resolvedFindings[0].id).toBe('NW3001');
  });

  it('returns empty resolvedFindings when no findings were removed', () => {
    const f = makeFinding();
    const current = { findings: [f], reachability: undefined };
    const baseline = makeBaseline([f]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.resolvedFindings).toHaveLength(0);
  });
});

describe('diffWithBaseline — unchanged findings', () => {
  it('places matching findings in unchangedFindings', () => {
    const f = makeFinding();
    const current = { findings: [f], reachability: undefined };
    const baseline = makeBaseline([f]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.unchangedFindings).toHaveLength(1);
  });
});

describe('diffWithBaseline — finding identity', () => {
  it('same id+namespace+kind+name = same finding regardless of message', () => {
    const base = makeFinding({ id: 'NW1001', message: 'old message' });
    const curr = makeFinding({ id: 'NW1001', message: 'new message' });
    const current = { findings: [curr], reachability: undefined };
    const baseline = makeBaseline([base]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(1);
  });

  it('different namespace = different finding', () => {
    const base = makeFinding({ namespace: 'ns-a', name: 'ns-a', kind: 'Namespace' });
    const curr = makeFinding({ namespace: 'ns-b', name: 'ns-b', kind: 'Namespace' });
    const current = { findings: [curr], reachability: undefined };
    const baseline = makeBaseline([base]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(1);
  });

  it('different rule id = different finding', () => {
    const base = makeFinding({ id: 'NW1001' });
    const curr = makeFinding({ id: 'NW1002' });
    const current = { findings: [curr], reachability: undefined };
    const baseline = makeBaseline([base]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// diffWithBaseline — open paths
// ---------------------------------------------------------------------------

describe('diffWithBaseline — new open paths', () => {
  it('detects a new open path not in baseline', () => {
    const path = makeEntry('frontend', 'backend');
    const current = {
      findings: [],
      reachability: { matrix: {}, unprotectedNamespaces: [], openPaths: [path] },
    };
    const baseline = makeBaseline([], []);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newOpenPaths).toHaveLength(1);
    expect(diff.newOpenPaths[0].from).toBe('frontend');
    expect(diff.newOpenPaths[0].to).toBe('backend');
  });

  it('returns empty newOpenPaths when all paths existed in baseline', () => {
    const path = makeEntry('a', 'b');
    const current = {
      findings: [],
      reachability: { matrix: {}, unprotectedNamespaces: [], openPaths: [path] },
    };
    const baseline = makeBaseline([], [path]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newOpenPaths).toHaveLength(0);
  });
});

describe('diffWithBaseline — resolved open paths', () => {
  it('detects a path in baseline that is gone in current', () => {
    const path = makeEntry('x', 'y');
    const current = {
      findings: [],
      reachability: { matrix: {}, unprotectedNamespaces: [], openPaths: [] },
    };
    const baseline = makeBaseline([], [path]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.resolvedOpenPaths).toHaveLength(1);
    expect(diff.resolvedOpenPaths[0].from).toBe('x');
    expect(diff.resolvedOpenPaths[0].to).toBe('y');
  });
});

// ---------------------------------------------------------------------------
// diffWithBaseline — empty baseline
// ---------------------------------------------------------------------------

describe('diffWithBaseline — empty baseline', () => {
  it('all current findings are new when baseline has no findings', () => {
    const findings = [makeFinding({ id: 'NW1001' }), makeFinding({ id: 'NW1002', name: 'np2' })];
    const current = { findings, reachability: undefined };
    const baseline = makeBaseline([]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newFindings).toHaveLength(2);
    expect(diff.resolvedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(0);
  });

  it('all current paths are new when baseline has no reachability', () => {
    const path = makeEntry('a', 'b');
    const current = {
      findings: [],
      reachability: { matrix: {}, unprotectedNamespaces: [], openPaths: [path] },
    };
    const baseline = makeBaseline([]);
    const diff = diffWithBaseline(current, baseline);
    expect(diff.newOpenPaths).toHaveLength(1);
    expect(diff.resolvedOpenPaths).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// diffWithBaseline — mixed scenario
// ---------------------------------------------------------------------------

describe('diffWithBaseline — mixed scenario', () => {
  it('correctly categorises new, resolved, and unchanged findings', () => {
    const common = makeFinding({ id: 'NW1003', name: 'default' });
    const resolved = makeFinding({ id: 'NW2001', name: 'svc', kind: 'Service', namespace: 'prod' });
    const newF = makeFinding({ id: 'NW4001', name: 'payments', kind: 'Namespace', namespace: 'payments' });

    const current = { findings: [common, newF], reachability: undefined };
    const baseline = makeBaseline([common, resolved]);
    const diff = diffWithBaseline(current, baseline);

    expect(diff.newFindings.map((f) => f.id)).toContain('NW4001');
    expect(diff.resolvedFindings.map((f) => f.id)).toContain('NW2001');
    expect(diff.unchangedFindings.map((f) => f.id)).toContain('NW1003');
  });
});
