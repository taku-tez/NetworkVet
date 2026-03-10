import fs from 'node:fs';
import type { Finding } from '../types.js';
import type { ReachabilityResult, ReachabilityEntry } from '../reachability/evaluator.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BaselineEntry {
  timestamp: string;
  findings: Finding[];
  reachability?: ReachabilityResult;
}

export interface DiffResult {
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
  newOpenPaths: ReachabilityEntry[];
  resolvedOpenPaths: ReachabilityEntry[];
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

/**
 * A finding is uniquely identified by its rule ID, namespace, and resource
 * (kind + name).  Two findings with the same key represent the same issue.
 */
function findingKey(f: Finding): string {
  return `${f.id}::${f.namespace}::${f.kind}::${f.name}`;
}

/**
 * An open path is identified by its source and destination namespace pair.
 */
function pathKey(p: ReachabilityEntry): string {
  return `${p.from}::${p.to}`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Persist the current analysis results to a JSON file so they can be used as a
 * baseline for future `--diff` runs.
 */
export function saveBaseline(
  findings: Finding[],
  reachability: ReachabilityResult | undefined,
  filePath: string,
): void {
  const entry: BaselineEntry = {
    timestamp: new Date().toISOString(),
    findings,
    ...(reachability !== undefined ? { reachability } : {}),
  };
  fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), 'utf8');
}

/**
 * Load a baseline file previously saved with `saveBaseline`.
 * Throws if the file cannot be read or parsed.
 */
export function loadBaseline(filePath: string): BaselineEntry {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw) as BaselineEntry;
}

/**
 * Compare the current analysis results against a saved baseline and return the
 * categorised differences.
 *
 * - `newFindings`       — findings in current that were not in baseline
 * - `resolvedFindings`  — findings in baseline that are no longer in current
 * - `unchangedFindings` — findings present in both
 * - `newOpenPaths`      — open paths in current that were not in baseline
 * - `resolvedOpenPaths` — open paths in baseline that are no longer in current
 */
export function diffWithBaseline(
  current: { findings: Finding[]; reachability?: ReachabilityResult },
  baseline: BaselineEntry,
): DiffResult {
  // --- Findings diff -----------------------------------------------------
  const baselineKeys = new Map<string, Finding>();
  for (const f of baseline.findings) {
    baselineKeys.set(findingKey(f), f);
  }

  const currentKeys = new Map<string, Finding>();
  for (const f of current.findings) {
    currentKeys.set(findingKey(f), f);
  }

  const newFindings: Finding[] = [];
  const unchangedFindings: Finding[] = [];
  for (const [key, f] of currentKeys) {
    if (baselineKeys.has(key)) {
      unchangedFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  const resolvedFindings: Finding[] = [];
  for (const [key, f] of baselineKeys) {
    if (!currentKeys.has(key)) {
      resolvedFindings.push(f);
    }
  }

  // --- Open paths diff --------------------------------------------------
  const baselineOpenPaths = baseline.reachability?.openPaths ?? [];
  const currentOpenPaths = current.reachability?.openPaths ?? [];

  const baselinePathKeys = new Map<string, ReachabilityEntry>();
  for (const p of baselineOpenPaths) {
    baselinePathKeys.set(pathKey(p), p);
  }

  const currentPathKeys = new Map<string, ReachabilityEntry>();
  for (const p of currentOpenPaths) {
    currentPathKeys.set(pathKey(p), p);
  }

  const newOpenPaths: ReachabilityEntry[] = [];
  for (const [key, p] of currentPathKeys) {
    if (!baselinePathKeys.has(key)) {
      newOpenPaths.push(p);
    }
  }

  const resolvedOpenPaths: ReachabilityEntry[] = [];
  for (const [key, p] of baselinePathKeys) {
    if (!currentPathKeys.has(key)) {
      resolvedOpenPaths.push(p);
    }
  }

  return {
    newFindings,
    resolvedFindings,
    unchangedFindings,
    newOpenPaths,
    resolvedOpenPaths,
  };
}
