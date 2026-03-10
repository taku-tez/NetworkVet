import type { Finding, ParsedResource, AnalysisContext, Rule } from '../types.js';
import { buildContext } from '../rules/engine.js';

export interface RuleTiming {
  ruleId: string;
  durationMs: number;
  findingCount: number;
}

export interface BenchmarkResult {
  findings: Finding[];
  timings: RuleTiming[];
  totalDurationMs: number;
}

/**
 * Run `rules` against `resources`, recording per-rule wall-clock timing.
 *
 * Rules that throw are silently skipped (same behaviour as `runRules`).
 * Returns the accumulated findings alongside a timing entry for each rule.
 */
export function benchmarkRules(
  resources: ParsedResource[],
  rules: Rule[],
  ctx?: AnalysisContext
): BenchmarkResult {
  const context = ctx ?? buildContext(resources);
  const findings: Finding[] = [];
  const timings: RuleTiming[] = [];

  const totalStart = performance.now();

  for (const rule of rules) {
    const start = performance.now();
    let ruleFindings: Finding[] = [];
    try {
      ruleFindings = rule.check(resources, context);
    } catch {
      // swallow — mirrors runRules behaviour
    }
    const durationMs = performance.now() - start;

    findings.push(...ruleFindings);
    timings.push({ ruleId: rule.id, durationMs, findingCount: ruleFindings.length });
  }

  const totalDurationMs = performance.now() - totalStart;

  return { findings, timings, totalDurationMs };
}

/**
 * Format benchmark timings as a human-readable table for --verbose output.
 * Printed to stderr so it doesn't pollute stdout-redirected output.
 */
export function formatTimings(timings: RuleTiming[], totalMs: number): string {
  if (timings.length === 0) return '';

  const sorted = [...timings].sort((a, b) => b.durationMs - a.durationMs);
  const lines: string[] = [
    '',
    '── Rule timing (--verbose) ──────────────────────',
    'Rule       Findings  Duration',
    '──────────────────────────────',
  ];

  for (const t of sorted) {
    const id = t.ruleId.padEnd(10);
    const findings = String(t.findingCount).padStart(8);
    const dur = `${t.durationMs.toFixed(2)}ms`;
    lines.push(`${id}  ${findings}  ${dur}`);
  }

  lines.push('──────────────────────────────');
  lines.push(`Total:               ${totalMs.toFixed(2)}ms`);
  lines.push('');

  return lines.join('\n');
}
