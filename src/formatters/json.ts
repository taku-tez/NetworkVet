import type { Finding } from '../types.js';
import type { ReachabilityResult } from '../reachability/evaluator.js';

export interface JsonOutput {
  version: string;
  timestamp: string;
  summary: {
    total: number;
    errors: number;
    warnings: number;
    infos: number;
  };
  findings: Finding[];
  reachability?: ReachabilityResult;
}

/**
 * Format findings (and optionally a reachability result) as structured JSON output.
 */
export function formatJson(findings: Finding[], reachability?: ReachabilityResult): string {
  const output: JsonOutput = {
    version: '0.3.0',
    timestamp: new Date().toISOString(),
    summary: {
      total: findings.length,
      errors: findings.filter((f) => f.severity === 'error').length,
      warnings: findings.filter((f) => f.severity === 'warning').length,
      infos: findings.filter((f) => f.severity === 'info').length,
    },
    findings,
  };

  if (reachability !== undefined) {
    output.reachability = reachability;
  }

  return JSON.stringify(output, null, 2);
}
