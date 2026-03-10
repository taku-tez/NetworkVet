import type { Finding } from '../types.js';
import type { ReachabilityResult } from '../reachability/evaluator.js';

export interface JsonOutput {
  version: string;
  timestamp: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
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
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      infos: findings.filter((f) => f.severity === 'info').length,
    },
    findings,
  };

  if (reachability !== undefined) {
    output.reachability = reachability;
  }

  return JSON.stringify(output, null, 2);
}
