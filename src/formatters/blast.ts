import chalk from 'chalk';
import type { BlastRadiusResult } from '../blast/index.js';

/**
 * Format a BlastRadiusResult as a human-readable TTY report with colors.
 */
export function formatBlastRadiusTty(result: BlastRadiusResult): string {
  const lines: string[] = [];

  const originKey = `${result.origin.namespace}/${result.origin.name}`;
  lines.push(chalk.green(`Blast Radius: ${originKey}`));
  lines.push('');

  lines.push(`Reachable workloads (${result.reachable.length}):`);
  if (result.reachable.length === 0) {
    lines.push('  (none)');
  } else {
    for (const w of result.reachable) {
      const key = `${w.namespace}/${w.name}`;
      const d = result.depth.get(key) ?? 0;
      const isHighRisk = result.highRiskTargets.includes(key);
      let line = `  [depth=${d}] ${w.namespace}/${w.name} (${w.kind})`;
      if (isHighRisk) {
        line += chalk.red(' ⚠ HIGH RISK');
      } else if (d > 1) {
        line = chalk.yellow(line);
      }
      lines.push(line);
    }
  }

  lines.push('');

  if (result.highRiskTargets.length > 0) {
    lines.push(chalk.red(`High-risk targets reachable: ${result.highRiskTargets.length}`));
    for (const target of result.highRiskTargets) {
      lines.push(chalk.red(`  - ${target}`));
    }
    lines.push('');
  }

  lines.push(`Contained (not reachable): ${result.unreachable.length} workloads`);

  return lines.join('\n');
}

/**
 * Format a BlastRadiusResult as pretty-printed JSON.
 */
export function formatBlastRadiusJson(result: BlastRadiusResult): string {
  const allWorkloadCount = 1 + result.reachable.length + result.unreachable.length;
  const maxDepth = result.reachable.length === 0
    ? 0
    : Math.max(...result.reachable.map((w) => result.depth.get(`${w.namespace}/${w.name}`) ?? 0));

  const output = {
    type: 'blast-radius',
    origin: result.origin,
    reachable: result.reachable,
    unreachable: result.unreachable,
    highRiskTargets: result.highRiskTargets,
    summary: {
      totalWorkloads: allWorkloadCount,
      reachableCount: result.reachable.length,
      unreachableCount: result.unreachable.length,
      highRiskCount: result.highRiskTargets.length,
      maxDepth,
    },
  };
  return JSON.stringify(output, null, 2);
}
