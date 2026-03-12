import chalk from 'chalk';
import type { SimulationDiff } from '../simulation/engine.js';
import type { PodReachabilityResult } from '../reachability/pod_evaluator.js';

// ---------------------------------------------------------------------------
// TTY formatter
// ---------------------------------------------------------------------------

function formatPathLine(result: PodReachabilityResult): string {
  return `${result.from.namespace}/${result.from.name} → ${result.to.namespace}/${result.to.name} [${result.reason}]`;
}

/**
 * Format a SimulationDiff as a human-readable TTY report with colors.
 */
export function formatSimulationTty(diff: SimulationDiff, simulatedFile: string): string {
  const lines: string[] = [];

  lines.push(`Simulation: applying ${simulatedFile}`);

  const totalChanged = diff.gained.length + diff.lost.length;

  if (totalChanged === 0) {
    lines.push('No reachability changes from applying this policy.');
  } else {
    // Gained paths
    lines.push(`GAINED paths (${diff.gained.length})`);
    if (diff.gained.length === 0) {
      lines.push('  (none)');
    } else {
      for (const r of diff.gained) {
        lines.push(chalk.green(`+ ${formatPathLine(r)}`));
      }
    }

    lines.push('');

    // Lost paths
    lines.push(`LOST paths (${diff.lost.length})`);
    if (diff.lost.length === 0) {
      lines.push('  (none)');
    } else {
      for (const r of diff.lost) {
        lines.push(chalk.red(`- ${formatPathLine(r)}`));
      }
    }

    lines.push('');
  }

  // Summary line
  lines.push(
    `Summary: ${diff.gained.length} gained, ${diff.lost.length} lost, ${diff.unchanged.length} unchanged`
  );

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

/**
 * Format a SimulationDiff as pretty-printed JSON.
 */
export function formatSimulationJson(diff: SimulationDiff, simulatedFile: string): string {
  const output = {
    type: 'simulation-diff',
    simulatedFile,
    gained: diff.gained,
    lost: diff.lost,
    unchanged: diff.unchanged,
    summary: {
      gained: diff.gained.length,
      lost: diff.lost.length,
      unchanged: diff.unchanged.length,
    },
  };
  return JSON.stringify(output, null, 2);
}
