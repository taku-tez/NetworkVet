import type { DiffResult } from '../diff/index.js';
import type { Finding } from '../types.js';
import type { ReachabilityEntry } from '../reachability/evaluator.js';

// ---------------------------------------------------------------------------
// TTY formatter
// ---------------------------------------------------------------------------

const SEP = '\u2500'.repeat(53); // ─────────────────────────────────────────

function formatFindingLine(prefix: string, f: Finding): string {
  const resource = `${f.kind}/${f.name}`;
  return `  ${prefix} ${f.id.padEnd(8)} ${f.severity.padEnd(8)} ${resource.padEnd(32)} ${f.message}`;
}

function formatPathLine(prefix: string, p: ReachabilityEntry): string {
  const arrow = `${p.from} \u2192 ${p.to}`;
  const riskFlag = p.risk === 'high' ? '  \u26A0\uFE0F HIGH' : p.risk !== 'none' ? '  \u26A0\uFE0F' : '';
  return `  ${prefix} ${arrow.padEnd(36)} ${p.status}${riskFlag}`;
}

/**
 * Format a DiffResult as a human-readable TTY report.
 */
export function formatDiffTty(diff: DiffResult): string {
  const lines: string[] = [];

  lines.push('NetworkVet Diff Report');
  lines.push(SEP);

  // --- New findings -------------------------------------------------------
  lines.push(`New issues (${diff.newFindings.length}):`);
  if (diff.newFindings.length === 0) {
    lines.push('  (none)');
  } else {
    for (const f of diff.newFindings) {
      lines.push(formatFindingLine('+', f));
    }
  }
  lines.push('');

  // --- Resolved findings --------------------------------------------------
  lines.push(`Resolved issues (${diff.resolvedFindings.length}):`);
  if (diff.resolvedFindings.length === 0) {
    lines.push('  (none)');
  } else {
    for (const f of diff.resolvedFindings) {
      lines.push(formatFindingLine('-', f));
    }
  }
  lines.push('');

  // --- New open paths -----------------------------------------------------
  lines.push(`New open paths (${diff.newOpenPaths.length}):`);
  if (diff.newOpenPaths.length === 0) {
    lines.push('  (none)');
  } else {
    for (const p of diff.newOpenPaths) {
      lines.push(formatPathLine('+', p));
    }
  }
  lines.push('');

  // --- Resolved open paths ------------------------------------------------
  lines.push(`Resolved open paths (${diff.resolvedOpenPaths.length}):`);
  if (diff.resolvedOpenPaths.length === 0) {
    lines.push('  (none)');
  } else {
    for (const p of diff.resolvedOpenPaths) {
      lines.push(formatPathLine('-', p));
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

/**
 * Format a DiffResult as pretty-printed JSON.
 */
export function formatDiffJson(diff: DiffResult): string {
  return JSON.stringify(diff, null, 2);
}
