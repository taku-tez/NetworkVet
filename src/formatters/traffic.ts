import type { TrafficAnalysisResult, TrafficViolation, PolicyGap } from '../traffic/types.js';

// ─── TTY formatter ────────────────────────────────────────────────────────────

const RULE = '─'.repeat(60);

function severityIcon(severity: TrafficViolation['severity']): string {
  switch (severity) {
    case 'error':   return '✖';
    case 'warning': return '⚠';
    case 'info':    return '·';
  }
}

function typeLabel(type: TrafficViolation['type']): string {
  switch (type) {
    case 'policy-gap':       return 'policy-gap';
    case 'unexpected-allow': return 'unexpected-allow';
    case 'unexpected-deny':  return 'unexpected-deny';
    case 'shadow-traffic':   return 'shadow-traffic';
  }
}

function commaNum(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * Format a TrafficAnalysisResult as a human-readable TTY string.
 */
export function formatTrafficTty(result: TrafficAnalysisResult): string {
  const lines: string[] = [];

  lines.push(`Traffic Analysis (${commaNum(result.totalFlows)} flows observed)`);
  lines.push(RULE);
  lines.push(`Allowed: ${commaNum(result.allowedFlows)}  Dropped: ${commaNum(result.droppedFlows)}`);

  // ── Policy Gaps ──────────────────────────────────────────────────────────
  if (result.policyGaps.length === 0) {
    lines.push('');
    lines.push('Policy Gaps: none');
  } else {
    lines.push('');
    lines.push(`Policy Gaps (${result.policyGaps.length}):`);
    for (const gap of result.policyGaps) {
      const portStr = gap.destPort > 0 ? `:${gap.destPort}` : '';
      lines.push(
        `  ⚠  ${gap.sourceNamespace} → ${gap.destNamespace}${portStr}  ` +
        `observed ${commaNum(gap.observedCount)} time${gap.observedCount === 1 ? '' : 's'} — ` +
        `no ingress policy in "${gap.destNamespace}"`,
      );
    }
  }

  // ── Violations ───────────────────────────────────────────────────────────
  if (result.violations.length === 0) {
    lines.push('');
    lines.push('Violations: none');
  } else {
    lines.push('');
    lines.push(`Violations (${result.violations.length}):`);
    for (const v of result.violations) {
      const { flow } = v;
      const portStr = flow.destPort !== undefined ? `:${flow.destPort}` : '';
      const proto = flow.protocol ? ` (${flow.protocol})` : '';
      const header =
        `  ${severityIcon(v.severity)} [${typeLabel(v.type)}] ` +
        `${flow.sourceNamespace} → ${flow.destNamespace}${portStr}${proto} ${flow.verdict}`;
      lines.push(header);
      lines.push(`     ${v.message}`);
    }
  }

  return lines.join('\n');
}

/**
 * Format a TrafficAnalysisResult as JSON.
 */
export function formatTrafficJson(result: TrafficAnalysisResult): string {
  return JSON.stringify(result, null, 2);
}
