import type { PodReachabilityResult, WorkloadInfo } from '../reachability/pod_evaluator.js';

// ---------------------------------------------------------------------------
// TTY formatter
// ---------------------------------------------------------------------------

/** Pad a string to `len` with trailing spaces (ANSI-aware). */
function pad(s: string, len: number): string {
  const plain = s.replace(/\u001b\[[0-9;]*m/g, '');
  return s + ' '.repeat(Math.max(0, len - plain.length));
}

function workloadLabel(w: WorkloadInfo): string {
  return `${w.namespace}/${w.kind}/${w.name}`;
}

/**
 * Format pod-level reachability as a TTY table.
 *
 * @param results - Output of computePodReachability()
 * @param opts.namespace - If set, only show pairs where src or dst is in this namespace
 */
export function formatPodMatrixTty(
  results: PodReachabilityResult[],
  opts?: { namespace?: string },
): string {
  if (results.length === 0) {
    return 'No workloads found — nothing to display.';
  }

  let filtered = results;
  if (opts?.namespace) {
    const ns = opts.namespace;
    filtered = results.filter(
      (r) => r.from.namespace === ns || r.to.namespace === ns,
    );
  }

  if (filtered.length === 0) {
    return `No reachability data for namespace "${opts?.namespace}".`;
  }

  const lines: string[] = [];
  lines.push('Pod-level Reachability Matrix:');
  lines.push('');

  // Collect distinct workload labels
  const workloadSet = new Map<string, WorkloadInfo>();
  for (const r of filtered) {
    workloadSet.set(workloadLabel(r.from), r.from);
    workloadSet.set(workloadLabel(r.to), r.to);
  }
  const labels = [...workloadSet.keys()].sort();

  const labelWidth = Math.max(10, ...labels.map((l) => l.length)) + 2;

  // Header
  const header =
    pad('  FROM \\ TO', labelWidth + 4) +
    labels.map((l) => pad(l, labelWidth)).join('  ');
  lines.push(header);
  lines.push('  ' + '-'.repeat(header.replace(/\u001b\[[0-9;]*m/g, '').length - 2));

  // Build a lookup from (fromLabel, toLabel) → result
  const lookup = new Map<string, PodReachabilityResult>();
  for (const r of filtered) {
    lookup.set(`${workloadLabel(r.from)}|${workloadLabel(r.to)}`, r);
  }

  // Rows
  for (const fromLabel of labels) {
    const cells = labels.map((toLabel) => {
      if (fromLabel === toLabel) return pad('-', labelWidth);
      const key = `${fromLabel}|${toLabel}`;
      const r = lookup.get(key);
      if (!r) return pad('?', labelWidth);
      return pad(r.allowed ? 'ALLOW' : 'DENY', labelWidth);
    });
    lines.push(`  ${pad(fromLabel, labelWidth)}  ${cells.join('  ')}`);
  }

  lines.push('');

  // Summary of allowed/denied paths
  const allowed = filtered.filter((r) => r.allowed);
  const denied = filtered.filter((r) => !r.allowed);

  lines.push(`Summary: ${allowed.length} allowed, ${denied.length} denied`);
  lines.push('');

  // Reason breakdown
  const byReason = new Map<string, number>();
  for (const r of filtered) {
    byReason.set(r.reason, (byReason.get(r.reason) ?? 0) + 1);
  }
  for (const [reason, count] of [...byReason.entries()].sort()) {
    lines.push(`  ${reason}: ${count}`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

export interface PodMatrixJsonOutput {
  type: 'pod-reachability';
  results: Array<{
    from: WorkloadInfo;
    to: WorkloadInfo;
    allowed: boolean;
    reason: string;
  }>;
  summary: {
    total: number;
    allowed: number;
    denied: number;
    byReason: Record<string, number>;
  };
}

/**
 * Format pod-level reachability as JSON.
 */
export function formatPodMatrixJson(results: PodReachabilityResult[]): string {
  const allowed = results.filter((r) => r.allowed).length;
  const denied = results.filter((r) => !r.allowed).length;

  const byReason: Record<string, number> = {};
  for (const r of results) {
    byReason[r.reason] = (byReason[r.reason] ?? 0) + 1;
  }

  const output: PodMatrixJsonOutput = {
    type: 'pod-reachability',
    results: results.map((r) => ({
      from: r.from,
      to: r.to,
      allowed: r.allowed,
      reason: r.reason,
    })),
    summary: {
      total: results.length,
      allowed,
      denied,
      byReason,
    },
  };

  return JSON.stringify(output, null, 2);
}
