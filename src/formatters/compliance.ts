import chalk from 'chalk';
import type { Finding } from '../types.js';
import { getComplianceRefs } from '../compliance/mapping.js';
import type { ComplianceRef } from '../compliance/mapping.js';

export type ComplianceFramework = 'cis' | 'nsa' | 'all';

interface ComplianceRow {
  ruleId: string;
  severity: string;
  framework: string;
  controlId: string;
  title: string;
  kind: string;
  name: string;
  namespace: string;
  message: string;
}

function severityColor(severity: string): (s: string) => string {
  switch (severity) {
    case 'critical': return chalk.red.bold;
    case 'high':     return chalk.red;
    case 'medium':   return chalk.yellow;
    case 'low':      return chalk.cyan;
    default:         return chalk.gray;
  }
}

/**
 * Format findings as a compliance report table (TTY).
 * Each finding is expanded to one row per compliance reference.
 */
export function formatComplianceTty(
  findings: Finding[],
  framework: ComplianceFramework = 'all'
): string {
  const rows: ComplianceRow[] = [];

  for (const f of findings) {
    const refs = getComplianceRefs(f.id).filter(
      (r) => framework === 'all' || r.framework.toLowerCase() === framework
    );

    if (refs.length === 0) {
      // Include findings with no mapping when framework=all
      if (framework === 'all') {
        rows.push({
          ruleId: f.id,
          severity: f.severity,
          framework: '—',
          controlId: '—',
          title: '—',
          kind: f.kind,
          name: f.name,
          namespace: f.namespace ?? '',
          message: f.message,
        });
      }
      continue;
    }

    for (const ref of refs) {
      rows.push({
        ruleId: f.id,
        severity: f.severity,
        framework: ref.framework,
        controlId: ref.id,
        title: ref.title,
        kind: f.kind,
        name: f.name,
        namespace: f.namespace ?? '',
        message: f.message,
      });
    }
  }

  if (rows.length === 0) {
    return chalk.green('No findings matching the selected compliance framework.');
  }

  // Deduplicate: one row per (ruleId, controlId, resource name)
  const seen = new Set<string>();
  const dedupedRows = rows.filter((r) => {
    const key = `${r.ruleId}|${r.controlId}|${r.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const lines: string[] = [];

  // Header
  lines.push(
    chalk.bold.underline('\nNetworkVet Compliance Report') + '\n'
  );

  // Column widths
  const col = {
    rule: 8,
    sev: 9,
    fw: 5,
    ctrl: 7,
    resource: 30,
    title: 48,
  };

  const header = [
    'Rule    ',
    'Severity ',
    'FW   ',
    'Control',
    'Resource                      ',
    'Control Title',
  ].join('  ');
  lines.push(chalk.bold(header));
  lines.push('─'.repeat(header.length + 10));

  for (const row of dedupedRows) {
    const colorFn = severityColor(row.severity);
    const resource = `${row.kind}/${row.name}`.slice(0, col.resource);
    const title = row.title.slice(0, col.title);
    const line = [
      colorFn(row.ruleId.padEnd(col.rule)),
      colorFn(row.severity.padEnd(col.sev)),
      chalk.bold(row.framework.padEnd(col.fw)),
      row.controlId.padEnd(col.ctrl),
      resource.padEnd(col.resource),
      chalk.gray(title),
    ].join('  ');
    lines.push(line);

    // Indent the finding message
    lines.push(chalk.gray(`         ${row.message}`));
  }

  lines.push('');
  lines.push(chalk.bold(`Total: ${dedupedRows.length} compliance finding(s) across ${findings.length} finding(s)`));

  return lines.join('\n');
}

/**
 * Format findings as compliance report JSON.
 */
export function formatComplianceJson(
  findings: Finding[],
  framework: ComplianceFramework = 'all'
): string {
  const result: Array<{
    ruleId: string;
    severity: string;
    kind: string;
    name: string;
    namespace: string;
    file: string;
    line: number;
    message: string;
    compliance: ComplianceRef[];
  }> = [];

  for (const f of findings) {
    const refs = getComplianceRefs(f.id).filter(
      (r) => framework === 'all' || r.framework.toLowerCase() === framework
    );
    if (framework !== 'all' && refs.length === 0) continue;
    result.push({
      ruleId: f.id,
      severity: f.severity,
      kind: f.kind,
      name: f.name,
      namespace: f.namespace ?? '',
      file: f.file,
      line: f.line,
      message: f.message,
      compliance: refs,
    });
  }

  return JSON.stringify({ complianceFindings: result, total: result.length }, null, 2);
}
