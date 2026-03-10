import chalk from 'chalk';
import type { Finding } from '../types.js';

type ChalkFn = (text: string) => string;

export type GroupBy = 'file' | 'namespace' | 'severity' | 'rule';

export interface FormatTtyOptions {
  groupBy?: GroupBy;
}

const SEVERITY_COLOR: Record<string, ChalkFn> = {
  error: chalk.red,
  warning: chalk.yellow,
  info: chalk.blue,
};

const SEVERITY_LABEL: Record<string, string> = {
  error: 'error  ',
  warning: 'warning',
  info: 'info   ',
};

const SEVERITY_ORDER: Record<string, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

// ─── Internal helpers ─────────────────────────────────────────────────────────

function formatFindingLine(f: Finding): string {
  const colorFn = SEVERITY_COLOR[f.severity] ?? chalk.white;
  const severityLabel = colorFn(SEVERITY_LABEL[f.severity] ?? f.severity);
  const ruleId = chalk.cyan(f.id.padEnd(8));
  const resource = chalk.gray(`${f.kind}/${f.name}`);
  const location = f.line > 0 ? chalk.gray(`:${f.line}`) : '';
  return `  ${ruleId}  ${severityLabel}  ${resource}${location}  ${f.message}`;
}

function formatDetail(f: Finding): string | null {
  if (!f.detail) return null;
  return `            ${chalk.dim(f.detail)}`;
}

function buildSummary(findings: Finding[]): string {
  const errors = findings.filter((f) => f.severity === 'error').length;
  const warnings = findings.filter((f) => f.severity === 'warning').length;
  const infos = findings.filter((f) => f.severity === 'info').length;

  const summaryParts: string[] = [];
  if (errors > 0) summaryParts.push(chalk.red(`${errors} error${errors !== 1 ? 's' : ''}`));
  if (warnings > 0) summaryParts.push(chalk.yellow(`${warnings} warning${warnings !== 1 ? 's' : ''}`));
  if (infos > 0) summaryParts.push(chalk.blue(`${infos} info${infos !== 1 ? 's' : ''}`));

  return (
    chalk.bold(`Found ${findings.length} finding${findings.length !== 1 ? 's' : ''}: `) +
    summaryParts.join(', ')
  );
}

function renderGroup(header: string, group: Finding[]): string[] {
  const lines: string[] = ['', chalk.bold.underline(header)];
  for (const f of group) {
    lines.push(formatFindingLine(f));
    const detail = formatDetail(f);
    if (detail) lines.push(detail);
  }
  return lines;
}

// ─── Group-by implementations ─────────────────────────────────────────────────

function byFile(findings: Finding[]): string {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.file)) map.set(f.file, []);
    map.get(f.file)!.push(f);
  }

  const lines: string[] = [];
  for (const [file, group] of map) {
    lines.push(...renderGroup(file, group));
  }
  return lines.join('\n');
}

function byNamespace(findings: Finding[]): string {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const ns = f.namespace || '(cluster-scoped)';
    if (!map.has(ns)) map.set(ns, []);
    map.get(ns)!.push(f);
  }

  // Sort namespaces alphabetically
  const sorted = [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  const lines: string[] = [];
  for (const [ns, group] of sorted) {
    lines.push(...renderGroup(`Namespace: ${ns}`, group));
  }
  return lines.join('\n');
}

function bySeverity(findings: Finding[]): string {
  const LABELS: Record<string, string> = {
    error: 'Errors',
    warning: 'Warnings',
    info: 'Info',
  };

  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.severity)) map.set(f.severity, []);
    map.get(f.severity)!.push(f);
  }

  const order = ['error', 'warning', 'info'];
  const lines: string[] = [];
  for (const sev of order) {
    const group = map.get(sev);
    if (!group?.length) continue;
    const colorFn = SEVERITY_COLOR[sev] ?? chalk.white;
    const header = colorFn(`${LABELS[sev] ?? sev} (${group.length})`);
    lines.push('', chalk.bold(header));
    for (const f of group) {
      lines.push(formatFindingLine(f));
      const detail = formatDetail(f);
      if (detail) lines.push(detail);
    }
  }
  return lines.join('\n');
}

function byRule(findings: Finding[]): string {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.id)) map.set(f.id, []);
    map.get(f.id)!.push(f);
  }

  // Sort by finding severity order then alphabetically by rule ID
  const sorted = [...map.entries()].sort((a, b) => {
    const sevA = SEVERITY_ORDER[a[1][0]?.severity ?? 'info'] ?? 99;
    const sevB = SEVERITY_ORDER[b[1][0]?.severity ?? 'info'] ?? 99;
    if (sevA !== sevB) return sevA - sevB;
    return a[0].localeCompare(b[0]);
  });

  const lines: string[] = [];
  for (const [ruleId, group] of sorted) {
    const sev = group[0]?.severity ?? 'info';
    const colorFn = SEVERITY_COLOR[sev] ?? chalk.white;
    lines.push(...renderGroup(`${chalk.cyan(ruleId)} — ${colorFn(sev)} (${group.length})`, group));
  }
  return lines.join('\n');
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Format findings for TTY output.
 * Supports grouping by file (default), namespace, severity, or rule.
 */
export function formatTty(findings: Finding[], options?: FormatTtyOptions): string {
  if (findings.length === 0) {
    return chalk.green('✓ No findings — all checks passed');
  }

  const groupBy = options?.groupBy ?? 'file';
  let grouped: string;

  switch (groupBy) {
    case 'namespace':
      grouped = byNamespace(findings);
      break;
    case 'severity':
      grouped = bySeverity(findings);
      break;
    case 'rule':
      grouped = byRule(findings);
      break;
    case 'file':
    default:
      grouped = byFile(findings);
      break;
  }

  const lines = [grouped, '', buildSummary(findings)];
  return lines.join('\n');
}
