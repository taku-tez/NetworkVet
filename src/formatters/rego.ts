import type { RegoPolicy } from '../rego/generator.js';
import { generateGatekeeperConstraint, generateConftestPolicy } from '../rego/generator.js';

const RULE = '─'.repeat(60);

/**
 * Format a summary list of Rego policies for TTY output.
 */
export function formatRegoTty(policies: RegoPolicy[]): string {
  if (policies.length === 0) {
    return 'No Rego policies generated (no findings or no Rego definitions for detected rule IDs).';
  }

  const lines: string[] = [];
  lines.push(`Rego Policies (${policies.length})`);
  lines.push(RULE);

  for (const p of policies) {
    const action = p.enforcementAction === 'deny' ? 'deny  ' : p.enforcementAction === 'warn' ? 'warn  ' : 'dryrun';
    lines.push(`  ${p.ruleId.padEnd(8)} [${action}]  ${p.description}`);
    lines.push(`           package: ${p.package}`);
  }

  lines.push('');
  lines.push('Use --format gatekeeper to generate ConstraintTemplate YAMLs.');
  lines.push('Use --format conftest to generate Conftest-compatible Rego policies.');
  return lines.join('\n');
}

/**
 * Returns a Map of filename → file content for all Rego policies.
 * Used when writing policy files to disk or piping individual policy blobs.
 */
export function formatRegoFiles(policies: RegoPolicy[]): Map<string, string> {
  const files = new Map<string, string>();
  for (const p of policies) {
    files.set(`${p.name}.rego`, p.rego + '\n');
  }
  return files;
}

/**
 * Format all policies as concatenated Rego policy files (for --format rego).
 */
export function formatRegoAll(policies: RegoPolicy[]): string {
  if (policies.length === 0) {
    return '# No Rego policies generated.\n';
  }
  return policies
    .map((p) => `# === ${p.ruleId}: ${p.description} ===\n${p.rego}\n`)
    .join('\n');
}

/**
 * Format all policies as concatenated GatekeeperConstraintTemplate YAMLs.
 */
export function formatGatekeeperAll(policies: RegoPolicy[]): string {
  if (policies.length === 0) {
    return '# No GatekeeperConstraintTemplate YAMLs generated.\n';
  }
  return policies.map((p) => generateGatekeeperConstraint(p)).join('---\n');
}

/**
 * Format all policies as concatenated Conftest-compatible Rego files.
 */
export function formatConftestAll(policies: RegoPolicy[]): string {
  if (policies.length === 0) {
    return '# No Conftest policies generated.\n';
  }
  return policies.map((p) => generateConftestPolicy(p)).join('\n');
}
