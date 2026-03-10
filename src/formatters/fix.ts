import type { FixSuggestion } from '../fixer/generator.js';

// ---------------------------------------------------------------------------
// TTY formatter
// ---------------------------------------------------------------------------

export function formatFixTty(suggestions: FixSuggestion[]): string {
  if (suggestions.length === 0) {
    return 'No fix suggestions generated.';
  }

  const lines: string[] = [];
  lines.push(`Fix Suggestions (${suggestions.length})`);
  lines.push('='.repeat(60));

  for (const s of suggestions) {
    lines.push('');
    const ns = s.namespace ? `namespace: ${s.namespace}` : '(namespace not specified in manifest)';
    lines.push(`[${s.findingId}] ${s.resource}  ${ns}`);
    lines.push(`  ${s.description}`);
    if (s.fix) {
      lines.push('');
      lines.push('  Suggested fix:');
      for (const line of s.fix.split('\n')) {
        lines.push(`    ${line}`);
      }
    }
    lines.push('-'.repeat(60));
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

export function formatFixJson(suggestions: FixSuggestion[]): string {
  return JSON.stringify(suggestions, null, 2);
}
