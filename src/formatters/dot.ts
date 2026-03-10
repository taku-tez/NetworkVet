import type { ReachabilityResult, ReachabilityEntry } from '../reachability/evaluator.js';

// ---------------------------------------------------------------------------
// Graphviz DOT formatter
// ---------------------------------------------------------------------------

/** Escape a namespace name for use as a DOT identifier (quoted string). */
function dotId(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Choose a fill colour for a namespace node based on protection status. */
function nodeColor(ns: string, unprotected: string[]): string {
  return unprotected.includes(ns) ? '#FFD700' : '#90EE90';
}

/** Choose edge colour and style from a ReachabilityEntry. */
function edgeAttrs(entry: ReachabilityEntry): string {
  switch (entry.status) {
    case 'allowed':
      return entry.risk === 'high'
        ? 'color="red", label="allowed (high risk)"'
        : 'color="green", label="allowed"';
    case 'allowed (no policy)':
      return 'color="orange", label="allowed (no policy)", style=dashed';
    case 'denied':
      return 'color="gray", label="denied", style=dotted';
    default:
      return 'color="gray", label="unknown", style=dotted';
  }
}

/**
 * Format a ReachabilityResult as a Graphviz DOT digraph.
 *
 * The resulting string can be piped to `dot -Tsvg` or `dot -Tpng` to render a
 * network topology diagram.
 */
export function formatDot(result: ReachabilityResult): string {
  const { matrix, unprotectedNamespaces } = result;
  const namespaces = Object.keys(matrix).sort();

  const lines: string[] = [];
  lines.push('digraph networkvet {');
  lines.push('  rankdir=LR;');
  lines.push('  node [shape=box, style=filled, fontname="Helvetica"];');
  lines.push('  edge [fontname="Helvetica", fontsize=10];');
  lines.push('');

  // Namespace nodes
  lines.push('  // Namespace nodes — color indicates protection status');
  for (const ns of namespaces) {
    const color = nodeColor(ns, unprotectedNamespaces);
    const label = unprotectedNamespaces.includes(ns)
      ? `${ns}\\n(unprotected)`
      : ns;
    lines.push(`  ${dotId(ns)} [fillcolor="${color}", label="${label.replace(/"/g, '\\"')}"];`);
  }

  lines.push('');
  lines.push('  // Traffic flow edges — style indicates reachability status');

  // Edges — only include non-self, non-denied edges or all-denied notice
  let hasEdges = false;
  for (const src of namespaces) {
    for (const dst of namespaces) {
      if (src === dst) continue; // skip self-loops for clarity
      const entry = matrix[src]?.[dst];
      if (!entry) continue;
      const attrs = edgeAttrs(entry);
      lines.push(`  ${dotId(src)} -> ${dotId(dst)} [${attrs}];`);
      hasEdges = true;
    }
  }

  if (!hasEdges && namespaces.length > 0) {
    lines.push('  // No cross-namespace traffic paths found');
  }

  lines.push('}');
  return lines.join('\n');
}
