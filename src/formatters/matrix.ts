import type { ReachabilityResult, ReachabilityEntry, ReachabilityRisk } from '../reachability/evaluator.js';

// ---------------------------------------------------------------------------
// ASCII / TTY matrix formatter
// ---------------------------------------------------------------------------

const STATUS_ICON: Record<string, string> = {
  'allowed': '✅',
  'denied': '🔒',
  'allowed (no policy)': '⚠️ ',
};

const RISK_LABEL: Record<ReachabilityRisk, string> = {
  none: '',
  low: ' (low risk)',
  medium: ' (unprotected)',
  high: ' (HIGH RISK)',
};

/** Pad a string to `len` with trailing spaces. */
function pad(s: string, len: number): string {
  // Strip ANSI escape codes for length calculation
  const plain = s.replace(/\u001b\[[0-9;]*m/g, '');
  return s + ' '.repeat(Math.max(0, len - plain.length));
}

/**
 * Format a ReachabilityResult as a human-readable ASCII matrix table.
 */
export function formatMatrix(result: ReachabilityResult): string {
  const { matrix, unprotectedNamespaces, openPaths } = result;
  const namespaces = Object.keys(matrix).sort();

  if (namespaces.length === 0) {
    return 'No namespaces found — nothing to display.';
  }

  const lines: string[] = [];
  lines.push('Reachability Matrix (cross-namespace):');
  lines.push('');

  // Determine column widths
  const fromWidth = Math.max(8, ...namespaces.map((n) => n.length)) + 2;
  const toWidth = Math.max(6, ...namespaces.map((n) => n.length)) + 2;

  // Header row
  const header = pad('  FROM \\ TO', fromWidth + 4) +
    namespaces.map((n) => pad(n, toWidth)).join('  ');
  lines.push(header);
  lines.push('  ' + '-'.repeat(header.length - 2));

  // One row per source namespace
  for (const src of namespaces) {
    const cells = namespaces.map((dst) => {
      const entry: ReachabilityEntry | undefined = matrix[src]?.[dst];
      if (!entry) return pad('?', toWidth);
      const icon = STATUS_ICON[entry.status] ?? '?';
      return pad(icon, toWidth);
    });
    lines.push(`  ${pad(src, fromWidth)}  ${cells.join('  ')}`);
  }

  lines.push('');

  // Detailed path list for non-denied entries
  lines.push('Path details:');
  let hasDetails = false;
  for (const src of namespaces) {
    for (const dst of namespaces) {
      const entry = matrix[src]?.[dst];
      if (!entry || entry.status === 'denied') continue;
      hasDetails = true;
      const icon = STATUS_ICON[entry.status] ?? '?';
      const risk = RISK_LABEL[entry.risk] ?? '';
      const fromPadded = pad(src, fromWidth);
      const toPadded = pad(dst, toWidth);
      lines.push(`  ${fromPadded} → ${toPadded}  ${icon} ${entry.status}${risk}`);
      lines.push(`    ${entry.reason}`);
    }
  }
  if (!hasDetails) {
    lines.push('  (no open paths — all traffic is denied)');
  }

  lines.push('');

  // Summary
  if (unprotectedNamespaces.length > 0) {
    lines.push(`⚠️  ${unprotectedNamespaces.length} unprotected namespace${unprotectedNamespaces.length !== 1 ? 's' : ''}: ${unprotectedNamespaces.join(', ')}`);
  } else {
    lines.push('✅ All namespaces have ingress NetworkPolicies.');
  }

  const openCount = openPaths.length;
  if (openCount > 0) {
    lines.push(`⚠️  ${openCount} open path${openCount !== 1 ? 's' : ''} detected`);
  } else {
    lines.push('✅ No open paths detected.');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// HTML matrix formatter
// ---------------------------------------------------------------------------

const STATUS_COLOR: Record<string, string> = {
  allowed: '#d4edda',         // green-ish
  denied: '#f8f9fa',          // light grey
  'allowed (no policy)': '#fff3cd', // amber
};

const RISK_BORDER: Record<ReachabilityRisk, string> = {
  none: '#dee2e6',
  low: '#28a745',
  medium: '#ffc107',
  high: '#dc3545',
};

const STATUS_TEXT: Record<string, string> = {
  allowed: '✅ allowed',
  denied: '🔒 denied',
  'allowed (no policy)': '⚠️ allowed<br>(no policy)',
};

/**
 * Format a ReachabilityResult as a self-contained interactive HTML page with:
 *   - A D3.js v7 force-directed graph visualisation (loaded from CDN)
 *   - A colour-coded reachability matrix table
 *   - A summary of unprotected namespaces and open paths
 */
export function formatHtml(result: ReachabilityResult): string {
  const { matrix, unprotectedNamespaces, openPaths } = result;
  const namespaces = Object.keys(matrix).sort();
  const ts = new Date().toISOString();

  // ---- D3 graph data ---------------------------------------------------
  // Nodes
  const nodes = namespaces.map((ns) => ({
    id: ns,
    protected: !unprotectedNamespaces.includes(ns),
  }));

  // Links — include all non-self edges
  interface GraphLink {
    source: string;
    target: string;
    status: string;
    risk: string;
  }
  const links: GraphLink[] = [];
  for (const src of namespaces) {
    for (const dst of namespaces) {
      if (src === dst) continue;
      const entry = matrix[src]?.[dst];
      if (!entry) continue;
      links.push({ source: src, target: dst, status: entry.status, risk: entry.risk });
    }
  }

  // Escape </script> sequences so the JSON cannot break out of the script tag.
  const graphData = JSON.stringify({ nodes, links }).replace(/<\//g, '<\\/');

  // ---- Matrix table ----------------------------------------------------
  const thStyle = 'padding:8px 12px;background:#343a40;color:#fff;text-align:center;white-space:nowrap;';
  const tdStyle = (bg: string, border: string) =>
    `padding:8px 12px;background:${bg};border:2px solid ${border};text-align:center;font-size:0.85em;`;

  const headerCells = namespaces
    .map((n) => `<th style="${thStyle}">${escHtml(n)}</th>`)
    .join('\n        ');

  const rows = namespaces
    .map((src) => {
      const cells = namespaces
        .map((dst) => {
          const entry = matrix[src]?.[dst];
          if (!entry) return `<td style="${tdStyle('#fff', '#dee2e6')}">?</td>`;
          const bg = STATUS_COLOR[entry.status] ?? '#fff';
          const border = RISK_BORDER[entry.risk] ?? '#dee2e6';
          const text = STATUS_TEXT[entry.status] ?? entry.status;
          const title = escHtml(entry.reason);
          return `<td style="${tdStyle(bg, border)}" title="${title}">${text}</td>`;
        })
        .join('\n        ');
      return `      <tr>
        <th style="${thStyle}">${escHtml(src)}</th>
        ${cells}
      </tr>`;
    })
    .join('\n');

  // ---- Open paths + unprotected summary --------------------------------
  const openPathsHtml =
    openPaths.length === 0
      ? '<p style="color:#28a745">&#x2705; No open paths detected.</p>'
      : '<ul>' +
        openPaths
          .map(
            (p) =>
              `<li><strong>${escHtml(p.from)}</strong> &rarr; <strong>${escHtml(p.to)}</strong>: ` +
              `${escHtml(p.status)} (risk: ${escHtml(p.risk)}) &mdash; ${escHtml(p.reason)}</li>`,
          )
          .join('\n') +
        '</ul>';

  const unprotectedHtml =
    unprotectedNamespaces.length === 0
      ? '<p style="color:#28a745">&#x2705; All namespaces have ingress NetworkPolicies.</p>'
      : `<p style="color:#856404">&#x26A0;&#xFE0F; Unprotected namespaces: <strong>${unprotectedNamespaces.map(escHtml).join(', ')}</strong></p>`;

  // ---- D3 script -------------------------------------------------------
  const d3Script = `
    const data = ${graphData};

    const width = document.getElementById('graph').clientWidth || 900;
    const height = 480;

    const svg = d3.select('#graph')
      .append('svg')
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', [0, 0, width, height]);

    // Arrow marker
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', '#999');

    function linkColor(d) {
      if (d.status === 'allowed' && d.risk === 'high') return '#dc3545';
      if (d.status === 'allowed') return '#28a745';
      if (d.status === 'allowed (no policy)') return '#ffc107';
      return '#adb5bd';
    }

    function linkDash(d) {
      if (d.status === 'allowed (no policy)') return '6,3';
      if (d.status === 'denied') return '3,3';
      return null;
    }

    const simulation = d3.forceSimulation(data.nodes)
      .force('link', d3.forceLink(data.links).id(d => d.id).distance(140))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(50));

    const link = svg.append('g')
      .selectAll('line')
      .data(data.links)
      .join('line')
        .attr('stroke', linkColor)
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', d => linkDash(d))
        .attr('marker-end', 'url(#arrow)')
        .attr('opacity', 0.8);

    const node = svg.append('g')
      .selectAll('g')
      .data(data.nodes)
      .join('g')
        .call(d3.drag()
          .on('start', dragstart)
          .on('drag', dragged)
          .on('end', dragend));

    node.append('rect')
      .attr('width', 100)
      .attr('height', 36)
      .attr('x', -50)
      .attr('y', -18)
      .attr('rx', 6)
      .attr('fill', d => d.protected ? '#90EE90' : '#FFD700')
      .attr('stroke', d => d.protected ? '#28a745' : '#856404')
      .attr('stroke-width', 2);

    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '12px')
      .attr('font-family', 'system-ui, sans-serif')
      .text(d => d.id);

    node.append('title').text(d => d.protected ? d.id : d.id + ' (unprotected)');

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
      node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
    });

    function dragstart(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    }
    function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
    function dragend(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null; d.fy = null;
    }
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetworkVet &mdash; Network Reachability Report</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #212529; background: #f8f9fa; }
    h1 { color: #343a40; margin-bottom: 0.25rem; }
    h2 { color: #343a40; margin-top: 2rem; }
    #graph { background: #fff; border: 1px solid #dee2e6; border-radius: 8px;
             padding: 0.5rem; margin: 1rem 0; min-height: 480px; }
    table { border-collapse: collapse; margin: 1rem 0; background: #fff;
            border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .legend { display: flex; gap: 1.5rem; margin: 1rem 0; font-size: 0.88em;
              flex-wrap: wrap; }
    .legend span { display: flex; align-items: center; gap: 0.4rem; }
    .swatch { width: 16px; height: 16px; display: inline-block;
              border: 2px solid #999; border-radius: 3px; }
    ul { padding-left: 1.5rem; }
    li { margin: 0.3rem 0; }
    p.meta { color: #6c757d; font-size: 0.88em; margin: 0; }
  </style>
</head>
<body>
  <h1>NetworkVet Network Reachability Report</h1>
  <p class="meta">Generated: ${escHtml(ts)}</p>

  <h2>Network Graph</h2>
  <div class="legend">
    <span><span class="swatch" style="background:#90EE90;border-color:#28a745"></span> Protected namespace</span>
    <span><span class="swatch" style="background:#FFD700;border-color:#856404"></span> Unprotected namespace</span>
    <span><span class="swatch" style="background:#28a745;border-color:#28a745"></span> Allowed traffic</span>
    <span><span class="swatch" style="background:#ffc107;border-color:#ffc107"></span> Allowed (no policy)</span>
    <span><span class="swatch" style="background:#dc3545;border-color:#dc3545"></span> Allowed (high risk)</span>
    <span><span class="swatch" style="background:#adb5bd;border-color:#adb5bd"></span> Denied</span>
  </div>
  <div id="graph"></div>

  <h2>Reachability Matrix</h2>
  <div class="legend">
    <span><span class="swatch" style="background:#d4edda;border-color:#28a745"></span> allowed</span>
    <span><span class="swatch" style="background:#fff3cd;border-color:#ffc107"></span> allowed (no policy)</span>
    <span><span class="swatch" style="background:#f8f9fa;border-color:#dee2e6"></span> denied</span>
    <span><span class="swatch" style="background:#fff;border-color:#dc3545"></span> high risk border</span>
  </div>
  <table>
    <thead>
      <tr>
        <th style="${thStyle}">FROM \\ TO</th>
        ${headerCells}
      </tr>
    </thead>
    <tbody>
${rows}
    </tbody>
  </table>

  <h2>Summary</h2>
  <div id="summary">
    <h3>Unprotected Namespaces</h3>
    ${unprotectedHtml}
    <h3>Open Paths (${openPaths.length})</h3>
    ${openPathsHtml}
  </div>

  <script>
  ${d3Script}
  </script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
