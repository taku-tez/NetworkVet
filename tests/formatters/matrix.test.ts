import { describe, it, expect } from 'vitest';
import { formatMatrix, formatHtml } from '../../src/formatters/matrix.js';
import type { ReachabilityResult } from '../../src/reachability/evaluator.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeEntry(
  from: string,
  to: string,
  status: 'allowed' | 'denied' | 'allowed (no policy)',
  risk: 'none' | 'low' | 'medium' | 'high',
  reason = 'test reason',
) {
  return { from, to, status, risk, reason };
}

/** A minimal result with two namespaces where everything is open. */
const openResult: ReachabilityResult = {
  matrix: {
    frontend: {
      frontend: makeEntry('frontend', 'frontend', 'allowed (no policy)', 'medium', 'No ingress NetworkPolicy'),
      backend: makeEntry('frontend', 'backend', 'allowed', 'low', 'NetworkPolicy allows frontend'),
    },
    backend: {
      frontend: makeEntry('backend', 'frontend', 'allowed (no policy)', 'medium', 'No ingress NetworkPolicy'),
      backend: makeEntry('backend', 'backend', 'allowed', 'high', 'from: [{}] allows all'),
    },
  },
  unprotectedNamespaces: ['frontend'],
  openPaths: [
    makeEntry('frontend', 'frontend', 'allowed (no policy)', 'medium', 'No ingress NetworkPolicy'),
    makeEntry('frontend', 'backend', 'allowed', 'low', 'NetworkPolicy allows frontend'),
    makeEntry('backend', 'frontend', 'allowed (no policy)', 'medium', 'No ingress NetworkPolicy'),
    makeEntry('backend', 'backend', 'allowed', 'high', 'from: [{}] allows all'),
  ],
};

/** A result where all paths are denied. */
const deniedResult: ReachabilityResult = {
  matrix: {
    'ns-a': {
      'ns-a': makeEntry('ns-a', 'ns-a', 'denied', 'none', 'Default deny'),
      'ns-b': makeEntry('ns-a', 'ns-b', 'denied', 'none', 'Default deny'),
    },
    'ns-b': {
      'ns-a': makeEntry('ns-b', 'ns-a', 'denied', 'none', 'Default deny'),
      'ns-b': makeEntry('ns-b', 'ns-b', 'denied', 'none', 'Default deny'),
    },
  },
  unprotectedNamespaces: [],
  openPaths: [],
};

/** Empty result with no namespaces. */
const emptyResult: ReachabilityResult = {
  matrix: {},
  unprotectedNamespaces: [],
  openPaths: [],
};

// ---------------------------------------------------------------------------
// formatMatrix tests
// ---------------------------------------------------------------------------

describe('formatMatrix', () => {
  it('returns "no namespaces" message for empty result', () => {
    const output = formatMatrix(emptyResult);
    expect(output).toContain('No namespaces found');
  });

  it('includes the header line', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('Reachability Matrix');
  });

  it('includes source namespace names in rows', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('frontend');
    expect(output).toContain('backend');
  });

  it('includes status icons for allowed entries', () => {
    const output = formatMatrix(openResult);
    // ✅ icon for allowed
    expect(output).toContain('✅');
  });

  it('includes warning icon for allowed (no policy) entries', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('⚠️');
  });

  it('includes lock icon for denied entries', () => {
    const output = formatMatrix(deniedResult);
    expect(output).toContain('🔒');
  });

  it('includes Path details section', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('Path details');
  });

  it('shows reason text in path details', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('No ingress NetworkPolicy');
    expect(output).toContain('NetworkPolicy allows frontend');
  });

  it('shows unprotected namespace count and names', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('1 unprotected namespace');
    expect(output).toContain('frontend');
  });

  it('shows "All namespaces protected" when none are unprotected', () => {
    const output = formatMatrix(deniedResult);
    expect(output).toContain('All namespaces have ingress NetworkPolicies');
  });

  it('shows open path count', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('4 open paths detected');
  });

  it('shows "No open paths" when everything is denied', () => {
    const output = formatMatrix(deniedResult);
    expect(output).toContain('No open paths detected');
  });

  it('shows "(no open paths)" message in path details when all denied', () => {
    const output = formatMatrix(deniedResult);
    expect(output).toContain('no open paths');
  });

  it('shows singular "path" when exactly one open path', () => {
    const singlePath: ReachabilityResult = {
      matrix: {
        a: { b: makeEntry('a', 'b', 'allowed (no policy)', 'medium', 'reason') },
        b: { a: makeEntry('b', 'a', 'denied', 'none', 'denied') },
      },
      unprotectedNamespaces: ['b'],
      openPaths: [makeEntry('a', 'b', 'allowed (no policy)', 'medium', 'reason')],
    };
    const output = formatMatrix(singlePath);
    expect(output).toContain('1 open path detected');
    expect(output).not.toContain('1 open paths');
  });

  it('shows singular "namespace" when exactly one is unprotected', () => {
    const output = formatMatrix(openResult);
    expect(output).toContain('1 unprotected namespace:');
    expect(output).not.toContain('1 unprotected namespaces');
  });
});

// ---------------------------------------------------------------------------
// formatHtml tests
// ---------------------------------------------------------------------------

describe('formatHtml', () => {
  it('outputs a valid HTML document', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('<!DOCTYPE html>');
    expect(output).toContain('</html>');
  });

  it('includes the page title', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('NetworkVet');
  });

  it('includes a table element', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('<table>');
    expect(output).toContain('</table>');
  });

  it('includes namespace names as table headers', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('<th');
    expect(output).toContain('frontend');
    expect(output).toContain('backend');
  });

  it('includes table data cells', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('<td');
  });

  it('includes allowed status text', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('✅ allowed');
  });

  it('includes denied status text for denied result', () => {
    const output = formatHtml(deniedResult);
    expect(output).toContain('🔒 denied');
  });

  it('includes unprotected namespaces section', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('Unprotected Namespaces');
    expect(output).toContain('frontend');
  });

  it('shows all-protected message when no unprotected namespaces', () => {
    const output = formatHtml(deniedResult);
    expect(output).toContain('All namespaces have ingress NetworkPolicies');
  });

  it('includes Open Paths section', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('Open Paths');
  });

  it('includes reason text in open paths list', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('No ingress NetworkPolicy');
  });

  it('includes a legend', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('legend');
  });

  it('includes a generated timestamp', () => {
    const output = formatHtml(openResult);
    expect(output).toContain('Generated:');
  });

  it('escapes HTML special characters in namespace names', () => {
    const xssResult: ReachabilityResult = {
      matrix: {
        '<script>alert(1)</script>': {
          '<script>alert(1)</script>': makeEntry(
            '<script>alert(1)</script>',
            '<script>alert(1)</script>',
            'denied',
            'none',
            '<b>reason</b>',
          ),
        },
      },
      unprotectedNamespaces: [],
      openPaths: [],
    };
    const output = formatHtml(xssResult);
    expect(output).not.toContain('<script>alert(1)</script>');
    expect(output).toContain('&lt;script&gt;');
  });

  it('shows no open paths message when result is all denied', () => {
    const output = formatHtml(deniedResult);
    expect(output).toContain('No open paths detected');
  });
});
