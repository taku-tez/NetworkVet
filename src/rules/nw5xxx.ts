import type { Rule, ParsedResource, AnalysisContext, Finding } from '../types.js';
import { isAuthorizationPolicy, isPeerAuthentication } from '../types.js';

function makeFinding(
  rule: Pick<Rule, 'id' | 'severity'>,
  r: ParsedResource,
  message: string,
  detail?: string
): Finding {
  return {
    id: rule.id,
    severity: rule.severity,
    kind: r.kind,
    name: r.metadata.name,
    namespace: r.metadata.namespace ?? '',
    file: r.file,
    line: r.line,
    message,
    detail,
  };
}

// ─── NW5001 ──────────────────────────────────────────────────────────────────
// AuthorizationPolicy ALLOW rule has principals: ["*"] — any workload identity
const nw5001: Rule = {
  id: 'NW5001',
  severity: 'error',
  description: 'AuthorizationPolicy ALLOW rule grants access to all principals (principals: ["*"])',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isAuthorizationPolicy(r)) continue;
      const spec = r.spec;
      if (spec.action && spec.action !== 'ALLOW') continue;
      for (const rule of spec.rules ?? []) {
        for (const from of rule.from ?? []) {
          if (from.source.principals?.includes('*')) {
            findings.push(makeFinding(
              nw5001,
              r,
              `AuthorizationPolicy "${r.metadata.name}" ALLOW rule grants access to all principals (principals: ["*"])`,
              'Restrict principals to specific service accounts or use DENY policy to block unwanted access.'
            ));
            break;
          }
        }
      }
    }
    return findings;
  },
};

// ─── NW5002 ──────────────────────────────────────────────────────────────────
// AuthorizationPolicy ALLOW rule has a "from" with no source constraints at all
const nw5002: Rule = {
  id: 'NW5002',
  severity: 'warning',
  description: 'AuthorizationPolicy ALLOW rule has a "from" clause with an empty source (matches any source)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isAuthorizationPolicy(r)) continue;
      const spec = r.spec;
      if (spec.action && spec.action !== 'ALLOW') continue;
      for (const rule of spec.rules ?? []) {
        for (const from of rule.from ?? []) {
          const src = from.source;
          const hasConstraint =
            (src.principals?.length ?? 0) > 0 ||
            (src.namespaces?.length ?? 0) > 0 ||
            (src.ipBlocks?.length ?? 0) > 0 ||
            (src.remoteIpBlocks?.length ?? 0) > 0 ||
            (src.notPrincipals?.length ?? 0) > 0 ||
            (src.notNamespaces?.length ?? 0) > 0 ||
            (src.notIpBlocks?.length ?? 0) > 0;
          if (!hasConstraint) {
            findings.push(makeFinding(
              nw5002,
              r,
              `AuthorizationPolicy "${r.metadata.name}" ALLOW rule has a "from" clause with an empty source`,
              'An empty source matches any caller. Add principals, namespaces, or ipBlocks constraints.'
            ));
            break;
          }
        }
      }
    }
    return findings;
  },
};

// ─── NW5003 ──────────────────────────────────────────────────────────────────
// AuthorizationPolicy ALLOW rule has methods: ["*"] — all HTTP methods allowed
const nw5003: Rule = {
  id: 'NW5003',
  severity: 'warning',
  description: 'AuthorizationPolicy ALLOW rule permits all HTTP methods (methods: ["*"])',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isAuthorizationPolicy(r)) continue;
      const spec = r.spec;
      if (spec.action && spec.action !== 'ALLOW') continue;
      for (const rule of spec.rules ?? []) {
        for (const to of rule.to ?? []) {
          if (to.operation.methods?.includes('*')) {
            findings.push(makeFinding(
              nw5003,
              r,
              `AuthorizationPolicy "${r.metadata.name}" ALLOW rule permits all HTTP methods (methods: ["*"])`,
              'Restrict to specific HTTP methods (GET, POST, etc.) to reduce the attack surface.'
            ));
            break;
          }
        }
      }
    }
    return findings;
  },
};

// ─── NW5004 ──────────────────────────────────────────────────────────────────
// AuthorizationPolicy ALLOW with a rule that has neither "from" nor "to"
// (matches all traffic unconditionally)
const nw5004: Rule = {
  id: 'NW5004',
  severity: 'error',
  description: 'AuthorizationPolicy ALLOW rule has neither "from" nor "to" — allows all traffic unconditionally',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isAuthorizationPolicy(r)) continue;
      const spec = r.spec;
      if (spec.action && spec.action !== 'ALLOW') continue;
      // An ALLOW policy with no rules also allows all traffic
      if (!spec.rules || spec.rules.length === 0) continue; // no-rules = DENY all; not a problem here
      for (const rule of spec.rules) {
        const hasFrom = (rule.from?.length ?? 0) > 0;
        const hasTo = (rule.to?.length ?? 0) > 0;
        if (!hasFrom && !hasTo) {
          findings.push(makeFinding(
            nw5004,
            r,
            `AuthorizationPolicy "${r.metadata.name}" ALLOW rule has neither "from" nor "to" — allows all traffic unconditionally`,
            'Add "from" (source) or "to" (operation) constraints to limit what traffic is allowed.'
          ));
          break;
        }
      }
    }
    return findings;
  },
};

// ─── NW5005 ──────────────────────────────────────────────────────────────────
// PeerAuthentication uses PERMISSIVE mTLS mode — allows both plaintext and mTLS
const nw5005: Rule = {
  id: 'NW5005',
  severity: 'warning',
  description: 'PeerAuthentication uses PERMISSIVE mTLS mode — plaintext traffic is accepted',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isPeerAuthentication(r)) continue;
      if (r.spec.mtls?.mode === 'PERMISSIVE') {
        findings.push(makeFinding(
          nw5005,
          r,
          `PeerAuthentication "${r.metadata.name}" uses PERMISSIVE mTLS mode — plaintext traffic is accepted`,
          'Switch to STRICT mode to enforce mutual TLS for all traffic to selected workloads.'
        ));
      }
    }
    return findings;
  },
};

// ─── NW5006 ──────────────────────────────────────────────────────────────────
// PeerAuthentication explicitly disables mTLS
const nw5006: Rule = {
  id: 'NW5006',
  severity: 'error',
  description: 'PeerAuthentication disables mTLS (mode: DISABLE) — all traffic is plaintext',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isPeerAuthentication(r)) continue;
      if (r.spec.mtls?.mode === 'DISABLE') {
        findings.push(makeFinding(
          nw5006,
          r,
          `PeerAuthentication "${r.metadata.name}" disables mTLS (mode: DISABLE) — all traffic is plaintext`,
          'Enable mTLS (STRICT or PERMISSIVE) to encrypt traffic between workloads.'
        ));
      }
    }
    return findings;
  },
};

// ─── NW5007 ──────────────────────────────────────────────────────────────────
// AuthorizationPolicy has no selector — applies to all workloads in the namespace
const nw5007: Rule = {
  id: 'NW5007',
  severity: 'info',
  description: 'AuthorizationPolicy has no workload selector — policy applies to all workloads in the namespace',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isAuthorizationPolicy(r)) continue;
      const sel = r.spec.selector;
      const isEmpty =
        !sel ||
        !sel.matchLabels ||
        Object.keys(sel.matchLabels).length === 0;
      if (isEmpty) {
        findings.push(makeFinding(
          nw5007,
          r,
          `AuthorizationPolicy "${r.metadata.name}" has no workload selector — applies to all workloads in namespace "${r.metadata.namespace ?? ''}"`,
          'Add a selector to scope the policy to specific workloads, or confirm this broad scope is intended.'
        ));
      }
    }
    return findings;
  },
};

// ─── NW5008 ──────────────────────────────────────────────────────────────────
// AuthorizationPolicy ALLOW rule has no namespace restriction in source
// (source.namespaces is absent or empty) while principals are set
const nw5008: Rule = {
  id: 'NW5008',
  severity: 'warning',
  description: 'AuthorizationPolicy ALLOW rule grants access without restricting the source namespace',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isAuthorizationPolicy(r)) continue;
      const spec = r.spec;
      if (spec.action && spec.action !== 'ALLOW') continue;
      for (const rule of spec.rules ?? []) {
        for (const from of rule.from ?? []) {
          const src = from.source;
          // Only flag when principals are set (specific identity) but namespace is unconstrained
          const hasPrincipals = (src.principals?.length ?? 0) > 0 &&
            !src.principals?.includes('*');
          const hasNamespace = (src.namespaces?.length ?? 0) > 0;
          if (hasPrincipals && !hasNamespace) {
            findings.push(makeFinding(
              nw5008,
              r,
              `AuthorizationPolicy "${r.metadata.name}" ALLOW rule specifies principals but does not restrict source namespace`,
              'Add source.namespaces to ensure the principal is only trusted from the expected namespace.'
            ));
            break;
          }
        }
      }
    }
    return findings;
  },
};

export const nw5xxxRules: Rule[] = [
  nw5001,
  nw5002,
  nw5003,
  nw5004,
  nw5005,
  nw5006,
  nw5007,
  nw5008,
];
