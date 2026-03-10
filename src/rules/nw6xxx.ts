import type { Rule, ParsedResource, AnalysisContext, Finding } from '../types.js';
import { isCiliumNetworkPolicy, isCiliumClusterwideNetworkPolicy } from '../types.js';

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

// ─── NW6001 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy ingress allows from "world" entity (any external IP)
const nw6001: Rule = {
  id: 'NW6001',
  severity: 'error',
  description: 'CiliumNetworkPolicy ingress rule allows traffic from the "world" entity (any external IP)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      for (const ingress of r.spec.ingress ?? []) {
        if (ingress.fromEntities?.includes('world')) {
          findings.push(makeFinding(
            nw6001,
            r,
            `CiliumNetworkPolicy "${r.metadata.name}" ingress rule allows from entity "world" (any external IP)`,
            'Restrict ingress to specific CIDRs or cluster-internal entities instead of "world".'
          ));
          break;
        }
      }
    }
    return findings;
  },
};

// ─── NW6002 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy egress allows to "world" entity (any external IP)
const nw6002: Rule = {
  id: 'NW6002',
  severity: 'warning',
  description: 'CiliumNetworkPolicy egress rule allows traffic to the "world" entity (any external IP)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      for (const egress of r.spec.egress ?? []) {
        if (egress.toEntities?.includes('world')) {
          findings.push(makeFinding(
            nw6002,
            r,
            `CiliumNetworkPolicy "${r.metadata.name}" egress rule allows to entity "world" (any external IP)`,
            'Restrict egress to specific CIDRs, FQDNs, or internal entities instead of "world".'
          ));
          break;
        }
      }
    }
    return findings;
  },
};

// ─── NW6003 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy uses "all" entity — matches any endpoint cluster-wide
const nw6003: Rule = {
  id: 'NW6003',
  severity: 'error',
  description: 'CiliumNetworkPolicy rule uses the "all" entity — matches every endpoint in the cluster',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      const spec = r.spec;
      const ingressHasAll = (spec.ingress ?? []).some((i) => i.fromEntities?.includes('all'));
      const egressHasAll = (spec.egress ?? []).some((e) => e.toEntities?.includes('all'));
      if (ingressHasAll || egressHasAll) {
        findings.push(makeFinding(
          nw6003,
          r,
          `CiliumNetworkPolicy "${r.metadata.name}" uses the "all" entity — grants access to/from every endpoint`,
          'Replace the "all" entity with more specific entities, selectors, or CIDRs.'
        ));
      }
    }
    return findings;
  },
};

// ─── NW6004 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy has an empty endpointSelector ({}) — applies to all pods
const nw6004: Rule = {
  id: 'NW6004',
  severity: 'info',
  description: 'CiliumNetworkPolicy has an empty endpointSelector — policy applies to all pods in the namespace',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      const sel = r.spec.endpointSelector;
      if (sel === undefined) continue; // selector absent is OK for CCNP
      const isEmpty = Object.keys(sel).length === 0;
      if (isEmpty) {
        findings.push(makeFinding(
          nw6004,
          r,
          `CiliumNetworkPolicy "${r.metadata.name}" has an empty endpointSelector ({}) — applies to all pods in namespace "${r.metadata.namespace ?? ''}"`,
          'Add label selectors to scope this policy to specific pods, or confirm the broad scope is intentional.'
        ));
      }
    }
    return findings;
  },
};

// ─── NW6005 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy ingress allows from 0.0.0.0/0 CIDR
const nw6005: Rule = {
  id: 'NW6005',
  severity: 'error',
  description: 'CiliumNetworkPolicy ingress rule allows from CIDR 0.0.0.0/0 (any IP)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      for (const ingress of r.spec.ingress ?? []) {
        const hasCatchAll =
          ingress.fromCIDR?.includes('0.0.0.0/0') ||
          ingress.fromCIDRSet?.some((s) => s.cidr === '0.0.0.0/0');
        if (hasCatchAll) {
          findings.push(makeFinding(
            nw6005,
            r,
            `CiliumNetworkPolicy "${r.metadata.name}" ingress rule allows from CIDR 0.0.0.0/0 (any IP)`,
            'Replace the 0.0.0.0/0 CIDR with specific source CIDR ranges.'
          ));
          break;
        }
      }
    }
    return findings;
  },
};

// ─── NW6006 ──────────────────────────────────────────────────────────────────
// CiliumClusterwideNetworkPolicy has no nodeSelector — applies to all nodes
const nw6006: Rule = {
  id: 'NW6006',
  severity: 'warning',
  description: 'CiliumClusterwideNetworkPolicy has no nodeSelector — applies to all nodes in the cluster',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumClusterwideNetworkPolicy(r)) continue;
      const sel = r.spec.nodeSelector;
      const isEmpty = !sel || Object.keys(sel).length === 0;
      if (isEmpty) {
        findings.push(makeFinding(
          nw6006,
          r,
          `CiliumClusterwideNetworkPolicy "${r.metadata.name}" has no nodeSelector — applies to all nodes in the cluster`,
          'Add a nodeSelector to restrict this policy to specific nodes, or confirm the cluster-wide scope is intentional.'
        ));
      }
    }
    return findings;
  },
};

// ─── NW6007 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy egress toFQDNs matchPattern: "*" — allows any DNS name
const nw6007: Rule = {
  id: 'NW6007',
  severity: 'warning',
  description: 'CiliumNetworkPolicy egress uses toFQDNs matchPattern: "*" — allows egress to any domain',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      for (const egress of r.spec.egress ?? []) {
        const hasWildcard = egress.toFQDNs?.some((f) => f.matchPattern === '*');
        if (hasWildcard) {
          findings.push(makeFinding(
            nw6007,
            r,
            `CiliumNetworkPolicy "${r.metadata.name}" egress uses toFQDNs matchPattern: "*" — allows egress to any domain`,
            'Restrict toFQDNs to specific domain names or patterns (e.g. "*.example.com").'
          ));
          break;
        }
      }
    }
    return findings;
  },
};

// ─── NW6008 ──────────────────────────────────────────────────────────────────
// CiliumNetworkPolicy uses L7 HTTP rules — informational, ensure these are intentional
const nw6008: Rule = {
  id: 'NW6008',
  severity: 'info',
  description: 'CiliumNetworkPolicy defines L7 HTTP rules — verify these application-layer rules are intentional',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isCiliumNetworkPolicy(r)) continue;
      const spec = r.spec;
      const allRules = [...(spec.ingress ?? []), ...(spec.egress ?? [])];
      const hasL7Http = allRules.some((rule) =>
        (rule as { toPorts?: Array<{ rules?: { http?: unknown[] } }> }).toPorts?.some(
          (p) => (p.rules?.http?.length ?? 0) > 0
        )
      );
      if (hasL7Http) {
        findings.push(makeFinding(
          nw6008,
          r,
          `CiliumNetworkPolicy "${r.metadata.name}" defines L7 HTTP rules — ensure application-layer enforcement is working correctly`,
          'L7 rules require Envoy proxy integration. Verify that Cilium L7 enforcement is enabled in your cluster.'
        ));
      }
    }
    return findings;
  },
};

export const nw6xxxRules: Rule[] = [
  nw6001,
  nw6002,
  nw6003,
  nw6004,
  nw6005,
  nw6006,
  nw6007,
  nw6008,
];
