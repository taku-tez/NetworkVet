import type { ParsedResource, NetworkPolicySpec, NetworkPolicyPeer } from '../types.js';
import { isNetworkPolicy } from '../types.js';

export type ReachabilityStatus = 'allowed' | 'denied' | 'allowed (no policy)';
export type ReachabilityRisk = 'none' | 'low' | 'medium' | 'high';

export interface ReachabilityEntry {
  from: string;
  to: string;
  status: ReachabilityStatus;
  risk: ReachabilityRisk;
  reason: string;
}

export interface ReachabilityResult {
  matrix: Record<string, Record<string, ReachabilityEntry>>;
  unprotectedNamespaces: string[];
  openPaths: ReachabilityEntry[];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function isEmptyObject(obj: unknown): boolean {
  return (
    obj !== null &&
    obj !== undefined &&
    typeof obj === 'object' &&
    !Array.isArray(obj) &&
    Object.keys(obj as object).length === 0
  );
}

/** Collect every distinct namespace referenced across all resources. */
function collectNamespaces(resources: ParsedResource[]): string[] {
  const ns = new Set<string>();
  for (const r of resources) {
    if (r.kind === 'Namespace') {
      ns.add(r.metadata.name);
    } else if (r.metadata.namespace) {
      ns.add(r.metadata.namespace);
    }
  }
  return [...ns].sort();
}

/** Return NetworkPolicies scoped to a namespace. */
function policiesForNamespace(resources: ParsedResource[], ns: string): Array<ParsedResource & { spec: NetworkPolicySpec }> {
  return resources.filter((r): r is ParsedResource & { spec: NetworkPolicySpec } => {
    return isNetworkPolicy(r) && r.metadata.namespace === ns;
  });
}

/**
 * Determine whether a given namespace has at least one NetworkPolicy that
 * lists Ingress in policyTypes (explicitly or implied by having ingress rules).
 */
function hasIngressPolicy(policies: Array<ParsedResource & { spec: NetworkPolicySpec }>): boolean {
  return policies.some((p) => {
    const spec = p.spec;
    const types = spec.policyTypes ?? [];
    return types.includes('Ingress') || spec.ingress !== undefined;
  });
}

/**
 * Determine whether a given namespace has at least one NetworkPolicy that
 * lists Egress in policyTypes (explicitly or implied by having egress rules).
 */
function hasEgressPolicy(policies: Array<ParsedResource & { spec: NetworkPolicySpec }>): boolean {
  return policies.some((p) => {
    const spec = p.spec;
    const types = spec.policyTypes ?? [];
    return types.includes('Egress') || spec.egress !== undefined;
  });
}

/**
 * Check whether a peer selector matches a given source namespace.
 *
 * Returns 'empty' if the peer is `{}` (allow all), 'match' if the
 * namespaceSelector matches srcNs, 'no-match' otherwise.
 */
function peerMatchesNamespace(peer: NetworkPolicyPeer, srcNs: string): 'empty' | 'match' | 'no-match' {
  // An empty peer object `{}` means "allow all"
  if (isEmptyObject(peer)) return 'empty';

  const nsSel = peer.namespaceSelector;
  if (nsSel === undefined) {
    // Only a podSelector — treats same-namespace pods; does not match cross-ns
    return 'no-match';
  }

  // namespaceSelector: {} means all namespaces
  if (isEmptyObject(nsSel)) return 'empty';

  // namespaceSelector with matchLabels — check if srcNs name matches
  const ml = (nsSel as Record<string, unknown>).matchLabels as Record<string, string> | undefined;
  if (ml) {
    // We check common patterns used to identify namespaces by name
    const nameValue = ml['kubernetes.io/metadata.name'] ?? ml['name'];
    if (nameValue !== undefined) {
      return nameValue === srcNs ? 'match' : 'no-match';
    }
    // Other label selectors — conservatively treat as a potential match
    return 'match';
  }

  // matchExpressions or other advanced selectors — conservatively allow
  return 'match';
}

/**
 * Evaluate reachability from srcNs → dstNs given the ingress policies on dstNs.
 */
function evaluateIngressReachability(
  srcNs: string,
  dstNs: string,
  dstPolicies: Array<ParsedResource & { spec: NetworkPolicySpec }>,
  srcHasEgress: boolean,
): ReachabilityEntry {
  const self = srcNs === dstNs;

  // No ingress policy at all → no restriction
  if (!hasIngressPolicy(dstPolicies)) {
    return {
      from: srcNs,
      to: dstNs,
      status: 'allowed (no policy)',
      risk: 'medium',
      reason: `Namespace "${dstNs}" has no ingress NetworkPolicy — all traffic is permitted`,
    };
  }

  // Collect only policies that actually govern Ingress
  const ingressPolicies = dstPolicies.filter((p) => {
    const spec = p.spec;
    const types = spec.policyTypes ?? [];
    return types.includes('Ingress') || spec.ingress !== undefined;
  });

  // Check each policy's ingress rules
  for (const policy of ingressPolicies) {
    const spec = policy.spec;
    const ingressRules = spec.ingress ?? [];

    // Policy has Ingress type but empty ingress rules → default deny
    if (ingressRules.length === 0) continue;

    for (const rule of ingressRules) {
      const froms = rule.from;

      // No from clause → allow from any source
      if (!froms || froms.length === 0) {
        return {
          from: srcNs,
          to: dstNs,
          status: 'allowed',
          risk: 'high',
          reason: `NetworkPolicy "${policy.metadata.name}" in "${dstNs}" has an ingress rule with no "from" clause (allows all sources)`,
        };
      }

      for (const peer of froms) {
        const match = peerMatchesNamespace(peer, srcNs);
        if (match === 'empty') {
          return {
            from: srcNs,
            to: dstNs,
            status: 'allowed',
            risk: 'high',
            reason: `NetworkPolicy "${policy.metadata.name}" in "${dstNs}" allows ingress from all sources (from: [{}])`,
          };
        }
        if (match === 'match') {
          const risk: ReachabilityRisk = srcHasEgress ? 'low' : 'low';
          return {
            from: srcNs,
            to: dstNs,
            status: 'allowed',
            risk,
            reason: `NetworkPolicy "${policy.metadata.name}" in "${dstNs}" explicitly allows ingress from namespace "${srcNs}"`,
          };
        }
      }
    }
  }

  // No matching allow rule found
  return {
    from: srcNs,
    to: dstNs,
    status: 'denied',
    risk: 'none',
    reason: self
      ? `Namespace "${dstNs}" has ingress policies but no rule matches same-namespace traffic`
      : `Namespace "${dstNs}" has ingress policies but none allow traffic from namespace "${srcNs}"`,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute cross-namespace reachability for all namespaces found in resources.
 */
export function computeReachability(resources: ParsedResource[]): ReachabilityResult {
  const namespaces = collectNamespaces(resources);

  // Build per-namespace policy index
  const policyMap = new Map<string, Array<ParsedResource & { spec: NetworkPolicySpec }>>();
  for (const ns of namespaces) {
    policyMap.set(ns, policiesForNamespace(resources, ns));
  }

  // Identify namespaces with no egress policy (they can send anywhere)
  const nsHasEgress = new Map<string, boolean>();
  for (const ns of namespaces) {
    nsHasEgress.set(ns, hasEgressPolicy(policyMap.get(ns)!));
  }

  // Unprotected namespaces = those with no ingress NetworkPolicy at all
  const unprotectedNamespaces = namespaces.filter(
    (ns) => !hasIngressPolicy(policyMap.get(ns)!),
  );

  // Build matrix
  const matrix: Record<string, Record<string, ReachabilityEntry>> = {};
  const openPaths: ReachabilityEntry[] = [];

  for (const src of namespaces) {
    matrix[src] = {};
    for (const dst of namespaces) {
      const dstPolicies = policyMap.get(dst)!;
      const srcHasEgress = nsHasEgress.get(src) ?? false;
      const entry = evaluateIngressReachability(src, dst, dstPolicies, srcHasEgress);
      matrix[src][dst] = entry;

      if (entry.status !== 'denied' && entry.risk !== 'none') {
        openPaths.push(entry);
      }
    }
  }

  return { matrix, unprotectedNamespaces, openPaths };
}
