import type { ParsedResource, NetworkPolicySpec } from '../types.js';
import { isNetworkPolicy } from '../types.js';

export interface WorkloadInfo {
  name: string;
  namespace: string;
  kind: string;
  labels: Record<string, string>;
}

export interface PodReachabilityResult {
  from: WorkloadInfo;
  to: WorkloadInfo;
  allowed: boolean;
  reason: string; // "default-allow" | "policy-allow" | "policy-deny" | "no-policy"
}

// Workload kinds to extract
const WORKLOAD_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job']);

/**
 * Extract workloads (Deployment, StatefulSet, DaemonSet, Pod, Job) from resources.
 * Only includes resources that have a namespace set.
 */
export function extractWorkloads(resources: ParsedResource[]): WorkloadInfo[] {
  const workloads: WorkloadInfo[] = [];
  for (const r of resources) {
    if (!WORKLOAD_KINDS.has(r.kind)) continue;
    if (!r.metadata.namespace) continue;
    workloads.push({
      name: r.metadata.name,
      namespace: r.metadata.namespace,
      kind: r.kind,
      labels: (r.metadata.labels as Record<string, string>) ?? {},
    });
  }
  return workloads;
}

/**
 * Evaluate if a podSelector's matchLabels matches a workload's labels.
 * An empty selector (undefined or {}) matches all pods.
 */
export function matchesPodSelector(
  selector: Record<string, string> | undefined,
  labels: Record<string, string>,
): boolean {
  // undefined or empty matchLabels → matches all
  if (!selector || Object.keys(selector).length === 0) return true;

  // All selector entries must match the pod's labels
  for (const [key, value] of Object.entries(selector)) {
    if (labels[key] !== value) return false;
  }
  return true;
}

/**
 * Check whether source workload matches any of an ingress rule's from peers
 * using podSelector (same namespace only).
 */
export function matchesIngressRule(source: WorkloadInfo, policy: ParsedResource): boolean {
  if (!isNetworkPolicy(policy)) return false;

  const spec = policy.spec as NetworkPolicySpec;
  const ingressRules = spec.ingress ?? [];

  for (const rule of ingressRules) {
    const froms = rule.from;

    // No from clause → allow from any source
    if (!froms || froms.length === 0) return true;

    for (const peer of froms) {
      // podSelector only (same-namespace peer)
      if (peer.podSelector !== undefined && peer.namespaceSelector === undefined) {
        const matchLabels = (peer.podSelector as Record<string, unknown>).matchLabels as
          | Record<string, string>
          | undefined;
        if (matchesPodSelector(matchLabels, source.labels)) {
          return true;
        }
      }

      // Empty peer {} → allow all
      if (
        peer.podSelector === undefined &&
        peer.namespaceSelector === undefined &&
        peer.ipBlock === undefined
      ) {
        return true;
      }

      // namespaceSelector only or combined podSelector+namespaceSelector
      // For pod-level analysis within same namespace, namespaceSelector: {} matches same ns
      if (peer.namespaceSelector !== undefined) {
        const nsSel = peer.namespaceSelector as Record<string, unknown>;
        const nsMatchLabels = nsSel.matchLabels as Record<string, string> | undefined;

        // namespaceSelector: {} → allow all namespaces (including same)
        if (!nsMatchLabels || Object.keys(nsMatchLabels).length === 0) {
          // If there's also a podSelector, check it
          if (peer.podSelector !== undefined) {
            const psSel = (peer.podSelector as Record<string, unknown>).matchLabels as
              | Record<string, string>
              | undefined;
            if (matchesPodSelector(psSel, source.labels)) return true;
          } else {
            return true;
          }
        } else {
          // Specific namespaceSelector — check if it matches the source namespace
          const nsName =
            nsMatchLabels['kubernetes.io/metadata.name'] ?? nsMatchLabels['name'];
          if (nsName !== undefined && nsName !== source.namespace) continue;

          // namespace matches — now check podSelector if present
          if (peer.podSelector !== undefined) {
            const psSel = (peer.podSelector as Record<string, unknown>).matchLabels as
              | Record<string, string>
              | undefined;
            if (matchesPodSelector(psSel, source.labels)) return true;
          } else {
            return true;
          }
        }
      }
    }
  }

  return false;
}

/**
 * Compute pod-to-pod reachability matrix.
 *
 * For each (source, destination) workload pair in the same namespace:
 * - If no NetworkPolicies select the destination pod: reason = "no-policy" (default allow)
 * - If a policy selects the destination with no ingress rules: reason = "policy-deny" (deny all)
 * - If a policy selects the destination with ingress rules that match source: reason = "policy-allow"
 * - If a policy selects the destination with ingress rules that don't match source: reason = "policy-deny"
 *
 * Cross-namespace pairs are included only if there are policies with namespaceSelector rules.
 */
export function computePodReachability(resources: ParsedResource[]): PodReachabilityResult[] {
  const workloads = extractWorkloads(resources);

  if (workloads.length === 0) return [];

  // Group NetworkPolicies by namespace
  const policiesByNs = new Map<string, Array<ParsedResource & { spec: NetworkPolicySpec }>>();
  for (const r of resources) {
    if (!isNetworkPolicy(r)) continue;
    if (!r.metadata.namespace) continue;
    const ns = r.metadata.namespace;
    if (!policiesByNs.has(ns)) policiesByNs.set(ns, []);
    policiesByNs.get(ns)!.push(r as ParsedResource & { spec: NetworkPolicySpec });
  }

  // Determine if any policies have cross-namespace (namespaceSelector) rules
  const hasCrossNsRules = [...policiesByNs.values()].some((policies) =>
    policies.some((p) => {
      const spec = p.spec as NetworkPolicySpec;
      const ingress = spec.ingress ?? [];
      return ingress.some((rule) =>
        (rule.from ?? []).some((peer) => peer.namespaceSelector !== undefined),
      );
    }),
  );

  const results: PodReachabilityResult[] = [];

  for (const dst of workloads) {
    const dstNsPolicies = policiesByNs.get(dst.namespace) ?? [];

    // Find policies that select this destination workload (via podSelector)
    const selectingPolicies = dstNsPolicies.filter((p) => {
      const spec = p.spec as NetworkPolicySpec;
      const podSel = spec.podSelector as Record<string, unknown>;
      const matchLabels = podSel?.matchLabels as Record<string, string> | undefined;
      // podSelector: {} matches all pods
      if (!podSel || Object.keys(podSel).length === 0) return true;
      return matchesPodSelector(matchLabels, dst.labels);
    });

    // Filter to only ingress-governing policies
    const ingressPolicies = selectingPolicies.filter((p) => {
      const spec = p.spec as NetworkPolicySpec;
      const types = spec.policyTypes ?? [];
      return types.includes('Ingress') || spec.ingress !== undefined;
    });

    for (const src of workloads) {
      // Skip self
      if (src.name === dst.name && src.namespace === dst.namespace) continue;

      const sameNamespace = src.namespace === dst.namespace;

      // For cross-namespace pairs, only include if cross-ns rules exist
      if (!sameNamespace && !hasCrossNsRules) continue;

      if (ingressPolicies.length === 0) {
        // No policy governs ingress to this workload
        results.push({
          from: src,
          to: dst,
          allowed: true,
          reason: 'no-policy',
        });
        continue;
      }

      // Check each ingress policy
      let allowed = false;
      for (const policy of ingressPolicies) {
        const spec = policy.spec as NetworkPolicySpec;
        const ingressRules = spec.ingress ?? [];

        // Policy with policyTypes: [Ingress] but no ingress rules → deny all
        if (ingressRules.length === 0) continue;

        // For same-namespace: check using matchesIngressRule
        if (sameNamespace) {
          if (matchesIngressRule(src, policy)) {
            allowed = true;
            break;
          }
        } else {
          // Cross-namespace: check namespaceSelector rules
          for (const rule of ingressRules) {
            const froms = rule.from;
            if (!froms || froms.length === 0) {
              allowed = true;
              break;
            }
            for (const peer of froms) {
              if (peer.namespaceSelector !== undefined) {
                const nsSel = peer.namespaceSelector as Record<string, unknown>;
                const nsMatchLabels = nsSel.matchLabels as Record<string, string> | undefined;
                if (!nsMatchLabels || Object.keys(nsMatchLabels).length === 0) {
                  // namespaceSelector: {} → allow all
                  allowed = true;
                  break;
                } else {
                  const nsName =
                    nsMatchLabels['kubernetes.io/metadata.name'] ?? nsMatchLabels['name'];
                  if (nsName === src.namespace) {
                    // Check podSelector if present
                    if (peer.podSelector !== undefined) {
                      const psSel = (peer.podSelector as Record<string, unknown>).matchLabels as
                        | Record<string, string>
                        | undefined;
                      if (matchesPodSelector(psSel, src.labels)) {
                        allowed = true;
                        break;
                      }
                    } else {
                      allowed = true;
                      break;
                    }
                  }
                }
              }
            }
            if (allowed) break;
          }
          if (allowed) break;
        }
      }

      results.push({
        from: src,
        to: dst,
        allowed,
        reason: allowed ? 'policy-allow' : 'policy-deny',
      });
    }
  }

  return results;
}
