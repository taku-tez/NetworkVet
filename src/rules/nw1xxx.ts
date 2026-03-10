import type {
  Rule,
  ParsedResource,
  AnalysisContext,
  Finding,
  NetworkPolicySpec,
  NetworkPolicyPeer,
} from '../types.js';
import { isNetworkPolicy, isClusterScoped } from '../types.js';

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

function isEmptyObject(obj: unknown): boolean {
  return (
    obj !== null &&
    obj !== undefined &&
    typeof obj === 'object' &&
    !Array.isArray(obj) &&
    Object.keys(obj as object).length === 0
  );
}

/** NW1001: Ingress from: [{}] — allows all sources */
export const NW1001: Rule = {
  id: 'NW1001',
  severity: 'high',
  description: 'Ingress from: [{}] allows all sources',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      if (!spec.ingress) continue;
      for (const rule of spec.ingress) {
        if (!rule.from) continue;
        const hasEmptyPeer = rule.from.some(
          (peer) => isEmptyObject(peer)
        );
        if (hasEmptyPeer) {
          findings.push(
            makeFinding(NW1001, r, 'Ingress from: [{}] allows traffic from all sources', 'Remove the empty peer object or restrict with podSelector/namespaceSelector')
          );
        }
      }
    }
    return findings;
  },
};

/** NW1002: Egress to: [{}] — allows all destinations */
export const NW1002: Rule = {
  id: 'NW1002',
  severity: 'high',
  description: 'Egress to: [{}] allows all destinations',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      if (!spec.egress) continue;
      for (const rule of spec.egress) {
        if (!rule.to) continue;
        const hasEmptyPeer = rule.to.some(
          (peer) => isEmptyObject(peer)
        );
        if (hasEmptyPeer) {
          findings.push(
            makeFinding(NW1002, r, 'Egress to: [{}] allows traffic to all destinations', 'Remove the empty peer object or restrict with podSelector/namespaceSelector')
          );
        }
      }
    }
    return findings;
  },
};

/** NW1003: Namespace has no NetworkPolicy */
export const NW1003: Rule = {
  id: 'NW1003',
  severity: 'high',
  description: 'Namespace has no NetworkPolicy (all traffic permitted)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // Resource kinds that generate actual network traffic and therefore
    // require a NetworkPolicy.  Pure RBAC, config, and storage resources
    // (Role, RoleBinding, ConfigMap, Secret, PVC, …) do not generate traffic
    // and should NOT imply that a namespace needs a NetworkPolicy.
    const WORKLOAD_KINDS = new Set([
      'Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet',
      'Job', 'CronJob', 'Service', 'Ingress',
    ]);

    const namespacesWithPolicies = new Set<string>();
    for (const r of resources) {
      if (isNetworkPolicy(r) && r.metadata.namespace) {
        namespacesWithPolicies.add(r.metadata.namespace);
      }
    }

    // Build a map: namespace → first workload resource that implies it.
    // Only workload-typed resources with an explicit namespace are counted.
    const impliedNamespaceSources = new Map<string, ParsedResource>();
    for (const r of resources) {
      if (WORKLOAD_KINDS.has(r.kind) && r.metadata.namespace &&
          !impliedNamespaceSources.has(r.metadata.namespace)) {
        impliedNamespaceSources.set(r.metadata.namespace, r);
      }
    }

    // Check Namespace resources declared in manifests — only if they also
    // have at least one workload resource (otherwise it is a pure RBAC /
    // config namespace that does not need a NetworkPolicy).
    for (const r of resources) {
      if (r.kind !== 'Namespace') continue;
      const ns = r.metadata.name;
      if (namespacesWithPolicies.has(ns)) continue;
      // Only report when this namespace actually has workloads
      if (!impliedNamespaceSources.has(ns)) continue;
      findings.push({
        id: NW1003.id,
        severity: NW1003.severity,
        kind: 'Namespace',
        name: ns,
        namespace: ns,
        file: r.file,
        line: r.line,
        message: `Namespace "${ns}" has no NetworkPolicy — all traffic is permitted`,
        detail: 'Add at least one NetworkPolicy to restrict traffic in this namespace',
      });
    }

    // Also report implied namespaces (no explicit Namespace resource) that
    // have workloads but no NetworkPolicy.
    for (const [ns, sourceResource] of impliedNamespaceSources) {
      if (namespacesWithPolicies.has(ns)) continue;
      // Already reported via an explicit Namespace resource above
      const alreadyReported = resources.some(r => r.kind === 'Namespace' && r.metadata.name === ns);
      if (alreadyReported) continue;
      if (findings.some(f => f.namespace === ns)) continue;
      findings.push({
        id: NW1003.id,
        severity: NW1003.severity,
        kind: 'Namespace',
        name: ns,
        namespace: ns,
        // Bug 7 fix: use the actual file where the workload was found
        file: sourceResource.file,
        line: sourceResource.line,
        message: `Namespace "${ns}" has no NetworkPolicy — all traffic is permitted`,
        detail: 'Add at least one NetworkPolicy to restrict traffic in this namespace',
      });
    }

    return findings;
  },
};

/** NW1004: NetworkPolicy podSelector: {} targets all pods */
export const NW1004: Rule = {
  id: 'NW1004',
  severity: 'medium',
  description: 'NetworkPolicy podSelector: {} targets all pods in namespace',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      if (!isEmptyObject(spec.podSelector)) continue;

      // Skip default-deny policies — podSelector: {} is the standard pattern
      // for a default-deny NetworkPolicy that intentionally targets all pods.
      // A policy is a default-deny when it has explicit policyTypes AND
      // either its ingress list is absent/empty (deny all ingress) OR
      // its egress list is absent/empty (deny all egress).
      const types = spec.policyTypes ?? [];
      const isDefaultDeny =
        types.length > 0 &&
        (
          (types.includes('Ingress') && (!spec.ingress || spec.ingress.length === 0)) ||
          (types.includes('Egress') && (!spec.egress || spec.egress.length === 0))
        );
      if (isDefaultDeny) continue;

      findings.push(
        makeFinding(NW1004, r, 'NetworkPolicy uses podSelector: {} which targets all pods in the namespace', 'Use a specific podSelector with matchLabels to target only intended pods')
      );
    }
    return findings;
  },
};

/** NW1005: NetworkPolicy allows traffic from all namespaces (namespaceSelector: {}) */
export const NW1005: Rule = {
  id: 'NW1005',
  severity: 'medium',
  description: 'NetworkPolicy allows traffic from all namespaces (namespaceSelector: {})',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      const ingressRules = spec.ingress ?? [];
      for (const rule of ingressRules) {
        const froms = rule.from ?? [];
        for (const peer of froms) {
          if ('namespaceSelector' in peer && isEmptyObject(peer.namespaceSelector)) {
            findings.push(
              makeFinding(NW1005, r, 'NetworkPolicy allows ingress from all namespaces (namespaceSelector: {})', 'Restrict with specific namespace labels in namespaceSelector.matchLabels')
            );
            break;
          }
        }
      }
    }
    return findings;
  },
};

/** NW1006: NetworkPolicy does not restrict egress DNS (port 53) */
export const NW1006: Rule = {
  id: 'NW1006',
  severity: 'info',
  description: 'NetworkPolicy does not restrict egress DNS (port 53)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      const policyTypes = spec.policyTypes ?? [];

      if (!policyTypes.includes('Egress')) continue;

      const egressRules = spec.egress ?? [];
      // Check if any egress rule explicitly allows port 53
      const allowsDns = egressRules.some((rule) => {
        const ports = rule.ports ?? [];
        return ports.some((p) => p.port === 53 || p.port === 'dns');
      });

      if (!allowsDns) {
        findings.push(
          makeFinding(NW1006, r, 'NetworkPolicy restricts egress but does not explicitly allow DNS (port 53)', 'Add an egress rule allowing UDP/TCP port 53 to kube-dns to prevent DNS resolution failures')
        );
      }
    }
    return findings;
  },
};

/** NW1007: NetworkPolicy allows traffic from kube-system namespace */
export const NW1007: Rule = {
  id: 'NW1007',
  severity: 'low',
  description: 'NetworkPolicy allows traffic from kube-system namespace to workload pods',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      const ingressRules = spec.ingress ?? [];

      for (const rule of ingressRules) {
        const froms = rule.from ?? [];
        for (const peer of froms) {
          const ns = peer.namespaceSelector as Record<string, unknown> | undefined;
          if (!ns) continue;
          const ml = ns.matchLabels as Record<string, string> | undefined;
          if (ml && (ml['kubernetes.io/metadata.name'] === 'kube-system' || ml.name === 'kube-system')) {
            findings.push(
              makeFinding(NW1007, r, 'NetworkPolicy allows ingress from kube-system namespace', 'kube-system access to workload pods may expose cluster internals; restrict if not required')
            );
            break;
          }
        }
      }
    }
    return findings;
  },
};

/** NW1008: NetworkPolicy with empty policyTypes */
export const NW1008: Rule = {
  id: 'NW1008',
  severity: 'info',
  description: 'NetworkPolicy with empty policyTypes',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const spec = r.spec as NetworkPolicySpec;
      if (!spec.policyTypes || spec.policyTypes.length === 0) {
        findings.push(
          makeFinding(NW1008, r, 'NetworkPolicy has empty or missing policyTypes field', 'Explicitly set policyTypes to ["Ingress"] or ["Egress"] or both for clarity and correctness')
        );
      }
    }
    return findings;
  },
};

/** NW1009: Ingress policy missing — pod has no ingress restrictions */
export const NW1009: Rule = {
  id: 'NW1009',
  severity: 'medium',
  description: 'Ingress policy missing — pod has no ingress restrictions',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    // Find workloads (Deployments, StatefulSets, etc.) with no covering NetworkPolicy that includes Ingress
    const workloadKinds = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'Pod', 'ReplicaSet']);

    for (const r of resources) {
      if (!workloadKinds.has(r.kind)) continue;
      // Skip workloads without an explicit namespace — we cannot determine which
      // namespace they will be deployed into from the manifest alone.
      const ns = r.metadata.namespace;
      if (!ns) continue;

      // Check if there's any NetworkPolicy in the same namespace with Ingress policyType
      const hasCoverage = resources.some((p) => {
        if (!isNetworkPolicy(p)) return false;
        if (p.metadata.namespace !== ns) return false;
        const spec = p.spec as NetworkPolicySpec;
        const types = spec.policyTypes ?? [];
        // If policyTypes includes Ingress OR there are ingress rules defined (implied)
        return types.includes('Ingress') || (spec.ingress !== undefined);
      });

      if (!hasCoverage) {
        findings.push(
          makeFinding(NW1009, r, `${r.kind} "${r.metadata.name}" in namespace "${ns}" has no NetworkPolicy restricting ingress`, 'Create a NetworkPolicy with policyTypes: [Ingress] to restrict inbound traffic')
        );
      }
    }
    return findings;
  },
};

/** NW1010: Egress policy missing — pod has no egress restrictions */
export const NW1010: Rule = {
  id: 'NW1010',
  severity: 'medium',
  description: 'Egress policy missing — pod has no egress restrictions',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    const workloadKinds = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'Pod', 'ReplicaSet']);

    for (const r of resources) {
      if (!workloadKinds.has(r.kind)) continue;
      // Skip workloads without an explicit namespace — we cannot determine which
      // namespace they will be deployed into from the manifest alone.
      const ns = r.metadata.namespace;
      if (!ns) continue;

      const hasCoverage = resources.some((p) => {
        if (!isNetworkPolicy(p)) return false;
        if (p.metadata.namespace !== ns) return false;
        const spec = p.spec as NetworkPolicySpec;
        const types = spec.policyTypes ?? [];
        return types.includes('Egress') || (spec.egress !== undefined);
      });

      if (!hasCoverage) {
        findings.push(
          makeFinding(NW1010, r, `${r.kind} "${r.metadata.name}" in namespace "${ns}" has no NetworkPolicy restricting egress`, 'Create a NetworkPolicy with policyTypes: [Egress] to restrict outbound traffic')
        );
      }
    }
    return findings;
  },
};

export const nw1xxxRules: Rule[] = [
  NW1001,
  NW1002,
  NW1003,
  NW1004,
  NW1005,
  NW1006,
  NW1007,
  NW1008,
  NW1009,
  NW1010,
];
