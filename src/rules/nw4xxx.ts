import type {
  Rule,
  ParsedResource,
  AnalysisContext,
  Finding,
  NetworkPolicySpec,
} from '../types.js';
import { isNetworkPolicy } from '../types.js';

/** CNI plugins known to NOT enforce NetworkPolicy natively */
const NON_ENFORCING_CNIS = new Set(['flannel', 'kindnet']);

function makeNamespaceFinding(
  rule: Pick<Rule, 'id' | 'severity'>,
  namespace: string,
  file: string,
  line: number,
  message: string,
  detail?: string
): Finding {
  return {
    id: rule.id,
    severity: rule.severity,
    kind: 'Namespace',
    name: namespace,
    namespace,
    file,
    line,
    message,
    detail,
  };
}

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

/** NW4001: No default-deny NetworkPolicy in namespace */
export const NW4001: Rule = {
  id: 'NW4001',
  severity: 'warning',
  description: 'No default-deny NetworkPolicy in namespace',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // Collect all namespaces that have at least one NetworkPolicy.
    // Skip NetworkPolicies without an explicit namespace — they cannot be
    // reliably associated with a namespace from the manifest alone.
    const namespacePolicies = new Map<string, ParsedResource[]>();
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const ns = r.metadata.namespace;
      if (!ns) continue;
      if (!namespacePolicies.has(ns)) namespacePolicies.set(ns, []);
      namespacePolicies.get(ns)!.push(r);
    }

    for (const [ns, policies] of namespacePolicies) {
      // A default-deny policy: podSelector: {}, no ingress/egress rules, policyTypes covers both
      const hasDefaultDeny = policies.some((p) => {
        const spec = p.spec as NetworkPolicySpec;
        const types = spec.policyTypes ?? [];
        const hasEmptySelector = isEmptyObject(spec.podSelector);
        const hasIngressDeny =
          types.includes('Ingress') && (!spec.ingress || spec.ingress.length === 0);
        const hasEgressDeny =
          types.includes('Egress') && (!spec.egress || spec.egress.length === 0);
        return hasEmptySelector && (hasIngressDeny || hasEgressDeny);
      });

      if (!hasDefaultDeny) {
        const refPolicy = policies[0];
        findings.push(
          makeNamespaceFinding(
            NW4001,
            ns,
            refPolicy.file,
            refPolicy.line,
            `Namespace "${ns}" has no default-deny NetworkPolicy`,
            'Add a NetworkPolicy with podSelector: {} and empty ingress/egress to deny all traffic by default'
          )
        );
      }
    }

    return findings;
  },
};

/** NW4002: CNI does not support NetworkPolicy enforcement */
export const NW4002: Rule = {
  id: 'NW4002',
  severity: 'info',
  description: 'CNI plugin may not support NetworkPolicy enforcement',
  check(resources: ParsedResource[], ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // --- Cluster mode: use the CNI detected from the live cluster ---
    if (ctx.mode === 'cluster') {
      const cni = ctx.cni;
      // null = checked but unknown; undefined = not checked (skip)
      if (cni === undefined || cni === null) return [];
      if (NON_ENFORCING_CNIS.has(cni)) {
        findings.push({
          id: NW4002.id,
          severity: NW4002.severity,
          kind: 'Namespace',
          name: 'kube-system',
          namespace: 'kube-system',
          file: 'cluster:kube-system/CNI/detected',
          line: 0,
          message: `Detected CNI "${cni}" which does not enforce NetworkPolicies natively`,
          detail:
            'Switch to a CNI that supports NetworkPolicy (Calico, Cilium, WeaveNet, etc.) to enforce network isolation',
        });
      }
      return findings;
    }

    // --- File mode: detect CNI from DaemonSet/ConfigMap resources in manifests ---
    const cniIndicators = resources.filter(
      (r) =>
        (r.kind === 'ConfigMap' || r.kind === 'DaemonSet') &&
        (r.metadata.namespace === 'kube-system' || r.metadata.namespace === 'kube-flannel')
    );

    for (const r of cniIndicators) {
      if (
        r.metadata.name.toLowerCase().includes('flannel') ||
        r.metadata.namespace === 'kube-flannel'
      ) {
        findings.push(
          makeFinding(
            NW4002,
            r,
            `Detected Flannel CNI ("${r.metadata.name}") which does not enforce NetworkPolicies`,
            'Switch to a CNI that supports NetworkPolicy (Calico, Cilium, WeaveNet, etc.) to enforce network isolation'
          )
        );
      }
    }

    return findings;
  },
};

/** NW4003: Cross-namespace traffic not restricted */
export const NW4003: Rule = {
  id: 'NW4003',
  severity: 'warning',
  description: 'Cross-namespace traffic not restricted',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // Collect namespaces with NetworkPolicies.
    // Skip NetworkPolicies without an explicit namespace.
    const namespacesWithPolicies = new Map<string, ParsedResource[]>();
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const ns = r.metadata.namespace;
      if (!ns) continue;
      if (!namespacesWithPolicies.has(ns)) namespacesWithPolicies.set(ns, []);
      namespacesWithPolicies.get(ns)!.push(r);
    }

    for (const [ns, policies] of namespacesWithPolicies) {
      // Only check namespaces that actually have ingress rules (a deny-all with no ingress rules
      // already blocks everything, so no cross-namespace restriction is needed).
      const policiesWithIngressRules = policies.filter((p) => {
        const spec = p.spec as NetworkPolicySpec;
        return spec.ingress && spec.ingress.length > 0;
      });

      if (policiesWithIngressRules.length === 0) continue;

      // Check if any policy with ingress rules restricts ingress from other namespaces
      const hasNamespaceRestriction = policiesWithIngressRules.some((p) => {
        const spec = p.spec as NetworkPolicySpec;
        const ingressRules = spec.ingress ?? [];
        return ingressRules.some((rule) => {
          const froms = rule.from ?? [];
          return froms.some(
            (peer) =>
              peer.namespaceSelector &&
              !isEmptyObject(peer.namespaceSelector)
          );
        });
      });

      if (!hasNamespaceRestriction) {
        const refPolicy = policies[0];
        findings.push(
          makeNamespaceFinding(
            NW4003,
            ns,
            refPolicy.file,
            refPolicy.line,
            `Namespace "${ns}" has NetworkPolicies but none restrict cross-namespace ingress traffic`,
            'Add namespaceSelector with specific labels to ingress rules to control which namespaces can send traffic'
          )
        );
      }
    }

    return findings;
  },
};

/** NW4004: kube-dns accessible from all namespaces */
export const NW4004: Rule = {
  id: 'NW4004',
  severity: 'info',
  description: 'kube-dns accessible from all namespaces without restriction',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // Look for NetworkPolicies in kube-system that restrict DNS access
    const kubeDnsPolicies = resources.filter(
      (r) =>
        isNetworkPolicy(r) &&
        r.metadata.namespace === 'kube-system' &&
        (r.metadata.name.includes('dns') || r.metadata.name.includes('coredns'))
    );

    if (kubeDnsPolicies.length > 0) return findings; // already restricted

    // Only fire when kube-system is explicitly present as a namespace-scoped
    // resource (Pod, Deployment, DaemonSet, Service, ConfigMap, …) with an
    // explicit namespace field.  ValidatingWebhookConfiguration and other
    // cluster-scoped resources whose spec refers to kube-system webhooks do
    // NOT count — they don't mean kube-system pods are present in the
    // manifest set being analysed.
    const WORKLOAD_LIKE = new Set([
      'Pod', 'Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet', 'Job',
      'CronJob', 'Service', 'ConfigMap', 'Secret', 'NetworkPolicy',
    ]);

    const hasKubeSystemWorkload = resources.some(
      (r) => WORKLOAD_LIKE.has(r.kind) && r.metadata.namespace === 'kube-system'
    );

    const kubeSysNamespace = resources.find(
      (r) => r.kind === 'Namespace' && r.metadata.name === 'kube-system'
    );

    if (!hasKubeSystemWorkload && !kubeSysNamespace) return findings;

    const ref =
      kubeSysNamespace ??
      resources.find((r) => WORKLOAD_LIKE.has(r.kind) && r.metadata.namespace === 'kube-system') ??
      resources[0];

    if (ref) {
      findings.push({
        id: NW4004.id,
        severity: NW4004.severity,
        kind: 'Namespace',
        name: 'kube-system',
        namespace: 'kube-system',
        file: ref.file,
        line: ref.line,
        message:
          'kube-dns in kube-system has no NetworkPolicy restricting access — all namespaces can reach it',
        detail:
          'Add a NetworkPolicy in kube-system to restrict DNS access to only allowed namespaces/pods',
      });
    }

    return findings;
  },
};

const METADATA_API_IP = '169.254.169.254';

/** NW4005: MetadataAPI (169.254.169.254) not blocked in egress policies */
export const NW4005: Rule = {
  id: 'NW4005',
  severity: 'warning',
  description: 'Cloud metadata API (169.254.169.254) not blocked in egress NetworkPolicies',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // Get all namespaces that have egress NetworkPolicies.
    // Skip NetworkPolicies without an explicit namespace.
    const nsWithEgressPolicies = new Map<string, ParsedResource[]>();
    for (const r of resources) {
      if (!isNetworkPolicy(r)) continue;
      const ns = r.metadata.namespace;
      if (!ns) continue;
      const spec = r.spec as NetworkPolicySpec;
      const types = spec.policyTypes ?? [];
      if (!types.includes('Egress') && !spec.egress) continue;
      if (!nsWithEgressPolicies.has(ns)) nsWithEgressPolicies.set(ns, []);
      nsWithEgressPolicies.get(ns)!.push(r);
    }

    for (const [ns, policies] of nsWithEgressPolicies) {
      // Check if any egress rule explicitly blocks 169.254.169.254
      const blocksMetadata = policies.some((p) => {
        const spec = p.spec as NetworkPolicySpec;
        const egressRules = spec.egress ?? [];
        return egressRules.some((rule) => {
          const tos = rule.to ?? [];
          return tos.some((peer) => {
            const ipBlock = peer.ipBlock;
            if (!ipBlock) return false;
            // Check if CIDR covers metadata IP and it's in except list
            if (ipBlock.cidr === '0.0.0.0/0' || ipBlock.cidr === METADATA_API_IP + '/32') {
              const excepts = ipBlock.except ?? [];
              return excepts.includes(METADATA_API_IP + '/32') ||
                ipBlock.cidr === METADATA_API_IP + '/32';
            }
            return false;
          });
        });
      });

      if (!blocksMetadata) {
        const refPolicy = policies[0];
        findings.push(
          makeNamespaceFinding(
            NW4005,
            ns,
            refPolicy.file,
            refPolicy.line,
            `Namespace "${ns}" has egress policies but does not block the cloud metadata API (${METADATA_API_IP})`,
            `Add an egress rule that excludes ${METADATA_API_IP}/32 from allowed destinations to prevent SSRF attacks on cloud metadata`
          )
        );
      }
    }

    return findings;
  },
};

export const nw4xxxRules: Rule[] = [NW4001, NW4002, NW4003, NW4004, NW4005];
