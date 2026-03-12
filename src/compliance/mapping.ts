/**
 * Compliance framework mappings for NetworkVet rules.
 * Maps each rule ID to zero or more compliance references.
 *
 * Frameworks:
 *   CIS  — CIS Kubernetes Benchmark v1.8.0
 *   NSA  — NSA/CISA Kubernetes Hardening Guide v1.2 (2022)
 */

export interface ComplianceRef {
  framework: 'CIS' | 'NSA';
  id: string;       // e.g. "5.3.2" or "§3.2"
  title: string;    // short human-readable title
}

/** Map of rule ID → compliance references */
export const COMPLIANCE_MAP: Record<string, ComplianceRef[]> = {
  // ── NW1xxx: NetworkPolicy ─────────────────────────────────────────────────
  NW1001: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1002: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1003: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.1',  title: 'Use namespaces to isolate sensitive workloads' },
  ],
  NW1004: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1005: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1006: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1007: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1008: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1009: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW1010: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],

  // ── NW2xxx: Service Design ────────────────────────────────────────────────
  NW2001: [
    { framework: 'CIS', id: '5.4.2', title: 'Ensure that Service Account Tokens are not automatically mounted' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW2002: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW2003: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW2004: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW2006: [
    { framework: 'CIS', id: '5.4.1', title: 'Prefer using secrets as files over secrets as env variables' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW2008: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],

  // ── NW3xxx: Ingress Security ──────────────────────────────────────────────
  NW3001: [
    { framework: 'CIS', id: '5.4.1', title: 'Use TLS to protect data in transit' },
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW3002: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW3003: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW3004: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW3006: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW3007: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],

  // ── NW4xxx: Cluster-level ─────────────────────────────────────────────────
  NW4001: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.1',  title: 'Use namespaces to isolate sensitive workloads' },
  ],
  NW4002: [
    { framework: 'CIS', id: '5.3.1', title: 'Ensure that the CNI in use supports Network Policies' },
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW4003: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.1',  title: 'Use namespaces to isolate sensitive workloads' },
  ],
  NW4004: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW4005: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
    { framework: 'NSA', id: '§4.1',  title: 'Protect sensitive cloud credentials and metadata' },
  ],

  // ── NW5xxx: Istio / Service Mesh ──────────────────────────────────────────
  NW5001: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW5002: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW5003: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW5004: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW5005: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW5006: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],

  // ── NW6xxx: Cilium NetworkPolicy ──────────────────────────────────────────
  NW6001: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW6002: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW6003: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
  ],
  NW6005: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],

  // ── NW7xxx: Cloud Provider ────────────────────────────────────────────────
  NW7001: [
    { framework: 'CIS', id: '5.5.1', title: 'Configure Image Provenance using ImagePolicyWebhook' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW7002: [
    { framework: 'CIS', id: '5.2.1', title: 'Ensure that admission control plugin AlwaysPullImages is set' },
    { framework: 'NSA', id: '§6.1',  title: 'Enable audit logging' },
  ],
  NW7003: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW7004: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW7005: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW7006: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW7007: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW7009: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW7010: [
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW7012: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW7013: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW7015: [
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],

  // ── NW8xxx: Gateway API ───────────────────────────────────────────────────
  NW8001: [
    { framework: 'CIS', id: '5.4.1', title: 'Use TLS to protect data in transit' },
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
  ],
  NW8002: [
    { framework: 'CIS', id: '5.3.2', title: 'Ensure all Namespaces have Network Policies defined' },
    { framework: 'NSA', id: '§3.1',  title: 'Use namespaces to isolate sensitive workloads' },
  ],
  NW8003: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
  NW8004: [
    { framework: 'CIS', id: '5.4.1', title: 'Use TLS to protect data in transit' },
    { framework: 'NSA', id: '§3.4',  title: 'Encrypt traffic between pods using TLS or mTLS' },
    { framework: 'NSA', id: '§4.1',  title: 'Protect sensitive cloud credentials and metadata' },
  ],
  NW8005: [
    { framework: 'NSA', id: '§3.2',  title: 'Use NetworkPolicies to restrict pod-to-pod traffic' },
    { framework: 'NSA', id: '§3.3',  title: 'Limit access to cluster services' },
  ],
};

/**
 * Get compliance references for a given rule ID.
 * Returns empty array when no mapping is defined.
 */
export function getComplianceRefs(ruleId: string): ComplianceRef[] {
  return COMPLIANCE_MAP[ruleId.toUpperCase()] ?? [];
}

/**
 * Get all rule IDs that map to a specific framework.
 */
export function getRulesForFramework(framework: 'CIS' | 'NSA'): string[] {
  return Object.entries(COMPLIANCE_MAP)
    .filter(([, refs]) => refs.some((r) => r.framework === framework))
    .map(([id]) => id);
}
