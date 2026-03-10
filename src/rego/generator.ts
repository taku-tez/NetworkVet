import type { Finding } from '../types.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RegoPolicy {
  name: string;                // e.g. "nw1001_deny_wildcard_ingress"
  ruleId: string;              // e.g. "NW1001"
  description: string;
  package: string;             // e.g. "networkvet.nw1001"
  rego: string;                // full Rego policy text
  enforcementAction: 'deny' | 'warn' | 'dryrun';
}

// ─── Per-rule Rego definitions ────────────────────────────────────────────────

interface RuleRegoSpec {
  name: string;
  description: string;
  enforcementAction: RegoPolicy['enforcementAction'];
  rego: string;
}

const RULE_REGO_MAP: Record<string, RuleRegoSpec> = {
  NW1001: {
    name: 'nw1001_deny_wildcard_ingress',
    description: 'NetworkPolicy with wildcard ingress from: [{}] allows all sources',
    enforcementAction: 'deny',
    rego: `package networkvet.nw1001

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  peer := input.review.object.spec.ingress[_].from[_]
  peer == {}
  msg := sprintf("NetworkPolicy '%v' has wildcard ingress from: [{}] — allows all sources (NW1001)", [input.review.object.metadata.name])
}`,
  },

  NW1002: {
    name: 'nw1002_deny_wildcard_egress',
    description: 'NetworkPolicy with wildcard egress to: [{}] allows all destinations',
    enforcementAction: 'deny',
    rego: `package networkvet.nw1002

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  peer := input.review.object.spec.egress[_].to[_]
  peer == {}
  msg := sprintf("NetworkPolicy '%v' has wildcard egress to: [{}] — allows all destinations (NW1002)", [input.review.object.metadata.name])
}`,
  },

  NW1003: {
    name: 'nw1003_namespace_no_networkpolicy',
    description: 'Namespace created without a NetworkPolicy — all traffic is permitted',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1003

violation[{"msg": msg}] {
  input.review.object.kind == "Namespace"
  ns := input.review.object.metadata.name
  msg := sprintf("Namespace '%v' created without a NetworkPolicy — all traffic will be permitted (NW1003)", [ns])
}`,
  },

  NW2001: {
    name: 'nw2001_deny_nodeport',
    description: 'Service type NodePort exposes ports on all cluster nodes',
    enforcementAction: 'warn',
    rego: `package networkvet.nw2001

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "NodePort"
  msg := sprintf("Service '%v' uses NodePort — exposes ports on all nodes (NW2001)", [input.review.object.metadata.name])
}`,
  },

  NW2002: {
    name: 'nw2002_lb_no_local_traffic_policy',
    description: 'LoadBalancer Service without externalTrafficPolicy: Local masks source IPs',
    enforcementAction: 'warn',
    rego: `package networkvet.nw2002

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.spec.externalTrafficPolicy != "Local"
  msg := sprintf("LoadBalancer Service '%v' does not set externalTrafficPolicy: Local — source IP is masked (NW2002)", [input.review.object.metadata.name])
}`,
  },

  NW3001: {
    name: 'nw3001_ingress_no_tls',
    description: 'Ingress without TLS configured — traffic served over plain HTTP',
    enforcementAction: 'deny',
    rego: `package networkvet.nw3001

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  count(object.get(input.review.object.spec, "tls", [])) == 0
  msg := sprintf("Ingress '%v' has no TLS configured — traffic is served over plain HTTP (NW3001)", [input.review.object.metadata.name])
}`,
  },

  NW3004: {
    name: 'nw3004_ingress_wildcard_host',
    description: 'Ingress with wildcard host (*) — matches any hostname',
    enforcementAction: 'warn',
    rego: `package networkvet.nw3004

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  rule := input.review.object.spec.rules[_]
  rule.host == "*"
  msg := sprintf("Ingress '%v' uses a wildcard host '*' — matches any hostname (NW3004)", [input.review.object.metadata.name])
}`,
  },

  NW5001: {
    name: 'nw5001_authz_wildcard_principal',
    description: 'AuthorizationPolicy ALLOW rule grants access to all principals',
    enforcementAction: 'deny',
    rego: `package networkvet.nw5001

violation[{"msg": msg}] {
  input.review.object.kind == "AuthorizationPolicy"
  principal := input.review.object.spec.rules[_].from[_].source.principals[_]
  principal == "*"
  msg := sprintf("AuthorizationPolicy '%v' allows all principals (principals: [\"*\"]) (NW5001)", [input.review.object.metadata.name])
}`,
  },

  NW5005: {
    name: 'nw5005_peer_auth_permissive',
    description: 'PeerAuthentication uses PERMISSIVE mTLS mode — plaintext traffic accepted',
    enforcementAction: 'warn',
    rego: `package networkvet.nw5005

violation[{"msg": msg}] {
  input.review.object.kind == "PeerAuthentication"
  input.review.object.spec.mtls.mode == "PERMISSIVE"
  msg := sprintf("PeerAuthentication '%v' uses PERMISSIVE mTLS mode — plaintext traffic is accepted (NW5005)", [input.review.object.metadata.name])
}`,
  },

  NW5006: {
    name: 'nw5006_peer_auth_disable',
    description: 'PeerAuthentication disables mTLS — all traffic is plaintext',
    enforcementAction: 'deny',
    rego: `package networkvet.nw5006

violation[{"msg": msg}] {
  input.review.object.kind == "PeerAuthentication"
  input.review.object.spec.mtls.mode == "DISABLE"
  msg := sprintf("PeerAuthentication '%v' disables mTLS — all traffic is plaintext (NW5006)", [input.review.object.metadata.name])
}`,
  },

  NW6001: {
    name: 'nw6001_cilium_world_ingress',
    description: 'CiliumNetworkPolicy ingress allows from "world" entity',
    enforcementAction: 'deny',
    rego: `package networkvet.nw6001

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  entity := input.review.object.spec.ingress[_].fromEntities[_]
  entity == "world"
  msg := sprintf("CiliumNetworkPolicy '%v' ingress allows from entity 'world' (any external IP) (NW6001)", [input.review.object.metadata.name])
}`,
  },

  NW6005: {
    name: 'nw6005_cilium_any_cidr_ingress',
    description: 'CiliumNetworkPolicy ingress allows from CIDR 0.0.0.0/0',
    enforcementAction: 'deny',
    rego: `package networkvet.nw6005

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  cidr := input.review.object.spec.ingress[_].fromCIDR[_]
  cidr == "0.0.0.0/0"
  msg := sprintf("CiliumNetworkPolicy '%v' ingress allows from CIDR 0.0.0.0/0 (any IP) (NW6005)", [input.review.object.metadata.name])
}`,
  },
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Generate a RegoPolicy for a specific rule ID.
 * Returns null when no Rego is defined for the rule.
 */
export function generateRegoForRule(ruleId: string): RegoPolicy | null {
  const spec = RULE_REGO_MAP[ruleId.toUpperCase()];
  if (!spec) return null;
  return {
    name: spec.name,
    ruleId: ruleId.toUpperCase(),
    description: spec.description,
    package: `networkvet.${ruleId.toLowerCase()}`,
    rego: spec.rego,
    enforcementAction: spec.enforcementAction,
  };
}

/**
 * Generate Rego policies for each unique rule ID present in a findings list.
 * Rules that have no Rego definition are silently skipped.
 */
export function generateRegoForFindings(findings: Finding[]): RegoPolicy[] {
  const seenIds = new Set<string>();
  const policies: RegoPolicy[] = [];
  for (const f of findings) {
    const id = f.id.toUpperCase();
    if (seenIds.has(id)) continue;
    seenIds.add(id);
    const policy = generateRegoForRule(id);
    if (policy) policies.push(policy);
  }
  return policies;
}

/**
 * Generate a Gatekeeper ConstraintTemplate YAML that wraps the Rego policy.
 */
export function generateGatekeeperConstraint(policy: RegoPolicy): string {
  // Derive CRD kind name: e.g. "nw1001_deny_wildcard_ingress" → "NetworkvetNw1001"
  const ruleIdPart = policy.ruleId.replace(/(\d+)/, (m) => m);
  const kindName = `Networkvet${ruleIdPart.charAt(0).toUpperCase()}${ruleIdPart.slice(1).toLowerCase()}`;

  // Indent the rego body by 8 spaces for the YAML literal block scalar
  const indentedRego = policy.rego
    .split('\n')
    .map((line) => `        ${line}`)
    .join('\n');

  return `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: networkvet${policy.ruleId.toLowerCase()}
  annotations:
    description: "${policy.description}"
spec:
  crd:
    spec:
      names:
        kind: ${kindName}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
${indentedRego}
`;
}

/**
 * Generate a Conftest-compatible Rego policy file content.
 * Conftest uses `deny` and `warn` rules rather than `violation`.
 */
export function generateConftestPolicy(policy: RegoPolicy): string {
  const ruleName = policy.enforcementAction === 'deny' ? 'deny' : 'warn';
  // Transform the Rego: replace `violation[{"msg": msg}]` with the conftest rule name
  const conftestRego = policy.rego
    .replace(/violation\[{"msg":\s*msg}\]/g, `${ruleName}[msg]`);

  return `# NetworkVet ${policy.ruleId} — ${policy.description}
# Generated for use with Conftest (https://conftest.dev)
# Usage: conftest verify --policy <this-file> <manifest.yaml>
${conftestRego}
`;
}

/** All rule IDs that have Rego definitions available. */
export const REGO_SUPPORTED_RULES: string[] = Object.keys(RULE_REGO_MAP);
