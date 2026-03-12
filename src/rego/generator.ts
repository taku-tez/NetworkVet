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

  NW1004: {
    name: 'nw1004_podselect_all_pods',
    description: 'NetworkPolicy podSelector: {} targets all pods in namespace (not a default-deny)',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1004

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  object.get(input.review.object.spec, "podSelector", {}) == {}
  types := object.get(input.review.object.spec, "policyTypes", [])
  # Skip default-deny (empty ingress/egress rules with explicit policyTypes)
  not is_default_deny(input.review.object.spec, types)
  msg := sprintf("NetworkPolicy '%v' uses podSelector: {} which targets all pods — use specific matchLabels (NW1004)", [input.review.object.metadata.name])
}

is_default_deny(spec, types) {
  types[_] == "Ingress"
  count(object.get(spec, "ingress", [])) == 0
}

is_default_deny(spec, types) {
  types[_] == "Egress"
  count(object.get(spec, "egress", [])) == 0
}`,
  },

  NW1005: {
    name: 'nw1005_namespace_selector_wildcard',
    description: 'NetworkPolicy allows ingress from all namespaces (namespaceSelector: {})',
    enforcementAction: 'deny',
    rego: `package networkvet.nw1005

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  peer := input.review.object.spec.ingress[_].from[_]
  object.get(peer, "namespaceSelector", "absent") == {}
  msg := sprintf("NetworkPolicy '%v' allows ingress from all namespaces (namespaceSelector: {}) — restrict with specific labels (NW1005)", [input.review.object.metadata.name])
}`,
  },

  NW2003: {
    name: 'nw2003_lb_no_source_ranges',
    description: 'LoadBalancer Service without source IP restriction (loadBalancerSourceRanges)',
    enforcementAction: 'warn',
    rego: `package networkvet.nw2003

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  count(object.get(input.review.object.spec, "loadBalancerSourceRanges", [])) == 0
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/load-balancer-source-ranges"]
  msg := sprintf("LoadBalancer Service '%v' has no loadBalancerSourceRanges — all IPs can access this service (NW2003)", [input.review.object.metadata.name])
}`,
  },

  NW2004: {
    name: 'nw2004_service_ssh_port',
    description: 'Service exposes port 22 (SSH) — potential security risk',
    enforcementAction: 'warn',
    rego: `package networkvet.nw2004

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  port := input.review.object.spec.ports[_]
  port.port == 22
  msg := sprintf("Service '%v' exposes port 22 (SSH) — avoid exposing SSH via Kubernetes Services (NW2004)", [input.review.object.metadata.name])
}`,
  },

  NW2006: {
    name: 'nw2006_external_ips',
    description: 'Service externalIPs field set — potential MITM risk',
    enforcementAction: 'deny',
    rego: `package networkvet.nw2006

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  count(object.get(input.review.object.spec, "externalIPs", [])) > 0
  msg := sprintf("Service '%v' uses externalIPs — this can be exploited for MITM attacks (NW2006)", [input.review.object.metadata.name])
}`,
  },

  NW2008: {
    name: 'nw2008_externalname_internal_dns',
    description: 'Service of type ExternalName pointing to internal cluster DNS — bypasses NetworkPolicies',
    enforcementAction: 'deny',
    rego: `package networkvet.nw2008

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "ExternalName"
  externalName := input.review.object.spec.externalName
  endswith(externalName, ".cluster.local")
  msg := sprintf("ExternalName Service '%v' points to internal DNS '%v' — bypasses NetworkPolicies (NW2008)", [input.review.object.metadata.name, externalName])
}

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "ExternalName"
  externalName := input.review.object.spec.externalName
  endswith(externalName, ".svc")
  msg := sprintf("ExternalName Service '%v' points to internal DNS '%v' — bypasses NetworkPolicies (NW2008)", [input.review.object.metadata.name, externalName])
}`,
  },

  NW3002: {
    name: 'nw3002_ingress_no_hsts',
    description: 'Ingress has TLS but no HSTS annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw3002

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  count(object.get(input.review.object.spec, "tls", [])) > 0
  not input.review.object.metadata.annotations["nginx.ingress.kubernetes.io/hsts"]
  not input.review.object.metadata.annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
  not input.review.object.metadata.annotations["haproxy.router.openshift.io/hsts_header"]
  msg := sprintf("Ingress '%v' has TLS but no HSTS annotation — add nginx.ingress.kubernetes.io/hsts: \\"true\\" (NW3002)", [input.review.object.metadata.name])
}`,
  },

  NW3003: {
    name: 'nw3003_ingress_no_ssl_redirect',
    description: 'Ingress with TLS but no HTTP to HTTPS redirect annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw3003

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  count(object.get(input.review.object.spec, "tls", [])) > 0
  not input.review.object.metadata.annotations["nginx.ingress.kubernetes.io/ssl-redirect"]
  not input.review.object.metadata.annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"]
  not input.review.object.metadata.annotations["kubernetes.io/ingress.allow-http"]
  msg := sprintf("Ingress '%v' has TLS but no HTTP-to-HTTPS redirect annotation — add nginx.ingress.kubernetes.io/ssl-redirect: \\"true\\" (NW3003)", [input.review.object.metadata.name])
}`,
  },

  NW3006: {
    name: 'nw3006_ingress_admin_paths',
    description: 'Ingress exposes admin or internal paths publicly',
    enforcementAction: 'warn',
    rego: `package networkvet.nw3006

sensitive_prefixes := {"/admin", "/_", "/internal", "/metrics", "/debug", "/actuator", "/management"}

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  path := input.review.object.spec.rules[_].http.paths[_].path
  prefix := sensitive_prefixes[_]
  startswith(lower(path), prefix)
  msg := sprintf("Ingress '%v' exposes sensitive path '%v' publicly — restrict with IP allowlisting (NW3006)", [input.review.object.metadata.name, path])
}`,
  },

  NW4001: {
    name: 'nw4001_no_default_deny',
    description: 'Namespace has NetworkPolicies but no default-deny policy',
    enforcementAction: 'warn',
    rego: `package networkvet.nw4001

# This policy fires on Namespace resources that have no default-deny NetworkPolicy.
# Note: admission webhooks evaluate single resources, so this is a best-effort check.
violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  object.get(input.review.object.spec, "podSelector", "nonEmpty") != {}
  ns := input.review.object.metadata.namespace
  msg := sprintf("NetworkPolicy '%v' in namespace '%v' does not use an empty podSelector — ensure a default-deny policy also exists (NW4001)", [input.review.object.metadata.name, ns])
}`,
  },

  NW4005: {
    name: 'nw4005_metadata_api_not_blocked',
    description: 'Cloud metadata API (169.254.169.254) not blocked in egress NetworkPolicies',
    enforcementAction: 'deny',
    rego: `package networkvet.nw4005

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  types := object.get(input.review.object.spec, "policyTypes", [])
  types[_] == "Egress"
  egress_rules := object.get(input.review.object.spec, "egress", [])
  count(egress_rules) > 0
  not blocks_metadata_api(egress_rules)
  ns := input.review.object.metadata.namespace
  msg := sprintf("NetworkPolicy '%v' in namespace '%v' has egress rules but does not block the cloud metadata API (169.254.169.254) (NW4005)", [input.review.object.metadata.name, ns])
}

blocks_metadata_api(egress_rules) {
  rule := egress_rules[_]
  peer := rule.to[_]
  ipBlock := peer.ipBlock
  ipBlock.cidr == "0.0.0.0/0"
  ipBlock.except[_] == "169.254.169.254/32"
}

blocks_metadata_api(egress_rules) {
  rule := egress_rules[_]
  peer := rule.to[_]
  peer.ipBlock.cidr == "169.254.169.254/32"
}`,
  },

  NW5002: {
    name: 'nw5002_authz_empty_source',
    description: 'AuthorizationPolicy ALLOW rule has an empty source — matches any caller',
    enforcementAction: 'deny',
    rego: `package networkvet.nw5002

violation[{"msg": msg}] {
  input.review.object.kind == "AuthorizationPolicy"
  action := object.get(input.review.object.spec, "action", "ALLOW")
  action == "ALLOW"
  from := input.review.object.spec.rules[_].from[_]
  src := from.source
  count(object.get(src, "principals", [])) == 0
  count(object.get(src, "namespaces", [])) == 0
  count(object.get(src, "ipBlocks", [])) == 0
  msg := sprintf("AuthorizationPolicy '%v' ALLOW rule has an empty source — matches any caller (NW5002)", [input.review.object.metadata.name])
}`,
  },

  NW5003: {
    name: 'nw5003_authz_all_methods',
    description: 'AuthorizationPolicy ALLOW rule permits all HTTP methods (methods: ["*"])',
    enforcementAction: 'warn',
    rego: `package networkvet.nw5003

violation[{"msg": msg}] {
  input.review.object.kind == "AuthorizationPolicy"
  action := object.get(input.review.object.spec, "action", "ALLOW")
  action == "ALLOW"
  to := input.review.object.spec.rules[_].to[_]
  to.operation.methods[_] == "*"
  msg := sprintf("AuthorizationPolicy '%v' ALLOW rule permits all HTTP methods (methods: [\\"*\\"]) (NW5003)", [input.review.object.metadata.name])
}`,
  },

  NW5004: {
    name: 'nw5004_authz_unconditional_allow',
    description: 'AuthorizationPolicy ALLOW rule has neither from nor to — allows all traffic unconditionally',
    enforcementAction: 'deny',
    rego: `package networkvet.nw5004

violation[{"msg": msg}] {
  input.review.object.kind == "AuthorizationPolicy"
  action := object.get(input.review.object.spec, "action", "ALLOW")
  action == "ALLOW"
  rule := input.review.object.spec.rules[_]
  count(object.get(rule, "from", [])) == 0
  count(object.get(rule, "to", [])) == 0
  msg := sprintf("AuthorizationPolicy '%v' ALLOW rule has neither 'from' nor 'to' — allows all traffic unconditionally (NW5004)", [input.review.object.metadata.name])
}`,
  },

  NW5007: {
    name: 'nw5007_authz_no_selector',
    description: 'AuthorizationPolicy has no workload selector — applies to all workloads in the namespace',
    enforcementAction: 'warn',
    rego: `package networkvet.nw5007

violation[{"msg": msg}] {
  input.review.object.kind == "AuthorizationPolicy"
  sel := object.get(input.review.object.spec, "selector", {})
  count(object.get(sel, "matchLabels", {})) == 0
  msg := sprintf("AuthorizationPolicy '%v' has no workload selector — applies to all workloads in namespace '%v' (NW5007)", [input.review.object.metadata.name, input.review.object.metadata.namespace])
}`,
  },

  NW5008: {
    name: 'nw5008_authz_no_namespace_restriction',
    description: 'AuthorizationPolicy ALLOW rule specifies principals but does not restrict source namespace',
    enforcementAction: 'warn',
    rego: `package networkvet.nw5008

violation[{"msg": msg}] {
  input.review.object.kind == "AuthorizationPolicy"
  action := object.get(input.review.object.spec, "action", "ALLOW")
  action == "ALLOW"
  from := input.review.object.spec.rules[_].from[_]
  src := from.source
  principals := object.get(src, "principals", [])
  count(principals) > 0
  not principals[_] == "*"
  count(object.get(src, "namespaces", [])) == 0
  msg := sprintf("AuthorizationPolicy '%v' ALLOW rule has principals but no source namespace restriction (NW5008)", [input.review.object.metadata.name])
}`,
  },

  NW6002: {
    name: 'nw6002_cilium_world_egress',
    description: 'CiliumNetworkPolicy egress allows to "world" entity (any external IP)',
    enforcementAction: 'warn',
    rego: `package networkvet.nw6002

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  entity := input.review.object.spec.egress[_].toEntities[_]
  entity == "world"
  msg := sprintf("CiliumNetworkPolicy '%v' egress allows to entity 'world' (any external IP) (NW6002)", [input.review.object.metadata.name])
}`,
  },

  NW6003: {
    name: 'nw6003_cilium_all_entity',
    description: 'CiliumNetworkPolicy uses "all" entity — matches every endpoint in the cluster',
    enforcementAction: 'deny',
    rego: `package networkvet.nw6003

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  entity := input.review.object.spec.ingress[_].fromEntities[_]
  entity == "all"
  msg := sprintf("CiliumNetworkPolicy '%v' ingress uses 'all' entity — matches every endpoint (NW6003)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  entity := input.review.object.spec.egress[_].toEntities[_]
  entity == "all"
  msg := sprintf("CiliumNetworkPolicy '%v' egress uses 'all' entity — matches every endpoint (NW6003)", [input.review.object.metadata.name])
}`,
  },

  NW6004: {
    name: 'nw6004_cilium_empty_endpoint_selector',
    description: 'CiliumNetworkPolicy has empty endpointSelector — applies to all pods in namespace',
    enforcementAction: 'warn',
    rego: `package networkvet.nw6004

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  object.get(input.review.object.spec, "endpointSelector", "absent") == {}
  msg := sprintf("CiliumNetworkPolicy '%v' has an empty endpointSelector — applies to all pods in namespace '%v' (NW6004)", [input.review.object.metadata.name, input.review.object.metadata.namespace])
}`,
  },

  NW6006: {
    name: 'nw6006_ccnp_no_node_selector',
    description: 'CiliumClusterwideNetworkPolicy has no nodeSelector — applies to all nodes',
    enforcementAction: 'warn',
    rego: `package networkvet.nw6006

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumClusterwideNetworkPolicy"
  count(object.get(input.review.object.spec, "nodeSelector", {})) == 0
  msg := sprintf("CiliumClusterwideNetworkPolicy '%v' has no nodeSelector — applies to all nodes in the cluster (NW6006)", [input.review.object.metadata.name])
}`,
  },

  NW6007: {
    name: 'nw6007_cilium_fqdn_wildcard',
    description: 'CiliumNetworkPolicy egress uses toFQDNs matchPattern: "*" — allows egress to any domain',
    enforcementAction: 'warn',
    rego: `package networkvet.nw6007

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  fqdn := input.review.object.spec.egress[_].toFQDNs[_]
  fqdn.matchPattern == "*"
  msg := sprintf("CiliumNetworkPolicy '%v' egress uses toFQDNs matchPattern: '*' — allows any domain (NW6007)", [input.review.object.metadata.name])
}`,
  },

  NW1006: {
    name: 'nw1006_egress_no_dns',
    description: 'NetworkPolicy restricts egress but does not allow DNS (port 53)',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1006

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  types := object.get(input.review.object.spec, "policyTypes", [])
  types[_] == "Egress"
  egress_rules := object.get(input.review.object.spec, "egress", [])
  count(egress_rules) > 0
  not allows_dns(egress_rules)
  msg := sprintf("NetworkPolicy '%v' restricts egress but does not allow DNS (port 53) — pods may lose DNS resolution (NW1006)", [input.review.object.metadata.name])
}

allows_dns(egress_rules) {
  rule := egress_rules[_]
  port := rule.ports[_]
  port.port == 53
}

allows_dns(egress_rules) {
  rule := egress_rules[_]
  port := rule.ports[_]
  port.port == "dns"
}`,
  },

  NW1007: {
    name: 'nw1007_kube_system_ingress',
    description: 'NetworkPolicy allows ingress from kube-system namespace',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1007

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  peer := input.review.object.spec.ingress[_].from[_]
  ml := peer.namespaceSelector.matchLabels
  ml["kubernetes.io/metadata.name"] == "kube-system"
  msg := sprintf("NetworkPolicy '%v' allows ingress from kube-system namespace — verify this is intentional (NW1007)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  peer := input.review.object.spec.ingress[_].from[_]
  ml := peer.namespaceSelector.matchLabels
  ml.name == "kube-system"
  msg := sprintf("NetworkPolicy '%v' allows ingress from kube-system namespace — verify this is intentional (NW1007)", [input.review.object.metadata.name])
}`,
  },

  NW1008: {
    name: 'nw1008_empty_policy_types',
    description: 'NetworkPolicy has empty or missing policyTypes field',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1008

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  count(object.get(input.review.object.spec, "policyTypes", [])) == 0
  msg := sprintf("NetworkPolicy '%v' has no policyTypes field — set policyTypes explicitly to [\"Ingress\"] or [\"Egress\"] or both (NW1008)", [input.review.object.metadata.name])
}`,
  },

  NW1009: {
    name: 'nw1009_no_ingress_policy',
    description: 'Workload has no NetworkPolicy restricting ingress',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1009

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Pod", "ReplicaSet"}

violation[{"msg": msg}] {
  workload_kinds[input.review.object.kind]
  ns := input.review.object.metadata.namespace
  msg := sprintf("%v '%v' in namespace '%v' — ensure a NetworkPolicy with policyTypes: [Ingress] exists in this namespace (NW1009)", [input.review.object.kind, input.review.object.metadata.name, ns])
}`,
  },

  NW1010: {
    name: 'nw1010_no_egress_policy',
    description: 'Workload has no NetworkPolicy restricting egress',
    enforcementAction: 'warn',
    rego: `package networkvet.nw1010

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Pod", "ReplicaSet"}

violation[{"msg": msg}] {
  workload_kinds[input.review.object.kind]
  ns := input.review.object.metadata.namespace
  msg := sprintf("%v '%v' in namespace '%v' — ensure a NetworkPolicy with policyTypes: [Egress] exists in this namespace (NW1010)", [input.review.object.kind, input.review.object.metadata.name, ns])
}`,
  },

  NW2005: {
    name: 'nw2005_headless_no_selector',
    description: 'Headless Service (clusterIP: None) without selector — DNS returns manually managed endpoints',
    enforcementAction: 'warn',
    rego: `package networkvet.nw2005

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.clusterIP == "None"
  count(object.get(input.review.object.spec, "selector", {})) == 0
  msg := sprintf("Headless Service '%v' has no selector — DNS will return manually managed Endpoints (NW2005)", [input.review.object.metadata.name])
}`,
  },

  NW2007: {
    name: 'nw2007_stateful_no_session_affinity',
    description: 'Service targets a StatefulSet but has no sessionAffinity',
    enforcementAction: 'warn',
    rego: `package networkvet.nw2007

# Note: admission webhooks evaluate single resources; this rule is a best-effort reminder.
violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type != "Headless"
  affinity := object.get(input.review.object.spec, "sessionAffinity", "None")
  affinity == "None"
  count(object.get(input.review.object.spec, "selector", {})) > 0
  msg := sprintf("Service '%v' has no sessionAffinity — if it targets a StatefulSet, set sessionAffinity: ClientIP (NW2007)", [input.review.object.metadata.name])
}`,
  },

  NW3005: {
    name: 'nw3005_no_ssl_redirect_annotation',
    description: 'Ingress missing nginx ssl-redirect annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw3005

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  not input.review.object.metadata.annotations["nginx.ingress.kubernetes.io/ssl-redirect"]
  msg := sprintf("Ingress '%v' is missing nginx.ingress.kubernetes.io/ssl-redirect annotation — explicitly set to \"true\" or \"false\" (NW3005)", [input.review.object.metadata.name])
}`,
  },

  NW3007: {
    name: 'nw3007_ingress_missing_backend',
    description: 'Ingress references a Service backend that may not exist',
    enforcementAction: 'warn',
    rego: `package networkvet.nw3007

# Note: admission webhooks evaluate single resources; cross-resource checks are best-effort.
violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  path := input.review.object.spec.rules[_].http.paths[_]
  svc_name := path.backend.service.name
  not svc_name
  msg := sprintf("Ingress '%v' has a path rule with no backend service name defined (NW3007)", [input.review.object.metadata.name])
}`,
  },

  NW4002: {
    name: 'nw4002_cni_no_networkpolicy',
    description: 'CNI plugin may not support NetworkPolicy enforcement',
    enforcementAction: 'warn',
    rego: `package networkvet.nw4002

flannel_indicators := {"flannel", "kindnet"}

violation[{"msg": msg}] {
  input.review.object.kind == "DaemonSet"
  input.review.object.metadata.namespace == "kube-system"
  name := lower(input.review.object.metadata.name)
  flannel_indicators[_] == name
  msg := sprintf("DaemonSet '%v' indicates a CNI (flannel/kindnet) that does not enforce NetworkPolicies natively (NW4002)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "ConfigMap"
  input.review.object.metadata.namespace == "kube-flannel"
  msg := sprintf("ConfigMap '%v' in kube-flannel namespace indicates Flannel CNI — NetworkPolicies will not be enforced (NW4002)", [input.review.object.metadata.name])
}`,
  },

  NW4003: {
    name: 'nw4003_cross_namespace_unrestricted',
    description: 'NetworkPolicy does not restrict cross-namespace ingress traffic',
    enforcementAction: 'warn',
    rego: `package networkvet.nw4003

violation[{"msg": msg}] {
  input.review.object.kind == "NetworkPolicy"
  ingress_rules := object.get(input.review.object.spec, "ingress", [])
  count(ingress_rules) > 0
  from_rules := ingress_rules[_].from
  count(from_rules) > 0
  not any_namespace_restricted(ingress_rules)
  ns := input.review.object.metadata.namespace
  msg := sprintf("NetworkPolicy '%v' in namespace '%v' has ingress rules but none restrict cross-namespace traffic via namespaceSelector (NW4003)", [input.review.object.metadata.name, ns])
}

any_namespace_restricted(ingress_rules) {
  peer := ingress_rules[_].from[_]
  ns_sel := peer.namespaceSelector
  count(ns_sel) > 0
}`,
  },

  NW4004: {
    name: 'nw4004_kube_dns_unrestricted',
    description: 'kube-dns has no NetworkPolicy restricting access',
    enforcementAction: 'warn',
    rego: `package networkvet.nw4004

# Fires on Namespace resources to remind operators to add a DNS restriction NP in kube-system.
violation[{"msg": msg}] {
  input.review.object.kind == "Namespace"
  input.review.object.metadata.name == "kube-system"
  msg := "kube-system namespace created — ensure a NetworkPolicy restricting kube-dns access is also applied (NW4004)"
}`,
  },

  NW6008: {
    name: 'nw6008_cilium_l7_http',
    description: 'CiliumNetworkPolicy defines L7 HTTP rules — verify application-layer enforcement',
    enforcementAction: 'warn',
    rego: `package networkvet.nw6008

violation[{"msg": msg}] {
  input.review.object.kind == "CiliumNetworkPolicy"
  rules := array.concat(
    object.get(input.review.object.spec, "ingress", []),
    object.get(input.review.object.spec, "egress", [])
  )
  rule := rules[_]
  port := rule.toPorts[_]
  count(object.get(port, "rules", {}).http) > 0
  msg := sprintf("CiliumNetworkPolicy '%v' defines L7 HTTP rules — ensure Cilium L7 enforcement (Envoy) is enabled (NW6008)", [input.review.object.metadata.name])
}`,
  },

  NW7001: {
    name: 'nw7001_aws_nlb_not_internal',
    description: 'AWS NLB Service has no internal annotation — load balancer may be internet-facing',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7001

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  lb_type := input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-type"]
  lb_type == "nlb"
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"]
  msg := sprintf("Service '%v' uses AWS NLB without an internal annotation — NLB may be internet-facing (NW7001)", [input.review.object.metadata.name])
}`,
  },

  NW7002: {
    name: 'nw7002_aws_lb_access_logs_disabled',
    description: 'AWS LoadBalancer Service has access logs explicitly disabled',
    enforcementAction: 'deny',
    rego: `package networkvet.nw7002

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-access-log-enabled"] == "false"
  msg := sprintf("Service '%v' has AWS load balancer access logs explicitly disabled — enable for security audit trails (NW7002)", [input.review.object.metadata.name])
}`,
  },

  NW7003: {
    name: 'nw7003_aws_lb_no_ssl_cert',
    description: 'Public AWS LoadBalancer Service has no SSL certificate annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7003

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-type"]
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-cert"]
  msg := sprintf("Service '%v' is a public AWS LoadBalancer without an SSL certificate annotation — configure HTTPS offload via ACM (NW7003)", [input.review.object.metadata.name])
}`,
  },

  NW7004: {
    name: 'nw7004_aws_lb_no_tls_policy',
    description: 'AWS LoadBalancer Service has SSL configured but no TLS negotiation policy',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7004

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-cert"]
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy"]
  msg := sprintf("Service '%v' uses AWS LB SSL without a pinned TLS negotiation policy — specify ELBSecurityPolicy-TLS13-1-2-2021-06 (NW7004)", [input.review.object.metadata.name])
}`,
  },

  NW7005: {
    name: 'nw7005_alb_no_scheme',
    description: 'ALB Ingress has no scheme annotation — defaults to internet-facing',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7005

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  input.review.object.metadata.annotations["kubernetes.io/ingress.class"] == "alb"
  scheme := object.get(input.review.object.metadata.annotations, "alb.ingress.kubernetes.io/scheme", "internet-facing")
  scheme == "internet-facing"
  msg := sprintf("Ingress '%v' uses ALB without alb.ingress.kubernetes.io/scheme: internal — ALB is internet-facing (NW7005)", [input.review.object.metadata.name])
}`,
  },

  NW7006: {
    name: 'nw7006_alb_no_security_group',
    description: 'ALB Ingress has no custom security group annotation',
    enforcementAction: 'deny',
    rego: `package networkvet.nw7006

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  input.review.object.metadata.annotations["kubernetes.io/ingress.class"] == "alb"
  not input.review.object.metadata.annotations["alb.ingress.kubernetes.io/security-groups"]
  msg := sprintf("Ingress '%v' uses ALB without alb.ingress.kubernetes.io/security-groups — default security group may be overly permissive (NW7006)", [input.review.object.metadata.name])
}`,
  },

  NW7007: {
    name: 'nw7007_alb_no_ssl_policy',
    description: 'ALB Ingress has TLS configured but no ssl-policy annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7007

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  input.review.object.metadata.annotations["kubernetes.io/ingress.class"] == "alb"
  count(object.get(input.review.object.spec, "tls", [])) > 0
  not input.review.object.metadata.annotations["alb.ingress.kubernetes.io/ssl-policy"]
  msg := sprintf("Ingress '%v' uses ALB with TLS but no ssl-policy annotation — pin ELBSecurityPolicy-TLS13-1-2-2021-06 (NW7007)", [input.review.object.metadata.name])
}`,
  },

  NW7008: {
    name: 'nw7008_aws_lb_draining_disabled',
    description: 'AWS LoadBalancer Service has connection draining explicitly disabled',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7008

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled"] == "false"
  msg := sprintf("Service '%v' has AWS LB connection draining disabled — enable to allow in-flight requests to complete (NW7008)", [input.review.object.metadata.name])
}`,
  },

  NW7009: {
    name: 'nw7009_gke_lb_not_internal',
    description: 'GKE LoadBalancer Service has no internal annotation — may be internet-facing',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7009

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["networking.gke.io/load-balancer-type"]
  not input.review.object.metadata.annotations["networking.gke.io/load-balancer-type"] == "Internal"
  msg := sprintf("Service '%v' is a GKE LoadBalancer without networking.gke.io/load-balancer-type: Internal — may be internet-facing (NW7009)", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["cloud.google.com/load-balancer-type"]
  not input.review.object.metadata.annotations["cloud.google.com/load-balancer-type"] == "Internal"
  msg := sprintf("Service '%v' is a GKE LoadBalancer without cloud.google.com/load-balancer-type: Internal — may be internet-facing (NW7009)", [input.review.object.metadata.name])
}`,
  },

  NW7010: {
    name: 'nw7010_gce_ingress_http_allowed',
    description: 'GCE Ingress does not disable HTTP — traffic can reach backend unencrypted',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7010

gce_classes := {"gce", "gce-internal"}

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  cls := input.review.object.metadata.annotations["kubernetes.io/ingress.class"]
  gce_classes[cls]
  object.get(input.review.object.metadata.annotations, "kubernetes.io/ingress.allow-http", "true") != "false"
  msg := sprintf("Ingress '%v' uses GCE ingress without kubernetes.io/ingress.allow-http: \"false\" — HTTP is allowed (NW7010)", [input.review.object.metadata.name])
}`,
  },

  NW7011: {
    name: 'nw7011_gke_lb_no_type_annotation',
    description: 'GKE LoadBalancer Service does not set a load-balancer-type annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7011

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["networking.gke.io/load-balancer-type"]
  not input.review.object.metadata.annotations["cloud.google.com/load-balancer-type"]
  not input.review.object.metadata.annotations["networking.gke.io/load-balancer-type"]
  msg := sprintf("Service '%v' is a GKE LoadBalancer with no load-balancer-type annotation — confirm public vs internal intent (NW7011)", [input.review.object.metadata.name])
}`,
  },

  NW7012: {
    name: 'nw7012_gke_backend_config_no_cloud_armor',
    description: 'GKE BackendConfig has no Cloud Armor security policy configured',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7012

violation[{"msg": msg}] {
  input.review.object.kind == "BackendConfig"
  startswith(input.review.object.apiVersion, "cloud.google.com")
  not input.review.object.spec.securityPolicy
  msg := sprintf("GKE BackendConfig '%v' has no Cloud Armor security policy — add spec.securityPolicy to protect against DDoS (NW7012)", [input.review.object.metadata.name])
}`,
  },

  NW7013: {
    name: 'nw7013_aks_lb_explicit_public',
    description: 'AKS LoadBalancer Service has azure-load-balancer-internal: false — internet-facing confirmed',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7013

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] == "false"
  msg := sprintf("Service '%v' has azure-load-balancer-internal: \"false\" — this AKS LoadBalancer is explicitly internet-facing (NW7013)", [input.review.object.metadata.name])
}`,
  },

  NW7014: {
    name: 'nw7014_aks_lb_no_internal_annotation',
    description: 'AKS LoadBalancer Service has no azure-load-balancer-internal annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7014

violation[{"msg": msg}] {
  input.review.object.kind == "Service"
  input.review.object.spec.type == "LoadBalancer"
  input.review.object.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"]
  not input.review.object.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"]
  msg := sprintf("Service '%v' is an AKS LoadBalancer without azure-load-balancer-internal annotation — intent not explicit (NW7014)", [input.review.object.metadata.name])
}`,
  },

  NW7015: {
    name: 'nw7015_azure_agic_no_waf',
    description: 'Azure Application Gateway Ingress has no WAF policy annotation',
    enforcementAction: 'warn',
    rego: `package networkvet.nw7015

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  input.review.object.metadata.annotations["kubernetes.io/ingress.class"] == "azure/application-gateway"
  not input.review.object.metadata.annotations["appgw.ingress.kubernetes.io/waf-policy-for-path"]
  not input.review.object.metadata.annotations["azure.application-gateway/waf-policy-id"]
  msg := sprintf("Ingress '%v' uses Azure Application Gateway without a WAF policy — add appgw.ingress.kubernetes.io/waf-policy-for-path (NW7015)", [input.review.object.metadata.name])
}`,
  },

  // ── NW8xxx: Gateway API ────────────────────────────────────────────────────

  NW8001: {
    name: 'nw8001_httproute_no_tls',
    description: 'HTTPRoute is served over plain HTTP without TLS termination',
    enforcementAction: 'warn',
    rego: `package networkvet.nw8001

violation[{"msg": msg}] {
  input.review.object.kind == "HTTPRoute"
  startswith(input.review.object.apiVersion, "gateway.networking.k8s.io")
  parentRef := input.review.object.spec.parentRefs[_]
  sectionName := lower(object.get(parentRef, "sectionName", ""))
  sectionName != "https"
  sectionName != "tls"
  msg := sprintf("HTTPRoute '%v' is served over plain HTTP without TLS termination (NW8001)", [input.review.object.metadata.name])
}`,
  },

  NW8002: {
    name: 'nw8002_gateway_all_namespaces',
    description: "Gateway listener allows routes from all namespaces",
    enforcementAction: 'warn',
    rego: `package networkvet.nw8002

deny[{"msg": msg}] {
  input.review.object.kind == "Gateway"
  startswith(input.review.object.apiVersion, "gateway.networking.k8s.io")
  listener := input.review.object.spec.listeners[_]
  listener.allowedRoutes.namespaces.from == "All"
  msg := sprintf("Gateway '%v' listener '%v' allows routes from all namespaces — restrict with 'Same' or 'Selector' (NW8002)", [input.review.object.metadata.name, listener.name])
}`,
  },

  NW8003: {
    name: 'nw8003_httproute_cross_ns_no_grant',
    description: 'HTTPRoute references Service in a different namespace without a ReferenceGrant',
    enforcementAction: 'deny',
    rego: `package networkvet.nw8003

deny[{"msg": msg}] {
  input.review.object.kind == "HTTPRoute"
  startswith(input.review.object.apiVersion, "gateway.networking.k8s.io")
  backendRef := input.review.object.spec.rules[_].backendRefs[_]
  targetNs := backendRef.namespace
  routeNs := input.review.object.metadata.namespace
  targetNs != routeNs
  targetNs != ""
  msg := sprintf("HTTPRoute '%v' references Service '%v' in namespace '%v' — ensure a ReferenceGrant exists in that namespace (NW8003)", [input.review.object.metadata.name, backendRef.name, targetNs])
}`,
  },

  NW8004: {
    name: 'nw8004_gateway_https_no_cert',
    description: 'Gateway HTTPS/TLS listener has no certificateRefs configured',
    enforcementAction: 'deny',
    rego: `package networkvet.nw8004

deny[{"msg": msg}] {
  input.review.object.kind == "Gateway"
  startswith(input.review.object.apiVersion, "gateway.networking.k8s.io")
  listener := input.review.object.spec.listeners[_]
  upper(listener.protocol) == "HTTPS"
  count(object.get(object.get(listener, "tls", {}), "certificateRefs", [])) == 0
  msg := sprintf("Gateway '%v' HTTPS listener '%v' has no certificateRefs configured (NW8004)", [input.review.object.metadata.name, listener.name])
}

deny[{"msg": msg}] {
  input.review.object.kind == "Gateway"
  startswith(input.review.object.apiVersion, "gateway.networking.k8s.io")
  listener := input.review.object.spec.listeners[_]
  upper(listener.protocol) == "TLS"
  count(object.get(object.get(listener, "tls", {}), "certificateRefs", [])) == 0
  msg := sprintf("Gateway '%v' TLS listener '%v' has no certificateRefs configured (NW8004)", [input.review.object.metadata.name, listener.name])
}`,
  },

  NW8005: {
    name: 'nw8005_grpcroute_cross_ns_no_grant',
    description: 'GRPCRoute references Service in a different namespace without a ReferenceGrant',
    enforcementAction: 'deny',
    rego: `package networkvet.nw8005

deny[{"msg": msg}] {
  input.review.object.kind == "GRPCRoute"
  startswith(input.review.object.apiVersion, "gateway.networking.k8s.io")
  backendRef := input.review.object.spec.rules[_].backendRefs[_]
  targetNs := backendRef.namespace
  routeNs := input.review.object.metadata.namespace
  targetNs != routeNs
  targetNs != ""
  msg := sprintf("GRPCRoute '%v' references Service '%v' in namespace '%v' — ensure a ReferenceGrant exists in that namespace (NW8005)", [input.review.object.metadata.name, backendRef.name, targetNs])
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
