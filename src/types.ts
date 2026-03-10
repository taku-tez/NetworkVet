// Core type definitions for NetworkVet

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ResourceKind =
  | 'NetworkPolicy'
  | 'Service'
  | 'Ingress'
  | 'Namespace'
  | 'Pod'
  | 'Deployment'
  | 'StatefulSet'
  | 'DaemonSet'
  | string;

export interface K8sMetadata {
  name: string;
  /** Absent for cluster-scoped resources and for namespace-scoped resources
   *  whose manifests were applied without an explicit namespace field. */
  namespace?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  [key: string]: unknown;
}

/**
 * Kubernetes resource kinds that are cluster-scoped (not namespace-scoped).
 * These should never have a namespace assigned and must be excluded from
 * namespace-level rule checks.
 */
export const CLUSTER_SCOPED_KINDS = new Set([
  'ClusterRole',
  'ClusterRoleBinding',
  'CustomResourceDefinition',
  'Namespace',
  'Node',
  'PersistentVolume',
  'StorageClass',
  'IngressClass',
  'ValidatingWebhookConfiguration',
  'MutatingWebhookConfiguration',
  'APIService',
  'PriorityClass',
  'RuntimeClass',
  'ClusterIssuer',          // cert-manager
  'ClusterPolicy',          // Kyverno
  'ClusterPolicyReport',    // Kyverno
]);

/** Returns true when the resource kind is cluster-scoped (has no namespace). */
export function isClusterScoped(kind: string): boolean {
  return CLUSTER_SCOPED_KINDS.has(kind);
}

// NetworkPolicy spec types
export interface NetworkPolicyPort {
  protocol?: string;
  port?: number | string;
  endPort?: number;
}

export interface IPBlock {
  cidr: string;
  except?: string[];
}

export interface NetworkPolicyPeer {
  podSelector?: Record<string, unknown>;
  namespaceSelector?: Record<string, unknown>;
  ipBlock?: IPBlock;
}

export interface NetworkPolicyIngressRule {
  from?: NetworkPolicyPeer[];
  ports?: NetworkPolicyPort[];
}

export interface NetworkPolicyEgressRule {
  to?: NetworkPolicyPeer[];
  ports?: NetworkPolicyPort[];
}

export interface NetworkPolicySpec {
  podSelector: Record<string, unknown>;
  policyTypes?: string[];
  ingress?: NetworkPolicyIngressRule[];
  egress?: NetworkPolicyEgressRule[];
}

// Service spec types
export interface ServicePort {
  name?: string;
  protocol?: string;
  port: number;
  targetPort?: number | string;
  nodePort?: number;
}

export interface ServiceSpec {
  type?: string;
  clusterIP?: string;
  externalIPs?: string[];
  externalName?: string;
  externalTrafficPolicy?: string;
  sessionAffinity?: string;
  selector?: Record<string, string>;
  ports?: ServicePort[];
  loadBalancerSourceRanges?: string[];
}

// Ingress spec types
export interface IngressTLS {
  hosts?: string[];
  secretName?: string;
}

export interface IngressBackend {
  service?: {
    name: string;
    port: { number?: number; name?: string };
  };
  resource?: unknown;
}

export interface HTTPIngressPath {
  path?: string;
  pathType?: string;
  backend: IngressBackend;
}

export interface IngressRule {
  host?: string;
  http?: {
    paths: HTTPIngressPath[];
  };
}

export interface IngressSpec {
  tls?: IngressTLS[];
  rules?: IngressRule[];
  defaultBackend?: IngressBackend;
  ingressClassName?: string;
}

// ─── Istio spec types ────────────────────────────────────────────────────────

export interface IstioSource {
  principals?: string[];
  namespaces?: string[];
  ipBlocks?: string[];
  notPrincipals?: string[];
  notNamespaces?: string[];
  notIpBlocks?: string[];
  remoteIpBlocks?: string[];
}

export interface IstioOperation {
  hosts?: string[];
  ports?: string[];
  methods?: string[];
  paths?: string[];
  notHosts?: string[];
  notPorts?: string[];
  notMethods?: string[];
  notPaths?: string[];
}

export interface IstioRule {
  from?: Array<{ source: IstioSource }>;
  to?: Array<{ operation: IstioOperation }>;
  when?: unknown[];
}

export interface AuthorizationPolicySpec {
  /** Selector for the workload; absent = applies to entire namespace */
  selector?: { matchLabels?: Record<string, string> };
  action?: 'ALLOW' | 'DENY' | 'CUSTOM' | 'AUDIT';
  rules?: IstioRule[];
}

export interface PeerAuthenticationSpec {
  selector?: { matchLabels?: Record<string, string> };
  mtls?: { mode?: 'STRICT' | 'PERMISSIVE' | 'DISABLE' | 'UNSET' };
  portLevelMtls?: Record<string, { mode?: string }>;
}

// ─── Cilium spec types ────────────────────────────────────────────────────────

export interface CiliumNetworkPolicyEgressRule {
  toEntities?: string[];
  toCIDR?: string[];
  toCIDRSet?: Array<{ cidr: string; except?: string[] }>;
  toFQDNs?: Array<{ matchName?: string; matchPattern?: string }>;
  toPorts?: Array<{
    ports?: Array<{ port: string; protocol?: string }>;
    rules?: {
      http?: Array<{ method?: string; path?: string; headers?: string[] }>;
      dns?: unknown[];
    };
  }>;
  toEndpoints?: unknown[];
  toGroups?: unknown[];
  toServices?: unknown[];
}

export interface CiliumNetworkPolicyIngressRule {
  fromEntities?: string[];
  fromCIDR?: string[];
  fromCIDRSet?: Array<{ cidr: string; except?: string[] }>;
  fromEndpoints?: unknown[];
  fromRequires?: unknown[];
  toPorts?: Array<{
    ports?: Array<{ port: string; protocol?: string }>;
    rules?: unknown;
  }>;
}

export interface CiliumNetworkPolicySpec {
  /** Pod selector — empty `{}` matches all pods */
  endpointSelector?: Record<string, unknown>;
  nodeSelector?: Record<string, unknown>;
  ingress?: CiliumNetworkPolicyIngressRule[];
  egress?: CiliumNetworkPolicyEgressRule[];
  ingressDeny?: CiliumNetworkPolicyIngressRule[];
  egressDeny?: CiliumNetworkPolicyEgressRule[];
}

// Parsed resource from YAML
export interface ParsedResource {
  kind: ResourceKind;
  apiVersion: string;
  metadata: K8sMetadata;
  spec: NetworkPolicySpec | ServiceSpec | IngressSpec | AuthorizationPolicySpec | PeerAuthenticationSpec | CiliumNetworkPolicySpec | Record<string, unknown>;
  file: string;
  line: number;
}

// A single finding from a rule check
export interface Finding {
  id: string;
  severity: Severity;
  kind: ResourceKind;
  name: string;
  namespace: string;
  file: string;
  line: number;
  message: string;
  detail?: string;
}

// Analysis context passed to rules
export interface AnalysisContext {
  resources: ParsedResource[];
  namespaces: Set<string>;
  /** Detected CNI plugin name (e.g. 'calico', 'flannel'), null if unknown, undefined if not checked */
  cni?: string | null;
  /** Whether resources were loaded from files or a live cluster */
  mode?: 'file' | 'cluster';
  /** Ingress controller class — affects annotation checks (nginx, alb, gce, azure, etc.) */
  ingressClass?: string;
  /** Namespaces excluded from reachability analysis */
  excludeNamespaces?: string[];
  /** Forced cloud provider — overrides per-resource annotation inference */
  cloudProvider?: 'aws' | 'gcp' | 'azure';
}

// Rule definition
export interface Rule {
  id: string;
  severity: Severity;
  description: string;
  check: (resources: ParsedResource[], context: AnalysisContext) => Finding[];
}

// Helper type guards
export function isNetworkPolicy(r: ParsedResource): r is ParsedResource & { spec: NetworkPolicySpec } {
  return r.kind === 'NetworkPolicy';
}

export function isService(r: ParsedResource): r is ParsedResource & { spec: ServiceSpec } {
  return r.kind === 'Service';
}

export function isIngress(r: ParsedResource): r is ParsedResource & { spec: IngressSpec } {
  return r.kind === 'Ingress';
}

export function isNamespace(r: ParsedResource): boolean {
  return r.kind === 'Namespace';
}

export function isWorkload(r: ParsedResource): boolean {
  return ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob'].includes(r.kind);
}

/** Returns true when the resource is an Istio AuthorizationPolicy. */
export function isAuthorizationPolicy(r: ParsedResource): r is ParsedResource & { spec: AuthorizationPolicySpec } {
  return r.kind === 'AuthorizationPolicy' &&
    (r.apiVersion.startsWith('security.istio.io') || r.apiVersion.startsWith('istio.io'));
}

/** Returns true when the resource is an Istio PeerAuthentication. */
export function isPeerAuthentication(r: ParsedResource): r is ParsedResource & { spec: PeerAuthenticationSpec } {
  return r.kind === 'PeerAuthentication' &&
    (r.apiVersion.startsWith('security.istio.io') || r.apiVersion.startsWith('istio.io'));
}

/** Returns true when the resource is a Cilium CiliumNetworkPolicy. */
export function isCiliumNetworkPolicy(r: ParsedResource): r is ParsedResource & { spec: CiliumNetworkPolicySpec } {
  return r.kind === 'CiliumNetworkPolicy' &&
    (r.apiVersion.startsWith('cilium.io') || r.apiVersion.startsWith('networking.k8s.io'));
}

/** Returns true when the resource is a Cilium CiliumClusterwideNetworkPolicy. */
export function isCiliumClusterwideNetworkPolicy(r: ParsedResource): r is ParsedResource & { spec: CiliumNetworkPolicySpec } {
  return r.kind === 'CiliumClusterwideNetworkPolicy' &&
    (r.apiVersion.startsWith('cilium.io') || r.apiVersion.startsWith('networking.k8s.io'));
}

// ─── Annotation helpers ───────────────────────────────────────────────────────

/** Returns the value of a metadata annotation, or undefined if absent. */
export function getAnnotation(r: ParsedResource, key: string): string | undefined {
  return r.metadata.annotations?.[key];
}

/** Returns true when a metadata annotation key is present (value may be any string). */
export function hasAnnotation(r: ParsedResource, key: string): boolean {
  return key in (r.metadata.annotations ?? {});
}
