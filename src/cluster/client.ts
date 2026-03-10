import {
  KubeConfig,
  CoreV1Api,
  NetworkingV1Api,
  AppsV1Api,
} from '@kubernetes/client-node';
import type { ParsedResource, K8sMetadata } from '../types.js';

// ---- minimal K8s object shapes we need (avoid importing every V1 type) ----
interface K8sObjectMeta {
  name?: string;
  namespace?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: K8sObjectMeta;
  spec?: Record<string, unknown>;
}

interface K8sListResponse<T> {
  items: T[];
}

interface DaemonSetContainer {
  image?: string;
  name?: string;
}

interface DaemonSetSpec {
  template?: {
    spec?: {
      containers?: DaemonSetContainer[];
      initContainers?: DaemonSetContainer[];
    };
  };
}

interface K8sDaemonSet extends K8sObject {
  spec?: DaemonSetSpec & Record<string, unknown>;
}

/** Known CNI DaemonSet/image name fragments and the CNI they map to */
const CNI_PATTERNS: Array<{ pattern: RegExp; cni: string }> = [
  { pattern: /calico/i, cni: 'calico' },
  { pattern: /cilium/i, cni: 'cilium' },
  { pattern: /flannel/i, cni: 'flannel' },
  { pattern: /weave/i, cni: 'weave' },
  { pattern: /canal/i, cni: 'canal' },
  { pattern: /antrea/i, cni: 'antrea' },
  { pattern: /kindnet/i, cni: 'kindnet' },
];

/**
 * ClusterClient fetches Kubernetes resources from a live cluster via kubeconfig.
 */
export class ClusterClient {
  private kc: KubeConfig;
  private coreV1: CoreV1Api;
  private networkingV1: NetworkingV1Api;
  private appsV1: AppsV1Api;

  constructor(context?: string) {
    this.kc = new KubeConfig();

    try {
      this.kc.loadFromDefault();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Failed to load kubeconfig: ${msg}. ` +
          'Ensure ~/.kube/config exists or KUBECONFIG environment variable is set.'
      );
    }

    if (context) {
      try {
        this.kc.setCurrentContext(context);
      } catch {
        throw new Error(
          `Context "${context}" not found in kubeconfig. ` +
            `Available contexts: ${this.kc.getContexts().map((c) => c.name).join(', ')}`
        );
      }
    }

    this.coreV1 = this.kc.makeApiClient(CoreV1Api);
    this.networkingV1 = this.kc.makeApiClient(NetworkingV1Api);
    this.appsV1 = this.kc.makeApiClient(AppsV1Api);
  }

  /** Return the current context name */
  getCurrentContext(): string {
    return this.kc.getCurrentContext();
  }

  /** Return current namespace from kubeconfig context, or 'default' */
  getCurrentNamespace(): string {
    const ctx = this.kc.getContextObject(this.kc.getCurrentContext());
    return (ctx as { namespace?: string } | undefined)?.namespace ?? 'default';
  }

  // -------------------------------------------------------------------------
  // Fetch methods
  // -------------------------------------------------------------------------

  async listNetworkPolicies(namespace?: string): Promise<ParsedResource[]> {
    try {
      let response: K8sListResponse<K8sObject>;
      if (namespace) {
        response = await (this.networkingV1.listNamespacedNetworkPolicy as (
          param: { namespace: string }
        ) => Promise<K8sListResponse<K8sObject>>)({ namespace });
      } else {
        response = await (this.networkingV1.listNetworkPolicyForAllNamespaces as (
          param?: Record<string, unknown>
        ) => Promise<K8sListResponse<K8sObject>>)({});
      }
      return response.items.map((obj) => toResource('NetworkPolicy', 'networking.k8s.io/v1', obj));
    } catch (err) {
      throw wrapApiError('NetworkPolicy', err);
    }
  }

  async listServices(namespace?: string): Promise<ParsedResource[]> {
    try {
      let response: K8sListResponse<K8sObject>;
      if (namespace) {
        response = await (this.coreV1.listNamespacedService as (
          param: { namespace: string }
        ) => Promise<K8sListResponse<K8sObject>>)({ namespace });
      } else {
        response = await (this.coreV1.listServiceForAllNamespaces as (
          param?: Record<string, unknown>
        ) => Promise<K8sListResponse<K8sObject>>)({});
      }
      return response.items.map((obj) => toResource('Service', 'v1', obj));
    } catch (err) {
      throw wrapApiError('Service', err);
    }
  }

  async listIngresses(namespace?: string): Promise<ParsedResource[]> {
    try {
      let response: K8sListResponse<K8sObject>;
      if (namespace) {
        response = await (this.networkingV1.listNamespacedIngress as (
          param: { namespace: string }
        ) => Promise<K8sListResponse<K8sObject>>)({ namespace });
      } else {
        response = await (this.networkingV1.listIngressForAllNamespaces as (
          param?: Record<string, unknown>
        ) => Promise<K8sListResponse<K8sObject>>)({});
      }
      return response.items.map((obj) => toResource('Ingress', 'networking.k8s.io/v1', obj));
    } catch (err) {
      throw wrapApiError('Ingress', err);
    }
  }

  async listEndpoints(namespace?: string): Promise<ParsedResource[]> {
    try {
      let response: K8sListResponse<K8sObject>;
      if (namespace) {
        response = await (this.coreV1.listNamespacedEndpoints as (
          param: { namespace: string }
        ) => Promise<K8sListResponse<K8sObject>>)({ namespace });
      } else {
        response = await (this.coreV1.listEndpointsForAllNamespaces as (
          param?: Record<string, unknown>
        ) => Promise<K8sListResponse<K8sObject>>)({});
      }
      return response.items.map((obj) => toResource('Endpoints', 'v1', obj));
    } catch (err) {
      throw wrapApiError('Endpoints', err);
    }
  }

  async listNamespaces(): Promise<string[]> {
    try {
      const response = await (this.coreV1.listNamespace as (
        param?: Record<string, unknown>
      ) => Promise<K8sListResponse<K8sObject>>)({});
      return response.items
        .map((ns) => ns.metadata?.name ?? '')
        .filter(Boolean);
    } catch (err) {
      throw wrapApiError('Namespace', err);
    }
  }

  /**
   * Detect the CNI plugin by inspecting DaemonSets in kube-system.
   * Returns the CNI name string (e.g. 'calico', 'flannel') or null if unknown.
   */
  async detectCNI(): Promise<string | null> {
    let daemonSets: K8sDaemonSet[];
    try {
      const response = await (this.appsV1.listNamespacedDaemonSet as (
        param: { namespace: string }
      ) => Promise<K8sListResponse<K8sDaemonSet>>)({ namespace: 'kube-system' });
      daemonSets = response.items;
    } catch {
      // Can't access kube-system — can't detect CNI
      return null;
    }

    for (const ds of daemonSets) {
      const name = ds.metadata?.name ?? '';
      const containers = ds.spec?.template?.spec?.containers ?? [];
      const initContainers = ds.spec?.template?.spec?.initContainers ?? [];

      // Check DaemonSet name
      for (const { pattern, cni } of CNI_PATTERNS) {
        if (pattern.test(name)) return cni;
      }

      // Check container images
      for (const container of [...containers, ...initContainers]) {
        const image = container.image ?? '';
        for (const { pattern, cni } of CNI_PATTERNS) {
          if (pattern.test(image)) return cni;
        }
      }
    }

    // Also check the kube-flannel namespace DaemonSets
    try {
      const response = await (this.appsV1.listNamespacedDaemonSet as (
        param: { namespace: string }
      ) => Promise<K8sListResponse<K8sDaemonSet>>)({ namespace: 'kube-flannel' });
      if (response.items.length > 0) return 'flannel';
    } catch {
      // namespace doesn't exist — ignore
    }

    return null;
  }

  /**
   * Fetch all resources from the cluster.
   * If allNamespaces is true, fetches from every namespace.
   * Otherwise uses the provided namespace or the current one from kubeconfig.
   */
  async fetchAll(allNamespaces: boolean, namespace?: string): Promise<ParsedResource[]> {
    const ns = allNamespaces ? undefined : (namespace ?? this.getCurrentNamespace());

    const [networkPolicies, services, ingresses, endpoints] = await Promise.all([
      this.listNetworkPolicies(ns).catch(() => [] as ParsedResource[]),
      this.listServices(ns).catch(() => [] as ParsedResource[]),
      this.listIngresses(ns).catch(() => [] as ParsedResource[]),
      this.listEndpoints(ns).catch(() => [] as ParsedResource[]),
    ]);

    return [...networkPolicies, ...services, ...ingresses, ...endpoints];
  }
}

// -------------------------------------------------------------------------
// Conversion helpers: K8s API objects → ParsedResource
// -------------------------------------------------------------------------

function clusterFileRef(ns: string, kind: string, name: string): string {
  return `cluster:${ns}/${kind}/${name}`;
}

function extractMetadata(meta: K8sObjectMeta | undefined, defaultNs = 'default'): K8sMetadata {
  return {
    name: meta?.name ?? '',
    namespace: meta?.namespace ?? defaultNs,
    ...(meta?.labels ? { labels: meta.labels } : {}),
    ...(meta?.annotations ? { annotations: meta.annotations } : {}),
  };
}

function toResource(kind: string, defaultApiVersion: string, obj: K8sObject): ParsedResource {
  const metadata = extractMetadata(obj.metadata);
  const ns = metadata.namespace ?? 'default';

  return {
    kind,
    apiVersion: obj.apiVersion ?? defaultApiVersion,
    metadata,
    spec: (obj.spec ?? {}) as Record<string, unknown>,
    file: clusterFileRef(ns, kind, metadata.name),
    line: 0,
  };
}

function wrapApiError(resource: string, err: unknown): Error {
  const msg = err instanceof Error ? err.message : String(err);
  return new Error(`Failed to fetch ${resource} from cluster: ${msg}`);
}
