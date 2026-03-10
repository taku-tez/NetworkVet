import { describe, it, expect, vi, beforeEach } from 'vitest';

// -------------------------------------------------------------------------
// Mock @kubernetes/client-node before any imports that use it
// -------------------------------------------------------------------------

const mockListNamespacedNetworkPolicy = vi.fn();
const mockListNetworkPolicyForAllNamespaces = vi.fn();
const mockListNamespacedService = vi.fn();
const mockListServiceForAllNamespaces = vi.fn();
const mockListNamespacedIngress = vi.fn();
const mockListIngressForAllNamespaces = vi.fn();
const mockListNamespacedEndpoints = vi.fn();
const mockListEndpointsForAllNamespaces = vi.fn();
const mockListNamespace = vi.fn();
const mockListNamespacedDaemonSet = vi.fn();

const mockMakeApiClient = vi.fn();
const mockLoadFromDefault = vi.fn();
const mockSetCurrentContext = vi.fn();
const mockGetCurrentContext = vi.fn().mockReturnValue('test-context');
const mockGetContextObject = vi.fn().mockReturnValue({ namespace: 'default' });
const mockGetContexts = vi.fn().mockReturnValue([{ name: 'test-context' }, { name: 'prod-context' }]);

vi.mock('@kubernetes/client-node', () => {
  class MockCoreV1Api {
    listNamespacedService = mockListNamespacedService;
    listServiceForAllNamespaces = mockListServiceForAllNamespaces;
    listNamespacedEndpoints = mockListNamespacedEndpoints;
    listEndpointsForAllNamespaces = mockListEndpointsForAllNamespaces;
    listNamespace = mockListNamespace;
  }
  class MockNetworkingV1Api {
    listNamespacedNetworkPolicy = mockListNamespacedNetworkPolicy;
    listNetworkPolicyForAllNamespaces = mockListNetworkPolicyForAllNamespaces;
    listNamespacedIngress = mockListNamespacedIngress;
    listIngressForAllNamespaces = mockListIngressForAllNamespaces;
  }
  class MockAppsV1Api {
    listNamespacedDaemonSet = mockListNamespacedDaemonSet;
  }

  class MockKubeConfig {
    loadFromDefault = mockLoadFromDefault;
    setCurrentContext = mockSetCurrentContext;
    getCurrentContext = mockGetCurrentContext;
    getContextObject = mockGetContextObject;
    getContexts = mockGetContexts;
    makeApiClient = mockMakeApiClient;
  }

  return {
    KubeConfig: MockKubeConfig,
    CoreV1Api: MockCoreV1Api,
    NetworkingV1Api: MockNetworkingV1Api,
    AppsV1Api: MockAppsV1Api,
  };
});

// Stub makeApiClient to return appropriate mock API based on the class passed
mockMakeApiClient.mockImplementation((ApiClass: new () => unknown) => {
  const name = (ApiClass as { name?: string }).name ?? '';
  if (name === 'MockCoreV1Api') {
    return {
      listNamespacedService: mockListNamespacedService,
      listServiceForAllNamespaces: mockListServiceForAllNamespaces,
      listNamespacedEndpoints: mockListNamespacedEndpoints,
      listEndpointsForAllNamespaces: mockListEndpointsForAllNamespaces,
      listNamespace: mockListNamespace,
    };
  }
  if (name === 'MockNetworkingV1Api') {
    return {
      listNamespacedNetworkPolicy: mockListNamespacedNetworkPolicy,
      listNetworkPolicyForAllNamespaces: mockListNetworkPolicyForAllNamespaces,
      listNamespacedIngress: mockListNamespacedIngress,
      listIngressForAllNamespaces: mockListIngressForAllNamespaces,
    };
  }
  if (name === 'MockAppsV1Api') {
    return {
      listNamespacedDaemonSet: mockListNamespacedDaemonSet,
    };
  }
  return {};
});

// Import ClusterClient AFTER mock setup
import { ClusterClient } from '../../src/cluster/client.js';

// -------------------------------------------------------------------------
// Helpers to build mock K8s API response objects
// -------------------------------------------------------------------------

function makeNPResponse(items: object[]) {
  return { items };
}
function makeSvcResponse(items: object[]) {
  return { items };
}
function makeIngressResponse(items: object[]) {
  return { items };
}
function makeEndpointsResponse(items: object[]) {
  return { items };
}
function makeNsResponse(items: object[]) {
  return { items };
}
function makeDsResponse(items: object[]) {
  return { items };
}

const mockNetworkPolicy = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'NetworkPolicy',
  metadata: { name: 'deny-all', namespace: 'production', labels: { env: 'prod' } },
  spec: {
    podSelector: {},
    policyTypes: ['Ingress', 'Egress'],
  },
};

const mockService = {
  apiVersion: 'v1',
  kind: 'Service',
  metadata: { name: 'web-svc', namespace: 'production' },
  spec: { type: 'ClusterIP', ports: [{ port: 80 }] },
};

const mockIngress = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'Ingress',
  metadata: { name: 'web-ingress', namespace: 'production', annotations: { 'nginx.ingress.kubernetes.io/ssl-redirect': 'true' } },
  spec: { tls: [{ hosts: ['example.com'], secretName: 'tls-secret' }], rules: [{ host: 'example.com' }] },
};

const mockEndpoints = {
  apiVersion: 'v1',
  kind: 'Endpoints',
  metadata: { name: 'web-svc', namespace: 'production' },
};

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

describe('ClusterClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadFromDefault.mockImplementation(() => undefined);
    mockSetCurrentContext.mockImplementation(() => undefined);
    mockGetCurrentContext.mockReturnValue('test-context');
    mockGetContextObject.mockReturnValue({ namespace: 'default' });
    mockGetContexts.mockReturnValue([{ name: 'test-context' }, { name: 'prod-context' }]);
    mockMakeApiClient.mockImplementation((ApiClass: new () => unknown) => {
      const name = (ApiClass as { name?: string }).name ?? '';
      if (name === 'MockCoreV1Api') {
        return {
          listNamespacedService: mockListNamespacedService,
          listServiceForAllNamespaces: mockListServiceForAllNamespaces,
          listNamespacedEndpoints: mockListNamespacedEndpoints,
          listEndpointsForAllNamespaces: mockListEndpointsForAllNamespaces,
          listNamespace: mockListNamespace,
        };
      }
      if (name === 'MockNetworkingV1Api') {
        return {
          listNamespacedNetworkPolicy: mockListNamespacedNetworkPolicy,
          listNetworkPolicyForAllNamespaces: mockListNetworkPolicyForAllNamespaces,
          listNamespacedIngress: mockListNamespacedIngress,
          listIngressForAllNamespaces: mockListIngressForAllNamespaces,
        };
      }
      if (name === 'MockAppsV1Api') {
        return {
          listNamespacedDaemonSet: mockListNamespacedDaemonSet,
        };
      }
      return {};
    });
  });

  describe('constructor', () => {
    it('loads kubeconfig from default location', () => {
      new ClusterClient();
      expect(mockLoadFromDefault).toHaveBeenCalledOnce();
    });

    it('throws a descriptive error when kubeconfig fails to load', () => {
      mockLoadFromDefault.mockImplementationOnce(() => {
        throw new Error('no kubeconfig found');
      });
      expect(() => new ClusterClient()).toThrow('Failed to load kubeconfig');
    });

    it('sets context when context argument is provided', () => {
      new ClusterClient('prod-context');
      expect(mockSetCurrentContext).toHaveBeenCalledWith('prod-context');
    });

    it('throws when the specified context does not exist', () => {
      mockSetCurrentContext.mockImplementationOnce(() => {
        throw new Error('context not found');
      });
      expect(() => new ClusterClient('nonexistent-ctx')).toThrow('Context "nonexistent-ctx" not found');
    });

    it('does not call setCurrentContext when no context is given', () => {
      new ClusterClient();
      expect(mockSetCurrentContext).not.toHaveBeenCalled();
    });
  });

  describe('getCurrentContext / getCurrentNamespace', () => {
    it('returns the current context name', () => {
      const client = new ClusterClient();
      expect(client.getCurrentContext()).toBe('test-context');
    });

    it('returns namespace from kubeconfig context', () => {
      mockGetContextObject.mockReturnValueOnce({ namespace: 'payments' });
      const client = new ClusterClient();
      expect(client.getCurrentNamespace()).toBe('payments');
    });

    it('falls back to "default" when namespace not set in context', () => {
      mockGetContextObject.mockReturnValueOnce({ namespace: undefined });
      const client = new ClusterClient();
      expect(client.getCurrentNamespace()).toBe('default');
    });
  });

  describe('listNetworkPolicies', () => {
    it('fetches namespaced NetworkPolicies and converts to ParsedResource', async () => {
      mockListNamespacedNetworkPolicy.mockResolvedValueOnce(makeNPResponse([mockNetworkPolicy]));
      const client = new ClusterClient();
      const resources = await client.listNetworkPolicies('production');
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('NetworkPolicy');
      expect(resources[0].metadata.name).toBe('deny-all');
      expect(resources[0].metadata.namespace).toBe('production');
      expect(resources[0].file).toBe('cluster:production/NetworkPolicy/deny-all');
    });

    it('fetches all-namespace NetworkPolicies when no namespace given', async () => {
      mockListNetworkPolicyForAllNamespaces.mockResolvedValueOnce(makeNPResponse([mockNetworkPolicy]));
      const client = new ClusterClient();
      const resources = await client.listNetworkPolicies();
      expect(mockListNetworkPolicyForAllNamespaces).toHaveBeenCalledOnce();
      expect(resources).toHaveLength(1);
    });

    it('throws descriptive error when API call fails', async () => {
      mockListNamespacedNetworkPolicy.mockRejectedValueOnce(new Error('connection refused'));
      const client = new ClusterClient();
      await expect(client.listNetworkPolicies('default')).rejects.toThrow('Failed to fetch NetworkPolicy');
    });

    it('preserves labels and annotations from K8s metadata', async () => {
      mockListNamespacedNetworkPolicy.mockResolvedValueOnce(makeNPResponse([mockNetworkPolicy]));
      const client = new ClusterClient();
      const resources = await client.listNetworkPolicies('production');
      expect(resources[0].metadata.labels?.['env']).toBe('prod');
    });
  });

  describe('listServices', () => {
    it('fetches namespaced Services', async () => {
      mockListNamespacedService.mockResolvedValueOnce(makeSvcResponse([mockService]));
      const client = new ClusterClient();
      const resources = await client.listServices('production');
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('Service');
      expect(resources[0].metadata.name).toBe('web-svc');
      expect(resources[0].file).toBe('cluster:production/Service/web-svc');
    });

    it('fetches all-namespace Services when no namespace given', async () => {
      mockListServiceForAllNamespaces.mockResolvedValueOnce(makeSvcResponse([mockService]));
      const client = new ClusterClient();
      const resources = await client.listServices();
      expect(mockListServiceForAllNamespaces).toHaveBeenCalledOnce();
      expect(resources).toHaveLength(1);
    });

    it('throws descriptive error when API call fails', async () => {
      mockListServiceForAllNamespaces.mockRejectedValueOnce(new Error('forbidden'));
      const client = new ClusterClient();
      await expect(client.listServices()).rejects.toThrow('Failed to fetch Service');
    });
  });

  describe('listIngresses', () => {
    it('fetches namespaced Ingresses', async () => {
      mockListNamespacedIngress.mockResolvedValueOnce(makeIngressResponse([mockIngress]));
      const client = new ClusterClient();
      const resources = await client.listIngresses('production');
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('Ingress');
      expect(resources[0].metadata.name).toBe('web-ingress');
    });

    it('preserves annotations on Ingress', async () => {
      mockListNamespacedIngress.mockResolvedValueOnce(makeIngressResponse([mockIngress]));
      const client = new ClusterClient();
      const resources = await client.listIngresses('production');
      expect(resources[0].metadata.annotations?.['nginx.ingress.kubernetes.io/ssl-redirect']).toBe('true');
    });

    it('fetches all-namespace Ingresses when no namespace given', async () => {
      mockListIngressForAllNamespaces.mockResolvedValueOnce(makeIngressResponse([mockIngress]));
      const client = new ClusterClient();
      await client.listIngresses();
      expect(mockListIngressForAllNamespaces).toHaveBeenCalledOnce();
    });
  });

  describe('listEndpoints', () => {
    it('fetches namespaced Endpoints', async () => {
      mockListNamespacedEndpoints.mockResolvedValueOnce(makeEndpointsResponse([mockEndpoints]));
      const client = new ClusterClient();
      const resources = await client.listEndpoints('production');
      expect(resources).toHaveLength(1);
      expect(resources[0].kind).toBe('Endpoints');
      expect(resources[0].file).toBe('cluster:production/Endpoints/web-svc');
    });

    it('fetches all-namespace Endpoints when no namespace given', async () => {
      mockListEndpointsForAllNamespaces.mockResolvedValueOnce(makeEndpointsResponse([mockEndpoints]));
      const client = new ClusterClient();
      await client.listEndpoints();
      expect(mockListEndpointsForAllNamespaces).toHaveBeenCalledOnce();
    });
  });

  describe('listNamespaces', () => {
    it('returns list of namespace names', async () => {
      mockListNamespace.mockResolvedValueOnce(
        makeNsResponse([
          { metadata: { name: 'default' } },
          { metadata: { name: 'production' } },
          { metadata: { name: 'kube-system' } },
        ])
      );
      const client = new ClusterClient();
      const namespaces = await client.listNamespaces();
      expect(namespaces).toEqual(['default', 'production', 'kube-system']);
    });

    it('throws descriptive error on API failure', async () => {
      mockListNamespace.mockRejectedValueOnce(new Error('unauthorized'));
      const client = new ClusterClient();
      await expect(client.listNamespaces()).rejects.toThrow('Failed to fetch Namespace');
    });
  });

  describe('detectCNI', () => {
    it('detects Calico from DaemonSet name', async () => {
      mockListNamespacedDaemonSet.mockResolvedValueOnce(
        makeDsResponse([
          { metadata: { name: 'calico-node', namespace: 'kube-system' }, spec: { template: { spec: { containers: [] } } } },
        ])
      );
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBe('calico');
    });

    it('detects Cilium from DaemonSet name', async () => {
      mockListNamespacedDaemonSet.mockResolvedValueOnce(
        makeDsResponse([
          { metadata: { name: 'cilium', namespace: 'kube-system' }, spec: { template: { spec: { containers: [] } } } },
        ])
      );
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBe('cilium');
    });

    it('detects Flannel from DaemonSet name', async () => {
      mockListNamespacedDaemonSet
        .mockResolvedValueOnce(
          makeDsResponse([
            { metadata: { name: 'kube-flannel-ds', namespace: 'kube-system' }, spec: { template: { spec: { containers: [], initContainers: [] } } } },
          ])
        );
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBe('flannel');
    });

    it('detects Kindnet from container image', async () => {
      mockListNamespacedDaemonSet.mockResolvedValueOnce(
        makeDsResponse([
          {
            metadata: { name: 'kindnet', namespace: 'kube-system' },
            spec: {
              template: {
                spec: {
                  containers: [{ image: 'kindest/kindnetd:v20231011-d5167c9e' }],
                  initContainers: [],
                },
              },
            },
          },
        ])
      );
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBe('kindnet');
    });

    it('detects Weave from container image', async () => {
      mockListNamespacedDaemonSet.mockResolvedValueOnce(
        makeDsResponse([
          {
            metadata: { name: 'weave-net', namespace: 'kube-system' },
            spec: {
              template: {
                spec: {
                  containers: [{ image: 'ghcr.io/weaveworks/launcher/weave-kube:2.8.1' }],
                  initContainers: [],
                },
              },
            },
          },
        ])
      );
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBe('weave');
    });

    it('returns null when no known CNI is detected', async () => {
      mockListNamespacedDaemonSet.mockResolvedValueOnce(
        makeDsResponse([
          { metadata: { name: 'kube-proxy', namespace: 'kube-system' }, spec: { template: { spec: { containers: [{ image: 'registry.k8s.io/kube-proxy:v1.28.0' }] } } } },
        ])
      );
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBeNull();
    });

    it('returns null when kube-system API call fails', async () => {
      mockListNamespacedDaemonSet.mockRejectedValueOnce(new Error('forbidden'));
      const client = new ClusterClient();
      const cni = await client.detectCNI();
      expect(cni).toBeNull();
    });
  });

  describe('fetchAll', () => {
    beforeEach(() => {
      mockListNamespacedNetworkPolicy.mockResolvedValue(makeNPResponse([mockNetworkPolicy]));
      mockListNamespacedService.mockResolvedValue(makeSvcResponse([mockService]));
      mockListNamespacedIngress.mockResolvedValue(makeIngressResponse([mockIngress]));
      mockListNamespacedEndpoints.mockResolvedValue(makeEndpointsResponse([mockEndpoints]));
      mockListNetworkPolicyForAllNamespaces.mockResolvedValue(makeNPResponse([mockNetworkPolicy]));
      mockListServiceForAllNamespaces.mockResolvedValue(makeSvcResponse([mockService]));
      mockListIngressForAllNamespaces.mockResolvedValue(makeIngressResponse([mockIngress]));
      mockListEndpointsForAllNamespaces.mockResolvedValue(makeEndpointsResponse([mockEndpoints]));
    });

    it('uses namespaced calls when allNamespaces is false', async () => {
      const client = new ClusterClient();
      const resources = await client.fetchAll(false, 'production');
      expect(mockListNamespacedNetworkPolicy).toHaveBeenCalledWith({ namespace: 'production' });
      expect(mockListNamespacedService).toHaveBeenCalledWith({ namespace: 'production' });
      expect(resources.length).toBeGreaterThan(0);
    });

    it('uses all-namespace calls when allNamespaces is true', async () => {
      const client = new ClusterClient();
      await client.fetchAll(true);
      expect(mockListNetworkPolicyForAllNamespaces).toHaveBeenCalledOnce();
      expect(mockListServiceForAllNamespaces).toHaveBeenCalledOnce();
      expect(mockListIngressForAllNamespaces).toHaveBeenCalledOnce();
      expect(mockListEndpointsForAllNamespaces).toHaveBeenCalledOnce();
    });

    it('returns combined resources from all API calls', async () => {
      const client = new ClusterClient();
      const resources = await client.fetchAll(false, 'production');
      const kinds = resources.map((r) => r.kind);
      expect(kinds).toContain('NetworkPolicy');
      expect(kinds).toContain('Service');
      expect(kinds).toContain('Ingress');
      expect(kinds).toContain('Endpoints');
    });

    it('uses current namespace from kubeconfig when namespace not specified', async () => {
      mockGetContextObject.mockReturnValue({ namespace: 'staging' });
      const client = new ClusterClient();
      await client.fetchAll(false);
      expect(mockListNamespacedNetworkPolicy).toHaveBeenCalledWith({ namespace: 'staging' });
    });

    it('partial failure in one resource type does not crash fetchAll', async () => {
      mockListNamespacedIngress.mockRejectedValueOnce(new Error('not found'));
      const client = new ClusterClient();
      const resources = await client.fetchAll(false, 'production');
      // Should still return NP, Service, Endpoints
      const kinds = resources.map((r) => r.kind);
      expect(kinds).toContain('NetworkPolicy');
      expect(kinds).toContain('Service');
      expect(kinds).not.toContain('Ingress');
    });

    it('sets file to cluster:<ns>/<kind>/<name> format', async () => {
      const client = new ClusterClient();
      const resources = await client.fetchAll(false, 'production');
      expect(resources[0].file).toMatch(/^cluster:/);
    });

    it('sets line to 0 for all cluster resources', async () => {
      const client = new ClusterClient();
      const resources = await client.fetchAll(false, 'production');
      expect(resources.every((r) => r.line === 0)).toBe(true);
    });
  });
});
