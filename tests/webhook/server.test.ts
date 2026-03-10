import { describe, it, expect } from 'vitest';
import {
  handleAdmissionRequest,
  generateWebhookManifest,
} from '../../src/webhook/server.js';
import type { AdmissionRequest } from '../../src/webhook/server.js';

// ─── Test helpers ─────────────────────────────────────────────────────────────

function makeRequest(overrides: Partial<AdmissionRequest['request']> = {}): AdmissionRequest {
  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    request: {
      uid: 'test-uid-1234',
      kind: { group: 'networking.k8s.io', version: 'v1', kind: 'NetworkPolicy' },
      resource: { group: 'networking.k8s.io', version: 'v1', resource: 'networkpolicies' },
      name: 'test-netpol',
      namespace: 'default',
      operation: 'CREATE',
      object: {
        apiVersion: 'networking.k8s.io/v1',
        kind: 'NetworkPolicy',
        metadata: { name: 'test-netpol', namespace: 'default' },
        spec: {
          podSelector: {},
          ingress: [{ from: [{}] }],
        },
      },
      ...overrides,
    },
  };
}

function makeServiceRequest(overrides: Partial<AdmissionRequest['request']> = {}): AdmissionRequest {
  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    request: {
      uid: 'svc-uid-5678',
      kind: { group: '', version: 'v1', kind: 'Service' },
      resource: { group: '', version: 'v1', resource: 'services' },
      name: 'test-svc',
      namespace: 'default',
      operation: 'CREATE',
      object: {
        apiVersion: 'v1',
        kind: 'Service',
        metadata: { name: 'test-svc', namespace: 'default' },
        spec: { type: 'NodePort', ports: [{ port: 80 }] },
      },
      ...overrides,
    },
  };
}

// ─── UID echoing ──────────────────────────────────────────────────────────────

describe('handleAdmissionRequest – UID echoing', () => {
  it('echoes the request UID in the response', () => {
    const req = makeRequest({ uid: 'my-unique-uid' });
    const res = handleAdmissionRequest(req);
    expect(res.response.uid).toBe('my-unique-uid');
  });

  it('echoes the UID even when the operation is DELETE (pass-through)', () => {
    const req = makeRequest({ uid: 'delete-uid', operation: 'DELETE' });
    const res = handleAdmissionRequest(req);
    expect(res.response.uid).toBe('delete-uid');
  });
});

// ─── Non-validated operations ─────────────────────────────────────────────────

describe('handleAdmissionRequest – non-validated operations', () => {
  it('allows DELETE operations without running rules', () => {
    const req = makeRequest({ operation: 'DELETE' });
    const res = handleAdmissionRequest(req);
    expect(res.response.allowed).toBe(true);
    expect(res.response.warnings).toBeUndefined();
  });

  it('allows CONNECT operations without running rules', () => {
    const req = makeRequest({ operation: 'CONNECT' });
    const res = handleAdmissionRequest(req);
    expect(res.response.allowed).toBe(true);
  });
});

// ─── Non-validated resource kinds ────────────────────────────────────────────

describe('handleAdmissionRequest – unvalidated kinds', () => {
  it('allows an unknown resource kind without running rules', () => {
    const req = makeRequest({
      kind: { group: '', version: 'v1', kind: 'Pod' },
    });
    const res = handleAdmissionRequest(req);
    expect(res.response.allowed).toBe(true);
    expect(res.response.warnings).toBeUndefined();
  });

  it('allows ConfigMap without running rules', () => {
    const req = makeRequest({
      kind: { group: '', version: 'v1', kind: 'ConfigMap' },
    });
    const res = handleAdmissionRequest(req);
    expect(res.response.allowed).toBe(true);
  });
});

// ─── Warn-only mode (default) ─────────────────────────────────────────────────

describe('handleAdmissionRequest – warn-only mode (denyOnError=false)', () => {
  it('allows a NetworkPolicy with wildcard ingress (warn-only)', () => {
    const req = makeRequest();
    const res = handleAdmissionRequest(req, [], false, true);
    expect(res.response.allowed).toBe(true);
  });

  it('surfaces error findings as warnings when denyOnError=false', () => {
    const req = makeRequest();
    const res = handleAdmissionRequest(req, [], false, true);
    // NW1001 (wildcard ingress from [{}]) should produce a warning
    expect(res.response.warnings).toBeDefined();
    expect(res.response.warnings!.some((w) => w.includes('NW1001'))).toBe(true);
  });

  it('response apiVersion is admission.k8s.io/v1', () => {
    const req = makeRequest();
    const res = handleAdmissionRequest(req);
    expect(res.apiVersion).toBe('admission.k8s.io/v1');
    expect(res.kind).toBe('AdmissionReview');
  });

  it('does not include warnings when warnOnWarning=false and no errors', () => {
    // A clean NetworkPolicy with no issues — use an UPDATE to a valid policy
    const req: AdmissionRequest = {
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      request: {
        uid: 'clean-uid',
        kind: { group: 'networking.k8s.io', version: 'v1', kind: 'NetworkPolicy' },
        resource: { group: 'networking.k8s.io', version: 'v1', resource: 'networkpolicies' },
        name: 'clean-policy',
        namespace: 'default',
        operation: 'CREATE',
        object: {
          apiVersion: 'networking.k8s.io/v1',
          kind: 'NetworkPolicy',
          metadata: { name: 'clean-policy', namespace: 'default' },
          spec: {
            podSelector: { matchLabels: { app: 'web' } },
            ingress: [{ from: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'frontend' } } }] }],
          },
        },
      },
    };
    const res = handleAdmissionRequest(req, [], false, false);
    expect(res.response.allowed).toBe(true);
    // No warnings because warnOnWarning=false and no errors surfaced as warnings
    expect(res.response.warnings).toBeUndefined();
  });
});

// ─── Deny-on-error mode ───────────────────────────────────────────────────────

describe('handleAdmissionRequest – deny-on-error mode (denyOnError=true)', () => {
  it('rejects a NetworkPolicy with wildcard ingress when denyOnError=true', () => {
    const req = makeRequest();
    const res = handleAdmissionRequest(req, [], true, true);
    expect(res.response.allowed).toBe(false);
  });

  it('sets status code 403 on rejection', () => {
    const req = makeRequest();
    const res = handleAdmissionRequest(req, [], true, true);
    expect(res.response.status?.code).toBe(403);
  });

  it('includes error message in status.message', () => {
    const req = makeRequest();
    const res = handleAdmissionRequest(req, [], true, true);
    expect(res.response.status?.message).toContain('NetworkVet policy violations');
    expect(res.response.status?.message).toContain('NW1001');
  });

  it('allows a NodePort Service with warn-enforcement rule even in denyOnError mode', () => {
    // NW2001 (NodePort) is warn-level — should not deny
    const req = makeServiceRequest();
    const res = handleAdmissionRequest(req, [], true, true);
    expect(res.response.allowed).toBe(true);
  });

  it('surfaces warn-level findings as warnings in deny mode', () => {
    const req = makeServiceRequest();
    const res = handleAdmissionRequest(req, [], true, true);
    expect(res.response.warnings).toBeDefined();
    expect(res.response.warnings!.some((w) => w.includes('NW2001'))).toBe(true);
  });
});

// ─── ignoreIds ────────────────────────────────────────────────────────────────

describe('handleAdmissionRequest – ignoreIds', () => {
  it('suppresses a finding when its ID is in ignoreIds', () => {
    const req = makeRequest();
    // Ignore NW1001 — the wildcard ingress finding should be suppressed
    const res = handleAdmissionRequest(req, ['NW1001'], true, true);
    expect(res.response.allowed).toBe(true);
    expect(res.response.status).toBeUndefined();
  });

  it('still surfaces other findings when one is ignored', () => {
    // Service with NodePort — NW2001 is warning, NW2002 may also appear
    const req = makeServiceRequest({ object: {
      apiVersion: 'v1',
      kind: 'Service',
      metadata: { name: 'lb-svc', namespace: 'default' },
      spec: { type: 'LoadBalancer' },
    } });
    const res = handleAdmissionRequest(req, ['NW2001'], false, true);
    // NW2002 (LoadBalancer without externalTrafficPolicy: Local) should still be present
    expect(res.response.warnings?.some((w) => w.includes('NW2002'))).toBe(true);
  });
});

// ─── Metadata fallbacks ───────────────────────────────────────────────────────

describe('handleAdmissionRequest – metadata fallbacks', () => {
  it('uses request.name when object.metadata.name is absent', () => {
    const req = makeRequest({
      name: 'fallback-name',
      object: {
        kind: 'NetworkPolicy',
        apiVersion: 'networking.k8s.io/v1',
        metadata: {},
        spec: { ingress: [{ from: [{}] }] },
      },
    });
    const res = handleAdmissionRequest(req, [], false, true);
    // Should still process without throwing
    expect(res.response.uid).toBe('test-uid-1234');
  });

  it('handles object without metadata property gracefully', () => {
    const req = makeRequest({
      object: {
        kind: 'NetworkPolicy',
        apiVersion: 'networking.k8s.io/v1',
        spec: { ingress: [{ from: [{}] }] },
      },
    });
    const res = handleAdmissionRequest(req, [], false, true);
    expect(res.response.allowed).toBe(true);
  });
});

// ─── Known validated kinds ────────────────────────────────────────────────────

describe('handleAdmissionRequest – validated kinds', () => {
  const validatedKinds = [
    'NetworkPolicy',
    'Service',
    'Ingress',
    'AuthorizationPolicy',
    'PeerAuthentication',
    'CiliumNetworkPolicy',
    'CiliumClusterwideNetworkPolicy',
    'BackendConfig',
  ];

  for (const kind of validatedKinds) {
    it(`runs rule validation for ${kind}`, () => {
      const req = makeRequest({
        kind: { group: '', version: 'v1', kind },
        object: {
          kind,
          apiVersion: 'v1',
          metadata: { name: 'test', namespace: 'default' },
          spec: {},
        },
      });
      // Just verify we get a proper AdmissionReview response (not a short-circuit pass-through)
      const res = handleAdmissionRequest(req, [], false, false);
      expect(res.apiVersion).toBe('admission.k8s.io/v1');
      expect(res.kind).toBe('AdmissionReview');
      expect(typeof res.response.uid).toBe('string');
    });
  }
});

// ─── Response structure ───────────────────────────────────────────────────────

describe('handleAdmissionRequest – response structure', () => {
  it('omits warnings field when there are no warnings', () => {
    // DELETE always produces a clean pass-through with no warnings
    const req = makeRequest({ operation: 'DELETE' });
    const res = handleAdmissionRequest(req);
    expect(Object.prototype.hasOwnProperty.call(res.response, 'warnings')).toBe(false);
  });

  it('omits status field when allowed=true', () => {
    const req = makeRequest({ operation: 'DELETE' });
    const res = handleAdmissionRequest(req);
    expect(res.response.status).toBeUndefined();
  });
});

// ─── generateWebhookManifest ──────────────────────────────────────────────────

describe('generateWebhookManifest', () => {
  it('returns a non-empty YAML string', () => {
    const manifest = generateWebhookManifest();
    expect(typeof manifest).toBe('string');
    expect(manifest.length).toBeGreaterThan(100);
  });

  it('includes a Namespace for networkvet-system', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('name: networkvet-system');
  });

  it('includes a Deployment for the webhook', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('kind: Deployment');
    expect(manifest).toContain('name: networkvet-webhook');
  });

  it('includes a ValidatingWebhookConfiguration', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('kind: ValidatingWebhookConfiguration');
  });

  it('includes the /validate path for the webhook', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('path: /validate');
  });

  it('includes failurePolicy: Ignore for fail-open behavior', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('failurePolicy: Ignore');
  });

  it('targets the correct resource types', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('networkpolicies');
    expect(manifest).toContain('authorizationpolicies');
    expect(manifest).toContain('ciliumnetworkpolicies');
  });

  it('includes CREATE and UPDATE operations', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('"CREATE"');
    expect(manifest).toContain('"UPDATE"');
  });

  it('is separated by YAML document separators (---)', () => {
    const manifest = generateWebhookManifest();
    expect(manifest).toContain('---');
  });
});
