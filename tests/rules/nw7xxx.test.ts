import { describe, it, expect } from 'vitest';
import { nw7xxxRules, detectCloudProvider } from '../../src/rules/nw7xxx.js';
import type { ParsedResource, AnalysisContext } from '../../src/types.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

function makeSvc(
  name: string,
  annotations: Record<string, string>,
  svcType = 'LoadBalancer',
  namespace = 'default',
): ParsedResource {
  return {
    kind: 'Service',
    apiVersion: 'v1',
    metadata: { name, namespace, annotations },
    spec: { type: svcType },
    file: 'svc.yaml',
    line: 1,
  };
}

function makeIngress(
  name: string,
  annotations: Record<string, string>,
  extraSpec: Record<string, unknown> = {},
  namespace = 'default',
): ParsedResource {
  return {
    kind: 'Ingress',
    apiVersion: 'networking.k8s.io/v1',
    metadata: { name, namespace, annotations },
    spec: { ...extraSpec },
    file: 'ingress.yaml',
    line: 1,
  };
}

function makeBackendConfig(
  name: string,
  spec: Record<string, unknown>,
  namespace = 'default',
): ParsedResource {
  return {
    kind: 'BackendConfig',
    apiVersion: 'cloud.google.com/v1',
    metadata: { name, namespace },
    spec,
    file: 'bc.yaml',
    line: 1,
  };
}

function makeCtx(resources: ParsedResource[]): AnalysisContext {
  return { resources, namespaces: new Set(['default']) };
}

function ruleById(id: string) {
  const rule = nw7xxxRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

// ─── detectCloudProvider ─────────────────────────────────────────────────────

describe('detectCloudProvider', () => {
  it('returns aws when resource has aws-load-balancer annotation', () => {
    const r = makeSvc('lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    expect(detectCloudProvider([r])).toBe('aws');
  });

  it('returns aws when Ingress has alb class', () => {
    const r = makeIngress('alb', { 'kubernetes.io/ingress.class': 'alb' });
    expect(detectCloudProvider([r])).toBe('aws');
  });

  it('returns gcp when resource has cloud.google.com annotation', () => {
    const r = makeSvc('lb', { 'cloud.google.com/backend-config': '{}' });
    expect(detectCloudProvider([r])).toBe('gcp');
  });

  it('returns gcp when Ingress has gce class', () => {
    const r = makeIngress('gce', { 'kubernetes.io/ingress.class': 'gce' });
    expect(detectCloudProvider([r])).toBe('gcp');
  });

  it('returns azure when resource has azure annotation', () => {
    const r = makeSvc('lb', { 'service.beta.kubernetes.io/azure-load-balancer-internal': 'true' });
    expect(detectCloudProvider([r])).toBe('azure');
  });

  it('returns azure when Ingress has azure/application-gateway class', () => {
    const r = makeIngress('agic', { 'kubernetes.io/ingress.class': 'azure/application-gateway' });
    expect(detectCloudProvider([r])).toBe('azure');
  });

  it('returns unknown when no cloud annotations are present', () => {
    const r = makeSvc('plain', {});
    expect(detectCloudProvider([r])).toBe('unknown');
  });

  it('aws takes precedence when both aws and gcp resources present', () => {
    const aws = makeSvc('aws-lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const gcp = makeSvc('gcp-lb', { 'cloud.google.com/load-balancer-type': 'Internal' });
    // aws resource is first
    expect(detectCloudProvider([aws, gcp])).toBe('aws');
  });
});

// ─── NW7001 ──────────────────────────────────────────────────────────────────

describe('NW7001 — AWS NLB without internal annotation', () => {
  const rule = ruleById('NW7001');

  it('fires when NLB type with no internal annotation', () => {
    const r = makeSvc('api-nlb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7001');
    expect(findings[0].severity).toBe('medium');
  });

  it('does not fire when aws-load-balancer-internal: "true"', () => {
    const r = makeSvc('internal-nlb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-internal': 'true',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when scheme: internal', () => {
    const r = makeSvc('internal-nlb-scheme', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-scheme': 'internal',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when LB type is not nlb or external', () => {
    const r = makeSvc('classic-lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'elb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-AWS Service', () => {
    const r = makeSvc('plain-lb', {});
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-LoadBalancer Service type', () => {
    const r = makeSvc('cluster-ip', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' }, 'ClusterIP');
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7002 ──────────────────────────────────────────────────────────────────

describe('NW7002 — AWS LB access logs disabled', () => {
  const rule = ruleById('NW7002');

  it('fires when access-log-enabled: "false"', () => {
    const r = makeSvc('lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-access-log-enabled': 'false',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7002');
    expect(findings[0].severity).toBe('high');
  });

  it('does not fire when access logs enabled', () => {
    const r = makeSvc('lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-access-log-enabled': 'true',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when annotation is absent (not explicitly disabled)', () => {
    const r = makeSvc('lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-AWS resource', () => {
    const r = makeSvc('lb', { 'service.beta.kubernetes.io/azure-load-balancer-internal': 'true' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7003 ──────────────────────────────────────────────────────────────────

describe('NW7003 — Public AWS LB without SSL cert', () => {
  const rule = ruleById('NW7003');

  it('fires for public AWS LB without ssl-cert annotation', () => {
    const r = makeSvc('public-lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7003');
    expect(findings[0].severity).toBe('medium');
  });

  it('does not fire when ssl-cert annotation is set', () => {
    const r = makeSvc('public-lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-ssl-cert': 'arn:aws:acm:us-east-1:123:certificate/abc',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for internal LB (no public exposure)', () => {
    const r = makeSvc('internal-lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-internal': 'true',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7004 ──────────────────────────────────────────────────────────────────

describe('NW7004 — AWS LB with SSL cert but no TLS policy', () => {
  const rule = ruleById('NW7004');

  it('fires when ssl-cert is set but no negotiation policy', () => {
    const r = makeSvc('lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-ssl-cert': 'arn:aws:acm:us-east-1:123:certificate/abc',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7004');
    expect(findings[0].severity).toBe('info');
  });

  it('does not fire when both ssl-cert and negotiation policy are set', () => {
    const r = makeSvc('lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-ssl-cert': 'arn:aws:acm:us-east-1:123:certificate/abc',
      'service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy': 'ELBSecurityPolicy-TLS13-1-2-2021-06',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when no ssl-cert is set (TLS not configured)', () => {
    const r = makeSvc('lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7005 ──────────────────────────────────────────────────────────────────

describe('NW7005 — ALB Ingress without scheme annotation', () => {
  const rule = ruleById('NW7005');

  it('fires for ALB Ingress with no scheme annotation', () => {
    const r = makeIngress('alb-ingress', { 'kubernetes.io/ingress.class': 'alb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7005');
    expect(findings[0].severity).toBe('medium');
  });

  it('fires for ALB Ingress with scheme: internet-facing', () => {
    const r = makeIngress('alb-ingress', {
      'kubernetes.io/ingress.class': 'alb',
      'alb.ingress.kubernetes.io/scheme': 'internet-facing',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
  });

  it('does not fire for ALB Ingress with scheme: internal', () => {
    const r = makeIngress('internal-alb', {
      'kubernetes.io/ingress.class': 'alb',
      'alb.ingress.kubernetes.io/scheme': 'internal',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for nginx Ingress', () => {
    const r = makeIngress('nginx-ingress', { 'kubernetes.io/ingress.class': 'nginx' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for gce Ingress', () => {
    const r = makeIngress('gce-ingress', { 'kubernetes.io/ingress.class': 'gce' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7006 ──────────────────────────────────────────────────────────────────

describe('NW7006 — ALB Ingress without security group', () => {
  const rule = ruleById('NW7006');

  it('fires when ALB Ingress has no security-groups annotation', () => {
    const r = makeIngress('alb-ingress', {
      'kubernetes.io/ingress.class': 'alb',
      'alb.ingress.kubernetes.io/scheme': 'internet-facing',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7006');
    expect(findings[0].severity).toBe('high');
  });

  it('does not fire when security-groups annotation is set', () => {
    const r = makeIngress('alb-ingress', {
      'kubernetes.io/ingress.class': 'alb',
      'alb.ingress.kubernetes.io/security-groups': 'sg-0abc123def456',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-ALB Ingress', () => {
    const r = makeIngress('nginx-ingress', { 'kubernetes.io/ingress.class': 'nginx' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7007 ──────────────────────────────────────────────────────────────────

describe('NW7007 — ALB Ingress TLS without ssl-policy', () => {
  const rule = ruleById('NW7007');

  it('fires for ALB Ingress with TLS but no ssl-policy', () => {
    const r = makeIngress(
      'alb-tls',
      { 'kubernetes.io/ingress.class': 'alb' },
      { tls: [{ secretName: 'my-tls' }] },
    );
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7007');
    expect(findings[0].severity).toBe('low');
  });

  it('does not fire when ssl-policy is set', () => {
    const r = makeIngress(
      'alb-tls-policy',
      {
        'kubernetes.io/ingress.class': 'alb',
        'alb.ingress.kubernetes.io/ssl-policy': 'ELBSecurityPolicy-TLS13-1-2-2021-06',
      },
      { tls: [{ secretName: 'my-tls' }] },
    );
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when Ingress has no TLS (policy is only relevant with TLS)', () => {
    const r = makeIngress('alb-no-tls', { 'kubernetes.io/ingress.class': 'alb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7008 ──────────────────────────────────────────────────────────────────

describe('NW7008 — AWS LB connection draining disabled', () => {
  const rule = ruleById('NW7008');

  it('fires when connection-draining-enabled: "false"', () => {
    const r = makeSvc('lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled': 'false',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7008');
    expect(findings[0].severity).toBe('info');
  });

  it('does not fire when draining is enabled', () => {
    const r = makeSvc('lb', {
      'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb',
      'service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled': 'true',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when annotation is absent', () => {
    const r = makeSvc('lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7009 ──────────────────────────────────────────────────────────────────

describe('NW7009 — GKE LB without internal annotation', () => {
  const rule = ruleById('NW7009');

  it('fires for GKE LB without internal type annotation', () => {
    const r = makeSvc('gke-lb', { 'cloud.google.com/backend-config': '{"default":"bc"}' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7009');
    expect(findings[0].severity).toBe('medium');
  });

  it('does not fire when networking.gke.io/load-balancer-type: Internal', () => {
    const r = makeSvc('gke-internal', {
      'cloud.google.com/backend-config': '{"default":"bc"}',
      'networking.gke.io/load-balancer-type': 'Internal',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when cloud.google.com/load-balancer-type: Internal', () => {
    const r = makeSvc('gke-internal', {
      'cloud.google.com/backend-config': '{"default":"bc"}',
      'cloud.google.com/load-balancer-type': 'Internal',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-GCP resource', () => {
    const r = makeSvc('plain-lb', {});
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for AWS resource', () => {
    const r = makeSvc('aws-lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7010 ──────────────────────────────────────────────────────────────────

describe('NW7010 — GCE Ingress HTTP not disabled', () => {
  const rule = ruleById('NW7010');

  it('fires for gce Ingress without allow-http: false', () => {
    const r = makeIngress('gce-ingress', { 'kubernetes.io/ingress.class': 'gce' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7010');
    expect(findings[0].severity).toBe('medium');
  });

  it('fires when allow-http is set to "true"', () => {
    const r = makeIngress('gce-ingress', {
      'kubernetes.io/ingress.class': 'gce',
      'kubernetes.io/ingress.allow-http': 'true',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
  });

  it('does not fire when allow-http: "false"', () => {
    const r = makeIngress('gce-ingress', {
      'kubernetes.io/ingress.class': 'gce',
      'kubernetes.io/ingress.allow-http': 'false',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-GCE Ingress', () => {
    const r = makeIngress('nginx-ingress', { 'kubernetes.io/ingress.class': 'nginx' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('fires for gce-internal ingress class as well', () => {
    const r = makeIngress('gce-internal-ingress', { 'kubernetes.io/ingress.class': 'gce-internal' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
  });
});

// ─── NW7011 ──────────────────────────────────────────────────────────────────

describe('NW7011 — GKE LB without load-balancer-type annotation', () => {
  const rule = ruleById('NW7011');

  it('fires for GKE LB missing both type annotations', () => {
    const r = makeSvc('gke-lb', { 'cloud.google.com/backend-config': '{"default":"bc"}' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7011');
    expect(findings[0].severity).toBe('info');
  });

  it('does not fire when cloud.google.com/load-balancer-type is set', () => {
    const r = makeSvc('gke-lb', {
      'cloud.google.com/backend-config': '{"default":"bc"}',
      'cloud.google.com/load-balancer-type': 'Internal',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when networking.gke.io/load-balancer-type is set', () => {
    const r = makeSvc('gke-lb', {
      'cloud.google.com/backend-config': '{"default":"bc"}',
      'networking.gke.io/load-balancer-type': 'Internal',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-GCP resource', () => {
    const r = makeSvc('plain-lb', {});
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7012 ──────────────────────────────────────────────────────────────────

describe('NW7012 — GKE BackendConfig without Cloud Armor', () => {
  const rule = ruleById('NW7012');

  it('fires for BackendConfig with no securityPolicy', () => {
    const r = makeBackendConfig('bc', { timeoutSec: 30 });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7012');
    expect(findings[0].severity).toBe('medium');
  });

  it('does not fire when securityPolicy is set', () => {
    const r = makeBackendConfig('bc', { securityPolicy: { name: 'my-armor-policy' } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-GCP BackendConfig apiVersion', () => {
    const r: ParsedResource = {
      kind: 'BackendConfig',
      apiVersion: 'extensions/v1beta1', // wrong API group
      metadata: { name: 'bc', namespace: 'default' },
      spec: { timeoutSec: 30 },
      file: 'bc.yaml',
      line: 1,
    };
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7013 ──────────────────────────────────────────────────────────────────

describe('NW7013 — AKS LB explicitly internet-facing', () => {
  const rule = ruleById('NW7013');

  it('fires when azure-load-balancer-internal: "false"', () => {
    const r = makeSvc('aks-lb', { 'service.beta.kubernetes.io/azure-load-balancer-internal': 'false' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7013');
    expect(findings[0].severity).toBe('medium');
  });

  it('does not fire when azure-load-balancer-internal: "true"', () => {
    const r = makeSvc('aks-lb', { 'service.beta.kubernetes.io/azure-load-balancer-internal': 'true' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when annotation is absent', () => {
    const r = makeSvc('aks-lb', { 'service.beta.kubernetes.io/azure-load-balancer-resource-group': 'rg' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-Azure resource', () => {
    const r = makeSvc('plain-lb', {});
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7014 ──────────────────────────────────────────────────────────────────

describe('NW7014 — AKS LB without internal annotation', () => {
  const rule = ruleById('NW7014');

  it('fires for Azure LB without internal annotation', () => {
    const r = makeSvc('aks-lb', { 'service.beta.kubernetes.io/azure-load-balancer-resource-group': 'rg' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7014');
    expect(findings[0].severity).toBe('info');
  });

  it('does not fire when internal annotation is set', () => {
    const r = makeSvc('aks-lb', {
      'service.beta.kubernetes.io/azure-load-balancer-resource-group': 'rg',
      'service.beta.kubernetes.io/azure-load-balancer-internal': 'true',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-Azure resource (no azure annotations)', () => {
    const r = makeSvc('plain-lb', {});
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for GKE resource', () => {
    const r = makeSvc('gke-lb', { 'cloud.google.com/backend-config': '{"default":"bc"}' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for AWS resource', () => {
    const r = makeSvc('aws-lb', { 'service.beta.kubernetes.io/aws-load-balancer-type': 'nlb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW7015 ──────────────────────────────────────────────────────────────────

describe('NW7015 — Azure App Gateway Ingress without WAF', () => {
  const rule = ruleById('NW7015');

  it('fires for AGIC Ingress without WAF annotation', () => {
    const r = makeIngress('agic', { 'kubernetes.io/ingress.class': 'azure/application-gateway' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW7015');
    expect(findings[0].severity).toBe('medium');
  });

  it('does not fire when appgw waf-policy-for-path is set', () => {
    const r = makeIngress('agic', {
      'kubernetes.io/ingress.class': 'azure/application-gateway',
      'appgw.ingress.kubernetes.io/waf-policy-for-path': '/subscriptions/sub/rg/providers/waf-policy',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when azure.application-gateway/waf-policy-id is set', () => {
    const r = makeIngress('agic', {
      'kubernetes.io/ingress.class': 'azure/application-gateway',
      'azure.application-gateway/waf-policy-id': '/subscriptions/sub/rg/providers/waf-policy',
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-AGIC Ingress', () => {
    const r = makeIngress('nginx', { 'kubernetes.io/ingress.class': 'nginx' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for ALB Ingress', () => {
    const r = makeIngress('alb', { 'kubernetes.io/ingress.class': 'alb' });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── Export count sanity check ────────────────────────────────────────────────

describe('nw7xxxRules exports', () => {
  it('exports exactly 15 rules', () => {
    expect(nw7xxxRules).toHaveLength(15);
  });

  it('all rule IDs match NW7xxx pattern', () => {
    for (const rule of nw7xxxRules) {
      expect(rule.id).toMatch(/^NW7\d{3}$/);
    }
  });

  it('all rules have non-empty descriptions', () => {
    for (const rule of nw7xxxRules) {
      expect(rule.description.length).toBeGreaterThan(0);
    }
  });

  it('covers all three cloud providers', () => {
    const ids = nw7xxxRules.map((r) => r.id);
    // AWS: NW7001–NW7008
    expect(ids).toContain('NW7001');
    expect(ids).toContain('NW7008');
    // GCP: NW7009–NW7012
    expect(ids).toContain('NW7009');
    expect(ids).toContain('NW7012');
    // Azure: NW7013–NW7015
    expect(ids).toContain('NW7013');
    expect(ids).toContain('NW7015');
  });
});
