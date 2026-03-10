import type { Rule, ParsedResource, AnalysisContext, Finding } from '../types.js';
import { isService, isIngress, getAnnotation, hasAnnotation } from '../types.js';

// ─── Cloud provider detection ─────────────────────────────────────────────────

type CloudProvider = 'aws' | 'gcp' | 'azure' | 'unknown';

const AWS_ANNOTATION_FRAGMENTS = [
  'amazonaws',
  'aws-load-balancer',
  'alb.ingress.kubernetes.io',
  'service.beta.kubernetes.io/aws',
];

const GCP_ANNOTATION_FRAGMENTS = [
  'gke.io',
  'cloud.google.com',
  'networking.gke',
];

const AZURE_ANNOTATION_FRAGMENTS = [
  'azure',
  'application-gateway',
];

/**
 * Infer the cloud provider from annotation keys present across all resources.
 * Returns the first match found, or 'unknown'.
 */
export function detectCloudProvider(resources: ParsedResource[]): CloudProvider {
  for (const r of resources) {
    const keys = Object.keys(r.metadata.annotations ?? {});
    if (keys.some((k) => AWS_ANNOTATION_FRAGMENTS.some((f) => k.includes(f)))) return 'aws';
    if (keys.some((k) => GCP_ANNOTATION_FRAGMENTS.some((f) => k.includes(f)))) return 'gcp';
    if (keys.some((k) => AZURE_ANNOTATION_FRAGMENTS.some((f) => k.includes(f)))) return 'azure';
  }
  // Also check ingress class annotation values
  for (const r of resources) {
    const cls = getAnnotation(r, 'kubernetes.io/ingress.class');
    if (cls === 'alb' || cls === 'nlb') return 'aws';
    if (cls === 'gce' || cls === 'gce-internal') return 'gcp';
    if (cls === 'azure/application-gateway') return 'azure';
  }
  return 'unknown';
}

// ─── Per-resource provider checks ────────────────────────────────────────────

/** Returns true when a resource has any AWS-flavored annotation. */
function isAwsResource(r: ParsedResource): boolean {
  const keys = Object.keys(r.metadata.annotations ?? {});
  if (keys.some((k) => AWS_ANNOTATION_FRAGMENTS.some((f) => k.includes(f)))) return true;
  const cls = getAnnotation(r, 'kubernetes.io/ingress.class');
  return cls === 'alb' || cls === 'nlb';
}

/** Returns true when a resource has any GCP-flavored annotation. */
function isGcpResource(r: ParsedResource): boolean {
  const keys = Object.keys(r.metadata.annotations ?? {});
  if (keys.some((k) => GCP_ANNOTATION_FRAGMENTS.some((f) => k.includes(f)))) return true;
  const cls = getAnnotation(r, 'kubernetes.io/ingress.class');
  return cls === 'gce' || cls === 'gce-internal';
}

/** Returns true when a resource has any Azure-flavored annotation or ingress class. */
function isAzureResource(r: ParsedResource): boolean {
  const keys = Object.keys(r.metadata.annotations ?? {});
  if (keys.some((k) => AZURE_ANNOTATION_FRAGMENTS.some((f) => k.includes(f)))) return true;
  const cls = getAnnotation(r, 'kubernetes.io/ingress.class');
  return cls === 'azure/application-gateway';
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeFinding(
  rule: Pick<Rule, 'id' | 'severity'>,
  r: ParsedResource,
  message: string,
  detail?: string,
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

/** True when the resource is a Service of type LoadBalancer. */
function isLoadBalancerService(r: ParsedResource): boolean {
  if (!isService(r)) return false;
  return r.spec.type === 'LoadBalancer';
}

// ─── AWS rules ────────────────────────────────────────────────────────────────

/**
 * NW7001 — NLB without internal annotation.
 * Fires when the resource itself has an AWS LB type annotation and is not internal.
 */
const nw7001: Rule = {
  id: 'NW7001',
  severity: 'warning',
  description: 'AWS NLB Service has no internal annotation — load balancer may be internet-facing',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAwsResource(r)) continue;

      const lbType = getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-type');
      if (lbType !== 'nlb' && lbType !== 'external') continue;

      const isInternal =
        getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-internal') === 'true' ||
        getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-scheme') === 'internal';

      if (!isInternal) {
        findings.push(makeFinding(
          nw7001,
          r,
          `Service "${r.metadata.name}" uses AWS NLB (aws-load-balancer-type: ${lbType}) without an internal annotation — NLB is internet-facing`,
          'Add annotation service.beta.kubernetes.io/aws-load-balancer-internal: "true" or set aws-load-balancer-scheme: internal to make the NLB internal.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7002 — Access logs disabled on AWS LB.
 */
const nw7002: Rule = {
  id: 'NW7002',
  severity: 'error',
  description: 'AWS LoadBalancer Service has access logs explicitly disabled',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAwsResource(r)) continue;

      const logsEnabled = getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-access-log-enabled');
      if (logsEnabled === 'false') {
        findings.push(makeFinding(
          nw7002,
          r,
          `Service "${r.metadata.name}" has AWS load balancer access logs explicitly disabled`,
          'Enable access logs: set service.beta.kubernetes.io/aws-load-balancer-access-log-enabled: "true" and configure an S3 bucket for storage.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7003 — Public AWS LB without SSL cert annotation.
 */
const nw7003: Rule = {
  id: 'NW7003',
  severity: 'warning',
  description: 'AWS LoadBalancer Service has no SSL certificate annotation — HTTPS offload not configured',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAwsResource(r)) continue;

      // Only flag public-facing LBs (not internal)
      const isInternal =
        getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-internal') === 'true' ||
        getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-scheme') === 'internal';
      if (isInternal) continue;

      const hasSslCert = hasAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-ssl-cert');
      if (!hasSslCert) {
        findings.push(makeFinding(
          nw7003,
          r,
          `Service "${r.metadata.name}" is a public AWS LoadBalancer without an SSL certificate annotation`,
          'Add service.beta.kubernetes.io/aws-load-balancer-ssl-cert with an ACM certificate ARN to enable HTTPS offload.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7004 — AWS LB with SSL cert but no TLS negotiation policy.
 */
const nw7004: Rule = {
  id: 'NW7004',
  severity: 'info',
  description: 'AWS LoadBalancer Service has SSL configured but no TLS negotiation policy pinned',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAwsResource(r)) continue;

      const hasCert = hasAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-ssl-cert');
      if (!hasCert) continue; // only relevant when TLS is configured

      const hasPolicy = hasAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy');
      if (!hasPolicy) {
        findings.push(makeFinding(
          nw7004,
          r,
          `Service "${r.metadata.name}" uses AWS LB SSL but has no TLS negotiation policy pinned`,
          'Pin a policy such as ELBSecurityPolicy-TLS13-1-2-2021-06 via service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy to prevent weak cipher negotiation.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7005 — ALB Ingress without explicit internal scheme.
 * Fires when the Ingress uses the 'alb' class but has no scheme or scheme is internet-facing.
 */
const nw7005: Rule = {
  id: 'NW7005',
  severity: 'warning',
  description: 'ALB Ingress has no scheme annotation — load balancer defaults to internet-facing',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;

      const ingressClass =
        getAnnotation(r, 'kubernetes.io/ingress.class') ??
        (r.spec as { ingressClassName?: string }).ingressClassName;
      if (ingressClass !== 'alb') continue;

      const scheme = getAnnotation(r, 'alb.ingress.kubernetes.io/scheme');
      if (!scheme || scheme === 'internet-facing') {
        findings.push(makeFinding(
          nw7005,
          r,
          `Ingress "${r.metadata.name}" uses ALB without alb.ingress.kubernetes.io/scheme: internal — ALB is internet-facing`,
          'Add alb.ingress.kubernetes.io/scheme: internal if this ALB should not be publicly reachable, or explicitly set scheme: internet-facing to document the intent.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7006 — ALB Ingress without custom security group.
 */
const nw7006: Rule = {
  id: 'NW7006',
  severity: 'error',
  description: 'ALB Ingress has no custom security group annotation — uses permissive default security group',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;

      const ingressClass =
        getAnnotation(r, 'kubernetes.io/ingress.class') ??
        (r.spec as { ingressClassName?: string }).ingressClassName;
      if (ingressClass !== 'alb') continue;

      const hasSG = hasAnnotation(r, 'alb.ingress.kubernetes.io/security-groups');
      if (!hasSG) {
        findings.push(makeFinding(
          nw7006,
          r,
          `Ingress "${r.metadata.name}" uses ALB without alb.ingress.kubernetes.io/security-groups — default security group may be overly permissive`,
          'Attach a custom security group that restricts source IPs via alb.ingress.kubernetes.io/security-groups.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7007 — ALB Ingress with TLS but no TLS policy.
 */
const nw7007: Rule = {
  id: 'NW7007',
  severity: 'warning',
  description: 'ALB Ingress has TLS configured but no ssl-policy annotation — cipher suite not pinned',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;

      const ingressClass =
        getAnnotation(r, 'kubernetes.io/ingress.class') ??
        (r.spec as { ingressClassName?: string }).ingressClassName;
      if (ingressClass !== 'alb') continue;

      // Only flag when TLS is configured on the Ingress
      const spec = r.spec as { tls?: unknown[] };
      if (!spec.tls || spec.tls.length === 0) continue;

      const hasPolicy = hasAnnotation(r, 'alb.ingress.kubernetes.io/ssl-policy');
      if (!hasPolicy) {
        findings.push(makeFinding(
          nw7007,
          r,
          `Ingress "${r.metadata.name}" uses ALB with TLS but has no alb.ingress.kubernetes.io/ssl-policy annotation`,
          'Pin a TLS policy such as ELBSecurityPolicy-TLS13-1-2-2021-06 to prevent negotiation of weak ciphers.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7008 — Connection draining explicitly disabled on AWS LB.
 */
const nw7008: Rule = {
  id: 'NW7008',
  severity: 'info',
  description: 'AWS LoadBalancer Service has connection draining explicitly disabled',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAwsResource(r)) continue;

      const draining = getAnnotation(r, 'service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled');
      if (draining === 'false') {
        findings.push(makeFinding(
          nw7008,
          r,
          `Service "${r.metadata.name}" has AWS load balancer connection draining explicitly disabled`,
          'Enable connection draining to allow in-flight requests to complete before deregistering targets: set aws-load-balancer-connection-draining-enabled: "true".',
        ));
      }
    }
    return findings;
  },
};

// ─── GCP rules ────────────────────────────────────────────────────────────────

/**
 * NW7009 — GKE LoadBalancer without Internal annotation.
 * Fires when the resource has a GCP annotation and is type LoadBalancer,
 * but has no internal LB annotation.
 */
const nw7009: Rule = {
  id: 'NW7009',
  severity: 'warning',
  description: 'GKE LoadBalancer Service has no internal annotation — may be an external LoadBalancer',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isGcpResource(r)) continue;

      const isInternal =
        getAnnotation(r, 'networking.gke.io/load-balancer-type') === 'Internal' ||
        getAnnotation(r, 'cloud.google.com/load-balancer-type') === 'Internal';

      if (!isInternal) {
        findings.push(makeFinding(
          nw7009,
          r,
          `Service "${r.metadata.name}" is a GKE LoadBalancer without an internal annotation — may be internet-facing`,
          'Add networking.gke.io/load-balancer-type: Internal to create an internal passthrough NLB, or confirm the external LB intent.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7010 — GCE Ingress without HTTP disabled.
 * Fires for any Ingress with ingress.class=gce or gce-internal that lacks
 * kubernetes.io/ingress.allow-http: "false".
 */
const nw7010: Rule = {
  id: 'NW7010',
  severity: 'warning',
  description: 'GCE Ingress does not disable HTTP — traffic can reach the backend unencrypted',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;

      const ingressClass =
        getAnnotation(r, 'kubernetes.io/ingress.class') ??
        (r.spec as { ingressClassName?: string }).ingressClassName;
      if (ingressClass !== 'gce' && ingressClass !== 'gce-internal') continue;

      const httpDisabled = getAnnotation(r, 'kubernetes.io/ingress.allow-http');
      if (httpDisabled !== 'false') {
        findings.push(makeFinding(
          nw7010,
          r,
          `Ingress "${r.metadata.name}" uses GCE ingress class without kubernetes.io/ingress.allow-http: "false" — HTTP traffic is allowed`,
          'Add kubernetes.io/ingress.allow-http: "false" to disable plaintext HTTP and force HTTPS.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7011 — GKE LB without load-balancer-type annotation (informational).
 * Only fires when the resource is GCP-specific AND has no type annotation at all.
 */
const nw7011: Rule = {
  id: 'NW7011',
  severity: 'info',
  description: 'GKE LoadBalancer Service does not set a load-balancer-type annotation — intent (public vs internal) is not explicit',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isGcpResource(r)) continue; // only GCP-annotated resources

      const hasCloudGoogleType = hasAnnotation(r, 'cloud.google.com/load-balancer-type');
      const hasGkeType = hasAnnotation(r, 'networking.gke.io/load-balancer-type');
      if (!hasCloudGoogleType && !hasGkeType) {
        findings.push(makeFinding(
          nw7011,
          r,
          `Service "${r.metadata.name}" is a GKE LoadBalancer with no load-balancer-type annotation — confirm whether this is a public or internal LB`,
          'Set cloud.google.com/load-balancer-type: Internal for an internal LB, or document that this is an intentional public LB.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7012 — GKE BackendConfig without Cloud Armor security policy.
 */
const nw7012: Rule = {
  id: 'NW7012',
  severity: 'warning',
  description: 'GKE BackendConfig has no Cloud Armor security policy configured',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (r.kind !== 'BackendConfig') continue;
      if (!r.apiVersion.startsWith('cloud.google.com')) continue;

      const spec = r.spec as { securityPolicy?: unknown };
      if (!spec.securityPolicy) {
        findings.push(makeFinding(
          nw7012,
          r,
          `GKE BackendConfig "${r.metadata.name}" has no Cloud Armor security policy configured`,
          'Add spec.securityPolicy referencing a Cloud Armor security policy to protect backend services from DDoS and application-layer attacks.',
        ));
      }
    }
    return findings;
  },
};

// ─── Azure rules ──────────────────────────────────────────────────────────────

/**
 * NW7013 — AKS LB with internal=false explicitly set.
 * Only fires for resources that have an Azure annotation.
 */
const nw7013: Rule = {
  id: 'NW7013',
  severity: 'warning',
  description: 'AKS LoadBalancer Service has azure-load-balancer-internal explicitly set to "false" — internet-facing LB confirmed',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAzureResource(r)) continue;

      const internal = getAnnotation(r, 'service.beta.kubernetes.io/azure-load-balancer-internal');
      if (internal === 'false') {
        findings.push(makeFinding(
          nw7013,
          r,
          `Service "${r.metadata.name}" has azure-load-balancer-internal: "false" — this LoadBalancer is explicitly internet-facing`,
          'Confirm this is intentional. If the service should not be public, set service.beta.kubernetes.io/azure-load-balancer-internal: "true".',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7014 — AKS LB without internal annotation (informational).
 * Only fires for resources with Azure-flavored annotations.
 */
const nw7014: Rule = {
  id: 'NW7014',
  severity: 'info',
  description: 'AKS LoadBalancer Service has no azure-load-balancer-internal annotation — intent (public vs internal) not explicit',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isLoadBalancerService(r)) continue;
      if (!isAzureResource(r)) continue; // require Azure-specific annotations on the resource

      const hasInternal = hasAnnotation(r, 'service.beta.kubernetes.io/azure-load-balancer-internal');
      if (!hasInternal) {
        findings.push(makeFinding(
          nw7014,
          r,
          `Service "${r.metadata.name}" is an AKS LoadBalancer without azure-load-balancer-internal annotation — intent (public vs internal) is not explicit`,
          'Explicitly set service.beta.kubernetes.io/azure-load-balancer-internal: "true" for internal LBs or "false" to document that the public LB is intentional.',
        ));
      }
    }
    return findings;
  },
};

/**
 * NW7015 — Azure Application Gateway Ingress without WAF policy.
 */
const nw7015: Rule = {
  id: 'NW7015',
  severity: 'warning',
  description: 'Azure Application Gateway Ingress has no WAF policy annotation configured',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;

      const ingressClass =
        getAnnotation(r, 'kubernetes.io/ingress.class') ??
        (r.spec as { ingressClassName?: string }).ingressClassName;
      if (ingressClass !== 'azure/application-gateway') continue;

      const hasWaf =
        hasAnnotation(r, 'appgw.ingress.kubernetes.io/waf-policy-for-path') ||
        hasAnnotation(r, 'azure.application-gateway/waf-policy-id');
      if (!hasWaf) {
        findings.push(makeFinding(
          nw7015,
          r,
          `Ingress "${r.metadata.name}" uses Azure Application Gateway without a WAF policy annotation`,
          'Attach a WAF policy via appgw.ingress.kubernetes.io/waf-policy-for-path or azure.application-gateway/waf-policy-id to protect against OWASP threats.',
        ));
      }
    }
    return findings;
  },
};

// ─── Export ───────────────────────────────────────────────────────────────────

export const nw7xxxRules: Rule[] = [
  nw7001,
  nw7002,
  nw7003,
  nw7004,
  nw7005,
  nw7006,
  nw7007,
  nw7008,
  nw7009,
  nw7010,
  nw7011,
  nw7012,
  nw7013,
  nw7014,
  nw7015,
];
