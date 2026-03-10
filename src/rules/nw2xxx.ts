import type { Rule, ParsedResource, AnalysisContext, Finding, ServiceSpec } from '../types.js';
import { isService } from '../types.js';

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

/** NW2001: Service type NodePort */
export const NW2001: Rule = {
  id: 'NW2001',
  severity: 'warning',
  description: 'Service type NodePort exposes ports on every node',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.type === 'NodePort') {
        findings.push(
          makeFinding(NW2001, r, `Service "${r.metadata.name}" uses NodePort which exposes ports on all cluster nodes`, 'Consider using LoadBalancer or Ingress to control external access more safely')
        );
      }
    }
    return findings;
  },
};

/** NW2002: Service type LoadBalancer without externalTrafficPolicy: Local */
export const NW2002: Rule = {
  id: 'NW2002',
  severity: 'warning',
  description: 'LoadBalancer Service without externalTrafficPolicy: Local loses source IP',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.type === 'LoadBalancer' && spec.externalTrafficPolicy !== 'Local') {
        findings.push(
          makeFinding(
            NW2002,
            r,
            `LoadBalancer Service "${r.metadata.name}" does not set externalTrafficPolicy: Local — source IP is masked`,
            'Set externalTrafficPolicy: Local to preserve client source IPs for security logging and IP-based access controls'
          )
        );
      }
    }
    return findings;
  },
};

/** NW2003: LoadBalancer Service without source IP restriction annotation */
export const NW2003: Rule = {
  id: 'NW2003',
  severity: 'info',
  description: 'LoadBalancer Service without source IP restriction annotation',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.type !== 'LoadBalancer') continue;

      const hasSourceRanges =
        (spec.loadBalancerSourceRanges && spec.loadBalancerSourceRanges.length > 0) ||
        (r.metadata.annotations &&
          r.metadata.annotations['service.beta.kubernetes.io/load-balancer-source-ranges']);

      if (!hasSourceRanges) {
        findings.push(
          makeFinding(
            NW2003,
            r,
            `LoadBalancer Service "${r.metadata.name}" has no source IP restriction (loadBalancerSourceRanges)`,
            'Set spec.loadBalancerSourceRanges to restrict which CIDRs can access this LoadBalancer'
          )
        );
      }
    }
    return findings;
  },
};

/** NW2004: Service targets port 22 (SSH) */
export const NW2004: Rule = {
  id: 'NW2004',
  severity: 'warning',
  description: 'Service targets port 22 (SSH) — potential security risk',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      const ports = spec.ports ?? [];
      const hasSsh = ports.some((p) => p.port === 22 || p.targetPort === 22);
      if (hasSsh) {
        findings.push(
          makeFinding(
            NW2004,
            r,
            `Service "${r.metadata.name}" exposes port 22 (SSH) — avoid exposing SSH via Kubernetes Services`,
            'SSH access should use kubectl exec or a dedicated bastion; remove port 22 from this Service'
          )
        );
      }
    }
    return findings;
  },
};

/** NW2005: Headless Service (clusterIP: None) without selector */
export const NW2005: Rule = {
  id: 'NW2005',
  severity: 'info',
  description: 'Headless Service (clusterIP: None) without selector',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.clusterIP === 'None' && (!spec.selector || Object.keys(spec.selector).length === 0)) {
        findings.push(
          makeFinding(
            NW2005,
            r,
            `Headless Service "${r.metadata.name}" has no selector — DNS will return all Endpoints manually managed`,
            'Ensure Endpoints are manually maintained, or add a selector if this is unintentional'
          )
        );
      }
    }
    return findings;
  },
};

/** NW2006: Service externalIPs field set (potential MITM risk) */
export const NW2006: Rule = {
  id: 'NW2006',
  severity: 'warning',
  description: 'Service externalIPs field set — potential MITM risk',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.externalIPs && spec.externalIPs.length > 0) {
        findings.push(
          makeFinding(
            NW2006,
            r,
            `Service "${r.metadata.name}" uses externalIPs: ${spec.externalIPs.join(', ')} — this can be exploited for MITM attacks`,
            'Avoid using externalIPs; use LoadBalancer type or Ingress instead'
          )
        );
      }
    }
    return findings;
  },
};

/** NW2007: Service without sessionAffinity on stateful workload */
export const NW2007: Rule = {
  id: 'NW2007',
  severity: 'info',
  description: 'Service without sessionAffinity on stateful workload',
  check(resources: ParsedResource[], ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    // Find services whose selectors match StatefulSet pods
    const statefulSets = ctx.resources.filter((r) => r.kind === 'StatefulSet');

    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.sessionAffinity && spec.sessionAffinity !== 'None') continue;
      if (!spec.selector || Object.keys(spec.selector).length === 0) continue;

      // Check if this Service's selector overlaps with any StatefulSet
      const coversStateful = statefulSets.some((ss) => {
        const ssNs = ss.metadata.namespace;
        const svcNs = r.metadata.namespace;
        // If either side lacks an explicit namespace we can't reliably compare
        if (!ssNs || !svcNs || ssNs !== svcNs) return false;
        const ssSpec = ss.spec as Record<string, unknown>;
        const template = ssSpec.template as Record<string, unknown> | undefined;
        const templateMeta = template?.metadata as Record<string, unknown> | undefined;
        const ssLabels = templateMeta?.labels as Record<string, string> | undefined;
        if (!ssLabels) return false;
        return Object.entries(spec.selector ?? {}).every(
          ([k, v]) => ssLabels[k] === v
        );
      });

      if (coversStateful) {
        findings.push(
          makeFinding(
            NW2007,
            r,
            `Service "${r.metadata.name}" targets a StatefulSet but has no sessionAffinity set`,
            'Set sessionAffinity: ClientIP to ensure consistent routing to the same pod for stateful connections'
          )
        );
      }
    }
    return findings;
  },
};

/** NW2008: Service of type ExternalName pointing to internal cluster DNS */
export const NW2008: Rule = {
  id: 'NW2008',
  severity: 'error',
  description: 'Service of type ExternalName pointing to internal cluster DNS',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isService(r)) continue;
      const spec = r.spec as ServiceSpec;
      if (spec.type !== 'ExternalName') continue;
      const externalName = spec.externalName ?? '';
      // Detect internal cluster DNS patterns
      if (externalName.endsWith('.cluster.local') || externalName.endsWith('.svc')) {
        findings.push(
          makeFinding(
            NW2008,
            r,
            `ExternalName Service "${r.metadata.name}" points to internal DNS "${externalName}" — this can bypass NetworkPolicies`,
            'Use a regular ClusterIP Service or direct DNS references instead of ExternalName for internal services'
          )
        );
      }
    }
    return findings;
  },
};

export const nw2xxxRules: Rule[] = [
  NW2001,
  NW2002,
  NW2003,
  NW2004,
  NW2005,
  NW2006,
  NW2007,
  NW2008,
];
