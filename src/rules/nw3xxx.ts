import type { Rule, ParsedResource, AnalysisContext, Finding, IngressSpec, IngressRule } from '../types.js';
import { isIngress, isService } from '../types.js';

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

/** NW3001: Ingress without TLS configured */
export const NW3001: Rule = {
  id: 'NW3001',
  severity: 'high',
  description: 'Ingress without TLS configured',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;
      const spec = r.spec as IngressSpec;
      if (!spec.tls || spec.tls.length === 0) {
        findings.push(
          makeFinding(
            NW3001,
            r,
            `Ingress "${r.metadata.name}" has no TLS configured — traffic is served over plain HTTP`,
            'Add a spec.tls section with a valid Secret to enable HTTPS'
          )
        );
      }
    }
    return findings;
  },
};

/** NW3002: Ingress TLS but no HSTS annotation */
export const NW3002: Rule = {
  id: 'NW3002',
  severity: 'low',
  description: 'Ingress has TLS but no HSTS annotation',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;
      const spec = r.spec as IngressSpec;
      if (!spec.tls || spec.tls.length === 0) continue;
      const annotations = r.metadata.annotations ?? {};
      const hasHsts =
        annotations['nginx.ingress.kubernetes.io/configuration-snippet']?.includes('Strict-Transport-Security') ||
        annotations['nginx.ingress.kubernetes.io/hsts'] === 'true' ||
        annotations['haproxy.router.openshift.io/hsts_header'];
      if (!hasHsts) {
        findings.push(
          makeFinding(
            NW3002,
            r,
            `Ingress "${r.metadata.name}" has TLS but no HSTS (HTTP Strict Transport Security) annotation`,
            'Add nginx.ingress.kubernetes.io/configuration-snippet with Strict-Transport-Security header or set nginx.ingress.kubernetes.io/hsts: "true"'
          )
        );
      }
    }
    return findings;
  },
};

/** NW3003: Ingress without HTTP→HTTPS redirect */
export const NW3003: Rule = {
  id: 'NW3003',
  severity: 'low',
  description: 'Ingress without HTTP to HTTPS redirect',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;
      const spec = r.spec as IngressSpec;
      if (!spec.tls || spec.tls.length === 0) continue;
      const annotations = r.metadata.annotations ?? {};
      const hasRedirect =
        annotations['nginx.ingress.kubernetes.io/ssl-redirect'] === 'true' ||
        annotations['nginx.ingress.kubernetes.io/force-ssl-redirect'] === 'true' ||
        annotations['kubernetes.io/ingress.allow-http'] === 'false';
      if (!hasRedirect) {
        findings.push(
          makeFinding(
            NW3003,
            r,
            `Ingress "${r.metadata.name}" has TLS but does not redirect HTTP to HTTPS`,
            'Add annotation nginx.ingress.kubernetes.io/ssl-redirect: "true" to force HTTPS'
          )
        );
      }
    }
    return findings;
  },
};

/** NW3004: Ingress with wildcard host (*) */
export const NW3004: Rule = {
  id: 'NW3004',
  severity: 'medium',
  description: 'Ingress with wildcard host (*)',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;
      const spec = r.spec as IngressSpec;
      const rules = spec.rules ?? [];
      const hasWildcard = rules.some((rule) => rule.host === '*' || !rule.host);
      if (hasWildcard) {
        findings.push(
          makeFinding(
            NW3004,
            r,
            `Ingress "${r.metadata.name}" uses a wildcard or empty host — matches all hostnames`,
            'Specify explicit hostnames in Ingress rules to avoid unintentional traffic routing'
          )
        );
      }
    }
    return findings;
  },
};

/** NW3005: Ingress without ssl-redirect annotation */
export const NW3005: Rule = {
  id: 'NW3005',
  severity: 'info',
  description: 'Ingress without nginx.ingress.kubernetes.io/ssl-redirect annotation',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;
      const annotations = r.metadata.annotations ?? {};
      if (!annotations['nginx.ingress.kubernetes.io/ssl-redirect']) {
        findings.push(
          makeFinding(
            NW3005,
            r,
            `Ingress "${r.metadata.name}" is missing nginx.ingress.kubernetes.io/ssl-redirect annotation`,
            'Explicitly set nginx.ingress.kubernetes.io/ssl-redirect: "true" or "false" to make TLS redirect behavior clear'
          )
        );
      }
    }
    return findings;
  },
};

const SENSITIVE_PATH_PATTERNS = [
  /^\/admin/i,
  /^\/_/,
  /^\/internal/i,
  /^\/metrics/i,
  /^\/debug/i,
  /^\/actuator/i,
  /^\/management/i,
];

/** NW3006: Ingress exposes admin/internal paths publicly */
export const NW3006: Rule = {
  id: 'NW3006',
  severity: 'medium',
  description: 'Ingress exposes admin or internal paths publicly',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isIngress(r)) continue;
      const spec = r.spec as IngressSpec;
      const rules = spec.rules ?? [];

      for (const rule of rules) {
        const paths = rule.http?.paths ?? [];
        for (const p of paths) {
          const pathStr = p.path ?? '/';
          if (SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(pathStr))) {
            findings.push(
              makeFinding(
                NW3006,
                r,
                `Ingress "${r.metadata.name}" exposes sensitive path "${pathStr}" publicly`,
                'Restrict admin/internal paths using IP allowlisting or move them to a separate internal-only Ingress'
              )
            );
          }
        }
      }
    }
    return findings;
  },
};

/** NW3007: Ingress references non-existent Service backend */
export const NW3007: Rule = {
  id: 'NW3007',
  severity: 'high',
  description: 'Ingress references non-existent Service backend',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];

    // Build set of (namespace, serviceName) for all Services.
    // Services without an explicit namespace are included under a sentinel so
    // they don't accidentally satisfy namespace-qualified lookups.
    const serviceKeys = new Set<string>();
    for (const r of resources) {
      if (!isService(r)) continue;
      const ns = r.metadata.namespace;
      if (ns) serviceKeys.add(`${ns}/${r.metadata.name}`);
    }

    for (const r of resources) {
      if (!isIngress(r)) continue;
      const spec = r.spec as IngressSpec;
      // If the Ingress has no explicit namespace we cannot verify backend services.
      const ns = r.metadata.namespace;
      if (!ns) continue;
      const referencedServices: string[] = [];

      // Check defaultBackend
      if (spec.defaultBackend?.service?.name) {
        referencedServices.push(spec.defaultBackend.service.name);
      }

      // Check rules
      const rules = spec.rules ?? [];
      for (const rule of rules) {
        const paths = rule.http?.paths ?? [];
        for (const p of paths) {
          if (p.backend.service?.name) {
            referencedServices.push(p.backend.service.name);
          }
        }
      }

      for (const svcName of referencedServices) {
        if (!serviceKeys.has(`${ns}/${svcName}`)) {
          findings.push(
            makeFinding(
              NW3007,
              r,
              `Ingress "${r.metadata.name}" references Service "${svcName}" which does not exist in namespace "${ns}"`,
              'Ensure the referenced Service exists in the same namespace as the Ingress'
            )
          );
        }
      }
    }
    return findings;
  },
};

export const nw3xxxRules: Rule[] = [
  NW3001,
  NW3002,
  NW3003,
  NW3004,
  NW3005,
  NW3006,
  NW3007,
];
