import type { Rule, ParsedResource, AnalysisContext, Finding } from '../types.js';
import { isGateway, isHTTPRoute, isGRPCRoute, isReferenceGrant } from '../types.js';
import type { GatewaySpec, HTTPRouteSpec, GRPCRouteSpec, ReferenceGrantSpec } from '../types.js';

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

/**
 * Build a set of (grantNamespace, fromKind) → Set<toKind> from all ReferenceGrant resources.
 * A ReferenceGrant in namespace X with from[].kind=HTTPRoute and to[].kind=Service
 * means: HTTPRoute → Service cross-namespace access to namespace X is allowed.
 */
function buildReferenceGrantSet(resources: ParsedResource[]): Map<string, Set<string>> {
  // Key: `${grantNamespace}::${fromKind}` → Set of toKinds
  const grants = new Map<string, Set<string>>();
  for (const r of resources) {
    if (!isReferenceGrant(r)) continue;
    const spec = r.spec as ReferenceGrantSpec;
    const grantNs = r.metadata.namespace;
    if (!grantNs) continue;
    for (const from of spec.from ?? []) {
      for (const to of spec.to ?? []) {
        const key = `${grantNs}::${from.kind}`;
        if (!grants.has(key)) grants.set(key, new Set());
        grants.get(key)!.add(to.kind);
      }
    }
  }
  return grants;
}

// ─── NW8001 ──────────────────────────────────────────────────────────────────
// HTTPRoute served over plain HTTP without TLS
const nw8001: Rule = {
  id: 'NW8001',
  severity: 'medium',
  description: 'HTTPRoute is served over plain HTTP without TLS termination',
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isHTTPRoute(r)) continue;
      const spec = r.spec as HTTPRouteSpec;
      const parentRefs = spec.parentRefs ?? [];

      // Determine if the route appears to be HTTP-only:
      // - sectionName is "http" (common convention), OR
      // - sectionName is absent/not "https"/"tls", AND no TLS filter exists in any rule
      const hasTlsFilter = (spec.rules ?? []).some((rule) =>
        (rule.filters ?? []).some((f) => f.type === 'RequestRedirect' || f.type === 'URLRewrite')
      );

      let isHttpRoute = false;
      if (parentRefs.length === 0) {
        // No parent refs — treat as potentially unencrypted
        isHttpRoute = true;
      } else {
        for (const ref of parentRefs) {
          const sectionName = ref.sectionName?.toLowerCase() ?? '';
          if (sectionName === 'http' || (sectionName !== 'https' && sectionName !== 'tls')) {
            isHttpRoute = true;
            break;
          }
        }
      }

      if (isHttpRoute && !hasTlsFilter) {
        findings.push(
          makeFinding(
            nw8001,
            r,
            `HTTPRoute "${r.metadata.name}" is served over plain HTTP without TLS termination`,
            'Configure a Gateway HTTPS listener and reference it via sectionName, or add a RequestRedirect filter to enforce TLS'
          )
        );
      }
    }
    return findings;
  },
};

// ─── NW8002 ──────────────────────────────────────────────────────────────────
// Gateway allows routes from all namespaces
const nw8002: Rule = {
  id: 'NW8002',
  severity: 'medium',
  description: "Gateway listener allows routes from all namespaces; restrict with 'Same' or 'Selector'",
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isGateway(r)) continue;
      const spec = r.spec as GatewaySpec;
      const listeners = spec.listeners ?? [];
      for (const listener of listeners) {
        const from = listener.allowedRoutes?.namespaces?.from;
        if (from === 'All') {
          findings.push(
            makeFinding(
              nw8002,
              r,
              `Gateway "${r.metadata.name}" listener "${listener.name}" allows routes from all namespaces; restrict with 'Same' or 'Selector'`,
              "Set allowedRoutes.namespaces.from to 'Same' or 'Selector' to limit which namespaces can attach routes"
            )
          );
        }
      }
    }
    return findings;
  },
};

// ─── NW8003 ──────────────────────────────────────────────────────────────────
// HTTPRoute cross-namespace backendRef without ReferenceGrant
const nw8003: Rule = {
  id: 'NW8003',
  severity: 'high',
  description: "HTTPRoute references Service in a different namespace but no ReferenceGrant exists to permit this",
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    const grants = buildReferenceGrantSet(resources);

    for (const r of resources) {
      if (!isHTTPRoute(r)) continue;
      const spec = r.spec as HTTPRouteSpec;
      const routeNs = r.metadata.namespace;
      if (!routeNs) continue;

      for (const rule of spec.rules ?? []) {
        for (const backendRef of rule.backendRefs ?? []) {
          const targetNs = backendRef.namespace;
          if (!targetNs || targetNs === routeNs) continue;

          // Check if a ReferenceGrant exists in targetNs allowing HTTPRoute→Service
          const key = `${targetNs}::HTTPRoute`;
          const allowed = grants.get(key)?.has('Service') ?? false;
          if (!allowed) {
            findings.push(
              makeFinding(
                nw8003,
                r,
                `HTTPRoute "${r.metadata.name}" references Service "${backendRef.name}" in namespace '${targetNs}' but no ReferenceGrant exists to permit this`,
                `Create a ReferenceGrant in namespace '${targetNs}' that allows HTTPRoute resources to reference Services`
              )
            );
          }
        }
      }
    }
    return findings;
  },
};

// ─── NW8004 ──────────────────────────────────────────────────────────────────
// Gateway HTTPS/TLS listener without certificateRefs
const nw8004: Rule = {
  id: 'NW8004',
  severity: 'high',
  description: "Gateway HTTPS/TLS listener has no certificateRefs configured",
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    for (const r of resources) {
      if (!isGateway(r)) continue;
      const spec = r.spec as GatewaySpec;
      for (const listener of spec.listeners ?? []) {
        const protocol = listener.protocol?.toUpperCase();
        if (protocol !== 'HTTPS' && protocol !== 'TLS') continue;
        const certRefs = listener.tls?.certificateRefs ?? [];
        if (certRefs.length === 0) {
          findings.push(
            makeFinding(
              nw8004,
              r,
              `Gateway "${r.metadata.name}" HTTPS/TLS listener '${listener.name}' has no certificateRefs configured`,
              'Add spec.listeners[].tls.certificateRefs pointing to a TLS Secret to enable certificate termination'
            )
          );
        }
      }
    }
    return findings;
  },
};

// ─── NW8005 ──────────────────────────────────────────────────────────────────
// GRPCRoute cross-namespace backendRef without ReferenceGrant
const nw8005: Rule = {
  id: 'NW8005',
  severity: 'high',
  description: "GRPCRoute references Service in a different namespace but no ReferenceGrant exists to permit this",
  check(resources: ParsedResource[], _ctx: AnalysisContext): Finding[] {
    const findings: Finding[] = [];
    const grants = buildReferenceGrantSet(resources);

    for (const r of resources) {
      if (!isGRPCRoute(r)) continue;
      const spec = r.spec as GRPCRouteSpec;
      const routeNs = r.metadata.namespace;
      if (!routeNs) continue;

      for (const rule of spec.rules ?? []) {
        for (const backendRef of rule.backendRefs ?? []) {
          const targetNs = backendRef.namespace;
          if (!targetNs || targetNs === routeNs) continue;

          // Check if a ReferenceGrant exists in targetNs allowing GRPCRoute→Service
          const key = `${targetNs}::GRPCRoute`;
          const allowed = grants.get(key)?.has('Service') ?? false;
          if (!allowed) {
            findings.push(
              makeFinding(
                nw8005,
                r,
                `GRPCRoute "${r.metadata.name}" references Service "${backendRef.name}" in namespace '${targetNs}' but no ReferenceGrant exists to permit this`,
                `Create a ReferenceGrant in namespace '${targetNs}' that allows GRPCRoute resources to reference Services`
              )
            );
          }
        }
      }
    }
    return findings;
  },
};

export const nw8Rules: Rule[] = [
  nw8001,
  nw8002,
  nw8003,
  nw8004,
  nw8005,
];
