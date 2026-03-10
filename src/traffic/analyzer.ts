import type { ParsedResource, NetworkPolicySpec } from '../types.js';
import { isNetworkPolicy, isService } from '../types.js';
import type { TrafficFlow, TrafficViolation, PolicyGap, TrafficAnalysisResult } from './types.js';

// ─── NetworkPolicy helpers ────────────────────────────────────────────────────

/** All NetworkPolicies in a given namespace. */
function policiesForNamespace(
  resources: ParsedResource[],
  namespace: string,
): Array<ParsedResource & { spec: NetworkPolicySpec }> {
  return resources.filter(
    (r): r is ParsedResource & { spec: NetworkPolicySpec } =>
      isNetworkPolicy(r) && r.metadata.namespace === namespace,
  );
}

/**
 * Returns true when the namespace has at least one NetworkPolicy that
 * restricts ingress (Ingress in policyTypes, or has ingress rules).
 */
function namespaceHasIngressPolicy(resources: ParsedResource[], namespace: string): boolean {
  const policies = policiesForNamespace(resources, namespace);
  return policies.some((p) => {
    const spec = p.spec;
    const types = spec.policyTypes ?? [];
    return types.includes('Ingress') || spec.ingress !== undefined;
  });
}

/**
 * Returns true when at least one ingress NetworkPolicy in the destination
 * namespace has a rule that would allow traffic from the given source namespace.
 * This is a conservative approximation: we check namespaceSelector labels.
 */
function ingressPolicyAllowsSource(
  resources: ParsedResource[],
  destNamespace: string,
  sourceNamespace: string,
): boolean {
  const policies = policiesForNamespace(resources, destNamespace);
  for (const policy of policies) {
    const spec = policy.spec;
    const types = spec.policyTypes ?? [];
    const hasIngressType = types.includes('Ingress') || spec.ingress !== undefined;
    if (!hasIngressType) continue;

    for (const rule of spec.ingress ?? []) {
      if (!rule.from) return true; // ingress rule with no from = allow all
      for (const peer of rule.from) {
        if (Object.keys(peer).length === 0) return true; // empty peer = allow all
        if (peer.namespaceSelector) {
          const sel = peer.namespaceSelector as Record<string, unknown>;
          // Empty namespaceSelector = matches all namespaces
          if (Object.keys(sel).length === 0) return true;
          // matchLabels check: if the selector has name label matching source
          const matchLabels = (sel.matchLabels ?? {}) as Record<string, string>;
          if (
            matchLabels['kubernetes.io/metadata.name'] === sourceNamespace ||
            matchLabels.name === sourceNamespace
          ) {
            return true;
          }
        }
        if (!peer.namespaceSelector && !peer.podSelector && !peer.ipBlock) {
          // Peer with no fields = allow all
          return true;
        }
      }
    }
  }
  return false;
}

// ─── Service port helpers ─────────────────────────────────────────────────────

/** Set of all ports declared in Service resources across all namespaces. */
function allKnownServicePorts(resources: ParsedResource[]): Set<number> {
  const ports = new Set<number>();
  for (const r of resources) {
    if (!isService(r)) continue;
    for (const p of r.spec.ports ?? []) {
      if (p.port) ports.add(p.port);
      if (typeof p.targetPort === 'number') ports.add(p.targetPort);
    }
  }
  return ports;
}

// ─── Main analysis ────────────────────────────────────────────────────────────

/**
 * Detect policy gaps: traffic flows that were ALLOWED to a namespace with no
 * ingress NetworkPolicy — riskier than "no policy" alone because the path is
 * actively exercised.
 *
 * Deduplicates by (sourceNamespace, destNamespace, destPort) and counts
 * how many flows used each gap.
 */
export function detectPolicyGaps(
  flows: TrafficFlow[],
  resources: ParsedResource[],
): PolicyGap[] {
  type GapKey = string;
  const gapCounts = new Map<GapKey, { gap: PolicyGap; count: number }>();

  for (const flow of flows) {
    if (flow.verdict !== 'ALLOW') continue;
    if (!flow.destNamespace) continue;
    if (namespaceHasIngressPolicy(resources, flow.destNamespace)) continue;

    const port = flow.destPort ?? 0;
    const key: GapKey = `${flow.sourceNamespace}::${flow.destNamespace}::${port}`;
    const existing = gapCounts.get(key);
    if (existing) {
      existing.count++;
    } else {
      gapCounts.set(key, {
        gap: {
          sourceNamespace: flow.sourceNamespace,
          destNamespace: flow.destNamespace,
          destPort: port,
          observedCount: 0,
          message: `Traffic from "${flow.sourceNamespace}" to "${flow.destNamespace}":${port} is actively flowing but the destination namespace has no ingress NetworkPolicy`,
        },
        count: 1,
      });
    }
  }

  return [...gapCounts.values()].map(({ gap, count }) => ({
    ...gap,
    observedCount: count,
  }));
}

/**
 * Analyse observed traffic flows against declared NetworkPolicies and Services
 * to produce a TrafficAnalysisResult.
 */
export function analyzeTraffic(
  flows: TrafficFlow[],
  resources: ParsedResource[],
): TrafficAnalysisResult {
  const knownPorts = allKnownServicePorts(resources);
  const violations: TrafficViolation[] = [];

  let allowedFlows = 0;
  let droppedFlows = 0;

  // Track seen (srcNs, dstNs, dstPort) combos to avoid duplicate violations
  const seenGapKeys = new Set<string>();
  const seenAllowKeys = new Set<string>();
  const seenDenyKeys = new Set<string>();
  const seenShadowKeys = new Set<string>();

  for (const flow of flows) {
    if (flow.verdict === 'ALLOW') allowedFlows++;
    else if (flow.verdict === 'DROP') droppedFlows++;

    const { sourceNamespace, destNamespace, destPort, verdict } = flow;
    const port = destPort ?? 0;

    // ── policy-gap ─────────────────────────────────────────────────────
    // ALLOW to a namespace with no ingress NetworkPolicy
    if (verdict === 'ALLOW' && destNamespace) {
      if (!namespaceHasIngressPolicy(resources, destNamespace)) {
        const key = `gap::${sourceNamespace}::${destNamespace}::${port}`;
        if (!seenGapKeys.has(key)) {
          seenGapKeys.add(key);
          violations.push({
            type: 'policy-gap',
            flow,
            severity: 'warning',
            message: `Traffic from "${sourceNamespace}" to "${destNamespace}":${port || '*'} is actively observed but destination namespace has no ingress NetworkPolicy`,
          });
        }
      }
    }

    // ── unexpected-allow ────────────────────────────────────────────────
    // Traffic was ALLOWED to a namespace that HAS a NetworkPolicy, but the
    // declared policy should not allow this source namespace.
    if (verdict === 'ALLOW' && destNamespace && sourceNamespace) {
      if (
        namespaceHasIngressPolicy(resources, destNamespace) &&
        !ingressPolicyAllowsSource(resources, destNamespace, sourceNamespace)
      ) {
        const key = `unexpected-allow::${sourceNamespace}::${destNamespace}`;
        if (!seenAllowKeys.has(key)) {
          seenAllowKeys.add(key);
          violations.push({
            type: 'unexpected-allow',
            flow,
            severity: 'error',
            message: `Traffic from "${sourceNamespace}" to "${destNamespace}" was ALLOWED but no ingress NetworkPolicy rule permits this source — possible policy bypass or stale policy`,
          });
        }
      }
    }

    // ── unexpected-deny ─────────────────────────────────────────────────
    // Traffic was DROPPED to a namespace where the declared policy should
    // allow the source.
    if (verdict === 'DROP' && destNamespace && sourceNamespace) {
      if (ingressPolicyAllowsSource(resources, destNamespace, sourceNamespace)) {
        const key = `unexpected-deny::${sourceNamespace}::${destNamespace}`;
        if (!seenDenyKeys.has(key)) {
          seenDenyKeys.add(key);
          violations.push({
            type: 'unexpected-deny',
            flow,
            severity: 'warning',
            message: `Traffic from "${sourceNamespace}" to "${destNamespace}" was DROPPED but a declared ingress NetworkPolicy should allow it — check for policy sync issues or node-level firewall rules`,
          });
        }
      }
    }

    // ── shadow-traffic ──────────────────────────────────────────────────
    // Traffic (either allowed or dropped) on a port that appears in no
    // Service definition — may indicate unknown tunnelling or misconfig.
    if (port > 0 && knownPorts.size > 0 && !knownPorts.has(port)) {
      const key = `shadow::${destNamespace}::${port}`;
      if (!seenShadowKeys.has(key)) {
        seenShadowKeys.add(key);
        violations.push({
          type: 'shadow-traffic',
          flow,
          severity: 'info',
          message: `Traffic to port ${port} in namespace "${destNamespace}" is not covered by any declared Service — may indicate unknown tunnelling or a misconfigured application`,
        });
      }
    }
  }

  const policyGaps = detectPolicyGaps(flows, resources);

  return {
    totalFlows: flows.length,
    allowedFlows,
    droppedFlows,
    violations,
    policyGaps,
  };
}
