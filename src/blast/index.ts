import type { ParsedResource } from '../types.js';
import type { WorkloadInfo } from '../reachability/pod_evaluator.js';
import { computePodReachability, extractWorkloads } from '../reachability/pod_evaluator.js';

export interface BlastRadiusResult {
  origin: WorkloadInfo;
  reachable: WorkloadInfo[];      // all workloads reachable from origin (BFS)
  unreachable: WorkloadInfo[];    // workloads in the same resource set NOT reachable
  highRiskTargets: string[];      // known high-risk endpoints found in reachable set
  depth: Map<string, number>;     // workload key → BFS depth from origin
}

// Known high-risk targets to flag when reachable
const HIGH_RISK_NAMES = [
  'kube-apiserver', 'kubernetes', 'etcd',
  'metrics-server', 'coredns', 'kube-dns',
];

/**
 * Parse "namespace/name" or "name" (defaults to default namespace).
 */
export function parseWorkloadRef(ref: string): { namespace: string; name: string } {
  const slashIndex = ref.indexOf('/');
  if (slashIndex === -1) {
    return { namespace: 'default', name: ref };
  }
  const namespace = ref.slice(0, slashIndex);
  const name = ref.slice(slashIndex + 1);
  return { namespace, name };
}

/**
 * BFS from origin through reachability graph.
 */
export function computeBlastRadius(
  resources: ParsedResource[],
  originRef: string,  // "namespace/name" format
): BlastRadiusResult {
  const { namespace: originNs, name: originName } = parseWorkloadRef(originRef);

  // Get all workloads and reachability pairs
  const allWorkloads = extractWorkloads(resources);
  const reachabilityResults = computePodReachability(resources);

  // Find origin workload
  const origin = allWorkloads.find(
    (w) => w.namespace === originNs && w.name === originName,
  );

  if (!origin) {
    const availableWorkloads = allWorkloads
      .map((w) => `${w.namespace}/${w.name}`)
      .join(', ');
    throw new Error(
      `Workload "${originRef}" not found. Available workloads: ${availableWorkloads || '(none)'}`,
    );
  }

  // Build adjacency map: workloadKey → Set of reachable workload keys
  const workloadByKey = new Map<string, WorkloadInfo>();
  for (const w of allWorkloads) {
    workloadByKey.set(`${w.namespace}/${w.name}`, w);
  }

  // adjacency: from key → list of to WorkloadInfo (where allowed)
  const adjacency = new Map<string, WorkloadInfo[]>();
  for (const result of reachabilityResults) {
    if (!result.allowed) continue;
    const fromKey = `${result.from.namespace}/${result.from.name}`;
    if (!adjacency.has(fromKey)) {
      adjacency.set(fromKey, []);
    }
    adjacency.get(fromKey)!.push(result.to);
  }

  // BFS
  const originKey = `${origin.namespace}/${origin.name}`;
  const depth = new Map<string, number>();
  depth.set(originKey, 0);

  const queue: WorkloadInfo[] = [origin];
  const visited = new Set<string>([originKey]);
  const reachable: WorkloadInfo[] = [];

  while (queue.length > 0) {
    const current = queue.shift()!;
    const currentKey = `${current.namespace}/${current.name}`;
    const currentDepth = depth.get(currentKey)!;

    const neighbors = adjacency.get(currentKey) ?? [];
    for (const neighbor of neighbors) {
      const neighborKey = `${neighbor.namespace}/${neighbor.name}`;
      if (!visited.has(neighborKey)) {
        visited.add(neighborKey);
        depth.set(neighborKey, currentDepth + 1);
        reachable.push(neighbor);
        queue.push(neighbor);
      }
    }
  }

  // Identify high-risk targets in reachable set
  const highRiskTargets: string[] = [];
  for (const w of reachable) {
    if (HIGH_RISK_NAMES.includes(w.name)) {
      highRiskTargets.push(`${w.namespace}/${w.name}`);
    }
  }

  // Unreachable: all workloads MINUS origin MINUS reachable
  const reachableKeys = new Set(reachable.map((w) => `${w.namespace}/${w.name}`));
  const unreachable = allWorkloads.filter((w) => {
    const key = `${w.namespace}/${w.name}`;
    return key !== originKey && !reachableKeys.has(key);
  });

  return {
    origin,
    reachable,
    unreachable,
    highRiskTargets,
    depth,
  };
}
