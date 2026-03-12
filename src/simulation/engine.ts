import type { ParsedResource } from '../types.js';
import type { PodReachabilityResult } from '../reachability/pod_evaluator.js';

export interface SimulationDiff {
  gained: PodReachabilityResult[]; // paths that become allowed after simulation
  lost: PodReachabilityResult[];   // paths that become denied after simulation
  unchanged: PodReachabilityResult[]; // paths with same result
}

/**
 * Load hypothetical resources from a YAML file, merge with existing resources.
 * For each resource in `simulated`, if an existing resource has the same
 * kind, metadata.namespace, and metadata.name, replace it; otherwise append it.
 */
export function mergeSimulatedResources(
  existing: ParsedResource[],
  simulated: ParsedResource[]
): ParsedResource[] {
  const result: ParsedResource[] = [...existing];

  for (const sim of simulated) {
    const idx = result.findIndex(
      (r) =>
        r.kind === sim.kind &&
        r.metadata.namespace === sim.metadata.namespace &&
        r.metadata.name === sim.metadata.name
    );
    if (idx !== -1) {
      result[idx] = sim;
    } else {
      result.push(sim);
    }
  }

  return result;
}

/**
 * Compute the diff between before/after pod reachability.
 * Keys each result by "${from.namespace}/${from.name} → ${to.namespace}/${to.name}".
 */
export function computeSimulationDiff(
  before: PodReachabilityResult[],
  after: PodReachabilityResult[]
): SimulationDiff {
  const beforeMap = new Map<string, PodReachabilityResult>();
  for (const r of before) {
    const key = `${r.from.namespace}/${r.from.name} → ${r.to.namespace}/${r.to.name}`;
    beforeMap.set(key, r);
  }

  const afterMap = new Map<string, PodReachabilityResult>();
  for (const r of after) {
    const key = `${r.from.namespace}/${r.from.name} → ${r.to.namespace}/${r.to.name}`;
    afterMap.set(key, r);
  }

  const gained: PodReachabilityResult[] = [];
  const lost: PodReachabilityResult[] = [];
  const unchanged: PodReachabilityResult[] = [];

  // Check all keys from both before and after
  const allKeys = new Set([...beforeMap.keys(), ...afterMap.keys()]);

  for (const key of allKeys) {
    const b = beforeMap.get(key);
    const a = afterMap.get(key);

    if (b === undefined && a !== undefined) {
      // New path that didn't exist before — if now allowed, it's gained
      if (a.allowed) {
        gained.push(a);
      } else {
        unchanged.push(a);
      }
    } else if (b !== undefined && a === undefined) {
      // Path existed before but not after — treat as unchanged (no data to compare)
      unchanged.push(b);
    } else if (b !== undefined && a !== undefined) {
      if (!b.allowed && a.allowed) {
        // Was denied, now allowed → gained
        gained.push(a);
      } else if (b.allowed && !a.allowed) {
        // Was allowed, now denied → lost
        lost.push(a);
      } else {
        // Same result
        unchanged.push(a);
      }
    }
  }

  return { gained, lost, unchanged };
}
