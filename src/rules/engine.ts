import type { Finding, ParsedResource, AnalysisContext, Rule, Severity } from '../types.js';
import type { NetworkVetConfig } from '../config/loader.js';
import { nw1xxxRules } from './nw1xxx.js';
import { nw2xxxRules } from './nw2xxx.js';
import { nw3xxxRules } from './nw3xxx.js';
import { nw4xxxRules } from './nw4xxx.js';
import { nw5xxxRules } from './nw5xxx.js';
import { nw6xxxRules } from './nw6xxx.js';
import { nw7xxxRules } from './nw7xxx.js';
import { nw8Rules } from './nw8xxx.js';

const SEVERITY_ORDER: Record<string, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

const INLINE_IGNORE_ANNOTATION = 'networkvet.io/ignore';

/**
 * Returns the set of rule IDs that a specific resource wants to suppress.
 * Reads the annotation "networkvet.io/ignore" from the resource's metadata.
 */
function getInlineIgnores(r: ParsedResource): Set<string> {
  const annotation = r.metadata.annotations?.[INLINE_IGNORE_ANNOTATION];
  if (!annotation) return new Set();
  return new Set(
    annotation.split(',').map((id) => id.trim().toUpperCase()).filter(Boolean)
  );
}

export const allRules: Rule[] = [
  ...nw1xxxRules,
  ...nw2xxxRules,
  ...nw3xxxRules,
  ...nw4xxxRules,
  ...nw5xxxRules,
  ...nw6xxxRules,
  ...nw7xxxRules,
  ...nw8Rules,
];

/**
 * Build an AnalysisContext from a list of parsed resources.
 * Optional overrides allow callers to inject cni / mode / config-derived fields.
 */
export function buildContext(
  resources: ParsedResource[],
  overrides?: Partial<Omit<AnalysisContext, 'resources' | 'namespaces'>>
): AnalysisContext {
  const namespaces = new Set<string>();
  for (const r of resources) {
    if (r.kind === 'Namespace') {
      namespaces.add(r.metadata.name);
    } else if (r.metadata.namespace) {
      namespaces.add(r.metadata.namespace);
    }
  }
  return { resources, namespaces, ...overrides };
}

/**
 * Apply config overrides to a list of findings.
 * - `config.override[id].severity` replaces the finding's severity.
 */
function applyConfigOverrides(
  findings: Finding[],
  config: NetworkVetConfig
): Finding[] {
  if (!config.override) return findings;

  return findings.map((f) => {
    const key = f.id.toUpperCase();
    // Try exact match and case-insensitive match
    const override =
      config.override![f.id] ??
      config.override![key] ??
      config.override![f.id.toLowerCase()];
    if (!override) return f;

    const updated = { ...f };
    if (override.severity) {
      updated.severity = override.severity as Severity;
    }
    return updated;
  });
}

/**
 * Run all rules against a list of resources, filtering out ignored IDs.
 * Accepts an optional `NetworkVetConfig` to apply severity overrides and
 * config-level ignores. Returns findings sorted by file then severity.
 */
export function runRules(
  resources: ParsedResource[],
  ignoreIds: string[] = [],
  contextOverrides?: Partial<Omit<AnalysisContext, 'resources' | 'namespaces'>>,
  config?: NetworkVetConfig
): Finding[] {
  // Merge ignore lists from CLI and config (both already normalised by mergeConfig,
  // but we also handle the raw case when config is passed directly).
  const configIgnore = config?.ignore ?? [];
  const allIgnore = [...ignoreIds, ...configIgnore];
  const ignoreSet = new Set(allIgnore.map((id) => id.trim().toUpperCase()));

  // Build context — include config-derived context fields
  const ctxOverrides: Partial<Omit<AnalysisContext, 'resources' | 'namespaces'>> = {
    ...contextOverrides,
  };
  if (config?.ingressClass !== undefined && !ctxOverrides.ingressClass) {
    ctxOverrides.ingressClass = config.ingressClass;
  }
  if (config?.excludeNamespaces !== undefined && !ctxOverrides.excludeNamespaces) {
    ctxOverrides.excludeNamespaces = config.excludeNamespaces;
  }
  if (config?.cloudProvider !== undefined && !ctxOverrides.cloudProvider) {
    ctxOverrides.cloudProvider = config.cloudProvider;
  }

  const context = buildContext(resources, ctxOverrides);
  const findings: Finding[] = [];

  for (const rule of allRules) {
    // Skip rules disabled via config.rules
    const ruleKey = rule.id.toLowerCase();
    if (config?.rules?.[ruleKey]?.enabled === false) continue;
    if (ignoreSet.has(rule.id.toUpperCase())) continue;

    try {
      const ruleFindings = rule.check(resources, context);
      findings.push(...ruleFindings);
    } catch {
      // Rule execution errors are swallowed — individual rules should not crash the tool
    }
  }

  // Apply per-rule severity overrides from config
  const overridden = applyConfigOverrides(findings, config ?? {});

  // Apply per-resource inline ignores (networkvet.io/ignore annotation)
  const resourceIgnoreMap = new Map<string, Set<string>>();
  for (const r of resources) {
    const ignores = getInlineIgnores(r);
    if (ignores.size > 0) {
      const key = `${r.kind}::${r.metadata.namespace ?? ''}::${r.metadata.name}`;
      resourceIgnoreMap.set(key, ignores);
    }
  }

  let filteredFindings = overridden;
  if (resourceIgnoreMap.size > 0) {
    filteredFindings = filteredFindings.filter((f) => {
      const key = `${f.kind}::${f.namespace ?? ''}::${f.name}`;
      const ignores = resourceIgnoreMap.get(key);
      return !ignores || !ignores.has(f.id.toUpperCase());
    });
  }

  // Sort: first by file, then by severity (error < warning < info), then by rule ID
  filteredFindings.sort((a, b) => {
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    const sevCmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    if (sevCmp !== 0) return sevCmp;
    return a.id.localeCompare(b.id);
  });

  return filteredFindings;
}

/**
 * Run a specific subset of rules by their IDs.
 */
export function runSpecificRules(
  resources: ParsedResource[],
  ruleIds: string[]
): Finding[] {
  const idSet = new Set(ruleIds.map((id) => id.toUpperCase()));
  const selectedRules = allRules.filter((r) => idSet.has(r.id.toUpperCase()));
  const context = buildContext(resources);
  const findings: Finding[] = [];

  for (const rule of selectedRules) {
    try {
      findings.push(...rule.check(resources, context));
    } catch {
      // swallow
    }
  }

  findings.sort((a, b) => {
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    const sevCmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    if (sevCmp !== 0) return sevCmp;
    return a.id.localeCompare(b.id);
  });

  return findings;
}
