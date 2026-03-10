import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';

export interface NetworkVetConfig {
  /** Rule IDs to ignore globally (merged with CLI --ignore) */
  ignore?: string[];
  /** Per-rule overrides — currently supports severity override */
  override?: Record<string, {
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  }>;
  /** Ingress controller type — affects annotation checks */
  ingressClass?: string;
  /** Namespaces to exclude from the reachability matrix */
  excludeNamespaces?: string[];
  /** Force cloud-provider detection instead of inferring from annotations */
  cloudProvider?: 'aws' | 'gcp' | 'azure';
  /** Per-rule enable/disable toggles */
  rules?: Record<string, { enabled?: boolean }>;
}

/** Search candidates in priority order (first match wins). */
const SEARCH_NAMES = [
  '.networkvet.yaml',
  '.networkvet.yml',
  'networkvet.config.yaml',
];

/**
 * Load a NetworkVetConfig from disk.
 *
 * Resolution order:
 *   1. Explicit `configPath` argument
 *   2. `.networkvet.yaml` in cwd
 *   3. `.networkvet.yml` in cwd
 *   4. `networkvet.config.yaml` in cwd
 *
 * Returns an empty config `{}` if no file is found.
 * Throws a descriptive `Error` if a file exists but cannot be parsed.
 */
export function loadConfig(configPath?: string): NetworkVetConfig {
  const filePath = resolveConfigPath(configPath);
  if (!filePath) return {};

  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`NetworkVet: could not read config file "${filePath}": ${msg}`);
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`NetworkVet: invalid YAML in config file "${filePath}": ${msg}`);
  }

  if (parsed === null || parsed === undefined) {
    // Empty file → treat as empty config
    return {};
  }

  if (typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(
      `NetworkVet: config file "${filePath}" must be a YAML mapping (object), got ${Array.isArray(parsed) ? 'array' : typeof parsed}`
    );
  }

  return parsed as NetworkVetConfig;
}

/**
 * Merge a config file with CLI-level options.
 * CLI options take precedence: the `ignore` list is a deduplicated union of
 * both sources.
 */
export function mergeConfig(
  config: NetworkVetConfig,
  cliOptions: { ignore?: string[] }
): NetworkVetConfig {
  const configIgnore = config.ignore ?? [];
  const cliIgnore = cliOptions.ignore ?? [];

  // Deduplicated union — CLI entries first so they are visible at the front
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const id of [...cliIgnore, ...configIgnore]) {
    const upper = id.trim().toUpperCase();
    if (upper && !seen.has(upper)) {
      seen.add(upper);
      merged.push(upper);
    }
  }

  return {
    ...config,
    ignore: merged,
  };
}

// ─── Internal helpers ──────────────────────────────────────────────────────────

function resolveConfigPath(explicit?: string): string | null {
  if (explicit) {
    const abs = resolve(explicit);
    if (!existsSync(abs)) {
      throw new Error(`NetworkVet: config file not found: "${abs}"`);
    }
    return abs;
  }

  for (const name of SEARCH_NAMES) {
    const abs = resolve(name);
    if (existsSync(abs)) return abs;
  }

  return null;
}
