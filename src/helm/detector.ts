/**
 * Helm/Kustomize template detection and resolution utilities.
 */

export interface HelmValues {
  release?: { Name?: string; Namespace?: string; Service?: string };
  values?: Record<string, unknown>;
}

/**
 * Returns true if the content contains Helm template expressions ({{ ... }}).
 */
export function hasHelmTemplates(content: string): boolean {
  return content.includes('{{') && content.includes('}}');
}

/**
 * Extracts all template variable names from content.
 * Returns dotted paths like "Release.Namespace", "Values.image.tag".
 */
export function extractTemplateVars(content: string): string[] {
  const vars: string[] = [];
  // Match {{ .Something.Path }} patterns (simple dotted paths)
  const regex = /\{\{\s*\.([\w.]+)\s*\}\}/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    vars.push(match[1]);
  }
  return [...new Set(vars)];
}

/**
 * Resolves Helm template expressions in content using provided values.
 * Only simple dotted paths are resolved:
 *   .Release.Namespace → helmValues.release?.Namespace
 *   .Release.Name      → helmValues.release?.Name
 *   .Release.Service   → helmValues.release?.Service
 *   .Values.foo        → helmValues.values?.foo
 *   .Values.foo.bar    → helmValues.values?.foo?.bar (nested)
 * Complex expressions (include, required, if, range, etc.) are left as-is.
 */
export function resolveHelmTemplates(content: string, values: HelmValues): string {
  // Only replace simple {{ .X.Y }} patterns (no pipes, no function calls)
  return content.replace(/\{\{\s*\.([\w.]+)\s*\}\}/g, (match, path: string) => {
    const parts = path.split('.');
    const resolved = resolveValuePath(parts, values);
    if (resolved !== undefined) {
      return String(resolved);
    }
    // Leave unresolvable templates as-is
    return match;
  });
}

function resolveValuePath(parts: string[], values: HelmValues): unknown {
  if (parts.length === 0) return undefined;

  const [top, ...rest] = parts;

  if (top === 'Release' && values.release) {
    if (rest.length === 1) {
      const key = rest[0] as keyof NonNullable<HelmValues['release']>;
      return values.release[key];
    }
    return undefined;
  }

  if (top === 'Values' && values.values) {
    // Navigate nested values
    let current: unknown = values.values;
    for (const key of rest) {
      if (current === null || typeof current !== 'object') return undefined;
      current = (current as Record<string, unknown>)[key];
    }
    return current;
  }

  return undefined;
}
