import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { glob } from 'glob';
import type { ParsedResource, K8sMetadata } from '../types.js';
import { hasHelmTemplates, resolveHelmTemplates } from '../helm/detector.js';
import type { HelmValues } from '../helm/detector.js';

export interface ParseOptions {
  helmValues?: HelmValues;
}

interface RawK8sDoc {
  kind?: string;
  apiVersion?: string;
  metadata?: Record<string, unknown>;
  spec?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Parse a single YAML file, returning all K8s resources found (supports multi-doc).
 */
export function parseFile(filePath: string): ParsedResource[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  return parseContent(content, filePath);
}

/**
 * Parse YAML content string, supporting multi-document YAML separated by `---`.
 */
export function parseContent(content: string, filePath: string = '<inline>'): ParsedResource[] {
  const results: ParsedResource[] = [];

  // Split on document separators and track approximate line numbers
  const documents = splitYamlDocuments(content);

  for (const { docContent, startLine } of documents) {
    if (!docContent.trim()) continue;

    let doc: unknown;
    try {
      doc = yaml.load(docContent);
    } catch {
      // Skip unparseable documents
      continue;
    }

    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) continue;

    const rawDoc = doc as RawK8sDoc;
    if (!rawDoc.kind || !rawDoc.apiVersion) continue;

    const metadata = (rawDoc.metadata ?? {}) as Record<string, unknown>;
    const name = typeof metadata.name === 'string' ? metadata.name : '';
    const namespace = typeof metadata.namespace === 'string' ? metadata.namespace : undefined;

    const parsedMetadata: K8sMetadata = {
      name,
      ...(namespace !== undefined ? { namespace } : {}),
      ...(metadata.labels && typeof metadata.labels === 'object'
        ? { labels: metadata.labels as Record<string, string> }
        : {}),
      ...(metadata.annotations && typeof metadata.annotations === 'object'
        ? { annotations: metadata.annotations as Record<string, string> }
        : {}),
    };

    results.push({
      kind: rawDoc.kind,
      apiVersion: rawDoc.apiVersion,
      metadata: parsedMetadata,
      spec: (rawDoc.spec ?? {}) as Record<string, unknown>,
      file: filePath,
      line: startLine,
    });
  }

  return results;
}

/**
 * Split a YAML string into individual documents, tracking start line numbers.
 */
function splitYamlDocuments(content: string): Array<{ docContent: string; startLine: number }> {
  const lines = content.split('\n');
  const docs: Array<{ docContent: string; startLine: number }> = [];
  let currentLines: string[] = [];
  let currentStartLine = 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('---')) {
      if (currentLines.length > 0) {
        docs.push({ docContent: currentLines.join('\n'), startLine: currentStartLine });
      }
      currentLines = [];
      currentStartLine = i + 2; // next line after ---
    } else {
      currentLines.push(line);
    }
  }

  if (currentLines.length > 0) {
    docs.push({ docContent: currentLines.join('\n'), startLine: currentStartLine });
  }

  // If nothing was pushed (no --- separator, single doc), treat whole content
  if (docs.length === 0 && content.trim()) {
    docs.push({ docContent: content, startLine: 1 });
  }

  return docs;
}

/**
 * Recursively walk a directory and return all YAML file paths.
 */
function walkDir(dir: string): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkDir(fullPath));
    } else if (entry.isFile() && /\.(yaml|yml)$/.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Recursively parse all YAML files in a directory (async, uses glob).
 * Returns parsed resources and a list of files skipped due to unresolved Helm templates.
 */
export async function parseDir(
  dir: string,
  opts?: ParseOptions
): Promise<{ resources: ParsedResource[]; skippedHelmFiles: string[] }> {
  const absDir = path.resolve(dir);
  const files = await glob('**/*.{yaml,yml}', { cwd: absDir, absolute: true });
  files.sort();

  const results: ParsedResource[] = [];
  const skippedHelmFiles: string[] = [];

  for (const file of files) {
    try {
      const rawContent = fs.readFileSync(file, 'utf-8');

      if (hasHelmTemplates(rawContent)) {
        // Attempt to resolve templates if values are provided
        const resolved = opts?.helmValues
          ? resolveHelmTemplates(rawContent, opts.helmValues)
          : rawContent;

        // If templates remain, skip this file
        if (hasHelmTemplates(resolved)) {
          skippedHelmFiles.push(file);
          continue;
        }

        // Parse resolved content
        const parsed = parseContent(resolved, file);
        results.push(...parsed);
      } else {
        const parsed = parseFile(file);
        results.push(...parsed);
      }
    } catch {
      // Skip files that can't be read
    }
  }

  return { resources: results, skippedHelmFiles };
}

/**
 * Synchronous version of parseDir using manual directory walk.
 */
export function parseDirSync(dir: string): ParsedResource[] {
  const absDir = path.resolve(dir);
  const files = walkDir(absDir);
  files.sort();

  const results: ParsedResource[] = [];
  for (const file of files) {
    try {
      const parsed = parseFile(file);
      results.push(...parsed);
    } catch {
      // Skip files that can't be read
    }
  }
  return results;
}
