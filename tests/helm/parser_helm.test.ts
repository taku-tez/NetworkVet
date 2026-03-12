import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseDir } from '../../src/parser/index.js';

const PLAIN_YAML = `
apiVersion: v1
kind: Namespace
metadata:
  name: production
`;

const HELM_YAML = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app
  namespace: {{ .Release.Namespace }}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
`;

const HELM_YAML_WITH_VALUES = `
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: {{ .Release.Namespace }}
spec:
  selector:
    app: {{ .Values.appName }}
  ports:
    - port: 80
`;

describe('parser/parseDir with Helm templates', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'networkvet-helm-test-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('adds Helm-templated file to skippedHelmFiles when no helmValues provided', async () => {
    writeFileSync(join(tmpDir, 'helm-np.yaml'), HELM_YAML);

    const result = await parseDir(tmpDir);
    expect(result.skippedHelmFiles).toHaveLength(1);
    expect(result.skippedHelmFiles[0]).toContain('helm-np.yaml');
    expect(result.resources).toHaveLength(0);
  });

  it('does not add plain YAML file to skippedHelmFiles', async () => {
    writeFileSync(join(tmpDir, 'namespace.yaml'), PLAIN_YAML);

    const result = await parseDir(tmpDir);
    expect(result.skippedHelmFiles).toHaveLength(0);
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('Namespace');
  });

  it('returns skippedHelmFiles: [] when no Helm templates present', async () => {
    writeFileSync(join(tmpDir, 'plain.yaml'), PLAIN_YAML);

    const result = await parseDir(tmpDir);
    expect(result.skippedHelmFiles).toEqual([]);
  });

  it('resolves Helm templates and parses file when helmValues provided', async () => {
    writeFileSync(join(tmpDir, 'helm-np.yaml'), HELM_YAML);

    const result = await parseDir(tmpDir, {
      helmValues: { release: { Namespace: 'production' } },
    });

    expect(result.skippedHelmFiles).toHaveLength(0);
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('NetworkPolicy');
    expect(result.resources[0].metadata.namespace).toBe('production');
  });

  it('partially resolved files still in skippedHelmFiles if templates remain', async () => {
    writeFileSync(join(tmpDir, 'helm-svc.yaml'), HELM_YAML_WITH_VALUES);

    // Only provide Release.Namespace, not Values.appName
    const result = await parseDir(tmpDir, {
      helmValues: { release: { Namespace: 'staging' } },
    });

    // .Values.appName is still unresolved, so file should be skipped
    expect(result.skippedHelmFiles).toHaveLength(1);
    expect(result.skippedHelmFiles[0]).toContain('helm-svc.yaml');
    expect(result.resources).toHaveLength(0);
  });

  it('resolves file when all templates are resolved', async () => {
    writeFileSync(join(tmpDir, 'helm-svc.yaml'), HELM_YAML_WITH_VALUES);

    const result = await parseDir(tmpDir, {
      helmValues: {
        release: { Namespace: 'staging' },
        values: { appName: 'my-app' },
      },
    });

    expect(result.skippedHelmFiles).toHaveLength(0);
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('Service');
    expect(result.resources[0].metadata.namespace).toBe('staging');
  });

  it('handles mix of plain and Helm files', async () => {
    writeFileSync(join(tmpDir, 'plain.yaml'), PLAIN_YAML);
    writeFileSync(join(tmpDir, 'helm.yaml'), HELM_YAML);

    const result = await parseDir(tmpDir);
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('Namespace');
    expect(result.skippedHelmFiles).toHaveLength(1);
    expect(result.skippedHelmFiles[0]).toContain('helm.yaml');
  });

  it('returns empty skippedHelmFiles when no files in directory', async () => {
    const result = await parseDir(tmpDir);
    expect(result.resources).toHaveLength(0);
    expect(result.skippedHelmFiles).toHaveLength(0);
  });
});
