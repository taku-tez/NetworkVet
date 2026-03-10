import { describe, it, expect, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig, mergeConfig } from '../../src/config/loader.js';
import type { NetworkVetConfig } from '../../src/config/loader.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function tmpFile(name: string, content: string): string {
  const p = join(tmpdir(), `networkvet-test-${Date.now()}-${name}`);
  writeFileSync(p, content, 'utf8');
  return p;
}

const created: string[] = [];
function tempConfig(name: string, content: string): string {
  const p = tmpFile(name, content);
  created.push(p);
  return p;
}

afterEach(() => {
  for (const p of created.splice(0)) {
    try { if (existsSync(p)) unlinkSync(p); } catch { /* ignore */ }
  }
});

// ─── loadConfig ───────────────────────────────────────────────────────────────

describe('loadConfig', () => {
  it('returns empty object when no config file exists and no explicit path given', () => {
    // Passing undefined triggers auto-discovery; with no .networkvet.yaml in cwd during tests,
    // it returns an empty object.
    const cfg = loadConfig(undefined);
    expect(cfg).toEqual({});
  });

  it('returns empty object when no path given and no auto-discovered file', () => {
    // This test relies on the CWD having no .networkvet.yaml — which is true in tests
    // (the CWD is set to the project root, which has no .networkvet.yaml)
    // We can only verify there is no throw here
    const cfg = loadConfig(undefined);
    expect(cfg).toEqual({});
  });

  it('throws descriptive error when explicit path does not exist', () => {
    expect(() => loadConfig('/tmp/networkvet-nonexistent-99999.yaml')).toThrow(
      /not found/i
    );
  });

  it('loads a valid YAML config with ignore list', () => {
    const p = tempConfig('valid.yaml', `
ignore:
  - NW1001
  - NW2003
`);
    const cfg = loadConfig(p);
    expect(cfg.ignore).toEqual(['NW1001', 'NW2003']);
  });

  it('loads a valid YAML config with override block', () => {
    const p = tempConfig('override.yaml', `
override:
  NW1003:
    severity: error
`);
    const cfg = loadConfig(p);
    expect(cfg.override?.['NW1003']?.severity).toBe('error');
  });

  it('loads ingressClass from config', () => {
    const p = tempConfig('ingress.yaml', `
ingressClass: nginx
`);
    const cfg = loadConfig(p);
    expect(cfg.ingressClass).toBe('nginx');
  });

  it('loads excludeNamespaces from config', () => {
    const p = tempConfig('exclude-ns.yaml', `
excludeNamespaces:
  - kube-system
  - cert-manager
`);
    const cfg = loadConfig(p);
    expect(cfg.excludeNamespaces).toEqual(['kube-system', 'cert-manager']);
  });

  it('loads cloudProvider from config', () => {
    const p = tempConfig('cloud.yaml', `cloudProvider: aws`);
    const cfg = loadConfig(p);
    expect(cfg.cloudProvider).toBe('aws');
  });

  it('loads per-rule enable flags', () => {
    const p = tempConfig('rules.yaml', `
rules:
  nw1009:
    enabled: false
  nw1010:
    enabled: true
`);
    const cfg = loadConfig(p);
    expect(cfg.rules?.nw1009?.enabled).toBe(false);
    expect(cfg.rules?.nw1010?.enabled).toBe(true);
  });

  it('returns empty config for an empty YAML file', () => {
    const p = tempConfig('empty.yaml', '');
    const cfg = loadConfig(p);
    expect(cfg).toEqual({});
  });

  it('returns empty config for a YAML file containing only null', () => {
    const p = tempConfig('null.yaml', 'null\n');
    const cfg = loadConfig(p);
    expect(cfg).toEqual({});
  });

  it('throws descriptive error for invalid YAML', () => {
    const p = tempConfig('bad.yaml', ': this is not valid yaml: {[');
    expect(() => loadConfig(p)).toThrow(/invalid yaml/i);
  });

  it('throws descriptive error when YAML is a plain array (not mapping)', () => {
    const p = tempConfig('array.yaml', '- item1\n- item2\n');
    expect(() => loadConfig(p)).toThrow(/must be a yaml mapping/i);
  });

  it('includes the file path in the error message for invalid YAML', () => {
    const p = tempConfig('bad2.yaml', ': {bad');
    try {
      loadConfig(p);
      expect.fail('should have thrown');
    } catch (err) {
      expect(String(err)).toContain(p);
    }
  });

  it('loads a full realistic config', () => {
    const p = tempConfig('full.yaml', `
ignore:
  - NW1006
  - NW2007
override:
  NW1003:
    severity: error
ingressClass: alb
excludeNamespaces:
  - kube-system
cloudProvider: aws
rules:
  nw1009:
    enabled: false
`);
    const cfg = loadConfig(p);
    expect(cfg.ignore).toContain('NW1006');
    expect(cfg.override?.['NW1003']?.severity).toBe('error');
    expect(cfg.ingressClass).toBe('alb');
    expect(cfg.excludeNamespaces).toContain('kube-system');
    expect(cfg.cloudProvider).toBe('aws');
    expect(cfg.rules?.nw1009?.enabled).toBe(false);
  });
});

// ─── mergeConfig ──────────────────────────────────────────────────────────────

describe('mergeConfig', () => {
  it('returns config unchanged when no CLI ignore provided', () => {
    const cfg: NetworkVetConfig = { ignore: ['NW1001'] };
    const merged = mergeConfig(cfg, {});
    expect(merged.ignore).toEqual(['NW1001']);
  });

  it('CLI ignore and config ignore are merged into a union', () => {
    const cfg: NetworkVetConfig = { ignore: ['NW1001', 'NW2003'] };
    const merged = mergeConfig(cfg, { ignore: ['NW3001'] });
    expect(merged.ignore).toContain('NW1001');
    expect(merged.ignore).toContain('NW2003');
    expect(merged.ignore).toContain('NW3001');
  });

  it('deduplicates overlapping ignore IDs', () => {
    const cfg: NetworkVetConfig = { ignore: ['NW1001', 'NW2001'] };
    const merged = mergeConfig(cfg, { ignore: ['NW1001', 'NW3001'] });
    // NW1001 should appear only once
    const count = merged.ignore!.filter((id) => id === 'NW1001').length;
    expect(count).toBe(1);
  });

  it('normalises ignore IDs to uppercase', () => {
    const cfg: NetworkVetConfig = { ignore: ['nw1001'] };
    const merged = mergeConfig(cfg, { ignore: ['nw2001'] });
    expect(merged.ignore).toContain('NW1001');
    expect(merged.ignore).toContain('NW2001');
  });

  it('preserves other config keys unchanged', () => {
    const cfg: NetworkVetConfig = {
      ignore: ['NW1001'],
      ingressClass: 'nginx',
      excludeNamespaces: ['kube-system'],
    };
    const merged = mergeConfig(cfg, { ignore: ['NW2001'] });
    expect(merged.ingressClass).toBe('nginx');
    expect(merged.excludeNamespaces).toEqual(['kube-system']);
  });

  it('works when config has no ignore list', () => {
    const cfg: NetworkVetConfig = { ingressClass: 'gce' };
    const merged = mergeConfig(cfg, { ignore: ['NW1001'] });
    expect(merged.ignore).toContain('NW1001');
  });

  it('works when CLI provides no ignore list', () => {
    const cfg: NetworkVetConfig = { ignore: ['NW1001'] };
    const merged = mergeConfig(cfg, {});
    expect(merged.ignore).toContain('NW1001');
  });
});
