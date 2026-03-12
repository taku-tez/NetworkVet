import { describe, it, expect } from 'vitest';
import {
  hasHelmTemplates,
  extractTemplateVars,
  resolveHelmTemplates,
} from '../../src/helm/detector.js';

describe('helm/detector', () => {
  describe('hasHelmTemplates', () => {
    it('returns true for {{ .Release.Namespace }}', () => {
      expect(hasHelmTemplates('namespace: {{ .Release.Namespace }}')).toBe(true);
    });

    it('returns true for {{ .Values.image.tag }}', () => {
      expect(hasHelmTemplates('image: {{ .Values.image.tag }}')).toBe(true);
    });

    it('returns true for content with multiple templates', () => {
      const content = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Release.Name }}-sa
  namespace: {{ .Release.Namespace }}
`;
      expect(hasHelmTemplates(content)).toBe(true);
    });

    it('returns false for plain YAML without templates', () => {
      const content = `
apiVersion: v1
kind: Namespace
metadata:
  name: production
`;
      expect(hasHelmTemplates(content)).toBe(false);
    });

    it('returns false for empty string', () => {
      expect(hasHelmTemplates('')).toBe(false);
    });

    it('returns false when only {{ is present without }}', () => {
      expect(hasHelmTemplates('some {{ incomplete')).toBe(false);
    });

    it('returns false when only }} is present without {{', () => {
      expect(hasHelmTemplates('some }} incomplete')).toBe(false);
    });
  });

  describe('extractTemplateVars', () => {
    it('extracts Release.Namespace from simple template', () => {
      const vars = extractTemplateVars('namespace: {{ .Release.Namespace }}');
      expect(vars).toContain('Release.Namespace');
    });

    it('extracts Values.image.tag from nested Values template', () => {
      const vars = extractTemplateVars('image: {{ .Values.image.tag }}');
      expect(vars).toContain('Values.image.tag');
    });

    it('extracts Release.Name', () => {
      const vars = extractTemplateVars('name: {{ .Release.Name }}-app');
      expect(vars).toContain('Release.Name');
    });

    it('extracts multiple variables from multi-template content', () => {
      const content = `
name: {{ .Release.Name }}
namespace: {{ .Release.Namespace }}
image: {{ .Values.image.tag }}
`;
      const vars = extractTemplateVars(content);
      expect(vars).toContain('Release.Name');
      expect(vars).toContain('Release.Namespace');
      expect(vars).toContain('Values.image.tag');
    });

    it('deduplicates repeated variables', () => {
      const content = `
a: {{ .Release.Namespace }}
b: {{ .Release.Namespace }}
`;
      const vars = extractTemplateVars(content);
      expect(vars.filter((v) => v === 'Release.Namespace')).toHaveLength(1);
    });

    it('ignores complex expressions like include and if', () => {
      const content = `
name: {{ include "chart.fullname" . }}
{{- if .Values.enabled }}
{{- end }}
`;
      // complex expressions won't match simple .X.Y pattern, so they are ignored
      const vars = extractTemplateVars(content);
      expect(vars).not.toContain('include');
    });

    it('returns empty array for plain YAML', () => {
      expect(extractTemplateVars('namespace: production')).toEqual([]);
    });
  });

  describe('resolveHelmTemplates', () => {
    it('replaces {{ .Release.Namespace }} with provided namespace', () => {
      const content = 'namespace: {{ .Release.Namespace }}';
      const result = resolveHelmTemplates(content, { release: { Namespace: 'production' } });
      expect(result).toBe('namespace: production');
    });

    it('replaces {{ .Release.Name }} with provided release name', () => {
      const content = 'name: {{ .Release.Name }}-app';
      const result = resolveHelmTemplates(content, { release: { Name: 'my-release' } });
      expect(result).toBe('name: my-release-app');
    });

    it('replaces {{ .Release.Service }}', () => {
      const content = 'service: {{ .Release.Service }}';
      const result = resolveHelmTemplates(content, { release: { Service: 'Helm' } });
      expect(result).toBe('service: Helm');
    });

    it('replaces {{ .Values.xxx }} with values', () => {
      const content = 'image: {{ .Values.image }}';
      const result = resolveHelmTemplates(content, { values: { image: 'nginx:1.25' } });
      expect(result).toBe('image: nginx:1.25');
    });

    it('replaces nested {{ .Values.image.tag }}', () => {
      const content = 'tag: {{ .Values.image.tag }}';
      const result = resolveHelmTemplates(content, {
        values: { image: { tag: '1.25.0' } },
      });
      expect(result).toBe('tag: 1.25.0');
    });

    it('leaves unresolvable templates as-is (partial resolution)', () => {
      const content = `
namespace: {{ .Release.Namespace }}
name: {{ .Values.unknown.path }}
`;
      const result = resolveHelmTemplates(content, { release: { Namespace: 'staging' } });
      expect(result).toContain('namespace: staging');
      expect(result).toContain('{{ .Values.unknown.path }}');
    });

    it('leaves complex expressions like include as-is', () => {
      const content = 'name: {{ include "chart.fullname" . }}';
      const result = resolveHelmTemplates(content, { release: { Name: 'test' } });
      // complex expressions don't match simple pattern, remain unchanged
      expect(result).toContain('{{ include "chart.fullname" . }}');
    });

    it('resolves multiple templates in one content string', () => {
      const content = `
namespace: {{ .Release.Namespace }}
name: {{ .Release.Name }}
`;
      const result = resolveHelmTemplates(content, {
        release: { Namespace: 'prod', Name: 'my-app' },
      });
      expect(result).toContain('namespace: prod');
      expect(result).toContain('name: my-app');
    });

    it('handles empty values gracefully', () => {
      const content = 'namespace: {{ .Release.Namespace }}';
      const result = resolveHelmTemplates(content, {});
      // No release provided, template stays as-is
      expect(result).toContain('{{ .Release.Namespace }}');
    });
  });
});
