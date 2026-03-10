import { describe, it, expect } from 'vitest';
import { nw5xxxRules } from '../../src/rules/nw5xxx.js';
import type { ParsedResource, AnalysisContext } from '../../src/types.js';

// ─── helpers ─────────────────────────────────────────────────────────────────

function makeAuthzPolicy(
  name: string,
  spec: Record<string, unknown>,
  namespace = 'default'
): ParsedResource {
  return {
    kind: 'AuthorizationPolicy',
    apiVersion: 'security.istio.io/v1beta1',
    metadata: { name, namespace },
    spec,
    file: 'authz.yaml',
    line: 1,
  };
}

function makePeerAuth(
  name: string,
  spec: Record<string, unknown>,
  namespace = 'default'
): ParsedResource {
  return {
    kind: 'PeerAuthentication',
    apiVersion: 'security.istio.io/v1beta1',
    metadata: { name, namespace },
    spec,
    file: 'peer.yaml',
    line: 1,
  };
}

function makeCtx(resources: ParsedResource[]): AnalysisContext {
  return { resources, namespaces: new Set(['default']) };
}

function ruleById(id: string) {
  const rule = nw5xxxRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

// ─── NW5001 ──────────────────────────────────────────────────────────────────

describe('NW5001 — AuthorizationPolicy ALLOW with principals: ["*"]', () => {
  const rule = ruleById('NW5001');

  it('fires when ALLOW rule has principals: ["*"]', () => {
    const r = makeAuthzPolicy('allow-all', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['*'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5001');
    expect(findings[0].severity).toBe('error');
    expect(findings[0].name).toBe('allow-all');
  });

  it('fires when action is absent (implicit ALLOW) and principals: ["*"]', () => {
    const r = makeAuthzPolicy('implicit-allow', {
      rules: [{ from: [{ source: { principals: ['*'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
  });

  it('does not fire when principals are specific', () => {
    const r = makeAuthzPolicy('specific-allow', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['cluster.local/ns/default/sa/myapp'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for DENY policy with principals: ["*"]', () => {
    const r = makeAuthzPolicy('deny-all-principals', {
      action: 'DENY',
      rules: [{ from: [{ source: { principals: ['*'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for non-Istio resources', () => {
    const r: ParsedResource = {
      kind: 'AuthorizationPolicy',
      apiVersion: 'rbac.authorization.k8s.io/v1',
      metadata: { name: 'k8s-rbac', namespace: 'default' },
      spec: {},
      file: 'x.yaml',
      line: 1,
    };
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW5002 ──────────────────────────────────────────────────────────────────

describe('NW5002 — AuthorizationPolicy ALLOW with empty source', () => {
  const rule = ruleById('NW5002');

  it('fires when from source has no constraints', () => {
    const r = makeAuthzPolicy('empty-source', {
      action: 'ALLOW',
      rules: [{ from: [{ source: {} }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5002');
    expect(findings[0].severity).toBe('warning');
  });

  it('does not fire when source has principals', () => {
    const r = makeAuthzPolicy('with-principals', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['cluster.local/ns/ns1/sa/app'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when source has namespaces', () => {
    const r = makeAuthzPolicy('with-namespaces', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { namespaces: ['trusted-ns'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for DENY policy', () => {
    const r = makeAuthzPolicy('deny-empty-src', {
      action: 'DENY',
      rules: [{ from: [{ source: {} }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW5003 ──────────────────────────────────────────────────────────────────

describe('NW5003 — AuthorizationPolicy ALLOW with methods: ["*"]', () => {
  const rule = ruleById('NW5003');

  it('fires when to operation has methods: ["*"]', () => {
    const r = makeAuthzPolicy('allow-all-methods', {
      action: 'ALLOW',
      rules: [{ to: [{ operation: { methods: ['*'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5003');
    expect(findings[0].severity).toBe('warning');
  });

  it('does not fire when methods are specific', () => {
    const r = makeAuthzPolicy('specific-methods', {
      action: 'ALLOW',
      rules: [{ to: [{ operation: { methods: ['GET', 'POST'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for DENY policy', () => {
    const r = makeAuthzPolicy('deny-methods', {
      action: 'DENY',
      rules: [{ to: [{ operation: { methods: ['*'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW5004 ──────────────────────────────────────────────────────────────────

describe('NW5004 — AuthorizationPolicy ALLOW rule with no from/to', () => {
  const rule = ruleById('NW5004');

  it('fires when ALLOW rule has neither from nor to', () => {
    const r = makeAuthzPolicy('unconditional-allow', {
      action: 'ALLOW',
      rules: [{}],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5004');
    expect(findings[0].severity).toBe('error');
  });

  it('does not fire when rule has "from"', () => {
    const r = makeAuthzPolicy('with-from', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { namespaces: ['ns1'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when rule has "to"', () => {
    const r = makeAuthzPolicy('with-to', {
      action: 'ALLOW',
      rules: [{ to: [{ operation: { methods: ['GET'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when rules array is empty (DENY all)', () => {
    const r = makeAuthzPolicy('deny-all-no-rules', {
      action: 'ALLOW',
      rules: [],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for DENY policy', () => {
    const r = makeAuthzPolicy('deny-no-from-to', {
      action: 'DENY',
      rules: [{}],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW5005 ──────────────────────────────────────────────────────────────────

describe('NW5005 — PeerAuthentication PERMISSIVE mTLS', () => {
  const rule = ruleById('NW5005');

  it('fires for PERMISSIVE mode', () => {
    const r = makePeerAuth('permissive-mtls', { mtls: { mode: 'PERMISSIVE' } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5005');
    expect(findings[0].severity).toBe('warning');
  });

  it('does not fire for STRICT mode', () => {
    const r = makePeerAuth('strict-mtls', { mtls: { mode: 'STRICT' } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when no mtls mode is set', () => {
    const r = makePeerAuth('no-mtls', { selector: { matchLabels: { app: 'test' } } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for AuthorizationPolicy', () => {
    const r = makeAuthzPolicy('not-peer-auth', {});
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW5006 ──────────────────────────────────────────────────────────────────

describe('NW5006 — PeerAuthentication DISABLE mTLS', () => {
  const rule = ruleById('NW5006');

  it('fires for DISABLE mode', () => {
    const r = makePeerAuth('disabled-mtls', { mtls: { mode: 'DISABLE' } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5006');
    expect(findings[0].severity).toBe('error');
  });

  it('does not fire for PERMISSIVE mode', () => {
    const r = makePeerAuth('permissive', { mtls: { mode: 'PERMISSIVE' } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for STRICT mode', () => {
    const r = makePeerAuth('strict', { mtls: { mode: 'STRICT' } });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('reports correct name and namespace', () => {
    const r = makePeerAuth('my-auth', { mtls: { mode: 'DISABLE' } }, 'production');
    const findings = rule.check([r], makeCtx([r]));
    expect(findings[0].name).toBe('my-auth');
    expect(findings[0].namespace).toBe('production');
  });
});

// ─── NW5007 ──────────────────────────────────────────────────────────────────

describe('NW5007 — AuthorizationPolicy with no selector', () => {
  const rule = ruleById('NW5007');

  it('fires when selector is absent', () => {
    const r = makeAuthzPolicy('no-selector', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { namespaces: ['ns1'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5007');
    expect(findings[0].severity).toBe('info');
  });

  it('fires when selector.matchLabels is empty', () => {
    const r = makeAuthzPolicy('empty-selector', {
      selector: { matchLabels: {} },
      action: 'ALLOW',
      rules: [],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
  });

  it('does not fire when selector has labels', () => {
    const r = makeAuthzPolicy('scoped-selector', {
      selector: { matchLabels: { app: 'myapp' } },
      action: 'ALLOW',
      rules: [],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── NW5008 ──────────────────────────────────────────────────────────────────

describe('NW5008 — AuthorizationPolicy ALLOW with no namespace restriction', () => {
  const rule = ruleById('NW5008');

  it('fires when principals are set but no namespace', () => {
    const r = makeAuthzPolicy('no-ns-restriction', {
      action: 'ALLOW',
      rules: [{
        from: [{ source: { principals: ['cluster.local/ns/any/sa/app'] } }],
      }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW5008');
    expect(findings[0].severity).toBe('warning');
  });

  it('does not fire when both principals and namespaces are set', () => {
    const r = makeAuthzPolicy('with-ns', {
      action: 'ALLOW',
      rules: [{
        from: [{ source: { principals: ['cluster.local/ns/ns1/sa/app'], namespaces: ['ns1'] } }],
      }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when principals include wildcard (NW5001 handles that)', () => {
    const r = makeAuthzPolicy('wildcard-principal', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { principals: ['*'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when only namespaces are set (no principals)', () => {
    const r = makeAuthzPolicy('ns-only', {
      action: 'ALLOW',
      rules: [{ from: [{ source: { namespaces: ['trusted'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });

  it('does not fire for DENY policy', () => {
    const r = makeAuthzPolicy('deny', {
      action: 'DENY',
      rules: [{ from: [{ source: { principals: ['cluster.local/ns/any/sa/app'] } }] }],
    });
    const findings = rule.check([r], makeCtx([r]));
    expect(findings).toHaveLength(0);
  });
});

// ─── Export count sanity check ────────────────────────────────────────────────

describe('nw5xxxRules exports', () => {
  it('exports exactly 8 rules', () => {
    expect(nw5xxxRules).toHaveLength(8);
  });

  it('all rule IDs start with NW5', () => {
    for (const rule of nw5xxxRules) {
      expect(rule.id).toMatch(/^NW5\d{3}$/);
    }
  });

  it('all rules have descriptions', () => {
    for (const rule of nw5xxxRules) {
      expect(rule.description.length).toBeGreaterThan(0);
    }
  });
});
