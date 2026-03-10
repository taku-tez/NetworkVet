import { describe, it, expect } from 'vitest';
import { parseContent } from '../../src/parser/index.js';
import { buildContext } from '../../src/rules/engine.js';
import {
  NW2001,
  NW2002,
  NW2003,
  NW2004,
  NW2005,
  NW2006,
  NW2007,
  NW2008,
} from '../../src/rules/nw2xxx.js';

function check(rule: typeof NW2001, yaml: string) {
  const resources = parseContent(yaml, 'test.yaml');
  const ctx = buildContext(resources);
  return rule.check(resources, ctx);
}

describe('NW2001 — Service type NodePort', () => {
  it('triggers for NodePort service', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-nodeport
  namespace: default
spec:
  type: NodePort
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
      nodePort: 30080
`;
    const findings = check(NW2001, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2001');
    expect(findings[0].severity).toBe('warning');
    expect(findings[0].name).toBe('my-nodeport');
  });

  it('does not trigger for ClusterIP service', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-clusterip
  namespace: default
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - port: 80
`;
    expect(check(NW2001, yaml)).toHaveLength(0);
  });

  it('does not trigger for LoadBalancer service', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-lb
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 443
`;
    expect(check(NW2001, yaml)).toHaveLength(0);
  });
});

describe('NW2002 — LoadBalancer without externalTrafficPolicy: Local', () => {
  it('triggers when LoadBalancer has no externalTrafficPolicy', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-lb
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 443
`;
    const findings = check(NW2002, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2002');
  });

  it('triggers when externalTrafficPolicy is Cluster (default)', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-lb
  namespace: default
spec:
  type: LoadBalancer
  externalTrafficPolicy: Cluster
  ports:
    - port: 443
`;
    const findings = check(NW2002, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger when externalTrafficPolicy is Local', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-lb
  namespace: default
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  ports:
    - port: 443
`;
    expect(check(NW2002, yaml)).toHaveLength(0);
  });

  it('does not trigger for ClusterIP service', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    expect(check(NW2002, yaml)).toHaveLength(0);
  });
});

describe('NW2003 — LoadBalancer without source IP restriction', () => {
  it('triggers when LoadBalancer has no loadBalancerSourceRanges', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: open-lb
  namespace: default
spec:
  type: LoadBalancer
  ports:
    - port: 443
`;
    const findings = check(NW2003, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2003');
    expect(findings[0].severity).toBe('info');
  });

  it('does not trigger when loadBalancerSourceRanges is set', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: restricted-lb
  namespace: default
spec:
  type: LoadBalancer
  loadBalancerSourceRanges:
    - 10.0.0.0/8
    - 172.16.0.0/12
  ports:
    - port: 443
`;
    expect(check(NW2003, yaml)).toHaveLength(0);
  });

  it('does not trigger for ClusterIP', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    expect(check(NW2003, yaml)).toHaveLength(0);
  });
});

describe('NW2004 — Service targets port 22 (SSH)', () => {
  it('triggers when service exposes port 22', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: ssh-service
  namespace: default
spec:
  type: ClusterIP
  selector:
    app: bastion
  ports:
    - port: 22
      targetPort: 22
`;
    const findings = check(NW2004, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2004');
    expect(findings[0].severity).toBe('warning');
  });

  it('triggers when targetPort is 22', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: redirect-ssh
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 2222
      targetPort: 22
`;
    const findings = check(NW2004, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger for port 443', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: https-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 443
      targetPort: 8443
`;
    expect(check(NW2004, yaml)).toHaveLength(0);
  });
});

describe('NW2005 — Headless Service without selector', () => {
  it('triggers for headless service without selector', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: headless-no-selector
  namespace: default
spec:
  clusterIP: None
`;
    const findings = check(NW2005, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2005');
    expect(findings[0].severity).toBe('info');
  });

  it('does not trigger for headless service with selector', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: headless-with-selector
  namespace: default
spec:
  clusterIP: None
  selector:
    app: my-statefulset
`;
    expect(check(NW2005, yaml)).toHaveLength(0);
  });

  it('does not trigger for normal ClusterIP service', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: normal-svc
  namespace: default
spec:
  type: ClusterIP
  selector:
    app: web
`;
    expect(check(NW2005, yaml)).toHaveLength(0);
  });
});

describe('NW2006 — Service externalIPs set', () => {
  it('triggers when externalIPs is set', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: ext-ip-svc
  namespace: default
spec:
  type: ClusterIP
  externalIPs:
    - 192.168.1.100
  ports:
    - port: 80
`;
    const findings = check(NW2006, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2006');
    expect(findings[0].severity).toBe('warning');
  });

  it('triggers when multiple externalIPs are set', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: multi-ext-ip
  namespace: default
spec:
  externalIPs:
    - 10.0.0.1
    - 10.0.0.2
  ports:
    - port: 80
`;
    const findings = check(NW2006, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('10.0.0.1');
  });

  it('does not trigger when externalIPs is not set', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: normal-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    expect(check(NW2006, yaml)).toHaveLength(0);
  });
});

describe('NW2007 — Service without sessionAffinity for StatefulSet', () => {
  it('triggers when Service targets StatefulSet without sessionAffinity', () => {
    const yaml = `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-db
  namespace: database
spec:
  replicas: 3
  serviceName: my-db
  selector:
    matchLabels:
      app: my-db
  template:
    metadata:
      labels:
        app: my-db
    spec:
      containers:
        - name: db
          image: postgres:15
---
apiVersion: v1
kind: Service
metadata:
  name: my-db-svc
  namespace: database
spec:
  selector:
    app: my-db
  ports:
    - port: 5432
`;
    const findings = check(NW2007, yaml);
    expect(findings.some(f => f.id === 'NW2007')).toBe(true);
  });

  it('does not trigger when sessionAffinity is ClientIP', () => {
    const yaml = `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-db
  namespace: database
spec:
  replicas: 3
  serviceName: my-db
  selector:
    matchLabels:
      app: my-db
  template:
    metadata:
      labels:
        app: my-db
    spec:
      containers:
        - name: db
          image: postgres:15
---
apiVersion: v1
kind: Service
metadata:
  name: my-db-svc
  namespace: database
spec:
  selector:
    app: my-db
  sessionAffinity: ClientIP
  ports:
    - port: 5432
`;
    const findings = check(NW2007, yaml);
    expect(findings.filter(f => f.id === 'NW2007')).toHaveLength(0);
  });

  it('does not trigger when Service has no matching StatefulSet', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: stateless-svc
  namespace: default
spec:
  selector:
    app: web
  ports:
    - port: 80
`;
    expect(check(NW2007, yaml)).toHaveLength(0);
  });
});

describe('NW2008 — ExternalName Service pointing to internal DNS', () => {
  it('triggers when ExternalName points to .cluster.local', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: internal-external
  namespace: default
spec:
  type: ExternalName
  externalName: my-service.other-namespace.svc.cluster.local
`;
    const findings = check(NW2008, yaml);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('NW2008');
    expect(findings[0].severity).toBe('error');
  });

  it('triggers when ExternalName points to .svc suffix', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: bypass-policy
  namespace: default
spec:
  type: ExternalName
  externalName: backend.production.svc
`;
    const findings = check(NW2008, yaml);
    expect(findings).toHaveLength(1);
  });

  it('does not trigger when ExternalName points to external hostname', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: external-api
  namespace: default
spec:
  type: ExternalName
  externalName: api.example.com
`;
    expect(check(NW2008, yaml)).toHaveLength(0);
  });

  it('does not trigger for non-ExternalName service', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: clusterip-svc
  namespace: default
spec:
  type: ClusterIP
  ports:
    - port: 80
`;
    expect(check(NW2008, yaml)).toHaveLength(0);
  });
});
