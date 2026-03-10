# NetworkVet

Kubernetes network security analyzer. Detects missing NetworkPolicies, overly permissive traffic rules, and insecure Service/Ingress configurations. Generates a pod-to-pod reachability matrix.

```
$ networkvet --dir ./k8s/

k8s/network-policies.yaml
  NW1001  error    NetworkPolicy/allow-all  ingress from: [{}] allows all sources
  NW1002  warning  Namespace/payments       no NetworkPolicy defined — all traffic allowed

k8s/services.yaml
  NW2001  warning  Service/api-server  type NodePort exposes port 8080 on all nodes
  NW3001  error    Ingress/main-ingress  no TLS configured

Reachability Matrix (cross-namespace):
  frontend → backend:  ✅ allowed (NetworkPolicy)
  frontend → payments: ✅ allowed (no policy = open)  ⚠️
  backend  → payments: ✅ allowed (no policy = open)  ⚠️
  *        → monitoring: ✅ allowed (no policy = open) ⚠️

2 errors, 4 warnings — 3 unprotected namespaces
```

## Installation

```bash
npm install -g networkvet
```

## Usage

```bash
# Scan manifest files
networkvet networkpolicy.yaml service.yaml ingress.yaml

# Scan a directory
networkvet --dir ./k8s/

# Live cluster scan
networkvet --cluster
networkvet --cluster --all-namespaces

# Reachability analysis
networkvet --reachability --dir ./k8s/
networkvet --reachability --cluster

# Output formats
networkvet --format tty   --dir ./k8s/
networkvet --format json  --dir ./k8s/
networkvet --format sarif --dir ./k8s/
networkvet --format matrix --cluster   # reachability matrix (text table)
```

## Rules

30+ rules across 4 categories:

| Prefix | Category | Count |
|--------|----------|-------|
| NW1xxx | NetworkPolicy | 10 |
| NW2xxx | Service Design | 8 |
| NW3xxx | Ingress Security | 7 |
| NW4xxx | Cluster-Level | 5 |

### NW1xxx — NetworkPolicy

| ID | Severity | Description |
|----|----------|-------------|
| NW1001 | error | Ingress `from: [{}]` — allows all sources |
| NW1002 | error | Egress `to: [{}]` — allows all destinations |
| NW1003 | warning | Namespace has no NetworkPolicy (all traffic permitted) |
| NW1004 | warning | NetworkPolicy `podSelector: {}` targets all pods in namespace |
| NW1005 | warning | NetworkPolicy allows traffic from all namespaces (`namespaceSelector: {}`) |
| NW1006 | info | NetworkPolicy does not restrict egress DNS (port 53) |
| NW1007 | warning | NetworkPolicy allows traffic from `kube-system` namespace to workload pods |
| NW1008 | info | NetworkPolicy with empty `policyTypes` |
| NW1009 | warning | Ingress policy missing — pod has no ingress restrictions |
| NW1010 | warning | Egress policy missing — pod has no egress restrictions |

### NW2xxx — Service Design

| ID | Severity | Description |
|----|----------|-------------|
| NW2001 | warning | Service type `NodePort` (exposes port on all cluster nodes) |
| NW2002 | warning | Service type `LoadBalancer` without `externalTrafficPolicy: Local` |
| NW2003 | info | `LoadBalancer` Service without source IP restriction annotation |
| NW2004 | warning | Service targets port 22 (SSH) |
| NW2005 | info | Headless Service (`clusterIP: None`) without selector |
| NW2006 | warning | Service `externalIPs` field set (potential MITM risk) |
| NW2007 | info | Service without `sessionAffinity` on stateful workload |
| NW2008 | error | Service of type `ExternalName` pointing to internal cluster DNS |

### NW3xxx — Ingress Security

| ID | Severity | Description |
|----|----------|-------------|
| NW3001 | error | Ingress without TLS configured |
| NW3002 | warning | Ingress TLS but no HSTS annotation |
| NW3003 | warning | Ingress without HTTP→HTTPS redirect |
| NW3004 | warning | Ingress with wildcard host (`*`) |
| NW3005 | info | Ingress without `nginx.ingress.kubernetes.io/ssl-redirect` annotation |
| NW3006 | warning | Ingress exposes admin/internal paths publicly (`/admin`, `/_`) |
| NW3007 | error | Ingress references non-existent Service backend |

### NW4xxx — Cluster-Level

| ID | Severity | Description |
|----|----------|-------------|
| NW4001 | warning | No default-deny NetworkPolicy in namespace |
| NW4002 | info | CNI does not support NetworkPolicy enforcement (detected from annotations) |
| NW4003 | warning | Cross-namespace traffic not restricted |
| NW4004 | info | `kube-dns` accessible from all namespaces |
| NW4005 | warning | MetadataAPI (169.254.169.254) not blocked in egress policies |

## Reachability Matrix

```bash
networkvet --reachability --cluster --format json | jq '.matrix'
```

Output:
```json
{
  "matrix": {
    "frontend": { "backend": "allowed", "payments": "allowed (no policy)", "monitoring": "allowed (no policy)" },
    "backend":  { "payments": "allowed (no policy)", "monitoring": "denied" },
    "payments": { "frontend": "denied", "monitoring": "allowed" }
  },
  "unprotectedNamespaces": ["payments", "monitoring"],
  "openPaths": [
    { "from": "frontend", "to": "payments", "risk": "medium", "reason": "no NetworkPolicy in payments namespace" }
  ]
}
```

## Configuration

Create `.networkvet.yaml`:

```yaml
ignore:
  - NW1006   # DNS egress restriction (managed by CNI)
  - NW2007   # Session affinity

override:
  NW1003:
    severity: error  # no NetworkPolicy = error in our env

# Known ingress controllers (affects annotation checks)
ingressClass: nginx

# Namespaces excluded from reachability matrix
excludeNamespaces:
  - kube-system
  - cert-manager
```

## CI Integration

```yaml
- name: Scan Network Policies
  run: |
    npm install -g networkvet
    networkvet --format sarif --dir ./k8s/ > network-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: network-results.sarif
```

## License

MIT
