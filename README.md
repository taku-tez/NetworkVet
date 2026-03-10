# NetworkVet

Kubernetes network security analyzer. Detects missing NetworkPolicies, overly permissive traffic rules, insecure Service/Ingress configurations, Istio AuthorizationPolicy misconfigurations, Cilium NetworkPolicy issues, and cloud provider firewall misconfigurations. Correlates observed traffic (Hubble, Falco, tcpdump) against declared policies to find real-world gaps. Exports findings as OPA/Rego policies for Gatekeeper and Conftest. Runs as a Kubernetes ValidatingWebhook for live cluster admission control.

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

## Traffic Log Analysis

Correlate observed network flows against declared NetworkPolicies to expose real-world policy gaps and misconfigurations. Supports **Hubble** (Cilium), **Falco**, and generic CSV (tcpdump-like) log formats.

```bash
# Analyze Hubble flow logs against manifests (auto-detect format)
networkvet --dir ./k8s/ --traffic-log hubble-flows.json

# Specify format explicitly
networkvet --dir ./k8s/ --traffic-log flows.json --traffic-format hubble

# Falco events
networkvet --cluster --traffic-log /var/log/falco-events.json --traffic-format falco

# Generic CSV (tcpdump-like)
networkvet --dir ./k8s/ --traffic-log network-flows.csv --traffic-format generic

# JSON output includes trafficAnalysis key
networkvet --dir ./k8s/ --traffic-log flows.json --format json | jq '.trafficAnalysis'
```

### Violation types detected

| Type | Severity | Description |
|------|----------|-------------|
| `policy-gap` | warning | Traffic was ALLOWED to a namespace with no ingress NetworkPolicy — gap is actively exploited |
| `unexpected-allow` | error | Traffic reached a destination that has a NetworkPolicy blocking this source — possible bypass |
| `unexpected-deny` | warning | Traffic was DROPPED but a declared policy should permit it — sync issue or node firewall |
| `shadow-traffic` | info | Traffic on a port not covered by any Service — unknown protocol or misconfigured app |

## Rules

53+ rules across 7 categories:

| Prefix | Category | Count |
|--------|----------|-------|
| NW1xxx | NetworkPolicy | 10 |
| NW2xxx | Service Design | 8 |
| NW3xxx | Ingress Security | 7 |
| NW4xxx | Cluster-Level | 5 |
| NW5xxx | Istio (AuthorizationPolicy / PeerAuthentication) | 8 |
| NW6xxx | Cilium (CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy) | 8 |
| NW7xxx | Cloud Provider (AWS EKS / GCP GKE / Azure AKS) | 15 |

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

### NW5xxx — Istio AuthorizationPolicy / PeerAuthentication

| ID | Severity | Description |
|----|----------|-------------|
| NW5001 | error | AuthorizationPolicy ALLOW rule grants access to all principals (`principals: ["*"]`) |
| NW5002 | warning | AuthorizationPolicy ALLOW rule has a `from` clause with an empty source (matches any source) |
| NW5003 | warning | AuthorizationPolicy ALLOW rule permits all HTTP methods (`methods: ["*"]`) |
| NW5004 | error | AuthorizationPolicy ALLOW rule has neither `from` nor `to` — allows all traffic unconditionally |
| NW5005 | warning | PeerAuthentication uses PERMISSIVE mTLS mode — plaintext traffic is accepted |
| NW5006 | error | PeerAuthentication disables mTLS (`mode: DISABLE`) — all traffic is plaintext |
| NW5007 | info | AuthorizationPolicy has no workload selector — applies to all workloads in the namespace |
| NW5008 | warning | AuthorizationPolicy ALLOW rule specifies principals but does not restrict source namespace |

### NW6xxx — Cilium CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy

| ID | Severity | Description |
|----|----------|-------------|
| NW6001 | error | CiliumNetworkPolicy ingress rule allows traffic from the `"world"` entity (any external IP) |
| NW6002 | warning | CiliumNetworkPolicy egress rule allows traffic to the `"world"` entity (any external IP) |
| NW6003 | error | CiliumNetworkPolicy rule uses the `"all"` entity — matches every endpoint in the cluster |
| NW6004 | info | CiliumNetworkPolicy has an empty `endpointSelector` — applies to all pods in the namespace |
| NW6005 | error | CiliumNetworkPolicy ingress rule allows from CIDR `0.0.0.0/0` (any IP) |
| NW6006 | warning | CiliumClusterwideNetworkPolicy has no `nodeSelector` — applies to all nodes in the cluster |
| NW6007 | warning | CiliumNetworkPolicy egress uses `toFQDNs matchPattern: "*"` — allows egress to any domain |
| NW6008 | info | CiliumNetworkPolicy defines L7 HTTP rules — verify application-layer enforcement is working |

### NW7xxx — Cloud Provider (AWS EKS / GCP GKE / Azure AKS)

Rules fire only when cloud-provider-specific annotations are detected on the resource. Cloud provider is inferred automatically from annotation namespaces (e.g. `alb.ingress.kubernetes.io/` → AWS, `cloud.google.com/` → GCP, `azure` → Azure).

#### AWS (EKS)

| ID | Severity | Description |
|----|----------|-------------|
| NW7001 | warning | AWS NLB Service has no internal annotation — load balancer may be internet-facing |
| NW7002 | error | AWS LoadBalancer Service has access logs explicitly disabled |
| NW7003 | warning | Public AWS LoadBalancer has no SSL certificate annotation — HTTPS offload not configured |
| NW7004 | info | AWS LoadBalancer Service has SSL configured but no TLS negotiation policy pinned |
| NW7005 | warning | ALB Ingress has no scheme annotation — defaults to internet-facing |
| NW7006 | error | ALB Ingress has no custom security group annotation — uses permissive default |
| NW7007 | warning | ALB Ingress has TLS configured but no ssl-policy annotation — cipher suite not pinned |
| NW7008 | info | AWS LoadBalancer Service has connection draining explicitly disabled |

#### GCP (GKE)

| ID | Severity | Description |
|----|----------|-------------|
| NW7009 | warning | GKE LoadBalancer Service has no internal annotation — may be internet-facing |
| NW7010 | warning | GCE Ingress does not disable HTTP — traffic can reach backend unencrypted |
| NW7011 | info | GKE LoadBalancer Service has no load-balancer-type annotation — intent not explicit |
| NW7012 | warning | GKE BackendConfig has no Cloud Armor security policy configured |

#### Azure (AKS)

| ID | Severity | Description |
|----|----------|-------------|
| NW7013 | warning | AKS LoadBalancer Service has `azure-load-balancer-internal: "false"` — explicitly internet-facing |
| NW7014 | info | AKS LoadBalancer Service has no `azure-load-balancer-internal` annotation — intent not explicit |
| NW7015 | warning | Azure Application Gateway Ingress has no WAF policy annotation |

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

## OPA/Rego Policy Export

Export detected findings as enforcement policies for OPA-based tools.

```bash
# Show a summary of available Rego policies (TTY)
networkvet --dir ./k8s/ --format rego

# Export raw Rego policies (for OPA evaluation)
networkvet --dir ./k8s/ --format rego > policies.rego

# Export Gatekeeper ConstraintTemplate YAMLs
networkvet --dir ./k8s/ --format gatekeeper > gatekeeper-constraints.yaml
kubectl apply -f gatekeeper-constraints.yaml

# Export Conftest-compatible Rego policies
networkvet --dir ./k8s/ --format conftest > policy.rego
conftest verify --policy policy.rego ./k8s/
```

Rego policies are available for: NW1001, NW1002, NW1003, NW2001, NW2002, NW3001, NW3004, NW5001, NW5005, NW5006, NW6001, NW6005.

## Admission Webhook

Run NetworkVet as a Kubernetes `ValidatingWebhookConfiguration` to validate resources at admission time.

```bash
# Print the deployment manifest (Namespace, ServiceAccount, Deployment, Service, ValidatingWebhookConfiguration)
networkvet --webhook-manifest | kubectl apply -f -

# Apply TLS secret for the webhook server
kubectl create secret tls networkvet-webhook-tls \
  --cert=tls.crt --key=tls.key \
  -n networkvet-system

# Run the webhook server manually (for testing)
networkvet --webhook --webhook-port 8443 \
  --webhook-cert /etc/networkvet/tls/tls.crt \
  --webhook-key  /etc/networkvet/tls/tls.key \
  --webhook-deny-on-error
```

### Webhook endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/validate` | POST | AdmissionReview handler — validates CREATE/UPDATE for supported resource kinds |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe |

### Webhook modes

| Flag | Behavior |
|------|----------|
| _(default)_ | Warn-only: errors and warnings are returned as `AdmissionReview.response.warnings`; admission always succeeds |
| `--webhook-deny-on-error` | Deny mode: findings with `severity=error` cause `allowed: false` with HTTP 403 status |

Webhook uses `failurePolicy: Ignore` — if the webhook server is unavailable, admission continues unimpeded.

### Validated resource kinds

`NetworkPolicy`, `Service`, `Ingress`, `AuthorizationPolicy`, `PeerAuthentication`, `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `BackendConfig`

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
