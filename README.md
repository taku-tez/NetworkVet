# NetworkVet

Kubernetes network security analyzer. Detects misconfigurations across **66 rules** in NetworkPolicy, Istio, Cilium, Gateway API, and cloud provider resources. Computes pod-to-pod reachability, simulates policy changes, analyzes traffic logs, exports OPA/Rego policies, and runs as a ValidatingWebhook.

```
$ networkvet --dir ./k8s/

k8s/network-policies.yaml
  NW1001  error    NetworkPolicy/allow-all  ingress from: [{}] allows all sources
  NW1002  warning  Namespace/payments       no NetworkPolicy defined — all traffic allowed

k8s/services.yaml
  NW2001  warning  Service/api-server  type NodePort exposes port 8080 on all nodes
  NW3001  error    Ingress/main-ingress  no TLS configured

2 errors, 4 warnings — 3 unprotected namespaces
```

## Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Rules](#rules)
- [Reachability Analysis](#reachability-analysis)
- [Policy Simulation](#policy-simulation)
- [Blast Radius Analysis](#blast-radius-analysis)
- [Traffic Log Analysis](#traffic-log-analysis)
- [Fix Suggestions](#fix-suggestions)
- [Helm / Kustomize Support](#helm--kustomize-support)
- [OPA / Rego Export](#oparego-export)
- [Compliance Reporting](#compliance-reporting)
- [Admission Webhook](#admission-webhook)
- [CI / CD Integration](#cicd-integration)
- [Configuration File](#configuration-file)
- [Per-Resource Ignores](#per-resource-ignores)
- [Exit Codes](#exit-codes)

---

## Installation

```bash
npm install -g networkvet
```

Requires Node.js 18+.

---

## Quick Start

```bash
# Scan a directory of manifests
networkvet --dir ./k8s/

# Scan a single file
networkvet --file deployment.yaml

# Scan live cluster (current kubeconfig context)
networkvet --cluster

# Scan all namespaces in cluster
networkvet --cluster --all-namespaces

# JSON output
networkvet --dir ./k8s/ --format json

# SARIF output (for GitHub Code Scanning)
networkvet --dir ./k8s/ --format sarif --output results.sarif
```

---

## CLI Reference

### Input

| Flag | Description |
|------|-------------|
| `--dir <path>` | Scan all YAML files in a directory (recursive) |
| `--file <path>` | Scan a single YAML file |
| `--cluster` | Fetch resources from the live cluster (current kubeconfig context) |
| `--all-namespaces` | With `--cluster`: scan all namespaces |
| `--namespace <ns>` | Filter output to a specific namespace |

### Output

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: `tty` (default), `json`, `sarif`, `matrix`, `dot`, `rego`, `gatekeeper`, `conftest`, `compliance` |
| `--output <file>` | Write output to a file instead of stdout |
| `--severity <level>` | Show only findings at or above: `critical`, `high`, `medium`, `low`, `info` |
| `--rule <ids>` | Show only findings for specific rules (comma-separated, e.g. `NW1001,NW2003`) |
| `--group-by <key>` | Group TTY output by: `file`, `namespace`, `severity`, `rule` |
| `--no-color` | Disable color output |

### Analysis

| Flag | Description |
|------|-------------|
| `--reachability` | Include namespace-level reachability analysis |
| `--level <lvl>` | Reachability detail level: `namespace` (default) or `pod` |
| `--simulate <file>` | Simulate applying a YAML file; show gained/lost reachability paths |
| `--blast-radius <ref>` | BFS blast radius from a workload (format: `namespace/name` or `name`) |
| `--traffic-log <file>` | Correlate observed traffic flows against declared policies |
| `--traffic-format <fmt>` | Traffic log format: `hubble`, `falco`, `generic` (auto-detected if omitted) |
| `--fix` | Generate least-permissive fix suggestions for each finding |
| `--fix-lang <lang>` | Fix suggestion language: `en` (default) or `ja` |
| `--diff <file>` | Compare current scan against a previous JSON baseline |

### CI / CD

| Flag | Description |
|------|-------------|
| `--fail-on <level>` | Exit code 1 when findings at or above this severity exist (default: `high`) |
| `--ignore <ids>` | Globally suppress rule IDs (comma-separated) |
| `--config <file>` | Path to `.networkvet.yaml` config (auto-discovered if omitted) |

### Helm / Kustomize

| Flag | Description |
|------|-------------|
| `--helm-values <file>` | Path to Helm `values.yaml` for resolving `{{ .Values.xxx }}` |
| `--helm-release-name <name>` | Helm release name for `{{ .Release.Name }}` (default: `release`) |
| `--helm-release-namespace <ns>` | Helm release namespace for `{{ .Release.Namespace }}` |

### Verbose / Debug

| Flag | Description |
|------|-------------|
| `--verbose` | Print per-rule timing table, resource count, and skipped Helm files to stderr |

---

## Rules

**66 rules across 8 categories.** All rules include fix suggestions (`--fix`), OPA/Rego policies, and CIS/NSA compliance mappings.

| Prefix | Category | Count |
|--------|----------|-------|
| NW1xxx | NetworkPolicy | 10 |
| NW2xxx | Service Design | 8 |
| NW3xxx | Ingress Security | 7 |
| NW4xxx | Cluster-Level | 5 |
| NW5xxx | Istio (AuthorizationPolicy / PeerAuthentication) | 8 |
| NW6xxx | Cilium (CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy) | 8 |
| NW7xxx | Cloud Provider (AWS EKS / GCP GKE / Azure AKS) | 15 |
| NW8xxx | Kubernetes Gateway API | 5 |

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
| NW5002 | warning | AuthorizationPolicy ALLOW rule has a `from` clause with an empty source |
| NW5003 | warning | AuthorizationPolicy ALLOW rule permits all HTTP methods (`methods: ["*"]`) |
| NW5004 | error | AuthorizationPolicy ALLOW rule has neither `from` nor `to` — allows all traffic unconditionally |
| NW5005 | warning | PeerAuthentication uses PERMISSIVE mTLS mode — plaintext traffic accepted |
| NW5006 | error | PeerAuthentication disables mTLS (`mode: DISABLE`) — all traffic is plaintext |
| NW5007 | info | AuthorizationPolicy has no workload selector — applies to all workloads in the namespace |
| NW5008 | warning | AuthorizationPolicy ALLOW rule specifies principals but does not restrict source namespace |

### NW6xxx — Cilium CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy

| ID | Severity | Description |
|----|----------|-------------|
| NW6001 | error | Ingress rule allows traffic from the `"world"` entity (any external IP) |
| NW6002 | warning | Egress rule allows traffic to the `"world"` entity (any external IP) |
| NW6003 | error | Rule uses the `"all"` entity — matches every endpoint in the cluster |
| NW6004 | info | Empty `endpointSelector` — applies to all pods in the namespace |
| NW6005 | error | Ingress rule allows from CIDR `0.0.0.0/0` (any IP) |
| NW6006 | warning | CiliumClusterwideNetworkPolicy has no `nodeSelector` — applies to all cluster nodes |
| NW6007 | warning | Egress uses `toFQDNs matchPattern: "*"` — allows egress to any domain |
| NW6008 | info | L7 HTTP rules defined — verify application-layer enforcement is active |

### NW7xxx — Cloud Provider (AWS EKS / GCP GKE / Azure AKS)

Rules fire only when cloud-provider-specific annotations are detected. Provider is inferred automatically from annotation namespaces (`alb.ingress.kubernetes.io/` → AWS, `cloud.google.com/` → GCP, `azure` → Azure).

#### AWS (EKS)

| ID | Severity | Description |
|----|----------|-------------|
| NW7001 | warning | NLB Service has no internal annotation — load balancer may be internet-facing |
| NW7002 | error | LoadBalancer Service has access logs explicitly disabled |
| NW7003 | warning | Public LoadBalancer has no SSL certificate annotation — HTTPS offload not configured |
| NW7004 | info | SSL configured but no TLS negotiation policy pinned |
| NW7005 | warning | ALB Ingress has no scheme annotation — defaults to internet-facing |
| NW7006 | error | ALB Ingress has no custom security group annotation |
| NW7007 | warning | ALB Ingress TLS configured but no ssl-policy annotation — cipher suite not pinned |
| NW7008 | info | LoadBalancer Service has connection draining explicitly disabled |

#### GCP (GKE)

| ID | Severity | Description |
|----|----------|-------------|
| NW7009 | warning | LoadBalancer Service has no internal annotation — may be internet-facing |
| NW7010 | warning | GCE Ingress does not disable HTTP — unencrypted path to backend |
| NW7011 | info | LoadBalancer Service has no load-balancer-type annotation — intent not explicit |
| NW7012 | warning | BackendConfig has no Cloud Armor security policy configured |

#### Azure (AKS)

| ID | Severity | Description |
|----|----------|-------------|
| NW7013 | warning | LoadBalancer Service has `azure-load-balancer-internal: "false"` — explicitly internet-facing |
| NW7014 | info | LoadBalancer Service has no `azure-load-balancer-internal` annotation — intent not explicit |
| NW7015 | warning | Azure Application Gateway Ingress has no WAF policy annotation |

### NW8xxx — Kubernetes Gateway API

| ID | Severity | Description |
|----|----------|-------------|
| NW8001 | medium | HTTPRoute served over plain HTTP without TLS termination |
| NW8002 | medium | Gateway listener allows routes from all namespaces (`allowedRoutes.namespaces.from: All`) |
| NW8003 | high | HTTPRoute cross-namespace backendRef without a ReferenceGrant |
| NW8004 | high | Gateway HTTPS/TLS listener has no `certificateRefs` configured |
| NW8005 | high | GRPCRoute cross-namespace backendRef without a ReferenceGrant |

---

## Reachability Analysis

### Namespace-level (default)

```bash
networkvet --reachability --dir ./k8s/
networkvet --reachability --cluster --format json | jq '.matrix'
networkvet --reachability --cluster --format matrix   # ASCII table
```

### Pod-level

```bash
# Show which workloads can reach each other (label-selector aware)
networkvet --reachability --level pod --dir ./k8s/

# JSON output with full result set
networkvet --reachability --level pod --dir ./k8s/ --format json | jq '.podReachability'
```

Output includes per-pair results with `allowed`, `reason` (`no-policy`, `policy-allow`, `policy-deny`), and a summary with counts by reason.

---

## Policy Simulation

Preview reachability changes before applying a new NetworkPolicy:

```bash
# Show which paths are gained or lost when applying a new policy
networkvet --dir ./k8s/ --simulate new-policy.yaml

# JSON output
networkvet --dir ./k8s/ --simulate new-policy.yaml --format json | jq '.simulationDiff'
```

Output:
```
Simulation: applying new-policy.yaml

GAINED paths (2):
  + production/api → production/payments [policy-allow]
  + production/frontend → production/api [policy-allow]

LOST paths (1):
  - production/legacy → production/db [policy-deny]

Summary: 2 gained, 1 lost, 14 unchanged
```

`--simulate` overlays the provided YAML onto the existing resource set (replacing any resource with the same kind/namespace/name) before computing reachability. Normal analysis continues after the simulation output.

---

## Blast Radius Analysis

Compute how far an attacker can move laterally from a compromised workload:

```bash
# Blast radius from a specific workload
networkvet --dir ./k8s/ --blast-radius production/api-server

# Short form (defaults to 'default' namespace)
networkvet --dir ./k8s/ --blast-radius api-server

# JSON output
networkvet --dir ./k8s/ --blast-radius production/api-server --format json
```

Output:
```
Blast Radius: production/api-server

Reachable workloads (4):
  [depth=1] production/payments-svc (Deployment)
  [depth=1] production/db (StatefulSet)
  [depth=2] kube-system/metrics-server (Deployment)  ⚠ HIGH RISK
  [depth=2] kube-system/coredns (Deployment)         ⚠ HIGH RISK

High-risk targets reachable: 2
Contained (not reachable): 3 workloads
```

High-risk targets: `kube-apiserver`, `kubernetes`, `etcd`, `metrics-server`, `coredns`, `kube-dns`.

---

## Traffic Log Analysis

Correlate observed network flows against declared NetworkPolicies to expose real-world gaps. Supports Hubble (Cilium), Falco, and generic CSV (tcpdump-like) formats.

```bash
# Auto-detect format
networkvet --dir ./k8s/ --traffic-log hubble-flows.json

# Explicit format
networkvet --dir ./k8s/ --traffic-log flows.json --traffic-format hubble
networkvet --cluster --traffic-log /var/log/falco-events.json --traffic-format falco
networkvet --dir ./k8s/ --traffic-log network-flows.csv --traffic-format generic

# JSON includes trafficAnalysis key
networkvet --dir ./k8s/ --traffic-log flows.json --format json | jq '.trafficAnalysis'
```

### Violation types

| Type | Description |
|------|-------------|
| `policy-gap` | Traffic allowed to a namespace with no ingress NetworkPolicy — gap is actively exploited |
| `unexpected-allow` | Traffic reached a destination that has a NetworkPolicy blocking this source |
| `unexpected-deny` | Traffic dropped but a declared policy should permit it |
| `shadow-traffic` | Traffic on a port not covered by any Service |

---

## Fix Suggestions

Generate least-permissive remediation YAML for each finding:

```bash
# Show fix suggestions in terminal
networkvet --dir ./k8s/ --fix

# Japanese explanations
networkvet --dir ./k8s/ --fix --fix-lang ja

# JSON output includes fixSuggestions
networkvet --dir ./k8s/ --fix --format json | jq '.fixSuggestions'
```

Fix suggestions are available for all 66 rules and include copy-paste YAML snippets.

---

## Helm / Kustomize Support

YAML files containing unresolved Helm template expressions (`{{ ... }}`) are automatically detected and skipped to avoid parse errors. Use `--verbose` to see which files were skipped.

```bash
# Scan a Helm chart directory — templated files are skipped safely
networkvet --dir ./charts/my-app/templates/ --verbose

# Resolve templates before scanning
networkvet --dir ./charts/my-app/templates/ \
  --helm-values ./charts/my-app/values.yaml \
  --helm-release-name my-release \
  --helm-release-namespace production
```

**Resolved expressions:**

| Expression | Resolved from |
|------------|--------------|
| `{{ .Release.Name }}` | `--helm-release-name` |
| `{{ .Release.Namespace }}` | `--helm-release-namespace` |
| `{{ .Release.Service }}` | `--helm-release-name` |
| `{{ .Values.x.y }}` | `--helm-values` file |

Complex expressions (`{{ include ... }}`, `{{ if ... }}`, `{{ range ... }}`) are left as-is; files containing them after resolution are skipped.

---

## OPA / Rego Export

Export findings as enforcement policies for OPA-based tooling. All 66 rules have Rego policies.

```bash
# Gatekeeper ConstraintTemplate YAMLs
networkvet --dir ./k8s/ --format gatekeeper > gatekeeper-constraints.yaml
kubectl apply -f gatekeeper-constraints.yaml

# Conftest-compatible Rego policies
networkvet --dir ./k8s/ --format conftest > policy.rego
conftest verify --policy policy.rego ./k8s/

# Raw Rego (for opa eval)
networkvet --dir ./k8s/ --format rego > policies.rego
opa eval --data policies.rego --input resource.json "data.networkvet.deny"
```

---

## Compliance Reporting

Map findings to **CIS Kubernetes Benchmark v1.8** and **NSA/CISA Kubernetes Hardening Guide** controls.

```bash
# All frameworks
networkvet --dir ./k8s/ --format compliance

# Filter by framework
networkvet --dir ./k8s/ --format compliance --compliance cis
networkvet --dir ./k8s/ --format compliance --compliance nsa

# JSON
networkvet --dir ./k8s/ --format compliance --compliance cis --format json | jq '.complianceFindings'
```

SARIF output includes taxonomy and relationship metadata for GitHub Code Scanning compliance views.

---

## Admission Webhook

Run NetworkVet as a Kubernetes `ValidatingWebhookConfiguration` to enforce policies at admission time.

```bash
# Deploy webhook (prints Namespace, ServiceAccount, Deployment, Service, ValidatingWebhookConfiguration)
networkvet --webhook-manifest | kubectl apply -f -

# Create TLS secret
kubectl create secret tls networkvet-webhook-tls \
  --cert=tls.crt --key=tls.key \
  -n networkvet-system

# Run webhook server manually
networkvet --webhook --webhook-port 8443 \
  --webhook-cert /etc/networkvet/tls/tls.crt \
  --webhook-key  /etc/networkvet/tls/tls.key \
  --webhook-deny-on-error
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /validate` | AdmissionReview handler for supported resource kinds |
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness probe |

### Modes

| Flag | Behavior |
|------|----------|
| _(default)_ | Warn-only: findings returned as `AdmissionReview.response.warnings`; admission always succeeds |
| `--webhook-deny-on-error` | Deny mode: `severity=error` findings cause `allowed: false` |

**Validated kinds:** `NetworkPolicy`, `Service`, `Ingress`, `AuthorizationPolicy`, `PeerAuthentication`, `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `BackendConfig`, `Gateway`, `HTTPRoute`, `GRPCRoute`

`failurePolicy: Ignore` — webhook unavailability never blocks admission.

---

## CI / CD Integration

### GitHub Action (recommended)

```yaml
# .github/workflows/network-scan.yml
name: Network Security Scan
on: [push, pull_request]

jobs:
  networkvet:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: NetworkVet/networkvet@main
        with:
          dir: ./k8s/
          format: sarif
          fail-on: high          # exit 1 on high/critical findings
          output: results.sarif  # auto-uploaded to GitHub Code Scanning
```

#### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `dir` | — | Directory of manifests to scan |
| `file` | — | Single manifest file |
| `format` | `sarif` | Output format |
| `output` | `networkvet-results.sarif` | Output file path |
| `fail-on` | `high` | Minimum severity for exit code 1 |
| `ignore` | — | Comma-separated rule IDs to suppress |
| `severity` | — | Minimum severity to display |
| `config` | — | Path to `.networkvet.yaml` |
| `version` | `latest` | npm version of networkvet to install |

#### Action outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `finding-count` | Total number of findings (JSON format only) |

### Manual CI setup

```yaml
- name: Scan Network Policies
  run: |
    npm install -g networkvet
    networkvet --dir ./k8s/ --format sarif --output results.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### Pre-commit hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
changed=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.ya?ml$')
if [ -n "$changed" ]; then
  networkvet --file $changed --fail-on high
fi
```

---

## Configuration File

Create `.networkvet.yaml` (or `.networkvet.yml` / `networkvet.config.yaml`) in your project root:

```yaml
# Suppress specific rules globally
ignore:
  - NW1006   # DNS egress restriction (managed by CNI)
  - NW2007   # Session affinity

# Override rule severity
override:
  NW1003:
    severity: error   # no NetworkPolicy = error in our environment
  NW2001:
    enabled: false    # disable NodePort rule entirely

# Known ingress controller (affects annotation checks)
ingressClass: nginx

# Namespaces excluded from reachability analysis
excludeNamespaces:
  - kube-system
  - cert-manager

# Force cloud provider detection (skips auto-detection)
cloudProvider: aws
```

Config file is auto-discovered walking up from the current directory. Override with `--config <path>`.

---

## Per-Resource Ignores

Suppress specific rules on individual resources using the `networkvet.io/ignore` annotation:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: production
  annotations:
    networkvet.io/ignore: "NW1004,NW1005"  # suppress these rules for this resource only
spec:
  podSelector: {}
  ingress:
    - from:
        - namespaceSelector: {}
```

Multiple rule IDs are comma-separated. The annotation is processed at analysis time and never propagates to the cluster.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` threshold |
| `1` | One or more findings at or above `--fail-on` threshold (default: `high`) |
| `2` | Fatal error (file not found, cluster unreachable, invalid arguments) |

`--severity` filters displayed output but does **not** affect the exit code. Exit code always reflects the full unfiltered finding set.

---

## License

MIT
