# NetworkVet Roadmap

## v0.1.0 — Manifest Mode (Week 6)

**Goal:** Static analysis of NetworkPolicy, Service, and Ingress manifests.

**Dependencies:** ManifestVet parser (reused)

- [ ] YAML parser (reuse ManifestVet parser)
- [ ] Rule engine (NW1–4, 30+ rules)
- [ ] TTY / JSON / SARIF formatters
- [ ] CLI (`--dir`, `--format`, `--ignore`)
- [ ] 90+ tests
- [ ] npm publish

---

## v0.2.0 — Live Cluster Mode (Week 7)

**Goal:** Analyze network configuration from a running cluster.

- [ ] `--cluster` flag — kubeconfig integration
- [ ] `--all-namespaces` — cross-namespace analysis
- [ ] Fetch NetworkPolicy, Service, Ingress, Endpoints via K8s API
- [ ] Detect CNI plugin type from cluster (affects rule applicability)

---

## v0.3.0 — Reachability Analysis (Week 8)

**Goal:** Compute pod-to-pod and namespace-to-namespace reachability.

- [ ] NetworkPolicy evaluator (given policy set, can A reach B?)
- [ ] Namespace-level reachability matrix
- [ ] `--reachability` flag with text/JSON/HTML output
- [ ] Open path detection (unprotected namespaces + exposed pods)
- [ ] `--format matrix` — ASCII table output

---

## v0.4.0 — LLM Fix Suggestions (Week 9)

**Goal:** Generate least-permissive NetworkPolicy for each workload.

- [ ] `--fix` flag — generate default-deny + targeted allow policies
- [ ] Auto-detect required ports from Service definitions
- [ ] Suggest HSTS and redirect annotations for Ingress
- [ ] Japanese explanations (`--fix-lang ja`)

---

## v0.5.0 — Visualization & Reporting (Week 10)

**Goal:** Interactive network topology reporting.

- [ ] `--format html` — interactive network graph (D3.js)
- [ ] DOT format for Graphviz rendering
- [ ] `--diff` — compare network policies before/after change
- [ ] Baseline mode (only report new open paths vs last scan)

---

## Future

- [ ] Service mesh support (Istio AuthorizationPolicy)
- [ ] Cilium NetworkPolicy support (eBPF-based)
- [ ] Cloud provider-specific firewall rule correlation (VPC, Security Groups)
- [ ] Real-time traffic analysis integration (eBPF-based sniffing)
