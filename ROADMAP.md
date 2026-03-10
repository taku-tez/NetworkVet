# NetworkVet Roadmap

## v0.1.0 — Manifest Mode (Week 6)

**Goal:** Static analysis of NetworkPolicy, Service, and Ingress manifests.

**Dependencies:** ManifestVet parser (reused)

- [x] YAML parser (reuse ManifestVet parser)
- [x] Rule engine (NW1–4, 30+ rules)
- [x] TTY / JSON / SARIF formatters
- [x] CLI (`--dir`, `--format`, `--ignore`)
- [x] 90+ tests
- [x] npm publish

---

## v0.2.0 — Live Cluster Mode (Week 7)

**Goal:** Analyze network configuration from a running cluster.

- [x] `--cluster` flag — kubeconfig integration
- [x] `--all-namespaces` — cross-namespace analysis
- [x] Fetch NetworkPolicy, Service, Ingress, Endpoints via K8s API
- [x] Detect CNI plugin type from cluster (affects rule applicability)

---

## v0.3.0 — Reachability Analysis (Week 8)

**Goal:** Compute pod-to-pod and namespace-to-namespace reachability.

- [x] NetworkPolicy evaluator (given policy set, can A reach B?)
- [x] Namespace-level reachability matrix
- [x] `--reachability` flag with text/JSON/HTML output
- [x] Open path detection (unprotected namespaces + exposed pods)
- [x] `--format matrix` — ASCII table output

---

## v0.4.0 — LLM Fix Suggestions (Week 9)

**Goal:** Generate least-permissive NetworkPolicy for each workload.

- [x] `--fix` flag — generate default-deny + targeted allow policies
- [x] Auto-detect required ports from Service definitions
- [x] Suggest HSTS and redirect annotations for Ingress
- [x] Japanese explanations (`--fix-lang ja`)

---

## v0.5.0 — Visualization & Reporting (Week 10)

**Goal:** Interactive network topology reporting.

- [x] `--format html` — interactive network graph (D3.js)
- [x] DOT format for Graphviz rendering
- [x] `--diff` — compare network policies before/after change
- [x] Baseline mode (only report new open paths vs last scan)

---

## v0.6.0 — Service Mesh & Cilium Support + npm Publish (Week 11)

**Goal:** Extend analysis to Istio and Cilium policies; prepare for public distribution.

- [x] Istio `AuthorizationPolicy` rules (NW5001–NW5008, 8 rules)
- [x] Istio `PeerAuthentication` rules (NW5005–NW5006)
- [x] Cilium `CiliumNetworkPolicy` rules (NW6001–NW6008, 8 rules)
- [x] Cilium `CiliumClusterwideNetworkPolicy` rules (NW6006)
- [x] Type guards: `isAuthorizationPolicy`, `isPeerAuthentication`, `isCiliumNetworkPolicy`, `isCiliumClusterwideNetworkPolicy`
- [x] 36 NW5xxx tests + 33 NW6xxx tests
- [x] `package.json` publish fields (`files`, `keywords`, `repository`, `bugs`, `homepage`)
- [x] `.npmignore` to exclude source/tests from npm package
- [x] `LICENSE` (MIT)
- [x] README updated with NW5xxx/NW6xxx rule tables (46+ rules total)

---

## v0.7.0 — Cloud Provider Firewall Correlation (Week 12)

**Goal:** Detect cloud-provider-specific annotation misconfigurations on Services and Ingresses for AWS EKS, GCP GKE, and Azure AKS.

- [x] `detectCloudProvider()` helper — infers AWS/GCP/Azure from annotation namespaces
- [x] `getAnnotation()` and `hasAnnotation()` helpers in `src/types.ts`
- [x] AWS rules NW7001–NW7008 (NLB internet-facing, access logs, SSL cert, TLS policy, ALB scheme, security group, ssl-policy, connection draining)
- [x] GCP rules NW7009–NW7012 (GKE LB internal, GCE HTTP disabled, LB type annotation, BackendConfig Cloud Armor)
- [x] Azure rules NW7013–NW7015 (AKS internal annotation explicit/implicit, AGIC WAF policy)
- [x] Per-resource provider detection — no cross-provider false positives when scanning mixed environments
- [x] 73 NW7xxx tests
- [x] Cloud fixture files: `tests/fixtures/cloud/aws-services.yaml`, `gke-ingress.yaml`, `aks-services.yaml`
- [x] README updated with NW7xxx tables (53+ rules total)
- [x] `package.json` version bumped to `0.7.0`, cloud keywords added

---

## v0.8.0 — Real-time Traffic Analysis Integration (Week 13)

**Goal:** Correlate observed network flows from Hubble, Falco, and generic CSV logs against declared NetworkPolicies to detect real-world policy gaps and violations.

- [x] `src/traffic/types.ts` — `TrafficFlow`, `TrafficViolation`, `PolicyGap`, `TrafficAnalysisResult` interfaces
- [x] `src/traffic/parser.ts` — `parseHubbleLogs()`, `parseFalcoLogs()`, `parseGenericLogs()`, `detectLogFormat()`, `parseTrafficLog()`
- [x] `src/traffic/analyzer.ts` — `analyzeTraffic()`, `detectPolicyGaps()` with four violation types: `policy-gap`, `unexpected-allow`, `unexpected-deny`, `shadow-traffic`
- [x] `src/formatters/traffic.ts` — `formatTrafficTty()`, `formatTrafficJson()`
- [x] CLI flags: `--traffic-log <file>`, `--traffic-format <hubble|falco|generic>`
- [x] JSON output includes `trafficAnalysis` key when `--traffic-log` is used
- [x] 34 parser tests + 23 analyzer tests + 18 formatter tests (75 total new tests)
- [x] Fixture files: `tests/fixtures/traffic/hubble-flows.json`, `falco-events.json`, `generic-flows.csv`
- [x] README updated with Traffic Log Analysis section and violation type table
- [x] `package.json` version bumped to `0.8.0`

---

## v0.9.0 — OPA/Rego Export & Admission Webhook (Week 14)

**Goal:** Close the policy-as-code loop by exporting findings as enforceable OPA/Rego policies and enabling live admission control via Kubernetes ValidatingWebhook.

- [x] `src/rego/generator.ts` — `generateRegoForRule()`, `generateRegoForFindings()`, `generateGatekeeperConstraint()`, `generateConftestPolicy()`, `REGO_SUPPORTED_RULES`
- [x] `src/rego/index.ts` — re-exports
- [x] Rego policies for 12 rules: NW1001, NW1002, NW1003, NW2001, NW2002, NW3001, NW3004, NW5001, NW5005, NW5006, NW6001, NW6005
- [x] `src/formatters/rego.ts` — `formatRegoTty()`, `formatRegoFiles()`, `formatRegoAll()`, `formatGatekeeperAll()`, `formatConftestAll()`
- [x] CLI flags: `--format rego`, `--format gatekeeper`, `--format conftest`
- [x] `src/webhook/server.ts` — `handleAdmissionRequest()`, `createWebhookServer()`, `generateWebhookManifest()`; `AdmissionRequest`/`AdmissionResponse`/`WebhookOptions` types
- [x] `src/webhook/index.ts` — re-exports
- [x] Validated kinds: NetworkPolicy, Service, Ingress, AuthorizationPolicy, PeerAuthentication, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, BackendConfig
- [x] Fail-open on internal error (always `allowed: true` + warning message)
- [x] TLS support via `https.createServer()` when `--webhook-cert` and `--webhook-key` are provided
- [x] Health endpoints: `/healthz`, `/readyz`
- [x] CLI flags: `--webhook`, `--webhook-port`, `--webhook-cert`, `--webhook-key`, `--webhook-deny-on-error`, `--webhook-manifest`
- [x] 37 Rego generator tests + 38 webhook server tests (75 total new tests)
- [x] `scripts/prepublish-check.sh` — pre-publish validation script
- [x] `package.json` version bumped to `0.9.0`, `publish:dry` script added, OPA/webhook keywords added
- [x] README updated with OPA/Rego and Admission Webhook sections

---

## v0.10.0 — Quality, Ecosystem Integration & Production-Readiness (Week 15)

**Goal:** Fill remaining production gaps: config file support, CI/CD automation, performance visibility, severity overrides, and advanced output filtering.

- [x] `src/config/loader.ts` — `loadConfig()`, `mergeConfig()`, `NetworkVetConfig` interface; searches `.networkvet.yaml` → `.networkvet.yml` → `networkvet.config.yaml`; throws descriptive errors for bad YAML; returns `{}` when no file found
- [x] `src/types.ts` — `AnalysisContext` extended with `ingressClass`, `excludeNamespaces`, `cloudProvider`
- [x] `src/rules/engine.ts` — `runRules()` accepts `NetworkVetConfig`; applies `config.override` severity changes, config-level `ignore`, per-rule `enabled` toggles, and propagates `ingressClass`/`excludeNamespaces`/`cloudProvider` into context
- [x] `src/perf/benchmark.ts` — `benchmarkRules()`, `formatTimings()`; per-rule wall-clock timing with `RuleTiming[]`
- [x] `src/formatters/tty.ts` — `formatTty()` extended with `options.groupBy: 'file' | 'namespace' | 'severity' | 'rule'`
- [x] `.github/workflows/ci.yml` — matrix test on Node 18/20/22, TypeScript lint, self-scan on own fixtures with SARIF upload
- [x] `.github/workflows/release.yml` — auto-publish to npm on `v*` tag push
- [x] CLI flags: `--config`, `--severity`, `--rule`, `--group-by`, `--verbose`
- [x] `--severity` filters displayed findings; exit code still uses unfiltered finding set
- [x] `--rule` filters displayed findings by comma-separated rule IDs
- [x] `--namespace` in file mode filters displayed findings by namespace field
- [x] `--verbose` prints per-rule timing table and resource count to stderr
- [x] 22 config loader tests + 15 benchmark tests + 22 TTY groupBy tests (59 total new tests)
- [x] `package.json` version bumped to `0.10.0`
