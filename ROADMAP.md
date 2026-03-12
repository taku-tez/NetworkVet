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

---

## v0.11.0 — Rule Quality & Rego Coverage (Week 16)

**Goal:** Fix known gaps and false positives in existing rules; expand OPA/Rego export coverage from 12 to 33 rules.

- [x] **NW4005 bug fix**: deny-all egress policies (`policyTypes: [Egress]`, no egress rules) no longer trigger a false positive — all egress is already blocked
- [x] **NW4005 gap fix**: namespaces with workloads but no egress NetworkPolicy now trigger NW4005 with a distinct message about unrestricted egress allowing metadata API access
- [x] **Rego coverage expanded** from 12 → 33 rules: NW1004, NW1005, NW2003, NW2004, NW2006, NW2008, NW3002, NW3003, NW3006, NW4001, NW4005, NW5002, NW5003, NW5004, NW5007, NW5008, NW6002, NW6003, NW6004, NW6006, NW6007 added
- [x] 24 new tests (3 NW4005 rule tests + 21 Rego generator tests) — 743 total tests
- [x] `package.json` version bumped to `0.11.0`

---

## v0.12.0 — Rego 100% Coverage + Compliance Framework Mapping (Week 17)

**Goal:** Complete OPA/Rego export for all 61 rules; add CIS Kubernetes Benchmark and NSA/CISA Hardening Guide compliance mapping.

- [x] **Rego 100% coverage**: Added remaining 28 Rego definitions — NW1006–NW1010, NW2005, NW2007, NW3005, NW3007, NW4002–NW4004, NW6008, NW7001–NW7015 — total now 61/61 rules
- [x] `src/compliance/mapping.ts` — `COMPLIANCE_MAP`, `getComplianceRefs()`, `getRulesForFramework()` covering 50+ rules mapped to CIS K8s Benchmark v1.8.0 and NSA/CISA K8s Hardening Guide §3–§6
- [x] `src/formatters/compliance.ts` — `formatComplianceTty()` (table with rule/severity/framework/control/resource columns) and `formatComplianceJson()`
- [x] `src/formatters/sarif.ts` — SARIF output now includes `taxonomies` (CIS + NSA) and per-rule `relationships` for GitHub Code Scanning compliance integration
- [x] CLI `--format compliance` — compliance report output (default: all frameworks)
- [x] CLI `--compliance cis|nsa|all` — filter compliance report by framework
- [x] 103 new tests across 4 new/updated test files — **794 total tests** across 29 test files
- [x] `package.json` version bumped to `0.12.0`

---

## v0.13.0 — Fix Suggestion 完全カバー (Week 18)

**Goal:** `--fix` が全 61 ルールで修正案を返すようにする。NW5xxx (Istio)、NW6xxx (Cilium)、NW7xxx (Cloud Provider) の 31 ルール分の MSG (en/ja) と YAML スニペットを追加。

- [x] `src/fixer/generator.ts` — MSG に NW5001–5008, NW6001–6008, NW7001–7015 の英日メッセージ追加
- [x] `fixBuilders` に同 31 ルール追加 — Istio は PeerAuthentication/AuthorizationPolicy YAML、Cilium は entity/CIDR/FQDN スニペット、Cloud は各プロバイダーのアノテーション修正 YAML
- [x] NW6008 (L7 HTTP rules) は情報提供のみのため YAML スニペットなし (説明文のみ)
- [x] 20 新規テスト追加 — **813 テスト** (29 ファイル) 全通過
- [x] `package.json` version bumped to `0.13.0`

---

## v0.14.0 — CI/CD & Developer UX (Week 19)

**Goal:** Improve CI/CD integration, per-resource inline ignores, and output file support.

- [x] `--fail-on <severity>` flag — configurable exit-code threshold (critical/high/medium/low/info, default: high)
- [x] `networkvet.io/ignore` annotation — per-resource inline rule suppression (e.g. `"NW1001,NW2003"`)
- [x] `--output <file>` flag — write output to file instead of stdout
- [x] `action.yml` — composite GitHub Action with SARIF upload to GitHub Code Scanning
- [x] 15 new tests (`tests/cli/fail_on.test.ts`, `tests/rules/inline_ignore.test.ts`) — **828 tests** (31 files) all passing
- [x] `package.json` version bumped to `0.14.0`

---

## v0.15.0 — Helm/Kustomize Template Awareness (Week 20)

**Goal:** Detect Helm template variables in YAML files during parsing, optionally resolve them using `--helm-values`, and emit warnings when files are skipped due to unresolvable templates.

- [x] `src/helm/detector.ts` — `hasHelmTemplates()`, `extractTemplateVars()`, `resolveHelmTemplates()`, `HelmValues` interface
- [x] `src/helm/index.ts` — re-exports
- [x] `src/parser/index.ts` — `ParseOptions` interface; `parseDir()` updated to accept `opts?: ParseOptions` and return `{ resources, skippedHelmFiles }`; files containing unresolved `{{ ... }}` after optional substitution are skipped and reported
- [x] CLI flags: `--helm-values <file>`, `--helm-release-name <name>` (default: `release`), `--helm-release-namespace <namespace>`
- [x] `--verbose` mode prints skipped Helm file count and paths to stderr
- [x] Resolution: `.Release.Namespace`, `.Release.Name`, `.Release.Service`, `.Values.xxx.yyy` (nested) — complex expressions (`include`, `required`, `if`, `range`) left as-is
- [x] 15 detector tests + 9 parser integration tests — **852 tests** (33 files) all passing
- [x] `package.json` version bumped to `0.15.0`

---

## v0.16.0 — Pod-level Reachability Analysis (Week 21)

**Goal:** Upgrade reachability analysis from namespace-level to workload/pod-level. Add `--reachability --level pod` support that evaluates label selectors and shows which specific workloads can reach each other.

- [x] `src/reachability/pod_evaluator.ts` — `WorkloadInfo`, `PodReachabilityResult` interfaces; `extractWorkloads()`, `matchesPodSelector()`, `matchesIngressRule()`, `computePodReachability()` functions
- [x] `src/formatters/pod_matrix.ts` — `formatPodMatrixTty()` (ASCII table with ALLOW/DENY, summary, reason breakdown), `formatPodMatrixJson()` (structured JSON with type/results/summary)
- [x] CLI `--level` option: `choices: ['namespace', 'pod'], default: 'namespace'`; when `--reachability --level pod`, calls `computePodReachability()` and formats output
- [x] `--namespace` filter applies to pod-level TTY output
- [x] JSON format includes `podReachability` key when `--reachability --level pod` is set
- [x] Workload kinds supported: Deployment, StatefulSet, DaemonSet, Pod, Job
- [x] Reason values: `no-policy` (default-allow), `policy-allow`, `policy-deny`
- [x] Cross-namespace pairs only included when namespaceSelector rules exist in policies
- [x] Tests: `tests/reachability/pod_evaluator.test.ts` (extractWorkloads, matchesPodSelector, computePodReachability — all reason values)
- [x] Tests: `tests/formatters/pod_matrix.test.ts` (TTY formatter, JSON formatter, namespace filter)
- [x] `package.json` version bumped to `0.16.0`

---

## v0.17.0 — Kubernetes Gateway API Support (Week 22)

**Goal:** Add NW8xxx rules for Kubernetes Gateway API resources (Gateway, HTTPRoute, GRPCRoute, ReferenceGrant) — the next-generation networking resources replacing Ingress.

- [x] `src/types.ts` — Added `GatewayResource`, `HTTPRouteResource`, `GRPCRouteResource`, `ReferenceGrantResource` interfaces + type guards (`isGateway`, `isHTTPRoute`, `isGRPCRoute`, `isReferenceGrant`)
- [x] `src/rules/nw8xxx.ts` — 5 new rules:
  - NW8001 (medium): HTTPRoute served over plain HTTP without TLS termination
  - NW8002 (medium): Gateway listener allows routes from all namespaces
  - NW8003 (high): HTTPRoute cross-namespace backendRef without ReferenceGrant
  - NW8004 (high): Gateway HTTPS/TLS listener has no certificateRefs configured
  - NW8005 (high): GRPCRoute cross-namespace backendRef without ReferenceGrant
- [x] `src/rules/engine.ts` — registered `nw8Rules` in `allRules`
- [x] `src/rego/generator.ts` — Rego policies for NW8001–NW8005
- [x] `src/fixer/generator.ts` — MSG entries (en+ja) and fixBuilders for NW8001–NW8005
- [x] `src/compliance/mapping.ts` — CIS 5.4.1, NSA §3.1–§3.4, §4.1 mappings for NW8001–NW8005
- [x] `tests/rules/nw8xxx.test.ts` — 40+ test cases covering all 5 rules
- [x] `tests/rego/nw8xxx_rego.test.ts` — Rego presence and content validation tests
- [x] `tests/fixtures/gateway/` — `gateway-basic.yaml`, `httproute-basic.yaml`, `referencegrant-basic.yaml`
- [x] `package.json` version bumped to `0.17.0`

---

## v0.18.0 — Policy Simulation Mode (Week 23)

**Goal:** Allow users to test "what would happen if I apply this NetworkPolicy?" before deploying it. The `--simulate <yaml-file>` flag overlays a hypothetical policy onto the existing resource set and shows what reachability paths are gained or lost.

- [x] `src/simulation/engine.ts` — `SimulationDiff` interface; `mergeSimulatedResources()` (replace existing resource with same kind/ns/name or append); `computeSimulationDiff()` (keyed by from/to path, classifies gained/lost/unchanged)
- [x] `src/simulation/index.ts` — re-exports from engine.ts
- [x] `src/formatters/simulation.ts` — `formatSimulationTty()` (green `+ALLOW` gained lines, red `-DENY` lost lines, summary); `formatSimulationJson()` (structured JSON with type/simulatedFile/gained/lost/unchanged/summary)
- [x] CLI `--simulate <file>` option: parses hypothetical YAML, merges with existing resources, computes pod reachability before/after, prints simulation diff (TTY or JSON), continues with normal analysis
- [x] `tests/simulation/engine.test.ts` — mergeSimulatedResources (replace/append/unchanged), computeSimulationDiff (gained/lost/unchanged/edge cases)
- [x] `tests/formatters/simulation.test.ts` — TTY formatter (header, gained/lost sections, no-changes message, summary), JSON formatter (structure, summary counts, round-trip data)
- [x] `package.json` version bumped to `0.18.0`

---

## v0.19.0 — Blast Radius Analysis (Week 24)

**Goal:** Add `--blast-radius <namespace/workload>` flag that performs BFS traversal from a specified workload to enumerate all reachable workloads, helping security teams understand lateral movement risk if a workload is compromised.

- [x] `src/blast/index.ts` — `BlastRadiusResult` interface; `parseWorkloadRef()` (parses "namespace/name" or "name" → defaults to "default" namespace); `computeBlastRadius()` (BFS from origin through pod reachability graph, tracks depth, identifies high-risk targets, enumerates unreachable workloads)
- [x] Known high-risk names flagged: `kube-apiserver`, `kubernetes`, `etcd`, `metrics-server`, `coredns`, `kube-dns`
- [x] `src/formatters/blast.ts` — `formatBlastRadiusTty()` (tree-like display with depth, HIGH RISK markers in red, contained count); `formatBlastRadiusJson()` (structured JSON with summary: totalWorkloads, reachableCount, unreachableCount, highRiskCount, maxDepth)
- [x] CLI `--blast-radius <workload>` option; exits 0 after output (informational); exits 2 with error if workload not found; supports `--format json` and `--output <file>`
- [x] `tests/blast/index.test.ts` — parseWorkloadRef, computeBlastRadius (chain BFS, isolation, high-risk detection, unreachable enumeration, error on not-found)
- [x] `tests/formatters/blast.test.ts` — TTY formatter (header, reachable list, depth, HIGH RISK markers, contained count), JSON formatter (structure, summary counts, round-trip data, empty result handling)
- [x] `package.json` version bumped to `0.19.0`
