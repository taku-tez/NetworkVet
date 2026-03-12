#!/usr/bin/env node
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import path from 'path';
import { parseDir, parseFile } from './parser/index.js';
import type { ParseOptions } from './parser/index.js';
import { runRules } from './rules/engine.js';
import { formatTty } from './formatters/tty.js';
import { formatJson } from './formatters/json.js';
import { formatSarif } from './formatters/sarif.js';
import { formatMatrix, formatHtml } from './formatters/matrix.js';
import { formatFixTty, formatFixJson } from './formatters/fix.js';
import { formatDot } from './formatters/dot.js';
import { formatDiffTty, formatDiffJson } from './formatters/diff.js';
import { formatRegoTty, formatRegoAll, formatGatekeeperAll, formatConftestAll } from './formatters/rego.js';
import { formatComplianceTty } from './formatters/compliance.js';
import type { ComplianceFramework } from './formatters/compliance.js';
import { computeReachability } from './reachability/evaluator.js';
import { computePodReachability } from './reachability/pod_evaluator.js';
import { formatPodMatrixTty, formatPodMatrixJson } from './formatters/pod_matrix.js';
import { generateRegoForFindings } from './rego/index.js';
import { loadConfig, mergeConfig } from './config/loader.js';
import { benchmarkRules, formatTimings } from './perf/benchmark.js';
import { allRules } from './rules/engine.js';
import type { GroupBy } from './formatters/tty.js';
import type { NetworkVetConfig } from './config/loader.js';
import { generateFixes } from './fixer/generator.js';
import { saveBaseline, loadBaseline, diffWithBaseline } from './diff/index.js';
import { parseTrafficLog, detectLogFormat } from './traffic/parser.js';
import { analyzeTraffic } from './traffic/analyzer.js';
import { formatTrafficTty, formatTrafficJson } from './formatters/traffic.js';
import type { FixLang } from './fixer/generator.js';
import type { Finding, ParsedResource } from './types.js';
import type { ReachabilityResult } from './reachability/evaluator.js';
import type { TrafficAnalysisResult } from './traffic/types.js';
import type { TrafficLogFormat } from './traffic/types.js';
import { mergeSimulatedResources, computeSimulationDiff } from './simulation/index.js';
import { formatSimulationTty, formatSimulationJson } from './formatters/simulation.js';
import { computeBlastRadius } from './blast/index.js';
import { formatBlastRadiusTty, formatBlastRadiusJson } from './formatters/blast.js';

type OutputFormat = 'tty' | 'json' | 'sarif' | 'matrix' | 'html' | 'dot' | 'rego' | 'gatekeeper' | 'conftest' | 'compliance';

async function main(): Promise<void> {
  const argv = await yargs(hideBin(process.argv))
    .command('$0 [dir]', 'Analyze Kubernetes manifests for network security issues', (y) => {
      y.positional('dir', {
        describe: 'Directory to scan (shorthand for --dir)',
        type: 'string',
      });
    })
    // --- File mode options ---
    .option('dir', {
      alias: 'd',
      type: 'string',
      description: 'Directory containing Kubernetes manifests to analyze',
    })
    .option('file', {
      alias: 'f',
      type: 'string',
      description: 'Single manifest file to analyze',
    })
    // --- Cluster mode options ---
    .option('cluster', {
      type: 'boolean',
      description: 'Fetch resources from a live Kubernetes cluster via kubeconfig',
      default: false,
    })
    .option('all-namespaces', {
      alias: 'A',
      type: 'boolean',
      description: 'Scan all namespaces (requires --cluster)',
      default: false,
    })
    .option('namespace', {
      alias: 'n',
      type: 'string',
      description: 'Namespace to scan when using --cluster (default: current context namespace)',
    })
    .option('context', {
      type: 'string',
      description: 'Kubernetes context name to use (overrides current-context in kubeconfig)',
    })
    // --- Analysis options ---
    .option('reachability', {
      alias: 'r',
      type: 'boolean',
      description: 'Compute and output namespace-level reachability matrix',
      default: false,
    })
    .option('level', {
      choices: ['namespace', 'pod'] as const,
      default: 'namespace' as 'namespace' | 'pod',
      description: 'Reachability analysis level: namespace (default) or pod (workload-level)',
    })
    // --- Shared options ---
    .option('format', {
      choices: ['tty', 'json', 'sarif', 'matrix', 'html', 'dot', 'rego', 'gatekeeper', 'conftest', 'compliance'] as const,
      default: 'tty' as OutputFormat,
      description: 'Output format (matrix, html, and dot imply --reachability; rego/gatekeeper/conftest export OPA policies)',
    })
    .option('compliance', {
      choices: ['cis', 'nsa', 'all'] as const,
      default: 'all' as ComplianceFramework,
      description: 'Compliance framework filter for --format compliance (cis, nsa, or all)',
    })
    .option('ignore', {
      alias: 'i',
      type: 'string',
      description: 'Comma-separated list of rule IDs to ignore (e.g. NW1001,NW2003)',
    })
    .option('fix', {
      type: 'boolean',
      description: 'Generate fix suggestions for each finding',
      default: false,
    })
    .option('fix-lang', {
      choices: ['en', 'ja'] as const,
      default: 'en' as FixLang,
      description: 'Language for fix descriptions (en or ja)',
    })
    .option('diff', {
      type: 'boolean',
      description: 'Compare current results against a saved baseline',
      default: false,
    })
    .option('baseline', {
      type: 'string',
      description: 'Path to the baseline file used with --diff or --save-baseline',
      default: '.networkvet-baseline.json',
    })
    .option('save-baseline', {
      type: 'boolean',
      description: 'Save current results as baseline for future --diff runs',
      default: false,
    })
    .option('traffic-log', {
      type: 'string',
      description: 'Path to a traffic log file (Hubble JSON, Falco JSON, or generic CSV) to analyze alongside manifests',
    })
    .option('traffic-format', {
      choices: ['hubble', 'falco', 'generic'] as const,
      description: 'Traffic log format — auto-detected from content when not specified',
    })
    // --- Webhook mode options ---
    .option('webhook', {
      type: 'boolean',
      description: 'Run as a Kubernetes ValidatingWebhook HTTP(S) server',
      default: false,
    })
    .option('webhook-port', {
      type: 'number',
      description: 'Port for the webhook server (default: 8443)',
      default: 8443,
    })
    .option('webhook-cert', {
      type: 'string',
      description: 'Path to TLS certificate file for the webhook server',
    })
    .option('webhook-key', {
      type: 'string',
      description: 'Path to TLS private key file for the webhook server',
    })
    .option('webhook-deny-on-error', {
      type: 'boolean',
      description: 'Reject resources with critical/high severity findings (default: warn-only)',
      default: false,
    })
    .option('webhook-manifest', {
      type: 'boolean',
      description: 'Print a Kubernetes deployment manifest for the webhook and exit',
      default: false,
    })
    // --- Config options ---
    .option('config', {
      type: 'string',
      description: 'Path to .networkvet.yaml config file (auto-discovered if not specified)',
    })
    // --- Helm options ---
    .option('helm-values', {
      type: 'string',
      description: 'Path to a Helm values.yaml file for resolving {{ .Values.xxx }} template expressions',
    })
    .option('helm-release-name', {
      type: 'string',
      default: 'release',
      description: 'Helm release name used to resolve {{ .Release.Name }} (default: release)',
    })
    .option('helm-release-namespace', {
      type: 'string',
      description: 'Helm release namespace used to resolve {{ .Release.Namespace }}',
    })
    // --- Output filtering ---
    .option('severity', {
      choices: ['critical', 'high', 'medium', 'low', 'info'] as const,
      description: 'Only show findings at or above this severity level',
    })
    .option('rule', {
      type: 'string',
      description: 'Only show findings for specific rule ID(s), comma-separated (e.g. NW1001,NW2001)',
    })
    .option('group-by', {
      choices: ['file', 'namespace', 'severity', 'rule'] as const,
      default: 'file' as GroupBy,
      description: 'Group TTY output by file, namespace, severity, or rule',
    })
    // --- Verbose / perf ---
    .option('verbose', {
      type: 'boolean',
      description: 'Print per-rule timing and resource count to stderr',
      default: false,
    })
    .option('fail-on', {
      choices: ['critical', 'high', 'medium', 'low', 'info'] as const,
      default: 'high' as Finding['severity'],
      description: 'Minimum severity that causes a non-zero exit code (default: high)',
    })
    .option('output', {
      alias: 'o',
      type: 'string',
      description: 'Write output to a file instead of (or in addition to) stdout',
    })
    .option('simulate', {
      type: 'string',
      description: 'Path to a YAML file to simulate applying; shows reachability changes (gained/lost paths)',
    })
    .option('blast-radius', {
      type: 'string',
      description: 'Compute blast radius for a workload (format: namespace/name or name). Shows all reachable workloads via BFS.',
    })
    .option('no-color', {
      type: 'boolean',
      description: 'Disable color output',
    })
    .help()
    .alias('help', 'h')
    .version('0.19.0')
    .alias('version', 'v')
    .example('$0 --dir ./k8s', 'Scan all YAML files in the k8s directory')
    .example('$0 --dir ./k8s --format json', 'Output findings as JSON')
    .example('$0 --dir ./k8s --reachability', 'Include reachability analysis in TTY output')
    .example('$0 --dir ./k8s --format matrix', 'Show namespace reachability matrix')
    .example('$0 --dir ./k8s --format html', 'Output reachability matrix as HTML')
    .example('$0 --cluster', 'Analyze live cluster (current context + namespace)')
    .example('$0 --cluster --all-namespaces', 'Analyze all namespaces in the live cluster')
    .example('$0 --cluster --context prod-ctx --namespace payments', 'Use specific context and namespace')
    .example('$0 --dir ./k8s --ignore NW1003,NW2003', 'Ignore specific rules')
    .example('$0 --dir ./k8s --format rego', 'Export OPA/Rego policies for detected findings')
    .example('$0 --dir ./k8s --format gatekeeper', 'Export Gatekeeper ConstraintTemplate YAMLs')
    .example('$0 --dir ./k8s --format conftest', 'Export Conftest-compatible Rego policies')
    .example('$0 --webhook --webhook-port 8443 --webhook-deny-on-error', 'Run as validating webhook server')
    .example('$0 --webhook-manifest', 'Print Kubernetes deployment manifest for webhook')
    .example('$0 --dir ./k8s --format compliance', 'Show CIS/NSA compliance report')
    .example('$0 --dir ./k8s --format compliance --compliance cis', 'Show CIS Benchmark findings only')
    .example('$0 --dir ./k8s --config ./myconfig.yaml', 'Use a specific config file')
    .example('$0 --dir ./k8s --severity high', 'Only show high and critical findings')
    .example('$0 --dir ./k8s --group-by namespace', 'Group output by namespace')
    .example('$0 --dir ./k8s --rule NW1001,NW2001', 'Show findings for specific rules only')
    .example('$0 --dir ./k8s --verbose', 'Show per-rule timing statistics')
    .example('$0 --dir ./k8s --fail-on medium', 'Exit 1 when any medium/high/critical finding exists')
    .example('$0 --dir ./k8s --format sarif --output results.sarif', 'Write SARIF results to file')
    .parse();

  const clusterMode = argv.cluster as boolean;
  const allNamespaces = argv['all-namespaces'] as boolean;
  const contextArg = argv.context as string | undefined;
  const namespaceArg = argv.namespace as string | undefined;
  const dirArg = (argv.dir as string | undefined) ?? (argv['_']?.[0] as string | undefined);
  const fileArg = argv.file as string | undefined;
  const format = argv.format as OutputFormat;
  const wantFix = argv.fix as boolean;
  const fixLang = argv['fix-lang'] as FixLang;
  const wantDiff = argv.diff as boolean;
  const baselinePath = argv.baseline as string;
  const wantSaveBaseline = argv['save-baseline'] as boolean;
  const trafficLogPath = argv['traffic-log'] as string | undefined;
  const trafficFormatArg = argv['traffic-format'] as TrafficLogFormat | undefined;
  const wantWebhook = argv.webhook as boolean;
  const webhookPort = argv['webhook-port'] as number;
  const webhookCert = argv['webhook-cert'] as string | undefined;
  const webhookKey = argv['webhook-key'] as string | undefined;
  const webhookDenyOnError = argv['webhook-deny-on-error'] as boolean;
  const wantWebhookManifest = argv['webhook-manifest'] as boolean;
  const configPath = argv.config as string | undefined;
  const helmValuesPath = argv['helm-values'] as string | undefined;
  const helmReleaseName = argv['helm-release-name'] as string;
  const helmReleaseNamespace = argv['helm-release-namespace'] as string | undefined;
  const severityFilter = argv.severity as 'critical' | 'high' | 'medium' | 'low' | 'info' | undefined;
  const ruleFilter = argv.rule as string | undefined;
  const groupBy = argv['group-by'] as GroupBy;
  const wantVerbose = argv.verbose as boolean;
  const reachabilityLevel = argv.level as 'namespace' | 'pod';
  const simulateArg = argv.simulate as string | undefined;
  const blastRadiusArg = argv['blast-radius'] as string | undefined;

  // matrix, html, and dot formats imply --reachability
  const wantReachability =
    (argv.reachability as boolean) ||
    format === 'matrix' ||
    format === 'html' ||
    format === 'dot' ||
    wantDiff ||
    wantSaveBaseline;

  // ---- Webhook manifest mode --------------------------------------------
  if (wantWebhookManifest) {
    const { generateWebhookManifest } = await import('./webhook/index.js');
    console.log(generateWebhookManifest());
    process.exit(0);
  }

  // ---- Webhook server mode ----------------------------------------------
  if (wantWebhook) {
    const { createWebhookServer } = await import('./webhook/index.js');
    const ignoreIds = argv.ignore
      ? String(argv.ignore).split(',').map((id) => id.trim()).filter(Boolean)
      : [];
    const server = createWebhookServer({
      port: webhookPort,
      tlsCert: webhookCert,
      tlsKey: webhookKey,
      ignoreIds,
      denyOnError: webhookDenyOnError,
      warnOnWarning: true,
    });
    server.listen(webhookPort);
    // Keep process alive — the server handles its own lifecycle
    return;
  }

  // Validate flags
  if (allNamespaces && !clusterMode) {
    console.error('Error: --all-namespaces requires --cluster');
    process.exit(2);
  }
  if ((contextArg || namespaceArg) && !clusterMode) {
    console.error('Error: --context and --namespace require --cluster');
    process.exit(2);
  }
  if (clusterMode && (dirArg || fileArg)) {
    console.error('Error: --cluster cannot be combined with --dir or --file');
    process.exit(2);
  }
  if (!clusterMode && !dirArg && !fileArg) {
    console.error('Error: Please provide a directory (--dir), file (--file), or use --cluster');
    process.exit(2);
  }

  let resources: ParsedResource[] = [];
  let detectedCni: string | null | undefined = undefined;

  if (clusterMode) {
    const { ClusterClient } = await import('./cluster/index.js');

    let client: InstanceType<typeof ClusterClient>;
    try {
      client = new ClusterClient(contextArg);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error connecting to cluster: ${message}`);
      process.exit(2);
    }

    if (format === 'tty') {
      const ctx = client.getCurrentContext();
      const ns = allNamespaces ? 'all namespaces' : (namespaceArg ?? client.getCurrentNamespace());
      console.error(`Scanning cluster (context: ${ctx}, namespace: ${ns})...`);
    }

    try {
      [resources, detectedCni] = await Promise.all([
        client.fetchAll(allNamespaces, namespaceArg),
        client.detectCNI(),
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error fetching resources from cluster: ${message}`);
      process.exit(2);
    }
  } else {
    try {
      if (fileArg) {
        resources = parseFile(path.resolve(fileArg));
      } else {
        // Build Helm options if any Helm flags were provided
        let parseOpts: ParseOptions | undefined;
        if (helmValuesPath || helmReleaseNamespace || helmReleaseName !== 'release') {
          const helmValues: import('./helm/detector.js').HelmValues = {
            release: {
              Name: helmReleaseName,
              ...(helmReleaseNamespace ? { Namespace: helmReleaseNamespace } : {}),
            },
          };
          if (helmValuesPath) {
            try {
              const { readFileSync } = await import('fs');
              const valuesContent = readFileSync(helmValuesPath, 'utf-8');
              const { default: jsyaml } = await import('js-yaml');
              const loaded = jsyaml.load(valuesContent);
              if (loaded && typeof loaded === 'object' && !Array.isArray(loaded)) {
                helmValues.values = loaded as Record<string, unknown>;
              }
            } catch (err) {
              const message = err instanceof Error ? err.message : String(err);
              console.error(`Error loading helm-values file: ${message}`);
              process.exit(2);
            }
          }
          parseOpts = { helmValues };
        }

        const result = await parseDir(path.resolve(dirArg!), parseOpts);
        resources = result.resources;

        if (wantVerbose && result.skippedHelmFiles.length > 0) {
          process.stderr.write(
            `Skipped ${result.skippedHelmFiles.length} file(s) with unresolved Helm templates:\n`
          );
          for (const f of result.skippedHelmFiles) {
            process.stderr.write(`  ${f}\n`);
          }
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error reading manifests: ${message}`);
      process.exit(2);
    }
  }

  if (resources.length === 0) {
    console.error('No Kubernetes resources found in the specified location');
    process.exit(0);
  }

  // ---- Simulation mode --------------------------------------------------
  if (simulateArg) {
    try {
      const simulatedResources = parseFile(path.resolve(simulateArg));
      const merged = mergeSimulatedResources(resources, simulatedResources);
      const before = computePodReachability(resources);
      const after = computePodReachability(merged);
      const simDiff = computeSimulationDiff(before, after);
      const simOutput =
        format === 'json'
          ? formatSimulationJson(simDiff, simulateArg)
          : formatSimulationTty(simDiff, simulateArg);
      console.log(simOutput);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error running simulation: ${message}`);
      process.exit(2);
    }
  }

  // ---- Blast radius mode ------------------------------------------------
  if (blastRadiusArg) {
    try {
      const blastResult = computeBlastRadius(resources, blastRadiusArg);
      const blastOutput =
        format === 'json'
          ? formatBlastRadiusJson(blastResult)
          : formatBlastRadiusTty(blastResult);
      const outputFile = argv.output as string | undefined;
      if (outputFile) {
        const { writeFileSync } = await import('fs');
        writeFileSync(outputFile, blastOutput, 'utf8');
      } else {
        console.log(blastOutput);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error computing blast radius: ${message}`);
      process.exit(2);
    }
    process.exit(0);
  }

  // Load and merge configuration
  let config: NetworkVetConfig = {};
  try {
    const rawConfig = loadConfig(configPath);
    // Inform user when a config file was found (only in TTY/non-JSON modes)
    if (Object.keys(rawConfig).length > 0 && format === 'tty') {
      const cfgLabel = configPath ?? '.networkvet.yaml';
      process.stderr.write(`Using config: ${cfgLabel}\n`);
    }
    const cliIgnore = argv.ignore
      ? String(argv.ignore).split(',').map((id) => id.trim()).filter(Boolean)
      : [];
    config = mergeConfig(rawConfig, { ignore: cliIgnore });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error loading config: ${message}`);
    process.exit(2);
  }

  // Parse ignore list (already merged into config by mergeConfig)
  const ignoreIds = config.ignore ?? [];

  // Run rules — with optional verbose benchmark mode
  let findings: Finding[];
  if (wantVerbose) {
    const start = Date.now();
    const { findings: bf, timings, totalDurationMs } = benchmarkRules(resources, allRules, undefined);
    // Apply ignores, config overrides, sort — mirror runRules post-processing
    const { runRules: run } = await import('./rules/engine.js');
    findings = run(resources, ignoreIds, {
      cni: detectedCni,
      mode: clusterMode ? 'cluster' : 'file',
    }, config);
    const elapsed = Date.now() - start;
    process.stderr.write(`Scanned ${resources.length} resources in ${elapsed}ms\n`);
    process.stderr.write(formatTimings(timings, totalDurationMs));
    void bf; // benchmarkRules result used for timing only; findings come from runRules
  } else {
    findings = runRules(resources, ignoreIds, {
      cni: detectedCni,
      mode: clusterMode ? 'cluster' : 'file',
    }, config);
  }

  // ---- Filtering --------------------------------------------------------
  // --severity filter
  const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  let filteredFindings = findings;
  if (severityFilter) {
    const threshold = SEVERITY_RANK[severityFilter] ?? 2;
    filteredFindings = filteredFindings.filter(
      (f) => (SEVERITY_RANK[f.severity] ?? 2) <= threshold
    );
  }
  // --rule filter
  if (ruleFilter) {
    const wantedIds = new Set(
      ruleFilter.split(',').map((id) => id.trim().toUpperCase()).filter(Boolean)
    );
    filteredFindings = filteredFindings.filter((f) => wantedIds.has(f.id.toUpperCase()));
  }
  // --namespace filter (extend to file mode: filter by finding.namespace)
  if (namespaceArg && !clusterMode) {
    filteredFindings = filteredFindings.filter(
      (f) => !f.namespace || f.namespace === namespaceArg
    );
  }

  // Use filteredFindings for output; keep original findings for exit-code logic
  const displayFindings = filteredFindings;

  // Optionally compute reachability
  let reachability: ReachabilityResult | undefined;
  if (wantReachability && reachabilityLevel !== 'pod') {
    reachability = computeReachability(resources);
  }

  // Pod-level reachability
  const wantPodReachability =
    (argv.reachability as boolean) && reachabilityLevel === 'pod';
  let podReachabilityOutput: string | undefined;
  if (wantPodReachability) {
    const podResults = computePodReachability(resources);
    if (format === 'json') {
      podReachabilityOutput = formatPodMatrixJson(podResults);
    } else {
      podReachabilityOutput = formatPodMatrixTty(podResults, {
        namespace: namespaceArg,
      });
    }
  }

  // ---- Traffic log analysis ---------------------------------------------
  let trafficResult: TrafficAnalysisResult | undefined;
  if (trafficLogPath) {
    try {
      const flows = parseTrafficLog(trafficLogPath, trafficFormatArg);
      trafficResult = analyzeTraffic(flows, resources);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error analyzing traffic log: ${message}`);
      process.exit(2);
    }
  }

  // ---- Save baseline mode -----------------------------------------------
  if (wantSaveBaseline) {
    saveBaseline(findings, reachability, baselinePath);
    console.log(`Baseline saved to ${baselinePath}`);
    process.exit(0);
  }

  // ---- Diff mode --------------------------------------------------------
  if (wantDiff) {
    let baseline;
    try {
      baseline = loadBaseline(baselinePath);
    } catch {
      console.error(`Error: could not load baseline from "${baselinePath}". Run with --save-baseline first.`);
      process.exit(2);
    }
    const diff = diffWithBaseline({ findings, reachability }, baseline);
    const diffOutput = format === 'json' ? formatDiffJson(diff) : formatDiffTty(diff);
    console.log(diffOutput);
    process.exit(0);
  }

  // ---- Normal output ----------------------------------------------------
  let output: string;

  switch (format) {
    case 'json':
      output = formatJson(displayFindings, reachability);
      break;
    case 'sarif':
      output = formatSarif(displayFindings);
      break;
    case 'matrix':
      output = formatMatrix(reachability!);
      break;
    case 'html':
      output = formatHtml(reachability!);
      break;
    case 'dot':
      output = formatDot(reachability!);
      break;
    case 'rego': {
      const policies = generateRegoForFindings(displayFindings);
      if (process.stdout.isTTY) {
        output = formatRegoTty(policies);
      } else {
        output = formatRegoAll(policies);
      }
      break;
    }
    case 'gatekeeper': {
      const policies = generateRegoForFindings(displayFindings);
      output = formatGatekeeperAll(policies);
      break;
    }
    case 'conftest': {
      const policies = generateRegoForFindings(displayFindings);
      output = formatConftestAll(policies);
      break;
    }
    case 'compliance':
      output = formatComplianceTty(displayFindings, argv.compliance as ComplianceFramework);
      break;
    case 'tty':
    default:
      output = formatTty(displayFindings, { groupBy });
      if (reachability) {
        output += '\n\n' + formatMatrix(reachability);
      }
      if (podReachabilityOutput) {
        output += '\n\n' + podReachabilityOutput;
      }
      if (trafficResult) {
        output += '\n\n' + formatTrafficTty(trafficResult);
      }
      break;
  }

  // For JSON format, merge pod reachability and traffic analysis into the JSON output
  if (format === 'json' && (podReachabilityOutput || trafficResult)) {
    const parsed = JSON.parse(output) as Record<string, unknown>;
    if (podReachabilityOutput) {
      parsed.podReachability = JSON.parse(podReachabilityOutput);
    }
    if (trafficResult) {
      parsed.trafficAnalysis = trafficResult;
    }
    output = JSON.stringify(parsed, null, 2);
  }

  console.log(output);

  const outputFile = argv.output as string | undefined;
  if (outputFile) {
    const { writeFileSync } = await import('fs');
    writeFileSync(outputFile, output, 'utf8');
    if (format === 'tty') {
      process.stderr.write(`Output written to ${outputFile}\n`);
    }
  }

  // Optionally generate and output fix suggestions
  if (wantFix) {
    const suggestions = generateFixes(findings, resources, fixLang);
    const fixOutput = format === 'json' ? formatFixJson(suggestions) : formatFixTty(suggestions);
    console.log('\n' + fixOutput);
  }

  // Exit with code 1 if any errors were found at or above --fail-on severity threshold
  // (using unfiltered findings so --severity filter doesn't suppress the exit code)
  const failOnSeverity = argv['fail-on'] as Finding['severity'];
  const failThreshold = SEVERITY_RANK[failOnSeverity] ?? 1;
  const hasErrors = findings.some((f) => (SEVERITY_RANK[f.severity] ?? 4) <= failThreshold) ||
    (trafficResult?.violations.some((v) => v.severity === 'error') ?? false);
  process.exit(hasErrors ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(2);
});
