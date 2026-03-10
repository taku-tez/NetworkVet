import type { Finding, ParsedResource, ServiceSpec, IngressSpec } from '../types.js';
import { isService, isIngress } from '../types.js';

export type FixLang = 'en' | 'ja';

export interface FixSuggestion {
  findingId: string;   // rule ID like NW1001
  resource: string;    // "NetworkPolicy/allow-all"
  namespace: string;
  description: string;
  descriptionJa?: string;
  fix?: string;        // YAML snippet — omitted for generic suggestions
}

// ---------------------------------------------------------------------------
// i18n strings
// ---------------------------------------------------------------------------

interface Messages {
  en: string;
  ja: string;
}

const MSG: Record<string, Messages> = {
  NW1001: {
    en: 'Replace the wildcard ingress peer {} with specific namespace selectors to restrict traffic sources.',
    ja: 'ワイルドカードのイングレスピア {} を、特定の Namespace セレクタに置き換えてトラフィック元を制限してください。',
  },
  NW1002: {
    en: 'Replace the wildcard egress peer {} with specific namespace/port selectors to restrict traffic destinations.',
    ja: 'ワイルドカードのエグレスピア {} を、特定の Namespace・ポートセレクタに置き換えてトラフィック先を制限してください。',
  },
  NW1003: {
    en: 'Add a default-deny NetworkPolicy to restrict all ingress and egress traffic in this namespace.',
    ja: 'デフォルト拒否の NetworkPolicy を追加して、この Namespace の全インバウンド・アウトバウンドトラフィックを制限してください。',
  },
  NW1004: {
    en: 'Specify a targeted podSelector with matchLabels instead of selecting all pods.',
    ja: 'すべての Pod を対象にする代わりに、matchLabels を使った具体的な podSelector を指定してください。',
  },
  NW1005: {
    en: 'Replace the empty namespaceSelector with one that specifies exact namespace labels.',
    ja: '空の namespaceSelector を、特定の Namespace ラベルを指定したものに置き換えてください。',
  },
  NW1006: {
    en: 'Add an explicit egress rule allowing UDP/TCP port 53 to kube-dns so DNS resolution continues to work.',
    ja: 'kube-dns への UDP/TCP ポート 53 を明示的に許可するエグレスルールを追加して、DNS 解決が機能するようにしてください。',
  },
  NW1007: {
    en: 'Remove or restrict the kube-system ingress rule if access from cluster infrastructure is not required.',
    ja: 'クラスターインフラからのアクセスが不要な場合は、kube-system イングレスルールを削除または制限してください。',
  },
  NW1008: {
    en: 'Explicitly set policyTypes: [Ingress] or [Egress] or both to make the policy intent clear.',
    ja: 'policyTypes: [Ingress] または [Egress] あるいは両方を明示的に設定して、ポリシーの意図を明確にしてください。',
  },
  NW1009: {
    en: 'Create a NetworkPolicy with policyTypes: [Ingress] to restrict inbound traffic for this workload.',
    ja: 'policyTypes: [Ingress] を含む NetworkPolicy を作成して、このワークロードへのインバウンドトラフィックを制限してください。',
  },
  NW1010: {
    en: 'Create a NetworkPolicy with policyTypes: [Egress] to restrict outbound traffic for this workload.',
    ja: 'policyTypes: [Egress] を含む NetworkPolicy を作成して、このワークロードからのアウトバウンドトラフィックを制限してください。',
  },
  NW2001: {
    en: 'Consider using ClusterIP + Ingress instead of NodePort to limit exposure. If NodePort is required, restrict access at the firewall/security-group level.',
    ja: 'NodePort の代わりに ClusterIP + Ingress の使用を検討して、公開範囲を限定してください。NodePort が必要な場合はファイアウォール / セキュリティグループで制限してください。',
  },
  NW2002: {
    en: 'Set externalTrafficPolicy: Local to preserve the client source IP for security logging and IP-based controls.',
    ja: 'セキュリティログや IP ベースのアクセス制御のために externalTrafficPolicy: Local を設定してクライアント送信元 IP を保持してください。',
  },
  NW2003: {
    en: 'Set spec.loadBalancerSourceRanges to restrict which CIDRs can access this LoadBalancer.',
    ja: 'spec.loadBalancerSourceRanges を設定して、この LoadBalancer へアクセスできる CIDR を制限してください。',
  },
  NW2004: {
    en: 'Remove port 22 from this Service. Use kubectl exec for pod access or a dedicated bastion host instead.',
    ja: 'この Service からポート 22 を削除してください。Pod へのアクセスには kubectl exec または専用の踏み台ホストを使用してください。',
  },
  NW2005: {
    en: 'Add a selector to this headless Service, or ensure Endpoints are manually managed if intentional.',
    ja: 'このヘッドレス Service にセレクタを追加するか、意図的な場合は Endpoints を手動で管理してください。',
  },
  NW2006: {
    en: 'Remove externalIPs from this Service to prevent potential MITM attacks. Use LoadBalancer type or Ingress instead.',
    ja: 'MITM 攻撃を防ぐためにこの Service から externalIPs を削除してください。代わりに LoadBalancer タイプまたは Ingress を使用してください。',
  },
  NW2007: {
    en: 'Set sessionAffinity: ClientIP on this Service to ensure consistent routing to the same StatefulSet pod.',
    ja: 'この Service に sessionAffinity: ClientIP を設定して、同じ StatefulSet Pod への一貫したルーティングを確保してください。',
  },
  NW2008: {
    en: 'Avoid ExternalName pointing to internal cluster DNS. Use a ClusterIP Service or direct internal DNS references.',
    ja: 'クラスター内部 DNS を指す ExternalName の使用は避けてください。ClusterIP Service または直接の内部 DNS 参照を使用してください。',
  },
  NW3001: {
    en: 'Configure TLS on this Ingress with a valid certificate Secret to serve traffic over HTTPS.',
    ja: '有効な証明書 Secret を使ってこの Ingress に TLS を設定し、HTTPS でトラフィックを提供してください。',
  },
  NW3002: {
    en: 'Add an HSTS header via the nginx.ingress.kubernetes.io/hsts annotation to enforce HTTPS in browsers.',
    ja: 'ブラウザで HTTPS を強制するために nginx.ingress.kubernetes.io/hsts アノテーションで HSTS ヘッダーを追加してください。',
  },
  NW3003: {
    en: 'Add nginx.ingress.kubernetes.io/ssl-redirect: "true" to redirect HTTP traffic to HTTPS.',
    ja: 'HTTP トラフィックを HTTPS にリダイレクトするために nginx.ingress.kubernetes.io/ssl-redirect: "true" を追加してください。',
  },
  NW3004: {
    en: 'Replace the wildcard or empty host with a specific hostname to prevent unintended traffic routing.',
    ja: 'ワイルドカードまたは空のホストを特定のホスト名に置き換えて、意図しないトラフィックルーティングを防いでください。',
  },
  NW3005: {
    en: 'Explicitly set nginx.ingress.kubernetes.io/ssl-redirect to "true" or "false" to clarify TLS redirect behavior.',
    ja: 'TLS リダイレクトの動作を明確にするために nginx.ingress.kubernetes.io/ssl-redirect を "true" または "false" に明示的に設定してください。',
  },
  NW3006: {
    en: 'Restrict admin/internal paths using IP allowlisting or move them to a separate internal-only Ingress.',
    ja: '管理者 / 内部パスを IP 許可リストで制限するか、内部専用の Ingress に移動してください。',
  },
  NW3007: {
    en: 'Ensure the referenced Service exists in the same namespace as the Ingress, or correct the backend service name.',
    ja: '参照している Service が Ingress と同じ Namespace に存在することを確認するか、バックエンドサービス名を修正してください。',
  },
  NW4001: {
    en: 'Add a default-deny NetworkPolicy to block all traffic by default, then selectively allow required traffic.',
    ja: 'デフォルト拒否の NetworkPolicy を追加してすべてのトラフィックをデフォルトでブロックし、必要なトラフィックのみを選択的に許可してください。',
  },
  NW4002: {
    en: 'Switch to a CNI plugin that supports NetworkPolicy enforcement (Calico, Cilium, WeaveNet, Antrea).',
    ja: 'NetworkPolicy を適用できる CNI プラグイン（Calico、Cilium、WeaveNet、Antrea）に切り替えてください。',
  },
  NW4003: {
    en: 'Add namespaceSelector with specific labels to ingress rules to control which namespaces can send traffic.',
    ja: 'イングレスルールに特定のラベルを持つ namespaceSelector を追加して、トラフィックを送信できる Namespace を制御してください。',
  },
  NW4004: {
    en: 'Add a NetworkPolicy in kube-system to restrict kube-dns access to only the namespaces that require it.',
    ja: 'kube-system に NetworkPolicy を追加して、kube-dns へのアクセスを必要な Namespace のみに制限してください。',
  },
  NW4005: {
    en: 'Add an egress rule that blocks 169.254.169.254/32 (cloud metadata API) to prevent SSRF attacks.',
    ja: 'SSRF 攻撃を防ぐために 169.254.169.254/32（クラウドメタデータ API）をブロックするエグレスルールを追加してください。',
  },
};

// ---------------------------------------------------------------------------
// YAML fix snippets
// ---------------------------------------------------------------------------

function defaultDenyYaml(namespace: string): string {
  return `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ${namespace}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress`;
}

function restrictIngressYaml(namespace: string, ports: number[]): string {
  const portsYaml =
    ports.length > 0
      ? `      ports:\n${ports.map((p) => `        - port: ${p}`).join('\n')}\n`
      : '';
  return `# Apply to the NetworkPolicy in namespace "${namespace}"
spec:
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <allowed-namespace>
${portsYaml}  policyTypes:
    - Ingress`;
}

function restrictEgressYaml(namespace: string, ports: number[]): string {
  const portsYaml =
    ports.length > 0
      ? `      ports:\n${ports.map((p) => `        - port: ${p}\n        - port: ${p}\n          protocol: UDP`).join('\n')}\n`
      : '';
  return `# Apply to the NetworkPolicy in namespace "${namespace}"
spec:
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <allowed-namespace>
${portsYaml}  policyTypes:
    - Egress`;
}

function dnsEgressYaml(): string {
  return `# Add to existing NetworkPolicy egress rules
spec:
  egress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP`;
}

function externalTrafficPolicyYaml(): string {
  return `# Patch the Service spec
spec:
  externalTrafficPolicy: Local`;
}

function loadBalancerSourceRangesYaml(): string {
  return `# Patch the Service spec
spec:
  loadBalancerSourceRanges:
    - 10.0.0.0/8      # Replace with your trusted CIDR ranges
    - 192.168.0.0/16`;
}

function tlsYaml(hosts: string[]): string {
  const hostList =
    hosts.length > 0
      ? hosts.map((h) => `        - ${h}`).join('\n')
      : '        - your.domain.example.com';
  const secretName =
    hosts.length > 0 ? `${hosts[0].replace(/\*/g, 'wildcard').replace(/\./g, '-')}-tls` : 'tls-secret';
  return `# Add to the Ingress spec
spec:
  tls:
    - hosts:
${hostList}
      secretName: ${secretName}
  rules: [] # keep existing rules`;
}

function hstsAnnotationYaml(): string {
  return `# Add to the Ingress metadata
metadata:
  annotations:
    nginx.ingress.kubernetes.io/hsts: "true"
    nginx.ingress.kubernetes.io/hsts-max-age: "31536000"
    nginx.ingress.kubernetes.io/hsts-include-subdomains: "true"`;
}

function sslRedirectYaml(): string {
  return `# Add to the Ingress metadata
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"`;
}

function blockMetadataYaml(namespace: string): string {
  return `# Apply to a NetworkPolicy in namespace "${namespace}"
spec:
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
  policyTypes:
    - Egress`;
}

// ---------------------------------------------------------------------------
// Port auto-detection from Service resources
// ---------------------------------------------------------------------------

function portsForNamespace(resources: ParsedResource[], namespace: string): number[] {
  const ports = new Set<number>();
  for (const r of resources) {
    if (!isService(r)) continue;
    if ((r.metadata.namespace ?? 'default') !== namespace) continue;
    const spec = r.spec as ServiceSpec;
    for (const p of spec.ports ?? []) {
      if (typeof p.port === 'number') ports.add(p.port);
    }
  }
  return [...ports].sort((a, b) => a - b);
}

function hostsForIngress(resources: ParsedResource[], namespace: string, resourceName: string): string[] {
  for (const r of resources) {
    if (!isIngress(r)) continue;
    if ((r.metadata.namespace ?? 'default') !== namespace) continue;
    if (r.metadata.name !== resourceName) continue;
    const spec = r.spec as IngressSpec;
    const hosts: string[] = [];
    for (const rule of spec.rules ?? []) {
      if (rule.host) hosts.push(rule.host);
    }
    return hosts;
  }
  return [];
}

// ---------------------------------------------------------------------------
// Deduplication key
// ---------------------------------------------------------------------------

function dedupeKey(finding: Finding): string {
  return `${finding.id}::${finding.namespace}::${finding.kind}::${finding.name}`;
}

// ---------------------------------------------------------------------------
// Per-rule fix builders
// ---------------------------------------------------------------------------

type FixBuilder = (finding: Finding, resources: ParsedResource[]) => Omit<FixSuggestion, 'findingId' | 'resource' | 'namespace'>;

const fixBuilders: Record<string, FixBuilder> = {
  NW1001: (finding, resources) => {
    const ports = portsForNamespace(resources, finding.namespace);
    return {
      description: MSG.NW1001.en,
      descriptionJa: MSG.NW1001.ja,
      fix: restrictIngressYaml(finding.namespace, ports),
    };
  },

  NW1002: (finding, resources) => {
    const ports = portsForNamespace(resources, finding.namespace);
    return {
      description: MSG.NW1002.en,
      descriptionJa: MSG.NW1002.ja,
      fix: restrictEgressYaml(finding.namespace, ports),
    };
  },

  NW1003: (finding) => ({
    description: MSG.NW1003.en,
    descriptionJa: MSG.NW1003.ja,
    fix: defaultDenyYaml(finding.namespace),
  }),

  NW1004: () => ({
    description: MSG.NW1004.en,
    descriptionJa: MSG.NW1004.ja,
    fix: `# Update the NetworkPolicy podSelector
spec:
  podSelector:
    matchLabels:
      app: <your-app-label>`,
  }),

  NW1005: () => ({
    description: MSG.NW1005.en,
    descriptionJa: MSG.NW1005.ja,
    fix: `# Replace empty namespaceSelector in the ingress rule
spec:
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <allowed-namespace>`,
  }),

  NW1006: () => ({
    description: MSG.NW1006.en,
    descriptionJa: MSG.NW1006.ja,
    fix: dnsEgressYaml(),
  }),

  NW1007: () => ({
    description: MSG.NW1007.en,
    descriptionJa: MSG.NW1007.ja,
    fix: `# Remove or narrow the kube-system ingress peer in the NetworkPolicy
spec:
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <specific-system-ns>
          podSelector:
            matchLabels:
              <required-label>: <value>`,
  }),

  NW1008: () => ({
    description: MSG.NW1008.en,
    descriptionJa: MSG.NW1008.ja,
    fix: `# Add explicit policyTypes to the NetworkPolicy
spec:
  policyTypes:
    - Ingress
    - Egress`,
  }),

  NW1009: (finding, resources) => {
    const ports = portsForNamespace(resources, finding.namespace);
    return {
      description: MSG.NW1009.en,
      descriptionJa: MSG.NW1009.ja,
      fix: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-ingress-${finding.name.toLowerCase()}
  namespace: ${finding.namespace}
spec:
  podSelector:
    matchLabels:
      app: ${finding.name}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <allowed-namespace>${ports.length > 0 ? '\n      ports:\n' + ports.map((p) => `        - port: ${p}`).join('\n') : ''}`,
    };
  },

  NW1010: (finding, resources) => {
    const ports = portsForNamespace(resources, finding.namespace);
    return {
      description: MSG.NW1010.en,
      descriptionJa: MSG.NW1010.ja,
      fix: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress-${finding.name.toLowerCase()}
  namespace: ${finding.namespace}
spec:
  podSelector:
    matchLabels:
      app: ${finding.name}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <allowed-namespace>${ports.length > 0 ? '\n      ports:\n' + ports.map((p) => `        - port: ${p}`).join('\n') : ''}`,
    };
  },

  NW2001: () => ({
    description: MSG.NW2001.en,
    descriptionJa: MSG.NW2001.ja,
    fix: `# Option A — change Service type to ClusterIP and add an Ingress
spec:
  type: ClusterIP
# Then create an Ingress resource pointing to this Service

# Option B — if NodePort is required, restrict at the network level
# Add firewall rules to allow only trusted source IPs on the nodePort`,
  }),

  NW2002: () => ({
    description: MSG.NW2002.en,
    descriptionJa: MSG.NW2002.ja,
    fix: externalTrafficPolicyYaml(),
  }),

  NW2003: () => ({
    description: MSG.NW2003.en,
    descriptionJa: MSG.NW2003.ja,
    fix: loadBalancerSourceRangesYaml(),
  }),

  NW2004: () => ({
    description: MSG.NW2004.en,
    descriptionJa: MSG.NW2004.ja,
    fix: `# Remove port 22 from the Service ports list
spec:
  ports:
    # Delete or comment out the SSH port entry:
    # - port: 22
    #   targetPort: 22`,
  }),

  NW2005: () => ({
    description: MSG.NW2005.en,
    descriptionJa: MSG.NW2005.ja,
    fix: `# Add a selector to the headless Service
spec:
  clusterIP: None
  selector:
    app: <your-app-label>`,
  }),

  NW2006: () => ({
    description: MSG.NW2006.en,
    descriptionJa: MSG.NW2006.ja,
    fix: `# Remove externalIPs from the Service spec
spec:
  # Delete the externalIPs field:
  # externalIPs: []`,
  }),

  NW2007: () => ({
    description: MSG.NW2007.en,
    descriptionJa: MSG.NW2007.ja,
    fix: `# Add sessionAffinity to the Service spec
spec:
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800`,
  }),

  NW2008: () => ({
    description: MSG.NW2008.en,
    descriptionJa: MSG.NW2008.ja,
    fix: `# Replace ExternalName with a ClusterIP Service
spec:
  type: ClusterIP
  # Remove externalName and add selector + ports`,
  }),

  NW3001: (finding, resources) => {
    const hosts = hostsForIngress(resources, finding.namespace, finding.name);
    return {
      description: MSG.NW3001.en,
      descriptionJa: MSG.NW3001.ja,
      fix: tlsYaml(hosts),
    };
  },

  NW3002: () => ({
    description: MSG.NW3002.en,
    descriptionJa: MSG.NW3002.ja,
    fix: hstsAnnotationYaml(),
  }),

  NW3003: () => ({
    description: MSG.NW3003.en,
    descriptionJa: MSG.NW3003.ja,
    fix: sslRedirectYaml(),
  }),

  NW3004: () => ({
    description: MSG.NW3004.en,
    descriptionJa: MSG.NW3004.ja,
    fix: `# Set an explicit host in every Ingress rule
spec:
  rules:
    - host: your.specific.domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: <your-service>
                port:
                  number: 80`,
  }),

  NW3005: () => ({
    description: MSG.NW3005.en,
    descriptionJa: MSG.NW3005.ja,
    fix: `# Add ssl-redirect annotation explicitly
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"`,
  }),

  NW3006: () => ({
    description: MSG.NW3006.en,
    descriptionJa: MSG.NW3006.ja,
    fix: `# Option A — restrict with IP allowlist annotation
metadata:
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,192.168.0.0/16"

# Option B — move sensitive paths to an internal-only Ingress
# Create a separate Ingress for /admin paths with ingressClassName pointing
# to an internal controller not exposed to the public internet`,
  }),

  NW3007: () => ({
    description: MSG.NW3007.en,
    descriptionJa: MSG.NW3007.ja,
    fix: `# Ensure the backend Service exists in the same namespace, e.g.:
apiVersion: v1
kind: Service
metadata:
  name: <missing-service-name>
  namespace: <ingress-namespace>
spec:
  type: ClusterIP
  selector:
    app: <your-app-label>
  ports:
    - port: 80
      targetPort: 8080`,
  }),

  NW4001: (finding) => ({
    description: MSG.NW4001.en,
    descriptionJa: MSG.NW4001.ja,
    fix: defaultDenyYaml(finding.namespace),
  }),

  NW4002: () => ({
    description: MSG.NW4002.en,
    descriptionJa: MSG.NW4002.ja,
    // No YAML fix — requires infrastructure change
  }),

  NW4003: (finding) => ({
    description: MSG.NW4003.en,
    descriptionJa: MSG.NW4003.ja,
    fix: `# Add namespaceSelector to ingress rules in NetworkPolicies in namespace "${finding.namespace}"
spec:
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: <allowed-namespace>`,
  }),

  NW4004: () => ({
    description: MSG.NW4004.en,
    descriptionJa: MSG.NW4004.ja,
    fix: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-coredns
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      k8s-app: kube-dns
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              dns-access: allowed
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP`,
  }),

  NW4005: (finding) => ({
    description: MSG.NW4005.en,
    descriptionJa: MSG.NW4005.ja,
    fix: blockMetadataYaml(finding.namespace),
  }),
};

// Generic suggestion for rules that have messages but no dedicated builder
function genericSuggestion(finding: Finding): Omit<FixSuggestion, 'findingId' | 'resource' | 'namespace'> {
  const msg = MSG[finding.id];
  return {
    description: msg?.en ?? `Review and remediate finding ${finding.id}: ${finding.message}`,
    descriptionJa: msg?.ja,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate deterministic fix suggestions for a list of findings.
 *
 * - Deduplicates by (ruleId, namespace, kind, name) so the same issue in the
 *   same resource produces a single suggestion.
 * - When lang === 'ja', the description field is set to the Japanese text.
 *   The English text is always available in descriptionJa for reference.
 */
export function generateFixes(
  findings: Finding[],
  resources: ParsedResource[],
  lang: FixLang = 'en',
): FixSuggestion[] {
  const seen = new Set<string>();
  const suggestions: FixSuggestion[] = [];

  for (const finding of findings) {
    const key = dedupeKey(finding);
    if (seen.has(key)) continue;
    seen.add(key);

    const builder = fixBuilders[finding.id] ?? null;
    const partial = builder
      ? builder(finding, resources)
      : genericSuggestion(finding);

    const suggestion: FixSuggestion = {
      findingId: finding.id,
      resource: `${finding.kind}/${finding.name}`,
      namespace: finding.namespace,
      description: lang === 'ja' && partial.descriptionJa ? partial.descriptionJa : partial.description,
      descriptionJa: partial.descriptionJa,
      ...(partial.fix !== undefined ? { fix: partial.fix } : {}),
    };

    suggestions.push(suggestion);
  }

  return suggestions;
}
