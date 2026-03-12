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

  // ── NW5xxx: Istio / Service Mesh ──────────────────────────────────────────
  NW5001: {
    en: 'Replace principals: ["*"] with specific service account URIs (e.g. cluster.local/ns/<ns>/sa/<sa>) to restrict which identities are allowed.',
    ja: 'principals: ["*"] を特定のサービスアカウント URI（例: cluster.local/ns/<ns>/sa/<sa>）に置き換えて、許可する ID を制限してください。',
  },
  NW5002: {
    en: 'Add principals, namespaces, or ipBlocks to the "source" field so the ALLOW rule is not open to any caller.',
    ja: '"source" フィールドに principals、namespaces、または ipBlocks を追加して、ALLOW ルールが任意の呼び出し元に開放されないようにしてください。',
  },
  NW5003: {
    en: 'Replace methods: ["*"] with the specific HTTP methods this operation should permit (e.g. ["GET", "POST"]).',
    ja: 'methods: ["*"] をこの操作で許可すべき特定の HTTP メソッド（例: ["GET", "POST"]）に置き換えてください。',
  },
  NW5004: {
    en: 'Add a "from" (source) or "to" (operation) clause to the ALLOW rule to avoid unconditionally permitting all traffic.',
    ja: 'ALLOW ルールに "from"（送信元）または "to"（操作）句を追加して、すべてのトラフィックを無条件に許可しないようにしてください。',
  },
  NW5005: {
    en: 'Switch mTLS mode from PERMISSIVE to STRICT to reject plaintext traffic and enforce mutual TLS.',
    ja: 'mTLS モードを PERMISSIVE から STRICT に変更して、平文トラフィックを拒否し、相互 TLS を強制してください。',
  },
  NW5006: {
    en: 'Enable mTLS by setting mode to STRICT (or PERMISSIVE during migration) instead of DISABLE.',
    ja: 'DISABLE の代わりに mode を STRICT（または移行中は PERMISSIVE）に設定して mTLS を有効化してください。',
  },
  NW5007: {
    en: 'Add a selector.matchLabels to scope the AuthorizationPolicy to specific workloads rather than all pods in the namespace.',
    ja: 'selector.matchLabels を追加して、AuthorizationPolicy を Namespace 内のすべての Pod ではなく特定のワークロードに限定してください。',
  },
  NW5008: {
    en: 'Add source.namespaces to restrict the ALLOW rule to principals from the expected namespace only.',
    ja: 'source.namespaces を追加して、ALLOW ルールを期待する Namespace のプリンシパルのみに制限してください。',
  },

  // ── NW6xxx: Cilium NetworkPolicy ──────────────────────────────────────────
  NW6001: {
    en: 'Replace the "world" entity with specific fromCIDR ranges or more restrictive entities to limit external ingress sources.',
    ja: '"world" エンティティを特定の fromCIDR レンジまたはより制限的なエンティティに置き換えて、外部イングレス元を制限してください。',
  },
  NW6002: {
    en: 'Replace the "world" entity in egress with specific toCIDR ranges or toFQDNs to restrict outbound destinations.',
    ja: 'エグレスの "world" エンティティを特定の toCIDR レンジまたは toFQDNs に置き換えて、アウトバウンド先を制限してください。',
  },
  NW6003: {
    en: 'Replace the "all" entity with more specific entities (e.g. "cluster", "host") or label selectors.',
    ja: '"all" エンティティをより具体的なエンティティ（例: "cluster"、"host"）またはラベルセレクタに置き換えてください。',
  },
  NW6004: {
    en: 'Add matchLabels to the endpointSelector to scope this policy to specific pods rather than all pods in the namespace.',
    ja: 'endpointSelector に matchLabels を追加して、このポリシーを Namespace 内のすべての Pod ではなく特定の Pod に限定してください。',
  },
  NW6005: {
    en: 'Replace the 0.0.0.0/0 CIDR with specific source CIDR ranges that should be allowed.',
    ja: '0.0.0.0/0 CIDR を許可すべき特定の送信元 CIDR レンジに置き換えてください。',
  },
  NW6006: {
    en: 'Add a nodeSelector to restrict this CiliumClusterwideNetworkPolicy to specific nodes.',
    ja: 'nodeSelector を追加して、この CiliumClusterwideNetworkPolicy を特定のノードに限定してください。',
  },
  NW6007: {
    en: 'Replace the toFQDNs matchPattern: "*" with specific domain patterns (e.g. "*.example.com") to limit egress destinations.',
    ja: 'toFQDNs matchPattern: "*" を特定のドメインパターン（例: "*.example.com"）に置き換えて、エグレス先を制限してください。',
  },
  NW6008: {
    en: 'Verify that Cilium L7 enforcement (Envoy) is enabled in your cluster and that the L7 HTTP rules are intentional.',
    ja: 'クラスターで Cilium L7 適用（Envoy）が有効になっていることと、L7 HTTP ルールが意図的なものであることを確認してください。',
  },

  // ── NW7xxx: Cloud Provider ────────────────────────────────────────────────
  NW7001: {
    en: 'Add the annotation service.beta.kubernetes.io/aws-load-balancer-internal: "true" or set aws-load-balancer-scheme: internal to make the NLB internal.',
    ja: 'NLB を内部化するためにアノテーション service.beta.kubernetes.io/aws-load-balancer-internal: "true" を追加するか aws-load-balancer-scheme: internal を設定してください。',
  },
  NW7002: {
    en: 'Enable access logs by setting service.beta.kubernetes.io/aws-load-balancer-access-log-enabled: "true" and configure an S3 bucket for log storage.',
    ja: 'service.beta.kubernetes.io/aws-load-balancer-access-log-enabled: "true" を設定してアクセスログを有効化し、ログ保存用の S3 バケットを設定してください。',
  },
  NW7003: {
    en: 'Add service.beta.kubernetes.io/aws-load-balancer-ssl-cert with an ACM certificate ARN to enable HTTPS offload.',
    ja: 'ACM 証明書 ARN を指定した service.beta.kubernetes.io/aws-load-balancer-ssl-cert を追加して HTTPS オフロードを有効化してください。',
  },
  NW7004: {
    en: 'Pin a TLS negotiation policy by adding service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06".',
    ja: 'service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06" を追加して TLS ネゴシエーションポリシーを固定してください。',
  },
  NW7005: {
    en: 'Add alb.ingress.kubernetes.io/scheme: internal to make the ALB internal, or set scheme: internet-facing explicitly to document the intent.',
    ja: 'ALB を内部化するために alb.ingress.kubernetes.io/scheme: internal を追加するか、意図を文書化するために scheme: internet-facing を明示的に設定してください。',
  },
  NW7006: {
    en: 'Attach a custom security group via alb.ingress.kubernetes.io/security-groups to restrict which source IPs can reach the ALB.',
    ja: 'alb.ingress.kubernetes.io/security-groups でカスタムセキュリティグループをアタッチして、ALB にアクセスできる送信元 IP を制限してください。',
  },
  NW7007: {
    en: 'Pin the TLS cipher policy by adding alb.ingress.kubernetes.io/ssl-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06" to prevent weak cipher negotiation.',
    ja: 'alb.ingress.kubernetes.io/ssl-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06" を追加して TLS 暗号ポリシーを固定し、脆弱な暗号のネゴシエーションを防いでください。',
  },
  NW7008: {
    en: 'Enable connection draining by setting service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled: "true" to allow in-flight requests to complete.',
    ja: 'service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled: "true" を設定して接続ドレインを有効化し、処理中のリクエストを完了させてください。',
  },
  NW7009: {
    en: 'Add networking.gke.io/load-balancer-type: Internal to create an internal passthrough NLB, or confirm the external LB is intentional.',
    ja: 'networking.gke.io/load-balancer-type: Internal を追加して内部パススルー NLB を作成するか、外部 LB が意図的なものであることを確認してください。',
  },
  NW7010: {
    en: 'Add kubernetes.io/ingress.allow-http: "false" to the Ingress annotations to disable plaintext HTTP traffic.',
    ja: 'Ingress アノテーションに kubernetes.io/ingress.allow-http: "false" を追加して、平文 HTTP トラフィックを無効化してください。',
  },
  NW7011: {
    en: 'Add cloud.google.com/load-balancer-type: Internal for an internal LB, or document the external intent explicitly.',
    ja: '内部 LB の場合は cloud.google.com/load-balancer-type: Internal を追加するか、外部 LB であることを明示的に文書化してください。',
  },
  NW7012: {
    en: 'Add spec.securityPolicy referencing a Cloud Armor security policy to protect backend services from DDoS and OWASP threats.',
    ja: 'Cloud Armor セキュリティポリシーを参照する spec.securityPolicy を追加して、DDoS および OWASP の脅威からバックエンドサービスを保護してください。',
  },
  NW7013: {
    en: 'If this AKS LoadBalancer should be internal, change azure-load-balancer-internal from "false" to "true".',
    ja: 'この AKS LoadBalancer を内部にする場合は azure-load-balancer-internal を "false" から "true" に変更してください。',
  },
  NW7014: {
    en: 'Explicitly set service.beta.kubernetes.io/azure-load-balancer-internal: "true" for internal LBs or "false" to document the public intent.',
    ja: '内部 LB の場合は service.beta.kubernetes.io/azure-load-balancer-internal: "true" を、外部 LB の意図を文書化する場合は "false" を明示的に設定してください。',
  },
  NW7015: {
    en: 'Attach a WAF policy via appgw.ingress.kubernetes.io/waf-policy-for-path or azure.application-gateway/waf-policy-id to protect against OWASP threats.',
    ja: 'OWASP の脅威から保護するために appgw.ingress.kubernetes.io/waf-policy-for-path または azure.application-gateway/waf-policy-id で WAF ポリシーをアタッチしてください。',
  },

  // ── NW8xxx: Gateway API ────────────────────────────────────────────────────
  NW8001: {
    en: 'Reference an HTTPS Gateway listener via sectionName in parentRefs, or add a RequestRedirect filter to enforce TLS.',
    ja: 'parentRefs の sectionName で HTTPS Gateway リスナーを参照するか、RequestRedirect フィルターを追加して TLS を強制してください。',
  },
  NW8002: {
    en: "Change allowedRoutes.namespaces.from from 'All' to 'Same' or 'Selector' to restrict which namespaces can attach routes.",
    ja: "allowedRoutes.namespaces.from を 'All' から 'Same' または 'Selector' に変更して、ルートをアタッチできる Namespace を制限してください。",
  },
  NW8003: {
    en: 'Create a ReferenceGrant in the target namespace that permits HTTPRoute resources to reference Services.',
    ja: 'HTTPRoute リソースが Service を参照できるように、対象の Namespace に ReferenceGrant を作成してください。',
  },
  NW8004: {
    en: 'Add spec.listeners[].tls.certificateRefs pointing to a TLS Secret to enable HTTPS/TLS termination.',
    ja: 'TLS Secret を参照する spec.listeners[].tls.certificateRefs を追加して HTTPS/TLS 終端を有効化してください。',
  },
  NW8005: {
    en: 'Create a ReferenceGrant in the target namespace that permits GRPCRoute resources to reference Services.',
    ja: 'GRPCRoute リソースが Service を参照できるように、対象の Namespace に ReferenceGrant を作成してください。',
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

  // ── NW5xxx: Istio ─────────────────────────────────────────────────────────
  NW5001: () => ({
    description: MSG.NW5001.en,
    descriptionJa: MSG.NW5001.ja,
    fix: `# Restrict AuthorizationPolicy principals to specific service accounts
spec:
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/<namespace>/sa/<service-account>"`,
  }),

  NW5002: () => ({
    description: MSG.NW5002.en,
    descriptionJa: MSG.NW5002.ja,
    fix: `# Add source constraints to the ALLOW rule
spec:
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/<namespace>/sa/<service-account>"
            namespaces:
              - "<allowed-namespace>"`,
  }),

  NW5003: () => ({
    description: MSG.NW5003.en,
    descriptionJa: MSG.NW5003.ja,
    fix: `# Restrict HTTP methods in the AuthorizationPolicy
spec:
  rules:
    - to:
        - operation:
            methods: ["GET", "POST"]  # Replace with required methods only`,
  }),

  NW5004: () => ({
    description: MSG.NW5004.en,
    descriptionJa: MSG.NW5004.ja,
    fix: `# Add from or to conditions to the ALLOW rule
spec:
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/<namespace>/sa/<service-account>"
      to:
        - operation:
            methods: ["GET"]`,
  }),

  NW5005: () => ({
    description: MSG.NW5005.en,
    descriptionJa: MSG.NW5005.ja,
    fix: `# Change mTLS mode from PERMISSIVE to STRICT
spec:
  mtls:
    mode: STRICT`,
  }),

  NW5006: () => ({
    description: MSG.NW5006.en,
    descriptionJa: MSG.NW5006.ja,
    fix: `# Enable mTLS — use STRICT for full enforcement or PERMISSIVE during migration
spec:
  mtls:
    mode: STRICT`,
  }),

  NW5007: () => ({
    description: MSG.NW5007.en,
    descriptionJa: MSG.NW5007.ja,
    fix: `# Add a workload selector to scope the AuthorizationPolicy
spec:
  selector:
    matchLabels:
      app: <your-app-label>`,
  }),

  NW5008: () => ({
    description: MSG.NW5008.en,
    descriptionJa: MSG.NW5008.ja,
    fix: `# Add source namespace restriction alongside principals
spec:
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/<namespace>/sa/<service-account>"
            namespaces:
              - "<expected-namespace>"`,
  }),

  // ── NW6xxx: Cilium ────────────────────────────────────────────────────────
  NW6001: () => ({
    description: MSG.NW6001.en,
    descriptionJa: MSG.NW6001.ja,
    fix: `# Replace "world" entity with specific CIDRs
spec:
  ingress:
    - fromCIDR:
        - "203.0.113.0/24"  # Replace with your trusted external CIDR ranges`,
  }),

  NW6002: () => ({
    description: MSG.NW6002.en,
    descriptionJa: MSG.NW6002.ja,
    fix: `# Replace "world" entity with specific egress destinations
spec:
  egress:
    - toCIDR:
        - "203.0.113.0/24"  # Replace with allowed external CIDR
    # Or use FQDN-based egress:
    # - toFQDNs:
    #     - matchName: "api.example.com"`,
  }),

  NW6003: () => ({
    description: MSG.NW6003.en,
    descriptionJa: MSG.NW6003.ja,
    fix: `# Replace "all" entity with more specific entities
spec:
  ingress:
    - fromEntities:
        - "cluster"   # Only allow intra-cluster traffic
    # Or use label selectors:
    # - fromEndpoints:
    #     - matchLabels:
    #         app: <allowed-app>`,
  }),

  NW6004: () => ({
    description: MSG.NW6004.en,
    descriptionJa: MSG.NW6004.ja,
    fix: `# Add label selectors to the endpointSelector
spec:
  endpointSelector:
    matchLabels:
      app: <your-app-label>`,
  }),

  NW6005: () => ({
    description: MSG.NW6005.en,
    descriptionJa: MSG.NW6005.ja,
    fix: `# Replace 0.0.0.0/0 with specific trusted source CIDRs
spec:
  ingress:
    - fromCIDR:
        - "10.0.0.0/8"        # Internal network
        - "203.0.113.0/24"    # Trusted external CIDR`,
  }),

  NW6006: () => ({
    description: MSG.NW6006.en,
    descriptionJa: MSG.NW6006.ja,
    fix: `# Add nodeSelector to restrict this policy to specific nodes
spec:
  nodeSelector:
    matchLabels:
      node-role.kubernetes.io/worker: ""  # Replace with target node label`,
  }),

  NW6007: () => ({
    description: MSG.NW6007.en,
    descriptionJa: MSG.NW6007.ja,
    fix: `# Replace wildcard FQDN pattern with specific domains
spec:
  egress:
    - toFQDNs:
        - matchName: "api.example.com"
        - matchPattern: "*.your-domain.com"  # Restrict to your domain`,
  }),

  NW6008: () => ({
    description: MSG.NW6008.en,
    descriptionJa: MSG.NW6008.ja,
    // Informational — no YAML fix needed, just guidance
  }),

  // ── NW7xxx: Cloud Provider ────────────────────────────────────────────────
  NW7001: () => ({
    description: MSG.NW7001.en,
    descriptionJa: MSG.NW7001.ja,
    fix: `# Add internal annotation to the Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    # Or for AWS Load Balancer Controller:
    # service.beta.kubernetes.io/aws-load-balancer-scheme: internal`,
  }),

  NW7002: () => ({
    description: MSG.NW7002.en,
    descriptionJa: MSG.NW7002.ja,
    fix: `# Enable access logs on the AWS LoadBalancer Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-access-log-enabled: "true"
    service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-name: "<your-s3-bucket>"
    service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-prefix: "elb-logs"`,
  }),

  NW7003: () => ({
    description: MSG.NW7003.en,
    descriptionJa: MSG.NW7003.ja,
    fix: `# Add SSL certificate annotation to the Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-ssl-cert: "arn:aws:acm:<region>:<account>:certificate/<cert-id>"
    service.beta.kubernetes.io/aws-load-balancer-ssl-ports: "443"`,
  }),

  NW7004: () => ({
    description: MSG.NW7004.en,
    descriptionJa: MSG.NW7004.ja,
    fix: `# Pin the TLS negotiation policy on the Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06"`,
  }),

  NW7005: () => ({
    description: MSG.NW7005.en,
    descriptionJa: MSG.NW7005.ja,
    fix: `# Add scheme annotation to the ALB Ingress
metadata:
  annotations:
    alb.ingress.kubernetes.io/scheme: internal       # for internal ALB
    # alb.ingress.kubernetes.io/scheme: internet-facing  # for public ALB (explicit)`,
  }),

  NW7006: () => ({
    description: MSG.NW7006.en,
    descriptionJa: MSG.NW7006.ja,
    fix: `# Attach a custom security group to the ALB Ingress
metadata:
  annotations:
    alb.ingress.kubernetes.io/security-groups: "sg-<your-security-group-id>"`,
  }),

  NW7007: () => ({
    description: MSG.NW7007.en,
    descriptionJa: MSG.NW7007.ja,
    fix: `# Pin the SSL cipher policy on the ALB Ingress
metadata:
  annotations:
    alb.ingress.kubernetes.io/ssl-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06"`,
  }),

  NW7008: () => ({
    description: MSG.NW7008.en,
    descriptionJa: MSG.NW7008.ja,
    fix: `# Enable connection draining on the AWS LoadBalancer Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled: "true"
    service.beta.kubernetes.io/aws-load-balancer-connection-draining-timeout: "60"`,
  }),

  NW7009: () => ({
    description: MSG.NW7009.en,
    descriptionJa: MSG.NW7009.ja,
    fix: `# Make the GKE LoadBalancer internal
metadata:
  annotations:
    networking.gke.io/load-balancer-type: Internal
    # For older GKE versions:
    # cloud.google.com/load-balancer-type: Internal`,
  }),

  NW7010: () => ({
    description: MSG.NW7010.en,
    descriptionJa: MSG.NW7010.ja,
    fix: `# Disable HTTP on the GCE Ingress
metadata:
  annotations:
    kubernetes.io/ingress.allow-http: "false"`,
  }),

  NW7011: () => ({
    description: MSG.NW7011.en,
    descriptionJa: MSG.NW7011.ja,
    fix: `# Add explicit load-balancer-type annotation to the GKE Service
metadata:
  annotations:
    cloud.google.com/load-balancer-type: Internal   # or omit for external (document intent)`,
  }),

  NW7012: () => ({
    description: MSG.NW7012.en,
    descriptionJa: MSG.NW7012.ja,
    fix: `# Add Cloud Armor security policy to the BackendConfig
spec:
  securityPolicy:
    name: "<your-cloud-armor-policy-name>"`,
  }),

  NW7013: () => ({
    description: MSG.NW7013.en,
    descriptionJa: MSG.NW7013.ja,
    fix: `# Change to internal if this should not be public
metadata:
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"`,
  }),

  NW7014: () => ({
    description: MSG.NW7014.en,
    descriptionJa: MSG.NW7014.ja,
    fix: `# Explicitly declare the intent for this AKS LoadBalancer
metadata:
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"   # for internal
    # service.beta.kubernetes.io/azure-load-balancer-internal: "false"  # for public (explicit)`,
  }),

  NW7015: () => ({
    description: MSG.NW7015.en,
    descriptionJa: MSG.NW7015.ja,
    fix: `# Attach a WAF policy to the Azure Application Gateway Ingress
metadata:
  annotations:
    appgw.ingress.kubernetes.io/waf-policy-for-path: "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/<policy>"`,
  }),

  // ── NW8xxx: Gateway API ────────────────────────────────────────────────────
  NW8001: () => ({
    description: MSG.NW8001.en,
    descriptionJa: MSG.NW8001.ja,
    fix: `# Update the HTTPRoute parentRefs to point to an HTTPS listener
spec:
  parentRefs:
    - name: <your-gateway-name>
      sectionName: https   # Reference the HTTPS listener by name
# Then ensure the Gateway has an HTTPS listener:
# spec:
#   listeners:
#     - name: https
#       port: 443
#       protocol: HTTPS
#       tls:
#         mode: Terminate
#         certificateRefs:
#           - name: <tls-secret-name>`,
  }),

  NW8002: (finding) => ({
    description: MSG.NW8002.en,
    descriptionJa: MSG.NW8002.ja,
    fix: `# Restrict allowed route namespaces in the Gateway listener
# Option A — allow only routes from the same namespace
spec:
  listeners:
    - name: <listener-name>
      allowedRoutes:
        namespaces:
          from: Same

# Option B — allow routes from specific namespaces via label selector
spec:
  listeners:
    - name: <listener-name>
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              gateway.networking.k8s.io/route-allowed: "true"
# (label the allowed namespaces accordingly)`,
  }),

  NW8003: (finding) => ({
    description: MSG.NW8003.en,
    descriptionJa: MSG.NW8003.ja,
    fix: `# Create a ReferenceGrant in the target namespace to permit cross-namespace access
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-httproute-from-${finding.namespace}
  namespace: <target-namespace>   # The namespace where the backend Service lives
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: ${finding.namespace}
  to:
    - group: ""
      kind: Service`,
  }),

  NW8004: () => ({
    description: MSG.NW8004.en,
    descriptionJa: MSG.NW8004.ja,
    fix: `# Add certificateRefs to the HTTPS/TLS listener in the Gateway
spec:
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - name: <tls-secret-name>   # Name of a TLS Secret in this namespace
            # namespace: <other-ns>  # omit if Secret is in same namespace`,
  }),

  NW8005: (finding) => ({
    description: MSG.NW8005.en,
    descriptionJa: MSG.NW8005.ja,
    fix: `# Create a ReferenceGrant in the target namespace to permit cross-namespace access
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: ReferenceGrant
metadata:
  name: allow-grpcroute-from-${finding.namespace}
  namespace: <target-namespace>   # The namespace where the backend Service lives
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: GRPCRoute
      namespace: ${finding.namespace}
  to:
    - group: ""
      kind: Service`,
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
