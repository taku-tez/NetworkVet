import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import { runRules } from '../rules/engine.js';
import type { ParsedResource } from '../types.js';

// ─── AdmissionReview types ────────────────────────────────────────────────────

export interface AdmissionRequest {
  apiVersion: 'admission.k8s.io/v1';
  kind: 'AdmissionReview';
  request: {
    uid: string;
    kind: { group: string; version: string; kind: string };
    resource: { group: string; version: string; resource: string };
    name: string;
    namespace?: string;
    operation: 'CREATE' | 'UPDATE' | 'DELETE' | 'CONNECT';
    object: Record<string, unknown>;
    oldObject?: Record<string, unknown>;
  };
}

export interface AdmissionResponse {
  apiVersion: 'admission.k8s.io/v1';
  kind: 'AdmissionReview';
  response: {
    uid: string;
    allowed: boolean;
    status?: { code: number; message: string };
    warnings?: string[];
  };
}

export interface WebhookOptions {
  port: number;
  tlsCert?: string;    // path to TLS certificate file
  tlsKey?: string;     // path to TLS private key file
  ignoreIds?: string[];
  denyOnError?: boolean;   // reject resource when findings include severity=error
  warnOnWarning?: boolean; // surface severity=warning as AdmissionReview warnings
}

// ─── Resource kinds the webhook validates ────────────────────────────────────

const VALIDATED_KINDS = new Set([
  'NetworkPolicy',
  'Service',
  'Ingress',
  'AuthorizationPolicy',
  'PeerAuthentication',
  'CiliumNetworkPolicy',
  'CiliumClusterwideNetworkPolicy',
  'BackendConfig',
]);

// ─── Convert AdmissionReview object to ParsedResource ────────────────────────

function admissionObjectToResource(
  obj: Record<string, unknown>,
  fallbackName: string,
  fallbackNamespace: string | undefined,
): ParsedResource {
  const meta = (obj.metadata ?? {}) as Record<string, unknown>;
  const name = typeof meta.name === 'string' ? meta.name : fallbackName;
  const namespace = typeof meta.namespace === 'string'
    ? meta.namespace
    : typeof fallbackNamespace === 'string'
      ? fallbackNamespace
      : undefined;
  const labels = (meta.labels && typeof meta.labels === 'object' && !Array.isArray(meta.labels))
    ? meta.labels as Record<string, string>
    : undefined;
  const annotations = (meta.annotations && typeof meta.annotations === 'object' && !Array.isArray(meta.annotations))
    ? meta.annotations as Record<string, string>
    : undefined;

  return {
    kind: typeof obj.kind === 'string' ? obj.kind : 'Unknown',
    apiVersion: typeof obj.apiVersion === 'string' ? obj.apiVersion : 'v1',
    metadata: {
      name,
      ...(namespace !== undefined ? { namespace } : {}),
      ...(labels ? { labels } : {}),
      ...(annotations ? { annotations } : {}),
    },
    spec: (obj.spec && typeof obj.spec === 'object' ? obj.spec : {}) as Record<string, unknown>,
    file: '<webhook>',
    line: 0,
  };
}

// ─── Core handler ─────────────────────────────────────────────────────────────

/**
 * Process a single AdmissionReview request and return an AdmissionReview response.
 */
export function handleAdmissionRequest(
  body: AdmissionRequest,
  ignoreIds: string[] = [],
  denyOnError = false,
  warnOnWarning = true,
): AdmissionResponse {
  const req = body.request;
  const uid = req.uid;

  // Skip non-CREATE/UPDATE operations and kinds we don't validate
  const resourceKind = req.kind.kind;
  if (!VALIDATED_KINDS.has(resourceKind) || req.operation === 'DELETE' || req.operation === 'CONNECT') {
    return {
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      response: { uid, allowed: true },
    };
  }

  // Build ParsedResource from the admission object
  const resource = admissionObjectToResource(req.object, req.name, req.namespace);

  // Run rules against the single resource
  const findings = runRules([resource], ignoreIds);

  // Separate by severity
  const errors = findings.filter((f) => f.severity === 'error');
  const warnings = findings.filter((f) => f.severity === 'warning' || f.severity === 'info');

  // Build warnings list (always include error messages as warnings too when not denying)
  const warningMessages: string[] = [];
  if (warnOnWarning) {
    for (const f of warnings) {
      warningMessages.push(`[${f.id}] ${f.message}`);
    }
  }
  // When denying, errors are in the status message; when not denying, include them as warnings too
  if (!denyOnError) {
    for (const f of errors) {
      warningMessages.push(`[${f.id}] ${f.message}`);
    }
  }

  if (denyOnError && errors.length > 0) {
    const errorMessages = errors.map((f) => `[${f.id}] ${f.message}`).join('; ');
    return {
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      response: {
        uid,
        allowed: false,
        status: {
          code: 403,
          message: `NetworkVet policy violations: ${errorMessages}`,
        },
        ...(warningMessages.length > 0 ? { warnings: warningMessages } : {}),
      },
    };
  }

  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: {
      uid,
      allowed: true,
      ...(warningMessages.length > 0 ? { warnings: warningMessages } : {}),
    },
  };
}

// ─── Generate webhook deployment manifest ─────────────────────────────────────

export function generateWebhookManifest(): string {
  return `apiVersion: v1
kind: Namespace
metadata:
  name: networkvet-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: networkvet-webhook
  namespace: networkvet-system
---
apiVersion: v1
kind: Service
metadata:
  name: networkvet-webhook
  namespace: networkvet-system
spec:
  ports:
  - port: 443
    targetPort: 8443
    protocol: TCP
  selector:
    app: networkvet-webhook
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: networkvet-webhook
  namespace: networkvet-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: networkvet-webhook
  template:
    metadata:
      labels:
        app: networkvet-webhook
    spec:
      serviceAccountName: networkvet-webhook
      containers:
      - name: networkvet-webhook
        image: networkvet:0.9.0
        args:
        - --webhook
        - --webhook-port=8443
        - --webhook-deny-on-error
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/networkvet/tls
          readOnly: true
      volumes:
      - name: tls-certs
        secret:
          secretName: networkvet-webhook-tls
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: networkvet
webhooks:
- name: networkvet.io
  rules:
  - apiGroups: ["", "networking.k8s.io", "security.istio.io", "cilium.io"]
    apiVersions: ["*"]
    resources:
    - networkpolicies
    - services
    - ingresses
    - authorizationpolicies
    - peerauthentications
    - ciliumnetworkpolicies
    operations: ["CREATE", "UPDATE"]
  admissionReviewVersions: ["v1"]
  clientConfig:
    service:
      name: networkvet-webhook
      namespace: networkvet-system
      path: /validate
  sideEffects: None
  failurePolicy: Ignore
  timeoutSeconds: 10
`;
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

/**
 * Create and return an HTTP(S) server that handles AdmissionReview requests.
 */
export function createWebhookServer(options: WebhookOptions): http.Server | https.Server {
  const {
    port,
    tlsCert,
    tlsKey,
    ignoreIds = [],
    denyOnError = false,
    warnOnWarning = true,
  } = options;

  const validatedKindList = [...VALIDATED_KINDS].join(', ');

  function requestHandler(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Health check
    if (req.url === '/healthz' || req.url === '/readyz') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    if (req.url !== '/validate' || req.method !== 'POST') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      let body: AdmissionRequest;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as AdmissionRequest;
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid JSON body' }));
        return;
      }

      let admissionResponse: AdmissionResponse;
      try {
        admissionResponse = handleAdmissionRequest(body, ignoreIds, denyOnError, warnOnWarning);
      } catch (err) {
        // On unexpected error, allow through (fail-open) to avoid disrupting cluster operations
        const uid = body?.request?.uid ?? '';
        admissionResponse = {
          apiVersion: 'admission.k8s.io/v1',
          kind: 'AdmissionReview',
          response: {
            uid,
            allowed: true,
            warnings: [`NetworkVet internal error: ${(err as Error).message}`],
          },
        };
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(admissionResponse));
    });
  }

  let server: http.Server | https.Server;

  if (tlsCert && tlsKey) {
    const tlsOptions = {
      cert: fs.readFileSync(tlsCert),
      key: fs.readFileSync(tlsKey),
    };
    server = https.createServer(tlsOptions, requestHandler);
  } else {
    server = http.createServer(requestHandler);
  }

  server.on('listening', () => {
    const mode = denyOnError ? 'deny-on-error' : 'warn-only';
    process.stderr.write(
      `NetworkVet webhook server listening on :${port}\n` +
      `Validating: ${validatedKindList}\n` +
      `Mode: ${mode}${denyOnError ? '' : ' (use --webhook-deny-on-error to enable rejection)'}\n`,
    );
  });

  return server;
}
