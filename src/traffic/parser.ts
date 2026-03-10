import fs from 'node:fs';
import type { TrafficFlow, TrafficLogFormat } from './types.js';

// ─── Hubble parser ────────────────────────────────────────────────────────────

/**
 * Hubble JSON format (one JSON object per line).
 *
 * Relevant fields:
 *   time, verdict (FORWARDED | DROPPED | AUDIT | ERROR),
 *   source.namespace, source.pod_name,
 *   destination.namespace, destination.pod_name,
 *   l4.TCP.destination_port | l4.UDP.destination_port,
 *   IP.source, IP.destination,
 *   traffic_direction
 */
export function parseHubbleLogs(content: string): TrafficFlow[] {
  const flows: TrafficFlow[] = [];
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue; // skip malformed lines
    }

    // Normalise verdict
    const rawVerdict = String((obj.verdict as string | undefined) ?? '').toUpperCase();
    let verdict: TrafficFlow['verdict'];
    if (rawVerdict === 'FORWARDED' || rawVerdict === 'ALLOW') {
      verdict = 'ALLOW';
    } else if (rawVerdict === 'DROPPED' || rawVerdict === 'DROP') {
      verdict = 'DROP';
    } else if (rawVerdict === 'AUDIT') {
      verdict = 'AUDIT';
    } else {
      verdict = 'UNKNOWN';
    }

    const src = (obj.source ?? obj.Source ?? {}) as Record<string, unknown>;
    const dst = (obj.destination ?? obj.Destination ?? {}) as Record<string, unknown>;
    const ip = (obj.IP ?? obj.ip ?? {}) as Record<string, unknown>;
    const l4 = (obj.l4 ?? obj.L4 ?? {}) as Record<string, unknown>;

    // Extract dest port from l4.TCP or l4.UDP
    let destPort: number | undefined;
    const tcp = (l4.TCP ?? l4.tcp ?? {}) as Record<string, unknown>;
    const udp = (l4.UDP ?? l4.udp ?? {}) as Record<string, unknown>;
    if (tcp.destination_port !== undefined) {
      destPort = Number(tcp.destination_port);
    } else if (udp.destination_port !== undefined) {
      destPort = Number(udp.destination_port);
    } else if (dst.port !== undefined) {
      destPort = Number(dst.port);
    }

    const protocol =
      l4.TCP ?? l4.tcp ? 'TCP'
      : l4.UDP ?? l4.udp ? 'UDP'
      : undefined;

    const sourceNamespace = String(src.namespace ?? '');
    const sourcePod = String(src.pod_name ?? src.workload ?? '');
    const destNamespace = String(dst.namespace ?? '');
    const destPod = String(dst.pod_name ?? dst.workload ?? '');
    const timestamp = String(obj.time ?? obj.timestamp ?? '');
    const sourceIP = ip.source ? String(ip.source) : undefined;
    const destIP = ip.destination ? String(ip.destination) : undefined;
    const reason = obj.drop_reason
      ? String(obj.drop_reason)
      : obj.reason
        ? String(obj.reason)
        : undefined;

    // Skip entries without sufficient namespace/pod info
    if (!sourceNamespace && !sourcePod && !destNamespace && !destPod) continue;

    flows.push({
      timestamp,
      sourceNamespace,
      sourcePod,
      sourceIP,
      destNamespace,
      destPod,
      destIP,
      destPort: Number.isNaN(destPort) ? undefined : destPort,
      protocol,
      verdict,
      reason,
    });
  }
  return flows;
}

// ─── Falco parser ─────────────────────────────────────────────────────────────

/**
 * Falco JSON format (one JSON object per line).
 *
 * Relevant fields:
 *   time, rule, priority (WARNING|ERROR|INFO|...), output (free text), source
 *
 * We extract namespace/pod from the output field using known patterns:
 *   "namespace=<ns> pod=<pod>" or "k8s.ns.name=<ns> k8s.pod.name=<pod>"
 */
export function parseFalcoLogs(content: string): TrafficFlow[] {
  const flows: TrafficFlow[] = [];
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }

    // Must look like a Falco event
    if (!obj.rule && !obj.priority && !obj.output) continue;

    const output = String(obj.output ?? '');
    const timestamp = String(obj.time ?? obj.timestamp ?? '');

    // Extract namespace and pod from output patterns
    const nsMatch = /(?:namespace|k8s\.ns\.name)=([^\s)]+)/.exec(output);
    const podMatch = /(?:\bpod\b|k8s\.pod\.name)=([^\s)]+)/.exec(output);
    const portMatch = /(?:fd\.rport|dport|rport)=(\d+)/.exec(output);
    const ripMatch = /(?:fd\.name|fd\.rip|ip\.dst)=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?/.exec(output);

    const sourceNamespace = nsMatch ? nsMatch[1] : '';
    const sourcePod = podMatch ? podMatch[1] : '';
    const destPort = portMatch ? Number(portMatch[1]) : ripMatch?.[2] ? Number(ripMatch[2]) : undefined;
    const destIP = ripMatch ? ripMatch[1] : undefined;

    // Map priority to verdict
    const priority = String(obj.priority ?? '').toUpperCase();
    let verdict: TrafficFlow['verdict'] = 'AUDIT';
    if (priority === 'EMERGENCY' || priority === 'ALERT' || priority === 'CRITICAL' || priority === 'ERROR') {
      verdict = 'DROP';
    } else if (priority === 'WARNING' || priority === 'NOTICE') {
      verdict = 'AUDIT';
    }

    flows.push({
      timestamp,
      sourceNamespace,
      sourcePod,
      destNamespace: '',      // Falco doesn't distinguish dest namespace
      destPod: '',
      destIP,
      destPort,
      protocol: 'TCP',
      verdict,
      reason: String(obj.rule ?? ''),
    });
  }
  return flows;
}

// ─── Generic CSV parser ───────────────────────────────────────────────────────

/**
 * Generic CSV format (tcpdump-like).
 * Expected header:
 *   timestamp,src_ns,src_pod,dst_ns,dst_pod,dst_port,protocol,verdict
 *
 * Lines beginning with '#' are treated as comments and skipped.
 * The header row (first non-comment line) is detected by content, not position.
 */
export function parseGenericLogs(content: string): TrafficFlow[] {
  const flows: TrafficFlow[] = [];
  const lines = content.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));

  if (lines.length === 0) return flows;

  // Detect whether first line is a header
  const firstLine = lines[0].toLowerCase();
  const hasHeader =
    firstLine.includes('timestamp') ||
    firstLine.includes('src_ns') ||
    firstLine.includes('src_pod') ||
    firstLine.includes('verdict');
  const dataLines = hasHeader ? lines.slice(1) : lines;

  for (const line of dataLines) {
    const parts = line.split(',').map((p) => p.trim());
    if (parts.length < 7) continue; // need at least 7 columns

    const [timestamp, sourceNamespace, sourcePod, destNamespace, destPod, dstPortStr, protocol, verdictRaw] = parts;

    const rawVerdict = (verdictRaw ?? '').toUpperCase();
    let verdict: TrafficFlow['verdict'];
    if (rawVerdict === 'ALLOW' || rawVerdict === 'ALLOWED' || rawVerdict === 'FORWARDED') {
      verdict = 'ALLOW';
    } else if (rawVerdict === 'DROP' || rawVerdict === 'DROPPED' || rawVerdict === 'DENY' || rawVerdict === 'DENIED') {
      verdict = 'DROP';
    } else if (rawVerdict === 'AUDIT') {
      verdict = 'AUDIT';
    } else {
      verdict = 'UNKNOWN';
    }

    const destPort = dstPortStr ? Number(dstPortStr) : undefined;

    flows.push({
      timestamp: timestamp ?? '',
      sourceNamespace: sourceNamespace ?? '',
      sourcePod: sourcePod ?? '',
      destNamespace: destNamespace ?? '',
      destPod: destPod ?? '',
      destPort: Number.isNaN(destPort) ? undefined : destPort,
      protocol: protocol || undefined,
      verdict,
    });
  }
  return flows;
}

// ─── Auto-detect + unified entry point ────────────────────────────────────────

/**
 * Attempt to detect the log format from the file content.
 * Returns the detected format or 'generic' as fallback.
 */
export function detectLogFormat(content: string): TrafficLogFormat {
  const firstNonEmpty = content
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.length > 0 && !l.startsWith('#'));

  if (!firstNonEmpty) return 'generic';

  if (firstNonEmpty.startsWith('{')) {
    // Try JSON — distinguish Hubble vs Falco by key presence
    try {
      const obj = JSON.parse(firstNonEmpty) as Record<string, unknown>;
      if (obj.rule !== undefined || obj.priority !== undefined || obj.output !== undefined) {
        return 'falco';
      }
      // Hubble has verdict / source / destination
      if (obj.verdict !== undefined || obj.source !== undefined || obj.destination !== undefined) {
        return 'hubble';
      }
      // Generic JSON-like but not clearly either — fall through
    } catch {
      // Not valid JSON
    }
  }

  return 'generic';
}

/**
 * Parse a traffic log file, auto-detecting or using the provided format.
 */
export function parseTrafficLog(filePath: string, format?: TrafficLogFormat): TrafficFlow[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read traffic log file "${filePath}": ${(err as Error).message}`);
  }

  const resolvedFormat = format ?? detectLogFormat(content);

  switch (resolvedFormat) {
    case 'hubble':
      return parseHubbleLogs(content);
    case 'falco':
      return parseFalcoLogs(content);
    case 'generic':
    default:
      return parseGenericLogs(content);
  }
}
