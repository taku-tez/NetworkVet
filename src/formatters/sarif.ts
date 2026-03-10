import type { Finding } from '../types.js';

// SARIF 2.1.0 types (simplified)
interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties?: { tags?: string[]; severity?: string };
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation: { uri: string; uriBaseId?: string };
    region?: { startLine: number };
  };
  logicalLocations?: Array<{ name: string; kind: string }>;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: SarifLocation[];
  properties?: { detail?: string };
}

interface SarifTool {
  driver: {
    name: string;
    version: string;
    informationUri: string;
    rules: SarifRule[];
  };
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
}

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

const SEVERITY_TO_LEVEL: Record<string, SarifResult['level']> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  info: 'note',
};

/**
 * Format findings as SARIF 2.1.0 output for GitHub Code Scanning integration.
 */
export function formatSarif(findings: Finding[]): string {
  // Collect unique rules
  const rulesMap = new Map<string, SarifRule>();
  for (const f of findings) {
    if (!rulesMap.has(f.id)) {
      rulesMap.set(f.id, {
        id: f.id,
        name: ruleIdToName(f.id),
        shortDescription: { text: f.message },
        helpUri: `https://github.com/NetworkVet/networkvet/blob/main/docs/rules/${f.id.toLowerCase()}.md`,
        properties: {
          tags: ['security', 'kubernetes', 'network'],
          severity: f.severity,
        },
      });
    }
  }

  const results: SarifResult[] = findings.map((f) => {
    const location: SarifLocation = {
      physicalLocation: {
        artifactLocation: {
          uri: normalizeUri(f.file),
          uriBaseId: '%SRCROOT%',
        },
        ...(f.line > 0 ? { region: { startLine: f.line } } : {}),
      },
      logicalLocations: [
        {
          name: `${f.namespace}/${f.kind}/${f.name}`,
          kind: 'resource',
        },
      ],
    };

    const result: SarifResult = {
      ruleId: f.id,
      level: SEVERITY_TO_LEVEL[f.severity] ?? 'note',
      message: { text: f.message },
      locations: [location],
    };

    if (f.detail) {
      result.properties = { detail: f.detail };
    }

    return result;
  });

  const sarifLog: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'NetworkVet',
            version: '0.1.0',
            informationUri: 'https://github.com/NetworkVet/networkvet',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}

function ruleIdToName(id: string): string {
  // Convert NW1001 -> NetworkVetNW1001
  return `NetworkVet${id}`;
}

function normalizeUri(filePath: string): string {
  // Convert absolute paths to relative-looking URIs for SARIF
  if (filePath === '<cluster>' || filePath === '<inline>') return filePath;
  // Remove leading slash and convert to forward slashes
  return filePath.replace(/\\/g, '/').replace(/^\//, '');
}
