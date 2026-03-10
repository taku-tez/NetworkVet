// Traffic analysis type definitions for NetworkVet

export type TrafficLogFormat = 'hubble' | 'falco' | 'generic';

export interface TrafficFlow {
  timestamp: string;
  sourceNamespace: string;
  sourcePod: string;
  sourceIP?: string;
  destNamespace: string;
  destPod: string;
  destIP?: string;
  destPort?: number;
  protocol?: string;
  verdict: 'ALLOW' | 'DROP' | 'AUDIT' | 'UNKNOWN';
  reason?: string;
}

export interface TrafficViolation {
  type: 'unexpected-allow' | 'unexpected-deny' | 'policy-gap' | 'shadow-traffic';
  flow: TrafficFlow;
  message: string;
  severity: 'error' | 'warning' | 'info';
}

export interface PolicyGap {
  sourceNamespace: string;
  destNamespace: string;
  destPort: number;
  observedCount: number;
  message: string;
}

export interface TrafficAnalysisResult {
  totalFlows: number;
  allowedFlows: number;
  droppedFlows: number;
  violations: TrafficViolation[];
  policyGaps: PolicyGap[];
}
