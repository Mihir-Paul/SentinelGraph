export type HostStatus = "HEALTHY" | "SUSPICIOUS" | "COMPROMISED" | "ISOLATED";
export type HostCriticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type EventSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type SimulationStatus = "ACTIVE" | "CONTAINED" | "FAILED";

export interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  host_type: string;
  status: HostStatus;
  criticality: HostCriticality;
  updated_at?: string;
}

export interface SecurityEvent {
  id: string;
  simulation_id: string;
  timestamp: string;
  source_ip: string;
  target_host: string;
  event_type: string;
  severity: EventSeverity;
  details: Record<string, any>;
  created_at?: string;
}

export interface Simulation {
  id: string;
  scenario_id: string;
  status: SimulationStatus;
  current_tick: number;
  threat_score: number;
  severity: string;
  created_at: string;
  updated_at: string;
}

export interface ThreatFactor {
  event_type: string;
  contribution: number;
  reason: string;
}

export interface ThreatScoreResponse {
  score: number;
  raw_score?: number;
  severity: string;
  factors: ThreatFactor[];
}

export interface SimulationStateResponse {
  simulation: Simulation | null;
  hosts: Host[];
  events: SecurityEvent[];
  threat?: ThreatScoreResponse;
}

export interface SimulationStepResponse {
  completed: boolean;
  event?: SecurityEvent;
  simulation?: Simulation;
  hosts?: Host[];
  threat?: ThreatScoreResponse;
}

export interface CorrelationItem {
  stage: string;
  events: string[];
  explanation: string;
}

export interface AttackChainItem {
  stage: string;
  event_types: string[];
}

export interface AffectedHostItem {
  host: string;
  role: string;
  impact: string;
}

export interface InvestigationData {
  simulation_id: string;
  scenario_id: string;
  threat: {
    score: number;
    severity: string;
  };
  detection_summary: string;
  correlations: CorrelationItem[];
  attack_chain: AttackChainItem[];
  affected_hosts: AffectedHostItem[];
  threat_analysis: string;
  investigation_summary: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  recommendations: string[];
}

export interface InvestigationResponse {
  simulation_id: string;
  scenario_id: string;
  investigation: InvestigationData;
}

export interface ProposedActionData {
  action_id: string;
  action_type: string;
  target: string;
  reason: string;
  priority: string;
  status: "PROPOSED" | "APPROVED" | "REJECTED" | "EXECUTED" | "FAILED";
}

export interface ResponseData {
  simulation_id: string;
  scenario_id: string;
  status: string;
  proposed_actions: ProposedActionData[];
  approved_actions: ProposedActionData[];
  executed_actions: ProposedActionData[];
  summary: string;
}

export interface ResponseRunResponse {
  simulation_id: string;
  scenario_id: string;
  investigation: InvestigationData;
  response: ResponseData;
  hosts?: Host[];
}

export interface AttackGraphNode {
  id: string;
  type: "SOURCE" | "EVENT" | "HOST" | "IMPACT";
  label: string;
  severity: string;
  details: Record<string, any>;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
}

export interface AttackGraphResponse {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}
