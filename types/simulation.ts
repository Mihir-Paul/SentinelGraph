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

export interface SimulationStateResponse {
  simulation: Simulation | null;
  hosts: Host[];
  events: SecurityEvent[];
}

export interface SimulationStepResponse {
  completed: boolean;
  event?: SecurityEvent;
  simulation?: Simulation;
  hosts?: Host[];
}
