from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class CorrelationItem(BaseModel):
    stage: str = Field(description="Stage of attack e.g. Initial Access, Privilege Escalation")
    events: List[str] = Field(description="List of event_type strings associated with this stage")
    explanation: str = Field(description="Defensive SOC explanation of how these events correlate")

class AttackChainItem(BaseModel):
    stage: str = Field(description="Stage name e.g. Initial Access, Lateral Movement, Impact")
    event_types: List[str] = Field(description="Exact event types matching this stage from simulation")

class AffectedHostItem(BaseModel):
    host: str = Field(description="Host name e.g. server-01, database, server-03")
    role: str = Field(description="Host role e.g. Application Server, Database Node")
    impact: str = Field(description="Description of impact observed from simulated events")

class InvestigationReport(BaseModel):
    simulation_id: str
    scenario_id: str
    threat: Dict[str, Any]  # {"score": int, "severity": str}
    detection_summary: str
    correlations: List[CorrelationItem]
    attack_chain: List[AttackChainItem]
    affected_hosts: List[AffectedHostItem]
    threat_analysis: str
    investigation_summary: str
    confidence: str  # HIGH, MEDIUM, LOW
    recommendations: List[str]
