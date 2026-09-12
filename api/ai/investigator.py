import os
import json
import logging
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END

from api.ai.schemas import (
    InvestigationReport,
    CorrelationItem,
    AttackChainItem,
    AffectedHostItem,
)
from backend.engine.threat_scorer import calculate_severity, EVENT_WEIGHTS, EVENT_REASONS

logger = logging.getLogger("sentinelgraph.investigator")

class SentinelInvestigationState(TypedDict):
    simulation_id: str
    scenario_id: str
    events: List[Dict[str, Any]]
    hosts: List[Dict[str, Any]]
    threat_score: int
    severity: str
    detection_summary: Optional[str]
    correlations: Optional[List[Dict[str, Any]]]
    attack_chain: Optional[List[Dict[str, Any]]]
    affected_hosts: Optional[List[Dict[str, Any]]]
    threat_analysis: Optional[str]
    investigation_summary: Optional[str]
    confidence: Optional[str]
    recommendations: Optional[List[str]]
    final_report: Optional[Dict[str, Any]]

# Stage mapping helper based on event type
EVENT_STAGE_MAP = {
    "FAILED_LOGIN": "Initial Access",
    "SUCCESSFUL_LOGIN": "Initial Access",
    "SUSPICIOUS_LOGIN": "Initial Access",
    "SUSPICIOUS_LOGIN_LOCATION": "Initial Access",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "PRIVILEGE_CHANGE": "Privilege Escalation",
    "SERVER_ACCESS": "Lateral Movement",
    "SENSITIVE_FILE_ACCESS": "Sensitive Resource Access",
    "SENSITIVE_RESOURCE_ACCESS": "Sensitive Resource Access",
    "DATA_AGGREGATION": "Data Staging",
    "LARGE_OUTBOUND_TRANSFER": "Exfiltration",
    "MASS_FILE_MODIFICATION": "Impact / Encryption",
}

def detect_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    events = state.get("events", [])
    if not events:
        summary = "No security events detected in the current simulation tick window. Baseline monitoring active."
    else:
        event_types = [e.get("event_type", "UNKNOWN") for e in events if isinstance(e, dict)]
        unique_types = sorted(list(set(event_types)))
        targets = sorted(list(set([e.get("target_host") for e in events if isinstance(e, dict) and e.get("target_host")])))
        sources = sorted(list(set([e.get("source_ip") for e in events if isinstance(e, dict) and e.get("source_ip")])))

        summary = (
            f"Detected {len(events)} security event(s) across target(s) {', '.join(targets) if targets else 'N/A'} "
            f"from source IP(s) {', '.join(sources) if sources else 'N/A'}. "
            f"Captured signals include: {', '.join(unique_types)}."
        )

    return {"detection_summary": summary}

def correlate_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    events = state.get("events", [])
    if not events:
        return {"correlations": [], "attack_chain": []}

    stage_groups: Dict[str, List[str]] = {}
    correlations: List[Dict[str, Any]] = []

    for evt in events:
        if not isinstance(evt, dict):
            continue
        etype = evt.get("event_type", "UNKNOWN")
        stage = EVENT_STAGE_MAP.get(etype, "Execution")

        if stage not in stage_groups:
            stage_groups[stage] = []
        if etype not in stage_groups[stage]:
            stage_groups[stage].append(etype)

    attack_chain: List[Dict[str, Any]] = []
    for stage, etypes in stage_groups.items():
        attack_chain.append({
            "stage": stage,
            "event_types": etypes,
        })
        reasons = [EVENT_REASONS.get(et, f"Event {et} recorded.") for et in etypes]
        correlations.append({
            "stage": stage,
            "events": etypes,
            "explanation": " ".join(reasons),
        })

    return {
        "correlations": correlations,
        "attack_chain": attack_chain,
    }

def analyze_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    events = state.get("events", [])
    hosts = state.get("hosts", [])
    score = state.get("threat_score", 0)
    severity = state.get("severity", "LOW")

    # Affected hosts identification strictly grounded in events & simulation hosts
    affected_map: Dict[str, Dict[str, Any]] = {}
    for evt in events:
        if not isinstance(evt, dict):
            continue
        thost = evt.get("target_host")
        if thost and thost not in affected_map:
            matching_host = next((h for h in hosts if isinstance(h, dict) and h.get("hostname") == thost or h.get("id") == thost), None)
            role = matching_host.get("host_type", "Application Server") if matching_host else "Simulated Host"
            etype = evt.get("event_type", "")
            impact_desc = EVENT_REASONS.get(etype, f"Simulated {etype} activity observed.")
            affected_map[thost] = {
                "host": thost,
                "role": role,
                "impact": impact_desc,
            }

    affected_hosts = list(affected_map.values())

    # Determine confidence strictly based on evidence volume
    if not events:
        confidence = "LOW"
    elif len(events) >= 4:
        confidence = "HIGH"
    else:
        confidence = "MEDIUM"

    # Try optional LLM synthesis if API key is configured
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    threat_analysis = None
    investigation_summary = None
    recommendations = None

    if api_key:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            from langchain_core.messages import SystemMessage, HumanMessage

            llm = ChatGoogleGenerativeAI(
                model="gemini-2.5-flash",
                google_api_key=api_key,
                temperature=0.1,
            )

            prompt = (
                f"You are the SentinelGraph SOC Investigator.\n"
                f"Analyze this synthetic security simulation strictly grounded in provided data.\n"
                f"RULES:\n"
                f"- Never invent events, hosts, or IP addresses.\n"
                f"- Treat threat score {score} and severity {severity} as authoritative.\n"
                f"- Output MUST be JSON matching keys: threat_analysis, investigation_summary, recommendations.\n\n"
                f"Simulation ID: {state.get('simulation_id')}\n"
                f"Scenario ID: {state.get('scenario_id')}\n"
                f"Threat Score: {score} ({severity})\n"
                f"Events: {json.dumps(events)}\n"
                f"Affected Hosts: {json.dumps(affected_hosts)}\n"
            )

            response = llm.invoke([
                SystemMessage(content="You are a defensive SOC security analyst. Respond ONLY in valid JSON."),
                HumanMessage(content=prompt),
            ])

            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            parsed = json.loads(content)
            threat_analysis = parsed.get("threat_analysis")
            investigation_summary = parsed.get("investigation_summary")
            recommendations = parsed.get("recommendations")
        except Exception as err:
            logger.warning("[AI Investigator] LLM invocation fallback used: %s", err)

    # Deterministic SOC synthesis fallback if no API key or LLM call fails
    if not threat_analysis:
        if not events:
            threat_analysis = "Baseline simulation environment. No security anomalies or threat vectors identified."
            investigation_summary = "Normal operational state. No automated SOC intervention required."
            recommendations = [
                "Maintain baseline continuous network monitoring.",
                "Verify standard audit logging configuration.",
            ]
        else:
            threat_analysis = (
                f"The simulation reached {severity} severity with a deterministic threat score of {score}/100. "
                f"The attack sequence progressed across {len(events)} event(s), targeting host(s) "
                f"{', '.join([h['host'] for h in affected_hosts]) if affected_hosts else 'internal assets'}."
            )
            investigation_summary = (
                f"Investigated scenario '{state.get('scenario_id')}' with threat score {score} ({severity}). "
                f"Confirmed sequential threat indicators culminating in {events[-1].get('event_type')}."
            )

            # Defensive recommendations tailored to event types present
            event_types = set(e.get("event_type") for e in events if isinstance(e, dict))
            recs = []
            if "FAILED_LOGIN" in event_types or "SUCCESSFUL_LOGIN" in event_types or "SUSPICIOUS_LOGIN" in event_types:
                recs.append("Review simulated authentication logs and enforce multi-factor authentication policies.")
            if "PRIVILEGE_ESCALATION" in event_types:
                recs.append("Audit administrative privilege escalations and review sudoers configuration on target host.")
            if "SERVER_ACCESS" in event_types:
                recs.append("Restrict internal lateral network traffic protocols (SMB/RPC) between non-tier-0 servers.")
            if "SENSITIVE_FILE_ACCESS" in event_types:
                recs.append("Audit access control lists (ACLs) for sensitive simulated files and database tables.")
            if "MASS_FILE_MODIFICATION" in event_types:
                recs.append("Isolate affected simulated host from internal subnets and verify immutable backup integrity.")
            if "DATA_AGGREGATION" in event_types or "LARGE_OUTBOUND_TRANSFER" in event_types:
                recs.append("Inspect outbound egress bandwidth metrics and restrict unapproved protocol transfers.")

            recommendations = recs if recs else ["Preserve simulated event timeline for SOC post-incident review."]

    return {
        "threat_analysis": threat_analysis,
        "investigation_summary": investigation_summary,
        "affected_hosts": affected_hosts,
        "confidence": confidence,
        "recommendations": recommendations,
    }

def report_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    report_model = InvestigationReport(
        simulation_id=state.get("simulation_id", ""),
        scenario_id=state.get("scenario_id", ""),
        threat={
            "score": state.get("threat_score", 0),
            "severity": state.get("severity", "LOW"),
        },
        detection_summary=state.get("detection_summary", ""),
        correlations=[CorrelationItem(**c) for c in (state.get("correlations") or [])],
        attack_chain=[AttackChainItem(**a) for a in (state.get("attack_chain") or [])],
        affected_hosts=[AffectedHostItem(**h) for h in (state.get("affected_hosts") or [])],
        threat_analysis=state.get("threat_analysis", ""),
        investigation_summary=state.get("investigation_summary", ""),
        confidence=state.get("confidence", "LOW"),
        recommendations=state.get("recommendations") or [],
    )

    return {"final_report": report_model.model_dump()}

# Build LangGraph StateGraph
def create_investigator_graph():
    builder = StateGraph(SentinelInvestigationState)

    builder.add_node("detect", detect_node)
    builder.add_node("correlate", correlate_node)
    builder.add_node("analyze", analyze_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "detect")
    builder.add_edge("detect", "correlate")
    builder.add_edge("correlate", "analyze")
    builder.add_edge("analyze", "report")
    builder.add_edge("report", END)

    return builder.compile()

investigator_graph = create_investigator_graph()

def run_investigation(simulation_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the LangGraph investigation workflow for a given simulation state.
    Strictly read-only: does not modify simulation state or threat score.
    """
    sim = simulation_state.get("simulation") or {}
    events = simulation_state.get("events") or []
    hosts = simulation_state.get("hosts") or []
    threat = simulation_state.get("threat") or {}

    initial_state: SentinelInvestigationState = {
        "simulation_id": sim.get("id", ""),
        "scenario_id": sim.get("scenario_id", ""),
        "events": events,
        "hosts": hosts,
        "threat_score": threat.get("score", sim.get("threat_score", 0)),
        "severity": threat.get("severity", sim.get("severity", "LOW")),
        "detection_summary": None,
        "correlations": None,
        "attack_chain": None,
        "affected_hosts": None,
        "threat_analysis": None,
        "investigation_summary": None,
        "confidence": None,
        "recommendations": None,
        "final_report": None,
    }

    result = investigator_graph.invoke(initial_state)
    return result.get("final_report") or {}
