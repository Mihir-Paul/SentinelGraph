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
    ProposedAction,
    CriticResult,
    ResponseExecutionResult,
)
from backend.engine.threat_scorer import calculate_severity, EVENT_WEIGHTS, EVENT_REASONS
from api.ai.response_engine import validate_response_action, execute_commander_action, ALLOWED_ACTION_TYPES

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
    # Extended Response & Critic State
    planning_attempts: int
    response_plan: Optional[List[Dict[str, Any]]]
    critic_result: Optional[Dict[str, Any]]
    approved_actions: Optional[List[Dict[str, Any]]]
    executed_actions: Optional[List[Dict[str, Any]]]
    response_summary: Optional[str]
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
            matching_host = next((h for h in hosts if isinstance(h, dict) and (h.get("hostname") == thost or h.get("id") == thost)), None)
            role = matching_host.get("host_type", "Application Server") if matching_host else "Simulated Host"
            etype = evt.get("event_type", "")
            impact_desc = EVENT_REASONS.get(etype, f"Simulated {etype} activity observed.")
            affected_map[thost] = {
                "host": thost,
                "role": role,
                "impact": impact_desc,
            }

    affected_hosts = list(affected_map.values())

    if not events:
        confidence = "LOW"
    elif len(events) >= 4:
        confidence = "HIGH"
    else:
        confidence = "MEDIUM"

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

def response_planner_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    events = state.get("events", [])
    hosts = state.get("hosts", [])
    scenario_id = state.get("scenario_id", "")
    event_types = set(e.get("event_type") for e in events if isinstance(e, dict))

    target_hosts = set(e.get("target_host") for e in events if isinstance(e, dict) and e.get("target_host"))
    source_ips = set(e.get("source_ip") for e in events if isinstance(e, dict) and e.get("source_ip"))

    plan: List[Dict[str, Any]] = []
    idx = 1

    # Scenario & Event-specific response planning logic
    if "MASS_FILE_MODIFICATION" in event_types or scenario_id == "ransomware":
        for thost in target_hosts:
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "ISOLATE_HOST",
                "target": thost,
                "reason": f"Simulated host {thost} exhibits mass file modification consistent with ransomware encryption payload.",
                "priority": "HIGH",
                "status": "PROPOSED",
            })
            idx += 1
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "REVOKE_SIMULATED_SESSION",
                "target": thost,
                "reason": f"Revoke active unauthenticated sessions on compromised host {thost}.",
                "priority": "HIGH",
                "status": "PROPOSED",
            })
            idx += 1

        for src in source_ips:
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "BLOCK_SIMULATED_SOURCE",
                "target": src,
                "reason": f"Block synthetic attacker source IP {src} at simulated perimeter firewall.",
                "priority": "HIGH",
                "status": "PROPOSED",
            })
            idx += 1

    elif "LARGE_OUTBOUND_TRANSFER" in event_types or scenario_id == "data_exfiltration":
        for src in source_ips:
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "BLOCK_SIMULATED_SOURCE",
                "target": src,
                "reason": f"Terminate and block large outbound transfer stream to external IP {src}.",
                "priority": "HIGH",
                "status": "PROPOSED",
            })
            idx += 1

        for thost in target_hosts:
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "MARK_HOST_UNDER_INVESTIGATION",
                "target": thost,
                "reason": f"Flag database host {thost} for forensic investigation following data aggregation dump.",
                "priority": "MEDIUM",
                "status": "PROPOSED",
            })
            idx += 1

    elif "PRIVILEGE_ESCALATION" in event_types or scenario_id == "credential_compromise":
        for thost in target_hosts:
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "REVOKE_SIMULATED_SESSION",
                "target": thost,
                "reason": f"Terminate compromised user session on host {thost} following privilege escalation.",
                "priority": "HIGH",
                "status": "PROPOSED",
            })
            idx += 1
            plan.append({
                "action_id": f"act-{idx}",
                "action_type": "DISABLE_SIMULATED_ACCOUNT",
                "target": "admin",
                "reason": f"Disable simulated compromised account 'admin' pending credential reset.",
                "priority": "HIGH",
                "status": "PROPOSED",
            })
            idx += 1

    # Default baseline timeline preservation action
    plan.append({
        "action_id": f"act-{idx}",
        "action_type": "PRESERVE_EVENT_TIMELINE",
        "target": state.get("simulation_id", "simulation"),
        "reason": "Lock and preserve synthetic SOC forensic event log timeline.",
        "priority": "LOW",
        "status": "PROPOSED",
    })

    return {"response_plan": plan}

def critic_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    attempts = state.get("planning_attempts", 0) + 1
    plan = state.get("response_plan") or []

    approved: List[Dict[str, Any]] = []
    rejected_reasons: List[str] = []

    for action in plan:
        is_valid, err_msg = validate_response_action(action, state)
        if is_valid:
            act_copy = dict(action)
            act_copy["status"] = "APPROVED"
            approved.append(act_copy)
        else:
            rejected_reasons.append(f"{action.get('action_id')}: {err_msg}")

    is_fully_approved = (len(rejected_reasons) == 0)

    critic_res = {
        "approved": is_fully_approved,
        "reason": "All proposed actions passed deterministic safety audit." if is_fully_approved else "Some proposed actions failed safety audit.",
        "rejected_actions": rejected_reasons,
    }

    return {
        "planning_attempts": attempts,
        "approved_actions": approved,
        "critic_result": critic_res,
    }

def commander_node(state: SentinelInvestigationState) -> Dict[str, Any]:
    approved = state.get("approved_actions") or []
    sim_id = state.get("simulation_id", "")

    executed: List[Dict[str, Any]] = []
    for action in approved:
        res_action = execute_commander_action(action, sim_id)
        executed.append(res_action)

    summary = (
        f"Simulated response workflow executed successfully. "
        f"{len(executed)} action(s) approved by Critic and executed cleanly in simulation."
    )

    return {
        "executed_actions": executed,
        "response_summary": summary,
    }

def should_retry(state: SentinelInvestigationState) -> str:
    critic_res = state.get("critic_result") or {}
    attempts = state.get("planning_attempts", 0)

    if not critic_res.get("approved") and attempts < 2:
        logger.info("[LANGGRAPH] Critic rejected actions; retrying response planning (attempt %d/2)", attempts)
        return "response_planner"

    return "commander"

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

    response_model = None
    if state.get("executed_actions") is not None:
        response_model = ResponseExecutionResult(
            simulation_id=state.get("simulation_id", ""),
            scenario_id=state.get("scenario_id", ""),
            status="COMPLETED",
            proposed_actions=[ProposedAction(**a) for a in (state.get("response_plan") or [])],
            approved_actions=[ProposedAction(**a) for a in (state.get("approved_actions") or [])],
            executed_actions=[ProposedAction(**a) for a in (state.get("executed_actions") or [])],
            summary=state.get("response_summary", ""),
        )

    final_payload = {
        "simulation_id": state.get("simulation_id", ""),
        "scenario_id": state.get("scenario_id", ""),
        "threat": {
            "score": state.get("threat_score", 0),
            "severity": state.get("severity", "LOW"),
        },
        "investigation": report_model.model_dump(),
    }

    if response_model:
        final_payload["response"] = response_model.model_dump()

    return {"final_report": final_payload}

# Build LangGraph StateGraph
def create_investigator_graph():
    builder = StateGraph(SentinelInvestigationState)

    builder.add_node("detect", detect_node)
    builder.add_node("correlate", correlate_node)
    builder.add_node("analyze", analyze_node)
    builder.add_node("response_planner", response_planner_node)
    builder.add_node("critic", critic_node)
    builder.add_node("commander", commander_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "detect")
    builder.add_edge("detect", "correlate")
    builder.add_edge("correlate", "analyze")
    builder.add_edge("analyze", "response_planner")
    builder.add_edge("response_planner", "critic")

    builder.add_conditional_edges(
        "critic",
        should_retry,
        {
            "response_planner": "response_planner",
            "commander": "commander",
        }
    )

    builder.add_edge("commander", "report")
    builder.add_edge("report", END)

    return builder.compile()

investigator_graph = create_investigator_graph()

def _build_initial_state(simulation_state: Dict[str, Any]) -> SentinelInvestigationState:
    sim = simulation_state.get("simulation") or {}
    events = simulation_state.get("events") or []
    hosts = simulation_state.get("hosts") or []
    threat = simulation_state.get("threat") or {}

    return {
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
        "planning_attempts": 0,
        "response_plan": None,
        "critic_result": None,
        "approved_actions": None,
        "executed_actions": None,
        "response_summary": None,
        "final_report": None,
    }

def run_investigation(simulation_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the LangGraph investigation workflow for a given simulation state.
    Strictly read-only: does not modify simulation state or threat score.
    """
    initial_state = _build_initial_state(simulation_state)
    result = investigator_graph.invoke(initial_state)
    report = result.get("final_report") or {}
    return report.get("investigation") or {}

def run_response_workflow(simulation_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the full LangGraph investigation + defensive response + commander workflow.
    Score integrity preserved; updates fictional host status in simulation database if ISOLATE_HOST approved.
    """
    initial_state = _build_initial_state(simulation_state)
    result = investigator_graph.invoke(initial_state)
    return result.get("final_report") or {}
