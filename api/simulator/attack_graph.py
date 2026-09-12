from typing import Dict, Any, List
from api.simulator.engine import get_simulation_state

def get_attack_graph(simulation_id: str) -> Dict[str, Any]:
    """
    Deterministically constructs attack graph nodes and edges from simulation events & hosts.
    Derived 100% from actual event history.
    """
    state = get_simulation_state(simulation_id)
    if not state.get("simulation"):
        return {"nodes": [], "edges": []}

    events = state.get("events") or []
    hosts = state.get("hosts") or []

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    if not events:
        return {"nodes": [], "edges": []}

    # 1. Source Attacker Node
    source_ip = events[0].get("source_ip", "192.0.2.1")
    src_node_id = f"src-{source_ip}"
    nodes.append({
        "id": src_node_id,
        "type": "SOURCE",
        "label": f"Source: {source_ip}",
        "severity": "LOW",
        "details": {"source_ip": source_ip},
    })

    prev_node_id = src_node_id

    # 2. Sequential Security Event Nodes
    for i, evt in enumerate(events):
        evt_id = evt.get("id") or f"evt-{i}"
        etype = evt.get("event_type", "UNKNOWN")
        severity = evt.get("severity", "LOW")

        node_id = f"node-{evt_id}"
        nodes.append({
            "id": node_id,
            "type": "EVENT",
            "label": etype,
            "severity": severity,
            "details": {
                "timestamp": evt.get("timestamp"),
                "source_ip": evt.get("source_ip"),
                "target_host": evt.get("target_host"),
                "event_type": etype,
                "severity": severity,
                "details": evt.get("details", {}),
            },
        })

        rel = "GENERATED" if prev_node_id == src_node_id else "FOLLOWS"
        edges.append({
            "id": f"edge-{prev_node_id}-{node_id}",
            "source": prev_node_id,
            "target": node_id,
            "relationship": rel,
        })
        prev_node_id = node_id

    # 3. Target Host Node
    target_host_name = events[-1].get("target_host")
    host_node_id = f"host-{target_host_name}"
    if target_host_name:
        matching_host = next((h for h in hosts if h.get("hostname") == target_host_name or h.get("id") == target_host_name), None)
        host_status = matching_host.get("status", "HEALTHY") if matching_host else "UNKNOWN"

        nodes.append({
            "id": host_node_id,
            "type": "HOST",
            "label": f"Host: {target_host_name}",
            "severity": "CRITICAL" if host_status == "COMPROMISED" else "HIGH",
            "details": {
                "hostname": target_host_name,
                "status": host_status,
                "ip_address": matching_host.get("ip_address") if matching_host else "",
            },
        })

        edges.append({
            "id": f"edge-{prev_node_id}-{host_node_id}",
            "source": prev_node_id,
            "target": host_node_id,
            "relationship": "AFFECTS",
        })

    # 4. Impact Node
    last_event_type = events[-1].get("event_type", "")
    if last_event_type == "MASS_FILE_MODIFICATION":
        impact_id = "impact-ransomware"
        nodes.append({
            "id": impact_id,
            "type": "IMPACT",
            "label": "SIMULATED RANSOMWARE IMPACT",
            "severity": "CRITICAL",
            "details": {"description": "Mass file modification payload executed on target host."},
        })
        edges.append({
            "id": f"edge-{host_node_id}-{impact_id}",
            "source": host_node_id,
            "target": impact_id,
            "relationship": "RESULTED_IN",
        })
    elif last_event_type == "LARGE_OUTBOUND_TRANSFER":
        impact_id = "impact-exfiltration"
        nodes.append({
            "id": impact_id,
            "type": "IMPACT",
            "label": "SIMULATED DATA EXFILTRATION",
            "severity": "CRITICAL",
            "details": {"description": "Massive outbound data transfer completed to remote destination."},
        })
        edges.append({
            "id": f"edge-{host_node_id}-{impact_id}",
            "source": host_node_id,
            "target": impact_id,
            "relationship": "RESULTED_IN",
        })

    return {"nodes": nodes, "edges": edges}
