import json
import logging
from typing import Dict, Any, List, Tuple
from api.db.database import get_db

logger = logging.getLogger("sentinelgraph.response_engine")

ALLOWED_ACTION_TYPES = {
    "ISOLATE_HOST",
    "REVOKE_SIMULATED_SESSION",
    "DISABLE_SIMULATED_ACCOUNT",
    "BLOCK_SIMULATED_SOURCE",
    "PRESERVE_EVENT_TIMELINE",
    "MARK_HOST_UNDER_INVESTIGATION",
}

PROHIBITED_PATTERNS = [
    "rm ", "sudo", "exec", "system", "shell", "bash", "powershell",
    "http://", "https://", "curl", "wget", "chmod", "kill ", "format",
    "drop ", "delete ", "truncate", "iptables", "netsh"
]

def validate_response_action(action: Dict[str, Any], state: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Deterministic Python safety guard.
    Strictly validates proposed simulation response actions against allowlist and simulation targets.
    Prohibits shell instructions, arbitrary code, URLs, and unknown targets.
    """
    if not isinstance(action, dict):
        return False, "Action is not a valid dictionary object."

    atype = action.get("action_type")
    if atype not in ALLOWED_ACTION_TYPES:
        return False, f"Action type '{atype}' is not permitted by simulation safety policy."

    target = action.get("target")
    if not target or not isinstance(target, str):
        return False, "Action target is missing or invalid."

    # Extract valid hosts and IPs from simulation state
    hosts = state.get("hosts") or []
    events = state.get("events") or []

    valid_host_names = set(h.get("hostname") for h in hosts if isinstance(h, dict) and h.get("hostname"))
    valid_host_ids = set(h.get("id") for h in hosts if isinstance(h, dict) and h.get("id"))
    valid_hosts = valid_host_names.union(valid_host_ids)

    valid_sources = set(e.get("source_ip") for e in events if isinstance(e, dict) and e.get("source_ip"))

    # Target-specific validation
    if atype in ("ISOLATE_HOST", "MARK_HOST_UNDER_INVESTIGATION"):
        if target not in valid_hosts:
            return False, f"Target host '{target}' is not present in active simulation host inventory."
    elif atype == "BLOCK_SIMULATED_SOURCE":
        if target not in valid_sources and target not in valid_hosts:
            return False, f"Target '{target}' is not a recognized simulated source IP or host."

    # Prohibited pattern audit
    action_repr = json.dumps(action).lower()
    for pattern in PROHIBITED_PATTERNS:
        if pattern in action_repr:
            return False, f"Action contains prohibited system string pattern '{pattern}'."

    return True, "Action passed deterministic safety guard audit."

def execute_commander_action(action: Dict[str, Any], simulation_id: str) -> Dict[str, Any]:
    """
    Commander Node execution:
    Executes approved actions purely within FICTIONAL simulation database/state.
    No system execution, no external calls.
    """
    atype = action.get("action_type")
    target = action.get("target", "")

    executed_action = dict(action)
    executed_action["status"] = "EXECUTED"

    if atype == "ISOLATE_HOST":
        conn = get_db()
        try:
            cursor = conn.cursor()
            placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"
            cursor.execute(
                f"""
                UPDATE hosts SET status = 'ISOLATED'
                WHERE (id = {placeholders} OR hostname = {placeholders}) AND simulation_id = {placeholders}
                """,
                (target, target, simulation_id)
            )
            conn.commit()
            logger.info("[COMMANDER] Isolated host %s in simulation %s", target, simulation_id)
        finally:
            conn.close()
    elif atype == "MARK_HOST_UNDER_INVESTIGATION":
        conn = get_db()
        try:
            cursor = conn.cursor()
            placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"
            cursor.execute(
                f"""
                UPDATE hosts SET status = 'SUSPICIOUS'
                WHERE (id = {placeholders} OR hostname = {placeholders}) AND simulation_id = {placeholders} AND status != 'ISOLATED'
                """,
                (target, target, simulation_id)
            )
            conn.commit()
            logger.info("[COMMANDER] Marked host %s under investigation in simulation %s", target, simulation_id)
        finally:
            conn.close()
    else:
        logger.info("[COMMANDER] Simulated response %s executed on target %s", atype, target)

    return executed_action
