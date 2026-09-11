import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from api.db.database import get_db
from api.simulator.scenarios import SCENARIOS, INITIAL_HOSTS
from api.engine.threat_scorer import score_events

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def start_simulation(scenario_id: str) -> Dict[str, Any]:
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Invalid scenario_id: '{scenario_id}'. Allowed: {list(SCENARIOS.keys())}")

    sim_id = f"sim-{uuid.uuid4().hex[:8]}"
    now = _utc_now_iso()

    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"

        # Create simulation record
        cursor.execute(
            f"""
            INSERT INTO simulations (id, scenario_id, status, current_tick, threat_score, severity, created_at, updated_at)
            VALUES ({placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders})
            """,
            (sim_id, scenario_id, "ACTIVE", 0, 0, "LOW", now, now)
        )

        # Initialize fictional hosts
        for host in INITIAL_HOSTS:
            cursor.execute(
                f"""
                INSERT INTO hosts (id, simulation_id, hostname, ip_address, host_type, status, criticality, updated_at)
                VALUES ({placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders})
                """,
                (
                    host["id"],
                    sim_id,
                    host["hostname"],
                    host["ip_address"],
                    host["host_type"],
                    host["status"],
                    host["criticality"],
                    now,
                )
            )

        conn.commit()
    finally:
        conn.close()

    return get_simulation_state(sim_id)

def step_simulation(simulation_id: str) -> Dict[str, Any]:
    state = get_simulation_state(simulation_id)
    if not state.get("simulation"):
        raise ValueError(f"Simulation not found: '{simulation_id}'")

    sim = state["simulation"]
    scenario_id = sim["scenario_id"]
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario ID '{scenario_id}' in simulation '{simulation_id}'")

    scenario = SCENARIOS[scenario_id]
    total_events = len(scenario["events"])
    current_tick = sim["current_tick"]

    if current_tick >= total_events:
        return {
            "completed": True,
            "simulation": sim,
            "hosts": state["hosts"],
            "events": state["events"],
            "threat": state["threat"],
        }

    next_tick = current_tick + 1
    event_def = scenario["events"][next_tick - 1]
    evt_id = f"evt-{uuid.uuid4().hex[:8]}"
    now = _utc_now_iso()

    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"

        # Insert security event
        cursor.execute(
            f"""
            INSERT INTO events (id, simulation_id, timestamp, source_ip, target_host, event_type, severity, details, created_at)
            VALUES ({placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders}, {placeholders})
            """,
            (
                evt_id,
                simulation_id,
                event_def["timestamp"],
                event_def["source_ip"],
                event_def["target_host"],
                event_def["event_type"],
                event_def["severity"],
                json.dumps(event_def["details"]),
                now,
            )
        )

        # Apply host state changes if specified
        if "host_state_change" in event_def:
            change = event_def["host_state_change"]
            cursor.execute(
                f"""
                UPDATE hosts SET status = {placeholders}, updated_at = {placeholders}
                WHERE id = {placeholders} AND simulation_id = {placeholders}
                """,
                (change["new_status"], now, change["host_id"], simulation_id)
            )

        conn.commit()
    finally:
        conn.close()

    # Re-evaluate all accumulated events for deterministic threat scoring
    updated_state = get_simulation_state(simulation_id)
    events_list = updated_state["events"]
    threat_res = score_events(events_list)

    # Persist updated threat score and severity to database
    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"
        cursor.execute(
            f"""
            UPDATE simulations SET current_tick = {placeholders}, threat_score = {placeholders}, severity = {placeholders}, updated_at = {placeholders}
            WHERE id = {placeholders}
            """,
            (next_tick, threat_res["score"], threat_res["severity"], now, simulation_id)
        )
        conn.commit()
    finally:
        conn.close()

    # Final state refresh
    final_state = get_simulation_state(simulation_id)
    is_completed = (next_tick >= total_events)

    inserted_event = next((e for e in final_state["events"] if e["id"] == evt_id), None)

    return {
        "completed": is_completed,
        "event": inserted_event,
        "simulation": final_state["simulation"],
        "hosts": final_state["hosts"],
        "threat": final_state["threat"],
    }

def get_simulation_state(simulation_id: str) -> Dict[str, Any]:
    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"

        # Query simulation
        cursor.execute(f"SELECT * FROM simulations WHERE id = {placeholders}", (simulation_id,))
        sim_row = cursor.fetchone()
        if not sim_row:
            return {"simulation": None, "hosts": [], "events": [], "threat": None}

        sim_dict = _row_to_dict(cursor, sim_row)

        # Query hosts
        cursor.execute(f"SELECT * FROM hosts WHERE simulation_id = {placeholders} ORDER BY id ASC", (simulation_id,))
        host_rows = cursor.fetchall()
        hosts = [_row_to_dict(cursor, r) for r in host_rows]

        # Query events
        cursor.execute(f"SELECT * FROM events WHERE simulation_id = {placeholders} ORDER BY created_at ASC", (simulation_id,))
        event_rows = cursor.fetchall()
        events = []
        for r in event_rows:
            d = _row_to_dict(cursor, r)
            if isinstance(d.get("details"), str):
                try:
                    d["details"] = json.loads(d["details"])
                except Exception:
                    pass
            events.append(d)

        # Calculate threat score deterministically from accumulated events
        threat_res = score_events(events)

        # Keep simulation dictionary in sync with calculated score and severity
        sim_dict["threat_score"] = threat_res["score"]
        sim_dict["severity"] = threat_res["severity"]

        return {
            "simulation": sim_dict,
            "hosts": hosts,
            "events": events,
            "threat": threat_res,
        }
    finally:
        conn.close()

def reset_simulation(simulation_id: str) -> Dict[str, Any]:
    state = get_simulation_state(simulation_id)
    if not state.get("simulation"):
        raise ValueError(f"Simulation not found: '{simulation_id}'")

    now = _utc_now_iso()
    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"

        # Reset simulation values
        cursor.execute(
            f"""
            UPDATE simulations SET current_tick = 0, status = 'ACTIVE', threat_score = 0, severity = 'LOW', updated_at = {placeholders}
            WHERE id = {placeholders}
            """,
            (now, simulation_id)
        )

        # Reset hosts to HEALTHY
        cursor.execute(
            f"""
            UPDATE hosts SET status = 'HEALTHY', updated_at = {placeholders}
            WHERE simulation_id = {placeholders}
            """,
            (now, simulation_id)
        )

        # Clear events
        cursor.execute(
            f"DELETE FROM events WHERE simulation_id = {placeholders}",
            (simulation_id,)
        )

        conn.commit()
    finally:
        conn.close()

    return get_simulation_state(simulation_id)

def _row_to_dict(cursor, row) -> Dict[str, Any]:
    if isinstance(row, dict):
        return row
    if hasattr(row, "_asdict"):
        return row._asdict()
    if hasattr(cursor, "description") and cursor.description:
        colnames = [desc[0] for desc in cursor.description]
        return dict(zip(colnames, row))
    return dict(row)
