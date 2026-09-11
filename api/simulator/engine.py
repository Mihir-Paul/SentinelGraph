import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from api.db.database import get_db
from api.simulator.scenarios import SCENARIOS, INITIAL_HOSTS

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

        # Create simulation record
        cursor.execute(
            """
            INSERT INTO simulations (id, scenario_id, status, current_tick, threat_score, severity, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (sim_id, scenario_id, "ACTIVE", 0, 0, "LOW", now, now) if hasattr(cursor, 'mogrify') or not isinstance(conn, type(get_db())) else None
        ) if False else None

        # Compatible query execution for both PostgreSQL and SQLite
        placeholders = "%s" if "postgresql" in str(type(conn)).lower() or "psycopg" in str(type(conn)).lower() else "?"
        
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

        # Apply state changes if specified
        if "host_state_change" in event_def:
            change = event_def["host_state_change"]
            cursor.execute(
                f"""
                UPDATE hosts SET status = {placeholders}, updated_at = {placeholders}
                WHERE id = {placeholders} AND simulation_id = {placeholders}
                """,
                (change["new_status"], now, change["host_id"], simulation_id)
            )

        # Update simulation current_tick
        cursor.execute(
            f"""
            UPDATE simulations SET current_tick = {placeholders}, updated_at = {placeholders}
            WHERE id = {placeholders}
            """,
            (next_tick, now, simulation_id)
        )

        conn.commit()
    finally:
        conn.close()

    updated_state = get_simulation_state(simulation_id)
    is_completed = (next_tick >= total_events)

    # Find the inserted event
    inserted_event = next((e for e in updated_state["events"] if e["id"] == evt_id), None)

    return {
        "completed": is_completed,
        "event": inserted_event,
        "simulation": updated_state["simulation"],
        "hosts": updated_state["hosts"],
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
            return {"simulation": None, "hosts": [], "events": []}

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

        return {
            "simulation": sim_dict,
            "hosts": hosts,
            "events": events,
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
