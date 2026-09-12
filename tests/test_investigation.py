import pytest
from fastapi.testclient import TestClient
from api.index import app
from api.ai.investigator import investigator_graph, run_investigation, create_investigator_graph
from api.ai.schemas import InvestigationReport
from api.simulator.scenarios import SCENARIOS

client = TestClient(app, raise_server_exceptions=False)

def test_graph_construction():
    graph = create_investigator_graph()
    assert graph is not None

def test_empty_events():
    state = {
        "simulation": {"id": "sim-empty", "scenario_id": "test_empty"},
        "events": [],
        "hosts": [],
        "threat": {"score": 0, "severity": "LOW"},
    }
    report = run_investigation(state)
    assert report["threat"]["score"] == 0
    assert report["threat"]["severity"] == "LOW"
    assert "No security events detected" in report["detection_summary"]
    assert report["confidence"] == "LOW"

def test_single_failed_login_hallucination_check():
    state = {
        "simulation": {"id": "sim-single", "scenario_id": "test_single"},
        "events": [
            {
                "tick": 1,
                "timestamp": "10:00:00",
                "event_type": "FAILED_LOGIN",
                "severity": "LOW",
                "target_host": "server-01",
                "source_ip": "192.0.2.1",
                "details": {"username": "admin"},
            }
        ],
        "hosts": [{"id": "server-01", "hostname": "server-01", "host_type": "APP"}],
        "threat": {"score": 5, "severity": "LOW"},
    }
    report = run_investigation(state)

    # Validate output structure against Pydantic schema
    validated = InvestigationReport(**report)

    # Verify score integrity
    assert validated.threat["score"] == 5
    assert validated.threat["severity"] == "LOW"

    # Hallucination check: ensure no false claims of escalation or encryption
    full_text = (validated.detection_summary + " " + validated.threat_analysis + " " + validated.investigation_summary).lower()
    assert "privilege escalation" not in full_text
    assert "ransomware" not in full_text
    assert "mass file modification" not in full_text
    assert "exfiltration" not in full_text

def test_ransomware_investigation_input():
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    sim_id = res.json()["simulation"]["id"]

    # Step simulation to accumulate events
    for _ in range(7):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    # Run AI investigation
    inv_res = client.post("/api/investigation/run", json={"simulation_id": sim_id})
    assert inv_res.status_code == 200

    data = inv_res.json()
    assert data["simulation_id"] == sim_id
    assert data["scenario_id"] == "ransomware"

    inv = data["investigation"]
    assert inv["threat"]["score"] == 100
    assert inv["threat"]["severity"] == "CRITICAL"
    assert len(inv["correlations"]) > 0
    assert len(inv["attack_chain"]) > 0

    # Ensure affected host is server-03
    affected_host_names = [h["host"] for h in inv["affected_hosts"]]
    assert "server-03" in affected_host_names

def test_credential_compromise_investigation_input():
    res = client.post("/api/simulation/start", json={"scenario_id": "credential_compromise"})
    sim_id = res.json()["simulation"]["id"]

    for _ in range(7):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    inv_res = client.post("/api/investigation/run", json={"simulation_id": sim_id})
    assert inv_res.status_code == 200

    data = inv_res.json()
    inv = data["investigation"]
    assert inv["threat"]["score"] == 85
    assert inv["threat"]["severity"] == "CRITICAL"

    # Must NOT mention mass file modification / ransomware
    full_text = json.dumps(inv).lower()
    assert "mass_file_modification" not in full_text
    assert "ransomware" not in full_text

def test_data_exfiltration_investigation_input():
    res = client.post("/api/simulation/start", json={"scenario_id": "data_exfiltration"})
    sim_id = res.json()["simulation"]["id"]

    for _ in range(4):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    inv_res = client.post("/api/investigation/run", json={"simulation_id": sim_id})
    assert inv_res.status_code == 200

    data = inv_res.json()
    inv = data["investigation"]
    assert inv["threat"]["score"] == 85
    assert inv["threat"]["severity"] == "CRITICAL"

    # Must NOT mention ransomware or mass file modification
    full_text = json.dumps(inv).lower()
    assert "mass_file_modification" not in full_text
    assert "ransomware" not in full_text

def test_score_integrity():
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    sim_id = res.json()["simulation"]["id"]

    client.post("/api/simulation/step", json={"simulation_id": sim_id})
    client.post("/api/simulation/step", json={"simulation_id": sim_id})

    # Fetch state before investigation
    state_before = client.get(f"/api/simulation/state?simulation_id={sim_id}").json()
    score_before = state_before["simulation"]["threat_score"]

    # Run AI investigation
    inv_res = client.post("/api/investigation/run", json={"simulation_id": sim_id})
    assert inv_res.status_code == 200

    # Fetch state after investigation
    state_after = client.get(f"/api/simulation/state?simulation_id={sim_id}").json()
    score_after = state_after["simulation"]["threat_score"]

    # Score MUST remain unchanged
    assert score_before == score_after

def test_invalid_simulation_id():
    res = client.post("/api/investigation/run", json={"simulation_id": "sim-non-existent-xyz"})
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()
