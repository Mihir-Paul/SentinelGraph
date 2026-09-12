# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from api.index import app
from api.simulator.scenarios import SCENARIOS

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "service": "sentinelgraph-api"}

def test_all_scenario_ids_are_valid():
    expected_ids = {"credential_compromise", "ransomware", "data_exfiltration"}
    assert set(SCENARIOS.keys()) == expected_ids

def test_invalid_scenario():
    res = client.post("/api/simulation/start", json={"scenario_id": "invalid_scenario_xyz"})
    assert res.status_code == 400
    assert "Invalid scenario_id" in res.json()["detail"]

def test_invalid_simulation_id():
    res = client.post("/api/simulation/step", json={"simulation_id": "sim-non-existent"})
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

def test_credential_compromise_scenario():
    # 1. Start simulation
    res = client.post("/api/simulation/start", json={"scenario_id": "credential_compromise"})
    assert res.status_code == 200
    data = res.json()
    sim_id = data["simulation"]["id"]
    assert data["simulation"]["scenario_id"] == "credential_compromise"
    assert data["simulation"]["current_tick"] == 0
    assert data["simulation"]["threat_score"] == 0
    assert data["simulation"]["severity"] == "LOW"

    # 2. Step through 7 events
    expected_types = [
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "SUCCESSFUL_LOGIN",
        "SUSPICIOUS_LOGIN",
        "PRIVILEGE_ESCALATION",
        "SENSITIVE_FILE_ACCESS",
    ]

    for idx, expected_event_type in enumerate(expected_types):
        step_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["event"]["event_type"] == expected_event_type
        assert step_data["event"]["target_host"] == "server-01"
        assert step_data["event"]["source_ip"] == "192.0.2.42"
        assert step_data["simulation"]["current_tick"] == idx + 1

    # 3. Final state check: expected 85 / CRITICAL
    state_res = client.get(f"/api/simulation/state?simulation_id={sim_id}")
    assert state_res.status_code == 200
    state_data = state_res.json()
    assert state_data["simulation"]["threat_score"] == 85
    assert state_data["simulation"]["severity"] == "CRITICAL"
    assert state_data["threat"]["score"] == 85
    assert state_data["threat"]["severity"] == "CRITICAL"

def test_ransomware_scenario_step_by_step():
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    assert res.status_code == 200
    sim_id = res.json()["simulation"]["id"]

    # Expected progression:
    # Tick 1: FAILED_LOGIN (+5) -> 5 LOW
    # Tick 2: FAILED_LOGIN (+5) -> 10 LOW
    # Tick 3: SUCCESSFUL_LOGIN (+10) -> 20 LOW
    # Tick 4: PRIVILEGE_ESCALATION (+25) -> 45 MEDIUM
    # Tick 5: SERVER_ACCESS (+10) -> 55 MEDIUM
    # Tick 6: SENSITIVE_FILE_ACCESS (+20) -> 75 HIGH
    # Tick 7: MASS_FILE_MODIFICATION (+35) -> 100 CRITICAL
    expected_steps = [
        ("FAILED_LOGIN", 5, "LOW"),
        ("FAILED_LOGIN", 10, "LOW"),
        ("SUCCESSFUL_LOGIN", 20, "LOW"),
        ("PRIVILEGE_ESCALATION", 45, "MEDIUM"),
        ("SERVER_ACCESS", 55, "MEDIUM"),
        ("SENSITIVE_FILE_ACCESS", 75, "HIGH"),
        ("MASS_FILE_MODIFICATION", 100, "CRITICAL"),
    ]

    for expected_type, expected_score, expected_severity in expected_steps:
        step_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["event"]["event_type"] == expected_type
        assert step_data["event"]["target_host"] == "server-03"
        assert step_data["event"]["source_ip"] == "192.0.2.66"
        assert step_data["simulation"]["threat_score"] == expected_score
        assert step_data["simulation"]["severity"] == expected_severity
        assert step_data["threat"]["score"] == expected_score
        assert step_data["threat"]["severity"] == expected_severity

    # Verify server-03 status changed to COMPROMISED
    state_res = client.get(f"/api/simulation/state?simulation_id={sim_id}")
    assert state_res.status_code == 200
    hosts = state_res.json()["hosts"]
    server_03 = next(h for h in hosts if h["id"] == "server-03")
    assert server_03["status"] == "COMPROMISED"

    # Reset simulation
    reset_res = client.post("/api/simulation/reset", json={"simulation_id": sim_id})
    assert reset_res.status_code == 200
    reset_data = reset_res.json()
    assert reset_data["simulation"]["current_tick"] == 0
    assert reset_data["simulation"]["threat_score"] == 0
    assert reset_data["simulation"]["severity"] == "LOW"
    assert len(reset_data["events"]) == 0

def test_data_exfiltration_scenario():
    res = client.post("/api/simulation/start", json={"scenario_id": "data_exfiltration"})
    assert res.status_code == 200
    sim_id = res.json()["simulation"]["id"]

    expected_types = [
        "SUSPICIOUS_LOGIN",
        "SENSITIVE_FILE_ACCESS",
        "DATA_AGGREGATION",
        "LARGE_OUTBOUND_TRANSFER",
    ]

    for expected_type in expected_types:
        step_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["event"]["event_type"] == expected_type
        assert step_data["event"]["target_host"] == "database"
        assert step_data["event"]["source_ip"] == "192.0.2.99"

    # Verify final score: 15 + 20 + 20 + 30 = 85 -> CRITICAL
    state_res = client.get(f"/api/simulation/state?simulation_id={sim_id}")
    assert state_res.status_code == 200
    state_data = state_res.json()
    assert state_data["simulation"]["threat_score"] == 85
    assert state_data["simulation"]["severity"] == "CRITICAL"
    assert len(state_data["events"]) == 4

def test_repeated_state_retrieval_determinism():
    res = client.post("/api/simulation/start", json={"scenario_id": "data_exfiltration"})
    sim_id = res.json()["simulation"]["id"]

    client.post("/api/simulation/step", json={"simulation_id": sim_id})
    client.post("/api/simulation/step", json={"simulation_id": sim_id})

    # Retrieve state twice
    state1 = client.get(f"/api/simulation/state?simulation_id={sim_id}").json()
    state2 = client.get(f"/api/simulation/state?simulation_id={sim_id}").json()

    assert state1["simulation"]["threat_score"] == state2["simulation"]["threat_score"]
    assert state1["simulation"]["severity"] == state2["simulation"]["severity"]
    assert state1["threat"] == state2["threat"]
