import pytest
from fastapi.testclient import TestClient
from api.index import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "service": "sentinelgraph-api"}

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
    assert len(data["hosts"]) == 5

    # 2. Step through 7 events
    expected_types = [
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "SUCCESSFUL_LOGIN",
        "SUSPICIOUS_LOGIN_LOCATION",
        "PRIVILEGE_CHANGE",
        "SENSITIVE_RESOURCE_ACCESS",
    ]

    for idx, expected_event_type in enumerate(expected_types):
        step_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["event"]["event_type"] == expected_event_type
        assert step_data["simulation"]["current_tick"] == idx + 1
        if idx < 6:
            assert step_data["completed"] is False
        else:
            assert step_data["completed"] is True

    # 3. Step again when completed
    completed_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
    assert completed_res.status_code == 200
    assert completed_res.json()["completed"] is True

    # 4. Verify full state query
    state_res = client.get(f"/api/simulation/state?simulation_id={sim_id}")
    assert state_res.status_code == 200
    state_data = state_res.json()
    assert len(state_data["events"]) == 7

def test_ransomware_scenario_and_host_state_change():
    # 1. Start simulation
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    assert res.status_code == 200
    sim_id = res.json()["simulation"]["id"]

    expected_types = [
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "SUCCESSFUL_LOGIN",
        "PRIVILEGE_ESCALATION",
        "SERVER_ACCESS",
        "SENSITIVE_FILE_ACCESS",
        "MASS_FILE_MODIFICATION",
    ]

    for idx, expected_event_type in enumerate(expected_types):
        step_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["event"]["event_type"] == expected_event_type

    # Verify server-03 status changed to COMPROMISED after MASS_FILE_MODIFICATION
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
    assert len(reset_data["events"]) == 0
    server_03_reset = next(h for h in reset_data["hosts"] if h["id"] == "server-03")
    assert server_03_reset["status"] == "HEALTHY"

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

    for idx, expected_event_type in enumerate(expected_types):
        step_res = client.post("/api/simulation/step", json={"simulation_id": sim_id})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["event"]["event_type"] == expected_event_type

    # Verify event count = 4
    state_res = client.get(f"/api/simulation/state?simulation_id={sim_id}")
    assert state_res.status_code == 200
    assert len(state_res.json()["events"]) == 4
