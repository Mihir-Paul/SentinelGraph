import pytest
import inspect
from fastapi.testclient import TestClient
from api.index import app
from api.ai.response_engine import validate_response_action, ALLOWED_ACTION_TYPES, execute_commander_action
from api.simulator.engine import get_simulation_state
from api.simulator.attack_graph import get_attack_graph

client = TestClient(app, raise_server_exceptions=False)

def test_response_action_allowlist():
    assert "ISOLATE_HOST" in ALLOWED_ACTION_TYPES
    assert "REVOKE_SIMULATED_SESSION" in ALLOWED_ACTION_TYPES
    assert "DISABLE_SIMULATED_ACCOUNT" in ALLOWED_ACTION_TYPES
    assert "BLOCK_SIMULATED_SOURCE" in ALLOWED_ACTION_TYPES
    assert "PRESERVE_EVENT_TIMELINE" in ALLOWED_ACTION_TYPES
    assert "MARK_HOST_UNDER_INVESTIGATION" in ALLOWED_ACTION_TYPES

def test_invalid_action_rejection():
    mock_state = {
        "hosts": [{"id": "server-01", "hostname": "server-01"}],
        "events": [{"source_ip": "192.0.2.42"}],
    }

    # Unknown action type
    valid, msg = validate_response_action({"action_type": "HACK_DATABASE", "target": "server-01"}, mock_state)
    assert not valid
    assert "not permitted" in msg

    # Unknown target host
    valid, msg = validate_response_action({"action_type": "ISOLATE_HOST", "target": "unknown-server-999"}, mock_state)
    assert not valid
    assert "not present" in msg

    # Shell command injection attempt
    valid, msg = validate_response_action({
        "action_type": "ISOLATE_HOST",
        "target": "server-01",
        "command": "sudo rm -rf /"
    }, mock_state)
    assert not valid
    assert "prohibited system string" in msg

    # Arbitrary URL attempt
    valid, msg = validate_response_action({
        "action_type": "ISOLATE_HOST",
        "target": "server-01",
        "url": "https://malicious.example.com/payload"
    }, mock_state)
    assert not valid
    assert "prohibited system string" in msg

def test_simulated_isolation_execution():
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    sim_id = res.json()["simulation"]["id"]

    # Execute simulated isolate host via commander
    execute_commander_action({"action_type": "ISOLATE_HOST", "target": "server-03"}, sim_id)

    # Check updated host status in simulation database
    state = get_simulation_state(sim_id)
    s03 = next((h for h in state["hosts"] if h["hostname"] == "server-03"), None)
    assert s03 is not None
    assert s03["status"] == "ISOLATED"

def test_ransomware_end_to_end_response():
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    sim_id = res.json()["simulation"]["id"]

    for _ in range(7):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    # Run AI Defensive Response endpoint
    resp_res = client.post("/api/response/run", json={"simulation_id": sim_id})
    assert resp_res.status_code == 200

    data = resp_res.json()
    assert data["response"]["status"] == "COMPLETED"
    assert len(data["response"]["executed_actions"]) > 0

    executed_types = [a["action_type"] for a in data["response"]["executed_actions"]]
    assert "ISOLATE_HOST" in executed_types

    # Verify server-03 is now ISOLATED
    state_after = client.get(f"/api/simulation/state?simulation_id={sim_id}").json()
    s03 = next((h for h in state_after["hosts"] if h["hostname"] == "server-03"), None)
    assert s03["status"] == "ISOLATED"
    assert state_after["simulation"]["threat_score"] == 100  # Score integrity preserved

def test_credential_compromise_response():
    res = client.post("/api/simulation/start", json={"scenario_id": "credential_compromise"})
    sim_id = res.json()["simulation"]["id"]

    for _ in range(7):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    resp_res = client.post("/api/response/run", json={"simulation_id": sim_id})
    assert resp_res.status_code == 200

    data = resp_res.json()
    executed_types = [a["action_type"] for a in data["response"]["executed_actions"]]
    assert "REVOKE_SIMULATED_SESSION" in executed_types
    assert "DISABLE_SIMULATED_ACCOUNT" in executed_types

    # Ensure server-03 was NOT isolated for credential compromise
    state_after = client.get(f"/api/simulation/state?simulation_id={sim_id}").json()
    s03 = next((h for h in state_after["hosts"] if h["hostname"] == "server-03"), None)
    assert s03["status"] == "HEALTHY"

def test_data_exfiltration_response():
    res = client.post("/api/simulation/start", json={"scenario_id": "data_exfiltration"})
    sim_id = res.json()["simulation"]["id"]

    for _ in range(4):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    resp_res = client.post("/api/response/run", json={"simulation_id": sim_id})
    assert resp_res.status_code == 200

    data = resp_res.json()
    executed_types = [a["action_type"] for a in data["response"]["executed_actions"]]
    assert "BLOCK_SIMULATED_SOURCE" in executed_types or "MARK_HOST_UNDER_INVESTIGATION" in executed_types

def test_attack_graph_generation():
    res = client.post("/api/simulation/start", json={"scenario_id": "ransomware"})
    sim_id = res.json()["simulation"]["id"]

    for _ in range(7):
        client.post("/api/simulation/step", json={"simulation_id": sim_id})

    graph_res = client.get(f"/api/simulation/attack-graph?simulation_id={sim_id}")
    assert graph_res.status_code == 200

    graph = graph_res.json()
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0

    labels = [n["label"] for n in graph["nodes"]]
    assert any("Source: 192.0.2.66" in l for l in labels)
    assert "MASS_FILE_MODIFICATION" in labels
    assert "SIMULATED RANSOMWARE IMPACT" in labels

def test_no_real_system_calls():
    import api.ai.response_engine as re_mod
    import api.ai.investigator as inv_mod

    re_code = inspect.getsource(re_mod)
    inv_code = inspect.getsource(inv_mod)

    prohibited_calls = ["import subprocess", "os.system(", "shell=True", "socket.connect("]
    for term in prohibited_calls:
        assert term not in re_code, f"Forbidden system call '{term}' found in response_engine.py"
        assert term not in inv_code, f"Forbidden system call '{term}' found in investigator.py"
