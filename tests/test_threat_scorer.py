import pytest
from backend.engine.threat_scorer import (
    score_events,
    calculate_severity,
    EVENT_WEIGHTS,
    EVENT_REASONS,
)

def test_empty_event_list():
    res = score_events([])
    assert res["score"] == 0
    assert res["severity"] == "LOW"
    assert res["factors"] == []

def test_one_failed_login():
    res = score_events([{"event_type": "FAILED_LOGIN"}])
    assert res["score"] == 5
    assert res["severity"] == "LOW"
    assert len(res["factors"]) == 1
    assert res["factors"][0]["contribution"] == 5

def test_privilege_escalation_contribution():
    res = score_events([{"event_type": "PRIVILEGE_ESCALATION"}])
    assert res["score"] == 25
    assert res["factors"][0]["contribution"] == 25

def test_mass_file_modification_contribution():
    res = score_events([{"event_type": "MASS_FILE_MODIFICATION"}])
    assert res["score"] == 35
    assert res["factors"][0]["contribution"] == 35

def test_score_never_exceeds_100():
    events = [{"event_type": "MASS_FILE_MODIFICATION"}] * 5  # 5 * 35 = 175
    res = score_events(events)
    assert res["raw_score"] == 175
    assert res["score"] == 100
    assert res["severity"] == "CRITICAL"

def test_credential_compromise_score():
    events = [
        {"event_type": "FAILED_LOGIN"},
        {"event_type": "FAILED_LOGIN"},
        {"event_type": "FAILED_LOGIN"},
        {"event_type": "SUCCESSFUL_LOGIN"},
        {"event_type": "SUSPICIOUS_LOGIN_LOCATION"},
        {"event_type": "PRIVILEGE_CHANGE"},
        {"event_type": "SENSITIVE_RESOURCE_ACCESS"},
    ]
    res = score_events(events)
    # 5 + 5 + 5 + 10 + 15 + 25 + 20 = 85
    assert res["score"] == 85
    assert res["severity"] == "CRITICAL"

def test_ransomware_score():
    events = [
        {"event_type": "FAILED_LOGIN"},
        {"event_type": "FAILED_LOGIN"},
        {"event_type": "SUCCESSFUL_LOGIN"},
        {"event_type": "PRIVILEGE_ESCALATION"},
        {"event_type": "SERVER_ACCESS"},
        {"event_type": "SENSITIVE_FILE_ACCESS"},
        {"event_type": "MASS_FILE_MODIFICATION"},
    ]
    res = score_events(events)
    # 5 + 5 + 10 + 25 + 10 + 20 + 35 = 110 -> capped at 100
    assert res["raw_score"] == 110
    assert res["score"] == 100
    assert res["severity"] == "CRITICAL"

def test_data_exfiltration_score():
    events = [
        {"event_type": "SUSPICIOUS_LOGIN"},
        {"event_type": "SENSITIVE_FILE_ACCESS"},
        {"event_type": "DATA_AGGREGATION"},
        {"event_type": "LARGE_OUTBOUND_TRANSFER"},
    ]
    res = score_events(events)
    # 15 + 20 + 20 + 30 = 85
    assert res["score"] == 85
    assert res["severity"] == "CRITICAL"

def test_unknown_event_contribution():
    res = score_events([{"event_type": "UNKNOWN_ATTACK_VECTOR_99"}])
    assert res["score"] == 0
    assert res["factors"][0]["contribution"] == 0
    assert "registered" in res["factors"][0]["reason"].lower()

def test_severity_thresholds():
    assert calculate_severity(0) == "LOW"
    assert calculate_severity(30) == "LOW"
    assert calculate_severity(31) == "MEDIUM"
    assert calculate_severity(60) == "MEDIUM"
    assert calculate_severity(61) == "HIGH"
    assert calculate_severity(80) == "HIGH"
    assert calculate_severity(81) == "CRITICAL"
    assert calculate_severity(100) == "CRITICAL"
