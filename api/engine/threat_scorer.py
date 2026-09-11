from typing import List, Dict, Any

# Configurable event scoring weights
EVENT_WEIGHTS: Dict[str, int] = {
    "FAILED_LOGIN": 5,
    "SUCCESSFUL_LOGIN": 10,
    "SUSPICIOUS_LOGIN": 15,
    "SUSPICIOUS_LOGIN_LOCATION": 15,
    "PRIVILEGE_ESCALATION": 25,
    "PRIVILEGE_CHANGE": 25,
    "SENSITIVE_FILE_ACCESS": 20,
    "SENSITIVE_RESOURCE_ACCESS": 20,
    "SERVER_ACCESS": 10,
    "MASS_FILE_MODIFICATION": 35,
    "DATA_AGGREGATION": 20,
    "LARGE_OUTBOUND_TRANSFER": 30,
}

# Defensive SOC explanations for contributing factors
EVENT_REASONS: Dict[str, str] = {
    "FAILED_LOGIN": "Failed authentication attempt detected on target host.",
    "SUCCESSFUL_LOGIN": "Successful login following prior failed attempts or suspicious activity.",
    "SUSPICIOUS_LOGIN": "Anomalous login detected from untrusted location or off-hours window.",
    "SUSPICIOUS_LOGIN_LOCATION": "Anomalous login detected from untrusted geographic location or Tor exit node.",
    "PRIVILEGE_ESCALATION": "Privilege escalation detected; attacker obtained elevated administrative access.",
    "PRIVILEGE_CHANGE": "Administrative privilege change executed; user added to privileged group.",
    "SENSITIVE_FILE_ACCESS": "Unauthorized access to sensitive system files or database records.",
    "SENSITIVE_RESOURCE_ACCESS": "Access to restricted system resource (/etc/shadow) detected.",
    "SERVER_ACCESS": "Lateral server access via internal network protocols (SMB/RPC).",
    "MASS_FILE_MODIFICATION": "Rapid mass file modification detected; indicative of active ransomware encryption payload.",
    "DATA_AGGREGATION": "Staging and compression of sensitive data files into temporary archive.",
    "LARGE_OUTBOUND_TRANSFER": "Unusually large data exfiltration stream to external IP address.",
}

def calculate_severity(score: int) -> str:
    """
    Determines threat severity from numerical score (0-100).
    0-30   = LOW
    31-60  = MEDIUM
    61-80  = HIGH
    81-100 = CRITICAL
    """
    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"

def score_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates threat score (0-100), severity, and explainable factors
    deterministically from a list of security events.
    """
    total_raw_score = 0
    factors: List[Dict[str, Any]] = []

    for evt in events:
        event_type = evt.get("event_type", "")
        weight = EVENT_WEIGHTS.get(event_type, 0)
        reason = EVENT_REASONS.get(event_type, f"Event {event_type} registered.")

        factors.append({
            "event_type": event_type,
            "contribution": weight,
            "reason": reason,
        })

        total_raw_score += weight

    final_score = min(total_raw_score, 100)
    severity = calculate_severity(final_score)

    return {
        "score": final_score,
        "raw_score": total_raw_score,
        "severity": severity,
        "factors": factors,
    }
