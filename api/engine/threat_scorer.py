"""
Re-export threat scoring functionality from backend.engine.threat_scorer
for Vercel serverless / API module compatibility.
"""
from backend.engine.threat_scorer import (
    EVENT_WEIGHTS,
    EVENT_REASONS,
    calculate_severity,
    score_events,
)

__all__ = [
    "EVENT_WEIGHTS",
    "EVENT_REASONS",
    "calculate_severity",
    "score_events",
]
