import logging
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
from typing import Dict, Any

from api.simulator.engine import get_simulation_state
from api.ai.investigator import run_response_workflow

logger = logging.getLogger("sentinelgraph.api.response")

router = APIRouter(prefix="/api/response", tags=["response"])

class ResponseRunRequest(BaseModel):
    simulation_id: str

@router.post("/run")
def api_run_response(req: ResponseRunRequest):
    logger.info("[RESPONSE RUN] simulation_id=%s", req.simulation_id)
    if not req.simulation_id or not req.simulation_id.strip():
        raise HTTPException(status_code=400, detail="simulation_id is required")

    try:
        state = get_simulation_state(req.simulation_id)
        if not state.get("simulation"):
            raise HTTPException(status_code=404, detail=f"Simulation '{req.simulation_id}' not found.")

        result = run_response_workflow(state)

        # Refresh state to return updated host status after simulated Commander execution
        refreshed_state = get_simulation_state(req.simulation_id)
        if "response" in result and isinstance(result["response"], dict):
            result["hosts"] = refreshed_state.get("hosts", [])

        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("RESPONSE RUN FAILED simulation_id=%s", req.simulation_id)
        raise HTTPException(status_code=500, detail=f"Defensive response execution failed: {str(exc)}")
