import logging
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
from typing import Dict, Any

from api.simulator.engine import get_simulation_state
from api.ai.investigator import run_investigation

logger = logging.getLogger("sentinelgraph.api.investigation")

router = APIRouter(prefix="/api/investigation", tags=["investigation"])

class InvestigationRunRequest(BaseModel):
    simulation_id: str

@router.post("/run")
def api_run_investigation(req: InvestigationRunRequest):
    logger.info("[INVESTIGATION RUN] simulation_id=%s", req.simulation_id)
    if not req.simulation_id or not req.simulation_id.strip():
        raise HTTPException(status_code=400, detail="simulation_id is required")

    try:
        state = get_simulation_state(req.simulation_id)
        if not state.get("simulation"):
            raise HTTPException(status_code=404, detail=f"Simulation '{req.simulation_id}' not found.")

        investigation_result = run_investigation(state)

        return {
            "simulation_id": req.simulation_id,
            "scenario_id": state["simulation"].get("scenario_id", ""),
            "investigation": investigation_result,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("INVESTIGATION RUN FAILED simulation_id=%s", req.simulation_id)
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(exc)}")
