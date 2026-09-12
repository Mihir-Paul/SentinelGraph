import logging
import traceback
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from api.simulator.engine import (
    start_simulation,
    step_simulation,
    get_simulation_state,
    reset_simulation,
)
from api.simulator.scenarios import SCENARIOS

logger = logging.getLogger("sentinelgraph.api")
logging.basicConfig(level=logging.INFO)

router = APIRouter(prefix="/api/simulation", tags=["simulation"])

class SimulationStartRequest(BaseModel):
    scenario_id: str

class SimulationStepRequest(BaseModel):
    simulation_id: str

class SimulationResetRequest(BaseModel):
    simulation_id: str

@router.post("/start")
def api_start_simulation(req: SimulationStartRequest):
    logger.info("[SIMULATION START] scenario_id=%s", req.scenario_id)
    if req.scenario_id not in SCENARIOS:
        logger.warning("[SIMULATION] scenario_id=%s not in registry", req.scenario_id)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario_id: '{req.scenario_id}'. Allowed scenarios: {list(SCENARIOS.keys())}",
        )
    try:
        logger.info("[SIMULATION] validating scenario: %s", req.scenario_id)
        logger.info("[SIMULATION] loading scenario: %s", req.scenario_id)
        logger.info("[SIMULATION] creating simulation record")
        res = start_simulation(req.scenario_id)
        logger.info("[SIMULATION] returning response for scenario_id=%s", req.scenario_id)
        return res
    except Exception as exc:
        logger.exception("SIMULATION START FAILED scenario_id=%s", req.scenario_id)
        raise HTTPException(status_code=500, detail=f"Simulation start failed: {str(exc)}")

@router.post("/step")
def api_step_simulation(req: SimulationStepRequest):
    logger.info("[SIMULATION STEP] simulation_id=%s", req.simulation_id)
    try:
        result = step_simulation(req.simulation_id)
        return result
    except ValueError as ve:
        logger.warning("[SIMULATION STEP] 404: %s", ve)
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as exc:
        logger.exception("SIMULATION STEP FAILED simulation_id=%s", req.simulation_id)
        raise HTTPException(status_code=500, detail=f"Simulation step failed: {str(exc)}")

@router.get("/state")
def api_get_simulation_state(simulation_id: str = Query(..., description="The ID of the active simulation")):
    logger.info("[SIMULATION STATE] simulation_id=%s", simulation_id)
    try:
        state = get_simulation_state(simulation_id)
        if not state.get("simulation"):
            raise HTTPException(status_code=404, detail=f"Simulation '{simulation_id}' not found.")
        return state
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("SIMULATION STATE FAILED simulation_id=%s", simulation_id)
        raise HTTPException(status_code=500, detail=f"Simulation state retrieval failed: {str(exc)}")

@router.post("/reset")
def api_reset_simulation(req: SimulationResetRequest):
    logger.info("[SIMULATION RESET] simulation_id=%s", req.simulation_id)
    try:
        return reset_simulation(req.simulation_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as exc:
        logger.exception("SIMULATION RESET FAILED simulation_id=%s", req.simulation_id)
        raise HTTPException(status_code=500, detail=f"Simulation reset failed: {str(exc)}")
