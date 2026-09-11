import traceback
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from api.simulator.engine import (
    start_simulation,
    step_simulation,
    get_simulation_state,
    reset_simulation,
)
from api.simulator.scenarios import SCENARIOS

router = APIRouter(prefix="/api/simulation", tags=["simulation"])

class SimulationStartRequest(BaseModel):
    scenario_id: str

class SimulationStepRequest(BaseModel):
    simulation_id: str

class SimulationResetRequest(BaseModel):
    simulation_id: str

@router.post("/start")
def api_start_simulation(req: SimulationStartRequest):
    if req.scenario_id not in SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario_id: '{req.scenario_id}'. Allowed scenarios: {list(SCENARIOS.keys())}",
        )
    try:
        return start_simulation(req.scenario_id)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Simulation start failed: {str(e)}")

@router.post("/step")
def api_step_simulation(req: SimulationStepRequest):
    try:
        result = step_simulation(req.simulation_id)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Simulation step failed: {str(e)}")

@router.get("/state")
def api_get_simulation_state(simulation_id: str = Query(..., description="The ID of the active simulation")):
    try:
        state = get_simulation_state(simulation_id)
        if not state.get("simulation"):
            raise HTTPException(status_code=404, detail=f"Simulation '{simulation_id}' not found.")
        return state
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Simulation state retrieval failed: {str(e)}")

@router.post("/reset")
def api_reset_simulation(req: SimulationResetRequest):
    try:
        return reset_simulation(req.simulation_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Simulation reset failed: {str(e)}")
