# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
from api.routers.simulation import router as simulation_router
from api.routers.investigation import router as investigation_router

app = FastAPI(title="SentinelGraph API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(simulation_router)
app.include_router(investigation_router)

@app.get("/api")
def get_root():
    return {"message": "SentinelGraph API"}

@app.get("/api/health")
def get_health():
    return {"status": "ok", "service": "sentinelgraph-api"}
