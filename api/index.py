from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SentinelGraph API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api")
def get_root():
    return {"message": "SentinelGraph API"}

@app.get("/api/health")
def get_health():
    return {"status": "ok", "service": "sentinelgraph-api"}
