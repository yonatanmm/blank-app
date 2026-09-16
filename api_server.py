from fastapi import FastAPI

from api.fact import router as fact_router
from api.wide import router as wide_router
from api.raw import router as raw_router

app = FastAPI(
    title="NEXUS Power BI API",
    version="1.0.0"
)

app.include_router(fact_router)
app.include_router(wide_router)
app.include_router(raw_router)


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "NEXUS Power BI API",
        "endpoints": [
            "/api/powerbi/fact",
            "/api/powerbi/wide",
            "/api/powerbi/raw"
        ]
    }


@app.get("/api/powerbi/health")
def health():
    return {
        "status": "healthy"
    }
