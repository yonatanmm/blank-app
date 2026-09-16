import json
import os
import secrets
import hmac
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

APP_NAME = "NEXUS DANIP Power BI API"
API_KEY = os.getenv("POWERBI_API_KEY", "").strip()
AUTO_GENERATE = os.getenv("POWERBI_AUTO_GENERATE_API_KEY", "true").strip().lower() in {"1", "true", "yes", "on"}

if not API_KEY and AUTO_GENERATE:
    API_KEY = "nexus_pbi_" + secrets.token_urlsafe(32)
    print("============================================================")
    print("NEXUS POWER BI API KEY (SAVE THIS IN YOUR DEPLOYMENT SECRETS)")
    print(API_KEY)
    print("============================================================")

if not API_KEY:
    raise RuntimeError("POWERBI_API_KEY is not configured and auto-generation is disabled.")

DATA_DIR = Path(os.getenv("POWERBI_DATA_DIR", "./powerbi_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "datasets.json"
LOCK = Lock()

def _empty_store():
    return {"wide": [], "fact": [], "raw": [], "updated_at": None}

def _load_store():
    if not DATA_FILE.exists():
        return _empty_store()
    try:
        with DATA_FILE.open("r", encoding="utf-8") as f:
            value = json.load(f)
        if not isinstance(value, dict):
            return _empty_store()
        store = _empty_store()
        store.update({k: value.get(k, store[k]) for k in store})
        return store
    except Exception:
        return _empty_store()

STORE = _load_store()

def _save_store():
    tmp = DATA_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(STORE, f, ensure_ascii=False, separators=(",", ":"))
    tmp.replace(DATA_FILE)

def _authorized(supplied: str | None) -> bool:
    return bool(supplied and API_KEY and hmac.compare_digest(str(supplied).strip(), API_KEY))

def require_key(x_api_key: str | None):
    if not _authorized(x_api_key):
        raise HTTPException(status_code=401, detail="Unauthorized — valid x-api-key required.")

app = FastAPI(title=APP_NAME, version="1.0.0")

@app.get("/")
def root():
    return {"service": APP_NAME, "status": "ok", "endpoints": [
        "/api/powerbi/health", "/api/powerbi/wide", "/api/powerbi/fact",
        "/api/powerbi/raw", "/api/powerbi/publish"
    ]}

@app.get("/api/powerbi/health")
def health():
    return {"status": "ok", "service": APP_NAME, "updated_at": STORE.get("updated_at")}

@app.get("/api/powerbi/wide")
def wide(x_api_key: str | None = Header(default=None, alias="x-api-key")):
    require_key(x_api_key)
    return {"status": "success", "dataset": "wide", "grain": "period × organisation",
            "updated_at": STORE.get("updated_at"), "data": STORE.get("wide", [])}

@app.get("/api/powerbi/fact")
def fact(x_api_key: str | None = Header(default=None, alias="x-api-key")):
    require_key(x_api_key)
    return {"status": "success", "dataset": "fact",
            "grain": "period × organisation × indicator",
            "updated_at": STORE.get("updated_at"), "data": STORE.get("fact", [])}

@app.get("/api/powerbi/raw")
def raw(x_api_key: str | None = Header(default=None, alias="x-api-key")):
    require_key(x_api_key)
    return {"status": "success", "dataset": "raw", "grain": "source record",
            "updated_at": STORE.get("updated_at"), "data": STORE.get("raw", [])}

@app.post("/api/powerbi/publish")
async def publish(request: Request, x_api_key: str | None = Header(default=None, alias="x-api-key")):
    require_key(x_api_key)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid publish payload.")

    with LOCK:
        STORE["wide"] = payload.get("wide", []) if isinstance(payload.get("wide", []), list) else []
        STORE["fact"] = payload.get("fact", []) if isinstance(payload.get("fact", []), list) else []
        STORE["raw"] = payload.get("raw", []) if isinstance(payload.get("raw", []), list) else []
        STORE["updated_at"] = payload.get("updated_at") or datetime.now(timezone.utc).isoformat()
        _save_store()

    return {"status": "success", "message": "Power BI datasets published.",
            "wide_rows": len(STORE["wide"]), "fact_rows": len(STORE["fact"]),
            "raw_rows": len(STORE["raw"]), "updated_at": STORE["updated_at"]}

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"status": "error", "message": "Endpoint not found."})
