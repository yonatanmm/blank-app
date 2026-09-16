from fastapi import FastAPI, Header, HTTPException
from typing import Optional
import json
import os

app = FastAPI(title="NEXUS Power BI Wide API")

API_KEY = os.getenv("POWERBI_API_KEY", "")
WIDE_FILE = "data/wide.json"


def check_api_key(x_api_key: Optional[str]):
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="POWERBI_API_KEY is not configured"
        )

    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )


@app.get("/api/wide")
def get_wide(x_api_key: Optional[str] = Header(None)):

    check_api_key(x_api_key)

    if not os.path.exists(WIDE_FILE):
        return {
            "data": [],
            "count": 0,
            "message": "Wide dataset not published yet"
        }

    with open(WIDE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "data": data,
        "count": len(data)
    }
