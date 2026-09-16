import os, json, hmac, sqlite3
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

API_KEY=os.getenv("POWERBI_API_KEY","").strip()
DB_PATH=os.getenv("POWERBI_DB_PATH","powerbi.db")
app=FastAPI(title="NEXUS DANIP Power BI API",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=False,allow_methods=["GET","POST","OPTIONS"],allow_headers=["*"])
class PublishPayload(BaseModel):
    wide:list[Dict[str,Any]]=Field(default_factory=list)
    fact:list[Dict[str,Any]]=Field(default_factory=list)
    raw:list[Dict[str,Any]]=Field(default_factory=list)
    updated_at:str|None=None

def db():
    c=sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS datasets (dataset TEXT PRIMARY KEY,payload TEXT NOT NULL,updated_at TEXT NOT NULL)")
    c.commit(); return c

def auth(key): return bool(API_KEY and key and hmac.compare_digest(str(key),API_KEY))
def save(name,rows,updated):
    c=db()
    try:
        c.execute("INSERT INTO datasets(dataset,payload,updated_at) VALUES(?,?,?) ON CONFLICT(dataset) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at",(name,json.dumps(rows,ensure_ascii=False,default=str),updated)); c.commit()
    finally: c.close()
def load(name):
    c=db()
    try: row=c.execute("SELECT payload,updated_at FROM datasets WHERE dataset=?",(name,)).fetchone()
    finally: c.close()
    return (json.loads(row[0]),row[1]) if row else ([],None)
@app.get("/api/powerbi/health")
def health(): return {"status":"ok","service":"NEXUS DANIP Power BI API","timestamp":datetime.now(timezone.utc).isoformat()}
@app.post("/api/powerbi/publish")
def publish(payload:PublishPayload,x_api_key:str|None=Header(default=None)):
    if not auth(x_api_key): raise HTTPException(401,"Unauthorized — valid x-api-key required.")
    updated=payload.updated_at or datetime.now(timezone.utc).isoformat()
    save("wide",payload.wide,updated); save("fact",payload.fact,updated); save("raw",payload.raw,updated)
    return {"status":"success","updated_at":updated,"counts":{"wide":len(payload.wide),"fact":len(payload.fact),"raw":len(payload.raw)}}
def response(name,grain,key):
    if not auth(key): raise HTTPException(401,"Unauthorized — valid x-api-key required.")
    rows,updated=load(name); return {"status":"success","dataset":name,"grain":grain,"updated_at":updated,"data":rows}
@app.get("/api/powerbi/wide")
def wide(x_api_key:str|None=Header(default=None)): return response("wide","period × organisation",x_api_key)
@app.get("/api/powerbi/fact")
def fact(x_api_key:str|None=Header(default=None)): return response("fact","period × organisation × indicator",x_api_key)
@app.get("/api/powerbi/raw")
def raw(x_api_key:str|None=Header(default=None)): return response("raw","source record",x_api_key)
