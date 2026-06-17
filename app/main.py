import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from app.orchestrator import SOCPilotOrchestrator

# Ensure static directory exists
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app = FastAPI(title="SOC Co-Pilot POC", description="Multi-Agent Security Triage Orchestrator")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Log location
LOGS_PATH = "data/logs.json"

class QueryRequest(BaseModel):
    query: str

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze")
async def analyze_query(request_body: QueryRequest):
    orchestrator = SOCPilotOrchestrator(logs_path=LOGS_PATH)
    try:
        result = orchestrator.execute_flow(request_body.query)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to execute orchestrator flow: {str(e)}"}
        )

@app.get("/api/logs")
async def get_raw_logs():
    if not os.path.exists(LOGS_PATH):
        return JSONResponse(status_code=404, content={"error": "Log database not found."})
    try:
        with open(LOGS_PATH, "r") as f:
            logs = json.load(f)
        return JSONResponse(content=logs)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to read logs: {str(e)}"})
