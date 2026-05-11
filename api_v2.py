import json

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.v2_pipeline import run_v2_pipeline
from data_layer.database import init_db, save_analysis_run, save_raw_logs
from data_layer.event_format_adapter import get_ip_events
from data_layer.log_parser import parse_log_lines


app = FastAPI(title="AI Security Log Analyzer API V2")

init_db()


class AnalyzeV2Request(BaseModel):
    log: str


@app.get("/")
def root():
    return {"message": "AI Security Log Analyzer API V2 is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


def serialize_detection_report(report: dict) -> dict:
    return json.loads(json.dumps(report, default=str))


@app.post("/analyze-v2")
def analyze_v2(request: AnalyzeV2Request):
    if not request.log.strip():
        raise HTTPException(status_code=400, detail="log must not be empty")

    parsed_logs, _ = parse_log_lines(request.log.splitlines())
    run_id = save_analysis_run([], source="api-v2")
    save_raw_logs(run_id, parsed_logs)

    if not any(log.get("parse_status") == "parsed" for log in parsed_logs):
        raise HTTPException(status_code=400, detail="no supported log lines found")

    events_by_ip = get_ip_events(run_id)
    report = run_v2_pipeline(events_by_ip)

    return JSONResponse(content=serialize_detection_report(report))
