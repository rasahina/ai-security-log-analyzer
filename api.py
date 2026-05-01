from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json
import os
from database import (
    init_db,
    save_analysis_run,
    get_analysis_runs,
    get_detections_by_run,
    save_raw_logs,
    update_analysis_run_summary,
)

from analyzer import analyze_run_from_db
from parsers.log_parser import parse_log_lines

app = FastAPI(title="AI Security Log Analyzer API")

#データベース初期化
init_db()


RESULT_FILE = "output/result.json"


class AnalyzeRequest(BaseModel):
    log: str

def parse_logs_for_analysis(lines):
    parsed_logs, skipped_logs = parse_log_lines(lines)

    return {
        "raw_logs": parsed_logs,
        "skipped_logs": skipped_logs,
    }

@app.get("/")
def root():
    return {"message": "AI Security Log Analyzer API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/results")
def get_results():
    if not os.path.exists(RESULT_FILE):
        raise HTTPException(status_code=404, detail="result.json not found")

    with open(RESULT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return JSONResponse(content=data)


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    lines = request.log.splitlines()

    parsed = parse_logs_for_analysis(lines)
    raw_logs = parsed["raw_logs"]
    skipped_logs = parsed["skipped_logs"]

    run_id = save_analysis_run([], source="text")
    save_raw_logs(run_id, raw_logs)

    results = analyze_run_from_db(run_id)
    update_analysis_run_summary(run_id, results)

    return JSONResponse(content={
        "run_id": run_id,
        "analysis": results,
        "raw_logs": raw_logs
    })

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8")

    lines = text.splitlines()

    parsed = parse_logs_for_analysis(lines)
    raw_logs = parsed["raw_logs"]
    skipped_logs = parsed["skipped_logs"]

    run_id = save_analysis_run([], source=file.filename)
    save_raw_logs(run_id, raw_logs)

    results = analyze_run_from_db(run_id)
    update_analysis_run_summary(run_id, results)

    return JSONResponse(content={
        "run_id": run_id,
        "analysis": results,
        "raw_logs": raw_logs
    })

@app.get("/history")
def history():
    return JSONResponse(content=get_analysis_runs())

@app.get("/history/{run_id}")
def history_detail(run_id: int):
    detections = get_detections_by_run(run_id)

    if not detections:
        raise HTTPException(status_code=404, detail="history not found")

    return JSONResponse(content={
        "run_id": run_id,
        "detections": detections
    })