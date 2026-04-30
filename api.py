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
)

from analyzer import analyze_log_lines
from parsers.log_parser import parse_log_lines

app = FastAPI(title="AI Security Log Analyzer API")

#データベース初期化
init_db()


RESULT_FILE = "output/result.json"


class AnalyzeRequest(BaseModel):
    log: str


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

    results = analyze_log_lines(lines)
    raw_logs = parse_log_lines(lines)

    run_id = save_analysis_run(results, source="text")

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

    results = analyze_log_lines(lines)
    raw_logs = parse_log_lines(lines)

    run_id = save_analysis_run(results, source=file.filename)

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