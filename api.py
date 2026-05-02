from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json
import os
from data_layer.database import (
    init_db,
    get_analysis_runs,
    get_detections_by_run,
)

from core.analyzer import analyze_run_from_db
from core.analyzer import analyze_single_file, analyze_multiple_files
from data_layer.log_parser import parse_log_lines

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
    result = analyze_single_file(
        text=request.log,
        source="text"
    )

    return JSONResponse(content=result)

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8")

    result = analyze_single_file(
        text=text,
        source=file.filename
    )

    return JSONResponse(content=result)

@app.post("/analyze-files")
async def analyze_files(files: list[UploadFile] = File(...)):
    files_data = []

    for file in files:
        content = await file.read()
        text = content.decode("utf-8")

        files_data.append({
            "file_name": file.filename,
            "text": text
        })

    result = analyze_multiple_files(files_data)

    return JSONResponse(content=result)

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