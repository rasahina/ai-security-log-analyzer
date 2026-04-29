from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from database import init_db, save_analysis_run
import json
import os


from analyzer import analyze_log_lines, parse_log_lines

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
