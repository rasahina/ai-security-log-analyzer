# AI Security Log Analyzer

## Overview

This project analyzes web access logs to detect suspicious or potentially malicious activity.

It focuses on identifying patterns such as unauthorized access attempts, brute-force behavior, and scanning activity, and provides clear explanations of detected events.

---

## Features

- Log parsing and normalization
- Suspicious activity detection
  - Brute-force attempts
  - Admin access attempts
  - Scanning behavior
  - Burst access patterns
- Risk scoring per IP
- Time-series analysis of traffic patterns
- Anomaly detection using failure rate and signal aggregation
- Priority-based ranking of risky IPs
- Interactive visualization (Streamlit + Plotly)
- AI-based explanation of detected events (Ollama, local LLM)

---

## Architecture

- Frontend: Streamlit
- Backend: FastAPI
- Analysis Engine: Python (pandas-based)
- AI Explanation: Ollama (local LLM)
- Environment:
  - Windows: Ollama server
  - WSL: Backend + UI

---

## AI Policy

- AI is NOT used for detection
- Detection and scoring are handled by Python logic
- AI is used ONLY for explanation:
  - Why the activity is suspicious
  - What action should be taken
- Explanations must be evidence-based (no speculation)

---

## Example Detection

Event:
Unauthorized access attempt to /admin

Risk level:
Medium

Reason:
A request from IP 10.0.0.5 targeted a sensitive admin endpoint and resulted in failed authentication (401). A single failed attempt does not indicate a confirmed attack.

Recommended action:
Monitor for repeated attempts from this IP.

---

## Usage

1. Start Ollama (Windows PowerShell)

ollama serve

2. Run backend (WSL)

uvicorn api:app --reload

3. Run UI (WSL)

streamlit run app.py

4. Open browser

http://localhost:8501

---

## Development Status

- Core detection logic implemented
- Time-series analysis and anomaly detection completed
- Interactive UI implemented
- AI explanation integrated

---

## Next Steps

- Improve attack phase classification
- Support multi-log aggregation
- Enhance scoring accuracy
- Refine UI/UX