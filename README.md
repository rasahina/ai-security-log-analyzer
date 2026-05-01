# AI Security Log Analyzer

## Overview

AI Security Log Analyzer is a lightweight cybersecurity log analysis tool designed to detect suspicious activity from web access logs and provide clear, actionable insights.

It automatically identifies attack patterns such as brute-force attempts, admin access probing, and automated scanning, then explains the findings in a human-readable way.

This project is both:
- a learning project for security and AI system design
- an MVP prototype for a future AI-assisted security monitoring product


## Key Concept

This is NOT an AI-driven detection system.

Detection = deterministic Python logic
AI = explanation only

The system is designed to remain reliable, explainable, and secure, even without AI.


## Features

- Log parsing and normalization
- Suspicious activity detection
  - Brute-force login attempts
  - Admin access attempts
  - Automated scanning behavior
  - Burst traffic patterns
  - Night-time access anomalies
- Risk scoring per IP
- Risk classification: HIGH / MEDIUM / LOW
- Time-series traffic visualization
- Anomaly detection based on:
  - Failure rate
  - Access volume
  - Signal patterns
- Priority ranking of risky IPs
- Interactive Streamlit dashboard
- IP-level detailed analysis
- CSV export
- Response guide system (YAML-based actionable guidance)

### AI (Optional)

- Human-readable explanation generation
- Local LLM (Ollama) integration
- Explanation caching
- Sanitized output (prompt injection protection)


## Architecture

- Frontend: Streamlit
- Backend API: FastAPI
- Analysis Engine: Python / pandas
- Visualization: Plotly
- Database: SQLite (planned PostgreSQL migration)
- AI (optional): Ollama (local LLM)

### Environment

- WSL: FastAPI + Streamlit
- Windows: Ollama (optional)


## AI Policy (Critical Design Rules)

### AI is strictly limited to explanation only.

### AI is NOT used for:
- Attack detection
- Risk scoring
- Decision making
- Recommended actions

### AI is ONLY used for:
- Explaining already-detected results


### Security Principles

- All logs are treated as untrusted input
- AI must not follow instructions embedded in logs
- AI must not infer attacker intent
- AI must not modify detection results
- AI output is sanitized before display
- Explanations must be evidence-based


## Why AI is Optional

The system is designed to work fully without AI.

AI OFF -> Fast, lightweight, safe
AI ON  -> Better explanations

AI is disabled by default to ensure:
- Low resource usage
- Stable performance
- Safe execution


## Example Detection

Event:
Automated scanning activity and admin access attempts

Risk level:
HIGH

Reason:
IP address 172.16.0.9 shows a high failure rate with repeated access to sensitive endpoints such as /admin and /login. The activity includes multiple 404 responses and burst access patterns.

Recommended action:
Apply rate limiting and block scanning source if confirmed / Investigate immediately


## Usage

### 1. Start Ollama (optional)

ollama serve

### 2. Start backend (WSL)

uvicorn api:app --reload

### 3. Start UI (WSL)

streamlit run app.py

### 4. Open browser

http://localhost:8501


## AI Mode

### AI can be toggled inside the UI.

- OFF: no AI calls, lightweight mode
- ON: generates explanations using local LLM


### Ollama Configuration (Optional)

When using AI, Ollama runs on Windows and is accessed from WSL:

OLLAMA_URL = "http://172.30.176.1:11434/api/generate"

### Check Ollama:

#### Windows:
curl http://localhost:11434

#### WSL:
curl http://172.30.176.1:11434


## Current Status

- Detection logic implemented
- Risk scoring implemented
- FastAPI backend implemented
- Streamlit UI implemented
- Time-series analysis implemented
- Anomaly detection implemented
- AI explanation integrated (optional)
- Prompt injection defenses implemented
- AI output sanitization implemented
- AI caching implemented
- CSV export implemented
- History storage implemented (SQLite)
- Response guide system implemented
- Attack type priority system implemented (index.yaml)
- UI data/display separation implemented


## Roadmap

### Short-term:
- Improve detection accuracy
- Reduce false positives
- Expand response guides
- Improve usability

### Mid-term:
- Support multiple log formats (nginx, apache, auth.log)
- Cross-run analysis (recurring IP detection)
- Better anomaly detection

### Long-term:
- SaaS version
- Multi-tenant support
- Automated log collection agent
- Alerting system (email / webhook)


## Target Users

- Developers running web services
- Small teams without dedicated security staff
- Anyone needing simple log-based security visibility


## Philosophy

Do not rely on AI for security decisions.
Use AI only where it adds clarity, not risk.