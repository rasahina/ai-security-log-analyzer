# AI Security Log Analyzer

## Overview

This project analyzes web access logs to detect suspicious or potentially malicious activity.

It focuses on identifying patterns such as unauthorized access attempts and brute-force behavior, and provides clear explanations of detected events.

## Features

* Log parsing and normalization
* Suspicious activity detection (e.g. repeated failed logins)
* Risk scoring for each event
* AI-based explanation of security events (via Ollama)

## Example Detection

```
Event:
Unauthorized access attempt to /admin

Risk level:
Medium

Reason:
A request from IP 10.0.0.5 targeted a sensitive admin endpoint and resulted in failed authentication (401).

Recommended action:
Monitor for repeated attempts from this IP.
```

## Current Status

* Core log analysis implemented
* Basic scoring system in place
* AI explanation integrated (local LLM)

## Next Steps

* Improve brute-force detection logic
* Support multiple log aggregation
* Add Streamlit-based UI
* Enhance scoring accuracy

## Notes

* Access to sensitive endpoints like `/admin` is treated with higher priority
* Repeated 401 responses may indicate brute-force attempts

## Usage

### 1. Start Ollama (Windows PowerShell)

```powershell
ollama serve
```

---

### 2. Run the backend (WSL)

```bash
uvicorn api:app --reload
```

---

### 3. Run the UI (WSL)

```bash
streamlit run app.py
```

---

### 4. Open in browser

```
http://localhost:8501
```


