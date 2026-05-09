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


## Current Phase: DetectionReport Contract Stabilization

The current development focus is the V2 detection pipeline contract.

```text
Detection Pipeline V2
↓
Interpretation Layer
↓
DetectionReport
↓
Minimal UI
```

The goal is to stabilize the `DetectionReport` schema, not to build a rich UI.

The current UI direction is:

```text
DetectionReport Viewer
```

The minimal viewer should support:

```text
Upload
↓
Analyze
↓
Overview
↓
IP Reports
↓
Findings
```

Current priority:

```text
1. api_v2.py
2. POST /analyze-v2
3. DetectionReport JSON confirmation
4. app_v2.py
5. ui_v2/components.py
```

The formal V2 output artifact is:

```text
output/detection_report_v2.json
```


## Knowledge Management Direction

The project architecture has moved from an Obsidian-based document model to a Notion-based database model.

Knowledge entities are managed as structured databases:

- signals
- signal clusters
- attacks
- response actions

The analyzer should treat these as reference knowledge, not procedural execution logic.

Core detection logic remains deterministic Python code.


## Response Guide Redesign

The response guide model has been redesigned.

The system should not store large per-attack response manuals directly inside attack definitions.

Instead, attacks reference response action values such as:

- IP_Block
- Password_Modification
- Account_Lock
- Rate_Limit
- Investigation_Required

Detailed operational procedures are maintained separately in a Notion response database.

This separates:

```text
Detection knowledge
≠
Operational response knowledge
```

The current direction is:

```text
Attack
↓
response_action values
↓
Response Action DB (Notion)
```

This keeps DetectionReport compact and prevents operational manuals from leaking into detection logic.


## V2 Architecture

V2 is organized into three layers:

```text
Core Engine
↓
Interpretation Layer
↓
Presentation Layer / UI
```

### Core Engine

Responsible for deterministic security analysis:

- SignalFinding
- SignalCluster
- ClusterRelation
- AttackFinding
- Score
- Risk

Core Engine must not know about:

- UI
- AI explanation
- graph rendering
- timeline rendering
- response guides

### Interpretation Layer

Responsible for converting deterministic engine output into a stable external report:

- DetectionReport generation
- evidence organization
- suspicious activity interpretation
- explainability structure
- timeline meaning structure
- knowledge attachment

### Presentation Layer / UI

Responsible for rendering `DetectionReport` only.

UI must not:

- perform detection
- calculate score
- determine risk
- reinterpret relations


## DetectionReport Schema

Current schema version:

```text
v2_minimal_0.1
```

Minimal structure:

```text
DetectionReport
- schema_version
- generated_at
- ip_reports[]

IPReport
- source_ip
- overall_score
- risk_level
- attack_count
- time_range
- findings[]

FindingReport
- finding_id
- finding_type
- attack_type
- score
- risk_level
- source_ip
- time_range
```

Minimum contract:

```text
Who       source_ip
When      time_range
What      attack_type / finding_type
Severity  score / risk_level
```

`finding_id` format:

```text
v2-{source_ip}-{attack_type}-{timestamp}
```

Example:

```text
v2-10.0.0.4-brute_force-20260501T110000
```


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
- Knowledge DB: Notion
- AI (optional): external / BYO AI

### Environment

- WSL: FastAPI + Streamlit
- Windows: Ollama (optional)


## AI Policy (Critical Design Rules)

### AI is strictly limited to explanation and assistance.

### AI is NOT used for:
- Attack detection
- Risk scoring
- Decision making
- Recommended action decisions

### AI is ONLY used for:
- Explaining already-detected results
- Assisting investigations

### V2 AI direction

AI is separated from the analyzer.

Rules:

- AI is not part of Core Engine
- AI does not participate in deterministic detection
- AI reads DetectionReport
- AI performs assistance, not detection
- AI is an assistant, not a decision maker
- Users should run AI in their own environment
- The system must work without AI
- Explainability evidence must originate from deterministic engine output
- AI provider independence must be preserved
- Bring Your Own AI is preferred


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


## Usage

### 1. Start Ollama (optional)

```bash
ollama serve
```

### 2. Start backend (WSL)

```bash
uvicorn api_v2:app --reload
```

### 3. Start UI (WSL)

```bash
streamlit run app_v2.py
```

### 4. Open browser

```text
http://localhost:8501
```


## Current Status

Classic line:

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
- UI data/display separation implemented

V2 line:

- Detection Pipeline V2 implemented
- Core Engine and Interpretation Layer separated
- DetectionReport generation implemented
- Minimal schema version: `v2_minimal_0.1`
- Notion-based knowledge management direction established
- Response action reference model established
- Formal output target: `output/detection_report_v2.json`
- Next focus: `api_v2.py` and `POST /analyze-v2`


## Roadmap

### Short-term:
- Stabilize DetectionReport contract
- Add `POST /analyze-v2`
- Confirm API response matches `output/detection_report_v2.json`
- Build minimal DetectionReport Viewer
- Keep UI display-only

### Mid-term:
- Improve detection accuracy
- Reduce false positives
- Expand signal / attack DBs
- Support multiple log formats (nginx, apache, auth.log)
- Cross-run analysis (recurring IP detection)
- Better anomaly detection

### Long-term:
- Investigation Workspace
- Timeline
- Evidence panel
- Attack Graph
- Raw log view
- AI Copilot
- Knowledge layer
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

For V2, the central principle is:

```text
DetectionReport = public contract
```

Everything outside the deterministic engine should consume the report contract, not internal engine objects.
