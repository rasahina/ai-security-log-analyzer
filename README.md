# AI Security Log Analyzer

## Overview

AI Security Log Analyzer is a lightweight cybersecurity log analysis tool designed to detect suspicious activity from web access logs and emit a stable, explainable DetectionReport.

This repository is an experimental public alpha and MVP runtime skeleton. It is intended for architecture validation, deterministic detection experiments, and early feedback.

It is NOT production-ready security infrastructure.

This project intentionally prioritizes:

* explainability over complexity
* deterministic evidence over probabilistic confidence
* understandable detection over opaque automation

The active runtime is the V2 API and DetectionReport Viewer:

* API: `api_v2.py`
* Viewer: `app_v2.py`
* Pipeline: `core/v2_pipeline.py`
* Report contract: `v2_minimal_0.1`

The project aims to make defensive security more understandable, readable, and forkable.

---

## What This Project Is

* deterministic web log detection runtime
* explainable DetectionReport generator
* security learning / experimentation project
* small observable-first analysis pipeline
* public MVP architecture skeleton
* foundation for future investigation tooling

---

## What This Project Is NOT

This project is intentionally NOT:

* an autonomous AI SOC
* an AI-based detection engine
* a giant SIEM replacement
* a UEBA platform
* an endpoint telemetry platform
* a speculative attack inference engine
* a production-grade security guarantee
* a realtime prevention or blocking system

The analyzer only handles activity directly observable from logs.

The system intentionally avoids:

* black-box AI detection
* probabilistic attacker intent inference
* opaque scoring systems
* speculative attack-chain reconstruction
* fake certainty

---

## Public Alpha Scope

The current public alpha focuses on a small deterministic runtime path:

```text
Upload/Paste log text
-> POST /analyze-v2
-> Detection Pipeline V2
-> DetectionReport v2_minimal_0.1
-> DetectionReport Viewer
```

Non-goals for this alpha:

* production SOC or SIEM replacement
* realtime monitoring
* multi-user workflows or RBAC
* autonomous remediation
* AI/LLM-based detection decisions
* sanitizer, masking, or AI Guard behavior
* broad incident response orchestration

The project should be treated as an experimental foundation, not an operational security control.


## Key Concept

This is NOT an AI-driven detection system.

Detection = deterministic Python logic  
AI = outside the active detection runtime

The system is designed to remain reliable, explainable, and secure, even without AI.


## Current Phase: V2 MVP Stabilized

The V2 MVP is now the active runtime path.

```text
Detection Pipeline V2
↓
Interpretation Layer
↓
DetectionReport
↓
DetectionReport Viewer
```

The current viewer supports:

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

The generated V2 output artifact is:

```text
output/detection_report_v2.json
```

A minimal pytest safety net verifies `/health`, `POST /analyze-v2`, and the minimal DetectionReport contract.


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
- V2 suspicious activity detection
  - Brute-force login attempts
  - Admin access attempts
  - Automated scanning behavior
  - Burst traffic patterns
- Risk scoring per IP
- Risk classification
- DetectionReport generation
- Minimal Streamlit DetectionReport Viewer
- Pytest safety net for the V2 API contract

Legacy UI/API/Core/AI implementations are not part of the public alpha runtime.


## Architecture

- Frontend: Streamlit
- Active UI: `app_v2.py`
- Backend API: `api_v2.py`
- Analysis Engine: deterministic Python V2 pipeline
- Database: SQLite
- Knowledge DB: Notion
- AI: external / BYO AI, not part of Core detection

### Environment

- WSL: FastAPI + Streamlit


## AI Policy (Critical Design Rules)

### AI is strictly limited to explanation and assistance outside the project

### AI is NOT used for:
- Attack detection
- Risk scoring
- Decision making
- Recommended action decisions

### V2 AI direction

AI is separated from the analyzer.

Rules:

- Detection, evaluation, and response guidance are deterministic
- The system must work without AI
- AI provider independence must be preserved: Bring Your Own AI

### Security Principles

- All logs are treated as untrusted input
- AI must not follow instructions embedded in logs
- AI must not infer attacker intent
- AI must not modify detection results
- Explanations must be evidence-based


## AI Runtime Status

The active V2 runtime does not include AI or legacy AI/Ollama code.

Future AI assistants should read DetectionReport only.

## Usage
Tested on WSL/Linux environments.
### 1. Clone repository

```bash
git clone <repository-url>
cd ai-security-log-analyzer
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start backend API

```bash
uvicorn api_v2:app --reload
```

The backend API will start on:

```text
http://127.0.0.1:8000
```

### 5. Start DetectionReport Viewer

Open a second terminal, activate the same virtual environment, then run:

```bash
streamlit run app_v2.py
```

The viewer will start on:

```text
http://localhost:8501
```

### 6. Analyze sample log

Use the included sample log:

```text
data/sample.log
```

Upload or paste the log into the viewer to generate a DetectionReport.

### 7. Run tests

```bash
venv/bin/python -m pytest
```


## Current Status

- Public alpha documentation added
- Licensed under Apache License 2.0
- Detection Pipeline V2 implemented
- Core Engine and Interpretation Layer separated
- DetectionReport generation implemented
- V2 API active: `api_v2.py`
- V2 Viewer active: `app_v2.py`
- Minimal schema version: `v2_minimal_0.1`
- Minimal pytest safety net implemented
- Legacy UI/API/Core/AI lines removed from public alpha runtime
- Response action reference model established
- Generated output target: `output/detection_report_v2.json`


## Roadmap

### Short-term:
- Keep DetectionReport contract stable
- Use pytest before cleanup merges
- Prepare YAML layer split under `config/v2/`
- Keep UI display-only

### Mid-term:
- Split V2 YAML by layer
- Improve detection accuracy
- Reduce false positives
- Expand signal / attack DBs
- Support multiple log formats (nginx, apache, auth.log)
- Cross-run analysis (recurring IP detection)
- Observable anomaly heuristics

### Long-term:
- Investigation Workspace
- Timeline
- Evidence panel
- Attack Graph
- Raw log view
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


## License

Apache License 2.0. See [LICENSE](LICENSE).


## Security

See [SECURITY.md](SECURITY.md). This project is an experimental public alpha;
do not use it as the sole basis for security decisions.
