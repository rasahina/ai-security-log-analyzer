# AI Security Log Analyzer

Deterministic and explainable security log analysis runtime.

Observable-first.
Evidence-oriented.
AI-separated.

---

## Current Status

Experimental public alpha.

This project currently focuses on:

* deterministic detection architecture
* explainable evidence
* observable-first telemetry analysis
* runtime boundary validation
* DetectionReport-based analysis flow

This project is not production-ready security infrastructure.

---

## What This Project Is

AI Security Log Analyzer is:

* a deterministic Web log analysis runtime
* an explainable DetectionReport generator
* an observable-first detection pipeline
* a layered security telemetry architecture
* a security learning and experimentation project

---

## What This Project Is NOT

This project is intentionally NOT:

* a SIEM replacement
* an autonomous SOC agent
* an AI-based detection engine
* a probabilistic black-box scoring system
* an endpoint telemetry platform
* a speculative attack inference engine
* a realtime prevention or blocking system

The analyzer only handles activity directly observable from logs.

---

## Core Principles

* Observable-first
* Deterministic runtime behavior
* Explainable evidence
* AI separation
* Minimal retention
* No fake certainty

See:

* DESIGN_PRINCIPLES.md

---

## Runtime Architecture

```
Raw Log Input
↓
Parser
↓
Record Minimizer
↓
Persistence
↓
Runtime Eligibility
↓
Canonical Runtime Event
↓
Detection Engine
↓
Evaluation
↓
DetectionReport
```

See:

* ARCHITECTURE.md

---

## Current Capabilities

* Access log parsing
* Error log parsing
* Deterministic signal detection
* Runtime eligibility filtering
* UTC-aware runtime normalization
* Signal clustering
* Explainable DetectionReport generation
* Streamlit DetectionReport Viewer
* Minimal pytest runtime safety net

---

## Active Runtime

Current active runtime:

```
API:
- api_v2.py

Viewer:
- app_v2.py

Pipeline:
- core/v2_pipeline.py

DetectionReport schema:
- v2_minimal_0.1
```

---

## AI Philosophy

AI is intentionally separated from the core runtime.

The runtime must function fully without AI.

Users may optionally use external AI systems with exported DetectionReports under their own control.

AI is not responsible for:

* signal generation
* attack classification
* risk scoring
* deterministic runtime decisions

---

## Usage

### 1. Clone repository

```
git clone <repository-url>
cd ai-security-log-analyzer
```

### 2. Create virtual environment

```
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```
pip install -r requirements.txt
```

### 4. Start backend API

```
uvicorn api_v2:app --reload
```

Backend API:

```
http://127.0.0.1:8000
```

### 5. Start DetectionReport Viewer

```
streamlit run app_v2.py
```

Viewer:

```
http://localhost:8501
```

### 6. Analyze sample log

Sample log:

```
data/sample.log
```

### 7. Run tests

```
venv/bin/python -m pytest
```

---

## Documents

* ARCHITECTURE.md
* DESIGN_PRINCIPLES.md
* TECH_DEBT.md
* AGENTS.md
* SECURITY.md

---

## License

Apache License 2.0. See LICENSE.

---

## Security

See SECURITY.md.

This project is an experimental public alpha and should not be used as the sole basis for security decisions.
