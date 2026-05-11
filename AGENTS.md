# AGENTS.md

## Project Overview

This project is an AI Security Log Analyzer focused on:

* deterministic security detection
* explainable detection pipelines
* layered architecture
* investigation-oriented security analysis

The system is designed as a long-term extensible security analytics platform, not a simple demo analyzer.

---

# Core Architecture

The project is built around a layered detection pipeline.

SignalFinding
→ SignalCluster
→ ClusterRelation
→ AttackFinding
→ Score
→ Risk

The system is additionally separated into:

Core Engine
↓
Interpretation Layer
↓
Presentation Layer / UI

---

# Current Phase

The active runtime path is Detection Pipeline V2 → Interpretation Layer → DetectionReport → DetectionReport Viewer.

The priority is preserving the stabilized DetectionReport contract while preparing the next cleanup/configuration phases.

This is not a rich UI phase.

Current active runtime:

* `app_v2.py`
* `api_v2.py`
* `POST /analyze-v2`
* `core/v2_pipeline.py`
* `core/v2_report_engine.py`
* DetectionReport `v2_minimal_0.1`

Current UI target:

DetectionReport Viewer

Do not expand scope into Timeline, Attack Graph, AI Explanation, Response Guide UI, SOC Queue, realtime, multi-user, RBAC, MITRE Mapping, Evidence Graph, or Investigation Workspace during this phase.

---

# Development Workflow

The project uses an AI-assisted deterministic development workflow.

Workflow:

1. `main` is treated as the stable baseline
2. Codex creates a feature branch from latest `main`
3. Codex implements a small scoped change
4. Codex commits and pushes the feature branch
5. Local environment pulls the branch
6. Local verification is performed
7. `venv/bin/python -m pytest` is run when tests are present
8. DetectionReport JSON is verified
9. UI/API behavior is verified if applicable
10. Local environment merges into `main`
11. `main` is pushed to origin
12. The next task starts again from latest `main`

Important Rules:

- 1 branch = 1 responsibility
- Keep diffs small
- Do not mix Core and UI changes
- Schema changes must be isolated
- DetectionReport contract must be verified before merge
- pytest must pass before merge when available
- debug JSON should be checked before merge
- `main` must remain stable
- cleanup branches should be small, deterministic, and easy to revert

---

# Knowledge Management Direction

The architecture direction has moved from Obsidian-based notes to Notion-based databases.

Knowledge entities should be managed as structured DB records:

* signals
* signal clusters
* attacks
* response actions

Notion is treated as a knowledge/reference DB.

Notion must NOT contain:

* detection logic
* procedural execution logic
* hidden runtime behavior

Core deterministic logic remains in Python.

---

# Layer Responsibilities

## Core Engine

Responsible for:

* detection
* clustering
* relation resolution
* scoring
* risk evaluation

Core Engine must NOT contain:

* UI logic
* presentation logic
* AI explanation logic
* response guide rendering
* graph rendering
* timeline rendering
* Notion rendering logic

Core Engine must remain deterministic.

Same input must produce same output.

---

## Interpretation Layer

Responsible for:

* DetectionReport generation
* evidence organization
* suspicious activity interpretation
* explainability structure
* timeline meaning structure
* knowledge attachment
* response action references

Interpretation Layer converts:

Core internal concepts
↓
Human-readable structures

Interpretation Layer does NOT render UI.

---

## Presentation Layer / UI

Responsible for:

* rendering DetectionReport
* table rendering
* graph rendering
* timeline rendering
* investigation workflow

UI must NOT:

* calculate score
* determine risk
* perform detection
* reinterpret relations

UI reads DetectionReport only.

---

# DetectionReport Philosophy

DetectionReport is the canonical external output.

Everything outside Core Engine should consume:

DetectionReport

Examples:

* UI
* API
* AI assistant
* export adapters
* SIEM adapters

Core internal structures must not directly leak outside.

Current schema version:

v2_minimal_0.1

Minimum contract:

* Who: source_ip
* When: time_range
* What: attack_type / finding_type
* Severity: score / risk_level

Generated output path:

output/detection_report_v2.json

---

# Response Guide Philosophy

The response guide design has changed.

Do NOT attach large response manuals directly to attacks.

Instead:

```text
Attack
↓
response_action values
↓
Response Action DB
```

Examples of response_action values:

* IP_Block
* Password_Modification
* Account_Lock
* Rate_Limit
* Investigation_Required

Detailed operational procedures are managed separately in Notion.

Detection knowledge and operational response knowledge are intentionally separated.

Response action values are references, not execution instructions.

---

# AI Philosophy

## AI Separation Design

AI is intentionally separated from the detection system.

Rules:

* AI must NOT be part of Core Engine
* AI must NOT participate in deterministic detection
* AI reads DetectionReport only
* AI performs assistance, not detection
* AI acts as assistant, not decision maker
* System must function without AI
* Explainability evidence must originate from Core Engine
* AI provider independence must be preserved
* Bring Your Own AI is the preferred model
* Users should execute AI within their own environment

Users should be able to use:

* OpenAI
* Claude
* Gemini
* Local LLM
* Ollama
* Azure OpenAI

without changing the detection system.

---

# Detection Principles

## Deterministic Detection

Detection logic must remain deterministic.

Avoid:

* LLM-based detection decisions
* probabilistic AI-only classification
* hidden scoring logic

Detection decisions must be explainable from evidence.

---

## Explainability

Evidence must be preserved.

Important concepts:

* absorbed is NOT deletion
* supporting evidence must remain accessible
* evidence tracing must be possible
* timeline reconstruction must remain possible

---

# Project Structure Philosophy

Keep the codebase:

* small
* understandable
* maintainable

Avoid unnecessary abstraction.

---

# Structural Rules

* avoid deep directory trees
* avoid excessive files
* prefer simple interfaces
* separate config from logic
* separate display text from logic

---

# YAML Rules

YAML stores:

* configuration
* thresholds
* parameters

YAML must NOT contain:

* processing logic
* procedural behavior
* hidden execution flow

Python contains reusable logic.

---

# Parallel Migration Strategy

Large redesigns must use parallel implementation.

Rules:

* do not break existing pipeline
* implement new line separately
* validate through debug outputs
* remove old line only after stabilization

Current structure:

Active V2 runtime

Legacy implementations are not part of the public alpha runtime tree.

---

# Debug / Output Rules

Separate:

* logs
* debug
* output

Definitions:

logs:

* execution logs
* audit logs

debug:

* intermediate verification JSON

output:

* final artifacts

DetectionReport belongs to:

output/

---

# Test Rules

Use the V2 pytest safety net before merging runtime cleanup or config changes:

```bash
venv/bin/python -m pytest
```

At minimum, also run:

```bash
venv/bin/python -m py_compile api_v2.py app_v2.py core/v2_pipeline.py core/v2_report_engine.py
```

Tests must preserve:

* `POST /analyze-v2`
* DetectionReport `v2_minimal_0.1`
* `ip_reports`
* minimal report structure

---

# UI Philosophy

The first UI is NOT a SOC platform.

The first UI is:

DetectionReport Viewer

Purpose:

* validate schema
* validate structure
* validate investigation flow

Minimal flow:

Upload
↓
Analyze
↓
Overview
↓
IP Reports
↓
Findings

---

# Future Direction

The long-term goal is an investigation-oriented security workspace.

Possible future features:

* Timeline
* Attack Graph
* Evidence Panel
* Investigation Workspace
* AI Copilot
* Knowledge Layer
* MITRE Mapping
* Threat Intelligence

These are future extensions.

Do not prematurely implement them.

---

# Forbidden Patterns

Do NOT:

* put detection logic inside UI
* put processing logic inside YAML
* put procedural logic inside Notion
* put large logic inside analyzer.py
* mix detection and presentation
* let AI determine detection results
* tightly couple UI and Core Engine

---

# Development Philosophy

Implement incrementally.

Priorities:

1. architecture stability
2. responsibility separation
3. deterministic behavior
4. explainability
5. extensibility
6. UI sophistication

The current phase is:

Building a stable foundation for future investigation systems.
