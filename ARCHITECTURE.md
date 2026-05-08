# Architecture

## Current Phase

The current phase is:

```text
Detection Pipeline V2
↓
Interpretation Layer
↓
DetectionReport
↓
Minimal UI
```

The immediate goal is:

```text
DetectionReport schema stabilization
```

This is not a rich UI phase.

The current UI should be treated as:

```text
DetectionReport Viewer
```

---

## V2 Layer Model

V2 uses three layers:

```text
Core Engine
↓
Interpretation Layer
↓
Presentation Layer / UI
```

---

## Core Engine

Responsible for deterministic detection and scoring.

Core concepts:

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

Core Engine must remain deterministic.

Same input should produce the same output.

---

## Interpretation Layer

Responsible for converting Core Engine output into stable, human-readable structures.

Responsibilities:

- DetectionReport generation
- evidence organization
- suspicious activity interpretation
- explainability structure
- timeline meaning structure
- knowledge attachment

Current minimal artifact:

```text
DetectionReport
```

Current implementation:

```text
core/v2_report_engine.py
```

---

## Presentation Layer / UI

The UI consumes:

```text
DetectionReport only
```

UI must not:

- perform detection
- calculate score
- determine risk
- reinterpret relations

The UI is display-only at this stage.

---

## Detection Pipeline V2

Current flow:

```text
SignalFinding
→ SignalCluster
→ ClusterRelation
→ AttackFinding
→ Score
→ Risk
→ DetectionReport
```

Current implementation files:

```text
core/timeseries_signal_detector.py
core/cluster_engine.py
core/cluster_relation_engine.py
core/attack_engine.py
core/score_engine.py
core/risk_engine.py
core/v2_pipeline.py
core/v2_report_engine.py
```

---

## DetectionReport Schema

Current schema version:

```text
v2_minimal_0.1
```

Structure:

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

---

## Finding ID

Format:

```text
v2-{source_ip}-{attack_type}-{timestamp}
```

Example:

```text
v2-10.0.0.4-brute_force-20260501T110000
```

Intended future uses:

- timeline
- evidence
- graph
- investigation
- explainability

---

## Absorbed Semantics

`absorbed` does not mean deleted.

It means:

```text
absorbed into a higher-level meaning
```

Absorbed clusters should remain available as evidence.

Future uses:

- Timeline
- Evidence
- Attack Graph
- Explainability

---

## Suspicious Activity Semantics

`suspicious_activity` means:

```text
abnormal activity below confirmed attack level
```

Core internal concept:

```text
fallback_candidate
```

External report concept:

```text
suspicious_activity
```

---

## AI Philosophy

AI is intentionally separated from the detection system.

Core principles:

- AI is not part of Core Engine
- AI does not participate in deterministic detection
- AI reads DetectionReport
- AI performs assistance, not detection
- AI is an assistant, not a decision maker
- AI provider independence must be preserved
- Bring Your Own AI is the default strategy
- Users should run AI within their own environment
- The system must function without AI
- Explainability evidence must originate from Core Engine

Possible AI providers:

- OpenAI
- Claude
- Gemini
- Ollama
- Local LLM
- Azure OpenAI

The analyzer itself should remain AI-provider neutral.

---

## Project Rules

- Do not put logic in YAML
- Do not put large logic in `analyzer.py`
- Keep Core / Interpretation / UI separated
- Keep V2 as a parallel line
- Implement small changes
- Confirm with debug JSON
- Treat output JSON as the formal artifact

---

## Debug and Output

Debug files:

```text
debug/
```

Used for intermediate JSON inspection.

Formal output:

```text
output/detection_report_v2.json
```

The UI should be able to consume DetectionReport JSON as input.

---

## Minimal UI V2

Current UI goal:

```text
DetectionReport Viewer
```

Minimal flow:

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

Planned files:

```text
api_v2.py

app_v2.py

ui_v2/
├── components.py
├── i18n.py
└── styles.py
```

---

## Not Now

Do not implement these in the current phase:

- Timeline
- Attack Graph
- AI Explanation
- Response Guide UI
- SOC Queue
- Realtime
- WebSocket
- Multi-user
- RBAC
- MITRE Mapping
- Evidence Graph
- Investigation Workspace

---

## Final Direction

The long-term UI direction is:

```text
Investigation Workspace
```

Possible future structure:

```text
Alert Queue
↓
Investigation Workspace
├ Timeline
├ Evidence
├ Attack Graph
├ Raw Logs
├ AI Copilot
└ Knowledge
```

But the current phase is:

```text
schema validator phase
```

---

## Current Priority

Next implementation order:

```text
1. api_v2.py
2. POST /analyze-v2
3. DetectionReport JSON confirmation
4. app_v2.py
5. ui_v2/components.py
```

Current top priority:

```text
DetectionReport contract stabilization
```
