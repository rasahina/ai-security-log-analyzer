# Architecture

## Current Phase

The V2 MVP is the active runtime path:

```text
app_v2.py
↓
api_v2.py
↓
Detection Pipeline V2
↓
Interpretation Layer
↓
DetectionReport
```

The active implementation is:

```text
app_v2.py
api_v2.py
core/v2_pipeline.py
core/v2_report_engine.py
```

Current schema:

```text
v2_minimal_0.1
```

The legacy UI/API/Core/AI lines have been removed from active runtime. Historical implementations are kept under `archive/`.

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

## Knowledge Management Model

The design source has moved from Obsidian-based documents to Notion-based databases.

The following knowledge entities are managed in databases:

* signals
* signal clusters
* cluster relations
* attacks
* response actions

The analyzer should treat these as structured knowledge sources, not free-form document notes.

Core detection logic must still remain in Python.

Notion databases are used for knowledge management and reference data, not procedural execution logic.

---

## YAML Layer Split Model

V2 YAML is currently transitioning from a single combined file toward layer-separated YAML files.

Current active runtime:

```text
config/v2_detection_rules.yaml
```

Current extracted layer files:

```text
config/v2_signals.yaml
config/v2_clusters.yaml
```

The active runtime still keeps the combined V2 YAML as the primary source of truth during migration.

Long-term direction:

```text
config/
├── v2_signals.yaml
├── v2_clusters.yaml
├── v2_cluster_relations.yaml
├── v2_attacks.yaml
└── v2_response_actions.yaml
```

Layer responsibilities:

```text
v2_signals.yaml
= signal definitions and signal support data used by deterministic signal detection

v2_clusters.yaml
= SignalFinding → SignalCluster mapping and cluster parameters

v2_cluster_relations.yaml
= SignalCluster relation resolution rules
  (fallback handling, absorption, overlap handling, confidence adjustment)

v2_attacks.yaml
= SignalCluster → AttackFinding mapping and attack metadata

v2_response_actions.yaml
= response action references and lightweight response metadata
```

YAML files are database snapshots / configuration inputs.

YAML must not contain procedural logic.

Notion remains the knowledge management source.

Python remains the execution and detection logic source.

---

## Naming Conventions

Use stable IDs that reveal the layer clearly.

Recommended naming:

```text
signal:
failed_login
admin_access
many_404

cluster:
brute_force_cluster
admin_access_cluster
automated_scanner_cluster

attack:
brute_force
admin_access
automated_scanner

response_action:
block_ip
review_auth_logs
enable_waf
```

Avoid mixing layer names.

For example, cluster IDs should not use `_event`.

Preferred pattern:

```text
*_cluster
```

for cluster-layer records.

---

## Core Engine

Responsible for deterministic detection and scoring.

Core concepts:

* SignalFinding
* SignalCluster
* ClusterRelation
* AttackFinding
* Score
* Risk

Core Engine must not know about:

* UI
* AI explanation
* graph rendering
* timeline rendering
* response guide rendering
* Notion page rendering

Core Engine must remain deterministic.

Same input should produce the same output.

AI is not part of Core detection. AI may read DetectionReport in future assistant workflows, but it must not participate in detection, scoring, risk, or relation decisions.

---

## Interpretation Layer

Responsible for converting Core Engine output into stable, human-readable structures.

Responsibilities:

* DetectionReport generation
* evidence organization
* suspicious activity interpretation
* explainability structure
* timeline meaning structure
* knowledge attachment
* response action reference attachment

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

* perform detection
* calculate score
* determine risk
* reinterpret relations
* decide response actions

The UI is display-only at this stage.

Current implementation:

```text
app_v2.py
```

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

Active API boundary:

```text
api_v2.py
POST /analyze-v2
```

---

## Detection Layer Responsibilities

### Signal Layer

Responsible for deterministic event pattern detection.

Produces:

```text
SignalFinding
```

Current extracted runtime file:

```text
config/v2_signals.yaml
```

Current runtime content:

* paths
* signals

`paths` belongs to the signal layer because signal filters depend on shared path groups.

---

### Cluster Layer

Responsible for grouping SignalFindings into SignalClusters.

Produces:

```text
SignalCluster
```

Current extracted runtime file:

```text
config/v2_clusters.yaml
```

Current runtime content:

* signal_clusters

---

### Cluster Relation Layer

Responsible for resolving relationships between SignalClusters before AttackFinding generation.

Produces:

```text
Resolved SignalCluster
```

Responsibilities:

* overlap resolution
* absorbed semantics
* fallback candidate handling
* suspicious activity confidence adjustment
* relation metadata

Important:

`cluster_relation_engine` references attack metadata through:

```text
attacks.*.source_cluster
```

This is intentional.

The engine uses attack-defined source clusters to determine which SignalClusters become primary attack candidates versus fallback suspicious activity candidates.

This layer is therefore a transition layer between:

```text
SignalCluster
↓
ClusterRelation
↓
AttackFinding
```

Current implementation:

```text
core/cluster_relation_engine.py
```

Current runtime content:

```text
cluster_relation
```

Current relation behavior mainly supports:

```text
suspicious_activity
```

fallback semantics.

---

### Attack Layer

Responsible for converting resolved SignalClusters into AttackFindings.

Produces:

```text
AttackFinding
```

Current runtime content:

```text
attacks
```

Responsibilities:

* attack naming
* attack metadata
* source_cluster mapping
* attack scoring metadata

Attack layer does not resolve overlap timing or absorption behavior.

Those belong to ClusterRelation.

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

Response action references may be added later, but the current priority remains schema stabilization.

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

* timeline
* evidence
* graph
* investigation
* explainability

---

## Absorbed Semantics

`absorbed` does not mean deleted.

It means:

```text
absorbed into a higher-level meaning
```

Absorbed clusters should remain available as evidence.

Future uses:

* Timeline
* Evidence
* Attack Graph
* Explainability

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

## Response Guide Model

The response guide design has changed.

The system should not store a large response manual directly for each attack.

Instead, each attack should reference response action values such as:

* block_ip
* reset_password
* review_auth_logs
* add_rate_limit
* enable_waf
* investigation_required

The detailed response manuals are maintained separately in a Notion response database.

Attack knowledge and response knowledge are therefore separated:

```text
Attack
↓
response_action values
↓
Response Action DB in Notion
```

This keeps DetectionReport compact and prevents response-guide text from becoming detection logic.

Response action values are references, not execution instructions.

---

## AI Philosophy

AI is intentionally separated from the detection system.

Core principles:

* AI is not part of Core Engine
* AI does not participate in deterministic detection
* AI reads DetectionReport
* AI performs assistance, not detection
* AI is an assistant, not a decision maker
* AI provider independence must be preserved
* Bring Your Own AI is the default strategy
* Users should run AI within their own environment
* The system must function without AI
* Explainability evidence must originate from Core Engine

Possible AI providers:

* OpenAI
* Claude
* Gemini
* Ollama
* Local LLM
* Azure OpenAI

The analyzer itself should remain AI-provider neutral.

---

## Project Rules

* Do not put logic in YAML
* Do not put procedural logic in Notion
* Do not put large logic in `analyzer.py`
* Keep Core / Interpretation / UI separated
* Keep V2 as a parallel line
* Implement small changes
* Confirm with debug JSON
* Treat output JSON as the formal artifact
* Treat Notion as knowledge/reference DB, not execution runtime
* Keep YAML split by layer when moving V2 configuration forward

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

Current active UI:

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

Current files:

```text
api_v2.py
app_v2.py
```

The previous dashboard UI, legacy API, legacy core line, and old AI/Ollama explanation path are outside active runtime.

Archive locations:

```text
archive/legacy_ai_path/
archive/legacy_core_line/
```

---

## Not Now

Do not implement these in the current phase:

* Timeline
* Attack Graph
* AI Explanation
* Response Guide UI
* SOC Queue
* Realtime
* WebSocket
* Multi-user
* RBAC
* MITRE Mapping
* Evidence Graph
* Investigation Workspace
* Notion synchronization engine
* automated response execution

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

Current priority:

```text
Preserve DetectionReport v2_minimal_0.1
Keep V2 runtime deterministic
Use pytest before cleanup merges
```

Current migration direction:

```text
single V2 YAML
↓
runtime layer separation
↓
physical YAML split
```

Next active split candidates:

```text
v2_attacks.yaml
v2_cluster_relations.yaml
```

---

## V2 Roadmap

* V2 runtime stabilization
* pytest safety net
* runtime rule separation
* YAML split
* response action redesign
* UI expansion

```
```
