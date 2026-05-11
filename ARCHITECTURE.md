# Architecture

## Current Phase

The V2 MVP is the active runtime path:

```text
app_v2.py
↓
api_v2.py
↓
Ingestion / Normalization
↓
Persistence
↓
Event Format Adapter
↓
Detection Pipeline V2
↓
Evaluation Layer
↓
Interpretation Layer
↓
DetectionReport
```

The active implementation is:

```text
app_v2.py
api_v2.py
data_layer/log_parser.py
data_layer/database.py
data_layer/event_format_adapter.py
core/v2_pipeline.py
core/v2_report_engine.py
```

Current schema:

```text
v2_minimal_0.1
```

The legacy UI/API/Core/AI lines have been removed from the public alpha runtime.

---

## V2 Layer Model

V2 uses the following major layers:

```text
Ingestion / Normalization Layer
↓
Persistence Layer
↓
Event Format Adapter
↓
Detection Layer
↓
Evaluation Layer
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
* attacks
* response actions

The analyzer should treat these as structured knowledge sources, not free-form document notes.

Core detection logic must still remain in Python.

Notion databases are used for knowledge management and reference data, not procedural execution logic.

---

## Data Engine

The Data Engine prepares deterministic, safe, and consistent runtime events
before Core Detection.

Responsible for:

* log parsing
* normalization
* minimization / sanitization
* persistence
* event format adaptation
* Canonical Runtime Event preparation

Detection logic must not exist in the Data Engine. Detection semantics, scoring,
and risk evaluation belong to Core Detection and Evaluation layers.

Processing flow:

```text
Raw Log Input
↓
Line Split
↓
Format Detection
↓
Parser
↓
Minimizer / Sanitizer
↓
Persistence
↓
Event Format Adapter
↓
Canonical Runtime Event
↓
Detection Engine
```
### Parser

Extracts minimal observation fields from untrusted input.

Must not:

* perform detection logic
* assign attack meaning
* calculate score or risk

### Log Format and Log Type Boundary

`log_format` is a parser-level input format classification.

Examples:

* `common_access`
* `combined_access`
* `simple_access`
* `error_log`

It is used for:

* parsing
* parser debugging
* traceability

`log_format` is not intended as a Core Detection semantic field.

`log_type` is a runtime-level event category.

Examples:

* `access`
* `error`

It is used by:

* Canonical Runtime Event
* Detection Engine

Parser may emit both `log_format` and `log_type`.
Persistence may store both when useful.
Canonical Runtime Event should include `log_type`.
Core Detection should not depend on parser-specific `log_format` by default.


### Minimizer / Sanitizer

Removes unnecessary or dangerous retained data, minimizes attacker-controlled
free text, and supports the AI-safe direction.

Must not:

* decide whether an attack occurred
* perform scoring or risk evaluation
* add hidden behavior or procedural logic

### Persistence

Stores minimized records only. Traceability should primarily rely on:

* `file_id`
* `line_number`

Persistence is not intended as a SIEM-scale raw log warehouse.

### Event Format Adapter

Validates runtime eligibility, converts timestamps to timezone-aware UTC runtime
datetimes, and produces Canonical Runtime Events.

The adapter must not guess missing timezone information.

### Canonical Runtime Event

Deterministic runtime-safe structure and the only trusted Core input shape.

Core Detection consumes Canonical Runtime Events only.

Design principles:

* no hidden assumptions
* no timezone guessing
* attacker-controlled input remains untrusted
* minimal retention preferred
* YAML must not contain procedural logic
* Core Detection consumes Canonical Runtime Events only

---

## Data Layer Model

The `data_layer` package is responsible for preparing external log input before it reaches the deterministic V2 core.

Current files:

```text
data_layer/log_parser.py
data_layer/database.py
data_layer/event_format_adapter.py
```

Responsibilities:

```text
log_parser.py
= raw log parsing and normalization

database.py
= SQLite persistence, schema initialization, raw log/run storage

event_format_adapter.py
= conversion from persisted log records to Core Engine input shape
```

The Core Engine expects:

```text
events_by_ip
```

The Event Format Adapter owns the boundary between persisted log rows and this runtime input shape.

Internal runtime timestamps are timezone-aware UTC datetimes. The runtime does
not silently guess missing timezone information; persisted rows with naive
timestamps are skipped at the Event Format Adapter boundary.

Detection logic must not be placed in `data_layer`.

Masking, sanitization, and AI Guard behavior may be introduced later as a separate boundary before persistence or before AI exposure, but they must not be mixed into detection logic.

---

## Data Layer Event Contract

Canonical flow:

```text
Raw Log Line
-> Parsed Log Record
-> Persisted Raw Log Row
-> Canonical Runtime Event
-> Detection Pipeline V2
```

### Raw Log Line

Original untrusted text input.

Responsible for:

* providing parser input
* preserving future evidence traceability

Must not:

* carry detection meaning
* affect scoring, risk, or attack interpretation directly
* be trusted as structured runtime data

### Parsed Log Record

Dictionary produced by `data_layer/log_parser.py`.

Expected fields may include:

* `timestamp`
* `ip`
* `method`
* `url`
* `status`
* `line_number`
* `user_agent`
* `error_message`
* `log_type`
* `level`

Responsible for:

* representing extracted parser output
* carrying parser limitations explicitly through missing or partial fields

Must not:

* be treated as a trusted Core runtime event
* contain detection semantics
* perform scoring, risk, or attack interpretation

### Persisted Raw Log Row

SQLite storage representation of parsed records.

Responsible for:

* preserving parsed fields for an analysis run
* supporting retrieval by run
* remaining persistence-only

Must not:

* introduce detection semantics
* reinterpret parser output
* infer missing timezone information

### Canonical Runtime Event

Event object passed to Core Detection through `events_by_ip`.

Responsible for:

* grouping events by source IP
* carrying `line_number` for minimal evidence traceability when available
* containing only fields needed by deterministic Core Detection
* using timezone-aware UTC `datetime` values for `timestamp`
* excluding naive, malformed, or incomplete timestamp records at the Event Format Adapter boundary

Must not:

* guess missing timezone information
* contain scoring, risk, or attack interpretation
* expose SQLite row details to Core Detection

Core Detection consumes Canonical Runtime Events only. Detection logic must not
exist in the parser, persistence layer, or event adapter.

### Data Layer Contract Invariants

* Same input should produce the same parsed, persisted, and runtime event shape.
* Runtime timestamps are timezone-aware UTC datetimes only.
* Missing timezone information is not silently guessed.
* Malformed or incomplete records must not silently become trusted runtime events.
* Detection semantics begin in Core Detection, not in the Data Layer.
* Parser, persistence, and adapter responsibilities must remain separate.

---

## Data Layer Minimal Retention Policy

The Data Layer should keep only information required for:

* deterministic detection
* explainable evidence
* minimal investigation traceability

This analyzer is not a full log warehouse or SIEM storage platform.

Raw attacker-controlled text should be minimized. `raw_line` should not be
persisted by default. Traceability should primarily rely on:

* `file_id`
* `line_number`

The Data Layer should avoid unnecessary retention of:

* full raw logs
* cookies
* authorization headers
* request bodies
* unnecessary free text
* excessive user identifiers

Attacker-controlled fields are untrusted input at every stage:

```text
Raw Log Line
-> Parsed Log Record
-> Persisted Raw Log Row
-> Canonical Runtime Event
```

Minimal normalized observations are preferred over broad raw-data retention.

Smaller trusted runtime data reduces:

* AI exposure risk
* accidental sensitive data retention
* prompt injection surface
* storage complexity

Retention choices must not introduce detection semantics before Core Detection.

---

## YAML Runtime Configuration Model

The active V2 runtime no longer uses a single combined YAML file.

Runtime configuration is now separated by responsibility.

Current runtime files:

```text
config/v2_signals.yaml
config/v2_clusters.yaml
config/v2_attacks.yaml
config/v2_evaluation_rules.yaml
```

The previous combined runtime file:

```text
config/v2_detection_rules.yaml
```

is no longer used by the active runtime.

Current runtime loading is centralized through:

```text
core/yaml_loader.py
```

Current runtime config separation:

```text
v2_signals.yaml
= signal detection configuration

v2_clusters.yaml
= SignalFinding → SignalCluster mapping

v2_attacks.yaml
= Cluster relation semantics and AttackFinding mapping

v2_evaluation_rules.yaml
= score and risk evaluation policy
```

YAML files are deterministic runtime configuration snapshots.

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

## Ingestion / Normalization Layer

Responsible for converting raw log text into normalized log records.

Current runtime file:

```text
data_layer/log_parser.py
```

Responsibilities:

* log format detection
* access log parsing
* error log parsing
* timestamp normalization
* raw text line to normalized dictionary conversion

This layer does not perform detection, scoring, risk evaluation, or DetectionReport generation.

---

## Persistence Layer

Responsible for SQLite storage and retrieval.

Current runtime file:

```text
data_layer/database.py
```

Responsibilities:

* DB initialization
* schema creation
* analysis run storage
* raw log storage
* analysis file storage
* persisted log retrieval support

Persistence does not perform detection.

---

## Event Format Adapter

Responsible for converting persisted log records into the input shape required by V2 Core.

Current runtime file:

```text
data_layer/event_format_adapter.py
```

Responsibilities:

* read persisted normalized log records
* group events by source IP
* convert timezone-aware timestamp strings into UTC runtime datetime values
* produce `events_by_ip` for `core/v2_pipeline.py`

This adapter exists so that Core Engine does not need to know about SQLite rows or upload formats.

---

## Detection Layer

Responsible for deterministic detection semantics.

Current flow:

```text
SignalFinding
↓
SignalCluster
↓
ClusterRelation
↓
AttackFinding
```

Current runtime files:

```text
core/timeseries_signal_detector.py
core/cluster_engine.py
core/cluster_relation_engine.py
core/attack_engine.py
```

---

## Signal Layer

Responsible for deterministic event pattern detection.

Produces:

```text
SignalFinding
```

Current runtime config:

```text
config/v2_signals.yaml
```

Current runtime content:

* paths
* signals

`paths` belongs to the signal layer because signal filters depend on shared path groups.

---

## Cluster Layer

Responsible for grouping SignalFindings into SignalClusters.

Produces:

```text
SignalCluster
```

Current runtime config:

```text
config/v2_clusters.yaml
```

Current runtime content:

* signal_clusters

---

## Attack Layer

Responsible for attack preparation semantics and AttackFinding generation.

Produces:

```text
AttackFinding
```

Current runtime config:

```text
config/v2_attacks.yaml
```

Current runtime content:

```text
cluster_relation
attacks
```

Responsibilities:

* cluster overlap resolution
* absorbed semantics
* fallback candidate handling
* suspicious activity semantics
* confidence adjustment
* AttackFinding mapping
* attack metadata
* source_cluster mapping
* base attack scoring metadata

Important:

`cluster_relation_engine` intentionally references:

```text
attacks.*.source_cluster
```

This is intentional runtime behavior.

The attack layer therefore acts as the transition layer between:

```text
SignalCluster
↓
AttackFinding
```

The attack layer currently contains most higher-level detection semantics.

The actual AttackFinding mapping layer is intentionally thin.

---

## Evaluation Layer

Responsible for severity and importance evaluation.

Produces:

```text
Score
Risk
```

Current runtime config:

```text
config/v2_evaluation_rules.yaml
```

Current runtime content:

```text
score
risk
```

Responsibilities:

* attack score calculation
* risk level thresholds
* severity evaluation
* environment tuning
* evaluation policy

Evaluation is intentionally separated from deterministic detection semantics.

Current runtime files:

```text
core/score_engine.py
core/risk_engine.py
```

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
raw log text
→ normalized log records
→ persisted raw logs
→ events_by_ip
→ SignalFinding
→ SignalCluster
→ ClusterRelation
→ AttackFinding
→ Score
→ Risk
→ DetectionReport
```

Current implementation files:

```text
data_layer/log_parser.py
data_layer/database.py
data_layer/event_format_adapter.py
core/timeseries_signal_detector.py
core/cluster_engine.py
core/cluster_relation_engine.py
core/attack_engine.py
core/score_engine.py
core/risk_engine.py
core/v2_pipeline.py
core/v2_report_engine.py
```

Current runtime config loading:

```text
load_yaml_config("signals")
load_yaml_config("clusters")
load_yaml_config("attacks")
load_yaml_config("evaluation")
```

Current runtime loader:

```text
core/yaml_loader.py
```

Active API boundary:

```text
api_v2.py
POST /analyze-v2
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

* AI is not part of deterministic detection
* AI does not participate in detection semantics
* AI does not participate in scoring or risk evaluation
* AI reads DetectionReport
* AI performs assistance, not detection
* AI is an assistant, not a decision maker
* AI provider independence must be preserved
* Bring Your Own AI is the default strategy
* Users should run AI within their own environment
* The system must function without AI
* Explainability evidence must originate from deterministic runtime logic


The analyzer itself should remain AI-provider neutral.

Users should be able to use external AI systems without changing the analyzer runtime.


---

## Project Rules

* Do not put logic in YAML
* Do not put procedural logic in Notion
* Do not put detection logic in `data_layer`
* Do not put persistence logic in Core Engine
* Do not put large logic in `analyzer.py`
* Keep Ingestion / Persistence / Adapter / Detection / Evaluation / Interpretation / UI separated
* Implement small changes
* Confirm with debug JSON
* Treat output JSON as the formal artifact
* Treat Notion as knowledge/reference DB, not execution runtime
* Preserve deterministic behavior
* Preserve DetectionReport stability

---

## Debug and Output

Debug files:

```text
debug/
```

Used for intermediate JSON inspection.

Generated runtime output:

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

The previous dashboard UI, legacy API, legacy core line, and old AI/Ollama
explanation path are outside the public alpha runtime.

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

Current active runtime separation:

```text
ingestion / normalization
↓
persistence
↓
event format adapter
↓
detection
↓
evaluation
↓
interpretation
↓
DetectionReport
```

---

## V2 Roadmap

* V2 runtime stabilization
* pytest safety net
* YAML runtime separation
* Detection / Evaluation separation
* Data layer responsibility separation
* response action redesign
* UI expansion

```
```
