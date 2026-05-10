# Data Layer Responsibility Audit

## Scope

This audit covers the current `data_layer` package:

- `data_layer/database.py`
- `data_layer/log_parser.py`
- `data_layer/analysis_repository.py`

It documents current responsibilities only. It does not recommend runtime
changes in this branch.

## Current V2 Flow

The active V2 API path uses `data_layer` before calling the deterministic V2
pipeline:

```text
POST /analyze-v2
-> data_layer.analysis_repository.create_run_from_text
-> data_layer.log_parser.parse_log_lines
-> data_layer.database.save_analysis_run
-> data_layer.database.save_raw_logs
-> data_layer.database.get_ip_events
-> core.v2_pipeline.run_v2_pipeline
```

`api_v2.py` also calls `data_layer.database.init_db` at import time.

## Module Responsibilities

### `log_parser.py`

Current responsibility:

- log parsing and normalization
- log format detection
- timestamp normalization to ISO-like strings
- conversion from raw text lines to normalized dictionaries

Supported parser paths include:

- simple five-field access logs
- common access logs
- combined access logs
- nginx-style error logs with optional client/request extraction

Active in V2:

- `parse_log_lines`
- parser helpers called by `parse_log_lines`

This module does not persist data and does not perform detection, scoring, risk
classification, or DetectionReport generation.

### `analysis_repository.py`

Current responsibility:

- ingestion orchestration
- converting submitted text/files into parsed log records
- creating an analysis run
- saving parsed logs as raw log rows
- returning parsed and skipped log records to callers

Active in V2:

- `create_run_from_text`

Not active in the current V2 API path, but potentially useful for upload flows:

- `create_run_from_files`
- `build_log_stats`

This module currently acts as an ingestion service over parser and persistence
functions. It does not own database schema and does not prepare the final
DetectionReport.

### `database.py`

Current responsibility:

- SQLite connection handling
- database initialization
- analysis run persistence
- raw log persistence
- analysis file persistence
- legacy detection/result persistence
- V2 pipeline input preparation from persisted raw logs

Active in V2:

- `init_db`
- `save_analysis_run`
- `save_raw_logs`
- `get_ip_events`

`get_ip_events` is the active bridge from persisted raw logs to V2 pipeline
input. It groups rows by source IP and converts timestamp strings back to
`datetime` objects before `run_v2_pipeline` receives the data.

Possibly legacy or unclear for the current V2 path:

- `create_analysis_file`
- `get_analysis_runs`
- `get_detections_by_run`
- `update_analysis_run_summary`
- `get_ip_timestamps`

The `detections` table and related functions appear to reflect older analysis
storage because current V2 output is the DetectionReport JSON, not stored rows in
`detections`. `save_analysis_run` is still active, but in V2 it is called with an
empty result list to create a run record before saving raw logs.

## Responsibility Boundary Findings

The current `data_layer` package mixes several boundaries:

- ingestion orchestration in `analysis_repository.py`
- raw log parsing and normalization in `log_parser.py`
- persistence and schema setup in `database.py`
- V2 input preparation in `database.get_ip_events`
- legacy analysis result storage in `database.py`

This mixing is structural. The active V2 behavior is still deterministic:
database reads and parser normalization prepare inputs, while detection decisions
remain in `core`.

## Recommended Future Direction

A future cleanup should consider introducing both an Ingestion Layer and a
Persistence Layer.

Recommended conceptual split:

```text
Ingestion Layer
-> parse raw text
-> normalize log records
-> create ingestion/run requests

Persistence Layer
-> initialize SQLite schema
-> save raw logs and run metadata
-> read stored logs/events

V2 Input Adapter
-> convert persisted raw log rows into events_by_ip for core/v2_pipeline.py
```

This does not require new abstractions immediately. If implemented later, the
split should be small and behavior-preserving:

- keep parser behavior unchanged
- keep database schema unchanged until a separate migration is planned
- keep `POST /analyze-v2` behavior unchanged
- keep `DetectionReport v2_minimal_0.1` unchanged
- move or rename functions only in a dedicated refactor branch

## Conclusion

`data_layer` currently represents ingestion, persistence, legacy analysis
storage, and V2 pipeline input preparation at the same time.

The most useful future architecture is both:

- an Ingestion Layer for parsing and orchestration
- a Persistence Layer for SQLite storage and retrieval

The V2 pipeline should continue receiving prepared `events_by_ip` data and
should not take on parsing, persistence, or database responsibilities.
