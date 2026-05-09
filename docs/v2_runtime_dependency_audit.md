# V2 Runtime Dependency Audit

Branch: `feature/v2-runtime-dependency-audit`

Purpose: identify which shared modules are still required by the active V2 MVP before any further cleanup. This is an audit only; no runtime code is changed here.

## Active V2 Entry Points

Active runtime boundary:

- `api_v2.py`
- `app_v2.py`
- `core/v2_pipeline.py`
- `core/v2_report_engine.py`
- `POST /analyze-v2`
- DetectionReport schema `v2_minimal_0.1`

`app_v2.py` does not import Core or data-layer modules. It posts log text to the configured API URL and renders returned DetectionReport fields only.

## Required Runtime Chain

Request flow:

1. `app_v2.py`
   - `requests.post(api_url, json={"log": log_text})`
   - renders returned DetectionReport with `pandas` and `streamlit`
2. `api_v2.py`
   - validates `AnalyzeV2Request`
   - calls `create_run_from_text`
   - calls `get_ip_events`
   - calls `run_v2_pipeline`
   - serializes datetime values with `json.dumps(..., default=str)`
3. `core/v2_pipeline.py`
   - loads V2 rules
   - detects signal findings
   - builds clusters and relations
   - builds attacks, scores, and risk
   - builds and saves DetectionReport
4. `core/v2_report_engine.py`
   - converts risk output into `v2_minimal_0.1`

## Shared Module Findings

### `data_layer/database.py`

Required by V2:

- `init_db`
  - called by `api_v2.py` at import/startup.
  - creates `analysis_runs`, `raw_logs`, and `analysis_files`, all currently needed by V2 ingestion.
- `save_analysis_run`
  - called by `create_run_from_text`.
  - V2 currently passes an empty `results` list and uses the returned `run_id`.
- `save_raw_logs`
  - called by `create_run_from_text`.
  - persists parsed log rows used by `get_ip_events`.
- `get_ip_events`
  - called by `api_v2.py`.
  - converts stored raw logs into the event shape consumed by `core/v2_pipeline.py`.
- `get_connection`
  - internal helper used by required functions.
- `DB_FILE`
  - internal path value derived from `DB_PATH`.

Clearly unused by active V2:

- `get_analysis_runs`
- `get_detections_by_run`
- `get_ip_stats`
- `get_ip_timestamps`
- `update_analysis_run_summary`
- `sql_in_values`, unless `get_ip_stats` remains

Possible simplification candidates:

- `save_analysis_run(results, source)` still contains legacy detection-summary insertion behavior. V2 only needs run creation metadata.
- `detections` table creation appears legacy-only after old API/UI removal.
- summary columns on `analysis_runs` (`total_ips`, `high_count`, `medium_count`, `low_count`) are legacy history/UI fields.
- `load_detection_rules` import is only used by `get_ip_stats`; if `get_ip_stats` is removed, this import can go too.

Keep shared for now:

- database initialization and raw log persistence are still the bridge between `api_v2.py` and `core/v2_pipeline.py`.

### `data_layer/analysis_repository.py`

Required by V2:

- `create_run_from_text`
  - called by `api_v2.py`.
  - calls `parse_log_lines`, `save_analysis_run`, and `save_raw_logs`.

Clearly unused by active V2:

- `create_run_from_files`
- `build_log_stats`
- `create_analysis_file` import, unless `create_run_from_files` remains

Possible simplification candidates:

- Split text-run creation from legacy multi-file upload helpers.
- Rename or narrow this module toward V2 ingestion once old multi-file behavior is no longer needed.

Keep shared for now:

- `create_run_from_text` is part of the active `/analyze-v2` path.

### `data_layer/log_parser.py`

Required by V2:

- `parse_log_lines`
  - called by `create_run_from_text`.
- Transitive parser helpers used by `parse_log_lines`:
  - `detect_log_format`
  - `parse_access_log_line`
  - `parse_common_access_log_line`
  - `parse_combined_access_log_line`
  - `parse_error_log_line`
  - `parse_timestamp`

Possible simplification candidates:

- Keep all currently supported formats unless a separate parser contract decision narrows V2 input.
- The parser remains shared ingestion infrastructure, not legacy UI/API code.

Keep shared for now:

- Required for V2 API log ingestion.

### `core/detection_rules.py`

Required by V2:

- `load_detection_rules("v2")`
  - called by `core/v2_pipeline.py`.
- `DETECTION_RULES_PATH_V2`
  - used through `RULE_PATHS["v2"]`.

Legacy compatibility still present:

- default `load_detection_rules()` uses `"classic"`.
- `RULE_PATHS["classic"]` points at `DETECTION_RULES_PATH`.
- `DETECTION_RULES_PATH` points at `config/timeseries_detection_rules.yaml`.

Possible simplification candidates:

- Require explicit rule type or make V2 the default after all classic callers are removed.
- Remove classic rule path support only after confirming no archived/runtime code imports it.

Keep shared for now:

- The loader is active V2 infrastructure.

### `core/config.py`

Required by V2:

- `PROJECT_ROOT`
- `CONFIG_DIR`
- `DATA_DIR`
- `DEBUG_DIR`
- `OUTPUT_DIR`
- `DETECTION_RULES_PATH_V2`
- `DB_PATH`

Legacy compatibility still present:

- `LOGS_DIR` has no active V2 reference found.
- `DETECTION_RULES_PATH` supports the classic rule path.

Possible simplification candidates:

- Remove `LOGS_DIR` if no non-archived runtime code references it.
- Remove `DETECTION_RULES_PATH` when classic rule loading is retired.
- Remove unused `OUTPUT_DIR` import from `core/v2_pipeline.py`; `core.output.save_output_json` already owns output path usage.

Keep shared for now:

- central paths are still used by V2 API, debug output, DetectionReport output, and rule loading.

### `requirements.txt`

Clearly active top-level V2 needs:

- `fastapi`
- `pydantic`
- `requests`
- `streamlit`
- `pandas`
- `PyYAML`
- `uvicorn`

Standard-library runtime dependencies not from requirements:

- `json`
- `sqlite3`
- `datetime`
- `pathlib`
- `re`
- `os`

Possible cleanup candidates after code cleanup stabilizes:

- `plotly` appears tied to the removed legacy dashboard.
- `scikit-learn`, `scipy`, `joblib`, and `threadpoolctl` have no active V2 imports found.
- `python-multipart` was needed by the removed legacy upload API, not by `/analyze-v2`.
- Many entries are likely transitive dependencies from a frozen environment. Prefer rebuilding requirements from direct V2 dependencies in a separate dependency-pruning branch.

Keep for now:

- Do not prune requirements in this audit branch.

## Suggested Next Cleanup Order

1. Remove unused active imports that have no behavior impact:
   - `OUTPUT_DIR` import in `core/v2_pipeline.py`
2. Simplify `data_layer/analysis_repository.py`:
   - remove `create_run_from_files`
   - remove `build_log_stats`
   - remove `create_analysis_file` import
3. Simplify `data_layer/database.py`:
   - remove history/detections helpers no longer used by active runtime
   - remove `get_ip_stats`, `get_ip_timestamps`, `update_analysis_run_summary`
   - remove `sql_in_values` and `load_detection_rules` import if no longer needed
4. Revisit database schema:
   - decide whether `detections` table and summary columns should remain for compatibility or be migrated out
5. Simplify rule/config compatibility:
   - remove classic rule path only after the shared DB cleanup no longer imports it
6. Rebuild `requirements.txt` from active V2 top-level dependencies in a dedicated branch.

## Verification Checklist

After each cleanup step:

- `venv/bin/python -m py_compile api_v2.py app_v2.py core/v2_pipeline.py core/v2_report_engine.py`
- Start `api_v2.py`
- Confirm `GET /health`
- Confirm `POST /analyze-v2`
- Confirm response contains `schema_version: v2_minimal_0.1`
- Start `app_v2.py` and confirm it renders Overview, IP Reports, and Findings
