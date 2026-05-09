# Legacy Cleanup Plan

Branch: `feature/legacy-cleanup-audit`

Purpose: identify safe cleanup candidates before removing the legacy analysis line. This is an audit only; do not remove legacy code until the V2 MVP is verified after each cleanup step.

## V2 MVP Boundary

Keep these files and contracts intact:

- `api_v2.py`
- `app_v2.py`
- `core/v2_pipeline.py`
- `core/v2_report_engine.py`
- `output/detection_report_v2.json`
- `config/v2_detection_rules.yaml`
- DetectionReport schema version `v2_minimal_0.1`
- `POST /analyze-v2`

V2 runtime dependencies currently required by `api_v2.py` and `core/v2_pipeline.py`:

- `data_layer/analysis_repository.py`
  - `create_run_from_text`
- `data_layer/database.py`
  - `init_db`
  - `save_analysis_run`
  - `save_raw_logs`
  - `get_ip_events`
  - table setup for `analysis_runs`, `raw_logs`, and `analysis_files`
- `data_layer/log_parser.py`
  - `parse_log_lines`
- `core/detection_rules.py`
  - `load_detection_rules("v2")`
- `core/config.py`
  - `CONFIG_DIR`, `DEBUG_DIR`, `OUTPUT_DIR`, `DB_PATH`, `DETECTION_RULES_PATH_V2`
- V2 detection stack:
  - `core/timeseries_signal_detector.py`
  - `core/cluster_engine.py`
  - `core/cluster_relation_engine.py`
  - `core/attack_engine.py`
  - `core/score_engine.py`
  - `core/risk_engine.py`
  - `core/debug.py`
  - `core/outout.py`

`app_v2.py` is display-only and depends on `requests`, `pandas`, and `streamlit`. It does not import Core modules directly.

## Legacy Line Candidates

These appear to belong to the old API/UI line and are not required by `api_v2.py`, `app_v2.py`, `core/v2_pipeline.py`, or `core/v2_report_engine.py`.

| Candidate | Current role | Cleanup note |
| --- | --- | --- |
| `api.py` | Legacy FastAPI app with `/analyze`, `/analyze-file`, `/analyze-files`, `/history`, `/results` | Remove only after confirming no local workflow depends on old endpoints. |
| `app.py` | Legacy Streamlit dashboard with history, timeline, AI, response guide rendering | Remove after V2 viewer is accepted as the active UI. |
| `client/api_client.py` | Client for legacy `api.py` routes | Remove with `app.py`/`api.py`. |
| `ui/components.py` | Legacy dashboard components, timeline, response guide, AI UI | Remove with `app.py`. |
| `core/analyzer.py` | Legacy orchestration combining old scoring, guides, and partial V2 debug flow | Remove only after `api.py` is removed. |
| `core/scoring.py` | Classic score/risk helpers | Legacy-only via `core/analyzer.py`. |
| `core/attack_detector.py` | Classic signal-to-attack helper | Legacy-only via `core/analyzer.py`. |
| `core/response_guides.py` | Loads response guide YAML and formats actions/events | Legacy UI/API response-guide path. Not part of V2 MVP. |
| `core/correlation.py` | Imported by legacy analyzer | No V2 references found. |
| `core/time_series.py` | Legacy UI timeline helper | No V2 references found. |
| `ai_explainer.py` | Legacy AI/Ollama explanation path | Not part of V2 MVP. |
| `security/ai_guard.py` | Legacy AI payload sanitizer/log writer | Not part of V2 MVP. |
| `sanitizer.py` | AI explanation sanitizer dependency | Remove with `ai_explainer.py`. |
| `prompts/detection_prompt.txt` | Legacy AI prompt | Remove with `ai_explainer.py`. |
| `guides/` | Legacy response-guide YAML content | Remove only after confirming response guide UI/API are retired. |
| `config/timeseries_detection_rules.yaml` | Classic rule path used by default `load_detection_rules()` | Remove after legacy analyzer/scoring/database stats are gone. |
| `config/detection_rules.yaml` | No direct references found in current code | Candidate for earlier removal after one final search. |
| `output/result.json` | Legacy `/results` artifact | Remove with `api.py` `/results`. |

## Shared Files To Keep For Now

Do not remove these during the first cleanup pass:

- `data_layer/database.py`: contains V2-required storage and `get_ip_events`; legacy summary/history functions can be split or removed later.
- `data_layer/analysis_repository.py`: `create_run_from_text` is required by `api_v2.py`; `create_run_from_files` and `build_log_stats` are legacy candidates after old upload UI removal.
- `data_layer/log_parser.py`: required by V2 ingestion.
- `core/detection_rules.py`: required by V2 rule loading; default classic behavior can be simplified only after legacy removal.
- `requirements.txt`: includes dependencies for both old and V2 lines; prune only after code removal.
- `data/*.log`: keep sample logs until V2 verification fixtures are formalized.
- `output/detection_report_v2.json`: formal V2 output artifact.

## Generated / Cache Artifacts

Safe cleanup candidates:

- untracked `__pycache__/` directories and `.pyc` files
- ignored `debug/*_v2.json` and `debug/debug_*.json` files
- tracked `screenshots/FinalProductImage.png:Zone.Identifier`

The Zone.Identifier file is a Windows sidecar and should be removed in a separate tiny cleanup commit.

## Suggested Cleanup Order

1. Remove generated/cache artifacts only.
2. Remove legacy AI path: `ai_explainer.py`, `security/ai_guard.py`, `sanitizer.py`, `prompts/detection_prompt.txt`, and related legacy UI references by removing the old UI first.
3. Remove legacy presentation/client line: `app.py`, `ui/components.py`, `client/api_client.py`, screenshots if no longer needed.
4. Remove legacy API line: `api.py`, `output/result.json`, history/result route expectations.
5. Remove legacy core orchestration and helpers: `core/analyzer.py`, `core/scoring.py`, `core/attack_detector.py`, `core/response_guides.py`, `core/correlation.py`, `core/time_series.py`.
6. Simplify shared modules only after the old line is gone:
   - remove `get_ip_stats`, `get_ip_timestamps`, `get_analysis_runs`, `get_detections_by_run`, `update_analysis_run_summary` if no longer referenced
   - remove `create_run_from_files` and `build_log_stats` if no V2 UI/API uses multi-file upload stats
   - simplify `load_detection_rules()` to require explicit V2 loading or keep a compatibility wrapper
7. Prune legacy YAML and requirements after imports are clean.

## Verification After Each Removal

- `venv/bin/python -m py_compile api_v2.py app_v2.py core/v2_pipeline.py core/v2_report_engine.py`
- Start `api_v2.py` and verify `GET /health`
- POST sample logs to `/analyze-v2`
- Confirm response includes `schema_version: v2_minimal_0.1`
- Confirm `output/detection_report_v2.json` is generated
- Start `app_v2.py` and confirm it renders Overview, IP Reports, and Findings from the API response
