# Codex Task Template

Use this template for small, deterministic repository tasks. Keep each task to
one responsibility and make the expected verification explicit.

## Repository

```text
Repository:
rasahina/ai-security-log-analyzer

Use latest main.
```

## Branch

```text
Create branch:
feature/<short-task-name>
```

## Task

```text
Task:
<Describe the concrete change.>
```

## Goal

```text
Goal:
<Explain the intended outcome and why the change is needed.>
```

## Preserve

List public behavior, contracts, and active runtime files that must remain
stable. Include any relevant items from this baseline:

```text
Preserve:
- api_v2.py behavior
- app_v2.py behavior
- POST /analyze-v2
- core/v2_pipeline.py
- DetectionReport v2_minimal_0.1
- current parser behavior
- current database schema
- current YAML loading behavior
```

## Constraints

```text
Constraints:
- Keep diff small
- Preserve deterministic behavior
- Preserve DetectionReport v2_minimal_0.1
- No unrelated cleanup
- No broad rewrites
- No new abstraction layers unless explicitly requested
- Do not modify detection/evaluation logic unless explicitly requested
- Do not modify DB schema unless explicitly requested
- Do not modify YAML unless task is YAML-specific
```

## Architecture Sync

`ARCHITECTURE.md` synchronization is required when a task changes any of:

- runtime structure
- layer responsibility
- file paths
- public contracts

README updates are optional and should only be made when external usage changes,
such as commands, setup, API usage, or user-facing behavior.

## Verification

Use the repository virtual environment when available:

```bash
venv/bin/python -m pytest
venv/bin/python -m py_compile api_v2.py app_v2.py core/v2_pipeline.py core/yaml_loader.py data_layer/database.py data_layer/log_parser.py data_layer/event_format_adapter.py
```

If the task explicitly asks for generic commands, these are the standard
equivalents:

```bash
python -m pytest
python -m py_compile api_v2.py app_v2.py core/v2_pipeline.py core/yaml_loader.py data_layer/database.py data_layer/log_parser.py data_layer/event_format_adapter.py
```

Add targeted runtime checks when API, UI, ingestion, or output behavior changes.

## Merge Notes

Before merge, include:

- branch name
- commit hash
- files changed
- verification results
- any generated files intentionally excluded from the commit
- any known follow-up tasks

Origin feature branches may remain after merge. Deleting remote feature branches
is optional and can be handled separately.
