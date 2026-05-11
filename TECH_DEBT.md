# TECH_DEBT

This file tracks intentionally deferred improvements,
future cleanup candidates, and architectural follow-up items.

These are not necessarily bugs.
Many are conscious tradeoffs made to preserve:
- deterministic behavior
- small runtime surface
- architecture clarity
- public alpha simplicity


## Data Engine

- Avoid double timestamp parsing in event_format_adapter.py
- Consider cached policy loading for record_minimizer.py
- Consider explicit partial parse_status in future
- Consider runtime eligibility debug export
- Consider parser warning categorization

## Naming consistency

- Consider renaming get_ip_events() to build_runtime_events_by_ip()
- Consider renaming parse_access_log_line() to parse_simple_access_log_line()
- Consider renaming get_raw_logs_by_run() to reflect minimized persisted records
- Consider clarifying parse_log_lines() skipped return semantics