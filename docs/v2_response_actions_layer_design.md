# V2 Response Actions Layer Design

## Purpose

The future V2 `response_actions` layer should define stable response action
references that attacks may point to. It must not add runtime behavior,
operational playbooks, or execution instructions to detection.

This is a design note only. The active runtime still loads
`config/v2_detection_rules.yaml` exactly as it does today, and no
`response_actions` YAML section exists yet.

## Intended Model

Attacks may later reference response action IDs:

```yaml
attacks:
  brute_force:
    response_actions:
      - block_ip
      - review_auth_logs
      - reset_password
```

Those IDs should be references to response knowledge, not embedded procedures.
The detection pipeline can carry or expose the references only after a separate
schema/runtime change is designed and approved.

Example response action IDs:

- `block_ip`
- `review_auth_logs`
- `reset_password`
- `enable_waf`
- `add_rate_limit`

## Responsibility Boundary

`response_actions` should contain stable identifiers and lightweight metadata,
such as display names, categories, or links to external knowledge records.

`response_actions` must not contain:

- command execution steps
- firewall or identity-provider procedures
- branching incident workflows
- detection conditions
- score, risk, or clustering logic
- UI rendering behavior

Detailed response manuals belong outside runtime detection, for example in a
Notion response-action database or another knowledge DB. Runtime Python remains
responsible for deterministic behavior. YAML provides configuration and
references only.

## DetectionReport Boundary

The current `DetectionReport` schema is `v2_minimal_0.1` and must remain stable
until a separate schema change is made.

The UI should continue to display only DetectionReport data. It should not infer
response actions from attack names, calculate response decisions, or load
response manuals directly from YAML.

## Why References Only

Response actions must stay as references because execution instructions would
mix operational response logic into deterministic detection configuration. That
would make behavior harder to audit, couple detection to environment-specific
procedures, and risk turning static YAML into hidden workflow logic.

Keeping response actions as IDs preserves the separation:

```text
AttackFinding
-> response_action IDs
-> external response knowledge/manuals
```

Detection decides what happened. Response knowledge explains what an operator
may do next.
