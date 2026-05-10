# V2 YAML Layer Responsibility Audit

## Scope

This audit covers the active V2 runtime path:

```text
api_v2.py
-> core/v2_pipeline.py
-> core/detection_rules.py
-> config/v2_detection_rules.yaml
```

Archived YAML under `archive/` and environment YAML from dependencies are not active
V2 runtime inputs.

## Active YAML Files

| YAML file | Active in V2 runtime | Loaded by | Notes |
| --- | --- | --- | --- |
| `config/v2_detection_rules.yaml` | Yes | `core/detection_rules.py` via `load_detection_rules("v2")` | Single active V2 rules/config file. |
| `config/detection_rules.yaml` | No for V2 | `core/detection_rules.py` only when `rule_type="classic"` | Classic path reference only. |
| `config/timeseries_detection_rules.yaml` | No for V2 | `core/detection_rules.py` only when `rule_type="classic"` | Classic path reference only. |

## Python Load Path

`core/v2_pipeline.py` calls:

```python
rules = load_detection_rules("v2")
```

`core/detection_rules.py` maps that rule type to:

```python
DETECTION_RULES_PATH_V2
```

`core/config.py` defines:

```python
DETECTION_RULES_PATH_V2 = CONFIG_DIR / "v2_detection_rules.yaml"
```

The V2 UI (`app_v2.py`) does not load YAML. It calls the API and renders the
DetectionReport response.

## Current Responsibility Mapping

`config/v2_detection_rules.yaml` currently combines several layers in one file:

| YAML section | Current responsibility | Target layer |
| --- | --- | --- |
| `paths` | Shared path groups used by signal filters. | Signal support data |
| `signals` | Signal definitions, filters, windows, and thresholds. | `signals` |
| `signal_clusters` | Required/optional signal groupings and cluster parameters. | `signal_clusters` |
| `attacks` | Cluster-to-attack mapping and attack base scores. | `attacks` |
| `score` | Global scoring caps. | Scoring config, outside the four knowledge layers |
| `risk` | Risk level thresholds. | Risk config, outside the four knowledge layers |
| `cluster_relation` | Suspicious activity absorption parameters. | Cluster relation config, adjacent to `signal_clusters` |

The active YAML does not yet cleanly map one file to each of:

- `signals`
- `signal_clusters`
- `attacks`
- `response_actions`

Instead, the active V2 runtime uses one combined YAML file containing signal,
cluster, attack, score, risk, and relation configuration.

## Procedural Logic Check

The YAML is mostly declarative configuration:

- signal filters (`status`, `status_in`, `path_group`, `any`)
- thresholds and windows
- required and optional signal names
- confidence and intensity parameters
- cluster-to-attack references
- score and risk thresholds

No executable code, ordered procedures, or response playbooks were found in the
active V2 YAML.

The closest behavior-shaping fields are:

- `fallback: true`
- `absorb_lift`
- `overlap_strategy`
- `base_score`
- score/risk thresholds

These are configuration values consumed by Python logic. They are not standalone
procedural logic in YAML.

## Response Actions

No active V2 YAML section currently defines `response_actions`.

No active V2 YAML entry attaches response manuals, operational procedures, or
execution instructions to attacks. Therefore, response actions are not mixed into
the active attack definitions, but the intended response action reference layer
is also not present yet.

## Layer Mixing Assessment

The active YAML mixes multiple responsibility layers in a single file:

- signal definitions and supporting path groups
- signal cluster definitions
- attack mappings and scoring metadata
- score/risk thresholds
- cluster relation parameters

The concepts are separated by top-level YAML sections, so the mixing is
structural rather than semantic. The file is not split into the intended
`config/v2/` layer files yet.

## Runtime Observations

`config/v2_detection_rules.yaml` uses `metric_type` in signal definitions, while
`core/timeseries_signal_detector.py` currently dispatches ratio handling from
`type` and defaults to count behavior. This audit does not change that behavior.

`cluster_relation.suspicious_activity.max_confidence` and
`cluster_relation.suspicious_activity.overlap_strategy` are present in YAML, but
the active relation engine currently consumes `absorb_lift` for suspicious
activity confidence adjustment.

## Conclusion

The active V2 YAML is deterministic and does not contain procedural response
logic. It does not yet cleanly map to the planned four-file layer model:

```text
signals
signal_clusters
attacks
response_actions
```

The current state is a single combined V2 config file with clear top-level
sections. A future YAML split can be done as a separate migration, but this audit
does not recommend changing runtime behavior, DetectionReport schema, detection
logic, or loaders.
