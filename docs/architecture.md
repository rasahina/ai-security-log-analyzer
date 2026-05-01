AI Security Log Analyzer - Architecture Specification

---

## [Core Principle]

* Detection and scoring are handled by Python (deterministic logic)
* YAML is used only for response guides (no logic)
* AI is used only for explanation (never for decision making)

---

## [System Structure]

FastAPI:

* Log analysis backend
* Detection logic execution

Streamlit:

* UI / visualization
* User interaction

---

## [Responsibility Separation]

Python (Analyzer):

* Parse logs
* Detect patterns
* Assign risk score
* Generate attack_type

YAML (Response Guides):

* User-facing explanations
* Recommended actions
* No influence on detection

AI:

* Explanation only
* Not used for classification or scoring

---

## [Attack Type Management]

* attack_type is an internal key (English)
* Managed centrally via guides/index.yaml
* Multiple attack types allowed (comma-separated)
* Display limited to top 2 (based on priority)

Example:
Brute Force, Admin Access

---

## [Priority Rules]

* Priority is defined by the order in guides/index.yaml
* Top entries = higher priority

---

## [Event Generation]

* Event is generated from YAML title
* Not hardcoded in Python

Example:
title: "ブルートフォース攻撃"

→ event = "ブルートフォース攻撃"

---

## [Response Guide System]

* Loaded via get_guides(attack_type)
* Each attack_type maps to a YAML file
* Displayed in detail view only (not in table)

Structure:

* title
* plain_explanation
* immediate_actions
* short_term_actions
* long_term_actions
* escalation
* admin_support
* advanced_commands

---

## [UI Design]

Data separation:

* df → full internal data
* df_display → UI table

Table shows:

* ip
* event
* risk_label
* risk_score
* attack_type
* access_count
* recommended_action

Detail view shows:

* Response Guide
* Timeline
* AI Explanation (collapsed)

---

## [Detection Logic]

Implemented rules:

* Brute Force (failure rate + login attempts)
* Scanner (404 + suspicious paths)
* Admin Access (requires status 200/401/403)
* Burst Access (time-based clustering)
* Anomalous Timing (night access)
* Combined patterns:

  * Coordinated Brute Force
  * Automated Scanner
  * Suspicious Admin Timing

---

## [Important Rules]

* Do NOT use YAML for detection logic
* Do NOT use AI for decision making
* attack_type must match index.yaml exactly
* index.yaml is the single source of truth
* Do NOT remove response_guides from internal data

---

## [Current Limitations]

* Single file upload only
* No database persistence yet
* Correlation logic partially implemented

---

## [Next Phase]

* Introduce SQLite database
* Store analysis runs
* Support multi-file input
* Enable cross-log correlation

---

## END OF SPEC
