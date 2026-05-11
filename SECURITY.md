# Security Policy

## Public Alpha Status

AI Security Log Analyzer is an experimental public alpha and MVP runtime
skeleton. It is not a production security product, SIEM, SOC platform, or
incident response automation system.

Use it only in controlled environments and review results before making security
decisions.

## Supported Versions

Only the current `main` branch is in scope for public alpha security reports.
Older branches, archived code under `archive/`, and experimental feature
branches are not supported.

## Reporting a Vulnerability

Please report security issues through GitHub private vulnerability reporting if
enabled for the repository. If that is unavailable, open a GitHub issue with a
minimal description and avoid posting exploit details, private logs, secrets, or
credentials.

Useful reports include:

- affected file or endpoint
- reproduction steps using synthetic data
- expected behavior
- observed behavior
- impact assessment

## Security Boundaries

The active V2 runtime is deterministic. AI/LLM logic is not part of detection,
scoring, risk evaluation, or response decisions.

Current non-goals:

- production incident response automation
- autonomous blocking or remediation
- AI/LLM-based detection decisions
- secret scanning or data loss prevention
- log masking, sanitizer, or AI Guard behavior
- multi-user security controls such as RBAC

Logs are treated as untrusted input. Do not submit real secrets, credentials, or
sensitive customer data to public issues or examples.
