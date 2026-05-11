# DESIGN_PRINCIPLES.md

## Purpose

This document describes the core engineering and architectural principles of the AI Security Log Analyzer project.

It explains:

* why the system is designed this way
* what tradeoffs are intentional
* what architectural boundaries must be preserved
* how detection, evidence, and runtime responsibilities are separated

This file focuses on design philosophy and engineering principles.

Implementation details belong in:

* ARCHITECTURE.md
* source code
* config/
* tests/

---

# Core Philosophy

## Observable-First

The system is designed around observable telemetry.

Detection logic should rely on information that is actually present in logs,
not on speculative assumptions.

Examples of preferred observable signals:

* request frequency
* HTTP method usage
* path access patterns
* status codes
* source IP behavior
* timing relationships
* repeated failures

Examples of intentionally avoided assumptions:

* attacker intent
* device identity
* user identity certainty
* session ownership assumptions
* hidden infrastructure state
* endpoint telemetry not present in logs

The project prioritizes:

* explainable evidence
* observable behavior
* deterministic reasoning

instead of:

* black-box inference
* speculative attack reconstruction
* opaque scoring systems

---

## Deterministic Runtime

Core runtime behavior must remain deterministic.

Given the same:

* logs
* configuration
* YAML
* runtime version

The system should produce the same:

* signals
* clusters
* attack findings
* evaluations
* DetectionReports

The project intentionally avoids:

* hidden heuristics
* probabilistic runtime behavior
* AI-generated detection decisions
* non-reproducible scoring behavior

Deterministic behavior improves:

* explainability
* debugging
* testability
* analyst trust
* operational predictability

---

## Explainable Detection

Detection results must be explainable.

Analysts should be able to understand:

* what triggered
* why it triggered
* which observations contributed
* which runtime events were involved

The project prioritizes:

* explicit evidence
* stable signal behavior
* traceable runtime flow
* transparent evaluation logic

The system should avoid:

* opaque confidence systems
* unexplained classifications
* hidden attack assumptions
* fake certainty

---

## No Fake Certainty

The system must not imply certainty that it cannot justify from observable evidence.

Examples:

The system may say:

* suspicious scanning behavior observed
* repeated failed login attempts observed
* access pattern resembles enumeration

The system should avoid claims such as:

* attacker successfully compromised host
* attacker intent confirmed
* malware infection confirmed
* user account definitively stolen

unless directly supported by observable evidence.

---

# AI Separation Philosophy

## AI Is Outside the Core Runtime

AI is intentionally separated from:

* Data Engine
* Detection Engine
* Evaluation Engine

The core runtime must function fully without AI.

The system architecture follows a:

* Bring Your Own AI (BYO AI)

model.

Users may optionally:

* export DetectionReports
* use external LLMs
* generate summaries externally
* perform AI-assisted investigation workflows

However:

* AI must not determine signals
* AI must not determine risk
* AI must not determine attack classification
* AI must not replace deterministic runtime behavior

---

## AI Output Is Untrusted

Even when external AI systems are used:

* AI output must be treated as untrusted
* AI explanations are not authoritative evidence
* AI summaries must not replace runtime evidence

The runtime remains the canonical source of:

* signals
* evidence
* runtime telemetry
* evaluation results

---

# Data Engine Principles

## Data Engine Responsibilities

The Data Engine is responsible for:

* log parsing
* normalization
* minimization
* persistence
* runtime eligibility
* Canonical Runtime Event construction

The Data Engine is not responsible for:

* attack detection
* scoring
* risk evaluation
* attack interpretation
* AI reasoning

---

## Minimal Retention

The project intentionally minimizes retained data.

The system is not intended to become:

* a SIEM data lake
* a long-term log warehouse
* a raw telemetry archive

Retention should preserve only what is necessary for:

* deterministic detection
* explainable evidence
* minimal traceability
* runtime debugging

The project intentionally avoids unnecessary retention of:

* raw log lines
* cookies
* authorization headers
* request bodies
* unnecessary attacker-controlled free text
* excessive user identifiers

---

## Persistence-Safe vs Core-Safe

A persisted record is not automatically eligible for Core Detection.

The system separates:

* what may be retained
* what may enter Core Detection

Examples of persisted but runtime-ineligible records:

* malformed timestamps
* timezone-naive timestamps
* non-parsed records
* records missing source IPs

This separation helps prevent:

* Detection Engine pollution
* noisy signal generation
* false correlation
* broken event ordering

---

## Canonical Runtime Event

Core Detection consumes only Canonical Runtime Events.

Canonical Runtime Events represent:

* normalized
* runtime-safe
* deterministic
* observable telemetry

Canonical Runtime Events must not contain:

* persistence-only metadata
* runtime exclusion metadata
* scoring data
* attack interpretation
* AI-generated semantics

Canonical Runtime Events are runtime contracts,
not configurable policy objects.

---

# Evidence and Interpretation Model

## Runtime Event

A Canonical Runtime Event represents:

* a normalized observable runtime event
* trusted Core Detection input
* runtime telemetry only

It is not itself a security conclusion.

---

## SignalFinding

A SignalFinding represents:

* a direct observable detection
* primary runtime evidence

Examples:

* repeated 404 responses
* repeated failed login attempts
* suspicious path access
* scanner-like request frequency

Signals should remain:

* explainable
* deterministic
* observable-first

---

## SignalCluster

A SignalCluster represents:

* grouped signal evidence
* correlated runtime behavior

Clusters aggregate multiple SignalFindings into:

* higher-level observable behavior

Clusters are still evidence.

They are not final attack interpretation.

---

## ClusterRelation

A ClusterRelation represents:

* relationships between clusters
* timing relationships
* correlated behavior sequences

Cluster relations remain evidence-oriented.

They should not imply unsupported attacker intent.

---

## AttackFinding

An AttackFinding represents:

* interpretation of evidence
* higher-level security assessment

Attack findings are derived from:

* SignalFindings
* SignalClusters
* ClusterRelations

Attack findings are interpretations,
not raw evidence.

---

## Evaluation

Evaluation is separate from detection.

Evaluation includes:

* risk scoring
* severity assignment
* recommended actions
* prioritization

Evaluation must remain explainable and deterministic.

---

# YAML Philosophy

## YAML Stores Policy, Not Procedure

YAML is used for:

* thresholds
* configuration
* retention policy
* detection tuning
* runtime policy values

Python is responsible for:

* runtime execution
* orchestration
* canonicalization
* validation
* detection logic

The project intentionally avoids:

* procedural YAML engines
* YAML-driven runtime execution
* hidden runtime logic in configuration

---

# Architecture Principles

## Small Explicit Boundaries

The project prefers:

* small functions
* explicit boundaries
* narrow responsibilities
* deterministic runtime flow

over:

* large orchestration blobs
* implicit side effects
* hidden cross-layer coupling

---

## Stable Runtime Contracts

Core runtime contracts should remain stable.

Examples:

* Canonical Runtime Event
* DetectionReport schema
* Runtime eligibility behavior

Configuration may evolve.

Runtime invariants should remain stable.

---

## Layer Responsibility Separation

The project strongly separates:

* Data Engine
* Detection Engine
* Evaluation Engine
* Response Guidance
* External AI systems

Each layer should have:

* explicit responsibilities
* explicit boundaries
* minimal coupling

---

# Engineering Style

The project prefers:

* small deterministic diffs
* incremental refactoring
* explicit runtime behavior
* minimal abstractions
* architecture consistency
* understandable runtime flow

The project intentionally avoids:

* unnecessary frameworks
* speculative architecture
* premature abstraction
* hidden runtime magic
* unnecessary complexity

---

# Public Alpha Philosophy

The project is currently:

* experimental
* architecture-focused
* public alpha
* explainability-oriented

The goal is not production completeness.

The goal is validating:

* deterministic detection architecture
* observable-first detection design
* explainable runtime boundaries
* evidence-oriented security analysis
