# Healing Core

## Core Idea

Healing Core functions as a distributed, policy‑constrained autonomic remediation subsystem that ingests heterogeneous telemetry streams—structured logs, metric anomalies, health‑check failures, and resource exhaustion signals—to detect, classify, triage, contain, and safely repair operational faults across the platform. It enforces a strict, layered pipeline: anomaly classification maps raw events to incident categories using a hybrid rule‑and‑ML ensemble; triage assigns risk scores and containment scopes based on severity, category weights, and asset criticality; a signed snapshot of affected state is captured before any mutating action; containment primitives (cgroups, seccomp profiles, traffic shaping, circuit breakers) are applied to limit blast radius; and a verifier harness simulates candidate remediation playbooks in an isolated sandbox prior to staged, policy‑gated execution. The system maintains an append‑only, cryptographically attested audit ledger of all decisions and actions, enabling deterministic rollback to any pre‑remediation snapshot and providing a non‑repudiable chain of custody for forensic analysis. Healing Core delegates sovereign authority for high‑impact or security‑sensitive actions to human operators via integrated escalation workflows, and it promotes validated remediation primitives into a versioned, reusable registry, thereby continuously improving its autonomous repair capability while remaining strictly bound by operational policy and safety budgets.

## Constituent Subsystems

- Telemetry Ingestion & Anomaly Classifier
- Containment & Snapshot Controller
- Remediation Playbook Executor
- Audit Ledger & Policy Governor
- Incident Orchestrator & Escalation Gateway

## Comprehensive Capabilities

- Ingestion of heterogeneous telemetry: structured logs, Prometheus metrics, health‑check endpoints, and system resource probes (CPU, memory, disk, network)
- Rolling‑window aggregation of health signals with configurable thresholds and hysteresis
- Hybrid classification combining high‑precision rule predicates with online ML anomaly detection for unknown fault patterns
- Incident categorization: `TRANSIENT`, `RESOURCE`, `SEMANTIC`, `SYSTEMIC`, `SECURITY`, `UNKNOWN`
- Risk scoring incorporating normalized severity, category weight, asset criticality, and historical incident frequency
- Scope determination (`MODULE`, `SUBSYSTEM`, `GLOBAL`) to guide containment proportionality
- Policy‑driven gating of all automated actions by cost, impact, and category budgets
- Human‑approval triggers for fixes exceeding impact thresholds or classified as security incidents
- Signed snapshot capture of relevant state (config files, process IDs, database offsets, Kafka consumer positions) before any remediation attempt
- Cryptographic attestation of snapshots and audit entries using HMAC or Ed25519 signatures with key material stored in a KMS
- Container‑native containment: dynamic adjustment of cgroup limits (CPU quota, memory cap), seccomp profile application, and network egress filtering via iptables/nftables
- Application‑layer containment: circuit breaker activation, rate‑limiter throttling, and feature‑flag toggles for degraded‑mode operation
- Layered remediation strategies: (1) rollback to signed snapshot, (2) in‑place fix from primitives registry, (3) CRDT‑based state reconciliation, (4) orchestrated migration to healthy infrastructure
- Staged execution of remediation playbooks with pre‑flight verifier simulation in an ephemeral sandbox (container or microVM)
- Automatic rollback to the most recent verified snapshot upon any step failure or post‑remediation health check violation
- Append‑only audit ledger with per‑entry signing and periodic integrity verification; tampering triggers immediate alerts
- Versioned primitives registry that promotes successful fixes and deprecates ineffective or unsafe playbooks
- Cooldown windows per actor/subsystem to prevent repair loops and cascading failures
- Integration with Risk Core for exposure checks before high‑impact financial or contractual actions
- Integration with Custody Core to request signed approval for warranty‑affecting firmware updates or contract modifications
- Escalation workflows to ITSM platforms (ServiceNow, Jira), on‑call alerting (PagerDuty, Opsgenie), and chat collaboration (Slack, Teams)
- Operator console with manual override, approval queue, and incident lifecycle visibility
- Observability pipeline exporting metrics (incident rates, remediation success/failure, MTTR), structured logs, and distributed traces
- Deterministic replay of historical incidents for root‑cause analysis, training, and promotion‑gate validation
- Leader election and replicated decision log for high‑availability deployments across multiple nodes
- Hot‑reloadable policy and primitive definitions from remote configuration stores (etcd, Consul, Git)
- Extensible plugin architecture for custom containment actions, remediation steps, and verifier sandbox runtimes
