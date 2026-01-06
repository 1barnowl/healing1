Startup & policy bootstrap — load healing policies, operator escalation rules, resource budgets, and trusted keys.

Health signal collection — sample ticks, allocation/I-O errors, model divergence, verification results, and scheduler metrics.

Anomaly detection & classification — lightweight detectors triage incidents into transient/systemic/resource/semantic categories.

Incident triage & prioritization — score incidents by risk, impact, and SLO violation to decide containment vs. remediation.

Containment & isolation — sandbox, shadow-mode, circuit-breakers, and QoS throttles to limit blast radius.

Snapshot & forensic capture — create signed checkpoints and memory/state snapshots for rollback and post-mortem.

Remediation workflows (policy-gated) — layered fixes: deterministic rollback, quarantined micro-patching, CRDT/event-log reconciliation, or host migration.

Deterministic ratchet-test & verifier harness — replay failing sequences in simulator/sandbox to validate fixes before promotion.

Audit, provenance & operator flows — append-only, tamper-evident logs of detections/actions with optional human-in-the-loop escalation and signed attestations.

Metrics, SLOs & healing primitives promotion — track healing effectiveness, avoid oscillation with thresholds, and convert validated repairs into versioned healing primitives.
