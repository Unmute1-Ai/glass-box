# U1 Agent Assurance v3

Two connected capabilities, built on the existing Glass Box / Sentinel direction:

- Agent Watchtower: deterministic pre-effect allowlist and scope enforcement, a session action budget, restricted-data denial, human-approval requirements, an emergency kill switch, and a hash-chained audit trail.
- Independent Evaluation Lab protocol: repeatable adversarial evaluation, reviewer access boundaries, evidence retention, and release-blocking invariants.

## Quick start

Requires Python 3.10+ and no third-party packages.

    cd v3-agent-assurance
    python -m unittest -v
    python run_scenarios.py --output report.json

## Integration contract

Call the policy gate immediately before an effect. Route actions through a fixed server-side dispatcher; do not evaluate model-generated code or let a model choose an arbitrary callable. A denied decision must terminate the path before side effects.

## Security and evidence limits

- This is a reference implementation, not a drop-in production control plane.
- The hash chain detects edits in the current log but cannot stop an administrator who rewrites the entire log and recomputes hashes. Export and sign checkpoints in a separate trust domain.
- The in-memory session counter and kill switch do not coordinate across processes or regions. Production use needs a transactional shared store, authenticated operator identity, durable kill-switch propagation, and concurrency tests.
- The protocol does not make a third-party evaluator independent by itself. Independence requires governance, scoped access, conflict disclosure, and evidence the reviewer actually ran the agreed tests.
- Included tests and scenarios are synthetic. They are not evidence of deployed performance, external certification, or zero risk.

## Files

- agent_watchtower.py: deterministic gate, kill switch, hash-chain audit.
- test_agent_watchtower.py: regression tests for deny-before-effect, scope, approval, kill switch, rate limit, and tamper detection.
- test_supply_chain_security.py: synthetic regression tests for cross-tenant resource attempts, privilege escalation, credential mutation, monitor-disable requests, and audit evidence.
- DELEGATED_IDENTITY_TEST_PLAN.md: threat cases, expected outcomes, and production-validation gaps for delegated identity and supply-chain abuse.
- scenarios.json and run_scenarios.py: reproducible synthetic scenario runner and machine-readable report.
- u1siq/: hardened TypeScript reference for the U1SiQ five-gate check and tool-side enforcer (signed, envelope-bound, replay-protected, chain-verified receipts; authenticated consent; fail-closed acoustic gate). See u1siq/README.md for the same-process trust limit.
- INDEPENDENT_EVALUATION_PROTOCOL.md: reviewer model, required test families, evidence package, and pass/fail invariants.
