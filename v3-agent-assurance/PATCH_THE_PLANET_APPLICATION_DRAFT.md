# Patch the Planet — Application Draft

**Status:** Draft for Matthew Sacks / Unmute1AI review. Not submitted. Confirm project details and ownership before using externally.

## Project

**Project name:** U1 Glass Box / Agent Watchtower  
**Public repository:** https://github.com/Unmute1-Ai/glass-box  
**Project type:** Open-source security reference implementation and reproducible synthetic evaluation suite for AI-agent authorization boundaries.

## Short application summary

U1 Glass Box explores a narrow but increasingly important security property: an AI system may propose an action, but it must not be able to grant itself authority to perform that action. The public repository contains a deterministic pre-effect policy gate, a hash-chained audit trail, a synthetic test harness, and an independent-evaluation protocol. The project explicitly labels its current tests as synthetic and does not claim external certification or production security guarantees.

We are seeking hands-on security engineering support to improve the repository's threat model, test quality, CI and supply-chain posture, and reproducibility. Priority areas include delegated identity misuse, cross-tenant resource access, privilege escalation, credential and service-principal changes, monitor tampering, approval replay, and audit checkpoint integrity. The aim is to produce maintainable tests and fixes that other developers can reproduce, not to publish unverified security claims.

## Why this could benefit the wider ecosystem

Agent frameworks increasingly connect models to tools, identities, APIs, and data stores. A reusable set of tests for deny-before-effect behavior, least-privilege boundaries, and independently verifiable audit evidence could help maintainers discover gaps earlier. We would welcome expert review of whether the test model matches real integration failure modes and where the reference implementation is insufficient.

## Requested assistance

- Independent review of the threat model and security boundaries.
- Review of the Python reference implementation and adversarial tests.
- CI hardening, dependency and release-integrity review, and reproducible test execution.
- Guidance on signed evidence checkpoints outside the system under test.
- Prioritized, maintainer-approved patches and regression tests.

## Current evidence and limitations

The repository contains a reference policy gate and synthetic regression tests. The new delegated-identity tests cover cross-tenant resource requests, unapproved privilege escalation, credential-mutation actions, monitor-disable actions, audit-chain validity, and denial accounting. A local mirror of these six tests passed during preparation, but the new branch has not yet had a repository-hosted CI run. These tests do not contact real tenants, cloud credentials, production monitoring, or customer data.

The project does not currently claim that it is critical infrastructure, widely deployed, externally audited, certified, or proven to prevent real-world attacks. An application should describe its actual maintainer capacity, usage, dependency footprint, and public benefit only after those facts are verified.

## Before submission — owner checklist

- Confirm the applicant and repository maintainer identity.
- Verify that the program accepts this type and scale of security reference project.
- Add current maintainer and contact details.
- Provide accurate project activity, users/dependents, test and CI status, and relevant dependencies if requested.
- Confirm willingness to work with selected security engineers and accept maintainer-reviewed patches.
- Do not represent synthetic test results as a production penetration test or external validation.
