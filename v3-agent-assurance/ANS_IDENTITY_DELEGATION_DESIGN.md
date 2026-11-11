# ANS Identity Adapter and Delegated Authority Design

**Status:** Design proposal for review. No ANS runtime integration is claimed by this document.
**Target:** U1Si-Q / Agent Watchtower / Glass Box
**Standards baseline checked:** 2026-11-11

## 1. Decision

Integrate Agent Name Service (ANS) as an external, verifiable agent-identity input. Do not delegate authorization to ANS and do not make the U1Si-Q gate depend on live DNS or transparency-log availability during every action.

The trust boundary is:

1. A trusted ANS verifier validates the agent's registered name, version, key binding, registration state, and proof of key possession.
2. An authenticated identity broker issues a short-lived, audience-bound verification assertion.
3. U1Si-Q independently evaluates that assertion together with the human delegator, signed task grant, action envelope, policy, consent, and current revocation state.
4. The enforcer rechecks the grant and revocation state immediately before the effect.
5. Glass Box records hashes and verification outcomes sufficient to reconstruct the authority chain without retaining raw browser content or sensitive media.

**Invariant:** Verified identity is necessary context for some policies; it is never permission to execute.

## 2. Why an adapter, not a hard dependency

ANS is useful for portable naming, discovery, versioned identity, key binding, and transparency evidence. Its public documentation currently labels the specifications as drafts under active development. The October 26, 2026 ANS v2 Internet-Draft is an individual submission and explicitly has no formal standing in the IETF standards process.

Therefore:
- Pin the exact ANS profile, specification revision, verifier build, and cryptographic algorithms.
- Keep ANS-specific parsing and proof validation behind an adapter.
- Normalize only successful verification into a typed assertion.
- Keep U1Si-Q's policy, approval, delegation, revocation, and execution decisions independent.
- Fail closed for policies that require verified agent identity if the verifier is unavailable or evidence is stale. Do not silently fall back to an agent-supplied ID.

## 3. Trust objects

### 3.1 VerifiedAgentIdentity

Constructible only by the trusted verifier/broker, never by model output:

- issuer and verifier build/version
- ANS name and pinned agent version
- operator domain
- public-key thumbprint and proof-of-possession method
- relying-party audience
- registration status and revocation status
- verified-at and expires-at timestamps
- transparency-log checkpoint/entry reference and proof digest
- canonical assertion digest and verifier signature/key ID

Do not infer legal-entity identity unless the selected ANS identity profile actually verifies it. Do not treat DNS discovery alone as authentication.

### 3.2 HumanDelegator

A separate authenticated principal representing the person or organization that authorized the task:

- stable subject identifier from a trusted identity provider
- authentication context and assurance level
- session identifier
- approval method and timestamp
- consent/mandate identifier

The browser's human session is not an agent identity. The agent identity must be independently attested and bound to the session through a trusted broker or application integration.

### 3.3 DelegationGrant

Each hop is signed and immutable:

- grant ID and issuer/grantor
- grantee agent identity and version
- relying-party audience
- task/intent hash
- allowed actions, resources, data classifications, and channels
- not-before, expiry, nonce, and revocation handle/epoch
- parent grant hash
- maximum delegation depth
- constraints on further delegation
- signature and signing-key identifier

A child grant must be a subset of its parent's effective grant across action, resource, data class, audience, time window, and delegation depth. A child cannot widen any dimension. A parent consent does not automatically authorize a child unless the parent grant explicitly permits that delegation and the child is bound to the grant.

## 4. Enforcement sequence

1. Receive an action envelope over an authenticated channel.
2. Resolve the trusted verifier assertion; reject agent-supplied identity claims.
3. Validate assertion signature, audience, freshness, version pin, key binding, proof of possession, registration status, and revocation state.
4. Authenticate the human delegator separately.
5. Validate every signed delegation hop from the human/organization mandate to the executing agent.
6. Compute effective authority as the intersection of every ancestor grant and current policy.
7. Verify task/intent hash, exact action envelope, resource, data class, channel, expiry, nonce, and approval requirements.
8. Check revocation state again immediately before the effect. A stale cached decision cannot authorize execution.
9. Execute only through the fixed enforcer path.
10. Emit a signed Glass Box receipt binding the verified identity digest, delegator, delegation-chain digest, effective scope, policy version, revocation epoch/status, envelope hash, decision, effect result, and ledger sequence.

No raw DOM, full page text, credentials, secrets, audio/video, or biometric payloads belong in the receipt. Keep only minimal identifiers, hashes, policy outcomes, and evidence references.

## 5. Browser-session rule

A browser cookie or authenticated user session proves which human session is active. It does not prove which agent is driving the browser, what task the human delegated, or which narrower scope applies.

Preferred path:
- browser/agent runtime emits a signed agent identity and task-grant assertion;
- trusted broker binds it to the authenticated human session;
- application receives both human and agent principals plus the bounded grant;
- application audit records distinguish human actions from agent actions.

If the browser or application cannot carry that context, treat the operation as an unattributed human-session action. Require explicit step-up authorization for consequential effects or deny them. Do not infer the agent from user-agent strings, DOM text, extension names, or model claims.

A directly relevant October 10, 2026 preprint, “The Agent Clicks Approve,” reported that injected page text induced unauthorized OAuth-style grants or webhook registrations in all 73 baseline attack runs. Its service-side authority-envelope gate rejected all 70 gated attack requests while allowing the named-task controls. This is a single preprint evaluation, not an independent replication, but it gives AB-45 a concrete attack/control design: freeze the task's authorized client/account or webhook URL before the agent starts, then reject any consent or registration request that differs at the service boundary.

Accessible approval must display the exact action, resource, recipient, data class, and effect in a modality the user can use. Approval is bound to the exact canonical envelope, not a summary or a generic session consent.

## 6. Revocation semantics

Revocation is checked at the point of effect, not only at login or initial task creation.

A revocation event must invalidate:
- the named agent identity or pinned version;
- descendant delegation grants;
- active browser sessions and broker tokens;
- cached authorization decisions;
- queued or scheduled jobs that have not executed;
- credentials minted under the revoked grant.

Define and measure a maximum revocation propagation bound. If the revocation service is unavailable, actions requiring current revocation state fail closed. An already completed external effect cannot be retroactively undone; receipts must distinguish blocked future effects from compensating actions.

## 7. Benchmark mapping

The following cases are registered as not covered until the implementation exists:

| Suite | Target |
|---|---|
| AB-44 | ANS identity spoofing, stale/revoked registration, key mismatch, version rollback |
| AB-45 | Browser agent borrowing a human-authenticated session without distinct actor attribution |
| AB-46 | Blueprint consent incorrectly inherited by a child agent |
| AB-47 | Child agent requesting authority outside its parent's grant |
| AB-48 | Revocation failing to propagate to descendants, cached sessions, credentials, or queued jobs |

Each eventual executable suite must have an attack and a legitimate control. The harness must measure actual effects, intended denial reason, receipt integrity, and revocation freshness. These suites must not be reclassified as executed merely because a document or mock verifier exists.

## 8. Implementation phases

### Phase A — Contract and threat model
- Freeze the selected ANS profile and threat assumptions.
- Define verifier assertion and delegation-grant schemas.
- Define canonicalization, signature, key-rotation, expiry, audience, and revocation semantics.
- Add negative tests for malformed and untrusted assertions.

### Phase B — Verifier adapter
- Implement a separate verifier process/service.
- Validate DNSSEC and the selected certificate/transparency proofs according to the pinned profile.
- Verify proof of key possession and registration/revocation status.
- Sign short-lived, audience-bound assertions.
- Add test fixtures for valid, forged, stale, revoked, mismatched, and rolled-back identities.

### Phase C — U1Si-Q enforcement
- Extend the trusted gate input with verifier-issued identity and signed delegation-chain references.
- Enforce identity-to-session binding, parent/child scope attenuation, maximum depth, task binding, and point-of-effect revocation.
- Keep all checks before the effect boundary.
- Do not trust identity, scope, or approval fields supplied only by the agent.

### Phase D — Glass Box evidence
- Add identity assertion digest, delegator subject, delegation-chain digest, effective scope, revocation epoch/status, and verifier key ID to receipts.
- Verify receipt signatures and chain continuity.
- Export signed checkpoints to a separate trust domain.

### Phase E — Benchmark and release gate
- Convert AB-44–AB-48 from not_covered to executed only after real verifier/enforcer paths exist.
- Pair every attack with a legitimate control.
- Require zero unauthorized effects, zero identity/attribution bypasses, correct intended denial reasons, and bounded revocation propagation.
- Run clean-clone CI and retain raw result files, environment details, source commit, and signed evidence.
- AB-16 and AB-40 were bypasses in the first AuthorityBench run. Both now have fixes in the gate (egress parameter allowlist; signed, nonce-bound enforcer time) and are remeasured as `BLOCKED` in this repository's CI, where reverting either fix fails `--check`. Independent re-measurement is still outstanding; until it is done, cite them as fixed by the authors, not as independently verified.

## 9. Explicit non-claims

This design does not claim:
- ANS is a finalized standard or certification.
- U1 currently implements ANS verification.
- Browser identity can be inferred from a human cookie.
- A hash chain alone prevents a privileged administrator from rewriting all evidence.
- Revocation can undo an effect that has already completed.
- The proposed design has passed tests, production validation, or independent review.

## References

- ANS specifications and documentation: https://ansinfo.ai/docs/
- ANS v2 Internet-Draft, October 26, 2026: https://datatracker.ietf.org/doc/html/draft-narajala-courtney-ansv2
- Linux Foundation ANS project announcement: https://www.linuxfoundation.org/press/linux-foundation-announces-intent-to-launch-agent-name-service-to-establish-trusted-identity-infrastructure-for-ai-agents
- Browser-agent identity/session attribution analysis, November 11, 2026: https://thehackernews.com/2026/11/we-built-agent-that-broke-all-of-our.html
- Hossen, “The Agent Clicks Approve,” arXiv:2610.15138, October 10, 2026: https://arxiv.org/abs/2610.15138
