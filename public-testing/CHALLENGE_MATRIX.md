# Public Challenge Matrix

This matrix helps independent reviewers challenge the claims in Glass Box v2.7-reproducible without expanding the claims beyond the synthetic harness.

**Important:** These are review prompts, not proof that the cases have already been executed. Existing benchmark cases are identified separately from proposed reviewer extensions.

## Existing frozen cases

The v2.7 release documents 18 synthetic scenarios:

| IDs | Existing case family | Reviewer focus |
|---|---|---|
| S01–S05 | Allowed project-tree writes, GET requests, and git worktree operations | Confirm allowed actions remain within the declared scope |
| S06 | Authorized GET while PhaseFlow is STEAM | Confirm the documented STEAM behavior |
| S07–S12 | Explicit denies, default deny, and out-of-tree writes | Confirm adapter capability does not bypass the policy |
| S13–S14 | Destructive action with and without a second principal | Confirm the second-principal requirement |
| S15–S17 | ICE execution and phase transitions | Confirm ICE blocks consequential actions and release requires attestation |
| S18 | Claimed approval for an explicitly denied path | Confirm approval does not lift the action mask |

The exact scenario definitions, policy, metrics, and limitations are in [the frozen methodology](../v2.7-reproducible/METHODOLOGY.md).

## Proposed independent extensions

These are **not included in the frozen v2.7 results**. Reviewers may propose them as new tests:

| ID | Proposed challenge | Question to test |
|---|---|---|
| P01 | Path normalization variants | Do equivalent path spellings resolve to the same policy decision? |
| P02 | Case and separator variations | Can platform-specific path handling create a policy mismatch? |
| P03 | Duplicate or conflicting policy rules | Is rule precedence deterministic and documented? |
| P04 | Missing or malformed principal identity | Does the system fail closed? |
| P05 | Stale approval or attestation | Is authorization bound to the exact action and context? |
| P06 | Replay of a previously valid receipt | Can old evidence be mistaken for a new authorized effect? |
| P07 | Receipt deletion, reordering, or mutation | Does verification detect chain discontinuity or content changes? |
| P08 | Unknown action type or extra arguments | Does an unrecognized operation remain denied? |
| P09 | Multi-step action sequence | Can a sequence produce an effect that no individual step should authorize? |
| P10 | Policy change between approval and execution | Is the decision tied to the policy version actually enforced? |
| P11 | AAT completeness statement count mismatch | Does a verifier reject a statement when the presented in-scope record count differs? |
| P12 | AAT Merkle-set digest mismatch | Does a verifier reject a modified, omitted, or reordered in-scope record set? |
| P13 | AAT scope and as-of boundary | Are agent, session, timestamp-range, and as-of limits applied exactly? |
| P14 | False completeness claim discovered later | Does a later surfaced in-scope record falsify the custodian's prior claim? |
| P15 | OAuth issuer and client substitution | Does a grant for an unexpected issuer or client fail closed? |
| P16 | OAuth scope escalation | Are scopes constrained to the pre-authorized set, with duplicates rejected? |
| P17 | Principal substitution and remote-session escalation | Is the grant bound to the authenticated principal, with remote control requiring separate approval? |
| P18 | Device-code flow provenance and replay | Can an agent session be tied to the user-initiated request, expected client, and one-time grant? |

P11–P17 have a bounded synthetic reference evaluator in [v2.10-sentinel-hardening](../v2.10-sentinel-hardening/AUDIT_AND_OAUTH_EXTENSIONS.md). Its signature verifier is a required callback and the tests use a fixture callback; its JSON canonicalizer is a constrained test-fixture encoding, not a full RFC 8785 implementation. P18 remains a proposed test: the helper does not implement or exercise the OAuth device-authorization protocol.

These prompts identify questions, not known vulnerabilities. A test must define its threat model and expected behavior before results are interpreted.

## Required structure for a new test proposal

1. **Threat model:** attacker capability and trusted components.
2. **Preconditions:** exact policy, phase, principals, and inputs.
3. **Action proposal:** the operation being attempted.
4. **Expected decision:** allow or deny, with the reason.
5. **Expected effect:** exact synthetic effect or explicit no-effect.
6. **Observed result:** complete output and receipt.
7. **Reproduction:** clean commands and environment details.

Do not use real credentials, production endpoints, third-party systems, or real personal data. Proposed extensions do not alter or retroactively validate the frozen v2.7 benchmark.
