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
