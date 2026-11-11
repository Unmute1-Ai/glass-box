# AuthorityBench for the U1SiQ gate

Registers 48 AuthorityBench suites (AB-01 to AB-48). The 26 covered suites execute against the U1SiQ gate and enforcer in `../`; 22 are explicitly not covered and are not counted as passes. No outcome is written in by hand: an attack counts as **BLOCKED** only if its effect function never ran, and as **BYPASSED** if it did.

    cd v3-agent-assurance/u1siq
    node bench/run.ts --check        # writes bench/out/, exits 1 on any unexpected change

## Latest result

| | Count |
|---|---|
| Registered suites | 48 |
| Executed against the gate | 26 |
| Not covered (outside what this gate can see) | 22 |
| Attacks blocked, direct check | 19 |
| Attacks blocked, consequence only | 5 |
| **Attacks bypassed** | **2 (AB-16, AB-40)** |
| Legitimate controls allowed | 26 of 26 |
| False positives | 0 |

How to read it:

- **Every executed suite has a control**: a legitimate version of the same action that must be allowed. A gate that denied everything would fail every control.
- **Every block is checked for its reason.** `BLOCKED_BY` in `suites.ts` names the reason each attack must be stopped for. A block for an incidental reason counts as a mismatch. This caught a bad AB-04 scenario during development.
- **Direct** means the gate checks the exact property the attack targets (consent binding, replay, signatures, chain order, allowlists).
- **Consequence only** (AB-15, 17, 18, 19, 21) means the gate does **not** detect the prompt injection. It blocks the consequential action the injection tries to cause, because that action has no signed consent.
- **Not covered** suites are untested here, **not passed**. Existing gaps include UI audit (AB-22–28), OS sandbox (AB-29–33 and AB-42), egress proxy (AB-02, 34 and 35), delegation depth (AB-09), and tenant identity (AB-14). Newly registered AB-44–48 cover ANS identity verification, browser-session actor attribution, inherited blueprint consent, child-scope attenuation, and descendant revocation. These remain untested until the trusted verifier and delegation model are implemented.

## Newly registered identity and delegation gaps (AB-44–AB-48)

These five cases are deliberately marked not covered. The gate currently has no trusted ANS verifier, browser-agent/session binding, signed parent-to-child grant chain, authority attenuation, or descendant revocation registry. See [ANS_IDENTITY_DELEGATION_DESIGN.md](../ANS_IDENTITY_DELEGATION_DESIGN.md) and [DELEGATED_IDENTITY_TEST_PLAN.md](../../DELEGATED_IDENTITY_TEST_PLAN.md) for the trust model and acceptance criteria. Their presence increases the inventory to 48 suites and the not-covered count to 22; it does not increase the number of executed tests or change the measured outcomes above.

## Known gaps the bench found

- **AB-16, exfiltration through an allowed host.** A tier-0 `image.fetch` to an allowlisted CDN can carry record data in its query string. The gate checks action, resource and tier, not the data inside parameters. Fix options: no free-form parameters on tier-0 egress actions, a data-flow taint check, or treating any egress as tier 2.
- **AB-40, clock rollback.** An attacker who controls the enforcer's clock can make an expired receipt valid again. Replay protection still limits it to one use. Fix: a trusted or monotonic time source, or expiry by ledger sequence rather than wall clock.

Both are predicted `BYPASSED` in `suites.ts`, so CI stays green while they're open. When one is fixed, CI goes red until the prediction is updated, which records the fix.

## Proving the check works

Disabling the enforcer's replay check makes the run report `AB-05 attack: expected BLOCKED, got BYPASSED` and exit 1. Re-run that mutation whenever the harness changes.

## Output

- `bench/out/authoritybench-results.jsonl`: one row per attack, control or not-covered suite, with the stage it stopped at, the gate or enforcer reasons, the receipt hash, and whether the ledger chain verified.
- `bench/out/authoritybench-summary.json`: counts, bypassed and not-covered suite ids, and limits.

Signing keys are generated per run, so receipt hashes differ between runs. Outcomes and reasons are deterministic.

## Limits

- These are synthetic scenarios against a reference implementation, not a deployed system.
- The gate shares a process with the agent (see `../README.md`). The bench tests the gate's logic, not process isolation.
- The WCAG 2.2 "evaluation" rows from the earlier dataset generator are not reproduced here. That generator assigned outcomes by cohort and measured nothing. Real accessibility numbers need audits of real consent screens.
