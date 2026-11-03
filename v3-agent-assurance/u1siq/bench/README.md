# AuthorityBench for the U1SiQ gate

Runs the 43 AuthorityBench suites (AB-01 to AB-43) as real scenarios against the U1SiQ gate and enforcer in `../`, and records what actually happened. No outcome is written in by hand: an attack counts as **BLOCKED** only if its effect function never ran, and as **BYPASSED** if it did.

    cd v3-agent-assurance/u1siq
    node bench/run.ts --check        # writes bench/out/, exits 1 on any unexpected change

## Latest result

| | Count |
|---|---|
| Suites | 43 |
| Executed against the gate | 26 |
| Not covered (outside what this gate can see) | 17 |
| Attacks blocked, direct check | 21 |
| Attacks blocked, consequence only | 5 |
| **Attacks bypassed** | **0** (AB-16 and AB-40 were bypasses until fixed; see below) |
| Legitimate controls allowed | 26 of 26 |
| False positives | 0 |

How to read it:

- **Every executed suite has a control**: a legitimate version of the same action that must be allowed. A gate that denied everything would fail every control.
- **Every block is checked for its reason.** `BLOCKED_BY` in `suites.ts` names the reason each attack must be stopped for. A block for an incidental reason counts as a mismatch. This caught a bad AB-04 scenario during development.
- **Direct** means the gate checks the exact property the attack targets (consent binding, replay, signatures, chain order, allowlists).
- **Consequence only** (AB-15, 17, 18, 19, 21) means the gate does **not** detect the prompt injection. It blocks the consequential action the injection tries to cause, because that action has no signed consent.
- **Not covered** suites are untested here, **not passed**. Each row says what would test it: a UI audit for AB-22–28, an OS sandbox for AB-29–33 and AB-42, an egress proxy for AB-02, 34 and 35. The gate also has no delegation-depth (AB-09) or tenant (AB-14) model.

## Gaps the bench found, and their fixes

- **AB-16, exfiltration through an allowed host (fixed).** A tier-0 `image.fetch` to an allowlisted CDN could carry record data in an extra query parameter. Now any `egress` action below the consent tier must declare a `parameters` allowlist (key → anchored regex and max length), and the gate refuses to start with a policy that lacks one. Extra keys and non-matching values are denied. **Limit:** data that fits the allowed pattern (for example encoded into an allowed path) is not detected. That needs data-flow taint tracking or a fixed set of fetchable URLs.
- **AB-40, clock rollback (fixed).** The enforcer trusted its local clock, so rolling it back revived an expired receipt. Now the enforcer takes a `TrustedClock`: time signed by a `TimeAuthority` over a fresh random nonce, Roughtime-style, with a high-water mark. The bench attack also replays a signed timestamp captured while the receipt was valid and rewrites its nonce, and the signature check rejects it. Without a trusted clock, the plain clock is wrapped in a `MonotonicClock` that refuses any backward step after a reading. **Limit:** the time authority's key must live outside the agent's trust domain, and a monotonic local clock cannot detect a rollback that happens before its first reading.

Both suites now predict `BLOCKED`. Undoing either fix turns its attack back into `BYPASSED` and fails `--check` (verified).

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
