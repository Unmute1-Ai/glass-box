---
license: apache-2.0
pretty_name: U1 AuthorityBench (U1SiQ gate, measured)
tags:
  - agent-security
  - authorization
  - benchmark
  - synthetic
configs:
  - config_name: default
    data_files:
      - split: results
        path: authoritybench-results.jsonl
---

# U1 AuthorityBench: measured results for the U1SiQ gate

Each row is the **measured** outcome of one scenario run against the open-source U1SiQ reference gate and enforcer (`Unmute1-Ai/glass-box`, `v3-agent-assurance/u1siq`). Rows come from `node bench/run.ts`; nothing is assigned by hand.

## What a row means

| Field | Meaning |
|---|---|
| `case` | `attack`, `control` (legitimate version that must be allowed), or `none` (suite not covered) |
| `outcome` | `BLOCKED` / `BYPASSED` for attacks, `ALLOWED` / `FALSE_POSITIVE` for controls, `NOT_COVERED` |
| `coverage` | `direct`: the gate checks the targeted property. `consequence_only`: the attack itself is not detected; only its consequential action is blocked |
| `stopped_at` | `gate`, `enforcer`, or `effect` (the effect ran) |
| `reasons` | Verbatim gate reasons or enforcer error code |
| `blocked_for_intended_reason` | Whether a block came from the property the suite targets |
| `receipt_hash`, `ledger_chain_ok` | The gate's signed receipt hash and a chain re-verification for that run |

## Headline (policy `authoritybench-1`)

26 of 48 registered suites executed. 26 attacks blocked (21 direct, 5 consequence-only) and 0 bypassed. 26 of 26 controls allowed, with 0 false positives. 22 suites not covered (including five registered identity/delegation gaps, AB-44–AB-48). AB-16 and AB-40 were bypasses in the first run and were fixed in the gate. The fixes have stated limits; see `bench/README.md`.

## Do not read this as

- **A certification or a deployed-system result.** It is synthetic scenarios against a reference implementation that shares a process with the agent.
- **"48 of 48 passed."** Not-covered suites are untested.
- **Prompt-injection detection.** Consequence-only rows show the injected action was stopped, not that the injection was seen.
- **Evidence about other models or products.** No other system was run.

The five new suites AB-44–AB-48 are explicitly marked not covered. They are gap registrations, not test passes. The executed result counts above are unchanged until a trusted ANS verifier, browser actor binding, signed delegation model, and revocation enforcement are implemented and tested.

## Reproduce

    git clone https://github.com/Unmute1-Ai/glass-box
    cd glass-box/v3-agent-assurance/u1siq
    node bench/run.ts --check --out-dir out    # Node 22.18+
