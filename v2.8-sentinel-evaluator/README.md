# U1 Sentinel v2.8 — Independent Evaluator Reference

This directory adds a hardened reference integration for an independent model evaluator (for example, NVIDIA Nemotron) **without granting the model authorization authority**.

## Security invariant

```text
MODEL OUTPUT ∉ AUTHORITY
```

If deterministic policy denies an action, no evaluator output can lift that denial.

```text
deterministic_policy(P, A) = DENY
    =>
authorize(P, A, M) = DENY
for every model output M
```

## Control flow

```text
caller
  -> authenticate principal
  -> load immutable proposal by proposal_id
  -> canonicalize + compute proposal_digest
  -> deterministic policy checks
  -> independent evaluator review
  -> bound confirmation
  -> atomically consume nonce
  -> reload proposal + verify digest unchanged
  -> re-run deterministic policy
  -> deterministic executor
  -> cryptographic/audit receipt
```

The evaluator receives the immutable server-side proposal plus authoritative policy context. It never receives caller-selected replacement action fields as authority-bearing input.

## Fail-closed behavior

Execution is denied on:

- deterministic policy rejection
- principal/proposal mismatch
- proposal mutation after review
- malformed evaluator output
- evaluator timeout/provider failure
- unknown evaluator verdict/risk value
- evaluator `deny`
- expired confirmation
- confirmation/proposal digest mismatch
- nonce replay, including concurrent replay
- final pre-effect policy rejection

`manual_review` is a separate non-execution outcome.

## Files

- `sentinel_control.py` — deterministic orchestration and evaluator contract
- `nemotron.py` — OpenAI-compatible Nemotron adapter
- `test_sentinel_control.py` — regression tests for authority invariants and replay resistance
- `requirements.txt` — runtime dependency for the optional Nemotron adapter

## Nemotron

The adapter expects:

```bash
export NEBIUS_API_KEY="..."
```

and uses the shared OpenAI-compatible endpoint shown in NVIDIA/Nebius tooling. Shared endpoints are appropriate for evaluation/testing; production deployments should use an appropriately controlled dedicated or local inference deployment.

## Important

This reference implementation does **not** claim that an LLM can determine authorization from prose. Ownership, effective permissions, resource classification, scope, nonce state, and execution limits remain deterministic server-side facts. The evaluator may discover hazards, but it cannot create authority.
