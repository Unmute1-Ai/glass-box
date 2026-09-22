# U1 Sentinel × NVIDIA NOOA Enterprise Showcase

Authority-lift benchmark for model substitution under a fixed principal and policy.

## Invariant

`A(M1, P, Pi) = A(M2, P, Pi)` for the tested model variants under a fixed principal `P` and policy digest `Pi`.

The benchmark records deterministic SHA3-256 decision receipts, verifies a tamper-evident audit chain, and checks that protected effects remain zero when model identity changes.

## Run

```bash
python -m benchmarks.run_invariant
pytest
```

## Security boundary

NOOA supplies cognition/capability invocation. U1 Sentinel evaluates authority before effects. An OS/container/VM sandbox remains the final containment boundary.

## Claim scope

The benchmark demonstrates authority lift = 0 only for the tested fixed-principal/fixed-policy suite. It is not a universal proof that arbitrary agents cannot escalate authority.
