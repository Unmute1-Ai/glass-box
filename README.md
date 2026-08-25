# glass-box

Public evidence repository for the U1 control plane: separation of agent capability from execution authority.

## Runnable release — v2.7-reproducible

**Release ID:** `u1-control-plane-evidence-v2.7-reproducible`

This is the package independent reviewers should clone and run. It ships source, exact reproduction steps, raw receipts, SHA-256 digests, and a detached Ed25519 signature.

- **Claim class:** Internally tested synthetic benchmark. Not externally certified.
- **Validated local result:** 4/4 tests PASS · Policy Authority Lift = 0 · Unauthorized Effects = 0 · Audit Integrity = VALID · Manifest signature = VALID
- **Boundary:** Results apply to the included benchmark, frozen scenarios, and policy configuration.

See [`v2.7-reproducible/`](v2.7-reproducible/) and [`v2.7-reproducible/REPRODUCE.md`](v2.7-reproducible/REPRODUCE.md).

```bash
cd v2.7-reproducible
python3 authoritybench.py --self-test
python3 authoritybench.py --run
python3 verify_release.py
```

## Historical freeze — v2.6-enterprise

The v2.6-enterprise directory is frozen and is not rewritten by later versions.

- **Claim:** Internally tested, publicly reproducible evidence. Not externally certified.
- **Invariant:** Capability ↑ · World Topology unchanged · Authority fixed · Unauthorized Effects = 0 · Audit Integrity = VALID
- **Qualifier:** All 11,850-action results are under the tested policy boundary.

See [`v2.6-enterprise/`](v2.6-enterprise/) for the historical package (manifest, hashes, checklist, communications).

Making accessibility mainstream — as a movement.  
Unmute1AI
