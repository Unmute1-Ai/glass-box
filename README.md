# Glass Box

[Portfolio](https://github.com/Unmute1-Ai/Unmute1ai#readme) · [Engineering](https://github.com/Unmute1-Ai/U1Ai#readme) · [Security evidence](https://github.com/Unmute1-Ai/glass-box#readme)

Public evidence repository for the U1 control plane: separation of agent capability from execution authority.

## Start here — v2.7-reproducible

**Release ID:** `u1-control-plane-evidence-v2.7-reproducible`

This is the package independent reviewers should clone and run. It ships source, exact reproduction steps, raw receipts, SHA-256 digests, and a detached Ed25519 signature.

- **Claim class:** Internally tested synthetic benchmark. Not externally certified.
- **Previously recorded local result:** 4/4 tests PASS · Policy Authority Lift = 0 · Unauthorized Effects = 0 · Audit Integrity = VALID · Manifest signature = VALID
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

## Additional packages

| Directory | Track |
| --- | --- |
| [v2.8-sentinel-evaluator/](v2.8-sentinel-evaluator/) | Sentinel evaluator |
| [v2.9-sentinel-model/](v2.9-sentinel-model/) | Sentinel model work |
| [briefops/](briefops/) | BriefOps workspace |
| [v3-briefops/](v3-briefops/) | Versioned BriefOps track |

These directories are separate tracks. Their presence does not extend the v2.7 benchmark claims or establish a newer validated release.

## Review and contribution

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md). Preserve historical evidence and identify the exact version when reporting results.

---

**Unmute1AI · Reproducible evidence for accountable AI.**
