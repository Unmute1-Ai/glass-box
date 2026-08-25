# U1 Control-Plane Evidence — v2.7-reproducible

**Release ID:** `u1-control-plane-evidence-v2.7-reproducible`  
**Status:** Frozen, runnable, independently verifiable  
**Claim class:** Internally tested synthetic benchmark. Not externally certified.

This directory is a new version. It does not modify the frozen v2.6-enterprise record.

## Why v2.7 exists

Independent review of the v2.6 publication could not get past step zero: the earlier package described results without shipping runnable source, exact reproduction steps, raw receipts, or a verifiable detached signature over real file digests.

v2.7 answers that with a tree a reviewer can clone, run, hash, and signature-check.

## What this package contains

| Path | Role |
|---|---|
| `authoritybench.py` | Deterministic 18-scenario × 2-adapter harness |
| `verify_release.py` | Hash + Ed25519 + self-test verifier |
| `REPRODUCE.md` | Exact reproduction procedure |
| `METHODOLOGY.md` | Policy, PhaseFlow, metrics, scenario table |
| `CLAIMS.md` | Claims boundary (read this before quoting results) |
| `evidence/` | Raw receipts, comparison, test transcript |
| `HASHES/SHA256SUMS` | SHA-256 of every hashed file |
| `KEYS/release-ed25519.pub` | Release-specific Ed25519 public key |
| `SIGNATURES/manifest.ed25519.sig` | Detached signature over `MANIFEST.canonical.json` |

## Validated local result

* 4/4 tests PASS
* Policy Authority Lift = 0
* Unauthorized Effects = 0 observed
* Audit Integrity = VALID
* Manifest signature = VALID

These are bounded benchmark results under the supplied policy/scenario configuration, not a claim of universal security or external certification.

## Reproduce in three commands

```bash
python3 authoritybench.py --self-test
python3 authoritybench.py --run
python3 verify_release.py
```

See `REPRODUCE.md` for the full procedure, including signature verification without `cryptography` (OpenSSL 3 fallback).

## Invariant under this freeze

- Adapter capability may increase (the stronger mock proposes a larger action vocabulary, including attacks).
- Policy / world topology is frozen and identical for both adapters.
- Authority is not a function of adapter identity. The mask is never consulted from the adapter.
- Policy Authority Lift = 0
- Unauthorized Effects = 0
- Audit Integrity = VALID

Making accessibility mainstream — as a movement.  
Unmute1AI
