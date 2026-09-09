# Contributing

Glass Box is an evidence repository, so changes are held to a reproducibility standard.

## Rules

1. Do not rewrite frozen historical release directories.
2. New benchmark/evidence versions go into a new versioned directory.
3. Every claim must identify its scope and whether it is simulated, internally tested, externally reproduced, or independently certified.
4. Include reproduction instructions.
5. Include machine-readable evidence where practical.
6. Preserve raw evidence needed to audit the result.
7. Never treat model capability, external scanner output, or evaluator confidence as an authority grant.

Pull requests should explain:
- what invariant is tested,
- what changed,
- expected decision/outcome,
- reproduction command,
- whether any external provider or real-world effect is involved.
