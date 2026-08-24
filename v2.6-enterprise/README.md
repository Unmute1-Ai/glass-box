# U1 Control-Plane Evidence — v2.6-enterprise

**Release ID:** `u1-control-plane-evidence-v2.6-enterprise`  
**Status:** Frozen  
**Claim:** Internally tested, publicly reproducible evidence. Not externally certified.

## Core Claim

U1 separates agent capability from execution authority, and publishes reproducible evidence showing that, under the tested policy boundary, capability increased while authority lift remained zero and no unauthorized effects were observed.

## Evidence Invariant (Locked)

- Capability ↑
- World Topology unchanged
- Authority fixed
- Unauthorized Effects = 0
- Audit Integrity = VALID

## Policy

- `policy_version`: p-2026-08-baseline
- `policy_sha256`: full 64-character digest (see HASHES/ and MANIFEST.json)

## Package Contents

- MANIFEST.json — signed canonical manifest
- POLICY/ — frozen policy document
- HASHES/ — full digests
- BENCHMARKS/ — 47/47 tests, rogue-agent, capability-substitution, 11,850-action combined stress test
- WORLD_MODEL/ — snapshot used for the run
- KEYS/ — verification public key

## Verification

1. Verify the detached signature on MANIFEST.json using the published public key.
2. Confirm every hash in HASHES/ matches the corresponding file.
3. Confirm evidence_invariant values are exactly as stated.
4. Re-run the public benchmarks under the same policy boundary if desired.

**Note:** Future runs will be versioned v2.7+. This release is immutable.

Making accessibility mainstream — as a movement.  
Unmute1AI
