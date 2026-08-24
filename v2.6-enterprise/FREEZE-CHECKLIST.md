# Freeze Checklist — u1-control-plane-evidence-v2.6-enterprise

Execute in order. Do not skip or reorder.

1. Confirm policy document bytes are final.  
   Compute `policy_sha256 = SHA-256(POLICY/p-2026-08-baseline.pdf)`.  
   Write full 64-character digest into `HASHES/policy.sha256` and into `MANIFEST.json`.

2. Confirm world-model snapshot is final.  
   Compute `world_model_hash = SHA-256(WORLD_MODEL/snapshot.tar.zst)`.  
   Write full digest into `HASHES/world_model.sha256` and `MANIFEST.json`.

3. Confirm all benchmark result files under `BENCHMARKS/` are final and contain the exact qualifier string “under the tested policy boundary” wherever the 11,850-action result appears.

4. Build the complete package directory tree exactly as specified.

5. Compute `package_sha256` over the entire directory (or the final archive).  
   Write full digest into `HASHES/package.sha256` and `MANIFEST.json`.

6. Populate remaining `MANIFEST.json` fields (release_id, created_utc, evidence_invariant, benchmark_summary).  
   Canonicalize per RFC 8785 (exclude signature object).  
   Sign with the private key corresponding to `KEYS/control-plane-evidence-v2.6.pub`.  
   Insert signature object.

7. Verify locally:  
   - signature validates  
   - every listed hash matches the corresponding file  
   - evidence_invariant values are exactly as locked  
   - no truncated digests remain anywhere

8. Publish the package to the canonical location (Hugging Face dataset) under the exact release identifier `u1-control-plane-evidence-v2.6-enterprise`.  
   Do not overwrite any previously published object under this path.

9. Publish the public verification key and its fingerprint.

10. Record the freeze timestamp and the three full digests in an internal immutable log.  
    Future runs must use a new version string (v2.7+).

**Rule:** If any frozen input changes after step 1, abort the freeze, increment the version, and restart. Silent mutation of v2.6 is forbidden.
