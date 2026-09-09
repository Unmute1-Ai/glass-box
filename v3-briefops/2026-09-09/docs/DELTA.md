# U1 BriefOps v3 Delta — 2026-09-09

Baseline: U1 Sentinel v3 / AuthorityBench v3. The baseline already enforces signed model provenance, component admission, cross-domain consent, scoped single-use credentials, simulation-before-live physical gating, multimodal accessibility intent, and signed effect receipts.

## Material changes

1. **Compute provenance metadata** — record registry owner, hardware vendor, and optional hardware attestation, while explicitly preventing any of those facts from creating principal authority. Motivated by OpenAI–Samsung custom-chip work and NVIDIA–Hugging Face platform consolidation.
2. **Advisory-inspector invariant** — external safety monitors, scanners, model judges, and marketplace inspectors are evidence inputs only. They cannot convert a Sentinel DENY into ALLOW or mint credentials.
3. **PRIMER child-profile boundary** — treat transitions into persistent child profiles as sensitive. Adaptation requires explicit authorized guardian/owner consent and exact single-use credentials for consequential writes.
4. **AnnealMesh commercial metadata** — public funding, acquisition status, registry ownership, or vendor scale may influence routing/business evaluation but never `verified_advantage`, provenance admission, or authority.
5. **Quantum CHIPS opportunity** — no security-policy change. Record as a partnership/funding route only; federal awards to named quantum vendors are not treated as an open U1 grant.

## Preserved invariants

- Model capability can change without changing principal authority.
- External inspector/monitor output is advisory only.
- Sensitive cross-domain transitions require explicit consent.
- Unverified component provenance fails closed.
- Consequential effects require scoped single-use credentials.
- No destructive, financial, health-system, physical, or official-emergency side effect is executed by this package.
