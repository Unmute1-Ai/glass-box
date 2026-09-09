# Production / Publication Readiness

**Repository role: public evidence and reproducibility, not a production runtime.**

A release is publication-ready when:

- [ ] benchmark self-test passes
- [ ] benchmark run reproduces expected results
- [ ] release verification passes
- [ ] hashes/signatures verify
- [ ] claim scope is explicit
- [ ] simulated vs live integrations are clearly labeled
- [ ] unauthorized-effect count is reported
- [ ] authority-lift result is reported
- [ ] raw evidence needed for audit is included
- [ ] frozen historical releases remain unchanged

For a runtime implementation, use a separate versioned package/repository and reference this repository as evidence rather than turning evidence history into mutable application code.
