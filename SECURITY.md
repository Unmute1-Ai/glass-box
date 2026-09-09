# Security Policy

## Purpose

This repository is a public evidence repository. It demonstrates tested authority-control invariants within explicitly bounded benchmark packages.

## Reporting

Use GitHub private vulnerability reporting/security advisories when available for issues that could undermine benchmark integrity, receipt verification, manifest signing, or policy enforcement.

Do not publish private signing keys, credentials, or unreleased exploit details.

## Evidence integrity

- Historical evidence directories are immutable once frozen.
- New versions must use new directories/releases rather than rewriting prior evidence.
- Hashes/signatures must be regenerated only for a new release artifact.
- Scanner/evaluator output is advisory; it cannot grant authority.
- Benchmark success applies only to the tested policy/scenario boundary.

This repository is not a security certification of arbitrary agents or production systems.
