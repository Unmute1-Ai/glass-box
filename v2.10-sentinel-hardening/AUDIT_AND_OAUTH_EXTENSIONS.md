# v2.10 audit-completeness and agent OAuth challenge extensions

Status: **new synthetic test module; not a production integration or certification**.

This extension adds two bounded evaluators to the existing v2.10 hardening track:

1. An AAT v11 Section 8.5 completeness-statement verifier using the RFC 6962 Merkle leaf/node construction.
2. Synthetic policy checks for OAuth grants used by agent sessions: issuer, client, principal, scope, expiry, and separate approval for remote sessions.

## Run

```sh
cd v2.10-sentinel-hardening
python3 -m unittest -v test_audit_completeness.py
```

## Evidence boundary

- The AAT verifier requires a caller-supplied signature-verification callback. The tests use a fixture callback and **do not perform cryptographic signature verification**.
- The JSON canonicalizer supports the constrained fixtures in this module and is **not a complete RFC 8785 JCS implementation**.
- The OAuth helper is a deterministic policy test, not an OAuth device-authorization flow, identity provider, token issuer, or network integration.
- The tests use synthetic records and identities only. No live accounts, providers, endpoints, or credentials are accessed.
- A valid completeness statement proves only that the presented in-scope set matches the signed count and digest. It cannot prove that the custodian disclosed every record it produced. A later-discovered in-scope record falsifies the claim, consistent with AAT v11 Section 14.7.

## Source alignment

- [AAT v11 Section 8.5 and 14.7](https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-11)
- [RFC 6962 Merkle construction](https://www.rfc-editor.org/rfc/rfc6962)

This module does not modify the frozen v2.7 evidence or upgrade any production-readiness claim.
