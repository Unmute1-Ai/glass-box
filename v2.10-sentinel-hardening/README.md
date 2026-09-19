# SENTINEL v2.10 — approval hardening reference

Status: reference code for review, not a production security product. No network listener, agent execution service, or customer deployment is included. Historical evidence directories are unchanged.

## Reproduced findings

At base commit `4ec50b2a119b6ac54bc8017f532d092c014aaed3`, v2.8 snapshots time before asynchronous work. A confirmation that expires during evaluator review can still execute if the nonce adapter does not independently reject expiry. A deterministic local reproduction advanced the clock past expiry inside the evaluator and recorded one effect.

The v2.8 test adapter only tracks previously seen tokens. It accepts arbitrary unissued tokens, so it demonstrates duplicate rejection, not authenticated approval issuance. The reference protocol did not make the issuance requirement explicit. The reference also does not impose its own evaluator timeout.

## Changes

- Recheck current server time before evaluation, after evaluation, and immediately before executor dispatch. Remove the caller-supplied `now` argument; clock mocking stays in tests.
- Bound cooperative asynchronous evaluator review with a validated timeout (10 seconds by default, at most 60).
- Document issued-token semantics and provide a SQLite adapter with random 256-bit tokens stored as SHA-256 hashes, exact principal/digest/expiry binding, atomic consumption, restart persistence, and denial on database errors.
- Check time after acquiring the database write lock.

`issue()` is a trusted approval-service operation. The application must authenticate the approver and enforce approval policy before calling it. An HTTP request must never directly construct an authenticated `Principal`, call `issue()`, or choose policy/store/executor dependencies. The test-only `AtomicNonceStore` is intentionally retained solely to isolate orchestration regression tests and is not a deployable approval store.

## Verification

Python 3.10+, standard library only:

```sh
cd v2.10-sentinel-hardening
python3 -m unittest -v
```

19 tests passed locally on 2026-09-17: 10 existing policy/replay regressions and 9 new cases covering expiry during review, expiry during final reload, hung review, unissued approvals, binding tampering, concurrent connections and restart replay, store expiry, database failure, and valid one-shot execution. Concurrent tests use separate SQLite connections and threads, not a multi-host database.

## Remaining production blockers

This patch is deliberately not a production-readiness declaration. A real deployment still needs authenticated identity and approval issuance, a concrete policy engine with canonical resource resolution, executor-side deadline and policy enforcement at the effect boundary, durable pre-effect audit intent and crash recovery, and idempotent effects. The returned receipt is not itself a signed durable audit log. Python cooperative cancellation cannot stop a blocking or malicious evaluator; isolate that work in a separately bounded process. SQLite does not supply multi-host coordination. Protect the database directory and backups; do not expose the approval database or retained records through a web root.

There is no signing key, exposed API, payment processor, production deployment, or universal security guarantee in this package.
